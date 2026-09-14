//! Native implementation of `governance.policy`.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::error::AuditError;

use super::common::{denominator, finding, ProviderInput};
use legion_contracts::{FindingRef, ProviderStatus};

/// Normalize one policy record while retaining every source field.
pub fn policy_evidence(value: &Value) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "policy must be an object".to_owned())?;
    for key in [
        "policy",
        "owner",
        "authority",
        "status",
        "disposition",
        "expiresAt",
    ] {
        if object
            .get(key)
            .is_none_or(|item| item.is_null() || item.as_str().is_some_and(str::is_empty))
        {
            return Err(format!("policy {key} required"));
        }
    }
    if object.get("status").and_then(Value::as_str) == Some("verified")
        && object
            .get("evidence")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err("verified policy evidence required".into());
    }
    let mut row = object.clone();
    row.entry("evidence")
        .or_insert_with(|| Value::Array(Vec::new()));
    row.insert("certificationClaim".into(), Value::Bool(false));
    Ok(Value::Object(row))
}

fn valid_instant(now: Option<&str>) -> bool {
    let Some(now) = now else { return false };
    now.parse::<chrono_like::DateTime>().is_ok()
}

// Small RFC3339 ordering helper; this avoids pulling a date/time runtime into
// the audit crate.  It accepts the ISO forms emitted by the legacy provider.
mod chrono_like {
    #[derive(Clone, Copy)]
    pub struct DateTime(pub i64);

    impl std::str::FromStr for DateTime {
        type Err = ();
        fn from_str(value: &str) -> Result<Self, Self::Err> {
            let bytes = value.as_bytes();
            if bytes.len() < 20
                || bytes.get(4) != Some(&b'-')
                || bytes.get(7) != Some(&b'-')
                || bytes.get(10) != Some(&b'T') && bytes.get(10) != Some(&b' ')
            {
                return Err(());
            }
            let year = value[0..4].parse::<i64>().map_err(|_| ())?;
            let month = value[5..7].parse::<i64>().map_err(|_| ())?;
            let day = value[8..10].parse::<i64>().map_err(|_| ())?;
            let hour = value[11..13].parse::<i64>().map_err(|_| ())?;
            let minute = value[14..16].parse::<i64>().map_err(|_| ())?;
            let second = value[17..19].parse::<i64>().map_err(|_| ())?;
            if !(1..=12).contains(&month)
                || !(1..=31).contains(&day)
                || hour > 23
                || minute > 59
                || second > 60
            {
                return Err(());
            }
            Ok(Self(
                (((year * 12 + month) * 31 + day) * 24 + hour) * 3600 + minute * 60 + second,
            ))
        }
    }

    pub fn expired(expires: &str, now: &str) -> bool {
        match (now.parse::<DateTime>(), expires.parse::<DateTime>()) {
            (Ok(now), Ok(expires)) => expires.0 <= now.0,
            _ => true,
        }
    }
}

/// Analyze policy artifacts supplied in adapter input.
pub fn analyze(input: &ProviderInput<'_>) -> Result<serde_json::Value, AuditError> {
    let policies = input
        .artifacts
        .get("policies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut normalized = Vec::new();
    let mut gaps = Vec::new();
    let instant = input.now.filter(|now| valid_instant(Some(*now)));
    for policy in &policies {
        match policy_evidence(policy) {
            Ok(row) => {
                let expires = row
                    .get("expiresAt")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if instant.is_none_or(|now| chrono_like::expired(expires, now)) {
                    gaps.push(json!({"kind":"policy-evidence-invalid","reason":"policy evidence expired or clock absent"}));
                    continue;
                }
                // Evidence authority remains a typed input boundary.  The
                // native adapter validates presence/shape here; host-bound
                // bytes, storage, and tool receipts remain host evidence.
                if row.get("status").and_then(Value::as_str) == Some("verified") {
                    let valid = row
                        .get("evidence")
                        .and_then(Value::as_array)
                        .is_some_and(|refs| {
                            refs.iter().all(|reference| {
                                reference.as_str().is_some_and(|item| !item.is_empty())
                            })
                        });
                    if !valid {
                        gaps.push(json!({"kind":"policy-evidence-invalid","reason":"evidence refs invalid"}));
                        continue;
                    }
                }
                normalized.push(row);
            }
            Err(reason) => gaps.push(json!({"kind":"policy-evidence-invalid","reason":reason})),
        }
    }
    if policies.is_empty() {
        gaps.push(json!({"kind":"policy-denominator-zero"}));
    }
    Ok(json!({
        "status": if gaps.is_empty() { "pass" } else { "unproven" },
        "complete": gaps.is_empty(),
        "denominator": {"kind":"governance-policies", "expected": policies.len(), "examined": normalized.len()},
        "findings": normalized.iter().filter(|row| row.get("status").and_then(Value::as_str) != Some("verified")).cloned().collect::<Vec<_>>(),
        "coverageGaps": gaps,
    }))
}

/// ProviderExecutor-facing entrypoint. Governance is artifact-driven rather
/// than source-file-driven, so its frozen selector denominator is used only as
/// the contract binding and not as policy evidence itself.
pub fn execute(input: &ProviderInput<'_>) -> Result<legion_contracts::ProviderResult, AuditError> {
    let denominator = denominator(input)?;
    let analyzed = analyze(input)?;
    let gaps = analyzed
        .get("coverageGaps")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item.get("kind")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let findings = analyzed
        .get("findings")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .enumerate()
                .map(|(index, row)| {
                    let policy = row
                        .get("policy")
                        .and_then(Value::as_str)
                        .unwrap_or("policy");
                    let id = format!("governance:{policy}:{index}");
                    finding(&id, "warning", "artifacts.policies", index + 1)
                })
                .collect::<Vec<FindingRef>>()
        })
        .unwrap_or_default();
    let mut details = BTreeMap::new();
    details.insert(
        "policyFindings".into(),
        analyzed
            .get("findings")
            .cloned()
            .unwrap_or(Value::Array(Vec::new())),
    );
    details.insert("analysis".into(), analyzed);
    let complete = gaps.is_empty();
    super::common::result(
        input,
        if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        &denominator,
        denominator.entries.len(),
        findings,
        gaps.clone(),
        gaps,
        details,
    )
}
