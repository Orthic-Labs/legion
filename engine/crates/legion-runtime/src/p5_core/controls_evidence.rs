//! Ported from src/lib/controls/evidence/{capabilities,external-manifest,
//! impacts}.mjs (packet P5b-controls-config).
//!
//! `Date.parse`/`Date.now()` handling in the JS source is adapted to
//! pre-parsed `i64` unix-millisecond timestamps: no date-parsing crate is in
//! this crate's dependency set (see report for the suggested Cargo.toml
//! patch), and callers already hold parsed instants before crossing into
//! this pure logic.

use super::controls_support::{same_binding, Value};

/// One host capability receipt, mirroring `host.capabilities[hostKey]`.
#[derive(Debug, Clone, Default)]
pub struct CapabilityReceipt {
    pub active: bool,
    pub receipt_binding: Option<Value>,
    pub artifact_digest: Option<String>,
    pub environment: Option<String>,
    pub limitations: Option<Vec<String>>,
    pub observed_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
    pub receipt_value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityStatus {
    pub id: String,
    pub available: bool,
    pub owner: String,
    pub receipt: Option<Value>,
    pub reason: Option<String>,
}

/// Port of the `MAP` host-key -> capability-id table.
const MAP: &[(&str, &str)] = &[
    ("repository", "repository"),
    ("projectExecution", "build"),
    ("browser", "browser"),
    ("nativeSurface", "desktop"),
    ("virtualMachine", "vm"),
    ("simulator", "simulator-emulator"),
    ("mobileDevice", "physical-device"),
    ("serviceAccess", "service-deployment"),
    ("cloudAccess", "cloud-dns-store-provider"),
    ("operationsAccess", "operations"),
    ("reviewer", "reviewer"),
    ("humanDecision", "human"),
    ("signing", "signing"),
    ("mutation", "mutation"),
    ("externalEvidence", "external-evidence"),
];

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}

fn receipt_valid(receipt: &CapabilityReceipt, now_ms: i64, expected_binding: Option<&Value>) -> bool {
    if expected_binding.is_none() {
        return false;
    }
    let digest_ok = same_binding(receipt.receipt_binding.as_ref(), expected_binding);
    let artifact_ok = receipt
        .artifact_digest
        .as_deref()
        .is_some_and(is_sha256);
    let env_ok = receipt.environment.as_deref().is_some_and(|s| !s.is_empty());
    let limitations_ok = receipt.limitations.is_some();
    let observed_ok = receipt.observed_at_ms.is_some_and(|t| t <= now_ms);
    let expires_ok = receipt.expires_at_ms.is_some_and(|t| t > now_ms);
    digest_ok && artifact_ok && env_ok && limitations_ok && observed_ok && expires_ok
}

/// Port of `evidenceCapabilities(host)`. `now_ms`/`binding` stand in for
/// `host.clock.now()` / `host.binding`.
pub fn evidence_capabilities(
    capabilities: &std::collections::BTreeMap<String, CapabilityReceipt>,
    now_ms: Option<i64>,
    binding: Option<&Value>,
) -> Vec<CapabilityStatus> {
    MAP.iter()
        .map(|(host_key, id)| {
            let value = capabilities.get(*host_key);
            let available = value.is_some_and(|v| {
                v.active
                    && now_ms.is_some_and(|now| receipt_valid(v, now, binding))
            });
            let reason = if available {
                None
            } else if value.is_some_and(|v| v.active) {
                Some("host-capability-receipt-invalid-stale-or-mismatched".to_string())
            } else {
                Some("host-capability-unavailable".to_string())
            };
            CapabilityStatus {
                id: id.to_string(),
                available,
                owner: "host".to_string(),
                receipt: value.and_then(|v| v.receipt_value.clone()),
                reason,
            }
        })
        .collect()
}

/// One record in an external evidence manifest.
#[derive(Debug, Clone, Default)]
pub struct ExternalEvidenceRecord {
    pub claim_levels: Vec<String>,
    pub producer: Option<String>,
    pub scope: Option<String>,
    pub environment: Option<String>,
    pub binding: Option<Value>,
    pub artifact_digest: Option<String>,
    pub observed_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
    pub limitations: Option<Vec<String>>,
}

/// Port of `validateExternalEvidence(manifest, binding, { now })`.
pub fn validate_external_evidence(
    records: &[ExternalEvidenceRecord],
    binding: Option<&Value>,
    now_ms: i64,
) -> Result<(), String> {
    for record in records {
        let mut seen = std::collections::BTreeSet::new();
        for level in &record.claim_levels {
            if !seen.insert(level.clone()) {
                return Err("duplicate claim level".to_string());
            }
        }

        let base_ok = record.producer.is_some()
            && record.scope.is_some()
            && record.environment.is_some()
            && record.binding.is_some()
            && same_binding(record.binding.as_ref(), binding);
        if !base_ok {
            return Err("invalid external evidence record".to_string());
        }

        if !record.claim_levels.is_empty() {
            let digest_ok = record.artifact_digest.as_deref().is_some_and(is_sha256);
            let times_ok = record.observed_at_ms.is_some() && record.expires_at_ms.is_some();
            let limitations_ok = record.limitations.is_some();
            if !digest_ok || !times_ok || !limitations_ok {
                return Err("external evidence requires artifact digest and freshness".to_string());
            }
        }

        if let (Some(observed), Some(expires)) = (record.observed_at_ms, record.expires_at_ms) {
            if expires <= observed {
                return Err("external evidence freshness interval is invalid".to_string());
            }
            if expires <= now_ms {
                return Err("external evidence expired".to_string());
            }
        }
    }
    Ok(())
}

/// A control as seen by `capabilityImpacts`: only the fields it reads.
#[derive(Debug, Clone)]
pub struct BaselineControlRef {
    pub id: String,
    pub target_ids: Vec<String>,
    pub claim_levels: Vec<String>,
    pub evidence: Vec<String>,
    pub missing_evidence_effect: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityImpact {
    pub control_id: String,
    pub target_ids: Vec<String>,
    pub claim_levels: Vec<String>,
    pub evidence: String,
    pub effect: String,
}

/// Port of `capabilityImpacts(baseline, capabilities)`.
pub fn capability_impacts(
    controls: &[BaselineControlRef],
    capabilities: &[CapabilityStatus],
) -> Vec<CapabilityImpact> {
    let available: std::collections::BTreeSet<&str> = capabilities
        .iter()
        .filter(|c| c.available)
        .map(|c| c.id.as_str())
        .collect();

    controls
        .iter()
        .flat_map(|control| {
            control
                .evidence
                .iter()
                .filter(move |item| !item.starts_with("provider:") && !available.contains(item.as_str()))
                .map(move |item| CapabilityImpact {
                    control_id: control.id.clone(),
                    target_ids: control.target_ids.clone(),
                    claim_levels: control.claim_levels.clone(),
                    evidence: item.clone(),
                    effect: control.missing_evidence_effect.clone(),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn unavailable_capability_is_reported_unavailable() {
        let caps = BTreeMap::new();
        let statuses = evidence_capabilities(&caps, Some(1000), Some(&Value::str("b")));
        assert!(statuses.iter().all(|s| !s.available));
        assert_eq!(
            statuses[0].reason.as_deref(),
            Some("host-capability-unavailable")
        );
    }

    #[test]
    fn active_receipt_with_matching_binding_is_available() {
        let binding = Value::str("b1");
        let mut caps = BTreeMap::new();
        caps.insert(
            "repository".to_string(),
            CapabilityReceipt {
                active: true,
                receipt_binding: Some(binding.clone()),
                artifact_digest: Some(format!("sha256:{}", "a".repeat(64))),
                environment: Some("ci".to_string()),
                limitations: Some(vec![]),
                observed_at_ms: Some(500),
                expires_at_ms: Some(1500),
                receipt_value: None,
            },
        );
        let statuses = evidence_capabilities(&caps, Some(1000), Some(&binding));
        let repo = statuses.iter().find(|s| s.id == "repository").unwrap();
        assert!(repo.available);
        assert!(repo.reason.is_none());
    }

    #[test]
    fn active_receipt_with_stale_window_is_invalid() {
        let binding = Value::str("b1");
        let mut caps = BTreeMap::new();
        caps.insert(
            "repository".to_string(),
            CapabilityReceipt {
                active: true,
                receipt_binding: Some(binding.clone()),
                artifact_digest: Some(format!("sha256:{}", "a".repeat(64))),
                environment: Some("ci".to_string()),
                limitations: Some(vec![]),
                observed_at_ms: Some(500),
                expires_at_ms: Some(600), // already expired at now=1000
                receipt_value: None,
            },
        );
        let statuses = evidence_capabilities(&caps, Some(1000), Some(&binding));
        let repo = statuses.iter().find(|s| s.id == "repository").unwrap();
        assert!(!repo.available);
        assert_eq!(
            repo.reason.as_deref(),
            Some("host-capability-receipt-invalid-stale-or-mismatched")
        );
    }

    #[test]
    fn duplicate_claim_level_rejected() {
        let record = ExternalEvidenceRecord {
            claim_levels: vec!["inventory".into(), "inventory".into()],
            producer: Some("p".into()),
            scope: Some("s".into()),
            environment: Some("e".into()),
            binding: Some(Value::str("b")),
            ..Default::default()
        };
        let err = validate_external_evidence(&[record], Some(&Value::str("b")), 0).unwrap_err();
        assert_eq!(err, "duplicate claim level");
    }

    #[test]
    fn expired_record_rejected() {
        let record = ExternalEvidenceRecord {
            claim_levels: vec!["inventory".into()],
            producer: Some("p".into()),
            scope: Some("s".into()),
            environment: Some("e".into()),
            binding: Some(Value::str("b")),
            artifact_digest: Some(format!("sha256:{}", "a".repeat(64))),
            observed_at_ms: Some(0),
            expires_at_ms: Some(100),
            limitations: Some(vec![]),
        };
        let err = validate_external_evidence(&[record], Some(&Value::str("b")), 200).unwrap_err();
        assert_eq!(err, "external evidence expired");
    }

    #[test]
    fn capability_impacts_skips_provider_and_available_evidence() {
        let controls = vec![BaselineControlRef {
            id: "ctl.1".into(),
            target_ids: vec!["t1".into()],
            claim_levels: vec!["inventory".into()],
            evidence: vec!["provider:x".into(), "repository".into(), "browser".into()],
            missing_evidence_effect: "unproven".into(),
        }];
        let capabilities = vec![CapabilityStatus {
            id: "repository".into(),
            available: true,
            owner: "host".into(),
            receipt: None,
            reason: None,
        }];
        let impacts = capability_impacts(&controls, &capabilities);
        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].evidence, "browser");
    }
}
