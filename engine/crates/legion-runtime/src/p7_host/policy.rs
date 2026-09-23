//! Port of src/lib/policy/{accepted-risk,baseline,compliance,lineage,
//! org/index}.mjs.

use super::sha256_prefixed;
use serde_json::{json, Value};

// ---- accepted-risk.mjs ----

#[allow(clippy::too_many_arguments)]
pub fn accepted_risk(
    subject_kind: &str,
    subject_id: &str,
    accepted_by: &str,
    reason: &str,
    accepted_at: &str,
    expires_at: Option<&str>,
    binding_digest: Option<&str>,
) -> Value {
    let body = json!({
        "schemaVersion": 1,
        "kind": "legion-accepted-risk",
        "subjectKind": subject_kind,
        "subjectId": subject_id,
        "acceptedBy": accepted_by,
        "reason": reason,
        "acceptedAt": accepted_at,
        "expiresAt": expires_at,
        "bindingDigest": binding_digest,
    });
    let id = sha256_prefixed("accepted-risk", &body);
    let mut out = body;
    out["id"] = json!(id);
    out
}

pub fn is_expired(record: &Value, now: &str) -> bool {
    let Some(expires_at) = record.get("expiresAt").and_then(Value::as_str) else {
        return false;
    };
    expires_at <= now // ISO-8601 strings compare lexicographically like Date comparison for same format
}

pub fn applies_to(record: &Value, subject_kind: &str, subject_id: &str) -> bool {
    record.get("subjectKind").and_then(Value::as_str) == Some(subject_kind)
        && record.get("subjectId").and_then(Value::as_str) == Some(subject_id)
}

pub struct RiskEvaluation {
    pub active: bool,
    pub open: Vec<Value>,
    pub expired: Vec<Value>,
    pub binding_mismatch: Vec<Value>,
}

pub fn evaluate_risk(
    records: &[Value],
    subject_kind: &str,
    subject_id: &str,
    current_binding_digest: Option<&str>,
    now: &str,
) -> RiskEvaluation {
    let applicable: Vec<&Value> = records
        .iter()
        .filter(|r| applies_to(r, subject_kind, subject_id))
        .collect();
    let active: Vec<&Value> = applicable.iter().filter(|r| !is_expired(r, now)).copied().collect();
    let expired: Vec<Value> = applicable.iter().filter(|r| is_expired(r, now)).map(|r| (*r).clone()).collect();
    let binding_mismatch: Vec<&Value> = applicable
        .iter()
        .filter(|r| {
            r.get("bindingDigest")
                .and_then(Value::as_str)
                .is_some_and(|d| Some(d) != current_binding_digest)
        })
        .copied()
        .collect();
    let open: Vec<Value> = active
        .iter()
        .filter(|r: &&&Value| !binding_mismatch.iter().any(|m: &&Value| **m == ***r))
        .map(|r| (**r).clone())
        .collect();
    RiskEvaluation {
        active: !open.is_empty(),
        open,
        expired,
        binding_mismatch: binding_mismatch.into_iter().cloned().collect(),
    }
}

// ---- baseline.mjs ----

pub fn baseline_record(id: &str, revision: &Value, findings: &[Value], created_at: &str) -> Value {
    let mut finding_ids: Vec<String> = findings
        .iter()
        .filter_map(|f| f.get("id").and_then(Value::as_str).map(String::from))
        .collect();
    finding_ids.sort();
    let mut fingerprints: Vec<String> = findings
        .iter()
        .map(|f| {
            f.get("fingerprint")
                .and_then(Value::as_str)
                .or_else(|| f.get("id").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    fingerprints.sort();
    let mut retained: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id": f.get("id").cloned().unwrap_or(Value::Null),
                "fingerprint": f.get("fingerprint").or_else(|| f.get("id")).cloned().unwrap_or(Value::Null),
                "severity": f.get("severity").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    retained.sort_by(|a, b| {
        a["fingerprint"].as_str().unwrap_or("").cmp(b["fingerprint"].as_str().unwrap_or(""))
    });
    json!({
        "schemaVersion": 1,
        "kind": "legion-baseline",
        "id": id,
        "revision": revision,
        "findingIds": finding_ids,
        "findingFingerprints": fingerprints,
        "findings": retained,
        "createdAt": created_at,
    })
}

pub fn classify_finding(in_baseline: bool, in_current: bool) -> &'static str {
    match (in_baseline, in_current) {
        (false, true) => "new",
        (true, false) => "resolved",
        (true, true) => "unchanged",
        (false, false) => "reopened",
    }
}

pub fn finding_fingerprint(finding: &Value) -> String {
    let file = finding
        .get("file")
        .and_then(Value::as_str)
        .map(|f| f.replace('\\', "/"));
    let root_cause = finding
        .get("rootCauseDigest")
        .or_else(|| finding.get("rootCauseSignature"))
        .cloned()
        .unwrap_or(Value::Null);
    let body = json!({
        "ruleId": finding.get("ruleId").cloned().unwrap_or(Value::Null),
        "file": file,
        "rootCause": root_cause,
    });
    sha256_prefixed("finding", &body)
}

// ---- compliance.mjs ----

pub fn map_evidence_to_controls(report: &Value, controls: &[Value]) -> Vec<Value> {
    let empty = Vec::new();
    let findings = report.get("findings").and_then(Value::as_array).unwrap_or(&empty);
    let coverage_gaps = report.get("coverage_gaps").and_then(Value::as_array).unwrap_or(&empty);
    controls
        .iter()
        .map(|control| {
            let evidence_kinds: Vec<&str> = control
                .get("evidenceKinds")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let supporting: Vec<&Value> = findings
                .iter()
                .filter(|finding| {
                    let rule = finding.get("ruleId").and_then(Value::as_str).unwrap_or("").to_lowercase();
                    evidence_kinds.iter().any(|kind| {
                        let keyword = kind.trim_start_matches("control.").split('-').next().unwrap_or("").to_lowercase();
                        rule.contains(&keyword)
                    })
                })
                .collect();
            let unproven = evidence_kinds.iter().any(|kind| {
                let keyword = kind.trim_start_matches("control.").split('-').next().unwrap_or("").to_lowercase();
                coverage_gaps.iter().any(|gap| {
                    serde_json::to_string(gap).unwrap_or_default().to_lowercase().contains(&keyword)
                })
            });
            let mut ids: Vec<Value> = supporting
                .iter()
                .filter_map(|f| f.get("id").cloned())
                .collect();
            ids.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
            json!({
                "controlId": control.get("id").cloned().unwrap_or(Value::Null),
                "status": if !supporting.is_empty() { "supported" } else if unproven { "unproven" } else { "not-applicable" },
                "supportingFindingIds": ids,
                "absenceIsEvidence": false,
            })
        })
        .collect()
}

// ---- lineage.mjs ----

pub const LINEAGE_STATES: [&str; 7] = [
    "new", "unchanged", "resolved", "reopened", "accepted", "expired", "superseded",
];

#[derive(Debug, Clone, Default)]
pub struct LineageInput {
    pub in_baseline: bool,
    pub in_current: bool,
    pub previously_resolved: bool,
    pub superseded_by: Option<String>,
    pub accepted_risk_active: bool,
    pub accepted_risk_expired: bool,
    pub higher_impact_than_accepted: bool,
}

pub fn classify_lineage(input: &LineageInput) -> &'static str {
    if input.superseded_by.is_some() {
        return "superseded";
    }
    if !input.in_current {
        return if input.in_baseline { "resolved" } else { "new" };
    }
    if !input.in_baseline {
        return "new";
    }
    if input.higher_impact_than_accepted {
        return "reopened";
    }
    if input.accepted_risk_active {
        return "accepted";
    }
    if input.accepted_risk_expired {
        return "expired";
    }
    if input.previously_resolved {
        return "reopened";
    }
    "unchanged"
}

// ---- org/index.mjs ----

pub fn organization_policy(
    id: &str,
    version: &Value,
    digest: &Value,
    signature: &Value,
    rollout: &str,
    required_providers: &[String],
    thresholds: &Value,
    suppression_policy: &Value,
    compliance_mappings: &[String],
) -> Value {
    let mut providers = required_providers.to_vec();
    providers.sort();
    let mut mappings = compliance_mappings.to_vec();
    mappings.sort();
    json!({
        "schemaVersion": 1,
        "kind": "legion-organization-policy",
        "id": id,
        "version": version,
        "digest": digest,
        "signature": signature,
        "rollout": rollout,
        "requiredProviders": providers,
        "thresholds": thresholds,
        "suppressionPolicy": suppression_policy,
        "complianceMappings": mappings,
    })
}

pub fn apply_policy(policy: &Value, plan: &Value, host_policy: &Value) -> Value {
    let empty = Vec::new();
    let required: Vec<&str> = policy
        .get("requiredProviders")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let rollout = policy.get("rollout").and_then(Value::as_str).unwrap_or("advisory");
    let denominator_providers: Vec<&str> = plan
        .get("denominator")
        .and_then(|d| d.get("providerIds"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let disabled: Vec<&str> = host_policy
        .get("disabledProviders")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or(empty.iter().filter_map(|_: &Value| None).collect());

    let mut violations = Vec::new();
    if rollout == "blocking" {
        for provider in &required {
            if !denominator_providers.contains(provider) {
                violations.push(json!({"kind": "missing-required-provider", "provider": provider}));
            }
        }
    }
    for provider in &required {
        if disabled.contains(provider) {
            violations.push(json!({"kind": "host-bounded-provider", "provider": provider}));
        }
    }
    let blocked = rollout == "blocking"
        && violations
            .iter()
            .any(|v| v.get("kind").and_then(Value::as_str) == Some("missing-required-provider"));
    json!({
        "schemaVersion": 1,
        "kind": "legion-org-policy-application",
        "policyId": policy.get("id").cloned().unwrap_or(Value::Null),
        "rollout": rollout,
        "violations": violations,
        "blocked": blocked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_risk_is_expired_uses_lexicographic_iso_compare() {
        let record = json!({"expiresAt": "2026-01-01T00:00:00.000Z"});
        assert!(is_expired(&record, "2026-06-01T00:00:00.000Z"));
        assert!(!is_expired(&record, "2025-06-01T00:00:00.000Z"));
    }

    #[test]
    fn evaluate_risk_separates_open_expired_and_mismatched() {
        let records = vec![
            json!({"subjectKind": "finding", "subjectId": "f1", "expiresAt": "2099-01-01", "bindingDigest": "b1"}),
            json!({"subjectKind": "finding", "subjectId": "f1", "expiresAt": "2000-01-01", "bindingDigest": "b1"}),
            json!({"subjectKind": "finding", "subjectId": "f1", "expiresAt": "2099-01-01", "bindingDigest": "different"}),
        ];
        let result = evaluate_risk(&records, "finding", "f1", Some("b1"), "2026-01-01");
        assert_eq!(result.open.len(), 1);
        assert_eq!(result.expired.len(), 1);
        assert_eq!(result.binding_mismatch.len(), 1);
        assert!(result.active);
    }

    #[test]
    fn baseline_record_sorts_ids_and_fingerprints() {
        let findings = vec![json!({"id": "b", "fingerprint": "fb"}), json!({"id": "a", "fingerprint": "fa"})];
        let record = baseline_record("base1", &json!("r1"), &findings, "2026-01-01");
        assert_eq!(record["findingIds"], json!(["a", "b"]));
        assert_eq!(record["findingFingerprints"], json!(["fa", "fb"]));
    }

    #[test]
    fn classify_finding_matches_four_states() {
        assert_eq!(classify_finding(false, true), "new");
        assert_eq!(classify_finding(true, false), "resolved");
        assert_eq!(classify_finding(true, true), "unchanged");
        assert_eq!(classify_finding(false, false), "reopened");
    }

    #[test]
    fn compliance_mapping_marks_supported_and_not_applicable() {
        let report = json!({"findings": [{"id": "f1", "ruleId": "SQLI-001"}], "coverage_gaps": []});
        let controls = vec![
            json!({"id": "c1", "evidenceKinds": ["control.sqli-injection"]}),
            json!({"id": "c2", "evidenceKinds": ["control.xss-reflected"]}),
        ];
        let mapped = map_evidence_to_controls(&report, &controls);
        assert_eq!(mapped[0]["status"], "supported");
        assert_eq!(mapped[1]["status"], "not-applicable");
        assert_eq!(mapped[0]["absenceIsEvidence"], false);
    }

    #[test]
    fn classify_lineage_prioritizes_supersession_then_reopen() {
        let mut input = LineageInput { in_baseline: true, in_current: true, higher_impact_than_accepted: true, accepted_risk_active: true, ..Default::default() };
        assert_eq!(classify_lineage(&input), "reopened");
        input.higher_impact_than_accepted = false;
        assert_eq!(classify_lineage(&input), "accepted");
        input.superseded_by = Some("other".into());
        assert_eq!(classify_lineage(&input), "superseded");
    }

    #[test]
    fn apply_policy_blocks_on_missing_required_provider_under_blocking_rollout() {
        let policy = json!({"id": "p1", "rollout": "blocking", "requiredProviders": ["semgrep"]});
        let plan = json!({"denominator": {"providerIds": ["eslint"]}});
        let result = apply_policy(&policy, &plan, &json!({}));
        assert_eq!(result["blocked"], true);
    }

    #[test]
    fn apply_policy_flags_host_bounded_provider() {
        let policy = json!({"id": "p1", "rollout": "advisory", "requiredProviders": ["semgrep"]});
        let plan = json!({"denominator": {"providerIds": ["semgrep"]}});
        let host_policy = json!({"disabledProviders": ["semgrep"]});
        let result = apply_policy(&policy, &plan, &host_policy);
        assert_eq!(result["violations"].as_array().unwrap().len(), 1);
        assert_eq!(result["blocked"], false);
    }
}
