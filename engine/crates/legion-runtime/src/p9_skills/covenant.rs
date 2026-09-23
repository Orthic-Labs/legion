//! Packet P9-skill-scripts: Rust port of `skills/covenant/lib/contracts.mjs` (the deterministic
//! half of the Covenant packet engine: canonical digesting and the field-level validation rules
//! that do not require loading the JSON Schema files).
//!
//! `skills/covenant/lib/flows.mjs` (`runSeats`, `executeDecisionChallenge`,
//! `executeBlockerConsult`, `executePacketOnly`) orchestrates async calls out to independent LLM
//! seat providers via caller-supplied runner callbacks; that provider-IO orchestration is not
//! ported here (see the packet report). The pure, deterministic pieces of `flows.mjs` that do
//! not require provider IO — the contract-boundary constant list and disagreement/outcome
//! aggregation for a decision challenge — are ported as `CONTRACT_BOUNDARIES` and
//! `aggregate_decision_verdict`.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// `CONTRACT_BOUNDARIES` from flows.mjs.
pub const CONTRACT_BOUNDARIES: &[&str] = &[
    "changesSealedDecision",
    "changesLockedInvariant",
    "changesAcceptance",
    "expandsScope",
    "addsMaterialDependency",
    "changesPublicBehavior",
    "altersSecurity",
    "exceedsEffectClass",
];

const FORBIDDEN_AUTHORITY_TOKENS: &[&str] = &["DECISION_SEALED", "CONTROL_PASS"];

/// Canonical JSON serialization used for digesting: object keys sorted, arrays preserved
/// in order, matching `contracts.mjs`'s `canonical()`.
pub fn canonical(value: &Value) -> String {
    match value {
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: BTreeSet<&String> = BTreeSet::new();
            for k in map.keys() {
                keys.insert(k);
            }
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(&map[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".to_string()),
    }
}

/// `digestValue()`: `sha256:<hex>` over the canonical serialization.
pub fn digest_value(value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical(value).as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Mirrors `findForbiddenToken`: recursively scans strings for the forbidden authority tokens.
pub fn find_forbidden_token(value: &Value) -> Option<&'static str> {
    match value {
        Value::String(s) => FORBIDDEN_AUTHORITY_TOKENS
            .iter()
            .find(|t| s.contains(**t))
            .copied(),
        Value::Array(items) => items.iter().find_map(find_forbidden_token),
        Value::Object(map) => map.values().find_map(find_forbidden_token),
        _ => None,
    }
}

/// The mode -> allowed outcome sets from `REQUEST_OUTCOMES`.
pub fn allowed_outcomes(mode: &str) -> Option<&'static [&'static str]> {
    match mode {
        "DECISION_CHALLENGE" => Some(&["SUPPORTED", "REVISE", "UNRESOLVED"]),
        "BLOCKER_CONSULT" => Some(&["CONTRACT_SAFE", "AMENDMENT_REQUIRED", "INSUFFICIENT_EVIDENCE"]),
        "DISPUTE_REVIEW" => Some(&["SUPPORTED", "REVISE", "UNRESOLVED"]),
        _ => None,
    }
}

/// `aggregateDecisionVerdict`: aggregates fresh-verdict seat positions into one outcome.
pub fn aggregate_decision_verdict<I, S>(positions: I) -> &'static str
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let upper: Vec<String> = positions
        .into_iter()
        .map(|p| p.as_ref().to_ascii_uppercase())
        .collect();
    if upper
        .iter()
        .any(|p| p.contains("PROVIDER_FAILURE") || p.contains("UNRESOLVED"))
    {
        "UNRESOLVED"
    } else if upper
        .iter()
        .any(|p| p.contains("REVISE") || p.contains("MUTATION_DETECTED"))
    {
        "REVISE"
    } else {
        "SUPPORTED"
    }
}

/// Field-level validation from `validateCovenantRecord`, minus the generic JSON-Schema structural
/// pass (which lives in the schema files under `skills/covenant/schemas/*.json` and is not
/// re-implemented here — see the packet report).
pub fn validate_record_fields(record: &Value, request: Option<&Value>) -> Vec<String> {
    let mut errors = Vec::new();
    // A plain fn (rather than a closure) so the borrow's lifetime is tied to
    // each call site's argument, not fixed to one inferred signature.
    fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
        v.get(k)
    }

    let mode = record.get("mode").and_then(Value::as_str).unwrap_or("");
    if mode == "PACKET_ONLY" {
        errors.push("$.mode PACKET_ONLY cannot produce a CovenantRecord".to_string());
    }

    if let Some(request) = request {
        if get(record, "requestId") != get(request, "requestId") {
            errors.push("$.requestId does not match request".to_string());
        }
        if get(record, "mode") != get(request, "mode") {
            errors.push("$.mode does not match request".to_string());
        }
        if get(record, "packetDigest") != get(request, "packetDigest") {
            errors.push("$.packetDigest does not match request".to_string());
        }
        if get(record, "sourceRevision") != get(request, "sourceRevision") {
            errors.push("$.sourceRevision does not match request".to_string());
        }
    }

    if let Some(allowed) = allowed_outcomes(mode) {
        let outcome = record.get("outcome").and_then(Value::as_str).unwrap_or("");
        if !allowed.contains(&outcome) {
            errors.push(format!("$.outcome is invalid for {mode}"));
        }
    }

    if let Some(token) = find_forbidden_token(record) {
        errors.push(format!("$ contains forbidden authority token {token}"));
    }

    let digest_verified = record
        .pointer("/integrity/digestVerified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !digest_verified {
        errors.push("$.integrity.digestVerified must be true".to_string());
    }
    let mutation_detected = record
        .pointer("/integrity/mutationDetected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if mutation_detected {
        errors.push("$.integrity.mutationDetected invalidates review".to_string());
    }

    if let Some(seats) = record.get("seatRecords").and_then(Value::as_array) {
        if seats
            .iter()
            .any(|s| s.get("isolated").and_then(Value::as_bool) != Some(true))
        {
            errors.push("$.seatRecords must all be isolated".to_string());
        }
    }

    if mode == "DECISION_CHALLENGE" {
        validate_dispositions(record, &mut errors);
    }

    errors
}

fn validate_dispositions(record: &Value, errors: &mut Vec<String>) {
    let empty = Vec::new();
    let dispositions = record
        .get("callerDispositions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let findings = record.get("findings").and_then(Value::as_array).unwrap_or(&empty);
    for finding in findings {
        let finding_id = finding.get("findingId").and_then(Value::as_str).unwrap_or("");
        let item = dispositions
            .iter()
            .find(|d| d.get("findingId").and_then(Value::as_str) == Some(finding_id));
        let Some(item) = item else {
            errors.push(format!(
                "$.callerDispositions missing terminal disposition for {finding_id}"
            ));
            continue;
        };
        let disposition = item.get("disposition").and_then(Value::as_str).unwrap_or("");
        if disposition == "REJECT" {
            let rationale = item.get("rationale").and_then(Value::as_str).unwrap_or("").trim();
            if rationale.is_empty() {
                errors.push(format!(
                    "$.callerDispositions {finding_id} REJECT requires rationale"
                ));
            }
        }
        if disposition == "DEFER_TO_PHASE" {
            let owning_phase = item.get("owningPhase").and_then(Value::as_str).unwrap_or("").trim();
            if owning_phase.is_empty() {
                errors.push(format!(
                    "$.callerDispositions {finding_id} DEFER_TO_PHASE requires owningPhase"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_object_keys_and_preserves_arrays() {
        let a = json!({"b": 1, "a": [3, 2, 1]});
        assert_eq!(canonical(&a), r#"{"a":[3,2,1],"b":1}"#);
    }

    #[test]
    fn digest_is_stable_regardless_of_key_order() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(digest_value(&a), digest_value(&b));
        assert!(digest_value(&a).starts_with("sha256:"));
    }

    #[test]
    fn finds_forbidden_token_nested() {
        let v = json!({"nested": {"x": ["ok", "contains DECISION_SEALED here"]}});
        assert_eq!(find_forbidden_token(&v), Some("DECISION_SEALED"));
        let clean = json!({"nested": {"x": ["ok", "fine"]}});
        assert_eq!(find_forbidden_token(&clean), None);
    }

    #[test]
    fn aggregate_decision_verdict_prioritizes_unresolved_then_revise() {
        assert_eq!(aggregate_decision_verdict(["SUPPORTED", "PROVIDER_FAILURE: x"]), "UNRESOLVED");
        assert_eq!(aggregate_decision_verdict(["SUPPORTED", "REVISE"]), "REVISE");
        assert_eq!(aggregate_decision_verdict(["SUPPORTED", "SUPPORTED"]), "SUPPORTED");
    }

    #[test]
    fn validate_record_fields_catches_mismatched_request_and_bad_outcome() {
        let request = json!({"requestId": "R1", "mode": "BLOCKER_CONSULT", "packetDigest": "d", "sourceRevision": "r"});
        let record = json!({
            "requestId": "R2",
            "mode": "BLOCKER_CONSULT",
            "packetDigest": "d",
            "sourceRevision": "r",
            "outcome": "NOT_A_REAL_OUTCOME",
            "integrity": {"digestVerified": true, "mutationDetected": false},
            "seatRecords": [{"isolated": true}],
        });
        let errors = validate_record_fields(&record, Some(&request));
        assert!(errors.iter().any(|e| e.contains("requestId does not match")));
        assert!(errors.iter().any(|e| e.contains("outcome is invalid")));
    }

    #[test]
    fn validate_record_fields_requires_digest_verified_true() {
        let record = json!({
            "mode": "BLOCKER_CONSULT",
            "outcome": "CONTRACT_SAFE",
            "integrity": {"digestVerified": false},
        });
        let errors = validate_record_fields(&record, None);
        assert!(errors.iter().any(|e| e.contains("digestVerified must be true")));
    }

    #[test]
    fn decision_challenge_requires_terminal_dispositions() {
        let record = json!({
            "mode": "DECISION_CHALLENGE",
            "outcome": "REVISE",
            "integrity": {"digestVerified": true, "mutationDetected": false},
            "findings": [{"findingId": "F1"}],
            "callerDispositions": [],
        });
        let errors = validate_record_fields(&record, None);
        assert!(errors.iter().any(|e| e.contains("missing terminal disposition for F1")));
    }
}
