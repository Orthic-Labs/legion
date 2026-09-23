//! Port of `src/providers/runtime/web/operations/index.mjs`
//! (`verifyOperationsExercise`).
//!
//! Like `infrastructure.rs`, signature verification is behind
//! [`super::infrastructure::SignatureVerifier`]: no Ed25519 dependency is
//! wired into this crate yet, so this file is PORTED-PARTIAL for the same
//! reason (see the wf049 report).

use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

use super::infrastructure::SignatureVerifier;
use super::shared::{
    denominator, exact_binding, finalize, is_canonical_base64, safe_path, same_binding, sanitize_produced_artifact,
    sanitize_sensitive_value, sort_by_id, utc_millis,
};

const OPERATION_IDS: &[&str] = &[
    "alerts", "backlog", "backup", "capacity", "containment", "cost", "dashboards", "health", "incidents", "load",
    "provider", "quota", "region", "restore", "rollback", "rpo", "rto", "slo", "support",
];
const RESULT_STATUSES: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error"];

fn safe_identifier_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$").unwrap())
}

fn valid_artifact(artifact: &Value, binding: &Value) -> bool {
    if !safe_path(&artifact["path"]) {
        return false;
    }
    if !same_binding(binding, artifact.get("binding").unwrap_or(&Value::Null)) {
        return false;
    }
    sanitize_produced_artifact(artifact, &Value::Null).1
}

struct Unwrapped {
    id: Value,
    record: Value,
    producer: Value,
    evidence_digest: Value,
    gaps: Vec<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn unwrap(envelope: &Value, trusted_producers: &[Value], signature_verifier: &dyn SignatureVerifier) -> Unwrapped {
    let mut gaps: Vec<String> = Vec::new();
    let envelope_producer = envelope.get("producer").cloned().unwrap_or(Value::Null);
    let trusted = trusted_producers.iter().find(|item| item.get("id") == Some(&envelope_producer));
    let mut record = envelope.clone();

    let signed_content = envelope.get("signedContent").and_then(Value::as_str);
    let signature = envelope.get("signature").and_then(Value::as_str);

    if trusted.is_none() || signed_content.is_none() || signature.is_none() {
        gaps.push("signature-unproven".to_string());
    } else if !is_canonical_base64(signature.unwrap()) {
        gaps.push("signature-noncanonical".to_string());
    } else {
        let trusted = trusted.unwrap();
        let public_key = trusted.get("publicKey").and_then(Value::as_str).unwrap_or_default();
        let sig_bytes = super::shared::base64_decode(signature.unwrap()).unwrap_or_default();
        let content = signed_content.unwrap();
        if !signature_verifier.verify(public_key, content.as_bytes(), &sig_bytes) {
            gaps.push("signature-invalid".to_string());
        } else {
            match serde_json::from_str::<Value>(content) {
                Ok(parsed) => record = parsed,
                Err(_) => gaps.push("signature-invalid".to_string()),
            }
        }
    }

    if record.get("producer").is_some() && record.get("producer") != Some(&envelope_producer) {
        gaps.push("producer-mismatch".to_string());
    }

    let original_artifacts = record.get("artifacts").cloned();
    let record_binding = record.get("binding").cloned().unwrap_or(Value::Null);
    if let Some(artifacts) = &original_artifacts {
        let ok = artifacts.as_array().map(|items| items.iter().all(|a| valid_artifact(a, &record_binding))).unwrap_or(false);
        if !ok {
            gaps.push("operation-artifact-invalid".to_string());
        }
    }

    let (sanitized_value, sensitive) = sanitize_sensitive_value(&record, &Value::Null);
    let artifact_admissions: Vec<(Option<Value>, bool, bool)> = match &original_artifacts {
        Some(Value::Array(items)) => items.iter().map(|artifact| sanitize_produced_artifact(artifact, &Value::Null)).collect(),
        _ => Vec::new(),
    };
    let sanitized_artifacts: Value = match &original_artifacts {
        Some(Value::Array(_)) => Value::Array(
            artifact_admissions
                .iter()
                .filter(|(artifact, valid, _)| *valid && artifact.is_some())
                .map(|(artifact, _, _)| artifact.clone().unwrap())
                .collect(),
        ),
        other => other.clone().unwrap_or(Value::Null),
    };
    let any_sensitive_artifact = artifact_admissions.iter().any(|(_, _, sensitive)| *sensitive);
    if any_sensitive_artifact {
        gaps.push("operation-artifact-sanitized".to_string());
    }
    if sensitive {
        gaps.push("operation-sensitive-data".to_string());
    }

    let final_record = if sanitized_value.is_object() {
        let mut map = sanitized_value.as_object().cloned().unwrap_or_default();
        if original_artifacts.is_some() {
            map.insert("artifacts".to_string(), sanitized_artifacts);
        }
        Value::Object(map)
    } else {
        sanitized_value
    };

    let evidence_digest = signed_content.map(|c| Value::String(format!("sha256:{}", sha256_hex(c.as_bytes())))).unwrap_or(Value::Null);

    Unwrapped {
        id: final_record.get("id").cloned().unwrap_or_else(|| envelope.get("id").cloned().unwrap_or(Value::Null)),
        record: final_record,
        producer: envelope_producer,
        evidence_digest,
        gaps,
    }
}

pub struct VerifyOperationsExerciseInput<'a> {
    pub binding: Value,
    pub exercises: Vec<Value>,
    pub trusted_producers: Vec<Value>,
    pub now: Option<String>,
    pub max_age_ms: Option<f64>,
    pub signature_verifier: &'a dyn SignatureVerifier,
}

/// Port of `verifyOperationsExercise` in `operations/index.mjs`.
pub fn verify_operations_exercise(input: VerifyOperationsExerciseInput<'_>) -> Value {
    let VerifyOperationsExerciseInput { binding, exercises, trusted_producers, now, max_age_ms, signature_verifier } = input;

    if exercises.iter().any(|item| item.as_object().is_none()) || trusted_producers.iter().any(|item| item.as_object().is_none()) {
        return finalize(
            "legion-web-operations-exercise",
            serde_json::json!({
                "status": "error",
                "terminal": true,
                "binding": binding,
                "denominator": denominator(&[], &[], &[]).to_value(),
                "receipts": [],
                "coverageGaps": ["operations-collections-invalid"],
            }),
        );
    }

    // Mirrors the JS `[...exercises.flatMap(item => [item.id, item.producer].filter(v => v !== undefined)), ...trustedProducers.map(item => item.id)]`.
    let mut identifiers: Vec<Value> = Vec::new();
    for item in &exercises {
        if let Some(id) = item.get("id") {
            identifiers.push(id.clone());
        }
        if let Some(producer) = item.get("producer") {
            identifiers.push(producer.clone());
        }
    }
    for item in &trusted_producers {
        identifiers.push(item.get("id").cloned().unwrap_or(Value::Null));
    }
    let identifiers_valid = identifiers.iter().all(|id| match id.as_str() {
        Some(s) => safe_identifier_re().is_match(s),
        None => false,
    });
    if !identifiers_valid {
        return finalize(
            "legion-web-operations-exercise",
            serde_json::json!({
                "status": "error",
                "terminal": true,
                "binding": binding,
                "denominator": denominator(&[], &[], &[]).to_value(),
                "receipts": [],
                "coverageGaps": ["operations-identifiers-invalid"],
            }),
        );
    }

    let verified: Vec<Unwrapped> = sort_by_id(&exercises).iter().map(|item| unwrap(item, &trusted_producers, signature_verifier)).collect();
    let mut grouped: HashMap<String, Vec<&Unwrapped>> = HashMap::new();
    for item in &verified {
        let id = item.id.as_str().unwrap_or("").to_string();
        grouped.entry(id).or_default().push(item);
    }

    let mut global_gaps: Vec<String> = Vec::new();
    for (id, rows) in &grouped {
        if !OPERATION_IDS.contains(&id.as_str()) {
            global_gaps.push(format!("operation-unplanned:{}", if id.is_empty() { "missing" } else { id }));
        }
        if rows.len() > 1 {
            global_gaps.push(format!("operation-id-duplicate:{id}"));
        }
        if rows.iter().any(|row| row.gaps.contains(&"signature-unproven".to_string())) {
            global_gaps.push(format!("operation-signature-unproven:{id}"));
        }
        if rows.iter().any(|row| row.gaps.contains(&"signature-noncanonical".to_string())) {
            global_gaps.push(format!("operation-signature-noncanonical:{id}"));
        }
        if rows.iter().any(|row| row.gaps.contains(&"signature-invalid".to_string())) {
            global_gaps.push(format!("operation-signature-invalid:{id}"));
        }
    }

    let receipts: Vec<Value> = OPERATION_IDS
        .iter()
        .map(|id| {
            let rows = grouped.get(*id);
            let Some(rows) = rows.filter(|r| !r.is_empty()) else {
                return serde_json::json!({ "id": id, "status": "unproven", "terminal": true, "coverageGaps": ["operation-missing"] });
            };
            let selected = rows[0];
            let item = &selected.record;
            let mut gaps: Vec<String> = selected.gaps.clone();
            if item.get("id").and_then(Value::as_str) != Some(*id) {
                gaps.push("operation-id-mismatch".to_string());
            }
            if item.get("exercised") != Some(&Value::Bool(true)) {
                gaps.push("configured-not-exercised".to_string());
            }
            let status_str = item.get("status").and_then(Value::as_str);
            let status_valid = status_str.map(|s| RESULT_STATUSES.contains(&s)).unwrap_or(false);
            if !status_valid {
                gaps.push(format!("operation-status-invalid:{}", status_str.unwrap_or("missing")));
            }
            if item.get("terminal") != Some(&Value::Bool(true)) {
                gaps.push("operation-nonterminal".to_string());
            }
            if item.get("outcome").and_then(|o| o.get("executed")) != Some(&Value::Bool(true)) {
                gaps.push("operation-outcome-unexecuted".to_string());
            }
            if status_valid && status_str != Some("pass") {
                gaps.push(format!("operation-status-{}", status_str.unwrap_or("")));
            }
            if !same_binding(&binding, item.get("binding").unwrap_or(&Value::Null)) {
                gaps.push("binding-mismatch".to_string());
            }
            for key in [
                "workload", "dataset", "region", "providerLimits", "cost", "assumptions", "alert", "action", "recovery",
                "residualDamage",
            ] {
                if item.get(key).is_none() || item.get(key) == Some(&Value::Null) {
                    gaps.push(format!("missing-{key}"));
                }
            }
            for key in ["alert", "action", "recovery"] {
                if item.get(key) != Some(&Value::Bool(true)) {
                    gaps.push(format!("{key}-not-observed"));
                }
            }
            let residual_present = item.get("residualDamage").and_then(Value::as_array).map(|v| !v.is_empty()).unwrap_or(false);
            if residual_present {
                gaps.push("residual-damage-present".to_string());
            }
            let issued = utc_millis(item.get("issuedAt").and_then(Value::as_str));
            let checked = utc_millis(item.get("checkedAt").and_then(Value::as_str));
            let current = utc_millis(now.as_deref());
            let expires = utc_millis(item.get("expiresAt").and_then(Value::as_str));
            for (key, value) in [("issuedAt", issued), ("checkedAt", checked), ("now", current), ("expiresAt", expires)] {
                if value.is_none() {
                    gaps.push(format!("{key}-timestamp-invalid"));
                }
            }
            if issued.is_none() || checked.is_none() || current.is_none() || expires.is_none() {
                gaps.push("freshness-unbound".to_string());
            }
            let max_age_valid = max_age_ms.map(|v| v.is_finite() && v >= 0.0).unwrap_or(false);
            if !max_age_valid {
                gaps.push("freshness-window-invalid".to_string());
            }
            if let (Some(issued), Some(checked)) = (issued, checked) {
                if issued > checked {
                    gaps.push("issued-after-checked".to_string());
                }
            }
            if let (Some(checked), Some(current)) = (checked, current) {
                if checked > current {
                    gaps.push("checked-in-future".to_string());
                }
            }
            if let (Some(checked), Some(expires)) = (checked, expires) {
                if checked > expires {
                    gaps.push("checked-after-expiry".to_string());
                }
            }
            if let (Some(current), Some(expires)) = (current, expires) {
                if current > expires {
                    gaps.push("evidence-expired".to_string());
                }
            }
            if let (Some(checked), Some(current), Some(max_age_ms)) = (checked, current, max_age_ms) {
                if max_age_valid && (current - checked) as f64 > max_age_ms {
                    gaps.push("evidence-stale".to_string());
                }
            }
            let status = if !status_valid || item.get("terminal") != Some(&Value::Bool(true)) {
                "error".to_string()
            } else if status_str != Some("pass") {
                status_str.unwrap_or("").to_string()
            } else if !gaps.is_empty() {
                "unproven".to_string()
            } else {
                "pass".to_string()
            };
            let mut gaps_sorted = gaps;
            gaps_sorted.sort();
            gaps_sorted.dedup();
            serde_json::json!({
                "id": id,
                "producer": selected.producer,
                "evidenceDigest": selected.evidence_digest,
                "record": item,
                "status": status,
                "terminal": true,
                "coverageGaps": gaps_sorted,
            })
        })
        .collect();

    let counts = denominator(&OPERATION_IDS.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &receipts, &[]);
    let mut gaps: Vec<String> = global_gaps;
    gaps.extend(exact_binding(&binding).gaps.iter().map(|g| format!("binding-missing:{g}")));
    gaps.extend(OPERATION_IDS.iter().filter(|id| !grouped.contains_key(**id)).map(|id| format!("operation-omitted:{id}")));
    for receipt in &receipts {
        let id = receipt.get("id").and_then(Value::as_str).unwrap_or("");
        if let Some(coverage) = receipt.get("coverageGaps").and_then(Value::as_array) {
            for gap in coverage.iter().filter_map(Value::as_str) {
                gaps.push(format!("{id}:{gap}"));
            }
        }
    }
    if exercises.is_empty() {
        gaps.push("operations-denominator-empty".to_string());
    }
    let terminal_statuses: Vec<String> =
        receipts.iter().filter_map(|item| item.get("status").and_then(Value::as_str).map(str::to_string)).collect();
    let status = ["error", "fail", "blocked", "partial", "unproven"]
        .iter()
        .find(|candidate| terminal_statuses.iter().any(|s| s == *candidate))
        .map(|s| s.to_string())
        .unwrap_or_else(|| if !gaps.is_empty() { "unproven".to_string() } else { "pass".to_string() });

    let mut gaps_sorted = gaps;
    gaps_sorted.sort();
    gaps_sorted.dedup();

    finalize(
        "legion-web-operations-exercise",
        serde_json::json!({
            "status": status,
            "terminal": true,
            "claimLevel": "external",
            "suppliedOnly": true,
            "networkAttempted": false,
            "binding": binding,
            "denominator": counts.to_value(),
            "receipts": receipts,
            "coverageGaps": gaps_sorted,
        }),
    )
}
