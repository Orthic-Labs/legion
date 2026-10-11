//! Retained items of the visual port: `validate_judgment_receipt` (no
//! production caller) with its helpers. Other visual providers reachable only
//! from deleted tests were removed in the native-provider sweep.
use super::visual_core::sha256_digest;

use serde_json::{Map, Value};

fn arr<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|n| n != 0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(_)) => true,
    }
}

fn digest_value(value: &Value) -> String {
    sha256_digest(serde_json::to_string(value).unwrap_or_default().as_bytes())
}

pub fn validate_judgment_receipt(packet: &Value, input: &Value) -> Value {
    let reviewer = input
        .get("reviewer")
        .cloned()
        .unwrap_or(Value::Object(Map::new()));
    let renderer_identity = input
        .get("rendererIdentity")
        .cloned()
        .unwrap_or(Value::Null);
    let implementer_identity = input
        .get("implementerIdentity")
        .cloned()
        .unwrap_or(Value::Null);
    let independent = reviewer.get("fresh") == Some(&Value::Bool(true))
        && truthy(reviewer.get("provider"))
        && reviewer.get("provider") != Some(&renderer_identity)
        && reviewer.get("provider") != Some(&implementer_identity)
        && truthy(reviewer.get("contextId"));
    let evidence_refs: Vec<Value> = arr(input, "evidenceRefs").into_iter().cloned().collect();
    let screenshots: Vec<Value> = arr(packet, "screenshots").into_iter().cloned().collect();
    let packet_digest = packet.get("digest").cloned().unwrap_or(Value::Null);
    let evidence_valid = evidence_refs
        .iter()
        .all(|reference| screenshots.contains(reference) || *reference == packet_digest);
    let uncertainty = input.get("uncertainty").and_then(Value::as_array).cloned();
    let valid = independent
        && evidence_valid
        && truthy(input.get("counterargument"))
        && uncertainty.is_some();
    let claim_limits: Vec<Value> = if truthy(packet.get("designContext")) {
        vec![]
    } else {
        vec![Value::String("brand-context-missing".into())]
    };
    let mut receipt = serde_json::json!({
        "schemaVersion": 1, "kind": "legion-judgment-receipt", "family": "visual",
        "subjectId": packet.get("surfaceId").cloned().unwrap_or(Value::Null),
        "candidateId": packet_digest,
        "reviewer": reviewer,
        "evidenceRefs": evidence_refs,
        "omittedEvidence": packet.get("omittedEvidence").cloned().unwrap_or(Value::Array(vec![])),
        "verdict": input.get("verdict").and_then(Value::as_str).unwrap_or("UNPROVEN"),
        "rationaleClaims": input.get("rationaleClaims").cloned().unwrap_or(Value::Array(vec![])),
        "counterargument": input.get("counterargument").cloned().unwrap_or(Value::Null),
        "uncertainty": uncertainty.clone().unwrap_or_default(),
        "claimLimits": claim_limits,
        "policyEffect": input.get("policyEffect").and_then(Value::as_str).unwrap_or("advisory"),
        "binding": input.get("binding").cloned().unwrap_or(Value::Object(Map::new())),
    });
    let digest = digest_value(&receipt);
    receipt
        .as_object_mut()
        .unwrap()
        .insert("digest".into(), Value::String(digest));
    let mut errors: Vec<Value> = Vec::new();
    if !independent {
        errors.push(Value::String("reviewer-not-independent-or-fresh".into()));
    }
    if !evidence_valid {
        errors.push(Value::String("evidence-reference-invalid".into()));
    }
    if !truthy(input.get("counterargument")) {
        errors.push(Value::String("counterargument-missing".into()));
    }
    serde_json::json!({ "valid": valid, "errors": errors, "receipt": receipt })
}
