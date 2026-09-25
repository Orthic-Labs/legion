//! Port of `scripts/normalize-provider-result.mjs`.
//!
//! Validates and normalizes a provider result against the
//! `provider-result-v1` schema. The status enum is `enums::PROVIDER_STATUS`
//! — the same source `generate-schemas.mjs` reads — so the runtime
//! validator and the JSON schema stay in lockstep.

use serde_json::{Map, Value};
use thiserror::Error;

use crate::enums::PROVIDER_STATUS;

const REQUIRED_FIELDS: &[&str] = &["schemaVersion", "provider", "status", "complete"];

/// Fields that, when present, must be arrays (never `null`).
const ARRAY_FIELDS: &[&str] = &[
    "commands",
    "receipts",
    "inventory",
    "candidates",
    "findings",
    "coverageGaps",
    "artifacts",
    "degradation",
    "inputArtifacts",
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("provider result validation: {field}: {detail}")]
pub struct ProviderResultValidationError {
    pub field: String,
    pub detail: String,
}

fn err(field: &str, detail: impl Into<String>) -> ProviderResultValidationError {
    ProviderResultValidationError { field: field.to_string(), detail: detail.into() }
}

/// Faithful port of `validateProviderResult(result)`. Returns `Ok(())` on a
/// valid result, matching the JS function's `return true` (the boolean
/// return carries no information beyond "did not throw").
pub fn validate_provider_result(result: &Value) -> Result<(), ProviderResultValidationError> {
    let obj = result
        .as_object()
        .ok_or_else(|| err("root", "result must be a non-null object"))?;

    for field in REQUIRED_FIELDS {
        match obj.get(*field) {
            None | Some(Value::Null) => return Err(err(field, "required field is missing")),
            _ => {}
        }
    }

    match obj.get("provider") {
        Some(Value::String(s)) if !s.is_empty() => {}
        _ => return Err(err("provider", "must be a non-empty string")),
    }

    let status = obj.get("status").and_then(Value::as_str).unwrap_or_default();
    if !PROVIDER_STATUS.contains(&status) {
        return Err(err(
            "status",
            format!(
                "invalid status {:?}; expected one of {}",
                obj.get("status").cloned().unwrap_or(Value::Null),
                PROVIDER_STATUS.join(", ")
            ),
        ));
    }

    match obj.get("complete") {
        Some(Value::Bool(_)) => {}
        _ => return Err(err("complete", "must be a boolean")),
    }

    if obj.get("schemaVersion") != Some(&Value::from(1)) {
        return Err(err(
            "schemaVersion",
            format!(
                "expected 1, got {}",
                obj.get("schemaVersion").cloned().unwrap_or(Value::Null)
            ),
        ));
    }

    for field in ARRAY_FIELDS {
        match obj.get(*field) {
            Some(Value::Null) => return Err(err(field, "must be an array, never null")),
            Some(v) if !v.is_array() => return Err(err(field, "must be an array when present")),
            _ => {}
        }
    }

    if let Some(Value::Array(artifacts)) = obj.get("artifacts") {
        for artifact in artifacts {
            let a = artifact.as_object();
            let ok = a
                .map(|m| m.contains_key("kind") && m.contains_key("path") && m.contains_key("digest"))
                .unwrap_or(false)
                && !matches!(artifact.get("kind"), Some(Value::Null) | None)
                && !matches!(artifact.get("path"), Some(Value::Null) | None)
                && !matches!(artifact.get("digest"), Some(Value::Null) | None);
            if !ok {
                return Err(err("artifacts", "each artifact requires kind, path, and digest"));
            }
            let digest_ok = artifact
                .get("digest")
                .and_then(Value::as_str)
                .map(|d| d.starts_with("sha256:"))
                .unwrap_or(false);
            if !digest_ok {
                return Err(err("artifacts.digest", "must be a sha256: prefixed string"));
            }
        }
    }

    Ok(())
}

fn get_or<'a>(obj: &'a Value, key: &str, default: &'a Value) -> &'a Value {
    obj.get(key).filter(|v| !v.is_null()).unwrap_or(default)
}

/// Faithful port of `normalizeProviderResult(planContract, rawOutput)`.
pub fn normalize_provider_result(
    plan_contract: &Value,
    raw_output: &Value,
) -> Result<Value, ProviderResultValidationError> {
    let unbound = Value::from("sha256:unbound");
    let empty = Value::Array(vec![]);
    let empty_obj = Value::Object(Map::new());

    let provider = plan_contract
        .get("id")
        .filter(|v| !v.is_null())
        .or_else(|| raw_output.get("provider").filter(|v| !v.is_null()))
        .cloned()
        .unwrap_or_else(|| Value::from("unknown"));

    let applicable = get_or(raw_output, "applicable", &Value::Bool(true)).clone();
    let required = plan_contract
        .get("benchmark")
        .and_then(|b| b.get("requiredForCleanClaim"))
        .filter(|v| !v.is_null())
        .cloned()
        .unwrap_or(Value::Bool(false));
    let status = get_or(raw_output, "status", &Value::from("unproven")).clone();
    let complete = get_or(raw_output, "complete", &Value::Bool(false)).clone();

    let raw_coverage = raw_output.get("coverage").and_then(Value::as_object).cloned().unwrap_or_default();
    let denominator_digest = raw_coverage
        .get("denominatorDigest")
        .filter(|v| !v.is_null())
        .cloned()
        .or_else(|| {
            plan_contract
                .get("denominator")
                .and_then(|d| d.get("pathDigest"))
                .filter(|v| !v.is_null())
                .cloned()
        })
        .unwrap_or(unbound);
    let mut coverage = raw_coverage;
    coverage.insert("denominatorDigest".into(), denominator_digest);

    let mut normalized = Map::new();
    normalized.insert("schemaVersion".into(), Value::from(1));
    normalized.insert("provider".into(), provider);
    normalized.insert("applicable".into(), applicable);
    normalized.insert("required".into(), required);
    normalized.insert("status".into(), status);
    normalized.insert("complete".into(), complete);
    normalized.insert("coverage".into(), Value::Object(coverage));
    normalized.insert("commands".into(), get_or(raw_output, "commands", &empty).clone());
    normalized.insert("receipts".into(), get_or(raw_output, "receipts", &empty).clone());
    normalized.insert("inventory".into(), get_or(raw_output, "inventory", &empty).clone());
    normalized.insert("candidates".into(), get_or(raw_output, "candidates", &empty).clone());
    normalized.insert("findings".into(), get_or(raw_output, "findings", &empty).clone());
    normalized.insert("coverageGaps".into(), get_or(raw_output, "coverageGaps", &empty).clone());
    normalized.insert("artifacts".into(), get_or(raw_output, "artifacts", &empty).clone());
    normalized.insert("degradation".into(), get_or(raw_output, "degradation", &empty).clone());
    let _ = &empty_obj; // reserved: matches JS's implicit object-shaped defaults path

    let value = Value::Object(normalized);
    validate_provider_result(&value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_binds_digest_and_required_from_contract() {
        let result = normalize_provider_result(
            &json!({"id": "test.provider", "denominator": {"pathDigest": "sha256:test"}, "benchmark": {"requiredForCleanClaim": true}}),
            &json!({"status": "pass", "complete": true, "findings": []}),
        )
        .unwrap();
        assert_eq!(result["provider"], "test.provider");
        assert_eq!(result["status"], "pass");
        assert_eq!(result["coverage"]["denominatorDigest"], "sha256:test");
        assert_eq!(result["required"], true);
        assert!(result["degradation"].is_array());
    }

    #[test]
    fn validate_rejects_invalid_status() {
        let e = validate_provider_result(&json!({
            "schemaVersion": 1, "provider": "x", "status": "invalid-status", "complete": true
        }))
        .unwrap_err();
        assert_eq!(e.field, "status");
    }

    #[test]
    fn validate_rejects_null_array_field() {
        let e = validate_provider_result(&json!({
            "schemaVersion": 1, "provider": "x", "status": "pass", "complete": true, "findings": null
        }))
        .unwrap_err();
        assert_eq!(e.field, "findings");
    }
}
