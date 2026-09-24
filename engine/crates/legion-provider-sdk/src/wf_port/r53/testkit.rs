//! Port of `src/lib/providers/sdk/testkit.mjs` plus the two symbols it
//! re-exports from `scripts/normalize-provider-result.mjs`
//! (`validateProviderResult`, `normalizeProviderResult`) — that script has
//! no other Rust-port owner and `index.mjs`/`testkit.mjs` is its only
//! reachable public export surface, so it is ported here rather than left
//! stranded.

use serde_json::{Map, Value};

use super::canonical::canonical_json;
use super::contracts::PROVIDER_STATUS;

/// Port of `stableId(namespace, value)`. Note the JS body is
/// `JSON.stringify(canonicalJson(value))` — a *double* JSON encoding
/// (`canonicalJson` already returns a JSON string; JS then re-stringifies
/// that string, quoting and escaping it) — reproduced exactly, not
/// simplified to a single encoding.
pub fn stable_id(namespace: &str, value: &Value) -> String {
    let inner = canonical_json(value);
    let body = serde_json::to_string(&inner).expect("string always serializes");
    super::canonical::sha256_str(&format!("{namespace}\0{body}"))
}

/// Result of [`path_denominator`]. Mirrors the JS return object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDenominator {
    pub path_count: usize,
    pub paths: Vec<String>,
    pub path_digest: String,
}

/// Port of `pathDenominator(paths, { exclude = [] } = {})`.
pub fn path_denominator(paths: &[String], exclude: &[String]) -> PathDenominator {
    let mut seen = std::collections::BTreeSet::new();
    let mut normalized: Vec<String> = paths
        .iter()
        .filter(|p| seen.insert((*p).clone()))
        .filter(|p| !exclude.iter().any(|pattern| p.contains(pattern.as_str())))
        .cloned()
        .collect();
    normalized.sort();
    let digest_value: Value = Value::Array(normalized.iter().cloned().map(Value::String).collect());
    let path_digest = stable_id("path-denominator", &digest_value);
    PathDenominator {
        path_count: normalized.len(),
        paths: normalized,
        path_digest,
    }
}

/// Port of `validateProviderRecord(record)`: truthy checks on
/// `id`/`providerVersion`/`role`/`phase`, mirroring JS's `Boolean(a && b &&
/// c && d)` over `record?.field` optional chaining.
pub fn validate_provider_record(record: &Value) -> bool {
    fn truthy(v: Option<&Value>) -> bool {
        match v {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => !s.is_empty(),
            Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
            Some(_) => true,
        }
    }
    let obj = record.as_object();
    truthy(obj.and_then(|o| o.get("id")))
        && truthy(obj.and_then(|o| o.get("providerVersion")))
        && truthy(obj.and_then(|o| o.get("role")))
        && truthy(obj.and_then(|o| o.get("phase")))
}

/// Port of `ProviderResultValidationError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResultValidationError {
    pub field: String,
    pub detail: String,
}

impl std::fmt::Display for ProviderResultValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "provider result validation: {}: {}", self.field, self.detail)
    }
}
impl std::error::Error for ProviderResultValidationError {}

fn err(field: &str, detail: &str) -> ProviderResultValidationError {
    ProviderResultValidationError { field: field.to_string(), detail: detail.to_string() }
}

const REQUIRED_FIELDS: &[&str] = &["schemaVersion", "provider", "status", "complete"];
const ARRAY_FIELDS: &[&str] = &[
    "commands", "receipts", "inventory", "candidates", "findings",
    "coverageGaps", "artifacts", "degradation", "inputArtifacts",
];

/// Port of `validateProviderResult(result)`.
pub fn validate_provider_result(result: &Value) -> Result<bool, ProviderResultValidationError> {
    let obj = result.as_object().ok_or_else(|| err("root", "result must be a non-null object"))?;

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
    let status = obj.get("status").and_then(Value::as_str).unwrap_or("");
    if !PROVIDER_STATUS.contains(&status) {
        let status_json = serde_json::to_string(obj.get("status").unwrap_or(&Value::Null)).unwrap_or_default();
        return Err(err(
            "status",
            &format!("invalid status {status_json}; expected one of {}", PROVIDER_STATUS.join(", ")),
        ));
    }
    match obj.get("complete") {
        Some(Value::Bool(_)) => {}
        _ => return Err(err("complete", "must be a boolean")),
    }
    let schema_version_ok = matches!(obj.get("schemaVersion"), Some(Value::Number(n)) if n.as_i64() == Some(1));
    if !schema_version_ok {
        let got = obj
            .get("schemaVersion")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "undefined".to_string());
        return Err(err("schemaVersion", &format!("expected 1, got {got}")));
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
            let valid_shape = a.is_some_and(|a| {
                a.get("kind").is_some_and(|v| !v.is_null())
                    && a.get("path").is_some_and(|v| !v.is_null())
                    && a.get("digest").is_some_and(|v| !v.is_null())
            });
            if !valid_shape {
                return Err(err("artifacts", "each artifact requires kind, path, and digest"));
            }
            let digest_ok = a
                .and_then(|a| a.get("digest"))
                .and_then(Value::as_str)
                .is_some_and(|d| d.starts_with("sha256:"));
            if !digest_ok {
                return Err(err("artifacts.digest", "must be a sha256: prefixed string"));
            }
        }
    }
    Ok(true)
}

/// Port of `normalizeProviderResult(planContract, rawOutput)`. Both
/// arguments are duck-typed JSON in JS; kept as `&Value` here for the same
/// reason (arbitrary provider/plan shapes flow through this boundary).
pub fn normalize_provider_result(
    plan_contract: &Value,
    raw_output: &Value,
) -> Result<Value, ProviderResultValidationError> {
    fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
        v.as_object().and_then(|o| o.get(key))
    }
    fn get_path<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
        let mut cur = v;
        for key in path {
            cur = get(cur, key)?;
        }
        Some(cur)
    }
    fn or_default(v: Option<&Value>, default: Value) -> Value {
        match v {
            Some(Value::Null) | None => default,
            Some(v) => v.clone(),
        }
    }

    let provider = get(plan_contract, "id")
        .filter(|v| !v.is_null())
        .or_else(|| get(raw_output, "provider"))
        .cloned()
        .unwrap_or_else(|| Value::String("unknown".to_string()));

    let mut coverage = get(raw_output, "coverage")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let denominator_digest = get_path(raw_output, &["coverage", "denominatorDigest"])
        .filter(|v| !v.is_null())
        .or_else(|| get_path(plan_contract, &["denominator", "pathDigest"]))
        .cloned()
        .unwrap_or_else(|| Value::String("sha256:unbound".to_string()));
    coverage.insert("denominatorDigest".to_string(), denominator_digest);

    let mut normalized = Map::new();
    normalized.insert("schemaVersion".to_string(), Value::Number(1.into()));
    normalized.insert("provider".to_string(), provider);
    normalized.insert(
        "applicable".to_string(),
        or_default(get(raw_output, "applicable"), Value::Bool(true)),
    );
    normalized.insert(
        "required".to_string(),
        or_default(get_path(plan_contract, &["benchmark", "requiredForCleanClaim"]), Value::Bool(false)),
    );
    normalized.insert(
        "status".to_string(),
        or_default(get(raw_output, "status"), Value::String("unproven".to_string())),
    );
    normalized.insert(
        "complete".to_string(),
        or_default(get(raw_output, "complete"), Value::Bool(false)),
    );
    normalized.insert("coverage".to_string(), Value::Object(coverage));
    for field in ["commands", "receipts", "inventory", "candidates", "findings", "coverageGaps", "artifacts", "degradation"] {
        normalized.insert(field.to_string(), or_default(get(raw_output, field), Value::Array(vec![])));
    }

    let normalized = Value::Object(normalized);
    validate_provider_result(&normalized)?;
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stable_id_double_encodes_like_js() {
        let id = stable_id("ns", &json!({"a": 1}));
        assert!(id.starts_with("sha256:"));
        // Independently recompute the JS-equivalent double encoding.
        let inner = canonical_json(&json!({"a": 1}));
        let body = serde_json::to_string(&inner).unwrap();
        let expected = super::super::canonical::sha256_str(&format!("ns\0{body}"));
        assert_eq!(id, expected);
    }

    #[test]
    fn path_denominator_dedupes_sorts_and_excludes() {
        let paths = vec!["b/x".to_string(), "a/x".to_string(), "b/x".to_string(), "node_modules/y".to_string()];
        let d = path_denominator(&paths, &["node_modules".to_string()]);
        assert_eq!(d.paths, vec!["a/x".to_string(), "b/x".to_string()]);
        assert_eq!(d.path_count, 2);
    }

    #[test]
    fn validate_provider_record_requires_all_four_fields() {
        assert!(validate_provider_record(&json!({"id": "x", "providerVersion": "1", "role": "r", "phase": "p"})));
        assert!(!validate_provider_record(&json!({"id": "x", "providerVersion": "1", "role": "r"})));
        assert!(!validate_provider_record(&json!({"id": "", "providerVersion": "1", "role": "r", "phase": "p"})));
    }

    #[test]
    fn validate_provider_result_rejects_invalid_status() {
        let r = json!({"schemaVersion": 1, "provider": "x", "status": "invalid-status", "complete": true});
        let e = validate_provider_result(&r).unwrap_err();
        assert_eq!(e.field, "status");
    }

    #[test]
    fn validate_provider_result_rejects_null_array_field() {
        let r = json!({"schemaVersion": 1, "provider": "x", "status": "pass", "complete": true, "findings": null});
        let e = validate_provider_result(&r).unwrap_err();
        assert_eq!(e.field, "findings");
    }

    #[test]
    fn normalize_provider_result_matches_js_self_test() {
        let plan = json!({"id": "test.provider", "denominator": {"pathDigest": "sha256:test"}, "benchmark": {"requiredForCleanClaim": true}});
        let raw = json!({"status": "pass", "complete": true, "findings": []});
        let normalized = normalize_provider_result(&plan, &raw).unwrap();
        assert_eq!(normalized["provider"], "test.provider");
        assert_eq!(normalized["status"], "pass");
        assert_eq!(normalized["coverage"]["denominatorDigest"], "sha256:test");
        assert_eq!(normalized["required"], true);
        assert!(normalized["degradation"].is_array());
    }
}
