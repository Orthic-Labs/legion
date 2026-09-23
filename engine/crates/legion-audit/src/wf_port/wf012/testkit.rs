//! Faithful port of `src/lib/providers/sdk/testkit.mjs`.
//!
//! This module operates on `serde_json::Value` rather than a strongly typed
//! provider-result struct: the JS testkit is deliberately duck-typed (any
//! object with the right fields works), and the crate's existing typed
//! `ProviderResult`/`Coverage` model in `legion-provider-sdk::result` /
//! `legion-contracts` is a different, already-validated contract shape (see
//! that module's `normalize_result`) — reusing it here would silently change
//! this port's semantics away from the JS source. `stableId`/`pathDenominator`
//! reuse the crate's existing `canonical_digest`-style SHA-256 plumbing
//! (`legion-contracts::canonical`) is intentionally NOT done either, because
//! `stableId`'s hash input format (`${namespace}\0${body}`, with `body` being
//! a *double*-JSON-encoded canonical string — see below) is specific to this
//! module and not what `canonical_digest` produces.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Port of `canonicalize`/`canonicalJson` from `src/registry/provider-registry.mjs`:
/// ```js
/// export function canonicalize(value) {
///   if (Array.isArray(value)) return value.map(canonicalize);
///   if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
///   return value;
/// }
/// export function canonicalJson(value) { return JSON.stringify(canonicalize(value)); }
/// ```
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (key, val) in map {
                sorted.insert(key.clone(), canonicalize(val));
            }
            let mut out = Map::new();
            for (key, val) in sorted {
                out.insert(key, val);
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// `canonicalJson(value)` — returns the canonical JSON *string* (compact,
/// keys sorted), matching `JSON.stringify` output byte-for-byte for the
/// value shapes this crate feeds it (no NaN/Infinity, no `undefined`
/// inside arrays).
fn canonical_json_string(value: &Value) -> String {
    serde_json::to_string(&canonicalize(value)).expect("canonical value is serializable")
}

/// Port of `stableId(namespace, value)`:
/// ```js
/// export function stableId(namespace, value) {
///   const body = JSON.stringify(canonicalJson(value));
///   return `sha256:${createHash('sha256').update(`${namespace}\0${body}`).digest('hex')}`;
/// }
/// ```
/// Note `body` is `JSON.stringify` applied to the *string* returned by
/// `canonicalJson` — a double encoding (the canonical JSON text gets
/// re-quoted with its inner quotes escaped) — reproduced here exactly via
/// `serde_json::to_string` on the intermediate `String`, not on `value`
/// directly.
pub fn stable_id(namespace: &str, value: &Value) -> String {
    let canonical = canonical_json_string(value);
    let body = serde_json::to_string(&canonical).expect("string is serializable");
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update(b"\0");
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathDenominator {
    #[serde(rename = "pathCount")]
    pub path_count: usize,
    pub paths: Vec<String>,
    #[serde(rename = "pathDigest")]
    pub path_digest: String,
}

/// Port of `pathDenominator(paths, { exclude = [] } = {})`:
/// ```js
/// export function pathDenominator(paths, { exclude = [] } = {}) {
///   const normalized = [...new Set(paths)]
///     .filter((path) => !exclude.some((pattern) => path.includes(pattern)))
///     .sort();
///   return { pathCount: normalized.length, paths: normalized, pathDigest: stableId('path-denominator', normalized) };
/// }
/// ```
pub fn path_denominator(paths: &[String], exclude: &[String]) -> PathDenominator {
    // JS: `[...new Set(paths)]` dedupes preserving first-seen order, THEN
    // `.filter(...)` drops excluded paths, THEN `.sort()`.
    let mut deduped: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        if seen.insert(path.clone()) {
            deduped.push(path.clone());
        }
    }
    let mut normalized: Vec<String> = deduped
        .into_iter()
        .filter(|path| !exclude.iter().any(|pattern| path.contains(pattern.as_str())))
        .collect();
    normalized.sort();

    let path_digest = stable_id(
        "path-denominator",
        &Value::Array(normalized.iter().cloned().map(Value::String).collect()),
    );
    PathDenominator {
        path_count: normalized.len(),
        paths: normalized,
        path_digest,
    }
}

fn is_js_truthy(value: Option<&Value>) -> bool {
    match value {
        None => false,
        Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(_)) | Some(Value::Object(_)) => true,
    }
}

/// Port of `validateProviderRecord(record)`:
/// ```js
/// export function validateProviderRecord(record) {
///   return Boolean(record?.id && record?.providerVersion && record?.role && record?.phase);
/// }
/// ```
pub fn validate_provider_record(record: &Value) -> bool {
    let obj = record.as_object();
    let get = |key: &str| obj.and_then(|o| o.get(key));
    is_js_truthy(get("id"))
        && is_js_truthy(get("providerVersion"))
        && is_js_truthy(get("role"))
        && is_js_truthy(get("phase"))
}

/// `PROVIDER_STATUS` from `src/registry/provider-contracts.mjs`.
pub const PROVIDER_STATUS: &[&str] = &[
    "pass", "fail", "partial", "unproven", "skipped", "error", "pending", "missing",
    "candidates", "blocked",
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("provider result validation: {field}: {detail}")]
pub struct ProviderResultValidationError {
    pub field: String,
    pub detail: String,
}

impl ProviderResultValidationError {
    fn new(field: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            detail: detail.into(),
        }
    }
}

const REQUIRED_FIELDS: &[&str] = &["schemaVersion", "provider", "status", "complete"];
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

/// Port of `validateProviderResult(result)` from
/// `scripts/normalize-provider-result.mjs`.
pub fn validate_provider_result(result: &Value) -> Result<(), ProviderResultValidationError> {
    let obj = result.as_object().ok_or_else(|| {
        ProviderResultValidationError::new("root", "result must be a non-null object")
    })?;

    for field in REQUIRED_FIELDS {
        match obj.get(*field) {
            None | Some(Value::Null) => {
                return Err(ProviderResultValidationError::new(
                    *field,
                    "required field is missing",
                ))
            }
            _ => {}
        }
    }

    match obj.get("provider") {
        Some(Value::String(s)) if !s.is_empty() => {}
        _ => {
            return Err(ProviderResultValidationError::new(
                "provider",
                "must be a non-empty string",
            ))
        }
    }

    let status_ok = matches!(obj.get("status"), Some(Value::String(s)) if PROVIDER_STATUS.contains(&s.as_str()));
    if !status_ok {
        let status_repr = obj
            .get("status")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "undefined".to_string());
        return Err(ProviderResultValidationError::new(
            "status",
            format!(
                "invalid status {status_repr}; expected one of {}",
                PROVIDER_STATUS.join(", ")
            ),
        ));
    }

    if !matches!(obj.get("complete"), Some(Value::Bool(_))) {
        return Err(ProviderResultValidationError::new(
            "complete",
            "must be a boolean",
        ));
    }

    let schema_version_ok = matches!(obj.get("schemaVersion"), Some(Value::Number(n)) if n.as_i64() == Some(1) || n.as_f64() == Some(1.0));
    if !schema_version_ok {
        let got = obj
            .get("schemaVersion")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "undefined".to_string());
        return Err(ProviderResultValidationError::new(
            "schemaVersion",
            format!("expected 1, got {got}"),
        ));
    }

    for field in ARRAY_FIELDS {
        match obj.get(*field) {
            Some(Value::Null) => {
                return Err(ProviderResultValidationError::new(
                    *field,
                    "must be an array, never null",
                ))
            }
            Some(v) if !matches!(v, Value::Array(_)) => {
                return Err(ProviderResultValidationError::new(
                    *field,
                    "must be an array when present",
                ))
            }
            _ => {}
        }
    }

    if let Some(Value::Array(artifacts)) = obj.get("artifacts") {
        for artifact in artifacts {
            let artifact_obj = artifact.as_object();
            let valid_shape = artifact_obj
                .map(|a| {
                    is_js_truthy(a.get("kind"))
                        && is_js_truthy(a.get("path"))
                        && is_js_truthy(a.get("digest"))
                })
                .unwrap_or(false);
            if !valid_shape {
                return Err(ProviderResultValidationError::new(
                    "artifacts",
                    "each artifact requires kind, path, and digest",
                ));
            }
            let digest_ok = matches!(
                artifact_obj.and_then(|a| a.get("digest")),
                Some(Value::String(d)) if d.starts_with("sha256:")
            );
            if !digest_ok {
                return Err(ProviderResultValidationError::new(
                    "artifacts.digest",
                    "must be a sha256: prefixed string",
                ));
            }
        }
    }

    Ok(())
}

fn get_or<'a>(obj: &'a Map<String, Value>, key: &str, default: &'a Value) -> Value {
    match obj.get(key) {
        Some(Value::Null) | None => default.clone(),
        Some(v) => v.clone(),
    }
}

/// Port of `normalizeProviderResult(planContract, rawOutput)`. Both
/// arguments are optional-shaped (`planContract?.id`, `rawOutput?.status`,
/// etc.) so this accepts `Option<&Value>` to mirror `undefined` plan
/// contracts / raw outputs.
pub fn normalize_provider_result(
    plan_contract: Option<&Value>,
    raw_output: Option<&Value>,
) -> Result<Value, ProviderResultValidationError> {
    let empty = Map::new();
    let plan_obj = plan_contract.and_then(Value::as_object).unwrap_or(&empty);
    let raw_obj = raw_output.and_then(Value::as_object).unwrap_or(&empty);

    let provider = plan_obj
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| raw_obj.get("provider").and_then(Value::as_str))
        .unwrap_or("unknown")
        .to_string();

    let applicable = raw_obj.get("applicable").cloned().unwrap_or(Value::Bool(true));

    let required = plan_obj
        .get("benchmark")
        .and_then(Value::as_object)
        .and_then(|b| b.get("requiredForCleanClaim"))
        .cloned()
        .unwrap_or(Value::Bool(false));

    let status = raw_obj
        .get("status")
        .cloned()
        .unwrap_or_else(|| Value::String("unproven".to_string()));

    let complete = raw_obj.get("complete").cloned().unwrap_or(Value::Bool(false));

    let raw_coverage = raw_obj
        .get("coverage")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let denominator_digest = raw_coverage
        .get("denominatorDigest")
        .cloned()
        .or_else(|| {
            plan_obj
                .get("denominator")
                .and_then(Value::as_object)
                .and_then(|d| d.get("pathDigest"))
                .cloned()
        })
        .unwrap_or_else(|| Value::String("sha256:unbound".to_string()));
    let mut coverage = raw_coverage;
    coverage.insert("denominatorDigest".to_string(), denominator_digest);

    let empty_array = Value::Array(Vec::new());
    let mut normalized = Map::new();
    normalized.insert("schemaVersion".to_string(), Value::Number(1.into()));
    normalized.insert("provider".to_string(), Value::String(provider));
    normalized.insert("applicable".to_string(), applicable);
    normalized.insert("required".to_string(), required);
    normalized.insert("status".to_string(), status);
    normalized.insert("complete".to_string(), complete);
    normalized.insert("coverage".to_string(), Value::Object(coverage));
    normalized.insert("commands".to_string(), get_or(raw_obj, "commands", &empty_array));
    normalized.insert("receipts".to_string(), get_or(raw_obj, "receipts", &empty_array));
    normalized.insert("inventory".to_string(), get_or(raw_obj, "inventory", &empty_array));
    normalized.insert("candidates".to_string(), get_or(raw_obj, "candidates", &empty_array));
    normalized.insert("findings".to_string(), get_or(raw_obj, "findings", &empty_array));
    normalized.insert(
        "coverageGaps".to_string(),
        get_or(raw_obj, "coverageGaps", &empty_array),
    );
    normalized.insert("artifacts".to_string(), get_or(raw_obj, "artifacts", &empty_array));
    normalized.insert(
        "degradation".to_string(),
        get_or(raw_obj, "degradation", &empty_array),
    );

    let value = Value::Object(normalized);
    validate_provider_result(&value)?;
    Ok(value)
}
