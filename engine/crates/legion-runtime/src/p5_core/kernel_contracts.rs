//! Ported from src/packages/kernel/lib/contracts.mjs (packet P5d).
//!
//! Faithful port of the hand-rolled JSON-Schema-subset validator
//! (`assertContract`) and `bindRunIdentity`. Supports exactly the schema
//! vocabulary the JS validator supports: `$ref` (local `#/...` only),
//! `oneOf`, `const`, `enum`, `type` (single or array), string `minLength`/
//! `pattern`/`format: date-time`, number `minimum`, array `items`, and
//! object `required`/`additionalProperties: false`/`properties`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use legion_catalog::json::{self, Value};

use crate::p5_core::kernel_errors::{KernelError, KernelErrorOptions};

fn schemas_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is engine/crates/legion-runtime; the repo root is
    // three levels up from there.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/packages/contracts/schemas")
}

fn schema_path(name: &str) -> Option<PathBuf> {
    let known = [
        "execution-contract-v1",
        "execution-task-v1",
        "worker-capsule-v1",
        "artifact-v1",
        "effect-request-v1",
        "effect-receipt-v1",
        "evidence-capability-receipt-v1",
        "blocker-v1",
        "amendment-v1",
        "claim-v1",
        "covenant-request-v1",
        "covenant-record-v1",
        "operation-envelope-v1",
        "legion-result-v1",
        "run-identity-v1",
        "legacy-envelope-v1",
        "authority-dispatch-v1",
        "oracle-completion-validation-v1",
    ];
    if known.contains(&name) {
        Some(schemas_dir().join(format!("{name}.schema.json")))
    } else {
        None
    }
}

static SCHEMA_CACHE: OnceLock<Mutex<HashMap<String, Value>>> = OnceLock::new();

fn integrity_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "INVALID_ARGUMENT",
        message,
        KernelErrorOptions {
            category: Some("internal".to_string()),
            ..Default::default()
        },
    )
}

fn usage_error(message: impl Into<String>, details: Value) -> KernelError {
    KernelError::new(
        "INVALID_ARGUMENT",
        message,
        KernelErrorOptions {
            category: Some("usage".to_string()),
            details: Some(details),
            ..Default::default()
        },
    )
}

fn schema_for(name: &str) -> Result<Value, KernelError> {
    let path = schema_path(name).ok_or_else(|| {
        KernelError::new(
            "INVALID_ARGUMENT",
            format!("unknown contract schema: {name}"),
            KernelErrorOptions {
                category: Some("usage".to_string()),
                ..Default::default()
            },
        )
    })?;
    let cache = SCHEMA_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap();
    if let Some(existing) = guard.get(name) {
        return Ok(existing.clone());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|cause| integrity_error(format!("failed to read schema {name}: {cause}")))?;
    let value: Value = json::from_str(&text)
        .map_err(|cause| integrity_error(format!("failed to parse schema {name}: {cause}")))?;
    guard.insert(name.to_string(), value.clone());
    Ok(value)
}

fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let path = reference.strip_prefix("#/")?;
    let mut current = root;
    for segment in path.split('/') {
        let key = segment.replace("~1", "/").replace("~0", "~");
        current = current.get(&key)?;
    }
    Some(current)
}

fn matches_type(value: &Value, type_name: &str) -> bool {
    match type_name {
        "null" => value.is_null(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "integer" => value.is_i64() || value.is_u64() || value.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        _ => false,
    }
}

fn validate_node(schema: &Value, value: &Value, root: &Value, at: &str, errors: &mut Vec<String>) {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(target) = resolve_ref(root, reference) {
            validate_node(target, value, root, at, errors);
        } else {
            errors.push(format!("{at} references an unresolved schema: {reference}"));
        }
        return;
    }

    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = branches
            .iter()
            .filter(|candidate| {
                let mut candidate_errors = Vec::new();
                validate_node(candidate, value, root, at, &mut candidate_errors);
                candidate_errors.is_empty()
            })
            .count();
        if matches != 1 {
            errors.push(format!("{at} must match exactly one schema branch"));
        }
        return;
    }

    if let Some(constant) = schema.get("const") {
        if value != constant {
            errors.push(format!("{at} must equal {constant}"));
        }
    }

    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            errors.push(format!("{at} is not an allowed value"));
        }
    }

    if let Some(type_field) = schema.get("type") {
        let types: Vec<&str> = if let Some(single) = type_field.as_str() {
            vec![single]
        } else if let Some(list) = type_field.as_array() {
            list.iter().filter_map(Value::as_str).collect()
        } else {
            Vec::new()
        };
        if !types.is_empty() && !types.iter().any(|t| matches_type(value, t)) {
            errors.push(format!("{at} must be {}", types.join("|")));
            return;
        }
    }

    if let Some(text) = value.as_str() {
        if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64) {
            if (text.chars().count() as u64) < min_length {
                errors.push(format!("{at} is too short"));
            }
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            match regex_lite_is_match(pattern, text) {
                Ok(matched) => {
                    if !matched {
                        errors.push(format!("{at} has invalid format"));
                    }
                }
                Err(_) => errors.push(format!("{at} has invalid format")),
            }
        }
        if schema.get("format").and_then(Value::as_str) == Some("date-time") && !is_iso_date_time(text) {
            errors.push(format!("{at} must be an ISO date-time"));
        }
    }

    if let Some(number) = value.as_f64() {
        if value.is_number() {
            if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
                if number < minimum {
                    errors.push(format!("{at} is below minimum"));
                }
            }
        }
    }

    if let Some(items) = value.as_array() {
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                validate_node(item_schema, item, root, &format!("{at}[{index}]"), errors);
            }
        }
    }

    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    errors.push(format!("{at}.{field} is required"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            for key in object.keys() {
                let known = properties.map(|p| p.contains_key(key)).unwrap_or(false);
                if !known {
                    errors.push(format!("{at}.{key} is unknown"));
                }
            }
        }
        if let Some(properties) = properties {
            for (key, child_schema) in properties {
                if let Some(child_value) = object.get(key) {
                    validate_node(child_schema, child_value, root, &format!("{at}.{key}"), errors);
                }
            }
        }
    }
}

/// JS `new RegExp(pattern).test(value)` port via the `regex` crate. Every
/// pattern in Legion's contract schemas is an anchored ASCII character-class
/// pattern (no lookaround, backreferences, or Unicode property escapes), so
/// Rust's `regex` crate (a strict subset of ECMA-262 syntax for these
/// patterns) matches JS semantics exactly for the schema set actually
/// shipped.
fn regex_lite_is_match(pattern: &str, text: &str) -> Result<bool, ()> {
    let compiled = regex::Regex::new(pattern).map_err(|_| ())?;
    Ok(compiled.is_match(text))
}

fn is_iso_date_time(text: &str) -> bool {
    // Mirrors `Number.isNaN(Date.parse(value))` closely enough for the
    // RFC 3339 timestamps every schema actually uses.
    chrono_lite::parse_iso8601(text).is_some()
}

mod chrono_lite {
    /// Extremely small RFC 3339 sanity check: `YYYY-MM-DDTHH:MM:SS(.sss)?(Z|+HH:MM|-HH:MM)`.
    pub fn parse_iso8601(text: &str) -> Option<()> {
        let bytes = text.as_bytes();
        if bytes.len() < 20 {
            return None;
        }
        let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
        if !digits(&bytes[0..4]) || bytes[4] != b'-' || !digits(&bytes[5..7]) || bytes[7] != b'-' || !digits(&bytes[8..10]) {
            return None;
        }
        if bytes[10] != b'T' && bytes[10] != b't' {
            return None;
        }
        if !digits(&bytes[11..13]) || bytes[13] != b':' || !digits(&bytes[14..16]) || bytes[16] != b':' || !digits(&bytes[17..19]) {
            return None;
        }
        let rest = &text[19..];
        let rest = rest.strip_prefix('.').map(|withfrac| {
            let end = withfrac.find(|c: char| !c.is_ascii_digit()).unwrap_or(withfrac.len());
            &withfrac[end..]
        }).unwrap_or(rest);
        if rest == "Z" || rest == "z" {
            return Some(());
        }
        if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) {
            let offset_digits = rest.as_bytes();
            if digits(&offset_digits[1..3]) && offset_digits[3] == b':' && digits(&offset_digits[4..6]) {
                return Some(());
            }
        }
        None
    }
}

/// Port of `assertContract(name, value, label = name)`.
pub fn assert_contract(name: &str, value: &Value, label: Option<&str>) -> Result<Value, KernelError> {
    let schema = schema_for(name)?;
    let mut errors = Vec::new();
    validate_node(&schema, value, &schema, "$", &mut errors);
    if !errors.is_empty() {
        let label = label.unwrap_or(name);
        return Err(usage_error(
            format!("invalid {label}: {}", errors.join("; ")),
            json::json!({ "schema": name, "errors": errors }),
        ));
    }
    Ok(value.clone())
}

/// Port of `bindRunIdentity(fields)`.
pub fn bind_run_identity(fields: &Value) -> Result<Value, KernelError> {
    let mut identity = json::json!({ "schemaVersion": 1, "kind": "legion-run-identity" });
    if let (Some(target), Some(extra)) = (identity.as_object_mut(), fields.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    assert_contract("run-identity-v1", &identity, Some("run identity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_contract_rejects_unknown_schema() {
        let error = assert_contract("not-a-schema", &json::json!({}), None).unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
        assert_eq!(error.category, "usage");
    }

    #[test]
    fn bind_run_identity_accepts_a_fully_valid_identity() {
        let fields = json::json!({
            "runId": "run_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "workspace": "ws",
            "repository": "legion",
            "revision": "abcdef1234567",
            "dirtyDigest": null,
            "capturedAt": "2026-09-23T00:00:00.000Z",
        });
        let bound = bind_run_identity(&fields).unwrap();
        assert_eq!(bound["schemaVersion"], 1);
        assert_eq!(bound["kind"], "legion-run-identity");
    }

    #[test]
    fn bind_run_identity_rejects_bad_revision_min_length() {
        let fields = json::json!({
            "runId": "run_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "workspace": "ws",
            "repository": "legion",
            "revision": "short",
            "dirtyDigest": null,
            "capturedAt": "2026-09-23T00:00:00.000Z",
        });
        let error = bind_run_identity(&fields).unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
    }

    #[test]
    fn assert_contract_reads_real_run_identity_schema() {
        // Any structurally-empty object should fail run-identity-v1's
        // required-field checks, proving the schema file loaded and its
        // `required` list is enforced end to end.
        let error = assert_contract("run-identity-v1", &json::json!({}), Some("run identity")).unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
        assert!(error.details.is_some());
    }

    #[test]
    fn regex_lite_matches_ulid_pattern() {
        assert!(regex_lite_is_match("^run_[0-9A-HJKMNP-TV-Z]{26}$", "run_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap());
        assert!(!regex_lite_is_match("^run_[0-9A-HJKMNP-TV-Z]{26}$", "run_tooshort").unwrap());
    }

    #[test]
    fn regex_lite_matches_sha256_digest_pattern() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert!(regex_lite_is_match(r"^sha256:[0-9a-f]{64}$", &digest).unwrap());
        assert!(!regex_lite_is_match(r"^sha256:[0-9a-f]{64}$", "sha256:short").unwrap());
    }

    #[test]
    fn regex_lite_matches_dashed_id_group_pattern() {
        assert!(regex_lite_is_match("^[a-z0-9]+(?:-[a-z0-9]+)*$", "profile-name-1").unwrap());
        assert!(!regex_lite_is_match("^[a-z0-9]+(?:-[a-z0-9]+)*$", "Profile Name").unwrap());
    }

    #[test]
    fn regex_lite_matches_dotted_task_id_pattern() {
        assert!(regex_lite_is_match(r"^T-\d+(\.\d+)*$", "T-1.2.3").unwrap());
        assert!(!regex_lite_is_match(r"^T-\d+(\.\d+)*$", "T-1.").unwrap());
    }
}
