//! Port of `src/lib/contracts/arcane/validate.mjs`.
//!
//! JS loads a frozen contract schema by logical name from `SCHEMA_PATHS`
//! (`src/packages/contracts/index.mjs`), caches it, walks it with the
//! generic structural validator (`schema.rs`'s `validate_schema`, the same
//! port `runtime_schema.rs` uses), then additionally checks every
//! `format: date-time` field the schema declares (not just five fixed key
//! names, unlike `runtime_schema.rs`'s RFC3339 walk — the two JS modules
//! deliberately check dates differently, and this port preserves that
//! difference rather than unifying them).
//!
//! `packages/contracts/` is READ-ONLY to this lane in the JS source; the
//! Rust equivalent (the 18 embedded schema files under `schemas_contracts/`
//! in this owned module directory) is likewise treated as frozen fixture
//! data, not something this chunk edits.

use crate::wf_port::wf068::errors::ArcaneError;
use crate::wf_port::wf068::schema::validate_schema;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

macro_rules! schema_entry {
    ($name:literal, $file:literal) => {
        ($name, include_str!(concat!("schemas_contracts/", $file)))
    };
}

/// `(logical name, embedded JSON text)` for every entry JS's `SCHEMA_PATHS`
/// declares (`src/packages/contracts/index.mjs`).
const EMBEDDED: [(&str, &str); 18] = [
    schema_entry!("execution-contract-v1", "execution-contract-v1.schema.json"),
    schema_entry!("execution-task-v1", "execution-task-v1.schema.json"),
    schema_entry!("worker-capsule-v1", "worker-capsule-v1.schema.json"),
    schema_entry!("artifact-v1", "artifact-v1.schema.json"),
    schema_entry!("effect-request-v1", "effect-request-v1.schema.json"),
    schema_entry!("effect-receipt-v1", "effect-receipt-v1.schema.json"),
    schema_entry!(
        "evidence-capability-receipt-v1",
        "evidence-capability-receipt-v1.schema.json"
    ),
    schema_entry!("blocker-v1", "blocker-v1.schema.json"),
    schema_entry!("amendment-v1", "amendment-v1.schema.json"),
    schema_entry!("claim-v1", "claim-v1.schema.json"),
    schema_entry!("covenant-request-v1", "covenant-request-v1.schema.json"),
    schema_entry!("covenant-record-v1", "covenant-record-v1.schema.json"),
    schema_entry!("operation-envelope-v1", "operation-envelope-v1.schema.json"),
    schema_entry!("legion-result-v1", "legion-result-v1.schema.json"),
    schema_entry!("run-identity-v1", "run-identity-v1.schema.json"),
    schema_entry!("legacy-envelope-v1", "legacy-envelope-v1.schema.json"),
    schema_entry!("authority-dispatch-v1", "authority-dispatch-v1.schema.json"),
    schema_entry!(
        "oracle-completion-validation-v1",
        "oracle-completion-validation-v1.schema.json"
    ),
];

fn schema_map() -> &'static HashMap<&'static str, Value> {
    static MAP: OnceLock<HashMap<&'static str, Value>> = OnceLock::new();
    MAP.get_or_init(|| {
        EMBEDDED
            .iter()
            .map(|(name, text)| {
                let value: Value =
                    serde_json::from_str(text).unwrap_or_else(|e| panic!("embedded schema {name} is valid JSON: {e}"));
                (*name, value)
            })
            .collect()
    })
}

/// `{ valid, issues }`, matching JS's return shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationOutcome {
    pub valid: bool,
    pub issues: Vec<String>,
}

/// Port of `loadSchema(name)`. JS caches per-process via a module-level
/// `Map`; this port caches via `OnceLock` over the whole embedded set
/// instead (all schemas are frozen fixture data known at compile time, so
/// eager-load-all is equivalent to lazy-load-and-cache with the same
/// steady-state cost and no first-call parse tax at all after the first
/// call to any schema).
pub fn load_schema(name: &str) -> Result<&'static Value, ArcaneError> {
    schema_map().get(name).ok_or_else(|| {
        ArcaneError::with_details(
            "ARC_SCHEMA_INVALID",
            format!("unknown frozen schema: {name}"),
            serde_json::json!({ "name": name, "known": schema_map().keys().collect::<Vec<_>>() }),
        )
    })
}

/// Recursive `format: date-time` collector, port of JS `checkDateTimes`.
fn check_date_times(schema: &Value, value: &Value, path: &str, root: &Value, issues: &mut Vec<String>) {
    if !schema.is_object() {
        return;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(target) = resolve_ref(root, reference) {
            check_date_times(target, value, path, root, issues);
        }
        return;
    }
    if schema.get("format").and_then(Value::as_str) == Some("date-time") {
        if let Some(s) = value.as_str() {
            if !is_date_time(s) {
                issues.push(format!("{path}:format-date-time"));
            }
        }
    }
    if let (Some(items_schema), Some(arr)) = (schema.get("items"), value.as_array()) {
        for (i, v) in arr.iter().enumerate() {
            check_date_times(items_schema, v, &format!("{path}[{i}]"), root, issues);
        }
    }
    if let (Some(props), Some(obj)) = (schema.get("properties").and_then(Value::as_object), value.as_object()) {
        for (k, child) in props {
            if let Some(v) = obj.get(k) {
                check_date_times(child, v, &format!("{path}.{k}"), root, issues);
            }
        }
    }
}

fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix("#/")?;
    let mut node = root;
    for key in pointer.split('/') {
        node = node.get(key)?;
    }
    Some(node)
}

fn is_date_time(value: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$").unwrap()
    });
    re.is_match(value)
}

/// Port of `validateAgainst(name, value)`.
pub fn validate_against(name: &str, value: &Value) -> Result<ValidationOutcome, ArcaneError> {
    let schema = load_schema(name)?;
    let mut issues = validate_schema(schema, value);
    check_date_times(schema, value, "$", schema, &mut issues);
    Ok(ValidationOutcome { valid: issues.is_empty(), issues })
}

/// Port of `validateAgainstDef(name, defName, value)`.
pub fn validate_against_def(name: &str, def_name: &str, value: &Value) -> Result<ValidationOutcome, ArcaneError> {
    let root = load_schema(name)?;
    let def = root
        .get("$defs")
        .and_then(|d| d.get(def_name))
        .ok_or_else(|| {
            let known: Vec<String> = root
                .get("$defs")
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            ArcaneError::with_details(
                "ARC_SCHEMA_INVALID",
                format!("{name} has no $defs entry '{def_name}'"),
                serde_json::json!({ "schema": name, "known": known }),
            )
        })?;
    let mut issues = validate_schema(def, value);
    check_date_times(def, value, "$", root, &mut issues);
    Ok(ValidationOutcome { valid: issues.is_empty(), issues })
}

/// Port of `assertValid(name, value, label = name)`.
pub fn assert_valid(name: &str, value: &Value, label: Option<&str>) -> Result<(), ArcaneError> {
    let outcome = validate_against(name, value)?;
    if !outcome.valid {
        let label = label.unwrap_or(name);
        return Err(ArcaneError::with_details(
            "ARC_SCHEMA_INVALID",
            format!("{label} does not satisfy {name}"),
            serde_json::json!({ "schema": name, "issues": outcome.issues }),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn load_schema_unknown_name_is_arc_schema_invalid() {
        let err = load_schema("nonexistent-v1").unwrap_err();
        assert_eq!(err.code, "ARC_SCHEMA_INVALID");
    }

    #[test]
    fn load_schema_known_name_round_trips_all_eighteen() {
        for (name, _) in EMBEDDED {
            assert!(load_schema(name).is_ok(), "missing schema: {name}");
        }
    }

    #[test]
    fn validate_against_blocker_v1_reports_missing_required_field() {
        let outcome = validate_against("blocker-v1", &json!({})).unwrap();
        assert!(!outcome.valid);
        assert!(!outcome.issues.is_empty());
    }

    #[test]
    fn validate_against_def_unknown_def_is_arc_schema_invalid() {
        let err = validate_against_def("operation-envelope-v1", "NoSuchDef", &json!({})).unwrap_err();
        assert_eq!(err.code, "ARC_SCHEMA_INVALID");
    }

    #[test]
    fn assert_valid_uses_custom_label_in_message() {
        let err = assert_valid("blocker-v1", &json!({}), Some("my-thing")).unwrap_err();
        assert!(err.message.starts_with("my-thing does not satisfy blocker-v1"));
    }
}
