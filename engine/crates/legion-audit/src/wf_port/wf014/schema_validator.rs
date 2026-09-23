//! Port of `src/lib/qualification/schema-validator.mjs`.
//!
//! A small, dependency-free JSON-Schema subset validator. It walks a schema
//! and a `serde_json::Value` together and returns a flat list of
//! `path:reason` issue strings — never a boolean, never a thrown error for a
//! failed constraint. This mirrors the JS `validateSchema(schema, value,
//! path = '$', root = schema)` exactly: same recursion order, same issue
//! string shapes, same short-circuit on a type mismatch (JS returns
//! `[...issues, `${path}:type`]` immediately once `type` fails, skipping
//! every constraint below it — this port does the same).
//!
//! Supported keywords: `$ref` (only `#/...` JSON-pointer-style refs into the
//! root schema, matching the JS `resolveRef`, which throws on any other ref
//! form), `if`/`then` (evaluated eagerly, not treated as prose — same
//! comment as the JS source), `allOf`, `const`, `enum`, `type` (single type
//! or an array of alternatives), string `minLength`/`maxLength`/`pattern`/
//! `format: date-time`, number `minimum`/`maximum`, array `minItems`/
//! `maxItems`/`items`, and object `required`/`additionalProperties: false`/
//! `properties`.

use regex::Regex;
use serde_json::Value;

/// Mirrors the JS `throw new Error(\`unsupported schema ref: ${ref}\`)`.
///
/// The JS validator is otherwise infallible (it returns issue strings, not
/// errors), so this is the one path that can panic — exactly as the JS one
/// throws synchronously and uncaught.
fn resolve_ref<'a>(root: &'a Value, reference: &str) -> &'a Value {
    let Some(pointer) = reference.strip_prefix("#/") else {
        panic!("unsupported schema ref: {reference}");
    };
    let mut node = root;
    for key in pointer.split('/') {
        node = node
            .get(key)
            .unwrap_or_else(|| panic!("unsupported schema ref: {reference}"));
    }
    node
}

/// JS `typeMatches`: `type` may be a single JSON-Schema primitive name or an
/// array of alternatives (`anyOf`-style short form used by `type`).
fn type_matches(value: &Value, ty: &Value) -> bool {
    if let Some(list) = ty.as_array() {
        return list.iter().any(|candidate| type_matches(value, candidate));
    }
    let Some(name) = ty.as_str() else { return false };
    match name {
        "null" => value.is_null(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "integer" => value.is_i64() || value.is_u64() || matches!(value, Value::Number(n) if n.is_f64() && n.as_f64().is_some_and(|f| f.fract() == 0.0)),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        _ => false,
    }
}

/// JS `dateTimeMatches`: `Number.isFinite(Date.parse(value))` and the value
/// ends with a `T`-separated time zone offset or `Z`. `Date.parse` accepts a
/// broad ISO-8601-ish grammar; this port checks the same trailing-offset
/// shape the JS regex checks and additionally requires the value to parse as
/// RFC 3339, which covers the receipts this validator is used against
/// (`Date.parse` is more permissive on partial/legacy formats that never
/// appear in a qualification receipt — see wf014 report for detail).
fn date_time_matches(value: &str) -> bool {
    let has_t = value.contains('T');
    let ends_with_offset = value.ends_with('Z')
        || Regex::new(r"[+-]\d{2}:\d{2}$").unwrap().is_match(value);
    has_t && ends_with_offset && chrono_free_parse_ok(value)
}

/// A tiny RFC-3339 sanity parser (no chrono dependency available in this
/// workspace): validates that the date-time portion is numerically
/// well-formed. It does not replicate every `Date.parse` leniency; it exists
/// only to reject obviously-garbage strings that still pass the trailing
/// regex (e.g. `"not-a-dateT00:00:00Z"`).
fn chrono_free_parse_ok(value: &str) -> bool {
    let re = Regex::new(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$",
    )
    .unwrap();
    re.is_match(value)
}

/// Faithful port of `validateSchema`.
pub fn validate_schema(schema: &Value, value: &Value) -> Vec<String> {
    validate_schema_at(schema, value, "$", schema)
}

fn validate_schema_at(schema: &Value, value: &Value, path: &str, root: &Value) -> Vec<String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return validate_schema_at(resolve_ref(root, reference), value, path, root);
    }

    let mut issues = Vec::new();

    if let Some(if_schema) = schema.get("if") {
        if validate_schema_at(if_schema, value, path, root).is_empty() {
            if let Some(then_schema) = schema.get("then") {
                issues.extend(validate_schema_at(then_schema, value, path, root));
            }
        }
    }

    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for branch in all_of {
            issues.extend(validate_schema_at(branch, value, path, root));
        }
    }

    if let Some(constant) = schema.get("const") {
        if value != constant {
            issues.push(format!("{path}:const"));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            issues.push(format!("{path}:enum"));
        }
    }
    if let Some(ty) = schema.get("type") {
        if !type_matches(value, ty) {
            issues.push(format!("{path}:type"));
            return issues;
        }
    }

    if let Some(s) = value.as_str() {
        if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
            if (s.chars().count() as u64) < min {
                issues.push(format!("{path}:min-length"));
            }
        }
        if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
            if (s.chars().count() as u64) > max {
                issues.push(format!("{path}:max-length"));
            }
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            let re = Regex::new(pattern).unwrap_or_else(|e| panic!("invalid pattern {pattern}: {e}"));
            if !re.is_match(s) {
                issues.push(format!("{path}:pattern"));
            }
        }
        if schema.get("format").and_then(Value::as_str) == Some("date-time") && !date_time_matches(s) {
            issues.push(format!("{path}:format"));
        }
    }

    if let Some(n) = value.as_f64() {
        if value.is_number() {
            if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
                if n < min {
                    issues.push(format!("{path}:minimum"));
                }
            }
            if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
                if n > max {
                    issues.push(format!("{path}:maximum"));
                }
            }
        }
    }

    if let Some(arr) = value.as_array() {
        if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
            if (arr.len() as u64) < min {
                issues.push(format!("{path}:min-items"));
            }
        }
        if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
            if (arr.len() as u64) > max {
                issues.push(format!("{path}:max-items"));
            }
        }
        if let Some(items_schema) = schema.get("items") {
            for (index, item) in arr.iter().enumerate() {
                let child_path = format!("{path}[{index}]");
                issues.extend(validate_schema_at(items_schema, item, &child_path, root));
            }
        }
    }

    if let Some(obj) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required {
                if let Some(key) = key.as_str() {
                    if !obj.contains_key(key) {
                        issues.push(format!("{path}.{key}:required"));
                    }
                }
            }
        }
        let allowed: std::collections::HashSet<&str> = schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|props| props.keys().map(String::as_str).collect())
            .unwrap_or_default();
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            for key in obj.keys() {
                if !allowed.contains(key.as_str()) {
                    issues.push(format!("{path}.{key}:additional-property"));
                }
            }
        }
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            for (key, child_schema) in props {
                if let Some(child_value) = obj.get(key) {
                    let child_path = format!("{path}.{key}");
                    issues.extend(validate_schema_at(child_schema, child_value, &child_path, root));
                }
            }
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn const_mismatch_reports_path_const() {
        let schema = json!({ "const": "legion-book-qualification" });
        assert_eq!(validate_schema(&schema, &json!("other")), vec!["$:const"]);
        assert!(validate_schema(&schema, &json!("legion-book-qualification")).is_empty());
    }

    #[test]
    fn enum_mismatch_reports_path_enum() {
        let schema = json!({ "enum": ["a", "b"] });
        assert_eq!(validate_schema(&schema, &json!("c")), vec!["$:enum"]);
    }

    #[test]
    fn type_mismatch_short_circuits_remaining_string_checks() {
        let schema = json!({ "type": "string", "minLength": 5 });
        // A number value fails `type` and must not also emit `min-length`.
        assert_eq!(validate_schema(&schema, &json!(1)), vec!["$:type"]);
    }

    #[test]
    fn integer_type_rejects_fractional_number() {
        let schema = json!({ "type": "integer" });
        assert_eq!(validate_schema(&schema, &json!(1.5)), vec!["$:type"]);
        assert!(validate_schema(&schema, &json!(1)).is_empty());
    }

    #[test]
    fn required_and_additional_properties() {
        let schema = json!({
            "type": "object",
            "required": ["id"],
            "additionalProperties": false,
            "properties": { "id": { "type": "string" } },
        });
        let issues = validate_schema(&schema, &json!({ "extra": 1 }));
        assert!(issues.contains(&"$.id:required".to_string()));
        assert!(issues.contains(&"$.extra:additional-property".to_string()));
    }

    #[test]
    fn nested_property_path_is_dotted() {
        let schema = json!({
            "type": "object",
            "properties": { "task": { "type": "object", "properties": { "id": { "type": "string" } } } },
        });
        let issues = validate_schema(&schema, &json!({ "task": { "id": 1 } }));
        assert_eq!(issues, vec!["$.task.id:type"]);
    }

    #[test]
    fn array_items_are_indexed_in_path() {
        let schema = json!({ "type": "array", "items": { "type": "string" } });
        let issues = validate_schema(&schema, &json!(["a", 1]));
        assert_eq!(issues, vec!["$[1]:type"]);
    }

    #[test]
    fn ref_resolves_through_defs() {
        let schema = json!({
            "$defs": { "id": { "type": "string" } },
            "properties": { "id": { "$ref": "#/$defs/id" } },
        });
        let issues = validate_schema(&schema, &json!({ "id": 1 }));
        assert_eq!(issues, vec!["$.id:type"]);
    }

    #[test]
    fn if_then_is_evaluated_eagerly() {
        let schema = json!({
            "if": { "properties": { "decision": { "const": "BLOCKED" } } },
            "then": { "required": ["blockers"] },
        });
        let issues = validate_schema(&schema, &json!({ "decision": "BLOCKED" }));
        assert_eq!(issues, vec!["$.blockers:required"]);
        assert!(validate_schema(&schema, &json!({ "decision": "OTHER" })).is_empty());
    }

    #[test]
    fn date_time_format_accepts_rfc3339() {
        let schema = json!({ "type": "string", "format": "date-time" });
        assert!(validate_schema(&schema, &json!("2026-09-23T00:00:00Z")).is_empty());
        assert_eq!(
            validate_schema(&schema, &json!("not-a-date")),
            vec!["$:format"]
        );
    }
}
