//! Port of `src/lib/qualification/schema-validator.mjs`'s `validateSchema`.
//!
//! A small, dependency-free (beyond `serde_json`/`regex`, both already
//! `legion-policy` dependencies) JSON-Schema subset validator. It walks a
//! schema and a `serde_json::Value` together and returns a flat list of
//! `path:reason` issue strings — never a boolean, never a thrown error for a
//! failed constraint, matching the JS contract exactly: same recursion
//! order, same issue string shapes, same short-circuit on a type mismatch
//! (JS returns `[...issues, `${path}:type`]` immediately once `type` fails,
//! skipping every constraint below it; this port does the same).
//!
//! Supported keywords, matching the JS source 1:1: `$ref` (only `#/...`
//! JSON-pointer-style refs into the root schema — JS `resolveRef` throws on
//! any other form; this port panics the same way, since the JS validator is
//! otherwise infallible), `if`/`then` (evaluated eagerly), `allOf`, `const`,
//! `enum`, `type` (single type or an array of alternatives), string
//! `minLength`/`maxLength`/`pattern`/`format: date-time`, number
//! `minimum`/`maximum`, array `minItems`/`maxItems`/`items`, and object
//! `required`/`additionalProperties: false`/`properties`.
//!
//! A second, independently-shipped copy of this same JS source exists at
//! `engine/crates/legion-audit/src/wf_port/wf014/schema_validator.rs`
//! (a different crate; `legion-policy` cannot depend on `legion-audit`
//! without a dependency-graph inversion, so this chunk ports it again here
//! rather than reaching across crates it does not own).

use regex::Regex;
use serde_json::Value;

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

fn type_matches(value: &Value, ty: &Value) -> bool {
    if let Some(list) = ty.as_array() {
        return list.iter().any(|candidate| type_matches(value, candidate));
    }
    let Some(name) = ty.as_str() else { return false };
    match name {
        "null" => value.is_null(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "integer" => match value {
            Value::Number(n) => {
                n.as_i64().is_some()
                    || n.as_u64().is_some()
                    || n.as_f64().is_some_and(|f| f.is_finite() && f.fract() == 0.0)
            }
            _ => false,
        },
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        _ => false,
    }
}

/// JS `dateTimeMatches`: `Number.isFinite(Date.parse(value))` and the value
/// ends with a `T`-separated time zone offset or `Z`. This port checks a
/// concrete RFC 3339 grammar, which is the shape every producer in this repo
/// emits (`new Date().toISOString()`), plus offset forms.
fn date_time_matches(value: &str) -> bool {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$").unwrap()
    });
    re.is_match(value)
}

/// Faithful port of `validateSchema(schema, value, path = '$', root = schema)`.
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

    if value.is_number() {
        let n = value.as_f64().unwrap_or(f64::NAN);
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
        let schema = json!({ "const": "x" });
        assert_eq!(validate_schema(&schema, &json!("other")), vec!["$:const"]);
    }

    #[test]
    fn type_mismatch_short_circuits() {
        let schema = json!({ "type": "string", "minLength": 5 });
        assert_eq!(validate_schema(&schema, &json!(1)), vec!["$:type"]);
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
    fn date_time_format() {
        let schema = json!({ "type": "string", "format": "date-time" });
        assert!(validate_schema(&schema, &json!("2026-09-23T00:00:00Z")).is_empty());
        assert_eq!(validate_schema(&schema, &json!("not-a-date")), vec!["$:format"]);
    }
}
