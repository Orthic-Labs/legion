//! Local port of `src/providers/runtime/web/shared.mjs` (and the small
//! `verifyDataExercise`/`digest`/`kind`/`schemaVersion` stripping shim of
//! `src/providers/runtime/service/data/index.mjs`), scoped to this wf047
//! module. This crate does not carry an existing native shared-runtime
//! helper module for these exact `finalize`/`denominator`/`sameBinding`/
//! `exactBinding`/`sortById`/`redact`/`canonicalize`/`digest` semantics
//! (confirmed by `git grep` across `engine/` for these identifiers before
//! writing this file), so the wf047 chunk carries its own faithful copy
//! rather than reaching into another owner's file.

use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

pub const BINDING_KEYS: &[&str] = &[
    "targetId",
    "environment",
    "actorId",
    "tenantId",
    "browser",
    "browserVersion",
    "viewport",
    "locale",
    "sourceRevision",
    "artifactDigest",
];

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Port of JS `opaque(type, value)`: `opaque-${sha256(type:value).slice(0,24)}`.
fn opaque(kind: &str, value: &str) -> String {
    let full = sha256_hex(format!("{kind}:{value}").as_bytes());
    format!("opaque-{}", &full[..24.min(full.len())])
}

/// Port of `canonicalize(value, seen)`. `serde_json::Value` has no
/// `undefined`/`bigint`/`symbol`/`function` variants, so those branches are
/// unreachable for JSON input; cycles cannot occur in `serde_json::Value`
/// either (it is a tree), so the `seen` map is omitted — behaviourally
/// identical on all JSON-representable input, which is this port's entire
/// domain.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Port of `digest(value)`.
pub fn digest(value: &Value) -> String {
    let canonical = canonicalize(value);
    let json = serde_json::to_string(&canonical).unwrap_or_default();
    format!("sha256:{}", sha256_hex(json.as_bytes()))
}

fn json_cmp_key(value: &Value) -> String {
    serde_json::to_string(&canonicalize(value)).unwrap_or_default()
}

fn item_sort_id(value: &Value) -> String {
    let obj = value.as_object();
    let text = |k: &str| obj.and_then(|m| m.get(k)).and_then(Value::as_str);
    text("id")
        .or_else(|| text("controlId"))
        .or_else(|| text("name"))
        .unwrap_or("")
        .to_string()
}

/// Port of `sortById(values)`.
pub fn sort_by_id(values: &[Value]) -> Vec<Value> {
    let mut out = values.to_vec();
    out.sort_by(|left, right| {
        item_sort_id(left)
            .cmp(&item_sort_id(right))
            .then_with(|| json_cmp_key(left).cmp(&json_cmp_key(right)))
    });
    out
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

const SENSITIVE_KEYS: &[&str] = &[
    "apikey",
    "apitoken",
    "authorization",
    "authorizationheader",
    "clientsecret",
    "cookie",
    "email",
    "password",
    "passwd",
    "phone",
    "privatekey",
    "secret",
    "sessioncookie",
    "setcookie",
    "token",
    "accesstoken",
    "refreshtoken",
];
const SENSITIVE_SUFFIXES: &[&str] = &[
    "apikey",
    "authorization",
    "cookie",
    "password",
    "passwd",
    "privatekey",
    "secret",
    "secretkey",
    "token",
];

fn sensitive_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    SENSITIVE_KEYS.contains(&normalized.as_str())
        || SENSITIVE_SUFFIXES.iter().any(|suffix| normalized.ends_with(suffix))
}

/// Port of `exactBinding(binding)`.
pub struct ExactBinding {
    pub binding: Value,
    pub gaps: Vec<String>,
}

fn is_valid_binding_value(value: &Value) -> bool {
    match value.as_str() {
        Some(s) if !s.is_empty() && s.len() <= 128 => {
            let mut chars = s.chars();
            let first = chars.next().unwrap();
            let first_ok = first.is_ascii_alphanumeric();
            let rest_ok = chars.all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-')
            });
            first_ok && rest_ok
        }
        _ => false,
    }
}

pub fn exact_binding(binding: &Value) -> ExactBinding {
    let source = if binding.is_object() { binding.clone() } else { Value::Object(Map::new()) };
    let source_map = source.as_object().cloned().unwrap_or_default();

    let mut invalid: Vec<&str> = BINDING_KEYS
        .iter()
        .copied()
        .filter(|key| !source_map.get(*key).is_some_and(is_valid_binding_value))
        .collect();
    invalid.sort();

    let extras: Vec<String> = source_map
        .keys()
        .filter(|key| !BINDING_KEYS.contains(&key.as_str()))
        .cloned()
        .collect();

    let mut sorted_keys: Vec<&str> = BINDING_KEYS.to_vec();
    sorted_keys.sort();
    let mut normalized = Map::new();
    for key in sorted_keys {
        let value = if invalid.contains(&key) {
            let raw = source_map.get(key).cloned().unwrap_or(Value::Null);
            let canonical_json = serde_json::to_string(&canonicalize(&raw)).unwrap_or_default();
            Value::String(opaque("binding", &canonical_json))
        } else {
            source_map.get(key).cloned().unwrap_or(Value::Null)
        };
        normalized.insert(key.to_string(), value);
    }

    let mut gaps: Vec<String> = invalid.iter().map(|s| s.to_string()).collect();
    if extras.iter().any(|key| sensitive_key(key)) {
        gaps.push("binding-extra-sensitive".to_string());
    }
    if extras.iter().any(|key| !sensitive_key(key)) {
        gaps.push("binding-extra-undeclared".to_string());
    }

    ExactBinding { binding: Value::Object(normalized), gaps }
}

/// Port of `sameBinding(expected, actual)`.
pub fn same_binding(expected: &Value, actual: &Value) -> bool {
    let e = expected.as_object();
    let a = actual.as_object();
    BINDING_KEYS.iter().all(|key| {
        let ev = e.and_then(|m| m.get(*key)).cloned().unwrap_or(Value::Null);
        let av = a.and_then(|m| m.get(*key)).cloned().unwrap_or(Value::Null);
        ev == av
    })
}

static SENSITIVE_VALUE_EMAIL: &str = r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}";
static SENSITIVE_VALUE_BEARER: &str = r"(?i)bearer\s+\S+";

/// Port of `redact(value, key, seen)`. `serde_json::Value` cannot cycle, so
/// the `seen` guard is unnecessary here (see `canonicalize`'s note).
pub fn redact(value: &Value, key: &str) -> Value {
    // JS: `!value || typeof value !== 'object' || Array.isArray(value)`.
    // In JSON terms: not an object, or is an array (objects are never
    // "falsy" in JS; `null`'s `typeof` is `'object'` but `!value` is true).
    if sensitive_key(key) && !value.is_object() {
        return Value::String("[REDACTED]".to_string());
    }
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| redact(item, "")).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), redact(v, k));
            }
            Value::Object(out)
        }
        Value::String(s) => {
            let bearer_re = regex::Regex::new(SENSITIVE_VALUE_BEARER).unwrap();
            let email_re = regex::Regex::new(SENSITIVE_VALUE_EMAIL).unwrap();
            let replaced = bearer_re.replace_all(s, "[REDACTED]");
            let replaced = email_re.replace_all(&replaced, "[REDACTED]");
            Value::String(replaced.into_owned())
        }
        other => other.clone(),
    }
}

/// Port of `denominator(expected, receipts, omitted)`.
pub struct Denominator {
    pub total: usize,
    pub accounted: usize,
    pub receipts: usize,
    pub omitted: usize,
    pub missing: Vec<String>,
    pub expected_ids: Vec<String>,
}

pub fn denominator(expected: &[String], receipt_ids: &[String], omitted_ids: &[String]) -> Denominator {
    let mut expected_ids: Vec<String> = expected.to_vec();
    expected_ids.sort();
    expected_ids.dedup();

    let receipt_set: std::collections::HashSet<&String> = receipt_ids.iter().collect();
    let omitted_set: std::collections::HashSet<&String> = omitted_ids.iter().collect();

    let missing: Vec<String> = expected_ids
        .iter()
        .filter(|id| !receipt_set.contains(id) && !omitted_set.contains(id))
        .cloned()
        .collect();

    Denominator {
        total: expected_ids.len(),
        accounted: expected_ids.len() - missing.len(),
        receipts: receipt_set.len(),
        omitted: omitted_set.len(),
        missing,
        expected_ids,
    }
}

impl Denominator {
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "total": self.total,
            "accounted": self.accounted,
            "receipts": self.receipts,
            "omitted": self.omitted,
            "missing": self.missing,
            "expectedIds": self.expected_ids,
        })
    }
}

/// Port of `finalize(kind, value)`. `value` must be a JSON object; panics
/// (mirroring an unrecoverable programmer error, not a data-shape gap) if
/// it is not — every call site in this module passes an object literal, as
/// in JS.
pub fn finalize(kind: &str, value: Value) -> Value {
    let mut binding_gaps: Vec<String> = Vec::new();

    fn normalize_bindings(current: &Value, key: &str, binding_gaps: &mut Vec<String>) -> Value {
        if key == "binding" {
            let result = exact_binding(current);
            binding_gaps.extend(result.gaps);
            return result.binding;
        }
        match current {
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| normalize_bindings(item, "", binding_gaps)).collect())
            }
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for k in keys {
                    out.insert(k.clone(), normalize_bindings(&map[k], k, binding_gaps));
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    let mut safe_value = normalize_bindings(&value, "", &mut binding_gaps);

    if !binding_gaps.is_empty() {
        let obj = safe_value.as_object_mut().expect("finalize value must be an object");
        obj.insert("status".to_string(), Value::String("error".to_string()));
        obj.insert("terminal".to_string(), Value::Bool(true));
        if obj.contains_key("complete") {
            obj.insert("complete".to_string(), Value::Bool(false));
        }
        if obj.contains_key("proof") {
            obj.insert("proof".to_string(), Value::Bool(false));
        }
        let existing: Vec<String> = obj
            .get("coverageGaps")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let mut all_gaps: Vec<String> = existing;
        for gap in &binding_gaps {
            all_gaps.push(if gap.starts_with("binding-extra-") {
                gap.clone()
            } else {
                format!("binding-invalid:{gap}")
            });
        }
        all_gaps.sort();
        all_gaps.dedup();
        obj.insert(
            "coverageGaps".to_string(),
            Value::Array(all_gaps.into_iter().map(Value::String).collect()),
        );
    }

    let mut normalized_obj = Map::new();
    normalized_obj.insert("schemaVersion".to_string(), Value::Number(1.into()));
    normalized_obj.insert("kind".to_string(), Value::String(kind.to_string()));
    if let Value::Object(map) = &safe_value {
        for (k, v) in map {
            if k != "schemaVersion" && k != "kind" {
                normalized_obj.insert(k.clone(), v.clone());
            }
        }
    }
    let normalized = canonicalize(&Value::Object(normalized_obj));
    let digest_value = digest(&normalized);
    let mut out = normalized.as_object().cloned().unwrap_or_default();
    out.insert("digest".to_string(), Value::String(digest_value));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_under_key_order() {
        let a = serde_json::json!({"b": 1, "a": 2});
        let b = serde_json::json!({"a": 2, "b": 1});
        assert_eq!(digest(&a), digest(&b));
    }

    #[test]
    fn sort_by_id_orders_lexically() {
        let values = vec![
            serde_json::json!({"id": "b"}),
            serde_json::json!({"id": "a"}),
        ];
        let sorted = sort_by_id(&values);
        assert_eq!(sorted[0]["id"], "a");
        assert_eq!(sorted[1]["id"], "b");
    }

    #[test]
    fn exact_binding_flags_missing_keys() {
        let result = exact_binding(&serde_json::json!({}));
        assert_eq!(result.gaps.len(), BINDING_KEYS.len());
    }

    #[test]
    fn exact_binding_accepts_full_valid_binding() {
        let mut map = Map::new();
        for key in BINDING_KEYS {
            map.insert(key.to_string(), Value::String("v1".to_string()));
        }
        let result = exact_binding(&Value::Object(map));
        assert!(result.gaps.is_empty());
    }

    #[test]
    fn redact_masks_sensitive_string_field() {
        let value = serde_json::json!({"password": "hunter2", "name": "ok"});
        let redacted = redact(&value, "");
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["name"], "ok");
    }

    #[test]
    fn finalize_marks_error_on_binding_gap() {
        let out = finalize("kind.test", serde_json::json!({"binding": {}, "status": "pass", "terminal": true}));
        assert_eq!(out["status"], "error");
        assert_eq!(out["terminal"], true);
    }
}
