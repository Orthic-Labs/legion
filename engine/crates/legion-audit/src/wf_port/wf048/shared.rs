//! Port of `src/providers/runtime/web/shared.mjs` (chunk wf048 support).
//!
//! These are the untyped JSON helpers every `src/providers/runtime/web/*`
//! module composes with (`finalize`, `exactBinding`, `sameBinding`,
//! `denominator`, `redact`, `sortById`, `canonicalize`/`digest`). They are
//! reproduced here, scoped to `wf048`, because `shared.mjs` itself is not
//! part of this chunk's owned file list; if another chunk ports it to a
//! shared location first, this copy should be collapsed onto that one.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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

fn opaque(kind: &str, value: &str) -> String {
    let hash = Sha256::digest(format!("{kind}:{value}").as_bytes());
    format!("opaque-{}", hex::encode(hash)[..24].to_string())
}

/// Port of `canonicalize(value)`: deep-sorts object keys and replaces
/// non-JSON-safe primitives (bigint/symbol/function/undefined) and cycles
/// with stable opaque placeholders.
pub fn canonicalize(value: &Value) -> Value {
    canonicalize_inner(value, &mut Vec::new())
}

fn canonicalize_inner(value: &Value, seen: &mut Vec<*const Value>) -> Value {
    match value {
        Value::Array(items) => {
            let ptr = value as *const Value;
            if seen.contains(&ptr) {
                return Value::String(opaque("cycle", &format!("{:p}", ptr)));
            }
            seen.push(ptr);
            let out = Value::Array(items.iter().map(|item| canonicalize_inner(item, seen)).collect());
            seen.pop();
            out
        }
        Value::Object(map) => {
            let ptr = value as *const Value;
            if seen.contains(&ptr) {
                return Value::String(opaque("cycle", &format!("{:p}", ptr)));
            }
            seen.push(ptr);
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize_inner(&map[key], seen));
            }
            seen.pop();
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Port of `digest(value)`: sha256 of `JSON.stringify(canonicalize(value))`.
pub fn digest(value: &Value) -> String {
    let canonical = canonicalize(value);
    let text = serde_json::to_string(&canonical).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())))
}

fn sort_key(value: &Value) -> String {
    for key in ["id", "controlId", "name"] {
        if let Some(s) = value.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    String::new()
}

/// Port of `sortById(values)`.
pub fn sort_by_id(values: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = values.to_vec();
    out.sort_by(|left, right| {
        sort_key(left)
            .cmp(&sort_key(right))
            .then_with(|| {
                let l = serde_json::to_string(&canonicalize(left)).unwrap_or_default();
                let r = serde_json::to_string(&canonicalize(right)).unwrap_or_default();
                l.cmp(&r)
            })
    });
    out
}

fn valid_binding_value(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
}

fn normalized_sensitive_key(key: &str) -> String {
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

pub fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalized_sensitive_key(key);
    SENSITIVE_KEYS.contains(&normalized.as_str())
        || SENSITIVE_SUFFIXES.iter().any(|suffix| normalized.ends_with(suffix))
}

pub struct ExactBindingResult {
    pub binding: Value,
    pub gaps: Vec<String>,
}

/// Port of `exactBinding(binding)`.
pub fn exact_binding(binding: &Value) -> ExactBindingResult {
    let source = if binding.is_object() { binding.clone() } else { Value::Object(Map::new()) };
    let obj = source.as_object().cloned().unwrap_or_default();
    let mut invalid: Vec<&str> = Vec::new();
    for key in BINDING_KEYS {
        match obj.get(*key).and_then(Value::as_str) {
            Some(v) if valid_binding_value(v) => {}
            _ => invalid.push(key),
        }
    }
    let extras: Vec<&String> = obj.keys().filter(|k| !BINDING_KEYS.contains(&k.as_str())).collect();
    let mut sorted_keys: Vec<&str> = BINDING_KEYS.to_vec();
    sorted_keys.sort_unstable();
    let mut normalized = Map::new();
    for key in sorted_keys {
        let value = if invalid.contains(&key) {
            let raw = obj.get(key).cloned().unwrap_or(Value::Null);
            Value::String(opaque(
                "binding",
                &serde_json::to_string(&canonicalize(&raw)).unwrap_or_default(),
            ))
        } else {
            obj.get(key).cloned().unwrap_or(Value::Null)
        };
        normalized.insert(key.to_string(), value);
    }
    let mut gaps: Vec<String> = invalid.iter().map(|s| s.to_string()).collect();
    if extras.iter().any(|k| is_sensitive_key(k)) {
        gaps.push("binding-extra-sensitive".to_string());
    }
    if extras.iter().any(|k| !is_sensitive_key(k)) {
        gaps.push("binding-extra-undeclared".to_string());
    }
    ExactBindingResult { binding: Value::Object(normalized), gaps }
}

/// Port of `sameBinding(expected, actual)`.
pub fn same_binding(expected: &Value, actual: &Value) -> bool {
    BINDING_KEYS.iter().all(|key| expected.get(*key) == actual.get(*key))
}

/// Port of `redact(value, key)`.
pub fn redact(value: &Value) -> Value {
    redact_inner(value, "")
}

fn redact_inner(value: &Value, key: &str) -> Value {
    if is_sensitive_key(key) && !matches!(value, Value::Object(_)) {
        return Value::String("[REDACTED]".to_string());
    }
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| redact_inner(item, "")).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), redact_inner(v, k));
            }
            Value::Object(out)
        }
        Value::String(s) => Value::String(redact_sensitive_substrings(s)),
        other => other.clone(),
    }
}

fn redact_sensitive_substrings(input: &str) -> String {
    // Port of SENSITIVE_VALUE = /(bearer\s+\S+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/gi
    // Implemented without a regex crate dependency, matching the same two
    // alternatives token-by-token.
    let mut out = String::with_capacity(input.len());
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(end) = match_bearer(&bytes, i) {
            out.push_str("[REDACTED]");
            i = end;
            continue;
        }
        if let Some(end) = match_email(&bytes, i) {
            out.push_str("[REDACTED]");
            i = end;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn match_bearer(chars: &[char], start: usize) -> Option<usize> {
    let word = "bearer";
    if start + word.len() > chars.len() {
        return None;
    }
    let candidate: String = chars[start..start + word.len()].iter().collect::<String>().to_lowercase();
    if candidate != word {
        return None;
    }
    let mut i = start + word.len();
    let ws_start = i;
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    if i == ws_start {
        return None;
    }
    let token_start = i;
    while i < chars.len() && !chars[i].is_whitespace() {
        i += 1;
    }
    if i == token_start {
        return None;
    }
    Some(i)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '.' || c == '+' || c == '-'
}

fn match_email(chars: &[char], start: usize) -> Option<usize> {
    if !is_word_char(chars[start]) {
        return None;
    }
    let mut i = start;
    while i < chars.len() && is_word_char(chars[i]) {
        i += 1;
    }
    if i >= chars.len() || chars[i] != '@' {
        return None;
    }
    i += 1;
    let domain_start = i;
    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '.' || chars[i] == '-') {
        i += 1;
    }
    if i == domain_start {
        return None;
    }
    // must end with `.` + 2+ alpha chars, matching within what was consumed.
    let consumed: String = chars[domain_start..i].iter().collect();
    let last_dot = consumed.rfind('.')?;
    let tld = &consumed[last_dot + 1..];
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(i)
}

pub struct DenominatorCounts {
    pub total: usize,
    pub accounted: usize,
    pub receipts: usize,
    pub omitted: usize,
    pub missing: Vec<String>,
    pub expected_ids: Vec<String>,
}

impl DenominatorCounts {
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

/// Port of `denominator(expected, receipts, omitted)`.
pub fn denominator(expected: &[String], receipt_ids: &[String], omitted_ids: &[String]) -> DenominatorCounts {
    let mut expected_ids: Vec<String> = expected.iter().cloned().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    expected_ids.sort();
    let receipt_set: std::collections::HashSet<&String> = receipt_ids.iter().collect();
    let omitted_set: std::collections::HashSet<&String> = omitted_ids.iter().collect();
    let missing: Vec<String> = expected_ids
        .iter()
        .filter(|id| !receipt_set.contains(id) && !omitted_set.contains(id))
        .cloned()
        .collect();
    DenominatorCounts {
        total: expected_ids.len(),
        accounted: expected_ids.len() - missing.len(),
        receipts: receipt_set.len(),
        omitted: omitted_set.len(),
        missing,
        expected_ids,
    }
}

/// Port of `finalize(kind, value)`: normalizes every `binding` field found
/// anywhere in `value` through `exactBinding`, forces the envelope to
/// `error`/`terminal: true` (and `complete: false` / `proof: false` when
/// those keys exist) if any binding was invalid, then wraps the result with
/// `schemaVersion`, `kind`, and a content digest.
pub fn finalize(kind: &str, value: Value) -> Value {
    let mut binding_gaps: Vec<String> = Vec::new();
    let normalized = normalize_bindings(&value, "", &mut binding_gaps, &mut Vec::new());
    let mut safe_value = normalized;
    if !binding_gaps.is_empty() {
        if let Value::Object(map) = &mut safe_value {
            map.insert("status".to_string(), Value::String("error".to_string()));
            map.insert("terminal".to_string(), Value::Bool(true));
            if map.contains_key("complete") {
                map.insert("complete".to_string(), Value::Bool(false));
            }
            if map.contains_key("proof") {
                map.insert("proof".to_string(), Value::Bool(false));
            }
            let mut gaps: Vec<String> = map
                .get("coverageGaps")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            for gap in &binding_gaps {
                let full = if gap.starts_with("binding-extra-") {
                    gap.clone()
                } else {
                    format!("binding-invalid:{gap}")
                };
                if !gaps.contains(&full) {
                    gaps.push(full);
                }
            }
            gaps.sort();
            map.insert("coverageGaps".to_string(), Value::Array(gaps.into_iter().map(Value::String).collect()));
        }
    }
    let mut envelope = Map::new();
    envelope.insert("schemaVersion".to_string(), Value::Number(1.into()));
    envelope.insert("kind".to_string(), Value::String(kind.to_string()));
    if let Value::Object(map) = safe_value {
        for (k, v) in map {
            envelope.insert(k, v);
        }
    }
    let canonical = canonicalize(&Value::Object(envelope));
    let d = digest(&canonical);
    let mut out = canonical.as_object().cloned().unwrap_or_default();
    out.insert("digest".to_string(), Value::String(d));
    Value::Object(out)
}

fn normalize_bindings(current: &Value, key: &str, binding_gaps: &mut Vec<String>, seen: &mut Vec<*const Value>) -> Value {
    if key == "binding" {
        let result = exact_binding(current);
        binding_gaps.extend(result.gaps);
        return result.binding;
    }
    match current {
        Value::Array(items) => {
            let ptr = current as *const Value;
            if seen.contains(&ptr) {
                return Value::String(opaque("cycle", &format!("{:p}", ptr)));
            }
            seen.push(ptr);
            let out = Value::Array(items.iter().map(|item| normalize_bindings(item, "", binding_gaps, seen)).collect());
            seen.pop();
            out
        }
        Value::Object(map) => {
            let ptr = current as *const Value;
            if seen.contains(&ptr) {
                return Value::String(opaque("cycle", &format!("{:p}", ptr)));
            }
            seen.push(ptr);
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), normalize_bindings(&map[k], k, binding_gaps, seen));
            }
            seen.pop();
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub fn binding_missing_gaps(binding: &Value) -> Vec<String> {
    exact_binding(binding).gaps.into_iter().map(|k| format!("binding-missing:{k}")).collect()
}

/// Small convenience used by callers building sorted, de-duplicated gap
/// lists (mirrors the frequent `[...new Set(gaps)].sort()` JS idiom).
pub fn unique_sorted(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

pub type StringMap = BTreeMap<String, Value>;
