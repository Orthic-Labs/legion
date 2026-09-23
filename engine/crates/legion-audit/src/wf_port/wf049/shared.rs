//! Local port of `src/providers/runtime/web/shared.mjs` and the subset of
//! `src/lib/platform/artifact-sanitize.mjs` used by the wf049 chunk
//! (`infrastructure`, `integration`, `journey-plan`, `matrix`, `operations`).
//!
//! This module is intentionally self-contained: wf049 owns only
//! `wf_port/wf049/**`, so the canonicalize/digest/binding/sanitize primitives
//! that the JS originals share via `../shared.mjs` and
//! `../../../../lib/platform/artifact-sanitize.mjs` are reimplemented here
//! rather than pulled from a shared crate. Semantics match the JS source;
//! byte-identical digests with the JS implementation are not required since
//! `finalize`'s digest is self-referential output, never checked against a
//! value produced by the JS runtime.

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const BINDING_KEYS: [&str; 10] = [
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

fn sorted_binding_keys() -> Vec<&'static str> {
    let mut keys = BINDING_KEYS.to_vec();
    keys.sort_unstable();
    keys
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn opaque(kind: &str, value: &str) -> String {
    let digest = sha256_hex(format!("{kind}:{value}").as_bytes());
    format!("opaque-{}", &digest[..24])
}

/// Port of `canonicalize` in `shared.mjs`: sorts object keys recursively so
/// that `JSON.stringify` output is stable. Arrays and scalars pass through
/// unchanged (unlike `legion-topology::binding::canonicalize`, this does not
/// rewrite backslashes in strings; the JS `shared.mjs` canonicalize does not
/// do that either).
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

/// Port of `digest` in `shared.mjs`.
pub fn digest(value: &Value) -> String {
    let canonical = canonicalize(value);
    let bytes = serde_json::to_string(&canonical).unwrap_or_else(|_| "null".into());
    format!("sha256:{}", sha256_hex(bytes.as_bytes()))
}

fn id_key(value: &Value) -> String {
    value
        .get("id")
        .or_else(|| value.get("controlId"))
        .or_else(|| value.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Port of `sortById` in `shared.mjs`.
pub fn sort_by_id(values: &[Value]) -> Vec<Value> {
    let mut rows: Vec<Value> = values.to_vec();
    rows.sort_by(|left, right| {
        id_key(left).cmp(&id_key(right)).then_with(|| {
            let left_json = serde_json::to_string(&canonicalize(left)).unwrap_or_default();
            let right_json = serde_json::to_string(&canonicalize(right)).unwrap_or_default();
            left_json.cmp(&right_json)
        })
    });
    rows
}

fn binding_value_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$").unwrap())
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

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Port of `sensitiveKey` in `shared.mjs` (used by `exactBinding` for the
/// `binding-extra-sensitive` / `binding-extra-undeclared` gap split). This is
/// distinct from `artifact_common_sensitive_key`, which mirrors the
/// unrelated `commonSensitiveKey` in `artifact-sanitize.mjs`.
pub fn shared_sensitive_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    SENSITIVE_KEYS.contains(&normalized.as_str())
        || SENSITIVE_SUFFIXES.iter().any(|suffix| normalized.ends_with(suffix))
}

pub struct ExactBinding {
    pub binding: Value,
    pub gaps: Vec<String>,
}

/// Port of `exactBinding` in `shared.mjs`.
pub fn exact_binding(binding: &Value) -> ExactBinding {
    let empty = Map::new();
    let source = binding.as_object().unwrap_or(&empty);
    let mut invalid: Vec<String> = Vec::new();
    for key in BINDING_KEYS {
        let valid = source
            .get(key)
            .and_then(Value::as_str)
            .map(|value| binding_value_re().is_match(value))
            .unwrap_or(false);
        if !valid {
            invalid.push(key.to_string());
        }
    }
    let extras: Vec<&String> = source.keys().filter(|key| !BINDING_KEYS.contains(&key.as_str())).collect();
    let mut normalized = Map::new();
    for key in sorted_binding_keys() {
        let value = if invalid.iter().any(|k| k == key) {
            let raw = source.get(key).cloned().unwrap_or(Value::Null);
            Value::String(opaque(
                "binding",
                &serde_json::to_string(&canonicalize(&raw)).unwrap_or_default(),
            ))
        } else {
            source.get(key).cloned().unwrap_or(Value::Null)
        };
        normalized.insert(key.to_string(), value);
    }
    let mut gaps = invalid;
    if extras.iter().any(|key| shared_sensitive_key(key)) {
        gaps.push("binding-extra-sensitive".to_string());
    }
    if extras.iter().any(|key| !shared_sensitive_key(key)) {
        gaps.push("binding-extra-undeclared".to_string());
    }
    ExactBinding {
        binding: Value::Object(normalized),
        gaps,
    }
}

/// Port of `sameBinding` in `shared.mjs`.
pub fn same_binding(expected: &Value, actual: &Value) -> bool {
    BINDING_KEYS.iter().all(|key| expected.get(key) == actual.get(key))
}

pub struct Denominator {
    pub total: usize,
    pub accounted: usize,
    pub receipts: usize,
    pub omitted: usize,
    pub missing: Vec<String>,
    pub expected_ids: Vec<String>,
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

fn receipt_id(value: &Value) -> Option<String> {
    value
        .get("id")
        .or_else(|| value.get("controlId"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Port of `denominator` in `shared.mjs`.
pub fn denominator(expected: &[String], receipts: &[Value], omitted: &[Value]) -> Denominator {
    let mut expected_ids: Vec<String> = expected.to_vec();
    expected_ids.sort();
    expected_ids.dedup();
    let receipt_ids: std::collections::HashSet<String> = receipts.iter().filter_map(receipt_id).collect();
    let omitted_ids: std::collections::HashSet<String> = omitted
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let missing: Vec<String> = expected_ids
        .iter()
        .filter(|id| !receipt_ids.contains(*id) && !omitted_ids.contains(*id))
        .cloned()
        .collect();
    let accounted = expected_ids.len() - missing.len();
    Denominator {
        total: expected_ids.len(),
        accounted,
        receipts: receipt_ids.len(),
        omitted: omitted_ids.len(),
        missing,
        expected_ids,
    }
}

/// Port of `finalize` in `shared.mjs`. `value` must be a JSON object.
pub fn finalize(kind: &str, value: Value) -> Value {
    let mut binding_gaps: Vec<String> = Vec::new();
    let normalized = normalize_bindings(&value, "", &mut binding_gaps);
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
            let mut existing: Vec<String> = map
                .get("coverageGaps")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            for gap in &binding_gaps {
                let prefixed = if gap.starts_with("binding-extra-") {
                    gap.clone()
                } else {
                    format!("binding-invalid:{gap}")
                };
                existing.push(prefixed);
            }
            existing.sort();
            existing.dedup();
            map.insert(
                "coverageGaps".to_string(),
                Value::Array(existing.into_iter().map(Value::String).collect()),
            );
        }
    }
    let mut base = Map::new();
    base.insert("schemaVersion".to_string(), Value::from(1));
    base.insert("kind".to_string(), Value::String(kind.to_string()));
    if let Value::Object(map) = safe_value {
        for (key, val) in map {
            base.insert(key, val);
        }
    }
    let normalized = canonicalize(&Value::Object(base));
    let digest_value = digest(&normalized);
    let mut out = normalized.as_object().cloned().unwrap_or_default();
    out.insert("digest".to_string(), Value::String(digest_value));
    Value::Object(out)
}

fn normalize_bindings(value: &Value, key: &str, gaps: &mut Vec<String>) -> Value {
    if key == "binding" {
        let result = exact_binding(value);
        gaps.extend(result.gaps);
        return result.binding;
    }
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| normalize_bindings(item, "", gaps)).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), normalize_bindings(&map[k], k, gaps));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// artifact-sanitize.mjs (the subset used by wf049)
// ---------------------------------------------------------------------------

fn base64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$").unwrap())
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Minimal RFC 4648 base64 encoder (standard alphabet, padded). Used because
/// no base64 crate is currently a dependency of `legion-audit`.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        out.push(B64_ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { B64_ALPHABET[(n >> 6 & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_ALPHABET[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// Minimal RFC 4648 base64 decoder (standard alphabet). Returns `None` on
/// malformed input (wrong length, invalid characters, or invalid padding).
pub fn base64_decode(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    if value.len() % 4 != 0 {
        return None;
    }
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 || chunk[..chunk.len() - pad].iter().any(|&c| c == b'=') {
            return None;
        }
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' { 0 } else { val(c)? };
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Port of `isCanonicalBase64` in `artifact-sanitize.mjs`.
pub fn is_canonical_base64(value: &str) -> bool {
    if !base64_re().is_match(value) {
        return false;
    }
    match base64_decode(value) {
        Some(bytes) => base64_encode(&bytes) == value,
        None => false,
    }
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}").unwrap())
}
fn bearer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{4,}").unwrap())
}
fn ssn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap())
}
fn phone_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:\+\d[\d\s().-]{6,}\d|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b|\(\d{3}\)\s*\d{3}[-.\s]\d{4}\b)").unwrap()
    })
}

fn sanitize_string(value: &str) -> String {
    let value = bearer_re().replace_all(value, "[REDACTED]");
    let value = email_re().replace_all(&value, "[REDACTED]");
    let value = ssn_re().replace_all(&value, "[REDACTED]");
    let value = phone_re().replace_all(&value, "[REDACTED]");
    value.into_owned()
}

const COMMON_SENSITIVE_LIST: &[&str] = &["email", "phone", "phonenumber", "ssn", "socialsecuritynumber", "taxid"];

fn common_sensitive_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:secret|password|token|privatekey|apikey|cookie|authorization)$").unwrap())
}

/// Port of `commonSensitiveKey` in `artifact-sanitize.mjs`.
pub fn artifact_common_sensitive_key(normalized_key: &str) -> bool {
    common_sensitive_key_re().is_match(normalized_key) || COMMON_SENSITIVE_LIST.contains(&normalized_key)
}

fn trailing_identifier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z_$][A-Za-z0-9_$-]*$").unwrap())
}

/// Port of `configuredKeys` in `artifact-sanitize.mjs`.
pub fn configured_keys(fields: &Value) -> Vec<String> {
    let Some(array) = fields.as_array() else { return Vec::new() };
    array
        .iter()
        .filter_map(|field| {
            let raw = if let Some(s) = field.as_str() {
                Some(s.to_string())
            } else {
                field
                    .get("path")
                    .or_else(|| field.get("key"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            raw.map(|field| {
                let tail = trailing_identifier_re()
                    .find(&field)
                    .map(|m| m.as_str())
                    .unwrap_or(&field);
                normalized_key(tail)
            })
        })
        .collect()
}

struct SanitizeState {
    changed: bool,
}

fn sanitize_value(value: &Value, configured: &[String], state: &mut SanitizeState) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| sanitize_value(item, configured, state)).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, child) in map {
                let normalized = normalized_key(key);
                if artifact_common_sensitive_key(&normalized) || configured.iter().any(|c| c == &normalized) {
                    if child.as_str() != Some("[REDACTED]") {
                        state.changed = true;
                    }
                    out.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    out.insert(key.clone(), sanitize_value(child, configured, state));
                }
            }
            Value::Object(out)
        }
        Value::String(s) => {
            let sanitized = sanitize_string(s);
            if sanitized != *s {
                state.changed = true;
            }
            Value::String(sanitized)
        }
        other => other.clone(),
    }
}

/// Port of `sanitizeSensitiveValue` in `artifact-sanitize.mjs`.
pub fn sanitize_sensitive_value(value: &Value, sensitive_fields: &Value) -> (Value, bool) {
    let configured = configured_keys(sensitive_fields);
    let mut state = SanitizeState { changed: false };
    let sanitized = sanitize_value(value, &configured, &mut state);
    (sanitized, state.changed)
}

/// Port of `sanitizeArtifactContent` in `artifact-sanitize.mjs`.
/// Returns `(artifact_or_null, sensitive, invalid)`.
pub fn sanitize_artifact_content(artifact: &Value, sensitive_fields: &Value) -> (Option<Value>, bool, bool) {
    let Some(_) = artifact.as_object() else {
        return (Some(artifact.clone()), false, false);
    };
    let has_content = artifact.get("content").and_then(Value::as_str).is_some();
    let has_bytes = artifact.get("bytesBase64").and_then(Value::as_str).is_some();
    if has_content == has_bytes {
        return (Some(artifact.clone()), false, false);
    }
    if has_bytes {
        let bytes_b64 = artifact.get("bytesBase64").and_then(Value::as_str).unwrap();
        if !is_canonical_base64(bytes_b64) {
            return (None, true, true);
        }
    }
    let original = if has_content {
        artifact.get("content").and_then(Value::as_str).unwrap().to_string()
    } else {
        let bytes = base64_decode(artifact.get("bytesBase64").and_then(Value::as_str).unwrap()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let configured = configured_keys(sensitive_fields);
    let mut state = SanitizeState { changed: false };
    let sanitized = match serde_json::from_str::<Value>(&original) {
        Ok(parsed) => {
            let out = sanitize_value(&parsed, &configured, &mut state);
            serde_json::to_string(&out).unwrap_or_default()
        }
        Err(_) => {
            let out = sanitize_string(&original);
            state.changed = out != original;
            out
        }
    };
    if !state.changed {
        return (Some(artifact.clone()), false, false);
    }
    let mut rest = artifact.as_object().cloned().unwrap_or_default();
    rest.remove("content");
    rest.remove("bytesBase64");
    rest.remove("digest");
    rest.insert("content".to_string(), Value::String(sanitized.clone()));
    rest.insert(
        "digest".to_string(),
        Value::String(format!("sha256:{}", sha256_hex(sanitized.as_bytes()))),
    );
    (Some(Value::Object(rest)), true, false)
}

/// Port of `sanitizeProducedArtifact` in `artifact-sanitize.mjs`.
/// Returns `(artifact_or_null, valid, sensitive)`.
pub fn sanitize_produced_artifact(artifact: &Value, sensitive_fields: &Value) -> (Option<Value>, bool, bool) {
    if artifact.as_object().is_none() {
        return (None, false, false);
    }
    let has_content = artifact.get("content").and_then(Value::as_str).is_some();
    let has_bytes = artifact.get("bytesBase64").and_then(Value::as_str).is_some();
    if has_content == has_bytes {
        return (None, false, false);
    }
    let bytes: Option<Vec<u8>> = if has_content {
        Some(artifact.get("content").and_then(Value::as_str).unwrap().as_bytes().to_vec())
    } else {
        let b64 = artifact.get("bytesBase64").and_then(Value::as_str).unwrap();
        if is_canonical_base64(b64) {
            base64_decode(b64)
        } else {
            None
        }
    };
    let Some(bytes) = bytes else {
        return (None, false, false);
    };
    if bytes.is_empty() {
        return (None, false, false);
    }
    let expected_digest = format!("sha256:{}", sha256_hex(&bytes));
    if artifact.get("digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
        return (None, false, false);
    }
    let (sanitized_artifact, sensitive, _invalid) = sanitize_artifact_content(artifact, sensitive_fields);
    (sanitized_artifact, true, sensitive)
}

/// Port of `safePath` shared by `infrastructure/index.mjs`,
/// `integration/index.mjs`, and `operations/index.mjs`.
pub fn safe_path(value: &Value) -> bool {
    let Some(value) = value.as_str() else { return false };
    if value.is_empty() || value.contains('\\') || value.starts_with('/') {
        return false;
    }
    if windows_drive_re().is_match(value) {
        return false;
    }
    let segments: Vec<&str> = value.split('/').collect();
    if segments.len() <= 1 {
        return false;
    }
    let segment_re = segment_re();
    segments.iter().all(|segment| segment_re.is_match(segment) && *segment != "." && *segment != "..")
        && segments.join("/") == value
}

fn windows_drive_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z]:").unwrap())
}
fn segment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap())
}

/// Port of `utcMillis` shared by `infrastructure/index.mjs` and
/// `operations/index.mjs`. Returns `None` for anything that is not a
/// canonical `YYYY-MM-DDTHH:MM:SS[.sss]Z` string with a parseable date.
pub fn utc_millis(value: Option<&str>) -> Option<i64> {
    let value = value?;
    if !utc_millis_re().is_match(value) {
        return None;
    }
    // `YYYY-MM-DDTHH:MM:SS(.sss)?Z`; parse manually to avoid a chrono
    // dependency this crate does not currently have.
    let date_part = &value[0..10];
    let time_part = &value[11..19];
    let millis: i64 = if value.len() > 20 {
        value[20..value.len() - 1].parse().ok()?
    } else {
        0
    };
    let year: i32 = date_part[0..4].parse().ok()?;
    let month: u32 = date_part[5..7].parse().ok()?;
    let day: u32 = date_part[8..10].parse().ok()?;
    let hour: i64 = time_part[0..2].parse().ok()?;
    let minute: i64 = time_part[3..5].parse().ok()?;
    let second: i64 = time_part[6..8].parse().ok()?;
    if !(1..=12).contains(&month) || day < 1 {
        return None;
    }
    let days_since_epoch = days_from_civil(year, month, day)?;
    let millis_total = days_since_epoch * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1000 + millis;
    Some(millis_total)
}

fn utc_millis_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$").unwrap())
}

/// Howard Hinnant's civil-from-days algorithm, days since 1970-01-01.
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) {
        return None;
    }
    let y = if m <= 2 { y as i64 - 1 } else { y as i64 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let mp = (m as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    Some(era * 146097 + doe - 719468)
}
