//! Rust port of Legion's JS "external evidence" runtime providers.
//!
//! Ports (faithfully, modulo the divergences noted below):
//!   - src/providers/runtime/external-evidence/index.mjs      -> `import_external_evidence`
//!   - src/providers/runtime/external/analytics/index.mjs     -> `verify_analytics_evidence`
//!   - src/providers/runtime/external/backup/index.mjs        -> `verify_backup_evidence`
//!   - src/providers/runtime/external/cloud/index.mjs         -> `verify_cloud_evidence`
//!   - src/providers/runtime/external/commerce/index.mjs      -> `verify_commerce_evidence`
//!   - src/providers/runtime/external/dns/index.mjs           -> `verify_dns_evidence`
//!   - src/providers/runtime/external/email/index.mjs         -> `verify_email_evidence`
//!   - src/providers/runtime/external/incidents/index.mjs     -> `verify_incident_evidence`
//!   - src/providers/runtime/external/third-party/index.mjs   -> `verify_third_party_evidence`
//!
//! plus their shared dependencies:
//!   - src/lib/platform/external/validate.mjs                 -> `validate_external_evidence`
//!   - src/providers/runtime/web/shared.mjs                   -> canonicalize/digest/binding/redact/finalize helpers
//!   - src/providers/runtime/web/third-party/index.mjs        -> `verify_third_party_exercise`
//!   - src/providers/runtime/web/operations/index.mjs         -> `verify_operations_exercise`
//!   - src/providers/runtime/web/infrastructure/index.mjs     -> `verify_infrastructure_exercise`
//!   - src/lib/platform/artifact-sanitize.mjs                 -> sanitize helpers
//!
//! None of these files talk to Membrane or Blueprint; nothing was skipped for that reason.
//!
//! ## Known divergences from the JS source
//!
//! 1. **Signature verification always fails closed.** The JS source verifies Ed25519
//!    signatures over `signedContent` via `node:crypto`'s `verify(null, ...)`, using a PEM
//!    public key. `legion-audit`'s `Cargo.toml` (a shared file this packet may not edit) has
//!    no Ed25519/PEM-capable crypto crate (no `ring`, `ed25519-dalek`, or `pem`/`x509` crate
//!    in `engine/Cargo.lock`). Rather than fabricate a verifier or a pass, every signed
//!    envelope here is treated as unverifiable: it always contributes a `signature-*` gap and
//!    its payload is always treated as absent (`None`), so every downstream check that would
//!    only run "on a verified payload" is structurally unreachable and every evidence-bearing
//!    result is `unproven`/`error`, never a fabricated `pass`. See the inline signature checks
//!    in `validate_external_evidence`, `signed_not_applicable`, `ops_unwrap`, and
//!    `verify_infrastructure_exercise`.
//!    **NEW DEP NEEDED**: `ring` (already in `engine/Cargo.lock` for other crates) or
//!    `ed25519-dalek`, to add real EdDSA verification to `legion-audit/Cargo.toml`.
//! 2. **`digest`/`sha256` hashing is always canonicalized.** The JS `contracts.sha256` hashes
//!    `JSON.stringify(value)` in the object's original (insertion) key order, while
//!    `web/shared.mjs`'s `digest` hashes a key-sorted canonical form. This port always sorts
//!    keys before hashing (see `digest_of`), because `serde_json::Value` has no stable
//!    "insertion order" to preserve without the `preserve_order` feature (not enabled here).
//!    Digests are therefore internally self-consistent but will not byte-match the JS
//!    implementation's raw (non-canonical) digests.
//! 3. **PII redaction is regex-based but hand-mapped**, not byte-identical to the V8 regex
//!    engine's Unicode `\w` semantics; ASCII-range behavior matches the JS patterns.

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------------------------
// Minimal base64 (standard alphabet, padded). No base64 crate is available to this crate today.
// ---------------------------------------------------------------------------------------------
mod b64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[((n >> 6) & 0x3F) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(n & 0x3F) as usize] as char
            } else {
                '='
            });
        }
        out
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

    pub fn decode(input: &str) -> Option<Vec<u8>> {
        let bytes = input.as_bytes();
        if bytes.is_empty() || bytes.len() % 4 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        let mut i = 0;
        while i < bytes.len() {
            let chunk = &bytes[i..i + 4];
            let pad = chunk.iter().filter(|&&c| c == b'=').count();
            if pad > 2 || chunk[..4 - pad].iter().any(|&c| c == b'=') {
                return None;
            }
            let mut n: u32 = 0;
            for &c in chunk {
                n <<= 6;
                if c == b'=' {
                    continue;
                }
                n |= val(c)?;
            }
            out.push((n >> 16) as u8);
            if pad < 2 {
                out.push((n >> 8) as u8);
            }
            if pad < 1 {
                out.push(n as u8);
            }
            i += 4;
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------------------------
// Cached regexes (mirrors the JS module-level regex literals).
// ---------------------------------------------------------------------------------------------
fn re_base64() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$").unwrap()
    })
}

fn re_bearer_wide() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{4,}").unwrap())
}

fn re_email() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}").unwrap())
}

fn re_ssn() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap())
}

fn re_phone() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:\+\d[\d\s().-]{6,}\d|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b|\(\d{3}\)\s*\d{3}[-.\s]\d{4}\b)")
            .unwrap()
    })
}

fn re_bearer_email_narrow() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(bearer\s+\S+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})").unwrap())
}

fn re_safe_path_segment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap())
}

fn re_safe_identifier() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$").unwrap())
}

fn re_binding_value() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$").unwrap())
}

fn re_drive_letter() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z]:").unwrap())
}

fn re_iso_timestamp() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$").unwrap())
}

fn re_identifier_tail() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z_$][A-Za-z0-9_$-]*$").unwrap())
}

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------
const BINDING_KEYS: [&str; 10] = [
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

const SENSITIVE_KEYS: [&str; 17] = [
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
const SENSITIVE_SUFFIXES: [&str; 9] = [
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

const COMMON_SENSITIVE_SUFFIXES: [&str; 7] = [
    "secret",
    "password",
    "token",
    "privatekey",
    "apikey",
    "cookie",
    "authorization",
];
const COMMON_SENSITIVE_EXACT: [&str; 6] = [
    "email",
    "phone",
    "phonenumber",
    "ssn",
    "socialsecuritynumber",
    "taxid",
];

const CONDITIONAL_PROVIDERS: [&str; 4] = ["analytics", "commerce", "email", "payments"];

const OPERATION_IDS: [&str; 19] = [
    "alerts",
    "backlog",
    "backup",
    "capacity",
    "containment",
    "cost",
    "dashboards",
    "health",
    "incidents",
    "load",
    "provider",
    "quota",
    "region",
    "restore",
    "rollback",
    "rpo",
    "rto",
    "slo",
    "support",
];
const RESULT_STATUSES: [&str; 6] = ["pass", "fail", "partial", "unproven", "blocked", "error"];

// ---------------------------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------------------------
fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest_string(s: &str) -> String {
    digest_bytes(s.as_bytes())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonicalize(&map[k]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Digest of the canonical (key-sorted) form. See divergence (2) in the module docs.
fn digest_of(value: &Value) -> String {
    let canon = canonicalize(value);
    digest_bytes(serde_json::to_string(&canon).unwrap_or_default().as_bytes())
}

fn is_canonical_base64(s: &str) -> bool {
    if !re_base64().is_match(s) {
        return false;
    }
    match b64::decode(s) {
        Some(bytes) => b64::encode(&bytes) == s,
        None => false,
    }
}

fn safe_path(value: &str) -> bool {
    if value.is_empty() || value.contains('\\') || value.starts_with('/') || re_drive_letter().is_match(value) {
        return false;
    }
    let segments: Vec<&str> = value.split('/').collect();
    segments.len() > 1
        && segments
            .iter()
            .all(|s| *s != "." && *s != ".." && re_safe_path_segment().is_match(s))
        && segments.join("/") == value
}

fn safe_identifier(value: &str) -> bool {
    re_safe_identifier().is_match(value)
}

fn valid_binding_value(value: &str) -> bool {
    re_binding_value().is_match(value)
}

fn opaque(kind: &str, value: &str) -> String {
    format!("opaque-{}", &hex::encode(Sha256::digest(format!("{kind}:{value}").as_bytes()))[..24])
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn is_sensitive_key(key: &str) -> bool {
    let n = normalized_key(key);
    SENSITIVE_KEYS.contains(&n.as_str()) || SENSITIVE_SUFFIXES.iter().any(|suf| n.ends_with(suf))
}

fn is_sensitive_key_common(n: &str) -> bool {
    COMMON_SENSITIVE_SUFFIXES.iter().any(|suf| n.ends_with(suf)) || COMMON_SENSITIVE_EXACT.contains(&n)
}

fn sanitize_string(value: &str) -> String {
    let s = re_bearer_wide().replace_all(value, "[REDACTED]");
    let s = re_email().replace_all(&s, "[REDACTED]");
    let s = re_ssn().replace_all(&s, "[REDACTED]");
    let s = re_phone().replace_all(&s, "[REDACTED]");
    s.into_owned()
}

fn redact_value_string(value: &str) -> String {
    re_bearer_email_narrow().replace_all(value, "[REDACTED]").into_owned()
}

/// Port of `web/shared.mjs`'s `redact`.
fn redact(value: &Value, key: &str) -> Value {
    let is_plain_object = matches!(value, Value::Object(_));
    if is_sensitive_key(key) && !is_plain_object {
        return Value::String("[REDACTED]".to_string());
    }
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|v| redact(v, "")).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(k.clone(), redact(v, k));
            }
            Value::Object(out)
        }
        Value::String(s) => Value::String(redact_value_string(s)),
        other => other.clone(),
    }
}

fn exact_binding(binding: &Value) -> (Value, Vec<String>) {
    let obj = binding.as_object().cloned().unwrap_or_default();
    let mut invalid: Vec<String> = Vec::new();
    for key in BINDING_KEYS {
        let ok = obj
            .get(key)
            .and_then(Value::as_str)
            .map(valid_binding_value)
            .unwrap_or(false);
        if !ok {
            invalid.push(key.to_string());
        }
    }
    let extras: Vec<String> = obj.keys().filter(|k| !BINDING_KEYS.contains(&k.as_str())).cloned().collect();
    let mut sorted_keys = BINDING_KEYS.to_vec();
    sorted_keys.sort();
    let mut normalized = serde_json::Map::new();
    for key in sorted_keys {
        let value = if invalid.contains(&key.to_string()) {
            Value::String(opaque(
                "binding",
                &serde_json::to_string(&canonicalize(obj.get(key).unwrap_or(&Value::Null))).unwrap_or_default(),
            ))
        } else {
            obj.get(key).cloned().unwrap_or(Value::Null)
        };
        normalized.insert(key.to_string(), value);
    }
    let mut gaps: Vec<String> = invalid;
    if extras.iter().any(|k| is_sensitive_key(k)) {
        gaps.push("binding-extra-sensitive".to_string());
    }
    if extras.iter().any(|k| !is_sensitive_key(k)) {
        gaps.push("binding-extra-undeclared".to_string());
    }
    (Value::Object(normalized), gaps)
}

fn same_binding(expected: &Value, actual: &Value) -> bool {
    BINDING_KEYS
        .iter()
        .all(|key| expected.get(key).and_then(Value::as_str) == actual.get(key).and_then(Value::as_str))
}

fn denominator(expected: &[String], receipts: &[Value], omitted: &[Value]) -> Value {
    let mut expected_ids: Vec<String> = expected.to_vec();
    expected_ids.sort();
    expected_ids.dedup();
    let receipt_ids: HashSet<String> = receipts
        .iter()
        .filter_map(|r| r.get("id").or_else(|| r.get("controlId")).and_then(Value::as_str))
        .map(String::from)
        .collect();
    let omitted_ids: HashSet<String> = omitted
        .iter()
        .filter_map(|o| o.get("id").and_then(Value::as_str))
        .map(String::from)
        .collect();
    let missing: Vec<String> = expected_ids
        .iter()
        .filter(|id| !receipt_ids.contains(*id) && !omitted_ids.contains(*id))
        .cloned()
        .collect();
    json!({
        "total": expected_ids.len(),
        "accounted": expected_ids.len() - missing.len(),
        "receipts": receipt_ids.len(),
        "omitted": omitted_ids.len(),
        "missing": missing,
        "expectedIds": expected_ids,
    })
}

fn sort_by_id(mut values: Vec<Value>) -> Vec<Value> {
    values.sort_by(|a, b| {
        let ida = a
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| a.get("controlId").and_then(Value::as_str))
            .or_else(|| a.get("name").and_then(Value::as_str))
            .unwrap_or("");
        let idb = b
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| b.get("controlId").and_then(Value::as_str))
            .or_else(|| b.get("name").and_then(Value::as_str))
            .unwrap_or("");
        ida.cmp(idb).then_with(|| {
            let ja = serde_json::to_string(&canonicalize(a)).unwrap_or_default();
            let jb = serde_json::to_string(&canonicalize(b)).unwrap_or_default();
            ja.cmp(&jb)
        })
    });
    values
}

fn normalize_bindings(value: &Value, key: &str, gaps: &mut Vec<String>) -> Value {
    if key == "binding" {
        let (normalized, bgaps) = exact_binding(value);
        gaps.extend(bgaps);
        return normalized;
    }
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|v| normalize_bindings(v, "", gaps)).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), normalize_bindings(&map[k], k, gaps));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Port of `web/shared.mjs`'s `finalize`.
fn finalize(kind: &str, value: Value) -> Value {
    let mut binding_gaps: Vec<String> = Vec::new();
    let mut safe_value = normalize_bindings(&value, "", &mut binding_gaps);
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
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            for g in &binding_gaps {
                existing.push(if g.starts_with("binding-extra-") {
                    g.clone()
                } else {
                    format!("binding-invalid:{g}")
                });
            }
            existing.sort();
            existing.dedup();
            map.insert(
                "coverageGaps".to_string(),
                Value::Array(existing.into_iter().map(Value::String).collect()),
            );
        }
    }
    let mut out = serde_json::Map::new();
    out.insert("schemaVersion".to_string(), Value::from(1));
    out.insert("kind".to_string(), Value::String(kind.to_string()));
    if let Value::Object(map) = safe_value {
        for (k, v) in map {
            out.insert(k, v);
        }
    }
    let normalized = canonicalize(&Value::Object(out));
    let d = digest_of(&normalized);
    if let Value::Object(mut map) = normalized {
        map.insert("digest".to_string(), Value::String(d));
        Value::Object(map)
    } else {
        unreachable!("canonicalize(Object) always returns an Object")
    }
}

fn is_falsy_missing(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64().map(|f| f == 0.0).unwrap_or(false),
        Value::String(s) => s.is_empty(),
        Value::Array(_) | Value::Object(_) => false,
    }
}

/// Strict ISO-8601 UTC millis parser (`YYYY-MM-DDTHH:MM:SSZ` or with `.mmm`).
fn utc_millis(s: &str) -> Option<i64> {
    if !re_iso_timestamp().is_match(s) {
        return None;
    }
    let bytes = s.as_bytes();
    let digits = |a: usize, len: usize| -> Option<i64> { s.get(a..a + len)?.parse::<i64>().ok() };
    let year = digits(0, 4)?;
    let month = digits(5, 2)?;
    let day = digits(8, 2)?;
    let hour = digits(11, 2)?;
    let minute = digits(14, 2)?;
    let second = digits(17, 2)?;
    let millis = if bytes.len() == 24 { digits(20, 3)? } else { 0 };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Howard Hinnant's days-from-civil algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1_000 + millis)
}

// ---------------------------------------------------------------------------------------------
// artifact-sanitize.mjs port
// ---------------------------------------------------------------------------------------------
fn configured_keys(fields: &[String]) -> Vec<String> {
    fields
        .iter()
        .map(|f| {
            let m = re_identifier_tail().find(f).map(|m| m.as_str()).unwrap_or(f.as_str());
            normalized_key(m)
        })
        .collect()
}

fn sanitize_value_rec(value: &Value, configured: &[String], changed: &mut bool) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|v| sanitize_value_rec(v, configured, changed)).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let n = normalized_key(k);
                if is_sensitive_key_common(&n) || configured.contains(&n) {
                    if v.as_str() != Some("[REDACTED]") {
                        *changed = true;
                    }
                    out.insert(k.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    out.insert(k.clone(), sanitize_value_rec(v, configured, changed));
                }
            }
            Value::Object(out)
        }
        Value::String(s) => {
            let r = sanitize_string(s);
            if &r != s {
                *changed = true;
            }
            Value::String(r)
        }
        other => other.clone(),
    }
}

fn sanitize_sensitive_value(value: &Value, sensitive_fields: &[String]) -> (Value, bool) {
    let configured = configured_keys(sensitive_fields);
    let mut changed = false;
    let out = sanitize_value_rec(value, &configured, &mut changed);
    (out, changed)
}

/// Returns `(possibly-sanitized artifact, sensitive)`. Non-object / malformed artifacts pass
/// through unchanged with `sensitive = false`, matching the JS short-circuits.
fn sanitize_artifact_content(artifact: &Value, sensitive_fields: &[String]) -> (Value, bool) {
    if !artifact.is_object() {
        return (artifact.clone(), false);
    }
    let has_content = artifact.get("content").and_then(Value::as_str);
    let has_bytes = artifact.get("bytesBase64").and_then(Value::as_str);
    let original = match (has_content, has_bytes) {
        (Some(c), None) => c.to_string(),
        (None, Some(b)) => match b64::decode(b) {
            Some(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            None => return (artifact.clone(), false),
        },
        _ => return (artifact.clone(), false),
    };
    let configured = configured_keys(sensitive_fields);
    let mut changed = false;
    let sanitized_text = match serde_json::from_str::<Value>(&original) {
        Ok(parsed) => {
            let sv = sanitize_value_rec(&parsed, &configured, &mut changed);
            serde_json::to_string(&sv).unwrap_or_default()
        }
        Err(_) => {
            let s = sanitize_string(&original);
            changed = s != original;
            s
        }
    };
    if !changed {
        return (artifact.clone(), false);
    }
    let mut rest = artifact.as_object().cloned().unwrap_or_default();
    rest.remove("content");
    rest.remove("bytesBase64");
    rest.remove("digest");
    rest.insert("content".to_string(), Value::String(sanitized_text.clone()));
    rest.insert("digest".to_string(), Value::String(digest_string(&sanitized_text)));
    (Value::Object(rest), true)
}

/// Returns `(artifact if valid, valid, sensitive)`.
fn sanitize_produced_artifact(artifact: &Value) -> (Option<Value>, bool, bool) {
    if !artifact.is_object() {
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
        let b64s = artifact.get("bytesBase64").and_then(Value::as_str).unwrap();
        if is_canonical_base64(b64s) {
            b64::decode(b64s)
        } else {
            None
        }
    };
    let bytes = match bytes {
        Some(b) if !b.is_empty() => b,
        _ => return (None, false, false),
    };
    if artifact.get("digest").and_then(Value::as_str) != Some(digest_bytes(&bytes).as_str()) {
        return (None, false, false);
    }
    let (sanitized_artifact, sensitive) = sanitize_artifact_content(artifact, &[]);
    (Some(sanitized_artifact), true, sensitive)
}

// ---------------------------------------------------------------------------------------------
// validate.mjs port (`validate_external_evidence`) — always fails signature verification closed.
// ---------------------------------------------------------------------------------------------

/// Port of `src/lib/platform/external/validate.mjs`'s `validateExternalEvidence`.
///
/// Because signature verification always fails closed here (see module docs, divergence 1),
/// the envelope's signed payload is always treated as absent, so this can never return a
/// fabricated `pass` for evidence whose payload it cannot actually verify.
pub fn validate_external_evidence(evidence: &Value, expected: &Value) -> Value {
    let mut gaps: Vec<String> = Vec::new();
    for key in [
        "producer",
        "scope",
        "targetId",
        "environment",
        "artifactDigest",
        "controlId",
        "binding",
        "issuedAt",
        "checkedAt",
        "expiresAt",
    ] {
        if evidence.get(key).map(is_falsy_missing).unwrap_or(true) {
            gaps.push(format!("missing-{key}"));
        }
    }
    let trusted_producers = expected
        .get("trustedProducers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let producer_id = evidence.get("producer").and_then(Value::as_str);
    let trusted = trusted_producers
        .iter()
        .any(|p| p.get("id").and_then(Value::as_str) == producer_id);
    if !trusted {
        gaps.push("producer-untrusted".to_string());
    }
    let signed_content = evidence.get("signedContent").and_then(Value::as_str);
    let signature = evidence.get("signature").and_then(Value::as_str);
    if signed_content.is_none() || signature.is_none() {
        gaps.push("signature-unproven".to_string());
    } else if !is_canonical_base64(signature.unwrap()) {
        gaps.push("signature-noncanonical".to_string());
    } else if trusted {
        gaps.push("signature-invalid".to_string());
    }
    // payload is always None under fail-closed verification.
    for key in ["targetId", "environment", "artifactDigest", "controlId"] {
        if expected.get(key).is_some() {
            gaps.push(format!("mismatched-{key}"));
        }
    }
    if expected.get("scope").is_some() {
        gaps.push("mismatched-scope".to_string());
    }
    if evidence.get("producer").is_some() {
        gaps.push("mismatched-producer".to_string());
    }
    if expected.get("binding").is_some() {
        gaps.push("mismatched-binding".to_string());
    }
    gaps.push("issuedAt-invalid".to_string());
    gaps.push("checkedAt-invalid".to_string());
    gaps.push("expiresAt-invalid".to_string());
    let now = expected.get("now").and_then(Value::as_str).and_then(utc_millis);
    if now.is_none() {
        gaps.push("clock-invalid".to_string());
    }
    let max_age_ms = expected.get("maxAgeMs").and_then(Value::as_f64);
    if max_age_ms.map(|v| v < 0.0).unwrap_or(true) {
        gaps.push("max-age-invalid".to_string());
    }
    // artifacts are always [] because the payload is always None.
    gaps.push("produced-artifact-invalid".to_string());
    if expected.get("requiresExercise").and_then(Value::as_bool).unwrap_or(false) {
        gaps.push("exercise-required".to_string());
        if evidence.get("exerciseReceipt").is_some() {
            gaps.push("envelope-exercise-mismatch".to_string());
        }
    }
    gaps.sort();
    gaps.dedup();
    let status = if gaps.is_empty() { "pass" } else { "unproven" };
    json!({
        "schemaVersion": 1,
        "kind": "legion-external-evidence-validation",
        "evidenceDigest": if evidence.is_null() { Value::Null } else { Value::String(digest_of(evidence)) },
        "status": status,
        "payload": Value::Null,
        "gaps": gaps,
    })
}

// ---------------------------------------------------------------------------------------------
// web/third-party/index.mjs port
// ---------------------------------------------------------------------------------------------
fn applicability_source_valid(source: Option<&Value>, binding: &Value) -> bool {
    let Some(source) = source else { return false };
    if source.get("kind").and_then(Value::as_str) != Some("frozen-conditional-provider-applicability") {
        return false;
    }
    if source.get("id").and_then(Value::as_str) != Some("web:conditional-providers") {
        return false;
    }
    if !same_binding(binding, source.get("binding").unwrap_or(&Value::Null)) {
        return false;
    }
    let Some(providers) = source.get("providers").and_then(Value::as_array) else {
        return false;
    };
    if !providers.iter().all(|p| {
        p.is_object()
            && p.get("id").and_then(Value::as_str).is_some()
            && p.get("applicable").and_then(Value::as_bool).is_some()
            && p.get("reason").and_then(Value::as_str).is_some()
    }) {
        return false;
    }
    let mut sorted = providers.clone();
    sorted.sort_by(|a, b| {
        a.get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(b.get("id").and_then(Value::as_str).unwrap_or(""))
    });
    let ids: Vec<&str> = sorted.iter().map(|p| p.get("id").and_then(Value::as_str).unwrap_or("")).collect();
    if ids != CONDITIONAL_PROVIDERS.to_vec() {
        return false;
    }
    if sorted.iter().any(|p| {
        p.get("applicable").and_then(Value::as_bool) != Some(false)
            || p.get("reason").and_then(Value::as_str).map(str::is_empty).unwrap_or(true)
    }) {
        return false;
    }
    let expected_digest = digest_bytes(
        serde_json::to_string(&canonicalize(&Value::Array(sorted.clone())))
            .unwrap_or_default()
            .as_bytes(),
    );
    source.get("digest").and_then(Value::as_str) == Some(expected_digest.as_str())
}

/// Always fails closed: the payload behind a signed "not applicable" receipt can never be
/// trusted without real signature verification (divergence 1), so `valid` is always `false`.
fn signed_not_applicable(envelope: &Value, trusted_producers: &[Value]) -> (Option<String>, bool, Vec<String>) {
    let mut gaps = Vec::new();
    let producer_id = envelope.get("producer").and_then(Value::as_str);
    let trusted = trusted_producers
        .iter()
        .any(|p| p.get("id").and_then(Value::as_str) == producer_id);
    let signed_content = envelope.get("signedContent").and_then(Value::as_str);
    let signature = envelope.get("signature").and_then(Value::as_str);
    if !trusted || signed_content.is_none() || signature.is_none() {
        gaps.push("signature-unproven".to_string());
    } else if !is_canonical_base64(signature.unwrap()) {
        gaps.push("signature-noncanonical".to_string());
    } else {
        gaps.push("signature-invalid".to_string());
    }
    gaps.push("not-applicable-receipt-invalid".to_string());
    let provider = envelope.get("provider").and_then(Value::as_str).map(String::from);
    (provider, false, gaps)
}

fn dup_sorted(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut dups = HashSet::new();
    for v in values {
        if !seen.insert(v.clone()) {
            dups.insert(v.clone());
        }
    }
    let mut out: Vec<String> = dups.into_iter().collect();
    out.sort();
    out
}

/// Port of `web/third-party/index.mjs`'s `verifyThirdPartyExercise`.
pub fn verify_third_party_exercise(input: &Value) -> Value {
    let binding = input.get("binding").cloned().unwrap_or_else(|| json!({}));
    let configured_providers = input
        .get("configuredProviders")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let applicable_providers: Vec<String> = input
        .get("applicableProviders")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let exercises = input.get("exercises").and_then(Value::as_array).cloned().unwrap_or_default();
    let applicability_source = input.get("applicabilitySource").filter(|v| !v.is_null());
    let not_applicable_receipts = input
        .get("notApplicableReceipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let trusted_producers = input
        .get("trustedProducers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let now = input.get("now").and_then(Value::as_str).map(String::from);
    let max_age_ms = input.get("maxAgeMs").and_then(Value::as_f64);

    let collections_ok = input.get("configuredProviders").map(Value::is_array).unwrap_or(true)
        && input.get("applicableProviders").map(Value::is_array).unwrap_or(true)
        && input.get("exercises").map(Value::is_array).unwrap_or(true)
        && input.get("notApplicableReceipts").map(Value::is_array).unwrap_or(true)
        && input.get("trustedProducers").map(Value::is_array).unwrap_or(true)
        && configured_providers.iter().all(Value::is_object)
        && exercises.iter().all(Value::is_object)
        && not_applicable_receipts.iter().all(Value::is_object)
        && trusted_producers.iter().all(Value::is_object);
    if !collections_ok {
        return finalize(
            "legion-web-third-party-exercise",
            json!({
                "status": "error", "terminal": true, "claimLevel": "external", "suppliedOnly": true, "networkAttempted": false,
                "binding": binding, "denominator": denominator(&[], &[], &[]), "receipts": [],
                "coverageGaps": ["third-party-collections-invalid"],
            }),
        );
    }

    let mut identifiers: Vec<String> = applicable_providers.clone();
    for p in &configured_providers {
        if let Some(k) = p.get("key").and_then(Value::as_str) {
            identifiers.push(k.to_string());
        }
        if let Some(a) = p.get("adapterId").and_then(Value::as_str) {
            identifiers.push(a.to_string());
        }
    }
    for e in &exercises {
        if let Some(k) = e
            .get("adapterKey")
            .and_then(Value::as_str)
            .or_else(|| e.get("provider").and_then(Value::as_str))
        {
            identifiers.push(k.to_string());
        }
        if let Some(p) = e.get("provider").and_then(Value::as_str) {
            identifiers.push(p.to_string());
        }
        if let Some(p) = e.get("producer").and_then(Value::as_str) {
            identifiers.push(p.to_string());
        }
    }
    for r in &not_applicable_receipts {
        if let Some(p) = r.get("provider").and_then(Value::as_str) {
            identifiers.push(p.to_string());
        }
        if let Some(p) = r.get("producer").and_then(Value::as_str) {
            identifiers.push(p.to_string());
        }
    }
    for p in &trusted_producers {
        if let Some(id) = p.get("id").and_then(Value::as_str) {
            identifiers.push(id.to_string());
        }
    }
    if identifiers.iter().any(|id| !safe_identifier(id)) {
        return finalize(
            "legion-web-third-party-exercise",
            json!({
                "status": "error", "terminal": true, "claimLevel": "external", "suppliedOnly": true, "networkAttempted": false,
                "binding": binding, "denominator": denominator(&[], &[], &[]), "receipts": [],
                "coverageGaps": ["third-party-identifiers-invalid"],
            }),
        );
    }

    let config_keys: Vec<String> = configured_providers
        .iter()
        .filter_map(|p| p.get("key").and_then(Value::as_str).map(String::from))
        .collect();
    let adapter_ids: Vec<String> = configured_providers
        .iter()
        .filter_map(|p| p.get("adapterId").and_then(Value::as_str).map(String::from))
        .collect();
    let duplicate_config_keys = dup_sorted(&config_keys);
    let duplicate_adapter_ids = dup_sorted(&adapter_ids);
    let configured_valid = duplicate_config_keys.is_empty() && duplicate_adapter_ids.is_empty();
    let configured_map: HashMap<String, Value> = if configured_valid {
        configured_providers
            .iter()
            .filter_map(|p| p.get("key").and_then(Value::as_str).map(|k| (k.to_string(), p.clone())))
            .collect()
    } else {
        HashMap::new()
    };

    let source_valid = applicability_source_valid(applicability_source, &binding);
    let policy_excludes = |id: &str| -> bool {
        source_valid
            && applicability_source
                .unwrap()
                .get("providers")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .any(|p| p.get("id").and_then(Value::as_str) == Some(id) && p.get("applicable").and_then(Value::as_bool) == Some(false))
    };
    let conditional_fallback = applicable_providers.is_empty() && config_keys.is_empty();
    let expected: Vec<String> = if conditional_fallback {
        CONDITIONAL_PROVIDERS.iter().map(|s| s.to_string()).collect()
    } else {
        let mut e: Vec<String> = applicable_providers.iter().cloned().chain(config_keys.iter().cloned()).collect();
        e.sort();
        e.dedup();
        e
    };

    let exclusions: Vec<(Option<String>, bool, Vec<String>)> = not_applicable_receipts
        .iter()
        .map(|r| signed_not_applicable(r, &trusted_producers))
        .collect();

    let mut grouped: HashMap<String, Vec<Value>> = HashMap::new();
    for e in &exercises {
        let key = e
            .get("adapterKey")
            .and_then(Value::as_str)
            .or_else(|| e.get("provider").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        grouped.entry(key).or_default().push(e.clone());
    }

    let mut global_gaps: Vec<String> = Vec::new();
    if conditional_fallback && applicability_source.is_none() && not_applicable_receipts.is_empty() {
        global_gaps.push("conditional-provider-applicability-source-missing".to_string());
    }
    if conditional_fallback && applicability_source.is_some() && !source_valid {
        global_gaps.push("conditional-provider-applicability-source-invalid".to_string());
    }
    for id in &config_keys {
        if policy_excludes(id) {
            global_gaps.push(format!("provider-applicability-contradiction:{id}"));
        }
    }
    for (provider, _valid, ex_gaps) in &exclusions {
        for g in ex_gaps {
            global_gaps.push(format!(
                "provider-not-applicable-{g}:{}",
                provider.clone().unwrap_or_else(|| "missing".to_string())
            ));
        }
    }
    for (provider, valid, _) in &exclusions {
        if *valid {
            if let Some(p) = provider {
                if applicable_providers.contains(p) || config_keys.contains(p) {
                    global_gaps.push(format!("provider-applicability-contradiction:{p}"));
                }
            }
        }
    }
    for k in &duplicate_config_keys {
        global_gaps.push(format!("provider-config-key-duplicate:{k}"));
    }
    for a in &duplicate_adapter_ids {
        global_gaps.push(format!("provider-config-adapter-duplicate:{a}"));
    }
    for p in &configured_providers {
        let key_ok = p.get("key").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
        let adapter_ok = p
            .get("adapterId")
            .and_then(Value::as_str)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !key_ok || !adapter_ok {
            global_gaps.push("provider-config-invalid".to_string());
        }
    }

    let mut receipts: Vec<Value> = Vec::new();
    for id in &expected {
        let matches = grouped.get(id).cloned().unwrap_or_default();
        if matches.is_empty() {
            // NOTE: a valid `signed_not_applicable` exclusion can never occur here — signature
            // verification always fails closed (divergence 1) — so only a frozen-policy-source
            // exclusion can produce an "unsupported" receipt for a provider with no exercise.
            if source_valid && policy_excludes(id) && !config_keys.contains(id) {
                let source = applicability_source.unwrap();
                let reason = source
                    .get("providers")
                    .and_then(Value::as_array)
                    .unwrap()
                    .iter()
                    .find(|p| p.get("id").and_then(Value::as_str) == Some(id.as_str()))
                    .and_then(|p| p.get("reason").and_then(Value::as_str))
                    .unwrap_or("");
                receipts.push(json!({
                    "id": id, "provider": id, "status": "unsupported", "terminal": true, "reason": reason,
                    "applicabilityEvidence": source.get("id").cloned().unwrap_or(Value::Null), "coverageGaps": [],
                }));
            }
            continue;
        }
        let raw = &matches[0];
        let provider_cfg = configured_map.get(id);
        let validation = validate_external_evidence(
            raw,
            &json!({
                "trustedProducers": trusted_producers,
                "scope": "third-party",
                "targetId": binding.get("targetId").cloned().unwrap_or(Value::Null),
                "environment": provider_cfg.and_then(|p| p.get("environment")).cloned().unwrap_or_else(|| raw.get("environment").cloned().unwrap_or(Value::Null)),
                "artifactDigest": binding.get("artifactDigest").cloned().unwrap_or(Value::Null),
                "controlId": id,
                "binding": binding,
                "requiresExercise": true,
                "now": now,
                "maxAgeMs": max_age_ms,
            }),
        );
        let source = validation.get("payload").filter(|p| !p.is_null()).cloned().unwrap_or_else(|| raw.clone());
        let mut item = redact(&source, "").as_object().cloned().unwrap_or_default();
        let mut gaps: Vec<String> = validation
            .get("gaps")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        if provider_cfg.is_none() {
            gaps.push("provider-not-configured".to_string());
        }
        if raw.get("adapterKey").is_none() {
            gaps.push("adapter-key-missing".to_string());
        }
        if item.get("adapterKey").and_then(Value::as_str) != Some(id.as_str()) {
            gaps.push("adapter-key-mismatch".to_string());
        }
        if item.get("provider").and_then(Value::as_str) != Some(id.as_str()) {
            gaps.push("provider-identity-spoof".to_string());
            global_gaps.push(format!("provider-identity-spoof:{id}"));
        }
        if let Some(pid) = provider_cfg.and_then(|p| p.get("producerId").and_then(Value::as_str)) {
            if item.get("producer").and_then(Value::as_str) != Some(pid) {
                gaps.push("producer-config-mismatch".to_string());
            }
        }
        if matches.len() > 1 {
            gaps.push("provider-duplicate".to_string());
            global_gaps.push(format!("provider-duplicate:{id}"));
        }
        let environment = item.get("environment").and_then(Value::as_str).unwrap_or("");
        if !["sandbox", "test"].contains(&environment) {
            gaps.push("non-test-environment".to_string());
        }
        for key in [
            "client",
            "backend",
            "providerState",
            "userState",
            "consent",
            "webhook",
            "idempotency",
            "quota",
            "cost",
        ] {
            if item.get(key).map(Value::is_null).unwrap_or(true) {
                gaps.push(format!("missing-{key}"));
            }
        }
        if !same_binding(&binding, item.get("binding").unwrap_or(&Value::Null)) {
            gaps.push("binding-mismatch".to_string());
        }
        let issued = raw.get("issuedAt").and_then(Value::as_str).and_then(utc_millis);
        let checked = raw.get("checkedAt").and_then(Value::as_str).and_then(utc_millis);
        let expires = raw.get("expiresAt").and_then(Value::as_str).and_then(utc_millis);
        let current = now.as_deref().and_then(utc_millis);
        for (k, v) in [("issuedAt", issued), ("checkedAt", checked), ("expiresAt", expires), ("now", current)] {
            if v.is_none() {
                gaps.push(format!("{k}-timestamp-invalid"));
            }
        }
        if let (Some(c), Some(n)) = (checked, current) {
            if c > n {
                gaps.push("checked-in-future".to_string());
            }
        }
        if let (Some(n), Some(e)) = (current, expires) {
            if n > e {
                gaps.push("evidence-expired".to_string());
            }
        }
        if let (Some(c), Some(n), Some(m)) = (checked, current, max_age_ms) {
            if (n - c) as f64 > m {
                gaps.push("evidence-stale".to_string());
            }
        }
        let state_vals: HashSet<String> = ["client", "backend", "providerState", "userState"]
            .iter()
            .map(|k| serde_json::to_string(&canonicalize(item.get(*k).unwrap_or(&Value::Null))).unwrap_or_default())
            .collect();
        if state_vals.len() != 1 {
            gaps.push("state-divergence".to_string());
        }
        for key in ["consent", "webhook", "idempotency"] {
            if item.get(key).and_then(Value::as_bool) != Some(true) {
                gaps.push(format!("{key}-unproven"));
            }
        }
        gaps.sort();
        gaps.dedup();
        item.insert("id".to_string(), Value::String(id.clone()));
        item.insert("provider".to_string(), Value::String(id.clone()));
        item.insert(
            "adapterId".to_string(),
            provider_cfg.and_then(|p| p.get("adapterId")).cloned().unwrap_or(Value::Null),
        );
        item.insert(
            "status".to_string(),
            Value::String(if gaps.is_empty() { "pass".to_string() } else { "unproven".to_string() }),
        );
        item.insert("terminal".to_string(), Value::Bool(true));
        item.insert("coverageGaps".to_string(), Value::Array(gaps.into_iter().map(Value::String).collect()));
        receipts.push(Value::Object(item));
    }
    let receipts = sort_by_id(receipts);

    let counts = denominator(&expected, &receipts, &[]);
    let missing_ids: Vec<String> = counts
        .get("missing")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let unplanned: Vec<String> = {
        let mut u: Vec<String> = grouped.keys().filter(|k| !expected.contains(k)).cloned().collect();
        u.sort();
        u
    };
    let mut gaps: Vec<String> = global_gaps;
    let (_, bgaps) = exact_binding(&binding);
    gaps.extend(bgaps.iter().map(|k| format!("binding-missing:{k}")));
    gaps.extend(missing_ids.iter().map(|id| format!("provider-missing:{id}")));
    gaps.extend(unplanned.iter().map(|id| format!("provider-unplanned:{id}")));
    for r in &receipts {
        let rid = r.get("id").and_then(Value::as_str).unwrap_or("");
        if let Some(cg) = r.get("coverageGaps").and_then(Value::as_array) {
            for g in cg {
                if let Some(gs) = g.as_str() {
                    gaps.push(format!("{rid}:{gs}"));
                }
            }
        }
    }
    gaps.sort();
    gaps.dedup();

    finalize(
        "legion-web-third-party-exercise",
        json!({
            "status": if gaps.is_empty() { "pass" } else { "unproven" }, "terminal": true, "claimLevel": "external",
            "suppliedOnly": true, "networkAttempted": false, "binding": binding, "denominator": counts,
            "receipts": receipts, "coverageGaps": gaps,
        }),
    )
}

// ---------------------------------------------------------------------------------------------
// web/operations/index.mjs port
// ---------------------------------------------------------------------------------------------
fn valid_operation_artifact(artifact: &Value, binding: &Value) -> bool {
    let path_ok = artifact.get("path").and_then(Value::as_str).map(safe_path).unwrap_or(false);
    if !path_ok {
        return false;
    }
    if !same_binding(binding, artifact.get("binding").unwrap_or(&Value::Null)) {
        return false;
    }
    sanitize_produced_artifact(artifact).1
}

/// Always fails signature verification closed (divergence 1); `record` defaults to the raw
/// envelope, matching the JS fallback when the signed payload cannot be trusted.
fn ops_unwrap(envelope: &Value, trusted_producers: &[Value]) -> Value {
    let mut gaps: Vec<String> = Vec::new();
    let producer_id = envelope.get("producer").and_then(Value::as_str).map(String::from);
    let trusted = producer_id
        .as_ref()
        .and_then(|pid| trusted_producers.iter().find(|p| p.get("id").and_then(Value::as_str) == Some(pid.as_str())));
    let signed_content = envelope.get("signedContent").and_then(Value::as_str);
    let signature = envelope.get("signature").and_then(Value::as_str);
    let mut record = envelope.clone();
    if trusted.is_none() || signed_content.is_none() || signature.is_none() {
        gaps.push("signature-unproven".to_string());
    } else if !is_canonical_base64(signature.unwrap()) {
        gaps.push("signature-noncanonical".to_string());
    } else {
        gaps.push("signature-invalid".to_string());
    }
    if let Some(rp) = record.get("producer").and_then(Value::as_str) {
        if Some(rp.to_string()) != producer_id {
            gaps.push("producer-mismatch".to_string());
        }
    }
    let original_artifacts = record.get("artifacts").cloned();
    let binding_for_artifacts = record.get("binding").cloned().unwrap_or(Value::Null);
    let artifacts_valid = match &original_artifacts {
        None => true,
        Some(Value::Array(items)) => items.iter().all(|a| valid_operation_artifact(a, &binding_for_artifacts)),
        _ => false,
    };
    if !artifacts_valid {
        gaps.push("operation-artifact-invalid".to_string());
    }
    let (sanitized_value, sensitive) = sanitize_sensitive_value(&record, &[]);
    if sensitive {
        gaps.push("operation-sensitive-data".to_string());
    }
    let mut final_record = sanitized_value;
    if let Some(Value::Array(items)) = &original_artifacts {
        let admissions: Vec<(Option<Value>, bool)> = items
            .iter()
            .map(|a| {
                let (art, _valid, sens) = sanitize_produced_artifact(a);
                (art, sens)
            })
            .collect();
        if admissions.iter().any(|(_, sens)| *sens) {
            gaps.push("operation-artifact-sanitized".to_string());
        }
        let sanitized_artifacts: Vec<Value> = admissions.into_iter().filter_map(|(a, _)| a).collect();
        if let Value::Object(map) = &mut final_record {
            map.insert("artifacts".to_string(), Value::Array(sanitized_artifacts));
        }
    }
    record = final_record;
    let id = record.get("id").cloned().unwrap_or_else(|| envelope.get("id").cloned().unwrap_or(Value::Null));
    json!({
        "id": id,
        "record": record,
        "producer": producer_id,
        "evidenceDigest": signed_content.map(digest_string),
        "gaps": gaps,
    })
}

/// Port of `web/operations/index.mjs`'s `verifyOperationsExercise`.
pub fn verify_operations_exercise(input: &Value) -> Value {
    let binding = input.get("binding").cloned().unwrap_or_else(|| json!({}));
    let exercises = input.get("exercises").and_then(Value::as_array).cloned().unwrap_or_default();
    let trusted_producers = input
        .get("trustedProducers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let now = input.get("now").and_then(Value::as_str).map(String::from);
    let max_age_ms = input.get("maxAgeMs").and_then(Value::as_f64);

    let collections_ok = input.get("exercises").map(Value::is_array).unwrap_or(true)
        && input.get("trustedProducers").map(Value::is_array).unwrap_or(true)
        && exercises.iter().all(Value::is_object)
        && trusted_producers.iter().all(Value::is_object);
    if !collections_ok {
        return finalize(
            "legion-web-operations-exercise",
            json!({
                "status": "error", "terminal": true, "binding": binding,
                "denominator": denominator(&[], &[], &[]), "receipts": [],
                "coverageGaps": ["operations-collections-invalid"],
            }),
        );
    }

    let mut identifiers: Vec<String> = Vec::new();
    for e in &exercises {
        if let Some(id) = e.get("id").and_then(Value::as_str) {
            identifiers.push(id.to_string());
        }
        if let Some(p) = e.get("producer").and_then(Value::as_str) {
            identifiers.push(p.to_string());
        }
    }
    for p in &trusted_producers {
        if let Some(id) = p.get("id").and_then(Value::as_str) {
            identifiers.push(id.to_string());
        }
    }
    if identifiers.iter().any(|id| !safe_identifier(id)) {
        return finalize(
            "legion-web-operations-exercise",
            json!({
                "status": "error", "terminal": true, "binding": binding,
                "denominator": denominator(&[], &[], &[]), "receipts": [],
                "coverageGaps": ["operations-identifiers-invalid"],
            }),
        );
    }

    let verified = sort_by_id(exercises.iter().map(|e| ops_unwrap(e, &trusted_producers)).collect());
    let mut grouped: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for item in &verified {
        let id = item.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        grouped.entry(id).or_default().push(item.clone());
    }

    let mut global_gaps: Vec<String> = Vec::new();
    for (id, rows) in &grouped {
        if !OPERATION_IDS.contains(&id.as_str()) {
            global_gaps.push(format!("operation-unplanned:{}", if id.is_empty() { "missing" } else { id }));
        }
        if rows.len() > 1 {
            global_gaps.push(format!("operation-id-duplicate:{id}"));
        }
        let has_gap = |name: &str| rows.iter().any(|r| r.get("gaps").and_then(Value::as_array).map(|g| g.iter().any(|x| x.as_str() == Some(name))).unwrap_or(false));
        if has_gap("signature-unproven") {
            global_gaps.push(format!("operation-signature-unproven:{id}"));
        }
        if has_gap("signature-noncanonical") {
            global_gaps.push(format!("operation-signature-noncanonical:{id}"));
        }
        if has_gap("signature-invalid") {
            global_gaps.push(format!("operation-signature-invalid:{id}"));
        }
    }

    let receipts: Vec<Value> = OPERATION_IDS
        .iter()
        .map(|id| {
            let rows = grouped.get(*id).cloned().unwrap_or_default();
            if rows.is_empty() {
                return json!({"id": id, "status": "unproven", "terminal": true, "coverageGaps": ["operation-missing"]});
            }
            let selected = &rows[0];
            let item = selected.get("record").cloned().unwrap_or_else(|| json!({}));
            let mut gaps: Vec<String> = selected
                .get("gaps")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if item.get("id").and_then(Value::as_str) != Some(*id) {
                gaps.push("operation-id-mismatch".to_string());
            }
            if item.get("exercised").and_then(Value::as_bool) != Some(true) {
                gaps.push("configured-not-exercised".to_string());
            }
            let status_val = item.get("status").and_then(Value::as_str);
            let status_valid = status_val.map(|s| RESULT_STATUSES.contains(&s)).unwrap_or(false);
            if !status_valid {
                gaps.push(format!("operation-status-invalid:{}", status_val.unwrap_or("missing")));
            }
            if item.get("terminal").and_then(Value::as_bool) != Some(true) {
                gaps.push("operation-nonterminal".to_string());
            }
            if item.get("outcome").and_then(|o| o.get("executed")).and_then(Value::as_bool) != Some(true) {
                gaps.push("operation-outcome-unexecuted".to_string());
            }
            if status_valid && status_val != Some("pass") {
                gaps.push(format!("operation-status-{}", status_val.unwrap()));
            }
            if !same_binding(&binding, item.get("binding").unwrap_or(&Value::Null)) {
                gaps.push("binding-mismatch".to_string());
            }
            for key in [
                "workload",
                "dataset",
                "region",
                "providerLimits",
                "cost",
                "assumptions",
                "alert",
                "action",
                "recovery",
                "residualDamage",
            ] {
                if item.get(key).map(Value::is_null).unwrap_or(true) {
                    gaps.push(format!("missing-{key}"));
                }
            }
            for key in ["alert", "action", "recovery"] {
                if item.get(key).and_then(Value::as_bool) != Some(true) {
                    gaps.push(format!("{key}-not-observed"));
                }
            }
            if item.get("residualDamage").and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false) {
                gaps.push("residual-damage-present".to_string());
            }
            let issued = item.get("issuedAt").and_then(Value::as_str).and_then(utc_millis);
            let checked = item.get("checkedAt").and_then(Value::as_str).and_then(utc_millis);
            let current = now.as_deref().and_then(utc_millis);
            let expires = item.get("expiresAt").and_then(Value::as_str).and_then(utc_millis);
            for (k, v) in [("issuedAt", issued), ("checkedAt", checked), ("now", current), ("expiresAt", expires)] {
                if v.is_none() {
                    gaps.push(format!("{k}-timestamp-invalid"));
                }
            }
            if [issued, checked, current, expires].iter().any(Option::is_none) {
                gaps.push("freshness-unbound".to_string());
            }
            if max_age_ms.map(|v| v < 0.0).unwrap_or(true) {
                gaps.push("freshness-window-invalid".to_string());
            }
            if let (Some(i), Some(c)) = (issued, checked) {
                if i > c {
                    gaps.push("issued-after-checked".to_string());
                }
            }
            if let (Some(c), Some(n)) = (checked, current) {
                if c > n {
                    gaps.push("checked-in-future".to_string());
                }
            }
            if let (Some(c), Some(e)) = (checked, expires) {
                if c > e {
                    gaps.push("checked-after-expiry".to_string());
                }
            }
            if let (Some(n), Some(e)) = (current, expires) {
                if n > e {
                    gaps.push("evidence-expired".to_string());
                }
            }
            if let (Some(c), Some(n), Some(m)) = (checked, current, max_age_ms) {
                if (n - c) as f64 > m {
                    gaps.push("evidence-stale".to_string());
                }
            }
            gaps.sort();
            gaps.dedup();
            let status = if !status_valid || item.get("terminal").and_then(Value::as_bool) != Some(true) {
                "error".to_string()
            } else if status_val != Some("pass") {
                status_val.unwrap().to_string()
            } else if !gaps.is_empty() {
                "unproven".to_string()
            } else {
                "pass".to_string()
            };
            json!({
                "id": id, "producer": selected.get("producer").cloned().unwrap_or(Value::Null),
                "evidenceDigest": selected.get("evidenceDigest").cloned().unwrap_or(Value::Null),
                "record": item, "status": status, "terminal": true, "coverageGaps": gaps,
            })
        })
        .collect();

    let expected_ids: Vec<String> = OPERATION_IDS.iter().map(|s| s.to_string()).collect();
    let counts = denominator(&expected_ids, &receipts, &[]);
    let mut gaps: Vec<String> = global_gaps;
    let (_, bgaps) = exact_binding(&binding);
    gaps.extend(bgaps.iter().map(|k| format!("binding-missing:{k}")));
    for id in OPERATION_IDS {
        if !grouped.contains_key(id) {
            gaps.push(format!("operation-omitted:{id}"));
        }
    }
    for r in &receipts {
        let rid = r.get("id").and_then(Value::as_str).unwrap_or("");
        if let Some(cg) = r.get("coverageGaps").and_then(Value::as_array) {
            for g in cg {
                if let Some(gs) = g.as_str() {
                    gaps.push(format!("{rid}:{gs}"));
                }
            }
        }
    }
    if exercises.is_empty() {
        gaps.push("operations-denominator-empty".to_string());
    }
    let statuses: Vec<&str> = receipts.iter().filter_map(|r| r.get("status").and_then(Value::as_str)).collect();
    let status = ["error", "fail", "blocked", "partial", "unproven"]
        .iter()
        .find(|s| statuses.contains(s))
        .map(|s| s.to_string())
        .unwrap_or_else(|| if !gaps.is_empty() { "unproven".to_string() } else { "pass".to_string() });
    gaps.sort();
    gaps.dedup();

    finalize(
        "legion-web-operations-exercise",
        json!({
            "status": status, "terminal": true, "claimLevel": "external", "suppliedOnly": true, "networkAttempted": false,
            "binding": binding, "denominator": counts, "receipts": receipts, "coverageGaps": gaps,
        }),
    )
}

// ---------------------------------------------------------------------------------------------
// web/infrastructure/index.mjs port
// ---------------------------------------------------------------------------------------------

/// Port of `web/infrastructure/index.mjs`'s `verifyInfrastructureExercise`. Because signature
/// verification always fails closed (divergence 1), the signed payload is always absent, so
/// every result is `unproven`/`error`, never a fabricated `pass`. The full per-control fact
/// validation the JS performs once a payload is available is therefore unreachable here and is
/// omitted rather than shipped as dead code; it should be restored alongside the real verifier
/// (see NEW DEP NEEDED in the module docs).
pub fn verify_infrastructure_exercise(input: &Value) -> Value {
    let binding = input.get("binding").cloned().unwrap_or_else(|| json!({}));
    let evidence = input.get("evidence").cloned().filter(|v| !v.is_null());
    let trusted_producers = input
        .get("trustedProducers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let producers_valid = input.get("trustedProducers").map(Value::is_array).unwrap_or(true)
        && trusted_producers.iter().all(|p| {
            p.is_object()
                && p.get("id").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false)
                && p.get("publicKey").is_some()
        });
    if !producers_valid {
        let (_, bgaps) = exact_binding(&binding);
        let mut gaps: Vec<String> = bgaps.iter().map(|k| format!("binding-missing:{k}")).collect();
        gaps.push("trusted-producers-invalid".to_string());
        gaps.sort();
        gaps.dedup();
        return finalize(
            "legion-web-infrastructure-exercise",
            json!({
                "status": "error", "terminal": true, "claimLevel": "external", "suppliedOnly": true, "networkAttempted": false,
                "binding": binding, "producer": evidence.as_ref().and_then(|e| e.get("producer")).cloned().unwrap_or(Value::Null),
                "payload": Value::Null, "evidenceDigest": Value::Null, "coverageGaps": gaps,
            }),
        );
    }

    let (_, bgaps) = exact_binding(&binding);
    let mut gaps: Vec<String> = bgaps.iter().map(|k| format!("binding-missing:{k}")).collect();
    let producer_id = evidence.as_ref().and_then(|e| e.get("producer")).and_then(Value::as_str).map(String::from);
    let producer = producer_id
        .as_ref()
        .and_then(|pid| trusted_producers.iter().find(|p| p.get("id").and_then(Value::as_str) == Some(pid.as_str())));
    if evidence.is_none() {
        gaps.push("supplied-evidence-missing".to_string());
    }
    if producer.is_none() {
        gaps.push("producer-untrusted".to_string());
    }
    let signed_content = evidence.as_ref().and_then(|e| e.get("signedContent")).and_then(Value::as_str).map(String::from);
    let signature = evidence.as_ref().and_then(|e| e.get("signature")).and_then(Value::as_str);
    if signed_content.is_none() || signature.is_none() {
        gaps.push("signature-unproven".to_string());
    } else if !is_canonical_base64(signature.unwrap()) {
        gaps.push("signature-noncanonical".to_string());
    } else if producer.is_some() {
        gaps.push("signature-invalid".to_string());
    }
    // payload is always None under fail-closed verification.
    gaps.push("deployed-proof-required".to_string());
    gaps.push("rollback-not-exercised".to_string());
    gaps.sort();
    gaps.dedup();

    finalize(
        "legion-web-infrastructure-exercise",
        json!({
            "status": if gaps.is_empty() { "pass" } else { "unproven" }, "terminal": true, "claimLevel": "external",
            "suppliedOnly": true, "networkAttempted": false, "binding": binding, "producer": producer_id,
            "evidenceDigest": signed_content.as_deref().map(digest_string), "payload": Value::Null, "coverageGaps": gaps,
        }),
    )
}

// ---------------------------------------------------------------------------------------------
// Entry points (external-evidence/index.mjs + external/*/index.mjs)
// ---------------------------------------------------------------------------------------------

/// Port of `src/providers/runtime/external-evidence/index.mjs`'s `importExternalEvidence`.
pub fn import_external_evidence(input: &Value) -> Value {
    let evidence = input.get("evidence").and_then(Value::as_array).cloned().unwrap_or_default();
    let expected = input.get("expected").cloned().unwrap_or_else(|| json!({}));
    let mut coverage_gaps: Vec<String> = Vec::new();
    if evidence.is_empty() {
        coverage_gaps.push("external-evidence-denominator-empty".to_string());
    }
    let mut validations: Vec<Value> = Vec::new();
    let mut all_pass = true;
    for item in &evidence {
        let validation = validate_external_evidence(item, &expected);
        if validation.get("status").and_then(Value::as_str) != Some("pass") {
            all_pass = false;
        }
        if let Some(vg) = validation.get("gaps").and_then(Value::as_array) {
            for g in vg {
                if let Some(s) = g.as_str() {
                    coverage_gaps.push(s.to_string());
                }
            }
        }
        validations.push(json!({"evidence": item, "validation": validation}));
    }
    coverage_gaps.sort();
    let status = if !coverage_gaps.is_empty() || !all_pass { "unproven" } else { "pass" };
    json!({
        "schemaVersion": 1,
        "provider": "runtime.external-evidence",
        "status": status,
        "validations": validations,
        "coverageGaps": coverage_gaps,
    })
}

fn strip_receipt(receipt: &Value) -> Value {
    let mut map = receipt.as_object().cloned().unwrap_or_default();
    map.remove("digest");
    map.remove("kind");
    map.remove("schemaVersion");
    Value::Object(map)
}

/// `{ ...base, ...receipt }` — `receipt`'s own fields win on key collision, matching the JS
/// object-spread wrappers in each `external/*/index.mjs`.
fn merge_wrapper(receipt: Value, base: Vec<(&str, Value)>) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in base {
        map.insert(k.to_string(), v);
    }
    if let Value::Object(rmap) = receipt {
        for (k, v) in rmap {
            map.insert(k, v);
        }
    }
    Value::Object(map)
}

/// Port of `src/providers/runtime/external/analytics/index.mjs`.
pub fn verify_analytics_evidence(input: &Value) -> Value {
    let receipt = strip_receipt(&verify_third_party_exercise(input));
    let merged = merge_wrapper(
        receipt,
        vec![
            ("provider", Value::String("runtime.external.analytics".into())),
            ("family", Value::String("analytics".into())),
            ("networkAttempted", Value::Bool(false)),
        ],
    );
    finalize("legion-external-analytics-evidence", merged)
}

/// Port of `src/providers/runtime/external/backup/index.mjs`.
pub fn verify_backup_evidence(input: &Value) -> Value {
    let receipt = strip_receipt(&verify_operations_exercise(input));
    let merged = merge_wrapper(
        receipt,
        vec![
            ("provider", Value::String("runtime.external.backup".into())),
            ("family", Value::String("backup".into())),
            ("claimLevel", Value::String("external".into())),
            ("suppliedOnly", Value::Bool(true)),
            ("networkAttempted", Value::Bool(false)),
        ],
    );
    finalize("legion-external-backup-evidence", merged)
}

/// Port of `src/providers/runtime/external/cloud/index.mjs`.
pub fn verify_cloud_evidence(input: &Value) -> Value {
    let receipt = strip_receipt(&verify_infrastructure_exercise(input));
    let merged = merge_wrapper(
        receipt,
        vec![
            ("provider", Value::String("runtime.external.cloud".into())),
            ("family", Value::String("cloud".into())),
        ],
    );
    finalize("legion-external-cloud-evidence", merged)
}

/// Port of `src/providers/runtime/external/commerce/index.mjs`.
pub fn verify_commerce_evidence(input: &Value) -> Value {
    let receipt = strip_receipt(&verify_third_party_exercise(input));
    let merged = merge_wrapper(
        receipt,
        vec![
            ("provider", Value::String("runtime.external.commerce".into())),
            ("family", Value::String("commerce".into())),
            ("networkAttempted", Value::Bool(false)),
        ],
    );
    finalize("legion-external-commerce-evidence", merged)
}

/// Port of `src/providers/runtime/external/dns/index.mjs`.
pub fn verify_dns_evidence(input: &Value) -> Value {
    let receipt = strip_receipt(&verify_infrastructure_exercise(input));
    let merged = merge_wrapper(
        receipt,
        vec![
            ("provider", Value::String("runtime.external.dns".into())),
            ("family", Value::String("dns".into())),
        ],
    );
    finalize("legion-external-dns-evidence", merged)
}

/// Port of `src/providers/runtime/external/email/index.mjs`.
pub fn verify_email_evidence(input: &Value) -> Value {
    let receipt = strip_receipt(&verify_third_party_exercise(input));
    let merged = merge_wrapper(
        receipt,
        vec![
            ("provider", Value::String("runtime.external.email".into())),
            ("family", Value::String("email".into())),
            ("networkAttempted", Value::Bool(false)),
        ],
    );
    finalize("legion-external-email-evidence", merged)
}

/// Port of `src/providers/runtime/external/incidents/index.mjs`.
pub fn verify_incident_evidence(input: &Value) -> Value {
    let receipt = strip_receipt(&verify_operations_exercise(input));
    let merged = merge_wrapper(
        receipt,
        vec![
            ("provider", Value::String("runtime.external.incidents".into())),
            ("family", Value::String("incidents".into())),
            ("claimLevel", Value::String("external".into())),
            ("suppliedOnly", Value::Bool(true)),
            ("networkAttempted", Value::Bool(false)),
        ],
    );
    finalize("legion-external-incident-evidence", merged)
}

/// Port of `src/providers/runtime/external/third-party/index.mjs`.
pub fn verify_third_party_evidence(input: &Value) -> Value {
    let receipt = strip_receipt(&verify_third_party_exercise(input));
    let merged = merge_wrapper(
        receipt,
        vec![
            ("provider", Value::String("runtime.external.third-party".into())),
            ("family", Value::String("third-party".into())),
            ("networkAttempted", Value::Bool(false)),
        ],
    );
    finalize("legion-external-third-party-evidence", merged)
}
