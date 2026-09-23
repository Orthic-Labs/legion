//! Port of `src/lib/platform/artifact-sanitize.mjs`, scoped to the
//! functions `src/providers/runtime/web/{capture,data}/index.mjs` consume
//! (`sanitizeSensitiveValue`, `sanitizeProducedArtifact`) — chunk wf048
//! support. `artifact-sanitize.mjs` itself is not part of this chunk's
//! owned file list; if another chunk ports it to a shared location first,
//! this copy should be collapsed onto that one.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

// No `base64` crate is declared in this crate's `Cargo.toml` (see the
// report's `sharedPatches` for the suggested addition). Standard-alphabet
// base64 encode/decode is implemented locally with std only, matching
// Node's `Buffer.from(..., 'base64')` / `.toString('base64')` semantics
// (RFC 4648 standard alphabet, `=` padding).
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_ALPHABET[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
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
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 || chunk[..4 - pad].iter().any(|&c| c == b'=') {
            return None;
        }
        let mut n: u32 = 0;
        let mut valid_chars = 0usize;
        for &c in chunk {
            if c == b'=' {
                n <<= 6;
            } else {
                let v = val(c)?;
                n = (n << 6) | v;
                valid_chars += 1;
            }
        }
        let _ = valid_chars;
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

fn normalize_key(key: &str) -> String {
    key.chars().filter(|c| c.is_ascii_alphanumeric()).flat_map(|c| c.to_lowercase()).collect()
}

/// Port of `commonSensitiveKey(key)` (`key` is assumed already normalized).
fn common_sensitive_key(key: &str) -> bool {
    for suffix in ["secret", "password", "token", "privatekey", "apikey", "cookie", "authorization"] {
        if key.ends_with(suffix) {
            return true;
        }
    }
    matches!(key, "email" | "phone" | "phonenumber" | "ssn" | "socialsecuritynumber" | "taxid")
}

/// Port of the four regex redactions in `sanitizeString` (BEARER, EMAIL,
/// SSN, PHONE), applied in that order.
pub fn sanitize_string(input: &str) -> String {
    let after_bearer = redact_bearer(input);
    let after_email = redact_email(&after_bearer);
    let after_ssn = redact_ssn(&after_email);
    redact_phone(&after_ssn)
}

fn redact_bearer(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if let Some(end) = try_match_bearer(&chars, i) {
            out.push_str("[REDACTED]");
            i = end;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn try_match_bearer(chars: &[char], start: usize) -> Option<usize> {
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

fn is_email_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '.' || c == '+' || c == '-'
}

fn redact_email(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if let Some(end) = try_match_email(&chars, i) {
            out.push_str("[REDACTED]");
            i = end;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn try_match_email(chars: &[char], start: usize) -> Option<usize> {
    if !is_email_word_char(chars[start]) {
        return None;
    }
    let mut i = start;
    while i < chars.len() && is_email_word_char(chars[i]) {
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
    let consumed: String = chars[domain_start..i].iter().collect();
    let last_dot = consumed.rfind('.')?;
    let tld = &consumed[last_dot + 1..];
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(i)
}

/// Port of SSN = /\b\d{3}-\d{2}-\d{4}\b/g.
fn redact_ssn(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    let is_boundary = |chars: &[char], idx: isize| -> bool {
        if idx < 0 || idx as usize >= chars.len() {
            return true;
        }
        !chars[idx as usize].is_alphanumeric() && chars[idx as usize] != '_'
    };
    while i < chars.len() {
        if i + 11 <= chars.len() {
            let window: String = chars[i..i + 11].iter().collect();
            let bytes: Vec<char> = window.chars().collect();
            let matches = bytes[0..3].iter().all(|c| c.is_ascii_digit())
                && bytes[3] == '-'
                && bytes[4..6].iter().all(|c| c.is_ascii_digit())
                && bytes[6] == '-'
                && bytes[7..11].iter().all(|c| c.is_ascii_digit());
            if matches && is_boundary(&chars, i as isize - 1) && is_boundary(&chars, (i + 11) as isize) {
                out.push_str("[REDACTED]");
                i += 11;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Port of PHONE (three alternatives: `+…`, `\d{3}[-.\s]\d{3}[-.\s]\d{4}`,
/// `(\d{3}) \d{3}[-.\s]\d{4}`). This targets the same observable shapes
/// without a general regex engine.
fn redact_phone(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        if let Some(end) = try_match_plain_phone(&chars, i) {
            out.push_str("[REDACTED]");
            i = end;
            continue;
        }
        if let Some(end) = try_match_paren_phone(&chars, i) {
            out.push_str("[REDACTED]");
            i = end;
            continue;
        }
        if let Some(end) = try_match_intl_phone(&chars, i) {
            out.push_str("[REDACTED]");
            i = end;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn is_sep(c: char) -> bool {
    c == '-' || c == '.' || c.is_whitespace()
}

fn try_match_plain_phone(chars: &[char], start: usize) -> Option<usize> {
    // \b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b
    if start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
        return None;
    }
    let mut i = start;
    for _ in 0..3 {
        if i >= chars.len() || !chars[i].is_ascii_digit() {
            return None;
        }
        i += 1;
    }
    if i >= chars.len() || !is_sep(chars[i]) {
        return None;
    }
    i += 1;
    for _ in 0..3 {
        if i >= chars.len() || !chars[i].is_ascii_digit() {
            return None;
        }
        i += 1;
    }
    if i >= chars.len() || !is_sep(chars[i]) {
        return None;
    }
    i += 1;
    for _ in 0..4 {
        if i >= chars.len() || !chars[i].is_ascii_digit() {
            return None;
        }
        i += 1;
    }
    if i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
        return None;
    }
    Some(i)
}

fn try_match_paren_phone(chars: &[char], start: usize) -> Option<usize> {
    // \(\d{3}\)\s*\d{3}[-.\s]\d{4}\b
    let mut i = start;
    if i >= chars.len() || chars[i] != '(' {
        return None;
    }
    i += 1;
    for _ in 0..3 {
        if i >= chars.len() || !chars[i].is_ascii_digit() {
            return None;
        }
        i += 1;
    }
    if i >= chars.len() || chars[i] != ')' {
        return None;
    }
    i += 1;
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    for _ in 0..3 {
        if i >= chars.len() || !chars[i].is_ascii_digit() {
            return None;
        }
        i += 1;
    }
    if i >= chars.len() || !is_sep(chars[i]) {
        return None;
    }
    i += 1;
    for _ in 0..4 {
        if i >= chars.len() || !chars[i].is_ascii_digit() {
            return None;
        }
        i += 1;
    }
    if i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
        return None;
    }
    Some(i)
}

fn try_match_intl_phone(chars: &[char], start: usize) -> Option<usize> {
    // +\d[\d\s().-]{6,}\d
    if chars[start] != '+' {
        return None;
    }
    let mut i = start + 1;
    if i >= chars.len() || !chars[i].is_ascii_digit() {
        return None;
    }
    i += 1;
    let body_start = i;
    while i < chars.len() && (chars[i].is_ascii_digit() || chars[i].is_whitespace() || matches!(chars[i], '(' | ')' | '.' | '-')) {
        i += 1;
    }
    if i - body_start < 6 {
        return None;
    }
    // last consumed char must be a digit for the trailing \d.
    let mut end = i;
    while end > body_start && !chars[end - 1].is_ascii_digit() {
        end -= 1;
    }
    if end - body_start < 7 {
        return None;
    }
    Some(end)
}

pub struct SanitizedValue {
    pub value: Value,
    pub sensitive: bool,
}

/// Port of `sanitizeSensitiveValue(value, sensitiveFields = [])`. This
/// chunk's callers never pass `sensitiveFields`, so only the common
/// sensitive-key set and regex redactions are ported.
pub fn sanitize_sensitive_value(value: &Value) -> SanitizedValue {
    let mut changed = false;
    let sanitized = sanitize_value(value, &mut changed);
    SanitizedValue { value: sanitized, sensitive: changed }
}

fn sanitize_value(value: &Value, changed: &mut bool) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| sanitize_value(item, changed)).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, child) in map {
                let normalized = normalize_key(key);
                if common_sensitive_key(&normalized) {
                    if child != &Value::String("[REDACTED]".to_string()) {
                        *changed = true;
                    }
                    out.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    out.insert(key.clone(), sanitize_value(child, changed));
                }
            }
            Value::Object(out)
        }
        Value::String(s) => {
            let sanitized = sanitize_string(s);
            if &sanitized != s {
                *changed = true;
            }
            Value::String(sanitized)
        }
        other => other.clone(),
    }
}

fn is_canonical_base64(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    match b64_decode(value) {
        Some(bytes) => b64_encode(&bytes) == value,
        None => false,
    }
}

pub struct ProducedArtifactResult {
    pub artifact: Value,
    pub valid: bool,
    pub sensitive: bool,
}

/// Port of `sanitizeProducedArtifact(artifact, sensitiveFields = [])`.
pub fn sanitize_produced_artifact(artifact: &Value) -> ProducedArtifactResult {
    let obj = match artifact.as_object() {
        Some(o) => o,
        None => return ProducedArtifactResult { artifact: Value::Null, valid: false, sensitive: false },
    };
    let has_content = matches!(obj.get("content"), Some(Value::String(_)));
    let has_bytes = matches!(obj.get("bytesBase64"), Some(Value::String(_)));
    if has_content == has_bytes {
        return ProducedArtifactResult { artifact: Value::Null, valid: false, sensitive: false };
    }
    let bytes: Option<Vec<u8>> = if has_content {
        Some(obj.get("content").and_then(Value::as_str).unwrap_or_default().as_bytes().to_vec())
    } else {
        let b64 = obj.get("bytesBase64").and_then(Value::as_str).unwrap_or_default();
        if is_canonical_base64(b64) { b64_decode(b64) } else { None }
    };
    let bytes = match bytes {
        Some(b) if !b.is_empty() => b,
        _ => return ProducedArtifactResult { artifact: Value::Null, valid: false, sensitive: false },
    };
    let expected_digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if obj.get("digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
        return ProducedArtifactResult { artifact: Value::Null, valid: false, sensitive: false };
    }
    // Port of `sanitizeArtifactContent`.
    let original = if has_content {
        obj.get("content").and_then(Value::as_str).unwrap_or_default().to_string()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let mut changed = false;
    let sanitized_text = match serde_json::from_str::<Value>(&original) {
        Ok(parsed) => {
            let sanitized_value = sanitize_value(&parsed, &mut changed);
            serde_json::to_string(&sanitized_value).unwrap_or_default()
        }
        Err(_) => {
            let s = sanitize_string(&original);
            changed = s != original;
            s
        }
    };
    if !changed {
        return ProducedArtifactResult { artifact: artifact.clone(), valid: true, sensitive: false };
    }
    let mut rest = obj.clone();
    rest.remove("content");
    rest.remove("bytesBase64");
    rest.remove("digest");
    rest.insert("content".to_string(), Value::String(sanitized_text.clone()));
    rest.insert(
        "digest".to_string(),
        Value::String(format!("sha256:{}", hex::encode(Sha256::digest(sanitized_text.as_bytes())))),
    );
    ProducedArtifactResult { artifact: Value::Object(rest), valid: true, sensitive: true }
}
