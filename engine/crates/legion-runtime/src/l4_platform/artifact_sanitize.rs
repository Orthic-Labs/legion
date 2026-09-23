//! Port of `src/lib/platform/artifact-sanitize.mjs`.

use super::base64util;
use super::contracts::sha256_bytes;
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;

static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}").unwrap());
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{4,}").unwrap());
static SSN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
static PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\+\d[\d\s().-]{6,}\d|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b|\(\d{3}\)\s*\d{3}[-.\s]\d{4}\b)")
        .unwrap()
});
static TRAILING_IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_$][A-Za-z0-9_$-]*$").unwrap());

fn normalize(value: &str) -> String {
    value.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase()
}

fn common_sensitive_key(key: &str) -> bool {
    key.ends_with("secret")
        || key.ends_with("password")
        || key.ends_with("token")
        || key.ends_with("privatekey")
        || key.ends_with("apikey")
        || key.ends_with("cookie")
        || key.ends_with("authorization")
        || matches!(
            key,
            "email" | "phone" | "phonenumber" | "ssn" | "socialsecuritynumber" | "taxid"
        )
}

/// `configuredKeys(fields)`. Each field may be a plain string, or an object
/// with `path`/`key`; only the trailing identifier segment is normalized.
fn configured_keys(fields: &[Value]) -> Vec<String> {
    fields
        .iter()
        .filter_map(|field| match field {
            Value::String(s) => Some(s.clone()),
            Value::Object(map) => map
                .get("path")
                .and_then(Value::as_str)
                .or_else(|| map.get("key").and_then(Value::as_str))
                .map(str::to_string),
            _ => None,
        })
        .map(|field| {
            let trailing = TRAILING_IDENT.find(&field).map(|m| m.as_str()).unwrap_or(&field);
            normalize(trailing)
        })
        .collect()
}

fn sanitize_string(value: &str) -> String {
    let s = BEARER.replace_all(value, "[REDACTED]");
    let s = EMAIL.replace_all(&s, "[REDACTED]");
    let s = SSN.replace_all(&s, "[REDACTED]");
    let s = PHONE.replace_all(&s, "[REDACTED]");
    s.into_owned()
}

fn sanitize_value(value: &Value, configured: &[String], changed: &mut bool) -> Value {
    match value {
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| sanitize_value(item, configured, changed)).collect())
        }
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, child) in map {
                let normalized = normalize(key);
                if common_sensitive_key(&normalized) || configured.contains(&normalized) {
                    if child.as_str() != Some("[REDACTED]") {
                        *changed = true;
                    }
                    out.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    out.insert(key.clone(), sanitize_value(child, configured, changed));
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

pub struct SanitizedValue {
    pub value: Value,
    pub sensitive: bool,
}

/// `sanitizeSensitiveValue(value, sensitiveFields)`.
pub fn sanitize_sensitive_value(value: &Value, sensitive_fields: &[Value]) -> SanitizedValue {
    let mut changed = false;
    let configured = configured_keys(sensitive_fields);
    let sanitized = sanitize_value(value, &configured, &mut changed);
    SanitizedValue { value: sanitized, sensitive: changed }
}

pub struct SanitizedArtifact {
    pub artifact: Option<Value>,
    pub sensitive: bool,
    pub invalid: bool,
}

/// `sanitizeArtifactContent(artifact, sensitiveFields)`.
pub fn sanitize_artifact_content(artifact: &Value, sensitive_fields: &[Value]) -> SanitizedArtifact {
    let obj = match artifact.as_object() {
        Some(obj) => obj,
        None => return SanitizedArtifact { artifact: Some(artifact.clone()), sensitive: false, invalid: false },
    };
    let has_content = obj.get("content").map(Value::is_string).unwrap_or(false);
    let has_bytes = obj.get("bytesBase64").map(Value::is_string).unwrap_or(false);
    if has_content == has_bytes {
        return SanitizedArtifact { artifact: Some(artifact.clone()), sensitive: false, invalid: false };
    }
    if has_bytes {
        let b64 = obj.get("bytesBase64").and_then(Value::as_str).unwrap_or("");
        if !base64util::is_canonical(b64) {
            return SanitizedArtifact { artifact: None, sensitive: true, invalid: true };
        }
    }
    let original = if has_content {
        obj.get("content").and_then(Value::as_str).unwrap_or("").to_string()
    } else {
        let b64 = obj.get("bytesBase64").and_then(Value::as_str).unwrap_or("");
        let bytes = base64util::decode(b64).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let configured = configured_keys(sensitive_fields);
    let mut changed = false;
    let sanitized: String = match serde_json::from_str::<Value>(&original) {
        Ok(parsed) => {
            let sanitized_value = sanitize_value(&parsed, &configured, &mut changed);
            serde_json::to_string(&sanitized_value).unwrap_or_default()
        }
        Err(_) => {
            let s = sanitize_string(&original);
            changed = s != original;
            s
        }
    };
    if !changed {
        return SanitizedArtifact { artifact: Some(artifact.clone()), sensitive: false, invalid: false };
    }
    let mut rest = obj.clone();
    rest.remove("content");
    rest.remove("bytesBase64");
    rest.remove("digest");
    rest.insert("content".to_string(), Value::String(sanitized.clone()));
    rest.insert("digest".to_string(), Value::String(sha256_bytes(sanitized.as_bytes())));
    SanitizedArtifact { artifact: Some(Value::Object(rest)), sensitive: true, invalid: false }
}

pub struct ProducedArtifact {
    pub artifact: Option<Value>,
    pub valid: bool,
    pub sensitive: bool,
}

/// `sanitizeProducedArtifact(artifact, sensitiveFields)`.
pub fn sanitize_produced_artifact(artifact: &Value, sensitive_fields: &[Value]) -> ProducedArtifact {
    let obj = match artifact.as_object() {
        Some(obj) => obj,
        None => return ProducedArtifact { artifact: None, valid: false, sensitive: false },
    };
    let has_content = obj.get("content").map(Value::is_string).unwrap_or(false);
    let has_bytes = obj.get("bytesBase64").map(Value::is_string).unwrap_or(false);
    if has_content == has_bytes {
        return ProducedArtifact { artifact: None, valid: false, sensitive: false };
    }
    let bytes: Option<Vec<u8>> = if has_content {
        Some(obj.get("content").and_then(Value::as_str).unwrap_or("").as_bytes().to_vec())
    } else {
        let b64 = obj.get("bytesBase64").and_then(Value::as_str).unwrap_or("");
        if base64util::is_canonical(b64) { base64util::decode(b64) } else { None }
    };
    let bytes = match bytes {
        Some(b) if !b.is_empty() => b,
        _ => return ProducedArtifact { artifact: None, valid: false, sensitive: false },
    };
    let expected_digest = sha256_bytes(&bytes);
    let digest = obj.get("digest").and_then(Value::as_str).unwrap_or("");
    if digest != expected_digest {
        return ProducedArtifact { artifact: None, valid: false, sensitive: false };
    }
    let sanitized = sanitize_artifact_content(artifact, sensitive_fields);
    ProducedArtifact { artifact: sanitized.artifact, valid: true, sensitive: sanitized.sensitive }
}

/// `isCanonicalBase64(value)`.
pub fn is_canonical_base64(value: &str) -> bool {
    base64util::is_canonical(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sanitizes_email_and_bearer_tokens() {
        let value = json!({"note": "contact me@example.com with Bearer abcd1234"});
        let result = sanitize_sensitive_value(&value, &[]);
        assert!(result.sensitive);
        assert_eq!(result.value["note"], "contact [REDACTED] with [REDACTED]");
    }

    #[test]
    fn redacts_common_sensitive_keys() {
        let value = json!({"password": "hunter2", "safe": "ok"});
        let result = sanitize_sensitive_value(&value, &[]);
        assert!(result.sensitive);
        assert_eq!(result.value["password"], "[REDACTED]");
        assert_eq!(result.value["safe"], "ok");
    }

    #[test]
    fn produced_artifact_requires_matching_digest() {
        let bytes = b"hello";
        let digest = sha256_bytes(bytes);
        let artifact = json!({"content": "hello", "digest": digest});
        let result = sanitize_produced_artifact(&artifact, &[]);
        assert!(result.valid);

        let bad = json!({"content": "hello", "digest": "sha256:deadbeef"});
        assert!(!sanitize_produced_artifact(&bad, &[]).valid);
    }

    #[test]
    fn rejects_both_or_neither_content_forms() {
        let neither = json!({"digest": "sha256:x"});
        assert!(!sanitize_produced_artifact(&neither, &[]).valid);
        let both = json!({"content": "a", "bytesBase64": "YQ==", "digest": "sha256:x"});
        assert!(!sanitize_produced_artifact(&both, &[]).valid);
    }
}
