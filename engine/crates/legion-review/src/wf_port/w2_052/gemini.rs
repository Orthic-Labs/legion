//! Port of `src/lib/review/providers/gemini.py`.
//!
//! `GeminiAPIProvider.call` performs a live `urllib.request` POST to the
//! Gemini REST API. This crate has no HTTP client dependency (see
//! `legion-review/Cargo.toml`: no `reqwest`/`ureq`/`http` crate), and per
//! the chunk's dependency policy a new one is not added here — see the
//! chunk report for the exact `Cargo.toml` patch (`ureq` or `reqwest`
//! pinned to the version already resolved for `legion-provider-sdk`'s
//! `http_client.rs`, if any) needed to wire live transport.
//!
//! What ports faithfully, and is exactly what the Python does around the
//! network call, is: API-key resolution (first non-empty env var in the
//! configured list, `ProviderError` if none), request-URL construction,
//! request-payload construction (system instruction, multipart image
//! parts, generation config), response-candidate text extraction, and
//! HTTP-status-to-`ProviderError` classification (429/503 == quota-retry).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::base::{ProviderError, ProviderImage};

/// Mirrors `GeminiAPIProvider.__init__`'s stored config.
#[derive(Debug, Clone)]
pub struct GeminiConfig {
    pub name: String,
    pub base_url: String,
    pub key_env_names: Vec<String>,
    pub timeout_s: i64,
}

impl GeminiConfig {
    /// `base_url` is stored with any trailing `/` stripped
    /// (`config["base_url"].rstrip("/")`).
    pub fn new(name: impl Into<String>, base_url: &str, key_env_names: Vec<String>, timeout_s: i64) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.trim_end_matches('/').to_string(),
            key_env_names: if key_env_names.is_empty() {
                vec!["GEMINI_API_KEY".to_string()]
            } else {
                key_env_names
            },
            timeout_s,
        }
    }
}

/// Mirrors `_resolve_key`: first non-empty value across `key_env_names`,
/// read through `env_lookup` (a caller-supplied `os.environ.get` stand-in
/// so this stays testable without touching process env).
pub fn resolve_key(
    config: &GeminiConfig,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, ProviderError> {
    for env_name in &config.key_env_names {
        if let Some(val) = env_lookup(env_name) {
            if !val.is_empty() {
                return Ok(val);
            }
        }
    }
    Err(ProviderError::new(format!(
        "{}: no key in env {:?}",
        config.name, config.key_env_names
    )))
}

/// Mirrors the request-URL construction inside `call`:
/// `f"{base_url}/models/{model}:generateContent?key={key}"`.
pub fn build_request_url(config: &GeminiConfig, model: &str, key: &str) -> String {
    format!("{}/models/{model}:generateContent?key={key}", config.base_url)
}

/// Mirrors the `payload` dict built by `call`, before JSON-encoding.
pub fn build_payload(system: &str, user: &str, max_tokens: i64, images: &[ProviderImage]) -> Value {
    let mut parts: Vec<Value> = vec![json!({ "text": user })];
    for img in images {
        parts.push(json!({
            "inline_data": {
                "mime_type": img.mime,
                "data": img.b64,
            }
        }));
    }
    json!({
        "system_instruction": { "parts": [{ "text": system }] },
        "contents": [{ "parts": parts }],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0.2,
        }
    })
}

/// Mirrors the success path's candidate-text extraction:
/// `data["candidates"][0]["content"]["parts"]`, concatenating every part's
/// `"text"` field (parts without a `"text"` key are skipped — Python's
/// `p.get("text", "")` still concatenates an empty string for them, which
/// is behaviourally identical to skipping for the final joined result).
/// Returns `ProviderError` if `candidates` is empty, exactly as Python's
/// `if not cands: raise ProviderError(...)`.
pub fn extract_candidate_text(model: &str, data: &Value) -> Result<String, ProviderError> {
    let candidates = data.get("candidates").and_then(Value::as_array);
    let candidates = match candidates {
        Some(c) if !c.is_empty() => c,
        _ => {
            return Err(ProviderError::new(format!(
                "gemini/{model}: empty candidates"
            )))
        }
    };
    let parts = candidates[0]
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = String::new();
    for p in &parts {
        if let Some(t) = p.get("text").and_then(Value::as_str) {
            out.push_str(t);
        }
    }
    Ok(out)
}

/// Mirrors the `urllib.error.HTTPError` branch: builds the
/// `ProviderError` from the status code and (already-truncated-to-200-char)
/// response body, classifying 429/503 as quota-retryable.
pub fn classify_http_error(model: &str, status: i32, body_text: &str) -> ProviderError {
    let truncated: String = body_text.chars().take(200).collect();
    let is_quota = matches!(status, 429 | 503);
    ProviderError::with_status(
        format!("gemini/{model} HTTP {status}: {truncated}"),
        status,
        is_quota,
    )
}

/// Mirrors the `urllib.error.URLError` branch: always quota-retryable
/// (transient network failure).
pub fn classify_url_error(model: &str, message: &str) -> ProviderError {
    ProviderError::no_status(format!("gemini/{model} URL error: {message}"), true)
}

/// Convenience: env-var lookup against an in-memory map, used by both
/// production call sites that pre-collect relevant vars and by tests.
pub fn env_lookup_from_map(map: &BTreeMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
    move |name: &str| map.get(name).cloned()
}
