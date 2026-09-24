//! Port of `src/lib/review/providers/gemini.py`.
//!
//! `GeminiAPIProvider.call` performs a live `urllib.request` POST to the
//! Gemini REST API. That live transport is now wired here through the
//! [`HttpTransport`] trait (production impl [`ReqwestTransport`], backed by
//! `reqwest::blocking` per the r60 packet's allowed-crate list), so `call`
//! below is a faithful, end-to-end port rather than a documented gap.
//! Tests exercise the pure pieces plus `call` against a fake transport —
//! no real network access.
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

/// The result of one POST, exactly what `call` needs from the transport:
/// an HTTP status code plus the raw response body. Mirrors what Python's
/// `urllib.request.urlopen` (success) / `HTTPError` (failure) each expose.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: i32,
    pub body: String,
}

/// Transport boundary standing in for `urllib.request.urlopen` — lets
/// `call` be tested without touching the network, and lets production
/// wire a real client (`ReqwestTransport`) behind the same interface.
pub trait HttpTransport {
    /// Returns `Ok(HttpResponse)` for both 2xx and non-2xx statuses (the
    /// caller inspects `status`, matching how `urllib`'s `HTTPError` still
    /// carries a readable body); `Err(String)` only for a transport-level
    /// failure (DNS, connect, timeout — the `URLError` branch).
    fn post_json(&self, url: &str, body: &str, timeout_s: i64) -> Result<HttpResponse, String>;

    /// Same as `post_json` but with extra request headers layered on top
    /// of `Content-Type`/`User-Agent` — needed by providers (MiniMax) that
    /// send auth via a custom header rather than `Authorization: Bearer`.
    /// Default impl ignores `headers` and delegates to `post_json`, which
    /// is only correct for providers that pass an empty slice; providers
    /// that need headers must override this (as `ReqwestTransport` does).
    fn post_json_with_headers(
        &self,
        url: &str,
        body: &str,
        timeout_s: i64,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, String> {
        let _ = headers;
        self.post_json(url, body, timeout_s)
    }
}

/// Production transport: `reqwest::blocking`, one client per call (mirrors
/// Python's per-request `urllib.request.urlopen`, which does not pool
/// connections across calls either).
pub struct ReqwestTransport;

impl HttpTransport for ReqwestTransport {
    fn post_json(&self, url: &str, body: &str, timeout_s: i64) -> Result<HttpResponse, String> {
        self.post_json_with_headers(url, body, timeout_s, &[])
    }

    fn post_json_with_headers(
        &self,
        url: &str,
        body: &str,
        timeout_s: i64,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, String> {
        let mut builder = reqwest::blocking::Client::builder();
        // `timeout_s == 0` mirrors Python's `timeout=None` (no timeout).
        if timeout_s > 0 {
            builder = builder.timeout(std::time::Duration::from_secs(timeout_s as u64));
        }
        let client = builder.build().map_err(|e| e.to_string())?;
        let mut req = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "jury/0.1 (https://github.com/operator)");
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let resp = req.body(body.to_string()).send().map_err(|e| e.to_string())?;
        let status = resp.status().as_u16() as i32;
        let body = resp.text().map_err(|e| e.to_string())?;
        Ok(HttpResponse { status, body })
    }
}

/// Faithful end-to-end port of `GeminiAPIProvider.call`: resolves the key,
/// builds the URL and payload, POSTs through `transport`, and extracts the
/// candidate text — or maps the failure to the matching `ProviderError`
/// exactly as the Python's `except` branches do.
pub fn call(
    config: &GeminiConfig,
    transport: &impl HttpTransport,
    env_lookup: impl Fn(&str) -> Option<String>,
    model: &str,
    system: &str,
    user: &str,
    max_tokens: i64,
    images: &[ProviderImage],
) -> Result<String, ProviderError> {
    let key = resolve_key(config, env_lookup)?;
    let url = build_request_url(config, model, &key);
    let payload = build_payload(system, user, max_tokens, images);
    let body = serde_json::to_string(&payload)
        .map_err(|e| ProviderError::new(format!("gemini/{model}: payload encode error: {e}")))?;

    match transport.post_json(&url, &body, config.timeout_s) {
        Ok(resp) if (200..300).contains(&resp.status) => {
            let data: Value = serde_json::from_str(&resp.body).map_err(|e| {
                ProviderError::new(format!("gemini/{model}: invalid JSON response: {e}"))
            })?;
            extract_candidate_text(model, &data)
        }
        Ok(resp) => Err(classify_http_error(model, resp.status, &resp.body)),
        Err(message) => Err(classify_url_error(model, &message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTransport {
        response: RefCell<Option<Result<HttpResponse, String>>>,
    }

    impl HttpTransport for FakeTransport {
        fn post_json(&self, _url: &str, _body: &str, _timeout_s: i64) -> Result<HttpResponse, String> {
            self.response
                .borrow_mut()
                .take()
                .expect("fake transport called more than once in a test")
        }
    }

    fn config() -> GeminiConfig {
        GeminiConfig::new("gemini", "https://generativelanguage.googleapis.com/v1", vec!["GEMINI_API_KEY".to_string()], 30)
    }

    fn env_with_key() -> impl Fn(&str) -> Option<String> {
        |name: &str| if name == "GEMINI_API_KEY" { Some("k".to_string()) } else { None }
    }

    #[test]
    fn call_extracts_text_on_success() {
        let cfg = config();
        let transport = FakeTransport {
            response: RefCell::new(Some(Ok(HttpResponse {
                status: 200,
                body: serde_json::json!({
                    "candidates": [{"content": {"parts": [{"text": "hi"}]}}]
                })
                .to_string(),
            }))),
        };
        let out = call(&cfg, &transport, env_with_key(), "gemini-2.5-flash", "sys", "user", 512, &[]).unwrap();
        assert_eq!(out, "hi");
    }

    #[test]
    fn call_classifies_http_error_as_quota() {
        let cfg = config();
        let transport = FakeTransport {
            response: RefCell::new(Some(Ok(HttpResponse {
                status: 429,
                body: "rate limited".to_string(),
            }))),
        };
        let err = call(&cfg, &transport, env_with_key(), "gemini-2.5-flash", "sys", "user", 512, &[]).unwrap_err();
        assert!(err.is_quota);
        assert_eq!(err.status, Some(429));
    }

    #[test]
    fn call_classifies_transport_error_as_quota() {
        let cfg = config();
        let transport = FakeTransport {
            response: RefCell::new(Some(Err("connection refused".to_string()))),
        };
        let err = call(&cfg, &transport, env_with_key(), "gemini-2.5-flash", "sys", "user", 512, &[]).unwrap_err();
        assert!(err.is_quota);
        assert_eq!(err.status, None);
    }

    #[test]
    fn call_missing_key_errors_before_transport() {
        let cfg = config();
        let transport = FakeTransport { response: RefCell::new(None) };
        let err = call(&cfg, &transport, |_| None, "gemini-2.5-flash", "sys", "user", 512, &[]).unwrap_err();
        assert!(err.message.contains("no key in env"));
    }
}
