//! Port of `src/lib/review/providers/minimax_anthropic.py`.
//!
//! `MiniMaxAnthropicProvider.call`/`call_with_metadata` perform a live
//! `urllib.request` POST to `api.minimax.io/anthropic/v1/messages`. That
//! live transport is wired below through `gemini::HttpTransport` (shared
//! with the sibling Gemini port; production impl `gemini::ReqwestTransport`,
//! `reqwest::blocking`), so `call`/`call_with_metadata` are faithful,
//! end-to-end ports, tested against a fake transport. The Windows registry
//! fallback in `_env_value` (`winreg.OpenKey(HKEY_CURRENT_USER,
//! "Environment")`) is platform-specific I/O outside this port's scope; it
//! is modeled here as a second `env_lookup` closure the caller may wire to
//! that registry read.
//!
//! What ports faithfully is: env-var key resolution across both lookups,
//! the request-payload construction (image content blocks, `system`,
//! `max_tokens`, `temperature`, per-model `model_extra_body` merge), the
//! `min_gap_ms` inter-call wait calculation, response-content extraction
//! (`_content_from_response`), empty-content detection, and HTTP-status /
//! timeout classification against `retry_codes_as_quota`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use super::base::{ProviderError, ProviderImage};
use super::gemini::HttpTransport;

/// Mirrors `MiniMaxAnthropicProvider.__init__`'s stored config.
#[derive(Debug, Clone)]
pub struct MiniMaxConfig {
    pub name: String,
    pub base_url: String,
    pub key_env_names: Vec<String>,
    /// `None` mirrors Python's `timeout_s <= 0 -> None` (no timeout).
    pub timeout_s: Option<i64>,
    pub min_gap_ms: i64,
    pub retry_codes_as_quota: BTreeSet<i32>,
    pub model_extra_body: BTreeMap<String, Map<String, Value>>,
}

impl MiniMaxConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            base_url: "https://api.minimax.io/anthropic/v1".to_string(),
            key_env_names: vec!["MINIMAX_API_KEY".to_string()],
            timeout_s: Some(180),
            min_gap_ms: 0,
            retry_codes_as_quota: [429, 503, 504].into_iter().collect(),
            model_extra_body: BTreeMap::new(),
        }
    }

    /// `config.get("base_url", ...).rstrip("/")`.
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.trim_end_matches('/').to_string();
        self
    }

    /// `None if timeout_s <= 0 else timeout_s`.
    pub fn with_timeout_s(mut self, timeout_s: i64) -> Self {
        self.timeout_s = if timeout_s <= 0 { None } else { Some(timeout_s) };
        self
    }
}

/// Mirrors `_key`: first non-empty value across `key_env_names`, read
/// through `env_lookup` (which itself should already fold in the
/// Windows-registry fallback `_env_value` performs, since that fallback is
/// platform I/O this port does not perform directly).
pub fn resolve_key(
    config: &MiniMaxConfig,
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
        "{}: no API keys set",
        config.name
    )))
}

/// Mirrors `_content_from_response`: concatenate the `"text"` field of
/// every `{"type": "text", ...}` block in `data["content"]`.
pub fn content_from_response(data: &Value) -> String {
    let mut out = String::new();
    let Some(blocks) = data.get("content").and_then(Value::as_array) else {
        return out;
    };
    for block in blocks {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(text) = block.get("text").and_then(Value::as_str) {
                out.push_str(text);
            }
        }
    }
    out
}

/// Mirrors the `content` list built in `call_with_metadata`: image blocks
/// first (in `images` order), then one trailing `{"type": "text", ...}`
/// block for `user`.
pub fn build_content_blocks(user: &str, images: &[ProviderImage]) -> Vec<Value> {
    let mut content: Vec<Value> = Vec::new();
    for img in images {
        content.push(json!({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": img.mime,
                "data": img.b64,
            }
        }));
    }
    content.push(json!({ "type": "text", "text": user }));
    content
}

/// Mirrors the `payload` dict built in `call_with_metadata`, including
/// `payload.update(self.model_extra_body.get(model, {}))` — later
/// `model_extra_body` keys override the base fields of the same name,
/// exactly as Python `dict.update`.
pub fn build_payload(
    config: &MiniMaxConfig,
    model: &str,
    system: &str,
    user: &str,
    max_tokens: i64,
    temperature: f64,
    images: &[ProviderImage],
) -> Value {
    let content = build_content_blocks(user, images);
    let mut payload = Map::new();
    payload.insert("model".into(), json!(model));
    payload.insert("system".into(), json!(system));
    payload.insert(
        "messages".into(),
        json!([{ "role": "user", "content": content }]),
    );
    payload.insert("max_tokens".into(), json!(max_tokens));
    payload.insert("temperature".into(), json!(temperature));
    if let Some(extra) = config.model_extra_body.get(model) {
        for (k, v) in extra {
            payload.insert(k.clone(), v.clone());
        }
    }
    Value::Object(payload)
}

/// Mirrors the `min_gap_ms` throttle in `call_with_metadata`: returns the
/// number of milliseconds the caller should sleep before issuing the
/// request, given `last_call` and `now` as seconds since the same epoch
/// (matching Python's `time.time()` unit). Returns 0 (no wait) when
/// `min_gap_ms <= 0` or the gap has already elapsed.
pub fn wait_ms_before_call(config: &MiniMaxConfig, last_call_s: f64, now_s: f64) -> f64 {
    if config.min_gap_ms <= 0 {
        return 0.0;
    }
    let wait_s = (last_call_s + config.min_gap_ms as f64 / 1000.0) - now_s;
    if wait_s > 0.0 {
        wait_s * 1000.0
    } else {
        0.0
    }
}

/// Mirrors the empty-content guard:
/// `if not content_text.strip(): raise ProviderError(...)`.
pub fn require_non_empty_content(
    config: &MiniMaxConfig,
    model: &str,
    content_text: &str,
    data: &Value,
) -> Result<(), ProviderError> {
    if !content_text.trim().is_empty() {
        return Ok(());
    }
    let stop_reason = data
        .get("stop_reason")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Err(ProviderError::new(format!(
        "{}/{model} empty content (stop_reason={stop_reason})",
        config.name
    )))
}

/// Mirrors the `urllib.error.HTTPError` branch: builds the `ProviderError`
/// from the status code and (already-truncated-to-300-char) response body,
/// classifying `status` as quota-retryable via `retry_codes_as_quota`.
pub fn classify_http_error(
    config: &MiniMaxConfig,
    model: &str,
    status: i32,
    body_text: &str,
) -> ProviderError {
    let truncated: String = body_text.chars().take(300).collect();
    let is_quota = config.retry_codes_as_quota.contains(&status);
    ProviderError::with_status(
        format!("{}/{model} HTTP {status}: {truncated}", config.name),
        status,
        is_quota,
    )
}

/// Mirrors the `urllib.error.URLError` branch: always quota-retryable.
pub fn classify_url_error(config: &MiniMaxConfig, model: &str, message: &str) -> ProviderError {
    ProviderError::no_status(format!("{}/{model} URL error: {message}", config.name), true)
}

/// Mirrors the `(TimeoutError, socket.timeout)` branch: always
/// quota-retryable.
pub fn classify_timeout_error(config: &MiniMaxConfig, model: &str, message: &str) -> ProviderError {
    ProviderError::no_status(format!("{}/{model} timeout: {message}", config.name), true)
}

/// Mirrors the catch-all `except Exception` branch: never quota-retryable.
pub fn classify_generic_error(config: &MiniMaxConfig, model: &str, message: &str) -> ProviderError {
    ProviderError::no_status(format!("{}/{model} error: {message}", config.name), false)
}

/// Convenience: env-var lookup against an in-memory map, used by both
/// production call sites that pre-collect relevant vars and by tests.
pub fn env_lookup_from_map(map: &BTreeMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
    move |name: &str| map.get(name).cloned()
}

/// Result of `call_with_metadata`: text plus stop/usage metadata, mirroring
/// the dict Python returns.
#[derive(Debug, Clone, PartialEq)]
pub struct CallMetadata {
    pub text: String,
    pub model: String,
    pub stop_reason: Option<String>,
    pub stop_sequence: Option<String>,
    pub usage: Value,
}

/// Faithful end-to-end port of `MiniMaxAnthropicProvider.call_with_metadata`:
/// resolves the key, builds the payload (image blocks + trailing text
/// block, `model_extra_body` overlay), POSTs through `transport`, and
/// extracts text + metadata — or maps the failure to the matching
/// `ProviderError`, exactly as the Python's `except` branches do. The
/// `min_gap_ms` pacing sleep is the caller's responsibility (see
/// `wait_ms_before_call`); this function performs no sleep itself so it
/// stays deterministic under test.
#[allow(clippy::too_many_arguments)]
pub fn call_with_metadata(
    config: &MiniMaxConfig,
    transport: &impl HttpTransport,
    env_lookup: impl Fn(&str) -> Option<String>,
    model: &str,
    system: &str,
    user: &str,
    max_tokens: i64,
    temperature: f64,
    images: &[ProviderImage],
) -> Result<CallMetadata, ProviderError> {
    let key = resolve_key(config, env_lookup)?;
    let payload = build_payload(config, model, system, user, max_tokens, temperature, images);
    let body = serde_json::to_string(&payload).map_err(|e| {
        ProviderError::new(format!("{}/{model}: payload encode error: {e}", config.name))
    })?;
    let url = format!("{}/messages", config.base_url);

    let timeout_s = config.timeout_s.unwrap_or(0);
    let post = |body: &str| -> Result<gemini::HttpResponse, String> {
        transport.post_json_with_headers(
            &url,
            body,
            timeout_s,
            &[
                ("x-api-key", key.as_str()),
                ("anthropic-version", "2023-06-01"),
                ("Accept", "application/json"),
            ],
        )
    };

    match post(&body) {
        Ok(resp) if (200..300).contains(&resp.status) => {
            let data: Value = serde_json::from_str(&resp.body).map_err(|e| {
                ProviderError::new(format!("{}/{model}: invalid JSON response: {e}", config.name))
            })?;
            let content_text = content_from_response(&data);
            require_non_empty_content(config, model, &content_text, &data)?;
            Ok(CallMetadata {
                text: content_text,
                model: data
                    .get("model")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| model.to_string()),
                stop_reason: data.get("stop_reason").and_then(Value::as_str).map(str::to_string),
                stop_sequence: data.get("stop_sequence").and_then(Value::as_str).map(str::to_string),
                usage: data.get("usage").cloned().unwrap_or(Value::Object(Default::default())),
            })
        }
        Ok(resp) => Err(classify_http_error(config, model, resp.status, &resp.body)),
        Err(message) => Err(classify_url_error(config, model, &message)),
    }
}

/// Faithful port of `call`: `call_with_metadata(...)["text"]`.
#[allow(clippy::too_many_arguments)]
pub fn call(
    config: &MiniMaxConfig,
    transport: &impl HttpTransport,
    env_lookup: impl Fn(&str) -> Option<String>,
    model: &str,
    system: &str,
    user: &str,
    max_tokens: i64,
    temperature: f64,
    images: &[ProviderImage],
) -> Result<String, ProviderError> {
    call_with_metadata(config, transport, env_lookup, model, system, user, max_tokens, temperature, images)
        .map(|meta| meta.text)
}

use super::gemini;

#[cfg(test)]
mod call_tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTransport {
        response: RefCell<Option<Result<gemini::HttpResponse, String>>>,
    }

    impl HttpTransport for FakeTransport {
        fn post_json(&self, url: &str, body: &str, timeout_s: i64) -> Result<gemini::HttpResponse, String> {
            self.post_json_with_headers(url, body, timeout_s, &[])
        }

        fn post_json_with_headers(
            &self,
            _url: &str,
            _body: &str,
            _timeout_s: i64,
            _headers: &[(&str, &str)],
        ) -> Result<gemini::HttpResponse, String> {
            self.response.borrow_mut().take().expect("fake transport called more than once in a test")
        }
    }

    fn env_with_key() -> impl Fn(&str) -> Option<String> {
        |name: &str| if name == "MINIMAX_API_KEY" { Some("k".to_string()) } else { None }
    }

    #[test]
    fn call_with_metadata_extracts_text_and_usage() {
        let cfg = MiniMaxConfig::new("minimax");
        let transport = FakeTransport {
            response: RefCell::new(Some(Ok(gemini::HttpResponse {
                status: 200,
                body: json!({
                    "model": "minimax-m3",
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "hello"}],
                    "usage": {"input_tokens": 3, "output_tokens": 2},
                })
                .to_string(),
            }))),
        };
        let out = call_with_metadata(&cfg, &transport, env_with_key(), "minimax-m3", "sys", "user", 512, 0.2, &[]).unwrap();
        assert_eq!(out.text, "hello");
        assert_eq!(out.model, "minimax-m3");
        assert_eq!(out.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(out.usage["input_tokens"], 3);
    }

    #[test]
    fn call_with_metadata_empty_content_errors() {
        let cfg = MiniMaxConfig::new("minimax");
        let transport = FakeTransport {
            response: RefCell::new(Some(Ok(gemini::HttpResponse {
                status: 200,
                body: json!({"content": [], "stop_reason": "max_tokens"}).to_string(),
            }))),
        };
        let err = call_with_metadata(&cfg, &transport, env_with_key(), "minimax-m3", "sys", "user", 512, 0.2, &[]).unwrap_err();
        assert!(err.message.contains("max_tokens"));
    }

    #[test]
    fn call_with_metadata_quota_status_is_retryable() {
        let cfg = MiniMaxConfig::new("minimax");
        let transport = FakeTransport {
            response: RefCell::new(Some(Ok(gemini::HttpResponse {
                status: 503,
                body: "overloaded".to_string(),
            }))),
        };
        let err = call_with_metadata(&cfg, &transport, env_with_key(), "minimax-m3", "sys", "user", 512, 0.2, &[]).unwrap_err();
        assert!(err.is_quota);
    }

    #[test]
    fn call_returns_text_only() {
        let cfg = MiniMaxConfig::new("minimax");
        let transport = FakeTransport {
            response: RefCell::new(Some(Ok(gemini::HttpResponse {
                status: 200,
                body: json!({"content": [{"type": "text", "text": "ok"}]}).to_string(),
            }))),
        };
        let out = call(&cfg, &transport, env_with_key(), "minimax-m3", "sys", "user", 512, 0.2, &[]).unwrap();
        assert_eq!(out, "ok");
    }
}
