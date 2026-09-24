//! Port of `src/lib/review/providers/openai_compat.py`
//! (`OpenAICompatProvider`, used for NIM/Groq/Cerebras) and the assertions
//! in `test_openai_compat_streaming.py` / `test_minimax_anthropic.py`
//! (the MiniMax test exercises a sibling provider this chunk does not own,
//! but its `call_with_metadata` shape — text/model/usage passthrough on a
//! mocked transport — is the same contract asserted here).
//!
//! **Ported faithfully (pure, network-free):**
//! - key rotation ordering (`failover_only` vs `round_robin`) — [`order_keys`]
//! - per-model stream override lookup (`_stream_for`) — [`stream_for`]
//! - SSE event-stream accumulation (`_read_stream`) — [`read_sse_stream`]
//! - non-streaming response metadata extraction (the `choices[0]` /
//!   `finish_reason` / `usage` branch of `_call_with_key`) —
//!   [`parse_nonstream_response`]
//! - HTTP-status quota classification (`retry_codes_as_quota`) —
//!   [`is_quota_status`]
//! - empty-content detection (`content is None or not content.strip()`) —
//!   [`is_empty_content`]
//! - multipart image/text user-message construction (image-first) —
//!   [`build_user_content`]
//!
//! **Now wired end to end:** `call_with_key`/`call_with_metadata` below
//! perform the actual `{base_url}/chat/completions` POST (streamed or
//! buffered, matching `_stream_for`) through the shared
//! `gemini::HttpTransport` trait (production impl `ReqwestTransport`,
//! `reqwest::blocking`), including the key-exhaustion retry loop that
//! drives [`order_keys`]. The per-key `threading.Lock` + `min_gap_ms`
//! pacing stays the caller's responsibility — same treatment as
//! `minimax_anthropic::wait_ms_before_call` — so this module's own tests
//! stay deterministic and network-free (fake transport).

use std::collections::BTreeMap;

use serde_json::Value;

use super::super::w2_052::gemini::HttpTransport;

pub const ROTATION_FAILOVER: &str = "failover_only";
pub const ROTATION_ROUND_ROBIN: &str = "round_robin";

/// Port of `ProviderError`: `{message, status, is_quota}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError {
    pub message: String,
    pub status: Option<u16>,
    pub is_quota: bool,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProviderError {}

/// Port of `_ordered_keys`: reorder `keys` (each `(env_name, value)`) for
/// call order based on `rotation`.
///
/// - `failover_only` (or anything else): always key1 first (identity order).
/// - `round_robin` with more than one key: rotate the start position using
///   `rr_index` (read then incremented, matching the Python
///   `with self._rr_lock: start = self._rr_index % len(keys); self._rr_index += 1`),
///   then `keys[start:] + keys[:start]`.
///
/// `rr_index` is `&mut` in place of the Python instance's `_rr_index` +
/// `_rr_lock` (caller owns the mutex/atomicity).
pub fn order_keys<T: Clone>(keys: &[T], rotation: &str, rr_index: &mut u64) -> Vec<T> {
    if keys.is_empty() {
        return Vec::new();
    }
    if rotation == ROTATION_ROUND_ROBIN && keys.len() > 1 {
        let start = (*rr_index as usize) % keys.len();
        *rr_index = rr_index.wrapping_add(1);
        let mut out = Vec::with_capacity(keys.len());
        out.extend_from_slice(&keys[start..]);
        out.extend_from_slice(&keys[..start]);
        return out;
    }
    keys.to_vec()
}

/// Port of `_stream_for`: per-model override falling back to the provider
/// default.
pub fn stream_for(model_stream: &BTreeMap<String, bool>, default_stream: bool, model: &str) -> bool {
    *model_stream.get(model).unwrap_or(&default_stream)
}

/// Port of `retry_codes_as_quota` membership check (default `{429}` in the
/// Python constructor: `config.get("retry_codes_as_quota", [429])`).
pub fn is_quota_status(status: u16, retry_codes_as_quota: &[u16]) -> bool {
    retry_codes_as_quota.contains(&status)
}

/// Result of accumulating one SSE response, port of `_read_stream`'s return
/// dict (`text`/`model`/`finish_reason`/`usage`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StreamMetadata {
    pub text: String,
    pub model: Option<String>,
    pub finish_reason: String,
    pub usage: Value,
}

/// Port of `_read_stream`: accumulate SSE `data:` lines into text plus
/// terminal metadata, without estimating usage. `lines` are already
/// UTF-8-decoded, `.strip()`-equivalent trimmed lines (the Python decodes
/// each raw chunk with `"ignore"` errors and `.strip()`s it before this
/// point — decoding is the live-transport half and stays with the caller).
///
/// Matches Python behaviour exactly: non-`data:` lines are skipped; the
/// `[DONE]` sentinel stops accumulation; a line that fails `json.loads` (or
/// whose access raises) is swallowed via the bare `except Exception:
/// continue`; `finish_reason` defaults to `"stream"` when no chunk carried
/// one (`finish_reason or "stream"`).
pub fn read_sse_stream<'a, I: IntoIterator<Item = &'a str>>(lines: I) -> StreamMetadata {
    let mut parts = String::new();
    let mut usage = Value::Null;
    let mut response_model: Option<String> = None;
    let mut finish_reason: Option<String> = None;

    for line in lines {
        let line = line.trim();
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data == "[DONE]" {
            break;
        }
        let Ok(event) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        if let Some(u) = event.get("usage") {
            if !u.is_null() {
                usage = u.clone();
            }
        }
        if let Some(m) = event.get("model").and_then(Value::as_str) {
            response_model = Some(m.to_string());
        }
        let Some(choices) = event.get("choices").and_then(Value::as_array) else {
            continue;
        };
        let Some(choice) = choices.first() else {
            continue;
        };
        if let Some(piece) = choice
            .get("delta")
            .and_then(|d| d.get("content"))
            .and_then(Value::as_str)
        {
            if !piece.is_empty() {
                parts.push_str(piece);
            }
        }
        if let Some(fr) = choice.get("finish_reason") {
            if !fr.is_null() {
                finish_reason = fr.as_str().map(str::to_string).or(Some(fr.to_string()));
            }
        }
    }

    StreamMetadata {
        text: parts,
        model: response_model,
        finish_reason: finish_reason.unwrap_or_else(|| "stream".to_string()),
        usage,
    }
}

/// Port of the non-streaming branch of `_call_with_key`: parse a chat-
/// completions JSON body into `(text, model, finish_reason, usage)`, using
/// `fallback_model` where the response omits `"model"` (`data.get("model")
/// or model`). Returns `None` where the Python would raise a `KeyError`/
/// `IndexError` (`data["choices"][0]`) — the caller maps that to a
/// transport-level `ProviderError` as the Python's uncaught exception does.
pub fn parse_nonstream_response(body: &Value, fallback_model: &str) -> Option<StreamMetadata> {
    let choice = body.get("choices")?.get(0)?;
    let message = choice.get("message").cloned().unwrap_or(Value::Null);
    let content = message.get("content").and_then(Value::as_str).map(str::to_string);
    let finish_reason = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .unwrap_or(fallback_model)
        .to_string();
    let usage = body.get("usage").cloned().unwrap_or(Value::Object(Default::default()));
    Some(StreamMetadata {
        text: content.unwrap_or_default(),
        model: Some(model),
        finish_reason,
        usage,
    })
}

/// Port of `content is None or (isinstance(content, str) and not
/// content.strip())`.
pub fn is_empty_content(content: Option<&str>) -> bool {
    match content {
        None => true,
        Some(c) => c.trim().is_empty(),
    }
}

/// One image attachment, port of the `images` list's `{"mime", "b64"}`
/// dicts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageAttachment {
    pub mime: String,
    pub b64: String,
}

/// Port of the image/text `user_message` construction in `_call_with_key`:
/// image-first multipart content when `images` is non-empty, else a plain
/// string `content`.
pub fn build_user_content(user: &str, images: &[ImageAttachment]) -> Value {
    if images.is_empty() {
        return Value::String(user.to_string());
    }
    let mut content: Vec<Value> = images
        .iter()
        .map(|img| {
            serde_json::json!({
                "type": "image_url",
                "image_url": {
                    "url": format!("data:{};base64,{}", img.mime, img.b64),
                },
            })
        })
        .collect();
    content.push(serde_json::json!({"type": "text", "text": user}));
    Value::Array(content)
}

/// Faithful config for the parts of `OpenAICompatProvider.__init__` that
/// `call_with_key`/`call_with_metadata` need (the rest — key locks, RR
/// cursor — are caller-owned state, per [`order_keys`]'s doc comment).
#[derive(Clone, Debug)]
pub struct OpenAICompatConfig {
    pub name: String,
    pub base_url: String,
    pub timeout_s: i64,
    pub model_timeout_s: BTreeMap<String, i64>,
    pub model_extra_body: BTreeMap<String, serde_json::Map<String, Value>>,
    pub model_stream: BTreeMap<String, bool>,
    pub retry_codes_as_quota: Vec<u16>,
    pub stream: bool,
}

impl OpenAICompatConfig {
    pub fn new(name: impl Into<String>, base_url: &str) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.trim_end_matches('/').to_string(),
            timeout_s: 30,
            model_timeout_s: BTreeMap::new(),
            model_extra_body: BTreeMap::new(),
            model_stream: BTreeMap::new(),
            retry_codes_as_quota: vec![429],
            stream: false,
        }
    }
}

/// Faithful port of the request/response half of `_call_with_key` (the
/// per-key lock + `min_gap_ms` sleep at the top of the Python method is
/// the caller's responsibility, same treatment as
/// `minimax_anthropic::wait_ms_before_call`).
///
/// `images` uses `ImageAttachment` (already defined above) so callers don't
/// need a second image type; `timeout_s` mirrors `self.timeout_s if images
/// else self.model_timeout_s.get(model, self.timeout_s)`.
pub fn call_with_key(
    config: &OpenAICompatConfig,
    transport: &impl HttpTransport,
    key: &str,
    model: &str,
    system: &str,
    user: &str,
    max_tokens: i64,
    images: &[ImageAttachment],
) -> Result<StreamMetadata, ProviderError> {
    let user_content = build_user_content(user, images);
    let user_message = serde_json::json!({ "role": "user", "content": user_content });

    let mut payload = serde_json::Map::new();
    payload.insert("model".into(), Value::String(model.to_string()));
    payload.insert(
        "messages".into(),
        Value::Array(vec![
            serde_json::json!({ "role": "system", "content": system }),
            user_message,
        ]),
    );
    payload.insert("max_tokens".into(), serde_json::json!(max_tokens));
    payload.insert("temperature".into(), serde_json::json!(0.2));
    if let Some(extra) = config.model_extra_body.get(model) {
        for (k, v) in extra {
            payload.insert(k.clone(), v.clone());
        }
    }
    let stream = stream_for(&config.model_stream, config.stream, model);
    if stream {
        payload.insert("stream".into(), Value::Bool(true));
    }
    let body = serde_json::to_string(&Value::Object(payload))
        .map_err(|e| ProviderError { message: format!("{}/{model}: payload encode error: {e}", config.name), status: None, is_quota: false })?;

    let timeout_s = if !images.is_empty() {
        config.timeout_s
    } else {
        *config.model_timeout_s.get(model).unwrap_or(&config.timeout_s)
    };

    let url = format!("{}/chat/completions", config.base_url);
    let accept = if stream { "text/event-stream" } else { "application/json" };
    let auth = format!("Bearer {key}");
    let resp = transport
        .post_json_with_headers(&url, &body, timeout_s, &[("Authorization", auth.as_str()), ("Accept", accept)])
        .map_err(|e| ProviderError { message: format!("{}/{model} URL error: {e}", config.name), status: None, is_quota: true })?;

    if !(200..300).contains(&resp.status) {
        let truncated: String = resp.body.chars().take(200).collect();
        let is_quota = is_quota_status(resp.status as u16, &config.retry_codes_as_quota);
        return Err(ProviderError {
            message: format!("{}/{model} HTTP {}: {truncated}", config.name, resp.status),
            status: Some(resp.status as u16),
            is_quota,
        });
    }

    let metadata = if stream {
        let lines: Vec<&str> = resp.body.lines().collect();
        read_sse_stream(lines)
    } else {
        let data: Value = serde_json::from_str(&resp.body).map_err(|e| ProviderError {
            message: format!("{}/{model}: invalid JSON response: {e}", config.name),
            status: None,
            is_quota: false,
        })?;
        parse_nonstream_response(&data, model).ok_or_else(|| ProviderError {
            message: format!("{}/{model}: malformed response (missing choices)", config.name),
            status: None,
            is_quota: false,
        })?
    };

    if is_empty_content(if metadata.text.is_empty() { None } else { Some(metadata.text.as_str()) }) {
        return Err(ProviderError {
            message: format!("{}/{model} empty content (finish_reason={})", config.name, metadata.finish_reason),
            status: None,
            is_quota: false,
        });
    }

    Ok(StreamMetadata {
        text: metadata.text,
        model: Some(metadata.model.unwrap_or_else(|| model.to_string())),
        finish_reason: metadata.finish_reason,
        usage: metadata.usage,
    })
}

/// Faithful port of `call_with_metadata`'s key-exhaustion retry loop:
/// try each `(env_name, key)` pair in `keys` (already ordered by
/// [`order_keys`]), continuing to the next on a quota `ProviderError` and
/// failing fast on any other error.
pub fn call_with_metadata(
    config: &OpenAICompatConfig,
    transport: &impl HttpTransport,
    keys: &[(String, String)],
    model: &str,
    system: &str,
    user: &str,
    max_tokens: i64,
    images: &[ImageAttachment],
) -> Result<StreamMetadata, ProviderError> {
    if keys.is_empty() {
        return Err(ProviderError {
            message: format!("{}: no API keys set", config.name),
            status: None,
            is_quota: false,
        });
    }
    let mut last_err: Option<ProviderError> = None;
    for (_env_name, key) in keys {
        match call_with_key(config, transport, key, model, system, user, max_tokens, images) {
            Ok(meta) => return Ok(meta),
            Err(e) => {
                let is_quota = e.is_quota;
                last_err = Some(e);
                if is_quota {
                    continue;
                }
                return Err(last_err.unwrap());
            }
        }
    }
    Err(last_err.unwrap_or_else(|| ProviderError {
        message: format!("{}: all keys exhausted", config.name),
        status: None,
        is_quota: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- order_keys / rotation -------------------------------------------------

    #[test]
    fn failover_always_key1_first() {
        let keys = vec!["k1", "k2", "k3"];
        let mut rr = 0u64;
        assert_eq!(order_keys(&keys, ROTATION_FAILOVER, &mut rr), vec!["k1", "k2", "k3"]);
        // failover never advances the cursor.
        assert_eq!(rr, 0);
    }

    #[test]
    fn round_robin_rotates_and_advances_cursor() {
        let keys = vec!["k1", "k2", "k3"];
        let mut rr = 0u64;
        assert_eq!(order_keys(&keys, ROTATION_ROUND_ROBIN, &mut rr), vec!["k1", "k2", "k3"]);
        assert_eq!(order_keys(&keys, ROTATION_ROUND_ROBIN, &mut rr), vec!["k2", "k3", "k1"]);
        assert_eq!(order_keys(&keys, ROTATION_ROUND_ROBIN, &mut rr), vec!["k3", "k1", "k2"]);
        assert_eq!(order_keys(&keys, ROTATION_ROUND_ROBIN, &mut rr), vec!["k1", "k2", "k3"]);
    }

    #[test]
    fn round_robin_single_key_is_a_no_op() {
        let keys = vec!["only"];
        let mut rr = 0u64;
        assert_eq!(order_keys(&keys, ROTATION_ROUND_ROBIN, &mut rr), vec!["only"]);
        assert_eq!(rr, 0);
    }

    #[test]
    fn empty_keys_returns_empty() {
        let keys: Vec<&str> = vec![];
        let mut rr = 0u64;
        assert!(order_keys(&keys, ROTATION_ROUND_ROBIN, &mut rr).is_empty());
    }

    // --- stream_for --------------------------------------------------------
    // Mirrors test_openai_compat_streaming.py::test_per_model_stream_override.

    #[test]
    fn per_model_stream_override() {
        let mut model_stream = BTreeMap::new();
        model_stream.insert("deepseek-ai/deepseek-v4-flash".to_string(), false);
        model_stream.insert("z-ai/glm-5.2".to_string(), true);

        assert!(!stream_for(&model_stream, true, "deepseek-ai/deepseek-v4-flash"));
        assert!(stream_for(&model_stream, true, "z-ai/glm-5.2"));
        assert!(stream_for(&model_stream, true, "other"));
    }

    // --- is_quota_status -----------------------------------------------------

    #[test]
    fn default_quota_codes_is_429_only() {
        let default_codes = [429u16];
        assert!(is_quota_status(429, &default_codes));
        assert!(!is_quota_status(500, &default_codes));
        assert!(!is_quota_status(401, &default_codes));
    }

    #[test]
    fn configured_quota_codes_expand_set() {
        let codes = [429u16, 503];
        assert!(is_quota_status(503, &codes));
    }

    // --- read_sse_stream -----------------------------------------------------

    #[test]
    fn sse_stream_accumulates_content_and_stops_on_done() {
        let lines = [
            "data: {\"model\":\"m1\",\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}",
            "data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}",
            "data: [DONE]",
            "data: {\"choices\":[{\"delta\":{\"content\":\"ignored-after-done\"}}]}",
        ];
        let meta = read_sse_stream(lines);
        assert_eq!(meta.text, "hello");
        assert_eq!(meta.model.as_deref(), Some("m1"));
        assert_eq!(meta.finish_reason, "stop");
        assert_eq!(meta.usage["prompt_tokens"], 1);
        assert_eq!(meta.usage["completion_tokens"], 2);
    }

    #[test]
    fn sse_stream_ignores_non_data_lines_and_malformed_json() {
        let lines = [
            "event: ping",
            "",
            "data: not-json{{",
            "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}",
        ];
        let meta = read_sse_stream(lines);
        assert_eq!(meta.text, "ok");
    }

    #[test]
    fn sse_stream_defaults_finish_reason_to_stream() {
        let lines = ["data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}"];
        let meta = read_sse_stream(lines);
        assert_eq!(meta.finish_reason, "stream");
    }

    #[test]
    fn sse_stream_empty_choices_is_skipped() {
        let lines = ["data: {\"choices\":[]}"];
        let meta = read_sse_stream(lines);
        assert_eq!(meta.text, "");
        assert_eq!(meta.finish_reason, "stream");
    }

    // --- parse_nonstream_response --------------------------------------------
    // Mirrors test_openai_compat_streaming.py::test_call_with_metadata_preserves_nonstream_usage.

    #[test]
    fn nonstream_response_preserves_model_and_usage() {
        let body = serde_json::json!({
            "model": "test-model-revision",
            "choices": [{
                "message": {"content": "{\"verdict\":\"SHIP\"}"},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "total_tokens": 18,
            },
        });
        let meta = parse_nonstream_response(&body, "test-model").unwrap();
        assert_eq!(meta.text, "{\"verdict\":\"SHIP\"}");
        assert_eq!(meta.model.as_deref(), Some("test-model-revision"));
        assert_eq!(meta.finish_reason, "stop");
        assert_eq!(meta.usage["prompt_tokens"], 11);
        assert_eq!(meta.usage["completion_tokens"], 7);
        assert_eq!(meta.usage["total_tokens"], 18);
    }

    #[test]
    fn nonstream_response_falls_back_to_requested_model() {
        let body = serde_json::json!({
            "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
        });
        let meta = parse_nonstream_response(&body, "requested-model").unwrap();
        assert_eq!(meta.model.as_deref(), Some("requested-model"));
    }

    #[test]
    fn nonstream_response_missing_choices_returns_none() {
        let body = serde_json::json!({"model": "m"});
        assert!(parse_nonstream_response(&body, "m").is_none());
    }

    // --- is_empty_content ------------------------------------------------------

    #[test]
    fn empty_content_detection() {
        assert!(is_empty_content(None));
        assert!(is_empty_content(Some("")));
        assert!(is_empty_content(Some("   \n\t")));
        assert!(!is_empty_content(Some("x")));
    }

    // --- build_user_content ----------------------------------------------------

    #[test]
    fn user_content_without_images_is_plain_string() {
        assert_eq!(build_user_content("hello", &[]), Value::String("hello".into()));
    }

    #[test]
    fn user_content_with_images_is_image_first_multipart() {
        let images = vec![ImageAttachment {
            mime: "image/png".to_string(),
            b64: "AAAA".to_string(),
        }];
        let content = build_user_content("describe this", &images);
        let arr = content.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["type"], "image_url");
        assert_eq!(arr[0]["image_url"]["url"], "data:image/png;base64,AAAA");
        assert_eq!(arr[1], serde_json::json!({"type": "text", "text": "describe this"}));
    }
}

#[cfg(test)]
mod call_tests {
    use super::*;
    use crate::wf_port::w2_052::gemini::HttpResponse;
    use std::cell::RefCell;

    struct FakeTransport {
        responses: RefCell<Vec<Result<HttpResponse, String>>>,
    }

    impl FakeTransport {
        fn once(resp: Result<HttpResponse, String>) -> Self {
            Self { responses: RefCell::new(vec![resp]) }
        }
        fn sequence(resps: Vec<Result<HttpResponse, String>>) -> Self {
            // reverse so `.pop()` yields them in call order
            let mut r = resps;
            r.reverse();
            Self { responses: RefCell::new(r) }
        }
    }

    impl HttpTransport for FakeTransport {
        fn post_json(&self, url: &str, body: &str, timeout_s: i64) -> Result<HttpResponse, String> {
            self.post_json_with_headers(url, body, timeout_s, &[])
        }
        fn post_json_with_headers(
            &self,
            _url: &str,
            _body: &str,
            _timeout_s: i64,
            _headers: &[(&str, &str)],
        ) -> Result<HttpResponse, String> {
            self.responses.borrow_mut().pop().expect("fake transport exhausted")
        }
    }

    fn config() -> OpenAICompatConfig {
        OpenAICompatConfig::new("nim", "https://integrate.api.nvidia.com/v1")
    }

    #[test]
    fn call_with_key_parses_nonstream_success() {
        let cfg = config();
        let transport = FakeTransport::once(Ok(HttpResponse {
            status: 200,
            body: serde_json::json!({
                "model": "m1",
                "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            })
            .to_string(),
        }));
        let out = call_with_key(&cfg, &transport, "k1", "m1", "sys", "user", 512, &[]).unwrap();
        assert_eq!(out.text, "hi");
        assert_eq!(out.model.as_deref(), Some("m1"));
        assert_eq!(out.finish_reason, "stop");
    }

    #[test]
    fn call_with_key_parses_stream_success() {
        let mut cfg = config();
        cfg.stream = true;
        let sse_body = [
            "data: {\"model\":\"m1\",\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}",
            "data: [DONE]",
        ]
        .join("\n");
        let transport = FakeTransport::once(Ok(HttpResponse { status: 200, body: sse_body }));
        let out = call_with_key(&cfg, &transport, "k1", "m1", "sys", "user", 512, &[]).unwrap();
        assert_eq!(out.text, "hello");
        assert_eq!(out.finish_reason, "stop");
    }

    #[test]
    fn call_with_key_http_error_is_quota_when_configured() {
        let cfg = config();
        let transport = FakeTransport::once(Ok(HttpResponse { status: 429, body: "slow down".to_string() }));
        let err = call_with_key(&cfg, &transport, "k1", "m1", "sys", "user", 512, &[]).unwrap_err();
        assert!(err.is_quota);
        assert_eq!(err.status, Some(429));
    }

    #[test]
    fn call_with_key_empty_content_errors() {
        let cfg = config();
        let transport = FakeTransport::once(Ok(HttpResponse {
            status: 200,
            body: serde_json::json!({
                "choices": [{"message": {"content": ""}, "finish_reason": "length"}],
            })
            .to_string(),
        }));
        let err = call_with_key(&cfg, &transport, "k1", "m1", "sys", "user", 512, &[]).unwrap_err();
        assert!(err.message.contains("empty content"));
        assert!(!err.is_quota);
    }

    #[test]
    fn call_with_metadata_fails_over_to_second_key_on_quota() {
        let cfg = config();
        let transport = FakeTransport::sequence(vec![
            Ok(HttpResponse { status: 429, body: "rate limited".to_string() }),
            Ok(HttpResponse {
                status: 200,
                body: serde_json::json!({
                    "choices": [{"message": {"content": "second key ok"}, "finish_reason": "stop"}],
                })
                .to_string(),
            }),
        ]);
        let keys = vec![("KEY1".to_string(), "k1".to_string()), ("KEY2".to_string(), "k2".to_string())];
        let out = call_with_metadata(&cfg, &transport, &keys, "m1", "sys", "user", 512, &[]).unwrap();
        assert_eq!(out.text, "second key ok");
    }

    #[test]
    fn call_with_metadata_fails_fast_on_non_quota_error() {
        let cfg = config();
        let transport = FakeTransport::once(Ok(HttpResponse { status: 401, body: "bad auth".to_string() }));
        let keys = vec![("KEY1".to_string(), "k1".to_string()), ("KEY2".to_string(), "k2".to_string())];
        let err = call_with_metadata(&cfg, &transport, &keys, "m1", "sys", "user", 512, &[]).unwrap_err();
        assert_eq!(err.status, Some(401));
    }

    #[test]
    fn call_with_metadata_no_keys_errors() {
        let cfg = config();
        let transport = FakeTransport::once(Ok(HttpResponse { status: 200, body: "{}".to_string() }));
        let err = call_with_metadata(&cfg, &transport, &[], "m1", "sys", "user", 512, &[]).unwrap_err();
        assert!(err.message.contains("no API keys set"));
    }
}
