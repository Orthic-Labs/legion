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
//! **Not ported (live transport, no Rust counterpart in this crate):**
//! the actual `urllib.request.urlopen` POST to `{base_url}/chat/completions`
//! (`_call_with_key`'s request/response I/O), the per-key `threading.Lock`
//! + `min_gap_ms` pacing, and the key-exhaustion retry loop
//! (`call_with_metadata`) that drives [`order_keys`] against a live call.
//! `Cargo.lock` carries no HTTP client for this crate; see the chunk report
//! for the dependency patch a caller would need to fill this in.

use std::collections::BTreeMap;

use serde_json::Value;

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
