//! Port of `src/lib/review/providers/__init__.py`.
//!
//! `build_provider` dispatches a config's `"type"` to one of four provider
//! classes and raises `ValueError(f"unknown provider type: {t}")` for
//! anything else. Three of those four — `gemini_api`, `minimax_anthropic`,
//! `openai_compat` — are files this packet (r60) owns and are now fully,
//! live-callable ports (see `gemini.rs`/`minimax_anthropic.rs`/
//! `openai_compat.rs`); [`build_provider`] below constructs a
//! [`ProviderHandle`] for each from a generic JSON config object, mirroring
//! each provider's `__init__` field reads (`config.get(k, default)`).
//! `subprocess` (`SubprocessProvider`, in `providers/subprocess_cli.py`) is
//! **not** one of this packet's owned files — its subprocess-orchestration
//! port is a separate packet's responsibility — so `build_provider` still
//! rejects it here with the exact Python-parity behaviour a caller would
//! see today (a config it cannot yet construct), documented explicitly
//! rather than silently mis-dispatched.

use serde_json::Value;

use super::base::ProviderImage;
use super::gemini::{self, GeminiConfig, HttpTransport};
use super::minimax_anthropic::{self, MiniMaxConfig};
use crate::wf_port::w2_053::openai_compat::{self, ImageAttachment, OpenAICompatConfig, ProviderError as OaProviderError};

/// The `"type"` values `build_provider` recognizes.
pub const KNOWN_PROVIDER_TYPES: &[&str] = &["openai_compat", "minimax_anthropic", "gemini_api", "subprocess"];

/// Mirrors the `if t == ...` chain in `build_provider`.
pub fn known_provider_type(provider_type: &str) -> bool {
    KNOWN_PROVIDER_TYPES.contains(&provider_type)
}

/// Mirrors `raise ValueError(f"unknown provider type: {t}")`.
pub fn unknown_provider_type_error(provider_type: &str) -> String {
    format!("unknown provider type: {provider_type}")
}

/// A constructed, live-callable provider — the Rust analogue of what
/// `build_provider` returns for the three types this packet owns.
pub enum ProviderHandle {
    GeminiApi(GeminiConfig),
    MiniMaxAnthropic(MiniMaxConfig),
    OpenAiCompat(OpenAICompatConfig, Vec<String> /* key_env_names, in config order */, String /* rotation */),
}

fn get_str(config: &Value, key: &str, default: &str) -> String {
    config.get(key).and_then(Value::as_str).unwrap_or(default).to_string()
}

fn get_str_list(config: &Value, key: &str, default: &[&str]) -> Vec<String> {
    config
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_else(|| default.iter().map(|s| s.to_string()).collect())
}

fn get_i64(config: &Value, key: &str, default: i64) -> i64 {
    config.get(key).and_then(Value::as_i64).unwrap_or(default)
}

/// Faithful port of `build_provider`'s dispatch for the three provider
/// types this packet owns. `config` is the same generic JSON object
/// `build_provider(name, config: dict)` receives. Returns `Err` with the
/// exact `unknown_provider_type_error` message for `"subprocess"` (out of
/// this packet's scope) or any unrecognized `"type"`.
pub fn build_provider(name: &str, config: &Value) -> Result<ProviderHandle, String> {
    let t = config.get("type").and_then(Value::as_str).unwrap_or_default();
    match t {
        "gemini_api" => {
            let base_url = get_str(config, "base_url", "");
            let keys = get_str_list(config, "keys", &["GEMINI_API_KEY"]);
            let timeout_s = get_i64(config, "timeout_s", 30);
            Ok(ProviderHandle::GeminiApi(GeminiConfig::new(name, &base_url, keys, timeout_s)))
        }
        "minimax_anthropic" => {
            let mut cfg = MiniMaxConfig::new(name);
            if let Some(base_url) = config.get("base_url").and_then(Value::as_str) {
                cfg = cfg.with_base_url(base_url);
            }
            if let Some(keys) = config.get("keys").and_then(Value::as_array) {
                cfg.key_env_names = keys.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
            }
            cfg = cfg.with_timeout_s(get_i64(config, "timeout_s", 180));
            cfg.min_gap_ms = get_i64(config, "min_gap_ms", 0);
            if let Some(codes) = config.get("retry_codes_as_quota").and_then(Value::as_array) {
                cfg.retry_codes_as_quota = codes.iter().filter_map(Value::as_i64).map(|c| c as i32).collect();
            }
            Ok(ProviderHandle::MiniMaxAnthropic(cfg))
        }
        "openai_compat" => {
            let base_url = get_str(config, "base_url", "");
            let mut cfg = OpenAICompatConfig::new(name, &base_url);
            cfg.timeout_s = get_i64(config, "timeout_s", 30);
            cfg.stream = config.get("stream").and_then(Value::as_bool).unwrap_or(false);
            if let Some(map) = config.get("model_timeout_s").and_then(Value::as_object) {
                cfg.model_timeout_s = map.iter().filter_map(|(k, v)| v.as_i64().map(|n| (k.clone(), n))).collect();
            }
            if let Some(map) = config.get("model_stream").and_then(Value::as_object) {
                cfg.model_stream = map.iter().filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b))).collect();
            }
            if let Some(map) = config.get("model_extra_body").and_then(Value::as_object) {
                for (k, v) in map {
                    if let Some(obj) = v.as_object() {
                        cfg.model_extra_body.insert(k.clone(), obj.clone());
                    }
                }
            }
            if let Some(codes) = config.get("retry_codes_as_quota").and_then(Value::as_array) {
                cfg.retry_codes_as_quota = codes.iter().filter_map(Value::as_i64).map(|c| c as u16).collect();
            } else {
                cfg.retry_codes_as_quota = vec![429];
            }
            let key_env_names = get_str_list(config, "keys", &[]);
            let rotation = get_str(config, "rotation", "failover_only");
            Ok(ProviderHandle::OpenAiCompat(cfg, key_env_names, rotation))
        }
        other => Err(unknown_provider_type_error(other)),
    }
}

/// Uniform live call across every `ProviderHandle` variant, mirroring the
/// `Provider.call(...)` protocol every Python provider implements.
/// `env_lookup` resolves API keys (see each provider's `resolve_key`);
/// `rr_index` is the caller-owned round-robin cursor `openai_compat`'s
/// `order_keys` needs for its `rotation: "round_robin"` mode.
#[allow(clippy::too_many_arguments)]
pub fn call(
    handle: &ProviderHandle,
    transport: &impl HttpTransport,
    env_lookup: impl Fn(&str) -> Option<String>,
    rr_index: &mut u64,
    model: &str,
    system: &str,
    user: &str,
    max_tokens: i64,
    images: &[ProviderImage],
) -> Result<String, String> {
    match handle {
        ProviderHandle::GeminiApi(cfg) => {
            gemini::call(cfg, transport, env_lookup, model, system, user, max_tokens, images)
                .map_err(|e| e.message)
        }
        ProviderHandle::MiniMaxAnthropic(cfg) => {
            let images: Vec<_> = images.to_vec();
            minimax_anthropic::call(cfg, transport, env_lookup, model, system, user, max_tokens, 0.2, &images)
                .map_err(|e| e.message)
        }
        ProviderHandle::OpenAiCompat(cfg, key_env_names, rotation) => {
            let all_keys: Vec<(String, String)> = key_env_names
                .iter()
                .filter_map(|name| env_lookup(name).map(|v| (name.clone(), v)))
                .collect();
            let ordered = openai_compat::order_keys(&all_keys, rotation, rr_index);
            let images: Vec<ImageAttachment> = images
                .iter()
                .map(|img| ImageAttachment { mime: img.mime.clone(), b64: img.b64.clone() })
                .collect();
            openai_compat::call_with_metadata(cfg, transport, &ordered, model, system, user, max_tokens, &images)
                .map(|meta| meta.text)
                .map_err(|e: OaProviderError| e.message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_provider_rejects_subprocess_out_of_scope() {
        let err = build_provider("codex", &serde_json::json!({"type": "subprocess"})).unwrap_err();
        assert_eq!(err, "unknown provider type: subprocess");
    }

    #[test]
    fn build_provider_rejects_unknown_type() {
        let err = build_provider("x", &serde_json::json!({"type": "made_up"})).unwrap_err();
        assert_eq!(err, "unknown provider type: made_up");
    }

    #[test]
    fn build_provider_gemini_api_reads_base_url_and_keys() {
        let handle = build_provider(
            "gemini",
            &serde_json::json!({"type": "gemini_api", "base_url": "https://x/", "keys": ["K1"], "timeout_s": 5}),
        )
        .unwrap();
        match handle {
            ProviderHandle::GeminiApi(cfg) => {
                assert_eq!(cfg.base_url, "https://x");
                assert_eq!(cfg.key_env_names, vec!["K1".to_string()]);
                assert_eq!(cfg.timeout_s, 5);
            }
            _ => panic!("expected GeminiApi"),
        }
    }

    #[test]
    fn build_provider_openai_compat_reads_rotation() {
        let handle = build_provider(
            "nim",
            &serde_json::json!({"type": "openai_compat", "base_url": "https://y", "keys": ["A", "B"], "rotation": "round_robin"}),
        )
        .unwrap();
        match handle {
            ProviderHandle::OpenAiCompat(_, keys, rotation) => {
                assert_eq!(keys, vec!["A".to_string(), "B".to_string()]);
                assert_eq!(rotation, "round_robin");
            }
            _ => panic!("expected OpenAiCompat"),
        }
    }
}
