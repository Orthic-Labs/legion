//! Integration tests for wf_port chunk w2_052
//! (`src/lib/review/packet.py`, `src/lib/review/providers/{__init__,base,
//! gemini,minimax_anthropic}.py`).
//!
//! NOTE: depends on the integrator wiring `pub mod wf_port;` (with
//! `pub mod w2_052;` inside it) into `legion-review`'s `lib.rs`.

use std::collections::BTreeMap;

use serde_json::json;

use legion_review::wf_port::w2_052::{
    base::{JurorResult, ProviderError, ProviderImage},
    gemini, minimax_anthropic as minimax, packet, registry,
};

// ---------- packet.py — ported from src/lib/review/tests/test_packet.py ----------

const GOOD_PACKET: &str = "Some preamble text the author wrote above the fence.

```packet
ARTIFACT: src/capture.rs

SUCCESS_CRITERIA:
  - capture loop handles 1k events/sec without drop
  - mean latency under 50ms

NON_GOALS:
  - not touching the renderer
  - not adding new dependencies

CONSTRAINTS:
  - file:src/capture.rs:42 — must not break existing wiring
  - : TS is in Rust, not Python — Rust-only changes

ALTERNATIVES_CONSIDERED:
  - rewrite in tokio — overkill for current load
  - keep status quo — fails the latency goal

KNOWN_WEAKNESSES:
  - ignores backpressure on full buffer
  - lacks structured shutdown
  - no metric for dropped frames

USER_INTENTION:
  - Want: lighter, less-hungry capture loop on Windows
  - Mechanism: native Win32 hook — one of several

OMISSIONS:
  - did not benchmark on macOS
```

Trailing text is allowed.
";

const EMPTY_BODY: &str = "```packet
ARTIFACT:

SUCCESS_CRITERIA:

NON_GOALS:

CONSTRAINTS:

ALTERNATIVES_CONSIDERED:

KNOWN_WEAKNESSES:

USER_INTENTION:

OMISSIONS:
```
";

const NO_FENCE: &str = "Just prose, no fence at all.";

const SOLE_VIABLE_PACKET: &str = "```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - works

NON_GOALS:
  - no GUI

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - sole_viable: only one option exists; the alternatives are dominated because the codebase restricts changes to Rust files (CONSTRAINTS)

KNOWN_WEAKNESSES:
  - bug 1
  - bug 2
  - bug 3

USER_INTENTION:
  - Want: thing

OMISSIONS:
  - nothing
```
";

const MISSING_USER_INTENTION: &str = "```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - alt A — rejected
  - alt B — rejected

KNOWN_WEAKNESSES:
  - wk1
  - wk2
  - wk3

OMISSIONS:
  - nothing
```
";

const MISSING_OMISSIONS: &str = "```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - alt A — rejected
  - alt B — rejected

KNOWN_WEAKNESSES:
  - wk1
  - wk2
  - wk3

USER_INTENTION:
  - Want: x
```
";

const KWN_TOO_FEW: &str = "```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - alt A — rejected
  - alt B — rejected

KNOWN_WEAKNESSES:
  - wk1
  - wk2

USER_INTENTION:
  - Want: x

OMISSIONS:
  - nothing
```
";

const ALT_TOO_FEW: &str = "```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - file:src/x.rs:1 — bind

ALTERNATIVES_CONSIDERED:
  - alt A — rejected

KNOWN_WEAKNESSES:
  - wk1
  - wk2
  - wk3

USER_INTENTION:
  - Want: x

OMISSIONS:
  - nothing
```
";

const BAD_CONSTRAINTS: &str = "```packet
ARTIFACT: src/x.rs

SUCCESS_CRITERIA:
  - one

NON_GOALS:
  - none

CONSTRAINTS:
  - this is fine because we say so

ALTERNATIVES_CONSIDERED:
  - alt A
  - alt B

KNOWN_WEAKNESSES:
  - wk1
  - wk2
  - wk3

USER_INTENTION:
  - Want: x

OMISSIONS:
  - nothing
```
";

#[test]
fn good_packet_passes() {
    let v = packet::validate_packet(GOOD_PACKET);
    assert!(v.ok, "expected ok=true, got errors={:?}, warnings={:?}", v.errors, v.warnings);
    assert!(v.errors.is_empty());
    assert!(v.warnings.is_empty());
}

#[test]
fn no_fence_fails() {
    let v = packet::validate_packet(NO_FENCE);
    assert!(!v.ok);
    assert!(v.errors.contains(&packet::NO_PACKET_FENCE.to_string()));
    assert!(v.is_legacy_no_packet());
}

#[test]
fn empty_body_fails() {
    let v = packet::validate_packet(EMPTY_BODY);
    assert!(!v.ok);
    assert!(v.errors.len() >= 5, "errors={:?}", v.errors);
}

#[test]
fn sole_viable_marker_accepted() {
    let v = packet::validate_packet(SOLE_VIABLE_PACKET);
    assert!(v.ok, "errors={:?} warnings={:?}", v.errors, v.warnings);
    assert!(v.warnings.iter().any(|w| w.contains("sole_viable")));
}

#[test]
fn missing_user_intention_warns_not_errors() {
    let v = packet::validate_packet(MISSING_USER_INTENTION);
    assert!(v.ok);
    assert!(v.warnings.iter().any(|w| w.contains("USER_INTENTION")));
}

#[test]
fn missing_omissions_warns() {
    let v = packet::validate_packet(MISSING_OMISSIONS);
    assert!(v.ok);
    assert!(v.warnings.iter().any(|w| w.contains("OMISSIONS")));
}

#[test]
fn known_weaknesses_too_few_errors() {
    let v = packet::validate_packet(KWN_TOO_FEW);
    assert!(!v.ok);
    assert!(v.errors.iter().any(|e| e.contains("KNOWN_WEAKNESSES")));
}

#[test]
fn alternatives_too_few_errors() {
    let v = packet::validate_packet(ALT_TOO_FEW);
    assert!(!v.ok);
    assert!(v.errors.iter().any(|e| e.contains("ALTERNATIVES_CONSIDERED")));
}

#[test]
fn bad_constraint_warns_not_errors() {
    let v = packet::validate_packet(BAD_CONSTRAINTS);
    assert!(v.ok);
    assert!(v.warnings.iter().any(|w| w.contains("CONSTRAINTS")));
}

#[test]
fn extract_packet_returns_map() {
    let sections = packet::extract_packet(GOOD_PACKET).expect("fence present");
    assert_eq!(sections.get("ARTIFACT").map(String::as_str), Some("src/capture.rs"));
    assert!(!sections.contains_key("UNKNOWN"));
}

#[test]
fn packet_required_sections_match() {
    assert_eq!(
        packet::PACKET_REQUIRED_SECTIONS,
        &[
            "ARTIFACT",
            "SUCCESS_CRITERIA",
            "NON_GOALS",
            "CONSTRAINTS",
            "ALTERNATIVES_CONSIDERED",
            "KNOWN_WEAKNESSES",
            "USER_INTENTION",
            "OMISSIONS",
        ]
    );
}

#[test]
fn render_skeleton_includes_all_sections() {
    let text = packet::render_packet_skeleton(Some("plan"));
    for section in packet::PACKET_REQUIRED_SECTIONS {
        assert!(text.contains(section), "section {section} missing from skeleton");
    }
}

// ---------- providers/base.py ----------

#[test]
fn juror_result_defaults_match_dataclass() {
    let r = JurorResult::new("j1", "gemini", "gemini-2.0-flash");
    assert_eq!(r.verdict, "ERROR");
    assert_eq!(r.score, 0);
    assert_eq!(r.top_concern, "");
    assert!(r.scores.is_empty());
    assert!(r.answers.is_empty());
    assert!(r.blockers.is_empty());
    assert_eq!(r.raw_response, "");
    assert!(!r.parsed_ok);
    assert_eq!(r.latency_ms, 0);
    assert!(!r.degraded);
    assert!(!r.fallback_used);
    assert_eq!(r.error, None);
    assert!(!r.cache_hit);
    assert_eq!(r.lens, None);
    assert_eq!(r.call_count, 0);
    assert!(r.usage.is_empty());
    assert!(r.usage_complete);
}

#[test]
fn juror_result_to_dict_round_trips() {
    let mut r = JurorResult::new("j1", "gemini", "gemini-2.0-flash");
    r.verdict = "CONFIRMED".to_string();
    r.score = 3;
    let dict = r.to_dict();
    assert_eq!(dict["juror_id"], "j1");
    assert_eq!(dict["provider"], "gemini");
    assert_eq!(dict["model"], "gemini-2.0-flash");
    assert_eq!(dict["verdict"], "CONFIRMED");
    assert_eq!(dict["score"], 3);
    assert_eq!(dict["usage_complete"], true);
}

#[test]
fn provider_error_display_and_fields() {
    let e = ProviderError::with_status("boom", 429, true);
    assert_eq!(e.to_string(), "boom");
    assert_eq!(e.status, Some(429));
    assert!(e.is_quota);

    let e2 = ProviderError::no_status("net down", true);
    assert_eq!(e2.status, None);
    assert!(e2.is_quota);
}

// ---------- providers/__init__.py ----------

#[test]
fn build_provider_dispatch_table() {
    for t in ["openai_compat", "minimax_anthropic", "gemini_api", "subprocess"] {
        assert!(registry::known_provider_type(t), "{t} should be known");
    }
    assert!(!registry::known_provider_type("bogus"));
    assert_eq!(
        registry::unknown_provider_type_error("bogus"),
        "unknown provider type: bogus"
    );
}

// ---------- providers/gemini.py ----------

fn env_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn gemini_resolve_key_returns_first_nonempty() {
    let config = gemini::GeminiConfig::new(
        "gem",
        "https://generativelanguage.googleapis.com/v1beta/",
        vec!["MISSING_KEY".into(), "GEMINI_API_KEY".into()],
        30,
    );
    assert_eq!(config.base_url, "https://generativelanguage.googleapis.com/v1beta");

    let env = env_map(&[("GEMINI_API_KEY", "abc123")]);
    let key = gemini::resolve_key(&config, gemini::env_lookup_from_map(&env)).unwrap();
    assert_eq!(key, "abc123");
}

#[test]
fn gemini_resolve_key_errors_when_no_key_set() {
    let config = gemini::GeminiConfig::new("gem", "https://x", vec!["GEMINI_API_KEY".into()], 30);
    let env = BTreeMap::new();
    let err = gemini::resolve_key(&config, gemini::env_lookup_from_map(&env)).unwrap_err();
    assert!(err.message.contains("no key in env"));
}

#[test]
fn gemini_build_request_url_matches_python_fstring() {
    let config = gemini::GeminiConfig::new("gem", "https://x/", vec![], 30);
    let url = gemini::build_request_url(&config, "gemini-2.0-flash", "KEY");
    assert_eq!(url, "https://x/models/gemini-2.0-flash:generateContent?key=KEY");
}

#[test]
fn gemini_build_payload_includes_system_and_images() {
    let images = vec![ProviderImage {
        mime: "image/png".into(),
        b64: "AAA".into(),
        source: Some("/tmp/x.png".into()),
    }];
    let payload = gemini::build_payload("sys", "user text", 2048, &images);
    assert_eq!(payload["system_instruction"]["parts"][0]["text"], "sys");
    assert_eq!(payload["contents"][0]["parts"][0]["text"], "user text");
    assert_eq!(
        payload["contents"][0]["parts"][1]["inline_data"]["mime_type"],
        "image/png"
    );
    assert_eq!(payload["generationConfig"]["maxOutputTokens"], 2048);
    assert_eq!(payload["generationConfig"]["temperature"], 0.2);
}

#[test]
fn gemini_extract_candidate_text_concatenates_parts() {
    let data = json!({
        "candidates": [{
            "content": { "parts": [{"text": "Hello, "}, {"text": "world"}] }
        }]
    });
    let text = gemini::extract_candidate_text("gemini-2.0-flash", &data).unwrap();
    assert_eq!(text, "Hello, world");
}

#[test]
fn gemini_extract_candidate_text_errors_on_empty_candidates() {
    let data = json!({ "candidates": [] });
    let err = gemini::extract_candidate_text("gemini-2.0-flash", &data).unwrap_err();
    assert_eq!(err.message, "gemini/gemini-2.0-flash: empty candidates");
}

#[test]
fn gemini_classify_http_error_quota_codes() {
    let e429 = gemini::classify_http_error("m", 429, "rate limited");
    assert!(e429.is_quota);
    let e503 = gemini::classify_http_error("m", 503, "unavailable");
    assert!(e503.is_quota);
    let e400 = gemini::classify_http_error("m", 400, "bad request");
    assert!(!e400.is_quota);
    assert_eq!(e400.message, "gemini/m HTTP 400: bad request");
}

// ---------- providers/minimax_anthropic.py — ported from
// providers/test_minimax_anthropic.py::test_call_with_metadata_preserves_stop_reason_and_usage ----------

#[test]
fn minimax_resolve_key_from_configured_env_name() {
    let config = minimax::MiniMaxConfig::new("test").with_base_url("https://example.invalid");
    let mut config = config;
    config.key_env_names = vec!["MINIMAX_TEST_KEY".into()];
    let env = env_map(&[("MINIMAX_TEST_KEY", "test-only")]);
    let key = minimax::resolve_key(&config, minimax::env_lookup_from_map(&env)).unwrap();
    assert_eq!(key, "test-only");
}

#[test]
fn minimax_build_payload_sets_temperature_and_content() {
    let config = minimax::MiniMaxConfig::new("test").with_base_url("https://example.invalid");
    let payload = minimax::build_payload(&config, "MiniMax-M3", "system", "user", 64, 0.0, &[]);
    assert_eq!(payload["model"], "MiniMax-M3");
    assert_eq!(payload["system"], "system");
    assert_eq!(payload["temperature"], 0.0);
    assert_eq!(payload["max_tokens"], 64);
    assert_eq!(payload["messages"][0]["role"], "user");
    assert_eq!(payload["messages"][0]["content"][0]["type"], "text");
    assert_eq!(payload["messages"][0]["content"][0]["text"], "user");
}

#[test]
fn minimax_content_from_response_matches_fixture() {
    let data = json!({
        "model": "MiniMax-M3",
        "content": [{"type": "text", "text": "[]"}],
        "stop_reason": "max_tokens",
        "stop_sequence": null,
        "usage": {"input_tokens": 12, "output_tokens": 34},
    });
    let text = minimax::content_from_response(&data);
    assert_eq!(text, "[]");
}

#[test]
fn minimax_require_non_empty_content_rejects_blank() {
    let config = minimax::MiniMaxConfig::new("test");
    let data = json!({ "stop_reason": "max_tokens" });
    let err = minimax::require_non_empty_content(&config, "MiniMax-M3", "   ", &data).unwrap_err();
    assert!(err.message.contains("empty content (stop_reason=max_tokens)"));

    assert!(minimax::require_non_empty_content(&config, "MiniMax-M3", "[]", &data).is_ok());
}

#[test]
fn minimax_wait_ms_before_call() {
    let mut config = minimax::MiniMaxConfig::new("test");
    config.min_gap_ms = 1000;
    // last_call was 0.5s ago, gap is 1s -> should wait ~0.5s == 500ms
    let wait = minimax::wait_ms_before_call(&config, 10.0, 10.5);
    assert!((wait - 500.0).abs() < 1e-6, "wait={wait}");

    // gap already elapsed -> no wait
    let wait2 = minimax::wait_ms_before_call(&config, 10.0, 11.5);
    assert_eq!(wait2, 0.0);

    // min_gap_ms == 0 -> never wait
    config.min_gap_ms = 0;
    let wait3 = minimax::wait_ms_before_call(&config, 10.0, 10.0);
    assert_eq!(wait3, 0.0);
}

#[test]
fn minimax_classify_http_error_uses_retry_codes_as_quota() {
    let config = minimax::MiniMaxConfig::new("test");
    let e = minimax::classify_http_error(&config, "MiniMax-M3", 429, "rate limited");
    assert!(e.is_quota);
    assert_eq!(e.status, Some(429));
    let e2 = minimax::classify_http_error(&config, "MiniMax-M3", 400, "bad");
    assert!(!e2.is_quota);
}

#[test]
fn minimax_classify_generic_error_is_never_quota() {
    let config = minimax::MiniMaxConfig::new("test");
    let e = minimax::classify_generic_error(&config, "MiniMax-M3", "boom");
    assert!(!e.is_quota);
    assert_eq!(e.status, None);
}
