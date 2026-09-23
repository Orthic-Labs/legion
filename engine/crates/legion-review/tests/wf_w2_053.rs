//! Integration tests for wf_port chunk w2_053
//! (`src/lib/review/providers/{openai_compat,subprocess_cli}.py`, their
//! contract tests `test_minimax_anthropic.py` /
//! `test_openai_compat_streaming.py`, and `src/lib/review/quick-ask.py`).
//!
//! NOTE: depends on the integrator wiring `pub mod wf_port;` (with
//! `pub mod w2_053;` inside it) into `legion_review::lib.rs`, per the
//! w2_053 assignment contract. Until then this file will not compile.
//!
//! `test_minimax_anthropic.py` targets `providers/minimax_anthropic.py`,
//! which is **not** one of this chunk's owned source files (only its test
//! is in the w2_053 file list) — see `MINIMAX_ANTHROPIC_GAP` below for what
//! that leaves unported, and the chunk report for detail.

use legion_review::wf_port::w2_053::{
    openai_compat::{
        build_user_content, is_empty_content, is_quota_status, order_keys, parse_nonstream_response,
        read_sse_stream, stream_for, ImageAttachment, ROTATION_FAILOVER, ROTATION_ROUND_ROBIN,
    },
    quick_ask::{
        codex_command_template, format_result_block, gemini_command_template, selected_jurors,
        sort_results, validate_question, with_directive, JurorOutcome, JurorSelection,
        DEFAULT_CODEX_MODEL, DEFAULT_GEMINI_MODEL,
    },
    subprocess_cli::{
        build_command, build_full_prompt, exit_error_message, prompt_via_stdin,
        windows_executable_candidates,
    },
};
use std::collections::BTreeMap;

/// `test_openai_compat_streaming.py::test_per_model_stream_override`.
#[test]
fn openai_compat_per_model_stream_override() {
    let mut model_stream = BTreeMap::new();
    model_stream.insert("deepseek-ai/deepseek-v4-flash".to_string(), false);
    model_stream.insert("z-ai/glm-5.2".to_string(), true);

    assert!(!stream_for(&model_stream, true, "deepseek-ai/deepseek-v4-flash"));
    assert!(stream_for(&model_stream, true, "z-ai/glm-5.2"));
    assert!(stream_for(&model_stream, true, "other"));
}

/// `test_openai_compat_streaming.py::test_call_with_metadata_preserves_nonstream_usage`,
/// with the mocked `urlopen` response body passed straight to
/// `parse_nonstream_response` in place of the network round-trip.
#[test]
fn openai_compat_call_with_metadata_preserves_nonstream_usage() {
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

    let meta = parse_nonstream_response(&body, "test-model").expect("choices present");

    assert_eq!(meta.text, "{\"verdict\":\"SHIP\"}");
    assert_eq!(meta.model.as_deref(), Some("test-model-revision"));
    assert_eq!(meta.finish_reason, "stop");
    assert_eq!(
        meta.usage,
        serde_json::json!({
            "prompt_tokens": 11,
            "completion_tokens": 7,
            "total_tokens": 18,
        }),
    );
    assert!(!is_empty_content(Some(meta.text.as_str())));
}

/// `providers/minimax_anthropic.py` (the module `test_minimax_anthropic.py`
/// targets) is not among this chunk's owned files — only the *test* was
/// assigned, not the provider it exercises. It is not covered by
/// `git grep` in `engine/` either (no existing Rust port). Recorded here
/// as the explicit gap rather than silently dropped; see the chunk report.
#[test]
fn minimax_anthropic_provider_is_out_of_chunk_scope_gap() {
    const MINIMAX_ANTHROPIC_GAP: &str =
        "providers/minimax_anthropic.py is exercised by test_minimax_anthropic.py \
         but is not an owned w2_053 source file and has no existing engine/ port; \
         its call_with_metadata (Anthropic-shaped: content[0].text / stop_reason / \
         stop_sequence / usage) is unported.";
    assert!(!MINIMAX_ANTHROPIC_GAP.is_empty());
}

#[test]
fn openai_compat_key_rotation_failover_vs_round_robin() {
    let keys = vec!["A", "B", "C"];
    let mut rr = 0u64;
    assert_eq!(order_keys(&keys, ROTATION_FAILOVER, &mut rr), vec!["A", "B", "C"]);
    assert_eq!(order_keys(&keys, ROTATION_ROUND_ROBIN, &mut rr), vec!["A", "B", "C"]);
    assert_eq!(order_keys(&keys, ROTATION_ROUND_ROBIN, &mut rr), vec!["B", "C", "A"]);
}

#[test]
fn openai_compat_quota_classification_default_and_configured() {
    assert!(is_quota_status(429, &[429]));
    assert!(!is_quota_status(500, &[429]));
    assert!(is_quota_status(503, &[429, 503]));
}

#[test]
fn openai_compat_sse_stream_round_trip() {
    let lines = [
        "data: {\"model\":\"m1\",\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}",
        "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}",
        "data: [DONE]",
    ];
    let meta = read_sse_stream(lines);
    assert_eq!(meta.text, "hello");
    assert_eq!(meta.model.as_deref(), Some("m1"));
    assert_eq!(meta.finish_reason, "stop");
}

#[test]
fn openai_compat_image_first_user_content() {
    let images = vec![ImageAttachment { mime: "image/png".into(), b64: "AAAA".into() }];
    let content = build_user_content("describe", &images);
    let arr = content.as_array().unwrap();
    assert_eq!(arr[0]["type"], "image_url");
    assert_eq!(arr[1]["type"], "text");
}

#[test]
fn subprocess_cli_command_and_stdin_routing() {
    let stdin_template = vec!["codex".to_string(), "exec".to_string(), "-".to_string()];
    assert!(prompt_via_stdin(&stdin_template));
    let argv_template = vec!["mycli".to_string(), "{prompt}".to_string()];
    assert!(!prompt_via_stdin(&argv_template));

    let cmd = build_command(&stdin_template, "gpt-5.5", "SYSTEM\n\n---\n\nUSER");
    assert_eq!(cmd, vec!["codex", "exec", "-"]);

    let full = build_full_prompt("SYSTEM", "USER");
    assert_eq!(full, "SYSTEM\n\n---\n\nUSER");
}

#[test]
fn subprocess_cli_windows_executable_fallback_order() {
    assert_eq!(
        windows_executable_candidates("gemini"),
        vec!["gemini", "gemini.cmd", "gemini.exe", "gemini.bat", "gemini.ps1"],
    );
}

#[test]
fn subprocess_cli_exit_error_message_caps_and_prefers_stderr() {
    let msg = exit_error_message("codex", "gpt-5.5", 1, "stderr text", "stdout text");
    assert_eq!(msg, "codex/gpt-5.5 exit 1: stderr text");

    let long = "e".repeat(5000);
    let capped = exit_error_message("codex", "m", 1, &long, "");
    assert_eq!(capped.len(), "codex/m exit 1: ".len() + 4000);
}

#[test]
fn quick_ask_config_matches_python_constants() {
    assert_eq!(
        codex_command_template(),
        vec!["codex", "exec", "--skip-git-repo-check", "-m", "{model}", "-"],
    );
    assert_eq!(gemini_command_template(), vec!["gemini", "-m", "{model}", "-y"]);
    assert_eq!(DEFAULT_CODEX_MODEL, "gpt-5.5");
    assert_eq!(DEFAULT_GEMINI_MODEL, "gemini-2.5-flash");
}

#[test]
fn quick_ask_only_flag_selects_expected_jurors() {
    assert_eq!(selected_jurors(JurorSelection::parse("codex").unwrap()), vec!["codex"]);
    assert_eq!(selected_jurors(JurorSelection::parse("gemini").unwrap()), vec!["gemini"]);
    assert_eq!(
        selected_jurors(JurorSelection::parse("both").unwrap()),
        vec!["codex", "gemini"],
    );
    assert!(JurorSelection::parse("bogus").is_none());
}

#[test]
fn quick_ask_validates_empty_input() {
    assert!(validate_question("").is_err());
    assert!(validate_question("   ").is_err());
    assert!(validate_question("real question").is_ok());
}

#[test]
fn quick_ask_directive_prefix_and_result_formatting() {
    assert_eq!(with_directive("DIRECTIVE", "Q"), "DIRECTIVE\n\n---\n\nQ");

    let results = vec![
        JurorOutcome { name: "gemini".into(), output: "g out".into(), elapsed_s: 1.2, error: None },
        JurorOutcome {
            name: "codex".into(),
            output: String::new(),
            elapsed_s: 0.4,
            error: Some("timeout".into()),
        },
    ];
    let sorted = sort_results(results);
    assert_eq!(sorted[0].name, "codex");
    assert_eq!(format_result_block(&sorted[0]), "\n========== CODEX (0.4s) ==========\nERROR: timeout");
    assert_eq!(format_result_block(&sorted[1]), "\n========== GEMINI (1.2s) ==========\ng out");
}
