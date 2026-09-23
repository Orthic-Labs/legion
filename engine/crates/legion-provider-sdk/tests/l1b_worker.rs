//! Tests for the L1b `api-worker.py` port.

use legion_provider_sdk::l1b_port::{
    build_argv, clip, models_for_item, prepare_prompt, redacted_argv, strip_think,
    validate_model, validate_prompt, ModelSelector, FREE_PRIMARY_MODELS, MAX_FALLBACK_ATTEMPTS,
    MAX_PROMPT_CHARS, PAID_MODELS,
};

#[test]
fn validate_model_accepts_catalog_entries_only() {
    assert!(validate_model(FREE_PRIMARY_MODELS[0]).is_ok());
    let err = validate_model("not-a-real-model").unwrap_err();
    assert_eq!(err.code, "model_unavailable");
}

#[test]
fn validate_prompt_rejects_empty_and_oversized() {
    assert_eq!(validate_prompt("   ").unwrap_err().code, "invalid_prompt");
    let huge = "x".repeat(MAX_PROMPT_CHARS + 1);
    assert_eq!(validate_prompt(&huge).unwrap_err().code, "prompt_too_large");
    assert!(validate_prompt("review this file").is_ok());
}

#[test]
fn validate_prompt_rejects_secret_markers() {
    for bad in [
        "api_key: sk-live-abcdef",
        "-----BEGIN RSA PRIVATE KEY-----",
        "please read src/.env/local",
    ] {
        assert_eq!(validate_prompt(bad).unwrap_err().code, "unsafe_input", "should reject: {bad}");
    }
}

#[test]
fn build_argv_matches_expected_shape() {
    let argv = build_argv(FREE_PRIMARY_MODELS[0], "review this").expect("ok");
    assert_eq!(&argv[..3], &["pi", "--tools", "read,grep,find,ls"]);
    assert!(argv.contains(&"--model".to_string()));
    assert_eq!(argv.last().unwrap(), "review this");
}

#[test]
fn redacted_argv_hides_prompt_value() {
    let argv = build_argv(FREE_PRIMARY_MODELS[0], "secret prompt text").expect("ok");
    let redacted = redacted_argv(&argv);
    assert!(redacted.contains(&"<prompt-redacted>".to_string()));
    assert!(!redacted.iter().any(|a| a == "secret prompt text"));
}

#[test]
fn strip_think_removes_leading_reasoning_block() {
    assert_eq!(strip_think("<think>noise</think>\nanswer"), "answer");
    assert_eq!(strip_think("no think block here"), "no think block here");
}

#[test]
fn clip_truncates_with_ellipsis() {
    assert_eq!(clip("abcdef", 3), "abc\u{2026}");
    assert_eq!(clip("ab", 3), "ab");
}

#[test]
fn models_for_item_resolves_explicit_tier_and_fallback() {
    let free = models_for_item(&ModelSelector::Tier("free".to_string()), false).unwrap();
    assert_eq!(free, vec![FREE_PRIMARY_MODELS[0].to_string()]);

    let paid = models_for_item(&ModelSelector::Tier("paid".to_string()), false).unwrap();
    assert_eq!(paid, vec![PAID_MODELS[0].to_string()]);

    let fallback = models_for_item(&ModelSelector::Fallback("free".to_string()), false).unwrap();
    assert_eq!(fallback.len(), MAX_FALLBACK_ATTEMPTS);

    let default = models_for_item(&ModelSelector::Default, false).unwrap();
    assert_eq!(default, vec![FREE_PRIMARY_MODELS[0].to_string()]);
}

#[test]
fn models_for_item_rejects_unsupported_route() {
    let err = models_for_item(&ModelSelector::Default, true).unwrap_err();
    assert_eq!(err.code, "unsupported_route");
}

#[test]
fn models_for_item_rejects_unknown_tier_and_fallback() {
    assert_eq!(
        models_for_item(&ModelSelector::Tier("gold".to_string()), false).unwrap_err().code,
        "invalid_tier"
    );
    assert_eq!(
        models_for_item(&ModelSelector::Fallback("unknown".to_string()), false).unwrap_err().code,
        "invalid_fallback"
    );
}

#[test]
fn prepare_prompt_wraps_directive_and_clamps_token_budget() {
    let prompt = prepare_prompt("summarize this file", "system note", 4).expect("ok");
    assert!(prompt.contains("read-only code-analysis job"));
    assert!(prompt.contains("system note"));
    assert!(prompt.contains("roughly 128 tokens"));
    assert!(prompt.ends_with("summarize this file"));
}
