//! Port of `src/lib/review/providers/__init__.py`.
//!
//! `build_provider` dispatches a config's `"type"` to one of four provider
//! classes and raises `ValueError(f"unknown provider type: {t}")` for
//! anything else. Two of those four (`OpenAICompatProvider`,
//! `SubprocessProvider`) live outside this chunk's owned files
//! (`providers/openai_compat.py`, `providers/subprocess_cli.py`) and are
//! not ported here. What this module ports faithfully is the dispatch
//! *decision* — which type string is known and the exact error message
//! for an unknown one — so callers can validate a config's `"type"` before
//! attempting construction.

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
