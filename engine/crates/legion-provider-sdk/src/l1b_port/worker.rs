//! L1b literal port of `src/lib/coder-api-worker/api-worker.py`.
//!
//! Ports the pure preflight/shaping logic of the bounded, read-only Coder
//! worker: the confirmed Pi model catalog and fallback chains, prompt/model
//! validation (including the secret-marker preflight), argv construction,
//! redacted receipt shaping, `<think>` stripping, and per-item model
//! selection (`_models_for_item`/`_prepare_prompt`).
//!
//! The actual Pi CLI subprocess execution (`run_pi`, `run_batch`, the
//! `argparse` `main()`) is a process-transport hop, not logic, and is not
//! reproduced here — consistent with the L1 disposition for
//! `transcript_handoff.py`'s `request_continuity`. A caller wires its own
//! process execution around `build_argv`/`redacted_receipt_argv`.

use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;

pub const PI_COMMAND: &str = "pi";
pub const PI_TOOLS: &[&str] = &["read", "grep", "find", "ls"];
pub const NO_THINK: &str = "Return only a concise final answer; do not expose hidden reasoning.";
pub const READ_ONLY_DIRECTIVE: &str = "This is a read-only code-analysis job. Use only the supplied read-only Pi tools. Do not edit, write, delete, execute, or otherwise mutate files.";

pub const FREE_PRIMARY_MODELS: &[&str] = &[
    "opencode/hy3-free",
    "opencode-go/ox-alpha-free",
    "opencode/nemotron-3.5-lightning-free",
    "opencode/muse-spark-1.2-contributor-free",
];
pub const FREE_FALLBACK_MODELS: &[&str] = &[
    "opencode/mimo-v2.5-free",
    "opencode/nemotron-3-ultra-free",
    "opencode/x-preview-f-free",
];
pub const PAID_MODELS: &[&str] = &[
    "opencode-go/glm-5.3",
    "opencode-go/kimi-k3",
    "opencode/deepseek-v4-flash",
    "opencode/deepseek-v4-pro",
];

pub fn free_models() -> Vec<&'static str> {
    FREE_PRIMARY_MODELS.iter().chain(FREE_FALLBACK_MODELS).copied().collect()
}

pub fn model_catalog() -> BTreeSet<&'static str> {
    free_models().into_iter().chain(PAID_MODELS.iter().copied()).collect()
}

/// Fallback chain by name: "free"/"bulk"/"code"/"fast" all resolve to the
/// full free-model list (matching Python's `FALLBACK_CHAINS`), "paid" to
/// the paid list.
pub fn fallback_chain(name: &str) -> Option<Vec<&'static str>> {
    match name {
        "free" | "bulk" | "code" | "fast" => Some(free_models()),
        "paid" => Some(PAID_MODELS.to_vec()),
        _ => None,
    }
}

pub const MAX_FALLBACK_ATTEMPTS: usize = 2;
pub const MAX_POOL_SIZE: u32 = 8;
pub const MAX_PROMPT_CHARS: usize = 120_000;
pub const MAX_OUTPUT_CHARS: usize = 80_000;
pub const MAX_RECEIPT_TEXT_CHARS: usize = 2_000;
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 90;
pub const MAX_TIMEOUT_SECONDS: u32 = 600;

fn secret_markers() -> &'static [Regex] {
    static RE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        vec![
            Regex::new(r"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").unwrap(),
            Regex::new(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]").unwrap(),
            Regex::new(r"(?i)(?:^|[\\/])\.env(?:$|[\\/])").unwrap(),
        ]
    });
    &RE
}

fn think_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)^\s*<think>.*?</think>\s*").unwrap());
    &RE
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerFailure {
    pub code: String,
    pub message: String,
}

impl WorkerFailure {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}

impl std::fmt::Display for WorkerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for WorkerFailure {}

pub fn clip(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        value.to_string()
    } else {
        let truncated: String = value.chars().take(limit).collect();
        format!("{truncated}\u{2026}")
    }
}

pub fn strip_think(text: &str) -> String {
    think_re().replace(text, "").trim().to_string()
}

pub fn validate_model(model: &str) -> Result<String, WorkerFailure> {
    if !model_catalog().contains(model) {
        return Err(WorkerFailure::new(
            "model_unavailable",
            format!("model is not in confirmed Pi catalog: {model}"),
        ));
    }
    Ok(model.to_string())
}

pub fn validate_prompt(prompt: &str) -> Result<String, WorkerFailure> {
    if prompt.trim().is_empty() {
        return Err(WorkerFailure::new("invalid_prompt", "a non-empty prompt is required"));
    }
    if prompt.chars().count() > MAX_PROMPT_CHARS {
        return Err(WorkerFailure::new(
            "prompt_too_large",
            format!("prompt exceeds {MAX_PROMPT_CHARS} characters"),
        ));
    }
    for marker in secret_markers() {
        if marker.is_match(prompt) {
            return Err(WorkerFailure::new(
                "unsafe_input",
                "prompt appears to contain credentials or key material; redact it first",
            ));
        }
    }
    Ok(prompt.to_string())
}

/// Build argv without shell interpolation or mutation-capable tools.
pub fn build_argv(model: &str, prompt: &str) -> Result<Vec<String>, WorkerFailure> {
    validate_model(model)?;
    validate_prompt(prompt)?;
    Ok(vec![
        PI_COMMAND.to_string(),
        "--tools".to_string(),
        PI_TOOLS.join(","),
        "--no-session".to_string(),
        "--no-extensions".to_string(),
        "--no-skills".to_string(),
        "--no-prompt-templates".to_string(),
        "--no-themes".to_string(),
        "--no-context-files".to_string(),
        "--model".to_string(),
        model.to_string(),
        "-p".to_string(),
        prompt.to_string(),
    ])
}

/// Mirrors `_receipt_base`'s argv redaction: replaces the value following
/// `-p` with `<prompt-redacted>` so receipts never carry the raw prompt.
pub fn redacted_argv(argv: &[String]) -> Vec<String> {
    let mut safe = argv.to_vec();
    if let Some(index) = safe.iter().position(|a| a == "-p") {
        if let Some(value) = safe.get_mut(index + 1) {
            *value = "<prompt-redacted>".to_string();
        }
    }
    safe
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelSelector {
    Model(String),
    Tier(String),
    Fallback(String),
    Default,
}

/// Port of `_models_for_item`: resolves an explicit model, a tier
/// ("free"/"paid"), a named fallback chain (bounded to
/// `MAX_FALLBACK_ATTEMPTS`), or the default free-primary model, in that
/// priority order. `has_unsupported_route` mirrors the Python check for
/// `provider`/`endpoint`/`api_key` keys present on the manifest item,
/// which is rejected outright as an unsupported route.
pub fn models_for_item(
    selector: &ModelSelector,
    has_unsupported_route: bool,
) -> Result<Vec<String>, WorkerFailure> {
    if has_unsupported_route {
        return Err(WorkerFailure::new("unsupported_route", "only Pi CLI execution is supported"));
    }
    match selector {
        ModelSelector::Model(model) => Ok(vec![validate_model(model)?]),
        ModelSelector::Tier(tier) => match tier.as_str() {
            "free" => Ok(vec![FREE_PRIMARY_MODELS[0].to_string()]),
            "paid" => Ok(vec![PAID_MODELS[0].to_string()]),
            other => Err(WorkerFailure::new("invalid_tier", format!("unknown Pi tier: {other}"))),
        },
        ModelSelector::Fallback(name) => match fallback_chain(name) {
            Some(chain) => Ok(chain
                .into_iter()
                .take(MAX_FALLBACK_ATTEMPTS)
                .map(str::to_string)
                .collect()),
            None => Err(WorkerFailure::new("invalid_fallback", format!("unknown Pi fallback: {name}"))),
        },
        ModelSelector::Default => Ok(vec![FREE_PRIMARY_MODELS[0].to_string()]),
    }
}

/// Port of `_prepare_prompt`: wraps the caller's prompt in the read-only
/// directive, system preamble, and a soft token-budget hint, then re-runs
/// prompt validation on the assembled text.
pub fn prepare_prompt(prompt: &str, system: &str, max_tokens: i64) -> Result<String, WorkerFailure> {
    let max_tokens = max_tokens.clamp(128, 16_384);
    let assembled = format!(
        "{READ_ONLY_DIRECTIVE}\n{system}\nKeep response within roughly {max_tokens} tokens.\n\n{prompt}"
    );
    validate_prompt(&assembled)
}
