//! Port of `src/lib/review/providers/base.py`.
//!
//! Provider interface + shared types. The Python `Provider` protocol is a
//! trait boundary; its transport (`call`) is HTTP I/O, which this crate does
//! not own (see `gemini.rs` / `minimax_anthropic.rs` doc comments for the
//! network gap). What ports faithfully is the pure data shape: `JurorResult`
//! (with its `to_dict` field set) and `ProviderError`.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Mirrors the Python `@dataclass JurorResult`, including its
/// `field(default_factory=...)` defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JurorResult {
    pub juror_id: String,
    pub provider: String,
    pub model: String,
    #[serde(default = "default_verdict")]
    pub verdict: String,
    #[serde(default)]
    pub score: i64,
    #[serde(default)]
    pub top_concern: String,
    #[serde(default)]
    pub scores: BTreeMap<String, Value>,
    #[serde(default)]
    pub answers: BTreeMap<String, Value>,
    #[serde(default)]
    pub blockers: Vec<Value>,
    #[serde(default)]
    pub raw_response: String,
    #[serde(default)]
    pub parsed_ok: bool,
    #[serde(default)]
    pub latency_ms: i64,
    #[serde(default)]
    pub degraded: bool,
    #[serde(default)]
    pub fallback_used: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub cache_hit: bool,
    /// added 2026-07-14 per Fable review
    #[serde(default)]
    pub lens: Option<String>,
    #[serde(default)]
    pub call_count: i64,
    #[serde(default)]
    pub usage: BTreeMap<String, Value>,
    #[serde(default = "default_true")]
    pub usage_complete: bool,
}

fn default_verdict() -> String {
    "ERROR".to_string()
}

fn default_true() -> bool {
    true
}

impl JurorResult {
    /// New result with only the three Python-required (non-default)
    /// fields set; every other field takes its dataclass default.
    pub fn new(juror_id: impl Into<String>, provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            juror_id: juror_id.into(),
            provider: provider.into(),
            model: model.into(),
            verdict: default_verdict(),
            score: 0,
            top_concern: String::new(),
            scores: BTreeMap::new(),
            answers: BTreeMap::new(),
            blockers: Vec::new(),
            raw_response: String::new(),
            parsed_ok: false,
            latency_ms: 0,
            degraded: false,
            fallback_used: false,
            error: None,
            cache_hit: false,
            lens: None,
            call_count: 0,
            usage: BTreeMap::new(),
            usage_complete: true,
        }
    }

    /// Mirrors `JurorResult.to_dict()` (== `dataclasses.asdict(self)`),
    /// producing the equivalent `serde_json::Value` map.
    pub fn to_dict(&self) -> Value {
        serde_json::to_value(self).expect("JurorResult is always representable as JSON")
    }
}

/// Mirrors `class ProviderError(Exception)`: raised on transport / auth /
/// quota failures. The engine catches this and falls through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError {
    pub message: String,
    pub status: Option<i32>,
    pub is_quota: bool,
}

impl ProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: None,
            is_quota: false,
        }
    }

    pub fn with_status(message: impl Into<String>, status: i32, is_quota: bool) -> Self {
        Self {
            message: message.into(),
            status: Some(status),
            is_quota,
        }
    }

    /// No HTTP status (e.g. a transport-level `URLError`), but still
    /// flaggable as quota-retryable.
    pub fn no_status(message: impl Into<String>, is_quota: bool) -> Self {
        Self {
            message: message.into(),
            status: None,
            is_quota,
        }
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProviderError {}

/// An image attachment as passed to `Provider.call(images=...)`:
/// `{"mime": "image/png", "b64": "...", "source": "<path>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProviderImage {
    pub mime: String,
    pub b64: String,
    pub source: Option<String>,
}
