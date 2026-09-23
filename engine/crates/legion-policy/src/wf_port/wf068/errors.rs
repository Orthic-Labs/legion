//! Port of the `ArcaneError` shape from `src/lib/contracts/arcane/errors.mjs`,
//! scoped to the codes this chunk's three modules actually raise
//! (`ARC_SCHEMA_INVALID`). The full 40+ code taxonomy already exists
//! natively at `legion_arcane::ArcaneError` (`engine/crates/legion-arcane/src/error.rs`);
//! `legion-policy` does not depend on `legion-arcane` today (see the wf068
//! report), so this is a minimal, code-compatible stand-in rather than a
//! duplicate of the whole enum. Callers that need the full taxonomy should
//! use `legion_arcane::ArcaneError` once a dependency edge exists.

use serde_json::Value;
use std::fmt;

/// A typed Arcane refusal: `code`, human `message`, and optional structured
/// `details` — mirrors the JS `ArcaneError` (`new ArcaneError(code, message,
/// details)`), which always carries a machine-readable code and never a bare
/// string.
#[derive(Debug, Clone, PartialEq)]
pub struct ArcaneError {
    pub code: &'static str,
    pub message: String,
    pub details: Option<Value>,
}

impl ArcaneError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), details: None }
    }

    pub fn with_details(code: &'static str, message: impl Into<String>, details: Value) -> Self {
        Self { code, message: message.into(), details: Some(details) }
    }
}

impl fmt::Display for ArcaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ArcaneError {}
