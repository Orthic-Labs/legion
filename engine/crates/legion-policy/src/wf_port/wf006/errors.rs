//! Minimal typed error/decision types for wf006, scoped to the codes the
//! five ported modules actually raise. Faithful in shape to
//! `src/lib/contracts/arcane/errors.mjs`'s `ArcaneError`/`decision`, but not
//! the full closed code set — `engine/crates/legion-policy/src/arcane_port`
//! (ported separately, not yet wired) owns that. wf006 defines its own small
//! enum rather than depending on an unwired sibling module.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArcCode {
    ArcAuthLegacyDigest,
    ArcAuthUnauthenticated,
    ArcAuthForged,
    ArcAuthKeyUnavailable,
    ArcAuthorityModelClaimed,
    ArcBindingMismatch,
    ArcCapabilityRevoked,
    ArcCapabilityExpired,
    ArcCapabilityExhausted,
    ArcCapabilityUnknown,
    ArcStoreCorrupt,
}

impl ArcCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArcCode::ArcAuthLegacyDigest => "ARC_AUTH_LEGACY_DIGEST",
            ArcCode::ArcAuthUnauthenticated => "ARC_AUTH_UNAUTHENTICATED",
            ArcCode::ArcAuthForged => "ARC_AUTH_FORGED",
            ArcCode::ArcAuthKeyUnavailable => "ARC_AUTH_KEY_UNAVAILABLE",
            ArcCode::ArcAuthorityModelClaimed => "ARC_AUTHORITY_MODEL_CLAIMED",
            ArcCode::ArcBindingMismatch => "ARC_BINDING_MISMATCH",
            ArcCode::ArcCapabilityRevoked => "ARC_CAPABILITY_REVOKED",
            ArcCode::ArcCapabilityExpired => "ARC_CAPABILITY_EXPIRED",
            ArcCode::ArcCapabilityExhausted => "ARC_CAPABILITY_EXHAUSTED",
            ArcCode::ArcCapabilityUnknown => "ARC_CAPABILITY_UNKNOWN",
            ArcCode::ArcStoreCorrupt => "ARC_STORE_CORRUPT",
        }
    }

    /// Matches `FAIL_CLOSED_CODES` membership for the codes wf006 uses.
    pub fn is_fail_closed(&self) -> bool {
        matches!(self, ArcCode::ArcAuthKeyUnavailable | ArcCode::ArcStoreCorrupt)
    }
}

impl fmt::Display for ArcCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Thrown/fail-closed error. Mirrors JS `ArcaneError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcaneError {
    pub code: ArcCode,
    pub message: String,
    pub detail: Vec<(String, String)>,
}

impl ArcaneError {
    pub fn new(code: ArcCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), detail: Vec::new() }
    }
    pub fn with_detail(mut self, key: &str, value: impl Into<String>) -> Self {
        self.detail.push((key.to_string(), value.into()));
        self
    }
    pub fn fail_closed(&self) -> bool {
        self.code.is_fail_closed()
    }
}

impl fmt::Display for ArcaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ArcaneError {}

/// A typed decision record. Every gate returns one rather than throwing on
/// denial — a denial is data the caller must record. Mirrors JS `decision()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub code: Option<ArcCode>,
    pub message: String,
    pub detail: Vec<(String, String)>,
}

impl Decision {
    pub fn allow(detail: Vec<(String, String)>) -> Self {
        Self { allowed: true, code: None, message: String::new(), detail }
    }
    pub fn deny(code: ArcCode, message: impl Into<String>, detail: Vec<(String, String)>) -> Self {
        Self { allowed: false, code: Some(code), message: message.into(), detail }
    }
    pub fn fail_closed(&self) -> bool {
        self.code.map(|c| c.is_fail_closed()).unwrap_or(false)
    }
}
