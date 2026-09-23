//! Minimal typed error/decision types for wf067, scoped to the codes the
//! five ported modules actually raise. Faithful in shape to
//! `src/lib/contracts/arcane/errors.mjs`'s `ArcaneError`/`decision`, but not
//! the full closed code set — `engine/crates/legion-policy/src/arcane_port`
//! owns that (ported separately, not yet wired). wf067 defines its own small
//! enum rather than depending on an unwired sibling module.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArcCode {
    ArcAuthorityModelClaimed,
    ArcAuthorityNotAsserted,
    ArcAuthKeyUnavailable,
    ArcAuthForged,
    ArcBindingMismatch,
    ArcStoreCorrupt,
    ArcIdInvalid,
    ArcClaimPrerequisiteUnmet,
    ArcReplayNonceSeen,
}

impl ArcCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArcCode::ArcAuthorityModelClaimed => "ARC_AUTHORITY_MODEL_CLAIMED",
            ArcCode::ArcAuthorityNotAsserted => "ARC_AUTHORITY_NOT_ASSERTED",
            ArcCode::ArcAuthKeyUnavailable => "ARC_AUTH_KEY_UNAVAILABLE",
            ArcCode::ArcAuthForged => "ARC_AUTH_FORGED",
            ArcCode::ArcBindingMismatch => "ARC_BINDING_MISMATCH",
            ArcCode::ArcStoreCorrupt => "ARC_STORE_CORRUPT",
            ArcCode::ArcIdInvalid => "ARC_ID_INVALID",
            ArcCode::ArcClaimPrerequisiteUnmet => "ARC_CLAIM_PREREQUISITE_UNMET",
            ArcCode::ArcReplayNonceSeen => "ARC_REPLAY_NONCE_SEEN",
        }
    }
}

impl fmt::Display for ArcCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Thrown error. Mirrors JS `ArcaneError`.
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
}

impl fmt::Display for ArcaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ArcaneError {}

/// A typed decision record: a denial is data the caller must record, not an
/// exception. Mirrors JS `decision()`.
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
}
