//! Minimal typed error/decision vocabulary for wf069, scoped to the codes
//! the three ported modules actually raise. Faithful in shape to
//! `src/lib/contracts/arcane/errors.mjs`'s `ArcaneError`/`decision`, but not
//! the full closed code set — `engine/crates/legion-policy/src/arcane_port`
//! owns that (ported separately). See `wf_port::wf067::errors` for the
//! established pattern this mirrors.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArcCode {
    ArcSchemaInvalid,
    ArcClaimPrerequisiteUnmet,
    ArcEvidenceInsufficient,
    ArcProportionalityExcess,
    ArcMandatoryObligationMissing,
}

impl ArcCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArcCode::ArcSchemaInvalid => "ARC_SCHEMA_INVALID",
            ArcCode::ArcClaimPrerequisiteUnmet => "ARC_CLAIM_PREREQUISITE_UNMET",
            ArcCode::ArcEvidenceInsufficient => "ARC_EVIDENCE_INSUFFICIENT",
            ArcCode::ArcProportionalityExcess => "ARC_PROPORTIONALITY_EXCESS",
            ArcCode::ArcMandatoryObligationMissing => "ARC_MANDATORY_OBLIGATION_MISSING",
        }
    }
}

impl fmt::Display for ArcCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Thrown/schema error. Mirrors JS `ArcaneError`.
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
    pub fn allow(message: impl Into<String>, detail: Vec<(String, String)>) -> Self {
        Self { allowed: true, code: None, message: message.into(), detail }
    }
    pub fn deny(code: ArcCode, message: impl Into<String>, detail: Vec<(String, String)>) -> Self {
        Self { allowed: false, code: Some(code), message: message.into(), detail }
    }
}
