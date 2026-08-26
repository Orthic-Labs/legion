use crate::schema::{Confidence, EvidenceAuthority, Severity};
use legion_contracts::canonical_digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSpan {
    pub rule_id: String,
    pub path: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub text: String,
    pub evidence_hash: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub authority: EvidenceAuthority,
    pub uncertainty: Vec<String>,
    pub remediation: Option<String>,
}

impl EvidenceSpan {
    #[allow(clippy::too_many_arguments)]
    pub fn from_text(
        rule_id: impl Into<String>,
        path: impl Into<String>,
        start: usize,
        end: usize,
        text: String,
        severity: Severity,
        confidence: Confidence,
        authority: EvidenceAuthority,
        uncertainty: Vec<String>,
        remediation: Option<String>,
    ) -> Self {
        let evidence_hash =
            canonical_digest(&text).unwrap_or_else(|_| "sha256:".to_owned() + &"0".repeat(64));
        let mut uncertainty = uncertainty;
        uncertainty.sort();
        uncertainty.dedup();
        Self {
            rule_id: rule_id.into(),
            path: path.into(),
            byte_start: start,
            byte_end: end,
            text,
            evidence_hash,
            severity,
            confidence,
            authority,
            uncertainty,
            remediation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleCoverage {
    pub expected_files: usize,
    pub examined_files: usize,
    pub gaps: Vec<String>,
}

impl RuleCoverage {
    pub fn complete(&self) -> bool {
        self.expected_files > 0
            && self.gaps.is_empty()
            && self.expected_files == self.examined_files
    }
}
