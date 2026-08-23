use std::collections::BTreeSet;

use legion_contracts::FindingId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ReviewError;

/// Epistemic class of source material. Model judgments are never folded into
/// observed repository evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateClass {
    Observed,
    ModelJudgment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidence {
    pub candidate_id: FindingId,
    pub evidence_id: String,
    pub class: CandidateClass,
    pub source_revision: String,
    pub title: String,
    pub severity: String,
    pub message: String,
    pub locations: Vec<String>,
    pub facts: std::collections::BTreeMap<String, Value>,
}

impl CandidateEvidence {
    pub fn validate(&self) -> Result<(), ReviewError> {
        for (field, value) in [
            ("evidence_id", &self.evidence_id),
            ("source_revision", &self.source_revision),
            ("title", &self.title),
            ("message", &self.message),
        ] {
            if value.trim().is_empty() {
                return Err(ReviewError::Invalid(format!("{field} must be non-empty")));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEnvelope {
    pub schema_version: u32,
    pub review_id: String,
    pub evidence_pack: String,
    pub candidates: Vec<CandidateEvidence>,
}

impl CandidateEnvelope {
    pub fn validate(&self) -> Result<(), ReviewError> {
        if self.schema_version != 1 {
            return Err(ReviewError::Invalid(format!(
                "unsupported candidate schema {}",
                self.schema_version
            )));
        }
        if self.review_id.trim().is_empty() || self.evidence_pack.trim().is_empty() {
            return Err(ReviewError::Invalid(
                "review_id and evidence_pack must be non-empty".into(),
            ));
        }
        let mut candidates = BTreeSet::new();
        let mut evidence = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if !candidates.insert(candidate.candidate_id.clone()) {
                return Err(ReviewError::Duplicate(candidate.candidate_id.to_string()));
            }
            if !evidence.insert(candidate.evidence_id.clone()) {
                return Err(ReviewError::Duplicate(candidate.evidence_id.clone()));
            }
        }
        Ok(())
    }

    pub fn candidate(&self, id: &FindingId) -> Option<&CandidateEvidence> {
        self.candidates
            .iter()
            .find(|candidate| &candidate.candidate_id == id)
    }
    pub fn evidence_ids(&self) -> BTreeSet<String> {
        self.candidates
            .iter()
            .map(|candidate| candidate.evidence_id.clone())
            .collect()
    }
}
