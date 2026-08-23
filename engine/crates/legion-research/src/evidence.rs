use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{error::ResearchError, source::SourceRecord};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Observation,
    SourceAssertion,
    Synthesis,
    Uncertainty,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub schema_version: u32,
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub source_id: Option<String>,
    pub locator: Option<String>,
    pub text: String,
    pub content_digest: String,
    pub provenance: BTreeMap<String, String>,
}

impl EvidenceRecord {
    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.schema_version != 1 {
            return Err(ResearchError::InvalidEvidence(
                "unsupported evidence schema version".into(),
            ));
        }
        if self.evidence_id.trim().is_empty() || self.text.trim().is_empty() {
            return Err(ResearchError::InvalidEvidence(
                "evidence id and text must be non-empty".into(),
            ));
        }
        if self.content_digest.trim().is_empty() {
            return Err(ResearchError::InvalidEvidence(
                "content_digest must be non-empty".into(),
            ));
        }
        if matches!(self.kind, EvidenceKind::SourceAssertion)
            && self
                .source_id
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .is_none()
        {
            return Err(ResearchError::InvalidEvidence(
                "source assertions require source_id".into(),
            ));
        }
        Ok(())
    }

    pub fn from_source(
        source: &SourceRecord,
        evidence_id: impl Into<String>,
        locator: Option<String>,
        kind: EvidenceKind,
    ) -> Result<Self, ResearchError> {
        source.validate()?;
        let record = Self {
            schema_version: 1,
            evidence_id: evidence_id.into(),
            kind,
            source_id: Some(source.source_id.clone()),
            locator,
            text: source.text.clone(),
            content_digest: source.content_digest.clone(),
            provenance: source.metadata.clone(),
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub schema_version: u32,
    pub claim_id: String,
    pub text: String,
    pub kind: EvidenceKind,
    pub evidence_ids: Vec<String>,
    pub uncertainty: Option<String>,
    pub provenance: BTreeMap<String, String>,
}

impl Claim {
    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.schema_version != 1 {
            return Err(ResearchError::InvalidEvidence(
                "unsupported claim schema version".into(),
            ));
        }
        if self.claim_id.trim().is_empty() || self.text.trim().is_empty() {
            return Err(ResearchError::InvalidEvidence(
                "claim id and text must be non-empty".into(),
            ));
        }
        if self.evidence_ids.is_empty() {
            return Err(ResearchError::InvalidEvidence(format!(
                "claim {} must reference source evidence",
                self.claim_id
            )));
        }
        if self.evidence_ids.iter().any(|id| id.trim().is_empty()) {
            return Err(ResearchError::InvalidEvidence(
                "claim evidence ids must be non-empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvidenceLedger {
    records: BTreeMap<String, EvidenceRecord>,
    claims: BTreeMap<String, Claim>,
}

impl EvidenceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, record: EvidenceRecord) -> Result<(), ResearchError> {
        record.validate()?;
        if self
            .records
            .insert(record.evidence_id.clone(), record)
            .is_some()
        {
            return Err(ResearchError::InvalidEvidence(
                "duplicate evidence id".into(),
            ));
        }
        Ok(())
    }

    pub fn add_claim(&mut self, claim: Claim) -> Result<(), ResearchError> {
        claim.validate()?;
        let missing: Vec<_> = claim
            .evidence_ids
            .iter()
            .filter(|id| !self.records.contains_key(*id))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(ResearchError::InvalidEvidence(format!(
                "claim references unknown evidence: {missing:?}"
            )));
        }
        if self.claims.insert(claim.claim_id.clone(), claim).is_some() {
            return Err(ResearchError::InvalidEvidence("duplicate claim id".into()));
        }
        Ok(())
    }

    pub fn records(&self) -> impl Iterator<Item = &EvidenceRecord> {
        self.records.values()
    }
    pub fn claims(&self) -> impl Iterator<Item = &Claim> {
        self.claims.values()
    }
    pub fn record(&self, id: &str) -> Option<&EvidenceRecord> {
        self.records.get(id)
    }
    pub fn claim(&self, id: &str) -> Option<&Claim> {
        self.claims.get(id)
    }
    pub fn evidence_ids(&self) -> BTreeSet<String> {
        self.records.keys().cloned().collect()
    }
}
