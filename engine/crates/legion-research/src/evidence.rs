use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
        let expected_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.text.as_bytes()))
        );
        if self.content_digest != expected_digest {
            return Err(ResearchError::InvalidEvidence(
                "content_digest does not match evidence text".into(),
            ));
        }
        if self
            .locator
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ResearchError::InvalidEvidence(
                "opened evidence requires a locator".into(),
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
        if self
            .provenance
            .get("evidence_status")
            .map(|value| value.eq_ignore_ascii_case("lead"))
            .unwrap_or(false)
            || self
                .provenance
                .get("source_type")
                .map(|value| {
                    matches!(
                        value.to_ascii_lowercase().as_str(),
                        "search-hit"
                            | "search-snippet"
                            | "snippet"
                            | "ai-summary"
                            | "provider-answer"
                            | "notebooklm-answer"
                    )
                })
                .unwrap_or(false)
        {
            return Err(ResearchError::InvalidEvidence(
                "lead-only records cannot enter the evidence ledger".into(),
            ));
        }
        if matches!(self.kind, EvidenceKind::SourceAssertion)
            && self
                .provenance
                .get("provider")
                .map(String::is_empty)
                .unwrap_or(true)
        {
            return Err(ResearchError::InvalidEvidence(
                "source evidence requires provider provenance".into(),
            ));
        }
        if matches!(self.kind, EvidenceKind::SourceAssertion) {
            let external = self
                .provenance
                .get("uri")
                .map(|uri| uri.starts_with("http://") || uri.starts_with("https://"))
                .unwrap_or(false);
            if external
                && (self
                    .provenance
                    .get("retrieved_at")
                    .map(String::is_empty)
                    .unwrap_or(true)
                    || self
                        .provenance
                        .get("request_receipt")
                        .map(String::is_empty)
                        .unwrap_or(true))
            {
                return Err(ResearchError::InvalidEvidence(
                    "external source evidence requires retrieval and request receipt provenance"
                        .into(),
                ));
            }
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
        let mut provenance = source.metadata.clone();
        provenance.insert("provider".into(), source.provider.clone());
        provenance.insert("uri".into(), source.uri.clone());
        if let Some(retrieved_at) = &source.retrieved_at {
            provenance.insert("retrieved_at".into(), retrieved_at.clone());
        }
        let record = Self {
            schema_version: 1,
            evidence_id: evidence_id.into(),
            kind,
            source_id: Some(source.source_id.clone()),
            locator: locator.or_else(|| source.evidence_locator()),
            text: source.text.clone(),
            content_digest: source.content_digest.clone(),
            provenance,
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
        if matches!(self.kind, EvidenceKind::SourceAssertion) && self.evidence_ids.len() != 1 {
            return Err(ResearchError::InvalidEvidence(
                "source assertions must remain atomic and bind exactly one evidence record".into(),
            ));
        }
        if matches!(self.kind, EvidenceKind::Uncertainty | EvidenceKind::Unknown)
            && self
                .uncertainty
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        {
            return Err(ResearchError::InvalidEvidence(
                "uncertainty and unknown claims require an uncertainty reason".into(),
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
        if self.records.contains_key(&record.evidence_id) {
            return Err(ResearchError::InvalidEvidence(
                "duplicate evidence id".into(),
            ));
        }
        self.records.insert(record.evidence_id.clone(), record);
        Ok(())
    }

    pub fn add_claim(&mut self, claim: Claim) -> Result<(), ResearchError> {
        let mut claim = claim;
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
        let proof_ceiling = claim
            .evidence_ids
            .iter()
            .filter_map(|id| self.records.get(id))
            .map(Self::record_ceiling)
            .min_by_key(|value| Self::confidence_rank(value))
            .unwrap_or("low");
        if let Some(declared) = claim
            .provenance
            .get("confidence")
            .or_else(|| claim.provenance.get("confidence_ceiling"))
        {
            if !matches!(declared.as_str(), "low" | "medium" | "high") {
                return Err(ResearchError::InvalidEvidence(format!(
                    "claim {} declares unsupported confidence {}",
                    claim.claim_id, declared
                )));
            }
            if Self::confidence_rank(declared) > Self::confidence_rank(proof_ceiling) {
                return Err(ResearchError::InvalidEvidence(format!(
                    "claim {} exceeds bound proof ceiling {} with {} confidence",
                    claim.claim_id, proof_ceiling, declared
                )));
            }
        }
        claim
            .provenance
            .entry("confidence_ceiling".into())
            .or_insert_with(|| proof_ceiling.to_owned());
        if self.claims.contains_key(&claim.claim_id) {
            return Err(ResearchError::InvalidEvidence("duplicate claim id".into()));
        }
        self.claims.insert(claim.claim_id.clone(), claim);
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

    pub fn contradiction_groups(&self) -> BTreeMap<String, Vec<String>> {
        let mut groups = BTreeMap::<String, Vec<String>>::new();
        for record in self.records.values() {
            if let Some(group) = record
                .provenance
                .get("contradiction_group")
                .or_else(|| record.provenance.get("contradicts"))
                .filter(|group| !group.trim().is_empty())
            {
                groups
                    .entry(group.clone())
                    .or_default()
                    .push(record.evidence_id.clone());
            }
        }
        groups.retain(|_, evidence_ids| evidence_ids.len() > 1);
        groups
    }

    fn record_ceiling(record: &EvidenceRecord) -> &str {
        record
            .provenance
            .get("confidence_ceiling")
            .or_else(|| record.provenance.get("confidence"))
            .map(String::as_str)
            .filter(|value| matches!(*value, "low" | "medium" | "high"))
            .unwrap_or("medium")
    }

    fn confidence_rank(value: &str) -> u8 {
        match value {
            "high" => 3,
            "medium" => 2,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, confidence_ceiling: &str, contradiction_group: &str) -> EvidenceRecord {
        let text = format!("opened evidence {id}");
        EvidenceRecord {
            schema_version: 1,
            evidence_id: id.into(),
            kind: EvidenceKind::SourceAssertion,
            source_id: Some(format!("source-{id}")),
            locator: Some(format!("https://example.test/{id}#passage")),
            content_digest: format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes()))),
            text,
            provenance: BTreeMap::from([
                ("provider".into(), format!("provider-{id}")),
                ("uri".into(), format!("https://example.test/{id}")),
                ("retrieved_at".into(), "2026-08-26T00:00:00Z".into()),
                ("request_receipt".into(), format!("request-{id}")),
                ("confidence_ceiling".into(), confidence_ceiling.into()),
                ("contradiction_group".into(), contradiction_group.into()),
            ]),
        }
    }

    #[test]
    fn locator_and_lead_boundaries_reject_unusable_evidence() {
        let mut lead = record("lead", "medium", "");
        lead.provenance
            .insert("source_type".into(), "search-hit".into());
        assert!(lead.validate().is_err());

        let mut missing_locator = record("missing-locator", "medium", "");
        missing_locator.locator = None;
        assert!(missing_locator.validate().is_err());
    }

    #[test]
    fn claim_ceiling_and_contradiction_uncertainty_are_preserved() {
        let mut ledger = EvidenceLedger::new();
        ledger.add(record("one", "low", "group-a")).unwrap();
        ledger.add(record("two", "medium", "group-a")).unwrap();
        let too_confident = Claim {
            schema_version: 1,
            claim_id: "too-confident".into(),
            text: "unsupported high confidence".into(),
            kind: EvidenceKind::SourceAssertion,
            evidence_ids: vec!["one".into()],
            uncertainty: None,
            provenance: BTreeMap::from([("confidence".into(), "high".into())]),
        };
        assert!(ledger.add_claim(too_confident).is_err());

        let groups = ledger.contradiction_groups();
        assert_eq!(groups.get("group-a").map(Vec::len), Some(2));
        let uncertainty = Claim {
            schema_version: 1,
            claim_id: "uncertainty-group-a".into(),
            text: "sources disagree".into(),
            kind: EvidenceKind::Uncertainty,
            evidence_ids: groups["group-a"].clone(),
            uncertainty: Some("contradiction remains unresolved".into()),
            provenance: BTreeMap::from([
                ("contradiction_group".into(), "group-a".into()),
                ("confidence_ceiling".into(), "low".into()),
            ]),
        };
        ledger.add_claim(uncertainty).unwrap();
        assert_eq!(
            ledger
                .claim("uncertainty-group-a")
                .unwrap()
                .uncertainty
                .as_deref(),
            Some("contradiction remains unresolved")
        );
    }
}
