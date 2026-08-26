use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{BudgetCeiling, FindingId};
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

/// A bounded packet handed to an independent reviewer.  It is deliberately
/// data-only: a packet carries the subject, source-bound evidence, and an
/// explicit account of material that was not supplied.  It is not a verdict
/// and cannot close a candidate by itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgmentPacket {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub subject: Value,
    pub evidence: Vec<PacketEvidence>,
    pub omitted: Vec<String>,
    #[serde(rename = "reviewerRole")]
    pub reviewer_role: String,
    #[serde(default)]
    pub lens: Option<BTreeMap<String, Value>>,
    pub budget: BudgetCeiling,
    #[serde(rename = "verdicts")]
    pub allowed_verdicts: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketEvidence {
    pub evidence_id: String,
    pub source_revision: String,
    pub locator: String,
    pub summary: String,
}

impl JudgmentPacket {
    const CANONICAL_VERDICTS: [&'static str; 5] = [
        "confirmed",
        "rejected",
        "unproven",
        "needs-human",
        "unknown",
    ];

    pub fn validate(&self) -> Result<(), ReviewError> {
        if self.schema_version != 1 {
            return Err(ReviewError::Invalid(format!(
                "unsupported judgment packet schema {}",
                self.schema_version
            )));
        }
        if self.subject.is_null() {
            return Err(ReviewError::Invalid(
                "judgment packet subject must be present".into(),
            ));
        }
        if self.evidence.is_empty() && self.omitted.is_empty() {
            return Err(ReviewError::Invalid(
                "judgment packet requires evidence or explicit omissions".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        for evidence in &self.evidence {
            for (field, value) in [
                ("evidence_id", &evidence.evidence_id),
                ("source_revision", &evidence.source_revision),
                ("locator", &evidence.locator),
                ("summary", &evidence.summary),
            ] {
                if value.trim().is_empty() {
                    return Err(ReviewError::Invalid(format!(
                        "packet evidence {field} must be non-empty"
                    )));
                }
            }
            if !ids.insert(evidence.evidence_id.clone()) {
                return Err(ReviewError::Duplicate(evidence.evidence_id.clone()));
            }
        }
        if self.reviewer_role.trim().is_empty() {
            return Err(ReviewError::Invalid(
                "judgment packet reviewer_role must be non-empty".into(),
            ));
        }
        if self.budget.max_active_time_ms == 0 {
            return Err(ReviewError::Invalid(
                "judgment packet requires a positive active-time bound".into(),
            ));
        }
        if self.omitted.iter().any(|item| item.trim().is_empty()) {
            return Err(ReviewError::Invalid(
                "judgment packet omissions must be non-empty".into(),
            ));
        }
        let mut verdicts = BTreeSet::new();
        for verdict in &self.allowed_verdicts {
            if !Self::CANONICAL_VERDICTS.contains(&verdict.as_str()) {
                return Err(ReviewError::Invalid(format!(
                    "judgment packet verdict {verdict} is not canonical"
                )));
            }
            if !verdicts.insert(verdict.as_str()) {
                return Err(ReviewError::Duplicate(verdict.clone()));
            }
        }
        if verdicts.len() != Self::CANONICAL_VERDICTS.len()
            || Self::CANONICAL_VERDICTS
                .iter()
                .any(|verdict| !verdicts.contains(verdict))
        {
            return Err(ReviewError::Invalid(
                "judgment packet allowed_verdicts must equal canonical vocabulary".into(),
            ));
        }
        Ok(())
    }

    pub fn evidence_ids(&self) -> BTreeSet<String> {
        self.evidence
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect()
    }
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
            ("severity", &self.severity),
            ("message", &self.message),
        ] {
            if value.trim().is_empty() {
                return Err(ReviewError::Invalid(format!("{field} must be non-empty")));
            }
        }
        if self.locations.is_empty() || self.locations.iter().any(|item| item.trim().is_empty()) {
            return Err(ReviewError::Invalid(format!(
                "candidate {} requires non-empty evidence locations",
                self.candidate_id
            )));
        }
        if self.facts.keys().any(|key| key.trim().is_empty()) {
            return Err(ReviewError::Invalid(format!(
                "candidate {} has an empty provenance key",
                self.candidate_id
            )));
        }
        if matches!(self.class, CandidateClass::ModelJudgment) && self.producer_provider().is_none()
        {
            return Err(ReviewError::Provenance(format!(
                "model candidate {} requires producer provider identity",
                self.candidate_id
            )));
        }
        Ok(())
    }

    /// Model candidate producers identify themselves in facts so independent
    /// adjudication can reject self-closure. Facts are never provider verdicts.
    pub fn producer_provider(&self) -> Option<&str> {
        ["producer", "provider", "candidate_provider"]
            .iter()
            .find_map(|key| self.facts.get(*key).and_then(Value::as_str))
            .or_else(|| {
                self.facts
                    .get("provenance")
                    .and_then(Value::as_object)
                    .and_then(|provenance| provenance.get("provider"))
                    .and_then(Value::as_str)
            })
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn provenance(&self) -> BTreeMap<String, Value> {
        let mut provenance = BTreeMap::new();
        provenance.insert(
            "source_revision".into(),
            Value::String(self.source_revision.clone()),
        );
        provenance.insert(
            "locations".into(),
            Value::Array(self.locations.iter().cloned().map(Value::String).collect()),
        );
        provenance.extend(self.facts.clone());
        provenance
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
        if self.candidates.is_empty() {
            return Err(ReviewError::Invalid(
                "review packet requires at least one candidate".into(),
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

    /// Build the exact bounded packet a host reviewer may receive.  The
    /// caller must disclose omissions; this conversion never invents missing
    /// evidence or a verdict.
    pub fn judgment_packet(
        &self,
        subject: Value,
        reviewer_role: impl Into<String>,
        budget: BudgetCeiling,
        omitted: Vec<String>,
    ) -> Result<JudgmentPacket, ReviewError> {
        self.validate()?;
        let packet = JudgmentPacket {
            schema_version: 1,
            subject,
            evidence: self
                .candidates
                .iter()
                .map(|candidate| PacketEvidence {
                    evidence_id: candidate.evidence_id.clone(),
                    source_revision: candidate.source_revision.clone(),
                    locator: candidate.locations.join(","),
                    summary: candidate.message.clone(),
                })
                .collect(),
            omitted,
            reviewer_role: reviewer_role.into(),
            lens: None,
            budget,
            allowed_verdicts: vec![
                "confirmed".into(),
                "rejected".into(),
                "unproven".into(),
                "needs-human".into(),
                "unknown".into(),
            ],
        };
        packet.validate()?;
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn packet_requires_source_evidence_and_bound() {
        let packet = JudgmentPacket {
            schema_version: 1,
            subject: json!({"id": "finding-1"}),
            evidence: vec![PacketEvidence {
                evidence_id: "evidence-1".into(),
                source_revision: "git:abc".into(),
                locator: "src/lib.rs:10".into(),
                summary: "observed source fact".into(),
            }],
            omitted: vec!["runtime behavior not exercised".into()],
            reviewer_role: "independent-reviewer".into(),
            lens: Some(BTreeMap::from([("id".into(), json!("audit"))])),
            budget: BudgetCeiling {
                max_active_time_ms: 1000,
                ..BudgetCeiling::default()
            },
            allowed_verdicts: JudgmentPacket::CANONICAL_VERDICTS
                .iter()
                .map(|verdict| (*verdict).into())
                .collect(),
        };
        assert!(packet.validate().is_ok());
        assert_eq!(packet.evidence_ids().len(), 1);
        assert_eq!(packet.lens.as_ref().unwrap()["id"], json!("audit"));
        let wire = serde_json::to_value(&packet).unwrap();
        let wire = wire.as_object().unwrap();
        assert!(wire.contains_key("schemaVersion"));
        assert!(wire.contains_key("reviewerRole"));
        assert!(wire.contains_key("verdicts"));
        assert!(!wire.contains_key("schema_version"));
        assert!(!wire.contains_key("reviewer_role"));
        assert!(!wire.contains_key("allowed_verdicts"));
        assert!(!wire.contains_key("allowedVerdicts"));

        let mut invalid = packet;
        invalid.omitted = vec![" ".into()];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn packet_allows_omitted_only_disclosure() {
        let packet = JudgmentPacket {
            schema_version: 1,
            subject: json!({"id": "finding-1"}),
            evidence: Vec::new(),
            omitted: vec!["source unavailable".into()],
            reviewer_role: "independent-reviewer".into(),
            lens: None,
            budget: BudgetCeiling {
                max_active_time_ms: 1000,
                ..BudgetCeiling::default()
            },
            allowed_verdicts: JudgmentPacket::CANONICAL_VERDICTS
                .iter()
                .map(|verdict| (*verdict).into())
                .collect(),
        };
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn packet_rejects_noncanonical_verdict_set() {
        let packet = JudgmentPacket {
            schema_version: 1,
            subject: json!({"id": "finding-1"}),
            evidence: vec![PacketEvidence {
                evidence_id: "evidence-1".into(),
                source_revision: "git:abc".into(),
                locator: "src/lib.rs:10".into(),
                summary: "observed source fact".into(),
            }],
            omitted: Vec::new(),
            reviewer_role: "independent-reviewer".into(),
            lens: None,
            budget: BudgetCeiling {
                max_active_time_ms: 1000,
                ..BudgetCeiling::default()
            },
            allowed_verdicts: vec![
                "confirmed".into(),
                "rejected".into(),
                "unproven".into(),
                "needs-human".into(),
                "unknown".into(),
            ],
        };
        assert!(packet.validate().is_ok());

        let mut duplicate = packet.clone();
        duplicate.allowed_verdicts.push("unknown".into());
        assert!(duplicate.validate().is_err());

        let mut extra = packet;
        extra.allowed_verdicts.push("future".into());
        assert!(extra.validate().is_err());
    }

    #[test]
    fn candidate_provenance_keeps_source_and_locations() {
        let candidate = CandidateEvidence {
            candidate_id: FindingId::new("finding-1").unwrap(),
            evidence_id: "evidence-1".into(),
            class: CandidateClass::Observed,
            source_revision: "git:abc".into(),
            title: "Finding".into(),
            severity: "high".into(),
            message: "Observed fact".into(),
            locations: vec!["src/lib.rs:10".into()],
            facts: BTreeMap::new(),
        };
        assert!(candidate.validate().is_ok());
        assert_eq!(candidate.provenance()["source_revision"], "git:abc");

        let envelope = CandidateEnvelope {
            schema_version: 1,
            review_id: "review-1".into(),
            evidence_pack: "pack-1".into(),
            candidates: vec![candidate],
        };
        let packet = envelope
            .judgment_packet(
                json!({"id": "finding-1"}),
                "reviewer",
                BudgetCeiling {
                    max_active_time_ms: 1000,
                    ..BudgetCeiling::default()
                },
                vec!["runtime was not exercised".into()],
            )
            .unwrap();
        assert_eq!(packet.evidence[0].source_revision, "git:abc");
    }

    #[test]
    fn model_candidate_requires_producer_identity() {
        let candidate = CandidateEvidence {
            candidate_id: FindingId::new("model-finding").unwrap(),
            evidence_id: "model-evidence".into(),
            class: CandidateClass::ModelJudgment,
            source_revision: "git:abc".into(),
            title: "Model candidate".into(),
            severity: "high".into(),
            message: "Model-produced candidate requiring independent review".into(),
            locations: vec!["src/lib.rs:10".into()],
            facts: BTreeMap::new(),
        };
        assert!(matches!(
            candidate.validate(),
            Err(ReviewError::Provenance(_))
        ));
    }
}
