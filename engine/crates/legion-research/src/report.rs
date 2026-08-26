use legion_contracts::canonical_digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    error::ResearchError,
    evidence::{Claim, EvidenceKind, EvidenceLedger},
    workflow::{SourceFailure, WorkflowStage, WorkflowStatus},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Complete,
    Partial,
    Failed,
    Cancelled,
    Unproven,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportClaim {
    pub claim_id: String,
    pub text: String,
    pub evidence_ids: Vec<String>,
    pub provenance: BTreeMap<String, String>,
    pub uncertainty: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchReport {
    pub schema_version: u32,
    pub report_id: String,
    pub query: String,
    pub status: ReportStatus,
    pub observations: Vec<ReportClaim>,
    pub source_assertions: Vec<ReportClaim>,
    pub synthesis: Vec<ReportClaim>,
    pub uncertainties: Vec<ReportClaim>,
    pub unknowns: Vec<ReportClaim>,
    pub omissions: Vec<SourceFailure>,
}

impl ResearchReport {
    pub fn terminal_unproven(
        query: impl Into<String>,
        omissions: Vec<SourceFailure>,
    ) -> Result<Self, ResearchError> {
        let query = query.into();
        let report = Self {
            schema_version: 1,
            report_id: format!("research-{}", digest_key(&query)),
            query,
            status: ReportStatus::Unproven,
            observations: Vec::new(),
            source_assertions: Vec::new(),
            synthesis: Vec::new(),
            uncertainties: Vec::new(),
            unknowns: Vec::new(),
            omissions,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn terminal_cancelled(query: impl Into<String>) -> Result<Self, ResearchError> {
        let query = query.into();
        let report = Self {
            schema_version: 1,
            report_id: format!("research-{}", digest_key(&query)),
            query,
            status: ReportStatus::Cancelled,
            observations: Vec::new(),
            source_assertions: Vec::new(),
            synthesis: Vec::new(),
            uncertainties: Vec::new(),
            unknowns: Vec::new(),
            omissions: vec![SourceFailure {
                provider: "caller".into(),
                stage: WorkflowStage::Cancelled,
                reason: "caller cancellation observed before research effects".into(),
            }],
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.schema_version != 1 {
            return Err(ResearchError::Report(
                "unsupported report schema version".into(),
            ));
        }
        if self.report_id.trim().is_empty() || self.query.trim().is_empty() {
            return Err(ResearchError::Report(
                "report id and query must be non-empty".into(),
            ));
        }
        if self.status == ReportStatus::Unproven && self.omissions.is_empty() {
            return Err(ResearchError::Report(
                "unproven report must disclose at least one omission".into(),
            ));
        }
        if self.status == ReportStatus::Complete && !self.omissions.is_empty() {
            return Err(ResearchError::Report(
                "complete report cannot conceal omissions".into(),
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for claim in self
            .observations
            .iter()
            .chain(&self.source_assertions)
            .chain(&self.synthesis)
            .chain(&self.uncertainties)
            .chain(&self.unknowns)
        {
            if claim.evidence_ids.is_empty() {
                return Err(ResearchError::Report(format!(
                    "claim {} has no evidence",
                    claim.claim_id
                )));
            }
            if !ids.insert(&claim.claim_id) {
                return Err(ResearchError::Report("duplicate report claim id".into()));
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ResearchError> {
        canonical_digest(self).map_err(|error| ResearchError::Report(error.to_string()))
    }
}

pub struct ReportBuilder;

impl ReportBuilder {
    pub fn from_ledger(
        query: &str,
        status: WorkflowStatus,
        ledger: &EvidenceLedger,
        failures: &[SourceFailure],
    ) -> Result<ResearchReport, ResearchError> {
        let mut observations = Vec::new();
        let mut source_assertions = Vec::new();
        let mut synthesis = Vec::new();
        let mut uncertainties = Vec::new();
        let mut unknowns = Vec::new();
        for claim in ledger.claims() {
            let rendered = Self::render(claim);
            match claim.kind {
                EvidenceKind::Observation => observations.push(rendered),
                EvidenceKind::SourceAssertion => source_assertions.push(rendered),
                EvidenceKind::Synthesis => synthesis.push(rendered),
                EvidenceKind::Uncertainty => uncertainties.push(rendered),
                EvidenceKind::Unknown => unknowns.push(rendered),
            }
        }
        let report = ResearchReport {
            schema_version: 1,
            report_id: format!("research-{}", digest_key(query)),
            query: query.to_owned(),
            status: match status {
                WorkflowStatus::Ok => ReportStatus::Complete,
                WorkflowStatus::Partial => ReportStatus::Partial,
                WorkflowStatus::Failed => ReportStatus::Failed,
                WorkflowStatus::Cancelled => ReportStatus::Cancelled,
                WorkflowStatus::Unproven => ReportStatus::Unproven,
            },
            observations,
            source_assertions,
            synthesis,
            uncertainties,
            unknowns,
            omissions: failures.to_vec(),
        };
        report.validate()?;
        Ok(report)
    }

    fn render(claim: &Claim) -> ReportClaim {
        ReportClaim {
            claim_id: claim.claim_id.clone(),
            text: claim.text.clone(),
            evidence_ids: claim.evidence_ids.clone(),
            provenance: claim.provenance.clone(),
            uncertainty: claim.uncertainty.clone(),
        }
    }
}

fn digest_key(value: &str) -> String {
    let mut hash: u64 = 1469598103934665603;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    format!("{hash:016x}")
}
