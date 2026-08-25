use serde::{Deserialize, Serialize};

use crate::{
    budget::BudgetSnapshot,
    error::ResearchError,
    report::ResearchReport,
    workflow::{StageRecord, WorkflowOutcome, WorkflowStatus},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchReceipt {
    pub schema_version: u32,
    pub report_id: String,
    pub report_digest: String,
    pub status: WorkflowStatus,
    pub source_successes: u64,
    pub external_requests: u64,
    pub omissions: Vec<String>,
    pub budget: BudgetSnapshot,
    pub stages: Vec<StageRecord>,
}

impl ResearchReceipt {
    pub fn from_outcome(outcome: &WorkflowOutcome) -> Result<Self, ResearchError> {
        let report_digest = outcome.report.digest()?;
        let receipt = Self {
            schema_version: 1,
            report_id: outcome.report.report_id.clone(),
            report_digest,
            status: outcome.status,
            source_successes: outcome.ledger.records().count() as u64,
            external_requests: outcome
                .ledger
                .records()
                .filter(|record| record.provenance.contains_key("request_receipt"))
                .count() as u64,
            omissions: outcome
                .failures
                .iter()
                .map(|failure| format!("{}:{}", failure.provider, failure.reason))
                .collect(),
            budget: outcome.budget,
            stages: outcome.stages.clone(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.schema_version != 1 {
            return Err(ResearchError::Report(
                "unsupported receipt schema version".into(),
            ));
        }
        if self.report_id.trim().is_empty() || self.report_digest.trim().is_empty() {
            return Err(ResearchError::Report(
                "receipt report identity must be non-empty".into(),
            ));
        }
        if self.status == WorkflowStatus::Ok && !self.omissions.is_empty() {
            return Err(ResearchError::Report(
                "successful receipt cannot contain omissions".into(),
            ));
        }
        Ok(())
    }

    pub fn from_report(
        report: &ResearchReport,
        budget: BudgetSnapshot,
    ) -> Result<Self, ResearchError> {
        let receipt = Self {
            schema_version: 1,
            report_id: report.report_id.clone(),
            report_digest: report.digest()?,
            status: match report.status {
                crate::report::ReportStatus::Complete => WorkflowStatus::Ok,
                crate::report::ReportStatus::Partial => WorkflowStatus::Partial,
                crate::report::ReportStatus::Failed => WorkflowStatus::Failed,
                crate::report::ReportStatus::Cancelled => WorkflowStatus::Cancelled,
            },
            source_successes: report.source_assertions.len() as u64,
            external_requests: report
                .source_assertions
                .iter()
                .filter(|claim| claim.provenance.contains_key("request_receipt"))
                .count() as u64,
            omissions: report
                .omissions
                .iter()
                .map(|failure| format!("{}:{}", failure.provider, failure.reason))
                .collect(),
            budget,
            stages: Vec::new(),
        };
        receipt.validate()?;
        Ok(receipt)
    }
}
