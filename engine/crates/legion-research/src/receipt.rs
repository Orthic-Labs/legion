use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{
    budget::BudgetSnapshot,
    error::ResearchError,
    report::ResearchReport,
    workflow::{
        ResearchAuthorization, ResearchRoute, StageRecord, WorkflowOutcome, WorkflowStage,
        WorkflowStatus,
    },
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
    pub route_digest: String,
    pub allowed_effects: Vec<String>,
    pub effect_grant: Vec<String>,
    pub approval_receipt_ids: Vec<String>,
    pub selected_provider_denominator: u64,
}

impl ResearchReceipt {
    pub fn from_terminal(
        report: &ResearchReport,
        budget: BudgetSnapshot,
        stages: Vec<StageRecord>,
        source_successes: u64,
        _external_requests: u64,
    ) -> Result<Self, ResearchError> {
        let route = ResearchRoute::host_injected(&report.query);
        let authorization = ResearchAuthorization::full(&route)?;
        let selected_provider_denominator = report_provider_denominator(report);
        Self::from_terminal_bound(
            report,
            budget,
            stages,
            source_successes,
            budget.usage.calls,
            &route,
            &authorization,
            selected_provider_denominator,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_terminal_bound(
        report: &ResearchReport,
        budget: BudgetSnapshot,
        stages: Vec<StageRecord>,
        source_successes: u64,
        _external_requests: u64,
        route: &ResearchRoute,
        authorization: &ResearchAuthorization,
        selected_provider_denominator: u64,
    ) -> Result<Self, ResearchError> {
        report.validate()?;
        route.validate()?;
        authorization.validate(route)?;
        let receipt = Self {
            schema_version: 1,
            report_id: report.report_id.clone(),
            report_digest: report.digest()?,
            status: match report.status {
                crate::report::ReportStatus::Complete => WorkflowStatus::Ok,
                crate::report::ReportStatus::Partial => WorkflowStatus::Partial,
                crate::report::ReportStatus::Failed => WorkflowStatus::Failed,
                crate::report::ReportStatus::Cancelled => WorkflowStatus::Cancelled,
                crate::report::ReportStatus::Unproven => WorkflowStatus::Unproven,
            },
            source_successes,
            external_requests: budget.usage.calls,
            omissions: report
                .omissions
                .iter()
                .map(|failure| format!("{}:{}", failure.provider, failure.reason))
                .collect(),
            budget,
            stages,
            route_digest: route.digest()?,
            allowed_effects: route.allowed_effects.clone(),
            effect_grant: authorization.effect_grant.clone(),
            approval_receipt_ids: authorization.approval_receipt_ids.clone(),
            selected_provider_denominator,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn from_outcome(outcome: &WorkflowOutcome) -> Result<Self, ResearchError> {
        outcome.report.validate()?;
        let report_status = match outcome.report.status {
            crate::report::ReportStatus::Complete => WorkflowStatus::Ok,
            crate::report::ReportStatus::Partial => WorkflowStatus::Partial,
            crate::report::ReportStatus::Failed => WorkflowStatus::Failed,
            crate::report::ReportStatus::Cancelled => WorkflowStatus::Cancelled,
            crate::report::ReportStatus::Unproven => WorkflowStatus::Unproven,
        };
        if report_status != outcome.status {
            return Err(ResearchError::Report(
                "workflow outcome and report status disagree".into(),
            ));
        }
        let authorization = ResearchAuthorization {
            approval_receipt_ids: outcome.approval_receipt_ids.clone(),
            effect_grant: outcome.effect_grant.clone(),
        };
        Self::from_terminal_bound(
            &outcome.report,
            outcome.budget,
            outcome.stages.clone(),
            outcome.ledger.records().count() as u64,
            outcome
                .ledger
                .records()
                .filter(|record| record.provenance.contains_key("request_receipt"))
                .count() as u64,
            &outcome.route,
            &authorization,
            outcome.selected_provider_denominator,
        )
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
        if self.route_digest.trim().is_empty() {
            return Err(ResearchError::Report(
                "receipt must bind a frozen route digest".into(),
            ));
        }
        if self.status == WorkflowStatus::Ok && self.selected_provider_denominator == 0 {
            return Err(ResearchError::Report(
                "successful receipt must bind a nonzero provider denominator".into(),
            ));
        }
        if self.external_requests != self.budget.usage.calls {
            return Err(ResearchError::Report(
                "receipt external request count must equal bounded workflow calls".into(),
            ));
        }
        ResearchRoute::validate_effects(&self.allowed_effects)?;
        ResearchRoute::validate_effect_grant(&self.effect_grant)?;
        if self
            .effect_grant
            .iter()
            .any(|effect| !self.allowed_effects.iter().any(|allowed| allowed == effect))
        {
            return Err(ResearchError::Report(
                "receipt effect grant exceeds route allowance".into(),
            ));
        }
        if self
            .approval_receipt_ids
            .iter()
            .any(|identity| identity.trim().is_empty())
        {
            return Err(ResearchError::Report(
                "receipt approval identities must be non-empty".into(),
            ));
        }
        let mut approval_ids = self.approval_receipt_ids.clone();
        approval_ids.sort();
        approval_ids.dedup();
        if approval_ids.len() != self.approval_receipt_ids.len() {
            return Err(ResearchError::Report(
                "receipt approval identities must be unique".into(),
            ));
        }
        if self.status == WorkflowStatus::Ok && !self.omissions.is_empty() {
            return Err(ResearchError::Report(
                "successful receipt cannot contain omissions".into(),
            ));
        }
        let terminal = self.stages.iter().any(|stage| {
            stage.completed
                && matches!(
                    (self.status, stage.stage),
                    (
                        WorkflowStatus::Ok | WorkflowStatus::Partial,
                        WorkflowStage::Complete
                    ) | (WorkflowStatus::Cancelled, WorkflowStage::Cancelled)
                        | (
                            WorkflowStatus::Unproven | WorkflowStatus::Failed,
                            WorkflowStage::Unproven
                        )
                )
        });
        if !terminal {
            return Err(ResearchError::Report(
                "receipt must include a matching completed terminal stage".into(),
            ));
        }
        Ok(())
    }

    pub fn from_report(
        report: &ResearchReport,
        budget: BudgetSnapshot,
    ) -> Result<Self, ResearchError> {
        report.validate()?;
        let route = ResearchRoute::host_injected(&report.query);
        let authorization = ResearchAuthorization::full(&route)?;
        let selected_provider_denominator = report_provider_denominator(report);
        Self::from_terminal_bound(
            report,
            budget,
            vec![StageRecord {
                stage: match report.status {
                    crate::report::ReportStatus::Cancelled => WorkflowStage::Cancelled,
                    crate::report::ReportStatus::Unproven | crate::report::ReportStatus::Failed => {
                        WorkflowStage::Unproven
                    }
                    _ => WorkflowStage::Complete,
                },
                completed: true,
                detail: Some("terminal_report_receipt".into()),
            }],
            report.source_assertions.len() as u64,
            report
                .source_assertions
                .iter()
                .filter(|claim| claim.provenance.contains_key("request_receipt"))
                .count() as u64,
            &route,
            &authorization,
            selected_provider_denominator,
        )
    }
}

fn report_provider_denominator(report: &ResearchReport) -> u64 {
    report
        .source_assertions
        .iter()
        .chain(&report.observations)
        .chain(&report.synthesis)
        .chain(&report.uncertainties)
        .chain(&report.unknowns)
        .filter_map(|claim| claim.provenance.get("provider"))
        .filter(|provider| !provider.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BudgetLimits, BudgetUsage};

    #[test]
    fn clean_report_without_provider_binding_cannot_make_receipt() {
        let report = ResearchReport {
            schema_version: 1,
            report_id: "report-clean-empty".into(),
            query: "clean report".into(),
            status: crate::report::ReportStatus::Complete,
            observations: Vec::new(),
            source_assertions: Vec::new(),
            synthesis: Vec::new(),
            uncertainties: Vec::new(),
            unknowns: Vec::new(),
            omissions: Vec::new(),
        };
        let budget = BudgetSnapshot {
            limits: BudgetLimits::default(),
            usage: BudgetUsage::default(),
        };
        assert!(ResearchReceipt::from_report(&report, budget).is_err());
    }
}
