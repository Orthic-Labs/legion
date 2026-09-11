use std::collections::BTreeSet;

use crate::{
    error::AuditError, execution::ExecutionReport, integrity::verify, inventory::InventoryEnvelope,
    plan::FrozenPlan,
};

pub fn verify_binding(
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    key: Option<&[u8]>,
) -> Result<(), AuditError> {
    if inventory.repository_id != plan.plan().repository_id
        || inventory.generation != plan.plan().inventory_generation
    {
        return Err(AuditError::SourceDrift(
            "repository or inventory generation drift".into(),
        ));
    }
    if inventory.digest != plan.plan().inventory_digest {
        return Err(AuditError::SourceDrift("inventory digest drift".into()));
    }
    verify(plan.plan(), plan.digest(), plan.signature(), key)
}

pub fn verify_execution(report: &ExecutionReport) -> Result<(), AuditError> {
    if report.plan_signature.is_none() {
        return Err(AuditError::Invalid(
            "audit execution is not bound to a signed plan".into(),
        ));
    }
    verify_execution_structure(report)
}

/// Structural verification never turns an unsigned diagnostic into authenticated evidence.
pub fn verify_source_diagnostic(report: &ExecutionReport, plan: &FrozenPlan) -> Result<(), AuditError> {
    if report.plan_signature.is_some() || !report.gaps.iter().any(|gap| gap == "unsigned-plan") {
        return Err(AuditError::Invalid("source diagnostic requires explicit unsigned-plan gap".into()));
    }
    if plan.signature().is_some() || report.plan_digest != plan.digest()
        || report.generation != plan.plan().inventory_generation
        || report.inventory_digest != plan.plan().inventory_digest
        || report.planned_providers != plan.providers().iter().map(|p| p.id.clone()).collect::<Vec<_>>() {
        return Err(AuditError::Invalid("source diagnostic frozen plan mismatch".into()));
    }
    for provider in plan.providers() {
        if !crate::execution::source_diagnostic_allowed(provider) {
            let entry = report.results.iter().find(|entry| entry.provider == provider.id);
            let gap = format!("unsigned-plan-provider-not-executed:{}", provider.id);
            if !entry.is_some_and(|entry| entry.skipped) || !report.gaps.contains(&gap) {
                return Err(AuditError::Invalid("source diagnostic executed non-source provider".into()));
            }
        }
    }
    verify_execution_structure(report)
}

fn verify_execution_structure(report: &ExecutionReport) -> Result<(), AuditError> {
    if report.planned_providers.is_empty() {
        return Err(AuditError::Invalid(
            "audit execution has no planned providers".into(),
        ));
    }
    if report.inventory_digest.trim().is_empty() || report.generation.trim().is_empty() {
        return Err(AuditError::Invalid(
            "audit execution is missing frozen inventory identity".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    for item in &report.results {
        if !ids.insert(item.provider.clone()) {
            return Err(AuditError::Invalid("duplicate provider execution".into()));
        }
        if item.result.provider.to_string() != item.provider {
            return Err(AuditError::Invalid(
                "provider result identity mismatch".into(),
            ));
        }
        if item.skipped
            && !matches!(
                item.result.status,
                legion_contracts::ProviderStatus::Cancelled
            )
        {
            return Err(AuditError::Invalid(
                "skipped provider execution must be cancelled".into(),
            ));
        }
        if item.result.complete
            && !matches!(
                item.result.status,
                legion_contracts::ProviderStatus::Ok | legion_contracts::ProviderStatus::Complete
            )
        {
            return Err(AuditError::Invalid(
                "failed or cancelled provider cannot be complete".into(),
            ));
        }
        if item.result.complete
            && (!item.result.coverage_gaps.is_empty()
                || item
                    .result
                    .coverage
                    .as_ref()
                    .map(|coverage| !coverage.complete())
                    .unwrap_or(true))
        {
            return Err(AuditError::Invalid(
                "complete provider result lacks coverage proof".into(),
            ));
        }
    }
    let planned = report
        .planned_providers
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if planned.len() != report.planned_providers.len()
        || planned != ids
        || report.results.len() != report.planned_providers.len()
    {
        return Err(AuditError::Invalid(
            "planned and executed provider sets do not reconcile".into(),
        ));
    }
    Ok(())
}
