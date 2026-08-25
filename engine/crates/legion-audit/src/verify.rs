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
    if report.planned_providers.is_empty() {
        return Err(AuditError::Invalid(
            "audit execution has no planned providers".into(),
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
    if planned.len() != report.planned_providers.len() || planned != ids {
        return Err(AuditError::Invalid(
            "planned and executed provider sets do not reconcile".into(),
        ));
    }
    Ok(())
}
