use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{ProviderId, ProviderResult, ProviderStatus};

use crate::{
    error::AuditError,
    inventory::InventoryEnvelope,
    plan::{AuditProvider, FrozenPlan},
};

pub trait ProviderExecutor: Send + Sync {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderExecution {
    pub provider: String,
    pub result: ProviderResult,
    pub skipped: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReport {
    pub plan_digest: String,
    pub generation: String,
    pub results: Vec<ProviderExecution>,
    pub gaps: Vec<String>,
}

fn provider_id(value: &str) -> Result<ProviderId, AuditError> {
    ProviderId::new(value).map_err(AuditError::from)
}

pub fn execute(
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    executor: &dyn ProviderExecutor,
) -> Result<ExecutionReport, AuditError> {
    inventory.validate()?;
    if inventory.repository_id != plan.plan().repository_id
        || inventory.generation != plan.plan().inventory_generation
        || inventory.digest != plan.plan().inventory_digest
    {
        return Err(AuditError::SourceDrift(
            "inventory no longer matches frozen plan".into(),
        ));
    }
    let mut completed = BTreeSet::new();
    let mut failed = BTreeSet::new();
    let mut results = Vec::new();
    let mut gaps = Vec::new();
    for provider in plan.providers() {
        // Readiness is success of every dependency, not merely absence from
        // the failure set. This also blocks transitive dependents after a
        // skipped provider and keeps the frozen topological order intact.
        let blocked = provider
            .dependencies
            .iter()
            .any(|dependency| !completed.contains(dependency) || failed.contains(dependency));
        let execution = if blocked {
            let id = provider_id(&provider.id)?;
            let gap = format!("dependency-failed:{}", provider.id);
            gaps.push(gap.clone());
            failed.insert(provider.id.clone());
            ProviderExecution {
                provider: provider.id.clone(),
                skipped: true,
                result: ProviderResult {
                    schema_version: 1,
                    provider: id,
                    applicable: true,
                    required: provider.required,
                    status: ProviderStatus::Cancelled,
                    complete: false,
                    coverage: None,
                    findings: Vec::new(),
                    coverage_gaps: vec![gap],
                    degradation: vec!["skipped-after-dependency-failure".into()],
                    details: BTreeMap::new(),
                },
            }
        } else {
            match executor.execute(provider, inventory) {
                Ok(result) => {
                    if result.complete
                        && matches!(result.status, ProviderStatus::Ok | ProviderStatus::Complete)
                    {
                        completed.insert(provider.id.clone());
                    } else {
                        failed.insert(provider.id.clone());
                        gaps.extend(result.coverage_gaps.iter().cloned());
                    }
                    ProviderExecution {
                        provider: provider.id.clone(),
                        result,
                        skipped: false,
                    }
                }
                Err(error) => {
                    failed.insert(provider.id.clone());
                    let gap = error.to_string();
                    gaps.push(gap.clone());
                    ProviderExecution {
                        provider: provider.id.clone(),
                        skipped: false,
                        result: ProviderResult {
                            schema_version: 1,
                            provider: provider_id(&provider.id)?,
                            applicable: true,
                            required: provider.required,
                            status: ProviderStatus::Failed,
                            complete: false,
                            coverage: None,
                            findings: Vec::new(),
                            coverage_gaps: vec![gap],
                            degradation: vec!["provider-error".into()],
                            details: BTreeMap::new(),
                        },
                    }
                }
            }
        };
        results.push(execution);
    }
    gaps.sort();
    gaps.dedup();
    Ok(ExecutionReport {
        plan_digest: plan.digest().into(),
        generation: inventory.generation.clone(),
        results,
        gaps,
    })
}
