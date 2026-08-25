use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{ProviderId, ProviderResult, ProviderStatus};
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderExecution {
    pub provider: String,
    pub result: ProviderResult,
    pub skipped: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionReport {
    pub plan_digest: String,
    pub plan_signature: Option<String>,
    pub generation: String,
    pub planned_providers: Vec<String>,
    pub results: Vec<ProviderExecution>,
    pub selected_lenses: Vec<String>,
    pub lenses_ran: Vec<String>,
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
    let mut selected_lenses = plan
        .providers()
        .iter()
        .flat_map(|provider| provider.lens_ids.iter().cloned())
        .collect::<Vec<_>>();
    selected_lenses.sort();
    selected_lenses.dedup();
    let mut lenses_ran = Vec::new();
    let planned_providers = plan
        .providers()
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<Vec<_>>();
    for provider in plan.providers() {
        // Readiness is success of every dependency, not merely absence from
        // the failure set. This also blocks transitive dependents after a
        // skipped provider and keeps the frozen topological order intact.
        let blocked = provider
            .dependencies
            .iter()
            .any(|dependency| !completed.contains(dependency) || failed.contains(dependency));
        let execution = if blocked {
            let gap = format!("dependency-failed:{}", provider.id);
            gaps.push(gap.clone());
            failed.insert(provider.id.clone());
            failed_execution(provider, gap, "skipped-after-dependency-failure", true)?
        } else {
            match executor.execute(provider, inventory) {
                Ok(result) => {
                    let result_error = result
                        .validate()
                        .err()
                        .map(|error| error.to_string())
                        .or_else(|| {
                            (result.provider.to_string() != provider.id)
                                .then(|| "provider result identity mismatch".to_owned())
                        })
                        .or_else(|| {
                            (result.required != provider.required)
                                .then(|| "provider result required flag mismatch".to_owned())
                        })
                        .or_else(|| {
                            (!result.applicable)
                                .then(|| "selected provider reported not applicable".to_owned())
                        });
                    if let Some(error) = result_error {
                        let gap = format!("invalid-provider-result:{}:{error}", provider.id);
                        gaps.push(gap.clone());
                        failed.insert(provider.id.clone());
                        results.push(failed_execution(
                            provider,
                            gap,
                            "invalid-provider-result",
                            false,
                        )?);
                        continue;
                    }
                    if result.complete
                        && matches!(result.status, ProviderStatus::Ok | ProviderStatus::Complete)
                    {
                        completed.insert(provider.id.clone());
                        lenses_ran.extend(provider.lens_ids.iter().cloned());
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
                    failed_execution(provider, gap, "provider-error", false)?
                }
            }
        };
        results.push(execution);
        if provider.benchmark_required_for_clean_claim
            && (provider.benchmark_status != "qualified" || provider.qualification_digest.is_none())
        {
            gaps.push(format!("provider-unqualified:{}", provider.id));
        }
    }
    gaps.sort();
    gaps.dedup();
    lenses_ran.sort();
    lenses_ran.dedup();
    if lenses_ran != selected_lenses {
        gaps.push("selected reasoning lenses did not complete".into());
    }
    Ok(ExecutionReport {
        plan_digest: plan.digest().into(),
        plan_signature: plan.signature().map(ToOwned::to_owned),
        generation: inventory.generation.clone(),
        planned_providers,
        results,
        selected_lenses,
        lenses_ran,
        gaps,
    })
}

fn failed_execution(
    provider: &AuditProvider,
    gap: String,
    degradation: &str,
    skipped: bool,
) -> Result<ProviderExecution, AuditError> {
    Ok(ProviderExecution {
        provider: provider.id.clone(),
        skipped,
        result: ProviderResult {
            schema_version: 1,
            provider: provider_id(&provider.id)?,
            applicable: true,
            required: provider.required,
            status: if skipped {
                ProviderStatus::Cancelled
            } else {
                ProviderStatus::Failed
            },
            complete: false,
            coverage: None,
            findings: Vec::new(),
            coverage_gaps: vec![gap],
            degradation: vec![degradation.into()],
            details: BTreeMap::new(),
        },
    })
}
