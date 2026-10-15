use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{ProviderId, ProviderResult, ProviderStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::{
    error::AuditError,
    inventory::InventoryEnvelope,
    plan::{AuditProvider, FrozenPlan, PROVIDER_UNIVERSE_BOUND},
};

/// Immutable outputs available to a provider from earlier steps in this
/// frozen plan execution. Consumers must still validate provider-specific
/// evidence before using it.
pub struct ExecutionContext<'a> {
    pub plan_digest: &'a str,
    pub prior_results: &'a [ProviderExecution],
}

#[async_trait::async_trait]
pub trait ProviderExecutor: Send + Sync {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError>;

    /// Async seam for host capabilities. Existing native implementations keep
    /// their synchronous implementation; only injected external tools cross
    /// this boundary.
    async fn execute_async(
        &self,
        plan: &FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        _cancellation: CancellationToken,
    ) -> Result<ProviderResult, AuditError> {
        self.execute_bound(plan, provider, inventory)
    }

    /// Execute with the frozen plan identity available to providers that cross
    /// a host boundary. Existing in-process providers keep their original
    /// implementation through the default method; host providers override it
    /// so a receipt cannot be detached from the plan that admitted it.
    fn execute_bound(
        &self,
        plan: &FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let _ = plan;
        // Artifact and generic executors do not authenticate host receipts.
        // A claimed complete result from one of them must not bypass the
        // explicit plan-bound host implementation.
        if provider.kind == crate::plan::ProviderKind::HostService {
            return Err(AuditError::Provider(
                "host-service provider requires an authenticated plan-bound executor".into(),
            ));
        }
        self.execute(provider, inventory)
    }

    /// Execute with immutable same-run context. Existing providers retain
    /// their established plan-bound seam unless they explicitly consume prior
    /// results.
    fn execute_with_context(
        &self,
        plan: &FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        _context: &ExecutionContext<'_>,
    ) -> Result<ProviderResult, AuditError> {
        self.execute_bound(plan, provider, inventory)
    }

    /// Async counterpart to `execute_with_context`; existing async providers
    /// keep their established cancellation-aware seam by default.
    async fn execute_async_with_context(
        &self,
        plan: &FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        cancellation: CancellationToken,
        _context: &ExecutionContext<'_>,
    ) -> Result<ProviderResult, AuditError> {
        self.execute_async(plan, provider, inventory, cancellation)
            .await
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderExecution {
    pub provider: String,
    pub result: ProviderResult,
    pub skipped: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionReport {
    pub plan_digest: String,
    pub plan_signature: Option<String>,
    pub generation: String,
    pub inventory_digest: String,
    pub planned_providers: Vec<String>,
    pub results: Vec<ProviderExecution>,
    /// Every lens tag carried by a planned provider (reasoning or deterministic).
    pub selected_lenses: Vec<String>,
    /// Reasoning lenses that actually completed (host-service providers only).
    /// A lens tag on a deterministic provider is never counted here.
    pub lenses_ran: Vec<String>,
    /// Lens tags of reasoning providers that apply to this repository.
    #[serde(default)]
    pub selected_reasoning_lenses: Vec<String>,
    /// Reasoning providers whose work is `pending-host`: no reasoning host
    /// executed them in-process, so the invoking session must run their lens
    /// packets and ingest the results.
    #[serde(default)]
    pub pending_host: Vec<String>,
    /// Lens tag -> number of completed deterministic providers carrying it.
    /// Coverage tags only; these are not reasoning lenses.
    #[serde(default)]
    pub deterministic_lens_tags: BTreeMap<String, usize>,
    /// Non-blocking coverage notes. `unqualified:<provider>` records a provider
    /// that completed but has no passing benchmark class or qualification
    /// record and is not marked `benchmark.requiredForCleanClaim`. A note never
    /// blocks a clean verdict; a required provider that is unqualified is a
    /// `provider-unqualified:<provider>` gap instead.
    #[serde(default)]
    pub coverage_notes: Vec<String>,
    pub gaps: Vec<String>,
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

/// A provider is qualified when its registry entry carries a qualified
/// benchmark status and a qualification digest (a passing bench class or an
/// explicit qualification record).
fn provider_qualified(provider: &AuditProvider) -> bool {
    provider.benchmark_status == "qualified" && provider.qualification_digest.is_some()
}

/// Unqualified providers block a clean verdict only when the registry marks
/// them `requiredForCleanClaim`. Otherwise a completed unqualified provider is
/// reported as a non-blocking `unqualified:<id>` coverage note.
fn record_qualification(
    provider: &AuditProvider,
    completed: &BTreeSet<String>,
    gaps: &mut Vec<String>,
    notes: &mut Vec<String>,
) {
    if provider.not_applicable() || provider_qualified(provider) {
        return;
    }
    if provider.benchmark_required_for_clean_claim {
        gaps.push(format!("provider-unqualified:{}", provider.id));
    } else if completed.contains(&provider.id) {
        notes.push(format!("unqualified:{}", provider.id));
    }
}

/// `governance.capability-ownership` is advisory unless the host marks it
/// required (`AUDIT_OWNERSHIP_SCAN_REQUIRED`, frozen as `provider.required`).
/// An advisory provider that cannot complete degrades to non-blocking
/// coverage notes instead of blocking gaps.
pub(crate) fn is_advisory_ownership(provider: &AuditProvider) -> bool {
    provider.id == OWNERSHIP_PROVIDER_ID && !provider.required
}

pub(crate) const OWNERSHIP_PROVIDER_ID: &str = "governance.capability-ownership";

/// A declared scanner that is absent for a non-blocking class (substitutable
/// or informational) is a coverage note. Its incomplete result does not block
/// the run, because the registry names what covers the domain instead.
fn declared_capability_note(result: &ProviderResult) -> Option<String> {
    let absence = result.details.get("capabilityAbsence")?;
    if absence.get("blocking").and_then(serde_json::Value::as_bool) != Some(false) {
        return None;
    }
    absence
        .get("note")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn advisory_ownership_notes(result: &ProviderResult) -> Vec<String> {
    let mut notes: Vec<String> = result
        .coverage_gaps
        .iter()
        .map(|gap| format!("ownership-scan-degraded:{gap}"))
        .collect();
    if notes.is_empty() {
        notes.push("ownership-scan-degraded:incomplete".into());
    }
    notes
}

fn provider_id(value: &str) -> Result<ProviderId, AuditError> {
    ProviderId::new(value).map_err(AuditError::from)
}

fn is_reasoning(provider: &AuditProvider) -> bool {
    provider.kind == crate::plan::ProviderKind::HostService
}

fn record_lenses(
    provider: &AuditProvider,
    reasoning_ran: &mut Vec<String>,
    tags: &mut BTreeMap<String, usize>,
) {
    if is_reasoning(provider) {
        reasoning_ran.extend(provider.lens_ids.iter().cloned());
    } else {
        for lens in &provider.lens_ids {
            *tags.entry(lens.clone()).or_insert(0) += 1;
        }
    }
}

fn selected_reasoning_lenses(plan: &FrozenPlan) -> Vec<String> {
    let mut lenses = plan
        .providers()
        .iter()
        .filter(|provider| is_reasoning(provider) && !provider.not_applicable())
        .flat_map(|provider| provider.lens_ids.iter().cloned())
        .collect::<Vec<_>>();
    lenses.sort();
    lenses.dedup();
    lenses
}

fn is_pending_host(provider: &AuditProvider, result: &ProviderResult) -> bool {
    is_reasoning(provider)
        && result
            .details
            .get("reasoningHostState")
            .and_then(Value::as_str)
            == Some("pending-host")
}

/// True when a provider's own result is a well-formed not-applicable
/// declaration: nothing inspected, nothing claimed, and an explicit marker.
fn declares_not_applicable(provider: &AuditProvider, result: &ProviderResult) -> bool {
    !result.applicable
        && result.provider.to_string() == provider.id
        && result.required == provider.required
        && matches!(result.status, ProviderStatus::Ok)
        && !result.complete
        && result.coverage.is_none()
        && result.findings.is_empty()
        && result.coverage_gaps.is_empty()
        && result.degradation.is_empty()
        && result.details.get("applicability").and_then(Value::as_str) == Some("not-applicable")
}

fn not_applicable_execution(provider: &AuditProvider) -> Result<ProviderExecution, AuditError> {
    Ok(ProviderExecution {
        provider: provider.id.clone(),
        skipped: false,
        result: ProviderResult {
            schema_version: 1,
            provider: provider_id(&provider.id)?,
            applicable: false,
            required: provider.required,
            status: ProviderStatus::Ok,
            complete: false,
            coverage: None,
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::from([
                ("notApplicable".to_owned(), Value::Bool(true)),
                (
                    "notApplicableReason".to_owned(),
                    Value::String(
                        if provider.host_declaration_absent() {
                            "host-declaration-absent"
                        } else {
                            "selector-denominator-empty"
                        }
                        .into(),
                    ),
                ),
            ]),
        },
    })
}

pub fn execute(
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    executor: &dyn ProviderExecutor,
) -> Result<ExecutionReport, AuditError> {
    reject_provider_universe_execution_plan(plan)?;
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
    if plan.signature().is_none() {
        gaps.push("unsigned-plan".into());
    }
    let mut selected_lenses = plan
        .providers()
        .iter()
        .flat_map(|provider| provider.lens_ids.iter().cloned())
        .collect::<Vec<_>>();
    selected_lenses.sort();
    selected_lenses.dedup();
    let selected_reasoning = selected_reasoning_lenses(plan);
    let mut lenses_ran = Vec::new();
    let mut pending_host = Vec::new();
    let mut coverage_notes = Vec::new();
    let mut deterministic_lens_tags = BTreeMap::new();
    let planned_providers = plan
        .providers()
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<Vec<_>>();
    let candidate_denominators = plan
        .providers()
        .iter()
        .filter(|provider| provider.role == "candidate-generator")
        .map(|provider| {
            let selector = provider.configuration.get("selector").ok_or_else(|| {
                AuditError::Invalid(format!("provider {} is missing selector", provider.id))
            })?;
            inventory.denominator_entries(selector)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for provider in plan.providers() {
        // Readiness is success of every dependency, not merely absence from
        // the failure set. This also blocks transitive dependents after a
        // skipped provider and keeps the frozen topological order intact.
        let blocked = provider
            .dependencies
            .iter()
            .any(|dependency| !completed.contains(dependency) || failed.contains(dependency));
        // An unsigned plan still runs every provider; its only consequence is
        // the `unsigned-plan` gap recorded above, which keeps the verdict
        // non-clean. Providers that do not apply to this repository are
        // reported not-applicable, not failed.
        let execution = if provider.not_applicable() {
            completed.insert(provider.id.clone());
            not_applicable_execution(provider)?
        } else if blocked {
            let gap = format!("dependency-failed:{}", provider.id);
            gaps.push(gap.clone());
            failed.insert(provider.id.clone());
            failed_execution(provider, gap, "skipped-after-dependency-failure", true)?
        } else {
            let context = ExecutionContext {
                plan_digest: plan.digest(),
                prior_results: &results,
            };
            match executor.execute_with_context(plan, provider, inventory, &context) {
                // A provider that finds nothing of its kind in the frozen
                // inventory declares itself not applicable; that settles it
                // like a plan-level not-applicable, with no gap.
                Ok(result) if declares_not_applicable(provider, &result) => {
                    completed.insert(provider.id.clone());
                    ProviderExecution {
                        provider: provider.id.clone(),
                        result,
                        skipped: false,
                    }
                }
                Ok(result) => {
                    let denominator =
                        provider_denominator(provider, inventory, &candidate_denominators)?;
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
                        })
                        .or_else(|| validate_result(provider, &result, &denominator).err());
                    if let Some(error) = result_error {
                        let gap = format!("invalid-provider-result:{}:{error}", provider.id);
                        gaps.push(gap.clone());
                        failed.insert(provider.id.clone());
                        results.push(failed_execution_with_diagnostic(
                            provider,
                            gap,
                            "invalid-provider-result",
                            false,
                            Some(serde_json::to_value(&result).unwrap_or_else(|serialization_error| {
                                serde_json::json!({"serializationError":serialization_error.to_string()})
                            })),
                        )?);
                        continue;
                    }
                    if result.complete
                        && matches!(result.status, ProviderStatus::Ok | ProviderStatus::Complete)
                    {
                        completed.insert(provider.id.clone());
                        record_lenses(provider, &mut lenses_ran, &mut deterministic_lens_tags);
                    } else {
                        failed.insert(provider.id.clone());
                        if is_advisory_ownership(provider) {
                            coverage_notes.extend(advisory_ownership_notes(&result));
                        } else if let Some(note) = declared_capability_note(&result) {
                            coverage_notes.push(note);
                        } else {
                            gaps.push(format!("provider-incomplete:{}", provider.id));
                            gaps.extend(result.coverage_gaps.iter().cloned());
                        }
                        if is_pending_host(provider, &result) {
                            gaps.push(format!("reasoning-lens-pending-host:{}", provider.id));
                            pending_host.push(provider.id.clone());
                        }
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
        record_qualification(provider, &completed, &mut gaps, &mut coverage_notes);
    }
    gaps.sort();
    gaps.dedup();
    lenses_ran.sort();
    lenses_ran.dedup();
    if lenses_ran != selected_reasoning {
        gaps.push("selected reasoning lenses did not complete".into());
    }
    gaps.sort();
    gaps.dedup();
    Ok(ExecutionReport {
        plan_digest: plan.digest().into(),
        plan_signature: plan.signature().map(ToOwned::to_owned),
        generation: inventory.generation.clone(),
        inventory_digest: inventory.digest.clone(),
        planned_providers,
        results,
        selected_lenses,
        lenses_ran,
        selected_reasoning_lenses: selected_reasoning,
        pending_host,
        deterministic_lens_tags,
        coverage_notes: sorted_unique(coverage_notes),
        gaps,
    })
}

pub async fn execute_with_cancellation(
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    executor: &dyn ProviderExecutor,
    cancellation: CancellationToken,
) -> Result<ExecutionReport, AuditError> {
    // Keep validation/report assembly identical to legacy synchronous path;
    // host execution is selected through the async executor seam.
    reject_provider_universe_execution_plan(plan)?;
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
    if plan.signature().is_none() {
        gaps.push("unsigned-plan".into());
    }
    let mut selected_lenses = plan
        .providers()
        .iter()
        .flat_map(|p| p.lens_ids.iter().cloned())
        .collect::<Vec<_>>();
    selected_lenses.sort();
    selected_lenses.dedup();
    let selected_reasoning = selected_reasoning_lenses(plan);
    let mut lenses_ran = Vec::new();
    let mut pending_host = Vec::new();
    let mut coverage_notes = Vec::new();
    let mut deterministic_lens_tags = BTreeMap::new();
    let planned_providers = plan
        .providers()
        .iter()
        .map(|p| p.id.clone())
        .collect::<Vec<_>>();
    let candidate_denominators = plan
        .providers()
        .iter()
        .filter(|p| p.role == "candidate-generator")
        .map(|p| {
            let selector = p.configuration.get("selector").ok_or_else(|| {
                AuditError::Invalid(format!("provider {} is missing selector", p.id))
            })?;
            inventory.denominator_entries(selector)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for provider in plan.providers() {
        let blocked = provider
            .dependencies
            .iter()
            .any(|d| !completed.contains(d) || failed.contains(d));
        // An unsigned plan still runs every provider; its only consequence is
        // the `unsigned-plan` gap recorded above, which keeps the verdict
        // non-clean. Providers that do not apply to this repository are
        // reported not-applicable, not failed.
        let execution = if provider.not_applicable() {
            completed.insert(provider.id.clone());
            not_applicable_execution(provider)?
        } else if blocked {
            let gap = format!("dependency-failed:{}", provider.id);
            gaps.push(gap.clone());
            failed.insert(provider.id.clone());
            failed_execution(provider, gap, "skipped-after-dependency-failure", true)?
        } else {
            let context = ExecutionContext {
                plan_digest: plan.digest(),
                prior_results: &results,
            };
            match executor
                .execute_async_with_context(
                    plan,
                    provider,
                    inventory,
                    cancellation.clone(),
                    &context,
                )
                .await
            {
                // A provider that finds nothing of its kind in the frozen
                // inventory declares itself not applicable; that settles it
                // like a plan-level not-applicable, with no gap.
                Ok(result) if declares_not_applicable(provider, &result) => {
                    completed.insert(provider.id.clone());
                    ProviderExecution {
                        provider: provider.id.clone(),
                        result,
                        skipped: false,
                    }
                }
                Ok(result) => {
                    let denominator =
                        provider_denominator(provider, inventory, &candidate_denominators)?;
                    let result_error = result
                        .validate()
                        .err()
                        .map(|e| e.to_string())
                        .or_else(|| {
                            (result.provider.to_string() != provider.id)
                                .then(|| "provider result identity mismatch".into())
                        })
                        .or_else(|| {
                            (result.required != provider.required)
                                .then(|| "provider result required flag mismatch".into())
                        })
                        .or_else(|| {
                            (!result.applicable)
                                .then(|| "selected provider reported not applicable".into())
                        })
                        .or_else(|| validate_result(provider, &result, &denominator).err());
                    if let Some(error) = result_error {
                        let gap = format!("invalid-provider-result:{}:{error}", provider.id);
                        gaps.push(gap.clone());
                        failed.insert(provider.id.clone());
                        failed_execution_with_diagnostic(
                            provider,
                            gap,
                            "invalid-provider-result",
                            false,
                            Some(serde_json::to_value(&result).unwrap_or_else(|serialization_error| {
                                serde_json::json!({"serializationError":serialization_error.to_string()})
                            })),
                        )?
                    } else {
                        if result.complete
                            && matches!(
                                result.status,
                                ProviderStatus::Ok | ProviderStatus::Complete
                            )
                        {
                            completed.insert(provider.id.clone());
                            record_lenses(provider, &mut lenses_ran, &mut deterministic_lens_tags);
                        } else {
                            failed.insert(provider.id.clone());
                            if is_advisory_ownership(provider) {
                                coverage_notes.extend(advisory_ownership_notes(&result));
                            } else if let Some(note) = declared_capability_note(&result) {
                                coverage_notes.push(note);
                            } else {
                                gaps.push(format!("provider-incomplete:{}", provider.id));
                                gaps.extend(result.coverage_gaps.iter().cloned());
                            }
                            if is_pending_host(provider, &result) {
                                gaps.push(format!("reasoning-lens-pending-host:{}", provider.id));
                                pending_host.push(provider.id.clone());
                            }
                        }
                        ProviderExecution {
                            provider: provider.id.clone(),
                            result,
                            skipped: false,
                        }
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
        record_qualification(provider, &completed, &mut gaps, &mut coverage_notes);
    }
    gaps.sort();
    gaps.dedup();
    lenses_ran.sort();
    lenses_ran.dedup();
    if lenses_ran != selected_reasoning {
        gaps.push("selected reasoning lenses did not complete".into());
    }
    gaps.sort();
    gaps.dedup();
    Ok(ExecutionReport {
        plan_digest: plan.digest().into(),
        plan_signature: plan.signature().map(ToOwned::to_owned),
        generation: inventory.generation.clone(),
        inventory_digest: inventory.digest.clone(),
        planned_providers,
        results,
        selected_lenses,
        lenses_ran,
        selected_reasoning_lenses: selected_reasoning,
        pending_host,
        deterministic_lens_tags,
        coverage_notes: sorted_unique(coverage_notes),
        gaps,
    })
}

fn reject_provider_universe_execution_plan(plan: &FrozenPlan) -> Result<(), AuditError> {
    if plan.plan().bounds.contains_key(PROVIDER_UNIVERSE_BOUND) {
        return Err(AuditError::Invalid(
            "provider-universe plan cannot be executed".into(),
        ));
    }
    Ok(())
}

fn failed_execution(
    provider: &AuditProvider,
    gap: String,
    degradation: &str,
    skipped: bool,
) -> Result<ProviderExecution, AuditError> {
    failed_execution_with_diagnostic(provider, gap, degradation, skipped, None)
}

fn failed_execution_with_diagnostic(
    provider: &AuditProvider,
    gap: String,
    degradation: &str,
    skipped: bool,
    diagnostic: Option<Value>,
) -> Result<ProviderExecution, AuditError> {
    let mut details = BTreeMap::new();
    if let Some(diagnostic) = diagnostic {
        details.insert("invalidProviderResult".into(), diagnostic);
    }
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
            details,
        },
    })
}

fn validate_result(
    provider: &AuditProvider,
    result: &ProviderResult,
    denominator: &ProviderDenominator,
) -> Result<(), String> {
    if provider.role.contains("candidate") && !result.findings.is_empty() {
        return Err("candidate-generator cannot emit findings".into());
    }
    if provider.role.contains("candidate")
        && ["selfCertifies", "closesFindings", "adjudicated"]
            .iter()
            .any(|field| result.details.get(*field).and_then(Value::as_bool) == Some(true))
    {
        return Err("candidate-generator cannot self-close or adjudicate findings".into());
    }
    if matches!(provider.kind, crate::plan::ProviderKind::HostService)
        && ["selfCertifies", "closesFindings"]
            .iter()
            .any(|field| result.details.get(*field).and_then(Value::as_bool) == Some(true))
    {
        return Err(
            "host-service result cannot self-certify without independent adjudication".into(),
        );
    }
    if let Some(coverage) = &result.coverage {
        if coverage.denominator_digest != denominator.digest {
            return Err("provider coverage denominator does not match frozen inventory".into());
        }
        if coverage.expected != denominator.count as u64 {
            return Err(
                "provider coverage expected count does not match frozen selector denominator"
                    .into(),
            );
        }
        if coverage.examined > coverage.expected {
            return Err("provider coverage examined count exceeds denominator".into());
        }
    }
    if result.complete {
        let coverage = result
            .coverage
            .as_ref()
            .ok_or_else(|| "complete provider result is missing coverage".to_owned())?;
        if coverage.expected != coverage.examined || !coverage.gaps.is_empty() {
            return Err("complete provider result lacks exact denominator reconciliation".into());
        }
    }
    for finding in &result.findings {
        let evidence = result
            .details
            .get("findingEvidence")
            .and_then(Value::as_object)
            .and_then(|items| items.get(finding.id.as_str()))
            .filter(|value| value.is_object() && !value.as_object().is_some_and(|o| o.is_empty()))
            .ok_or_else(|| format!("finding {} is missing evidence", finding.id))?;
        let _ = evidence;
        let locations = result
            .details
            .get("findingLocations")
            .and_then(Value::as_object)
            .and_then(|items| items.get(finding.id.as_str()))
            .and_then(Value::as_array)
            .ok_or_else(|| format!("finding {} is missing location map", finding.id))?;
        let visual_artifact_only = provider.id == "legacy.visual.core"
            && locations.is_empty()
            && valid_visual_artifact_evidence(provider, evidence);
        if provider.id == "legacy.visual.core" {
            if !visual_artifact_only {
                return Err(format!(
                    "visual finding {} lacks bound artifact evidence or carries a source anchor",
                    finding.id
                ));
            }
            continue;
        }
        if locations.is_empty() && !visual_artifact_only {
            return Err(format!("finding {} is missing source location", finding.id));
        }
        if locations
            .iter()
            .any(|location| location.as_str().is_none_or(str::is_empty))
        {
            return Err(format!(
                "finding {} has invalid source location",
                finding.id
            ));
        }
        for location in locations.iter().filter_map(Value::as_str) {
            let path = location
                .rsplit_once(':')
                .map(|(path, _)| path)
                .unwrap_or(location)
                .replace('\\', "/");
            if !denominator.paths.contains(&path) {
                return Err(format!(
                    "finding {} location is outside frozen selector denominator: {path}",
                    finding.id
                ));
            }
        }
    }
    if matches!(
        provider.kind,
        crate::plan::ProviderKind::TypedExternalProjectTool
    ) {
        validate_external_receipt(provider, result)?;
    }
    Ok(())
}

fn valid_visual_artifact_evidence(provider: &AuditProvider, evidence: &Value) -> bool {
    let Some(visual) = provider
        .configuration
        .get("runner")
        .and_then(|runner| runner.get("visual"))
    else {
        return false;
    };
    let Some(spec) = visual.get("spec") else {
        return false;
    };
    let Some(spec_digest) = visual.get("specDigest").and_then(Value::as_str) else {
        return false;
    };
    if evidence.get("kind").and_then(Value::as_str) != Some("visual-artifact-difference")
        || evidence.get("specDigest").and_then(Value::as_str) != Some(spec_digest)
        || !is_sha256_digest(spec_digest)
    {
        return false;
    }
    let Some(capture_id) = evidence.get("captureId").and_then(Value::as_str) else {
        return false;
    };
    let Some(captures) = spec.get("captures").and_then(Value::as_array) else {
        return false;
    };
    let mut matching = captures
        .iter()
        .filter(|capture| capture.get("id").and_then(Value::as_str) == Some(capture_id));
    let Some(capture) = matching.next() else {
        return false;
    };
    if matching.next().is_some() {
        return false;
    }
    let Some(actual_path) = capture.get("path").and_then(Value::as_str) else {
        return false;
    };
    let Some(baseline_path) = capture.get("baseline").and_then(Value::as_str) else {
        return false;
    };
    let artifact_matches = |role: &str, expected_path: &str| {
        let Some(artifact) = evidence.get(role) else {
            return false;
        };
        artifact.get("path").and_then(Value::as_str) == Some(expected_path)
            && artifact
                .get("digest")
                .and_then(Value::as_str)
                .is_some_and(is_sha256_digest)
            && artifact
                .get("bytes")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0)
    };
    if !artifact_matches("actual", actual_path)
        || !artifact_matches("baseline", baseline_path)
        || !evidence.get("diff").is_some_and(Value::is_object)
    {
        return false;
    }
    if let Some(frozen_baselines) = visual.get("baselines") {
        let expected_digest = frozen_baselines
            .get("files")
            .and_then(Value::as_array)
            .and_then(|files| {
                files
                    .iter()
                    .find(|file| file.get("path").and_then(Value::as_str) == Some(baseline_path))
            })
            .and_then(|file| file.get("sha256"))
            .and_then(Value::as_str);
        if evidence
            .get("baseline")
            .and_then(|item| item.get("digest"))
            .and_then(Value::as_str)
            != expected_digest
        {
            return false;
        }
    }
    true
}

fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn provider_denominator(
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    candidates: &[crate::inventory::InventoryDenominator],
) -> Result<ProviderDenominator, AuditError> {
    let selector = provider.configuration.get("selector").ok_or_else(|| {
        AuditError::Invalid(format!("provider {} is missing selector", provider.id))
    })?;
    let denominator = inventory.denominator_entries_with_candidates(selector, candidates)?;
    let expected_digest = provider
        .configuration
        .get("denominatorDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AuditError::Invalid(format!(
                "provider {} is missing frozen denominator digest",
                provider.id
            ))
        })?;
    let expected_count = provider
        .configuration
        .get("denominatorCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            AuditError::Invalid(format!(
                "provider {} is missing frozen denominator count",
                provider.id
            ))
        })?;
    if denominator.digest != expected_digest || denominator.entries.len() as u64 != expected_count {
        return Err(AuditError::SourceDrift(format!(
            "provider {} denominator changed after plan freeze",
            provider.id
        )));
    }
    Ok(ProviderDenominator {
        count: denominator.entries.len(),
        digest: denominator.digest,
        paths: denominator
            .entries
            .into_iter()
            .map(|entry| entry.path)
            .collect(),
    })
}

struct ProviderDenominator {
    count: usize,
    digest: String,
    paths: BTreeSet<String>,
}

fn validate_external_receipt(
    provider: &AuditProvider,
    result: &ProviderResult,
) -> Result<(), String> {
    validate_external_receipt_projection(&provider.id, &result.details, result.complete)
}

/// Validate the complete external receipt projection before any caller treats
/// a typed refusal as unavailable. Kept shared with legacy-check projection so
/// that direct provider projection cannot suppress malformed receipts.
pub(crate) fn validate_external_receipt_projection(
    provider_id: &str,
    details: &BTreeMap<String, Value>,
    result_complete: bool,
) -> Result<(), String> {
    let receipt = details
        .get("executionReceipt")
        .or_else(|| details.get("receipt"))
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            "typed external project tool result is missing terminal execution receipt".to_owned()
        })?;
    let object = receipt.as_object().expect("object checked above");
    for field in [
        "schemaVersion",
        "receiptId",
        "requestId",
        "providerId",
        "planId",
        "policyId",
        "policy",
        "taskId",
        "state",
        "complete",
        "executable",
        "command",
        "cwd",
        "environmentNames",
        "sandbox",
        "processTree",
        "timing",
        "exitCode",
        "signal",
        "stdout",
        "stderr",
        "parser",
        "gaps",
    ] {
        if !object.contains_key(field) {
            return Err(format!("external execution receipt missing {field}"));
        }
    }
    if object.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || [
            "receiptId",
            "requestId",
            "providerId",
            "planId",
            "policyId",
            "state",
        ]
        .iter()
        .any(|field| {
            object
                .get(*field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        || object.get("complete").and_then(Value::as_bool).is_none()
        || object
            .get("environmentNames")
            .and_then(Value::as_array)
            .is_none()
        || object.get("gaps").and_then(Value::as_array).is_none()
        || ["sandbox", "processTree", "timing", "parser"]
            .iter()
            .any(|field| !object.get(*field).is_some_and(Value::is_object))
    {
        return Err("malformed external execution receipt projection".into());
    }
    if object.get("providerId").and_then(Value::as_str) != Some(provider_id) {
        return Err("external execution receipt provider identity mismatch".into());
    }
    if !matches!(
        object.get("state").and_then(Value::as_str),
        Some(
            "blocked"
                | "completed"
                | "failed"
                | "missing_executable"
                | "unsealed_executable"
                | "unauthorized_effect"
                | "sandbox_missing"
                | "spawn_failed"
                | "timeout"
                | "cancelled"
                | "output_limited"
                | "kill_failed"
                | "artifact_failed"
                | "internal"
        )
    ) {
        return Err("external execution receipt has unknown terminal state".into());
    }
    if let Some(policy) = object.get("policy").and_then(Value::as_object) {
        if policy.get("id").and_then(Value::as_str)
            != object.get("policyId").and_then(Value::as_str)
        {
            return Err("external execution receipt policy identity mismatch".into());
        }
    }
    validate_nested_projection(object)?;
    let state_completed = object.get("state").and_then(Value::as_str) == Some("completed");
    let gaps_empty = object
        .get("gaps")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    if state_completed != gaps_empty {
        return Err("external receipt completed state must match gap emptiness".into());
    }
    let receipt_complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .expect("validated above");
    let terminal_complete = state_completed && gaps_empty;
    if receipt_complete != terminal_complete {
        return Err("external receipt complete must match completed state and empty gaps".into());
    }
    if receipt_complete {
        let process = object
            .get("processTree")
            .and_then(Value::as_object)
            .unwrap();
        if process.get("started") != Some(&Value::Bool(true))
            || process.get("terminated") != Some(&Value::Bool(true))
            || process.get("reaped") != Some(&Value::Bool(true))
        {
            return Err("completed external receipt lacks process termination evidence".into());
        }
    }
    if result_complete && !receipt_complete {
        return Err("external provider cannot complete from an incomplete receipt".into());
    }
    Ok(())
}

fn validate_nested_projection(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    let object_value = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("external receipt {field} must be an object"))
    };
    let policy = object.get("policy").expect("required above");
    if let Some(policy) = policy.as_object() {
        for field in ["id", "version", "digest", "allowed", "reason"] {
            if !policy.contains_key(field) {
                return Err(format!("external receipt policy missing {field}"));
            }
        }
        if policy
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || policy.get("version").and_then(Value::as_u64).is_none()
            || policy
                .get("digest")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || policy.get("allowed").and_then(Value::as_bool).is_none()
            || (!policy.get("reason").is_some_and(Value::is_null)
                && policy.get("reason").and_then(Value::as_str).is_none())
        {
            return Err("malformed external receipt policy".into());
        }
    } else if !policy.is_null() {
        return Err("external receipt policy must be object or null".into());
    }
    if let Some(command) = object.get("command").filter(|value| !value.is_null()) {
        let command = command
            .as_object()
            .ok_or_else(|| "external receipt command must be object or null".to_owned())?;
        for field in [
            "executable",
            "args",
            "environmentNames",
            "redactedArgumentIndexes",
            "redactedEnvironmentNames",
        ] {
            if !command.contains_key(field) {
                return Err(format!("external receipt command missing {field}"));
            }
        }
        if command
            .get("executable")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || !string_array(command.get("args"))
            || !string_array(command.get("environmentNames"))
            || !string_array(command.get("redactedEnvironmentNames"))
            || !command.get("redactedArgumentIndexes").is_some_and(|value| {
                value
                    .as_array()
                    .is_some_and(|values| values.iter().all(Value::is_u64))
            })
        {
            return Err("malformed external receipt command".into());
        }
    }
    let sandbox = object_value("sandbox")?;
    if sandbox.get("required").and_then(Value::as_bool).is_none()
        || sandbox
            .get("networkEnabled")
            .and_then(Value::as_bool)
            .is_none()
        || (!sandbox.get("receiptId").is_some_and(Value::is_null)
            && sandbox.get("receiptId").and_then(Value::as_str).is_none())
    {
        return Err("malformed external receipt sandbox".into());
    }
    let process = object_value("processTree")?;
    if ["started", "terminated", "hardKilled", "reaped"]
        .iter()
        .any(|field| process.get(*field).and_then(Value::as_bool).is_none())
        || (!process.get("detail").is_some_and(Value::is_null)
            && process.get("detail").and_then(Value::as_str).is_none())
    {
        return Err("malformed external receipt processTree".into());
    }
    let timing = object_value("timing")?;
    let started = timing.get("startedAtMs").and_then(Value::as_u64);
    let completed = timing.get("completedAtMs").and_then(Value::as_u64);
    let duration = timing.get("durationMs").and_then(Value::as_u64);
    if started.is_none()
        || completed.is_none()
        || duration.is_none()
        || completed.unwrap() < started.unwrap()
        || completed.unwrap() - started.unwrap() != duration.unwrap()
    {
        return Err("malformed or inconsistent external receipt timing".into());
    }
    let parser = object_value("parser")?;
    let attempted = parser.get("attempted").and_then(Value::as_bool);
    let succeeded = parser.get("succeeded").and_then(Value::as_bool);
    if attempted.is_none()
        || succeeded.is_none()
        || (!parser.get("error").is_some_and(Value::is_null)
            && parser.get("error").and_then(Value::as_str).is_none())
        || (succeeded == Some(true)
            && (attempted != Some(true) || !parser.get("error").unwrap().is_null()))
        || (attempted == Some(false) && succeeded == Some(true))
    {
        return Err("malformed external receipt parser".into());
    }
    for field in ["stdout", "stderr"] {
        if let Some(artifact) = object.get(field).filter(|value| !value.is_null()) {
            let artifact = artifact
                .as_object()
                .ok_or_else(|| format!("external receipt {field} must be object or null"))?;
            if ["path", "digest", "bytes", "immutable"]
                .iter()
                .any(|key| !artifact.contains_key(*key))
                || artifact
                    .get("path")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || artifact
                    .get("digest")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || artifact.get("bytes").and_then(Value::as_u64).is_none()
                || artifact.get("immutable").and_then(Value::as_bool).is_none()
            {
                return Err(format!("malformed external receipt {field} artifact"));
            }
        }
    }
    if let Some(executable) = object.get("executable").filter(|value| !value.is_null()) {
        let executable = executable
            .as_object()
            .ok_or_else(|| "external receipt executable must be object or null".to_owned())?;
        for field in [
            "requestedPath",
            "canonicalPath",
            "digest",
            "digestState",
            "signature",
            "version",
        ] {
            if !executable.contains_key(field) {
                return Err(format!("external receipt executable missing {field}"));
            }
        }
        let version = object_value_from(executable, "version")?;
        if executable
            .get("requestedPath")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || (!executable.get("canonicalPath").is_some_and(Value::is_null)
                && executable
                    .get("canonicalPath")
                    .and_then(Value::as_str)
                    .is_none())
            || (!executable.get("digest").is_some_and(Value::is_null)
                && executable.get("digest").and_then(Value::as_str).is_none())
            || executable
                .get("digestState")
                .and_then(Value::as_str)
                .is_none()
            || executable
                .get("signature")
                .and_then(Value::as_str)
                .is_none()
            || !version.contains_key("args")
            || !version.contains_key("output")
            || !version.contains_key("exitCode")
            || !version.contains_key("qualified")
            || !string_array(version.get("args"))
            || (!version.get("output").is_some_and(Value::is_null)
                && version.get("output").and_then(Value::as_str).is_none())
            || (!version.get("exitCode").is_some_and(Value::is_null)
                && version.get("exitCode").and_then(Value::as_i64).is_none())
            || version.get("qualified").and_then(Value::as_bool).is_none()
        {
            return Err("malformed external receipt executable identity".into());
        }
    }
    for field in ["environmentNames", "gaps"] {
        if !string_array(object.get(field)) {
            return Err(format!("external receipt {field} must be a string array"));
        }
    }
    for field in ["taskId", "cwd"] {
        if !object.get(field).is_some_and(Value::is_null)
            && object.get(field).and_then(Value::as_str).is_none()
        {
            return Err(format!("external receipt {field} must be string or null"));
        }
    }
    for field in ["exitCode", "signal"] {
        if !object.get(field).is_some_and(Value::is_null)
            && object.get(field).and_then(Value::as_i64).is_none()
        {
            return Err(format!("external receipt {field} must be integer or null"));
        }
    }
    Ok(())
}

fn object_value_from<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("external receipt {field} must be an object"))
}

fn string_array(value: Option<&Value>) -> bool {
    value.is_some_and(|value| {
        value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::ProviderKind;
    use crate::{inventory::InventoryEntry, plan::AuditPlan};
    use legion_contracts::{Coverage, FindingId, FindingRef, ProviderSpec};
    use serde_json::json;
    use std::sync::Mutex;

    fn handoff_fixture() -> (FrozenPlan, InventoryEnvelope) {
        let inventory = InventoryEnvelope::new(
            "runtime-visual-order",
            "generation",
            vec![InventoryEntry {
                path: "src/app.ts".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            }],
        )
        .unwrap();
        let runtime: ProviderSpec = serde_json::from_value(serde_json::json!({
            "schemaVersion":2,"id":"legacy.runtime.app","providerVersion":"2.0.0",
            "family":"performance","lensIds":["runtime"],"role":"deterministic","phase":"runtime",
            "dependsOn":[],"consumes":[],"produces":["provider-result"],"selector":{"op":"always"},
            "denominatorKind":"repository-inventory","runner":{"kind":"legacy-check","check":"runtime","runtime":{"url":"https://example.test/","width":16,"height":12}},
            "hostCapabilities":[],"execution":{},"reasoning":{},"benchmark":{"status":"unproven","requiredForCleanClaim":false},
            "cleanClaim":"evidence-only","controlIds":[],"scopes":[],"selectable":true
        })).unwrap();
        let visual: ProviderSpec = serde_json::from_value(serde_json::json!({
            "schemaVersion":2,"id":"legacy.visual.core","providerVersion":"2.0.0",
            "family":"visual","lensIds":["visual"],"role":"deterministic","phase":"runtime",
            "dependsOn":[],"consumes":[],"produces":["provider-result"],"selector":{"op":"always"},
            "denominatorKind":"repository-inventory","runner":{"kind":"runtime-script","module":"legacy.visual.core","visual":{"captureSource":{"kind":"runtime-provider","providerId":"legacy.runtime.app"}}},
            "hostCapabilities":[],"execution":{},"reasoning":{},"benchmark":{"status":"unproven","requiredForCleanClaim":false},
            "cleanClaim":"evidence-only","controlIds":[],"scopes":[],"selectable":true
        })).unwrap();
        let plan = AuditPlan::compile(&inventory, &[visual, runtime])
            .unwrap()
            .freeze_source_diagnostic()
            .unwrap();
        (plan, inventory)
    }

    #[test]
    fn visual_artifact_only_evidence_is_bound_and_source_anchors_are_rejected() {
        let spec_digest = format!("sha256:{}", "a".repeat(64));
        let actual_digest = format!("sha256:{}", "b".repeat(64));
        let baseline_digest = format!("sha256:{}", "c".repeat(64));
        let provider = AuditProvider {
            id: "legacy.visual.core".into(),
            version: "1".into(),
            role: "deterministic".into(),
            phase: "runtime".into(),
            lens_ids: Vec::new(),
            dependencies: Vec::new(),
            kind: ProviderKind::RustAlgorithm,
            configuration: BTreeMap::from([
                ("selector".into(), json!({"op":"always"})),
                (
                    "denominatorDigest".into(),
                    json!(format!("sha256:{}", "d".repeat(64))),
                ),
                ("denominatorCount".into(), json!(0)),
                (
                    "runner".into(),
                    json!({"visual":{
                        "specDigest":spec_digest,
                        "spec":{"captures":[{"id":"home","path":"shots/home.png","baseline":"home.png"}]},
                        "baselines":{"files":[{"path":"home.png","sha256":baseline_digest}]}
                    }}),
                ),
            ]),
            bounds: BTreeMap::new(),
            clean_claim: "evidence-only".into(),
            benchmark_status: "unproven".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: false,
        };
        let finding = FindingRef {
            id: FindingId::new("visual-fixture").unwrap(),
            severity: "medium".into(),
        };
        let finding_id = finding.id.to_string();
        let evidence = json!({
            "kind":"visual-artifact-difference",
            "captureId":"home",
            "specDigest":spec_digest,
            "actual":{"path":"shots/home.png","digest":actual_digest,"bytes":24},
            "baseline":{"path":"home.png","digest":baseline_digest,"bytes":24},
            "diff":{"changedPixels":1}
        });
        let mut result = ProviderResult {
            schema_version: 1,
            provider: ProviderId::new("legacy.visual.core").unwrap(),
            applicable: true,
            required: false,
            status: ProviderStatus::Partial,
            complete: false,
            coverage: None,
            findings: vec![finding.clone()],
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::from([
                (
                    "findingEvidence".into(),
                    Value::Object(serde_json::Map::from_iter([(finding_id.clone(), evidence)])),
                ),
                (
                    "findingLocations".into(),
                    Value::Object(serde_json::Map::from_iter([(
                        finding_id.clone(),
                        json!([]),
                    )])),
                ),
            ]),
        };
        let denominator = ProviderDenominator {
            count: 0,
            digest: format!("sha256:{}", "d".repeat(64)),
            paths: BTreeSet::new(),
        };
        assert!(validate_result(&provider, &result, &denominator).is_ok());

        result.details.get_mut("findingLocations").unwrap()[finding.id.as_str()] =
            json!(["src/app.ts"]);
        assert!(validate_result(&provider, &result, &denominator)
            .unwrap_err()
            .contains("source anchor"));

        result.details.get_mut("findingLocations").unwrap()[finding.id.as_str()] = json!([]);
        result.details.get_mut("findingEvidence").unwrap()[finding.id.as_str()]["actual"]["path"] =
            json!("src/app.ts");
        assert!(validate_result(&provider, &result, &denominator)
            .unwrap_err()
            .contains("artifact evidence"));
        let mut other = provider.clone();
        other.id = "other.provider".into();
        result.provider = ProviderId::new("other.provider").unwrap();
        assert!(validate_result(&other, &result, &denominator)
            .unwrap_err()
            .contains("missing source location"));
    }

    #[derive(Default)]
    struct ContextOrder(Mutex<Vec<(String, usize, String)>>);

    impl ContextOrder {
        fn result(
            &self,
            provider: &AuditProvider,
            inventory: &InventoryEnvelope,
            context: &ExecutionContext<'_>,
        ) -> Result<ProviderResult, AuditError> {
            self.0.lock().unwrap().push((
                provider.id.clone(),
                context.prior_results.len(),
                context.plan_digest.to_owned(),
            ));
            let denominator =
                inventory.denominator_entries(provider.configuration.get("selector").unwrap())?;
            let gap = format!("{}-partial", provider.id);
            Ok(ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(&provider.id).unwrap(),
                applicable: true,
                required: provider.required,
                status: ProviderStatus::Partial,
                complete: false,
                coverage: Some(Coverage {
                    denominator_digest: denominator.digest,
                    expected: denominator.entries.len() as u64,
                    examined: 0,
                    gaps: vec![gap.clone()],
                }),
                findings: Vec::<FindingRef>::new(),
                coverage_gaps: vec![gap],
                degradation: Vec::new(),
                details: BTreeMap::new(),
            })
        }
    }

    #[async_trait::async_trait]
    impl ProviderExecutor for ContextOrder {
        fn execute(
            &self,
            _provider: &AuditProvider,
            _inventory: &InventoryEnvelope,
        ) -> Result<ProviderResult, AuditError> {
            unreachable!("execution loop invokes context seam")
        }

        fn execute_with_context(
            &self,
            _plan: &FrozenPlan,
            provider: &AuditProvider,
            inventory: &InventoryEnvelope,
            context: &ExecutionContext<'_>,
        ) -> Result<ProviderResult, AuditError> {
            self.result(provider, inventory, context)
        }

        async fn execute_async_with_context(
            &self,
            _plan: &FrozenPlan,
            provider: &AuditProvider,
            inventory: &InventoryEnvelope,
            _cancellation: CancellationToken,
            context: &ExecutionContext<'_>,
        ) -> Result<ProviderResult, AuditError> {
            self.result(provider, inventory, context)
        }
    }

    #[test]
    fn sync_context_orders_visual_after_partial_runtime_without_success_dependency() {
        let (plan, inventory) = handoff_fixture();
        assert!(plan.providers()[1].dependencies.is_empty());
        let executor = ContextOrder::default();
        execute(&plan, &inventory, &executor).unwrap();
        let seen = executor.0.lock().unwrap();
        assert_eq!(seen[0].0, "legacy.runtime.app");
        assert_eq!(seen[1].0, "legacy.visual.core");
        assert_eq!(seen[1].1, 1, "partial runtime result remains available");
        assert_eq!(seen[1].2, plan.digest());
    }

    #[test]
    fn async_context_orders_visual_after_partial_runtime_without_success_dependency() {
        let (plan, inventory) = handoff_fixture();
        assert!(plan.providers()[1].dependencies.is_empty());
        let executor = ContextOrder::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(execute_with_cancellation(
                &plan,
                &inventory,
                &executor,
                CancellationToken::new(),
            ))
            .unwrap();
        let seen = executor.0.lock().unwrap();
        assert_eq!(seen[0].0, "legacy.runtime.app");
        assert_eq!(seen[1].0, "legacy.visual.core");
        assert_eq!(seen[1].1, 1, "partial runtime result remains available");
        assert_eq!(seen[1].2, plan.digest());
    }

    #[test]
    fn provider_universe_purpose_is_rejected_before_sync_or_async_provider_effects() {
        use crate::plan::PROVIDER_UNIVERSE_BOUND;

        let (ordinary, inventory) = handoff_fixture();
        let mut plan = ordinary.plan().clone();
        plan.bounds.insert(
            PROVIDER_UNIVERSE_BOUND.into(),
            serde_json::json!({
                "schemaVersion": 1,
                "purpose": "audit-provider-universe",
                "selectedPlanDigest": ordinary.digest(),
            }),
        );
        let universe = plan.freeze(Some(b"execution-purpose-test-key")).unwrap();

        let executor = ContextOrder::default();
        assert!(execute(&universe, &inventory, &executor).is_err());
        assert!(executor.0.lock().unwrap().is_empty());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(runtime
            .block_on(execute_with_cancellation(
                &universe,
                &inventory,
                &executor,
                CancellationToken::new(),
            ))
            .is_err());
        assert!(executor.0.lock().unwrap().is_empty());
    }

    fn provider() -> AuditProvider {
        AuditProvider {
            id: "fixture-provider".into(),
            version: "1".into(),
            role: "deterministic".into(),
            phase: "source".into(),
            lens_ids: Vec::new(),
            dependencies: Vec::new(),
            kind: ProviderKind::TypedExternalProjectTool,
            configuration: BTreeMap::new(),
            bounds: BTreeMap::new(),
            clean_claim: "evidence-only".into(),
            benchmark_status: "qualified".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: true,
        }
    }

    #[test]
    fn invalid_provider_result_is_quarantined_without_promoting_its_claims() {
        let diagnostic = serde_json::json!({
            "status":"ok",
            "complete":true,
            "findings":[{"id":"untrusted-finding","severity":"critical"}],
            "details":{"raw":"preserve me"}
        });
        let execution = failed_execution_with_diagnostic(
            &provider(),
            "invalid-provider-result:fixture-provider:malformed".into(),
            "invalid-provider-result",
            false,
            Some(diagnostic.clone()),
        )
        .unwrap();

        assert_eq!(execution.result.status, ProviderStatus::Failed);
        assert!(!execution.result.complete);
        assert!(execution.result.findings.is_empty());
        assert!(execution.result.coverage_gaps[0].starts_with("invalid-provider-result:"));
        assert_eq!(
            execution.result.details["invalidProviderResult"],
            diagnostic
        );
    }

    fn receipt(state: &str, complete: bool, gaps: Value) -> Value {
        serde_json::json!({
            "schemaVersion": 1,
            "receiptId": "receipt:fixture",
            "requestId": "request:fixture",
            "providerId": "fixture-provider",
            "planId": "plan:fixture",
            "policyId": "policy:fixture",
            "policy": null,
            "taskId": null,
            "state": state,
            "complete": complete,
            "executable": null,
            "command": null,
            "cwd": null,
            "environmentNames": [],
            "sandbox": {"required": false, "receiptId": null, "networkEnabled": false},
            "processTree": {"started": false, "terminated": false, "hardKilled": false, "reaped": false, "detail": null},
            "timing": {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0},
            "exitCode": null,
            "signal": null,
            "stdout": null,
            "stderr": null,
            "parser": {"attempted": false, "succeeded": false, "error": null},
            "gaps": gaps,
        })
    }

    #[test]
    fn terminal_receipt_state_matches_gap_emptiness() {
        let provider = provider();
        let inconsistent = receipt("completed", false, serde_json::json!(["incomplete"]));
        assert!(validate_external_receipt(
            &provider,
            &ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(&provider.id).unwrap(),
                applicable: true,
                required: true,
                status: ProviderStatus::Partial,
                complete: false,
                coverage: None,
                findings: Vec::new(),
                coverage_gaps: vec!["incomplete".into()],
                degradation: Vec::new(),
                details: BTreeMap::from([("executionReceipt".into(), inconsistent)]),
            },
        )
        .is_err());
        let gapless_failure = receipt("failed", false, serde_json::json!([]));
        assert!(validate_external_receipt(
            &provider,
            &ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(&provider.id).unwrap(),
                applicable: true,
                required: true,
                status: ProviderStatus::Partial,
                complete: false,
                coverage: None,
                findings: Vec::new(),
                coverage_gaps: vec!["incomplete".into()],
                degradation: Vec::new(),
                details: BTreeMap::from([("executionReceipt".into(), gapless_failure)]),
            },
        )
        .is_err());
    }
}

#[cfg(test)]
mod declared_capability_tests {
    use super::*;
    use legion_contracts::ProviderId;
    use std::collections::BTreeMap;

    fn incomplete_with_absence(tool: &str, blocking: bool, note: &str) -> ProviderResult {
        let mut details = BTreeMap::new();
        details.insert(
            "capabilityAbsence".to_owned(),
            serde_json::json!({"tool": tool, "note": note, "blocking": blocking}),
        );
        ProviderResult {
            schema_version: 1,
            provider: ProviderId::new("legacy.security.secrets").unwrap(),
            applicable: true,
            required: false,
            status: ProviderStatus::Partial,
            complete: false,
            coverage: None,
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details,
        }
    }

    #[test]
    fn missing_substitutable_tool_is_a_note_not_a_blocking_gap() {
        let result = incomplete_with_absence("gitleaks", false, "capability-absent:gitleaks");
        assert_eq!(
            declared_capability_note(&result).as_deref(),
            Some("capability-absent:gitleaks")
        );
    }

    #[test]
    fn missing_advisory_tool_keeps_its_blocking_gap() {
        let result = incomplete_with_absence("cargo-audit", true, "host-capability:cargo-audit");
        assert_eq!(declared_capability_note(&result), None);
    }

    #[test]
    fn results_without_a_declared_absence_are_unchanged() {
        let mut result = incomplete_with_absence("gitleaks", false, "capability-absent:gitleaks");
        result.details.clear();
        assert_eq!(declared_capability_note(&result), None);
    }
}
