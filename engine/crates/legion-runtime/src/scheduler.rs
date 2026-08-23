use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use legion_contracts::{
    InvocationId, InvocationReceipt, InvocationStatus, ProviderId, ProviderResult, ProviderStatus,
    TaskSpec,
};
use legion_provider_sdk::{normalize_result, ProviderContext, ProviderRegistry};
use tokio_util::sync::CancellationToken;

use crate::{
    budget::{BudgetAccount, BudgetReservation},
    error::RuntimeError,
    plan::FrozenPlan,
    task::ContextRequest,
};

#[derive(Clone, Debug)]
pub struct SchedulerPolicy {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
    pub generation: u64,
    pub repository: String,
    pub node_reservation: BudgetReservation,
}

impl SchedulerPolicy {
    pub fn new(
        deadline: Instant,
        cancellation: CancellationToken,
        generation: u64,
        repository: impl Into<String>,
    ) -> Self {
        Self {
            deadline,
            cancellation,
            generation,
            repository: repository.into(),
            node_reservation: BudgetReservation {
                active_time_ms: 1,
                cost_micros: 1,
                output_bytes: 0,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerEvent {
    Ready(ProviderId),
    Started(ProviderId),
    Completed(ProviderId),
    Failed(ProviderId, String),
    Skipped(ProviderId, String),
    Cancelled,
}

#[derive(Clone, Debug, Default)]
pub struct SchedulerOutput {
    pub receipts: Vec<InvocationReceipt>,
    pub results: BTreeMap<ProviderId, ProviderResult>,
    pub events: Vec<SchedulerEvent>,
}

pub struct Scheduler<'a> {
    registry: &'a ProviderRegistry,
    plan: &'a FrozenPlan,
    request: &'a ContextRequest,
    task: &'a TaskSpec,
    grant: legion_contracts::InvocationGrant,
    invocation_id: InvocationId,
    policy: SchedulerPolicy,
    budget: BudgetAccount,
}

impl<'a> Scheduler<'a> {
    pub fn new(
        registry: &'a ProviderRegistry,
        plan: &'a FrozenPlan,
        request: &'a ContextRequest,
        task: &'a TaskSpec,
        grant: legion_contracts::InvocationGrant,
        invocation_id: InvocationId,
        policy: SchedulerPolicy,
    ) -> Self {
        let budget = BudgetAccount::new(grant.budget.clone());
        Self {
            registry,
            plan,
            request,
            task,
            grant,
            invocation_id,
            policy,
            budget,
        }
    }

    pub async fn run(mut self) -> Result<SchedulerOutput, RuntimeError> {
        self.request.ensure_available()?;
        let mut output = SchedulerOutput::default();
        let mut succeeded: BTreeSet<ProviderId> = BTreeSet::new();
        let mut failed: BTreeSet<ProviderId> = BTreeSet::new();
        let ordered = self
            .plan
            .plan()
            .ordered_nodes()
            .map_err(RuntimeError::from)?;
        for node in ordered {
            let Some(provider_id) = node.provider.clone() else {
                continue;
            };
            output
                .events
                .push(SchedulerEvent::Ready(provider_id.clone()));
            if self.policy.cancellation.is_cancelled() || Instant::now() >= self.policy.deadline {
                output.events.push(SchedulerEvent::Cancelled);
                output.receipts.push(self.receipt(
                    &provider_id,
                    InvocationStatus::Cancelled,
                    false,
                    vec!["scheduler cancelled".into()],
                ));
                continue;
            }
            let dependency_failed = node.depends_on.iter().any(|dependency| {
                failed
                    .iter()
                    .any(|provider| provider.as_str() == dependency.as_str())
            });
            if dependency_failed {
                let reason = "dependency did not complete".to_string();
                output
                    .events
                    .push(SchedulerEvent::Skipped(provider_id.clone(), reason.clone()));
                failed.insert(provider_id.clone());
                output.receipts.push(self.receipt(
                    &provider_id,
                    InvocationStatus::Failed,
                    false,
                    vec![reason],
                ));
                continue;
            }
            if let Err(error) = self.budget.reserve(&self.policy.node_reservation) {
                let reason = error.to_string();
                output
                    .events
                    .push(SchedulerEvent::Skipped(provider_id.clone(), reason.clone()));
                failed.insert(provider_id.clone());
                output.receipts.push(self.receipt(
                    &provider_id,
                    InvocationStatus::Failed,
                    false,
                    vec![reason],
                ));
                continue;
            }
            let provider = self
                .registry
                .get(&provider_id)
                .ok_or_else(|| RuntimeError::Scheduler(format!("provider {provider_id} missing")))?
                .clone();
            output
                .events
                .push(SchedulerEvent::Started(provider_id.clone()));
            let context = ProviderContext::new(
                self.plan.plan().clone(),
                self.request.envelope.clone(),
                self.task.clone(),
                self.policy.repository.clone(),
                self.policy.generation,
                self.policy.deadline,
                self.policy.cancellation.clone(),
                self.grant.clone(),
                self.request.sources.clone(),
                self.request.effects.clone(),
            );
            let remaining = self
                .policy
                .deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            let result = tokio::select! {
                _ = self.policy.cancellation.cancelled() => Err(legion_provider_sdk::ProviderError::cancelled()),
                result = tokio::time::timeout(remaining, provider.execute(&context)) => match result {
                    Ok(value) => value,
                    Err(_) => Err(legion_provider_sdk::ProviderError::timeout()),
                },
            };
            match result {
                Ok(value) => {
                    let normalized = normalize_result(value)?;
                    let complete =
                        normalized.complete && normalized.status == ProviderStatus::Complete;
                    if complete {
                        succeeded.insert(provider_id.clone());
                    } else {
                        failed.insert(provider_id.clone());
                    }
                    output
                        .events
                        .push(SchedulerEvent::Completed(provider_id.clone()));
                    output.receipts.push(self.receipt(
                        &provider_id,
                        if complete {
                            InvocationStatus::Ok
                        } else {
                            InvocationStatus::Partial
                        },
                        complete,
                        normalized.coverage_gaps.clone(),
                    ));
                    output.results.insert(provider_id, normalized);
                }
                Err(error) => {
                    let status = if error.kind == legion_provider_sdk::ProviderErrorKind::Cancelled
                    {
                        InvocationStatus::Cancelled
                    } else {
                        InvocationStatus::Failed
                    };
                    output.events.push(SchedulerEvent::Failed(
                        provider_id.clone(),
                        error.to_string(),
                    ));
                    failed.insert(provider_id.clone());
                    output.receipts.push(self.receipt(
                        &provider_id,
                        status,
                        false,
                        vec![error.to_string()],
                    ));
                }
            }
        }
        let _ = succeeded;
        Ok(output)
    }

    fn receipt(
        &self,
        provider: &ProviderId,
        status: InvocationStatus,
        complete: bool,
        gaps: Vec<String>,
    ) -> InvocationReceipt {
        InvocationReceipt {
            schema_version: 1,
            receipt_id: legion_contracts::ReceiptId::new(format!(
                "{}-{}",
                self.invocation_id, provider
            ))
            .expect("stable receipt id"),
            invocation_id: self.invocation_id.clone(),
            request_id: self.request.envelope.request_id.clone(),
            task_id: self.task.task_id.clone(),
            plan_id: self.plan.plan().id.clone(),
            provider: provider.clone(),
            status,
            complete,
            findings: Vec::new(),
            gaps,
            artifacts: BTreeMap::new(),
        }
    }
}
