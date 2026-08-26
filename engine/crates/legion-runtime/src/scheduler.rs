use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

use legion_contracts::{
    InvocationId, InvocationReceipt, InvocationStatus, ProviderId, ProviderResult, ProviderStatus,
    TaskSpec,
};
use legion_provider_sdk::{
    normalize_result, Provider, ProviderContext, ProviderError, ProviderErrorKind, ProviderRegistry,
};
use tokio_util::sync::CancellationToken;

use crate::{
    budget::{BudgetAccount, BudgetReservation},
    error::RuntimeError,
    plan::FrozenPlan,
    task::ContextRequest,
};

#[cfg(not(test))]
const PROVIDER_CLEANUP_GRACE: Duration = Duration::from_millis(2500);
#[cfg(test)]
const PROVIDER_CLEANUP_GRACE: Duration = Duration::from_millis(25);

#[derive(Clone, Copy)]
enum ProviderSignal {
    Cancelled,
    Deadline,
}

impl ProviderSignal {
    fn status(self) -> InvocationStatus {
        match self {
            Self::Cancelled => InvocationStatus::Cancelled,
            Self::Deadline => InvocationStatus::Failed,
        }
    }

    fn gap(self) -> &'static str {
        match self {
            Self::Cancelled => "provider cancelled",
            Self::Deadline => "provider deadline exceeded",
        }
    }
}

struct ProviderExecution {
    result: Result<ProviderResult, ProviderError>,
    signal: Option<ProviderSignal>,
    cleanup_unconfirmed: bool,
}

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
            if let Some(signal) = pre_provider_signal(&self.policy) {
                match signal {
                    ProviderSignal::Cancelled => {
                        output.events.push(SchedulerEvent::Cancelled);
                        output.receipts.push(self.receipt(
                            &provider_id,
                            signal.status(),
                            false,
                            vec![signal.gap().into()],
                        ));
                    }
                    ProviderSignal::Deadline => {
                        let gap = signal.gap().to_owned();
                        output
                            .events
                            .push(SchedulerEvent::Failed(provider_id.clone(), gap.clone()));
                        failed.insert(provider_id.clone());
                        output.receipts.push(self.receipt(
                            &provider_id,
                            signal.status(),
                            false,
                            vec![gap],
                        ));
                    }
                }
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
            let context = if let Some(tool) = self.request.external_project_tool().cloned() {
                context.with_external_project_tool(tool)
            } else {
                context
            };
            let remaining = self
                .policy
                .deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            let execution = Self::execute_provider(
                provider,
                context,
                self.policy.cancellation.clone(),
                remaining,
            )
            .await;
            match execution.result {
                Ok(value) => {
                    let mut normalized = normalize_result(value)?;
                    if let Some(signal) = execution.signal {
                        force_incomplete(&mut normalized, signal.gap());
                        if execution.cleanup_unconfirmed {
                            add_gap(&mut normalized, "cleanup_unconfirmed");
                        }
                    }
                    let complete =
                        normalized.complete && normalized.status == ProviderStatus::Complete;
                    if complete {
                        succeeded.insert(provider_id.clone());
                    } else {
                        failed.insert(provider_id.clone());
                    }
                    output.events.push(if execution.signal.is_some() {
                        SchedulerEvent::Failed(provider_id.clone(), "provider interrupted".into())
                    } else {
                        SchedulerEvent::Completed(provider_id.clone())
                    });
                    output.receipts.push(self.receipt(
                        &provider_id,
                        if let Some(signal) = execution.signal {
                            signal.status()
                        } else if complete {
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
                    let status =
                        execution
                            .signal
                            .map(ProviderSignal::status)
                            .unwrap_or_else(|| {
                                if error.kind == ProviderErrorKind::Cancelled {
                                    InvocationStatus::Cancelled
                                } else {
                                    InvocationStatus::Failed
                                }
                            });
                    let mut gaps = Vec::new();
                    if let Some(signal) = execution.signal {
                        gaps.push(signal.gap().into());
                    }
                    if execution.cleanup_unconfirmed {
                        gaps.push("cleanup_unconfirmed".into());
                    }
                    gaps.push(error.to_string());
                    output.events.push(SchedulerEvent::Failed(
                        provider_id.clone(),
                        error.to_string(),
                    ));
                    failed.insert(provider_id.clone());
                    output
                        .receipts
                        .push(self.receipt(&provider_id, status, false, gaps));
                }
            }
        }
        let _ = succeeded;
        Ok(output)
    }

    /// Run provider work in a detached task so a non-cooperative provider future is never
    /// cancelled by dropping the scheduler's handle. Signals cancel provider context, then
    /// bounded cleanup retains any terminal result arriving during grace period.
    async fn execute_provider(
        provider: Arc<dyn Provider>,
        context: ProviderContext,
        cancellation: CancellationToken,
        remaining: Duration,
    ) -> ProviderExecution {
        let provider_cancellation = context.cancellation().clone();
        let mut task = tokio::spawn(async move { provider.execute(&context).await });
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                provider_cancellation.cancel();
                Self::finish_after_signal(&mut task, ProviderSignal::Cancelled).await
            }
            _ = tokio::time::sleep(remaining) => {
                provider_cancellation.cancel();
                Self::finish_after_signal(&mut task, ProviderSignal::Deadline).await
            }
            result = &mut task => Self::join_result(result),
        }
    }

    async fn finish_after_signal(
        task: &mut tokio::task::JoinHandle<Result<ProviderResult, ProviderError>>,
        signal: ProviderSignal,
    ) -> ProviderExecution {
        match tokio::time::timeout(PROVIDER_CLEANUP_GRACE, task).await {
            Ok(result) => Self::join_result(result).with_signal(signal, false),
            Err(_) => ProviderExecution {
                result: Err(ProviderError::new(
                    match signal {
                        ProviderSignal::Cancelled => ProviderErrorKind::Cancelled,
                        ProviderSignal::Deadline => ProviderErrorKind::Timeout,
                    },
                    signal.gap(),
                )),
                signal: Some(signal),
                cleanup_unconfirmed: true,
            },
        }
    }

    fn join_result(
        result: Result<Result<ProviderResult, ProviderError>, tokio::task::JoinError>,
    ) -> ProviderExecution {
        let result = result.unwrap_or_else(|error| {
            Err(ProviderError::new(
                ProviderErrorKind::MalformedOutput,
                format!("provider task failed: {error}"),
            ))
        });
        ProviderExecution {
            result,
            signal: None,
            cleanup_unconfirmed: false,
        }
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

impl ProviderExecution {
    fn with_signal(mut self, signal: ProviderSignal, cleanup_unconfirmed: bool) -> Self {
        self.signal = Some(signal);
        self.cleanup_unconfirmed = cleanup_unconfirmed;
        self
    }
}

fn add_gap(result: &mut ProviderResult, gap: &str) {
    if !result.coverage_gaps.iter().any(|existing| existing == gap) {
        result.coverage_gaps.push(gap.into());
    }
    result.coverage_gaps.sort();
    if !result.degradation.iter().any(|existing| existing == gap) {
        result.degradation.push(gap.into());
    }
    result.degradation.sort();
}

fn force_incomplete(result: &mut ProviderResult, gap: &str) {
    result.complete = false;
    if matches!(result.status, ProviderStatus::Ok | ProviderStatus::Complete) {
        result.status = ProviderStatus::Partial;
    }
    add_gap(result, gap);
}

fn pre_provider_signal(policy: &SchedulerPolicy) -> Option<ProviderSignal> {
    if policy.cancellation.is_cancelled() {
        Some(ProviderSignal::Cancelled)
    } else if Instant::now() >= policy.deadline {
        Some(ProviderSignal::Deadline)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use legion_contracts::ProviderResult;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn cancellation_keeps_noncooperative_provider_future_alive_until_bounded_cleanup() {
        let started = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let probe_started = started.clone();
        let probe_dropped = dropped.clone();
        let mut task: tokio::task::JoinHandle<Result<ProviderResult, ProviderError>> =
            tokio::spawn(async move {
                probe_started.store(true, Ordering::SeqCst);
                let _probe = DropProbe(probe_dropped);
                std::future::pending::<Result<ProviderResult, ProviderError>>().await
            });
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        let execution = tokio::time::timeout(
            Duration::from_millis(200),
            Scheduler::finish_after_signal(&mut task, ProviderSignal::Cancelled),
        )
        .await
        .expect("bounded scheduler cleanup");
        assert!(execution.cleanup_unconfirmed);
        assert!(matches!(execution.signal, Some(ProviderSignal::Cancelled)));
        assert!(!dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn pre_provider_deadline_is_distinct_from_cancellation() {
        let cancellation = CancellationToken::new();
        let cancelled = SchedulerPolicy::new(
            Instant::now() + Duration::from_secs(1),
            cancellation.clone(),
            0,
            "scheduler-test-repository",
        );
        assert!(pre_provider_signal(&cancelled).is_none());
        cancellation.cancel();
        assert!(matches!(
            pre_provider_signal(&cancelled),
            Some(ProviderSignal::Cancelled)
        ));

        let expired = SchedulerPolicy::new(
            Instant::now() - Duration::from_secs(1),
            CancellationToken::new(),
            0,
            "scheduler-test-repository",
        );
        assert!(matches!(
            pre_provider_signal(&expired),
            Some(ProviderSignal::Deadline)
        ));
        assert_eq!(ProviderSignal::Deadline.status(), InvocationStatus::Failed);
        assert_eq!(ProviderSignal::Deadline.gap(), "provider deadline exceeded");
    }
}
