use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use legion_contracts::{
    ExecutionRequirementV1, InvocationId, InvocationReceipt, InvocationStatus, NodeId, Plan,
    PlanNode, ProviderId, ProviderResult, ProviderStatus, TaskSpec,
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
    pub journal: Option<ExecutionJournal>,
    pub resume: bool,
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
            journal: None,
            resume: false,
        }
    }

    pub fn with_journal(mut self, journal: ExecutionJournal, resume: bool) -> Self {
        self.journal = Some(journal);
        self.resume = resume;
        self
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
    Resumed(ProviderId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunLedgerEntry {
    pub work_unit: String,
    pub call: String,
    pub state: String,
    pub active_time_ms: u64,
    pub cost_micros: u64,
    pub observed_at_ms: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseDecisionReceipt {
    pub decision_id: String,
    pub work_unit: String,
    pub prompt_digest: String,
    pub response_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrajectoryRecord {
    pub parent: String,
    pub work_unit: String,
    pub dependencies: Vec<String>,
    pub submitted_at_ms: u128,
    pub terminal_state: Option<String>,
}

/// Append-only native execution journal. A sync occurs before acknowledgement,
/// so restart recovery, pause decisions, trajectories, ledgers & observations
/// all share one durable ordering boundary.
#[derive(Clone, Debug)]
pub struct ExecutionJournal {
    path: PathBuf,
}

impl ExecutionJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append(&self, fields: &[&str]) -> Result<(), RuntimeError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| RuntimeError::Scheduler(error.to_string()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| RuntimeError::Scheduler(error.to_string()))?;
        let encoded = fields
            .iter()
            .map(|value| escape_field(value))
            .collect::<Vec<_>>()
            .join("\t");
        writeln!(file, "{encoded}")
            .and_then(|_| file.sync_data())
            .map_err(|error| RuntimeError::Scheduler(error.to_string()))
    }

    fn records(&self) -> Result<Vec<Vec<String>>, RuntimeError> {
        let content = match fs::read_to_string(&self.path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(RuntimeError::Scheduler(error.to_string())),
        };
        Ok(content
            .lines()
            .map(|line| line.split('\t').map(unescape_field).collect())
            .collect())
    }

    pub fn completed_work(&self) -> Result<BTreeSet<String>, RuntimeError> {
        Ok(self
            .records()?
            .into_iter()
            .filter(|record| record.first().map(String::as_str) == Some("terminal"))
            .filter(|record| record.get(2).map(String::as_str) == Some("complete"))
            .filter_map(|record| record.get(1).cloned())
            .collect())
    }

    pub fn unfinished_work(
        &self,
        planned: impl IntoIterator<Item = String>,
    ) -> Result<BTreeSet<String>, RuntimeError> {
        let completed = self.completed_work()?;
        Ok(planned
            .into_iter()
            .filter(|work_unit| !completed.contains(work_unit))
            .collect())
    }

    pub fn submit_trajectory(&self, record: &TrajectoryRecord) -> Result<(), RuntimeError> {
        self.append(&[
            "trajectory",
            &record.parent,
            &record.work_unit,
            &record.dependencies.join(","),
            &record.submitted_at_ms.to_string(),
            record.terminal_state.as_deref().unwrap_or(""),
        ])
    }

    pub fn terminal(&self, work_unit: &str, state: &str) -> Result<(), RuntimeError> {
        self.append(&["terminal", work_unit, state, &now_ms().to_string()])
    }

    pub fn record_effect_once(&self, effect_id: &str) -> Result<bool, RuntimeError> {
        if self.records()?.iter().any(|record| {
            record.first().map(String::as_str) == Some("effect")
                && record.get(1).map(String::as_str) == Some(effect_id)
        }) {
            return Ok(false);
        }
        self.append(&["effect", effect_id, &now_ms().to_string()])?;
        Ok(true)
    }

    pub fn ledger(&self, entry: &RunLedgerEntry) -> Result<(), RuntimeError> {
        self.append(&[
            "ledger",
            &entry.work_unit,
            &entry.call,
            &entry.state,
            &entry.active_time_ms.to_string(),
            &entry.cost_micros.to_string(),
            &entry.observed_at_ms.to_string(),
        ])
    }

    pub fn pause(
        &self,
        decision_id: &str,
        work_unit: &str,
        prompt_digest: &str,
    ) -> Result<PauseDecisionReceipt, RuntimeError> {
        if decision_id.trim().is_empty()
            || work_unit.trim().is_empty()
            || prompt_digest.trim().is_empty()
        {
            return Err(RuntimeError::Scheduler(
                "pause decision fields must be named".into(),
            ));
        }
        self.append(&["pause", decision_id, work_unit, prompt_digest])?;
        Ok(PauseDecisionReceipt {
            decision_id: decision_id.into(),
            work_unit: work_unit.into(),
            prompt_digest: prompt_digest.into(),
            response_digest: None,
        })
    }

    pub fn bind_response(
        &self,
        receipt: &PauseDecisionReceipt,
        response_digest: &str,
    ) -> Result<PauseDecisionReceipt, RuntimeError> {
        if response_digest.trim().is_empty() {
            return Err(RuntimeError::Scheduler(
                "operator response digest is required".into(),
            ));
        }
        self.append(&[
            "resume",
            &receipt.decision_id,
            &receipt.work_unit,
            &receipt.prompt_digest,
            response_digest,
        ])?;
        let mut bound = receipt.clone();
        bound.response_digest = Some(response_digest.into());
        Ok(bound)
    }

    pub fn enqueue_observation(&self, event_id: &str, payload: &str) -> Result<bool, RuntimeError> {
        if self.records()?.iter().any(|record| {
            matches!(
                record.first().map(String::as_str),
                Some("observation") | Some("observation-acked")
            ) && record.get(1).map(String::as_str) == Some(event_id)
        }) {
            return Ok(false);
        }
        self.append(&["observation", event_id, payload, "0"])?;
        Ok(true)
    }

    pub fn observation_batch(
        &self,
        max_count: usize,
        max_bytes: usize,
    ) -> Result<Vec<(String, String)>, RuntimeError> {
        let mut terminal = BTreeSet::new();
        let records = self.records()?;
        for record in &records {
            if matches!(
                record.first().map(String::as_str),
                Some("observation-acked") | Some("dead-letter")
            ) {
                if let Some(id) = record.get(1) {
                    terminal.insert(id.clone());
                }
            } else if record.first().map(String::as_str) == Some("observation-redrive") {
                if let Some(id) = record.get(1) {
                    terminal.remove(id);
                }
            }
        }
        let mut bytes = 0usize;
        let mut batch = Vec::new();
        let mut seen = BTreeSet::new();
        for record in records {
            if record.first().map(String::as_str) != Some("observation") {
                continue;
            }
            let Some(id) = record.get(1) else { continue };
            let Some(payload) = record.get(2) else {
                continue;
            };
            if terminal.contains(id) || !seen.insert(id.clone()) || batch.len() >= max_count {
                continue;
            }
            if bytes.saturating_add(payload.len()) > max_bytes {
                continue;
            }
            bytes = bytes.saturating_add(payload.len());
            batch.push((id.clone(), payload.clone()));
        }
        Ok(batch)
    }

    pub fn acknowledge_observation(&self, event_id: &str) -> Result<(), RuntimeError> {
        self.append(&["observation-acked", event_id, &now_ms().to_string()])
    }

    pub fn dead_letter_observation(
        &self,
        event_id: &str,
        reason: &str,
    ) -> Result<(), RuntimeError> {
        self.append(&["dead-letter", event_id, reason, &now_ms().to_string()])
    }

    pub fn retry_observation(
        &self,
        event_id: &str,
        attempt: u32,
        max_attempts: u32,
        reason: &str,
    ) -> Result<bool, RuntimeError> {
        if attempt >= max_attempts {
            self.dead_letter_observation(event_id, reason)?;
            return Ok(false);
        }
        self.append(&[
            "observation-retry",
            event_id,
            &attempt.to_string(),
            reason,
            &now_ms().to_string(),
        ])?;
        Ok(true)
    }

    pub fn redrive_observation(&self, event_id: &str) -> Result<(), RuntimeError> {
        let payload = self
            .records()?
            .into_iter()
            .rev()
            .find(|record| {
                record.first().map(String::as_str) == Some("observation")
                    && record.get(1).map(String::as_str) == Some(event_id)
            })
            .and_then(|record| record.get(2).cloned())
            .ok_or_else(|| RuntimeError::Scheduler("dead-letter observation is unknown".into()))?;
        self.append(&[
            "observation-redrive",
            event_id,
            &payload,
            &now_ms().to_string(),
        ])?;
        self.append(&["observation", event_id, &payload, "redrive"])
    }
}

#[derive(Clone, Debug, Default)]
pub struct SchedulerOutput {
    pub receipts: Vec<InvocationReceipt>,
    pub results: BTreeMap<ProviderId, ProviderResult>,
    pub events: Vec<SchedulerEvent>,
    pub ledger: Vec<RunLedgerEntry>,
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
        let resumed = if self.policy.resume {
            self.policy
                .journal
                .as_ref()
                .map(ExecutionJournal::completed_work)
                .transpose()?
                .unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let ordered = self
            .plan
            .plan()
            .ordered_nodes()
            .map_err(RuntimeError::from)?;
        for node in ordered {
            let Some(provider_id) = node.provider.clone() else {
                continue;
            };
            if resumed.contains(provider_id.as_str()) {
                succeeded.insert(provider_id.clone());
                output.events.push(SchedulerEvent::Resumed(provider_id));
                continue;
            }
            output
                .events
                .push(SchedulerEvent::Ready(provider_id.clone()));
            consume_requirement(
                node.executor_requirement.as_ref(),
                &provider_id,
                self.registry,
                &self.grant,
            )?;
            validate_executor_action(&node)?;
            if let Some(journal) = &self.policy.journal {
                journal.submit_trajectory(&TrajectoryRecord {
                    parent: self.invocation_id.to_string(),
                    work_unit: provider_id.to_string(),
                    dependencies: node.depends_on.iter().map(ToString::to_string).collect(),
                    submitted_at_ms: now_ms(),
                    terminal_state: None,
                })?;
            }
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
            let elapsed = self.policy.node_reservation.active_time_ms;
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
                    let state = if complete { "complete" } else { "partial" };
                    let ledger = RunLedgerEntry {
                        work_unit: provider_id.to_string(),
                        call: "provider.execute".into(),
                        state: state.into(),
                        active_time_ms: elapsed,
                        cost_micros: self.policy.node_reservation.cost_micros,
                        observed_at_ms: now_ms(),
                    };
                    if let Some(journal) = &self.policy.journal {
                        journal.terminal(provider_id.as_str(), state)?;
                        journal.ledger(&ledger)?;
                        journal.enqueue_observation(
                            &format!("{}:{}", self.invocation_id, provider_id),
                            state,
                        )?;
                    }
                    output.ledger.push(ledger);
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
                    let ledger = RunLedgerEntry {
                        work_unit: provider_id.to_string(),
                        call: "provider.execute".into(),
                        state: "failed".into(),
                        active_time_ms: elapsed,
                        cost_micros: self.policy.node_reservation.cost_micros,
                        observed_at_ms: now_ms(),
                    };
                    if let Some(journal) = &self.policy.journal {
                        journal.terminal(provider_id.as_str(), "failed")?;
                        journal.ledger(&ledger)?;
                    }
                    output.ledger.push(ledger);
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

fn consume_requirement(
    requirement: Option<&ExecutionRequirementV1>,
    provider_id: &ProviderId,
    registry: &ProviderRegistry,
    grant: &legion_contracts::InvocationGrant,
) -> Result<(), RuntimeError> {
    let requirement = requirement.ok_or_else(|| {
        RuntimeError::Scheduler(format!(
            "provider {provider_id} has no compiled execution requirement"
        ))
    })?;
    requirement.validate().map_err(RuntimeError::from)?;
    let definition = registry.definition(provider_id).ok_or_else(|| {
        RuntimeError::Scheduler(format!("provider {provider_id} missing definition"))
    })?;
    for capability in &requirement.capabilities {
        if capability.starts_with("provider:") {
            continue;
        }
        if !definition.capabilities.contains(capability) {
            return Err(RuntimeError::Scheduler(format!(
                "provider {provider_id} requirement exceeds provider capabilities: {capability}"
            )));
        }
        if !grant.capabilities.is_empty() && !grant.capabilities.contains(capability) {
            return Err(RuntimeError::Scheduler(format!(
                "provider {provider_id} requirement exceeds invocation grant: {capability}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorActionEnvelope {
    pub action_id: String,
    pub operation: String,
    pub effect: String,
    pub payload_digest: String,
    pub corrected: bool,
}

fn validate_executor_action(node: &PlanNode) -> Result<ExecutorActionEnvelope, RuntimeError> {
    let requirement = node.executor_requirement.as_ref().ok_or_else(|| {
        RuntimeError::Scheduler(format!("work unit {} has no executor requirement", node.id))
    })?;
    let value = |key: &str| {
        node.configuration
            .get(key)
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    };
    normalize_executor_action(
        ExecutorActionEnvelope {
            action_id: value("actionId").unwrap_or_else(|| node.id.to_string()),
            operation: value("operation")
                .unwrap_or_else(|| requirement.operations.first().cloned().unwrap_or_default()),
            effect: value("effect")
                .unwrap_or_else(|| requirement.effects.first().cloned().unwrap_or_default()),
            payload_digest: value("payloadDigest").unwrap_or_else(|| "none".into()),
            corrected: false,
        },
        &node.id,
    )
}

fn normalize_executor_action(
    mut envelope: ExecutorActionEnvelope,
    node_id: &NodeId,
) -> Result<ExecutorActionEnvelope, RuntimeError> {
    let normalized = (
        envelope.action_id.trim().to_owned(),
        envelope.operation.trim().to_owned(),
        envelope.effect.trim().to_owned(),
        envelope.payload_digest.trim().to_owned(),
    );
    if normalized.0 != envelope.action_id
        || normalized.1 != envelope.operation
        || normalized.2 != envelope.effect
        || normalized.3 != envelope.payload_digest
    {
        envelope.action_id = normalized.0;
        envelope.operation = normalized.1;
        envelope.effect = normalized.2;
        envelope.payload_digest = normalized.3;
        envelope.corrected = true;
    }
    if envelope.action_id.is_empty()
        || envelope.operation.is_empty()
        || envelope.effect.is_empty()
        || envelope.payload_digest.is_empty()
    {
        return Err(RuntimeError::Scheduler(format!(
            "work unit {} produced malformed executor action after one correction",
            node_id
        )));
    }
    Ok(envelope)
}

/// Replace only unfinished graph nodes. Completed nodes & their output-bearing
/// identities remain intact, while normal plan validation rejects dependency
/// drift or cycles in replacement graph.
pub fn replan_remaining(
    current: &Plan,
    completed: &BTreeSet<NodeId>,
    replacement: Vec<PlanNode>,
) -> Result<Plan, RuntimeError> {
    let mut nodes: Vec<PlanNode> = current
        .nodes
        .iter()
        .filter(|node| completed.contains(&node.id))
        .cloned()
        .collect();
    if replacement.iter().any(|node| completed.contains(&node.id)) {
        return Err(RuntimeError::Plan(
            "replacement graph may not rewrite completed work".into(),
        ));
    }
    nodes.extend(replacement);
    let providers = nodes
        .iter()
        .filter_map(|node| node.provider.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut plan =
        Plan::new(1, current.id.clone(), nodes, providers).map_err(RuntimeError::from)?;
    plan.resources = current.resources.clone();
    plan.validate().map_err(RuntimeError::from)?;
    Ok(plan)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn escape_field(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\t', "%09")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn unescape_field(value: &str) -> String {
    value
        .replace("%0A", "\n")
        .replace("%0D", "\r")
        .replace("%09", "\t")
        .replace("%25", "%")
}

#[cfg(test)]
mod tests {
    use super::*;
    use legion_contracts::{
        ExecutionCompletionCheck, ExecutionEscalationPolicy, ExecutionSemanticRequirement,
        ExecutorBindingOutcome, PlanId, PlanNodeKind, ProviderResult,
    };
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

    fn test_journal(name: &str) -> ExecutionJournal {
        ExecutionJournal::new(std::env::temp_dir().join(format!(
            "legion-{name}-{}-{}.journal",
            std::process::id(),
            now_ms()
        )))
    }

    fn test_requirement() -> ExecutionRequirementV1 {
        ExecutionRequirementV1 {
            semantic_requirement: ExecutionSemanticRequirement::Required,
            capabilities: vec!["test".into()],
            operations: vec!["execute".into()],
            effects: vec!["PROVIDER_EXECUTION".into()],
            authority_ceiling: vec!["ambient".into()],
            completion: vec![ExecutionCompletionCheck {
                kind: "provider-result".into(),
                id: "complete".into(),
            }],
            escalation: ExecutionEscalationPolicy {
                permitted_on: vec![ExecutorBindingOutcome::Unsupported],
                forbidden_on: vec![ExecutorBindingOutcome::Denied],
            },
        }
    }

    fn test_node(id: &str, dependencies: &[&str]) -> PlanNode {
        PlanNode {
            id: NodeId::new(id).expect("node id"),
            kind: PlanNodeKind::Provider,
            provider: Some(ProviderId::new(id).expect("provider id")),
            depends_on: dependencies
                .iter()
                .map(|value| NodeId::new(*value).expect("dependency id"))
                .collect(),
            configuration: BTreeMap::new(),
            executor_requirement: Some(test_requirement()),
        }
    }

    #[test]
    fn leg_017_durable_checkpoint_resumes_unfinished_work_and_deduplicates_effects() {
        let journal = test_journal("leg-017");
        journal
            .terminal("done", "complete")
            .expect("terminal checkpoint");
        assert!(journal
            .record_effect_once("effect-1")
            .expect("first effect"));
        assert!(!journal
            .record_effect_once("effect-1")
            .expect("deduped effect"));
        let completed = journal.completed_work().expect("completed work");
        assert!(completed.contains("done"));
        let unfinished = journal
            .unfinished_work(vec!["done".into(), "unfinished".into()])
            .expect("unfinished work");
        assert_eq!(unfinished, BTreeSet::from(["unfinished".into()]));
    }

    #[test]
    fn leg_018_pause_receipt_binds_response_to_exact_work() {
        let journal = test_journal("leg-018");
        let paused = journal
            .pause("approve-write", "work-7", "sha256:prompt")
            .expect("pause");
        let resumed = journal
            .bind_response(&paused, "sha256:response")
            .expect("resume");
        assert_eq!(resumed.work_unit, "work-7");
        assert_eq!(resumed.response_digest.as_deref(), Some("sha256:response"));
    }

    #[test]
    fn leg_019_run_ledger_records_steps_calls_spend_and_time() {
        let journal = test_journal("leg-019");
        let entry = RunLedgerEntry {
            work_unit: "work-1".into(),
            call: "provider.execute".into(),
            state: "complete".into(),
            active_time_ms: 12,
            cost_micros: 34,
            observed_at_ms: now_ms(),
        };
        journal.ledger(&entry).expect("ledger");
        let records = journal.records().expect("records");
        assert!(records.iter().any(
            |record| record.first().map(String::as_str) == Some("ledger")
                && record.get(4).map(String::as_str) == Some("12")
                && record.get(5).map(String::as_str) == Some("34")
        ));
    }

    #[test]
    fn leg_020_replan_replaces_only_remaining_dag() {
        let current = Plan::new(
            1,
            PlanId::new("replan").expect("plan id"),
            vec![test_node("done", &[]), test_node("old", &["done"])],
            vec![
                ProviderId::new("done").unwrap(),
                ProviderId::new("old").unwrap(),
            ],
        )
        .expect("current plan");
        let completed = BTreeSet::from([NodeId::new("done").unwrap()]);
        let replaced = replan_remaining(&current, &completed, vec![test_node("new", &["done"])])
            .expect("replacement plan");
        assert!(replaced.nodes.iter().any(|node| node.id.as_str() == "done"));
        assert!(replaced.nodes.iter().any(|node| node.id.as_str() == "new"));
        assert!(!replaced.nodes.iter().any(|node| node.id.as_str() == "old"));
    }

    #[test]
    fn leg_021_executor_action_gets_one_bounded_normalization() {
        let envelope = normalize_executor_action(
            ExecutorActionEnvelope {
                action_id: " action ".into(),
                operation: " execute ".into(),
                effect: " PROVIDER_EXECUTION ".into(),
                payload_digest: " none ".into(),
                corrected: false,
            },
            &NodeId::new("action").unwrap(),
        )
        .expect("normalized action");
        assert!(envelope.corrected);
        assert_eq!(envelope.operation, "execute");
    }

    #[test]
    fn leg_022_trajectory_persists_parent_dependencies_submission_and_terminal_state() {
        let journal = test_journal("leg-022");
        journal
            .submit_trajectory(&TrajectoryRecord {
                parent: "run-1".into(),
                work_unit: "work-2".into(),
                dependencies: vec!["work-1".into()],
                submitted_at_ms: now_ms(),
                terminal_state: None,
            })
            .expect("trajectory");
        journal.terminal("work-2", "complete").expect("terminal");
        let records = journal.records().expect("records");
        assert!(records
            .iter()
            .any(
                |record| record.first().map(String::as_str) == Some("trajectory")
                    && record.get(1).map(String::as_str) == Some("run-1")
                    && record.get(3).map(String::as_str) == Some("work-1")
            ));
        assert!(journal
            .completed_work()
            .expect("completed")
            .contains("work-2"));
    }

    #[test]
    fn leg_026_outbox_batches_dead_letters_redrives_and_deduplicates() {
        let journal = test_journal("leg-026");
        assert!(journal
            .enqueue_observation("event-1", "payload")
            .expect("enqueue"));
        assert!(!journal
            .enqueue_observation("event-1", "payload")
            .expect("dedupe"));
        assert_eq!(journal.observation_batch(1, 64).expect("batch").len(), 1);
        assert!(journal
            .retry_observation("event-1", 1, 2, "temporary")
            .expect("retry"));
        journal
            .dead_letter_observation("event-1", "delivery failed")
            .expect("dead letter");
        assert!(journal
            .observation_batch(1, 64)
            .expect("terminal batch")
            .is_empty());
        journal.redrive_observation("event-1").expect("redrive");
        assert_eq!(
            journal
                .observation_batch(1, 64)
                .expect("redriven batch")
                .len(),
            1
        );
    }
}
