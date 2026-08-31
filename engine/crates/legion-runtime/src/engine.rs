use std::{
    path::Path,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use legion_contracts::{
    AgentId, EffectRequest, InvocationGrant, InvocationId, ProviderResult, TaskSpec,
};
use legion_provider_sdk::ProviderRegistry;

use crate::{
    error::RuntimeError,
    plan::{compile_plan, FrozenPlan},
    route::{select_route, RouteCandidate, SelectedRoute},
    scheduler::{ExecutionJournal, Scheduler, SchedulerOutput, SchedulerPolicy},
    task::{validate_task, ContextRequest},
    AgentProfile,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateEvidence {
    pub provider: legion_contracts::ProviderId,
    pub result: ProviderResult,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Adjudication {
    pub candidates: Vec<CandidateEvidence>,
    pub complete: bool,
    pub gaps: Vec<String>,
}

/// Adjudication is deliberately observation-only: it sorts and summarizes results,
/// but never edits provider facts.
pub fn adjudicate(output: &SchedulerOutput) -> Adjudication {
    let mut candidates: Vec<_> = output
        .results
        .iter()
        .map(|(provider, result)| CandidateEvidence {
            provider: provider.clone(),
            result: result.clone(),
        })
        .collect();
    candidates.sort_by(|left, right| left.provider.cmp(&right.provider));
    let mut gaps = Vec::new();
    for receipt in &output.receipts {
        gaps.extend(receipt.gaps.iter().cloned());
    }
    gaps.sort();
    gaps.dedup();
    Adjudication {
        complete: !candidates.is_empty()
            && gaps.is_empty()
            && candidates.iter().all(|item| item.result.complete),
        candidates,
        gaps,
    }
}

pub trait EffectPolicy: Send + Sync {
    fn authorize(&self, request: &EffectRequest) -> Result<(), RuntimeError>;
}

#[derive(Clone)]
pub struct Invocation {
    pub invocation_id: InvocationId,
    pub task: TaskSpec,
    pub grant: InvocationGrant,
    pub context: ContextRequest,
    pub routes: Vec<RouteCandidate>,
}

#[derive(Clone, Debug)]
pub struct EngineOutcome {
    pub route: SelectedRoute,
    pub plan: FrozenPlan,
    pub scheduled: SchedulerOutput,
    pub adjudication: Adjudication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeState {
    Running = 0,
    Quiescing = 1,
    Stopped = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainReport {
    pub drained: usize,
    pub forced: usize,
    pub state: RuntimeState,
}

struct RuntimeAdmissionInner {
    state: AtomicU8,
    active: AtomicUsize,
    tokens: Mutex<Vec<tokio_util::sync::CancellationToken>>,
}

#[derive(Clone)]
pub struct RuntimeAdmission {
    inner: Arc<RuntimeAdmissionInner>,
}

struct ActiveOperation {
    admission: RuntimeAdmission,
}

impl RuntimeAdmission {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RuntimeAdmissionInner {
                state: AtomicU8::new(RuntimeState::Running as u8),
                active: AtomicUsize::new(0),
                tokens: Mutex::new(Vec::new()),
            }),
        }
    }

    pub fn state(&self) -> RuntimeState {
        match self.inner.state.load(Ordering::SeqCst) {
            0 => RuntimeState::Running,
            1 => RuntimeState::Quiescing,
            _ => RuntimeState::Stopped,
        }
    }

    fn admit(
        &self,
        token: tokio_util::sync::CancellationToken,
    ) -> Result<ActiveOperation, RuntimeError> {
        if self.state() != RuntimeState::Running {
            return Err(RuntimeError::Scheduler(
                "runtime admission is closed while quiescing or stopped".into(),
            ));
        }
        self.inner.active.fetch_add(1, Ordering::SeqCst);
        if self.state() != RuntimeState::Running {
            self.inner.active.fetch_sub(1, Ordering::SeqCst);
            return Err(RuntimeError::Scheduler(
                "runtime admission closed during submission".into(),
            ));
        }
        self.inner
            .tokens
            .lock()
            .expect("runtime token registry")
            .push(token);
        Ok(ActiveOperation {
            admission: self.clone(),
        })
    }

    pub async fn quiesce(&self, deadline: Instant) -> DrainReport {
        let before = self.inner.active.load(Ordering::SeqCst);
        self.inner
            .state
            .store(RuntimeState::Quiescing as u8, Ordering::SeqCst);
        while self.inner.active.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let forced = self.inner.active.load(Ordering::SeqCst);
        if forced > 0 {
            for token in self
                .inner
                .tokens
                .lock()
                .expect("runtime token registry")
                .iter()
            {
                token.cancel();
            }
        }
        self.inner
            .state
            .store(RuntimeState::Stopped as u8, Ordering::SeqCst);
        DrainReport {
            drained: before.saturating_sub(forced),
            forced,
            state: RuntimeState::Stopped,
        }
    }
}

impl Default for RuntimeAdmission {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ActiveOperation {
    fn drop(&mut self) {
        self.admission.inner.active.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct LegionEngine {
    profile: AgentProfile,
    registry: Arc<ProviderRegistry>,
    policy: Option<Arc<dyn EffectPolicy>>,
    admission: RuntimeAdmission,
}

impl LegionEngine {
    pub fn new(profile: AgentProfile, registry: Arc<ProviderRegistry>) -> Self {
        Self {
            profile,
            registry,
            policy: None,
            admission: RuntimeAdmission::new(),
        }
    }
    pub fn with_policy(mut self, policy: Arc<dyn EffectPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }
    pub fn profile(&self) -> &AgentProfile {
        &self.profile
    }
    pub fn registry(&self) -> &ProviderRegistry {
        &self.registry
    }

    pub async fn execute(&self, invocation: Invocation) -> Result<EngineOutcome, RuntimeError> {
        let _active = self
            .admission
            .admit(invocation.context.cancellation.clone())?;
        let grant = self.profile.authorize(invocation.grant)?;
        validate_task(&invocation.task, &grant)?;
        invocation.context.ensure_available()?;
        let route = select_route(&invocation.routes, self.profile.definition(), &grant)?;
        let plan = compile_plan(&invocation.task, &self.registry, &route)?;
        let resume = grant
            .context
            .get("resume")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let mut policy = SchedulerPolicy::new(
            invocation.context.deadline,
            invocation.context.cancellation.clone(),
            invocation.context.generation,
            invocation.context.repository.to_string(),
        );
        let repository = Path::new(&*invocation.context.repository);
        if repository.is_dir() {
            let safe_id = invocation
                .invocation_id
                .to_string()
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() || character == '-' {
                        character
                    } else {
                        '_'
                    }
                })
                .collect::<String>();
            policy = policy.with_journal(
                ExecutionJournal::new(
                    repository
                        .join(".legion/runtime")
                        .join(format!("{safe_id}.journal")),
                ),
                resume,
            );
        }
        let scheduled = Scheduler::new(
            &self.registry,
            &plan,
            &invocation.context,
            &invocation.task,
            grant,
            invocation.invocation_id,
            policy,
        )
        .run()
        .await?;
        for receipt in &scheduled.receipts {
            receipt.validate().map_err(RuntimeError::from)?;
        }
        let adjudication = adjudicate(&scheduled);
        Ok(EngineOutcome {
            route,
            plan,
            scheduled,
            adjudication,
        })
    }

    pub async fn run(&self, invocation: Invocation) -> Result<EngineOutcome, RuntimeError> {
        self.execute(invocation).await
    }

    pub fn authorize_effect(&self, request: &EffectRequest) -> Result<(), RuntimeError> {
        self.policy
            .as_ref()
            .ok_or_else(|| RuntimeError::Policy("no injected effect policy".into()))?
            .authorize(request)
    }

    pub fn can_escalate(
        &self,
        target: &AgentId,
        grant: &crate::escalation::EscalationGrant,
    ) -> Result<(), RuntimeError> {
        crate::escalation::validate_target(self.profile.definition(), target, grant)
    }

    pub fn policy(&self) -> Option<&Arc<dyn EffectPolicy>> {
        self.policy.as_ref()
    }

    pub fn runtime_state(&self) -> RuntimeState {
        self.admission.state()
    }

    pub async fn quiesce(&self, deadline: Instant) -> DrainReport {
        self.admission.quiesce(deadline).await
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[tokio::test]
    async fn leg_025_quiescing_rejects_admission_drains_and_reports_forced_count() {
        let admission = RuntimeAdmission::new();
        let token = tokio_util::sync::CancellationToken::new();
        let operation = admission.admit(token.clone()).expect("running admission");
        let report = admission.quiesce(Instant::now()).await;
        assert_eq!(report.state, RuntimeState::Stopped);
        assert_eq!(report.forced, 1);
        assert!(token.is_cancelled());
        assert!(admission
            .admit(tokio_util::sync::CancellationToken::new())
            .is_err());
        drop(operation);
    }
}
