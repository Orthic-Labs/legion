use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use legion_contracts::task::RequestEnvelope;
use legion_contracts::{EffectRequest, InvocationGrant, Plan, TaskSpec};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::error::ProviderError;

/// Typed, injected read-only source access available to a provider.
pub trait SourceInterface: Send + Sync {
    fn read(&self, source: &str, query: &Value) -> Result<Value, ProviderError>;
}

/// Typed effect boundary available to a provider. Implementations authorize
/// and record effects; this SDK does not expose process or filesystem APIs.
pub trait EffectInterface: Send + Sync {
    fn request(&self, effect: &EffectRequest) -> Result<Value, ProviderError>;
}

#[derive(Clone)]
pub struct ProviderContext {
    plan: Arc<Plan>,
    request: Arc<RequestEnvelope>,
    task: Arc<TaskSpec>,
    repository: Arc<str>,
    generation: u64,
    deadline: Instant,
    cancellation: CancellationToken,
    policy_grant: Arc<InvocationGrant>,
    sources: Arc<dyn SourceInterface>,
    effects: Arc<dyn EffectInterface>,
}

impl ProviderContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan: Plan,
        request: RequestEnvelope,
        task: TaskSpec,
        repository: impl Into<Arc<str>>,
        generation: u64,
        deadline: Instant,
        cancellation: CancellationToken,
        policy_grant: InvocationGrant,
        sources: Arc<dyn SourceInterface>,
        effects: Arc<dyn EffectInterface>,
    ) -> Self {
        Self {
            plan: Arc::new(plan),
            request: Arc::new(request),
            task: Arc::new(task),
            repository: repository.into(),
            generation,
            deadline,
            cancellation,
            policy_grant: Arc::new(policy_grant),
            sources,
            effects,
        }
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn request(&self) -> &RequestEnvelope {
        &self.request
    }
    pub fn task(&self) -> &TaskSpec {
        &self.task
    }
    pub fn repository(&self) -> &str {
        &self.repository
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
    pub fn policy_grant(&self) -> &InvocationGrant {
        &self.policy_grant
    }
    pub fn sources(&self) -> &Arc<dyn SourceInterface> {
        &self.sources
    }
    pub fn effects(&self) -> &Arc<dyn EffectInterface> {
        &self.effects
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn remaining(&self, now: Instant) -> Duration {
        self.deadline
            .checked_duration_since(now)
            .unwrap_or_default()
    }

    pub fn ensure_available(&self, now: Instant) -> Result<(), ProviderError> {
        if self.is_cancelled() {
            return Err(ProviderError::cancelled());
        }
        if now >= self.deadline {
            return Err(ProviderError::timeout());
        }
        Ok(())
    }
}
