use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use legion_contracts::task::RequestEnvelope;
use legion_contracts::{EffectRequest, InvocationGrant, Plan, TaskSpec};
use legion_effects::{
    receipt::{ExecutionReceipt, ExecutionState},
    request::ExternalToolRequest,
};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::{error::ProviderError, external_project_tool::ExternalProjectTool};

const EXTERNAL_TOOL_CLEANUP_GRACE: Duration = Duration::from_millis(2500);

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
    external_project_tool: Option<Arc<dyn ExternalProjectTool>>,
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
            external_project_tool: None,
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
    pub fn with_external_project_tool(mut self, tool: Arc<dyn ExternalProjectTool>) -> Self {
        self.external_project_tool = Some(tool);
        self
    }
    pub fn external_project_tool(&self) -> Option<&Arc<dyn ExternalProjectTool>> {
        self.external_project_tool.as_ref()
    }

    /// Executes only through the injected effects-owned boundary and never turns absence into
    /// provider success.
    pub async fn execute_external_project_tool(
        &self,
        request: ExternalToolRequest,
    ) -> ExecutionReceipt {
        let Some(tool) = self.external_project_tool.as_ref() else {
            return ExecutionReceipt::failure(
                &request,
                ExecutionState::Blocked,
                "external_project_tool_unavailable",
            );
        };
        if self.is_cancelled() {
            return ExecutionReceipt::failure(
                &request,
                ExecutionState::Cancelled,
                "provider cancelled",
            );
        }
        let remaining = self.remaining(Instant::now());
        if remaining.is_zero() {
            return ExecutionReceipt::failure(
                &request,
                ExecutionState::Timeout,
                "provider deadline exceeded",
            );
        }
        let cancellation = self.cancellation.child_token();
        let execution = tool.execute(request.clone(), cancellation.clone());
        tokio::pin!(execution);
        let deadline = tokio::time::sleep(remaining);
        tokio::pin!(deadline);
        tokio::select! {
            // Cancellation wins deterministic ties with the context deadline; callers never
            // receive a successful provider result after cancellation became observable.
            biased;
            _ = self.cancellation.cancelled() => {
                cancellation.cancel();
                match tokio::time::timeout(EXTERNAL_TOOL_CLEANUP_GRACE, &mut execution).await {
                    Ok(receipt) => Self::incomplete_context_receipt(
                        receipt,
                        ExecutionState::Cancelled,
                        "provider cancelled",
                    ),
                    Err(_) => Self::unconfirmed_cleanup_receipt(
                        &request,
                        "provider cancelled",
                    ),
                }
            }
            _ = &mut deadline => {
                cancellation.cancel();
                match tokio::time::timeout(EXTERNAL_TOOL_CLEANUP_GRACE, &mut execution).await {
                    Ok(receipt) => Self::incomplete_context_receipt(
                        receipt,
                        ExecutionState::Timeout,
                        "provider deadline exceeded",
                    ),
                    Err(_) => Self::unconfirmed_cleanup_receipt(
                        &request,
                        "provider deadline exceeded",
                    ),
                }
            }
            receipt = &mut execution => receipt,
        }
    }

    fn incomplete_context_receipt(
        mut receipt: ExecutionReceipt,
        state: ExecutionState,
        gap: &str,
    ) -> ExecutionReceipt {
        if receipt.state != ExecutionState::KillFailed {
            receipt.state = state;
        }
        receipt.complete = false;
        if !receipt.gaps.iter().any(|existing| existing == gap) {
            receipt.gaps.push(gap.into());
        }
        receipt
    }

    fn unconfirmed_cleanup_receipt(request: &ExternalToolRequest, gap: &str) -> ExecutionReceipt {
        let mut receipt = ExecutionReceipt::failure(request, ExecutionState::KillFailed, gap);
        receipt.gaps.push("cleanup_unconfirmed".into());
        receipt.gaps.push("kill_failed".into());
        receipt
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
