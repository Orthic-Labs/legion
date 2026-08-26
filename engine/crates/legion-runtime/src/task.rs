use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use legion_contracts::task::RequestEnvelope;
use legion_contracts::{InvocationGrant, TaskSpec};
use legion_provider_sdk::{EffectInterface, ExternalProjectTool, SourceInterface};
use tokio_util::sync::CancellationToken;

use crate::error::RuntimeError;

#[derive(Clone)]
pub struct ContextRequest {
    pub envelope: RequestEnvelope,
    pub repository: Arc<str>,
    pub generation: u64,
    pub deadline: Instant,
    pub cancellation: CancellationToken,
    pub sources: Arc<dyn SourceInterface>,
    pub effects: Arc<dyn EffectInterface>,
    /// Optional effects-owned project execution boundary supplied by application composition.
    pub external_project_tool: Option<Arc<dyn ExternalProjectTool>>,
}

impl ContextRequest {
    pub fn new(
        envelope: RequestEnvelope,
        repository: impl Into<Arc<str>>,
        generation: u64,
        deadline: Instant,
        cancellation: CancellationToken,
        sources: Arc<dyn SourceInterface>,
        effects: Arc<dyn EffectInterface>,
    ) -> Result<Self, RuntimeError> {
        envelope
            .validate()
            .map_err(|error| RuntimeError::InvalidTask(error.to_string()))?;
        let repository: Arc<str> = repository.into();
        if repository.trim().is_empty() {
            return Err(RuntimeError::InvalidTask(
                "repository must be non-empty".into(),
            ));
        }
        Ok(Self {
            envelope,
            repository,
            generation,
            deadline,
            cancellation,
            sources,
            effects,
            external_project_tool: None,
        })
    }

    /// Attach the effects-owned project tool without changing the frozen constructor shape.
    pub fn with_external_project_tool(mut self, tool: Arc<dyn ExternalProjectTool>) -> Self {
        self.external_project_tool = Some(tool);
        self
    }

    pub fn external_project_tool(&self) -> Option<&Arc<dyn ExternalProjectTool>> {
        self.external_project_tool.as_ref()
    }

    pub fn remaining(&self) -> Duration {
        self.deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default()
    }
    pub fn ensure_available(&self) -> Result<(), RuntimeError> {
        // Admission is intentionally non-consuming. Scheduler owns selected-provider
        // cancellation/deadline truth so terminal receipts are emitted for both states.
        Ok(())
    }
}

pub fn validate_task(task: &TaskSpec, grant: &InvocationGrant) -> Result<(), RuntimeError> {
    task.validate()
        .map_err(|error| RuntimeError::InvalidTask(error.to_string()))?;
    if task.assigned_authority != grant.agent_id {
        return Err(RuntimeError::InvalidTask(
            "assigned authority does not match grant".into(),
        ));
    }
    if task.task_id != grant.task_id {
        return Err(RuntimeError::InvalidTask(
            "task identity does not match grant".into(),
        ));
    }
    Ok(())
}
