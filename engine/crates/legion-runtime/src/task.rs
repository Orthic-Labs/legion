use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use legion_contracts::task::RequestEnvelope;
use legion_contracts::{InvocationGrant, TaskSpec};
use legion_provider_sdk::{EffectInterface, SourceInterface};
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
        })
    }

    pub fn remaining(&self) -> Duration {
        self.deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default()
    }
    pub fn ensure_available(&self) -> Result<(), RuntimeError> {
        if self.cancellation.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        if self.remaining().is_zero() {
            return Err(RuntimeError::DeadlineExceeded);
        }
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
