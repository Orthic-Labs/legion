use thiserror::Error;

/// Stable failure states at Legion's external-effect boundary.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum EffectError {
    #[error("missing_executable: {0}")]
    MissingExecutable(String),
    #[error("unsealed_executable: {0}")]
    UnsealedExecutable(String),
    #[error("unauthorized_effect: {0}")]
    UnauthorizedEffect(String),
    #[error("sandbox_missing: {0}")]
    SandboxMissing(String),
    #[error("spawn_failed: {0}")]
    SpawnFailed(String),
    #[error("timeout")]
    Timeout,
    #[error("cancelled")]
    Cancelled,
    #[error("output_limited: {0}")]
    OutputLimited(String),
    #[error("kill_failed: {0}")]
    KillFailed(String),
    #[error("artifact_failed: {0}")]
    ArtifactFailed(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

impl EffectError {
    pub fn state(&self) -> crate::receipt::ExecutionState {
        use crate::receipt::ExecutionState;
        match self {
            Self::MissingExecutable(_) => ExecutionState::MissingExecutable,
            Self::UnsealedExecutable(_) => ExecutionState::UnsealedExecutable,
            Self::UnauthorizedEffect(_) => ExecutionState::UnauthorizedEffect,
            Self::SandboxMissing(_) => ExecutionState::SandboxMissing,
            Self::SpawnFailed(_) => ExecutionState::SpawnFailed,
            Self::Timeout => ExecutionState::Timeout,
            Self::Cancelled => ExecutionState::Cancelled,
            Self::OutputLimited(_) => ExecutionState::OutputLimited,
            Self::KillFailed(_) => ExecutionState::KillFailed,
            Self::ArtifactFailed(_) => ExecutionState::ArtifactFailed,
            Self::Internal(_) | Self::InvalidRequest(_) => ExecutionState::Internal,
        }
    }
}
