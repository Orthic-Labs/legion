use std::collections::BTreeSet;

use crate::{artifact::ArtifactRecord, executable::ExecutableIdentity, request::RedactedRequest};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExecutionState {
    Blocked,
    Completed,
    Failed,
    MissingExecutable,
    UnsealedExecutable,
    UnauthorizedEffect,
    SandboxMissing,
    SpawnFailed,
    Timeout,
    Cancelled,
    OutputLimited,
    KillFailed,
    ArtifactFailed,
    Internal,
}

impl ExecutionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::MissingExecutable => "missing_executable",
            Self::UnsealedExecutable => "unsealed_executable",
            Self::UnauthorizedEffect => "unauthorized_effect",
            Self::SandboxMissing => "sandbox_missing",
            Self::SpawnFailed => "spawn_failed",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::OutputLimited => "output_limited",
            Self::KillFailed => "kill_failed",
            Self::ArtifactFailed => "artifact_failed",
            Self::Internal => "internal",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessTreeEvidence {
    pub started: bool,
    pub terminated: bool,
    pub hard_killed: bool,
    pub reaped: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxEvidence {
    pub required: bool,
    pub receipt_id: Option<String>,
    pub network_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimingEvidence {
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParserState {
    pub attempted: bool,
    pub succeeded: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub request_id: String,
    pub provider_id: String,
    pub plan_id: String,
    pub policy_id: String,
    pub task_id: Option<String>,
    pub state: ExecutionState,
    pub complete: bool,
    pub executable: Option<ExecutableIdentity>,
    pub command: Option<RedactedRequest>,
    pub cwd: Option<String>,
    pub environment_names: BTreeSet<String>,
    pub sandbox: SandboxEvidence,
    pub process_tree: ProcessTreeEvidence,
    pub timing: TimingEvidence,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Option<ArtifactRecord>,
    pub stderr: Option<ArtifactRecord>,
    pub parser: ParserState,
    pub gaps: Vec<String>,
}

impl ExecutionReceipt {
    pub fn failure(
        request: &crate::request::ExternalToolRequest,
        state: ExecutionState,
        gap: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            receipt_id: format!("receipt:{}", request.request_id),
            request_id: request.request_id.clone(),
            provider_id: request.provider_id.clone(),
            plan_id: request.plan_id.clone(),
            policy_id: request.policy_id.clone(),
            task_id: request.task_id.clone(),
            state,
            complete: false,
            executable: None,
            command: Some(request.redacted()),
            cwd: Some(request.cwd.clone()),
            environment_names: request.environment.keys().cloned().collect(),
            sandbox: SandboxEvidence {
                required: request.requires_network_sandbox,
                receipt_id: request.sandbox.as_ref().map(|item| item.id.clone()),
                network_enabled: request
                    .sandbox
                    .as_ref()
                    .map(|item| item.network)
                    .unwrap_or(false),
            },
            process_tree: ProcessTreeEvidence {
                started: false,
                terminated: false,
                hard_killed: false,
                reaped: false,
                detail: None,
            },
            timing: TimingEvidence {
                started_at_ms: 0,
                completed_at_ms: 0,
                duration_ms: 0,
            },
            exit_code: None,
            signal: None,
            stdout: None,
            stderr: None,
            parser: ParserState {
                attempted: false,
                succeeded: false,
                error: None,
            },
            gaps: vec![gap.into()],
        }
    }
    pub fn is_complete(&self) -> bool {
        self.complete && self.state == ExecutionState::Completed && self.gaps.is_empty()
    }
}
