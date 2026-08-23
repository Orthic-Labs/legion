use crate::{
    artifact::ArtifactSink,
    environment::allowlisted_environment,
    executable::{ExecutableIdentity, VersionProbeEvidence},
    platform::{PlatformProcess, ProcessLaunch},
    receipt::{ExecutionReceipt, ExecutionState, ParserState, SandboxEvidence},
    request::ExternalToolRequest,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_digest: String,
    pub reason: Option<String>,
}

pub trait PolicyAuthorizer: Send + Sync {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision;
}

#[derive(Clone, Debug)]
pub struct StaticPolicy {
    pub decision: PolicyDecision,
}
impl PolicyAuthorizer for StaticPolicy {
    fn authorize(&self, _: &ExternalToolRequest) -> PolicyDecision {
        self.decision.clone()
    }
}

pub struct EffectExecutor<P, A, G> {
    platform: P,
    artifacts: A,
    policy: G,
}

impl<P, A, G> EffectExecutor<P, A, G>
where
    P: PlatformProcess,
    A: ArtifactSink,
    G: PolicyAuthorizer,
{
    pub fn new(platform: P, artifacts: A, policy: G) -> Self {
        Self {
            platform,
            artifacts,
            policy,
        }
    }

    pub async fn execute(&self, request: &ExternalToolRequest) -> ExecutionReceipt {
        self.execute_with_cancellation(request, tokio_util::sync::CancellationToken::new())
            .await
    }

    pub async fn execute_with_cancellation(
        &self,
        request: &ExternalToolRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> ExecutionReceipt {
        if let Err(error) = request.validate() {
            return ExecutionReceipt::failure(request, error.state(), error.to_string());
        }
        let decision = self.policy.authorize(request);
        if !decision.allowed {
            return ExecutionReceipt::failure(
                request,
                ExecutionState::UnauthorizedEffect,
                decision
                    .reason
                    .unwrap_or_else(|| "policy denied effect".into()),
            );
        }
        let cwd = match std::fs::canonicalize(&request.cwd) {
            Ok(path) if path.is_dir() => path,
            Ok(_) => {
                return ExecutionReceipt::failure(
                    request,
                    ExecutionState::Internal,
                    "cwd is not a directory",
                )
            }
            Err(error) => {
                return ExecutionReceipt::failure(
                    request,
                    ExecutionState::Internal,
                    error.to_string(),
                )
            }
        };
        let identity = match ExecutableIdentity::resolve(
            &request.executable,
            request.expected_digest.as_deref(),
        ) {
            Ok(value) => value.with_version_probe(VersionProbeEvidence {
                args: request.version_args.clone(),
                output: request.version_output.clone(),
                exit_code: request.version_exit_code,
                qualified: request.version_requirement.is_none()
                    || request.version_output.is_some() && request.version_exit_code == Some(0),
            }),
            Err(error) => {
                return self.failure_with_identity(
                    request,
                    error.state(),
                    error.to_string(),
                    None,
                    cwd.to_string_lossy().into_owned(),
                )
            }
        };
        if request.expected_digest.is_none() {
            return self.failure_with_identity(
                request,
                ExecutionState::UnsealedExecutable,
                "executable digest is required",
                Some(identity),
                cwd.to_string_lossy().into_owned(),
            );
        }
        if !identity.version_qualified(request.version_requirement.as_deref()) {
            return self.failure_with_identity(
                request,
                ExecutionState::UnsealedExecutable,
                "executable version is not qualified",
                Some(identity),
                cwd.to_string_lossy().into_owned(),
            );
        }
        if request.requires_network_sandbox
            && request
                .sandbox
                .as_ref()
                .map(|receipt| receipt.network)
                .unwrap_or(false)
                == false
        {
            return self.failure_with_identity(
                request,
                ExecutionState::SandboxMissing,
                "network sandbox receipt is required",
                Some(identity),
                cwd.to_string_lossy().into_owned(),
            );
        }
        let environment = allowlisted_environment(
            &request.environment,
            &request.environment_allowlist,
            &request.sensitive_environment_names,
        );
        let stdout_path = format!("{}/stdout", request.request_id);
        let stderr_path = format!("{}/stderr", request.request_id);
        if let Err(error) = self.artifacts.reserve(&[&stdout_path, &stderr_path]) {
            return self.failure_with_identity(
                request,
                ExecutionState::ArtifactFailed,
                error.to_string(),
                Some(identity),
                cwd.to_string_lossy().into_owned(),
            );
        }
        let launch = ProcessLaunch {
            executable: identity
                .canonical_path
                .as_ref()
                .expect("resolved executable")
                .to_string_lossy()
                .into_owned(),
            args: request.args.clone(),
            cwd: cwd.to_string_lossy().into_owned(),
            environment: environment.values,
            stdout_limit: request.stdout_limit,
            stderr_limit: request.stderr_limit,
            timeout_ms: request.timeout_ms,
            termination_grace_ms: 2_000,
            cancellation,
        };
        let output = match self.platform.run(launch).await {
            Ok(value) => value,
            Err(error) => {
                return self.failure_with_identity(
                    request,
                    error.state(),
                    error.to_string(),
                    Some(identity),
                    cwd.to_string_lossy().into_owned(),
                )
            }
        };
        let stdout = match self.artifacts.write(&stdout_path, &output.stdout) {
            Ok(value) => value,
            Err(error) => {
                return self.failure_with_identity(
                    request,
                    ExecutionState::ArtifactFailed,
                    error.to_string(),
                    Some(identity),
                    cwd.to_string_lossy().into_owned(),
                )
            }
        };
        let stderr = match self.artifacts.write(&stderr_path, &output.stderr) {
            Ok(value) => value,
            Err(error) => {
                return self.failure_with_identity(
                    request,
                    ExecutionState::ArtifactFailed,
                    error.to_string(),
                    Some(identity),
                    cwd.to_string_lossy().into_owned(),
                )
            }
        };
        let state = if output.output_limited {
            ExecutionState::OutputLimited
        } else if output.timed_out {
            ExecutionState::Timeout
        } else if output.cancelled {
            ExecutionState::Cancelled
        } else if output.exit_code == Some(0) {
            ExecutionState::Completed
        } else {
            ExecutionState::Failed
        };
        let mut gaps = Vec::new();
        if state != ExecutionState::Completed {
            gaps.push(state.as_str().into());
        }
        if !output.kill_succeeded && (output.timed_out || output.cancelled || output.output_limited)
        {
            gaps.push("kill_failed".into());
        }
        let complete = state == ExecutionState::Completed
            && output.process_tree.reaped
            && stdout.immutable
            && stderr.immutable
            && gaps.is_empty();
        ExecutionReceipt {
            schema_version: 1,
            receipt_id: format!("receipt:{}", request.request_id),
            request_id: request.request_id.clone(),
            provider_id: request.provider_id.clone(),
            plan_id: request.plan_id.clone(),
            policy_id: decision.policy_id,
            task_id: request.task_id.clone(),
            state,
            complete,
            executable: Some(identity),
            command: Some(request.redacted()),
            cwd: Some(cwd.to_string_lossy().into_owned()),
            environment_names: environment.names,
            sandbox: SandboxEvidence {
                required: request.requires_network_sandbox,
                receipt_id: request.sandbox.as_ref().map(|item| item.id.clone()),
                network_enabled: request
                    .sandbox
                    .as_ref()
                    .map(|item| item.network)
                    .unwrap_or(false),
            },
            process_tree: output.process_tree,
            timing: crate::receipt::TimingEvidence {
                started_at_ms: output.started_at_ms,
                completed_at_ms: output.completed_at_ms,
                duration_ms: output.completed_at_ms.saturating_sub(output.started_at_ms),
            },
            exit_code: output.exit_code,
            signal: output.signal,
            stdout: Some(stdout),
            stderr: Some(stderr),
            parser: ParserState {
                attempted: false,
                succeeded: false,
                error: None,
            },
            gaps,
        }
    }

    fn failure_with_identity(
        &self,
        request: &ExternalToolRequest,
        state: ExecutionState,
        gap: impl Into<String>,
        identity: Option<ExecutableIdentity>,
        cwd: String,
    ) -> ExecutionReceipt {
        let mut receipt = ExecutionReceipt::failure(request, state, gap);
        receipt.executable = identity;
        receipt.cwd = Some(cwd);
        receipt
    }
}

impl<P, A, G> EffectExecutor<P, A, G> {
    pub fn platform(&self) -> &P {
        &self.platform
    }
}
