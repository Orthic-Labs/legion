use crate::{
    artifact::ArtifactSink,
    environment::allowlisted_environment,
    executable::{ExecutableIdentity, VersionProbeEvidence},
    platform::{PlatformProcess, ProcessLaunch},
    receipt::{ExecutionReceipt, ExecutionState, ParserState, PolicyEvidence, SandboxEvidence},
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
        let policy = PolicyEvidence {
            id: decision.policy_id.clone(),
            version: decision.policy_version,
            digest: decision.policy_digest.clone(),
            allowed: decision.allowed,
            reason: decision.reason.clone(),
        };
        if !decision.allowed {
            return Self::failure_with_policy(
                request,
                ExecutionState::UnauthorizedEffect,
                decision
                    .reason
                    .unwrap_or_else(|| "policy denied effect".into()),
                None,
                request.cwd.clone(),
                policy,
            );
        }
        let cwd = match std::fs::canonicalize(&request.cwd) {
            Ok(path) if path.is_dir() => path,
            Ok(_) => {
                return Self::failure_with_policy(
                    request,
                    ExecutionState::Internal,
                    "cwd is not a directory",
                    None,
                    request.cwd.clone(),
                    policy,
                )
            }
            Err(error) => {
                return Self::failure_with_policy(
                    request,
                    ExecutionState::Internal,
                    error.to_string(),
                    None,
                    request.cwd.clone(),
                    policy,
                )
            }
        };
        let identity = match ExecutableIdentity::resolve(
            &request.executable,
            request.expected_digest.as_deref(),
        ) {
            Ok(value) => value,
            Err(error) => {
                return Self::failure_with_policy(
                    request,
                    error.state(),
                    error.to_string(),
                    None,
                    cwd.to_string_lossy().into_owned(),
                    policy,
                )
            }
        };
        if request.expected_digest.is_none() {
            return Self::failure_with_policy(
                request,
                ExecutionState::UnsealedExecutable,
                "executable digest is required",
                Some(identity),
                cwd.to_string_lossy().into_owned(),
                policy,
            );
        }
        if request.requires_network_sandbox
            && !request
                .sandbox
                .as_ref()
                .map(|receipt| receipt.network)
                .unwrap_or(false)
        {
            return Self::failure_with_policy(
                request,
                ExecutionState::SandboxMissing,
                "network sandbox receipt is required",
                Some(identity),
                cwd.to_string_lossy().into_owned(),
                policy,
            );
        }
        let environment = allowlisted_environment(
            &request.environment,
            &request.environment_allowlist,
            &request.sensitive_environment_names,
        );
        let identity = if request.skip_version_probe && identity.sealed() {
            // Identity is pinned by a verified digest; the caller opted out of
            // executing the binary for a version. Record the skip truthfully.
            identity.with_version_probe(VersionProbeEvidence {
                args: Vec::new(),
                output: None,
                exit_code: None,
                qualified: false,
                skipped_by_policy: true,
            })
        } else {
            let version_launch = ProcessLaunch {
                executable: identity
                    .canonical_path
                    .as_ref()
                    .expect("resolved executable")
                    .to_string_lossy()
                    .into_owned(),
                args: request.version_args.clone(),
                cwd: cwd.to_string_lossy().into_owned(),
                environment: environment.values.clone(),
                stdout_limit: request.stdout_limit,
                stderr_limit: request.stderr_limit,
                timeout_ms: request.timeout_ms,
                termination_grace_ms: 2_000,
                cancellation: cancellation.clone(),
            };
            let version_output = match self.platform.run(version_launch).await {
                Ok(value) => value,
                Err(error) => {
                    return Self::failure_with_policy(
                        request,
                        error.state(),
                        error.to_string(),
                        Some(identity),
                        cwd.to_string_lossy().into_owned(),
                        policy,
                    )
                }
            };
            let version = VersionProbeEvidence {
                args: request.version_args.clone(),
                output: Some(combined_probe_output(
                    &version_output.stdout,
                    &version_output.stderr,
                )),
                exit_code: version_output.exit_code,
                qualified: version_output.exit_code == Some(0)
                    && !version_output.timed_out
                    && !version_output.cancelled
                    && !version_output.output_limited
                    && version_output.kill_succeeded
                    && version_output.process_tree.started
                    && version_output.process_tree.terminated
                    && version_output.process_tree.reaped,
                skipped_by_policy: false,
            };
            let identity = identity.with_version_probe(version);
            if !identity.version_qualified(request.version_requirement.as_deref()) {
                let state = if !version_output.kill_succeeded
                    || !version_output.process_tree.started
                    || !version_output.process_tree.terminated
                    || !version_output.process_tree.reaped
                {
                    ExecutionState::KillFailed
                } else if version_output.output_limited {
                    ExecutionState::OutputLimited
                } else if version_output.timed_out {
                    ExecutionState::Timeout
                } else if version_output.cancelled {
                    ExecutionState::Cancelled
                } else {
                    ExecutionState::UnsealedExecutable
                };
                return Self::failure_with_policy(
                    request,
                    state,
                    "actual executable version probe is not qualified",
                    Some(identity),
                    cwd.to_string_lossy().into_owned(),
                    policy,
                );
            }
            identity
        };
        let stdout_path = format!("{}/stdout", request.request_id);
        let stderr_path = format!("{}/stderr", request.request_id);
        if let Err(error) = self.artifacts.reserve(&[&stdout_path, &stderr_path]) {
            return Self::failure_with_policy(
                request,
                ExecutionState::ArtifactFailed,
                error.to_string(),
                Some(identity),
                cwd.to_string_lossy().into_owned(),
                policy,
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
                return Self::failure_with_policy(
                    request,
                    error.state(),
                    error.to_string(),
                    Some(identity),
                    cwd.to_string_lossy().into_owned(),
                    policy,
                )
            }
        };
        let process_state = if !output.kill_succeeded
            || !output.process_tree.started
            || !output.process_tree.terminated
            || !output.process_tree.reaped
        {
            ExecutionState::KillFailed
        } else if output.output_limited {
            ExecutionState::OutputLimited
        } else if output.timed_out {
            ExecutionState::Timeout
        } else if output.cancelled {
            ExecutionState::Cancelled
        } else if output
            .exit_code
            .is_some_and(|code| request.accepted_exit_codes.contains(&code))
        {
            ExecutionState::Completed
        } else {
            ExecutionState::Failed
        };
        let mut gaps = Vec::new();
        if process_state != ExecutionState::Completed && process_state != ExecutionState::KillFailed
        {
            gaps.push(process_state.as_str().into());
        }
        if process_state == ExecutionState::KillFailed {
            gaps.push("kill_failed".into());
        }
        let mut artifact_error = None;
        let stdout = match self.artifacts.write(&stdout_path, &output.stdout) {
            Ok(value) => Some(value),
            Err(error) => {
                artifact_error = Some(error.to_string());
                None
            }
        };
        let stderr = if artifact_error.is_none() {
            match self.artifacts.write(&stderr_path, &output.stderr) {
                Ok(value) => Some(value),
                Err(error) => {
                    artifact_error = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };
        if artifact_error.is_none()
            && (stdout.as_ref().is_none_or(|value| !value.immutable)
                || stderr.as_ref().is_none_or(|value| !value.immutable))
        {
            artifact_error = Some("artifact_failed: artifact is not immutable".into());
        }
        if let Some(error) = artifact_error {
            gaps.push(error);
        }
        let state = if process_state == ExecutionState::Completed && !gaps.is_empty() {
            ExecutionState::ArtifactFailed
        } else {
            process_state
        };
        let complete = state == ExecutionState::Completed
            && output.process_tree.reaped
            && output.process_tree.started
            && output.process_tree.terminated
            && stdout.as_ref().is_some_and(|value| value.immutable)
            && stderr.as_ref().is_some_and(|value| value.immutable)
            && gaps.is_empty();
        ExecutionReceipt {
            schema_version: 1,
            receipt_id: format!("receipt:{}", request.request_id),
            request_id: request.request_id.clone(),
            provider_id: request.provider_id.clone(),
            plan_id: request.plan_id.clone(),
            policy_id: decision.policy_id,
            policy: Some(policy),
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
            stdout,
            stderr,
            parser: ParserState {
                attempted: false,
                succeeded: false,
                error: None,
            },
            gaps,
        }
    }

    fn failure_with_policy(
        request: &ExternalToolRequest,
        state: ExecutionState,
        gap: impl Into<String>,
        identity: Option<ExecutableIdentity>,
        cwd: String,
        policy: PolicyEvidence,
    ) -> ExecutionReceipt {
        let mut receipt = ExecutionReceipt::failure(request, state, gap);
        receipt.executable = identity;
        receipt.cwd = Some(cwd);
        receipt.policy_id = policy.id.clone();
        receipt.policy = Some(policy);
        receipt
    }
}

impl<P, A, G> EffectExecutor<P, A, G> {
    pub fn platform(&self) -> &P {
        &self.platform
    }
}

fn combined_probe_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    if stdout.is_empty() {
        return stderr.into_owned();
    }
    if stderr.is_empty() {
        return stdout.into_owned();
    }
    let mut combined = stdout.into_owned();
    if !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(&stderr);
    combined
}

#[cfg(test)]
mod exact_version_gate_tests {
    use super::*;
    use crate::{
        artifact::ArtifactWriter,
        platform::{ProcessFuture, ProcessOutput},
        receipt::ProcessTreeEvidence,
        request::ExternalToolRequest,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct ProbePlatform {
        marker: PathBuf,
        launches: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl PlatformProcess for ProbePlatform {
        fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a> {
            let marker = self.marker.clone();
            let launches = Arc::clone(&self.launches);
            Box::pin(async move {
                launches.lock().unwrap().push(launch.args.clone());
                let is_probe = launch.args.as_slice() == ["--version"];
                if !is_probe {
                    fs::write(marker, b"main command launched").unwrap();
                }
                Ok(ProcessOutput {
                    stdout: if is_probe {
                        b"pnpm 19.1.0\n".to_vec()
                    } else {
                        Vec::new()
                    },
                    stderr: Vec::new(),
                    exit_code: Some(0),
                    signal: None,
                    timed_out: false,
                    cancelled: false,
                    output_limited: false,
                    kill_succeeded: true,
                    process_tree: ProcessTreeEvidence {
                        started: true,
                        terminated: true,
                        hard_killed: false,
                        reaped: true,
                        detail: None,
                    },
                    started_at_ms: 1,
                    completed_at_ms: 2,
                })
            })
        }
    }

    #[test]
    fn exact_pinned_mismatch_is_rejected_before_test_command_launch() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "legion-effects-exact-version-{}-{nonce}",
            std::process::id()
        ));
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        let executable = root.join("pnpm");
        fs::write(&executable, b"sealed fixture executable").unwrap();
        let expected_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"sealed fixture executable"))
        );
        let marker = root.join("main-launched.marker");
        let launches = Arc::new(Mutex::new(Vec::new()));
        let executor = EffectExecutor::new(
            ProbePlatform {
                marker: marker.clone(),
                launches: Arc::clone(&launches),
            },
            ArtifactWriter::new(&artifacts),
            StaticPolicy {
                decision: PolicyDecision {
                    allowed: true,
                    policy_id: "test".into(),
                    policy_version: 1,
                    policy_digest: "sha256:test".into(),
                    reason: None,
                },
            },
        );
        let request = ExternalToolRequest {
            request_id: "request-test".into(),
            provider_id: "legacy.quality.test".into(),
            plan_id: "plan-test".into(),
            policy_id: "test".into(),
            executable: executable.to_string_lossy().into_owned(),
            args: vec!["run".into(), "test".into()],
            cwd: root.to_string_lossy().into_owned(),
            expected_digest: Some(expected_digest),
            version_requirement: Some("exact:9.1.0".into()),
            ..ExternalToolRequest::default()
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let receipt = runtime.block_on(executor.execute(&request));
        assert_eq!(receipt.state, ExecutionState::UnsealedExecutable);
        assert_eq!(
            launches.lock().unwrap().as_slice(),
            &[vec!["--version".to_owned()]]
        );
        assert!(!marker.exists());
        fs::remove_dir_all(root).unwrap();
    }
    fn skip_probe_launches(
        tag: &str,
        configure: impl FnOnce(&mut ExternalToolRequest, String),
    ) -> (ExecutionReceipt, Vec<Vec<String>>) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "legion-effects-skip-probe-{tag}-{}-{nonce}",
            std::process::id()
        ));
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        let executable = root.join("multicall");
        fs::write(&executable, b"sealed multicall executable").unwrap();
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"sealed multicall executable"))
        );
        let launches = Arc::new(Mutex::new(Vec::new()));
        let executor = EffectExecutor::new(
            ProbePlatform {
                marker: root.join("main-launched.marker"),
                launches: Arc::clone(&launches),
            },
            ArtifactWriter::new(&artifacts),
            StaticPolicy {
                decision: PolicyDecision {
                    allowed: true,
                    policy_id: "test".into(),
                    policy_version: 1,
                    policy_digest: "sha256:test".into(),
                    reason: None,
                },
            },
        );
        let mut request = ExternalToolRequest {
            request_id: "request-skip".into(),
            provider_id: "legacy.quality.test".into(),
            plan_id: "plan-test".into(),
            policy_id: "test".into(),
            executable: executable.to_string_lossy().into_owned(),
            args: vec!["request-digest".into()],
            cwd: root.to_string_lossy().into_owned(),
            ..ExternalToolRequest::default()
        };
        configure(&mut request, digest);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let receipt = runtime.block_on(executor.execute(&request));
        let recorded = launches.lock().unwrap().clone();
        fs::remove_dir_all(root).unwrap();
        (receipt, recorded)
    }

    #[test]
    fn skip_version_probe_runs_only_the_main_command_and_records_policy_skip() {
        let (receipt, launches) = skip_probe_launches("pinned", |request, digest| {
            request.expected_digest = Some(digest);
            request.skip_version_probe = true;
        });
        assert_eq!(launches, vec![vec!["request-digest".to_owned()]]);
        let identity = receipt.executable.expect("identity recorded");
        assert!(identity.sealed());
        assert!(identity.version.skipped_by_policy);
        assert!(!identity.version.qualified);
        assert!(identity.version.output.is_none());
    }

    #[test]
    fn default_request_still_probes_before_the_main_command() {
        let (_, launches) = skip_probe_launches("default", |request, digest| {
            request.expected_digest = Some(digest);
        });
        assert_eq!(launches.first(), Some(&vec!["--version".to_owned()]));
    }

    #[test]
    fn skip_version_probe_never_bypasses_digest_verification() {
        let (receipt, launches) = skip_probe_launches("mismatch", |request, _| {
            request.expected_digest = Some(format!("sha256:{}", "0".repeat(64)));
            request.skip_version_probe = true;
        });
        assert!(launches.is_empty());
        assert_ne!(receipt.state, ExecutionState::Completed);
        let (receipt, launches) = skip_probe_launches("undigested", |request, _| {
            request.skip_version_probe = true;
        });
        assert!(launches.is_empty());
        assert_ne!(receipt.state, ExecutionState::Completed);
        let (receipt, launches) = skip_probe_launches("requirement", |request, digest| {
            request.expected_digest = Some(digest);
            request.skip_version_probe = true;
            request.version_requirement = Some("exact:1.0.0".into());
        });
        assert!(launches.is_empty());
        assert_ne!(receipt.state, ExecutionState::Completed);
    }
}
