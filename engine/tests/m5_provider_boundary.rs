//! Deterministic M5 adversarial corpus for the effects-owned provider seam.

use async_trait::async_trait;
use legion_contracts::{
    agent::BudgetCeiling, task::RequestEnvelope, AgentId, EffectRequest, InvocationGrant, Latitude,
    Plan, PlanId, RequestId, TaskId, TaskSpec, TaskStatus,
};
use legion_effects::{
    artifact::{ArtifactRecord, ArtifactSink},
    error::EffectError,
    executor::{EffectExecutor, PolicyDecision, StaticPolicy},
    platform::{PlatformProcess, ProcessFuture, ProcessLaunch, ProcessOutput},
    receipt::{ExecutionReceipt, ExecutionState, PolicyEvidence, ProcessTreeEvidence},
    request::ExternalToolRequest,
    ExecutableIdentity,
};
use legion_provider_sdk::{
    EffectInterface, ExternalProjectTool, ProviderContext, ProviderError, SourceInterface,
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct ScriptedPlatform {
    outputs: Arc<Mutex<VecDeque<Result<ProcessOutput, EffectError>>>>,
    launches: Arc<Mutex<Vec<ProcessLaunch>>>,
}

impl ScriptedPlatform {
    fn new(outputs: impl IntoIterator<Item = Result<ProcessOutput, EffectError>>) -> Self {
        Self {
            outputs: Arc::new(Mutex::new(outputs.into_iter().collect())),
            launches: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn launches(&self) -> Vec<ProcessLaunch> {
        self.launches.lock().expect("launch mutex poisoned").clone()
    }
}

impl PlatformProcess for ScriptedPlatform {
    fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a> {
        self.launches
            .lock()
            .expect("launch mutex poisoned")
            .push(launch);
        let output = self
            .outputs
            .lock()
            .expect("output mutex poisoned")
            .pop_front()
            .unwrap_or_else(|| Err(EffectError::Internal("unexpected process launch".into())));
        Box::pin(async move { output })
    }
}

#[derive(Clone, Copy, Default)]
struct MemoryArtifacts {
    fail_write: bool,
    fail_stderr: bool,
}

impl ArtifactSink for MemoryArtifacts {
    fn write(&self, path: &str, bytes: &[u8]) -> Result<ArtifactRecord, EffectError> {
        if self.fail_write || (self.fail_stderr && path.ends_with("/stderr")) {
            let detail = if self.fail_stderr {
                "injected stderr artifact failure"
            } else {
                "injected artifact failure"
            };
            return Err(EffectError::ArtifactFailed(detail.into()));
        }
        Ok(ArtifactRecord {
            path: path.into(),
            digest: "sha256:test".into(),
            bytes: bytes.len(),
            immutable: true,
        })
    }
}

fn output(stdout: &str, exit_code: Option<i32>) -> ProcessOutput {
    ProcessOutput {
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
        exit_code,
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
            detail: Some("deterministic fake".into()),
        },
        started_at_ms: 10,
        completed_at_ms: 20,
    }
}

fn stopped_output(
    timed_out: bool,
    cancelled: bool,
    output_limited: bool,
    kill_succeeded: bool,
) -> ProcessOutput {
    ProcessOutput {
        stdout: b"partial".to_vec(),
        stderr: Vec::new(),
        exit_code: None,
        signal: Some(9),
        timed_out,
        cancelled,
        output_limited,
        kill_succeeded,
        process_tree: ProcessTreeEvidence {
            started: true,
            terminated: kill_succeeded,
            hard_killed: true,
            reaped: true,
            detail: Some("deterministic fake cleanup".into()),
        },
        started_at_ms: 10,
        completed_at_ms: 20,
    }
}

fn policy(allowed: bool) -> StaticPolicy {
    StaticPolicy {
        decision: PolicyDecision {
            allowed,
            policy_id: "policy-m5".into(),
            policy_version: 7,
            policy_digest: "sha256:policy-m5".into(),
            reason: Some(if allowed {
                "allowed by test policy".into()
            } else {
                "denied by test policy".into()
            }),
        },
    }
}

fn sealed_request() -> ExternalToolRequest {
    let executable = std::env::current_exe().expect("test executable path");
    let executable_text = executable.to_string_lossy().into_owned();
    let digest = ExecutableIdentity::resolve(&executable_text, None)
        .expect("test executable is readable")
        .digest
        .expect("test executable digest");
    ExternalToolRequest {
        request_id: "m5-test-request".into(),
        provider_id: "m5-provider".into(),
        plan_id: "m5-plan".into(),
        policy_id: "policy-request".into(),
        executable: executable_text,
        cwd: std::env::current_dir()
            .expect("test cwd")
            .to_string_lossy()
            .into_owned(),
        expected_digest: Some(digest),
        args: vec!["--run".into()],
        version_args: vec!["--version".into()],
        ..Default::default()
    }
}

fn assert_incomplete(receipt: &ExecutionReceipt) {
    assert!(
        !receipt.is_complete(),
        "failure must never be complete: {receipt:?}"
    );
    assert!(!receipt.complete);
}

async fn wait_for_started(started: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("tool future did not start within 2 seconds");
}

async fn join_with_timeout(
    execution: tokio::task::JoinHandle<ExecutionReceipt>,
) -> ExecutionReceipt {
    tokio::time::timeout(Duration::from_secs(4), execution)
        .await
        .expect("tool cleanup did not finish within 4 seconds")
        .expect("tool task panicked")
}

#[tokio::test]
async fn policy_denial_binds_exact_evidence() {
    let platform = ScriptedPlatform::default();
    let receipt = EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(false))
        .execute(&sealed_request())
        .await;
    assert_eq!(receipt.state, ExecutionState::UnauthorizedEffect);
    assert_eq!(
        receipt.policy,
        Some(PolicyEvidence {
            id: "policy-m5".into(),
            version: 7,
            digest: "sha256:policy-m5".into(),
            allowed: false,
            reason: Some("denied by test policy".into()),
        })
    );
    assert!(platform.launches().is_empty());
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn actual_version_probe_precedes_requested_argv() {
    let platform = ScriptedPlatform::new([
        Ok(output("tool 1.2.3\n", Some(0))),
        Ok(output("command output", Some(0))),
    ]);
    let request = sealed_request();
    let receipt = EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(true))
        .execute(&request)
        .await;
    let launches = platform.launches();
    assert!(receipt.is_complete());
    assert_eq!(launches.len(), 2);
    assert_eq!(launches[0].args, request.version_args);
    assert_eq!(launches[1].args, request.args);
    assert_eq!(launches[0].termination_grace_ms, 2_000);
    assert_eq!(launches[1].termination_grace_ms, 2_000);
    assert_eq!(
        receipt
            .executable
            .as_ref()
            .unwrap()
            .version
            .output
            .as_deref(),
        Some("tool 1.2.3\n")
    );
    assert_eq!(receipt.policy.as_ref().unwrap().version, 7);
}

#[tokio::test]
async fn version_mismatch_and_nonzero_are_incomplete() {
    for (version_output, exit_code) in [("tool 1.0\n", Some(0)), ("tool 2.0\n", Some(9))] {
        let platform = ScriptedPlatform::new([Ok(output(version_output, exit_code))]);
        let mut request = sealed_request();
        request.version_requirement = Some("2.0".into());
        let receipt =
            EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(true))
                .execute(&request)
                .await;
        assert_eq!(receipt.state, ExecutionState::UnsealedExecutable);
        assert_incomplete(&receipt);
        assert_eq!(platform.launches().len(), 1, "requested argv must not run");
    }
}

#[tokio::test]
async fn timeout_cancellation_and_output_limit_are_incomplete() {
    for (expected, probe) in [
        (
            ExecutionState::Timeout,
            stopped_output(true, false, false, true),
        ),
        (
            ExecutionState::Cancelled,
            stopped_output(false, true, false, true),
        ),
        (
            ExecutionState::OutputLimited,
            stopped_output(false, false, true, true),
        ),
    ] {
        let platform = ScriptedPlatform::new([Ok(probe)]);
        let receipt = EffectExecutor::new(platform, MemoryArtifacts::default(), policy(true))
            .execute(&sealed_request())
            .await;
        assert_eq!(receipt.state, expected);
        assert_incomplete(&receipt);
    }
}

#[tokio::test]
async fn cleanup_failure_precedes_other_terminal_reasons() {
    let platform = ScriptedPlatform::new([
        Ok(output("tool 1.2.3\n", Some(0))),
        Ok(stopped_output(true, false, false, false)),
    ]);
    let receipt = EffectExecutor::new(platform, MemoryArtifacts::default(), policy(true))
        .execute(&sealed_request())
        .await;
    assert_eq!(receipt.state, ExecutionState::KillFailed);
    assert_eq!(receipt.gaps, ["kill_failed"]);
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn version_probe_cleanup_failure_blocks_requested_argv() {
    let platform = ScriptedPlatform::new([Ok(stopped_output(true, false, false, false))]);
    let receipt = EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(true))
        .execute(&sealed_request())
        .await;
    assert_eq!(receipt.state, ExecutionState::KillFailed);
    assert_incomplete(&receipt);
    assert_eq!(platform.launches().len(), 1, "requested argv must not run");
}

#[tokio::test]
async fn successful_version_exit_with_failed_cleanup_blocks_requested_argv() {
    let mut probe = output("tool 1.2.3\n", Some(0));
    probe.kill_succeeded = false;
    let platform = ScriptedPlatform::new([Ok(probe)]);
    let receipt = EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(true))
        .execute(&sealed_request())
        .await;
    assert_eq!(receipt.state, ExecutionState::KillFailed);
    assert_incomplete(&receipt);
    assert_eq!(platform.launches().len(), 1, "requested argv must not run");
}

#[tokio::test]
async fn version_probe_with_unterminated_tree_blocks_requested_argv() {
    let mut probe = output("tool 1.2.3\n", Some(0));
    probe.process_tree.terminated = false;
    let platform = ScriptedPlatform::new([Ok(probe)]);
    let receipt = EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(true))
        .execute(&sealed_request())
        .await;
    assert_eq!(receipt.state, ExecutionState::KillFailed);
    assert_incomplete(&receipt);
    assert_eq!(platform.launches().len(), 1, "requested argv must not run");
}

#[tokio::test]
async fn requested_execution_with_unterminated_tree_is_kill_failed() {
    let mut command = output("command output", Some(0));
    command.process_tree.terminated = false;
    let platform = ScriptedPlatform::new([Ok(output("tool 1.2.3\n", Some(0))), Ok(command)]);
    let receipt = EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(true))
        .execute(&sealed_request())
        .await;
    assert_eq!(receipt.state, ExecutionState::KillFailed);
    assert!(!receipt.process_tree.terminated);
    assert!(receipt.process_tree.reaped);
    assert_incomplete(&receipt);
    assert_eq!(platform.launches().len(), 2);
}

#[tokio::test]
async fn missing_process_tree_start_evidence_is_kill_failed() {
    for (probe_started, command_started, expected_launches) in [(false, true, 1), (true, false, 2)]
    {
        let mut probe = output("tool 1.2.3\n", Some(0));
        probe.process_tree.started = probe_started;
        let mut command = output("command output", Some(0));
        command.process_tree.started = command_started;
        let platform = if expected_launches == 1 {
            ScriptedPlatform::new([Ok(probe)])
        } else {
            ScriptedPlatform::new([Ok(probe), Ok(command)])
        };
        let receipt =
            EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(true))
                .execute(&sealed_request())
                .await;
        assert_eq!(receipt.state, ExecutionState::KillFailed);
        assert_incomplete(&receipt);
        assert_eq!(platform.launches().len(), expected_launches);
    }
}

#[tokio::test]
async fn stderr_only_version_evidence_can_satisfy_requirement() {
    let mut probe = output("", Some(0));
    probe.stderr = b"tool 9.4.1\n".to_vec();
    let platform = ScriptedPlatform::new([Ok(probe), Ok(output("command output", Some(0)))]);
    let mut request = sealed_request();
    request.version_requirement = Some("9.4.1".into());
    let receipt = EffectExecutor::new(platform.clone(), MemoryArtifacts::default(), policy(true))
        .execute(&request)
        .await;
    assert!(receipt.is_complete());
    assert_eq!(platform.launches().len(), 2);
    assert_eq!(
        receipt
            .executable
            .as_ref()
            .unwrap()
            .version
            .output
            .as_deref(),
        Some("tool 9.4.1\n")
    );
}

#[tokio::test]
async fn artifact_failure_is_receipt_backed_and_incomplete() {
    let platform = ScriptedPlatform::new([
        Ok(output("tool 1.2.3\n", Some(0))),
        Ok(output("command output", Some(0))),
    ]);
    let receipt = EffectExecutor::new(
        platform,
        MemoryArtifacts {
            fail_write: true,
            ..Default::default()
        },
        policy(true),
    )
    .execute(&sealed_request())
    .await;
    assert_eq!(receipt.state, ExecutionState::ArtifactFailed);
    assert_incomplete(&receipt);
    assert!(receipt.policy.is_some());
}

#[tokio::test]
async fn stderr_artifact_failure_retains_stdout_and_process_evidence() {
    let platform = ScriptedPlatform::new([
        Ok(output("tool 1.2.3\n", Some(0))),
        Ok(output("command output", Some(0))),
    ]);
    let receipt = EffectExecutor::new(
        platform,
        MemoryArtifacts {
            fail_stderr: true,
            ..Default::default()
        },
        policy(true),
    )
    .execute(&sealed_request())
    .await;
    assert_eq!(receipt.state, ExecutionState::ArtifactFailed);
    assert!(receipt.stdout.is_some());
    assert!(receipt.stderr.is_none());
    assert_eq!(receipt.exit_code, Some(0));
    assert!(receipt.process_tree.reaped);
    assert_eq!(
        receipt.gaps,
        ["artifact_failed: injected stderr artifact failure"]
    );
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn process_failure_precedes_artifact_failure_gap_order() {
    let platform = ScriptedPlatform::new([
        Ok(output("tool 1.2.3\n", Some(0))),
        Ok(stopped_output(true, false, false, false)),
    ]);
    let receipt = EffectExecutor::new(
        platform,
        MemoryArtifacts {
            fail_stderr: true,
            ..Default::default()
        },
        policy(true),
    )
    .execute(&sealed_request())
    .await;
    assert_eq!(receipt.state, ExecutionState::KillFailed);
    assert_eq!(
        receipt.gaps,
        [
            "kill_failed",
            "artifact_failed: injected stderr artifact failure"
        ]
    );
    assert!(receipt.stdout.is_some());
    assert!(receipt.stderr.is_none());
    assert!(receipt.process_tree.started);
    assert!(receipt.process_tree.reaped);
    assert_eq!(receipt.exit_code, None);
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn missing_and_unsealed_executables_are_incomplete() {
    let mut missing = sealed_request();
    missing.executable = PathBuf::from(&missing.cwd)
        .join("missing-m5-executable")
        .to_string_lossy()
        .into_owned();
    let missing_receipt = EffectExecutor::new(
        ScriptedPlatform::default(),
        MemoryArtifacts::default(),
        policy(true),
    )
    .execute(&missing)
    .await;
    assert_eq!(missing_receipt.state, ExecutionState::MissingExecutable);
    assert_incomplete(&missing_receipt);

    let mut unsealed = sealed_request();
    unsealed.expected_digest = None;
    let unsealed_receipt = EffectExecutor::new(
        ScriptedPlatform::default(),
        MemoryArtifacts::default(),
        policy(true),
    )
    .execute(&unsealed)
    .await;
    assert_eq!(unsealed_receipt.state, ExecutionState::UnsealedExecutable);
    assert_incomplete(&unsealed_receipt);
}

struct DummySources;

impl SourceInterface for DummySources {
    fn read(&self, _: &str, _: &Value) -> Result<Value, ProviderError> {
        Err(ProviderError::malformed("unused test source"))
    }
}

struct DummyEffects;

impl EffectInterface for DummyEffects {
    fn request(&self, _: &EffectRequest) -> Result<Value, ProviderError> {
        Err(ProviderError::malformed("unused test effect"))
    }
}

fn provider_context(deadline: Instant, cancellation: CancellationToken) -> ProviderContext {
    let agent = AgentId::new("m5-agent").unwrap();
    let task_id = TaskId::new("m5-task").unwrap();
    let request_id = RequestId::new("m5-request").unwrap();
    let plan = Plan::new(1, PlanId::new("m5-plan").unwrap(), Vec::new(), Vec::new()).unwrap();
    let task = TaskSpec {
        schema_version: 1,
        task_id: task_id.clone(),
        request_id: request_id.clone(),
        title: "M5 test".into(),
        description: None,
        own_scope: vec!["m5".into()],
        read_scope: vec!["m5".into()],
        depends_on: Vec::new(),
        implements_decisions: Vec::new(),
        latitude: Latitude::Bounded,
        declared_checks: Vec::new(),
        evidence_requirements: Vec::new(),
        status: TaskStatus::Complete,
        assigned_authority: agent.clone(),
    };
    let envelope = RequestEnvelope {
        schema_version: 1,
        request_id,
        task_id: Some(task_id.clone()),
        payload: Value::Null,
        extensions: Default::default(),
    };
    let grant = InvocationGrant::new(
        agent,
        task_id,
        BudgetCeiling {
            max_active_time_ms: 1_000,
            ..Default::default()
        },
    )
    .unwrap();
    ProviderContext::new(
        plan,
        envelope,
        task,
        "m5-repository",
        0,
        deadline,
        cancellation,
        grant,
        Arc::new(DummySources),
        Arc::new(DummyEffects),
    )
}

struct StubTool {
    called: Arc<AtomicBool>,
}

struct CleanupAwareTool {
    started: Arc<AtomicBool>,
    cleaned: Arc<AtomicBool>,
}

struct CleanupFailureTool {
    started: Arc<AtomicBool>,
    cleaned: Arc<AtomicBool>,
}

struct DelayedCleanupTool {
    started: Arc<AtomicBool>,
    cleaned: Arc<AtomicBool>,
}

#[async_trait]
impl ExternalProjectTool for DelayedCleanupTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        self.started.store(true, Ordering::SeqCst);
        cancellation.cancelled().await;
        tokio::time::sleep(Duration::from_millis(2100)).await;
        self.cleaned.store(true, Ordering::SeqCst);
        let mut receipt = ExecutionReceipt::failure(&request, ExecutionState::Completed, "seed");
        receipt.complete = true;
        receipt.gaps.clear();
        receipt
    }
}

struct IgnoresCancellationTool {
    started: Arc<AtomicBool>,
}

#[async_trait]
impl ExternalProjectTool for IgnoresCancellationTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        _: CancellationToken,
    ) -> ExecutionReceipt {
        self.started.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(60)).await;
        ExecutionReceipt::failure(&request, ExecutionState::Completed, "unexpected completion")
    }
}

#[async_trait]
impl ExternalProjectTool for CleanupFailureTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        self.started.store(true, Ordering::SeqCst);
        cancellation.cancelled().await;
        self.cleaned.store(true, Ordering::SeqCst);
        ExecutionReceipt::failure(&request, ExecutionState::KillFailed, "kill_failed")
    }
}

#[async_trait]
impl ExternalProjectTool for CleanupAwareTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        self.started.store(true, Ordering::SeqCst);
        cancellation.cancelled().await;
        self.cleaned.store(true, Ordering::SeqCst);
        let mut receipt = ExecutionReceipt::failure(&request, ExecutionState::Completed, "seed");
        receipt.complete = true;
        receipt.gaps.clear();
        receipt
    }
}

#[async_trait]
impl ExternalProjectTool for StubTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        _: CancellationToken,
    ) -> ExecutionReceipt {
        self.called.store(true, Ordering::SeqCst);
        ExecutionReceipt::failure(&request, ExecutionState::Blocked, "stub-result")
    }
}

#[tokio::test]
async fn provider_context_absence_is_typed_incomplete_degradation() {
    let request = sealed_request();
    let context = provider_context(
        Instant::now() + Duration::from_secs(1),
        CancellationToken::new(),
    );
    let receipt = context.execute_external_project_tool(request).await;
    assert_eq!(receipt.state, ExecutionState::Blocked);
    assert_eq!(receipt.gaps, ["external_project_tool_unavailable"]);
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn provider_context_injected_tool_is_the_only_execution_seam() {
    let called = Arc::new(AtomicBool::new(false));
    let request = sealed_request();
    let context = provider_context(
        Instant::now() + Duration::from_secs(1),
        CancellationToken::new(),
    )
    .with_external_project_tool(Arc::new(StubTool {
        called: called.clone(),
    }));
    let receipt = context.execute_external_project_tool(request).await;
    assert!(called.load(Ordering::SeqCst));
    assert_eq!(receipt.state, ExecutionState::Blocked);
    assert_eq!(receipt.gaps, ["stub-result"]);
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn provider_cancellation_waits_for_tool_cleanup_and_normalizes_receipt() {
    let parent_cancellation = CancellationToken::new();
    let started = Arc::new(AtomicBool::new(false));
    let cleaned = Arc::new(AtomicBool::new(false));
    let request = sealed_request();
    let context = provider_context(
        Instant::now() + Duration::from_secs(1),
        parent_cancellation.clone(),
    )
    .with_external_project_tool(Arc::new(CleanupAwareTool {
        started: started.clone(),
        cleaned: cleaned.clone(),
    }));
    let execution =
        tokio::spawn(async move { context.execute_external_project_tool(request).await });
    wait_for_started(&started).await;
    parent_cancellation.cancel();
    let receipt = join_with_timeout(execution).await;
    assert!(cleaned.load(Ordering::SeqCst));
    assert_eq!(receipt.state, ExecutionState::Cancelled);
    assert_eq!(receipt.gaps, ["provider cancelled"]);
    assert!(
        receipt.command.is_some(),
        "normalization retains receipt evidence"
    );
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn provider_deadline_waits_for_tool_cleanup_and_normalizes_receipt() {
    let started = Arc::new(AtomicBool::new(false));
    let cleaned = Arc::new(AtomicBool::new(false));
    let request = sealed_request();
    let context = provider_context(
        Instant::now() + Duration::from_secs(1),
        CancellationToken::new(),
    )
    .with_external_project_tool(Arc::new(CleanupAwareTool {
        started: started.clone(),
        cleaned: cleaned.clone(),
    }));
    let execution =
        tokio::spawn(async move { context.execute_external_project_tool(request).await });
    wait_for_started(&started).await;
    let receipt = join_with_timeout(execution).await;
    assert!(cleaned.load(Ordering::SeqCst));
    assert_eq!(receipt.state, ExecutionState::Timeout);
    assert_eq!(receipt.gaps, ["provider deadline exceeded"]);
    assert!(
        receipt.command.is_some(),
        "normalization retains receipt evidence"
    );
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn provider_cancellation_preserves_tool_cleanup_failure_state() {
    let parent_cancellation = CancellationToken::new();
    let started = Arc::new(AtomicBool::new(false));
    let cleaned = Arc::new(AtomicBool::new(false));
    let request = sealed_request();
    let context = provider_context(
        Instant::now() + Duration::from_secs(1),
        parent_cancellation.clone(),
    )
    .with_external_project_tool(Arc::new(CleanupFailureTool {
        started: started.clone(),
        cleaned: cleaned.clone(),
    }));
    let execution =
        tokio::spawn(async move { context.execute_external_project_tool(request).await });
    wait_for_started(&started).await;
    parent_cancellation.cancel();
    let receipt = join_with_timeout(execution).await;
    assert!(cleaned.load(Ordering::SeqCst));
    assert_eq!(receipt.state, ExecutionState::KillFailed);
    assert_eq!(receipt.gaps, ["kill_failed", "provider cancelled"]);
    assert!(receipt.command.is_some(), "cleanup evidence is retained");
    assert_incomplete(&receipt);
}

#[tokio::test]
async fn provider_ignored_tool_cleanup_is_bounded_and_incomplete() {
    for (cancelled, expected_gap) in [
        (true, "provider cancelled"),
        (false, "provider deadline exceeded"),
    ] {
        let parent_cancellation = CancellationToken::new();
        let started = Arc::new(AtomicBool::new(false));
        let request = sealed_request();
        let deadline = if cancelled {
            Instant::now() + Duration::from_secs(1)
        } else {
            Instant::now() + Duration::from_millis(300)
        };
        let context = provider_context(deadline, parent_cancellation.clone())
            .with_external_project_tool(Arc::new(IgnoresCancellationTool {
                started: started.clone(),
            }));
        let execution =
            tokio::spawn(async move { context.execute_external_project_tool(request).await });
        wait_for_started(&started).await;
        if cancelled {
            parent_cancellation.cancel();
        }
        let receipt = join_with_timeout(execution).await;
        assert_eq!(receipt.state, ExecutionState::KillFailed);
        assert_eq!(
            receipt.gaps,
            [expected_gap, "cleanup_unconfirmed", "kill_failed"]
        );
        assert_incomplete(&receipt);
    }
}

#[tokio::test]
async fn provider_delayed_cleanup_within_grace_retains_terminal_receipt() {
    let parent_cancellation = CancellationToken::new();
    let started = Arc::new(AtomicBool::new(false));
    let cleaned = Arc::new(AtomicBool::new(false));
    let request = sealed_request();
    let context = provider_context(
        Instant::now() + Duration::from_secs(4),
        parent_cancellation.clone(),
    )
    .with_external_project_tool(Arc::new(DelayedCleanupTool {
        started: started.clone(),
        cleaned: cleaned.clone(),
    }));
    let execution =
        tokio::spawn(async move { context.execute_external_project_tool(request).await });
    wait_for_started(&started).await;
    parent_cancellation.cancel();
    let receipt = join_with_timeout(execution).await;
    assert!(cleaned.load(Ordering::SeqCst));
    assert_eq!(receipt.state, ExecutionState::Cancelled);
    assert_eq!(receipt.gaps, ["provider cancelled"]);
    assert!(!receipt.gaps.iter().any(|gap| gap == "cleanup_unconfirmed"));
    assert!(receipt.command.is_some());
    assert_incomplete(&receipt);
}
