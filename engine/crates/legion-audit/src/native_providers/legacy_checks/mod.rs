//! Native execution for the frozen `legacy-check` provider surface.
//!
//! The registry contains two kinds of legacy checks.  Checks whose historical
//! boundary was filesystem analysis are implemented in Rust below.  Checks
//! which deliberately name a project tool require the application's authorized
//! `ExternalProjectTool` capability. Resolution and execution remain behind
//! that typed boundary; missing host tools return typed degradation without
//! starting a process. Neither a tool name nor parser success is evidence.

mod contracts;
mod registry;
mod resolver;

pub use contracts::{
    CommandShape, LegacyCheckError, LegacyCheckExecution, LegacyCheckInput, LegacyCheckOutput,
    LegacyCheckProcessRequest, LegacyCheckProcessState, LegacyCheckSpec, CONTRACT_SCHEMA_VERSION,
    REQUEST_KIND,
};
pub use registry::{spec, specs, LEGACY_CHECK_SPECS};
pub use resolver::{resolve_command, resolve_request, ResolveError, ResolvedCommand};

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use legion_provider_sdk::{ExternalProjectTool, ExternalToolRequest};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio_util::sync::CancellationToken;

use crate::{
    error::AuditError,
    execution::ProviderExecutor,
    inventory::{InventoryEntry, InventoryEnvelope},
    plan::AuditProvider,
};

/// Production Audit adapter that keeps effect artifacts under repository
/// cache. Registry request ids contain punctuation (including `:`), which is
/// not a valid Windows path component; receipts retain provider/plan ids.
pub struct AuditExternalProjectTool<T> {
    inner: T,
}

impl<T> AuditExternalProjectTool<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<T> ExternalProjectTool for AuditExternalProjectTool<T>
where
    T: ExternalProjectTool,
{
    async fn execute(
        &self,
        mut request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> legion_provider_sdk::ExecutionReceipt {
        let requested_executable = request.executable.clone();
        let resolved = match resolve_request(
            &PathBuf::from(&request.cwd),
            &requested_executable,
            &request.args,
        ) {
            Ok(value) => value,
            Err(error) => {
                let state = match error {
                    ResolveError::MissingExecutable(_) => {
                        legion_provider_sdk::ExecutionState::MissingExecutable
                    }
                    ResolveError::Unavailable(_) => legion_provider_sdk::ExecutionState::Internal,
                };
                return legion_provider_sdk::ExecutionReceipt::failure(
                    &request,
                    state,
                    error.message(),
                );
            }
        };
        request.executable = resolved.executable.to_string_lossy().into_owned();
        request.args = resolved.args;
        request.expected_digest = Some(resolved.digest);
        request.cwd = resolved.cwd.to_string_lossy().into_owned();
        request.request_id = audit_artifact_request_id(&request.request_id);
        self.inner.execute(request, cancellation).await
    }
}

static AUDIT_ARTIFACT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn audit_artifact_request_id(request_id: &str) -> String {
    let sequence = AUDIT_ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let material = format!("{request_id}:{now}:{sequence}");
    format!(
        ".cache/legion-audit/{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

/// Immutable request builder for the legacy provider boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct LegacyCheckDispatcher;

impl LegacyCheckDispatcher {
    pub const fn new() -> Self {
        Self
    }

    pub fn contains(&self, provider_id: &str) -> bool {
        spec(provider_id).is_some()
    }

    pub fn contract(&self, provider_id: &str) -> Option<&'static LegacyCheckSpec> {
        spec(provider_id)
    }

    pub fn request(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: impl Into<PathBuf>,
        binding: Option<&Value>,
        projection: Option<&Value>,
        artifacts: &Value,
    ) -> Result<LegacyCheckProcessRequest, LegacyCheckError> {
        let contract = spec(&provider.id).ok_or_else(|| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: provider.id.clone(),
            state: LegacyCheckProcessState::Failed,
            message: "provider is not one of the frozen legacy-check contracts".into(),
        })?;
        contracts::validate_provider(provider, contract)?;
        let root = root.into();
        if !root.is_absolute() {
            return Err(LegacyCheckError {
                provider_id: provider.id.clone(),
                check: contract.check.into(),
                state: LegacyCheckProcessState::Failed,
                message: "legacy-check cwd must be absolute".into(),
            });
        }
        let selector = provider
            .configuration
            .get("selector")
            .ok_or_else(|| LegacyCheckError {
                provider_id: provider.id.clone(),
                check: contract.check.into(),
                state: LegacyCheckProcessState::Failed,
                message: "provider selector is missing".into(),
            })?;
        let denominator =
            inventory
                .denominator_entries(selector)
                .map_err(|error| LegacyCheckError {
                    provider_id: provider.id.clone(),
                    check: contract.check.into(),
                    state: LegacyCheckProcessState::Failed,
                    message: error.to_string(),
                })?;
        Ok(LegacyCheckProcessRequest {
            schema_version: CONTRACT_SCHEMA_VERSION,
            kind: REQUEST_KIND,
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            cwd: root,
            binding: binding.cloned(),
            denominator,
            projection: projection.cloned(),
            artifacts: artifacts.clone(),
            command: contract.command,
        })
    }

    pub fn input(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: impl Into<PathBuf>,
        binding: Option<&Value>,
        projection: Option<&Value>,
        artifacts: &Value,
    ) -> Result<LegacyCheckInput, LegacyCheckError> {
        let request = self.request(provider, inventory, root, binding, projection, artifacts)?;
        Ok(LegacyCheckInput {
            provider_id: request.provider_id,
            check: request.check,
            root: request.cwd,
            inventory_generation: inventory.generation.clone(),
            inventory_digest: inventory.digest.clone(),
            denominator: request.denominator,
            binding: request.binding,
            projection: request.projection,
            artifacts: request.artifacts,
        })
    }

    pub fn request_for_path(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: &Path,
    ) -> Result<LegacyCheckProcessRequest, LegacyCheckError> {
        self.request(provider, inventory, root, None, None, &Value::Null)
    }

    /// Project terminal process metadata into the validated common result.
    pub fn project_result(
        &self,
        provider: &AuditProvider,
        input: &LegacyCheckInput,
        execution: LegacyCheckExecution,
    ) -> Result<ProviderResult, LegacyCheckError> {
        let contract = spec(&provider.id).ok_or_else(|| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: provider.id.clone(),
            state: LegacyCheckProcessState::Failed,
            message: "provider is not one of the frozen legacy-check contracts".into(),
        })?;
        contracts::validate_provider(provider, contract)?;
        let provider_id = ProviderId::new(&provider.id).map_err(|error| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            state: LegacyCheckProcessState::Failed,
            message: error.to_string(),
        })?;
        let mut output = execution.output.unwrap_or_default();
        let process_ok = execution.state == LegacyCheckProcessState::Completed;
        let mut gaps = output.coverage_gaps.clone();
        let mut degradation = output.degradation.clone();
        if !process_ok {
            gaps.push(format!("external-process:{}", execution.state.as_str()));
            degradation.push(format!("external-process:{}", execution.state.as_str()));
        }
        if let Some(error) = &execution.error {
            gaps.push(format!("external-error:{}", error.message));
            degradation.push(format!("external-error:{}", error.message));
        }
        let coverage = output.coverage.take().unwrap_or_else(|| Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected: input.denominator.entries.len() as u64,
            examined: 0,
            gaps: gaps.clone(),
        });
        if coverage.denominator_digest != input.denominator.digest {
            gaps.push("denominator-digest-mismatch".into());
        }
        gaps.extend(coverage.gaps.iter().cloned());
        gaps.sort();
        gaps.dedup();
        degradation.sort();
        degradation.dedup();
        let complete = process_ok && output.complete && gaps.is_empty() && coverage.complete();
        output
            .details
            .insert("check".into(), Value::String(contract.check.into()));
        output
            .details
            .insert("tool".into(), Value::String(contract.tool.into()));
        output.details.insert(
            "processState".into(),
            Value::String(execution.state.as_str().into()),
        );
        output.details.insert(
            "exitCode".into(),
            execution.exit_code.map(Value::from).unwrap_or(Value::Null),
        );
        output.details.insert(
            "stdoutBytes".into(),
            Value::from(execution.stdout.len() as u64),
        );
        output.details.insert(
            "stderrBytes".into(),
            Value::from(execution.stderr.len() as u64),
        );
        let candidates = std::mem::take(&mut output.candidates);
        output
            .details
            .insert("candidates".into(), Value::Array(candidates));
        output.details.insert(
            "commandShape".into(),
            Value::String(command_name(contract.command).into()),
        );
        if let Some(receipt_id) = execution.receipt_id {
            output
                .details
                .insert("receiptId".into(), Value::String(receipt_id));
        }
        if let Some(error) = execution.error {
            output.details.insert(
                "executionError".into(),
                json!({"state": error.state.as_str(), "message": error.message}),
            );
        }
        let status = if complete {
            if matches!(output.status, ProviderStatus::Ok) {
                ProviderStatus::Ok
            } else {
                ProviderStatus::Complete
            }
        } else if process_ok {
            output.status
        } else {
            ProviderStatus::Failed
        };
        let result = ProviderResult {
            schema_version: 1,
            provider: provider_id,
            applicable: true,
            required: provider.required,
            status,
            complete,
            coverage: Some(Coverage {
                denominator_digest: coverage.denominator_digest,
                expected: coverage.expected,
                examined: coverage.examined,
                gaps: gaps.clone(),
            }),
            findings: output.findings,
            coverage_gaps: gaps,
            degradation,
            details: output.details,
        };
        result.validate().map_err(|error| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            state: LegacyCheckProcessState::Failed,
            message: error.to_string(),
        })?;
        Ok(result)
    }
}

/// Native Rust owner for all 32 frozen legacy provider IDs.
#[derive(Clone)]
pub struct NativeLegacyCheckExecutor {
    root: PathBuf,
    external_project_tool: Option<Arc<dyn ExternalProjectTool>>,
}

impl std::fmt::Debug for NativeLegacyCheckExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeLegacyCheckExecutor")
            .field("root", &self.root)
            .field(
                "external_project_tool",
                &self.external_project_tool.is_some(),
            )
            .finish()
    }
}

impl NativeLegacyCheckExecutor {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            external_project_tool: None,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn with_external_project_tool(mut self, tool: Arc<dyn ExternalProjectTool>) -> Self {
        self.external_project_tool = Some(tool);
        self
    }

    pub async fn execute_async(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ProviderResult, AuditError> {
        let dispatcher = LegacyCheckDispatcher::new();
        let input = dispatcher
            .input(
                provider,
                inventory,
                self.root.clone(),
                None,
                None,
                &Value::Null,
            )
            .map_err(|error| AuditError::Provider(error.to_string()))?;
        let contract = spec(&provider.id).expect("validated above");
        if matches!(contract.command, CommandShape::Native { .. }) {
            return self.execute(provider, inventory);
        }
        let Some(tool) = &self.external_project_tool else {
            return dispatcher
                .project_result(
                    provider,
                    &input,
                    execute_external(&input, contract.command, now_ms()),
                )
                .map_err(|error| AuditError::Provider(error.to_string()));
        };
        let (executable, args) = command_parts(contract.command);
        let request_id = format!(
            "audit:{}:{}:{}",
            provider.id,
            plan.digest(),
            inventory.digest
        );
        let (environment, environment_allowlist) = audit_environment();
        let request = ExternalToolRequest {
            request_id,
            provider_id: provider.id.clone(),
            plan_id: plan.digest().into(),
            policy_id: provider
                .configuration
                .get("policyId")
                .and_then(Value::as_str)
                .unwrap_or("audit")
                .into(),
            task_id: Some(contract.check.into()),
            executable: executable.into(),
            args,
            cwd: self.root.to_string_lossy().into_owned(),
            shell: false,
            expected_digest: None,
            accepted_exit_codes: accepted_exit_codes(contract.check),
            environment,
            environment_allowlist,
            // Native Audit has no authenticated sandbox receipt. The effects
            // executor therefore refuses project/network/runtime checks before
            // process start; safe read-only git and gitleaks checks remain
            // executable under the explicit Audit policy.
            requires_network_sandbox: sandbox_required_check(contract.check),
            timeout_ms: provider
                .bounds
                .get("timeoutMs")
                .and_then(Value::as_u64)
                .unwrap_or(120_000),
            stdout_limit: provider
                .bounds
                .get("stdoutLimit")
                .and_then(Value::as_u64)
                .unwrap_or(8 * 1024 * 1024) as usize,
            stderr_limit: provider
                .bounds
                .get("stderrLimit")
                .and_then(Value::as_u64)
                .unwrap_or(8 * 1024 * 1024) as usize,
            ..ExternalToolRequest::default()
        };
        let receipt = tool.execute(request, cancellation).await;
        let execution = execution_from_receipt(&input, contract.command, &self.root, receipt);
        dispatcher
            .project_result(provider, &input, execution)
            .map_err(|error| AuditError::Provider(error.to_string()))
    }

    pub fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let dispatcher = LegacyCheckDispatcher::new();
        let input = dispatcher
            .input(
                provider,
                inventory,
                self.root.clone(),
                None,
                None,
                &Value::Null,
            )
            .map_err(|error| AuditError::Provider(error.to_string()))?;
        let execution = execute_input(&input, spec(&provider.id).expect("validated above"));
        dispatcher
            .project_result(provider, &input, execution)
            .map_err(|error| AuditError::Provider(error.to_string()))
    }
}

fn sandbox_required_check(check: &str) -> bool {
    matches!(
        check,
        "build"
            | "lint"
            | "types"
            | "dead_code"
            | "duplication"
            | "ci_lint"
            | "docker"
            | "sast"
            | "swift_lint"
            | "js_licenses"
            | "cargo_unsafe"
            | "cargo_unused_deps"
            | "runtime"
            | "deps_cve"
            | "py_deps_cve"
            | "cargo_audit"
            | "cargo_deny"
            | "outdated"
            | "cargo_outdated"
    )
}

fn accepted_exit_codes(check: &str) -> BTreeSet<i32> {
    match check {
        "repo" | "build" => [0].into_iter().collect(),
        "debt_markers" | "secrets" | "deps_cve" => [0, 1].into_iter().collect(),
        _ => [0, 1, 2].into_iter().collect(),
    }
}

fn audit_environment() -> (BTreeMap<String, String>, BTreeSet<String>) {
    let names = [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
        "TEMP",
        "TMP",
    ];
    let environment = names
        .iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| ((*name).to_owned(), value))
        })
        .collect();
    let allowlist = names.into_iter().map(str::to_owned).collect();
    (environment, allowlist)
}

#[async_trait::async_trait]
impl ProviderExecutor for NativeLegacyCheckExecutor {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        Self::execute(self, provider, inventory)
    }

    async fn execute_async(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ProviderResult, AuditError> {
        self.execute_async(plan, provider, inventory, cancellation)
            .await
    }
}

fn execution_from_receipt(
    input: &LegacyCheckInput,
    command: CommandShape,
    root: &Path,
    receipt: legion_provider_sdk::ExecutionReceipt,
) -> LegacyCheckExecution {
    let state = match receipt.state {
        legion_provider_sdk::ExecutionState::Completed => LegacyCheckProcessState::Completed,
        legion_provider_sdk::ExecutionState::MissingExecutable => {
            LegacyCheckProcessState::MissingExecutable
        }
        legion_provider_sdk::ExecutionState::UnauthorizedEffect
        | legion_provider_sdk::ExecutionState::Blocked
        | legion_provider_sdk::ExecutionState::SandboxMissing
        | legion_provider_sdk::ExecutionState::UnsealedExecutable => {
            LegacyCheckProcessState::Unauthorized
        }
        legion_provider_sdk::ExecutionState::Timeout => LegacyCheckProcessState::Timeout,
        legion_provider_sdk::ExecutionState::Cancelled => LegacyCheckProcessState::Cancelled,
        legion_provider_sdk::ExecutionState::OutputLimited => {
            LegacyCheckProcessState::OutputLimited
        }
        legion_provider_sdk::ExecutionState::KillFailed
        | legion_provider_sdk::ExecutionState::ArtifactFailed => {
            LegacyCheckProcessState::CleanupUnconfirmed
        }
        _ => LegacyCheckProcessState::Failed,
    };
    let mut output = empty_output(receipt.gaps.clone());
    let stdout = receipt
        .stdout
        .as_ref()
        .and_then(|a| readable_artifact(root, a));
    let stderr = receipt
        .stderr
        .as_ref()
        .and_then(|a| readable_artifact(root, a));
    let mut parsed = false;
    if let Some(bytes) = stdout.as_deref() {
        if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
            parsed = parse_external_value(input, &value, &mut output);
        }
        if !parsed {
            parsed = parse_text_output(input, bytes, &mut output);
        }
    }
    if receipt.complete && parsed && output.coverage.is_none() {
        output.coverage = Some(Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected: input.denominator.entries.len() as u64,
            examined: input.denominator.entries.len() as u64,
            gaps: output.coverage_gaps.clone(),
        });
    }
    let (_, args) = command_parts(command);
    let receipt_value = json!({
        "schemaVersion": receipt.schema_version, "receiptId": receipt.receipt_id,
        "requestId": receipt.request_id, "providerId": receipt.provider_id,
        "planId": receipt.plan_id, "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}", e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}", e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode": receipt.exit_code, "signal": receipt.signal,
        "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error}, "gaps": receipt.gaps,
        "requestArgs": args
    });
    output
        .details
        .insert("executionReceipt".into(), receipt_value);
    if !parsed && receipt.complete {
        output
            .coverage_gaps
            .push("artifact-bytes-unreadable".into());
    }
    output.complete = receipt.complete && parsed;
    LegacyCheckExecution {
        state,
        exit_code: receipt.exit_code,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
        receipt_id: Some(receipt.receipt_id),
        output: Some(output),
        error: None,
    }
}

fn readable_artifact(
    root: &Path,
    artifact: &legion_effects::artifact::ArtifactRecord,
) -> Option<Vec<u8>> {
    if !artifact.immutable {
        return None;
    }
    let path = Path::new(&artifact.path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let bytes = std::fs::read(path).ok()?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    (bytes.len() == artifact.bytes && digest == artifact.digest).then_some(bytes)
}

fn execute_input(input: &LegacyCheckInput, contract: &LegacyCheckSpec) -> LegacyCheckExecution {
    let started = now_ms();
    if input.denominator.entries.is_empty() {
        let message = "frozen selector denominator is empty";
        let gaps = vec!["denominator-empty".to_owned()];
        return terminal_execution(
            input,
            contract.command,
            LegacyCheckProcessState::Failed,
            None,
            Vec::new(),
            Vec::new(),
            empty_output(gaps.clone()),
            gaps,
            started,
            false,
            Some(message),
        );
    }
    match contract.command {
        CommandShape::Native { operation } => {
            let output = native_operation(input, operation);
            let gaps = output.coverage_gaps.clone();
            let state = if gaps.is_empty() {
                LegacyCheckProcessState::Completed
            } else {
                LegacyCheckProcessState::Failed
            };
            let error = (!gaps.is_empty()).then(|| "native source analysis was incomplete");
            terminal_execution(
                input,
                contract.command,
                state,
                Some(0),
                Vec::new(),
                Vec::new(),
                output,
                gaps,
                started,
                true,
                error,
            )
        }
        command => execute_external(input, command, started),
    }
}

fn native_operation(input: &LegacyCheckInput, operation: &str) -> LegacyCheckOutput {
    let (files, mut gaps) = read_denominator(input);
    let mut output = empty_output(Vec::new());
    output
        .details
        .insert("implementation".into(), Value::String("native-rust".into()));
    output
        .details
        .insert("operation".into(), Value::String(operation.into()));
    if files.is_empty() {
        gaps.push("denominator-unreadable".into());
    }
    match input.check.as_str() {
        "apple_platform" => native_apple(&files, &mut output),
        "decomposition" => native_decomposition(&files, &mut output),
        "negative_space" => native_negative_space(&files, &mut output),
        "tool_coverage" => native_tool_coverage(input, &files, &mut output),
        "react_hooks" => native_react_hooks(&files, &mut output),
        "binary_pins" => native_binary_pins(&files, &mut output),
        "dep_pinning" => native_dependency_pinning(input, &files, &mut output),
        "vendored_deps" => native_vendored(&files, &mut output),
        "tauri_capabilities" => native_tauri_capabilities(&files, &mut output),
        "contract_mirror" => native_contract_mirror(&files, &mut output),
        _ => gaps.push(format!("native-operation-unimplemented:{}", input.check)),
    }
    output.coverage_gaps.extend(gaps);
    output.coverage_gaps.sort();
    output.coverage_gaps.dedup();
    output.complete = output.coverage_gaps.is_empty();
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: files.len() as u64,
        gaps: output.coverage_gaps.clone(),
    });
    output
}

fn execute_external(
    input: &LegacyCheckInput,
    command: CommandShape,
    started: u64,
) -> LegacyCheckExecution {
    // Raw Command::output would bypass provider authorization, timeout/output
    // bounds and process-tree cleanup. Do not revive it as an implicit fallback.
    let (program, args) = command_parts(command);
    let gap = "external-project-tool-capability-unavailable".to_owned();
    let message = "legacy external check requires the application-owned authorized ExternalProjectTool capability";
    let mut output = empty_output(vec![gap.clone()]);
    output.degradation.push(message.into());
    output.details.insert(
        "implementation".into(),
        json!("native-external-capability-unavailable"),
    );
    output.details.insert("executable".into(), json!(program));
    output.details.insert("arguments".into(), json!(args));
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: 0,
        gaps: vec![gap.clone()],
    });
    let mut execution = terminal_execution(
        input,
        command,
        LegacyCheckProcessState::Unauthorized,
        None,
        Vec::new(),
        Vec::new(),
        output,
        vec![gap],
        started,
        false,
        Some(message),
    );
    // This is refusal evidence, not a policy grant or a process receipt from a
    // tool we did not run. Preserve explicit not-started/not-attempted facts.
    if let Some(output) = execution.output.as_mut() {
        let receipt = output
            .details
            .get_mut("executionReceipt")
            .expect("terminal receipt");
        receipt["policy"] = Value::Null;
        receipt["policyId"] = json!("unresolved-external-capability");
        receipt["executable"]["digestState"] = json!("not-checked");
        receipt["executable"]["version"]["qualified"] = json!(false);
        receipt["processTree"] = json!({"started":false,"terminated":false,"hardKilled":false,"reaped":false,"detail":"process not started: external capability unavailable"});
        // stdout/stderr are already null for non-native receipts: indexing a
        // null receipt field would resurrect an artifact object with a null
        // path, which the frozen external-receipt validator rejects.
        receipt["parser"]["attempted"] = json!(false);
    }
    execution
}

fn terminal_execution(
    input: &LegacyCheckInput,
    command: CommandShape,
    state: LegacyCheckProcessState,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    mut output: LegacyCheckOutput,
    gaps: Vec<String>,
    started: u64,
    parser_ok: bool,
    error: Option<&str>,
) -> LegacyCheckExecution {
    let completed = now_ms().max(started);
    let receipt_id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            format!(
                "{}:{}:{}",
                input.provider_id, input.inventory_digest, started
            )
            .as_bytes()
        ))
    );
    let receipt = execution_receipt(
        input,
        command,
        state,
        exit_code,
        &stdout,
        &stderr,
        started,
        completed,
        &gaps,
        parser_ok && error.is_none(),
        error,
    );
    output.details.insert("executionReceipt".into(), receipt);
    LegacyCheckExecution {
        state,
        exit_code,
        stdout,
        stderr,
        receipt_id: Some(receipt_id),
        output: Some(output),
        error: error.map(|message| LegacyCheckError {
            provider_id: input.provider_id.clone(),
            check: input.check.clone(),
            state,
            message: message.to_owned(),
        }),
    }
}

fn execution_receipt(
    input: &LegacyCheckInput,
    command: CommandShape,
    state: LegacyCheckProcessState,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    started: u64,
    completed: u64,
    gaps: &[String],
    parser_ok: bool,
    error: Option<&str>,
) -> Value {
    let (executable, args) = command_parts(command);
    let executable_path = format!("native://legion-audit/{}", input.check);
    let requested = if executable == "native" {
        executable_path
    } else {
        executable.to_owned()
    };
    let native = matches!(command, CommandShape::Native { .. });
    json!({
        "schemaVersion": 1,
        "kind": if native { "native-legacy-check-receipt" } else { "external-tool-refusal-receipt" },
        "receiptId": format!("native-receipt:{}:{}", input.provider_id, started),
        "requestId": format!("native-request:{}:{}", input.provider_id, input.inventory_generation),
        "providerId": input.provider_id,
        "planId": input.inventory_digest,
        "policyId": "native-legacy-check-v1",
        "policy": null,
        "taskId": input.check,
        "state": state.as_str(),
        "complete": state == LegacyCheckProcessState::Completed && gaps.is_empty(),
        // The frozen external-receipt validator reads a non-null executable
        // object as a real executable identity, so an unverified external tool
        // must carry an explicit unverified signature rather than null.
        "executable": {"requestedPath":requested,"canonicalPath":Value::Null,"digest":Value::Null,"digestState":"not-applicable","signature":if native { Value::Null } else { json!("unverified") },"version":{"args":args,"output":Value::Null,"exitCode":exit_code,"qualified":false}},
        "command": {"executable":executable,"args":args,"environmentNames":[],"redactedArgumentIndexes":[],"redactedEnvironmentNames":[]},
        "cwd": input.root.to_string_lossy(),
        "environmentNames": [],
        "sandbox": {"required":false,"networkEnabled":false,"receiptId":Value::Null},
        "processTree": {"started":false,"terminated":false,"hardKilled":false,"reaped":false,"detail":if native { "in-process Rust analysis; no external process" } else { "external capability unavailable; no process started" }},
        "timing": {"startedAtMs":started,"completedAtMs":completed,"durationMs":completed-started},
        "exitCode": exit_code,
        "signal": Value::Null,
        // No process started means no captured streams: the receipt must not
        // present an artifact object whose path is null, because the frozen
        // external-receipt validator reads a non-null object as a real capture.
        "stdout": if native { json!({"path":null,"digest":format!("sha256:{}",hex::encode(Sha256::digest(stdout))),"bytes":stdout.len(),"immutable":false}) } else { Value::Null },
        "stderr": if native { json!({"path":null,"digest":format!("sha256:{}",hex::encode(Sha256::digest(stderr))),"bytes":stderr.len(),"immutable":false}) } else { Value::Null },
        "parser": {"attempted":true,"succeeded":parser_ok,"error":error},
        "gaps":gaps,
    })
}

fn command_parts(command: CommandShape) -> (&'static str, Vec<String>) {
    match command {
        CommandShape::Native { .. } => ("native", Vec::new()),
        CommandShape::Fixed { executable, args }
        | CommandShape::Named {
            tool: executable,
            args,
        } => (
            executable,
            args.iter().map(|arg| (*arg).to_owned()).collect(),
        ),
    }
}

fn empty_output(gaps: Vec<String>) -> LegacyCheckOutput {
    LegacyCheckOutput {
        status: if gaps.is_empty() {
            ProviderStatus::Ok
        } else {
            ProviderStatus::Partial
        },
        complete: false,
        coverage: None,
        findings: Vec::new(),
        candidates: Vec::new(),
        coverage_gaps: gaps,
        degradation: Vec::new(),
        details: BTreeMap::new(),
    }
}

fn read_denominator(input: &LegacyCheckInput) -> (Vec<(InventoryEntry, String)>, Vec<String>) {
    let mut files = Vec::new();
    let mut gaps = Vec::new();
    const MAX_FILE_BYTES: u64 = 1_048_576;
    const MAX_TOTAL_BYTES: u64 = 33_554_432;
    let root = match std::fs::canonicalize(&input.root) {
        Ok(root) => root,
        Err(error) => return (files, vec![format!("source-root-unavailable:{error}")]),
    };
    let mut total = 0_u64;
    for entry in &input.denominator.entries {
        let read = (|| -> Result<String, String> {
            let relative = entry.path.replace('\\', "/");
            if relative.contains(':')
                || relative
                    .split('/')
                    .any(|part| matches!(part, "" | "." | ".."))
            {
                return Err("unsafe-source-path".into());
            }
            let mut path = root.clone();
            for part in relative.split('/') {
                path.push(part);
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|error| format!("source-unavailable:{error}"))?;
                if metadata.file_type().is_symlink() {
                    return Err("source-link-not-followed".into());
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err("source-reparse-point-not-followed".into());
                    }
                }
            }
            let resolved = std::fs::canonicalize(&path)
                .map_err(|error| format!("source-unavailable:{error}"))?;
            if !resolved.starts_with(&root) {
                return Err("source-escaped-root".into());
            }
            let file = std::fs::File::open(&path)
                .map_err(|error| format!("source-unavailable:{error}"))?;
            let metadata = file
                .metadata()
                .map_err(|error| format!("source-unavailable:{error}"))?;
            if !metadata.is_file() {
                return Err("source-not-regular-file".into());
            }
            if metadata.len() > MAX_FILE_BYTES {
                return Err("source-file-byte-limit".into());
            }
            if total.saturating_add(metadata.len()) > MAX_TOTAL_BYTES {
                return Err("source-total-byte-limit".into());
            }
            let mut bytes = Vec::new();
            file.take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("source-unavailable:{error}"))?;
            if bytes.len() as u64 > MAX_FILE_BYTES {
                return Err("source-file-byte-limit".into());
            }
            total = total.saturating_add(bytes.len() as u64);
            if total > MAX_TOTAL_BYTES {
                return Err("source-total-byte-limit".into());
            }
            if let Some(expected) = &entry.digest {
                let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
                if *expected != actual {
                    return Err("source-digest-drift".into());
                }
            }
            String::from_utf8(bytes).map_err(|_| "source-invalid-utf8".into())
        })();
        match read {
            Ok(text) => files.push((entry.clone(), text)),
            Err(gap) => gaps.push(format!("{gap}:{}", entry.path)),
        }
    }
    (files, gaps)
}

fn native_apple(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        if contains_any(
            text,
            &["import UIKit", "import AppKit", "import SwiftUI", "@objc"],
        ) {
            push_candidate(
                output,
                "apple.platform-api",
                "medium",
                &entry.path,
                first_line(
                    text,
                    &["import UIKit", "import AppKit", "import SwiftUI", "@objc"],
                ),
                "Apple platform API usage requires platform-target confirmation.",
            );
        }
    }
}

fn native_decomposition(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        let lines = text.lines().count();
        if lines > 800 {
            push_finding(
                output,
                "architecture.file-too-large",
                "warning",
                &entry.path,
                1,
                "source file exceeds the native decomposition threshold",
            );
        }
    }
}

fn native_negative_space(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        if text.trim().is_empty() {
            push_finding(
                output,
                "quality.empty-source-file",
                "warning",
                &entry.path,
                1,
                "denominator contains an empty source file",
            );
        }
    }
}

fn native_tool_coverage(
    _input: &LegacyCheckInput,
    files: &[(InventoryEntry, String)],
    output: &mut LegacyCheckOutput,
) {
    let paths = files
        .iter()
        .map(|(entry, _)| entry.path.clone())
        .collect::<Vec<_>>();
    let manifests = paths.iter().filter(|path| is_manifest(path)).count();
    output.details.insert("toolCoverage".into(), json!({"files":paths,"manifestCount":manifests,"sourceCount":files.iter().filter(|(entry, _)| entry.source_file).count()}));
}

fn native_react_hooks(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        if contains_any(text, &["import React", "from 'react'", "from \"react\""]) {
            for hook in [
                "useState(",
                "useEffect(",
                "useMemo(",
                "useCallback(",
                "useContext(",
            ] {
                for offset in occurrences(text, hook) {
                    let prefix = &text[..offset];
                    if prefix
                        .rfind("if (")
                        .is_some_and(|index| index > prefix.rfind('}').unwrap_or(0))
                    {
                        push_finding(
                            output,
                            "react.hooks.conditional-call",
                            "warning",
                            &entry.path,
                            line_at(text, offset),
                            "React hook appears in a conditional block",
                        );
                    }
                }
            }
        }
    }
}

fn native_binary_pins(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        for (line, value) in text.lines().enumerate() {
            if contains_any(value, &["https://", "http://"])
                && !contains_any(value, &["sha256", "integrity", "@"])
            {
                push_candidate(
                    output,
                    "security.binary-unpinned",
                    "high",
                    &entry.path,
                    line + 1,
                    "downloaded binary URL has no visible immutable digest",
                );
            }
        }
    }
}

fn native_dependency_pinning(
    input: &LegacyCheckInput,
    files: &[(InventoryEntry, String)],
    output: &mut LegacyCheckOutput,
) {
    let paths = input
        .denominator
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    for (entry, text) in files {
        let is_package = entry.path.ends_with("package.json");
        let is_cargo = entry.path.ends_with("Cargo.toml");
        if (is_package
            && !paths.contains("package-lock.json")
            && !paths.contains("pnpm-lock.yaml")
            && !paths.contains("yarn.lock"))
            || (is_cargo && !paths.contains("Cargo.lock"))
        {
            push_candidate(
                output,
                "security.dependency-unpinned",
                "medium",
                &entry.path,
                first_nonempty_line(text),
                "manifest has no corresponding lockfile in the frozen repository",
            );
        }
    }
}

fn native_vendored(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, _text) in files {
        if entry.path.split('/').any(|part| {
            matches!(
                part.to_ascii_lowercase().as_str(),
                "vendor" | "vendored" | "third_party" | "third-party"
            )
        }) {
            push_candidate(
                output,
                "security.vendored-manifest",
                "low",
                &entry.path,
                1,
                "vendored dependency material is present in the frozen scope",
            );
        }
    }
}

fn native_tauri_capabilities(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    let mut has_config = false;
    let mut frontend = BTreeSet::new();
    let mut backend = BTreeSet::new();
    for (entry, text) in files {
        if entry.path.ends_with("tauri.conf.json")
            || entry.path.ends_with("tauri.conf.json5")
            || entry.path.ends_with("Tauri.toml")
        {
            has_config = true;
        }
        if contains_any(
            text,
            &[
                "shell:allow-execute",
                "shell:allow-spawn",
                "fs:allow-write",
                "fs:allow-remove",
            ],
        ) && !contains_any(text, &["windows", "webviews", "platforms"])
        {
            push_candidate(
                output,
                "tauri.broad-capability",
                "medium",
                &entry.path,
                1,
                "powerful Tauri capability is not visibly platform or window scoped",
            );
        }
        for command in quoted_invocations(text, "invoke(") {
            frontend.insert(command);
        }
        for command in annotated_rust_functions(text) {
            backend.insert(command);
        }
    }
    if !has_config {
        push_candidate(
            output,
            "tauri.config-missing",
            "high",
            "src-tauri",
            1,
            "Tauri source is present but no supported configuration file is visible",
        );
    }
    for command in frontend.difference(&backend) {
        push_candidate(
            output,
            "tauri.unregistered-command",
            "high",
            "src-tauri",
            1,
            &format!("frontend invokes {command} without a matching Tauri command"),
        );
    }
}

fn native_contract_mirror(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    let mut frontend = BTreeSet::new();
    let mut backend = BTreeSet::new();
    for (entry, text) in files {
        for command in quoted_invocations(text, "invoke(") {
            frontend.insert(command);
        }
        for command in annotated_rust_functions(text) {
            backend.insert(command);
        }
        if entry.path.ends_with("tauri.conf.json") && text.contains("allow-all") {
            push_candidate(
                output,
                "tauri.contract-broad-permission",
                "medium",
                &entry.path,
                1,
                "Tauri configuration contains a broad permission marker",
            );
        }
    }
    for command in frontend.difference(&backend) {
        push_candidate(
            output,
            "tauri.contract-missing",
            "high",
            "src-tauri",
            1,
            &format!("frontend contract has no backend command: {command}"),
        );
    }
}

fn parse_external_value(
    input: &LegacyCheckInput,
    value: &Value,
    output: &mut LegacyCheckOutput,
) -> bool {
    if input.check == "secrets" && value.is_array() {
        let items = value.as_array().expect("checked above");
        let mut redacted = Vec::with_capacity(items.len());
        for item in items {
            let rule = item.get("RuleID").and_then(Value::as_str);
            let file = item.get("File").and_then(Value::as_str);
            let line = item.get("StartLine").and_then(Value::as_u64);
            let digest = item
                .get("Fingerprint")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    format!(
                        "sha256:{}",
                        hex::encode(Sha256::digest(
                            format!(
                                "{}\0{}\0{}",
                                rule.unwrap_or_default(),
                                file.unwrap_or_default(),
                                line.map(|value| value.to_string()).unwrap_or_default()
                            )
                            .as_bytes()
                        ))
                    )
                });
            redacted.push(json!({
                "digest": digest,
                "rule": rule,
                "file": file,
                "line": line,
            }));
        }
        output.candidates.extend(redacted.iter().cloned());
        output
            .details
            .insert("secretCandidates".into(), Value::Array(redacted));
        output.complete = true;
        return true;
    }
    let object = match value.as_object() {
        Some(value) => value,
        None => return false,
    };
    let Some(complete) = object.get("complete").and_then(Value::as_bool) else {
        output
            .coverage_gaps
            .push("external-output-envelope-invalid".into());
        output.complete = false;
        return true;
    };
    output.details.insert("toolOutput".into(), value.clone());
    if let Some(gaps) = object.get("coverageGaps").and_then(Value::as_array) {
        output.coverage_gaps.extend(gaps.iter().map(|gap| {
            gap.as_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| gap.to_string())
        }));
    }
    if let Some(findings) = object.get("findings").and_then(Value::as_array) {
        for finding in findings {
            add_external_finding(input, finding, output);
        }
    }
    if let Some(candidates) = object.get("candidates").and_then(Value::as_array) {
        output.candidates.extend(candidates.iter().cloned());
    }
    output.complete = complete;
    if object.get("status").and_then(Value::as_str) == Some("error") {
        output.complete = false;
    }
    true
}

fn parse_text_output(
    input: &LegacyCheckInput,
    bytes: &[u8],
    output: &mut LegacyCheckOutput,
) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let mut parsed = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        parsed = true;
        let (path, line_number) = parse_tool_location(line, input.denominator.entries.first());
        if input.check == "repo" {
            output
                .details
                .insert("repositoryStatus".into(), Value::String(line.into()));
        } else if is_candidate_provider(input.provider_id.as_str()) {
            push_candidate(
                output,
                "legacy.tool-output",
                "medium",
                &path,
                line_number,
                line,
            );
        } else {
            let finding = finding_ref(input, "legacy.tool-output", &path, line_number, "warning");
            output.findings.push(finding.clone());
            add_evidence(
                output,
                input,
                &finding,
                &safe_location(input, &path),
                line_number,
                line,
            );
        }
    }
    output.complete = parsed || bytes.is_empty();
    parsed || bytes.is_empty()
}

fn add_external_finding(input: &LegacyCheckInput, value: &Value, output: &mut LegacyCheckOutput) {
    if is_candidate_provider(&input.provider_id) {
        output.candidates.push(value.clone());
        return;
    }
    let path = value
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            input
                .denominator
                .entries
                .first()
                .map(|entry| entry.path.as_str())
                .unwrap_or("provider-artifacts")
        });
    let line = value.get("line").and_then(Value::as_u64).unwrap_or(1) as usize;
    let rule = value
        .get("ruleId")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("legacy.tool-finding");
    let severity = value
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("warning");
    let finding = finding_ref(input, rule, path, line, severity);
    output.findings.push(finding.clone());
    add_evidence(
        output,
        input,
        &finding,
        &safe_location(input, path),
        line,
        &value.to_string(),
    );
}

fn add_evidence(
    output: &mut LegacyCheckOutput,
    input: &LegacyCheckInput,
    finding: &FindingRef,
    path: &str,
    line: usize,
    raw: &str,
) {
    let id = finding.id.to_string();
    let evidence = output
        .details
        .entry("findingEvidence".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(items) = evidence {
        items.insert(
            id.clone(),
            json!({"provider":input.provider_id,"path":path,"line":line,"detail":raw}),
        );
    }
    let locations = output
        .details
        .entry("findingLocations".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(items) = locations {
        items.insert(id, json!([format!("{path}:{line}")]));
    }
}

fn finding_ref(
    input: &LegacyCheckInput,
    rule: &str,
    path: &str,
    line: usize,
    severity: &str,
) -> FindingRef {
    let id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            format!("{}\0{}\0{}\0{}", input.provider_id, rule, path, line).as_bytes()
        ))
    );
    FindingRef {
        id: FindingId::new(id).expect("derived finding id is valid"),
        severity: severity.into(),
    }
}

fn push_finding(
    output: &mut LegacyCheckOutput,
    rule: &str,
    severity: &str,
    path: &str,
    line: usize,
    message: &str,
) {
    let id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(format!("{rule}\0{path}\0{line}").as_bytes()))
    );
    let finding = FindingRef {
        id: FindingId::new(id).expect("derived finding id is valid"),
        severity: severity.into(),
    };
    let finding_id = finding.id.to_string();
    output.findings.push(finding);
    output
        .details
        .entry("findingEvidence".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(Value::Object(items)) = output.details.get_mut("findingEvidence") {
        items.insert(
            finding_id.clone(),
            json!({"ruleId":rule,"path":path,"line":line,"message":message}),
        );
    }
    output
        .details
        .entry("findingLocations".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(Value::Object(items)) = output.details.get_mut("findingLocations") {
        items.insert(finding_id, json!([format!("{path}:{line}")]));
    }
}

fn push_candidate(
    output: &mut LegacyCheckOutput,
    rule: &str,
    severity: &str,
    path: &str,
    line: usize,
    claim: &str,
) {
    let id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(format!("{rule}\0{path}\0{line}").as_bytes()))
    );
    output.candidates.push(json!({"id":id,"ruleId":rule,"role":"candidate-generator","claim":claim,"severityHint":severity,"evidence":[{"file":path,"line":line}],"evidenceStrength":"candidate","verdict":"UNADJUDICATED","adjudicationRequired":true}));
}

fn safe_location(input: &LegacyCheckInput, path: &str) -> String {
    input
        .denominator
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.path.clone())
        .or_else(|| {
            input
                .denominator
                .entries
                .first()
                .map(|entry| entry.path.clone())
        })
        .unwrap_or_else(|| "provider-artifacts".into())
}

fn parse_tool_location(line: &str, fallback: Option<&InventoryEntry>) -> (String, usize) {
    if let Some((path, rest)) = line.split_once(':') {
        if let Some((number, _)) = rest.split_once(':') {
            if let Ok(line_number) = number.parse::<usize>() {
                return (path.to_owned(), line_number);
            }
        }
    }
    (
        fallback
            .map(|entry| entry.path.clone())
            .unwrap_or_else(|| "provider-artifacts".into()),
        1,
    )
}

fn is_candidate_provider(provider: &str) -> bool {
    spec(provider).is_some_and(|contract| contract.role.contains("candidate"))
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn occurrences(text: &str, needle: &str) -> Vec<usize> {
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(index) = text[offset..].find(needle) {
        let absolute = offset + index;
        result.push(absolute);
        offset = absolute + needle.len();
        if offset >= text.len() {
            break;
        }
    }
    result
}

fn first_line(text: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .filter_map(|needle| text.find(needle).map(|index| line_at(text, index)))
        .min()
        .unwrap_or(1)
}
fn first_nonempty_line(text: &str) -> usize {
    text.lines()
        .position(|line| !line.trim().is_empty())
        .map(|line| line + 1)
        .unwrap_or(1)
}
fn line_at(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
fn is_manifest(path: &str) -> bool {
    matches!(
        path.rsplit('/').next(),
        Some(
            "package.json"
                | "Cargo.toml"
                | "pyproject.toml"
                | "go.mod"
                | "pom.xml"
                | "composer.json"
        )
    )
}

fn quoted_invocations(text: &str, marker: &str) -> Vec<String> {
    occurrences(text, marker)
        .into_iter()
        .filter_map(|offset| {
            let remainder = &text[offset + marker.len()..];
            let quote = remainder.chars().next()?;
            if quote != '\'' && quote != '"' {
                return None;
            }
            let value = remainder[1..].split(quote).next()?.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect()
}

fn annotated_rust_functions(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for offset in occurrences(text, "#[tauri::command]") {
        if let Some(function) = text[offset..].find("fn ") {
            let rest = &text[offset + function + 3..];
            let name = rest
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .next()
                .unwrap_or_default();
            if !name.is_empty() {
                names.push(name.to_owned());
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn provider(id: &str, selector: Value) -> AuditProvider {
        let contract = spec(id).expect("frozen provider");
        AuditProvider {
            id: id.into(),
            version: "2.0.0".into(),
            role: contract.role.into(),
            phase: contract.phase.into(),
            lens_ids: Vec::new(),
            dependencies: Vec::new(),
            kind: crate::plan::ProviderKind::TypedExternalProjectTool,
            configuration: BTreeMap::from([
                ("selector".into(), selector),
                (
                    "runner".into(),
                    json!({"kind":"legacy-check","check":contract.check}),
                ),
            ]),
            bounds: BTreeMap::new(),
            clean_claim: "evidence-only".into(),
            benchmark_status: "unproven".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: false,
        }
    }

    fn temp_root() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("legion-native-legacy-{suffix}"));
        fs::create_dir_all(root.join("src-tauri")).unwrap();
        root
    }

    #[test]
    fn native_provider_emits_real_candidate_and_frozen_denominator() {
        let root = temp_root();
        fs::write(
            root.join("src-tauri/frontend.ts"),
            "invoke('missing_command');",
        )
        .unwrap();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "generation",
            vec![InventoryEntry {
                path: "src-tauri/frontend.ts".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            }],
        )
        .unwrap();
        let selected = inventory
            .denominator_entries(&json!({"op":"anyPath","patterns":["src-tauri/**"]}))
            .unwrap();
        let provider = provider(
            "legacy.tauri.contract-mirror",
            json!({"op":"anyPath","patterns":["src-tauri/**"]}),
        );
        let result = NativeLegacyCheckExecutor::new(&root)
            .execute(&provider, &inventory)
            .unwrap();
        assert_eq!(result.provider.to_string(), provider.id);
        assert_eq!(
            result.coverage.as_ref().unwrap().denominator_digest,
            selected.digest
        );
        assert!(result.complete);
        assert!(!result
            .details
            .get("candidates")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_external_tool_is_an_incomplete_typed_result() {
        let root = temp_root();
        fs::write(root.join("package.json"), "{}").unwrap();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "generation",
            vec![InventoryEntry {
                path: "package.json".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: false,
                digest: None,
            }],
        )
        .unwrap();
        let provider = provider(
            "legacy.quality.build",
            json!({"op":"anyPath","patterns":["**/package.json"]}),
        );
        let result = NativeLegacyCheckExecutor::new(&root)
            .execute(&provider, &inventory)
            .unwrap();
        assert!(!result.complete);
        assert!(result
            .details
            .get("processState")
            .and_then(Value::as_str)
            .is_some());
        assert!(result.coverage.as_ref().unwrap().expected > 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn every_frozen_legacy_id_is_dispatchable() {
        let dispatcher = LegacyCheckDispatcher::new();
        assert_eq!(specs().len(), 32);
        for contract in specs() {
            assert!(dispatcher.contains(contract.provider_id));
        }
    }
}

fn command_name(command: CommandShape) -> &'static str {
    match command {
        CommandShape::Native { .. } => "native",
        CommandShape::Fixed { .. } => "fixed",
        CommandShape::Named { .. } => "named",
    }
}
