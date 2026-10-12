use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use legion_audit::{
    native_providers::legacy_checks::{
        AttestedRunsEnrollment, AuditExternalProjectTool, AuditScratch, NativeLegacyCheckExecutor,
    },
    AuditPlan, FilesystemInventorySource, InventoryEntry, InventoryEnvelope, InventorySource,
    NativeProviderRegistry,
};
use legion_effects::{DigestState, ExecutableIdentity, SignatureState, VersionProbeEvidence};
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use serde_json::json;
use sha2::Digest;
use tokio_util::sync::CancellationToken;

/// Parallel tests must never share a scratch root (clock resolution alone collides).
static ROOT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "legion-external-test-{}-{nonce}-{}",
        std::process::id(),
        ROOT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn enrollment(root: &Path, schema_version: u32, client_name: &str) -> AttestedRunsEnrollment {
    enrollment_with(
        root,
        schema_version,
        client_name,
        "33".repeat(32),
        json!({}),
    )
}

fn enrollment_with(
    root: &Path,
    schema_version: u32,
    client_name: &str,
    client_digest: String,
    adapters: serde_json::Value,
) -> AttestedRunsEnrollment {
    let public_key = format!("04{}", "11".repeat(64));
    let key_id = hex::encode(sha2::Sha256::digest(hex::decode(&public_key).unwrap()));
    serde_json::from_value(json!({
        "schemaVersion":schema_version,
        "host":"fixture-host",
        "keyId":key_id,
        "publicKey":public_key,
        "brokerDigest":"22".repeat(32),
        "clientExecutable":root.join(client_name),
        "clientDigest":client_digest,
        "adapters":adapters
    }))
    .unwrap()
}

fn inventory() -> InventoryEnvelope {
    InventoryEnvelope::new(
        "repo",
        "generation",
        vec![InventoryEntry {
            path: "package.json".into(),
            symbols: vec![],
            dependencies: vec![],
            package_scripts: vec![],
            source_file: false,
            digest: None,
        }],
    )
    .unwrap()
}

struct FakeTool {
    state: ExecutionState,
    body: Option<Vec<u8>>,
}

struct CapturingTool {
    request: Arc<Mutex<Option<ExternalToolRequest>>>,
}

#[async_trait]
impl ExternalProjectTool for CapturingTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        _cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        *self.request.lock().unwrap() = Some(request.clone());
        ExecutionReceipt::failure(&request, ExecutionState::Internal, "captured")
    }
}

#[async_trait]
impl ExternalProjectTool for FakeTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        let mut receipt = ExecutionReceipt::failure(&request, self.state, self.state.as_str());
        receipt.process_tree.started = self.state == ExecutionState::Completed;
        receipt.process_tree.terminated = receipt.process_tree.started;
        receipt.process_tree.reaped = receipt.process_tree.started;
        receipt.parser.attempted = self.body.is_some();
        receipt.parser.succeeded = self.body.is_some();
        if self.state == ExecutionState::Completed {
            receipt.gaps.clear();
            receipt.complete = true;
            if let Some(body) = &self.body {
                let path = PathBuf::from(&request.cwd).join("stdout.json");
                fs::write(&path, body).unwrap();
                receipt.stdout = Some(legion_effects::ArtifactRecord {
                    path: "stdout.json".into(),
                    digest: format!("sha256:{}", hex::encode(sha2::Sha256::digest(body))),
                    bytes: body.len(),
                    immutable: true,
                });
            }
        }
        if cancellation.is_cancelled() {
            receipt.state = ExecutionState::Cancelled;
            receipt.complete = false;
        }
        receipt
    }
}

struct TestRunTool {
    exit_code: i32,
    request: Arc<Mutex<Option<ExternalToolRequest>>>,
    version_output: Option<String>,
}

#[async_trait]
impl ExternalProjectTool for TestRunTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        _cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        *self.request.lock().unwrap() = Some(request.clone());
        let mut receipt = ExecutionReceipt::failure(
            &request,
            ExecutionState::Completed,
            "fixture test runner exited normally",
        );
        receipt.gaps.clear();
        receipt.complete = true;
        receipt.exit_code = Some(self.exit_code);
        receipt.process_tree.started = true;
        receipt.process_tree.terminated = true;
        receipt.process_tree.reaped = true;
        receipt.executable = Some(ExecutableIdentity {
            requested_path: request.executable.clone(),
            canonical_path: Some(PathBuf::from(&request.executable)),
            digest: request.expected_digest.clone(),
            digest_state: if request.expected_digest.is_some() {
                DigestState::Sealed
            } else {
                DigestState::Unchecked
            },
            signature: SignatureState::Unknown,
            version: VersionProbeEvidence {
                args: request.version_args.clone(),
                output: self.version_output.clone().or_else(|| {
                    request.version_requirement.as_deref().map(|requirement| {
                        requirement
                            .strip_prefix("exact:")
                            .unwrap_or(requirement)
                            .to_owned()
                    })
                }),
                exit_code: Some(0),
                qualified: true,
            },
        });
        receipt
    }
}

fn plan_for(
    inventory: &InventoryEnvelope,
    id: &str,
    check: &str,
    role: &str,
) -> legion_audit::FrozenPlan {
    AuditPlan::compile(inventory, &[serde_json::from_value(json!({
        "schemaVersion":2,"id":id,"providerVersion":"2.0.0","family":"legacy","role":role,"phase":"source","lensIds":[if role == "candidate-generator" { "security" } else { "installer-hygiene" }],"dependsOn":[],"consumes":["repository-inventory"],"produces":["provider-result"],"selector":if id == "legacy.quality.test" { json!({"op":"any","selectors":[{"op":"anyPackageScript","names":["test"]},{"op":"anyPath","patterns":["package.json","Cargo.toml","src-tauri/Cargo.toml"]}]}) } else { json!({"op":"always"}) },"denominatorKind":"repository-inventory","runner":{"kind":"legacy-check","check":check},"hostCapabilities":[],"execution":{},"reasoning":{},"benchmark":{"status":"unproven","requiredForCleanClaim":false},"cleanClaim":"evidence-only","controlIds":[],"scopes":[],"selectable":true
    })).unwrap()]).unwrap().freeze(Some(b"test-key")).unwrap()
}

fn plan(inventory: &InventoryEnvelope) -> legion_audit::FrozenPlan {
    plan_for(inventory, "legacy.quality.build", "build", "deterministic")
}

#[test]
fn completed_receipt_reads_immutable_stdout_and_projects_result() {
    let root = root();
    fs::write(root.join("package.json"), "{}").unwrap();
    let inventory = inventory();
    let plan = plan(&inventory);
    let body = br#"{"complete":true,"status":"ok","coverageGaps":[]}"#.to_vec();
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Completed,
            body: Some(body),
        }));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = &report.results[0].result;
    assert!(result.complete);
    assert_eq!(result.coverage.as_ref().unwrap().examined, 1);
    assert!(result.details["executionReceipt"]["requestId"]
        .as_str()
        .unwrap()
        .starts_with("audit:"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn terminal_states_remain_incomplete_and_typed() {
    for state in [
        ExecutionState::MissingExecutable,
        ExecutionState::UnauthorizedEffect,
        ExecutionState::Timeout,
        ExecutionState::Cancelled,
        ExecutionState::OutputLimited,
        ExecutionState::ArtifactFailed,
    ] {
        let root = root();
        fs::write(root.join("package.json"), "{}").unwrap();
        let inventory = inventory();
        let plan = plan(&inventory);
        let registry = NativeProviderRegistry::new(&root)
            .with_external_project_tool(Arc::new(FakeTool { state, body: None }));
        let report = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(legion_audit::execute_with_cancellation(
                &plan,
                &inventory,
                &registry,
                CancellationToken::new(),
            ))
            .unwrap();
        assert!(!report.results[0].result.complete);
        assert!(!report.results[0].result.coverage_gaps.is_empty());
        assert_eq!(
            report.results[0].result.details["executionReceipt"]["state"],
            state.as_str()
        );
        fs::remove_dir_all(root).unwrap();
    }
}

/// Refuses before any process starts, the way the effect layer does when a
/// network-sandboxed check has no sandbox (Windows has no sandbox).
struct SandboxRefusedTool;

#[async_trait]
impl ExternalProjectTool for SandboxRefusedTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        _cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        ExecutionReceipt::failure(
            &request,
            ExecutionState::SandboxMissing,
            "network sandbox receipt is required",
        )
    }
}

#[test]
fn sandbox_refusal_is_typed_unavailable_not_a_failed_provider() {
    let root = root();
    fs::write(root.join("package.json"), "{}").unwrap();
    let inventory = inventory();
    let plan = plan(&inventory);
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(SandboxRefusedTool));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = &report.results[0].result;
    assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
    assert!(!result.complete);
    assert!(
        result
            .coverage_gaps
            .iter()
            .any(|gap| gap.starts_with("unavailable:sandbox-missing:")),
        "{:?}",
        result.coverage_gaps
    );
    assert!(
        !result
            .coverage_gaps
            .iter()
            .any(|gap| gap == "external-process:unauthorized_effect"),
        "{:?}",
        result.coverage_gaps
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn untyped_json_can_never_become_a_false_clean() {
    let root = root();
    fs::write(root.join("package.json"), "{}").unwrap();
    let inventory = inventory();
    let plan = plan(&inventory);
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Completed,
            body: Some(br#"{"status":"ok"}"#.to_vec()),
        }));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = &report.results[0].result;
    assert!(!result.complete);
    assert!(
        result
            .coverage_gaps
            .iter()
            .any(|gap| gap == "external-output-envelope-invalid"),
        "{result:?}"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn gitleaks_json_is_redacted_before_projection() {
    let root = root();
    fs::write(root.join("package.json"), "{}").unwrap();
    let inventory = inventory();
    let plan = plan_for(
        &inventory,
        "legacy.security.secrets",
        "secrets",
        "candidate-generator",
    );
    let body = br#"[{"Fingerprint":"fingerprint","RuleID":"token","File":"src/main.rs","StartLine":7,"Secret":"must-not-survive","Match":"must-not-survive"}]"#.to_vec();
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Completed,
            body: Some(body),
        }));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = &report.results[0].result;
    assert!(result.complete);
    assert_eq!(result.details["candidates"][0]["digest"], "fingerprint");
    let serialized = serde_json::to_string(result).unwrap();
    assert!(!serialized.contains("must-not-survive"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn production_adapter_resolves_and_seals_symbolic_request() {
    let root = root();
    let bin = root.join("node_modules/.bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(
        root.join("package.json"),
        r#"{"packageManager":"pnpm@11.18.0","scripts":{"build":"build"}}"#,
    )
    .unwrap();
    fs::write(bin.join("pnpm"), "fixture package manager").unwrap();
    let captured = Arc::new(Mutex::new(None));
    let adapter = AuditExternalProjectTool::new(CapturingTool {
        request: Arc::clone(&captured),
    });
    let request = ExternalToolRequest {
        request_id: "audit:provider:plan:inventory".into(),
        provider_id: "legacy.quality.build".into(),
        plan_id: "plan".into(),
        policy_id: "audit".into(),
        executable: "project-build".into(),
        cwd: root.to_string_lossy().into_owned(),
        ..ExternalToolRequest::default()
    };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(adapter.execute(request, CancellationToken::new()));
    let request = captured.lock().unwrap().clone().unwrap();
    assert!(PathBuf::from(&request.executable).is_absolute());
    assert_eq!(
        request.args,
        ["--config.verify-deps-before-run=false", "run", "build"]
    );
    assert!(request
        .expected_digest
        .as_deref()
        .is_some_and(|digest| digest.starts_with("sha256:")));
    assert!(request.request_id.starts_with("legion-audit/"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_test_without_trust_has_no_start_receipt_or_tree_writes() {
    let root = root();
    fs::write(
        root.join("package.json"),
        r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"vitest"}}"#,
    )
    .unwrap();
    let before = fs::read(root.join("package.json")).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory("fixture")
        .unwrap();
    let plan = plan_for(&inventory, "legacy.quality.test", "test", "deterministic");
    let request = Arc::new(Mutex::new(None));
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(TestRunTool {
            exit_code: 0,
            request: Arc::clone(&request),
            version_output: None,
        }));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = &report.results[0].result;
    assert!(!result.complete);
    assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
    assert!(result.findings.is_empty());
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "unavailable:managed-test-trust-not-configured"));
    assert_eq!(
        result.details["availability"],
        json!({"state":"unavailable","reason":"managed-test-trust-not-configured"})
    );
    assert_eq!(result.details["processState"], "missing_executable");
    let receipt = &result.details["executionReceipt"];
    assert_eq!(receipt["kind"], "external-tool-refusal-receipt");
    assert_eq!(receipt["state"], "missing_executable");
    assert_eq!(receipt["complete"], false);
    assert_eq!(receipt["processTree"]["started"], false);
    assert_eq!(receipt["parser"]["attempted"], false);
    assert_eq!(receipt["parser"]["succeeded"], false);
    assert_eq!(receipt["executable"]["digestState"], "not-checked");
    assert_eq!(receipt["executable"]["version"]["qualified"], false);
    assert!(receipt["stdout"].is_null());
    assert!(receipt["stderr"].is_null());
    assert!(result.details.get("executionError").is_none());
    assert!(result
        .coverage_gaps
        .iter()
        .all(|gap| !gap.contains("invalid-provider-result")
            && !gap.contains("external-process:cleanup_unconfirmed")));
    assert!(request.lock().unwrap().is_none(), "test runner was invoked");
    assert_eq!(fs::read(root.join("package.json")).unwrap(), before);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_enrollment_fails_before_copy_or_client_call() {
    let root = root();
    fs::write(
        root.join("package.json"),
        r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"vitest"}}"#,
    )
    .unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory("fixture")
        .unwrap();
    let plan = plan_for(&inventory, "legacy.quality.test", "test", "deterministic");
    let request = Arc::new(Mutex::new(None));
    let invalid = enrollment(&root, 2, "missing-rightkit");
    let registry = NativeProviderRegistry::new(&root)
        .with_external_project_tool(Arc::new(TestRunTool {
            exit_code: 0,
            request: Arc::clone(&request),
            version_output: None,
        }))
        .with_attested_runs(invalid.clone());
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = &report.results[0].result;
    assert!(!result.complete);
    assert_eq!(result.status, legion_contracts::ProviderStatus::Failed);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("test-enrollment-invalid:")));
    assert_eq!(result.details["testCommandResolution"]["status"], "invalid");
    assert!(result.details.get("availability").is_none());
    assert_eq!(result.details["executionReceipt"]["state"], "failed");
    assert_eq!(
        result.details["executionReceipt"]["processTree"]["started"],
        false
    );
    assert_eq!(
        result.details["executionReceipt"]["parser"]["attempted"],
        false
    );
    assert!(request.lock().unwrap().is_none());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    let sync_result = NativeLegacyCheckExecutor::new(&root)
        .with_attested_runs(invalid)
        .execute(plan.provider("legacy.quality.test").unwrap(), &inventory)
        .unwrap();
    assert_eq!(sync_result.status, legion_contracts::ProviderStatus::Failed);
    assert!(sync_result
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("test-enrollment-invalid:")));
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_attested_client_is_typed_unavailable_before_copy_or_tool_call() {
    let root = root();
    fs::write(
        root.join("package.json"),
        r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"vitest"}}"#,
    )
    .unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory("fixture")
        .unwrap();
    let plan = plan_for(&inventory, "legacy.quality.test", "test", "deterministic");
    let request = Arc::new(Mutex::new(None));
    let registry = NativeProviderRegistry::new(&root)
        .with_external_project_tool(Arc::new(TestRunTool {
            exit_code: 0,
            request: Arc::clone(&request),
            version_output: None,
        }))
        .with_attested_runs(enrollment(&root, 1, "missing-rightkit"));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = &report.results[0].result;
    assert!(!result.complete);
    assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| { gap == "unavailable:managed-test-attestation-cli-unavailable" }));
    assert_eq!(
        result.details["executionReceipt"]["processTree"]["started"],
        false
    );
    assert_eq!(
        result.details["executionReceipt"]["parser"]["attempted"],
        false
    );
    assert!(request.lock().unwrap().is_none());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn enrolled_runner_registration_and_version_gaps_do_not_copy_or_launch() {
    for (adapters, expected_reason) in [
        (json!({}), "managed-test-runner-not-registered:pnpm"),
        (
            json!({"pnpm":{"brokerAdapterId":"pnpm-test-adapter","qualifiedVersion":"9.0.0"}}),
            "managed-test-runner-version-mismatch:pnpm",
        ),
    ] {
        let root = root();
        fs::write(
            root.join("package.json"),
            r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"vitest"}}"#,
        )
        .unwrap();
        let client = root.join("trusted-bin/rightkit");
        fs::create_dir_all(client.parent().unwrap()).unwrap();
        let bytes = b"fixture rightkit client";
        fs::write(&client, bytes).unwrap();
        let client_digest = hex::encode(sha2::Sha256::digest(bytes));
        let inventory = FilesystemInventorySource::new(&root)
            .unwrap()
            .inventory("fixture")
            .unwrap();
        let plan = plan_for(&inventory, "legacy.quality.test", "test", "deterministic");
        let request = Arc::new(Mutex::new(None));
        let scratch_path = root.with_file_name(format!(
            "{}-scratch",
            root.file_name().unwrap().to_string_lossy()
        ));
        let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &scratch_path).unwrap());
        let registry = NativeProviderRegistry::new(&root)
            .with_scratch(Arc::clone(&scratch))
            .with_external_project_tool(Arc::new(TestRunTool {
                exit_code: 0,
                request: Arc::clone(&request),
                version_output: None,
            }))
            .with_attested_runs(enrollment_with(
                &root,
                1,
                "trusted-bin/rightkit",
                client_digest,
                adapters,
            ));
        let report = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(legion_audit::execute_with_cancellation(
                &plan,
                &inventory,
                &registry,
                CancellationToken::new(),
            ))
            .unwrap();
        let result = &report.results[0].result;
        assert!(!result.complete);
        assert_eq!(result.status, legion_contracts::ProviderStatus::Partial);
        assert!(result
            .coverage_gaps
            .iter()
            .any(|gap| gap == &format!("unavailable:{expected_reason}")));
        assert_eq!(
            result.details["executionReceipt"]["state"],
            "missing_executable"
        );
        assert_eq!(
            result.details["executionReceipt"]["processTree"]["started"],
            false
        );
        assert_eq!(
            result.details["executionReceipt"]["parser"]["attempted"],
            false
        );
        assert!(request.lock().unwrap().is_none());
        assert!(fs::read_dir(&scratch_path).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("test-copy-")
        }));
        fs::remove_dir_all(scratch_path).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn rust_managed_tests_without_trust_refuse_before_copy_or_tool_call() {
    let root = root();
    fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
    fs::write(root.join("Cargo.toml"), "[package]\nname='fixture'\n").unwrap();
    fs::write(root.join("node_modules/.bin/rightkit"), "fixture rightkit").unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory("fixture")
        .unwrap();
    let plan = plan_for(&inventory, "legacy.quality.test", "test", "deterministic");
    let request = Arc::new(Mutex::new(None));
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(TestRunTool {
            exit_code: 0,
            request: Arc::clone(&request),
            version_output: None,
        }));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    let result = &report.results[0].result;
    assert!(!result.complete);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| { gap == "unavailable:managed-test-trust-not-configured" }));
    assert_eq!(
        result.details["availability"]["reason"],
        "managed-test-trust-not-configured"
    );
    assert_eq!(
        result.details["executionReceipt"]["processTree"]["started"],
        false
    );
    assert_eq!(
        result.details["executionReceipt"]["parser"]["attempted"],
        false
    );
    assert!(request.lock().unwrap().is_none());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn candidate_generator_reports_audit_hits_as_candidates_never_findings() {
    let root = root();
    fs::write(root.join("package.json"), "{}").unwrap();
    let inventory = inventory();
    let plan = plan_for(
        &inventory,
        "legacy.security.node-dependencies",
        "deps_cve",
        "candidate-generator",
    );
    let body = br#"{"metadata":{"vulnerabilities":{"total":2}}}"#.to_vec();
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(FakeTool {
            state: ExecutionState::Completed,
            body: Some(body),
        }));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(legion_audit::execute_with_cancellation(
            &plan,
            &inventory,
            &registry,
            CancellationToken::new(),
        ))
        .unwrap();
    assert!(
        !report
            .gaps
            .iter()
            .any(|gap| gap.starts_with("invalid-provider-result:")),
        "{:?}",
        report.gaps
    );
    let result = &report.results[0].result;
    assert!(result.findings.is_empty());
    assert_eq!(result.details["candidates"].as_array().unwrap().len(), 1);
    fs::remove_dir_all(root).unwrap();
}
