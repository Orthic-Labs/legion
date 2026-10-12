use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use legion_audit::{
    native_providers::legacy_checks::AuditExternalProjectTool, AuditPlan,
    FilesystemInventorySource, InventoryEntry, InventoryEnvelope, InventorySource,
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
    assert_eq!(request.args, ["run", "build"]);
    assert!(request
        .expected_digest
        .as_deref()
        .is_some_and(|digest| digest.starts_with("sha256:")));
    assert!(request.request_id.starts_with("legion-audit/"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn declared_tests_complete_with_pass_or_failure_evidence_without_tree_writes() {
    for exit_code in [0, 1] {
        let root = root();
        fs::write(
            root.join("package.json"),
            r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"vitest"}}"#,
        )
        .unwrap();
        fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        fs::write(root.join("node_modules/.bin/pnpm"), "fixture pnpm").unwrap();
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        let before = fs::read(root.join("package.json")).unwrap();
        let inventory = FilesystemInventorySource::new(&root)
            .unwrap()
            .inventory("fixture")
            .unwrap();
        let plan = plan_for(&inventory, "legacy.quality.test", "test", "deterministic");
        let request = Arc::new(Mutex::new(None));
        let registry =
            NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(TestRunTool {
                exit_code,
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
        assert!(result.complete, "{exit_code}: {:?}", result.coverage_gaps);
        assert_eq!(result.findings.len(), usize::from(exit_code != 0));
        let request = request.lock().unwrap();
        let request = request.as_ref().unwrap();
        if cfg!(target_os = "macos") {
            assert!(request.executable.ends_with("sandbox-exec"));
            assert!(request.args.ends_with(&["run".into(), "test".into()]));
        } else {
            assert_eq!(request.args, ["run", "test"]);
        }
        assert!(request.requires_network_sandbox);
        assert_eq!(request.version_requirement.as_deref(), Some("exact:9.1.0"));
        assert_eq!(
            result.details["testCommandSource"]["family"],
            "package-script"
        );
        if exit_code == 1 {
            let finding_id = result.findings[0].id.to_string();
            assert_eq!(
                result.details["findingEvidence"][&finding_id]["kind"],
                "project-test-failure"
            );
            assert_eq!(
                result.details["findingLocations"][&finding_id],
                json!(["package.json"])
            );
        }
        assert_eq!(fs::read(root.join("package.json")).unwrap(), before);
        assert_eq!(
            fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap(),
            "lockfileVersion: '9.0'\n"
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn package_manager_pin_mismatch_stays_typed_incomplete() {
    let root = root();
    fs::write(
        root.join("package.json"),
        r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"vitest"}}"#,
    )
    .unwrap();
    fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
    fs::write(root.join("node_modules/.bin/pnpm"), "fixture pnpm").unwrap();
    fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory("fixture")
        .unwrap();
    let plan = plan_for(&inventory, "legacy.quality.test", "test", "deterministic");
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(TestRunTool {
            exit_code: 0,
            request: Arc::new(Mutex::new(None)),
            version_output: Some("19.1.0\n".into()),
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
    assert!(result.findings.is_empty());
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "unavailable:test-runner-version-mismatch:test"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_declared_test_runner_stays_incomplete_and_typed() {
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
    let registry =
        NativeProviderRegistry::new(&root).with_external_project_tool(Arc::new(TestRunTool {
            exit_code: 0,
            request: Arc::new(Mutex::new(None)),
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
        .any(|gap| { gap.starts_with("unavailable:tool-missing:pnpm") }));
    assert_eq!(
        result.details["testCommandResolution"]["status"],
        "unavailable"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rust_tests_without_owner_containment_receipt_stay_incomplete() {
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
        .any(|gap| gap.starts_with("read-only-test-owner-unavailable")));
    assert_eq!(
        result.details["testCommandSource"]["family"],
        "rust-rightkit"
    );
    assert_eq!(
        result.details["testCommandSource"]["argv"],
        json!(["cargo", "test"])
    );
    assert!(request.lock().unwrap().is_none());
    assert!(fs::read_dir(&root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("target")
    }));
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
