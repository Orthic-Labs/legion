use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use legion_audit::{
    native_providers::legacy_checks::AuditExternalProjectTool, AuditPlan, InventoryEntry,
    InventoryEnvelope, NativeProviderRegistry,
};
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

fn plan_for(
    inventory: &InventoryEnvelope,
    id: &str,
    check: &str,
    role: &str,
) -> legion_audit::FrozenPlan {
    AuditPlan::compile(inventory, &[serde_json::from_value(json!({
        "schemaVersion":2,"id":id,"providerVersion":"2.0.0","family":"legacy","role":role,"phase":"source","lensIds":[if role == "candidate-generator" { "security" } else { "installer-hygiene" }],"dependsOn":[],"consumes":["repository-inventory"],"produces":["provider-result"],"selector":{"op":"always"},"denominatorKind":"repository-inventory","runner":{"kind":"legacy-check","check":check},"hostCapabilities":[],"execution":{},"reasoning":{},"benchmark":{"status":"unproven","requiredForCleanClaim":false},"cleanClaim":"evidence-only","controlIds":[],"scopes":[],"selectable":true
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
    assert!(request.request_id.starts_with(".cache/legion-audit/"));
    fs::remove_dir_all(root).unwrap();
}
