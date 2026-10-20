//! Genuine pinned RustRight jobs over native disposable-copy SDK controls.
//! Explicit fixture admission only; production CLI admission remains denied.
#![cfg(unix)]

use legion_audit::native_providers::legacy_checks::{
    AttestedRunsEnrollment, AuditExternalProjectTool, AuditScratch,
};
use legion_audit::{
    execute_with_cancellation, AuditPlan, FilesystemInventorySource, InventorySource,
    NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision};
use legion_provider_sdk::{ExecutionReceipt, ExternalProjectTool};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const ID: &str = "legacy.quality.test";
const POLICY: &str = "legion-quality-test-constructed-sdk-v1";
const HARNESS: &str = "engine/crates/legion-audit/tests/real_quality_test_accuracy.rs";
const VALIDATOR: &str = "scripts/ci/audit-quality-test-accuracy.py";
const CORPUS: &str = "engine/crates/legion-audit/tests/fixtures/quality-test/controls.json";

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn canonical(value: &Value) -> Vec<u8> {
    legion_audit::canonical_bytes(value).unwrap()
}
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            assert!(!path.is_symlink());
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/"),
                    sha(&fs::read(path).unwrap()),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}
fn registry() -> Value {
    let value: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    value["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == ID)
        .unwrap()
        .clone()
}
fn generated_session_provenance(relative: &Path) -> bool {
    relative.parent()
        == Some(Path::new(
            "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance",
        ))
        && relative
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(|name| {
                name.len() == 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

fn bind_source_tree(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
    assert!(!path.is_symlink(), "source binding refuses symlinks");
    if path.is_file() && generated_session_provenance(path.strip_prefix(root).unwrap()) {
        return;
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            bind_source_tree(root, &entry.unwrap().path(), files);
        }
    } else {
        files.insert(
            path.strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/"),
            sha(&fs::read(path).unwrap()),
        );
    }
}

#[test]
fn source_binding_excludes_only_regular_generated_session_receipts() {
    fn snapshot(root: &Path) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        bind_source_tree(root, root, &mut files);
        files
    }
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let base = std::env::var_os("RUNNER_TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let scratch = Scratch(base.join(format!(
        "legion-sdk-source-binding-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    let root = &scratch.0;
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    let source = root.join("engine/crates/legion-audit/src/mod.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, b"pub fn source() {}\n").unwrap();
    let baseline = snapshot(root);
    let receipt = root.join(format!("{prefix}{}.json", "0123456789abcdef".repeat(4)));
    fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    fs::write(&receipt, b"generated receipt").unwrap();
    assert_eq!(snapshot(root), baseline);
    fs::write(&receipt, b"different host receipt").unwrap();
    assert_eq!(snapshot(root), baseline);
    fs::remove_file(&receipt).unwrap();
    fs::create_dir(&receipt).unwrap();
    fs::write(receipt.join("nested.rs"), b"retained child").unwrap();
    assert_eq!(snapshot(root).len(), baseline.len() + 1);
    fs::remove_dir_all(&receipt).unwrap();
    for relative in [
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.JSON", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}{}.json", "a".repeat(65)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("nested/{prefix}{}.json", "a".repeat(64)),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"must remain bound").unwrap();
        let before = snapshot(root);
        assert_eq!(before.len(), baseline.len() + 1, "{relative}");
        fs::write(&path, b"changed retained bytes").unwrap();
        assert_ne!(snapshot(root), before, "{relative}");
        fs::remove_file(path).unwrap();
    }
    // A Unix backslash is filename data, even when display normalization looks generated.
    #[cfg(unix)]
    for relative in [
        format!(
            r"engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance\{}.json",
            "a".repeat(64)
        ),
        format!(
            r"engine\crates/legion-audit/src/.audit/arcane/receipts/session-provenance/{}.json",
            "a".repeat(64)
        ),
        format!(
            r"engine\crates\legion-audit\src\.audit\arcane\receipts\session-provenance\{}.json",
            "a".repeat(64)
        ),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"literal backslash source").unwrap();
        let before = snapshot(root);
        assert_eq!(before.len(), baseline.len() + 1, "{relative}");
        fs::write(&path, b"changed literal backslash source").unwrap();
        assert_ne!(snapshot(root), before, "{relative}");
        fs::remove_file(path).unwrap();
    }
    assert_eq!(snapshot(root), baseline);
    fs::write(&source, b"pub fn changed_source() {}\n").unwrap();
    assert_ne!(snapshot(root), baseline);
    std::os::unix::fs::symlink(&source, &receipt).unwrap();
    assert!(std::panic::catch_unwind(|| snapshot(root)).is_err());
    fs::remove_file(receipt).unwrap();
}

fn binding() -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = BTreeMap::new();
    for name in [
        "legion-audit",
        "legion-effects",
        "legion-provider-sdk",
        "legion-contracts",
        "legion-rules",
    ] {
        let prefix = format!("engine/crates/{name}/src");
        bind_source_tree(&root, &root.join(&prefix), &mut files);
        let path = format!("engine/crates/{name}/Cargo.toml");
        files.insert(path.clone(), sha(&fs::read(root.join(path)).unwrap()));
    }
    for prefix in ["src/registry/rules", "src/registry/controls"] {
        bind_source_tree(&root, &root.join(prefix), &mut files);
    }
    for path in [
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/rust-toolchain.toml",
        HARNESS,
        VALIDATOR,
        CORPUS,
        "scripts/ci/provision-quality-test-native.py",
        "scripts/ci/tests/test_quality_test_interruption.py",
    ] {
        files.insert(path.to_owned(), sha(&fs::read(root.join(path)).unwrap()));
    }
    let mut spec = registry();
    spec.as_object_mut().unwrap().remove("benchmark");
    json!({"providerSpecDigest":sha(&canonical(&spec)),"providerSpec":spec,
        "sourcesDigest":sha(&canonical(&json!(files))),"sources":files,"fixture":HARNESS})
}
fn request_json(r: &ExternalToolRequest) -> Value {
    json!({"requestId":r.request_id,"providerId":r.provider_id,"planId":r.plan_id,
        "policyId":r.policy_id,"taskId":r.task_id,"executable":r.executable,"args":r.args,
        "cwd":r.cwd,"shell":r.shell,"expectedDigest":r.expected_digest,
        "environment":r.environment,"environmentAllowlist":r.environment_allowlist,
        "skipVersionProbe":r.skip_version_probe,"timeoutMs":r.timeout_ms,
        "requiresNetworkSandbox":r.requires_network_sandbox,"sandboxPresent":r.sandbox.is_some()})
}
fn receipt_json(r: &ExecutionReceipt) -> Value {
    json!({"receiptId":r.receipt_id,"requestId":r.request_id,"providerId":r.provider_id,
        "planId":r.plan_id,"taskId":r.task_id,"state":r.state.as_str(),"complete":r.complete,
        "policy":r.policy.as_ref().map(|p|json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "executable":r.executable.as_ref().map(|e|json!({"canonicalPath":e.canonical_path,"digest":e.digest,"versionSkipped":e.version.skipped_by_policy})),
        "cwd":r.cwd,"exitCode":r.exit_code,"signal":r.signal,"gaps":r.gaps,
        "processTree":{"started":r.process_tree.started,"terminated":r.process_tree.terminated,"reaped":r.process_tree.reaped,"hardKilled":r.process_tree.hard_killed,"detail":r.process_tree.detail},
        "timing":{"startedAtMs":r.timing.started_at_ms,"completedAtMs":r.timing.completed_at_ms,"durationMs":r.timing.duration_ms},
        "sandbox":{"required":r.sandbox.required,"receiptId":r.sandbox.receipt_id,"networkEnabled":r.sandbox.network_enabled},
        "stdout":r.stdout.as_ref().map(|a|json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr":r.stderr.as_ref().map(|a|json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable}))})
}

struct Policy {
    source: PathBuf,
    scratch: PathBuf,
    client: PathBuf,
    pin: String,
    plan: String,
    deny: bool,
    decisions: Mutex<Vec<Value>>,
}
impl PolicyAuthorizer for Policy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        let preparation = r.task_id.as_deref() == Some("managed-test-disposable-copy");
        let cwd = Path::new(&r.cwd);
        let operation = r.args.first().map(String::as_str).unwrap_or("");
        let allowed = !self.deny
            && !r.shell
            && r.provider_id == ID
            && r.plan_id == self.plan
            && Path::new(&r.executable) == self.client
            && if preparation {
                cwd == self.source && r.args == ["cargo", "test"]
            } else {
                cwd.starts_with(&self.scratch)
                    && cwd != self.scratch
                    && r.expected_digest.as_deref() == Some(self.pin.as_str())
                    && r.skip_version_probe
                    && matches!(
                        operation,
                        "request-digest" | "cargo" | "status" | "cancel" | "verify-receipt"
                    )
            };
        let decision = PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: sha(&canonical(
                &json!({"id":POLICY,"source":self.source,"scratch":self.scratch,
                "client":self.client,"pin":self.pin,"plan":self.plan,"deny":self.deny}),
            )),
            reason: Some(
                "explicit bounded constructed SDK control; no production admission claim".into(),
            ),
        };
        self.decisions.lock().unwrap().push(
            json!({"request":request_json(r),"allowed":allowed,"digest":decision.policy_digest}),
        );
        decision
    }
}
struct SharedPolicy(Arc<Policy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(r)
    }
}

// This transport always delegates to real native SDK effects. Negative controls mutate
// only explicitly recorded verifier input or sandbox requirement, never manufacture receipts.
struct Recording {
    inner: Arc<dyn ExternalProjectTool>,
    mode: String,
    events: Arc<Mutex<Vec<Value>>>,
    cancellation: CancellationToken,
    artifacts: PathBuf,
    retained: PathBuf,
    broker_logs: PathBuf,
    pending: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}
#[async_trait::async_trait]
impl ExternalProjectTool for Recording {
    async fn execute(
        &self,
        mut r: ExternalToolRequest,
        token: CancellationToken,
    ) -> ExecutionReceipt {
        let original = request_json(&r);
        let operation = r.args.first().cloned().unwrap_or_default();
        let verification_input = if operation == "verify-receipt" {
            Some(PathBuf::from(
                &r.args[r.args.iter().position(|v| v == "--receipt").unwrap() + 1],
            ))
        } else {
            None
        };
        let mut mutation = Value::Null;
        if operation == "verify-receipt" && self.mode.starts_with("tamper-") {
            let index = r.args.iter().position(|v| v == "--receipt").unwrap() + 1;
            let path = Path::new(&r.args[index]);
            let before = fs::read(path).unwrap();
            let mut value: Value = serde_json::from_slice(&before).unwrap();
            if self.mode == "tamper-signature" {
                let signature = value.pointer_mut("/receipt/provenance/signature/value");
                // Broker status embeds receipt either directly or under `receipt`.
                if let Some(signature) = signature {
                    *signature = json!("00".repeat(64));
                } else {
                    value["provenance"]["signature"]["value"] = json!("00".repeat(64));
                }
            } else {
                if let Some(payload) = value.pointer_mut("/receipt/provenance/payload") {
                    payload["outputDigest"] = json!("00".repeat(32));
                } else {
                    value["provenance"]["payload"]["outputDigest"] = json!("00".repeat(32));
                }
            }
            let after = serde_json::to_vec(&value).unwrap();
            fs::write(path, &after).unwrap();
            mutation = json!({"kind":self.mode,"before":before,"after":after});
        }
        if self.mode == "sandbox-missing" {
            r.requires_network_sandbox = true;
            r.sandbox = None;
        }
        let n = {
            let mut events = self.events.lock().unwrap();
            let n = events.len();
            events.push(json!({"originalRequest":original,"executedRequest":request_json(&r),"mutation":mutation,"receipt":null}));
            n
        };
        if self.mode == "cancellation" && operation == "cargo" {
            let cancellation = self.cancellation.clone();
            let events = self.events.clone();
            events.lock().unwrap()[n]["cancellation"] = json!({"delayMs":1500,"fired":false});
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(1500));
                events.lock().unwrap()[n]["cancellation"]["fired"] = json!(true);
                cancellation.cancel();
            });
            // Provider's cancellation select may drop this await. Retain the
            // genuine effect until its own bounded termination/reap completes.
            let inner = self.inner.clone();
            let events = self.events.clone();
            let (send, receive) = tokio::sync::oneshot::channel();
            let pending = tokio::spawn(async move {
                let receipt = inner.execute(r, token).await;
                events.lock().unwrap()[n]["receipt"] = receipt_json(&receipt);
                let _ = send.send(receipt);
            });
            self.pending.lock().unwrap().push(pending);
            return receive
                .await
                .expect("real cancellation effect receipt required");
        }
        let receipt = self.inner.execute(r, token).await;
        let mut broker_output = Value::Null;
        if let Some(input) = verification_input {
            let verification: Value = receipt
                .stdout
                .as_ref()
                .and_then(|a| fs::read(self.artifacts.join(&a.path)).ok())
                .and_then(|raw| serde_json::from_slice(&raw).ok())
                .unwrap_or(Value::Null);
            if verification["ok"] == true {
                let status: Value = serde_json::from_slice(&fs::read(&input).unwrap()).unwrap();
                let log = &status["receipt"]["output"]["log"];
                assert_eq!(log["truncated"], false, "complete broker output required");
                let path = PathBuf::from(log["path"].as_str().expect("real broker log required"));
                assert!(
                    log["bytes"].as_u64().unwrap() <= 8 * 1024 * 1024,
                    "qualification log bound exceeded"
                );
                assert!(
                    path.is_absolute()
                        && path.starts_with(&self.broker_logs)
                        && path != self.broker_logs
                );
                let relative = path.strip_prefix(&self.broker_logs).unwrap();
                let mut cursor = self.broker_logs.clone();
                for component in relative.components() {
                    assert!(matches!(component, std::path::Component::Normal(_)));
                    cursor.push(component);
                    assert!(!cursor.is_symlink());
                }
                assert!(fs::metadata(&path).unwrap().len() <= 8 * 1024 * 1024);
                let raw = fs::read(&path).unwrap();
                assert_eq!(raw.len() as u64, log["bytes"].as_u64().unwrap());
                assert_eq!(
                    sha(&raw),
                    format!(
                        "sha256:{}",
                        verification["payload"]["outputDigest"].as_str().unwrap()
                    )
                );
                let target = self.retained.join("broker-output.bin");
                assert!(!target.exists());
                fs::write(&target, &raw).unwrap();
                broker_output = json!({"originalPath":path,"logRoot":self.broker_logs,"statusInput":input,"file":"broker-output.bin","bytes":raw.len(),"digest":sha(&raw),"truncated":false});
            }
        }
        let mut events = self.events.lock().unwrap();
        events[n]["receipt"] = receipt_json(&receipt);
        events[n]["brokerOutput"] = broker_output;
        receipt
    }
}

fn fixture(contract: &Value, case: &Value) -> BTreeMap<String, String> {
    let mut files: BTreeMap<String, String> =
        serde_json::from_value(contract["commonFiles"].clone()).unwrap();
    files.insert(
        "src/lib.rs".into(),
        contract["programs"][case["program"].as_str().unwrap()]
            .as_str()
            .unwrap()
            .into(),
    );
    if let Some(extra) = case.get("files") {
        files.extend(serde_json::from_value::<BTreeMap<String, String>>(extra.clone()).unwrap());
    }
    files
}
fn case(base: &Path, contract: &Value, case: &Value, host_pin: &Value) -> Value {
    let id = case["id"].as_str().unwrap();
    let mode = case["mode"].as_str().unwrap();
    let dir = base.join(id);
    let root = dir.join("source");
    let run = dir.join("run");
    let files = fixture(contract, case);
    for (path, bytes) in &files {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry()).unwrap();
    let mut plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec]).unwrap();
    // Only bounds differ in timeout control; frozen selector & denominator remain original.
    if mode == "timeout" {
        plan.providers
            .iter_mut()
            .find(|p| p.id == ID)
            .unwrap()
            .bounds
            .insert("timeoutMs".into(), json!(2500));
    }
    let frozen = plan
        .freeze(Some(b"quality-test-explicit-constructed-sdk"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    assert!(provider.configuration["denominatorCount"].as_u64().unwrap() > 0);
    if let Some(change) = case.get("afterFreeze") {
        fs::write(
            root.join(change["path"].as_str().unwrap()),
            change["text"].as_str().unwrap(),
        )
        .unwrap();
    }
    let at_execution = snapshot(&root);
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let mut pin = host_pin.clone();
    if mode == "invalid-enrollment" {
        pin["schemaVersion"] = json!(0);
    }
    if mode == "client-pin-mismatch" {
        pin["clientDigest"] = json!("00".repeat(32));
    }
    if mode == "unregistered-runner" {
        pin["adapters"] = json!({});
    }
    let enrollment: AttestedRunsEnrollment = serde_json::from_value(pin.clone()).unwrap();
    let policy = Arc::new(Policy {
        source: root.clone(),
        scratch: run.clone(),
        client: PathBuf::from(host_pin["clientExecutable"].as_str().unwrap()),
        pin: format!("sha256:{}", host_pin["clientDigest"].as_str().unwrap()),
        plan: frozen.digest().into(),
        deny: mode == "admission-denied" || mode == "execution-denied",
        decisions: Mutex::new(Vec::new()),
    });
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
        SharedPolicy(policy.clone()),
    );
    let cancellation = CancellationToken::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let pending = Arc::new(Mutex::new(Vec::new()));
    let recording = Arc::new(Recording {
        inner: Arc::new(AuditExternalProjectTool::new(effects)),
        mode: mode.into(),
        events: events.clone(),
        cancellation: cancellation.clone(),
        artifacts: scratch.artifacts_dir(),
        pending: pending.clone(),
        retained: dir.clone(),
        broker_logs: fs::canonicalize(
            std::env::var_os("LEGION_QUALITY_TEST_BROKER_LOG_ROOT")
                .expect("explicit readable native owner broker log root required"),
        )
        .unwrap(),
    });
    let mut native = NativeProviderRegistry::new(&root)
        .with_scratch(scratch.clone())
        .with_external_project_tool(recording);
    if mode != "no-enrollment" {
        native = native.with_attested_runs(enrollment);
    }
    if mode != "admission-missing" {
        let prep = if mode == "execution-denied" {
            Arc::new(Policy {
                source: root.clone(),
                scratch: run.clone(),
                client: policy.client.clone(),
                pin: policy.pin.clone(),
                plan: frozen.digest().into(),
                deny: false,
                decisions: Mutex::new(Vec::new()),
            })
        } else {
            policy.clone()
        };
        native.legacy_checks = native.legacy_checks.with_fixture_policy_authorizer(prep);
    }
    let report = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let report = execute_with_cancellation(&frozen, &inventory, &native, cancellation)
            .await
            .unwrap();
        let effects = std::mem::take(&mut *pending.lock().unwrap());
        for effect in effects {
            tokio::time::timeout(Duration::from_secs(15), effect)
                .await
                .expect("bounded native cancellation cleanup completion required")
                .unwrap();
        }
        report
    });
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.planned_providers, vec![ID]);
    let result = &report.results[0].result;
    assert_eq!(
        snapshot(&root),
        at_execution,
        "test execution changed original fixture source"
    );
    let events = events.lock().unwrap().clone();
    let copies: BTreeMap<String, bool> = events
        .iter()
        .filter_map(|e| e["originalRequest"]["cwd"].as_str())
        .filter(|p| Path::new(p).starts_with(&run))
        .map(|p| (p.to_owned(), Path::new(p).exists()))
        .collect();
    let decisions = policy.decisions.lock().unwrap().clone();
    json!({"caseId":id,"control":case,"fixtureFiles":files,"sourceBeforeFreeze":before,
        "sourceAtExecution":at_execution,"sourceAfter":snapshot(&root),"inventory":inventory,
        "sourceRoot":root,"scratchRoot":run,"planDigest":frozen.digest(),"frozenProvider":provider,
        "enrollment":pin,"events":events,"decisions":decisions,"copyPathsAfter":copies,"nativeResult":result})
}

#[test]
#[ignore = "requires authenticated pinned installed RustRight enrollment & native managed broker; never fake client or receipts"]
fn real_quality_test_accuracy() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let contract: Value =
        serde_json::from_slice(&fs::read(repository.join(CORPUS)).unwrap()).unwrap();
    let out = PathBuf::from(
        std::env::var_os("LEGION_QUALITY_TEST_EVIDENCE")
            .expect("absolute fresh evidence directory required"),
    );
    assert!(
        out.is_absolute()
            && !out.exists()
            && !out.starts_with(fs::canonicalize(&repository).unwrap())
    );
    fs::create_dir_all(&out).unwrap();
    let out = fs::canonicalize(out).unwrap();
    let pin_path = PathBuf::from(
        std::env::var_os("LEGION_ATTESTED_RUNS_ENROLLMENT")
            .expect("explicit authentic external host enrollment required"),
    );
    assert!(
        pin_path.is_absolute()
            && !pin_path.starts_with(&out)
            && !pin_path.starts_with(fs::canonicalize(&repository).unwrap())
    );
    let enrollment =
        AttestedRunsEnrollment::load(&pin_path).expect("authentic public host pins required");
    enrollment.validate().unwrap();
    let pin: Value = serde_json::from_slice(&fs::read(&pin_path).unwrap()).unwrap();
    assert_eq!(
        sha(&canonical(&pin)),
        std::env::var("LEGION_QUALITY_TEST_EXPECTED_ENROLLMENT_SHA256")
            .expect("owner-pinned canonical enrollment digest required")
    );
    assert_eq!(
        sha(&fs::read(pin["clientExecutable"].as_str().unwrap()).unwrap()),
        format!("sha256:{}", pin["clientDigest"].as_str().unwrap())
    );
    let cases: Vec<Value> = contract["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|control| case(&out, &contract, control, &pin))
        .collect();
    let mut record = json!({"schema":"legion-quality-test-native-accuracy/1","provider":ID,
        "providerVersion":registry()["providerVersion"],"family":"quality-test-native","stage":"finding",
        "productionQualification":false,"wholeProviderQualified":false,"auditCleanClaim":false,
        "claimScope":"constructed native SDK controls with authentic RustRight attestation; original denominator",
        "modelCalls":0,"executionPath":"native-frozen-plan-disposable-copy-real-rustright",
        "admissionScope":"explicit constructed SDK authorizer; production owner admission remains unavailable",
        "osSandboxQualified":false,"binding":binding(),"hostEnrollmentDigest":sha(&canonical(&pin)),"hostEnrollment":pin,"evidenceRoot":out,"cases":cases});
    record["qualificationDigest"] = json!(sha(&canonical(&record)));
    fs::write(
        out.join("legacy_quality_test.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    println!(
        "QUALITY_TEST_NATIVE_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
}
