//! Real Rust known-answer SDK controls. Native execution required; semantic unsafe soundness stays unproven.
#![cfg(target_os = "macos")]
use legion_audit::{
    execute_with_cancellation,
    native_providers::{
        code,
        legacy_checks::{AuditExternalProjectTool, AuditScratch},
        security::producer::SandboxPolicy,
    },
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{
    ArtifactRecord, ExecutionReceipt, ExternalToolRequest, PolicyAuthorizer, PolicyDecision,
    ToolOrigin,
};
use legion_provider_sdk::ExternalProjectTool;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::process::ExitStatusExt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
const SOURCE: &str = "engine/crates/legion-audit/tests/real_rust_code_accuracy.rs";
const FIXTURES: &str = "scripts/ci/fixtures/audit-rust-code-sdk";
const POLICY: &str = "legion-real-rust-code-fixture-v1";
const ID: &str = "code.rust";
const TASKS: [&str; 5] = ["metadata", "check", "lint", "test", "dependency"];
const CONTROLS: [&str; 19] = [
    "positive",
    "nonempty-clean",
    "dependency-positive",
    "dependency-nonempty-clean",
    "unsafe-assessment",
    "features",
    "targets",
    "compiler-failure",
    "test-failure",
    "malformed-lock",
    "missing-database",
    "tampered-database",
    "missing-tool",
    "tampered-tool",
    "changed-source",
    "audit-config",
    "rejected-admission",
    "absent-sandbox",
    "budget-exhausted",
];
fn digest(bytes: &[u8]) -> String {
    let hex = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(items) => {
                let sorted: BTreeMap<_, _> = items.iter().collect();
                let mut object = serde_json::Map::new();
                for (key, value) in sorted {
                    object.insert(key.clone(), ordered(value));
                }
                Value::Object(object)
            }
            Value::Array(items) => Value::Array(items.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).unwrap()
}

fn registry_spec(id: &str) -> Value {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap()
        .clone()
}

fn binding(id: &str, fixtures: &BTreeMap<String, String>) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink(), "source binding refuses symlinks");
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), files);
            }
        } else {
            files.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut sources = BTreeMap::new();
    for path in [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/rust-toolchain.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
        FIXTURES,
        "engine/crates/legion-audit/tests/fixtures/cargo-audit",
        "scripts/ci/provision-rust-code-fixtures.py",
        "scripts/ci/provision-python-qualification-tools.py",
        "scripts/ci/audit-pip-audit-provider-accuracy.py",
    ] {
        walk(&root, &root.join(path), &mut sources);
    }
    let mut spec = registry_spec(id);
    spec.as_object_mut().unwrap().remove("benchmark");
    json!({
        "providerSpec": spec,
        "providerSpecDigest": digest(&canonical_bytes(&spec)),
        "sources": sources,
        "sourcesDigest": digest(&canonical_bytes(&json!(sources))),
        "fixtureSources": fixtures,
        "fixtureSourcesDigest": digest(&canonical_bytes(&json!(fixtures))),
        "fixture": SOURCE,
        "repositoryRoot": fs::canonicalize(&root).unwrap(),
    })
}

fn expected_environment(run: &Path) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let base = [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
    ];
    let mut env: BTreeMap<String, String> = base
        .iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| ((*name).into(), value))
        })
        .collect();
    let mut allowed: BTreeSet<String> = base.into_iter().map(str::to_owned).collect();
    for (name, path) in [
        ("TMPDIR", "tmp"),
        ("TEMP", "tmp"),
        ("TMP", "tmp"),
        ("XDG_CACHE_HOME", "cache/xdg"),
        ("CARGO_TARGET_DIR", "cache/cargo-target"),
        ("npm_config_cache", "cache/npm"),
        ("RUFF_CACHE_DIR", "cache/ruff"),
        ("MYPY_CACHE_DIR", "cache/mypy"),
        ("PYTHONPYCACHEPREFIX", "cache/pycache"),
        ("GOCACHE", "cache/go-build"),
    ] {
        env.insert(name.into(), run.join(path).to_string_lossy().into_owned());
        allowed.insert(name.into());
    }
    env.insert("PYTHONNOUSERSITE".into(), "1".into());
    env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
    allowed.insert("PYTHONNOUSERSITE".into());
    allowed.insert("GIT_CONFIG_NOSYSTEM".into());
    env.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
    allowed.insert("PYTHONDONTWRITEBYTECODE".into());
    for (name, value) in [
        ("NO_COLOR", "1"),
        ("CARGO_NET_OFFLINE", "true"),
        ("CARGO_TERM_COLOR", "never"),
    ] {
        env.insert(name.into(), value.into());
        allowed.insert(name.into());
    }
    for name in [
        "SDKROOT",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOPATH",
        "GOROOT",
        "GOMODCACHE",
    ] {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.into(), value);
            allowed.insert(name.into());
        }
    }
    (env, allowed)
}

fn actual_receipt(receipt: &ExecutionReceipt) -> Value {
    let value = json!({
        "schemaVersion": receipt.schema_version,
        "receiptId": receipt.receipt_id, "requestId": receipt.request_id,
        "providerId": receipt.provider_id, "planId": receipt.plan_id,
        "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}",e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}",e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified,"skippedByPolicy":e.version.skipped_by_policy}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode": receipt.exit_code, "signal": receipt.signal,
        "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error},
        "gaps": receipt.gaps,
    });
    value
}
fn request_value(request: &ExternalToolRequest) -> Value {
    json!({"schemaVersion":request.schema_version,"requestId":request.request_id,
        "providerId":request.provider_id,"planId":request.plan_id,"policyId":request.policy_id,"taskId":request.task_id,
        "executable":request.executable,"args":request.args,"cwd":request.cwd,"origin":format!("{:?}",request.origin),
        "shell":request.shell,"expectedDigest":request.expected_digest,"acceptedExitCodes":request.accepted_exit_codes,
        "versionArgs":request.version_args,"skipVersionProbe":request.skip_version_probe,"versionRequirement":request.version_requirement,
        "environment":request.environment,"environmentAllowlist":request.environment_allowlist,
        "sensitiveArgumentIndexes":request.sensitive_argument_indexes,"sensitiveEnvironmentNames":request.sensitive_environment_names,
        "requiresNetworkSandbox":request.requires_network_sandbox,
        "sandbox":request.sandbox.as_ref().map(|s|json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope})),
        "timeoutMs":request.timeout_ms,"stdoutLimit":request.stdout_limit,"stderrLimit":request.stderr_limit})
}
struct ScopedPolicy {
    plan: String,
    root: PathBuf,
    scratch: Arc<AuditScratch>,
    tools: BTreeMap<String, (PathBuf, String)>,
    wrapper: PathBuf,
    wrapper_digest: String,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
    absent_sandbox: bool,
    source_files: BTreeMap<String, String>,
    native_linker: Value,
    database: PathBuf,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn profile_text(&self) -> String {
        let escaped = self
            .root
            .to_str()
            .unwrap()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath \"{escaped}\"))\n")
    }
    fn profile(&self) -> PathBuf {
        self.scratch.sandbox_dir().join(format!(
            "audit-{}.sb",
            digest(self.profile_text().as_bytes()).trim_start_matches("sha256:")
        ))
    }
    fn sandbox_id(&self) -> String {
        format!(
            "sandbox:macos:{}",
            digest(self.profile_text().as_bytes()).trim_start_matches("sha256:")
        )
    }
    fn prefix(&self, tool: &str, args: &[String]) -> Vec<String> {
        let mut out = vec![
            "-f".into(),
            self.profile().to_string_lossy().into_owned(),
            "--".into(),
            self.tools[tool].0.to_string_lossy().into_owned(),
        ];
        out.extend_from_slice(args);
        out
    }
    fn suffix(task: &str) -> Vec<String> {
        match task {
            "metadata" => vec!["metadata", "--locked", "--offline", "--format-version", "1"],
            "check" => vec![
                "check",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--message-format=json",
            ],
            "lint" => vec![
                "clippy",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--message-format=json",
            ],
            "test" => vec![
                "test",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
            ],
            _ => vec![],
        }
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    fn command_args(&self, task: &str) -> Vec<String> {
        if task == "dependency" {
            vec![
                "audit".into(),
                "--json".into(),
                "--file".into(),
                self.root.join("Cargo.lock").to_str().unwrap().into(),
                "--db".into(),
                self.database.to_str().unwrap().into(),
                "--no-fetch".into(),
                "--no-yanked".into(),
            ]
        } else {
            Self::suffix(task)
        }
    }
    fn task_environment(&self, task: &str) -> (BTreeMap<String, String>, BTreeSet<String>) {
        let mut env = self.environment.clone();
        let mut allow = self.allowlist.clone();
        if task == "dependency" {
            env.insert(
                "CARGO_HOME".into(),
                self.scratch
                    .root()
                    .join("cache")
                    .join("rust-dependency-cargo-home")
                    .to_str()
                    .unwrap()
                    .into(),
            );
            allow.insert("CARGO_HOME".into());
        }
        (env, allow)
    }
    fn version_args(&self, task: &str) -> Vec<String> {
        self.prefix(
            if task == "dependency" {
                "cargo-audit"
            } else {
                "cargo"
            },
            &["--version".into()],
        )
    }
    fn accepted(task: &str) -> BTreeSet<i32> {
        match task {
            "check" | "lint" => [0, 101].into_iter().collect(),
            "dependency" => [0, 1].into_iter().collect(),
            _ => [0].into_iter().collect(),
        }
    }
    fn definition(&self) -> Value {
        json!({"id":POLICY,"version":1,"scope":"exact constructed Rust SDK fixtures; no production owner admission", "provider":ID,"planDigest":self.plan,"cwd":self.root,"toolIdentities":self.tools,
        "sourceFiles":self.source_files,"nativeLinker":self.native_linker,"database":self.database,"wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},"profile":{"path":self.profile(),"text":self.profile_text(),"receiptId":self.sandbox_id()},
        "commands":TASKS.iter().map(|task|json!({"task":task,"args":self.command_args(task),"versionArgs":self.version_args(task),"environment":self.task_environment(task).0,"environmentAllowlist":self.task_environment(task).1,"acceptedExitCodes":Self::accepted(task)})).collect::<Vec<_>>(),
        "timeoutMs":120000,"stdoutLimit":33554432,"stderrLimit":33554432,"maxRequestsPerTask":1,"absentSandboxControl":self.absent_sandbox})
    }
    fn permits(&self, r: &ExternalToolRequest) -> bool {
        let task = r.task_id.as_deref().unwrap_or("");
        if !TASKS.contains(&task) {
            return false;
        }
        let tool = if task == "dependency" {
            "cargo-audit"
        } else {
            "cargo"
        };
        let sandbox_ok = if self.absent_sandbox {
            r.sandbox.is_none()
        } else {
            r.sandbox.as_ref().is_some_and(|s| {
                s.id == self.sandbox_id()
                    && s.network
                    && s.filesystem_scope.as_deref() == self.root.to_str()
            }) && fs::read(self.profile()).is_ok_and(|b| b == self.profile_text().as_bytes())
        };
        r.schema_version == 1
            && r.provider_id == ID
            && r.plan_id == self.plan
            && r.policy_id == "audit"
            && r.request_id
                .strip_prefix("legion-audit/")
                .is_some_and(|id| {
                    id.len() == 64
                        && id
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                })
            && snapshot(&self.root) == self.source_files
            && r.cwd == self.root.to_string_lossy()
            && r.origin == ToolOrigin::TargetProject
            && !r.shell
            && r.executable == self.wrapper.to_string_lossy()
            && r.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && fs::read(&self.wrapper).is_ok_and(|b| digest(&b) == self.wrapper_digest)
            && self
                .tools
                .values()
                .all(|(p, d)| fs::read(p).is_ok_and(|b| digest(&b) == *d))
            && r.args == self.prefix(tool, &self.command_args(task))
            && r.version_args == self.version_args(task)
            && !r.skip_version_probe
            && r.version_requirement.is_none()
            && r.requires_network_sandbox
            && sandbox_ok
            && r.environment == self.task_environment(task).0
            && r.environment_allowlist == self.task_environment(task).1
            && r.sensitive_argument_indexes.is_empty()
            && r.sensitive_environment_names.is_empty()
            && r.timeout_ms == 120000
            && r.stdout_limit == 33554432
            && r.stderr_limit == 33554432
            && r.accepted_exit_codes == Self::accepted(task)
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        let mut decisions = self.decisions.lock().unwrap();
        let allowed = self.permits(r)
            && !decisions.iter().any(|d| {
                d["requestId"] == r.request_id
                    || (d["taskId"] == json!(r.task_id) && d["allowed"] == true)
            });
        decisions.push(json!({"requestId":r.request_id,"taskId":r.task_id,"allowed":allowed,"request":request_value(r)}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact constructed Rust SDK fixture request"
                } else {
                    "outside exact constructed Rust SDK fixture contract"
                }
                .into(),
            ),
        }
    }
}
struct SharedPolicy(Arc<ScopedPolicy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(r)
    }
}
fn stream(record: Option<&ArtifactRecord>, scratch: &AuditScratch) -> Value {
    let Some(r) = record else {
        return Value::Null;
    };
    let relative = Path::new(&r.path);
    assert!(
        r.immutable
            && !relative.is_absolute()
            && relative
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
    );
    let root = fs::canonicalize(scratch.artifacts_dir()).unwrap();
    let path = fs::canonicalize(root.join(relative)).unwrap();
    assert!(path.starts_with(&root));
    let bytes = fs::read(&path).unwrap();
    assert_eq!(r.digest, digest(&bytes));
    assert_eq!(r.bytes, bytes.len());
    json!({"path":r.path,"absolutePath":path,"digest":r.digest,"bytes":r.bytes,"immutable":r.immutable,"rawBytes":bytes})
}
struct Recorder {
    inner: Arc<dyn ExternalProjectTool>,
    scratch: Arc<AuditScratch>,
    rows: Arc<Mutex<Vec<Value>>>,
    requests: Arc<Mutex<Vec<ExternalToolRequest>>>,
}
#[async_trait::async_trait]
impl ExternalProjectTool for Recorder {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> ExecutionReceipt {
        let req = request_value(&request);
        self.requests.lock().unwrap().push(request.clone());
        let receipt = self.inner.execute(request, cancellation).await;
        let mut rows = self.rows.lock().unwrap();
        let path = self
            .scratch
            .root()
            .join(format!("sdk-execution-{}.json", rows.len()));
        // Retain original receipt before stream verification can fail; no receipt is minted here.
        let receipt_value = actual_receipt(&receipt);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&json!({"request":req,"executionReceipt":receipt_value,
            "stdout":null,"stderr":null}))
            .unwrap(),
        )
        .unwrap();
        let row = json!({"request":req,"executionReceipt":receipt_value,
            "stdout":stream(receipt.stdout.as_ref(),&self.scratch),"stderr":stream(receipt.stderr.as_ref(),&self.scratch)});
        fs::write(&path, serde_json::to_vec_pretty(&row).unwrap()).unwrap();
        rows.push(row);
        receipt
    }
}

fn fixture_files(control: &str) -> BTreeMap<String, String> {
    let control = if matches!(
        control,
        "missing-database"
            | "tampered-database"
            | "missing-tool"
            | "tampered-tool"
            | "changed-source"
            | "rejected-admission"
            | "absent-sandbox"
            | "budget-exhausted"
    ) {
        "nonempty-clean"
    } else {
        control
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(FIXTURES)
        .join(control);
    let mut files = BTreeMap::new();
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), files);
            }
        } else {
            files.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                fs::read_to_string(path).unwrap(),
            );
        }
    }
    walk(&root, &root, &mut files);
    files
}
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(
            !metadata.file_type().is_symlink(),
            "fixture/runtime closure refuses symlinks"
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), files);
            }
        } else {
            assert!(metadata.is_file());
            files.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    walk(root, root, &mut files);
    files
}
fn raw(row: &Value, stream: &str) -> Vec<u8> {
    row[stream]["rawBytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect()
}
fn case(base: &Path, retained: &Path, bin: &Path, control: &str) -> Value {
    let root = base.join("source");
    let fixtures = fixture_files(control);
    for (path, text) in &fixtures {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, text).unwrap();
    }
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(control)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(ID)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-rust-code-sdk-fixture-key"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, retained.join("run")).unwrap());
    let scanner = fs::canonicalize(std::env::var_os("LEGION_CARGO_AUDIT_BIN").unwrap()).unwrap();
    let tools: BTreeMap<String, (PathBuf, String)> = [
        ("cargo", bin.join("cargo")),
        ("rustc", bin.join("rustc")),
        ("cargo-clippy", bin.join("cargo-clippy")),
        ("clippy-driver", bin.join("clippy-driver")),
        ("cargo-audit", scanner.clone()),
    ]
    .into_iter()
    .map(|(name, path)| {
        let path = fs::canonicalize(path).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.starts_with(b"#!") && !path.starts_with(&root));
        (name.into(), (path, digest(&bytes)))
    })
    .collect();
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let (mut environment, allowlist) = expected_environment(scratch.root());
    let enrollment: Value = serde_json::from_slice(
        &fs::read(std::env::var_os("LEGION_RUST_CODE_ENROLLMENT_JSON").unwrap()).unwrap(),
    )
    .unwrap();
    let native_bin = PathBuf::from(enrollment["nativeLinker"]["bin"].as_str().unwrap());
    let search_dirs = vec![
        bin.to_path_buf(),
        scanner.parent().unwrap().to_path_buf(),
        native_bin,
    ];
    environment.insert(
        "PATH".into(),
        std::env::join_paths(&search_dirs)
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
    );
    let database = PathBuf::from(std::env::var_os("LEGION_RUST_CODE_ADVISORY_DB").unwrap());
    let policy = Arc::new(ScopedPolicy {
        plan: frozen.digest().into(),
        root: root.clone(),
        scratch: scratch.clone(),
        tools,
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        environment,
        allowlist,
        absent_sandbox: control == "absent-sandbox",
        source_files: before.clone(),
        native_linker: verify_native_linker(&enrollment["nativeLinker"]),
        database: database.clone(),
        decisions: Mutex::new(Vec::new()),
    });
    if control == "changed-source" {
        fs::write(root.join("src/lib.rs"), "pub fn answer()->u8{0}\n").unwrap();
    }
    let rows = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let actual: Arc<dyn ExternalProjectTool> = if control == "rejected-admission" {
        Arc::new(legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            legion_audit::execution_policy::OwnerAdmissionRequired,
        ))
    } else {
        Arc::new(legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            SharedPolicy(policy.clone()),
        ))
    };
    let recorder = Arc::new(Recorder {
        inner: actual,
        scratch: scratch.clone(),
        rows: rows.clone(),
        requests: requests.clone(),
    });
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let native = if control == "absent-sandbox" {
        let request = ExternalToolRequest {
            request_id: format!(
                "legion-audit/{}",
                digest(control.as_bytes()).trim_start_matches("sha256:")
            ),
            provider_id: ID.into(),
            plan_id: frozen.digest().into(),
            policy_id: "audit".into(),
            task_id: Some("metadata".into()),
            executable: policy.wrapper.to_string_lossy().into_owned(),
            args: policy.prefix("cargo", &ScopedPolicy::suffix("metadata")),
            cwd: root.to_str().unwrap().into(),
            expected_digest: Some(policy.wrapper_digest.clone()),
            version_args: policy.version_args("metadata"),
            environment: policy.environment.clone(),
            environment_allowlist: policy.allowlist.clone(),
            requires_network_sandbox: true,
            sandbox: None,
            stdout_limit: 33554432,
            stderr_limit: 33554432,
            ..ExternalToolRequest::default()
        };
        runtime.block_on(recorder.execute(request, tokio_util::sync::CancellationToken::new()));
        Value::Null
    } else {
        let search = if control == "missing-tool" {
            let empty = base.join("empty-bin");
            fs::create_dir(&empty).unwrap();
            vec![empty]
        } else {
            search_dirs
        };
        let registry = NativeProviderRegistry::new(&root)
            .with_scratch(scratch.clone())
            .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(recorder.clone())))
            .with_code(
                code::ProviderExecutorAdapter::new()
                    .with_root(&root)
                    .with_search_path(search)
                    .with_sandbox(SandboxPolicy::Required)
                    .with_tool_bounds(
                        120000,
                        if control == "budget-exhausted" {
                            0
                        } else {
                            600000
                        },
                    ),
            );
        let report = runtime
            .block_on(execute_with_cancellation(
                &frozen,
                &inventory,
                &registry,
                tokio_util::sync::CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(report.planned_providers, vec![ID]);
        assert_eq!(report.results.len(), 1);
        serde_json::to_value(&report.results[0].result).unwrap()
    };
    let sdk = rows.lock().unwrap().clone();
    let after = snapshot(&root);
    let mut row = json!({"control":control,"provider":ID,"fixtureFiles":fixtures,"fixtureSources":before,"sourceAfter":after,"inventory":inventory,
        "planDigest":frozen.digest(),"frozenProvider":provider,"nativeResult":native,"sdkExecutions":sdk,"policyDefinition":policy.definition(),"policyDecisions":policy.decisions.lock().unwrap().clone(),
        "databaseRoot":database,"databaseFiles":if database.exists(){json!(snapshot(&database))}else{json!({})},
        "scope":if control=="absent-sandbox"{"sdk-boundary-control"}else{"native-provider-known-answer-fixture"},"matched":false});
    // Preserve actual post-SDK evidence before assertions; failed controls cannot disappear.
    fs::write(
        retained.join("case-observation.json"),
        serde_json::to_vec_pretty(&row).unwrap(),
    )
    .unwrap();
    if control != "changed-source" {
        assert_eq!(
            after, before,
            "exact original source closure must remain unchanged"
        );
    }
    let rows = row["sdkExecutions"].as_array().unwrap();
    if control == "absent-sandbox" {
        assert_eq!(rows.len(), 1);
        let receipt = &rows[0]["executionReceipt"];
        assert_eq!(receipt["state"], "sandbox_missing");
        assert_eq!(receipt["policy"]["allowed"], true);
        assert_eq!(receipt["processTree"]["started"], false);
    } else {
        assert_eq!(native["coverage"]["expected"], before.len());
        assert_eq!(
            native["complete"], false,
            "subset-only assessment never establishes whole Rust security clean"
        );
        let gaps = native["coverage_gaps"].to_string();
        assert!(!native["coverage_gaps"].as_array().unwrap().is_empty());
        if control == "missing-tool" || control == "budget-exhausted" {
            assert!(rows.is_empty());
            assert!(gaps.contains(if control == "missing-tool" {
                "tool-missing"
            } else {
                "tool-budget-exhausted"
            }));
        } else if control == "changed-source" || control == "rejected-admission" {
            assert!(!rows.is_empty());
            assert!(rows
                .iter()
                .all(
                    |row| row["executionReceipt"]["processTree"]["started"] == false
                        && row["executionReceipt"]["policy"]["allowed"] == false
                ));
            if control == "rejected-admission" {
                assert!(gaps.contains(legion_audit::execution_policy::ADMISSION_UNAVAILABLE));
            } else {
                assert!(gaps.contains("changed-since-inventory"));
                assert_ne!(after, before);
            }
        } else {
            let unavailable_dependency = matches!(
                control,
                "missing-database" | "tampered-database" | "tampered-tool" | "audit-config"
            );
            let tasks: BTreeSet<&str> = rows
                .iter()
                .map(|row| row["request"]["taskId"].as_str().unwrap())
                .collect();
            let expected: BTreeSet<&str> = TASKS
                .into_iter()
                .filter(|task| !unavailable_dependency || *task != "dependency")
                .collect();
            assert_eq!(tasks, expected);
            assert_eq!(rows.len(), expected.len());
            for execution in rows {
                let receipt = &execution["executionReceipt"];
                let task = execution["request"]["taskId"].as_str().unwrap();
                assert_eq!(receipt["providerId"], ID);
                assert_eq!(receipt["planId"], frozen.digest());
                assert_eq!(receipt["policy"]["allowed"], true);
                assert_eq!(receipt["policy"]["id"], POLICY);
                assert_eq!(
                    receipt["policy"]["digest"],
                    digest(&canonical_bytes(&policy.definition()))
                );
                assert_eq!(
                    receipt["executable"]["canonicalPath"],
                    policy.wrapper.to_str().unwrap()
                );
                assert_eq!(receipt["executable"]["digest"], policy.wrapper_digest);
                assert_eq!(
                    receipt["executable"]["version"]["args"],
                    execution["request"]["versionArgs"]
                );
                assert_eq!(receipt["executable"]["version"]["qualified"], true);
                assert!(receipt["executable"]["version"]["output"]
                    .as_str()
                    .unwrap()
                    .starts_with(if task == "dependency" {
                        "cargo-audit 0.22.2"
                    } else {
                        "cargo 1.98.0 "
                    }));
                assert_eq!(receipt["sandbox"]["receiptId"], policy.sandbox_id());
                assert_eq!(receipt["sandbox"]["required"], true);
                for flag in ["started", "terminated", "reaped"] {
                    assert_eq!(receipt["processTree"][flag], true);
                }
                assert!(receipt["signal"].is_null());
                let projected = native["details"]["nativeProducer"]["toolReceipts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|entry| entry["tool"] == task)
                    .unwrap();
                assert_eq!(projected["sdkReceipt"], *receipt);
                if task == "dependency" {
                    assert_eq!(projected["nativeInputSnapshots"]["unchanged"], true);
                    assert_eq!(
                        projected["nativeInputSnapshots"]["before"],
                        projected["nativeInputSnapshots"]["after"]
                    );
                }
            }
            // SDK completion alone is insufficient: require actual producer parser outcomes.
            let analyzed = native["details"]["nativeAnalysis"]["toolEvidence"]
                .as_array()
                .unwrap();
            assert_eq!(analyzed.len(), TASKS.len());
            for task in TASKS {
                let item = analyzed.iter().find(|item| item["id"] == task).unwrap();
                let failed = control == "malformed-lock"
                    || (control == "compiler-failure" && matches!(task, "check" | "lint" | "test"))
                    || (control == "test-failure" && task == "test");
                let status = if unavailable_dependency && task == "dependency" {
                    "unavailable"
                } else if failed {
                    "fail"
                } else {
                    "pass"
                };
                assert_eq!(
                    item["status"], status,
                    "{control}/{task} actual parser outcome"
                );
                if status == "pass" {
                    assert!(item["artifactDigest"]
                        .as_str()
                        .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71));
                    assert_eq!(item["scope"]["runs"].as_array().unwrap().len(), 1);
                }
            }
            assert_eq!(
                native["coverage"]["examined"],
                if control == "audit-config" {
                    before.len() - 1
                } else {
                    before.len()
                }
            );
            let finding = |rule: &str, path: &str| {
                native["details"]["findingEvidence"]
                    .as_object()
                    .unwrap()
                    .values()
                    .any(|f| {
                        f["ruleId"] == rule
                            && f["path"] == path
                            && f["line"].as_u64().is_some_and(|n| n > 0)
                    })
            };
            let tool = |task: &str| {
                rows.iter()
                    .find(|row| row["request"]["taskId"] == task)
                    .unwrap()
            };
            match control {
                "positive" => {
                    assert!(finding("clippy:needless_return", "src/lib.rs"));
                    assert_eq!(tool("lint")["executionReceipt"]["exitCode"], 0);
                }
                "nonempty-clean" | "dependency-nonempty-clean" => {
                    assert!(native["findings"].as_array().unwrap().is_empty());
                    assert!(rows
                        .iter()
                        .all(|row| row["executionReceipt"]["exitCode"] == 0));
                }
                "dependency-positive" => {
                    assert!(finding("cargo-audit:RUSTSEC-2019-0009", "Cargo.lock"));
                    assert_eq!(tool("dependency")["executionReceipt"]["exitCode"], 1);
                    assert!(TASKS
                        .into_iter()
                        .filter(|task| *task != "dependency")
                        .all(|task| tool(task)["executionReceipt"]["exitCode"] == 0));
                }
                "compiler-failure" => {
                    assert!(finding("rustc:E0425", "src/lib.rs"));
                    assert_eq!(tool("check")["executionReceipt"]["exitCode"], 101);
                    assert!(gaps.contains("cargo-build-incomplete"));
                }
                "test-failure" => {
                    assert_eq!(tool("test")["executionReceipt"]["exitCode"], 101);
                    assert!(
                        String::from_utf8_lossy(&raw(tool("test"), "stdout")).contains("FAILED")
                    );
                    assert!(gaps.contains("tool-failed:test"));
                }
                "unsafe-assessment" => {
                    assert!(gaps.contains("unsafe-assessment-unavailable"));
                    assert!(native["findings"].as_array().unwrap().is_empty());
                }
                "features" | "targets" => {
                    assert!(gaps.contains("unproven-build-variant"));
                    assert_eq!(tool("test")["executionReceipt"]["exitCode"], 0);
                }
                "malformed-lock" => {
                    assert_eq!(tool("dependency")["executionReceipt"]["exitCode"], 2);
                    assert!(gaps.contains("tool-failed:dependency"));
                }
                "missing-database" | "tampered-database" | "tampered-tool" | "audit-config" => {
                    assert!(gaps.contains("rust-dependency-input-unavailable"));
                    assert!(!tasks.contains("dependency"));
                }
                _ => panic!("unhandled expected control"),
            }
            assert_eq!(native["details"]["nativeProducer"]["sourceFilesRead"], 1);
            assert_eq!(native["details"]["nativeProducer"]["contextFilesRead"], 3);
        }
    }
    row["matched"] = json!(true);
    fs::write(
        retained.join("case-observation.json"),
        serde_json::to_vec_pretty(&row).unwrap(),
    )
    .unwrap();
    row
}

fn native_runtime_snapshot(runtime: &Value) -> Value {
    fn walk(
        path: &Path,
        excluded: &[PathBuf],
        files: &mut BTreeMap<String, String>,
        links: &mut BTreeMap<String, String>,
    ) {
        if excluded.iter().any(|excluded| path == excluded) {
            return;
        }
        let key = path
            .strip_prefix("/")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let meta = fs::symlink_metadata(path).unwrap();
        if meta.file_type().is_symlink() {
            links.insert(
                key,
                fs::read_link(path).unwrap().to_string_lossy().into_owned(),
            );
        } else if meta.is_dir() {
            for item in fs::read_dir(path).unwrap() {
                walk(&item.unwrap().path(), excluded, files, links);
            }
        } else {
            assert!(meta.is_file(), "runtime closure contains special file");
            files.insert(key, digest(&fs::read(path).unwrap()));
        }
    }
    fn resolve(
        path: &Path,
        sealed: &BTreeMap<String, String>,
        excluded: &[PathBuf],
        allow_missing: bool,
    ) -> PathBuf {
        let mut pending: std::collections::VecDeque<String> = path
            .to_str()
            .unwrap()
            .split('/')
            .map(str::to_owned)
            .collect();
        let mut current = PathBuf::from("/");
        let mut hops = 0;
        while let Some(part) = pending.pop_front() {
            match part.as_str() {
                "" | "." => continue,
                ".." => {
                    assert!(current.pop(), "runtime path escapes filesystem root");
                    continue;
                }
                _ => current.push(&part),
            }
            assert!(
                !excluded.iter().any(|path| current.starts_with(path)),
                "runtime symlink enters global packages"
            );
            let meta = match fs::symlink_metadata(&current) {
                Ok(meta) => meta,
                Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
                    return current
                }
                Err(error) => panic!("runtime path unavailable: {error}"),
            };
            if meta.file_type().is_symlink() {
                hops += 1;
                assert!(hops <= 40, "runtime symlink cycle");
                let key = current
                    .strip_prefix("/")
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let target = fs::read_link(&current)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                assert_eq!(
                    sealed.get(&key),
                    Some(&target),
                    "unsealed runtime alias hop"
                );
                current.pop();
                if target.starts_with('/') {
                    current = PathBuf::from("/");
                }
                for item in target.split('/').rev() {
                    pending.push_front(item.to_owned());
                }
            }
        }
        assert_eq!(fs::canonicalize(path).unwrap(), current);
        current
    }
    assert_eq!(runtime["root"], "/");
    let roots: Vec<PathBuf> = runtime["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| PathBuf::from(item.as_str().unwrap()))
        .collect();
    assert!(!roots.is_empty());
    let excluded: Vec<PathBuf> = runtime["exclusions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| PathBuf::from(item.as_str().unwrap()))
        .collect();
    assert!(excluded.is_empty(), "native closure has no exclusions");
    let sealed: BTreeMap<String, String> =
        serde_json::from_value(runtime["links"].clone()).unwrap();
    let absent: Vec<String> = serde_json::from_value(runtime["absent"].clone()).unwrap();
    let mut sorted_absent = absent.clone();
    sorted_absent.sort();
    sorted_absent.dedup();
    assert_eq!(absent, sorted_absent);
    for path in &absent {
        assert!(Path::new(path).is_absolute());
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "loader candidate appeared"
        );
        resolve(Path::new(path), &sealed, &excluded, true);
    }
    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    for root in &roots {
        assert!(root.is_absolute());
        assert_eq!(fs::canonicalize(root).unwrap(), *root);
        walk(root, &excluded, &mut files, &mut links);
    }
    for (relative, target) in &sealed {
        assert!(
            !relative.starts_with('/')
                && Path::new(relative)
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
        );
        let path = Path::new("/").join(relative);
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(&path).unwrap().to_string_lossy(),
            target.as_str()
        );
        links.insert(relative.clone(), target.clone());
        let final_path = resolve(&path, &sealed, &excluded, false);
        let inside = roots.iter().any(|root| final_path.starts_with(root));
        let retained_ancestor = files
            .keys()
            .any(|file| Path::new("/").join(file).starts_with(&final_path));
        if roots.iter().any(|root| path.starts_with(root)) {
            assert!(inside, "walked runtime link escapes declared roots");
        } else {
            assert!(
                inside || retained_ancestor,
                "external alias has no retained runtime target"
            );
        }
    }
    assert_eq!(links, sealed, "runtime alias closure changed");
    let payload = json!({"absent":absent,"files":files,"links":links,"roots":roots});
    json!({"root":"/","roots":roots,"exclusions":excluded,"absent":absent,"files":files,"links":links,
        "digest":digest(&canonical_bytes(&payload))})
}

fn verify_native_linker(native: &Value) -> Value {
    let runtime = native_runtime_snapshot(&native["runtime"]);
    assert_eq!(runtime, native["runtime"]);
    let files = runtime["files"].as_object().unwrap();
    let bound = |path: &str| {
        let key = path.strip_prefix('/').unwrap();
        assert!(
            files.contains_key(key),
            "native identity outside sealed closure"
        );
        assert_eq!(files[key], digest(&fs::read(path).unwrap()));
    };
    let inspector = &native["nativeDiscovery"]["inspector"];
    assert_eq!(inspector["path"], "/usr/bin/otool");
    assert_eq!(
        inspector["digest"],
        digest(&fs::read("/usr/bin/otool").unwrap())
    );
    assert_eq!(
        native["nativeDiscovery"]["systemExemptions"],
        json!(["/usr/lib", "/System/Library"])
    );
    let mut discovery = native["nativeDiscovery"].clone();
    let seal = discovery.as_object_mut().unwrap().remove("digest").unwrap();
    assert_eq!(seal, digest(&canonical_bytes(&discovery)));
    for image in discovery["images"].as_array().unwrap() {
        bound(image["path"].as_str().unwrap());
        bound(image["executable"].as_str().unwrap());
        for dep in image["dependencies"].as_array().unwrap() {
            if dep["systemExempt"] != true {
                bound(dep["resolved"].as_str().unwrap());
            }
        }
    }
    for name in ["clang", "ld", "ar", "ranlib", "dsymutil"] {
        let item = &native["tools"][name];
        let path = item["path"].as_str().unwrap();
        bound(path);
        assert_eq!(item["digest"], digest(&fs::read(path).unwrap()));
        assert_eq!(
            fs::canonicalize(item["selectedPath"].as_str().unwrap()).unwrap(),
            PathBuf::from(path)
        );
    }
    assert_eq!(native["discoveryTool"]["path"], "/usr/bin/xcrun");
    bound("/usr/bin/xcrun");
    assert_eq!(
        native["discoveryTool"]["digest"],
        digest(&fs::read("/usr/bin/xcrun").unwrap())
    );
    let bin = Path::new(native["bin"].as_str().unwrap());
    let actual_names: BTreeSet<String> = fs::read_dir(bin)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_str().unwrap().into())
        .collect();
    assert_eq!(
        actual_names,
        ["clang", "cc", "ld", "ar", "ranlib", "dsymutil", "xcrun"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    for name in &actual_names {
        let target = if name == "xcrun" {
            "/usr/bin/xcrun"
        } else {
            native["tools"][if name == "cc" { "clang" } else { name.as_str() }]["path"]
                .as_str()
                .unwrap()
        };
        assert_eq!(
            fs::canonicalize(bin.join(name)).unwrap(),
            PathBuf::from(target)
        );
    }
    let sdk = Path::new(native["sdkRoot"].as_str().unwrap());
    let resource = Path::new(native["resourceRoot"].as_str().unwrap());
    let expected_roots = [
        sdk.join("usr/lib"),
        sdk.join("System/Library/Frameworks"),
        resource.join("lib/darwin"),
    ];
    assert_eq!(
        native["searchInputs"].as_object().unwrap().len(),
        expected_roots.len()
    );
    fn visit(
        base: &Path,
        path: &Path,
        sdk: &Path,
        resource: &Path,
        active: &mut BTreeSet<PathBuf>,
        count: &mut usize,
        files: &mut BTreeMap<String, String>,
    ) {
        *count += 1;
        assert!(*count <= 200000, "linker search enumeration bound");
        let target = fs::canonicalize(path).unwrap();
        assert!(target.starts_with(sdk) || target.starts_with(resource));
        if target.is_dir() {
            assert!(active.insert(target.clone()), "linker directory cycle");
            for item in fs::read_dir(path).unwrap() {
                let child = item.unwrap().path();
                let name = child.file_name().unwrap().to_str().unwrap();
                if ["Headers", "PrivateHeaders", "Modules"].contains(&name)
                    || name.ends_with(".swiftmodule")
                {
                    continue;
                }
                visit(base, &child, sdk, resource, active, count, files);
            }
            active.remove(&target);
        } else if ["tbd", "a", "dylib", "o"]
            .contains(&path.extension().and_then(|s| s.to_str()).unwrap_or(""))
        {
            assert!(target.is_file());
            files.insert(
                path.strip_prefix(base).unwrap().to_str().unwrap().into(),
                digest(&fs::read(target).unwrap()),
            );
        }
    }
    for root in expected_roots {
        let mut observed = BTreeMap::new();
        visit(
            &root,
            &root,
            sdk,
            resource,
            &mut BTreeSet::new(),
            &mut 0,
            &mut observed,
        );
        assert_eq!(
            json!(observed),
            native["searchInputs"][root.to_str().unwrap()]
        );
        for relative in observed.keys() {
            let path = fs::canonicalize(root.join(relative)).unwrap();
            bound(path.to_str().unwrap());
        }
    }
    assert_eq!(native["probes"].as_array().unwrap().len(), 10);
    let probes = native["probes"].as_array().unwrap();
    let root = Path::new(native["bin"].as_str().unwrap()).parent().unwrap();
    let expected_environment = json!({"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1"});
    for probe in probes {
        assert_eq!(probe["cwd"], root.to_str().unwrap());
        assert_eq!(probe["environment"], expected_environment);
    }
    let output = |probe: &Value, stream: &str| -> String {
        String::from_utf8(
            probe[stream]["rawBytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
                .collect(),
        )
        .unwrap()
    };
    for (index, name) in ["clang", "ld", "ar", "ranlib", "dsymutil"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            probes[index]["args"],
            json!(["/usr/bin/xcrun", "--find", name])
        );
        assert_eq!(
            output(&probes[index], "stdout").trim(),
            native["tools"][name]["selectedPath"].as_str().unwrap()
        );
    }
    assert_eq!(
        probes[5]["args"],
        json!(["/usr/bin/xcrun", "--show-sdk-path"])
    );
    assert_eq!(
        fs::canonicalize(output(&probes[5], "stdout").trim()).unwrap(),
        sdk.to_path_buf()
    );
    let clang = native["tools"]["clang"]["path"].as_str().unwrap();
    assert_eq!(probes[6]["args"], json!([clang, "-print-resource-dir"]));
    assert_eq!(
        fs::canonicalize(output(&probes[6], "stdout").trim()).unwrap(),
        resource.to_path_buf()
    );
    assert_eq!(probes[7]["args"], json!([clang, "--version"]));
    assert_eq!(probes[8]["args"], json!([clang, "-print-search-dirs"]));
    let ld = native["tools"]["ld"]["path"].as_str().unwrap();
    assert_eq!(
        probes[9]["args"],
        json!([
            clang,
            "-###",
            "-isysroot",
            sdk,
            format!("-fuse-ld={ld}"),
            "-Wl,-Z",
            format!("-L{}/usr/lib", sdk.to_str().unwrap()),
            format!("-F{}/System/Library/Frameworks", sdk.to_str().unwrap()),
            format!("-L{}/lib/darwin", resource.to_str().unwrap()),
            "-x",
            "c",
            "/dev/null",
            "-o",
            root.join("never-created-link-probe")
        ])
    );
    let trace = output(&probes[9], "stderr");
    assert!(trace.contains(ld) && trace.contains(sdk.to_str().unwrap()));

    for probe in native["probes"].as_array().unwrap() {
        assert_eq!(probe["exitCode"], 0);
        for stream in ["stdout", "stderr"] {
            let bytes: Vec<u8> = probe[stream]["rawBytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
                .collect();
            assert_eq!(probe[stream]["digest"], digest(&bytes));
        }
    }
    json!({"runtime":runtime,"searchInputs":native["searchInputs"],"tools":native["tools"],"bin":native["bin"],"sdkRoot":native["sdkRoot"],"resourceRoot":native["resourceRoot"],"nativeDiscovery":native["nativeDiscovery"],"discoveryTool":native["discoveryTool"],"probes":native["probes"]})
}

fn verify_enrollment(enrollment: &Value) -> Value {
    assert_eq!(
        enrollment["schema"],
        "legion-rust-code-fixture-enrollment/1"
    );
    assert_eq!(
        enrollment["scope"],
        "constructed offline SDK fixture inputs; no production, freshness or full RustSec claim"
    );
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let pins = fs::read(repo.join(FIXTURES).join("inputs.json")).unwrap();
    assert_eq!(enrollment["inputsDigest"], digest(&pins));
    let pins: Value = serde_json::from_slice(&pins).unwrap();
    let vendor = Path::new(enrollment["vendor"]["root"].as_str().unwrap());
    let mut expected_vendor = BTreeMap::new();
    let mut observed_archives = BTreeMap::new();
    let packages = pins["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 2);
    let versions: BTreeSet<&str> = packages
        .iter()
        .map(|p| p["version"].as_str().unwrap())
        .collect();
    assert_eq!(
        versions,
        ["0.6.9", "0.6.10"].into_iter().collect::<BTreeSet<_>>()
    );
    for package in packages {
        assert_eq!(package["name"], "smallvec");
        let prefix = format!("smallvec-{}", package["version"].as_str().unwrap());
        let expected_checksum = json!({"files":package["files"],"package":package["sha256"]});
        let checksum = vendor.join(&prefix).join(".cargo-checksum.json");
        let checksum_bytes = fs::read(&checksum).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&checksum_bytes).unwrap(),
            expected_checksum
        );
        expected_vendor.insert(
            format!("{prefix}/.cargo-checksum.json"),
            digest(&checksum_bytes),
        );
        for (path, hash) in package["files"].as_object().unwrap() {
            expected_vendor.insert(
                format!("{prefix}/{path}"),
                format!("sha256:{}", hash.as_str().unwrap()),
            );
        }
        let archive = &enrollment["archives"][&prefix];
        let archive_bytes = fs::read(archive["path"].as_str().unwrap()).unwrap();
        assert_eq!(
            digest(&archive_bytes),
            format!("sha256:{}", package["sha256"].as_str().unwrap())
        );
        assert_eq!(archive["digest"], digest(&archive_bytes));
        assert_eq!(archive["bytes"], archive_bytes.len());
        assert_eq!(archive["url"], package["url"]);
        observed_archives.insert(prefix,json!({"path":archive["path"],"digest":digest(&archive_bytes),"bytes":archive_bytes.len(),"url":archive["url"]}));
    }
    let actual_vendor = snapshot(vendor);
    assert_eq!(actual_vendor, expected_vendor);
    assert_eq!(json!(expected_vendor), enrollment["vendor"]["files"]);
    let config = Path::new(enrollment["cargoHome"]["configPath"].as_str().unwrap());
    let config_bytes = fs::read(config).unwrap();
    assert_eq!(
        enrollment["cargoHome"]["configDigest"],
        digest(&config_bytes)
    );
    let native = &enrollment["nativeLinker"];
    assert_eq!(native["schema"], "legion-rust-native-linker-enrollment/1");
    assert_eq!(native["target"], "aarch64-apple-darwin");
    assert_eq!(std::env::consts::ARCH, "aarch64");
    assert_eq!(
        std::env::var("SDKROOT").unwrap(),
        native["sdkRoot"].as_str().unwrap()
    );
    let clang = native["tools"]["clang"]["path"].as_str().unwrap();
    let ld = native["tools"]["ld"]["path"].as_str().unwrap();
    let flags = json!([
        "-C",
        format!("link-arg=-fuse-ld={ld}"),
        "-C",
        "link-arg=-isysroot",
        "-C",
        format!("link-arg={}", native["sdkRoot"].as_str().unwrap()),
        "-C",
        "link-arg=-Wl,-Z",
        "-C",
        format!("link-arg=-L{}/usr/lib", native["sdkRoot"].as_str().unwrap()),
        "-C",
        format!(
            "link-arg=-F{}/System/Library/Frameworks",
            native["sdkRoot"].as_str().unwrap()
        ),
        "-C",
        format!(
            "link-arg=-L{}/lib/darwin",
            native["resourceRoot"].as_str().unwrap()
        )
    ]);
    let expected=format!("[source.crates-io]\nreplace-with=\"legion-fixed-vendor\"\n[source.legion-fixed-vendor]\ndirectory={}\n[target.aarch64-apple-darwin]\nlinker={}\nrustflags={}\n",serde_json::to_string(vendor.to_str().unwrap()).unwrap(),serde_json::to_string(clang).unwrap(),serde_json::to_string(&flags).unwrap());
    let native_snapshot = verify_native_linker(native);
    assert_eq!(config_bytes, expected.as_bytes());
    if std::env::var_os("LEGION_RUST_CODE_CHILD").is_some() {
        assert_eq!(
            enrollment["cargoHome"]["root"].as_str().unwrap(),
            std::env::var("CARGO_HOME").unwrap()
        );
    }
    let home = Path::new(enrollment["cargoHome"]["root"].as_str().unwrap());
    for name in ["config", "credentials", "credentials.toml"] {
        assert!(
            matches!(fs::symlink_metadata(home.join(name)),Err(error) if error.kind()==std::io::ErrorKind::NotFound),
            "unenrolled Cargo configuration"
        );
    }
    let db = Path::new(enrollment["database"]["root"].as_str().unwrap());
    let actual_database = snapshot(db);
    assert_eq!(json!(actual_database), enrollment["database"]["files"]);
    assert_eq!(
        enrollment["database"]["files"]["crates/smallvec/RUSTSEC-2019-0009.md"],
        "sha256:678bd66f3703ac7279a9b9fe4219fbe3903395d8411d899647ee8136d19241c5"
    );
    json!({"schema":"legion-rust-code-actual-input-snapshot/1","inputsDigest":digest(&fs::read(repo.join(FIXTURES).join("inputs.json")).unwrap()),"vendor":{"root":vendor,"files":actual_vendor},"cargoHome":{"root":home,"configPath":config,"configDigest":digest(&config_bytes),"absent":["config","credentials","credentials.toml"]},"database":{"root":db,"files":actual_database},"archives":observed_archives,"nativeLinker":native_snapshot})
}
fn child(
    control: &str,
    base: &Path,
    retained: &Path,
    bin: &Path,
    scanner: &Path,
    cargo_home: &Path,
    enrollment_path: &Path,
) -> bool {
    use std::{process::Stdio, time::Duration};
    let work = base.join(control);
    let output = retained.join("cases").join(control);
    fs::create_dir_all(&work).unwrap();
    fs::create_dir_all(&output).unwrap();
    for name in ["home", "tmp"] {
        fs::create_dir(work.join(name)).unwrap();
    }
    let database = work.join("database");
    if control != "missing-database" {
        fs::create_dir_all(database.join("crates/smallvec")).unwrap();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let mut advisory = fs::read(
            repo.join("engine/crates/legion-audit/tests/fixtures/cargo-audit/RUSTSEC-2019-0009.md"),
        )
        .unwrap();
        assert_eq!(
            digest(&advisory),
            "sha256:678bd66f3703ac7279a9b9fe4219fbe3903395d8411d899647ee8136d19241c5"
        );
        if control == "tampered-database" {
            advisory.extend_from_slice(b"\ncontrolled byte drift\n");
        }
        fs::write(
            database.join("crates/smallvec/RUSTSEC-2019-0009.md"),
            advisory,
        )
        .unwrap();
    }
    let scanner = if control == "tampered-tool" {
        let dir = work.join("tampered-tool");
        fs::create_dir(&dir).unwrap();
        let copy = dir.join("cargo-audit");
        fs::copy(scanner, &copy).unwrap();
        let mut bytes = fs::read(&copy).unwrap();
        bytes.extend_from_slice(b"controlled-byte-drift");
        fs::write(&copy, bytes).unwrap();
        copy
    } else {
        scanner.to_path_buf()
    };
    let enrollment: Value = serde_json::from_slice(&fs::read(enrollment_path).unwrap()).unwrap();
    let native_bin = Path::new(enrollment["nativeLinker"]["bin"].as_str().unwrap());
    let mut owned = rightkit_child_process::OwnedCommand::new(std::env::current_exe().unwrap());
    owned
        .command_mut()
        .args([
            "--exact",
            "real_rust_code_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            fs::File::create(output.join("child.stdout.log")).unwrap(),
        ))
        .stderr(Stdio::from(
            fs::File::create(output.join("child.stderr.log")).unwrap(),
        ))
        .env_clear()
        .env(
            "PATH",
            std::env::join_paths([bin, scanner.parent().unwrap(), native_bin]).unwrap(),
        )
        .env(
            "SDKROOT",
            enrollment["nativeLinker"]["sdkRoot"].as_str().unwrap(),
        )
        .env("HOME", work.join("home"))
        .env("TMPDIR", work.join("tmp"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("CARGO_HOME", cargo_home)
        .env("LEGION_QUALITY_TOOLCHAIN_BIN", bin)
        .env("LEGION_CARGO_AUDIT_BIN", &scanner)
        .env("LEGION_RUST_CODE_ADVISORY_DB", &database)
        .env("LEGION_RUST_CODE_ENROLLMENT_JSON", enrollment_path)
        .env("LEGION_RUST_CODE_CHILD", control)
        .env("LEGION_RUST_CODE_CASE_ROOT", &work)
        .env("LEGION_RUST_CODE_CASE_OUTPUT", &output);
    let mut started = false;
    let (status, error) = match owned.spawn() {
        Ok(mut child) => {
            started = true;
            match child.wait_timeout(Duration::from_secs(660)) {
                Ok(Some(status)) => (Some(status), None),
                Ok(None) => {
                    let result = child.terminate_tree_bounded(Duration::from_secs(2));
                    (
                        None,
                        Some(format!("case-timeout; owned tree termination {result:?}")),
                    )
                }
                Err(error) => {
                    let result = child.terminate_tree_bounded(Duration::from_secs(2));
                    (
                        None,
                        Some(format!(
                            "case-wait:{error}; owned tree termination {result:?}"
                        )),
                    )
                }
            }
        }
        Err(error) => (None, Some(format!("case-spawn:{error}"))),
    };
    let stdout = fs::read(output.join("child.stdout.log")).unwrap();
    let stderr = fs::read(output.join("child.stderr.log")).unwrap();
    let success = status.as_ref().is_some_and(|status| status.success());
    let input_snapshots = fs::read(output.join("input-snapshots.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let receipt = json!({"schema":"legion-rust-code-owned-child/1","control":control,"started":started,"success":success,"inputSnapshots":input_snapshots,"exitCode":status.as_ref().and_then(|s|s.code()),"signal":status.as_ref().and_then(|s|s.signal()),"error":error,
        "stdout":{"file":"child.stdout.log","bytes":stdout.len(),"digest":digest(&stdout)},"stderr":{"file":"child.stderr.log","bytes":stderr.len(),"digest":digest(&stderr)}});
    fs::write(
        output.join("child-execution.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    success
}

#[test]
#[ignore = "actual Rust1.98.0 + Clippy/cargo-audit0.22.2 SDK controls; explicit CI-provisioned offline fixture inputs & retained output required"]
fn real_rust_code_accuracy() {
    let bin = fs::canonicalize(
        std::env::var_os("LEGION_QUALITY_TOOLCHAIN_BIN")
            .expect("actual pinned toolchain bin required"),
    )
    .unwrap();
    let enrollment_path = fs::canonicalize(
        std::env::var_os("LEGION_RUST_CODE_ENROLLMENT_JSON").expect("CI input enrollment required"),
    )
    .unwrap();
    let enrollment_bytes = fs::read(&enrollment_path).unwrap();
    let enrollment: Value = serde_json::from_slice(&enrollment_bytes).unwrap();
    let input_before = verify_enrollment(&enrollment);
    if let Ok(control) = std::env::var("LEGION_RUST_CODE_CHILD") {
        assert!(CONTROLS.contains(&control.as_str()));
        let base =
            fs::canonicalize(std::env::var_os("LEGION_RUST_CODE_CASE_ROOT").unwrap()).unwrap();
        let retained =
            fs::canonicalize(std::env::var_os("LEGION_RUST_CODE_CASE_OUTPUT").unwrap()).unwrap();
        let row = case(&base, &retained, &bin, &control);
        assert_eq!(row["matched"], true);
        let input_after = verify_enrollment(&enrollment);
        let unchanged = input_before == input_after;
        fs::write(
            retained.join("input-snapshots.json"),
            serde_json::to_vec_pretty(
                &json!({"before":input_before,"after":input_after,"unchanged":unchanged}),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(unchanged);
        return;
    }
    let retained = PathBuf::from(
        std::env::var_os("LEGION_RUST_CODE_RECEIPTS")
            .expect("explicit retained output root required"),
    );
    assert!(retained.is_absolute());
    fs::create_dir_all(&retained).unwrap();
    let retained = fs::canonicalize(retained).unwrap();
    let base = retained.join("fixture-roots");
    fs::create_dir(&base).unwrap();
    assert!(!retained.starts_with(Path::new(env!("CARGO_MANIFEST_DIR"))));
    let runtime_root = bin.parent().unwrap();
    let runtime_before = snapshot(runtime_root);
    let runtime_value = json!({"root":runtime_root,"files":runtime_before,"scope":"actual pinned Rust compiler/Cargo/Clippy/sysroot file closure; OS system libraries excluded"});
    let runtime_bytes = serde_json::to_vec_pretty(&runtime_value).unwrap();
    fs::write(retained.join("toolchain-runtime.json"), &runtime_bytes).unwrap();
    fs::write(retained.join("input-enrollment.json"), &enrollment_bytes).unwrap();
    let environment_bytes =
        fs::read(enrollment_path.parent().unwrap().join("environment.json")).unwrap();
    let environment: Value = serde_json::from_slice(&environment_bytes).unwrap();
    assert_eq!(
        environment,
        json!({"CARGO_HOME":enrollment["cargoHome"]["root"],"LEGION_RUST_CODE_ENROLLMENT_JSON":enrollment_path,"SDKROOT":enrollment["nativeLinker"]["sdkRoot"]})
    );
    fs::write(retained.join("environment.json"), &environment_bytes).unwrap();
    fs::create_dir(retained.join("input-archives")).unwrap();
    let mut archives = BTreeMap::new();
    for (name, archive) in enrollment["archives"].as_object().unwrap() {
        let bytes = fs::read(archive["path"].as_str().unwrap()).unwrap();
        let file = format!("input-archives/{name}.crate");
        fs::write(retained.join(&file), &bytes).unwrap();
        archives.insert(
            name.clone(),
            json!({"file":file,"digest":digest(&bytes),"bytes":bytes.len(),"url":archive["url"]}),
        );
    }
    let scanner = fs::canonicalize(std::env::var_os("LEGION_CARGO_AUDIT_BIN").unwrap()).unwrap();
    let cargo_home = fs::canonicalize(enrollment["cargoHome"]["root"].as_str().unwrap()).unwrap();
    let mut child_receipts = Vec::new();
    let mut cases = Vec::new();
    for control in CONTROLS {
        let success = child(
            control,
            &base,
            &retained,
            &bin,
            &scanner,
            &cargo_home,
            &enrollment_path,
        );
        let output = retained.join("cases").join(control);
        child_receipts.push(
            serde_json::from_slice::<Value>(
                &fs::read(output.join("child-execution.json")).unwrap(),
            )
            .unwrap(),
        );
        if let Ok(bytes) = fs::read(output.join("case-observation.json")) {
            cases.push(serde_json::from_slice::<Value>(&bytes).unwrap());
        }
        // Continue remaining controls after failure; no unstarted control vanishes from denominator.
        let progress = json!({"controls":CONTROLS,"children":child_receipts,"cases":cases,"lastControl":control,"lastSuccess":success});
        fs::write(
            retained.join("matrix-progress.json"),
            serde_json::to_vec_pretty(&progress).unwrap(),
        )
        .unwrap();
    }
    let runtime_after = snapshot(runtime_root);
    let runtime_stable = runtime_before == runtime_after;
    let runtime_after_bytes =
        serde_json::to_vec_pretty(&json!({"root":runtime_root,"files":runtime_after})).unwrap();
    fs::write(
        retained.join("toolchain-runtime-after.json"),
        &runtime_after_bytes,
    )
    .unwrap();
    let input_after = verify_enrollment(&enrollment);
    assert_eq!(fs::read(&enrollment_path).unwrap(), enrollment_bytes);
    let input_stable = input_before == input_after;
    let config = code::evidence::config_for(ID).unwrap();
    assert_eq!(config.tools, TASKS);
    assert_eq!(config.required_context, ["features", "targets"]);
    assert_eq!(config.extensions, ["rs"]);
    let observed: BTreeSet<&str> = cases
        .iter()
        .filter_map(|case| case["control"].as_str())
        .collect();
    let expected: BTreeSet<&str> = CONTROLS.into_iter().collect();
    let eligible = runtime_stable
        && input_stable
        && cases.len() == CONTROLS.len()
        && observed == expected
        && cases.iter().all(|case| case["matched"] == true)
        && child_receipts.len() == CONTROLS.len()
        && child_receipts
            .iter()
            .all(|child| child["success"] == true && child["inputSnapshots"]["unchanged"] == true);
    let fixture_sources: BTreeMap<String, String> = cases
        .iter()
        .flat_map(|case| {
            case["fixtureSources"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(path, digest)| {
                    (
                        format!("{}/{path}", case["control"].as_str().unwrap()),
                        digest.as_str().unwrap().to_owned(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let mut record = json!({"schema":"legion-rust-code-sdk-accuracy/1","kind":"code-rust-sdk-constructed","provider":ID,"providerVersion":registry_spec(ID)["providerVersion"],
        "platform":{"os":"macos","arch":std::env::consts::ARCH},"retainedRoot":retained,
        "productionQualification":false,"selfProducerQualification":false,"publicHelperQualification":false,"qualificationEligible":eligible,"claimScope":"known-answer-fixture-cases","modelCalls":0,
        "executionPath":"native-sdk-frozen-plan-self-sourced-code","admissionScope":"exact constructed authorizer & genuine default denial; no production owner admission",
        "requiredContract":{"tools":TASKS,"contexts":config.required_context,"unsafe":"keyword inventory & explicit soundness gap; no semantic assessment","dependency":"dependency/v1 official unchanged RUSTSEC-2019-0009 subset only"},
        "binding":binding(ID,&fixture_sources),"controls":CONTROLS,"children":child_receipts,"cases":cases,
        "environment":{"file":"environment.json","digest":digest(&environment_bytes),"bytes":environment_bytes.len()},
        "inputSnapshots":{"before":input_before,"after":input_after,"unchanged":input_stable},"inputArchives":archives,"inputEnrollment":{"file":"input-enrollment.json","digest":digest(&enrollment_bytes),"bytes":enrollment_bytes.len()},
        "toolchain":{"version":"1.98.0","file":"toolchain-runtime.json","digest":digest(&runtime_bytes),"bytes":runtime_bytes.len(),"after":{"file":"toolchain-runtime-after.json","digest":digest(&runtime_after_bytes),"bytes":runtime_after_bytes.len()},"unchanged":runtime_stable},
        "metrics":{"cases":cases.len(),"matched":cases.iter().filter(|case|case["matched"]==true).count(),"wholeProviderQualified":false,"boundedSdkAccuracyQualified":eligible},
        "runtimeLimitations":["dependency subset cannot establish full/current RustSec security clean","unsafe source soundness unassessed","feature/target variants unexercised","multiple manifests & project audit configuration remain explicit gaps"]});
    record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
    let bytes = serde_json::to_vec_pretty(&record).unwrap();
    fs::write(retained.join("code_rust.json"), &bytes).unwrap();
    let summary = json!({"schema":"legion-rust-code-sdk-artifact/1","provider":ID,"file":"code_rust.json","digest":digest(&bytes),"bytes":bytes.len(),"qualificationDigest":record["qualificationDigest"],"qualificationEligible":eligible,"productionQualification":false});
    println!(
        "RUST_CODE_SDK_ACCURACY_ARTIFACT {}",
        serde_json::to_string(&summary).unwrap()
    );
    assert!(eligible,"complete expected matrix & stable actual runtime inputs required; retained failures remain in denominator");
}
