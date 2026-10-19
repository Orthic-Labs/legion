//! Genuine Python SDK known-answer controls; no production admission is supplied.
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
    io::Write,
    os::unix::process::ExitStatusExt,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
const SOURCE: &str = "engine/crates/legion-audit/tests/real_python_code_command_accuracy.rs";
const FIXTURES: &str = "scripts/ci/fixtures/audit-code-python-sdk-accuracy";
const POLICY: &str = "legion-real-python-code-command-fixture-v1";
const PYTHON: &str = "code.python";
const CONTROLS: [&str; 13] = [
    "nonempty-clean",
    "lint-positive",
    "type-positive",
    "compile-error",
    "test-failure",
    "build-error",
    "invalid-wheel",
    "missing-backend",
    "malformed-config",
    "source-drift",
    "missing-tool",
    "rejected-admission",
    "absent-sandbox",
];
const ENV: [&str; 3] = [
    "LEGION_PYTHON_SDK_ENROLLMENT_JSON",
    "LEGION_PYTHON_SDK_PYTHON",
    "LEGION_PYTHON_SDK_BIN_DIR",
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

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = std::env::var_os("LEGION_PYTHON_CODE_COMMAND_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-python-code-command-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        for dir in ["home", "tmp"] {
            fs::create_dir(path.join(dir)).unwrap();
        }
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
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
        "scripts/ci/audit-python-sdk-bootstrap.py",
        "scripts/ci/provision-python-qualification-tools.py",
        "scripts/ci/audit-pip-audit-provider-accuracy.py",
        "scripts/ci/locks/code-python-sdk-macos-arm64-cp314.json",
        "scripts/ci/locks/code-python-sdk-macos-arm64-cp314.txt",
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
        "fixture": SOURCE
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
        ("PYTHONSAFEPATH", "1"),
    ] {
        env.insert(name.into(), value.into());
        allowed.insert(name.into());
    }
    for name in [
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

fn repository() -> PathBuf {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")).unwrap()
}
fn owned_literal(path: &str, name: &str) -> String {
    let text = fs::read_to_string(repository().join(path)).unwrap();
    let start = format!("const {name}: &str = r#\"");
    let body = text.split_once(&start).expect("source-owned literal").1;
    body.split_once("\"#;")
        .expect("source-owned literal end")
        .0
        .into()
}
struct ScopedPolicy {
    plan: String,
    root: PathBuf,
    scratch: Arc<AuditScratch>,
    fixtures: BTreeMap<String, String>,
    tools: BTreeMap<String, (PathBuf, String)>,
    wrapper: PathBuf,
    wrapper_digest: String,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
    absent_sandbox: bool,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn stage(&self) -> PathBuf {
        self.scratch.root().join("cache/python-sdk/source")
    }
    fn profile_text(&self) -> String {
        let root = self
            .root
            .to_str()
            .unwrap()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{root}\"))\n(deny file-write* (subpath \"{root}\"))\n")
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
    fn tool(task: &str) -> &str {
        match task {
            "lint" => "ruff",
            "type" => "mypy",
            "test" => "pytest",
            _ => "python3",
        }
    }
    fn prefix(&self, tool: &str, args: &[String]) -> Vec<String> {
        let mut out = vec![
            "-f".into(),
            self.profile().to_str().unwrap().into(),
            "--".into(),
            self.tools[tool].0.to_str().unwrap().into(),
        ];
        out.extend_from_slice(args);
        out
    }
    fn input_digest(&self) -> String {
        let files: BTreeMap<String, String> = self
            .fixtures
            .iter()
            .map(|(p, t)| (p.clone(), digest(t.as_bytes())))
            .collect();
        digest(&serde_json::to_vec(&json!({"schema":"legion-python-frozen-inputs/1","originalRoot":self.root,"files":files})).unwrap())
    }
    fn command_args(&self, task: &str, inspect: bool) -> Vec<String> {
        let cache = self.scratch.root().join("cache");
        let tmp = self.scratch.root().join("tmp");
        match task {
            "compile" => {
                let files: BTreeSet<_> = self
                    .fixtures
                    .keys()
                    .filter(|p| p.ends_with(".py"))
                    .cloned()
                    .collect();
                vec![
                    "-I".into(),
                    "-B".into(),
                    "-c".into(),
                    owned_literal(
                        "engine/crates/legion-audit/src/native_providers/code/tools.rs",
                        "PY_COMPILE_SCRIPT",
                    ),
                    tmp.join("py-compile-files.txt").to_str().unwrap().into(),
                    cache.join("py-compile").to_str().unwrap().into(),
                    serde_json::to_string(&files).unwrap(),
                ]
            }
            "lint" => ["check", "--no-cache", "--output-format", "json", "."]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            "type" => vec![
                "--no-incremental".into(),
                "--cache-dir".into(),
                cache.join("mypy").to_str().unwrap().into(),
                "--no-color-output".into(),
                "--show-error-codes".into(),
                "--no-pretty".into(),
                ".".into(),
            ],
            "test" => vec![
                "--assert=plain".into(),
                "-o".into(),
                format!("cache_dir={}", cache.join("pytest").display()),
                "--basetemp".into(),
                tmp.join("pytest").to_str().unwrap().into(),
            ],
            "package" if inspect => vec![
                "-I".into(),
                "-B".into(),
                "-c".into(),
                owned_literal(
                    "engine/crates/legion-audit/src/native_providers/code/python_commands.rs",
                    "WHEEL_INSPECT",
                ),
                cache.join("python-wheels-0").to_str().unwrap().into(),
                "fixture-pkg".into(),
                "1.0.0".into(),
                self.input_digest(),
            ],
            "package" => vec![
                "-I".into(),
                "-B".into(),
                "-m".into(),
                "build".into(),
                "--wheel".into(),
                "--no-isolation".into(),
                "--outdir".into(),
                cache.join("python-wheels-0").to_str().unwrap().into(),
                self.stage().to_str().unwrap().into(),
            ],
            _ => Vec::new(),
        }
    }
    fn version_args(&self, task: &str) -> Vec<String> {
        self.prefix(Self::tool(task), &["--version".into()])
    }
    fn accepted(task: &str) -> BTreeSet<i32> {
        if ["compile", "lint", "type"].contains(&task) {
            [0, 1].into_iter().collect()
        } else {
            [0].into_iter().collect()
        }
    }
    fn definition(&self) -> Value {
        let commands:Vec<Value>=[("compile",false),("lint",false),("type",false),("test",false),("package",false),("package",true)].into_iter().map(|(task,inspect)|json!({"task":task,"args":self.command_args(task,inspect),"versionArgs":self.version_args(task),"acceptedExitCodes":Self::accepted(task)})).collect();
        json!({"id":POLICY,"version":1,"scope":"exact constructed Python SDK fixtures; no production owner admission","provider":PYTHON,"planDigest":self.plan,"originalRoot":self.root,"cwd":self.stage(),"frozenSourceDigest":self.input_digest(),"toolIdentities":self.tools,"wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},"profile":{"path":self.profile(),"text":self.profile_text(),"receiptId":self.sandbox_id()},"commands":commands,"environment":self.environment,"environmentAllowlist":self.allowlist,"absentSandboxControl":self.absent_sandbox,"timeoutMs":120000,"stdoutLimit":33554432,"stderrLimit":33554432})
    }
    fn permits(&self, r: &ExternalToolRequest) -> bool {
        let task = r.task_id.as_deref().unwrap_or("");
        if !["compile", "lint", "type", "test", "package"].contains(&task) {
            return false;
        }
        let args_ok = r.args == self.prefix(Self::tool(task), &self.command_args(task, false))
            || (task == "package"
                && r.args == self.prefix("python3", &self.command_args(task, true)));
        let sandbox = if self.absent_sandbox {
            r.sandbox.is_none()
        } else {
            r.sandbox.as_ref().is_some_and(|s| {
                s.id == self.sandbox_id()
                    && s.network
                    && s.filesystem_scope.as_deref() == self.root.to_str()
            }) && fs::read(self.profile()).is_ok_and(|b| b == self.profile_text().as_bytes())
        };
        r.schema_version == 1
            && r.provider_id == PYTHON
            && r.plan_id == self.plan
            && r.policy_id == "audit"
            && r.request_id.strip_prefix("legion-audit/").is_some_and(|p| {
                p.len() == 64
                    && p.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            && r.cwd == self.stage().to_string_lossy()
            && r.origin == ToolOrigin::TargetProject
            && !r.shell
            && r.executable == self.wrapper.to_string_lossy()
            && r.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && fs::read(&self.wrapper).is_ok_and(|b| digest(&b) == self.wrapper_digest)
            && self
                .tools
                .values()
                .all(|(p, d)| fs::read(p).is_ok_and(|b| digest(&b) == *d))
            && args_ok
            && r.version_args == self.version_args(task)
            && !r.skip_version_probe
            && r.version_requirement.is_none()
            && r.requires_network_sandbox
            && sandbox
            && r.environment == self.environment
            && r.environment_allowlist == self.allowlist
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
        let allowed = self.permits(r) && !decisions.iter().any(|d| d["requestId"] == r.request_id);
        decisions.push(json!({"requestId":r.request_id,"taskId":r.task_id,"allowed":allowed,"request":request_value(r)}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact constructed Python SDK fixture request"
                } else {
                    "outside exact constructed Python SDK fixture contract"
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
fn request_mutations(
    captured: &ExternalToolRequest,
    original: &ScopedPolicy,
    runtime: &tokio::runtime::Runtime,
) -> Value {
    let mut controls = Vec::new();
    for field in ["args", "cwd", "executable", "planId"] {
        let scratch = Arc::new(
            AuditScratch::with_scratch_dir(
                &original.root,
                original.scratch.root().join("mutations").join(field),
            )
            .unwrap(),
        );
        // Same policy definition/digest; fresh replay state cannot hide a binding defect.
        let policy = Arc::new(ScopedPolicy {
            plan: original.plan.clone(),
            root: original.root.clone(),
            fixtures: original.fixtures.clone(),
            scratch: original.scratch.clone(),
            tools: original.tools.clone(),
            wrapper: original.wrapper.clone(),
            wrapper_digest: original.wrapper_digest.clone(),
            environment: original.environment.clone(),
            allowlist: original.allowlist.clone(),
            absent_sandbox: false,
            decisions: Mutex::new(Vec::new()),
        });
        let mut request = captured.clone();
        request.request_id = format!(
            "legion-audit/{}",
            digest(format!("{}:mutation:{field}", captured.request_id).as_bytes())
                .trim_start_matches("sha256:")
        );
        assert!(
            policy.permits(&request),
            "fresh request ID must not cause mutation refusal"
        );
        let baseline = request_value(&request);
        match field {
            "args" => request.args.push("--outside-fixture-command".into()),
            "cwd" => {
                request.cwd = original
                    .root
                    .parent()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            }
            "executable" => {
                request.executable = original.tools["python3"].0.to_string_lossy().into_owned()
            }
            "planId" => request.plan_id = "different-frozen-plan".into(),
            _ => unreachable!(),
        }
        let actual = legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            SharedPolicy(policy.clone()),
        );
        let rows = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder {
            inner: Arc::new(actual),
            scratch: scratch.clone(),
            rows: rows.clone(),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        runtime.block_on(recorder.execute(request, tokio_util::sync::CancellationToken::new()));
        let executions = rows.lock().unwrap().clone();
        let mut row = json!({"control":format!("request-mutation-{field}"),"scope":"sdk-exact-policy-boundary",
            "qualificationEligible":false,"sourceRequest":request_value(captured),"baselineRequest":baseline,
            "mutatedField":field,"policyDefinition":policy.definition(),"policyDecisions":policy.decisions.lock().unwrap().clone(),
            "sdkExecutions":executions,"matched":false});
        fs::write(
            scratch.root().join("mutation-observation.json"),
            serde_json::to_vec_pretty(&row).unwrap(),
        )
        .unwrap();
        assert_eq!(row["policyDefinition"], original.definition());
        assert_eq!(executions.len(), 1);
        let receipt = &executions[0]["executionReceipt"];
        assert_eq!(receipt["state"], "unauthorized_effect");
        assert_eq!(receipt["complete"], false);
        assert_eq!(receipt["processTree"]["started"], false);
        assert_eq!(receipt["policy"]["allowed"], false);
        assert_eq!(receipt["policy"]["id"], POLICY);
        assert_eq!(
            receipt["policy"]["digest"],
            digest(&canonical_bytes(&original.definition()))
        );
        assert!(receipt["executable"].is_null());
        assert_eq!(row["policyDecisions"].as_array().unwrap().len(), 1);
        row["matched"] = json!(true);
        fs::write(
            scratch.root().join("mutation-observation.json"),
            serde_json::to_vec_pretty(&row).unwrap(),
        )
        .unwrap();
        controls.push(row);
    }
    json!(controls)
}
fn fixture_files(control: &str) -> BTreeMap<String, String> {
    let control = if [
        "missing-tool",
        "rejected-admission",
        "absent-sandbox",
        "source-drift",
    ]
    .contains(&control)
    {
        "nonempty-clean"
    } else {
        control
    };
    let root = repository().join(FIXTURES).join(control);
    fn walk(root: &Path, p: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!p.is_symlink());
        if p.is_dir() {
            for e in fs::read_dir(p).unwrap() {
                walk(root, &e.unwrap().path(), out)
            }
        } else {
            out.insert(
                p.strip_prefix(root).unwrap().to_str().unwrap().into(),
                fs::read_to_string(p).unwrap(),
            );
        }
    }
    let mut files = BTreeMap::new();
    walk(&root, &root, &mut files);
    assert!(!files.is_empty());
    files
}
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, p: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!p.is_symlink());
        if p.is_dir() {
            for e in fs::read_dir(p).unwrap() {
                walk(root, &e.unwrap().path(), out)
            }
        } else {
            out.insert(
                p.strip_prefix(root).unwrap().to_str().unwrap().into(),
                digest(&fs::read(p).unwrap()),
            );
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}
fn raw(row: &Value, key: &str) -> Vec<u8> {
    row[key]["rawBytes"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|n| u8::try_from(n.as_u64().unwrap()).unwrap())
                .collect()
        })
        .unwrap_or_default()
}
fn runtime_closure(enrollment: &Value) -> Value {
    use std::io::Read;
    let expected = &enrollment["runtime"];
    assert_eq!(expected["root"], "/");
    let roots: Vec<PathBuf> = expected["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| PathBuf::from(v.as_str().unwrap()))
        .collect();
    let excluded: Vec<PathBuf> = expected["exclusions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| PathBuf::from(v.as_str().unwrap()))
        .collect();
    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut count = 0usize;
    fn walk(
        path: &Path,
        excluded: &[PathBuf],
        files: &mut BTreeMap<String, String>,
        links: &mut BTreeMap<String, String>,
        count: &mut usize,
        depth: usize,
    ) {
        if excluded.iter().any(|p| path == p) {
            return;
        }
        *count += 1;
        assert!(
            *count <= 200000 && depth <= 128,
            "bounded closed runtime traversal"
        );
        let m = fs::symlink_metadata(path).unwrap();
        let key = path.strip_prefix("/").unwrap().to_str().unwrap().to_owned();
        if m.file_type().is_symlink() {
            links.insert(key, fs::read_link(path).unwrap().to_str().unwrap().into());
        } else if m.is_dir() {
            for e in fs::read_dir(path).unwrap() {
                walk(&e.unwrap().path(), excluded, files, links, count, depth + 1)
            }
        } else {
            assert!(m.is_file() && m.len() <= 128 * 1024 * 1024);
            let mut f = fs::File::open(path).unwrap();
            let mut h = Sha256::new();
            let mut total = 0u64;
            let mut buf = [0u8; 65536];
            loop {
                let n = f.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                total += n as u64;
                assert!(total <= 128 * 1024 * 1024);
                h.update(&buf[..n]);
            }
            assert_eq!(total, m.len());
            let after = fs::symlink_metadata(path).unwrap();
            assert!(after.is_file());
            assert_eq!(after.len(), m.len());
            assert_eq!(after.modified().ok(), m.modified().ok());
            files.insert(
                key,
                format!(
                    "sha256:{}",
                    h.finalize()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
            );
        }
    }
    for root in &roots {
        assert!(root.is_absolute());
        assert_eq!(fs::canonicalize(root).unwrap(), *root);
        walk(root, &excluded, &mut files, &mut links, &mut count, 0)
    }
    for (rel, target) in expected["links"].as_object().unwrap() {
        let path = Path::new("/").join(rel);
        assert!(path.is_symlink());
        assert_eq!(
            fs::read_link(&path).unwrap().to_str().unwrap(),
            target.as_str().unwrap()
        );
        let resolved = fs::canonicalize(&path).unwrap();
        assert!(!excluded.iter().any(|p| resolved.starts_with(p)));
        let key = resolved.strip_prefix("/").unwrap().to_str().unwrap();
        assert!(
            files.contains_key(key) || files.keys().any(|p| p.starts_with(&format!("{key}/"))),
            "alias target bytes retained"
        );
        links.insert(rel.clone(), target.as_str().unwrap().to_owned());
    }
    for absent in expected["absent"].as_array().unwrap() {
        assert!(fs::symlink_metadata(absent.as_str().unwrap())
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound));
    }
    assert_eq!(json!(files), expected["files"]);
    assert_eq!(json!(links), expected["links"]);
    let value =
        json!({"absent":expected["absent"],"files":files,"links":links,"roots":expected["roots"]});
    assert_eq!(digest(&canonical_bytes(&value)), expected["digest"]);
    json!({"schema":"legion-python-sdk-runtime-observation/1","runtimeDigest":expected["digest"],"fileCount":files.len(),"linkCount":links.len(),"absentCount":expected["absent"].as_array().unwrap().len()})
}
fn verify_enrollment(enrollment: &Value) {
    assert_eq!(enrollment["schema"], "legion-python-sdk-enrollment/1");
    assert_eq!(enrollment["qualificationEligible"], false);
    assert_eq!(enrollment["interpreter"]["version"], "3.14.7");
    for (name, version) in [
        ("python3", "3.14.7"),
        ("ruff", "0.17.1"),
        ("mypy", "2.4.0"),
        ("pytest", "9.1.1"),
        ("build", "1.6.1"),
        ("hatchling", "1.32.4"),
    ] {
        assert_eq!(enrollment["tools"][name]["version"], version);
    }
    assert_eq!(
        enrollment["environment"]["LEGION_PYTHON_SDK_PYTHON"],
        std::env::var("LEGION_PYTHON_SDK_PYTHON").unwrap()
    );
    assert_eq!(
        enrollment["environment"]["LEGION_PYTHON_SDK_BIN_DIR"],
        std::env::var("LEGION_PYTHON_SDK_BIN_DIR").unwrap()
    );
    for (relative, descriptor) in enrollment["inputs"].as_object().unwrap() {
        assert_eq!(
            descriptor["digest"],
            digest(&fs::read(repository().join(relative)).unwrap())
        );
    }
    runtime_closure(enrollment);
}
fn case(base: &Path, retained: &Path, enrollment: &Value, control: &str) -> Value {
    let case_id = format!("code-python-{control}");
    let root = base.join(&case_id).join("source");
    let fixtures = fixture_files(control);
    for (rel, text) in &fixtures {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(PYTHON)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-python-sdk-fixture-key"))
        .unwrap();
    let scratch = Arc::new(
        AuditScratch::with_scratch_dir(&root, retained.join("cases").join(&case_id)).unwrap(),
    );
    let tools: BTreeMap<String, (PathBuf, String)> = ["python3", "ruff", "mypy", "pytest"]
        .into_iter()
        .map(|name| {
            let item = &enrollment["tools"][name];
            let p = PathBuf::from(item["path"].as_str().unwrap());
            assert!(p.is_absolute());
            let sha = digest(&fs::read(&p).unwrap());
            assert_eq!(sha, item["digest"]);
            (name.into(), (p, sha))
        })
        .collect();
    let bin = PathBuf::from(std::env::var("LEGION_PYTHON_SDK_BIN_DIR").unwrap());
    let (mut environment, allowlist) = expected_environment(scratch.root());
    environment.insert("PATH".into(), bin.to_str().unwrap().into());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let policy = Arc::new(ScopedPolicy {
        plan: frozen.digest().into(),
        root: root.clone(),
        scratch: scratch.clone(),
        fixtures: fixtures.clone(),
        tools,
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        environment,
        allowlist,
        absent_sandbox: control == "absent-sandbox",
        decisions: Mutex::new(Vec::new()),
    });
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
    if control == "source-drift" {
        fs::write(
            root.join("fixture_pkg/__init__.py"),
            "def answer() -> int:\n    return 99\n",
        )
        .unwrap();
    }
    let runtime_before = runtime_closure(enrollment);
    let native_result = if control == "absent-sandbox" {
        // An actual SDK boundary control; no observed native provider completion is invented.
        fs::create_dir_all(policy.stage()).unwrap();
        let request = ExternalToolRequest {
            request_id: format!(
                "legion-audit/{}",
                digest(case_id.as_bytes()).trim_start_matches("sha256:")
            ),
            provider_id: PYTHON.into(),
            plan_id: frozen.digest().into(),
            policy_id: "audit".into(),
            task_id: Some("type".into()),
            executable: policy.wrapper.to_str().unwrap().into(),
            args: policy.prefix("mypy", &policy.command_args("type", false)),
            cwd: policy.stage().to_str().unwrap().into(),
            expected_digest: Some(policy.wrapper_digest.clone()),
            version_args: policy.version_args("type"),
            environment: policy.environment.clone(),
            environment_allowlist: policy.allowlist.clone(),
            accepted_exit_codes: ScopedPolicy::accepted("type"),
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
            let empty = base.join(&case_id).join("empty-bin");
            fs::create_dir(&empty).unwrap();
            vec![empty]
        } else {
            vec![bin]
        };
        let native = NativeProviderRegistry::new(&root)
            .with_scratch(scratch.clone())
            .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(recorder)))
            .with_code(
                code::ProviderExecutorAdapter::new()
                    .with_root(&root)
                    .with_search_path(search)
                    .with_sandbox(SandboxPolicy::Required),
            );
        let report = runtime
            .block_on(execute_with_cancellation(
                &frozen,
                &inventory,
                &native,
                tokio_util::sync::CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(report.planned_providers, vec![PYTHON]);
        assert_eq!(report.results.len(), 1);
        serde_json::to_value(&report.results[0].result).unwrap()
    };
    let mut result = json!({"caseId":case_id,"control":control,"provider":PYTHON,"scope":if control=="absent-sandbox"{"sdk-boundary-control"}else{"native-provider-known-answer-fixture"},"fixtureFiles":fixtures,"fixtureSources":before,"inventory":inventory,"planDigest":frozen.digest(),"frozenProvider":frozen.provider(PYTHON).unwrap(),"nativeResult":native_result,"policyDefinition":policy.definition(),"policyDecisions":policy.decisions.lock().unwrap().clone(),"sdkExecutions":rows.lock().unwrap().clone(),"runtimeBefore":runtime_before,"matched":false});
    let path = scratch.root().join("case-observation.json");
    fs::write(&path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    // Original raw receipt/stdout/stderr bytes are durable before any assertion.
    result["runtimeAfter"] = runtime_closure(enrollment);
    assert_eq!(result["runtimeBefore"], result["runtimeAfter"]);
    if control != "source-drift" {
        assert_eq!(
            snapshot(&root),
            before,
            "audited frozen inputs must remain unchanged"
        );
    }
    let executions = result["sdkExecutions"].as_array().unwrap();
    let full = matches!(
        control,
        "nonempty-clean" | "lint-positive" | "type-positive"
    );
    if control == "absent-sandbox" {
        assert_eq!(executions.len(), 1);
        let r = &executions[0]["executionReceipt"];
        assert_eq!(r["state"], "sandbox_missing");
        assert_eq!(r["policy"]["allowed"], true);
        assert_eq!(r["processTree"]["started"], false);
    } else {
        assert_eq!(native_result["complete"], false);
        if full {
            assert_eq!(
                native_result["coverage_gaps"],
                json!(["code.python:lint-scope-unproven"])
            );
            assert_eq!(native_result["coverage"]["expected"], before.len());
            assert_eq!(native_result["coverage"]["examined"], before.len());
        } else {
            assert!(!native_result["coverage_gaps"]
                .as_array()
                .unwrap()
                .is_empty());
        }
        let expected_count = if ["source-drift", "missing-tool"].contains(&control) {
            0
        } else if control == "malformed-config" {
            4
        } else {
            6
        };
        assert_eq!(
            executions.len(),
            expected_count,
            "all applicable SDK calls must actually be attempted"
        );
        for row in executions {
            let r = &row["executionReceipt"];
            assert_eq!(r["providerId"], PYTHON);
            assert_eq!(r["planId"], frozen.digest());
            if control == "rejected-admission" {
                assert_eq!(r["state"], "unauthorized_effect");
                assert_eq!(r["policy"]["allowed"], false);
                assert_eq!(r["processTree"]["started"], false);
                continue;
            }
            assert_eq!(r["policy"]["allowed"], true);
            assert_eq!(r["policy"]["id"], POLICY);
            assert_eq!(r["sandbox"]["receiptId"], policy.sandbox_id());
            assert_eq!(r["sandbox"]["required"], true);
            // Config failures may legitimately fail their version probe; never call those clean.
            if r["state"] != "unsealed_executable" {
                assert_eq!(r["processTree"]["started"], true);
                assert_eq!(r["processTree"]["terminated"], true);
                assert_eq!(r["processTree"]["reaped"], true);
                assert_eq!(r["executable"]["version"]["qualified"], true);
            }
            assert_eq!(
                r["executable"]["version"]["args"],
                row["request"]["versionArgs"]
            );
        }
        if expected_count > 0 {
            let tasks: BTreeSet<_> = executions
                .iter()
                .map(|r| r["request"]["taskId"].as_str().unwrap())
                .collect();
            let expected: BTreeSet<_> = if control == "malformed-config" {
                ["compile", "lint", "type", "test"].into_iter().collect()
            } else {
                ["compile", "lint", "type", "test", "package"]
                    .into_iter()
                    .collect()
            };
            assert_eq!(tasks, expected);
        }
        if full {
            assert!(executions
                .iter()
                .all(|r| r["executionReceipt"]["state"] == "completed"
                    && r["executionReceipt"]["complete"] == true));
            let receipts = native_result["details"]["nativeProducer"]["toolReceipts"]
                .as_array()
                .unwrap();
            assert_eq!(receipts.len(), 6);
            for receipt in receipts {
                let snapshots = &receipt["nativeInputSnapshots"];
                assert_eq!(snapshots["unchanged"], true);
                assert_eq!(snapshots["before"], snapshots["after"]);
                assert_eq!(
                    snapshots["before"]["schema"],
                    "legion-python-input-snapshot/1"
                );
                assert!(executions
                    .iter()
                    .any(|r| r["executionReceipt"] == receipt["sdkReceipt"]));
            }
            let wheel: Value =
                serde_json::from_slice(&raw(executions.last().unwrap(), "stdout")).unwrap();
            assert_eq!(wheel["schema"], "legion-python-wheel/1");
            assert_eq!(wheel["sourceDigest"], policy.input_digest());
            assert_eq!(
                wheel["files"]["fixture_pkg/__init__.py"],
                before["fixture_pkg/__init__.py"]
            );
            assert!(wheel["files"]
                .as_object()
                .unwrap()
                .keys()
                .any(|p| p == "fixture_pkg/__init__.py"));
            let find = native_result["details"]["findingEvidence"]
                .as_object()
                .unwrap();
            match control {
                "nonempty-clean" => {
                    assert!(find.is_empty());
                    for r in executions {
                        assert_eq!(r["executionReceipt"]["exitCode"], 0);
                    }
                }
                "lint-positive" => assert!(find
                    .values()
                    .any(|f| f["ruleId"] == "ruff:F401" && f["path"] == "fixture_pkg/__init__.py")),
                "type-positive" => {
                    assert!(find.values().any(|f| f["ruleId"] == "mypy:return-value"
                        && f["path"] == "fixture_pkg/__init__.py"))
                }
                _ => unreachable!(),
            }
        }
        match control {
            "compile-error" => {
                let r = executions
                    .iter()
                    .find(|r| r["request"]["taskId"] == "compile")
                    .unwrap();
                assert!(String::from_utf8(raw(r, "stdout"))
                    .unwrap()
                    .contains("fixture_pkg/__init__.py"));
            }
            "test-failure" => {
                let r = executions
                    .iter()
                    .find(|r| r["request"]["taskId"] == "test")
                    .unwrap();
                assert_eq!(r["executionReceipt"]["exitCode"], 1);
                assert_eq!(r["executionReceipt"]["state"], "failed");
                assert!(String::from_utf8(raw(r, "stdout"))
                    .unwrap()
                    .contains("FAILED"));
            }
            "build-error" | "missing-backend" => {
                let r = executions
                    .iter()
                    .find(|r| r["request"]["taskId"] == "package")
                    .unwrap();
                assert_ne!(r["executionReceipt"]["exitCode"], 0);
                assert_eq!(r["executionReceipt"]["state"], "failed");
            }
            "invalid-wheel" => {
                let r = executions.last().unwrap();
                assert_eq!(r["request"]["taskId"], "package");
                assert_ne!(r["executionReceipt"]["exitCode"], 0);
                assert!(String::from_utf8(raw(r, "stderr"))
                    .unwrap()
                    .contains("wheel RECORD"));
            }
            "source-drift" => assert!(native_result["coverage_gaps"]
                .to_string()
                .contains("python-frozen-digest")),
            "missing-tool" => assert!(native_result["coverage_gaps"]
                .to_string()
                .contains("tool-missing")),
            "malformed-config" => assert!(native_result["coverage_gaps"]
                .to_string()
                .contains("python-package-manifest-malformed")),
            _ => {}
        }
    }
    if control == "nonempty-clean" {
        let captured = requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.task_id.as_deref() == Some("compile"))
            .unwrap()
            .clone();
        result["requestMutationControls"] = request_mutations(&captured, &policy, &runtime);
    }
    result["matched"] = json!(true);
    fs::write(&path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    result
}
fn emit(retained: &Path, record: &mut Value) {
    record["qualificationDigest"] = json!(digest(&canonical_bytes(record)));
    let bytes = serde_json::to_vec_pretty(record).unwrap();
    fs::write(retained.join("code_python.json"), &bytes).unwrap();
    assert_eq!(fs::read(retained.join("code_python.json")).unwrap(), bytes);
    println!("PYTHON_CODE_COMMAND_SDK_ACCURACY_ARTIFACT {}",serde_json::to_string(&json!({"schema":"legion-python-code-command-sdk-artifact/1","provider":PYTHON,"file":"code_python.json","digest":digest(&bytes),"bytes":bytes.len(),"qualificationDigest":record["qualificationDigest"],"qualificationEligible":record["qualificationEligible"],"productionQualification":false})).unwrap());
}
#[test]
#[ignore = "genuine Python SDK controls require CI-provisioned closed CPython/tool enrollment, native macOS sandbox & explicit scratch/output roots"]
fn real_python_code_command_accuracy() {
    if let Some(base) = std::env::var_os("LEGION_PYTHON_CODE_COMMAND_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let retained =
            fs::canonicalize(std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR").unwrap()).unwrap();
        let enrollment_path = PathBuf::from(std::env::var_os(ENV[0]).unwrap());
        let enrollment_bytes = fs::read(&enrollment_path).unwrap();
        fs::write(
            retained.join("python-sdk-enrollment.json"),
            &enrollment_bytes,
        )
        .unwrap();
        let enrollment: Value = serde_json::from_slice(&enrollment_bytes).unwrap();
        verify_enrollment(&enrollment);
        let runtime_before = runtime_closure(&enrollment);
        let cases: Vec<Value> = CONTROLS
            .into_iter()
            .map(|c| case(&base, &retained, &enrollment, c))
            .collect();
        let runtime_after = runtime_closure(&enrollment);
        assert_eq!(runtime_before, runtime_after);
        verify_enrollment(&enrollment);
        assert_eq!(fs::read(enrollment_path).unwrap(), enrollment_bytes);
        let config = code::evidence::config_for(PYTHON).unwrap();
        assert_eq!(config.tools, ["compile", "lint", "type", "test", "package"]);
        assert_eq!(config.required_context, ["packageRoots"]);
        assert_eq!(config.extensions, ["py"]);
        assert_eq!(json!(config.variants), json!([["python", ["py"]]]));
        let mutations = cases[0]["requestMutationControls"].as_array().unwrap();
        let eligible = cases.len() == CONTROLS.len()
            && cases.iter().all(|c| c["matched"] == true)
            && mutations.len() == 4
            && mutations.iter().all(|m| m["matched"] == true);
        assert!(
            eligible,
            "whole source-owned bounded matrix must match; no inferred missing control success"
        );
        let fixture_sources: BTreeMap<String, String> = cases
            .iter()
            .flat_map(|c| {
                c["fixtureSources"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(p, d)| {
                        (
                            format!("{}/{p}", c["caseId"].as_str().unwrap()),
                            d.as_str().unwrap().into(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut record = json!({"schema":"legion-python-code-command-sdk-accuracy/1","kind":"python-code-command-sdk-constructed","provider":PYTHON,"providerVersion":registry_spec(PYTHON)["providerVersion"],"productionQualification":false,"qualificationEligible":eligible,"claimScope":"known-answer-fixture-cases","executionPath":"native-sdk-frozen-plan-self-sourced-code","modelCalls":0,"admissionScope":"explicit constructed SDK authorizer; genuine OwnerAdmissionRequired denial; no production owner-admission claim","packageContract":"python-package/v1: actual offline PEP517 wheel build against declared installed backend; actual wheel METADATA/WHEEL/RECORD validation; frozen original/staged source identity","binding":binding(PYTHON,&fixture_sources),"requiredContract":{"tools":config.tools,"extensions":config.extensions,"variants":config.variants,"requiredContext":config.required_context},"executedScope":config.tools,"enrollment":{"file":"python-sdk-enrollment.json","digest":digest(&enrollment_bytes),"bytes":enrollment_bytes.len()},"runtimeBefore":runtime_before,"runtimeAfter":runtime_after,"cases":cases,"missingControls":[],"metrics":{"cases":CONTROLS.len(),"matched":CONTROLS.len(),"mismatched":0,"wholeProviderQualified":false,"boundedSdkAccuracyQualified":eligible},"status":"observed-known-answer-controls"});
        emit(&retained, &mut record);
        return;
    }
    let fixture = Fixture::new();
    let retained = PathBuf::from(
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR")
            .expect("explicit retained Python SDK output root required"),
    );
    assert!(retained.is_absolute());
    fs::create_dir_all(&retained).unwrap();
    let retained = fs::canonicalize(retained).unwrap();
    assert!(!retained.starts_with(&fixture.0) && !fixture.0.starts_with(&retained));
    let environment: BTreeMap<String, String> = ENV
        .into_iter()
        .map(|name| {
            let p = PathBuf::from(
                std::env::var_os(name).expect("explicit Python SDK enrollment required"),
            );
            assert!(p.is_absolute() && !p.starts_with(&fixture.0));
            (name.into(), p.to_str().unwrap().into())
        })
        .collect();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_python_code_command_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", &environment[ENV[2]])
        .env("HOME", fixture.0.join("home"))
        .env("XDG_CONFIG_HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .envs(environment)
        .env("LEGION_PYTHON_CODE_COMMAND_CHILD", &fixture.0)
        .env("LEGION_PROVIDER_BENCHMARK_DIR", &retained)
        .output()
        .unwrap();
    fs::write(retained.join("child.stdout.log"), &output.stdout).unwrap();
    fs::write(retained.join("child.stderr.log"), &output.stderr).unwrap();
    fs::write(retained.join("child-execution.json"),serde_json::to_vec_pretty(&json!({"schema":"legion-python-code-command-child-execution/1","productionQualification":false,"status":{"success":output.status.success(),"exitCode":output.status.code(),"signal":output.status.signal()},"stdout":{"file":"child.stdout.log","bytes":output.stdout.len(),"sha256":digest(&output.stdout)},"stderr":{"file":"child.stderr.log","bytes":output.stderr.len(),"sha256":digest(&output.stderr)}})).unwrap()).unwrap();
    assert!(
        output.status.success(),
        "actual Python SDK child failed; original receipts/artifacts & streams retained"
    );
    let marker = b"PYTHON_CODE_COMMAND_SDK_ACCURACY_ARTIFACT ";
    let lines: Vec<&[u8]> = output
        .stdout
        .split_inclusive(|b| *b == b'\n')
        .filter_map(|line| {
            line.windows(marker.len())
                .position(|w| w == marker)
                .map(|p| &line[p..])
        })
        .collect();
    assert_eq!(lines.len(), 1);
    let locator: Value = serde_json::from_slice(&lines[0][marker.len()..]).unwrap();
    let bytes = fs::read(retained.join("code_python.json")).unwrap();
    assert_eq!(
        locator["schema"],
        "legion-python-code-command-sdk-artifact/1"
    );
    assert_eq!(locator["provider"], PYTHON);
    assert_eq!(locator["digest"], digest(&bytes));
    assert_eq!(locator["bytes"], bytes.len());
    assert_eq!(locator["qualificationEligible"], true);
    assert_eq!(locator["productionQualification"], false);
    let mut record: Value = serde_json::from_slice(&bytes).unwrap();
    let q = record
        .as_object_mut()
        .unwrap()
        .remove("qualificationDigest")
        .unwrap();
    assert_eq!(q, digest(&canonical_bytes(&record)));
    assert_eq!(locator["qualificationDigest"], q);
    std::io::stdout().lock().write_all(lines[0]).unwrap();
}
