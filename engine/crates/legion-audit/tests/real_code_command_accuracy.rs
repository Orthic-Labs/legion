//! Constructed known-answer code SDK controls; partial contracts never qualify providers.
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
const SOURCE: &str = "engine/crates/legion-audit/tests/real_code_command_accuracy.rs";
const FIXTURES: &str = "scripts/ci/fixtures/audit-code-sdk-accuracy";
const POLICY: &str = "legion-real-code-command-fixture-v1";
const GO: &str = "code.go";
const GOVULN_ENV: [&str; 5] = [
    "LEGION_GOVULNCHECK_BIN",
    "LEGION_GOVULNCHECK_DB_ROOT",
    "LEGION_GOVULNCHECK_DB_ARCHIVE",
    "LEGION_GOVULNCHECK_ENROLLMENT_JSON",
    "GOMODCACHE",
];
const CONTROLS: [&str; 12] = [
    "positive",
    "nonempty-clean",
    "vulnerability-positive",
    "build-tags",
    "cgo",
    "workspace",
    "external-test",
    "test-failure",
    "malformed",
    "missing-tool",
    "rejected-admission",
    "absent-sandbox",
];
const PROVIDERS: [&str; 10] = [
    "code.c-family",
    "code.dotnet",
    "code.go",
    "code.javascript",
    "code.jvm",
    "code.long-tail",
    "code.mobile",
    "code.php-ruby",
    "code.python",
    "code.rust",
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
        let base = std::env::var_os("LEGION_CODE_COMMAND_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-code-command-{}-{}",
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
                .to_string_lossy()
                .replace('\\', "/"),
            digest(&fs::read(path).unwrap()),
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

fn binding(id: &str, fixtures: &BTreeMap<String, String>) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
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
        "scripts/ci/audit-govulncheck-bootstrap.py",
        "scripts/ci/audit-govulncheck-inputs.json",
    ] {
        bind_source_tree(&root, &root.join(path), &mut sources);
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
        ("GOPROXY", "off"),
        ("GOSUMDB", "off"),
        ("GOTOOLCHAIN", "local"),
        ("GOENV", "off"),
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
            "module" => vec!["list", "-m"],
            "vet" => vec!["vet", "./..."],
            "format" => vec!["-l", "."],
            "test" => vec!["test", "-count=1", "./..."],
            _ => vec![],
        }
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    fn db_url(&self) -> String {
        let path =
            fs::canonicalize(std::env::var_os("LEGION_GOVULNCHECK_DB_ROOT").unwrap()).unwrap();
        let mut url = String::from("file://");
        for b in path.to_str().unwrap().bytes() {
            if b.is_ascii_alphanumeric() || b"/-._~:".contains(&b) {
                url.push(b as char);
            } else {
                url.push_str(&format!("%{b:02X}"));
            }
        }
        url.push('/');
        url
    }
    fn source_stage(&self) -> PathBuf {
        self.scratch
            .root()
            .join("cache")
            .join("govulncheck")
            .join(digest(b"").trim_start_matches("sha256:"))
    }
    fn command_args(&self, task: &str) -> Vec<String> {
        if task == "vulnerability" {
            vec![
                "-C".into(),
                // Match production source.join("") for root-module argv.
                self.source_stage().join("").to_str().unwrap().into(),
                "-mode=source".into(),
                "-scan=symbol".into(),
                "-test".into(),
                "-json".into(),
                "-db".into(),
                self.db_url(),
                "./...".into(),
            ]
        } else {
            Self::suffix(task)
        }
    }
    fn task_environment(&self, task: &str) -> (BTreeMap<String, String>, BTreeSet<String>) {
        let mut environment = self.environment.clone();
        let mut allowed = self.allowlist.clone();
        if task == "vulnerability" {
            let home = self.source_stage().parent().unwrap().join(format!(
                "home-{}",
                digest(b"").trim_start_matches("sha256:")
            ));
            for (key, value) in [
                ("GOWORK", "off".into()),
                ("GOFLAGS", "-mod=readonly".into()),
                ("CGO_ENABLED", "0".into()),
                ("HOME", home.to_str().unwrap().into()),
                (
                    "XDG_CONFIG_HOME",
                    home.join(".config").to_str().unwrap().into(),
                ),
                (
                    "APPDATA",
                    home.join("AppData/Roaming").to_str().unwrap().into(),
                ),
            ] {
                environment.insert(key.into(), value);
                allowed.insert(key.into());
            }
        }
        (environment, allowed)
    }
    fn version_args(&self, task: &str) -> Vec<String> {
        if task == "vulnerability" {
            return self.prefix(
                "govulncheck",
                &["-db".into(), self.db_url(), "-version".into()],
            );
        }
        let mut args = vec!["version".into()];
        if task == "format" {
            args.push(self.tools["gofmt"].0.to_string_lossy().into_owned());
        }
        self.prefix("go", &args)
    }
    fn accepted(task: &str) -> BTreeSet<i32> {
        if task == "vet" {
            [0, 1, 2].into_iter().collect()
        } else {
            [0].into_iter().collect()
        }
    }
    fn definition(&self) -> Value {
        json!({"id":POLICY,"version":1,"scope":"exact constructed Go SDK fixtures; no production owner admission",
            "provider":GO,"planDigest":self.plan,"cwd":self.root,"toolIdentities":self.tools,
            "wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},
            "profile":{"path":self.profile(),"text":self.profile_text(),"receiptId":self.sandbox_id()},
            "commands":["go list -m","go vet ./...","gofmt -l .","go test -count=1 ./...","govulncheck -C <frozen-stage> -mode=source -scan=symbol -test -json -db <sealed-official-db> ./..."],
            "vulnerabilityCommand":{"args":self.command_args("vulnerability"),"versionArgs":self.version_args("vulnerability"),"environment":self.task_environment("vulnerability").0,"environmentAllowlist":self.task_environment("vulnerability").1},
            "environment":self.environment,"environmentAllowlist":self.allowlist,"absentSandboxControl":self.absent_sandbox,
            "timeoutMs":120000,"stdoutLimit":33554432,"stderrLimit":33554432})
    }
    fn permits(&self, r: &ExternalToolRequest) -> bool {
        let task = r.task_id.as_deref().unwrap_or("");
        if !["module", "vet", "format", "test", "vulnerability"].contains(&task) {
            return false;
        }
        let tool = match task {
            "format" => "gofmt",
            "vulnerability" => "govulncheck",
            _ => "go",
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
            && r.provider_id == GO
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
        let allowed = self.permits(r) && !decisions.iter().any(|d| d["requestId"] == r.request_id);
        decisions.push(json!({"requestId":r.request_id,"taskId":r.task_id,"allowed":allowed,"request":request_value(r)}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact constructed Go SDK fixture request"
                } else {
                    "outside exact constructed Go SDK fixture contract"
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

struct SharedRecorder(Arc<Recorder>);

#[async_trait::async_trait]
impl ExternalProjectTool for SharedRecorder {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> ExecutionReceipt {
        self.0.execute(request, cancellation).await
    }
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
    let name = if ["missing-tool", "rejected-admission", "absent-sandbox"].contains(&control) {
        "nonempty-clean"
    } else {
        control
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(FIXTURES)
        .join("go")
        .join(name);
    let mut paths = vec!["go.mod", "answer.go", "answer_test.go"];
    if control == "vulnerability-positive" {
        paths.push("go.sum");
    }
    if control == "build-tags" {
        paths.push("excluded_test.go");
    }
    if control == "cgo" {
        paths.push("cgo.go");
    }
    if control == "workspace" {
        paths.push("go.work");
    }
    paths
        .into_iter()
        .map(|p| (p.into(), fs::read_to_string(root.join(p)).unwrap()))
        .collect()
}
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for e in fs::read_dir(path).unwrap() {
                walk(root, &e.unwrap().path(), out);
            }
        } else {
            out.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}
fn case(base: &Path, retained: &Path, go_root: &Path, control: &str) -> Value {
    let case_id = format!("code-go-{control}");
    let root = base.join(&case_id).join("source");
    let fixtures = fixture_files(control);
    for (path, text) in &fixtures {
        let p = root.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(GO)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-code-sdk-fixture-key"))
        .unwrap();
    let provider = frozen.provider(GO).unwrap();
    let scratch = Arc::new(
        AuditScratch::with_scratch_dir(&root, retained.join("cases").join(&case_id)).unwrap(),
    );
    let scanner = fs::canonicalize(std::env::var_os("LEGION_GOVULNCHECK_BIN").unwrap()).unwrap();
    assert_eq!(scanner.file_name().unwrap(), "govulncheck");
    let tools: [(&str, PathBuf); 3] = [
        ("go", go_root.join("bin/go")),
        ("gofmt", go_root.join("bin/gofmt")),
        ("govulncheck", scanner.clone()),
    ];
    let tools: BTreeMap<String, (PathBuf, String)> = tools
        .into_iter()
        .map(|(n, p)| {
            let p = fs::canonicalize(p).unwrap();
            let b = fs::read(&p).unwrap();
            assert!(!p.starts_with(base) && !b.starts_with(b"#!"));
            (n.into(), (p, digest(&b)))
        })
        .collect();
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let (mut environment, allowlist) = expected_environment(scratch.root());
    let bin = go_root.join("bin");
    let search_dirs = vec![bin.clone(), scanner.parent().unwrap().to_path_buf()];
    environment.insert(
        "PATH".into(),
        std::env::join_paths(&search_dirs)
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
    );
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
    let native_result = if control == "absent-sandbox" {
        // Exact SDK refusal control, not an observed provider execution or owner receipt.
        let request = ExternalToolRequest {
            request_id: format!(
                "legion-audit/{}",
                digest(case_id.as_bytes()).trim_start_matches("sha256:")
            ),
            provider_id: GO.into(),
            plan_id: frozen.digest().into(),
            policy_id: "audit".into(),
            task_id: Some("module".into()),
            executable: policy.wrapper.to_string_lossy().into_owned(),
            args: policy.prefix("go", &ScopedPolicy::suffix("module")),
            cwd: root.to_string_lossy().into_owned(),
            expected_digest: Some(policy.wrapper_digest.clone()),
            version_args: policy.version_args("module"),
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
            let p = base.join(&case_id).join("empty-bin");
            fs::create_dir(&p).unwrap();
            vec![p]
        } else {
            search_dirs
        };
        let native = NativeProviderRegistry::new(&root)
            .with_scratch(scratch.clone())
            .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(SharedRecorder(
                recorder,
            ))))
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
        assert_eq!(report.planned_providers, vec![GO]);
        assert_eq!(report.results.len(), 1);
        serde_json::to_value(&report.results[0].result).unwrap()
    };
    let sdk = rows.lock().unwrap().clone();
    let decisions = policy.decisions.lock().unwrap().clone();
    let mut result = json!({"caseId":case_id,"control":control,"provider":GO,"scope":if control=="absent-sandbox" {"sdk-boundary-control"}else{"native-provider-known-answer-fixture"},
        "qualificationEligible":false,"fixtureFiles":fixtures,"fixtureSources":before,"inventory":inventory,
        "planDigest":frozen.digest(),"frozenProvider":provider,"nativeResult":native_result,
        "policyDefinition":policy.definition(),"policyDecisions":decisions,"sdkExecutions":sdk,
        "expected":{"providerQualificationEligible":false,"rawRule":if control=="positive" {json!("gofmt")}else{Value::Null}},"matched":false});
    fs::write(
        scratch.root().join("case-observation.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    assert_eq!(
        snapshot(&root),
        before,
        "exact fixture siblings must remain unchanged"
    );
    let rows = result["sdkExecutions"].as_array().unwrap();
    if control == "absent-sandbox" {
        assert_eq!(rows.len(), 1);
        let r = &rows[0]["executionReceipt"];
        assert_eq!(r["state"], "sandbox_missing");
        assert_eq!(r["policy"]["allowed"], true);
        assert_eq!(r["processTree"]["started"], false);
    } else {
        let expected_complete = matches!(
            control,
            "positive" | "nonempty-clean" | "vulnerability-positive" | "external-test"
        );
        assert_eq!(result["nativeResult"]["complete"],expected_complete,
            "complete fixture scope requires all five genuine tasks & full frozen source/context coverage");
        assert_eq!(
            result["nativeResult"]["coverage_gaps"]
                .as_array()
                .unwrap()
                .is_empty(),
            expected_complete
        );
        if expected_complete {
            let coverage = &result["nativeResult"]["coverage"];
            assert_eq!(coverage["expected"], before.len());
            assert_eq!(coverage["examined"], before.len());
        }
        if control == "missing-tool" {
            assert!(rows.is_empty());
            assert!(native_result.to_string().contains("tool-missing"));
        } else if control == "rejected-admission" {
            assert_eq!(rows.len(), 5);
            for row in rows {
                let r = &row["executionReceipt"];
                assert_eq!(r["state"], "unauthorized_effect");
                assert_eq!(r["processTree"]["started"], false);
                assert_eq!(r["policy"]["allowed"], false);
            }
        } else {
            assert_eq!(
                rows.len(),
                if control=="workspace" {4}else{5},
                "all applicable mandatory commands must execute; unsupported workspace vulnerability remains counted gap"
            );
            let tasks: BTreeSet<_> = rows
                .iter()
                .map(|r| r["request"]["taskId"].as_str().unwrap())
                .collect();
            let expected_tasks: BTreeSet<_> = if control == "workspace" {
                ["module", "vet", "format", "test"].into_iter().collect()
            } else {
                ["module", "vet", "format", "test", "vulnerability"]
                    .into_iter()
                    .collect()
            };
            assert_eq!(tasks, expected_tasks);
            for row in rows {
                let r = &row["executionReceipt"];
                assert_eq!(r["policy"]["allowed"], true);
                assert_eq!(r["policy"]["id"], POLICY);
                assert_eq!(r["planId"], frozen.digest());
                assert_eq!(r["providerId"], GO);
                assert_eq!(r["processTree"]["started"], true);
                assert_eq!(r["processTree"]["terminated"], true);
                assert_eq!(r["processTree"]["reaped"], true);
                assert_eq!(r["sandbox"]["receiptId"], policy.sandbox_id());
                assert_eq!(r["sandbox"]["required"], true);
                let malformed_probe_failure =
                    control == "malformed" && r["state"] == "unsealed_executable";
                if malformed_probe_failure {
                    assert_eq!(r["executable"]["version"]["qualified"], false);
                    assert_ne!(r["executable"]["version"]["exitCode"], 0);
                    assert!(r["executable"]["version"]["output"]
                        .as_str()
                        .unwrap()
                        .contains("invalid go version"));
                    assert_eq!(r["complete"], false);
                } else {
                    assert_eq!(r["executable"]["version"]["qualified"], true);
                }
                if row["request"]["taskId"] != "vulnerability" && !malformed_probe_failure {
                    assert!(r["executable"]["version"]["output"]
                        .as_str()
                        .unwrap()
                        .contains("go1.26.7"));
                }
                assert_eq!(
                    r["executable"]["version"]["args"],
                    row["request"]["versionArgs"]
                );
            }
            if control != "workspace" {
                let vulnerability = native_result["details"]["nativeProducer"]["toolReceipts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["tool"] == "vulnerability")
                    .expect("genuine vulnerability receipt retained by production producer");
                let snapshots = &vulnerability["nativeInputSnapshots"];
                assert_eq!(snapshots["unchanged"], true);
                assert!(snapshots["afterError"].is_null());
                assert_eq!(snapshots["before"], snapshots["after"]);
                assert_eq!(
                    snapshots["before"]["schema"],
                    "legion-govulncheck-input-snapshot/1"
                );
                assert_eq!(
                    snapshots["before"]["databaseDigest"],
                    "sha256:2078b194f64c8032800c110f934156298103d3e504ef58e9919faf5e0f5b05ed"
                );
                assert_eq!(
                    snapshots["before"]["databaseFiles"]
                        .as_object()
                        .unwrap()
                        .len(),
                    4713
                );
                let scanner_row = rows
                    .iter()
                    .find(|r| r["request"]["taskId"] == "vulnerability")
                    .unwrap();
                assert_eq!(vulnerability["sdkReceipt"], scanner_row["executionReceipt"]);
            }
            let test = rows
                .iter()
                .find(|r| r["request"]["taskId"] == "test")
                .unwrap();
            let format = rows
                .iter()
                .find(|r| r["request"]["taskId"] == "format")
                .unwrap();
            let raw = |row: &Value, stream: &str| {
                String::from_utf8(
                    row[stream]["rawBytes"]
                        .as_array()
                        .map(Vec::as_slice)
                        .unwrap_or(&[])
                        .iter()
                        .map(|n| n.as_u64().unwrap() as u8)
                        .collect(),
                )
                .unwrap()
            };
            match control {
                "positive" => {
                    assert_eq!(raw(format, "stdout").trim(), "answer.go");
                    assert_eq!(test["executionReceipt"]["exitCode"], 0);
                    assert!(native_result["details"]["findingEvidence"]
                        .as_object()
                        .unwrap()
                        .values()
                        .any(|f| f["ruleId"] == "gofmt"
                            && f["path"] == "answer.go"
                            && f["line"] == 1));
                }
                "nonempty-clean" => {
                    assert_eq!(raw(format, "stdout"), "");
                    assert_eq!(test["executionReceipt"]["exitCode"], 0);
                    assert!(native_result["findings"].as_array().unwrap().is_empty());
                    for row in rows {
                        assert_eq!(row["executionReceipt"]["state"], "completed");
                        assert_eq!(row["executionReceipt"]["exitCode"], 0);
                    }
                }
                "vulnerability-positive" => {
                    assert_eq!(test["executionReceipt"]["exitCode"], 0);
                    assert!(native_result["details"]["findingEvidence"]
                        .as_object()
                        .unwrap()
                        .values()
                        .any(|f| f["ruleId"] == "govulncheck:GO-2021-0113"
                            && (f["path"] == "answer.go" || f["path"] == "answer_test.go")
                            && f["line"] == 6));
                }
                "build-tags" | "cgo" => {
                    assert_eq!(test["executionReceipt"]["state"], "completed");
                    assert_eq!(test["executionReceipt"]["exitCode"], 0);
                    assert!(!raw(test, "stdout").contains("excluded build-tag test must not run"));
                    assert!(native_result["coverage_gaps"]
                        .to_string()
                        .contains("unproven-build-variant"));
                    assert_eq!(native_result["coverage"]["expected"], before.len());
                    assert_eq!(native_result["coverage"]["examined"], before.len());
                }
                "workspace" => {
                    assert_eq!(test["executionReceipt"]["exitCode"], 0);
                    for row in rows {
                        assert_eq!(row["executionReceipt"]["state"], "completed");
                    }
                    assert!(native_result["coverage_gaps"]
                        .to_string()
                        .contains("workspace-or-replacement-path-closure-unavailable"));
                    assert_eq!(native_result["coverage"]["expected"], before.len());
                    assert_eq!(native_result["coverage"]["examined"], before.len() - 1);
                }
                "external-test" => {
                    assert_eq!(test["executionReceipt"]["state"], "completed");
                    assert_eq!(test["executionReceipt"]["exitCode"], 0);
                    assert!(native_result["findings"].as_array().unwrap().is_empty());
                    for row in rows {
                        assert_eq!(row["executionReceipt"]["state"], "completed");
                    }
                }
                "test-failure" => {
                    assert_ne!(test["executionReceipt"]["exitCode"], 0);
                    assert_eq!(test["executionReceipt"]["state"], "failed");
                    assert!(raw(test, "stdout").contains("planted test failure"));
                }
                "malformed" => {
                    assert!(rows
                        .iter()
                        .any(|row| row["executionReceipt"]["state"] == "failed"
                            || row["executionReceipt"]["state"] == "unsealed_executable"));
                    assert!(rows.iter().any(|row| raw(row, "stderr")
                        .contains("invalid go version")
                        || row["executionReceipt"]["executable"]["version"]["output"]
                            .as_str()
                            .is_some_and(|text| text.contains("invalid go version"))));
                }
                _ => unreachable!(),
            }
        }
    }
    if control != "absent-sandbox" {
        let actual_gaps: BTreeSet<String> = native_result["coverage_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let mut expected_gaps = BTreeSet::new();
        let tool_gap = |task: &str| format!("code.go:tool-evidence-gap:{task}");
        match control {
            "build-tags" => {
                for file in ["answer.go", "excluded_test.go"] {
                    expected_gaps
                        .insert(format!("code.go:govulncheck:unproven-build-variant:{file}"));
                }
            }
            "cgo" => {
                expected_gaps.insert("code.go:govulncheck:unproven-build-variant:cgo.go".into());
            }
            "workspace" => {
                expected_gaps.extend([
                    tool_gap("vulnerability"),
                    "code.go:govulncheck:workspace-or-replacement-path-closure-unavailable".into(),
                    "code.go:tool-not-run:vulnerability:govulncheck-input-incomplete".into(),
                    "code.go:selection-narrower-than-denominator:3of4".into(),
                ]);
            }
            "missing-tool" => {
                for task in ["module", "format", "vet", "test", "vulnerability"] {
                    expected_gaps.insert(tool_gap(task));
                    expected_gaps.insert(format!("code.go:tool-missing:{task}"));
                }
            }
            "rejected-admission" => {
                for task in ["module", "format", "vet", "test", "vulnerability"] {
                    expected_gaps.insert(tool_gap(task));
                }
                expected_gaps.insert("code.go:native-owner-admission-unavailable".into());
            }
            "test-failure" | "malformed" => {
                for row in rows {
                    let task = row["request"]["taskId"].as_str().unwrap();
                    let receipt = &row["executionReceipt"];
                    if receipt["state"] == "failed" {
                        let exit = receipt["exitCode"].as_i64().unwrap();
                        assert_ne!(exit, 0);
                        expected_gaps.insert(tool_gap(task));
                        expected_gaps.insert(format!("code.go:tool-failed:{task}:exit-{exit}"));
                    } else if control == "malformed" && receipt["state"] == "unsealed_executable" {
                        expected_gaps.insert(tool_gap(task));
                        expected_gaps
                            .insert(format!("code.go:tool-failed:{task}:unsealed_executable"));
                    } else {
                        assert_eq!(receipt["state"], "completed");
                        assert_eq!(receipt["exitCode"], 0);
                    }
                }
            }
            _ => {}
        }
        // A tool that did not run also reports `unavailable:<reason>` (the
        // typed availability gap); the reason is the tool gap without its
        // provider prefix, and owner-admission denial reports its own reason.
        let twins: Vec<String> = expected_gaps
            .iter()
            .filter_map(|gap| {
                let rest = gap.strip_prefix("code.go:")?;
                ["tool-not-run:", "tool-failed:", "tool-missing:"]
                    .iter()
                    .any(|prefix| rest.starts_with(prefix))
                    .then(|| format!("unavailable:{rest}"))
            })
            .collect();
        expected_gaps.extend(twins);
        if expected_gaps.contains("code.go:native-owner-admission-unavailable") {
            expected_gaps.insert("unavailable:native-owner-admission-unavailable".into());
        }
        assert_eq!(
            actual_gaps, expected_gaps,
            "every runtime gap must match source-owned expected control disposition"
        );
    }
    if control == "nonempty-clean" {
        let captured = requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.task_id.as_deref() == Some("module"))
            .unwrap()
            .clone();
        result["requestMutationControls"] = request_mutations(&captured, &policy, &runtime);
    }
    result["matched"] = json!(true);
    fs::write(
        scratch.root().join("case-observation.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    result
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
                request.executable = original.tools["go"].0.to_string_lossy().into_owned()
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
fn toolchain_tree(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(
            !metadata.file_type().is_symlink(),
            "runtime tree cannot contain symlinks"
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), files);
            }
        } else {
            assert!(metadata.is_file(), "runtime tree requires regular files");
            files.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    assert!(!files.is_empty());
    files
}
fn verify_govuln_enrollment(enrollment: &Value, go_root: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let lock_bytes = fs::read(source.join("scripts/ci/audit-govulncheck-inputs.json")).unwrap();
    let lock: Value = serde_json::from_slice(&lock_bytes).unwrap();
    assert_eq!(lock["schema"], "legion-govulncheck-inputs/1");
    assert_eq!(enrollment["schema"], "legion-govulncheck-enrollment/1");
    assert_eq!(enrollment["qualificationEligible"], false);
    assert_eq!(enrollment["inputsDigest"], digest(&lock_bytes));
    assert_eq!(enrollment["database"]["files"], lock["database"]["files"]);
    assert_eq!(enrollment["database"]["digest"], lock["database"]["digest"]);
    assert_eq!(enrollment["moduleProxy"], lock["moduleProxy"]);
    for name in GOVULN_ENV {
        assert_eq!(
            enrollment["environment"][name].as_str().unwrap(),
            std::env::var(name).unwrap()
        );
    }
    assert_eq!(
        enrollment["go"]["runtime"]["root"].as_str().unwrap(),
        go_root.to_str().unwrap()
    );
    for part in ["database", "moduleCache"] {
        let root = Path::new(enrollment[part]["root"].as_str().unwrap());
        let files = toolchain_tree(root);
        assert_eq!(json!(files), enrollment[part]["files"]);
        assert_eq!(
            digest(&canonical_bytes(&json!(files))),
            enrollment[part]["digest"]
        );
    }
    assert_eq!(
        json!(toolchain_tree(go_root)),
        enrollment["go"]["runtime"]["files"]
    );
    let scanner = &enrollment["scanner"];
    assert_eq!(scanner["module"], lock["scanner"]["module"]);
    assert_eq!(scanner["version"], lock["scanner"]["version"]);
    assert_eq!(
        digest(&fs::read(scanner["path"].as_str().unwrap()).unwrap()),
        scanner["digest"]
    );
    assert_eq!(scanner["buildInfo"]["exitCode"], 0);
    assert!(scanner["buildInfo"]["stdout"]
        .as_str()
        .unwrap()
        .contains("\tmod\tgolang.org/x/vuln\tv1.9.0\t"));
    let archive = fs::read(enrollment["databaseArchivePath"].as_str().unwrap()).unwrap();
    assert_eq!(digest(&archive), enrollment["databaseArchiveDigest"]);
    assert_eq!(
        digest(&archive),
        format!("sha256:{}", lock["database"]["sha256"].as_str().unwrap())
    );
    let cache = enrollment["moduleCache"]["files"].as_object().unwrap();
    let positive: BTreeMap<String, Value> = cache
        .iter()
        .filter_map(|(p, d)| {
            p.strip_prefix("golang.org/x/text@v0.3.6/")
                .map(|rel| (rel.to_owned(), d.clone()))
        })
        .collect();
    assert_eq!(json!(positive), lock["positiveControl"]["files"]);
}
fn contract(id: &str) -> Value {
    let c = code::evidence::config_for(id).unwrap();
    json!({"tools":c.tools,"extensions":c.extensions,"variants":c.variants,"requiredContext":c.required_context,
        "coverageRequirement":"bounded SDK accuracy requires every declared tool/context & source-owned control; arbitrary-input, platform & variant completeness remains distinct"})
}
#[test]
#[ignore = "constructed SDK controls; requires pinned Go1.26.7, native macOS sandbox & explicit external scratch/output roots"]
fn real_code_command_accuracy() {
    if let Some(base) = std::env::var_os("LEGION_CODE_COMMAND_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let retained =
            fs::canonicalize(std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR").unwrap()).unwrap();
        let go_root = fs::canonicalize(std::env::var_os("LEGION_GO_ROOT").unwrap()).unwrap();
        let archive = PathBuf::from(std::env::var_os("LEGION_GO_ARCHIVE").unwrap());
        let expected = match std::env::consts::ARCH {
            "aarch64" => "sha256:020a1e8224811be75163e920bc77e0926a1390a6aeea19bdcf23f74b9d749f6d",
            "x86_64" => "sha256:92e8b34bff3c89ab16404c595669ac8cb004cc2f676dcbd1f5b87a6b8def3b47",
            _ => panic!("unsupported pinned Go archive architecture"),
        };
        assert_eq!(digest(&fs::read(&archive).unwrap()), expected);
        assert_eq!(
            fs::read_to_string(go_root.join("VERSION"))
                .unwrap()
                .lines()
                .next(),
            Some("go1.26.7")
        );
        let tree_before = toolchain_tree(&go_root);
        let tree_value = json!({"root":go_root,"files":tree_before});
        let tree_bytes = serde_json::to_vec_pretty(&tree_value).unwrap();
        fs::write(retained.join("toolchain-tree.json"), &tree_bytes).unwrap();
        let tree_descriptor = json!({"file":"toolchain-tree.json","digest":digest(&tree_bytes),"bytes":tree_bytes.len(),"fileCount":tree_before.len()});
        let enrollment_path = fs::canonicalize(
            std::env::var_os("LEGION_GOVULNCHECK_ENROLLMENT_JSON")
                .expect("CI-provisioned immutable enrollment required"),
        )
        .unwrap();
        let enrollment_bytes = fs::read(&enrollment_path).unwrap();
        fs::write(
            retained.join("govulncheck-enrollment.json"),
            &enrollment_bytes,
        )
        .unwrap();
        assert_eq!(
            fs::read(retained.join("govulncheck-enrollment.json")).unwrap(),
            enrollment_bytes
        );
        let enrollment_descriptor = json!({"file":"govulncheck-enrollment.json","digest":digest(&enrollment_bytes),"bytes":enrollment_bytes.len()});
        let enrollment: Value = serde_json::from_slice(&enrollment_bytes).unwrap();
        verify_govuln_enrollment(&enrollment, &go_root);
        let cases: Vec<Value> = CONTROLS
            .into_iter()
            .map(|control| case(&base, &retained, &go_root, control))
            .collect();
        assert_eq!(
            toolchain_tree(&go_root),
            tree_before,
            "full pinned Go compiler/linker/stdlib tree must remain unchanged"
        );
        verify_govuln_enrollment(&enrollment, &go_root);
        assert_eq!(
            fs::read(&enrollment_path).unwrap(),
            enrollment_bytes,
            "original enrollment bytes must remain unchanged"
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
                            d.as_str().unwrap().to_owned(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let tools: BTreeMap<String, String> = ["go", "gofmt"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    digest(&fs::read(go_root.join("bin").join(name)).unwrap()),
                )
            })
            .collect();
        let go_config = code::evidence::config_for(GO).unwrap();
        assert_eq!(
            go_config.tools,
            ["module", "format", "vet", "test", "vulnerability"]
        );
        assert_eq!(go_config.required_context, ["modules", "buildTags"]);
        assert_eq!(go_config.extensions, ["go"]);
        assert_eq!(json!(go_config.variants), json!([["go", ["go"]]]));
        let complete_controls = cases
            .iter()
            .filter(|case| {
                matches!(
                    case["control"].as_str(),
                    Some(
                        "positive" | "nonempty-clean" | "vulnerability-positive" | "external-test"
                    )
                )
            })
            .all(|case| {
                case["nativeResult"]["complete"] == true
                    && case["nativeResult"]["coverage_gaps"]
                        .as_array()
                        .unwrap()
                        .is_empty()
            });
        let mutations = cases
            .iter()
            .find(|case| case["control"] == "nonempty-clean")
            .unwrap()["requestMutationControls"]
            .as_array()
            .unwrap();
        let go_eligible = cases.len() == CONTROLS.len()
            && cases.iter().all(|case| case["matched"] == true)
            && complete_controls
            && mutations.len() == 4
            && mutations.iter().all(|case| case["matched"] == true);
        assert!(go_eligible,"bounded SDK accuracy requires full source-owned control matrix & genuine complete positive/clean controls");
        for id in PROVIDERS {
            let observed = id == GO;
            let eligible = observed && go_eligible;
            let mut record = json!({"schema":"legion-code-command-sdk-accuracy/1","kind":"code-command-sdk-constructed",
                "provider":id,"providerVersion":registry_spec(id)["providerVersion"],"productionQualification":false,"qualificationEligible":eligible,
                "claimScope":"known-answer-fixture-cases","executionPath":"native-sdk-frozen-plan-self-sourced-code","modelCalls":0,
                "admissionScope":"explicit constructed SDK authorizer; genuine OwnerAdmissionRequired denial control; no production owner-admission claim",
                "binding":binding(id,&fixture_sources),"requiredContract":contract(id),
                "toolchain":{"version":"go1.26.7","root":go_root,"archive":archive,"archiveDigest":expected,"binaryDigests":tools,"tree":tree_descriptor},
                "goVulnerability":{"enrollment":enrollment_descriptor},
                "executedScope":if observed {json!(["module","format","vet","test","vulnerability"])}else{json!([])},
                "missingControls":if eligible {json!([])}
                    else {json!([{"scope":"entire-provider-contract","reason":"not exercised by this Go fixture slice","required":contract(id)}])},
                "runtimeLimitations":if observed {json!([
                    {"control":"build-tags","scope":"excluded-build-variants","providerComplete":false},
                    {"control":"cgo","scope":"excluded-cgo-source","providerComplete":false},
                    {"control":"workspace","scope":"workspace-path-closure-unavailable","providerComplete":false}])}else{json!([])},
                "cases":if observed {json!(cases)}else{json!([])},
                "metrics":{"cases":if observed {cases.len()}else{0},"matched":if observed {cases.iter().filter(|case|case["matched"]==true).count()}else{0},"mismatched":if observed {cases.iter().filter(|case|case["matched"]!=true).count()}else{0},"wholeProviderQualified":false,"boundedSdkAccuracyQualified":eligible},
                "status":if eligible {"observed-known-answer-controls"}else{"unavailable"}});
            record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
            let file = format!("{}.json", id.replace('.', "_"));
            let bytes = serde_json::to_vec_pretty(&record).unwrap();
            fs::write(retained.join(&file), &bytes).unwrap();
            assert_eq!(fs::read(retained.join(&file)).unwrap(), bytes);
            let summary = json!({"schema":"legion-code-command-sdk-artifact/1","provider":id,"file":file,
                "digest":digest(&bytes),"bytes":bytes.len(),"qualificationDigest":record["qualificationDigest"],
                "qualificationEligible":eligible,"productionQualification":false});
            println!(
                "CODE_COMMAND_SDK_ACCURACY_ARTIFACT {}",
                serde_json::to_string(&summary).unwrap()
            );
        }
        return;
    }
    let fixture = Fixture::new();
    let retained = PathBuf::from(
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR")
            .expect("explicit retained code SDK output root required"),
    );
    assert!(retained.is_absolute());
    fs::create_dir_all(&retained).unwrap();
    let retained = fs::canonicalize(retained).unwrap();
    assert!(!retained.starts_with(&fixture.0) && !fixture.0.starts_with(&retained));
    let go_root = fs::canonicalize(
        std::env::var_os("LEGION_GO_ROOT")
            .expect("existing CI-provisioned pinned Go root required"),
    )
    .unwrap();
    let archive = fs::canonicalize(
        std::env::var_os("LEGION_GO_ARCHIVE").expect("existing authenticated Go archive required"),
    )
    .unwrap();
    let govuln_environment: BTreeMap<String, String> = GOVULN_ENV
        .into_iter()
        .map(|name| {
            let value =
                std::env::var_os(name).expect("exact CI govulncheck enrollment export required");
            let path = fs::canonicalize(value).unwrap();
            assert!(path.is_absolute() && !path.starts_with(&fixture.0));
            (name.to_owned(), path.to_str().unwrap().to_owned())
        })
        .collect();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_code_command_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", go_root.join("bin"))
        .env("HOME", fixture.0.join("home"))
        .env("XDG_CONFIG_HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("GOROOT", &go_root)
        .env("LEGION_GO_ROOT", &go_root)
        .env("LEGION_GO_ARCHIVE", &archive)
        .envs(&govuln_environment)
        .env("LEGION_CODE_COMMAND_CHILD", &fixture.0)
        .env("LEGION_PROVIDER_BENCHMARK_DIR", &retained)
        .output()
        .unwrap();
    fs::write(retained.join("child.stdout.log"), &output.stdout).unwrap();
    fs::write(retained.join("child.stderr.log"), &output.stderr).unwrap();
    fs::write(retained.join("child-execution.json"),serde_json::to_vec_pretty(&json!({"schema":"legion-code-command-child-execution/1",
        "productionQualification":false,"status":{"success":output.status.success(),"exitCode":output.status.code(),"signal":output.status.signal()},
        "stdout":{"file":"child.stdout.log","bytes":output.stdout.len(),"sha256":digest(&output.stdout)},
        "stderr":{"file":"child.stderr.log","bytes":output.stderr.len(),"sha256":digest(&output.stderr)}})).unwrap()).unwrap();
    assert!(
        output.status.success(),
        "actual code SDK child failed; original receipt/artifacts & full streams retained"
    );
    let marker = b"CODE_COMMAND_SDK_ACCURACY_ARTIFACT ";
    let lines: Vec<&[u8]> = output
        .stdout
        .split_inclusive(|b| *b == b'\n')
        .filter_map(|line| {
            line.windows(marker.len())
                .position(|w| w == marker)
                .map(|p| &line[p..])
        })
        .collect();
    assert_eq!(lines.len(), PROVIDERS.len());
    for (line, id) in lines.iter().zip(PROVIDERS) {
        assert_eq!(line.last(), Some(&b'\n'));
        let r: Value = serde_json::from_slice(&line[marker.len()..]).unwrap();
        assert_eq!(r["schema"], "legion-code-command-sdk-artifact/1");
        assert_eq!(r["provider"], id);
        assert_eq!(r["qualificationEligible"], id == GO);
        assert_eq!(r["productionQualification"], false);
        let file = format!("{}.json", id.replace('.', "_"));
        assert_eq!(r["file"], file);
        let bytes = fs::read(retained.join(&file)).unwrap();
        assert_eq!(r["digest"], digest(&bytes));
        assert_eq!(r["bytes"], bytes.len());
        let mut record: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record["provider"], id);
        assert_eq!(record["qualificationDigest"], r["qualificationDigest"]);
        assert_eq!(record["qualificationEligible"], id == GO);
        assert_eq!(record["productionQualification"], false);
        let q = record
            .as_object_mut()
            .unwrap()
            .remove("qualificationDigest")
            .unwrap();
        assert_eq!(q, digest(&canonical_bytes(&record)));
    }
    let mut stdout = std::io::stdout().lock();
    for line in lines {
        stdout.write_all(line).unwrap();
    }
}
