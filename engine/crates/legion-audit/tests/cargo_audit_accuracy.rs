//! Constructed native cargo-audit controls through shipped legacy provider & actual SDK.
//! Explicit fixture authorizer; no production CLI owner-admission claim.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute_with_cancellation,
    native_providers::legacy_checks::{resolve_request, AuditExternalProjectTool, AuditScratch},
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use legion_provider_sdk::{ExecutionReceipt, ExternalProjectTool};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

const SOURCE: &str = "engine/crates/legion-audit/tests/cargo_audit_accuracy.rs";
const POLICY: &str = "legion-cargo-audit-offline-fixture-v1";
const ID: &str = "legacy.security.rust-advisories";
const FIXTURES: &str = "engine/crates/legion-audit/tests/fixtures/cargo-audit";
const ARGV: &[&str] = &["audit", "--json"];
const SCOPE: &str = "constructed native SDK + pinned unchanged official RustSec advisory subset; aggregate unadjudicated candidate only";
const CONTROLS: &[&str] = &[
    "positive",
    "absence",
    "missing-database",
    "malformed-lock",
    "unsupported-argv",
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

fn generated_session_provenance(relative: &Path) -> bool {
    let Ok(tail) = relative
        .strip_prefix("engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance")
    else {
        return false;
    };
    let mut components = tail.components();
    let Some(std::path::Component::Normal(name)) = components.next() else {
        return false;
    };
    if components.next().is_some() {
        return false;
    }
    name.to_str()
        .and_then(|name| name.strip_suffix(".json"))
        .is_some_and(|name| {
            name.len() == 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn source_binding_walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
    assert!(!path.is_symlink(), "source binding refuses symlinks");
    if path.is_file() && generated_session_provenance(path.strip_prefix(root).unwrap()) {
        return;
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            source_binding_walk(root, &entry.unwrap().path(), files);
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
    let base = std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
    let root = base.join(format!(
        "legion-source-binding-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    let receipt = format!("{prefix}{}.json", "a".repeat(64));
    let retained = [
        "engine/crates/legion-audit/src/mod.rs".to_owned(),
        "engine/crates/legion-audit/src/nested/.audit/anything.rs".to_owned(),
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}{}.json", "a".repeat(65)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("{prefix}{}.json/child.rs", "b".repeat(64)),
        format!("engine/crates/legion-audit/src/nested/.audit/arcane/receipts/session-provenance/{}.json", "a".repeat(64)),
    ];
    for relative in retained.iter().chain(std::iter::once(&receipt)) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"original source\n").unwrap();
    }
    let source = root.join("engine/crates/legion-audit/src");
    let collect = || {
        let mut files = BTreeMap::new();
        source_binding_walk(&root, &source, &mut files);
        files
    };
    let before = collect();
    assert!(!before.contains_key(&receipt));
    for relative in &retained {
        assert_eq!(
            before.get(relative),
            Some(&digest(b"original source\n")),
            "{relative}"
        );
    }
    fs::write(root.join(&receipt), b"changed generated receipt\n").unwrap();
    assert_eq!(collect(), before);
    for relative in &retained {
        fs::write(root.join(relative), b"changed source\n").unwrap();
        assert_ne!(collect().get(relative), before.get(relative), "{relative}");
        fs::write(root.join(relative), b"original source\n").unwrap();
    }
    let excluded_name = root.join(&receipt);
    fs::remove_file(&excluded_name).unwrap();
    std::os::unix::fs::symlink(root.join(&retained[0]), &excluded_name).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect())).is_err());
    fs::remove_file(&excluded_name).unwrap();
    std::os::unix::fs::symlink(&source, &excluded_name).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect())).is_err());
    fs::remove_file(&excluded_name).unwrap();
    fs::write(&excluded_name, b"genuine generated receipt\n").unwrap();
    assert!(!collect().contains_key(&receipt));
    // On Unix these backslashes are filename bytes, not path separators.
    let alias = source.join(format!(
        r".audit\arcane\receipts\session-provenance\{}.json",
        "a".repeat(64)
    ));
    assert!(!generated_session_provenance(
        alias.strip_prefix(&root).unwrap()
    ));
    fs::write(&alias, b"literal-backslash source\n").unwrap();
    let original_alias = digest(b"literal-backslash source\n");
    assert_eq!(collect().get(&receipt), Some(&original_alias));
    fs::write(&alias, b"changed literal-backslash source\n").unwrap();
    assert_eq!(
        collect().get(&receipt),
        Some(&digest(b"changed literal-backslash source\n"))
    );
    assert_ne!(collect().get(&receipt), Some(&original_alias));
    fs::remove_dir_all(&root).unwrap();
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
    ] {
        source_binding_walk(&root, &root.join(path), &mut sources);
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
        "retainedRoot": fs::canonicalize(std::env::var_os("LEGION_CARGO_AUDIT_RECEIPTS").unwrap()).unwrap()
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
    env.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
    env.insert("PYTHONNOUSERSITE".into(), "1".into());
    env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
    allowed.insert("PYTHONDONTWRITEBYTECODE".into());
    allowed.insert("PYTHONNOUSERSITE".into());
    allowed.insert("GIT_CONFIG_NOSYSTEM".into());
    (env, allowed)
}

struct ScopedPolicy {
    id: String,
    check: String,
    plan: String,
    root: PathBuf,
    tool: PathBuf,
    tool_digest: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    profile: PathBuf,
    profile_text: String,
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
    accepted_exits: BTreeSet<i32>,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn sandbox_id(&self) -> String {
        format!(
            "sandbox:macos:{}",
            digest(self.profile_text.as_bytes()).trim_start_matches("sha256:")
        )
    }

    fn wrapped_args(&self, suffix: &[String]) -> Vec<String> {
        let mut args = vec![
            "-f".into(),
            self.profile.to_string_lossy().into_owned(),
            "--".into(),
            self.tool.to_string_lossy().into_owned(),
        ];
        args.extend_from_slice(suffix);
        args
    }

    fn definition(&self) -> Value {
        json!({
            "id": POLICY,
            "version": 1,
            "provider": self.id,
            "task": self.check,
            "plan": self.plan,
            "cwd": self.root,
            "artifactRequestId": "legion-audit/<64 lowercase hex>; one admission only",
            "tool": {"path": self.tool, "digest": self.tool_digest},
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest},
            "profile": {"path": self.profile, "text": self.profile_text,
                "digest": digest(self.profile_text.as_bytes()), "receiptId": self.sandbox_id()},
            "args": self.args,
            "wrappedArgs": self.wrapped_args(&self.args),
            "versionArgs": self.wrapped_args(&["--version".into()]),
            "environment": self.environment,
            "environmentAllowlist": self.allowlist,
            "timeoutMs": 120000,
            "stdoutLimit": 8388608,
            "stderrLimit": 8388608,
            "sandbox": "native-macos-allow-network-deny-project-write-cargo-audit-contract",
            "acceptedExitCodes": self.accepted_exits
        })
    }

    fn permits(&self, req: &ExternalToolRequest) -> bool {
        let artifact_id = req.request_id.strip_prefix("legion-audit/");
        req.schema_version == 1
            && artifact_id.is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            && req.provider_id == self.id
            && req.plan_id == self.plan
            && req.policy_id == "audit"
            && req.task_id.as_deref() == Some(self.check.as_str())
            && req.cwd == self.root.to_string_lossy().as_ref()
            && req.origin == ToolOrigin::TargetProject
            && !req.shell
            && req.requires_network_sandbox
            && req.sandbox.as_ref().is_some_and(|sandbox| {
                sandbox.id == self.sandbox_id()
                    && sandbox.network
                    && sandbox.filesystem_scope.as_deref() == self.root.to_str()
            })
            && !req.skip_version_probe
            && req.version_requirement.is_none()
            && req.executable == self.wrapper.to_string_lossy().as_ref()
            && req.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && fs::read(&self.wrapper).is_ok_and(|bytes| digest(&bytes) == self.wrapper_digest)
            && fs::read(&self.tool).is_ok_and(|bytes| digest(&bytes) == self.tool_digest)
            && !self.profile.is_symlink()
            && fs::read(&self.profile)
                .is_ok_and(|bytes| bytes.as_slice() == self.profile_text.as_bytes())
            && req.args == self.wrapped_args(&self.args)
            && req.version_args == self.wrapped_args(&["--version".into()])
            && req.environment == self.environment
            && req.environment_allowlist == self.allowlist
            && req.sensitive_argument_indexes.is_empty()
            && req.sensitive_environment_names.is_empty()
            && req.timeout_ms == 120000
            && req.stdout_limit == 8388608
            && req.stderr_limit == 8388608
            && req.accepted_exit_codes == self.accepted_exits
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let mut decisions = self.decisions.lock().unwrap();
        let allowed = decisions.is_empty() && self.permits(request);
        decisions.push(json!({
            "allowed": allowed,
            "requestId": request.request_id,
            "providerId": request.provider_id,
            "planId": request.plan_id,
            "taskId": request.task_id,
            "executable": request.executable,
            "expectedDigest": request.expected_digest,
            "args": request.args,
            "versionArgs": request.version_args,
            "cwd": request.cwd,
            "environmentNames": request.environment.keys().collect::<Vec<_>>(),
            "environmentDigest": digest(&serde_json::to_vec(&request.environment).unwrap()),
            "timeoutMs": request.timeout_ms,
            "stdoutLimit": request.stdout_limit,
            "stderrLimit": request.stderr_limit,
            "acceptedExitCodes": request.accepted_exit_codes,
            "requiresNetworkSandbox": request.requires_network_sandbox,
            "sandbox": request.sandbox.as_ref().map(|sandbox| json!({"id": sandbox.id,
                "network": sandbox.network, "filesystemScope": sandbox.filesystem_scope}))
        }));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact constructed cargo-audit fixture admission"
                } else {
                    "outside exact constructed cargo-audit fixture policy"
                }
                .into(),
            ),
        }
    }
}

struct SharedPolicy(Arc<ScopedPolicy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(request)
    }
}

fn artifact(receipt: &Value, stream: &str, scratch: &AuditScratch) -> Vec<u8> {
    let item = &receipt[stream];
    assert_eq!(item["immutable"], true);
    let relative = Path::new(item["path"].as_str().unwrap());
    assert!(!relative.is_absolute());
    let root = fs::canonicalize(scratch.artifacts_dir()).unwrap();
    let path = fs::canonicalize(root.join(relative)).unwrap();
    assert!(path.starts_with(&root));
    let bytes = fs::read(path).unwrap();
    assert_eq!(item["digest"], digest(&bytes));
    assert_eq!(item["bytes"], bytes.len());
    bytes
}

fn retained(root: &Path, artifact: &legion_effects::ArtifactRecord) -> Value {
    let bytes = fs::read(root.join(&artifact.path)).unwrap();
    assert!(artifact.immutable);
    assert_eq!(digest(&bytes), artifact.digest);
    assert_eq!(bytes.len(), artifact.bytes);
    json!({"path": artifact.path, "digest": artifact.digest, "bytes": artifact.bytes, "immutable": artifact.immutable, "raw": String::from_utf8(bytes).unwrap()})
}
/// Exact field projection of actual EffectExecutor receipt; no inferred process proof.
fn receipt_json(receipt: &legion_effects::ExecutionReceipt, artifacts: &Path) -> Value {
    json!({"schemaVersion": receipt.schema_version, "receiptId": receipt.receipt_id,
        "requestId": receipt.request_id, "providerId": receipt.provider_id, "planId": receipt.plan_id,
        "policyId": receipt.policy_id, "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}",e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}",e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified,"skippedByPolicy":e.version.skipped_by_policy}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd":receipt.cwd,"environmentNames":receipt.environment_names,
        "sandbox":{"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree":{"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing":{"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode":receipt.exit_code,"signal":receipt.signal,
        "stdout":receipt.stdout.as_ref().map(|a| retained(artifacts,a)),"stderr":receipt.stderr.as_ref().map(|a| retained(artifacts,a)),
        "parser":{"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error},"gaps":receipt.gaps})
}
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink(), "fixture snapshots refuse symlinks");
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), files);
            }
        } else {
            files.insert(
                path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

struct RecordingTool {
    inner: Arc<dyn ExternalProjectTool>,
    receipts: Arc<Mutex<Vec<ExecutionReceipt>>>,
    unsupported_argv: bool,
}
#[async_trait::async_trait]
impl ExternalProjectTool for RecordingTool {
    async fn execute(
        &self,
        mut request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        if self.unsupported_argv {
            // Deliberate regression control: reproduce old unsupported direct argv.
            // This case is explicitly excluded from shipped-command success claims.
            assert_eq!(request.args.get(4).map(String::as_str), Some("audit"));
            request.args.remove(4);
        }
        let receipt = self.inner.execute(request, cancellation).await;
        self.receipts.lock().unwrap().push(receipt.clone());
        receipt
    }
}

fn pin() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "sha256:33fbe81adca1b794f4ffe98574d59b0ebe6fcfdb310976fafed98a094c795111"
    } else if cfg!(target_arch = "x86_64") {
        "sha256:1a63bb3ab4f99a0220a8e4d8a677692afe5901cb44a949b2473c545a02028326"
    } else {
        panic!("unsupported pinned cargo-audit architecture")
    }
}
fn case(base: &Path, control: &str) -> Value {
    let fixture = base.join(control);
    fs::create_dir(&fixture).unwrap();
    let root = fixture.join("source");
    let run = fixture.join("run");
    let database = fixture.join("database");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let checked = repository.join(FIXTURES);
    fs::create_dir_all(root.join(".cargo")).unwrap();
    let lock_control = if control == "positive" {
        "positive"
    } else if control == "malformed-lock" {
        "malformed-lock"
    } else {
        "absence"
    };
    for (relative, source) in [
        ("Cargo.toml", checked.join("Cargo.toml")),
        ("Cargo.lock", checked.join(lock_control).join("Cargo.lock")),
    ] {
        fs::write(root.join(relative), fs::read(source).unwrap()).unwrap();
    }
    let config = fs::read_to_string(checked.join("audit.toml.in"))
        .unwrap()
        .replace("@DATABASE@", &serde_json::to_string(&database).unwrap());
    fs::write(root.join(".cargo/audit.toml"), &config).unwrap();
    let advisory = fs::read(checked.join("RUSTSEC-2019-0009.md")).unwrap();
    assert_eq!(
        digest(&advisory),
        "sha256:678bd66f3703ac7279a9b9fe4219fbe3903395d8411d899647ee8136d19241c5"
    );
    if control != "missing-database" {
        fs::create_dir_all(database.join("crates/smallvec")).unwrap();
        fs::write(
            database.join("crates/smallvec/RUSTSEC-2019-0009.md"),
            &advisory,
        )
        .unwrap();
    }
    // fetch=false takes Database::open, not Git/freshness code. No synthetic Git metadata.
    assert!(!database.join(".git").exists());
    let before = snapshot(&root);
    let database_before = if database.exists() {
        snapshot(&database)
    } else {
        BTreeMap::new()
    };
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(control)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(ID)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-cargo-audit-fixture-key"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    assert_eq!(provider.configuration["denominatorCount"], 1);
    let resolved = resolve_request(&root, "cargo-audit", &["--json".into()]).unwrap();
    assert_eq!(
        resolved.args,
        ARGV.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>()
    );
    let tool = fs::canonicalize(&resolved.executable).unwrap();
    assert_eq!(
        tool,
        fs::canonicalize(std::env::var_os("LEGION_CARGO_AUDIT_BIN").unwrap()).unwrap()
    );
    assert_eq!(digest(&fs::read(&tool).unwrap()), pin());
    assert!(!fs::read(&tool).unwrap().starts_with(b"#!"));
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let escaped = root
        .to_str()
        .unwrap()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile_text = format!("(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
    let profile = scratch.sandbox_dir().join(format!(
        "audit-{}.sb",
        digest(profile_text.as_bytes()).trim_start_matches("sha256:")
    ));
    let (environment, allowlist) = expected_environment(&run);
    let unsupported = control == "unsupported-argv";
    let args = if unsupported {
        vec!["--json".into()]
    } else {
        ARGV.iter().map(|a| (*a).into()).collect()
    };
    let policy = Arc::new(ScopedPolicy {
        id: ID.into(),
        check: "cargo_audit".into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: pin().into(),
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        profile,
        profile_text,
        args,
        environment,
        allowlist,
        accepted_exits: [0, 1, 2].into_iter().collect(),
        decisions: Mutex::new(Vec::new()),
    });
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
        SharedPolicy(policy.clone()),
    );
    let actual_receipts = Arc::new(Mutex::new(Vec::new()));
    let recording = RecordingTool {
        inner: Arc::new(AuditExternalProjectTool::new(effects)),
        receipts: actual_receipts.clone(),
        unsupported_argv: unsupported,
    };
    let mut native = NativeProviderRegistry::new(&root)
        .with_scratch(scratch.clone())
        .with_external_project_tool(Arc::new(recording));
    native.legacy_checks = native
        .legacy_checks
        .with_fixture_policy_authorizer(policy.clone());
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &native,
            CancellationToken::new(),
        ))
        .unwrap();
    assert_eq!(report.planned_providers, vec![ID]);
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0].result;
    let projected = &result.details["executionReceipt"];
    let raw_receipts = actual_receipts.lock().unwrap();
    assert_eq!(raw_receipts.len(), 1);
    let actual = receipt_json(&raw_receipts[0], &scratch.artifacts_dir());
    assert_eq!(actual["receiptId"], projected["receiptId"]);
    let stdout = artifact(projected, "stdout", &scratch);
    let stderr = artifact(projected, "stderr", &scratch);
    let stdout_text = std::str::from_utf8(&stdout).unwrap();
    let stderr_text = std::str::from_utf8(&stderr).unwrap();
    assert_eq!(
        actual["executable"]["version"]["output"]
            .as_str()
            .unwrap()
            .trim(),
        "cargo-audit 0.22.2"
    );
    assert_eq!(actual["complete"], true);
    assert_eq!(actual["state"], "completed");
    assert_eq!(actual["gaps"], json!([]));
    let failure = !matches!(control, "positive" | "absence");
    let expected_exit = if control == "absence" {
        0
    } else if control == "malformed-lock" || unsupported {
        2
    } else {
        1
    };
    assert_eq!(actual["exitCode"], expected_exit);
    assert!(
        result.findings.is_empty(),
        "provider emits only unadjudicated aggregate candidates"
    );
    let candidates = result.details["candidates"].as_array().unwrap();
    let tool_report: Option<Value> = if failure {
        None
    } else {
        Some(serde_json::from_slice(&stdout).unwrap())
    };
    if let Some(raw) = &tool_report {
        let count = u64::from(control == "positive");
        assert_eq!(raw["database"]["advisory-count"], 1);
        assert!(
            raw["database"]["last-commit"].is_null() && raw["database"]["last-updated"].is_null()
        );
        assert_eq!(raw["lockfile"]["dependency-count"], 1);
        assert_eq!(raw["vulnerabilities"]["count"], count);
        assert_eq!(
            raw["vulnerabilities"]["list"].as_array().unwrap().len() as u64,
            count
        );
        assert_eq!(result.details["findingsCount"], count);
        assert_eq!(candidates.len() as u64, count);
        assert!(result.applicable && result.complete);
        assert!(result.coverage_gaps.is_empty() && result.degradation.is_empty());
        let coverage = result.coverage.as_ref().unwrap();
        assert_eq!((coverage.expected, coverage.examined), (1, 1));
        assert!(coverage.gaps.is_empty());
        assert_eq!(
            coverage.denominator_digest,
            provider.configuration["denominatorDigest"]
                .as_str()
                .unwrap()
        );
        if count == 1 {
            assert_eq!(
                raw["vulnerabilities"]["list"][0]["advisory"]["id"],
                "RUSTSEC-2019-0009"
            );
            assert_eq!(
                raw["vulnerabilities"]["list"][0]["package"]["name"],
                "smallvec"
            );
            assert_eq!(
                raw["vulnerabilities"]["list"][0]["package"]["version"],
                "0.6.9"
            );
            assert_eq!(candidates[0]["severityHint"], "critical");
        }
    } else {
        assert!(!result.complete && !result.coverage_gaps.is_empty());
        assert!(result.details["findingsCount"].is_null() && candidates.is_empty());
        assert!(stdout.is_empty() && !stderr.is_empty());
        assert!(result
            .coverage_gaps
            .iter()
            .any(|gap| gap == "legacy-tool-output-unparseable:cargo_audit"));
    }
    assert_eq!(snapshot(&root), before);
    assert_eq!(
        if database.exists() {
            snapshot(&database)
        } else {
            BTreeMap::new()
        },
        database_before
    );
    assert_eq!(digest(&fs::read(&tool).unwrap()), pin());
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["allowed"], true);
    assert_eq!(decisions[0]["requestId"], actual["requestId"]);
    json!({"control":control,"root":root,"run":run,"database":database,"databaseSources":database_before,
        "fixtureSources":before,"fixtureLockControl":lock_control,"matched":true,
        "invocationScope":if unsupported {"deliberate old-argv SDK regression control"} else {"shipped provider argv"},
        "inventory":inventory,"frozenProvider":provider,"frozenPlan":frozen.plan(),"planDigest":frozen.digest(),"planSignature":frozen.signature(),
        "nativeResult":result,"policyDefinition":policy.definition(),"policyDecisions":*decisions,
        "actualSdkReceipt":actual,"actualStdout":stdout_text,"actualStderr":stderr_text,"actualToolReport":tool_report})
}

#[test]
#[ignore = "constructed native SDK qualification; pinned cargo-audit 0.22.2 & native macOS sandbox required"]
fn real_cargo_audit_accuracy() {
    let retained = fs::canonicalize(
        std::env::var_os("LEGION_CARGO_AUDIT_RECEIPTS")
            .expect("explicit retained directory required"),
    )
    .unwrap();
    assert_eq!(retained.file_name().unwrap(), "cargo-audit");
    assert_eq!(
        retained.parent().unwrap().file_name().unwrap(),
        "legion-provider-qualification"
    );
    if std::env::var_os("LEGION_CARGO_AUDIT_CHILD").is_some() {
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            retained.join("home")
        );
        let cases: Vec<Value> = CONTROLS
            .iter()
            .map(|control| case(&retained, control))
            .collect();
        let fixtures: BTreeMap<String, String> = cases
            .iter()
            .flat_map(|case| {
                case["fixtureSources"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(path, hash)| {
                        (
                            format!("{}/{path}", case["control"].as_str().unwrap()),
                            hash.as_str().unwrap().into(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut record = json!({"schema":"legion-cargo-audit-sdk-accuracy/1","provider":ID,"stage":"candidate","scope":SCOPE,
            "productionQualification":false,"selfProducerQualification":false,"publicHelperQualification":false,
            "qualificationEligible":true,"status":"pass","modelCalls":0,
            "databaseScope":"pinned unchanged official advisory subset; no population, full database, current database, freshness or admission claim",
            "locatorPrecision":"one native aggregate candidate at Cargo.lock:1; no vulnerability/source diagnostic localization claim",
            "binding":binding(ID,&fixtures),"cases":cases,"metrics":{"cases":5,"matched":5,"mismatched":0},
            "tool":{"version":"0.22.2","digest":pin(),"source":"https://github.com/rustsec/rustsec/releases/tag/cargo-audit/v0.22.2"}});
        record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
        fs::write(
            retained.join("legacy_security_rust-advisories.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        println!(
            "CARGO_AUDIT_PROVIDER_ACCURACY {}",
            serde_json::to_string(&record).unwrap()
        );
        return;
    }
    for name in ["home", "tmp"] {
        fs::create_dir(retained.join(name)).unwrap();
    }
    let tool = fs::canonicalize(std::env::var_os("LEGION_CARGO_AUDIT_BIN").unwrap()).unwrap();
    let mut paths = vec![tool.parent().unwrap().to_path_buf()];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_cargo_audit_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&retained)
        .env_clear()
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("HOME", retained.join("home"))
        .env("TMPDIR", retained.join("tmp"))
        .env("LEGION_CARGO_AUDIT_BIN", tool)
        .env("LEGION_CARGO_AUDIT_RECEIPTS", &retained)
        .env("LEGION_CARGO_AUDIT_CHILD", "1")
        .output()
        .unwrap();
    fs::write(retained.join("child.stdout.log"), &output.stdout).unwrap();
    fs::write(retained.join("child.stderr.log"), &output.stderr).unwrap();
    fs::write(retained.join("child-execution.json"),serde_json::to_vec_pretty(&json!({"success":output.status.success(),"exitCode":output.status.code(),"signal":output.status.signal(),"stdoutDigest":digest(&output.stdout),"stderrDigest":digest(&output.stderr)})).unwrap()).unwrap();
    assert!(
        output.status.success(),
        "cargo-audit child failed; actual streams retained"
    );
    let marker = b"CARGO_AUDIT_PROVIDER_ACCURACY ";
    let records: Vec<&[u8]> = output
        .stdout
        .split_inclusive(|b| *b == b'\n')
        .filter_map(|line| {
            line.windows(marker.len())
                .position(|w| w == marker)
                .map(|i| &line[i..])
        })
        .collect();
    assert_eq!(records.len(), 1);
    std::io::stdout().lock().write_all(records[0]).unwrap();
}
