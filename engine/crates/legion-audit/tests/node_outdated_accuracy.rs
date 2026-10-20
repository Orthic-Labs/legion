//! Constructed native npm outdated controls through shipped legacy provider & actual SDK.
//! No production CLI owner-admission claim; test provider still requires real attested enrollment.
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
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

const SOURCE: &str = "engine/crates/legion-audit/tests/node_outdated_accuracy.rs";
const POLICY: &str = "legion-npm-outdated-fixture-v1";
const ID: &str = "legacy.stack.node-outdated";
const FIXTURES: &str = "engine/crates/legion-audit/tests/fixtures/node-outdated";

const SCOPE: &str = "constructed native SDK; official tiny-invariant installed-data npm outdated positive/nonempty absence + registry/process failure + missing-tool; run-scoped public registry responses only, no production owner-admission claim";

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
    // Match filesystem components before display separator normalization.
    if relative.parent()
        != Some(Path::new(
            "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance",
        ))
    {
        return false;
    }
    relative
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

#[test]
fn source_binding_receipt_exclusion_is_exact() {
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    assert!(generated_session_provenance(Path::new(&format!(
        "{prefix}{}.json",
        "0123456789abcdef".repeat(4)
    ))));
    for relative in [
        "engine/crates/legion-audit/src/mod.rs".to_owned(),
        "engine/crates/legion-audit/src/nested/.audit/anything.rs".to_owned(),
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("nested/{prefix}{}.json", "a".repeat(64)),
    ] {
        assert!(
            !generated_session_provenance(Path::new(&relative)),
            "unexpected exclusion: {relative}"
        );
    }
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
    fn snapshot(root: &Path) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        source_binding_walk(
            root,
            &root.join("engine/crates/legion-audit/src"),
            &mut files,
        );
        files
    }
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let base = std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
    let scratch = Scratch(base.join(format!(
        "legion-source-binding-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    let root = &scratch.0;
    let source = root.join("engine/crates/legion-audit/src/mod.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, b"original source\n").unwrap();
    let baseline = snapshot(root);
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    let receipt = root.join(format!("{prefix}{}.json", "0123456789abcdef".repeat(4)));
    fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    fs::write(&receipt, b"generated receipt\n").unwrap();
    assert_eq!(snapshot(root), baseline);
    fs::write(&receipt, b"changed generated receipt\n").unwrap();
    assert_eq!(snapshot(root), baseline);

    // A matching directory remains traversed; only regular files are excluded.
    fs::remove_file(&receipt).unwrap();
    fs::create_dir(&receipt).unwrap();
    let nested = receipt.join("nested.rs");
    fs::write(&nested, b"retained nested source\n").unwrap();
    let nested_key = nested
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    assert_eq!(
        snapshot(root).get(&nested_key),
        Some(&digest(b"retained nested source\n"))
    );
    fs::write(&nested, b"changed nested source\n").unwrap();
    assert_eq!(
        snapshot(root).get(&nested_key),
        Some(&digest(b"changed nested source\n"))
    );
    fs::remove_dir_all(&receipt).unwrap();

    for relative in [
        "engine/crates/legion-audit/src/nested/.audit/anything.rs".to_owned(),
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.JSON", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}{}.json", "a".repeat(65)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("engine/crates/legion-audit/src/nested/.audit/arcane/receipts/session-provenance/{}.json", "a".repeat(64)),
        // Unix backslashes are literal filesystem name bytes.
        format!("engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance\\{}.json", "a".repeat(64)),
        format!("engine/crates/legion-audit/src/.audit\\arcane/receipts/session-provenance/{}.json", "a".repeat(64)),
        format!(r"engine/crates/legion-audit/src/.audit\arcane\receipts\session-provenance\{}.json", "a".repeat(64)),
    ] {
        let path = root.join(&relative);
        assert!(!generated_session_provenance(path.strip_prefix(root).unwrap()));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"retained source\n").unwrap();
        let key = relative.replace('\\', "/");
        let before = snapshot(root);
        assert_eq!(before.len(), baseline.len() + 1, "{relative}");
        assert_eq!(before.get(&key), Some(&digest(b"retained source\n")), "{relative}");
        fs::write(&path, b"changed retained source\n").unwrap();
        let changed = snapshot(root);
        assert_eq!(changed.get(&key), Some(&digest(b"changed retained source\n")), "{relative}");
        assert_ne!(changed.get(&key), before.get(&key), "{relative}");
        fs::remove_file(path).unwrap();
    }
    assert_eq!(snapshot(root), baseline);
    fs::write(&source, b"changed implementation\n").unwrap();
    assert_ne!(snapshot(root), baseline);

    // Symlink refusal precedes even an exactly matching receipt filename.
    std::os::unix::fs::symlink(&source, &receipt).unwrap();
    assert!(std::panic::catch_unwind(|| snapshot(root)).is_err());
    fs::remove_file(&receipt).unwrap();
    std::os::unix::fs::symlink(source.parent().unwrap(), &receipt).unwrap();
    assert!(std::panic::catch_unwind(|| snapshot(root)).is_err());
    fs::remove_file(&receipt).unwrap();
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
    operations: Vec<(Vec<String>, BTreeSet<i32>)>,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
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
            "artifactRequestId": "legion-audit/<64 lowercase hex>; one admission per ordered frozen operation",
            "tool": {"path": self.tool, "digest": self.tool_digest},
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest},
            "profile": {"path": self.profile, "text": self.profile_text,
                "digest": digest(self.profile_text.as_bytes()), "receiptId": self.sandbox_id()},
            "operations": self.operations,
            "versionArgs": self.wrapped_args(&["--version".into()]),
            "environment": self.environment,
            "environmentAllowlist": self.allowlist,
            "timeoutMs": 120000,
            "stdoutLimit": 8388608,
            "stderrLimit": 8388608,
            "sandbox": "native-macos-allow-network-deny-project-write",
            "acceptedExitCodes": "command-specific [0,1] for outdated, [0] otherwise"
        })
    }

    fn operation(&self, req: &ExternalToolRequest) -> Option<(usize, &BTreeSet<i32>)> {
        self.operations
            .iter()
            .enumerate()
            .find_map(|(index, (operation, exits))| {
                let cache = self
                    .root
                    .parent()
                    .unwrap()
                    .join("run/cache")
                    .join(format!("npm-outdated-{index}"));
                let config = cache.join("empty.npmrc");
                let global = cache.join("global.npmrc");
                let mut args = operation.clone();
                args.extend([
                    "--registry=https://registry.npmjs.org/".into(),
                    "--online".into(),
                    "--offline=false".into(),
                    "--prefer-offline=false".into(),
                    "--prefer-online=true".into(),
                    "--ignore-scripts=true".into(),
                    "--audit=false".into(),
                    "--fund=false".into(),
                    format!("--cache={}", cache.to_string_lossy()),
                    format!("--userconfig={}", config.to_string_lossy()),
                    format!("--globalconfig={}", global.to_string_lossy()),
                ]);
                (req.args == self.wrapped_args(&args)).then_some((index, exits))
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
            && self.operation(req).is_some()
            && req.version_args == self.wrapped_args(&["--version".into()])
            && self.operation(req).is_some_and(|(i, _)| {
                let mut env = self.environment.clone();
                env.insert(
                    "npm_config_cache".into(),
                    self.root
                        .parent()
                        .unwrap()
                        .join("run/cache")
                        .join(format!("npm-outdated-{i}"))
                        .to_string_lossy()
                        .into_owned(),
                );
                req.environment == env
            })
            && req.environment_allowlist == self.allowlist
            && req.sensitive_argument_indexes.is_empty()
            && req.sensitive_environment_names.is_empty()
            && req.timeout_ms > 0
            && req.timeout_ms <= 120000
            && req.stdout_limit == 8388608
            && req.stderr_limit == 8388608
            && self
                .operation(req)
                .is_some_and(|(_, exits)| &req.accepted_exit_codes == exits)
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let mut decisions = self.decisions.lock().unwrap();
        let allowed = self
            .operation(request)
            .is_some_and(|(index, _)| index == decisions.len())
            && self.permits(request);
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
                    "exact constructed npm outdated fixture admission"
                } else {
                    "outside exact constructed npm outdated fixture policy"
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
}
#[async_trait::async_trait]
impl ExternalProjectTool for RecordingTool {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        let receipt = self.inner.execute(request, cancellation).await;
        self.receipts.lock().unwrap().push(receipt.clone());
        receipt
    }
}

fn operations(manifest: &Value) -> Vec<(Vec<String>, BTreeSet<i32>)> {
    let mut commands = vec![
        (
            vec!["outdated".into(), "--json".into()],
            [0, 1].into_iter().collect(),
        ),
        (
            vec![
                "ls".into(),
                "--depth=0".into(),
                "--json".into(),
                "--include=dev".into(),
                "--include=optional".into(),
                "--include=peer".into(),
            ],
            [0].into_iter().collect(),
        ),
    ];
    let mut deps = BTreeMap::new();
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        for (name, version) in manifest[section].as_object().unwrap() {
            deps.insert(name.clone(), version.as_str().unwrap().to_owned());
        }
    }
    for (name, version) in deps {
        for suffix in [version, "latest".into()] {
            commands.push((
                vec!["view".into(), format!("{name}@{suffix}"), "--json".into()],
                [0].into_iter().collect(),
            ));
        }
    }
    commands
}
fn copy_tree(source: &Path, target: &Path) {
    assert!(!source.is_symlink());
    if source.is_dir() {
        fs::create_dir_all(target).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            copy_tree(&entry.path(), &target.join(entry.file_name()));
        }
    } else {
        fs::copy(source, target).unwrap();
    }
}
fn case(base: &Path, control: &str, provision: &Value) -> Value {
    let missing = control == "missing-tool";
    let fixture = base.join(control);
    fs::create_dir(&fixture).unwrap();
    let root = fixture.join("source");
    fs::create_dir(&root).unwrap();
    let run = fixture.join("run");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let template = if missing { "absence" } else { control };
    let package = fs::read(
        repository
            .join(FIXTURES)
            .join(template)
            .join("package.json"),
    )
    .unwrap();
    fs::write(root.join("package.json"), &package).unwrap();
    let manifest: Value = serde_json::from_slice(&package).unwrap();
    let version = manifest["dependencies"]["tiny-invariant"].as_str().unwrap();
    copy_tree(
        &repository.join(FIXTURES).join("packages").join(version),
        &root.join("node_modules/tiny-invariant"),
    );
    let fixtures = snapshot(&root);
    let before = fixtures.clone();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(control)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(ID)).unwrap();
    assert_eq!(
        registry_spec(ID)["execution"]["resourceClaims"]["projectExecution"],
        0
    );
    assert_eq!(
        registry_spec(ID)["selector"]["patterns"],
        json!(["**/package.json"])
    );
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-node-outdated-fixture-key"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    let tool = fs::canonicalize(std::env::var_os("LEGION_NODE_OUTDATED_NPM").unwrap()).unwrap();
    assert_eq!(digest(&fs::read(&tool).unwrap()), provision["npmCliDigest"]);
    let saved = std::env::var_os("PATH").unwrap();
    if missing {
        std::env::set_var("PATH", "/usr/bin:/bin");
        assert!(resolve_request(&root, "npm", &[]).is_err());
    } else {
        assert_eq!(resolve_request(&root, "npm", &[]).unwrap().executable, tool);
    }
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let escaped = root
        .to_str()
        .unwrap()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile_text=format!("(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
    let profile = scratch.sandbox_dir().join(format!(
        "audit-{}.sb",
        digest(profile_text.as_bytes()).trim_start_matches("sha256:")
    ));
    let (environment, allowlist) = expected_environment(&run);
    let policy = Arc::new(ScopedPolicy {
        id: ID.into(),
        check: "outdated".into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: provision["npmCliDigest"].as_str().unwrap().into(),
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        profile,
        profile_text,
        operations: operations(&manifest),
        environment,
        allowlist,
        decisions: Mutex::new(Vec::new()),
    });
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
        SharedPolicy(policy.clone()),
    );
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let recording = RecordingTool {
        inner: Arc::new(AuditExternalProjectTool::new(effects)),
        receipts: receipts.clone(),
    };
    let native = NativeProviderRegistry::new(&root)
        .with_scratch(scratch.clone())
        .with_external_project_tool(Arc::new(recording));
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &native,
            CancellationToken::new(),
        ))
        .unwrap();
    std::env::set_var("PATH", saved);
    assert_eq!(report.planned_providers, vec![ID]);
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0].result;
    let actual: Vec<_> = receipts
        .lock()
        .unwrap()
        .iter()
        .map(|r| receipt_json(r, &scratch.artifacts_dir()))
        .collect();
    let projected = result.details["npmOutdatedCompletion"]["probes"]
        .as_array()
        .unwrap();
    assert_eq!(actual.len(), projected.len());
    for (a, p) in actual.iter().zip(projected) {
        for key in [
            "receiptId",
            "requestId",
            "providerId",
            "planId",
            "policyId",
            "policy",
            "taskId",
            "state",
            "complete",
            "executable",
            "command",
            "cwd",
            "environmentNames",
            "sandbox",
            "processTree",
            "timing",
            "exitCode",
            "signal",
            "parser",
            "gaps",
        ] {
            assert_eq!(a[key], p["receipt"][key], "actual SDK projection {key}");
        }
        if a["stdout"].is_object() {
            assert_eq!(a["stdout"]["raw"], p["stdout"]);
            assert_eq!(a["stderr"]["raw"], p["stderr"]);
        }
    }
    if missing {
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0]["state"], "missing_executable");
        assert_eq!(actual[0]["processTree"]["started"], false);
        assert!(policy.decisions.lock().unwrap().is_empty());
        assert!(!result.complete && result.findings.is_empty());
        assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
    } else {
        assert_eq!(actual.len(), policy.operations.len());
        let decisions = policy.decisions.lock().unwrap();
        assert_eq!(decisions.len(), actual.len());
        assert!(decisions.iter().all(|d| d["allowed"] == true));
        for (a, d) in actual.iter().zip(decisions.iter()) {
            assert_eq!(a["requestId"], d["requestId"]);
            assert_eq!(a["command"]["args"], d["args"]);
            assert_eq!(
                a["executable"]["version"]["output"]
                    .as_str()
                    .unwrap()
                    .trim(),
                "10.9.8"
            );
            assert_eq!(a["executable"]["version"]["qualified"], true);
            assert_eq!(a["executable"]["version"]["skippedByPolicy"], false);
            assert_eq!(a["sandbox"]["networkEnabled"], true);
            assert_eq!(a["sandbox"]["required"], true);
            for key in ["started", "terminated", "reaped"] {
                assert_eq!(a["processTree"][key], true);
            }
        }
        if control == "process-error" {
            assert!(!result.complete);
            assert!(!result.coverage_gaps.is_empty());
            assert!(actual
                .iter()
                .any(|r| r["complete"] == false && r["exitCode"].as_i64().is_some_and(|n| n != 0)));
        } else {
            assert!(result.complete, "{:?}", result.coverage_gaps);
            assert!(result.coverage_gaps.is_empty());
            let count = usize::from(control == "positive");
            assert_eq!(result.findings.len(), count);
            assert_eq!(result.details["findingsCount"], count);
            let coverage = result.coverage.as_ref().unwrap();
            assert_eq!(coverage.expected, 1);
            assert_eq!(coverage.examined, 1);
            let reconciled = result.details["npmOutdatedCompletion"]["reconciled"]
                .as_array()
                .unwrap();
            assert_eq!(reconciled.len(), 1);
            assert_eq!(reconciled[0]["latest"], "1.3.3");
            assert_eq!(reconciled[0]["installed"], version);
            assert_eq!(reconciled[0]["declared"], version);
        }
    }
    assert_eq!(
        snapshot(&root),
        before,
        "npm operations must not write audited tree or execute fixture scripts"
    );
    json!({"control":control,"matched":true,"provider":ID,"root":root,"run":run,"fixtureTemplate":template,"fixtureSources":fixtures,"inventory":inventory,"frozenPlan":frozen.plan(),"frozenProvider":provider,"planDigest":frozen.digest(),"planSignature":frozen.signature(),"policyDefinition":policy.definition(),"policyDecisions":*policy.decisions.lock().unwrap(),"actualSdkReceipts":actual,"nativeResult":result,"sourceBefore":before,"sourceAfter":snapshot(&root)})
}

#[test]
#[ignore = "CI-only native npm registry controls; pinned Node22.23.2/npm10.9.8, actual SDK & macOS sandbox required"]
fn real_node_outdated_accuracy() {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    let base =
        fs::canonicalize(std::env::var_os("LEGION_NODE_OUTDATED_RECEIPTS").unwrap()).unwrap();
    let provision: Value = serde_json::from_slice(
        &fs::read(std::env::var_os("LEGION_NODE_OUTDATED_PROVISION").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(provision["schema"], "legion-node-outdated-ci-provision/1");
    assert_eq!(provision["nodeVersion"], "22.23.2");
    assert_eq!(provision["npmVersion"], "10.9.8");
    if std::env::var_os("LEGION_NODE_OUTDATED_CHILD").is_some() {
        let cases: Vec<_> = ["positive", "absence", "process-error", "missing-tool"]
            .iter()
            .map(|c| case(&base, c, &provision))
            .collect();
        let fixtures: BTreeMap<String, String> = cases
            .iter()
            .flat_map(|c| {
                c["fixtureSources"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(p, h)| {
                        (
                            format!("{}/{p}", c["control"].as_str().unwrap()),
                            h.as_str().unwrap().to_owned(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut record = json!({"schema":"legion-node-outdated-sdk-accuracy/1","provider":ID,"stage":"finding","scope":SCOPE,"productionQualification":false,"qualificationEligible":true,"status":"pass","modelCalls":0,"admissionScope":"explicit constructed SDK authorizer; no production CLI owner-admission claim","binding":binding(ID,&fixtures),"cases":cases,"metrics":{"cases":4,"matched":4,"mismatched":0},"provision":provision});
        record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
        fs::write(
            base.join("legacy_stack_node-outdated.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        println!(
            "NODE_OUTDATED_PROVIDER_ACCURACY {}",
            serde_json::to_string(&record).unwrap()
        );
        return;
    }
    for name in ["home", "tmp"] {
        fs::create_dir(base.join(name)).unwrap();
    }
    let node = fs::canonicalize(std::env::var_os("LEGION_NODE_OUTDATED_NODE").unwrap()).unwrap();
    assert_eq!(digest(&fs::read(&node).unwrap()), provision["nodeDigest"]);
    let executable = std::env::current_exe().unwrap();
    let file = base.join("child.log");
    let output = fs::File::create(&file).unwrap();
    let status = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "real_node_outdated_accuracy",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("LEGION_NODE_OUTDATED_CHILD", "1")
        .env("HOME", base.join("home"))
        .env("TMPDIR", base.join("tmp"))
        .env(
            "PATH",
            std::env::join_paths([
                node.parent().unwrap(),
                Path::new("/usr/bin"),
                Path::new("/bin"),
            ])
            .unwrap(),
        )
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .status()
        .unwrap();
    let bytes = fs::read(file).unwrap();
    std::io::stdout().write_all(&bytes).unwrap();
    assert!(status.success(), "native child failed: {status}");
}
