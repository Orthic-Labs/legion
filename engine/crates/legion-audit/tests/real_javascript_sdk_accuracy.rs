//! Genuine JS/TS SDK known-answer controls; source candidates never claim observed qualification.
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
    io::{Read, Write},
    os::unix::fs::{symlink, PermissionsExt},
    os::unix::process::ExitStatusExt,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
const SOURCE: &str = "engine/crates/legion-audit/tests/real_javascript_sdk_accuracy.rs";
const FIXTURES: &str = "scripts/ci/fixtures/audit-javascript-sdk";
const POLICY: &str = "legion-real-javascript-sdk-fixture-v1";
const JS: &str = "code.javascript";
const EXTENSIONS: [&str; 8] = ["js", "cjs", "mjs", "ts", "cts", "mts", "jsx", "tsx"];
const CONTROLS: [&str; 24] = [
    "nonempty-clean",
    "positive-js",
    "positive-cjs",
    "positive-mjs",
    "positive-ts",
    "positive-cts",
    "positive-mts",
    "positive-jsx",
    "positive-tsx",
    "build-failure",
    "test-failure",
    "build-noop",
    "test-noop",
    "test-empty",
    "test-unmet-plan",
    "malformed",
    "missing-tool",
    "rejected-admission",
    "absent-sandbox",
    "source-tamper",
    "tool-tamper",
    "scope-omission",
    "missing-manager",
    "manager-mismatch",
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
        let base = std::env::var_os("LEGION_JS_SDK_SCRATCH")
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
        "scripts/ci/audit-javascript-sdk-bootstrap.py",
        "scripts/ci/audit-javascript-sdk-inputs.json",
        "scripts/ci/audit-javascript-sdk-accuracy.py",
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
    let home = run.join("cache/javascript-home");
    for (name, path) in [
        ("HOME", home.clone()),
        ("USERPROFILE", home.clone()),
        ("XDG_CONFIG_HOME", home.join(".config")),
        ("APPDATA", home.join("AppData/Roaming")),
        ("LEGION_AUDIT_JS_OUTPUT", run.join("cache/javascript-build")),
    ] {
        env.insert(name.into(), path.to_string_lossy().into_owned());
        allowed.insert(name.into());
    }
    for (name, value) in [("CI", "true"), ("COREPACK_ENABLE_NETWORK", "0")] {
        env.insert(name.into(), value.into());
        allowed.insert(name.into());
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
fn bounded(path: &Path, limit: usize) -> Vec<u8> {
    let before = fs::metadata(path).unwrap();
    assert!(before.is_file() && before.len() <= limit as u64);
    let mut file = fs::File::open(path).unwrap();
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .unwrap();
    let after = file.metadata().unwrap();
    assert!(
        data.len() <= limit
            && data.len() as u64 == before.len()
            && after.len() == before.len()
            && after.modified().ok() == before.modified().ok()
    );
    data
}
fn runtime_tree(root: &Path) -> Value {
    let mut pending = vec![(root.join("node_modules"), 0usize)];
    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut total = 0usize;
    let mut nodes = 0usize;
    while let Some((path, depth)) = pending.pop() {
        nodes += 1;
        assert!(nodes <= 60000 && depth <= 64);
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_symlink() {
            let raw = fs::read_link(&path).unwrap();
            assert!(fs::canonicalize(&path).unwrap().starts_with(root));
            links.insert(relative, raw.to_str().unwrap().to_owned());
        } else if meta.is_dir() {
            directories.insert(relative);
            let mut children = Vec::new();
            for e in fs::read_dir(path).unwrap() {
                assert!(nodes + pending.len() + children.len() < 60000);
                children.push(e.unwrap().path());
            }
            children.sort();
            pending.extend(children.into_iter().rev().map(|p| (p, depth + 1)));
        } else {
            let bytes = bounded(&path, 512 * 1024 * 1024 - total);
            total += bytes.len();
            files.insert(relative,json!({"digest":digest(&bytes),"bytes":bytes.len(),"executable":meta.permissions().mode()&0o111!=0}));
        }
    }
    json!({"files":files,"links":links,"directories":directories})
}
fn copy_runtime(enrollment: &Value, root: &Path) {
    let source = Path::new(enrollment["toolRoot"].as_str().unwrap());
    for (relative, descriptor) in enrollment["runtime"]["files"].as_object().unwrap() {
        let rel = Path::new(relative);
        assert!(!rel.is_absolute() && rel.components().all(|p| matches!(p, Component::Normal(_))));
        let bytes = bounded(&source.join(rel), 32 * 1024 * 1024);
        assert_eq!(digest(&bytes), descriptor["digest"]);
        assert_eq!(bytes.len(), descriptor["bytes"].as_u64().unwrap() as usize);
        let target = root.join(rel);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, bytes).unwrap();
        fs::set_permissions(
            target,
            fs::Permissions::from_mode(if descriptor["executable"] == true {
                0o755
            } else {
                0o644
            }),
        )
        .unwrap();
    }
    for (relative, target) in enrollment["runtime"]["links"].as_object().unwrap() {
        let p = root.join(relative);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        symlink(target.as_str().unwrap(), p).unwrap();
    }
    assert_eq!(runtime_tree(root), enrollment["runtime"]);
}
fn fixtures(control: &str) -> BTreeMap<String, String> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(FIXTURES)
        .join("clean");
    let mut result: BTreeMap<String, String> = fs::read_dir(base)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.file_name().unwrap().to_str().unwrap().to_owned(),
                fs::read_to_string(p).unwrap(),
            )
        })
        .collect();
    if let Some(ext) = control.strip_prefix("positive-") {
        assert!(EXTENSIONS.contains(&ext));
        let p = format!("answer_{ext}.{ext}");
        let old = result[&p].clone();
        let bad = if ["ts", "cts", "mts", "tsx"].contains(&ext) {
            "const bad: number = 'wrong';\n"
        } else {
            "/** @type {number} */ const bad = 'wrong';\n"
        };
        result.insert(p, format!("debugger;\n{bad}{old}"));
    }
    if control == "build-failure" {
        result.insert(
            "tsconfig.build.json".into(),
            "{ invalid build configuration\n".into(),
        );
    }
    if control == "test-failure" {
        let text = result["test.mjs"].replace("(),42)", "(),43)");
        assert_ne!(text, result["test.mjs"]);
        result.insert("test.mjs".into(), text);
    }
    if ["build-noop", "test-noop"].contains(&control) {
        let mut manifest: Value = serde_json::from_str(&result["package.json"]).unwrap();
        manifest["scripts"][if control == "build-noop" {
            "build"
        } else {
            "test"
        }] = json!("node -e 'process.exit(0)'");
        result.insert(
            "package.json".into(),
            serde_json::to_string(&manifest).unwrap(),
        );
    }
    if control == "test-empty" {
        let marker = result["test.mjs"].find("{\n  const loaded").unwrap();
        result.insert("test.mjs".into(), result["test.mjs"][..marker].to_owned());
    }
    if control == "test-unmet-plan" {
        let text = result["test.mjs"].replacen(
            "    t.assert.strictEqual((loaded.answer || loaded.default.answer)(),42);\n",
            "",
            1,
        );
        assert_ne!(text, result["test.mjs"]);
        result.insert("test.mjs".into(), text);
    }
    if ["missing-manager", "manager-mismatch"].contains(&control) {
        let mut manifest: Value = serde_json::from_str(&result["package.json"]).unwrap();
        if control == "missing-manager" {
            manifest.as_object_mut().unwrap().remove("packageManager");
        } else {
            manifest["packageManager"] = json!("pnpm@11.23.0");
        }
        result.insert(
            "package.json".into(),
            serde_json::to_string(&manifest).unwrap(),
        );
    }
    if control == "malformed" {
        result.insert("tsconfig.json".into(), "{ invalid configuration\n".into());
    }
    if control == "scope-omission" {
        let mut config: Value = serde_json::from_str(&result["tsconfig.json"]).unwrap();
        config["exclude"] = json!(["answer_tsx.tsx"]);
        result.insert(
            "tsconfig.json".into(),
            serde_json::to_string(&config).unwrap(),
        );
        result
            .get_mut("eslint.config.mjs")
            .unwrap()
            .push_str("\n// Source fixture mutation: omit selected TSX scope.\n");
        let config = result["eslint.config.mjs"].replace(
            "export default [",
            "export default [{ignores:['answer_tsx.tsx']},",
        );
        result.insert("eslint.config.mjs".into(), config);
    }
    result
}
struct ScopedPolicy {
    plan: String,
    root: PathBuf,
    scratch: Arc<AuditScratch>,
    node: PathBuf,
    node_digest: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    runtime: Value,
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
    fn executable(&self, task: &str) -> PathBuf {
        self.root.join("node_modules/.bin").join(match task {
            "type" => "tsc",
            "lint" => "eslint",
            _ => "pnpm",
        })
    }
    fn suffix(task: &str) -> Vec<String> {
        match task {
            "type" => vec![
                "--noEmit",
                "-p",
                "tsconfig.json",
                "--pretty",
                "false",
                "--listFiles",
            ],
            "lint" => vec![
                "--no-cache",
                "--format",
                "json",
                "--no-error-on-unmatched-pattern",
                ".",
            ],
            "build" => vec!["run", "build"],
            "test" => vec!["run", "test"],
            _ => vec![],
        }
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    fn wrapped(&self, task: &str, args: &[String]) -> Vec<String> {
        let mut result = vec![
            "-f".into(),
            self.profile().to_str().unwrap().into(),
            "--".into(),
            self.executable(task).to_str().unwrap().into(),
        ];
        result.extend_from_slice(args);
        result
    }
    fn accepted(task: &str) -> BTreeSet<i32> {
        match task {
            "type" => [0, 1, 2].into_iter().collect(),
            "lint" => [0, 1].into_iter().collect(),
            _ => [0].into_iter().collect(),
        }
    }
    fn definition(&self) -> Value {
        json!({"id":POLICY,"version":1,"scope":"exact source-owned JS/TS SDK fixtures; no production owner admission","provider":JS,"planDigest":self.plan,"cwd":self.root,"node":{"path":self.node,"digest":self.node_digest},"runtime":self.runtime,"wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},"profile":{"path":self.profile(),"text":self.profile_text(),"receiptId":self.sandbox_id()},"environment":self.environment,"environmentAllowlist":self.allowlist,"absentSandboxControl":self.absent_sandbox,"commands":[{"task":"type","args":Self::suffix("type")},{"task":"lint","args":Self::suffix("lint")},{"task":"build","args":Self::suffix("build")},{"task":"test","args":Self::suffix("test")}],"timeoutMs":120000,"stdoutLimit":33554432,"stderrLimit":33554432})
    }
    fn permits(&self, r: &ExternalToolRequest) -> bool {
        let task = r.task_id.as_deref().unwrap_or("");
        if !["type", "lint", "build", "test"].contains(&task) {
            return false;
        }
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
            && r.provider_id == JS
            && r.plan_id == self.plan
            && r.policy_id == "audit"
            && r.request_id
                .strip_prefix("legion-audit/")
                .is_some_and(|id| {
                    id.len() == 64
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            && r.cwd == self.root.to_str().unwrap()
            && r.origin == ToolOrigin::TargetProject
            && !r.shell
            && r.executable == self.wrapper.to_str().unwrap()
            && r.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && digest(&bounded(&self.wrapper, 32 * 1024 * 1024)) == self.wrapper_digest
            && digest(&bounded(&self.node, 128 * 1024 * 1024)) == self.node_digest
            && runtime_tree(&self.root) == self.runtime
            && r.args == self.wrapped(task, &Self::suffix(task))
            && r.version_args == self.wrapped(task, &["--version".into()])
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
                    "exact JS/TS fixture request"
                } else {
                    "outside exact JS/TS fixture contract"
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
fn raw(row: &Value, name: &str) -> String {
    String::from_utf8(
        row[name]["rawBytes"]
            .as_array()
            .map(|v| v.iter().map(|n| n.as_u64().unwrap() as u8).collect())
            .unwrap_or_default(),
    )
    .unwrap()
}
fn source_snapshot(root: &Path, files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    files
        .keys()
        .map(|p| (p.clone(), digest(&bounded(&root.join(p), 1024 * 1024))))
        .collect()
}
fn case(base: &Path, retained: &Path, enrollment: &Value, control: &str) -> Value {
    let case_id = format!("javascript-{control}");
    let root = base.join(&case_id).join("source");
    fs::create_dir_all(&root).unwrap();
    let files = fixtures(control);
    for (relative, text) in &files {
        fs::write(root.join(relative), text).unwrap();
    }
    let source_before = source_snapshot(&root, &files);
    copy_runtime(enrollment, &root);
    if control == "missing-tool" {
        fs::remove_file(root.join("node_modules/.bin/eslint")).unwrap();
    }
    let runtime_before = runtime_tree(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(JS)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-javascript-sdk-fixture-key"))
        .unwrap();
    let provider = frozen.provider(JS).unwrap();
    let scratch = Arc::new(
        AuditScratch::with_scratch_dir(&root, retained.join("cases").join(&case_id)).unwrap(),
    );
    let node = fs::canonicalize(enrollment["node"]["path"].as_str().unwrap()).unwrap();
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let search = vec![
        root.join("node_modules/.bin"),
        node.parent().unwrap().to_path_buf(),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ];
    let (mut environment, allowlist) = expected_environment(scratch.root());
    environment.insert(
        "PATH".into(),
        std::env::join_paths(&search)
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
    );
    let policy = Arc::new(ScopedPolicy {
        plan: frozen.digest().into(),
        root: root.clone(),
        scratch: scratch.clone(),
        node: node.clone(),
        node_digest: enrollment["node"]["digest"].as_str().unwrap().into(),
        wrapper_digest: digest(&bounded(&wrapper, 32 * 1024 * 1024)),
        wrapper,
        runtime: runtime_before.clone(),
        environment,
        allowlist,
        absent_sandbox: control == "absent-sandbox",
        decisions: Mutex::new(Vec::new()),
    });
    if control == "source-tamper" {
        let mut text = files["answer_js.js"].clone();
        text.push_str("\n// changed after frozen inventory\n");
        fs::write(root.join("answer_js.js"), text).unwrap();
    }
    if control == "tool-tamper" {
        let target = root.join("node_modules/eslint/bin/eslint.js");
        let mut bytes = bounded(&target, 1024 * 1024);
        bytes.extend_from_slice(b"\n// changed after official enrollment\n");
        fs::write(target, bytes).unwrap();
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
    let native_result = if control == "absent-sandbox" {
        let request = ExternalToolRequest {
            request_id: format!(
                "legion-audit/{}",
                digest(case_id.as_bytes()).trim_start_matches("sha256:")
            ),
            provider_id: JS.into(),
            plan_id: frozen.digest().into(),
            policy_id: "audit".into(),
            task_id: Some("type".into()),
            executable: policy.wrapper.to_str().unwrap().into(),
            args: policy.wrapped("type", &ScopedPolicy::suffix("type")),
            cwd: root.to_str().unwrap().into(),
            origin: ToolOrigin::TargetProject,
            expected_digest: Some(policy.wrapper_digest.clone()),
            accepted_exit_codes: ScopedPolicy::accepted("type"),
            version_args: policy.wrapped("type", &["--version".into()]),
            environment: policy.environment.clone(),
            environment_allowlist: policy.allowlist.clone(),
            requires_network_sandbox: true,
            sandbox: None,
            timeout_ms: 120000,
            stdout_limit: 33554432,
            stderr_limit: 33554432,
            ..ExternalToolRequest::default()
        };
        runtime.block_on(recorder.execute(request, tokio_util::sync::CancellationToken::new()));
        Value::Null
    } else {
        let native = NativeProviderRegistry::new(&root)
            .with_scratch(scratch.clone())
            .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(SharedRecorder(
                recorder.clone(),
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
        assert_eq!(report.planned_providers, vec![JS]);
        assert_eq!(report.results.len(), 1);
        serde_json::to_value(&report.results[0].result).unwrap()
    };
    let executions = rows.lock().unwrap().clone();
    let decisions = policy.decisions.lock().unwrap().clone();
    let mut result = json!({"caseId":case_id,"control":control,"provider":JS,"scope":if control=="absent-sandbox"{"sdk-boundary-control"}else{"native-provider-known-answer-fixture"},"productionQualification":false,"qualificationEligible":false,"fixtureFiles":files,"sourceBefore":source_before,"sourceAfter":source_snapshot(&root,&files),"localRuntimeBefore":runtime_before,"localRuntimeAfter":runtime_tree(&root),"inventory":inventory,"planDigest":frozen.digest(),"frozenProvider":provider,"nativeResult":native_result,"policyDefinition":policy.definition(),"policyDecisions":decisions,"sdkExecutions":executions,"matched":false});
    if control == "tool-tamper" {
        result["toolTamperBytes"] = json!(bounded(
            &root.join("node_modules/eslint/bin/eslint.js"),
            1024 * 1024
        ));
    }
    // Original SDK receipts/raw streams survive any subsequent assertion failure.
    let path = scratch.root().join("case-observation.json");
    fs::write(&path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    let rows = result["sdkExecutions"].as_array().unwrap();
    let complete = control == "nonempty-clean" || control.starts_with("positive-");
    if control == "absent-sandbox" {
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["executionReceipt"]["state"], "sandbox_missing");
        assert_eq!(rows[0]["executionReceipt"]["processTree"]["started"], false);
        assert_eq!(rows[0]["executionReceipt"]["policy"]["allowed"], true);
    } else {
        assert_eq!(
            result["nativeResult"]["complete"], complete,
            "all four real tasks & complete frozen source scope required"
        );
        assert_eq!(
            result["nativeResult"]["coverage_gaps"]
                .as_array()
                .unwrap()
                .is_empty(),
            complete
        );
        if complete {
            let coverage = &result["nativeResult"]["coverage"];
            let expected = provider.configuration["denominatorCount"].as_u64().unwrap() as usize;
            assert_eq!(coverage["expected"], expected);
            assert_eq!(coverage["examined"], expected);
        }
        assert_eq!(
            rows.len(),
            if control == "source-tamper" {
                0
            } else if ["missing-manager", "manager-mismatch"].contains(&control) {
                2
            } else if control == "missing-tool" {
                3
            } else {
                4
            }
        );
        for row in rows {
            let receipt = &row["executionReceipt"];
            let refused = ["rejected-admission", "tool-tamper"].contains(&control);
            assert_eq!(receipt["processTree"]["started"], !refused);
            assert_eq!(receipt["policy"]["allowed"], !refused);
            if refused {
                assert_eq!(receipt["state"], "unauthorized_effect");
            } else {
                assert_eq!(receipt["sandbox"]["required"], true);
                assert_eq!(receipt["sandbox"]["receiptId"], policy.sandbox_id());
                assert_eq!(receipt["processTree"]["reaped"], true);
                assert_eq!(receipt["executable"]["version"]["qualified"], true);
                let task = row["request"]["taskId"].as_str().unwrap();
                assert_eq!(
                    receipt["executable"]["version"]["output"]
                        .as_str()
                        .unwrap()
                        .trim(),
                    match task {
                        "type" => "Version 5.9.3",
                        "lint" => "v9.39.1",
                        _ => "11.24.0",
                    }
                );
            }
        }
        if complete {
            let tasks: BTreeSet<_> = rows
                .iter()
                .map(|r| r["request"]["taskId"].as_str().unwrap())
                .collect();
            assert_eq!(
                tasks,
                ["type", "lint", "build", "test"].into_iter().collect()
            );
            let type_row = rows
                .iter()
                .find(|r| r["request"]["taskId"] == "type")
                .unwrap();
            let lint = rows
                .iter()
                .find(|r| r["request"]["taskId"] == "lint")
                .unwrap();
            let build = rows
                .iter()
                .find(|r| r["request"]["taskId"] == "build")
                .unwrap();
            let test = rows
                .iter()
                .find(|r| r["request"]["taskId"] == "test")
                .unwrap();
            assert!(raw(build, "stdout")
                .lines()
                .any(|line| line.starts_with("TSFILE: ")));
            assert!(raw(test, "stdout").contains("# pass 8"));
            assert!(raw(test, "stdout").contains("# fail 0"));
            if let Some(ext) = control.strip_prefix("positive-") {
                let target = root.join(format!("answer_{ext}.{ext}"));
                let typed = raw(type_row, "stdout");
                assert!(
                    typed.contains(&format!("answer_{ext}.{ext}(2,")) && typed.contains("TS2322")
                );
                let linted: Value = serde_json::from_str(&raw(lint, "stdout")).unwrap();
                assert!(linted
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|file| file["filePath"] == target.to_str().unwrap()
                        && file["messages"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|m| m["ruleId"] == "no-debugger"
                                && m["line"] == 1
                                && m["severity"] == 2)));
                let findings = result["nativeResult"]["details"]["findingEvidence"]
                    .as_object()
                    .unwrap();
                assert!(findings
                    .values()
                    .any(|f| f["ruleId"] == "eslint:no-debugger"
                        && f["path"] == format!("answer_{ext}.{ext}")
                        && f["line"] == 1));
                assert!(findings.values().any(|f| f["ruleId"] == "tsc:TS2322"
                    && f["path"] == format!("answer_{ext}.{ext}")
                    && f["line"] == 2));
            } else {
                assert_eq!(
                    result["nativeResult"]["findings"].as_array().unwrap().len(),
                    0
                );
            }
            assert_eq!(result["sourceBefore"], result["sourceAfter"]);
            assert_eq!(result["localRuntimeBefore"], result["localRuntimeAfter"]);
            let receipts = result["nativeResult"]["details"]["nativeProducer"]["toolReceipts"]
                .as_array()
                .unwrap();
            assert_eq!(receipts.len(), 4);
            for receipt in receipts {
                assert_eq!(receipt["nativeInputSnapshots"]["unchanged"], true);
                assert_eq!(
                    receipt["nativeInputSnapshots"]["before"],
                    receipt["nativeInputSnapshots"]["after"]
                );
                let row = rows
                    .iter()
                    .find(|r| r["request"]["taskId"] == receipt["tool"])
                    .unwrap();
                assert_eq!(receipt["sdkReceipt"], row["executionReceipt"]);
                if receipt["tool"] == "build" {
                    assert_eq!(
                        receipt["nativeOperationObservation"]["kind"],
                        "typescript-emission"
                    );
                    assert_eq!(
                        receipt["nativeOperationObservation"]["sourceToOutput"]
                            .as_object()
                            .unwrap()
                            .len(),
                        10
                    );
                }
                if receipt["tool"] == "test" {
                    assert_eq!(
                        receipt["nativeOperationObservation"]["kind"],
                        "node-planned-assertions"
                    );
                    assert_eq!(receipt["nativeOperationObservation"]["assertionCount"], 8);
                    assert_eq!(
                        receipt["nativeOperationObservation"]["assertedSourcePaths"]
                            .as_array()
                            .unwrap()
                            .len(),
                        8
                    );
                    assert!(receipt["nativeInputSnapshots"]["before"]["compiledInputs"].is_object());
                }
            }
            let emitted: BTreeMap<_, _> =
                fs::read_dir(scratch.root().join("cache/javascript-build"))
                    .unwrap()
                    .map(|e| {
                        let p = e.unwrap().path();
                        let bytes = bounded(&p, 1024 * 1024);
                        (
                            p.file_name().unwrap().to_str().unwrap().to_owned(),
                            json!({"digest":digest(&bytes),"bytes":bytes.len(),"rawBytes":bytes}),
                        )
                    })
                    .collect();
            assert_eq!(emitted.len(), 20);
            result["emittedModules"] = json!(emitted);
        }
    }
    if ["build-noop", "test-noop", "test-empty", "test-unmet-plan"].contains(&control) {
        assert_eq!(result["nativeResult"]["complete"], false);
        let task = if control == "build-noop" {
            "build"
        } else {
            "test"
        };
        let row = rows
            .iter()
            .find(|r| r["request"]["taskId"] == task)
            .unwrap();
        assert_eq!(
            row["executionReceipt"]["state"],
            if control == "test-unmet-plan" {
                "failed"
            } else {
                "completed"
            }
        );
        if control != "test-unmet-plan" {
            assert_eq!(row["executionReceipt"]["exitCode"], 0);
        }
        let gaps = result["nativeResult"]["coverage_gaps"].to_string();
        assert!(!gaps.is_empty() && gaps != "[]");
    }
    if control == "nonempty-clean" {
        let clean = requests.lock().unwrap()[0].clone();
        let mut mutations = Vec::new();
        for kind in ["argv", "cwd", "environment", "task"] {
            let mut request = clean.clone();
            request.request_id = format!(
                "legion-audit/{}",
                digest(format!("{case_id}:{kind}").as_bytes()).trim_start_matches("sha256:")
            );
            match kind {
                "argv" => request.args.push("--unexpected".into()),
                "cwd" => request.cwd = base.to_str().unwrap().into(),
                "environment" => {
                    request
                        .environment
                        .insert("NODE_OPTIONS".into(), "--inspect".into());
                    request.environment_allowlist.insert("NODE_OPTIONS".into());
                }
                _ => request.task_id = Some("unlisted".into()),
            }
            let receipt = runtime
                .block_on(recorder.execute(request, tokio_util::sync::CancellationToken::new()));
            assert_eq!(
                receipt.state,
                legion_provider_sdk::ExecutionState::UnauthorizedEffect
            );
            assert!(!receipt.process_tree.started);
            mutations.push(json!({"mutation":kind,"matched":true,"execution":recorder.rows.lock().unwrap().last().unwrap().clone()}));
        }
        result["requestMutationControls"] = json!(mutations);
    }
    result["matched"] = json!(true);
    fs::write(path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    result
}

#[test]
#[ignore = "requires managed-CI pinned Node/pnpm/TypeScript/ESLint closure & native authenticated macOS sandbox"]
fn real_javascript_sdk_accuracy() {
    let retained = PathBuf::from(
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR")
            .expect("explicit retained artifact directory"),
    );
    fs::create_dir_all(&retained).unwrap();
    let retained = fs::canonicalize(retained).unwrap();
    let enrollment_path = fs::canonicalize(
        std::env::var_os("LEGION_JS_SDK_ENROLLMENT").expect("source-bound official enrollment"),
    )
    .unwrap();
    let enrollment_bytes = bounded(&enrollment_path, 8 * 1024 * 1024);
    let enrollment: Value = serde_json::from_slice(&enrollment_bytes).unwrap();
    if let Some(child) = std::env::var_os("LEGION_JS_SDK_CHILD") {
        let base = fs::canonicalize(child).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let node = PathBuf::from(enrollment["node"]["path"].as_str().unwrap());
        assert_eq!(
            digest(&bounded(&node, 128 * 1024 * 1024)),
            enrollment["node"]["digest"]
        );
        assert!([
            "sha256:18e387c90ab8a8400183e8bdd396376e1e875b91b4c874b894dcade7b35bf572",
            "sha256:0b4f059915f3bf3c6cbb02422f4a529bfb21cbbec2d29851c9a5d833f78a04f6"
        ]
        .contains(&enrollment["node"]["digest"].as_str().unwrap()));
        assert_eq!(
            runtime_tree(Path::new(enrollment["toolRoot"].as_str().unwrap())),
            enrollment["runtime"]
        );
        assert_eq!(
            digest(&canonical_bytes(&enrollment["runtime"])),
            enrollment["runtimeDigest"]
        );
        let config = code::evidence::config_for(JS).unwrap();
        assert_eq!(config.tools, ["type", "lint", "build", "test"]);
        assert_eq!(
            config.extensions,
            ["js", "jsx", "ts", "tsx", "cjs", "mjs", "cts", "mts"]
        );
        assert_eq!(
            json!(config.variants),
            json!([
                ["javascript", ["js", "cjs", "mjs"]],
                ["typescript", ["ts", "cts", "mts"]],
                ["jsx", ["jsx"]],
                ["tsx", ["tsx"]]
            ])
        );
        assert!(config.required_context.is_empty());
        fs::write(retained.join("enrollment.json"), &enrollment_bytes).unwrap();
        let cases: Vec<_> = CONTROLS
            .iter()
            .map(|control| case(&base, &retained, &enrollment, control))
            .collect();
        assert!(cases.iter().all(|c| c["matched"] == true));
        assert_eq!(
            runtime_tree(Path::new(enrollment["toolRoot"].as_str().unwrap())),
            enrollment["runtime"]
        );
        assert_eq!(bounded(&enrollment_path, 8 * 1024 * 1024), enrollment_bytes);
        let fixture_sources: BTreeMap<String, String> = cases
            .iter()
            .flat_map(|case| {
                case["sourceBefore"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(p, d)| {
                        (
                            format!("{}/{p}", case["caseId"].as_str().unwrap()),
                            d.as_str().unwrap().to_owned(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut record = json!({"schema":"legion-javascript-sdk-accuracy/1","kind":"javascript-sdk-known-answer","provider":JS,"providerVersion":registry_spec(JS)["providerVersion"],"productionQualification":false,"qualificationEligible":true,"claimScope":"known-answer-fixture-cases","executionPath":"native-sdk-frozen-plan-self-sourced-code","modelCalls":0,"admissionScope":"exact fixture policy only; genuine default-owner refusal control; no production owner admission","binding":binding(JS,&fixture_sources),"requiredContract":{"extensions":config.extensions,"variants":config.variants,"tools":config.tools,"requiredContext":config.required_context},"enrollment":{"file":"enrollment.json","digest":digest(&enrollment_bytes),"bytes":enrollment_bytes.len()},"executedScope":["type","lint","build","test"],"cases":cases,"metrics":{"cases":CONTROLS.len(),"matched":CONTROLS.len(),"mismatched":0,"wholeProviderQualified":false,"boundedSdkAccuracyQualified":true},"runtimeLimitations":[{"scope":"package-manager","supported":"explicit pnpm@exact-version only; other/missing declarations remain gaps"},{"scope":"build","supported":"closed native tsc emit grammar; source maps bind every emitted selected input"},{"scope":"test","supported":"closed planned Node assertions over pure answer module forms; arbitrary sources/scripts remain gaps"},{"scope":"project-effects","mode":"authenticated deny-network; project writes allowed; default owner admission denied"}]});
        record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
        let bytes = serde_json::to_vec_pretty(&record).unwrap();
        fs::write(retained.join("code_javascript.json"), &bytes).unwrap();
        println!(
            "JAVASCRIPT_SDK_ACCURACY_ARTIFACT {}",
            json!({"provider":JS,"file":"code_javascript.json","digest":digest(&bytes),"bytes":bytes.len(),"qualificationDigest":record["qualificationDigest"],"qualificationEligible":true,"productionQualification":false})
        );
        return;
    }
    let fixture = Fixture::new();
    assert!(!retained.starts_with(&fixture.0) && !fixture.0.starts_with(&retained));
    let node = PathBuf::from(enrollment["node"]["path"].as_str().unwrap());
    let search = std::env::join_paths([
        node.parent().unwrap(),
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_javascript_sdk_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", search)
        .env("HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("LEGION_JS_SDK_CHILD", &fixture.0)
        .env("LEGION_JS_SDK_ENROLLMENT", &enrollment_path)
        .env("LEGION_PROVIDER_BENCHMARK_DIR", &retained)
        .output()
        .unwrap();
    fs::write(retained.join("child.stdout.log"), &output.stdout).unwrap();
    fs::write(retained.join("child.stderr.log"), &output.stderr).unwrap();
    fs::write(retained.join("child-execution.json"),serde_json::to_vec_pretty(&json!({"schema":"legion-javascript-sdk-child/1","productionQualification":false,"status":{"success":output.status.success(),"exitCode":output.status.code(),"signal":output.status.signal()},"stdout":{"file":"child.stdout.log","digest":digest(&output.stdout),"bytes":output.stdout.len()},"stderr":{"file":"child.stderr.log","digest":digest(&output.stderr),"bytes":output.stderr.len()}})).unwrap()).unwrap();
    std::io::stdout().write_all(&output.stdout).unwrap();
    std::io::stderr().write_all(&output.stderr).unwrap();
    assert!(output.status.success(),"genuine SDK child failed; original receipts/raw streams retained in explicit benchmark output");
}
