//! Constructed real-tool controls for external legacy linter adapters.
//! Explicitly ignored: requires actual actionlint, hadolint, SwiftLint & native macOS sandbox.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute_with_cancellation,
    native_providers::legacy_checks::{resolve_request, AuditExternalProjectTool, AuditScratch},
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
};

const SOURCE: &str = "engine/crates/legion-audit/tests/real_legacy_linter_accuracy.rs";
const POLICY: &str = "legion-real-legacy-linter-qualification-v1";
const ACTIONLINT: &str = "legacy.security.github-actions-lint";
const HADOLINT: &str = "legacy.security.docker";
const SWIFTLINT: &str = "legacy.quality.swift-lint";
const ACTION_PATH: &str = ".github/workflows/ci.yml";
const DOCKER_PATH: &str = "Dockerfile";
const SWIFT_PATH: &str = "Example.swift";

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
        let base = std::env::var_os("LEGION_REAL_LINTER_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-real-linter-{}-{}",
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
    // Match actual filesystem components before display separator normalization.
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
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let base = std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let scratch = Scratch(base.join(format!(
        "legion-source-binding-{}-{}",
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

    // Matching directories must recurse; only matching regular files are omitted.
    fs::remove_file(&receipt).unwrap();
    fs::create_dir(&receipt).unwrap();
    fs::write(receipt.join("nested.rs"), b"retained source").unwrap();
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
        // Unix backslashes are literal names, never receipt path separators.
        format!(
            "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance\\{}.json",
            "a".repeat(64)
        ),
        format!(
            "engine/crates/legion-audit/src/.audit\\arcane/receipts/session-provenance/{}.json",
            "a".repeat(64)
        ),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"must remain bound").unwrap();
        assert_eq!(snapshot(root).len(), baseline.len() + 1, "{relative}");
        fs::write(&path, b"changed retained bytes").unwrap();
        let changed = snapshot(root);
        fs::write(&path, b"must remain bound").unwrap();
        assert_ne!(snapshot(root), changed, "{relative}");
        fs::remove_file(path).unwrap();
    }
    assert_eq!(snapshot(root), baseline);
    fs::write(&source, b"pub fn mutated_source() {}\n").unwrap();
    assert_ne!(snapshot(root), baseline);

    // Reject matching symlinks before applying any generated-file exclusion.
    std::os::unix::fs::symlink(&source, &receipt).unwrap();
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
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
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
            "sandbox": "native-macos-deny-network-production-linter-contract",
            "acceptedExitCodes": [0, 1, 2]
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
            && req.accepted_exit_codes == [0, 1, 2].into_iter().collect()
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
                    "exact real-linter fixture admission"
                } else {
                    "outside exact real-linter fixture policy"
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

fn fixture_contents(id: &str, positive: bool) -> (&'static str, &'static str) {
    match (id, positive) {
        (ACTIONLINT, true) => (
            ACTION_PATH,
            "name: CI\non: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n        uses: actions/checkout@v4\n",
        ),
        (ACTIONLINT, false) => (
            ACTION_PATH,
            "name: CI\non: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        ),
        (HADOLINT, true) => (DOCKER_PATH, "FROM ubuntu:latest\nCMD [\"true\"]\n"),
        (HADOLINT, false) => (DOCKER_PATH, "FROM ubuntu:24.04\nCMD [\"true\"]\n"),
        // Default type_name examples: https://realm.github.io/SwiftLint/type_name.html
        // Space before braces avoids opening_brace; plain class avoids static_over_final_class.
        (SWIFTLINT, true) => (SWIFT_PATH, "class example {}\n"),
        (SWIFTLINT, false) => (SWIFT_PATH, "class Example {}\n"),
        _ => panic!("unsupported real linter provider {id}"),
    }
}

fn expected_args(id: &str) -> (&'static str, &'static str, &'static [&'static str]) {
    match id {
        ACTIONLINT => (
            "actionlint",
            "ci_lint",
            &["-format", "{{json .}}", "--", "./.github/workflows/ci.yml"],
        ),
        HADOLINT => ("hadolint", "docker", &["--format", "json", "Dockerfile"]),
        SWIFTLINT => (
            "swiftlint",
            "swift_lint",
            &["lint", "--quiet", "--reporter", "json"],
        ),
        _ => panic!("unsupported real linter provider {id}"),
    }
}

fn case(base: &Path, id: &str, positive: bool) -> Value {
    let (path, source) = fixture_contents(id, positive);
    let case_id = format!(
        "{}-{}",
        id.replace('.', "-"),
        if positive { "positive" } else { "absence" }
    );
    let root = base.join(&case_id).join("source");
    let run = base.join(&case_id).join("run");
    let file = root.join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(&file, source).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    assert_eq!(inventory.entries.len(), 1, "one frozen linter input");
    assert_eq!(inventory.entries[0].path, path);

    let spec: ProviderSpec = serde_json::from_value(registry_spec(id)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"real-linter-qualification-key"))
        .unwrap();
    let provider = frozen.provider(id).expect("provider frozen into plan");
    assert_eq!(provider.configuration["denominatorCount"], 1);

    let (tool_name, check, raw_args) = expected_args(id);
    let args: Vec<String> = raw_args.iter().map(|arg| (*arg).into()).collect();
    let resolved =
        resolve_request(&root, tool_name, &args).expect("provisioned real linter required");
    assert_eq!(resolved.args, args);
    let tool = fs::canonicalize(resolved.executable).unwrap();
    assert!(
        !tool.starts_with(base),
        "host tool must not come from fixture tree"
    );
    let tool_bytes = fs::read(&tool).unwrap();
    assert!(
        !tool_bytes.starts_with(b"#!"),
        "script substitutes are forbidden"
    );
    assert_eq!(digest(&tool_bytes), resolved.digest);
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").expect("native macOS sandbox required");
    let wrapper_digest = digest(&fs::read(&wrapper).unwrap());
    let escaped = root
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile_text = format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath \"{escaped}\"))\n");
    let profile_digest = digest(profile_text.as_bytes());
    let profile = scratch.sandbox_dir().join(format!(
        "audit-{}.sb",
        profile_digest.trim_start_matches("sha256:")
    ));
    let (environment, allowlist) = expected_environment(&run);
    let policy = Arc::new(ScopedPolicy {
        id: id.into(),
        check: check.into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: resolved.digest,
        wrapper,
        wrapper_digest,
        profile,
        profile_text,
        args,
        environment,
        allowlist,
        decisions: Mutex::new(Vec::new()),
    });
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
        SharedPolicy(policy.clone()),
    );
    let mut native = NativeProviderRegistry::new(&root)
        .with_scratch(scratch.clone())
        .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(effects)));
    native.legacy_checks = native
        .legacy_checks
        .with_fixture_policy_authorizer(policy.clone());
    let execution = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &native,
            tokio_util::sync::CancellationToken::new(),
        ));
    eprintln!(
        "LEGACY_LINTER_NATIVE_EXECUTION_DIAGNOSTIC {}",
        serde_json::to_string(&json!({
        "caseId":case_id,"execution":execution.as_ref().ok(),
        "executionError":execution.as_ref().err().map(ToString::to_string)}))
        .unwrap()
    );
    let report = execution.unwrap();
    // Capture every actual result & original immutable stream before asserting
    // successful completion; failed native tools must remain diagnosable.
    let diagnostic_results: Vec<Value> = report.results.iter().map(|entry| {
        let receipt = &entry.result.details["executionReceipt"];
        let streams: BTreeMap<_, _> = ["stdout", "stderr"].into_iter().map(|stream| {
            let item = &receipt[stream];
            let raw = item["path"].as_str().and_then(|path| fs::read(scratch.artifacts_dir().join(path)).ok());
            (stream, json!({"artifact":item,"raw":raw.as_ref().and_then(|b| std::str::from_utf8(b).ok()),
                "rawBytes":raw.as_ref(),"actualDigest":raw.as_ref().map(|b| digest(b))}))
        }).collect();
        json!({"provider":entry.provider,"actualProviderResult":entry.result,"streams":streams})
    }).collect();
    let diagnostic = json!({"schema":"legion-native-linter-diagnostic/1","caseId":case_id,
        "execution":report,"results":diagnostic_results,"policyDecisions":*policy.decisions.lock().unwrap()});
    let diagnostic_bytes = serde_json::to_vec(&diagnostic).unwrap();
    eprintln!(
        "LEGACY_LINTER_NATIVE_CASE_DIAGNOSTIC {}",
        serde_json::to_string(&diagnostic).unwrap()
    );
    let retained_diagnostic = if let Some(directory) =
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR")
    {
        let directory = PathBuf::from(directory).join("native-diagnostics");
        fs::create_dir_all(&directory).unwrap();
        let filename = format!(
            "native-diagnostic-{}.json",
            digest(&diagnostic_bytes).trim_start_matches("sha256:")
        );
        let retained = legion_effects::ArtifactWriter::new(&directory)
            .write_immutable(&filename, &diagnostic_bytes)
            .unwrap();
        assert_eq!(
            fs::read(directory.join(&retained.path)).unwrap(),
            diagnostic_bytes
        );
        assert!(retained.immutable);
        assert_eq!(retained.digest, digest(&diagnostic_bytes));
        assert_eq!(retained.bytes, diagnostic_bytes.len());
        let item = json!({"path":directory.join(retained.path),"digest":retained.digest,"bytes":retained.bytes,
            "qualificationEligible":false});
        eprintln!(
            "REAL_LINTER_DIAGNOSTIC_ARTIFACT {}",
            serde_json::to_string(&item).unwrap()
        );
        item
    } else {
        Value::Null
    };
    fs::write(run.join("native-case-diagnostic.json"), &diagnostic_bytes).unwrap();
    assert_eq!(report.planned_providers, vec![id]);
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0].result;
    assert!(
        result.applicable && result.complete,
        "{:?}",
        result.coverage_gaps
    );
    assert!(result.coverage_gaps.is_empty() && result.degradation.is_empty());
    if id != SWIFTLINT {
        assert!(
            result.findings.is_empty(),
            "candidate adapters must not adjudicate findings"
        );
    }
    let coverage = result.coverage.as_ref().expect("frozen coverage");
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
    assert!(coverage.gaps.is_empty());
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );

    let receipt = &result.details["executionReceipt"];
    assert_eq!(receipt["schemaVersion"], 1);
    assert!(receipt["receiptId"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(receipt["state"], "completed");
    assert_eq!(receipt["complete"], true);
    assert_eq!(receipt["policyId"], POLICY);
    assert_eq!(receipt["policy"]["allowed"], true);
    assert_eq!(receipt["policy"]["id"], POLICY);
    assert_eq!(receipt["policy"]["version"], 1);
    assert_eq!(
        receipt["policy"]["digest"],
        digest(&canonical_bytes(&policy.definition()))
    );
    assert_eq!(receipt["planId"], frozen.digest());
    assert_eq!(receipt["providerId"], id);
    assert_eq!(receipt["taskId"], check);
    assert_eq!(receipt["cwd"], root.to_string_lossy().as_ref());
    assert_eq!(
        receipt["executable"]["canonicalPath"],
        policy.wrapper.to_string_lossy().as_ref()
    );
    assert_eq!(receipt["executable"]["digest"], policy.wrapper_digest);
    assert_eq!(receipt["executable"]["version"]["qualified"], true);
    assert_eq!(
        receipt["executable"]["version"]["args"],
        json!(policy.wrapped_args(&["--version".into()]))
    );
    assert_eq!(receipt["executable"]["version"]["exitCode"], 0);
    let version = receipt["executable"]["version"]["output"].as_str().unwrap();
    assert!(
        !version.trim().is_empty(),
        "native sandboxed linter version probe"
    );
    assert_eq!(
        receipt["command"]["executable"],
        policy.wrapper.to_string_lossy().as_ref()
    );
    assert_eq!(
        receipt["command"]["args"],
        json!(policy.wrapped_args(&policy.args))
    );
    assert_eq!(receipt["sandbox"]["required"], true);
    assert_eq!(receipt["sandbox"]["networkEnabled"], true);
    assert_eq!(receipt["sandbox"]["receiptId"], policy.sandbox_id());
    assert_eq!(
        fs::read(&policy.profile).unwrap(),
        policy.profile_text.as_bytes()
    );
    assert_eq!(digest(&fs::read(&tool).unwrap()), policy.tool_digest);
    assert_eq!(
        fs::read(&file).unwrap(),
        source.as_bytes(),
        "linter fixture unchanged"
    );
    assert_eq!(receipt["processTree"]["started"], true);
    assert_eq!(receipt["processTree"]["terminated"], true);
    assert_eq!(receipt["processTree"]["reaped"], true);
    // SwiftLint exits 2 for error diagnostics; other positive controls exit 1.
    // https://github.com/realm/SwiftLint/blob/main/Source/SwiftLintFramework/LintOrAnalyzeCommand.swift
    let expected_exit = if !positive {
        0
    } else if id == SWIFTLINT {
        2
    } else {
        1
    };
    assert_eq!(receipt["exitCode"], expected_exit);
    assert!(receipt["signal"].is_null());
    assert_eq!(receipt["gaps"], json!([]));

    let stdout = artifact(receipt, "stdout", &scratch);
    let stderr = artifact(receipt, "stderr", &scratch);
    assert!(
        stderr.is_empty(),
        "linter diagnostics are expected on stdout"
    );
    let tool_report: Value = serde_json::from_slice(&stdout).expect("real linter JSON output");
    let tool_count = if tool_report.is_null() {
        0
    } else {
        tool_report.as_array().expect("linter JSON array").len()
    };
    let expected_count = u64::from(positive);
    assert_eq!(
        tool_count as u64, expected_count,
        "actual tool report count"
    );
    if id == HADOLINT && positive {
        assert_eq!(tool_report[0]["code"], "DL3007", "fixture-specific warning");
    }
    if id == SWIFTLINT && positive {
        assert_eq!(
            tool_report[0]["rule_id"], "type_name",
            "only planted SwiftLint rule"
        );
        assert_eq!(tool_report[0]["severity"], "Error");
        assert_eq!(tool_report[0]["file"], file.to_string_lossy().as_ref());
        assert_eq!(tool_report[0]["line"], 1);
    }
    assert_eq!(result.details["findingsCount"], expected_count);

    let rule = match id {
        ACTIONLINT => "legacy.ci_lint.actionlint",
        HADOLINT => "legacy.docker.hadolint",
        SWIFTLINT => "legacy.swift_lint.swiftlint",
        _ => panic!("unsupported real linter provider {id}"),
    };
    let claim = format!("{} reported 1 finding(s)", check);
    let actual_candidates: Vec<Value> = result.details["candidates"]
        .as_array()
        .expect("candidate projection")
        .iter()
        .map(|candidate| {
            let evidence = &candidate["evidence"][0];
            json!({
                "id": candidate["id"],
                "ruleId": candidate["ruleId"],
                "role": candidate["role"],
                "path": evidence["file"],
                "line": evidence["line"],
                "claim": candidate["claim"],
                "severityHint": candidate["severityHint"],
                "evidenceStrength": candidate["evidenceStrength"],
                "verdict": candidate["verdict"],
                "adjudicationRequired": candidate["adjudicationRequired"]
            })
        })
        .collect();
    let expected_candidates = if positive && id != SWIFTLINT {
        let candidate_id = digest(format!("{rule}\0{path}\0{}", 1).as_bytes());
        vec![json!({
            "id": candidate_id,
            "ruleId": rule,
            "role": "candidate-generator",
            "path": path,
            "line": 1,
            "claim": claim,
            "severityHint": "medium",
            "evidenceStrength": "candidate",
            "verdict": "UNADJUDICATED",
            "adjudicationRequired": true
        })]
    } else {
        Vec::new()
    };
    assert_eq!(actual_candidates, expected_candidates);
    let (expected, actual) = if id == SWIFTLINT {
        // Production apply_parse_outcome emits one deterministic summary finding,
        // not one finding per tool row or a candidate awaiting adjudication.
        let finding_id = digest(format!("{rule}\0{path}\0{}", 1).as_bytes());
        let expected_findings = if positive {
            json!([{"id":finding_id,"severity":"medium"}])
        } else {
            json!([])
        };
        let expected_evidence = if positive {
            json!({(finding_id.clone()):{"ruleId":rule,"path":path,"line":1,"message":claim}})
        } else {
            json!({})
        };
        let expected_locations = if positive {
            json!({(finding_id):[format!("{path}:1")]})
        } else {
            json!({})
        };
        (
            json!({"findingsCount":expected_count,"candidates":[],"findings":expected_findings,
                "findingEvidence":expected_evidence,"findingLocations":expected_locations}),
            json!({"findingsCount":result.details["findingsCount"],"candidates":actual_candidates,
                "findings":result.findings,
                "findingEvidence":result.details.get("findingEvidence").cloned().unwrap_or_else(|| json!({})),
                "findingLocations":result.details.get("findingLocations").cloned().unwrap_or_else(|| json!({}))}),
        )
    } else {
        (
            json!({"findingsCount":expected_count,"candidates":expected_candidates}),
            json!({"findingsCount":result.details["findingsCount"],"candidates":actual_candidates}),
        )
    };
    assert_eq!(actual, expected);

    let mut fixture_sources = BTreeMap::new();
    fixture_sources.insert(path.to_owned(), digest(source.as_bytes()));
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1, "one exact tool admission");
    assert_eq!(decisions[0]["allowed"], true);
    assert_eq!(decisions[0]["requestId"], receipt["requestId"]);
    assert_eq!(decisions[0]["providerId"], receipt["providerId"]);
    assert_eq!(decisions[0]["planId"], receipt["planId"]);
    assert_eq!(decisions[0]["taskId"], receipt["taskId"]);
    assert_eq!(
        decisions[0]["executable"],
        receipt["executable"]["canonicalPath"]
    );
    assert_eq!(
        decisions[0]["expectedDigest"],
        receipt["executable"]["digest"]
    );
    assert_eq!(decisions[0]["args"], receipt["command"]["args"]);
    assert_eq!(
        decisions[0]["versionArgs"],
        receipt["executable"]["version"]["args"]
    );
    assert_eq!(
        decisions[0]["sandbox"]["id"],
        receipt["sandbox"]["receiptId"]
    );
    json!({
        "caseId":case_id,
        "nativeDiagnostic":{"diagnostic":diagnostic,"retainedArtifact":retained_diagnostic,"rawBytes":diagnostic_bytes},
        "outputKind":if id == SWIFTLINT {"findings"} else {"candidates"},
        "control":if positive {"positive"} else {"absence"},
        "fixtureFiles":{(path):source},
        "fixtureSources":fixture_sources,
        "inventoryDigest":inventory.digest,
        "planDigest":frozen.digest(),
        "coverage":{"expected":coverage.expected,"examined":coverage.examined,
            "denominatorDigest":coverage.denominator_digest,"gaps":coverage.gaps},
        "expected":expected,
        "actual":actual,
        "matched":actual == expected,
        "expectedToolReportCount":expected_count,
        "actualToolReportCount":tool_count,
        "toolVersion":{"output":version,"exitCode":receipt["executable"]["version"]["exitCode"],
            "args":receipt["executable"]["version"]["args"],"qualified":receipt["executable"]["version"]["qualified"]},
        "toolIdentity":{"path":tool,"digest":policy.tool_digest},
        "actualStdout":String::from_utf8(stdout).unwrap(),
        "actualStderr":String::from_utf8(stderr).unwrap(),
        "nativeDetails":result.details,
        "nativeFindings":result.findings,
        "policyDefinition":policy.definition(),
        "policyDecisions":*decisions,
        "executionReceipt":receipt
    })
}

#[test]
#[ignore = "explicit real-linter qualification; requires provisioned actionlint, hadolint, SwiftLint & native macOS sandbox"]
fn real_legacy_linter_accuracy() {
    if let Some(base) = std::env::var_os("LEGION_REAL_LINTER_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let mut all_cases = Vec::new();
        for id in [ACTIONLINT, HADOLINT, SWIFTLINT] {
            all_cases.push(case(&base, id, true));
            all_cases.push(case(&base, id, false));
        }
        let mut counts = BTreeMap::new();
        counts.insert(ACTIONLINT, 2);
        counts.insert(HADOLINT, 2);
        counts.insert(SWIFTLINT, 2);
        for id in [ACTIONLINT, HADOLINT, SWIFTLINT] {
            let cases: Vec<_> = all_cases
                .iter()
                .filter(|case| {
                    case["caseId"]
                        .as_str()
                        .unwrap()
                        .starts_with(&id.replace('.', "-"))
                })
                .cloned()
                .collect();
            let matched = cases
                .iter()
                .filter(|case| case["expected"] == case["actual"])
                .count();
            assert_eq!(cases.len(), counts[id]);
            assert_eq!(matched, cases.len(), "{id}: real linter control mismatch");
            let version = cases[0]["toolVersion"]["output"].clone();
            let fixture_sources: BTreeMap<String, String> = cases
                .iter()
                .flat_map(|case| case["fixtureSources"].as_object().unwrap().iter())
                .map(|(path, value)| (path.clone(), value.as_str().unwrap().to_owned()))
                .collect();
            let mut record = json!({
                "schema":"legion-real-linter-provider-accuracy/1",
                "provider":id,
                "providerVersion":registry_spec(id)["providerVersion"],
                "modelCalls":0,
                "executionPath":"native-sdk-frozen-plan-real-linter",
                "coverageState":"complete",
                "outputKind":if id == SWIFTLINT {"findings"} else {"candidates"},
                "stage":if id == SWIFTLINT {"finding"} else {"candidate"},
                "scope":if id == SWIFTLINT {
                    "one actual tool diagnostic and one clean input; deterministic summary finding only"
                } else {
                    "one actual tool diagnostic and one clean input; candidates remain unadjudicated"
                },
                "binding":binding(id, &fixture_sources),
                "toolVersion":version,
                "cases":cases,
                "metrics":{"cases":cases.len(),"matched":matched,"mismatched":cases.len()-matched},
                "status":"pass"
            });
            record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
            if let Some(dir) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
                assert!(Path::new(&dir).is_absolute());
                fs::create_dir_all(&dir).unwrap();
                fs::write(
                    PathBuf::from(dir).join(format!("{}.json", id.replace('.', "_"))),
                    serde_json::to_vec_pretty(&record).unwrap(),
                )
                .unwrap();
            }
            println!(
                "LEGACY_LINTER_PROVIDER_ACCURACY {}",
                serde_json::to_string(&record).unwrap()
            );
        }
        return;
    }

    let fixture = Fixture::new();
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "real_legacy_linter_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", fixture.0.join("home"))
        .env("XDG_CONFIG_HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("LEGION_REAL_LINTER_CHILD", &fixture.0);
    if let Some(dir) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        assert!(Path::new(&dir).is_absolute());
        child.env("LEGION_PROVIDER_BENCHMARK_DIR", dir);
    }
    let output = child.output().unwrap();
    print!("{}", String::from_utf8(output.stdout).unwrap());
    eprint!("{}", String::from_utf8(output.stderr).unwrap());
    assert!(
        output.status.success(),
        "real-linter qualification child failed"
    );
}
