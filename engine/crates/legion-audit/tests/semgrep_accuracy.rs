//! Constructed Python controls exercising both packaged Semgrep rules through native SDK.
//! Fixture qualification only; production owner admission remains unqualified.
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
    process::Command,
    sync::{Arc, Mutex},
};

const SOURCE: &str = "engine/crates/legion-audit/tests/semgrep_accuracy.rs";
const POLICY: &str = "legion-semgrep-sdk-fixture-v1";
const ID: &str = "legacy.security.sast";
const SCOPE: &str = "constructed Python controls for two packaged intrafile taint rules; no auto parity, population accuracy, production admission or vulnerability adjudication";
const GATE: &str = "scripts/ci/audit-semgrep-provider-accuracy.py";
const WHEELS: &[&str] = &[
    "sha256:ca54b5cc71c832b56c9cf07fa17f087917b203dacb652d74be71aa8006f5a710",
    "sha256:4e9f494134b676c73722e1f5b7c2750c94491dddc0e8f337cb9560b0b78d20ce",
];
const CORES: &[&str] = &[
    "sha256:5b8937bf9596ad8b61fa8aeb4729ec5f0119d5e76f566b76cd6d0562b0d61032",
    "sha256:02faa1d3caa053d4bb64c71d68772006ab92488abd3d4f992e45a164cfe1ae21",
];

mod semgrep {
    pub const RULES: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/rules/opengrep/legion-core.yml"
    ));
    pub fn rules_digest() -> String {
        super::digest(RULES.as_bytes())
    }
    pub fn contract() -> serde_json::Value {
        serde_json::json!({"version":"1.141.0","rulesSource":"src/registry/rules/opengrep/legion-core.yml","rulesDigest":rules_digest(),
            "ruleIds":["legion-command-injection-shell","legion-sql-interpolation"],"languages":["python","javascript","typescript"],
            "scope":"two packaged intrafile taint rules only; no auto-rules parity or vulnerability adjudication",
            "suppression":"disabled","exitCodes":[0]})
    }
}

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
        let base = std::env::var_os("LEGION_SEMGREP_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-semgrep-{}-{}",
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
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
        GATE,
        "scripts/ci/provision-python-qualification-tools.py",
        "scripts/ci/python-tool-locks/semgrep-macos-arm64-cp314.json",
        "scripts/ci/python-tool-locks/semgrep-macos-arm64-cp314.txt",
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
    allowed.insert("PYTHONDONTWRITEBYTECODE".into());
    env.insert("PYTHONNOUSERSITE".into(), "1".into());
    allowed.insert("PYTHONNOUSERSITE".into());
    env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
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
            "sandbox": "native-macos-deny-network-production-semgrep-limited-contract",
            "acceptedExitCodes": [0]
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
            && req.version_requirement.as_deref() == Some("exact:1.141.0")
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
            && req.accepted_exit_codes == [0].into_iter().collect()
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
                    "exact Semgrep fixture admission"
                } else {
                    "outside exact Semgrep fixture policy"
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

fn enrollment() -> Value {
    let value: Value = serde_json::from_slice(
        &fs::read(
            std::env::var_os("LEGION_PYTHON_TOOL_ENROLLMENT")
                .expect("source-owned Python enrollment required"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(value["schema"], "legion-python-tool-enrollment/1");
    assert_eq!(value["tool"]["name"], "semgrep");
    assert_eq!(value["tool"]["version"], "1.141.0");
    assert!(WHEELS.contains(&value["tool"]["wheelSha256"].as_str().unwrap()));
    verify_enrollment(&value);
    value
}
fn verify_enrollment(value: &Value) {
    let runtime = &value["runtime"];
    let root = Path::new(runtime["root"].as_str().unwrap());
    assert!(root.is_absolute());
    let files = runtime["files"].as_object().unwrap();
    assert_eq!(runtime["root"], "/");
    let roots: Vec<PathBuf> = runtime["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| PathBuf::from(x.as_str().unwrap()))
        .collect();
    let exclusions: Vec<PathBuf> = runtime["exclusions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| PathBuf::from(x.as_str().unwrap()))
        .collect();
    let stdlib = PathBuf::from(value["interpreter"]["stdlibRoot"].as_str().unwrap());
    assert!(exclusions
        .iter()
        .all(|p| *p == stdlib.join("site-packages")));
    assert_eq!(
        runtime["digest"],
        digest(&canonical_bytes(
            &json!({"absent":runtime["absent"],"files":runtime["files"],"links":runtime["links"],"roots":runtime["roots"]})
        ))
    );
    let sealed_links: BTreeMap<String, String> =
        serde_json::from_value(runtime["links"].clone()).unwrap();
    fn resolve_sealed(
        path: &Path,
        links: &BTreeMap<String, String>,
        allow_missing: bool,
    ) -> PathBuf {
        use std::{collections::VecDeque, path::Component};
        assert!(path.is_absolute());
        let mut pending: VecDeque<_> = path
            .components()
            .map(|c| c.as_os_str().to_os_string())
            .collect();
        let mut resolved = PathBuf::from("/");
        let mut hops = 0;
        while let Some(part) = pending.pop_front() {
            let part_path = Path::new(&part);
            match part_path.components().next().unwrap() {
                Component::RootDir => resolved = PathBuf::from("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    assert!(resolved.pop());
                }
                Component::Normal(_) => {
                    resolved.push(&part);
                    let metadata = match fs::symlink_metadata(&resolved) {
                        Ok(metadata) => metadata,
                        Err(e) if allow_missing && e.kind() == std::io::ErrorKind::NotFound => {
                            return resolved
                        }
                        Err(e) => panic!("runtime path unavailable: {e}"),
                    };
                    if metadata.file_type().is_symlink() {
                        hops += 1;
                        assert!(hops <= 40, "runtime symlink hop bound");
                        let key = resolved
                            .strip_prefix("/")
                            .unwrap()
                            .to_string_lossy()
                            .into_owned();
                        let target = fs::read_link(&resolved).unwrap();
                        assert_eq!(
                            links.get(&key).map(String::as_str),
                            Some(target.to_str().unwrap()),
                            "unsealed runtime symlink hop"
                        );
                        resolved.pop();
                        for component in target.components().rev() {
                            pending.push_front(component.as_os_str().to_os_string());
                        }
                    }
                }
                Component::Prefix(_) => panic!("non-Unix runtime path"),
            }
        }
        resolved
    }
    fn walk(
        path: &Path,
        roots: &[PathBuf],
        exclusions: &[PathBuf],
        sealed: &BTreeMap<String, String>,
        files: &mut BTreeMap<String, String>,
        links: &mut BTreeMap<String, String>,
    ) {
        if exclusions.iter().any(|p| path.starts_with(p)) {
            return;
        }
        let name = path
            .strip_prefix("/")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if path.is_symlink() {
            assert!(roots
                .iter()
                .any(|r| resolve_sealed(path, sealed, false).starts_with(r)));
            links.insert(
                name,
                fs::read_link(path).unwrap().to_string_lossy().into_owned(),
            );
        } else if path.is_dir() {
            for child in fs::read_dir(path).unwrap() {
                walk(
                    &child.unwrap().path(),
                    roots,
                    exclusions,
                    sealed,
                    files,
                    links,
                );
            }
        } else if path.is_file() {
            files.insert(name, digest(&fs::read(path).unwrap()));
        } else {
            panic!("unsupported runtime entry");
        }
    }
    let mut observed_files = BTreeMap::new();
    let mut observed_links = BTreeMap::new();
    for root in &roots {
        assert_eq!(resolve_sealed(root, &sealed_links, false), *root);
        walk(
            root,
            &roots,
            &exclusions,
            &sealed_links,
            &mut observed_files,
            &mut observed_links,
        );
    }
    for (name, target) in &sealed_links {
        let relative = Path::new(name);
        assert!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)))
        );
        let path = Path::new("/").join(relative);
        assert!(path.is_symlink());
        assert_eq!(
            fs::read_link(&path).unwrap().to_str(),
            Some(target.as_str())
        );
        let final_path = resolve_sealed(&path, &sealed_links, false);
        assert!(
            roots.iter().any(|r| final_path.starts_with(r))
                || (final_path.is_dir()
                    && observed_files
                        .keys()
                        .any(|p| Path::new("/").join(p).starts_with(&final_path)))
        );
        observed_links.insert(name.clone(), target.clone());
    }
    let absent: Vec<String> = serde_json::from_value(runtime["absent"].clone()).unwrap();
    assert!(absent.windows(2).all(|pair| pair[0] < pair[1]));
    for path in absent {
        let path = Path::new(&path);
        assert!(path.is_absolute());
        assert!(fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound));
        resolve_sealed(path, &sealed_links, true);
    }
    assert_eq!(json!(observed_files), runtime["files"]);
    assert_eq!(json!(observed_links), runtime["links"]);
    for (name, expected) in files {
        let path = Path::new(name);
        assert!(
            !path.is_absolute()
                && path
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)))
        );
        assert_eq!(
            digest(&fs::read(root.join(path)).unwrap()),
            expected.as_str().unwrap()
        );
    }
    for key in ["launcher", "interpreter", "lock"] {
        let item = &value[key];
        let path = Path::new(item["path"].as_str().unwrap());
        assert!(path.is_absolute());
        assert_eq!(
            digest(&fs::read(path).unwrap()),
            item["digest"].as_str().unwrap()
        );
    }
    let lock: Value =
        serde_json::from_slice(&fs::read(value["lock"]["path"].as_str().unwrap()).unwrap())
            .unwrap();
    let locked_tool = lock["wheels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["name"] == "semgrep")
        .unwrap();
    assert_eq!(
        format!("sha256:{}", locked_tool["sha256"].as_str().unwrap()),
        value["tool"]["wheelSha256"].as_str().unwrap()
    );
    assert_eq!(locked_tool["version"], value["tool"]["version"]);
    let discovery = &value["nativeDiscovery"];
    let mut discovery_payload = discovery.clone();
    discovery_payload.as_object_mut().unwrap().remove("digest");
    assert_eq!(
        discovery["digest"],
        digest(&canonical_bytes(&discovery_payload))
    );
    assert_eq!(
        discovery["systemExemptions"],
        json!(["/usr/lib", "/System/Library"])
    );
    assert_eq!(discovery["inspector"]["path"], "/usr/bin/otool");
    assert_eq!(
        discovery["inspector"]["digest"],
        digest(&fs::read("/usr/bin/otool").unwrap())
    );
    let images = discovery["images"].as_array().unwrap();
    assert!(!images.is_empty());
    for image in images {
        for key in ["path", "executable"] {
            let p = Path::new(image[key].as_str().unwrap());
            assert!(p.is_absolute());
            assert!(files.contains_key(p.strip_prefix("/").unwrap().to_str().unwrap()));
        }
        for dependency in image["dependencies"].as_array().unwrap() {
            let p = Path::new(dependency["resolved"].as_str().unwrap());
            assert!(p.is_absolute());
            if dependency["systemExempt"] == true {
                assert!(p.starts_with("/usr/lib") || p.starts_with("/System/Library"));
            } else {
                assert_eq!(dependency["systemExempt"], false);
                assert!(files.contains_key(p.strip_prefix("/").unwrap().to_str().unwrap()));
            }
        }
    }
    assert!(images
        .iter()
        .any(|i| i["path"] == value["interpreter"]["path"]));
    assert!(images.iter().any(|i| i["path"]
        .as_str()
        .unwrap()
        .ends_with("/semgrep/bin/semgrep-core")));
    let core = files
        .iter()
        .find(|(p, _)| p.ends_with("/semgrep/bin/semgrep-core"))
        .expect("pinned native core member required");
    assert!(CORES.contains(&core.1.as_str().unwrap()));
}
fn fixtures() -> Vec<(&'static str, &'static str, Option<&'static str>)> {
    vec![
        ("shell-planted", "import os\nfrom flask import request\nos.system(request.args.get(\"cmd\")) # nosemgrep\n", Some("legion-command-injection-shell")),
        ("shell-clean", "import os\nfrom flask import request\nsupplied = request.args.get(\"cmd\")\nos.system(\"printf fixed\") # nosemgrep\n", None),
        ("sql-planted", "from flask import request\ndef query(cursor):\n    cursor.execute(request.args.get(\"sql\")) # nosemgrep\n", Some("legion-sql-interpolation")),
        ("sql-clean", "from flask import request\ndef query(cursor):\n    supplied = request.args.get(\"sql\")\n    cursor.execute(\"SELECT 1\") # nosemgrep\n", None),
        ("operational-error", "def broken(:\n", None),
    ]
}
fn run_case(
    base: &Path,
    name: &str,
    source: &str,
    expected_rule: Option<&str>,
    missing: bool,
    enrolled: &Value,
) -> Value {
    verify_enrollment(enrolled);
    let root = base.join(name).join("source");
    let run = base.join(name).join("run");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("app.py"), source).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(name)
        .unwrap();
    assert_eq!(inventory.entries.len(), 1);
    let frozen = AuditPlan::compile_with_root(
        Some(&root),
        &inventory,
        &[serde_json::from_value::<ProviderSpec>(registry_spec(ID)).unwrap()],
    )
    .unwrap()
    .freeze(Some(b"semgrep-fixture-key"))
    .unwrap();
    let provider = frozen.provider(ID).unwrap();
    assert_eq!(provider.configuration["denominatorCount"], 1);
    assert_eq!(
        provider.configuration["semgrepContract"],
        semgrep::contract()
    );
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let tool = PathBuf::from(enrolled["launcher"]["path"].as_str().unwrap());
    if !missing {
        let resolved = resolve_request(&root, "semgrep", &[]).unwrap();
        assert_eq!(resolved.executable, tool);
        assert_eq!(
            resolved.digest,
            enrolled["launcher"]["digest"].as_str().unwrap()
        );
    }
    let rules = run.join("reports").join(format!(
        "semgrep-{}.yml",
        semgrep::rules_digest().trim_start_matches("sha256:")
    ));
    let mut args: Vec<String> = match legion_audit::native_providers::legacy_checks::spec(ID)
        .unwrap()
        .command
    {
        legion_audit::native_providers::legacy_checks::CommandShape::Named { args, .. } => {
            args.iter().map(|x| (*x).into()).collect()
        }
        _ => panic!("named contract required"),
    };
    for arg in &mut args {
        if arg == "@legion-packaged-core" {
            *arg = rules.to_string_lossy().into_owned();
        }
    }
    args.extend(["--".into(), "./app.py".into()]);
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let escaped = root
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile_text=format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath \"{escaped}\"))\n");
    let profile = scratch.sandbox_dir().join(format!(
        "audit-{}.sb",
        digest(profile_text.as_bytes()).trim_start_matches("sha256:")
    ));
    let (environment, allowlist) = expected_environment(&run);
    let policy = Arc::new(ScopedPolicy {
        id: ID.into(),
        check: "sast".into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: enrolled["launcher"]["digest"].as_str().unwrap().into(),
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        profile,
        profile_text,
        args,
        environment,
        allowlist,
        decisions: Mutex::new(vec![]),
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
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &native,
            tokio_util::sync::CancellationToken::new(),
        ))
        .unwrap();
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0].result;
    let receipt = &result.details["executionReceipt"];
    let failed = missing || name == "operational-error";
    assert_eq!(result.complete, !failed, "{:?}", result.coverage_gaps);
    assert!(result.findings.is_empty());
    assert_eq!(result.coverage.as_ref().unwrap().expected, 1);
    assert_eq!(
        result.coverage.as_ref().unwrap().denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    let mut raw = Value::Null;
    let mut stdout = vec![];
    let mut stderr = vec![];
    let mut labels = vec![];
    if missing {
        assert_eq!(receipt["processTree"]["started"], false);
        assert_eq!(receipt["state"], "missing_executable");
        assert!(!result.coverage_gaps.is_empty());
        assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
        assert!(policy.decisions.lock().unwrap().is_empty());
    } else {
        assert_eq!(
            receipt["command"]["args"],
            json!(policy.wrapped_args(&policy.args))
        );
        assert_eq!(receipt["sandbox"]["receiptId"], policy.sandbox_id());
        assert_eq!(receipt["processTree"]["started"], true);
        assert_eq!(receipt["processTree"]["terminated"], true);
        assert_eq!(receipt["processTree"]["reaped"], true);
        assert_eq!(receipt["executable"]["version"]["qualified"], true);
        assert!(receipt["executable"]["version"]["output"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .any(|v| v == "1.141.0"));
        assert_eq!(policy.decisions.lock().unwrap().len(), 1);
        stdout = artifact(receipt, "stdout", &scratch);
        stderr = artifact(receipt, "stderr", &scratch);
        raw = serde_json::from_slice(&stdout).expect("actual Semgrep JSON");
        if failed {
            assert_ne!(receipt["exitCode"], 0);
            assert!(!raw["errors"].as_array().unwrap().is_empty());
            assert!(!result.coverage_gaps.is_empty());
            assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
        } else {
            assert_eq!(receipt["exitCode"], 0);
            assert_eq!(raw["errors"], json!([]));
            assert_eq!(raw["paths"]["skipped"], json!([]));
            assert_eq!(result.coverage.as_ref().unwrap().examined, 1);
            labels = raw["results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    format!(
                        "{}|{}|{}",
                        r["check_id"].as_str().unwrap(),
                        r["path"].as_str().unwrap().trim_start_matches("./"),
                        r["start"]["line"].as_u64().unwrap()
                    )
                })
                .collect();
            let expected = expected_rule
                .map(|r| vec![format!("{r}|app.py|3")])
                .unwrap_or_default();
            assert_eq!(labels, expected);
            assert_eq!(result.details["findingsCount"], expected.len());
            let candidates = result.details["candidates"].as_array().unwrap();
            assert_eq!(candidates.len(), expected.len());
            for candidate in candidates {
                assert_eq!(candidate["ruleId"], expected_rule.unwrap());
                assert_eq!(candidate["evidence"], json!([{"file":"app.py","line":3}]));
                assert_eq!(candidate["verdict"], "UNADJUDICATED");
                assert_eq!(candidate["adjudicationRequired"], true);
            }
        }
    }
    assert_eq!(fs::read(&rules).unwrap(), semgrep::RULES.as_bytes());
    assert_eq!(fs::read(root.join("app.py")).unwrap(), source.as_bytes());
    verify_enrollment(enrolled);
    json!({"caseId":name,"source":{"path":"app.py","bytes":source,"digest":digest(source.as_bytes())},"inventory":inventory,"frozenPlan":frozen.plan(),"planDigest":frozen.digest(),"planSignature":frozen.signature(),"providerConfiguration":provider.configuration,"policy":policy.definition(),"policyDecisions":*policy.decisions.lock().unwrap(),"executionReceipt":receipt,"actualStdout":String::from_utf8(stdout).unwrap(),"actualStderr":String::from_utf8(stderr).unwrap(),"actualRawReport":raw,"actualLabels":labels,"expectedRule":expected_rule,"actualProviderResult":result,"rules":{"path":rules,"digest":semgrep::rules_digest()},"runtimeEnrollment":enrolled,"runtimeVerifiedBefore":true,"runtimeVerifiedAfter":true})
}

#[test]
#[ignore = "requires hash-enrolled Semgrep1.141.0 Python runtime & native macOS sandbox"]
fn real_semgrep_accuracy() {
    let enrolled = enrollment();
    if let Some(base) = std::env::var_os("LEGION_SEMGREP_CHILD") {
        let base = PathBuf::from(base);
        let missing = std::env::var_os("LEGION_SEMGREP_MISSING").is_some();
        let cases = if missing {
            vec![run_case(
                &base,
                "missing-tool",
                "print('fixed')\n",
                None,
                true,
                &enrolled,
            )]
        } else {
            fixtures()
                .into_iter()
                .map(|(name, source, rule)| run_case(&base, name, source, rule, false, &enrolled))
                .collect::<Vec<_>>()
        };
        fs::write(
            base.join(if missing {
                "missing.json"
            } else {
                "cases.json"
            }),
            serde_json::to_vec(&cases).unwrap(),
        )
        .unwrap();
        return;
    }
    let fixture = Fixture::new();
    let log_dir = PathBuf::from(
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR")
            .expect("retained child-log directory required"),
    );
    assert!(log_dir.is_absolute());
    fs::create_dir_all(&log_dir).unwrap();
    let mut child_logs = Vec::new();
    for missing in [false, true] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "real_semgrep_accuracy",
                "--ignored",
                "--nocapture",
            ])
            .current_dir(&fixture.0)
            .env_clear()
            .env(
                "PATH",
                if missing {
                    std::ffi::OsString::new()
                } else {
                    std::env::var_os("PATH").unwrap()
                },
            )
            .env("HOME", fixture.0.join("home"))
            .env("TMPDIR", fixture.0.join("tmp"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONNOUSERSITE", "1")
            .env("LEGION_SEMGREP_CHILD", &fixture.0)
            .env(
                "LEGION_PYTHON_TOOL_ENROLLMENT",
                std::env::var_os("LEGION_PYTHON_TOOL_ENROLLMENT").unwrap(),
            );
        if missing {
            child.env("LEGION_SEMGREP_MISSING", "1");
        }
        let output = child.output().unwrap();
        let control = if missing { "missing-tool" } else { "controls" };
        let mut streams = serde_json::Map::new();
        for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            let name = format!("child-{control}.{stream}.log");
            fs::write(log_dir.join(&name), bytes).unwrap();
            assert_eq!(fs::read(log_dir.join(&name)).unwrap(), *bytes);
            streams.insert(
                stream.into(),
                json!({"path":name,"digest":digest(bytes),"bytes":bytes.len()}),
            );
        }
        let logs = json!({"control":control,"exitCode":output.status.code(),"streams":streams});
        println!(
            "SEMGREP_CHILD_LOG_ARTIFACTS {}",
            serde_json::to_string(&logs).unwrap()
        );
        child_logs.push(logs);
        assert!(
            output.status.success(),
            "child {control} failed; raw logs retained in {}",
            log_dir.display()
        );
    }
    let mut cases: Vec<Value> =
        serde_json::from_slice(&fs::read(fixture.0.join("cases.json")).unwrap()).unwrap();
    cases.extend(
        serde_json::from_slice::<Vec<Value>>(&fs::read(fixture.0.join("missing.json")).unwrap())
            .unwrap(),
    );
    let fixture_sources = cases
        .iter()
        .map(|case| {
            (
                format!("{}/app.py", case["caseId"].as_str().unwrap()),
                case["source"]["digest"].as_str().unwrap().into(),
            )
        })
        .collect();
    let mut record = json!({"schema":"legion-semgrep-provider-accuracy/1","provider":ID,"stage":"candidate","scope":SCOPE,"productionQualification":false,"qualificationEligible":true,"modelCalls":0,"status":"pass","binding":binding(ID,&fixture_sources),"contract":semgrep::contract(),"childLogs":child_logs,"cases":cases,"metrics":{"cases":6,"matched":6,"mismatched":0}});
    record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
    fs::write(
        log_dir.join("legacy_security_sast.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    println!(
        "SEMGREP_PROVIDER_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
}
