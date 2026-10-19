//! Constructed online pip-audit controls through native SDK; real output only.
//! No production admission, transitive dependency or immutable advisory DB claim.
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

const SOURCE: &str = "engine/crates/legion-audit/tests/pip_audit_accuracy.rs";
const POLICY: &str = "legion-pip-audit-sdk-qualification-v1";
const PROVIDER: &str = "legacy.security.python-dependencies";
const FIXTURES: &str = "engine/crates/legion-audit/tests/fixtures/pip-audit";
const WHEEL: &str = "sha256:16e02093872fac97580303f0848fa3ad64f7ecf600736ea7835a2b24de49613f";

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
        let base = std::env::var_os("LEGION_PIP_AUDIT_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-pip-audit-{}-{}",
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

fn generated_session_provenance(relative: &str) -> bool {
    relative
        .strip_prefix("engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/")
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
    assert!(generated_session_provenance(&format!(
        "{prefix}{}.json",
        "0123456789abcdef".repeat(4)
    )));
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
            !generated_session_provenance(&relative),
            "unexpected exclusion: {relative}"
        );
    }
}

fn binding(id: &str, fixtures: &BTreeMap<String, String>) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink(), "source binding refuses symlinks");
        if path.is_file()
            && generated_session_provenance(
                &path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            )
        {
            return;
        }
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
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
        FIXTURES,
        "scripts/ci/audit-pip-audit-provider-accuracy.py",
        "scripts/ci/provision-python-qualification-tools.py",
        "scripts/ci/python-tool-locks",
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
            "sandbox": "native-macos-allow-network-deny-project-write-pip-audit",
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
                    "exact pip-audit online fixture admission"
                } else {
                    "outside exact pip-audit fixture policy"
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

fn runtime_snapshot(enrollment: &Value) -> Value {
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
    let runtime = &enrollment["runtime"];
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
    let stdlib = Path::new(enrollment["interpreter"]["stdlibRoot"].as_str().unwrap());
    assert_eq!(excluded, vec![stdlib.join("site-packages")]);
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

fn enrollment() -> Value {
    let path = PathBuf::from(
        std::env::var_os("LEGION_PYTHON_TOOL_ENROLLMENT").expect("CI tool enrollment required"),
    );
    assert!(path.is_absolute() && !path.is_symlink());
    let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(value["schema"], "legion-python-tool-enrollment/1");
    assert_eq!(value["tool"]["name"], "pip-audit");
    assert_eq!(value["tool"]["version"], "2.10.0");
    assert_eq!(value["tool"]["wheelSha256"], WHEEL);
    for key in ["launcher", "interpreter"] {
        let path = Path::new(value[key]["path"].as_str().unwrap());
        assert!(path.is_absolute());
        assert_eq!(digest(&fs::read(path).unwrap()), value[key]["digest"]);
    }
    assert_eq!(runtime_snapshot(&value), value["runtime"]);
    value
}

fn case(base: &Path, control: &str) -> Value {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let expectations: Value =
        serde_json::from_slice(&fs::read(repository.join(FIXTURES).join("expected.json")).unwrap())
            .unwrap();
    let expected = &expectations[if control == "missing-tool" {
        "absence"
    } else {
        control
    }];
    let source = format!(
        "{}=={}\n",
        expected["name"].as_str().unwrap(),
        expected["version"].as_str().unwrap()
    );
    let root = base.join("source");
    let run = base.join("run");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("requirements.txt"), &source).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(control)
        .unwrap();
    assert_eq!(inventory.entries.len(), 1);
    let spec: ProviderSpec = serde_json::from_value(registry_spec(PROVIDER)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"pip-audit-exact-listed-pins-fixture"))
        .unwrap();
    let provider = frozen.provider(PROVIDER).unwrap();
    assert_eq!(provider.configuration["denominatorCount"], 1);
    let enrollment = enrollment();
    let before = runtime_snapshot(&enrollment);
    let tool = PathBuf::from(enrollment["launcher"]["path"].as_str().unwrap());
    assert!(
        !tool.starts_with(base),
        "tool environment must be outside audited fixture"
    );
    if control == "missing-tool" {
        assert!(resolve_request(&root, "pip-audit", &[]).is_err());
    } else {
        let resolved = resolve_request(&root, "pip-audit", &[]).unwrap();
        assert_eq!(resolved.executable, fs::canonicalize(&tool).unwrap());
        assert_eq!(resolved.digest, enrollment["launcher"]["digest"]);
    }
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let snapshot = run
        .join("reports")
        .join(format!("pip-audit-{}-0", std::process::id()))
        .join("requirements-0.txt");
    let mut args: Vec<String> = ["--format", "json", "--disable-pip", "--no-deps", "--strict"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    args.extend(["-r".into(), snapshot.to_string_lossy().into_owned()]);
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let escaped = root
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile_text = format!("(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
    let profile = scratch.sandbox_dir().join(format!(
        "audit-{}.sb",
        digest(profile_text.as_bytes()).trim_start_matches("sha256:")
    ));
    let (environment, allowlist) = expected_environment(&run);
    let policy = Arc::new(ScopedPolicy {
        id: PROVIDER.into(),
        check: "py_deps_cve".into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: enrollment["launcher"]["digest"].as_str().unwrap().into(),
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
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
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &native,
            tokio_util::sync::CancellationToken::new(),
        ))
        .unwrap();
    assert_eq!(report.planned_providers, vec![PROVIDER]);
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0].result;
    assert!(result.applicable);
    assert!(result.findings.is_empty());
    let receipt = &result.details["executionReceipt"];
    let decisions = policy.decisions.lock().unwrap();
    let (stdout, stderr) = if control == "missing-tool" {
        assert!(!result.complete);
        assert!(decisions.is_empty());
        assert_eq!(receipt["processTree"]["started"], false);
        assert!(receipt["stdout"].is_null() && receipt["stderr"].is_null());
        (Vec::new(), Vec::new())
    } else {
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["allowed"], true);
        assert_eq!(receipt["state"], "completed");
        assert_eq!(receipt["complete"], true);
        assert_eq!(
            receipt["policy"]["digest"],
            digest(&canonical_bytes(&policy.definition()))
        );
        assert_eq!(
            receipt["command"]["args"],
            json!(policy.wrapped_args(&policy.args))
        );
        assert_eq!(receipt["executable"]["version"]["exitCode"], 0);
        assert_eq!(receipt["executable"]["version"]["qualified"], true);
        let version = receipt["executable"]["version"]["output"].as_str().unwrap();
        assert_eq!(version.trim(), "pip-audit 2.10.0");
        assert_eq!(receipt["sandbox"]["receiptId"], policy.sandbox_id());
        for key in ["started", "terminated", "reaped"] {
            assert_eq!(receipt["processTree"][key], true);
        }
        assert!(receipt["signal"].is_null());
        assert_eq!(receipt["gaps"], json!([]));
        assert_eq!(
            receipt["exitCode"],
            if control == "absence" { 0 } else { 1 }
        );
        (
            artifact(receipt, "stdout", &scratch),
            artifact(receipt, "stderr", &scratch),
        )
    };
    let positive = control == "positive";
    let successful = positive || control == "absence";
    let mut ids: Vec<String> = Vec::new();
    if successful {
        assert!(result.complete, "{:?}", result.coverage_gaps);
        assert!(result.coverage_gaps.is_empty());
        let raw: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(raw["dependencies"].as_array().unwrap().len(), 1);
        assert_eq!(raw["fixes"], json!([]));
        let dependency = &raw["dependencies"][0];
        assert_eq!(dependency["name"], expected["name"]);
        assert_eq!(dependency["version"], expected["version"]);
        assert!(dependency.get("skip_reason").is_none());
        ids = dependency["vulns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        assert_eq!(
            json!(ids),
            expected["vulnerabilityIds"],
            "online source changed; never qualify a count mismatch"
        );
        assert_eq!(result.details["findingsCount"], ids.len());
    } else {
        assert!(!result.complete);
        assert!(!result.coverage_gaps.is_empty());
        assert!(result.details["findingsCount"].is_null());
        if control == "error" {
            assert!(!stderr.is_empty());
            assert!(serde_json::from_slice::<Value>(&stdout).is_err());
        }
    }
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.expected, 1);
    assert_eq!(coverage.examined, u64::from(successful));
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    let candidates = result
        .details
        .get("candidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(candidates.len(), usize::from(positive));
    if positive {
        let candidate = &candidates[0];
        let rule = "legacy.py_deps_cve.pip-audit";
        assert_eq!(
            candidate["id"],
            digest(format!("{rule}\0requirements.txt\0{}", 1).as_bytes())
        );
        assert_eq!(candidate["ruleId"], rule);
        assert_eq!(
            candidate["claim"],
            format!("py_deps_cve reported {} finding(s)", ids.len())
        );
        assert_eq!(candidate["verdict"], "UNADJUDICATED");
        assert_eq!(candidate["adjudicationRequired"], true);
    }
    assert_eq!(
        fs::read(root.join("requirements.txt")).unwrap(),
        source.as_bytes()
    );
    assert_eq!(fs::read(&snapshot).unwrap(), source.as_bytes());
    let after = runtime_snapshot(&enrollment);
    assert_eq!(before, after);
    assert_eq!(before, enrollment["runtime"]);
    json!({"control":control,"fixtureRoot":root,"scratchRoot":run,"fixtureFiles":{"requirements.txt":source},
        "fixtureSources":{"requirements.txt":digest(source.as_bytes())},"inventoryDigest":inventory.digest,
        "planDigest":frozen.digest(),"inventory":inventory,"selector":provider.configuration["selector"],"coverage":{"expected":coverage.expected,"examined":coverage.examined,
            "denominatorDigest":coverage.denominator_digest,"gaps":coverage.gaps},
        "complete":result.complete,"coverageGaps":result.coverage_gaps,"nativeDetails":result.details,"nativeFindings":result.findings,
        "actualVulnerabilityIds":ids,"actualStdout":String::from_utf8(stdout).unwrap(),"actualStderr":String::from_utf8(stderr).unwrap(),
        "executionReceipt":receipt,"policyDefinition":policy.definition(),"policyDecisions":*decisions,
        "toolEnrollment":enrollment,"runtimeBefore":before,"runtimeAfter":after})
}

#[test]
#[ignore = "explicit online pip-audit qualification; requires enrolled 2.10.0 & native macOS sandbox"]
fn real_pip_audit_accuracy() {
    if let Some(base) = std::env::var_os("LEGION_PIP_AUDIT_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let control = std::env::var("LEGION_PIP_AUDIT_CONTROL").unwrap();
        println!(
            "PIP_AUDIT_CASE {}",
            serde_json::to_string(&case(&base, &control)).unwrap()
        );
        return;
    }
    let mut cases = Vec::new();
    let mut fixture_sources = BTreeMap::new();
    let mut runtime_closures = BTreeMap::new();
    for control in ["positive", "absence", "error", "missing-tool"] {
        let fixture = Fixture::new();
        let empty_path = fixture.0.join("empty-path");
        fs::create_dir(&empty_path).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "real_pip_audit_accuracy",
                "--ignored",
                "--nocapture",
            ])
            .current_dir(&fixture.0)
            .env_clear()
            .env(
                "PATH",
                if control == "missing-tool" {
                    empty_path.into_os_string()
                } else {
                    std::env::var_os("PATH").unwrap()
                },
            )
            .env("HOME", fixture.0.join("home"))
            .env("TMPDIR", fixture.0.join("tmp"))
            .env("LEGION_PIP_AUDIT_CHILD", &fixture.0)
            .env("LEGION_PIP_AUDIT_CONTROL", control)
            .env(
                "LEGION_PYTHON_TOOL_ENROLLMENT",
                std::env::var_os("LEGION_PYTHON_TOOL_ENROLLMENT").unwrap(),
            );
        let output = child.output().unwrap();
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "{control}: native pip-audit case failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let rows: Vec<_> = stdout
            .lines()
            .filter_map(|line| line.strip_prefix("PIP_AUDIT_CASE "))
            .collect();
        assert_eq!(rows.len(), 1);
        let mut row: Value = serde_json::from_str(rows[0]).unwrap();
        for field in ["runtimeBefore", "runtimeAfter"] {
            let closure = row[field].clone();
            let key = closure["digest"].as_str().unwrap().to_owned();
            runtime_closures.insert(key.clone(), closure);
            row[field] = json!(key);
        }
        let closure = row["toolEnrollment"]["runtime"].clone();
        let key = closure["digest"].as_str().unwrap().to_owned();
        runtime_closures.insert(key.clone(), closure);
        row["toolEnrollment"]
            .as_object_mut()
            .unwrap()
            .remove("runtime");
        row["toolEnrollment"]["runtimeDigest"] = json!(key);
        fixture_sources.insert(
            format!("{control}/requirements.txt"),
            row["fixtureSources"]["requirements.txt"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        cases.push(row);
    }
    let mut record = json!({"schema":"legion-pip-audit-sdk-accuracy/1","provider":PROVIDER,
        "providerVersion":registry_spec(PROVIDER)["providerVersion"],"stage":"candidate","status":"pass","modelCalls":0,
        "coverageState":"complete","qualificationEligible":true,"productionQualification":false,"selfProducerQualification":false,
        "executionPath":"native-sdk-frozen-plan-real-pip-audit-online","scope":"exact-listed-online-pins-fixture-controls",
        "advisoryDatabase":"mutable online PyPI responses; no immutable database identity claim",
        "binding":binding(PROVIDER,&fixture_sources),"runtimeClosures":runtime_closures,"cases":cases,"metrics":{"cases":4,"matched":4,"mismatched":0}});
    record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
    if let Some(dir) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        assert!(Path::new(&dir).is_absolute());
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            PathBuf::from(dir).join("legacy_security_python-dependencies.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
    }
    println!(
        "PIP_AUDIT_SDK_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
}
