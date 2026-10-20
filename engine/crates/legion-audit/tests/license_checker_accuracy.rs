//! Constructed native license-checker controls; genuine published script, Node & SDK receipts.
//! Does not qualify host production admission or semantic security findings.
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

const SOURCE: &str = "engine/crates/legion-audit/tests/license_checker_accuracy.rs";
const POLICY: &str = "legion-license-checker-fixture-policy-v1";
const ID: &str = "legacy.security.js-licenses";
const RULE: &str = "legacy.js_licenses.license-checker";
const SCOPE: &str = "constructed native SDK license-checker controls; two actual installed package licenses, summary candidate only";
const MANIFEST: &str =
    "engine/crates/legion-audit/tests/fixtures/license-checker/official-tool-files.json";
const NODE_PINS: &[&str] = &[
    "sha256:18e387c90ab8a8400183e8bdd396376e1e875b91b4c874b894dcade7b35bf572",
    "sha256:0b4f059915f3bf3c6cbb02422f4a529bfb21cbbec2d29851c9a5d833f78a04f6",
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
    let receipt = format!("{prefix}{}.json", "f".repeat(64));
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
        "f".repeat(64)
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
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
        MANIFEST,
        ".rightgit.json",
        "package.json",
        "pnpm-lock.yaml",
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
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
    identity: Value,
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
            "runtimeIdentityDigest": digest(&canonical_bytes(&self.identity)),
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest},
            "profile": {"path": self.profile, "text": self.profile_text,
                "digest": digest(self.profile_text.as_bytes()), "receiptId": self.sandbox_id()},
            "args": self.args,
            "wrappedArgs": self.wrapped_args(&self.args),
            "versionArgs": self.wrapped_args(&["--help".into()]),
            "environment": self.environment,
            "environmentAllowlist": self.allowlist,
            "timeoutMs": 120000,
            "stdoutLimit": 8388608,
            "stderrLimit": 8388608,
            "sandbox": "native-macos-deny-network-shipped-js-licenses-contract",
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
            && runtime_identity() == self.identity
            && !self.profile.is_symlink()
            && fs::read(&self.profile)
                .is_ok_and(|bytes| bytes.as_slice() == self.profile_text.as_bytes())
            && req.args == self.wrapped_args(&self.args)
            && req.version_args == self.wrapped_args(&["--help".into()])
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
                    "exact license-checker fixture admission"
                } else {
                    "outside exact license-checker fixture policy"
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

// This is published JS, so identity includes script, every provisioned dependency
// byte/symlink & exact official Node binary. An interpreter digest alone is insufficient.
fn closure(root: &Path) -> BTreeMap<String, Value> {
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, Value>) {
        let meta = fs::symlink_metadata(path).unwrap();
        let name = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if meta.file_type().is_symlink() {
            let target = fs::canonicalize(path).unwrap();
            assert!(
                target.starts_with(root),
                "runtime symlink escapes provisioned closure"
            );
            files.insert(
                name,
                json!({"symlink":fs::read_link(path).unwrap(),
                "canonicalTarget":target.strip_prefix(root).unwrap()}),
            );
        } else if meta.is_dir() {
            for item in fs::read_dir(path).unwrap() {
                walk(root, &item.unwrap().path(), files);
            }
        } else {
            assert!(meta.is_file(), "nonregular runtime asset");
            files.insert(
                name,
                json!({"digest":digest(&fs::read(path).unwrap()),"bytes":meta.len()}),
            );
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

fn runtime_identity() -> Value {
    let provision =
        fs::canonicalize(std::env::var_os("LEGION_LICENSE_TOOL_ROOT").unwrap()).unwrap();
    let tool = fs::canonicalize(provision.join("bin/license-checker")).unwrap();
    assert!(tool.starts_with(&provision));
    assert_eq!(tool.file_name().unwrap(), "license-checker");
    assert_eq!(
        fs::read(&tool)
            .unwrap()
            .split(|c| *c == b'\n')
            .next()
            .unwrap(),
        b"#!/usr/bin/env node"
    );
    let package = tool.parent().unwrap().parent().unwrap();
    let manifest: Value = serde_json::from_str(include_str!(
        "fixtures/license-checker/official-tool-files.json"
    ))
    .unwrap();
    assert_eq!(manifest["version"], "25.0.1");
    for (name, hash) in manifest["files"].as_object().unwrap() {
        let path = package.join(name);
        assert!(!path.is_symlink());
        assert_eq!(
            digest(&fs::read(path).unwrap()),
            hash.as_str().unwrap(),
            "published tool bytes differ: {name}"
        );
    }
    let node =
        fs::canonicalize(resolve_request(&provision, "node", &[]).unwrap().executable).unwrap();
    let node_digest = digest(&fs::read(&node).unwrap());
    assert!(
        NODE_PINS.contains(&node_digest.as_str()),
        "shared Node must match official 22.23.2 binary"
    );
    let files = closure(&provision);
    json!({"toolRoot":provision,"toolPath":tool,"publishedPackageRoot":package,
        "publishedManifest":manifest,"node":{"path":node,"digest":node_digest,"version":"22.23.2"},
        "files":files,"filesDigest":digest(&canonical_bytes(&json!(files)))})
}

fn fixture(mode: &str) -> BTreeMap<String, String> {
    if mode == "malformed-manifest" {
        return [("package.json".into(), "{\n".into())]
            .into_iter()
            .collect();
    }
    let license = if mode == "copyleft-positive" {
        "GPL-3.0-only"
    } else {
        "MIT"
    };
    [
        ("package.json".into(), "{\"name\":\"legion-license-fixture\",\"version\":\"1.0.0\",\"license\":\"MIT\",\"dependencies\":{\"fixture-dependency\":\"1.0.0\"}}\n".into()),
        ("node_modules/fixture-dependency/package.json".into(), format!("{{\"name\":\"fixture-dependency\",\"version\":\"1.0.0\",\"license\":\"{license}\"}}\n")),
    ].into_iter().collect()
}

fn execute_case(base: &Path, mode: &str) -> Value {
    let root = base.join(mode).join("source");
    let run = base.join(mode).join("run");
    let files = fixture(mode);
    for (path, bytes) in &files {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let hashes: BTreeMap<String, String> = files
        .iter()
        .map(|(p, b)| (p.clone(), digest(b.as_bytes())))
        .collect();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(mode)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(ID)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"license-checker-constructed-fixture-key"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    assert_eq!(provider.configuration["denominatorCount"], 1);
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let missing = mode == "missing-tool";
    let args = vec!["--json".into(), "--production".into()];
    let identity = if missing {
        Value::Null
    } else {
        runtime_identity()
    };
    let tool = if missing {
        base.join("absent-license-checker")
    } else {
        let resolved = resolve_request(&root, "license-checker", &args).unwrap();
        let tool = fs::canonicalize(resolved.executable).unwrap();
        assert_eq!(json!(tool), identity["toolPath"]);
        tool
    };
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let escaped = root
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile_text = format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath \"{escaped}\"))\n");
    let profile = scratch.sandbox_dir().join(format!(
        "audit-{}.sb",
        digest(profile_text.as_bytes()).trim_start_matches("sha256:")
    ));
    let (environment, allowlist) = expected_environment(&run);
    let policy = Arc::new(ScopedPolicy {
        id: ID.into(),
        check: "js_licenses".into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: if missing {
            String::new()
        } else {
            digest(&fs::read(&tool).unwrap())
        },
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        profile,
        profile_text,
        args,
        environment,
        allowlist,
        identity: identity.clone(),
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
    assert_eq!(report.planned_providers, vec![ID]);
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0].result;
    let receipt = &result.details["executionReceipt"];
    // Retain real output before assertions so a mismatch remains diagnosable.
    let stdout = if missing {
        Vec::new()
    } else {
        artifact(receipt, "stdout", &scratch)
    };
    let stderr = if missing {
        Vec::new()
    } else {
        artifact(receipt, "stderr", &scratch)
    };
    let decisions = policy.decisions.lock().unwrap();
    let mut row = json!({"caseId":mode,"stage":"candidate","fixtureFiles":files,"fixtureSources":hashes,
        "inventory":inventory,"frozenPlan":frozen.plan(),"planSignature":frozen.signature(),"planDigest":frozen.digest(),
        "providerConfiguration":provider.configuration,"runtimeIdentityDigest":if missing {Value::Null} else {json!(digest(&canonical_bytes(&identity)))},
        "nativeResult":result,"executionReceipt":receipt,"policyDefinition":if missing {Value::Null} else {policy.definition()},
        "policyDecisions":*decisions,"actualStdout":String::from_utf8(stdout.clone()).unwrap(),
        "actualStderr":String::from_utf8(stderr.clone()).unwrap(),"productionQualification":false});
    fs::write(
        base.join(format!("{mode}.diagnostic.json")),
        serde_json::to_vec_pretty(&row).unwrap(),
    )
    .unwrap();
    assert!(result.applicable);
    assert!(
        result.findings.is_empty(),
        "candidate generator must not adjudicate"
    );
    assert_eq!(receipt["providerId"], ID);
    assert_eq!(receipt["planId"], frozen.digest());
    let candidates = result
        .details
        .get("candidates")
        .cloned()
        .unwrap_or_else(|| json!([]));
    if missing {
        assert!(!result.complete);
        assert!(result.coverage_gaps.is_empty());
        assert!(result.degradation.is_empty());
        assert_eq!(
            result.details["capabilityAbsence"],
            json!({"tool":"license-checker","note":"capability-absent:license-checker","blocking":false,"substitute":null})
        );
        assert_eq!(receipt["state"], "missing_executable");
        assert_eq!(receipt["complete"], false);
        assert_eq!(
            receipt["gaps"],
            json!(["missing executable: license-checker"])
        );
        assert_eq!(receipt["processTree"]["started"], false);
        assert!(decisions.is_empty());
        assert_eq!(candidates, json!([]));
    } else {
        assert_eq!(
            runtime_identity(),
            identity,
            "runtime closure changed during execution"
        );
        assert_eq!(receipt["state"], "completed");
        assert_eq!(receipt["complete"], true);
        assert_eq!(receipt["exitCode"], 0);
        assert!(receipt["signal"].is_null());
        assert_eq!(receipt["policyId"], POLICY);
        assert_eq!(receipt["policy"]["allowed"], true);
        assert_eq!(
            receipt["policy"]["digest"],
            digest(&canonical_bytes(&policy.definition()))
        );
        assert_eq!(
            receipt["executable"]["canonicalPath"],
            json!(policy.wrapper)
        );
        assert_eq!(receipt["executable"]["digest"], policy.wrapper_digest);
        assert_eq!(
            receipt["executable"]["version"]["args"],
            json!(policy.wrapped_args(&["--help".into()]))
        );
        assert_eq!(receipt["executable"]["version"]["exitCode"], 0);
        assert_eq!(receipt["executable"]["version"]["qualified"], true);
        assert!(receipt["executable"]["version"]["output"]
            .as_str()
            .unwrap()
            .lines()
            .any(|line| line.trim() == "license-checker@25.0.1"));
        assert_eq!(
            receipt["command"]["args"],
            json!(policy.wrapped_args(&policy.args))
        );
        assert_eq!(receipt["sandbox"]["required"], true);
        assert_eq!(receipt["sandbox"]["networkEnabled"], true); // Existing SDK name means network confinement active.
        assert_eq!(receipt["sandbox"]["receiptId"], policy.sandbox_id());
        for key in ["started", "terminated", "reaped"] {
            assert_eq!(receipt["processTree"][key], true);
        }
        assert_eq!(receipt["gaps"], json!([]));
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["allowed"], true);
        assert_eq!(decisions[0]["requestId"], receipt["requestId"]);
        let raw: Value = serde_json::from_slice(&stdout).unwrap();
        if mode == "malformed-manifest" {
            // Official CLI reports a read failure on stderr but still exits zero.
            assert_eq!(raw, json!({}));
            assert!(String::from_utf8_lossy(&stderr)
                .lines()
                .any(|line| line.trim() == "Found error"));
            assert!(!result.complete);
            assert!(result
                .coverage_gaps
                .iter()
                .any(|gap| gap == "legacy-tool-reported-error:js_licenses"));
            assert!(result.details["findingsCount"].is_null());
            assert_eq!(candidates, json!([]));
        } else {
            assert!(
                result.complete && result.coverage_gaps.is_empty() && result.degradation.is_empty()
            );
            let coverage = result.coverage.as_ref().unwrap();
            assert_eq!((coverage.expected, coverage.examined), (1, 1));
            assert!(coverage.gaps.is_empty());
            assert_eq!(
                json!(coverage.denominator_digest),
                provider.configuration["denominatorDigest"]
            );
            let positive = mode == "copyleft-positive";
            let expected_count = u64::from(positive);
            let object = raw.as_object().unwrap();
            assert_eq!(object.len(), 2, "actual installed package coverage");
            assert_eq!(raw["legion-license-fixture@1.0.0"]["licenses"], "MIT");
            assert_eq!(
                raw["fixture-dependency@1.0.0"]["licenses"],
                if positive { "GPL-3.0-only" } else { "MIT" }
            );
            assert_eq!(raw["legion-license-fixture@1.0.0"]["path"], json!(root));
            assert_eq!(
                raw["fixture-dependency@1.0.0"]["path"],
                json!(root.join("node_modules/fixture-dependency"))
            );
            assert!(stderr.is_empty(), "unexpected scan diagnostics");
            assert_eq!(result.details["totalDeps"], 2);
            assert_eq!(result.details["copyleft"], expected_count);
            assert_eq!(result.details["findingsCount"], expected_count);
            let expected = if positive {
                json!([{"id":digest(format!("{RULE}\0package.json\0{}",1).as_bytes()),
                "ruleId":RULE,"role":"candidate-generator","claim":"js_licenses reported 1 finding(s)","severityHint":"high",
                "evidence":[{"file":"package.json","line":1}],"evidenceStrength":"candidate","verdict":"UNADJUDICATED","adjudicationRequired":true}])
            } else {
                json!([])
            };
            assert_eq!(candidates, expected);
            row["expectedCandidates"] = expected;
            row["actualCandidates"] = candidates;
            row["actualPackageCount"] = json!(object.len());
        }
    }
    for (path, bytes) in &files {
        assert_eq!(fs::read(root.join(path)).unwrap(), bytes.as_bytes());
    }
    row["controlMatched"] = json!(true);
    row
}

#[test]
#[ignore = "requires published license-checker 25.0.1, official Node 22.23.2 & native macOS sandbox"]
fn real_license_checker_accuracy() {
    let base = PathBuf::from(std::env::var_os("LEGION_LICENSE_RECEIPTS").unwrap());
    assert!(base.is_absolute());
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    assert_eq!(base.file_name().unwrap(), "license-checker");
    assert_eq!(
        base.parent().unwrap().file_name().unwrap(),
        "legion-provider-qualification"
    );
    if let Ok(mode) = std::env::var("LEGION_LICENSE_CHILD_MODE") {
        assert!(mode == "controls" || mode == "missing-tool");
        let rows: Vec<Value> = if mode == "controls" {
            ["copyleft-positive", "mit-absence", "malformed-manifest"]
                .into_iter()
                .map(|id| execute_case(&base, id))
                .collect()
        } else {
            vec![execute_case(&base, "missing-tool")]
        };
        fs::write(
            base.join(format!("{mode}.json")),
            serde_json::to_vec_pretty(&rows).unwrap(),
        )
        .unwrap();
        return;
    }
    let identity = runtime_identity();
    fs::create_dir_all(base.join("home")).unwrap();
    fs::create_dir_all(base.join("empty-bin")).unwrap();
    let mut child_outputs = Vec::new();
    for mode in ["controls", "missing-tool"] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "real_license_checker_accuracy",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(&base)
            .env_clear()
            .env("HOME", base.join("home"))
            .env("LEGION_LICENSE_RECEIPTS", &base)
            .env("LEGION_LICENSE_CHILD_MODE", mode);
        if mode == "controls" {
            child.env("PATH", std::env::var_os("PATH").unwrap()).env(
                "LEGION_LICENSE_TOOL_ROOT",
                std::env::var_os("LEGION_LICENSE_TOOL_ROOT").unwrap(),
            );
        } else {
            child.env("PATH", base.join("empty-bin"));
        }
        let output = child.output().unwrap();
        let retained = json!({"mode":mode,"exitCode":output.status.code(),
            "stdout":String::from_utf8(output.stdout.clone()).unwrap(),"stderr":String::from_utf8(output.stderr.clone()).unwrap()});
        fs::write(
            base.join(format!("{mode}.child.json")),
            serde_json::to_vec_pretty(&retained).unwrap(),
        )
        .unwrap();
        print!("{}", String::from_utf8(output.stdout).unwrap());
        eprint!("{}", String::from_utf8(output.stderr).unwrap());
        assert!(output.status.success(), "real {mode} child failed");
        child_outputs.push(retained);
    }
    assert_eq!(runtime_identity(), identity);
    let mut rows: Vec<Value> =
        serde_json::from_slice(&fs::read(base.join("controls.json")).unwrap()).unwrap();
    let missing: Vec<Value> =
        serde_json::from_slice(&fs::read(base.join("missing-tool.json")).unwrap()).unwrap();
    assert_eq!(missing.len(), 1);
    rows.extend(missing);
    let fixtures: BTreeMap<String, String> = rows
        .iter()
        .flat_map(|row| {
            row["fixtureSources"]
                .as_object()
                .unwrap()
                .iter()
                .map(move |(path, hash)| {
                    (
                        format!("{}/{path}", row["caseId"].as_str().unwrap()),
                        hash.as_str().unwrap().to_owned(),
                    )
                })
        })
        .collect();
    let mut record = json!({"schema":"legion-license-checker-native-accuracy/1","provider":ID,
        "providerVersion":registry_spec(ID)["providerVersion"],"stage":"candidate","outputKind":"candidates",
        "executionPath":"native-sdk-frozen-plan-real-license-checker","scope":SCOPE,"modelCalls":0,
        "productionQualification":false,"qualificationEligible":true,"status":"pass","coverageState":"complete",
        "binding":binding(ID,&fixtures),"runtimeIdentity":identity,"cases":rows,"children":child_outputs,
        "metrics":{"cases":4,"matched":4,"mismatched":0}});
    record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
    fs::write(
        base.join("legacy_security_js-licenses.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    println!(
        "LICENSE_CHECKER_PROVIDER_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
}
