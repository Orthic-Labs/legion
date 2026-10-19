//! Constructed native cargo-geiger controls through shipped legacy provider & actual SDK.
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
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

const SOURCE: &str = "engine/crates/legion-audit/tests/cargo_geiger_accuracy.rs";
const POLICY: &str = "legion-cargo-geiger-full-scan-fixture-v1";
const ID: &str = "legacy.security.rust-unsafe";
const FIXTURES: &str = "engine/crates/legion-audit/tests/fixtures/cargo-geiger";
const ARGV: &[&str] = &["--output-format", "Json", "--quiet"];
const SCOPE: &str = "constructed native SDK; full SafetyReport unsafe positive/absence + compiler failure + missing-tool controls in disposable scratch; no production owner-admission claim";

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
            "sandbox": "native-macos-deny-network-project-code-cargo-geiger-contract",
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
                    && !sandbox.network
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
                    "exact constructed cargo-geiger fixture admission"
                } else {
                    "outside exact constructed cargo-geiger fixture policy"
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

fn pin() -> String {
    let provision: Value = serde_json::from_slice(
        &fs::read(std::env::var_os("LEGION_CARGO_GEIGER_PROVISION").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(provision["schema"], "legion-cargo-geiger-ci-provision/1");
    assert_eq!(
        provision["sourceCommit"],
        "08543ac0b48ff6eec12c0a1f2478ef9c3259cd4d"
    );
    assert_eq!(
        provision["archiveDigest"],
        "sha256:4fbe170b23e5130aadb2ede5b169d027596dada6ad2aadf6422f50a858ce3e3b"
    );
    assert_eq!(
        provision["lockDigest"],
        "sha256:3f11d51a112555ed76faec9ab9d10cf9ae0f852582e6a3b12773aabf41f583c4"
    );
    assert_eq!(provision["build"]["exitCode"], 0);
    provision["toolDigest"].as_str().unwrap().to_owned()
}
fn markers(path: &Path, found: &mut BTreeMap<String, String>) {
    if !path.exists() {
        return;
    }
    assert!(!path.is_symlink());
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            markers(&entry.unwrap().path(), found);
        }
    } else if path
        .file_name()
        .is_some_and(|name| name == "geiger-project-execution-marker")
    {
        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes, b"LEGION_GEIGER_PROJECT_CODE_EXECUTED");
        found.insert(path.to_str().unwrap().into(), digest(&bytes));
    }
}
fn case(base: &Path, control: &str) -> Value {
    let missing = control == "missing-tool";
    let fixture = base.join(control);
    fs::create_dir(&fixture).unwrap();
    let root = fixture.join("source");
    let run = fixture.join("run");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let template = if missing { "absence" } else { control };
    let mut fixtures = BTreeMap::new();
    for relative in ["Cargo.toml", "Cargo.lock", "build.rs", "src/lib.rs"] {
        let bytes = fs::read(repository.join(FIXTURES).join(template).join(relative)).unwrap();
        let target = root.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, &bytes).unwrap();
        fixtures.insert(relative.to_owned(), digest(&bytes));
    }
    let before = snapshot(&root);
    assert_eq!(before, fixtures);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(control)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(ID)).unwrap();
    assert_eq!(
        registry_spec(ID)["execution"]["resourceClaims"]["projectExecution"],
        1
    );
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-cargo-geiger-fixture-key"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    let tool = fs::canonicalize(std::env::var_os("LEGION_CARGO_GEIGER_BIN").unwrap()).unwrap();
    assert_eq!(digest(&fs::read(&tool).unwrap()), pin());
    assert!(!fs::read(&tool).unwrap().starts_with(b"#!"));
    let saved_path = std::env::var_os("PATH").unwrap();
    if missing {
        let bin = std::env::var_os("LEGION_CARGO_GEIGER_TOOLCHAIN_BIN").unwrap();
        std::env::set_var(
            "PATH",
            std::env::join_paths([
                PathBuf::from(bin),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin"),
            ])
            .unwrap(),
        );
        assert!(resolve_request(
            &root,
            "cargo-geiger",
            &ARGV.iter().map(|a| (*a).into()).collect::<Vec<_>>()
        )
        .is_err());
    } else {
        let resolved = resolve_request(
            &root,
            "cargo-geiger",
            &ARGV.iter().map(|a| (*a).into()).collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(resolved.executable, tool);
        assert_eq!(
            resolved.args,
            ARGV.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>()
        );
    }
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let escaped = root
        .to_str()
        .unwrap()
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
        check: "cargo_unsafe".into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: pin(),
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        profile,
        profile_text,
        args: ARGV.iter().map(|a| (*a).into()).collect(),
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
    std::env::set_var("PATH", saved_path);
    assert_eq!(report.planned_providers, vec![ID]);
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0].result;
    let actual_receipts = receipts.lock().unwrap();
    assert_eq!(actual_receipts.len(), 1);
    let actual = receipt_json(&actual_receipts[0], &scratch.artifacts_dir());
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut measured = Value::Null;
    let candidates = result.details["candidates"].as_array().unwrap();
    assert!(result.findings.is_empty());
    let mut executed = BTreeMap::new();
    markers(&run.join("cache/cargo-target"), &mut executed);
    if missing {
        assert_eq!(actual["state"], "missing_executable");
        assert_eq!(actual["complete"], false);
        assert_eq!(actual["processTree"]["started"], false);
        assert!(actual["exitCode"].is_null());
        assert!(!result.complete && candidates.is_empty());
        assert_eq!(result.details["capabilityAbsence"]["blocking"], false);
        assert_eq!(result.details["capabilityAbsence"]["tool"], "cargo-geiger");
        assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
        assert!(policy.decisions.lock().unwrap().is_empty());
        assert!(executed.is_empty());
    } else {
        let projected = &result.details["executionReceipt"];
        assert_eq!(actual["receiptId"], projected["receiptId"]);
        stdout = String::from_utf8(artifact(projected, "stdout", &scratch)).unwrap();
        stderr = String::from_utf8(artifact(projected, "stderr", &scratch)).unwrap();
        assert_eq!(
            actual["executable"]["version"]["output"]
                .as_str()
                .unwrap()
                .trim(),
            "cargo-geiger 0.13.0"
        );
        assert_eq!(actual["executable"]["version"]["qualified"], true);
        assert_eq!(actual["sandbox"]["required"], true);
        assert_eq!(actual["sandbox"]["networkEnabled"], false);
        assert_eq!(actual["complete"], true);
        assert_eq!(actual["state"], "completed");
        assert_eq!(actual["gaps"], json!([]));
        for key in ["started", "terminated", "reaped"] {
            assert_eq!(actual["processTree"][key], true);
        }
        assert!(actual["signal"].is_null());
        assert_eq!(
            actual["command"]["args"],
            json!(policy.wrapped_args(&policy.args))
        );
        assert_eq!(
            actual["policy"]["digest"],
            digest(&canonical_bytes(&policy.definition()))
        );
        if control == "process-error" {
            assert_eq!(actual["exitCode"], 1);
            assert!(!result.complete && candidates.is_empty());
            assert!(!result.coverage_gaps.is_empty());
            assert!(result.details["findingsCount"].is_null());
            assert!(stdout.trim().is_empty());
            assert!(stderr.contains("LEGION_GEIGER_PROCESS_ERROR_CONTROL"));
        } else {
            assert_eq!(actual["exitCode"], 0);
            measured = serde_json::from_str(&stdout).unwrap();
            assert!(!measured["packages"].as_array().unwrap().is_empty());
            assert_eq!(measured["packages_without_metrics"], json!([]));
            assert_eq!(measured["used_but_not_scanned_files"], json!([]));
            assert!(
                result.applicable && result.complete,
                "{:?}",
                result.coverage_gaps
            );
            assert!(result.coverage_gaps.is_empty() && result.degradation.is_empty());
            let expected = u64::from(control == "positive");
            assert_eq!(result.details["findingsCount"], expected);
            assert_eq!(candidates.len(), expected as usize);
            if expected > 0 {
                assert_eq!(candidates[0]["ruleId"], "legacy.cargo_unsafe.cargo-geiger");
                assert_eq!(candidates[0]["verdict"], "UNADJUDICATED");
            }
            let coverage = result.coverage.as_ref().unwrap();
            assert_eq!(
                coverage.expected,
                provider.configuration["denominatorCount"].as_u64().unwrap()
            );
            assert_eq!(coverage.examined, coverage.expected);
            assert!(coverage.expected > 0 && coverage.gaps.is_empty());
            assert!(
                !executed.is_empty(),
                "actual build-script execution marker required"
            );
        }
        let decisions = policy.decisions.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["allowed"], true);
        assert_eq!(decisions[0]["requestId"], actual["requestId"]);
    }
    assert_eq!(
        snapshot(&root),
        before,
        "disposable target source must remain bound"
    );
    assert_eq!(digest(&fs::read(&tool).unwrap()), pin());
    json!({"control":control,"matched":true,"provider":ID,"root":root,"run":run,"fixtureTemplate":template,"fixtureSources":fixtures,
        "inventory":inventory,"frozenPlan":frozen.plan(),"frozenProvider":provider,"planDigest":frozen.digest(),"planSignature":frozen.signature(),
        "policyDefinition":policy.definition(),"policyDecisions":*policy.decisions.lock().unwrap(),"actualSdkReceipt":actual,
        "nativeResult":result,"actualStdout":stdout,"actualStderr":stderr,"actualToolReport":measured,"projectExecutionMarkers":executed,
        "sourceBefore":before,"sourceAfter":snapshot(&root)})
}

#[test]
#[ignore = "CI-only full native scanner builds disposable project; pinned source build & native macOS sandbox required"]
fn real_cargo_geiger_accuracy() {
    assert_eq!(
        std::env::var("GITHUB_ACTIONS").as_deref(),
        Ok("true"),
        "nested Cargo qualification is CI-only"
    );
    let base = fs::canonicalize(std::env::var_os("LEGION_CARGO_GEIGER_RECEIPTS").unwrap()).unwrap();
    if std::env::var_os("LEGION_CARGO_GEIGER_CHILD").is_some() {
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let cases: Vec<Value> = ["positive", "absence", "process-error", "missing-tool"]
            .iter()
            .map(|c| case(&base, c))
            .collect();
        let fixtures: BTreeMap<String, String> = cases
            .iter()
            .flat_map(|case| {
                case["fixtureSources"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(p, h)| {
                        (
                            format!("{}/{p}", case["control"].as_str().unwrap()),
                            h.as_str().unwrap().to_owned(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let provision: Value = serde_json::from_slice(
            &fs::read(std::env::var_os("LEGION_CARGO_GEIGER_PROVISION").unwrap()).unwrap(),
        )
        .unwrap();
        let mut record = json!({"schema":"legion-cargo-geiger-sdk-accuracy/1","provider":ID,"stage":"candidate","scope":SCOPE,"productionQualification":false,"qualificationEligible":true,"status":"pass","modelCalls":0,
            "admissionScope":"explicit constructed SDK authorizer; no production CLI owner-admission claim",
            "binding":binding(ID,&fixtures),"cases":cases,"metrics":{"cases":4,"matched":4,"mismatched":0},"provision":provision,"tool":{"version":"0.13.0","digest":pin()}});
        record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
        fs::write(
            base.join("legacy_security_rust-unsafe.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        println!(
            "CARGO_GEIGER_PROVIDER_ACCURACY {}",
            serde_json::to_string(&record).unwrap()
        );
        return;
    }
    for d in ["home", "tmp"] {
        fs::create_dir(base.join(d)).unwrap();
    }
    let tool = fs::canonicalize(std::env::var_os("LEGION_CARGO_GEIGER_BIN").unwrap()).unwrap();
    let toolchain =
        fs::canonicalize(std::env::var_os("LEGION_CARGO_GEIGER_TOOLCHAIN_BIN").unwrap()).unwrap();
    let mut paths = vec![tool.parent().unwrap().to_path_buf(), toolchain.clone()];
    paths.extend([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_cargo_geiger_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&base)
        .env_clear()
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("HOME", base.join("home"))
        .env("TMPDIR", base.join("tmp"))
        .env("GITHUB_ACTIONS", "true")
        .env("LEGION_CARGO_GEIGER_BIN", tool)
        .env("LEGION_CARGO_GEIGER_TOOLCHAIN_BIN", toolchain)
        .env(
            "LEGION_CARGO_GEIGER_PROVISION",
            std::env::var_os("LEGION_CARGO_GEIGER_PROVISION").unwrap(),
        )
        .env("LEGION_CARGO_GEIGER_RECEIPTS", &base)
        .env("LEGION_CARGO_GEIGER_CHILD", "1")
        .output()
        .unwrap();
    fs::write(base.join("child.stdout.log"), &output.stdout).unwrap();
    fs::write(base.join("child.stderr.log"), &output.stderr).unwrap();
    fs::write(base.join("child-execution.json"),serde_json::to_vec_pretty(&json!({"success":output.status.success(),"exitCode":output.status.code(),"signal":output.status.signal(),"stdoutDigest":digest(&output.stdout),"stderrDigest":digest(&output.stderr)})).unwrap()).unwrap();
    assert!(
        output.status.success(),
        "actual scanner child failed; retained streams required"
    );
    let marker = b"CARGO_GEIGER_PROVIDER_ACCURACY ";
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
