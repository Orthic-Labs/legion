//! Real scanner qualification. Run explicitly on macOS with provisioned
//! ShellCheck: --ignored real_scanner_accuracy. Missing tools fail, never skip.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute,
    native_providers::{
        legacy_checks::{resolve_request, AuditExternalProjectTool},
        security::producer::ArtifactProducer,
    },
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use legion_provider_sdk::ExternalProjectTool;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const ID: &str = "security.scanner-shellcheck";
const POLICY: &str = "legion-real-shellcheck-benchmark-v1";
const SOURCE: &str = "engine/crates/legion-audit/tests/external_scanner_accuracy.rs";
const LIMIT: usize = 1024 * 1024;
const TIMEOUT: u64 = 30_000;

fn digest(bytes: &[u8]) -> String {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
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

fn bind_source_tree(root: &Path, path: &Path, files: &mut Vec<(String, String)>) {
    assert!(
        !path.is_symlink(),
        "implementation binding refuses symlinks"
    );
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
            bind_source_tree(root, &entry.unwrap().path(), files);
        }
    } else {
        files.push((
            path.strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"),
            digest(&fs::read(path).unwrap()),
        ));
    }
}

#[test]
fn source_binding_excludes_only_regular_generated_session_receipts() {
    fn snapshot(root: &Path) -> Vec<(String, String)> {
        let mut files = Vec::new();
        bind_source_tree(root, root, &mut files);
        files.sort();
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

fn implementation_binding(root: &Path) -> Value {
    let roots = [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
    ];
    let mut files = Vec::new();
    for tree in roots {
        bind_source_tree(root, &root.join(tree), &mut files);
    }
    for file in [
        "engine/Cargo.lock",
        "engine/Cargo.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
    ] {
        bind_source_tree(root, &root.join(file), &mut files);
    }
    files.sort();
    json!({"roots": roots, "fileCount": files.len(), "digest": digest(&serde_json::to_vec(&files).unwrap())})
}

fn spec() -> (ProviderSpec, Value) {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let entry = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == ID)
        .unwrap()
        .clone();
    (serde_json::from_value(entry.clone()).unwrap(), entry)
}

struct Fixture(PathBuf);
impl Fixture {
    fn new(case: &str) -> Self {
        let scratch = std::env::var_os("LEGION_REAL_SCANNER_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = scratch.join(format!(
            "legion-real-shellcheck-{case}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(path.join("source/src")).unwrap();
        fs::create_dir_all(path.join("run")).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// This benchmark admits exactly one provisioned executable, fixture root &
/// production argv. It cannot authorize project execution or sandbox bypass.
struct ScopedPolicy {
    root: PathBuf,
    run: PathBuf,
    tool: PathBuf,
    tool_digest: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    inventory_digest: String,
    decisions: Mutex<Vec<Value>>,
}

impl ScopedPolicy {
    fn new(root: &Path, run: &Path, inventory_digest: &str) -> Self {
        let tool = resolve_request(root, "shellcheck", &[]).unwrap_or_else(|error| {
            panic!("provisioned real ShellCheck required: {}", error.message())
        });
        let tool_path = fs::canonicalize(&tool.executable).unwrap();
        assert!(
            !tool_path.starts_with(root) && !tool_path.starts_with(run),
            "tool must be host provisioned"
        );
        let bytes = fs::read(&tool_path).unwrap();
        assert!(
            !bytes.starts_with(b"#!"),
            "benchmark refuses script substitutes for real ShellCheck"
        );
        assert_eq!(digest(&bytes), tool.digest);
        let wrapper =
            fs::canonicalize("/usr/bin/sandbox-exec").expect("native macOS sandbox required");
        let wrapper_digest = digest(&fs::read(&wrapper).unwrap());
        Self {
            root: root.into(),
            run: run.into(),
            tool: tool_path,
            tool_digest: tool.digest,
            wrapper,
            wrapper_digest,
            inventory_digest: inventory_digest.into(),
            decisions: Mutex::new(Vec::new()),
        }
    }

    fn definition(&self) -> Value {
        json!({"id": POLICY, "version": 1, "provider": ID, "root": self.root,
            "runDirectory": self.run, "inventoryDigest": self.inventory_digest,
            "tool": {"path": self.tool, "digest": self.tool_digest},
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest},
            "scannerArgs": ["--norc", "-f", "json", "--severity=style", "--", "./src/check.sh"],
            "versionArgs": ["--version"], "timeoutMsMaximum": TIMEOUT, "outputBytesMaximum": LIMIT,
            "sandbox": "native-macos-deny-network-deny-project-write"})
    }

    fn permits(&self, request: &ExternalToolRequest) -> bool {
        let is_scan = request.task_id.as_deref() == Some("shellcheck");
        let is_probe = request.task_id.as_deref() == Some("shellcheck-version-probe");
        if !(is_scan || is_probe)
            || request.provider_id != ID
            || request.plan_id != self.inventory_digest
            || request.policy_id != legion_audit::execution_policy::POLICY_ID
            || request.cwd != self.root.to_string_lossy().as_ref()
            || request.origin != ToolOrigin::System
            || request.shell
            || !request.requires_network_sandbox
            || request.skip_version_probe
            || request.version_requirement.is_some()
            || request.timeout_ms == 0
            || request.timeout_ms > TIMEOUT
            || request.stdout_limit == 0
            || request.stdout_limit > LIMIT
            || request.stderr_limit == 0
            || request.stderr_limit > LIMIT
            || request.expected_digest.as_deref() != Some(self.wrapper_digest.as_str())
            || fs::canonicalize(&request.executable).ok().as_ref() != Some(&self.wrapper)
            || !request.sensitive_argument_indexes.is_empty()
            || !request.sensitive_environment_names.is_empty()
            || request.args.len() < 5
            || request.args[0] != "-f"
            || request.args[2] != "--"
            || fs::canonicalize(&request.args[3]).ok().as_ref() != Some(&self.tool)
            || fs::read(&self.tool)
                .ok()
                .map(|bytes| digest(&bytes))
                .as_deref()
                != Some(self.tool_digest.as_str())
        {
            return false;
        }
        let suffix: Vec<String> = if is_scan {
            [
                "--norc",
                "-f",
                "json",
                "--severity=style",
                "--",
                "./src/check.sh",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        } else {
            vec!["--version".into()]
        };
        let accepted: BTreeSet<i32> = if is_scan {
            [0, 1].into_iter().collect()
        } else {
            [0].into_iter().collect()
        };
        if request.args[4..] != suffix || request.accepted_exit_codes != accepted {
            return false;
        }
        let mut version_args = request.args[..4].to_vec();
        version_args.push("--version".into());
        if request.version_args != version_args {
            return false;
        }
        let allowed: BTreeSet<String> = [
            "PATH",
            "PATHEXT",
            "SystemRoot",
            "COMSPEC",
            "HOME",
            "USERPROFILE",
            "TEMP",
            "TMP",
            "NO_COLOR",
            "SEMGREP_SEND_METRICS",
            "SEMGREP_ENABLE_VERSION_CHECK",
            "SYFT_CHECK_FOR_APP_UPDATE",
            "GOTOOLCHAIN",
            "GOPROXY",
            "GOSUMDB",
            "GOWORK",
            "CGO_ENABLED",
            "GOCACHE",
            "GOLANGCI_LINT_CACHE",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if request
            .environment
            .keys()
            .any(|name| !allowed.contains(name))
            || request.environment.keys().cloned().collect::<BTreeSet<_>>()
                != request.environment_allowlist
        {
            return false;
        }
        let Some(sandbox) = request.sandbox.as_ref() else {
            return false;
        };
        let Ok(profile_path) = fs::canonicalize(&request.args[1]) else {
            return false;
        };
        if !profile_path.starts_with(&self.run)
            || !sandbox.network
            || sandbox.filesystem_scope.as_deref() != self.root.to_str()
        {
            return false;
        }
        let escaped = self
            .root
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let expected_profile = format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
        let Ok(profile) = fs::read(&profile_path) else {
            return false;
        };
        let profile_digest: String = Sha256::digest(&profile)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        profile == expected_profile.as_bytes()
            && sandbox.id == format!("sandbox:macos:{profile_digest}")
    }
}

impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let allowed = self.permits(request);
        self.decisions.lock().unwrap().push(json!({"allowed": allowed, "requestId": request.request_id,
            "providerId": request.provider_id, "planId": request.plan_id, "taskId": request.task_id,
            "executable": request.executable, "expectedDigest": request.expected_digest,
            "args": request.args, "versionArgs": request.version_args, "cwd": request.cwd,
            "timeoutMs": request.timeout_ms, "stdoutLimit": request.stdout_limit, "stderrLimit": request.stderr_limit,
            "acceptedExitCodes": request.accepted_exit_codes, "requiresNetworkSandbox": request.requires_network_sandbox}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&serde_json::to_vec(&self.definition()).unwrap()),
            reason: Some(
                if allowed {
                    "fixture-scoped real ShellCheck benchmark"
                } else {
                    "outside exact benchmark policy"
                }
                .into(),
            ),
        }
    }
}

fn receipt_json(receipt: &legion_effects::ExecutionReceipt) -> Value {
    json!({"receiptId": receipt.receipt_id, "requestId": receipt.request_id, "providerId": receipt.provider_id,
        "planId": receipt.plan_id, "policyId": receipt.policy_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "policy": receipt.policy.as_ref().map(|policy| json!({"id": policy.id, "version": policy.version, "digest": policy.digest, "allowed": policy.allowed})),
        "executable": receipt.executable.as_ref().map(|exe| json!({"path": exe.canonical_path, "digest": exe.digest,
            "version": {"args": exe.version.args, "output": exe.version.output, "exitCode": exe.version.exit_code, "qualified": exe.version.qualified, "skippedByPolicy": exe.version.skipped_by_policy}})),
        "sandbox": {"required": receipt.sandbox.required, "receiptId": receipt.sandbox.receipt_id, "networkEnabled": receipt.sandbox.network_enabled},
        "processTree": {"started": receipt.process_tree.started, "reaped": receipt.process_tree.reaped},
        "stdout": receipt.stdout.as_ref().map(|out| json!({"path": out.path, "digest": out.digest, "bytes": out.bytes, "immutable": out.immutable})),
        "parser": {"attempted": receipt.parser.attempted, "succeeded": receipt.parser.succeeded, "error": receipt.parser.error},
        "exitCode": receipt.exit_code, "gaps": receipt.gaps})
}

fn version_probe(policy: Arc<ScopedPolicy>) -> Value {
    let auth = legion_effects::authenticate_sandbox(
        &policy.tool.to_string_lossy(),
        &["--version".into()],
        &policy.root.to_string_lossy(),
        legion_effects::SandboxMode::DenyNetworkDenyProjectWrite,
        &policy.run.join("version-sandbox"),
    )
    .unwrap();
    let request = ExternalToolRequest {
        request_id: "real-shellcheck-version".into(),
        provider_id: ID.into(),
        plan_id: policy.inventory_digest.clone(),
        policy_id: legion_audit::execution_policy::POLICY_ID.into(),
        task_id: Some("shellcheck-version-probe".into()),
        executable: auth.wrapped_executable,
        args: auth.wrapped_args.clone(),
        version_args: auth.wrapped_args,
        cwd: policy.root.to_string_lossy().into_owned(),
        origin: ToolOrigin::System,
        requires_network_sandbox: true,
        sandbox: Some(legion_effects::SandboxReceipt {
            id: auth.id,
            network: auth.network,
            filesystem_scope: auth.filesystem_scope,
        }),
        timeout_ms: TIMEOUT,
        stdout_limit: LIMIT,
        stderr_limit: LIMIT,
        ..ExternalToolRequest::default()
    };
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(policy.run.join("version-artifacts")),
        SharedPolicy(policy.clone()),
    );
    let tool = AuditExternalProjectTool::new(effects);
    let receipt = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(tool.execute(request, tokio_util::sync::CancellationToken::new()));
    assert_eq!(
        receipt.state,
        legion_effects::ExecutionState::Completed,
        "{:?}",
        receipt.gaps
    );
    assert!(receipt.complete && receipt.process_tree.started && receipt.process_tree.reaped);
    assert_eq!(receipt.exit_code, Some(0));
    assert!(receipt.gaps.is_empty());
    let identity = receipt.executable.as_ref().unwrap();
    assert_eq!(
        identity.digest.as_deref(),
        Some(policy.wrapper_digest.as_str())
    );
    assert!(identity.version.qualified && !identity.version.skipped_by_policy);
    assert_eq!(identity.version.exit_code, Some(0));
    let artifact = receipt.stdout.as_ref().unwrap();
    assert!(artifact.immutable);
    let raw = fs::read(policy.run.join("version-artifacts").join(&artifact.path)).unwrap();
    assert_eq!(digest(&raw), artifact.digest);
    assert_eq!(raw.len(), artifact.bytes);
    let output = identity.version.output.as_deref().unwrap();
    assert_eq!(String::from_utf8(raw).unwrap().trim(), output.trim());
    assert!(
        output.contains("ShellCheck"),
        "real tool version probe required"
    );
    let version = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("version:"))
        .expect("ShellCheck semantic version")
        .trim();
    assert!(!version.is_empty() && version.chars().all(|c| c.is_ascii_digit() || c == '.'));
    json!({"version": version, "rawVersionOutput": output, "receipt": receipt_json(&receipt)})
}

struct SharedPolicy(Arc<ScopedPolicy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(request)
    }
}

fn case(case_id: &str, source: &str, expected: &[&str]) -> Value {
    let fixture = Fixture::new(case_id);
    let root = fixture.0.join("source");
    let run = fixture.0.join("run");
    fs::write(root.join("src/check.sh"), source).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(case_id)
        .unwrap();
    let (spec, _) = spec();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"real-scanner-benchmark-key"))
        .unwrap();
    let provider = frozen.provider(ID).expect("applicable shipped provider");
    assert_eq!(provider.configuration["denominatorCount"], 1);
    let policy = Arc::new(ScopedPolicy::new(&root, &run, &inventory.digest));
    let version = version_probe(policy.clone());
    let mut registry = NativeProviderRegistry::new(&root);
    registry.security = registry.security.with_producer(
        ArtifactProducer::new(&root)
            .with_run_dir(&run)
            .with_bounds(TIMEOUT, LIMIT)
            .with_policy_authorizer(policy.clone()),
    );
    let execution = execute(&frozen, &inventory, &registry).unwrap();
    assert_eq!(execution.planned_providers, vec![ID]);
    assert_eq!(execution.results.len(), 1);
    let entry = &execution.results[0];
    assert_eq!(entry.provider, ID);
    assert!(!entry.skipped);
    let result = &entry.result;
    assert!(
        result.applicable && result.complete,
        "{case_id}: {:?}",
        result.coverage_gaps
    );
    assert!(result.coverage_gaps.is_empty() && result.degradation.is_empty());
    assert!(result.details.get("availability").is_none());
    assert!(
        result.findings.is_empty(),
        "scanner output remains candidates"
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.expected, 1);
    assert_eq!(coverage.examined, 1);
    assert!(coverage.gaps.is_empty());
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    let receipt = &result.details["executionReceipt"];
    assert_eq!(receipt["state"], "completed");
    assert_eq!(receipt["complete"], true);
    assert_eq!(receipt["policyId"], POLICY);
    assert_eq!(receipt["tool"]["name"], "shellcheck");
    assert_eq!(receipt["executableDigest"], policy.tool_digest);
    assert_eq!(receipt["sandbox"]["required"], true);
    assert!(receipt["sandbox"]["receiptId"]
        .as_str()
        .unwrap()
        .starts_with("sandbox:macos:"));
    assert_eq!(
        receipt["argv"],
        json!([
            "shellcheck",
            "--norc",
            "-f",
            "json",
            "--severity=style",
            "--",
            "./src/check.sh"
        ])
    );
    assert_eq!(receipt["exitCode"], if expected.is_empty() { 0 } else { 1 });
    assert!(receipt["stdoutDigest"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71));
    assert!(receipt["stdoutBytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
    let actual: Vec<String> = result.details["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|candidate| {
            assert_eq!(candidate["source"]["tool"], "shellcheck");
            assert_eq!(candidate["adjudication"], "required");
            format!(
                "{}|{}|{}",
                candidate["ruleId"].as_str().unwrap(),
                candidate["path"].as_str().unwrap(),
                candidate["line"].as_u64().unwrap()
            )
        })
        .collect();
    let expected: Vec<String> = expected.iter().map(|label| (*label).into()).collect();
    let matched = actual == expected;
    assert_eq!(
        fs::read(root.join("src/check.sh")).unwrap(),
        source.as_bytes()
    );
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(
        decisions.len(),
        2,
        "one bounded version probe & one scanner execution"
    );
    assert!(decisions.iter().all(|decision| decision["allowed"] == true));
    json!({"caseId": case_id, "source": {"path": "src/check.sh", "bytes": source, "digest": digest(source.as_bytes())},
        "expected": expected, "actual": actual, "controlMatched": matched,
        "planDigest": frozen.digest(), "inventoryDigest": inventory.digest, "coverage": result.coverage,
        "toolIdentity": {"path": policy.tool, "executableDigest": policy.tool_digest, "version": version},
        "policy": policy.definition(), "policyDecisions": *decisions,
        "executionReceipt": receipt, "actualProviderResult": result,
        "receiptRetentionLimit": "Scanner producer exposes its actual reduced tool receipt; full process-tree/parser receipt is not retained. Native version probe receipt is retained separately."})
}

#[test]
#[ignore = "requires real provisioned ShellCheck & native macOS sandbox"]
fn real_scanner_accuracy_shellcheck() {
    let cases = vec![
        case(
            "shellcheck-unquoted",
            "#!/bin/sh\nname=$1\necho $name\n",
            &["SC2086|src/check.sh|3"],
        ),
        case(
            "shellcheck-quoted",
            "#!/bin/sh\nname=$1\necho \"$name\"\n",
            &[],
        ),
    ];
    let (_, mut provider) = spec();
    provider.as_object_mut().unwrap().remove("benchmark");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let source = fs::read(root.join(SOURCE)).unwrap();
    let eligible = cases.iter().all(|case| case["controlMatched"] == true);
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut missed = 0usize;
    for case in &cases {
        let expected: BTreeSet<&str> = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        let actual = case["actual"].as_array().unwrap();
        let unique: BTreeSet<&str> = actual.iter().map(|value| value.as_str().unwrap()).collect();
        tp += expected.intersection(&unique).count();
        fp += unique.difference(&expected).count() + actual.len() - unique.len();
        missed += expected.difference(&unique).count();
    }
    let mut record = json!({"schema": "legion-external-provider-accuracy/1", "provider": ID, "stage": "candidate",
        "scope": "Constructed planted & clean controls; not population accuracy or production admission",
        "executionPath": "native-sdk-frozen-plan-real-external-scanner", "modelCalls": 0,
        "qualificationEligible": eligible, "coverageState": "complete", "coverageGaps": [],
        "binding": {"providerSpecDigest": digest(&serde_json::to_vec(&provider).unwrap()), "harnessPath": SOURCE,
            "harnessDigest": digest(&source), "implementation": implementation_binding(&root)},
        "metrics": {"truePositives": tp, "falsePositives": fp, "falseNegatives": missed,
            "precision": if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 },
            "recall": if tp + missed > 0 { tp as f64 / (tp + missed) as f64 } else { 0.0 }, "positiveCases": 1, "cleanCases": 1},
        "cases": cases, "status": if eligible { "pass" } else { "fail" }});
    record["qualificationDigest"] = json!(digest(&serde_json::to_vec(&record).unwrap()));
    if let Some(directory) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("security_scanner-shellcheck.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
    }
    println!(
        "EXTERNAL_PROVIDER_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
    assert!(
        eligible,
        "real ShellCheck controls must match exact expected output"
    );
}
