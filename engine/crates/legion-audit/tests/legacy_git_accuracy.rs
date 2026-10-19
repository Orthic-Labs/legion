//! Explicit real-Git qualification; no fabricated tool, output or effect receipt.
//! Run with --ignored real_legacy_git_accuracy. Requires provisioned Git & an
//! empty/missing system Git config. All repository writes stay in fixtures.
#![cfg(unix)]

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

const SOURCE: &str = "engine/crates/legion-audit/tests/legacy_git_accuracy.rs";
const POLICY: &str = "legion-real-git-qualification-v1";
const REPO: &str = "legacy.core.repo";
const DEBT: &str = "legacy.quality.debt-markers";
const CLEAN: &str = "export const answer = 42;\n";
const MARKER: &str = "// TODO: remove compatibility branch\nexport const answer = 42;\n";
const FILE: &str = "src/example.js";

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
        let base = std::env::var_os("LEGION_REAL_GIT_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-real-git-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        for dir in ["home", "hooks", "template", "tmp"] {
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

fn bind_source_tree(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
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

fn binding(id: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = BTreeMap::new();
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
        bind_source_tree(&root, &root.join(path), &mut files);
    }
    let mut spec = registry_spec(id);
    spec.as_object_mut().unwrap().remove("benchmark");
    json!({"providerSpec":spec, "providerSpecDigest":digest(&canonical_bytes(&spec)),
        "sources":files, "sourcesDigest":digest(&canonical_bytes(&json!(files))),
        "fixture":SOURCE})
}

// Setup commands use only provisioned Git, exact fixture paths & isolated
// config. They never run through a shell or modify global configuration.
fn git(tool: &Path, root: &Path, base: &Path, args: &[&str]) -> Output {
    assert!(root.starts_with(base));
    let output = Command::new(tool)
        .current_dir(root)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", base.join("home"))
        .env("XDG_CONFIG_HOME", base.join("home"))
        .env("TMPDIR", base.join("tmp"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Legion Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "credential.helper=",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture Git setup failed: {:?}",
        args
    );
    output
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
    for (name, value) in [
        ("PYTHONDONTWRITEBYTECODE", "1"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("PYTHONNOUSERSITE", "1"),
    ] {
        env.insert(name.into(), value.into());
        allowed.insert(name.into());
    }
    (env, allowed)
}

struct ScopedPolicy {
    id: String,
    check: String,
    plan: String,
    request: String,
    root: PathBuf,
    tool: PathBuf,
    tool_digest: String,
    version: String,
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn definition(&self) -> Value {
        json!({"id":POLICY, "version":1, "provider":self.id, "task":self.check,
            "plan":self.plan, "originalRequestId":self.request, "cwd":self.root,
            "artifactRequestId":"legion-audit/<64 lowercase hex>; one admission only",
            "executable":self.tool, "executableDigest":self.tool_digest,
            "expectedVersionOutput":self.version, "args":self.args, "versionArgs":["--version"],
            "environment":self.environment, "environmentAllowlist":self.allowlist,
            "timeoutMs":120000, "stdoutLimit":8388608, "stderrLimit":8388608,
            "sandbox":"not-required-by-shipped-read-only-git-contract",
            "acceptedExitCodes":if self.id == DEBT {vec![0,1]} else {vec![0]}})
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
            && !req.requires_network_sandbox
            && req.sandbox.is_none()
            && !req.skip_version_probe
            && req.version_requirement.is_none()
            && req.executable == self.tool.to_string_lossy().as_ref()
            && req.expected_digest.as_deref() == Some(self.tool_digest.as_str())
            && fs::read(&self.tool).is_ok_and(|bytes| digest(&bytes) == self.tool_digest)
            && req.args == self.args
            && req.version_args == ["--version"]
            && req.environment == self.environment
            && req.environment_allowlist == self.allowlist
            && req.sensitive_argument_indexes.is_empty()
            && req.sensitive_environment_names.is_empty()
            && req.timeout_ms == 120000
            && req.stdout_limit == 8388608
            && req.stderr_limit == 8388608
            && req.accepted_exit_codes
                == if self.id == DEBT {
                    [0, 1].into_iter().collect()
                } else {
                    [0].into_iter().collect()
                }
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let mut decisions = self.decisions.lock().unwrap();
        let allowed = decisions.is_empty() && self.permits(request);
        decisions.push(json!({"allowed":allowed,
            "requestId":request.request_id, "providerId":request.provider_id,
            "planId":request.plan_id, "taskId":request.task_id,
            "executable":request.executable, "expectedDigest":request.expected_digest,
            "args":request.args, "versionArgs":request.version_args, "cwd":request.cwd,
            "environmentNames":request.environment.keys().collect::<Vec<_>>(),
            "environmentDigest":digest(&serde_json::to_vec(&request.environment).unwrap()),
            "timeoutMs":request.timeout_ms, "stdoutLimit":request.stdout_limit,
            "stderrLimit":request.stderr_limit, "acceptedExitCodes":request.accepted_exit_codes,
            "requiresNetworkSandbox":request.requires_network_sandbox}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact real-Git fixture admission"
                } else {
                    "outside exact real-Git fixture policy"
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

fn case(base: &Path, tool: &Path, version: &str, id: &str, positive: bool) -> Value {
    let case_id = format!(
        "{}-{}",
        id.replace('.', "-"),
        if positive { "positive" } else { "absence" }
    );
    let root = base.join(&case_id).join("source");
    let run = base.join(&case_id).join("run");
    fs::create_dir_all(root.join("src")).unwrap();
    let source = if id == DEBT && positive {
        MARKER
    } else {
        CLEAN
    };
    fs::write(root.join(FILE), source).unwrap();
    let template = format!("--template={}", base.join("template").display());
    git(
        tool,
        &root,
        base,
        &["init", "--initial-branch=main", &template],
    );
    for (key, value) in [
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
        ("commit.gpgsign", "false"),
        ("status.showUntrackedFiles", "normal"),
        ("core.quotePath", "true"),
        ("core.autocrlf", "false"),
    ] {
        git(tool, &root, base, &["config", "--local", key, value]);
    }
    git(tool, &root, base, &["add", "--", FILE]);
    git(
        tool,
        &root,
        base,
        &["commit", "--no-verify", "-m", "fixture"],
    );
    if id == REPO && positive {
        fs::write(root.join(FILE), "export const answer = 43;\n").unwrap();
    }
    let source_before = fs::read(root.join(FILE)).unwrap();
    let head_before = fs::read(root.join(".git/HEAD")).unwrap();
    let config_before = fs::read(root.join(".git/config")).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    assert_eq!(
        inventory.entries.len(),
        1,
        "fixture inventory must exclude Git metadata"
    );
    assert_eq!(inventory.entries[0].path, FILE);
    let spec: ProviderSpec = serde_json::from_value(registry_spec(id)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"real-git-qualification-key"))
        .unwrap();
    let provider = frozen.provider(id).unwrap();
    assert_eq!(provider.configuration["denominatorCount"], 1);
    let args: Vec<String> = if id == REPO {
        vec!["status", "--porcelain=v1"]
    } else {
        vec!["grep", "-nIE", "(ponytail:|TODO|FIXME|HACK|XXX)"]
    }
    .into_iter()
    .map(str::to_owned)
    .collect();
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let (environment, allowlist) = expected_environment(&run);
    let native_id = format!("audit:{id}:{}:{}", frozen.digest(), inventory.digest);
    // Production adapter adds nonce/sequence to its platform-safe artifact ID.
    // Policy binds exact provider/plan/task & admits only its first request.
    let request = native_id;
    let policy = Arc::new(ScopedPolicy {
        id: id.into(),
        check: if id == REPO { "repo" } else { "debt_markers" }.into(),
        plan: frozen.digest().into(),
        request,
        root: root.clone(),
        tool: tool.into(),
        tool_digest: digest(&fs::read(tool).unwrap()),
        version: version.into(),
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
    assert_eq!(report.planned_providers, vec![id]);
    assert_eq!(report.results.len(), 1);
    let entry = &report.results[0];
    assert!(!entry.skipped);
    let result = &entry.result;
    assert!(
        result.applicable && result.complete,
        "{case_id}: {:?}",
        result.coverage_gaps
    );
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
    assert!(result
        .details
        .get("candidates")
        .is_none_or(|value| value.as_array().unwrap().is_empty()));
    let receipt = &result.details["executionReceipt"];
    assert_eq!(receipt["state"], "completed");
    assert_eq!(receipt["complete"], true);
    assert_eq!(receipt["policyId"], POLICY);
    assert_eq!(receipt["policy"]["allowed"], true);
    assert_eq!(
        receipt["policy"]["digest"],
        digest(&canonical_bytes(&policy.definition()))
    );
    assert_eq!(receipt["planId"], frozen.digest());
    assert_eq!(receipt["providerId"], id);
    assert_eq!(receipt["cwd"], root.to_string_lossy().as_ref());
    assert_eq!(
        receipt["executable"]["canonicalPath"],
        tool.to_string_lossy().as_ref()
    );
    assert_eq!(receipt["executable"]["digest"], policy.tool_digest);
    assert_eq!(receipt["executable"]["version"]["qualified"], true);
    assert_eq!(
        receipt["executable"]["version"]["args"],
        json!(["--version"])
    );
    assert_eq!(receipt["executable"]["version"]["exitCode"], 0);
    assert_eq!(
        receipt["executable"]["version"]["output"]
            .as_str()
            .unwrap()
            .trim(),
        version.trim()
    );
    assert_eq!(receipt["command"]["args"], json!(policy.args));
    assert_eq!(receipt["sandbox"]["required"], false);
    assert!(receipt["sandbox"]["receiptId"].is_null());
    assert_eq!(receipt["processTree"]["started"], true);
    assert_eq!(receipt["processTree"]["terminated"], true);
    assert_eq!(receipt["processTree"]["reaped"], true);
    assert_eq!(receipt["gaps"], json!([]));
    assert_eq!(
        receipt["exitCode"],
        if id == DEBT && !positive { 1 } else { 0 }
    );
    let stdout = artifact(receipt, "stdout", &scratch);
    assert!(artifact(receipt, "stderr", &scratch).is_empty());
    let expected_stdout = if id == REPO && positive {
        " M src/example.js\n"
    } else if id == DEBT && positive {
        "src/example.js:1:// TODO: remove compatibility branch\n"
    } else {
        ""
    };
    assert_eq!(stdout, expected_stdout.as_bytes());
    let expected = if id == REPO {
        if positive {
            json!({"repositoryStatus":" M src/example.js"})
        } else {
            json!({})
        }
    } else {
        json!({"findingsCount":if positive {1} else {0}, "ponytail":0,
            "ponytailNoTrigger":0, "todoFixme":if positive {1} else {0},
            "findings":if positive {vec![json!({"ruleId":"legacy.debt_markers.git-grep", "path":FILE,
                "line":1, "message":"debt_markers reported 1 finding(s)", "severity":"low"})]} else {vec![]}})
    };
    let actual = if id == REPO {
        assert!(result.findings.is_empty());
        result
            .details
            .get("repositoryStatus")
            .map_or_else(|| json!({}), |status| json!({"repositoryStatus":status}))
    } else {
        let findings: Vec<Value> = result
            .findings
            .iter()
            .map(|finding| {
                let mut evidence =
                    result.details["findingEvidence"][finding.id.to_string()].clone();
                evidence["severity"] = json!(finding.severity);
                evidence
            })
            .collect();
        json!({"findingsCount":result.details["findingsCount"], "ponytail":result.details["ponytail"],
            "ponytailNoTrigger":result.details["ponytailNoTrigger"], "todoFixme":result.details["todoFixme"],
            "findings":findings})
    };
    assert_eq!(actual, expected);
    assert_eq!(fs::read(root.join(FILE)).unwrap(), source_before);
    assert_eq!(fs::read(root.join(".git/HEAD")).unwrap(), head_before);
    assert_eq!(fs::read(root.join(".git/config")).unwrap(), config_before);
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["allowed"], true);
    json!({"caseId":case_id, "control":if positive {"positive"} else {"absence"},
        "inventoryDigest":inventory.digest, "planDigest":frozen.digest(),
        "coverage":{"expected":coverage.expected,"examined":coverage.examined,
            "denominatorDigest":coverage.denominator_digest,"gaps":coverage.gaps},
        "expected":expected, "actual":actual, "matched":actual == expected,
        "expectedStdout":expected_stdout, "actualStdout":String::from_utf8(stdout).unwrap(),
        "expectedStderr":"", "actualStderr":"",
        "fixtureSource":String::from_utf8(source_before.clone()).unwrap(),
        "fixtureSourceDigest":digest(&source_before),
        "nativeDetails":result.details, "nativeFindings":result.findings,
        "policyDefinition":policy.definition(),
        "policyDecisions":*decisions, "executionReceipt":receipt})
}

#[test]
#[ignore = "explicit real-Git qualification; requires provisioned Git & isolated scratch"]
fn real_legacy_git_accuracy() {
    // A separate copy of this test owns its entire environment. Never change
    // process-global HOME/config while other Rust tests may run concurrently.
    if let Some(base) = std::env::var_os("LEGION_REAL_GIT_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let resolved = resolve_request(&base, "git", &[]).expect("provisioned real Git required");
        let tool = fs::canonicalize(resolved.executable).unwrap();
        assert!(!tool.starts_with(&base));
        let bytes = fs::read(&tool).unwrap();
        assert!(
            !bytes.starts_with(b"#!"),
            "script substitutes are forbidden"
        );
        assert_eq!(digest(&bytes), resolved.digest);
        let version_output = git(&tool, &base, &base, &["--version"]);
        assert!(version_output.stderr.is_empty());
        let version = String::from_utf8(version_output.stdout).unwrap();
        assert!(version.starts_with("git version "));
        // Production audit_environment explicitly suppresses host system Git
        // config; fixture HOME/XDG_CONFIG_HOME isolate user config as well.
        assert_eq!(
            expected_environment(&base)
                .0
                .get("GIT_CONFIG_NOSYSTEM")
                .map(String::as_str),
            Some("1")
        );
        let system_config = json!({"state":"disabled-by-child-environment",
            "environmentName":"GIT_CONFIG_NOSYSTEM", "environmentValue":"1"});
        for id in [REPO, DEBT] {
            let cases = vec![
                case(&base, &tool, &version, id, true),
                case(&base, &tool, &version, id, false),
            ];
            let matched = cases
                .iter()
                .filter(|case| case["expected"] == case["actual"])
                .count();
            let mismatched = cases.len() - matched;
            assert_eq!(mismatched, 0);
            let mut record = json!({"schema":"legion-real-git-provider-accuracy/1", "provider":id,
                "providerVersion":registry_spec(id)["providerVersion"], "modelCalls":0,
                "executionPath":"native-sdk-frozen-plan-real-git", "coverageState":"complete",
                "outputKind":if id == REPO {"fact"} else {"findings"},
                "stage":if id == REPO {"fact-output"} else {"finding"},
                "scope":if id == REPO {"one dirty-path repository status & clean absence"}
                    else {"one summary finding & exact marker counts/raw grep; no marker-location accuracy claim"},
                "binding":binding(id), "systemGitConfig":system_config,
                "cases":cases, "metrics":{"cases":cases.len(),"matched":matched,"mismatched":mismatched},
                "status":"pass"});
            record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
            if let Some(dir) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
                fs::create_dir_all(&dir).unwrap();
                fs::write(
                    PathBuf::from(dir).join(format!("{}.json", id.replace('.', "_"))),
                    serde_json::to_vec_pretty(&record).unwrap(),
                )
                .unwrap();
            }
            println!(
                "LEGACY_GIT_PROVIDER_ACCURACY {}",
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
            "real_legacy_git_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", fixture.0.join("home"))
        .env("XDG_CONFIG_HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("LEGION_REAL_GIT_CHILD", &fixture.0);
    if let Some(dir) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        assert!(Path::new(&dir).is_absolute());
        child.env("LEGION_PROVIDER_BENCHMARK_DIR", dir);
    }
    let output = child.output().unwrap();
    print!("{}", String::from_utf8(output.stdout).unwrap());
    eprint!("{}", String::from_utf8(output.stderr).unwrap());
    assert!(
        output.status.success(),
        "real-Git qualification child failed"
    );
}
