//! Actual cargo-outdated controls through frozen audit SDK provider path.
//! Constructed fixture qualification only; it makes no production admission claim.
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
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
};

const SOURCE: &str = "engine/crates/legion-audit/tests/real_rust_outdated_accuracy.rs";
const POLICY: &str = "legion-rust-outdated-constructed-fixture-v1";
const PROVIDER: &str = "legacy.stack.rust-outdated";
const CHECK: &str = "cargo_outdated";
const MARKER: &[u8] = b"RUST_OUTDATED_PROVIDER_ACCURACY ";
const CASE_MARKER: &[u8] = b"RUST_OUTDATED_CASE ";
const ARM_BINARY: &str = "sha256:22003be477d106e10c285d11e677b680859fc72d1c0035fe599b3755ede231a8";
const X86_BINARY: &str = "sha256:63a2f5ffe56c7c7ad0e21eba87e4dcf7ebd757bc376c16d534caaa2d82ac127b";
const ARM_ASSET: &str = "sha256:c3a3ca56a748d94fdaa1f208c641685d996ee1c4954cd4fbe358b7c06a2186a5";
const X86_ASSET: &str = "sha256:945b64728ae9021be49a70346424da7634d889f181f2d33af64c7bf95265f6d3";
const VOID_CHECKSUM: &str = "bf1a31caf5a37d644b05946ac69108e2b39917aa5c203fd33eaf5b99adf8d2d2";
const VOID_LATEST_CHECKSUM: &str =
    "6a02e4885ed3bc0f2de90ea6dd45ebcbb66dacffe03547fadbb0eeae2770887d";

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
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
        let base = std::env::var_os("LEGION_RUST_OUTDATED_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-rust-outdated-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        for dir in ["home", "tmp", "empty-path"] {
            fs::create_dir(path.join(dir)).unwrap();
        }
        Self(path)
    }
}

fn registry_spec() -> Value {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == PROVIDER)
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

fn binding(fixtures: &BTreeMap<String, String>) -> Value {
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
        "engine/rust-toolchain.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
    ] {
        walk(&root, &root.join(path), &mut sources);
    }
    let mut spec = registry_spec();
    spec.as_object_mut().unwrap().remove("benchmark");
    json!({"providerSpec":spec,"providerSpecDigest":digest(&canonical_bytes(&spec)),
        "sources":sources,"sourcesDigest":digest(&canonical_bytes(&json!(sources))),
        "fixtureSources":fixtures,"fixtureSourcesDigest":digest(&canonical_bytes(&json!(fixtures))),"fixture":SOURCE})
}

fn fixture_files(control: &str) -> BTreeMap<String, String> {
    let malformed = control == "analysis-error";
    let version = if control == "absence" {
        "1.0.2"
    } else {
        "1.0.1"
    };
    let checksum = if control == "absence" {
        VOID_LATEST_CHECKSUM
    } else {
        VOID_CHECKSUM
    };
    let root_manifest = if malformed {
        "[package\n"
    } else {
        // Exact pin stays non-empty in absence control while matching current latest.
        if version == "1.0.2" {
            "[package]\nname = \"outdated-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nvoid = \"=1.0.2\"\n"
        } else {
            "[package]\nname = \"outdated-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nvoid = \"=1.0.1\"\n"
        }
    };
    let lock = format!("# This file is manually generated from registry package metadata.\nversion = 4\n\n[[package]]\nname = \"outdated-probe\"\nversion = \"0.1.0\"\ndependencies = [\n \"void\",\n]\n\n[[package]]\nname = \"void\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n");
    let mut files = BTreeMap::from([
        ("Cargo.toml".into(), root_manifest.into()),
        ("Cargo.lock".into(), lock),
        ("src/lib.rs".into(), "pub fn value() {}\n".into()),
    ]);
    if control == "uncovered-lock" {
        files.insert(
            "extra/Cargo.lock".into(),
            "# independently selected lock fixture\nversion = 3\n".into(),
        );
    }
    files
}

fn write_fixture(root: &Path, control: &str) -> BTreeMap<String, String> {
    let files = fixture_files(control);
    for (relative, source) in &files {
        let file = root.join(relative);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, source).unwrap();
    }
    files
}

fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for e in fs::read_dir(path).unwrap() {
                walk(root, &e.unwrap().path(), files);
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
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
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
    plan: String,
    root: PathBuf,
    tool: PathBuf,
    tool_digest: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    profile: PathBuf,
    profile_text: String,
    args: Vec<String>,
    version_args: Vec<String>,
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
    fn wrapped(&self, suffix: &[String]) -> Vec<String> {
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
        json!({"id":POLICY,"version":1,"provider":PROVIDER,"task":CHECK,"plan":self.plan,"cwd":self.root,
            "artifactRequestId":"legion-audit/<64 lowercase hex>; one admission only","tool":{"path":self.tool,"digest":self.tool_digest},
            "wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},"profile":{"path":self.profile,"text":self.profile_text,"digest":digest(self.profile_text.as_bytes()),"receiptId":self.sandbox_id()},
            "args":self.args,"wrappedArgs":self.wrapped(&self.args),"versionArgs":self.wrapped(&self.version_args),"environment":self.environment,
            "environmentAllowlist":self.allowlist,"timeoutMs":120000,"stdoutLimit":8388608,"stderrLimit":8388608,
            "sandbox":"native-macos-allow-network-deny-project-write","acceptedExitCodes":[0]})
    }
    fn permits(&self, req: &ExternalToolRequest) -> bool {
        let artifact = req.request_id.strip_prefix("legion-audit/");
        req.schema_version == 1
            && artifact.is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            && req.provider_id == PROVIDER
            && req.plan_id == self.plan
            && req.policy_id == "audit"
            && req.task_id.as_deref() == Some(CHECK)
            && req.cwd == self.root.to_string_lossy().as_ref()
            && req.origin == ToolOrigin::TargetProject
            && !req.shell
            && req.requires_network_sandbox
            && req.sandbox.as_ref().is_some_and(|s| {
                s.id == self.sandbox_id()
                    && s.network
                    && s.filesystem_scope.as_deref() == self.root.to_str()
            })
            && !req.skip_version_probe
            && req.version_requirement.is_none()
            && req.executable == self.wrapper.to_string_lossy().as_ref()
            && req.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && fs::read(&self.wrapper).is_ok_and(|b| digest(&b) == self.wrapper_digest)
            && fs::read(&self.tool).is_ok_and(|b| digest(&b) == self.tool_digest)
            && !self.profile.is_symlink()
            && fs::read(&self.profile).is_ok_and(|b| b.as_slice() == self.profile_text.as_bytes())
            && req.args == self.wrapped(&self.args)
            && req.version_args == self.wrapped(&self.version_args)
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
    fn authorize(&self, req: &ExternalToolRequest) -> PolicyDecision {
        let mut decisions = self.decisions.lock().unwrap();
        let allowed = decisions.is_empty() && self.permits(req);
        decisions.push(json!({"allowed":allowed,"requestId":req.request_id,"providerId":req.provider_id,"planId":req.plan_id,
            "taskId":req.task_id,"executable":req.executable,"expectedDigest":req.expected_digest,"args":req.args,"versionArgs":req.version_args,
            "cwd":req.cwd,"environmentNames":req.environment.keys().collect::<Vec<_>>(),"environmentDigest":digest(&serde_json::to_vec(&req.environment).unwrap()),
            "timeoutMs":req.timeout_ms,"stdoutLimit":req.stdout_limit,"stderrLimit":req.stderr_limit,"acceptedExitCodes":req.accepted_exit_codes,
            "requiresNetworkSandbox":req.requires_network_sandbox,"sandbox":req.sandbox.as_ref().map(|s| json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope}))}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact constructed cargo-outdated fixture admission"
                } else {
                    "outside exact constructed cargo-outdated fixture policy"
                }
                .into(),
            ),
        }
    }
}
struct SharedPolicy(Arc<dyn PolicyAuthorizer>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, req: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(req)
    }
}

fn artifact(receipt: &Value, stream: &str, scratch: &AuditScratch) -> Vec<u8> {
    let item = &receipt[stream];
    assert_eq!(item["immutable"], true);
    let rel = Path::new(item["path"].as_str().unwrap());
    assert!(!rel.is_absolute());
    let root = fs::canonicalize(scratch.artifacts_dir()).unwrap();
    let path = fs::canonicalize(root.join(rel)).unwrap();
    assert!(path.starts_with(&root));
    let bytes = fs::read(path).unwrap();
    assert_eq!(item["digest"], digest(&bytes));
    assert_eq!(item["bytes"], bytes.len());
    bytes
}

fn case(base: &Path, control: &str, missing: bool) -> Value {
    let case_id = if missing { "missing-tool" } else { control }.to_owned();
    let case_root = base.join(&case_id);
    let root = case_root.join("source");
    let run = case_root.join("run");
    let fixture = write_fixture(&root, if missing { "absence" } else { control });
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec()).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-rust-outdated-fixture-key"))
        .unwrap();
    let provider = frozen
        .provider(PROVIDER)
        .expect("shipped rust-outdated provider selected");
    let denominator = inventory
        .denominator_entries(&provider.configuration["selector"])
        .unwrap();
    let selected: Vec<String> = denominator
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    assert!(!selected.is_empty(), "preserve shipped selector coverage");
    assert!(
        selected.iter().all(|path| path.ends_with("Cargo.lock")),
        "shipped selector remains lock-file scoped"
    );
    if control == "uncovered-lock" {
        assert_eq!(
            selected,
            vec!["Cargo.lock".to_owned(), "extra/Cargo.lock".to_owned()]
        );
    }
    let inventory_count = provider.configuration["denominatorCount"].as_u64().unwrap();
    assert_eq!(inventory_count, selected.len() as u64);
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    fs::create_dir_all(base.join("home/.cargo")).unwrap();
    if missing {
        let reject = Arc::new(RejectPolicy(Mutex::new(Vec::new())));
        let report = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { run_sdk(&root, &inventory, &frozen, scratch, reject.clone()).await })
            .unwrap();
        let result = &report.results[0].result;
        assert!(!result.complete && result.findings.is_empty());
        let receipt = result
            .details
            .get("executionReceipt")
            .cloned()
            .unwrap_or(Value::Null);
        assert_eq!(receipt["state"], "missing_executable");
        assert_eq!(receipt["complete"], false);
        assert!(receipt["stdout"].is_null() && receipt["stderr"].is_null());
        let coverage = result
            .coverage
            .as_ref()
            .expect("missing tool retains selected denominator");
        assert_eq!(coverage.expected, inventory_count);
        assert_eq!(coverage.examined, 0);
        assert!(
            reject.0.lock().unwrap().is_empty(),
            "missing executable resolves before authorization"
        );
        return json!({"provider":PROVIDER,"caseId":case_id,"control":"missing-tool","fixtureFiles":fixture,"fixtureSources":before,
            "inventory":inventory,"selectedPaths":selected,"coverage":result.coverage,"planDigest":frozen.digest(),"frozenPlan":frozen.plan(),"frozenProvider":provider,
            "expected":{"complete":false,"findingCount":0,"executionState":"missing_executable"},"matched":true,"actualStdout":Value::Null,"actualStderr":Value::Null,
            "retainedArtifacts":Value::Null,"nativeResult":result,"fullProviderResult":result,"executionReceipt":receipt,"toolIdentity":Value::Null,
            "policyDefinition":Value::Null,"policyDecisions":[],"locatorPrecision":"no tool execution; actual missing-executable SDK receipt retained"});
    }
    let toolchain = fs::canonicalize(
        std::env::var_os("LEGION_RUST_OUTDATED_TOOLCHAIN_BIN")
            .expect("pinned native Cargo toolchain bin required"),
    )
    .unwrap();
    let cargo = fs::canonicalize(toolchain.join("cargo")).expect("native Cargo required");
    assert!(cargo.starts_with(&toolchain));
    let cargo_bytes = fs::read(&cargo).unwrap();
    assert!(!cargo_bytes.starts_with(b"#!"));
    let cargo_output = Command::new(&cargo)
        .arg("--version")
        .current_dir(&root)
        .env("HOME", base.join("home"))
        .env("CARGO_HOME", base.join("home/.cargo"))
        .output()
        .unwrap();
    assert!(cargo_output.status.success());
    let cargo_stdout = String::from_utf8(cargo_output.stdout.clone()).unwrap();
    assert!(
        cargo_stdout.starts_with("cargo 1.98.0 "),
        "pinned native Cargo runtime required"
    );
    let cargo_runtime = json!({"path":cargo,"binarySha256":digest(&cargo_bytes),"versionStdout":cargo_stdout,"versionStderr":String::from_utf8_lossy(&cargo_output.stderr),"exitCode":cargo_output.status.code(),"signal":cargo_output.status.signal()});
    let args = vec!["--format".into(), "json".into(), "--root-deps-only".into()];
    let resolved =
        resolve_request(&root, "cargo-outdated", &args).expect("pinned cargo-outdated provisioned");
    assert_eq!(
        resolved.args,
        [vec!["outdated".into()], args.clone()].concat()
    );
    assert_eq!(resolved.cwd, root);
    let tool = fs::canonicalize(&resolved.executable).unwrap();
    assert!(!tool.starts_with(base));
    let tool_bytes = fs::read(&tool).unwrap();
    assert!(!tool_bytes.starts_with(b"#!"));
    assert_eq!(digest(&tool_bytes), resolved.digest);
    let arch = std::env::consts::ARCH;
    let (official_binary, official_asset) = match arch {
        "aarch64" => (ARM_BINARY, ARM_ASSET),
        "x86_64" => (X86_BINARY, X86_ASSET),
        _ => panic!("unsupported macOS architecture {arch}"),
    };
    assert_eq!(
        std::env::var("LEGION_RUST_OUTDATED_BINARY_SHA256").expect("binary digest pin required"),
        official_binary
    );
    assert_eq!(
        std::env::var("LEGION_RUST_OUTDATED_ASSET_SHA256").expect("asset digest pin required"),
        official_asset
    );
    assert_eq!(resolved.digest, official_binary);
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").expect("native macOS sandbox required");
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
    let version_args = vec!["outdated".into(), "--version".into()];
    let policy = Arc::new(ScopedPolicy {
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: resolved.digest.clone(),
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        profile,
        profile_text,
        args: resolved.args.clone(),
        version_args,
        environment,
        allowlist,
        decisions: Mutex::new(Vec::new()),
    });
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async {
            run_sdk(&root, &inventory, &frozen, scratch.clone(), policy.clone()).await
        })
        .unwrap();
    let result = &report.results[0].result;
    let receipt = &result.details["executionReceipt"];
    let stdout = artifact(receipt, "stdout", &scratch);
    let stderr = artifact(receipt, "stderr", &scratch);
    let stdout_text = std::str::from_utf8(&stdout).unwrap();
    let stderr_text = std::str::from_utf8(&stderr).unwrap();
    let retained_artifacts = retain_streams(control, &stdout, &stderr);
    assert_eq!(receipt["executable"]["version"]["qualified"], true);
    assert!(
        receipt["executable"]["version"]["output"]
            .as_str()
            .is_some_and(|version| version.contains("0.19.0")),
        "pinned cargo-outdated version required"
    );
    assert_eq!(receipt["planId"], frozen.digest());
    assert_eq!(receipt["providerId"], PROVIDER);
    assert_eq!(receipt["taskId"], CHECK);
    assert_eq!(receipt["cwd"], root.to_str().unwrap());
    assert_eq!(receipt["policy"]["allowed"], true);
    assert_eq!(receipt["policy"]["id"], POLICY);
    assert_eq!(
        receipt["policy"]["digest"],
        digest(&canonical_bytes(&policy.definition()))
    );
    assert_eq!(
        receipt["command"]["args"],
        json!(policy.wrapped(&policy.args))
    );
    assert_eq!(
        receipt["executable"]["canonicalPath"],
        policy.wrapper.to_str().unwrap()
    );
    assert_eq!(receipt["executable"]["digest"], policy.wrapper_digest);
    assert_eq!(receipt["sandbox"]["required"], true);
    assert_eq!(receipt["sandbox"]["networkEnabled"], true);
    assert_eq!(receipt["sandbox"]["receiptId"], policy.sandbox_id());
    assert_eq!(receipt["processTree"]["started"], true);
    assert_eq!(receipt["processTree"]["terminated"], true);
    assert_eq!(receipt["processTree"]["reaped"], true);
    assert!(receipt["signal"].is_null());
    assert_eq!(snapshot(&root), before);
    assert_eq!(digest(&fs::read(&tool).unwrap()), policy.tool_digest);
    let malformed = control == "analysis-error";
    let uncovered = control == "uncovered-lock";
    let json_report: Option<Value> = serde_json::from_str(stdout_text).ok();
    let dependencies = json_report
        .as_ref()
        .and_then(|report| report["dependencies"].as_array());
    let void = dependencies.and_then(|items| items.iter().find(|dep| dep["name"] == "void"));
    if control == "positive" || uncovered {
        let finding = void.expect("real cargo-outdated report lists outdated void dependency");
        assert_eq!(finding["project"], "1.0.1");
        assert_eq!(finding["latest"], "1.0.2");
        assert!(!result.findings.is_empty());
        if uncovered {
            assert!(!result.complete);
            assert!(result
                .coverage_gaps
                .iter()
                .any(|g| g == "cargo-outdated-lock-uncovered:extra/Cargo.lock"));
        } else {
            assert!(result.complete);
        }
    } else if control == "absence" {
        assert!(
            void.is_none(),
            "absence control must have no actual void row"
        );
        assert!(
            dependencies.is_some_and(|items| items.is_empty()),
            "actual cargo-outdated JSON must report no outdated dependencies"
        );
        assert!(result.complete && result.findings.is_empty());
    } else if malformed {
        assert!(!result.complete && result.findings.is_empty());
        assert_eq!(receipt["exitCode"], 1);
        assert_eq!(receipt["state"], "failed");
        assert_eq!(receipt["complete"], false);
        assert!(result.coverage_gaps.iter().any(|g| g == "failed"));
        assert!(result
            .coverage_gaps
            .iter()
            .any(|g| g == "cargo-outdated-input-unproven:manifest-unparseable"));
        assert!(result
            .coverage_gaps
            .iter()
            .any(|g| g == "legacy-tool-output-unparseable:cargo_outdated"));
    }
    assert_eq!(fixture_snapshot(&root), before);
    assert_eq!(result.coverage.as_ref().unwrap().expected, inventory_count);
    assert_eq!(
        result.coverage.as_ref().unwrap().examined,
        if uncovered {
            1u64
        } else if malformed {
            0u64
        } else {
            1u64
        }
    );
    if !malformed {
        let input = &result.details["rustOutdatedInput"];
        assert_eq!(input["cwd"], root.to_str().unwrap());
        assert_eq!(input["manifest"]["path"], "Cargo.toml");
        assert_eq!(
            input["manifest"]["digest"],
            digest(&fs::read(root.join("Cargo.toml")).unwrap())
        );
        assert_eq!(input["manifest"]["name"], "outdated-probe");
        assert_eq!(input["lock"]["path"], "Cargo.lock");
        assert_eq!(
            input["lock"]["digest"],
            digest(&fs::read(root.join("Cargo.lock")).unwrap())
        );
        assert_eq!(
            input["analysisScope"],
            "executed-root-package-direct-dependencies"
        );
        assert!(input["denominatorDigest"].as_str().is_some());
    }
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["allowed"], true);
    assert_eq!(decisions[0]["requestId"], receipt["requestId"]);
    assert_eq!(decisions[0]["args"], receipt["command"]["args"]);
    json!({"provider":PROVIDER,"caseId":case_id,"control":control,"fixtureFiles":fixture,"fixtureSources":before,
        "inventory":inventory,"selectedPaths":selected,"coverage":result.coverage,"planDigest":frozen.digest(),"frozenPlan":frozen.plan(),"frozenProvider":provider,
        "expected":{"complete":!malformed && !uncovered,"findingCount":if control == "positive" || uncovered {1}else{0},"actualReportDependencies":dependencies,
        "expectedListedPin":{"name":"void","project":if control == "absence" {"1.0.2"} else {"1.0.1"},"latest":"1.0.2"},"denominatorCount":inventory_count},"matched":true,
        "actualStdout":stdout_text,"actualStderr":stderr_text,"retainedArtifacts":retained_artifacts,"nativeResult":result,"fullProviderResult":result,"executionReceipt":receipt,
        "toolIdentity":{"path":tool,"binarySha256":resolved.digest,"version":receipt["executable"]["version"]["output"],"officialAssetSha256":official_asset,"officialBinarySha256":official_binary,"cargoRuntime":cargo_runtime},
        "policyDefinition":policy.definition(),"policyDecisions":*decisions,
        "rustOutdatedInput":result.details.get("rustOutdatedInput").cloned().unwrap_or(Value::Null),"locatorPrecision":"aggregate report; package identities use actual JSON rows; Cargo.lock line 1 is fallback anchor"})
}

fn retain_streams(control: &str, stdout: &[u8], stderr: &[u8]) -> Value {
    let retained = PathBuf::from(
        std::env::var_os("LEGION_RUST_OUTDATED_RECEIPTS").expect("retained directory required"),
    );
    fs::create_dir_all(retained.join(control)).unwrap();
    let mut streams = serde_json::Map::new();
    for (name, bytes) in [("stdout", stdout), ("stderr", stderr)] {
        let file = format!("{control}/{name}.log");
        fs::write(retained.join(&file), bytes).unwrap();
        streams.insert(
            name.into(),
            json!({"file":file,"bytes":bytes.len(),"sha256":digest(bytes)}),
        );
    }
    Value::Object(streams)
}

fn fixture_snapshot(root: &Path) -> BTreeMap<String, String> {
    snapshot(root)
}

struct RejectPolicy(Mutex<Vec<Value>>);
impl PolicyAuthorizer for RejectPolicy {
    fn authorize(&self, req: &ExternalToolRequest) -> PolicyDecision {
        self.0
            .lock()
            .unwrap()
            .push(json!({"requestId":req.request_id,"providerId":req.provider_id}));
        PolicyDecision {
            allowed: false,
            policy_id: "missing-tool-control".into(),
            policy_version: 1,
            policy_digest: digest(b"missing-tool-control"),
            reason: Some("missing-tool control must not reach authorization".into()),
        }
    }
}

async fn run_sdk(
    root: &Path,
    inventory: &legion_audit::InventoryEnvelope,
    frozen: &legion_audit::FrozenPlan,
    scratch: Arc<AuditScratch>,
    policy: Arc<dyn PolicyAuthorizer>,
) -> Result<legion_audit::ExecutionReport, legion_audit::AuditError> {
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
        SharedPolicy(policy.clone()),
    );
    let mut native = NativeProviderRegistry::new(root)
        .with_scratch(scratch)
        .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(effects)));
    native.legacy_checks = native.legacy_checks.with_fixture_policy_authorizer(policy);
    execute_with_cancellation(
        frozen,
        inventory,
        &native,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
}

#[test]
#[ignore = "constructed SDK qualification; requires pinned cargo-outdated 0.19.0, official asset pin & native macOS sandbox"]
fn real_rust_outdated_accuracy() {
    if let Some(base) = std::env::var_os("LEGION_RUST_OUTDATED_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        for control in ["positive", "absence", "analysis-error", "uncovered-lock"] {
            let value = case(&base, control, false);
            println!(
                "{}{}",
                String::from_utf8_lossy(CASE_MARKER),
                serde_json::to_string(&value).unwrap()
            );
        }
        return;
    }
    if let Some(base) = std::env::var_os("LEGION_RUST_OUTDATED_MISSING_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert!(std::env::var("PATH").unwrap_or_default().is_empty());
        let value = case(&base, "absence", true);
        println!(
            "{}{}",
            String::from_utf8_lossy(CASE_MARKER),
            serde_json::to_string(&value).unwrap()
        );
        return;
    }
    let fixture = Fixture::new();
    let retained = PathBuf::from(
        std::env::var_os("LEGION_RUST_OUTDATED_RECEIPTS")
            .expect("retained receipt directory required"),
    );
    assert!(retained.is_absolute());
    fs::create_dir_all(&retained).unwrap();
    let retained = fs::canonicalize(retained).unwrap();
    assert!(!retained.starts_with(&fixture.0));
    let exe = std::env::current_exe().unwrap();
    let toolchain = std::env::var_os("LEGION_RUST_OUTDATED_TOOLCHAIN_BIN")
        .expect("native Cargo toolchain bin required");
    let mut child_paths =
        std::env::split_paths(&std::env::var_os("PATH").expect("cargo-outdated on PATH"))
            .collect::<Vec<_>>();
    child_paths.insert(0, PathBuf::from(&toolchain));
    let mut child = Command::new(&exe);
    child
        .args([
            "--exact",
            "real_rust_outdated_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", std::env::join_paths(child_paths).unwrap())
        .env("HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("CARGO_HOME", fixture.0.join("home/.cargo"))
        .env(
            "RUSTUP_HOME",
            std::env::var_os("RUSTUP_HOME").unwrap_or_default(),
        )
        .env("LEGION_RUST_OUTDATED_CHILD", &fixture.0)
        .env("LEGION_RUST_OUTDATED_TOOLCHAIN_BIN", &toolchain)
        .env(
            "LEGION_RUST_OUTDATED_BINARY_SHA256",
            std::env::var("LEGION_RUST_OUTDATED_BINARY_SHA256").expect("binary pin required"),
        )
        .env(
            "LEGION_RUST_OUTDATED_ASSET_SHA256",
            std::env::var("LEGION_RUST_OUTDATED_ASSET_SHA256").expect("asset pin required"),
        )
        .env("LEGION_RUST_OUTDATED_RECEIPTS", &retained);
    let output = child.output().unwrap();
    retain_child(&retained, "child", &output);
    assert!(
        output.status.success(),
        "rust-outdated child failed; streams retained"
    );
    let mut missing = Command::new(&exe);
    missing
        .args([
            "--exact",
            "real_rust_outdated_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", "")
        .env("HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("CARGO_HOME", fixture.0.join("home/.cargo"))
        .env("LEGION_RUST_OUTDATED_MISSING_CHILD", &fixture.0)
        .env("LEGION_RUST_OUTDATED_RECEIPTS", &retained);
    let missing_output = missing.output().unwrap();
    retain_child(&retained, "missing-tool-child", &missing_output);
    assert!(
        missing_output.status.success(),
        "missing-tool child failed; streams retained"
    );
    let mut cases = parse_cases(&output.stdout);
    cases.extend(parse_cases(&missing_output.stdout));
    assert_eq!(cases.len(), 5);
    let matched = cases.iter().filter(|c| c["matched"] == true).count();
    assert_eq!(matched, 5, "actual native provider controls must match");
    let fixtures: BTreeMap<String, String> = cases
        .iter()
        .flat_map(|c| {
            c["fixtureSources"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(p, d)| {
                    (
                        format!("{}{p}", format!("{}/", c["caseId"].as_str().unwrap())),
                        d.as_str().unwrap().into(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let spec = registry_spec();
    let mut record = json!({"schema":"legion-rust-outdated-sdk-accuracy/1","kind":"rust-outdated-provider-constructed","productionQualification":false,
        "selfProducerQualification":false,"claimScope":"constructed-native-sdk-fixture","provider":PROVIDER,"providerVersion":spec["providerVersion"],"modelCalls":0,
        "executionPath":"native-sdk-frozen-plan-real-cargo-outdated","admissionScope":"explicit constructed SDK authorizer; no production CLI owner-admission claim",
        "test":"real_rust_outdated_accuracy","binding":binding(&fixtures),"cases":cases,
        "retainedChildProcess":[read_child(&retained,"child"),read_child(&retained,"missing-tool-child")],
        "metrics":{"cases":5,"matched":matched,"mismatched":5-matched},"status":"pass"});
    record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
    fs::write(
        retained.join("cargo_outdated.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    println!(
        "{}{}",
        String::from_utf8_lossy(MARKER),
        serde_json::to_string(&record).unwrap()
    );
}

fn parse_cases(stdout: &[u8]) -> Vec<Value> {
    stdout
        .split_inclusive(|b| *b == b'\n')
        .filter_map(|line| {
            line.windows(CASE_MARKER.len())
                .position(|w| w == CASE_MARKER)
                .map(|p| serde_json::from_slice(&line[p + CASE_MARKER.len()..]).unwrap())
        })
        .collect()
}
fn retain_child(dir: &Path, name: &str, output: &Output) {
    let stdout_name = format!("{name}.stdout.log");
    let stderr_name = format!("{name}.stderr.log");
    fs::write(dir.join(&stdout_name), &output.stdout).unwrap();
    fs::write(dir.join(&stderr_name), &output.stderr).unwrap();
    let status = json!({"schema":"legion-rust-outdated-child-execution/1","productionQualification":false,"status":{"success":output.status.success(),"exitCode":output.status.code(),"signal":output.status.signal(),"display":output.status.to_string()},
        "stdout":{"file":stdout_name,"bytes":output.stdout.len(),"sha256":digest(&output.stdout)},"stderr":{"file":stderr_name,"bytes":output.stderr.len(),"sha256":digest(&output.stderr)}});
    fs::write(
        dir.join(format!("{name}-execution.json")),
        serde_json::to_vec_pretty(&status).unwrap(),
    )
    .unwrap();
}
fn read_child(dir: &Path, name: &str) -> Value {
    serde_json::from_slice(&fs::read(dir.join(format!("{name}-execution.json"))).unwrap()).unwrap()
}
