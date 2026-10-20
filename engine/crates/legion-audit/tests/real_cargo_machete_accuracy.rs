//! Actual cargo-machete controls through the frozen audit SDK provider path.
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

const SOURCE: &str = "engine/crates/legion-audit/tests/real_cargo_machete_accuracy.rs";
const POLICY: &str = "legion-real-cargo-machete-qualification-v1";
const PROVIDER: &str = "legacy.quality.rust-unused-deps";
const CHECK: &str = "cargo_unused_deps";
const MARKER: &[u8] = b"CARGO_MACHETE_PROVIDER_ACCURACY ";
const CASE_MARKER: &[u8] = b"CARGO_MACHETE_CASE ";
const ARM_BINARY: &str = "sha256:76ce4dc236df8204d8c110a4d1164a3abe8240fd622ab7016bf02f901d113167";
const X86_BINARY: &str = "sha256:e1cfbe4e076a040b6fa394f52e94a3895ff4078a1dd435ab5ed641f145a4815e";
const ARM_ASSET: &str = "sha256:72355383848acb154060e6fea2d5b7d58a825ed49fef157b46a6fe25180f8638";
const X86_ASSET: &str = "sha256:fd0c0dbcc9db0c1b8745fe9dc4f273d838b04391c6e487d1146957bf687a9703";

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
        let base = std::env::var_os("LEGION_CARGO_MACHETE_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-cargo-machete-{}-{}",
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
// Keep real fixture/run paths through the following live validator. CI runner-temp cleanup owns removal.

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

fn binding(fixtures: &BTreeMap<String, String>) -> Value {
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
    ] {
        source_binding_walk(&root, &root.join(path), &mut sources);
    }
    let mut spec = registry_spec();
    spec.as_object_mut().unwrap().remove("benchmark");
    json!({"providerSpec":spec,"providerSpecDigest":digest(&canonical_bytes(&spec)),
        "sources":sources,"sourcesDigest":digest(&canonical_bytes(&json!(sources))),
        "fixtureSources":fixtures,"fixtureSourcesDigest":digest(&canonical_bytes(&json!(fixtures))),"fixture":SOURCE})
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
        json!({"id":POLICY,"version":1,"provider":PROVIDER,"task":CHECK,"plan":self.plan,"cwd":self.root,
        "artifactRequestId":"legion-audit/<64 lowercase hex>; one admission only","tool":{"path":self.tool,"digest":self.tool_digest},
        "wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},"profile":{"path":self.profile,"text":self.profile_text,
        "digest":digest(self.profile_text.as_bytes()),"receiptId":self.sandbox_id()},"args":self.args,"wrappedArgs":self.wrapped_args(&self.args),
        "versionArgs":self.wrapped_args(&["--version".into()]),"environment":self.environment,"environmentAllowlist":self.allowlist,
        "timeoutMs":120000,"stdoutLimit":8388608,"stderrLimit":8388608,"sandbox":"native-macos-deny-network-production-linter-contract",
        "acceptedExitCodes":[0,1]})
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
            && req.args == self.wrapped_args(&self.args)
            && req.version_args == self.wrapped_args(&["--version".into()])
            && req.environment == self.environment
            && req.environment_allowlist == self.allowlist
            && req.sensitive_argument_indexes.is_empty()
            && req.sensitive_environment_names.is_empty()
            && req.timeout_ms == 120000
            && req.stdout_limit == 8388608
            && req.stderr_limit == 8388608
            && req.accepted_exit_codes == [0, 1].into_iter().collect()
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, req: &ExternalToolRequest) -> PolicyDecision {
        let mut decisions = self.decisions.lock().unwrap();
        let allowed = decisions.is_empty() && self.permits(req);
        decisions.push(json!({"allowed":allowed,"requestId":req.request_id,"providerId":req.provider_id,"planId":req.plan_id,
            "taskId":req.task_id,"executable":req.executable,"expectedDigest":req.expected_digest,"args":req.args,
            "versionArgs":req.version_args,"cwd":req.cwd,"environmentNames":req.environment.keys().collect::<Vec<_>>(),
            "environmentDigest":digest(&serde_json::to_vec(&req.environment).unwrap()),"timeoutMs":req.timeout_ms,"stdoutLimit":req.stdout_limit,
            "stderrLimit":req.stderr_limit,"acceptedExitCodes":req.accepted_exit_codes,"requiresNetworkSandbox":req.requires_network_sandbox,
            "sandbox":req.sandbox.as_ref().map(|s| json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope}))}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact constructed cargo-machete fixture admission"
                } else {
                    "outside exact constructed cargo-machete fixture policy"
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

fn fixture_files(control: &str) -> BTreeMap<String, String> {
    let manifest = match control { "analysis-error" => "[package\n", _ => "[package]\nname = \"machete-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nmachete-helper = { path = \"machete-helper\" }\n[workspace]\nmembers = [\"machete-helper\"]\n" };
    let lib = if control == "absence" {
        "pub fn value() -> u8 { machete_helper::value() }\n"
    } else {
        "pub fn value() -> u8 { 7 }\n"
    };
    // Match pinned Cargo's retained lock bytes before freezing the fixture;
    // metadata prepends these standard header lines when they are absent.
    [
        ("Cargo.toml", manifest),
        ("Cargo.lock", "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\n# This file is manually generated for offline fixture metadata.\nversion = 4\n\n[[package]]\nname = \"machete-helper\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"machete-probe\"\nversion = \"0.1.0\"\ndependencies = [\n \"machete-helper\",\n]\n"),
        (".cargo/config.toml", "[net]\noffline = true\n"), ("src/lib.rs", lib),
    ].into_iter().map(|(p,s)|(p.into(),s.into())).collect()
}
fn write_fixture(root: &Path, control: &str) -> BTreeMap<String, String> {
    let mut files = fixture_files(control);
    if control != "analysis-error" {
        files.insert(
            "machete-helper/Cargo.toml".into(),
            "[package]\nname = \"machete-helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                .into(),
        );
        files.insert(
            "machete-helper/src/lib.rs".into(),
            "pub fn value() -> u8 { 7 }\n".into(),
        );
    }
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
                walk(root, &e.unwrap().path(), files)
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

fn fixture_snapshot(root: &Path) -> BTreeMap<String, String> {
    snapshot(root)
}

fn case(base: &Path, control: &str, missing: bool) -> Value {
    let case_id = if missing {
        "missing-tool".to_owned()
    } else {
        control.to_owned()
    };
    let case_root = base.join(&case_id);
    let root = case_root.join("source");
    let run = case_root.join("run");
    let fixture = write_fixture(&root, if missing { "absence" } else { control });
    let before = fixture_snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec()).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-cargo-machete-fixture-key"))
        .unwrap();
    let provider = frozen
        .provider(PROVIDER)
        .expect("shipped cargo-machete provider selected");
    let denominator = inventory
        .denominator_entries(&provider.configuration["selector"])
        .unwrap();
    let selected: Vec<String> = denominator
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    assert!(!selected.is_empty(), "preserve shipped selector coverage");
    let inventory_count = provider.configuration["denominatorCount"].as_u64().unwrap();
    assert_eq!(inventory_count, selected.len() as u64);
    let args = vec!["--with-metadata".to_owned()];
    if missing {
        let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
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
        assert_eq!(
            receipt["state"], "missing_executable",
            "preserve only actual missing-tool receipt"
        );
        assert_eq!(receipt["complete"], false);
        assert!(receipt["stdout"].is_null() && receipt["stderr"].is_null());
        let coverage = result
            .coverage
            .as_ref()
            .expect("missing tool retains full selected denominator");
        assert_eq!(coverage.expected, inventory_count);
        assert_eq!(coverage.examined, 0);
        assert!(
            reject.0.lock().unwrap().is_empty(),
            "missing executable must be resolved before authorization"
        );
        return json!({"provider":PROVIDER,"caseId":case_id,"control":"missing-tool","fixtureFiles":fixture,
            "fixtureSources":before,"inventory":inventory,"selectedPaths":selected,"coverage":result.coverage,"planDigest":frozen.digest(),"frozenPlan":frozen.plan(),"frozenProvider":provider,
            "expected":{"complete":false,"findingCount":0,"executionState":"missing_executable"},"matched":true,
            "actualStdout":Value::Null,"actualStderr":Value::Null,"retainedArtifacts":Value::Null,
            "nativeResult":result,"fullProviderResult":result,"executionReceipt":receipt,"toolIdentity":Value::Null,
            "policyDefinition":Value::Null,"policyDecisions":[],"locatorPrecision":"no tool execution; actual missing-executable SDK failure receipt retained"});
    }
    let toolchain = fs::canonicalize(
        std::env::var_os("LEGION_CARGO_MACHETE_TOOLCHAIN_BIN")
            .expect("pinned native Cargo toolchain bin required"),
    )
    .unwrap();
    let cargo = fs::canonicalize(toolchain.join("cargo")).expect("native Cargo binary required");
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
    let cargo_runtime = json!({"path":cargo,"binarySha256":digest(&cargo_bytes),"versionStdout":cargo_stdout,
        "versionStderr":String::from_utf8_lossy(&cargo_output.stderr),"exitCode":cargo_output.status.code(),"signal":cargo_output.status.signal()});
    let resolved =
        resolve_request(&root, "cargo-machete", &args).expect("pinned cargo-machete provisioned");
    assert_eq!(resolved.args, args);
    assert_eq!(resolved.cwd, root);
    let tool = fs::canonicalize(&resolved.executable).unwrap();
    assert!(!tool.starts_with(base));
    let bytes = fs::read(&tool).unwrap();
    assert!(!bytes.starts_with(b"#!"));
    assert_eq!(digest(&bytes), resolved.digest);
    let arch = std::env::consts::ARCH;
    let (official_binary, official_asset) = match arch {
        "aarch64" => (ARM_BINARY, ARM_ASSET),
        "x86_64" => (X86_BINARY, X86_ASSET),
        _ => panic!("unsupported macOS architecture {arch}"),
    };
    assert_eq!(
        std::env::var("LEGION_CARGO_MACHETE_BINARY_SHA256").expect("binary SHA-256 required"),
        official_binary
    );
    assert_eq!(
        std::env::var("LEGION_CARGO_MACHETE_ASSET_SHA256")
            .expect("official asset SHA-256 required"),
        official_asset
    );
    assert_eq!(resolved.digest, official_binary);
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").expect("native macOS sandbox required");
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
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: resolved.digest.clone(),
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        profile,
        profile_text,
        args: args.clone(),
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
    let version = receipt["executable"]["version"]["output"].as_str().unwrap();
    assert_eq!(version.trim(), "0.9.1");
    assert_eq!(receipt["executable"]["version"]["qualified"], true);
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
        json!(policy.wrapped_args(&args))
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
    assert_eq!(fixture_snapshot(&root), before);
    assert_eq!(digest(&fs::read(&tool).unwrap()), policy.tool_digest);
    let retained_artifacts = retain_streams(control, &stdout, &stderr);
    let positive = control == "positive";
    let malformed = control == "analysis-error";
    if positive {
        assert_eq!(
            stderr_text,
            "Analyzing dependencies of crates in this directory...\nDone!\n"
        );
        let expected_stdout="cargo-machete found the following unused dependencies in this directory:\nmachete-probe -- ./Cargo.toml:\n\tmachete-helper\n\nIf you believe cargo-machete has detected an unused dependency incorrectly,\nyou can add the dependency to the list of dependencies to ignore in the\n`[package.metadata.cargo-machete]` section of the appropriate Cargo.toml.\nFor example:\n\n[package.metadata.cargo-machete]\nignored = [\"prost\"]\n\n";
        assert_eq!(stdout_text, expected_stdout);
        assert!(result.complete && result.applicable);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.details["findingsCount"], 1);
        let finding = serde_json::to_value(&result.findings[0]).unwrap();
        assert_eq!(finding["severity"], "low");
        let finding_id = result.findings[0].id.to_string();
        let evidence = &result.details["findingEvidence"][&finding_id];
        assert_eq!(evidence["ruleId"], "legacy.cargo_unused_deps.cargo-machete");
        assert_eq!(evidence["path"], selected[0]);
        assert_eq!(
            result.details["findingLocations"][&finding_id][0],
            format!("{}:1", selected[0])
        );
    } else if malformed {
        assert!(
            !result.complete,
            "malformed manifest must remain incomplete"
        );
        assert!(result.findings.is_empty());
        assert_eq!(result.details["findingsCount"], Value::Null);
        assert_eq!(receipt["exitCode"].as_i64(), Some(0));
        assert!(stderr_text.starts_with("Analyzing dependencies of crates in this directory...\nerror when handling ./Cargo.toml:"));
        assert!(stderr_text.ends_with("\nDone!\n"));
        assert_eq!(
            stdout_text,
            "cargo-machete didn't find any unused dependencies in this directory. Good job!\n"
        );
        assert!(result
            .coverage_gaps
            .iter()
            .any(|gap| gap == "cargo-machete-analysis-unproven"));
    } else {
        assert_eq!(
            stderr_text,
            "Analyzing dependencies of crates in this directory...\nDone!\n"
        );
        assert_eq!(
            stdout_text,
            "cargo-machete didn't find any unused dependencies in this directory. Good job!\n"
        );
        assert!(result.complete && result.applicable);
        assert!(result.findings.is_empty());
        assert!(
            result.details["findingsCount"].is_null(),
            "zero-as-null parser semantics"
        );
    }
    assert!(result.coverage_gaps.is_empty() || malformed);
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["allowed"], true);
    assert_eq!(decisions[0]["requestId"], receipt["requestId"]);
    assert_eq!(decisions[0]["args"], receipt["command"]["args"]);
    json!({"provider":PROVIDER,"caseId":case_id,"control":control,"fixtureFiles":fixture,"fixtureSources":before,
        "inventory":inventory,"selectedPaths":selected,"coverage":result.coverage,"planDigest":frozen.digest(),"frozenPlan":frozen.plan(),"frozenProvider":provider,
        "expected":{"complete":!malformed,"findingCount":usize::from(positive),"findingsCount":if positive {json!(1)}else{Value::Null},
            "ruleId":"legacy.cargo_unused_deps.cargo-machete","aggregateFallbackAnchor":selected[0]},
        "matched":true,"actualStdout":stdout_text,"actualStderr":stderr_text,"retainedArtifacts":retained_artifacts,
        "nativeResult":result,"fullProviderResult":result,
        "toolIdentity":{"path":tool,"binarySha256":resolved.digest,"version":version,"officialAssetSha256":official_asset,"officialBinarySha256":official_binary,
            "cargoRuntime":cargo_runtime},
        "policyDefinition":policy.definition(),"policyDecisions":*decisions,"executionReceipt":receipt,
        "locatorPrecision":"aggregate fallback anchor is first selected path, not exact diagnostic locus"})
}

fn retain_streams(case_id: &str, stdout: &[u8], stderr: &[u8]) -> Value {
    let root = PathBuf::from(
        std::env::var_os("LEGION_CARGO_MACHETE_RECEIPTS")
            .expect("shared retained evidence directory required"),
    );
    assert!(root.is_absolute());
    let dir = root.join(case_id);
    fs::create_dir_all(&dir).unwrap();
    let stdout_file = format!("{case_id}/stdout.log");
    let stderr_file = format!("{case_id}/stderr.log");
    fs::write(root.join(&stdout_file), stdout).unwrap();
    fs::write(root.join(&stderr_file), stderr).unwrap();
    json!({"stdout":{"file":stdout_file,"bytes":stdout.len(),"sha256":digest(stdout)},
        "stderr":{"file":stderr_file,"bytes":stderr.len(),"sha256":digest(stderr)}})
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
#[ignore = "constructed SDK qualification; requires pinned cargo-machete 0.9.1, official asset pin & native macOS sandbox"]
fn real_cargo_machete_accuracy() {
    if let Some(base) = std::env::var_os("LEGION_CARGO_MACHETE_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let cases: Vec<Value> = ["positive", "absence", "analysis-error"]
            .into_iter()
            .map(|control| case(&base, control, false))
            .collect();
        let fixtures: BTreeMap<String, String> = cases
            .iter()
            .flat_map(|c| {
                c["fixtureSources"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(p, d)| {
                        (
                            format!("{}/{p}", c["caseId"].as_str().unwrap()),
                            d.as_str().unwrap().into(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        for c in &cases {
            println!(
                "{}{}",
                String::from_utf8_lossy(CASE_MARKER),
                serde_json::to_string(c).unwrap()
            );
        }
        let _ = fixtures;
        return;
    }
    if let Some(base) = std::env::var_os("LEGION_CARGO_MACHETE_MISSING_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert!(std::env::var("PATH").unwrap_or_default().is_empty());
        let c = case(&base, "absence", true);
        println!(
            "{}{}",
            String::from_utf8_lossy(CASE_MARKER),
            serde_json::to_string(&c).unwrap()
        );
        return;
    }
    let fixture = Fixture::new();
    let retained = PathBuf::from(
        std::env::var_os("LEGION_CARGO_MACHETE_RECEIPTS")
            .expect("retained receipt directory required"),
    );
    assert!(retained.is_absolute());
    fs::create_dir_all(&retained).unwrap();
    let retained = fs::canonicalize(retained).unwrap();
    assert!(!retained.starts_with(&fixture.0));
    let exe = std::env::current_exe().unwrap();
    let mut normal_paths =
        std::env::split_paths(&std::env::var_os("PATH").expect("cargo-machete on PATH"))
            .collect::<Vec<_>>();
    let mut child = Command::new(&exe);
    child
        .args([
            "--exact",
            "real_cargo_machete_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env(
            "PATH",
            std::env::join_paths({
                let mut p = vec![PathBuf::from(
                    std::env::var_os("LEGION_CARGO_MACHETE_TOOLCHAIN_BIN")
                        .expect("native Cargo toolchain bin required"),
                )];
                p.extend(normal_paths.drain(..));
                p
            })
            .unwrap(),
        )
        .env("HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("CARGO_HOME", fixture.0.join("home/.cargo"))
        .env("LEGION_CARGO_MACHETE_CHILD", &fixture.0)
        .env(
            "LEGION_CARGO_MACHETE_TOOLCHAIN_BIN",
            std::env::var_os("LEGION_CARGO_MACHETE_TOOLCHAIN_BIN")
                .expect("native Cargo toolchain bin required"),
        )
        .env(
            "LEGION_CARGO_MACHETE_BINARY_SHA256",
            std::env::var("LEGION_CARGO_MACHETE_BINARY_SHA256")
                .expect("pinned binary SHA required"),
        )
        .env(
            "LEGION_CARGO_MACHETE_ASSET_SHA256",
            std::env::var("LEGION_CARGO_MACHETE_ASSET_SHA256")
                .expect("official asset SHA required"),
        )
        .env("LEGION_CARGO_MACHETE_RECEIPTS", &retained);
    let output = child.output().unwrap();
    retain_child(&retained, "child", &output);
    assert!(
        output.status.success(),
        "cargo-machete child failed; full streams retained"
    );
    let mut missing = Command::new(&exe);
    missing
        .args([
            "--exact",
            "real_cargo_machete_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", "")
        .env("HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("CARGO_HOME", fixture.0.join("home/.cargo"))
        .env("LEGION_CARGO_MACHETE_MISSING_CHILD", &fixture.0)
        .env("LEGION_CARGO_MACHETE_RECEIPTS", &retained);
    let missing_output = missing.output().unwrap();
    retain_child(&retained, "missing-tool-child", &missing_output);
    assert!(
        missing_output.status.success(),
        "missing-tool child failed; full streams retained"
    );
    let mut cases = parse_cases(&output.stdout);
    cases.extend(parse_cases(&missing_output.stdout));
    assert_eq!(cases.len(), 4);
    let matched = cases.iter().filter(|c| c["matched"] == true).count();
    assert_eq!(matched, 4, "actual native provider controls must match");
    let fixtures: BTreeMap<String, String> = cases
        .iter()
        .flat_map(|c| {
            c["fixtureSources"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(p, d)| {
                    (
                        format!("{}/{p}", c["caseId"].as_str().unwrap()),
                        d.as_str().unwrap().into(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let spec = registry_spec();
    let mut record = json!({"schema":"legion-cargo-machete-accuracy/1","kind":"cargo-machete-provider-constructed",
        "productionQualification":false,"selfProducerQualification":false,"claimScope":"constructed-native-sdk-fixture",
        "provider":PROVIDER,"providerVersion":spec["providerVersion"],"modelCalls":0,"executionPath":"native-sdk-frozen-plan-real-cargo-machete",
        "admissionScope":"explicit constructed SDK authorizer; no production CLI owner-admission claim","binding":binding(&fixtures),"cases":cases,
        "retainedChildProcess":[serde_json::from_slice::<Value>(&fs::read(retained.join("child-execution.json")).unwrap()).unwrap(),
            serde_json::from_slice::<Value>(&fs::read(retained.join("missing-tool-child-execution.json")).unwrap()).unwrap()],
        "metrics":{"cases":4,"matched":matched,"mismatched":4-matched},"status":"pass"});
    record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
    fs::write(
        retained.join("cargo_unused_deps.json"),
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
    let status = json!({"schema":"legion-cargo-machete-child-execution/1","productionQualification":false,
        "status":{"success":output.status.success(),"exitCode":output.status.code(),"signal":output.status.signal(),"display":output.status.to_string()},
        "stdout":{"file":stdout_name,"bytes":output.stdout.len(),"sha256":digest(&output.stdout)},
        "stderr":{"file":stderr_name,"bytes":output.stderr.len(),"sha256":digest(&output.stderr)}});
    fs::write(
        dir.join(format!("{name}-execution.json")),
        serde_json::to_vec_pretty(&status).unwrap(),
    )
    .unwrap();
}
