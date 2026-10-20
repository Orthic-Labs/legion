//! Candidate to integrate as engine/crates/legion-audit/tests/ast_grep_accuracy.rs.
//! Constructed fixture evidence only; CI must run this ignored test on macOS.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute,
    native_providers::{
        security::{ast_grep, SecurityProviderExecutor},
        NativeProviderRegistry,
    },
    AuditPlan, FilesystemInventorySource, InventorySource, ProviderExecutor,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const ID: &str = "structural.ast-grep";
const POLICY_ID: &str = "legion-ast-grep-fixture-accuracy-v1";
const SOURCE: &str = "engine/crates/legion-audit/tests/ast_grep_accuracy.rs";

fn sha(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

// serde_json/preserve_order is enabled workspace-wide. Match Python's recursive
// sorted-key, compact UTF-8 encoding instead of hashing registry insertion order.
fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort();
                let mut sorted = serde_json::Map::new();
                for key in keys {
                    sorted.insert(key.clone(), ordered(&object[key]));
                }
                Value::Object(sorted)
            }
            Value::Array(array) => Value::Array(array.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).unwrap()
}

struct Policy {
    provider: String,
    plan: String,
    root: PathBuf,
    tool: PathBuf,
    tool_digest: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    args: Vec<String>,
    version_args: Vec<String>,
    sandbox: legion_effects::SandboxReceipt,
    environment: BTreeMap<String, String>,
    decisions: Mutex<Vec<Value>>,
}
impl PolicyAuthorizer for Policy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let accepted: BTreeSet<i32> = [0, 1].into_iter().collect();
        let allowed = request.provider_id == self.provider
            && request.plan_id == self.plan
            && request.policy_id == legion_audit::execution_policy::POLICY_ID
            && request.task_id.as_deref() == Some("ast-grep")
            && request.cwd == self.root.to_string_lossy()
            && request.origin == ToolOrigin::System
            && !request.shell
            && request.executable == self.wrapper.to_string_lossy()
            && request.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && request.args == self.args
            && request.version_args == self.version_args
            && request.accepted_exit_codes == accepted
            && request.requires_network_sandbox
            && !request.skip_version_probe
            && request.version_requirement.is_none()
            && request.sandbox.as_ref() == Some(&self.sandbox)
            && request.environment == self.environment
            && request.environment_allowlist == self.environment.keys().cloned().collect()
            && request.sensitive_argument_indexes.is_empty()
            && request.sensitive_environment_names.is_empty()
            && request.timeout_ms == 30_000
            && request.stdout_limit == 1_048_576
            && request.stderr_limit == 1_048_576
            && fs::canonicalize(&self.tool).ok().as_ref() == Some(&self.tool)
            && fs::read(&self.tool).ok().as_deref().map(sha) == Some(self.tool_digest.clone());
        self.decisions.lock().unwrap().push(json!({"allowed":allowed,"providerId":request.provider_id,
            "planId":request.plan_id,"cwd":request.cwd,"executable":request.executable,
            "expectedDigest":request.expected_digest,"args":request.args,"versionArgs":request.version_args,
            "sandbox":request.sandbox.as_ref().map(|s|json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope})),
            "environmentKeys":request.environment.keys().collect::<Vec<_>>() }));
        PolicyDecision {
            allowed,
            policy_id: POLICY_ID.into(),
            policy_version: 1,
            policy_digest: sha(b"exact fixture-only ast-grep command policy v1"),
            reason: Some("one exact fixture-rooted ast-grep command".into()),
        }
    }
}
struct SharedPolicy(Arc<Policy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(request)
    }
}

fn provider_spec() -> ProviderSpec {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    serde_json::from_value(
        registry["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == ID)
            .unwrap()
            .clone(),
    )
    .unwrap()
}

// Generated host receipts are runtime evidence, never implementation inputs.
// Match one exact repository-relative directory & lowercase SHA-256 JSON name.
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
            sha(&fs::read(path).unwrap()),
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
        Some(&sha(b"retained nested source\n"))
    );
    fs::write(&nested, b"changed nested source\n").unwrap();
    assert_eq!(
        snapshot(root).get(&nested_key),
        Some(&sha(b"changed nested source\n"))
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
        assert_eq!(before.get(&key), Some(&sha(b"retained source\n")), "{relative}");
        fs::write(&path, b"changed retained source\n").unwrap();
        let changed = snapshot(root);
        assert_eq!(changed.get(&key), Some(&sha(b"changed retained source\n")), "{relative}");
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

fn source_binding(root: &Path) -> Value {
    let roots = [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
        "engine/crates/legion-audit/tests/fixtures/ast-grep",
    ];
    let mut files = BTreeMap::new();
    for path in roots {
        source_binding_walk(root, &root.join(path), &mut files);
    }
    for path in [
        SOURCE,
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
    ] {
        source_binding_walk(root, &root.join(path), &mut files);
    }
    let registry: Value =
        serde_json::from_slice(&fs::read(root.join("src/registry/providers.json")).unwrap())
            .unwrap();
    let mut spec = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == ID)
        .unwrap()
        .clone();
    spec.as_object_mut().unwrap().remove("benchmark");
    let provider_spec_digest = sha(&canonical_bytes(&spec));
    json!({"repositoryRoot":fs::canonicalize(root).unwrap(),"roots":roots,"files":files,"providerSpec":spec,"providerSpecDigest":provider_spec_digest})
}

fn artifact_text(root: &Path, receipt: &Option<legion_effects::ArtifactRecord>) -> String {
    let record = receipt.as_ref().expect("actual SDK stream artifact");
    let bytes = fs::read(root.join(&record.path)).unwrap();
    assert_eq!(bytes.len(), record.bytes);
    assert_eq!(sha(&bytes), record.digest);
    String::from_utf8(bytes).unwrap()
}

fn run_case(kind: &str, fixture: &Path, planted: bool) -> Value {
    let root = fs::canonicalize(fixture).unwrap();
    let run = PathBuf::from(std::env::var_os("LEGION_AST_GREP_RUN_DIR").unwrap()).join(kind);
    fs::create_dir_all(&run).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(kind)
        .unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[provider_spec()])
        .unwrap()
        .freeze(Some(b"ast-grep-accuracy-fixture-key"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    let selected = inventory
        .denominator_entries(&provider.configuration["selector"])
        .unwrap();
    let mut paths = selected
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(
        paths,
        [
            "rules/no-console-error-leak.yml",
            "rules/no-inner-html.yml",
            "sgconfig.yml",
            "src/probe.ts"
        ]
    );
    let expected_asset = std::env::var("LEGION_AST_GREP_ASSET_SHA256").unwrap();
    assert!(matches!(
        expected_asset.as_str(),
        "sha256:e18e13c27ed6c4b3ec4de00745b0755dee9dc26c035e226f4dd5d147dca99cc8"
            | "sha256:8438fe549da59da28518c45bdaab5b851aabafe8fb4f8dc05c261a7649b4eca6"
    ));
    let tool = fs::canonicalize(std::env::var_os("LEGION_AST_GREP_BIN").unwrap()).unwrap();
    assert!(!tool.starts_with(&root));
    let tool_bytes = fs::read(&tool).unwrap();
    assert!(
        !tool_bytes.starts_with(b"#!"),
        "script substitutes are not a native ast-grep binary"
    );
    let tool_digest = sha(&tool_bytes);
    let contract = ast_grep::command_contract(
        tool.to_string_lossy(),
        "sgconfig.yml",
        &paths,
        root.to_string_lossy(),
        Some(&json!({"providerTimeoutMs":30000,"maxOutputBytes":1048576})),
    );
    let auth = legion_effects::authenticate_sandbox(
        &contract.executable,
        &contract.args,
        &contract.cwd,
        legion_effects::SandboxMode::DenyNetworkDenyProjectWrite,
        &run.join("sandbox"),
    )
    .unwrap();
    let wrapper = fs::canonicalize(&auth.wrapped_executable).unwrap();
    let wrapper_digest = sha(&fs::read(&wrapper).unwrap());
    let mut args = auth.wrapped_args.clone();
    let mut version_args = args[..4].to_vec();
    version_args.push("--version".into());
    let environment: BTreeMap<String, String> = ["PATH", "HOME", "TEMP", "TMP"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok().map(|value| (key.into(), value)))
        .collect();
    let sandbox = legion_effects::SandboxReceipt {
        id: auth.id,
        network: auth.network,
        filesystem_scope: auth.filesystem_scope,
    };
    let policy = Arc::new(Policy {
        provider: ID.into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool,
        tool_digest: tool_digest.clone(),
        wrapper,
        wrapper_digest,
        args: args.clone(),
        version_args: version_args.clone(),
        sandbox: sandbox.clone(),
        environment: environment.clone(),
        decisions: Mutex::new(Vec::new()),
    });
    let request = ExternalToolRequest {
        request_id: format!("ast-grep-accuracy-{kind}"),
        provider_id: ID.into(),
        plan_id: frozen.digest().into(),
        policy_id: legion_audit::execution_policy::POLICY_ID.into(),
        task_id: Some("ast-grep".into()),
        executable: auth.wrapped_executable,
        args: std::mem::take(&mut args),
        version_args,
        cwd: root.to_string_lossy().into_owned(),
        origin: ToolOrigin::System,
        shell: false,
        expected_digest: Some(policy.wrapper_digest.clone()),
        accepted_exit_codes: [0, 1].into_iter().collect(),
        environment: environment.clone(),
        environment_allowlist: environment.keys().cloned().collect(),
        requires_network_sandbox: true,
        sandbox: Some(sandbox),
        timeout_ms: 30_000,
        stdout_limit: 1_048_576,
        stderr_limit: 1_048_576,
        ..ExternalToolRequest::default()
    };
    let artifacts_dir = run.join("artifacts");
    fs::create_dir_all(&artifacts_dir).unwrap();
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(&artifacts_dir),
        SharedPolicy(policy.clone()),
    );
    let receipt = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(effects.execute(&request));
    assert!(receipt.is_complete(), "SDK receipt: {receipt:?}");
    assert!(receipt.process_tree.started && receipt.process_tree.reaped);
    let stdout = artifact_text(&artifacts_dir, &receipt.stdout);
    let stderr = artifact_text(&artifacts_dir, &receipt.stderr);
    let version = receipt
        .executable
        .as_ref()
        .unwrap()
        .version
        .output
        .as_deref()
        .unwrap_or_default();
    assert!(
        version.contains("0.51.0"),
        "actual version output: {version}"
    );
    let stream: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    // Pinned ast-grep 0.51.0 reports error-level matches as DiagnosticError:
    // completed JSON output, exit 1 & this exact non-TTY stderr summary.
    // Configuration, parse, traversal & other errors must never pass here.
    for row in &stream {
        let expected_severity = match row.get("ruleId").and_then(Value::as_str) {
            Some("no-console-error-leak") => "warning",
            Some("no-inner-html") => "error",
            _ => panic!("unexpected raw scanner rule: {row}"),
        };
        assert_eq!(
            row.get("severity").and_then(Value::as_str),
            Some(expected_severity)
        );
    }
    let error_count = stream
        .iter()
        .filter(|row| row.get("severity").and_then(Value::as_str) == Some("error"))
        .count();
    let expected_stderr = if error_count == 0 {
        String::new()
    } else {
        format!("Error: {error_count} error(s) found in code.\nHelp: Scan succeeded and found error level diagnostics in the codebase.\n\n")
    };
    assert_eq!(
        receipt.exit_code,
        Some(if error_count == 0 { 0 } else { 1 })
    );
    assert_eq!(stderr, expected_stderr, "unexpected actual stderr");
    let matches = stream
        .into_iter()
        .map(|mut row| {
            if let Some(file) = row.get("file").and_then(Value::as_str) {
                let path = Path::new(file);
                let relative = path
                    .strip_prefix(&root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/");
                row["file"] = json!(relative.strip_prefix("./").unwrap_or(&relative));
            }
            for edge in ["start", "end"] {
                let pointer = format!("/range/{edge}/line");
                let line = row.pointer(&pointer).and_then(Value::as_u64);
                if let Some(line) = line {
                    row["range"][edge]["line"] = json!(line + 1);
                }
            }
            row
        })
        .collect::<Vec<_>>();
    let normalized = ast_grep::normalize_stream(&matches, "ast-grep.rule");
    let supported_extensions = [
        "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "java", "c", "h", "cpp", "cc",
        "cxx", "hpp", "cs", "rb", "php", "swift", "kt", "kts", "scala", "lua", "sh", "bash",
        "html", "css", "json", "yaml", "yml", "ex", "exs", "nix",
    ];
    let unsupported_grammars = paths
        .iter()
        .filter_map(|path| {
            Path::new(path)
                .extension()
                .and_then(|ext| ext.to_str())
                .filter(|ext| !supported_extensions.contains(ext))
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    assert!(unsupported_grammars.is_empty());
    let artifacts = json!({"astGrepTool":{"name":"ast-grep","version":version.trim(),"executableDigest":tool_digest},
        "examinedPaths":paths,"unsupportedGrammars":unsupported_grammars,"structuralMatches":normalized});
    let provider_input = json!({"plan":{"binding":{"repositoryRevision":inventory.generation,"digest":inventory.digest},
            "denominator":{"pathCount":paths.len()}},
        "projection":{"files":paths.iter().map(|path|json!({"path":path})).collect::<Vec<_>>()},
        "artifacts":artifacts,"producer":{"mode":"fixture-sdk-command","sdkReceiptId":receipt.receipt_id}});
    let mut native = NativeProviderRegistry::new(&root);
    native.security = SecurityProviderExecutor::new(BTreeMap::from([(ID.into(), provider_input)]));
    let report = execute(&frozen, &inventory, &native).unwrap();
    assert_eq!(report.planned_providers, vec![ID]);
    assert_eq!(report.results.len(), 1);
    assert!(!report.results[0].skipped);
    let result = &report.results[0].result;
    assert!(
        result.applicable && result.complete,
        "native provider result: {result:?}"
    );
    assert!(result.coverage_gaps.is_empty() && result.degradation.is_empty());
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (4, 4));
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    assert!(result.findings.is_empty());
    let mut actual = result.details["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|candidate| {
            format!(
                "{}|{}|{}",
                candidate["ruleId"].as_str().unwrap(),
                candidate["file"].as_str().unwrap(),
                candidate
                    .pointer("/range/start/line")
                    .unwrap()
                    .as_u64()
                    .unwrap()
            )
        })
        .collect::<Vec<_>>();
    actual.sort();
    let expected = if planted {
        vec![
            "no-console-error-leak|src/probe.ts|2".to_owned(),
            "no-inner-html|src/probe.ts|4".to_owned(),
        ]
    } else {
        vec![]
    };
    assert_eq!(actual, expected);
    let policy_decisions = policy.decisions.lock().unwrap().clone();
    assert_eq!(policy_decisions.len(), 1);
    assert!(policy_decisions
        .iter()
        .all(|decision| decision["allowed"] == true));
    let profile_path = fs::read_dir(run.join("sandbox"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "sb"))
        .unwrap();
    let profile_raw = fs::read(&profile_path).unwrap();
    let profile = String::from_utf8(profile_raw.clone()).unwrap();
    assert!(profile.contains("(deny network*)") && profile.contains("(deny file-write*"));
    let wrapper_identity = receipt.executable.as_ref().unwrap();
    assert_eq!(wrapper_identity.requested_path, "/usr/bin/sandbox-exec");
    assert_eq!(
        wrapper_identity.canonical_path.as_deref(),
        Some(policy.wrapper.as_path())
    );
    assert_eq!(
        wrapper_identity.digest.as_deref(),
        Some(policy.wrapper_digest.as_str())
    );
    assert_eq!(
        fs::read(&policy.tool).ok().as_deref().map(sha),
        Some(tool_digest.clone())
    );
    let sdk_receipt = json!({"schemaVersion":receipt.schema_version,
        "wrapperIdentity":{"requestedPath":"/usr/bin/sandbox-exec","canonicalPath":policy.wrapper,"digest":policy.wrapper_digest},"state":receipt.state.as_str(),"complete":receipt.complete,
        "receiptId":receipt.receipt_id,"requestId":receipt.request_id,"providerId":receipt.provider_id,"planId":receipt.plan_id,
        "policyId":receipt.policy_id,"taskId":receipt.task_id,"cwd":receipt.cwd,
        "policy":receipt.policy.as_ref().map(|p|json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "executable":receipt.executable.as_ref().map(|e|json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,
            "digest":e.digest,"digestState":format!("{:?}",e.digest_state),"signature":format!("{:?}",e.signature),
            "version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,
                "qualified":e.version.qualified,"skippedByPolicy":e.version.skipped_by_policy}})),
        "command":receipt.command.as_ref().map(|c|json!({"executable":c.executable,"args":c.args,
            "environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,
            "redactedEnvironmentNames":c.redacted_environment_names})),
        "environmentNames":receipt.environment_names,
        "sandbox":{"required":receipt.sandbox.required,"networkEnabled":receipt.sandbox.network_enabled,
            "receiptId":receipt.sandbox.receipt_id,"profilePath":profile_path,"profileRaw":profile,
            "profileDigest":sha(&profile_raw)},
        "processTree":{"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,
            "hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing":{"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode":receipt.exit_code,"signal":receipt.signal,
        "parser":{"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error},
        "gaps":receipt.gaps,
        "stdout":{"path":receipt.stdout.as_ref().unwrap().path,"raw":stdout,"digest":receipt.stdout.as_ref().unwrap().digest,
            "bytes":receipt.stdout.as_ref().unwrap().bytes,"immutable":receipt.stdout.as_ref().unwrap().immutable},
        "stderr":{"path":receipt.stderr.as_ref().unwrap().path,"raw":stderr,"digest":receipt.stderr.as_ref().unwrap().digest,
            "bytes":receipt.stderr.as_ref().unwrap().bytes,"immutable":receipt.stderr.as_ref().unwrap().immutable}});
    json!({"id":kind,"fixtureRoot":root,"expected":expected,"actual":actual,"streamParsing":{"attempted":true,"succeeded":true,"rowCount":matches.len()},
        "commandContract":{"executable":contract.executable,"args":contract.args,"cwd":contract.cwd,
            "timeoutMs":contract.timeout_ms,"maxOutputBytes":contract.max_output_bytes,"environmentKeys":contract.environment_keys},
        "policyDecisions":policy_decisions,"coverage":{"expected":coverage.expected,"examined":coverage.examined,
        "denominatorDigest":coverage.denominator_digest,"gaps":coverage.gaps},
        "fixtureFiles":paths.iter().map(|p|json!({"path":p,"text":fs::read_to_string(root.join(p)).unwrap()})).collect::<Vec<_>>(),
        "fixtureSourceDigests":paths.iter().map(|p|json!({"path":p,"digest":sha(&fs::read(root.join(p)).unwrap())})).collect::<Vec<_>>(),
        "unsupportedGrammars":artifacts["unsupportedGrammars"],
        "providerResult":result,"sdkReceipt":sdk_receipt,"astGrepArtifacts":artifacts,"assetDigest":expected_asset,
        "tool":{"versionToken":"0.51.0","rawVersionStdout":version,"executablePath":policy.tool,"executableDigest":tool_digest,"assetDigest":expected_asset}})
}

#[test]
#[ignore = "requires official hash-verified ast-grep 0.51.0 & authenticated macOS deny-network sandbox"]
fn real_ast_grep_accuracy() {
    let root = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")).unwrap();
    let fixtures = fs::canonicalize(PathBuf::from(
        std::env::var_os("LEGION_AST_GREP_FIXTURES").expect("CI fixture directory"),
    ))
    .unwrap();
    assert_eq!(
        fixtures,
        root.join("engine/crates/legion-audit/tests/fixtures/ast-grep")
    );
    let planted = run_case("planted", &fixtures.join("planted"), true);
    let clean = run_case("clean", &fixtures.join("clean"), false);
    let record = json!({"schema":"legion-ast-grep-accuracy/1","providerId":ID,
        "claimScope":"constructed-native-sdk-artifact-fixture","productionQualification":false,"selfProducerQualification":false,
        "tool":planted["tool"],"sourceBinding":source_binding(&root),"cases":[planted,clean]});
    println!(
        "AST_GREP_PROVIDER_ACCURACY={}",
        serde_json::to_string(&record).unwrap()
    );
    let path = std::env::var_os("LEGION_AST_GREP_RECORD").expect("CI output path");
    fs::write(path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
}
