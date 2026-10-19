//! Constructed native SDK/artifact controls, not production owner admission or
//! self-producing OpenGrep qualification. Runs only with pinned real host tool.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute,
    native_providers::{
        legacy_checks::{resolve_request, AuditExternalProjectTool},
        security::opengrep,
    },
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use legion_provider_sdk::ExternalProjectTool;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const SOURCE: &str = "engine/crates/legion-audit/tests/opengrep_accuracy.rs";
const GATE: &str = "scripts/ci/audit-opengrep-artifact-accuracy.py";
const RULE_SOURCE: &str = "src/registry/rules/opengrep/legion-core.yml";
const RULES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../src/registry/rules/opengrep/legion-core.yml"
));
const PROVIDER: &str = "security.opengrep";
const POLICY: &str = "legion-opengrep-sdk-artifact-fixture-v1";
const SCOPE: &str = "constructed-native-sdk-artifact-fixture";
const TIMEOUT: u64 = 30_000;
const LIMIT: usize = 4 * 1024 * 1024;
const SHELL: &str = "import os\nfrom flask import request\nos.system(request.args.get(\"cmd\"))\n";
const SQL: &str = "from flask import request\ndef query(cursor):\n    cursor.execute(request.args.get(\"sql\"))\n";
const CLEAN: &str = "import os\nfrom flask import request\ndef query(cursor):\n    supplied = request.args.get(\"value\")\n    print(supplied)\n    os.system(\"printf fixed\")\n    cursor.execute(\"SELECT 1\")\n";
const EXPECTATION_SOURCES: &[&str] = &[
    "https://github.com/opengrep/opengrep/releases/expanded_assets/v1.31.0",
    "https://raw.githubusercontent.com/opengrep/opengrep/v1.31.0/src/osemgrep/cli_scan/Scan_CLI.ml",
    "https://raw.githubusercontent.com/opengrep/opengrep/v1.31.0/src/osemgrep/networking/Rule_fetching.ml",
];
const IMPL_TREES: &[&str] = &[
    "engine/crates/legion-audit/src",
    "engine/crates/legion-effects/src",
    "engine/crates/legion-provider-sdk/src",
    "engine/crates/legion-contracts/src",
    "engine/crates/legion-rules/src",
    "src/registry/rules",
    "src/registry/controls",
];
const IMPL_FILES: &[&str] = &[
    "engine/Cargo.lock",
    "engine/Cargo.toml",
    "engine/crates/legion-audit/Cargo.toml",
    "engine/crates/legion-effects/Cargo.toml",
    "engine/crates/legion-provider-sdk/Cargo.toml",
    "engine/crates/legion-contracts/Cargo.toml",
    "engine/crates/legion-rules/Cargo.toml",
    SOURCE,
    GATE,
];

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
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
        .find(|p| p["id"] == PROVIDER)
        .unwrap()
        .clone();
    (serde_json::from_value(entry.clone()).unwrap(), entry)
}
fn pinned_digest() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "sha256:035dd8fd2410fe68513916df0c2895257fffafcd5314b4a118484ce8db62bedb"
    } else if cfg!(target_arch = "x86_64") {
        "sha256:2f0d0c7a41a3e48dc02c30dabc4851bc37c18f021b46c9ae54b15177ece088ee"
    } else {
        panic!("no pinned native OpenGrep asset for this architecture")
    }
}
fn sources(root: &Path) -> BTreeMap<String, String> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for child in fs::read_dir(path).unwrap() {
                visit(root, &child.unwrap().path(), out);
            }
        } else {
            out.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut out = BTreeMap::new();
    for path in IMPL_TREES.iter().chain(IMPL_FILES.iter()) {
        visit(root, &root.join(path), &mut out);
    }
    out
}
struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let parent = PathBuf::from(
            std::env::var_os("LEGION_OPENGREP_SCRATCH")
                .expect("explicit authorized scratch required"),
        );
        assert!(parent.is_absolute());
        let path = parent.join(format!(
            "opengrep-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        for child in ["source", "run", "run/home"] {
            fs::create_dir(path.join(child)).unwrap();
        }
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Only native fixture requests with exact tool bytes, command contract,
/// scrubbed environment, source bytes, frozen rules & authenticated profile.
struct ScopedPolicy {
    root: PathBuf,
    run: PathBuf,
    plan: String,
    inventory: String,
    source_digest: String,
    tool: PathBuf,
    wrapper: PathBuf,
    wrapper_digest: String,
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn definition(&self) -> Value {
        json!({"id": POLICY, "version": 1, "provider": PROVIDER, "scope": SCOPE,
            "root": self.root, "runDirectory": self.run, "planDigest": self.plan, "inventoryDigest": self.inventory,
            "sourceDigest": self.source_digest, "rulesDigest": digest(RULES.as_bytes()),
            "tool": {"path": self.tool, "digest": pinned_digest(), "versionRequirement": "exact:1.31.0"},
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest}, "args": self.args,
            "environment": self.environment, "timeoutMs": TIMEOUT, "outputLimit": LIMIT,
            "sandbox": "native-macos-deny-network-deny-project-write"})
    }
    fn permits(&self, request: &ExternalToolRequest) -> bool {
        if request.provider_id != PROVIDER
            || request.plan_id != self.plan
            || request.policy_id != POLICY
            || request.task_id.as_deref() != Some("opengrep-sdk-artifact")
            || request.cwd != self.root.to_string_lossy().as_ref()
            || request.origin != ToolOrigin::System
            || request.shell
            || !request.requires_network_sandbox
            || request.skip_version_probe
            || request.version_requirement.as_deref() != Some("exact:1.31.0")
            || request.timeout_ms != TIMEOUT
            || request.stdout_limit != LIMIT
            || request.stderr_limit != LIMIT
            || request.expected_digest.as_deref() != Some(self.wrapper_digest.as_str())
            || request.executable != self.wrapper.to_string_lossy().as_ref()
            || request.args.len() != self.args.len() + 4
            || request.args[0] != "-f"
            || request.args[2] != "--"
            || request.args[3] != self.tool.to_string_lossy().as_ref()
            || request.args[4..] != self.args
            || request.accepted_exit_codes != [0].into_iter().collect()
            || request.environment != self.environment
            || request.environment_allowlist != self.environment.keys().cloned().collect()
            || !request.sensitive_argument_indexes.is_empty()
            || !request.sensitive_environment_names.is_empty()
        {
            return false;
        }
        let mut version = request.args[..4].to_vec();
        version.push("--version".into());
        if request.version_args != version {
            return false;
        }
        let Some(sandbox) = request.sandbox.as_ref() else {
            return false;
        };
        let Ok(profile) = fs::canonicalize(&request.args[1]) else {
            return false;
        };
        if !profile.starts_with(&self.run)
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
        let expected = format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
        fs::read(&self.tool).ok().map(|b| digest(&b)).as_deref() == Some(pinned_digest())
            && fs::read(&self.wrapper).ok().map(|b| digest(&b)).as_deref()
                == Some(self.wrapper_digest.as_str())
            && fs::read(self.root.join("app.py"))
                .ok()
                .map(|b| digest(&b))
                .as_deref()
                == Some(self.source_digest.as_str())
            && fs::read(self.run.join("legion-core.yml")).ok().as_deref() == Some(RULES.as_bytes())
            && fs::read(profile).ok().as_deref() == Some(expected.as_bytes())
            && sandbox.id
                == format!(
                    "sandbox:macos:{}",
                    digest(expected.as_bytes()).trim_start_matches("sha256:")
                )
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let allowed = self.permits(request);
        self.decisions.lock().unwrap().push(
            json!({"allowed": allowed, "requestId": request.request_id,
            "args": request.args, "versionArgs": request.version_args, "planId": request.plan_id,
            "providerId": request.provider_id, "policyId": request.policy_id}),
        );
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&serde_json::to_vec(&self.definition()).unwrap()),
            reason: Some("constructed native SDK/artifact fixture only".into()),
        }
    }
}
struct SharedPolicy(Arc<ScopedPolicy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(request)
    }
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

fn case(id: &str, source: &str, expected: &[&str]) -> Value {
    let fixture = Fixture::new(id);
    let root = fixture.0.join("source");
    let run = fixture.0.join("run");
    fs::write(root.join("app.py"), source).unwrap();
    fs::write(run.join("legion-core.yml"), RULES).unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(id)
        .unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.entries[0].path, "app.py");
    assert_eq!(
        inventory.entries[0].digest.as_deref(),
        Some(digest(source.as_bytes()).as_str())
    );
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec().0])
        .unwrap()
        .freeze(Some(b"opengrep-sdk-artifact-fixture-key"))
        .unwrap();
    let provider = frozen.provider(PROVIDER).unwrap();
    assert_eq!(provider.configuration["denominatorCount"], 1);
    let tool = fs::canonicalize(
        resolve_request(&root, "opengrep", &[])
            .expect("real pinned OpenGrep required")
            .executable,
    )
    .unwrap();
    assert!(!tool.starts_with(&fixture.0));
    assert_eq!(digest(&fs::read(&tool).unwrap()), pinned_digest());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let wrapper_digest = digest(&fs::read(&wrapper).unwrap());
    let contract = opengrep::command_contract(
        tool.to_string_lossy(),
        run.join("output.json").to_string_lossy(),
        run.join("output.sarif").to_string_lossy(),
        run.join("legion-core.yml").to_string_lossy(),
        &["app.py".into()],
        root.to_string_lossy(),
        Some(&json!({"providerTimeoutMs":TIMEOUT,"maxOutputBytes":LIMIT})),
    );
    let environment: BTreeMap<String, String> = contract
        .environment_keys
        .iter()
        .filter_map(|key| match key.as_str() {
            "HOME" => Some((key.clone(), run.join("home").to_string_lossy().into_owned())),
            "PATH" => std::env::var(key).ok().map(|value| (key.clone(), value)),
            _ => None,
        })
        .collect();
    let policy = Arc::new(ScopedPolicy {
        root: root.clone(),
        run: run.clone(),
        plan: frozen.digest().into(),
        inventory: inventory.digest.clone(),
        source_digest: digest(source.as_bytes()),
        tool: tool.clone(),
        wrapper: wrapper.clone(),
        wrapper_digest: wrapper_digest.clone(),
        args: contract.args.clone(),
        environment: environment.clone(),
        decisions: Mutex::new(vec![]),
    });
    let auth = legion_effects::authenticate_sandbox(
        &contract.executable,
        &contract.args,
        &contract.cwd,
        legion_effects::SandboxMode::DenyNetworkDenyProjectWrite,
        &run.join("sandbox"),
    )
    .unwrap();
    let mut version_args = auth.wrapped_args[..4].to_vec();
    version_args.push("--version".into());
    let request = ExternalToolRequest {
        request_id: format!("opengrep-{id}"),
        provider_id: PROVIDER.into(),
        plan_id: frozen.digest().into(),
        policy_id: POLICY.into(),
        task_id: Some("opengrep-sdk-artifact".into()),
        executable: auth.wrapped_executable,
        args: auth.wrapped_args,
        version_args,
        cwd: contract.cwd.clone(),
        origin: ToolOrigin::System,
        expected_digest: Some(wrapper_digest),
        version_requirement: Some("exact:1.31.0".into()),
        environment_allowlist: environment.keys().cloned().collect(),
        environment,
        requires_network_sandbox: true,
        sandbox: Some(legion_effects::SandboxReceipt {
            id: auth.id,
            network: auth.network,
            filesystem_scope: auth.filesystem_scope,
        }),
        timeout_ms: contract.timeout_ms,
        stdout_limit: contract.max_output_bytes as usize,
        stderr_limit: contract.max_output_bytes as usize,
        ..ExternalToolRequest::default()
    };
    let artifacts = run.join("artifacts");
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(&artifacts),
        SharedPolicy(policy.clone()),
    );
    let receipt = tokio::runtime::Runtime::new().unwrap().block_on(
        AuditExternalProjectTool::new(effects)
            .execute(request, tokio_util::sync::CancellationToken::new()),
    );
    assert_eq!(
        receipt.state,
        legion_effects::ExecutionState::Completed,
        "{:?}",
        receipt.gaps
    );
    assert!(
        receipt.complete
            && receipt.process_tree.started
            && receipt.process_tree.terminated
            && receipt.process_tree.reaped
            && receipt.gaps.is_empty()
    );
    assert_eq!(receipt.exit_code, Some(0));
    let full_receipt = receipt_json(&receipt, &artifacts);
    let output_bytes =
        fs::read(run.join("output.json")).expect("actual native JSON output required");
    let sarif_bytes =
        fs::read(run.join("output.sarif")).expect("actual native SARIF output required");
    // Seal actual tool-written streams after successful native process termination.
    let writer = legion_effects::ArtifactWriter::new(run.join("retained-output"));
    let output_record = writer
        .write_immutable("output.json", &output_bytes)
        .unwrap();
    let sarif_record = writer
        .write_immutable("output.sarif", &sarif_bytes)
        .unwrap();
    let output: Value = serde_json::from_slice(&output_bytes).unwrap();
    let sarif: Value = serde_json::from_slice(&sarif_bytes).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert!(output["errors"].as_array().unwrap().is_empty(), "{output}");
    assert_eq!(output["paths"]["scanned"], json!(["app.py"]));
    let ruleset = opengrep::ruleset_identity(
        Some(run.join("legion-core.yml").to_str().unwrap()),
        Some(digest(RULES.as_bytes()).as_str()),
        None,
        Some(RULE_SOURCE),
        None,
    );
    let version = receipt
        .executable
        .as_ref()
        .unwrap()
        .version
        .output
        .as_deref()
        .unwrap();
    let candidates: Vec<Value> = output["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| {
            assert_eq!(raw["path"], "app.py");
            assert!(raw["start"]["line"].as_u64().is_some());
            let normalized =
                opengrep::normalize_finding(raw, Some(PROVIDER), Some(version), Some(&ruleset));
            opengrep::to_candidate(
                &normalized,
                Some(PROVIDER),
                Some(version),
                provider.configuration["denominatorDigest"].as_str(),
            )
        })
        .collect();
    let actual: Vec<String> = output["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| {
            format!(
                "{}|{}|{}",
                raw["check_id"].as_str().unwrap(),
                raw["path"].as_str().unwrap(),
                raw["start"]["line"].as_u64().unwrap()
            )
        })
        .collect();
    let expected: Vec<String> = expected.iter().map(|s| (*s).into()).collect();
    let tool_identity =
        json!({"name":"opengrep","version":version,"executableDigest":pinned_digest()});
    let mut evidence_receipt = full_receipt.clone();
    evidence_receipt["tool"] = tool_identity.clone();
    evidence_receipt["stdoutArtifact"] = full_receipt["stdout"].clone();
    evidence_receipt["jsonOutputArtifact"] =
        json!({"digest":output_record.digest,"bytes":output_record.bytes});
    let binding = json!({"repositoryRevision":inventory.generation,"digest":inventory.digest});
    let input = json!({"plan":{"binding":binding,"denominator":{"pathCount":1}},"projection":{"files":[{"path":"app.py"}]},"artifacts":{"opengrep":{"binding":binding,"denominator":{"digest":provider.configuration["denominatorDigest"],"expected":1,"examined":output["paths"]["scanned"].as_array().unwrap().len()},"ruleset":ruleset,"tool":tool_identity,"executionReceipt":evidence_receipt,"candidates":candidates}}});
    let mut registry = NativeProviderRegistry::new(&root);
    registry
        .security
        .artifacts
        .insert(PROVIDER.into(), input.clone());
    let execution = execute(&frozen, &inventory, &registry).unwrap();
    assert_eq!(execution.results.len(), 1);
    let result = &execution.results[0].result;
    assert!(
        result.complete
            && result.applicable
            && result.findings.is_empty()
            && result.coverage_gaps.is_empty()
            && result.degradation.is_empty(),
        "{result:?}"
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    assert_eq!(result.details["candidates"], json!(candidates));
    for candidate in &candidates {
        assert_eq!(candidate["verdict"], "UNADJUDICATED");
        assert_eq!(candidate["adjudicationRequired"], true);
    }
    assert_eq!(fs::read(root.join("app.py")).unwrap(), source.as_bytes());
    assert_eq!(
        fs::read(run.join("legion-core.yml")).unwrap(),
        RULES.as_bytes()
    );
    assert_eq!(digest(&fs::read(&tool).unwrap()), pinned_digest());
    // Genuine missing-artifact control uses the same frozen plan with no host
    // artifacts & no producer: it cannot acquire evidence from a caller flag.
    let mut missing_registry = NativeProviderRegistry::new(&root);
    missing_registry.security =
        legion_audit::native_providers::security::adapter::SecurityProviderExecutor::new(
            BTreeMap::new(),
        );
    let missing_execution = execute(&frozen, &inventory, &missing_registry).unwrap();
    let missing = &missing_execution.results[0].result;
    assert!(!missing.complete && missing.findings.is_empty());
    assert_eq!(
        missing.details["analysis"]["coverageGaps"],
        json!([{"kind":"opengrep-evidence-missing"}])
    );
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["allowed"], true);
    json!({"caseId":id,"source":{"path":"app.py","bytes":source,"digest":digest(source.as_bytes())},"expected":expected,"actual":actual,"controlMatched":actual==expected,
        "planDigest":frozen.digest(),"frozenPlan":frozen.plan(),"planSignature":frozen.signature(),"inventory":inventory,"providerConfiguration":provider.configuration,"policy":policy.definition(),"policyDecisions":*decisions,
        "actualExecutionReceipt":full_receipt,"jsonOutput":retained(writer.root(),&output_record),"sarifOutput":retained(writer.root(),&sarif_record),
        "actualArtifactInput":input,"actualProviderResult":result,"missingContextProviderResult":missing,"productionQualification":false,"executionPath":"native-sdk-command-contract-to-frozen-registry-artifact"})
}

#[test]
#[ignore = "requires official pinned OpenGrep 1.31.0 native binary & macOS sandbox"]
fn real_sdk_artifact_accuracy_opengrep() {
    // Fixed sink lines & shipped IDs, independently specified before execution.
    let cases = vec![
        case(
            "shell-planted",
            SHELL,
            &["legion-command-injection-shell|app.py|3"],
        ),
        case("sql-planted", SQL, &["legion-sql-interpolation|app.py|3"]),
        case("clean", CLEAN, &[]),
    ];
    let matched = cases.iter().all(|case| case["controlMatched"] == true);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let source_binding = sources(&root);
    let (_, mut provider) = spec();
    provider.as_object_mut().unwrap().remove("benchmark");
    let rules = json!({"path":RULE_SOURCE,"bytes":RULES,"digest":digest(RULES.as_bytes())});
    let (mut true_positives, mut false_positives, mut false_negatives) = (0usize, 0usize, 0usize);
    for case in &cases {
        let expected: BTreeSet<&str> = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        let actual = case["actual"].as_array().unwrap();
        let unique: BTreeSet<&str> = actual.iter().map(|s| s.as_str().unwrap()).collect();
        true_positives += expected.intersection(&unique).count();
        false_positives += unique.difference(&expected).count() + actual.len() - unique.len();
        false_negatives += expected.difference(&unique).count();
    }
    let mut record = json!({"schema":"legion-opengrep-sdk-artifact-accuracy/1","provider":PROVIDER,"stage":"candidate","scope":SCOPE,
        "productionQualification":false,"selfProducerQualification":false,"modelCalls":0,"qualificationEligible":matched,"status":if matched {"pass"} else {"fail"},
        "binding":{"providerSpec":provider,"harnessPath":SOURCE,"sources":source_binding,"sourcesDigest":digest(&serde_json::to_vec(&source_binding).unwrap()),"rules":rules},
        "expectationSources":EXPECTATION_SOURCES,"metrics":{"truePositives":true_positives,"falsePositives":false_positives,"falseNegatives":false_negatives,"positiveCases":2,"cleanCases":1},"cases":cases});
    record["qualificationDigest"] = json!(digest(&serde_json::to_vec(&record).unwrap()));
    let directory = PathBuf::from(
        std::env::var_os("LEGION_OPENGREP_RECEIPTS")
            .expect("explicit retained receipt directory required"),
    );
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("security_opengrep_sdk_artifact.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    println!(
        "OPENGREP_SDK_ARTIFACT_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
    assert!(matched, "exact shipped-rule controls must match");
}
