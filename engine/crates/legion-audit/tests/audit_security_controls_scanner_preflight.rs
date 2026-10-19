//! Genuine self-producing scanner prerequisite for retained lifecycle controls.
//! Fixture-only SDK admission; no public owner admission or model qualification.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute_with_cancellation,
    native_providers::{
        legacy_checks::resolve_request, reasoning::scanner_candidates_from_execution,
        security::producer::ArtifactProducer,
    },
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

const PROVIDER: &str = "security.opengrep";
const RULE: &str = "qualification-command-shell";
const POLICY: &str = "legion-security-controls-scanner-fixture-v1";
const CORPUS: &str = "scripts/ci/fixtures/audit-security-controls";
const TIMEOUT: u64 = 120_000;
const LIMIT: usize = 8 * 1024 * 1024;
const FILES: [&str; 4] = [".semgrep.yml", "literal.py", "seed.py", "variant.py"];
const PYTHON: [&str; 3] = ["literal.py", "seed.py", "variant.py"];
const CASES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../scripts/ci/fixtures/audit-security-controls/cases.json"
));
const SCHEMA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../scripts/ci/fixtures/audit-security-controls/schema.json"
));

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn bytes(path: &Path, limit: usize) -> Vec<u8> {
    let meta = fs::symlink_metadata(path).unwrap();
    assert!(meta.is_file() && !meta.file_type().is_symlink());
    assert!(meta.len() <= limit as u64);
    let mut data = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data.len() as u64, meta.len());
    data
}
fn hashes(root: &Path) -> BTreeMap<String, String> {
    assert!(!fs::symlink_metadata(root).unwrap().file_type().is_symlink());
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        assert!(
            FILES.contains(&name.as_str()),
            "unexpected fixture entry: {name}"
        );
        out.insert(name, digest(&bytes(&entry.path(), 64 * 1024)));
    }
    assert_eq!(out.len(), FILES.len());
    out
}
fn pinned_digest() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "sha256:035dd8fd2410fe68513916df0c2895257fffafcd5314b4a118484ce8db62bedb"
    } else if cfg!(target_arch = "x86_64") {
        "sha256:2f0d0c7a41a3e48dc02c30dabc4851bc37c18f021b46c9ae54b15177ece088ee"
    } else {
        panic!("no managed native OpenGrep 1.31.0 pin for this architecture")
    }
}
fn directory(name: &str, repo: &Path) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(name).expect("explicit managed scratch/receipts required"));
    assert!(path.is_absolute());
    assert!(!fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    let path = fs::canonicalize(path).unwrap();
    assert!(path.is_dir() && !path.starts_with(repo));
    path
}
fn fresh(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).expect("fresh fixture/evidence directory required");
    fs::canonicalize(path).unwrap()
}
fn retain(root: &Path, name: &str, value: &Value) -> Value {
    let raw = serde_json::to_vec_pretty(value).unwrap();
    let record = legion_effects::ArtifactWriter::new(root)
        .write_immutable(name, &raw)
        .unwrap();
    json!({"path":root.join(&record.path),"digest":record.digest,"bytes":record.bytes})
}
fn args() -> Vec<String> {
    [
        "scan",
        "--json",
        "--quiet",
        "--metrics",
        "off",
        "--disable-version-check",
        "--config",
        ".semgrep.yml",
        ".",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn environment() -> BTreeMap<String, String> {
    let mut env: BTreeMap<_, _> = [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
        "TEMP",
        "TMP",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect();
    for (key, value) in [
        ("NO_COLOR", "1"),
        ("SEMGREP_SEND_METRICS", "off"),
        ("SEMGREP_ENABLE_VERSION_CHECK", "0"),
        ("SYFT_CHECK_FOR_APP_UPDATE", "false"),
    ] {
        env.insert(key.into(), value.into());
    }
    env
}

/// Exact self-producer request, not the artifact harness's different argv.
/// Producer receipts identify inventory as planId; frozen plan identity stays
/// separately bound here & in original ExecutionReport. No injected artifacts.
struct ScopedPolicy {
    root: PathBuf,
    run: PathBuf,
    inventory: String,
    plan: String,
    signature: String,
    source: BTreeMap<String, String>,
    tool: PathBuf,
    wrapper: PathBuf,
    wrapper_digest: String,
    environment: BTreeMap<String, String>,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn definition(&self) -> Value {
        json!({"id":POLICY,"version":1,"scope":"constructed-self-producing-security-controls-scanner-only",
            "provider":PROVIDER,"root":self.root,"run":self.run,"inventoryDigest":self.inventory,
            "frozenPlanDigest":self.plan,"frozenPlanSignature":self.signature,"sourceFiles":self.source,
            "tool":{"path":self.tool,"digest":pinned_digest(),"version":"1.31.0"},
            "wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},"args":args(),
            "requestPolicyId":legion_audit::execution_policy::POLICY_ID,
            "environment":self.environment,"timeoutMs":TIMEOUT,"outputLimit":LIMIT,
            "sandbox":"native-macos-deny-network-deny-project-write"})
    }
    fn profile(&self) -> String {
        let root = self
            .root
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{root}\"))\n(deny file-write* (subpath \"{root}\"))\n")
    }
    fn permits(&self, request: &ExternalToolRequest) -> bool {
        if request.schema_version != ExternalToolRequest::default().schema_version
            || request.request_id != format!("security-producer:{PROVIDER}:{}", self.inventory)
            || request.provider_id != PROVIDER
            || request.plan_id != self.inventory
            || request.policy_id != legion_audit::execution_policy::POLICY_ID
            || request.task_id.as_deref() != Some("opengrep")
            || request.cwd != self.root.to_string_lossy().as_ref()
            || request.origin != ToolOrigin::System
            || request.shell
            || request.expected_digest.is_some()
            || request.version_requirement.is_some()
            || request.skip_version_probe
            || !request.requires_network_sandbox
            || request.timeout_ms != TIMEOUT
            || request.stdout_limit != LIMIT
            || request.stderr_limit != LIMIT
            || request.accepted_exit_codes != [0, 1].into_iter().collect()
            || request.environment != self.environment
            || request.environment_allowlist != self.environment.keys().cloned().collect()
            || !request.sensitive_argument_indexes.is_empty()
            || !request.sensitive_environment_names.is_empty()
            || request.executable != self.wrapper.to_string_lossy().as_ref()
            || request.args.len() != args().len() + 4
            || request.args[0] != "-f"
            || request.args[2] != "--"
            || request.args[3] != self.tool.to_string_lossy().as_ref()
            || request.args[4..] != args()
        {
            return false;
        }
        let mut version_args = request.args[..4].to_vec();
        version_args.push("--version".into());
        if request.version_args != version_args {
            return false;
        }
        let Some(sandbox) = request.sandbox.as_ref() else {
            return false;
        };
        let profile = self.profile();
        let profile_digest = digest(profile.as_bytes());
        let profile_path = Path::new(&request.args[1]);
        let Some(sandbox_dir) = profile_path.parent() else {
            return false;
        };
        let Some(scratch) = sandbox_dir.parent() else {
            return false;
        };
        if scratch.parent() != Some(self.run.as_path())
            || !scratch
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("legion-audit-security-"))
            || sandbox_dir.file_name().and_then(|s| s.to_str()) != Some("sandbox")
            || profile_path.file_name().and_then(|s| s.to_str())
                != Some(
                    format!("audit-{}.sb", profile_digest.trim_start_matches("sha256:")).as_str(),
                )
            || !sandbox.network
            || sandbox.filesystem_scope.as_deref() != self.root.to_str()
            || sandbox.id
                != format!(
                    "sandbox:macos:{}",
                    profile_digest.trim_start_matches("sha256:")
                )
        {
            return false;
        }
        // Authenticate each component before opening profile; do not admit a
        // symlink escape even when its bytes happen to match.
        for path in [scratch, sandbox_dir, profile_path] {
            if fs::symlink_metadata(path).map_or(true, |m| m.file_type().is_symlink()) {
                return false;
            }
        }
        fs::canonicalize(profile_path).ok().as_deref() == Some(profile_path)
            && fs::read(profile_path).ok().as_deref() == Some(profile.as_bytes())
            && fs::read(&self.tool)
                .ok()
                .map(|data| digest(&data))
                .as_deref()
                == Some(pinned_digest())
            && fs::read(&self.wrapper)
                .ok()
                .map(|data| digest(&data))
                .as_deref()
                == Some(self.wrapper_digest.as_str())
            && hashes(&self.root) == self.source
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let allowed = self.permits(request);
        self.decisions.lock().unwrap().push(
            json!({"allowed":allowed,"requestId":request.request_id,
            "providerId":request.provider_id,"planId":request.plan_id,"policyId":request.policy_id,
            "executable":request.executable,"args":request.args,"versionArgs":request.version_args,
            "cwd":request.cwd,"environment":request.environment,"profile":self.profile()}),
        );
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&serde_json::to_vec(&self.definition()).unwrap()),
            reason: Some("exact constructed native scanner fixture only".into()),
        }
    }
}
fn require(problems: &mut Vec<String>, condition: bool, message: &str) {
    if !condition {
        problems.push(message.into());
    }
}
fn labels(raw: &Value) -> BTreeSet<(String, String, u64)> {
    raw.as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            (
                row["check_id"].as_str().unwrap_or("").to_owned(),
                row["path"]
                    .as_str()
                    .unwrap_or("")
                    .strip_prefix("./")
                    .unwrap_or(row["path"].as_str().unwrap_or(""))
                    .to_owned(),
                row["start"]["line"].as_u64().unwrap_or(0),
            )
        })
        .collect()
}
fn expected_labels() -> BTreeSet<(String, String, u64)> {
    [
        (RULE.into(), "literal.py".into(), 3),
        (RULE.into(), "seed.py".into(), 4),
    ]
    .into_iter()
    .collect()
}

fn run_case(
    repo: &Path,
    work: &Path,
    retained: &Path,
    id: &str,
    source: &BTreeMap<String, String>,
    tool: &Path,
    spec: &ProviderSpec,
) -> Value {
    let original = repo.join(CORPUS).join("projects").join(id);
    let original_before = hashes(&original);
    assert_eq!(original_before, *source);
    let root = fresh(work, id);
    for name in FILES {
        fs::write(root.join(name), bytes(&original.join(name), 64 * 1024)).unwrap();
    }
    let before = hashes(&root);
    assert_eq!(&before, source);
    let run = fresh(retained, id);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(root.to_str().unwrap())
        .unwrap();
    assert_eq!(
        inventory.entries.len(),
        4,
        "rule config must remain in full inventory"
    );
    for entry in &inventory.entries {
        assert_eq!(entry.digest.as_ref(), source.get(&entry.path));
    }
    let python: Vec<_> = inventory
        .entries
        .iter()
        .filter(|entry| entry.source_file)
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(python, PYTHON);
    // Compile actual registered provider unchanged. Rule configuration stays
    // bound by full inventory & source map; scanner coverage owns Python paths.
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, std::slice::from_ref(spec))
        .unwrap()
        .freeze(Some(b"security-controls-scanner-constructed-fixture-key"))
        .unwrap();
    assert_eq!(frozen.providers().len(), 1);
    let provider = frozen.provider(PROVIDER).unwrap();
    assert_eq!(provider.role, "candidate-generator");
    assert_eq!(provider.configuration["selector"], spec.selector);
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let policy = Arc::new(ScopedPolicy {
        root: root.clone(),
        run: run.clone(),
        inventory: inventory.digest.clone(),
        plan: frozen.digest().into(),
        signature: frozen.signature().unwrap().into(),
        source: source.clone(),
        tool: tool.to_owned(),
        wrapper: wrapper.clone(),
        wrapper_digest: digest(&bytes(&wrapper, 16 * 1024 * 1024)),
        environment: environment(),
        decisions: Mutex::new(Vec::new()),
    });
    let mut registry = NativeProviderRegistry::new(&root);
    assert!(registry.security.artifacts.is_empty());
    registry.security = registry.security.with_producer(
        ArtifactProducer::new(&root)
            .with_run_dir(&run)
            .with_search_path(vec![tool.parent().unwrap().to_owned()])
            .with_bounds(TIMEOUT, LIMIT)
            .with_policy_authorizer(policy.clone()),
    );
    assert!(registry.security.artifacts.is_empty());
    let execution = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &registry,
            CancellationToken::new(),
        ));
    assert!(
        registry.security.artifacts.is_empty(),
        "selfproducer must not inject caller artifacts"
    );
    let execution_json = match &execution {
        Ok(value) => serde_json::to_value(value).unwrap(),
        Err(error) => json!({"error":error.to_string()}),
    };
    let execution_binding = retain(&run, "execution.json", &execution_json);
    let after = hashes(&root);
    let original_after = hashes(&original);
    let mut problems = Vec::new();
    require(
        &mut problems,
        after == before && original_after == original_before,
        "source bytes changed",
    );
    require(
        &mut problems,
        digest(&bytes(tool, 256 * 1024 * 1024)) == pinned_digest(),
        "tool identity changed",
    );
    require(
        &mut problems,
        digest(&bytes(&wrapper, 16 * 1024 * 1024)) == policy.wrapper_digest,
        "sandbox executable identity changed",
    );
    let decisions = policy.decisions.lock().unwrap().clone();
    require(
        &mut problems,
        decisions.len() == 1 && decisions[0]["allowed"] == true,
        "exact native SDK admission missing or repeated",
    );
    let candidates = execution
        .as_ref()
        .ok()
        .map(|execution| scanner_candidates_from_execution(&root, &frozen, execution))
        .unwrap_or_default();
    let candidate_labels: BTreeSet<_> = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.rule.clone(),
                candidate.path.clone().unwrap_or_default(),
                candidate.line.unwrap_or(0),
            )
        })
        .collect();
    require(
        &mut problems,
        candidates.len() == 2
            && candidate_labels == expected_labels()
            && candidates
                .iter()
                .all(|candidate| candidate.provider == PROVIDER),
        "actual native candidate population differs",
    );
    let ids: BTreeSet<_> = candidates
        .iter()
        .map(|candidate| candidate.finding_id.as_str())
        .collect();
    require(
        &mut problems,
        ids.len() == candidates.len(),
        "duplicate candidate identities",
    );
    require(
        &mut problems,
        candidates
            .iter()
            .all(|candidate| candidate.path.as_deref() != Some("variant.py")),
        "unexpected native variant candidate",
    );
    let result = execution
        .as_ref()
        .ok()
        .and_then(|execution| execution.results.first());
    if let Some(execution) = execution.as_ref().ok() {
        require(
            &mut problems,
            execution.results.len() == 1
                && execution.planned_providers == [PROVIDER]
                && execution.plan_digest == frozen.digest()
                && execution.plan_signature.as_deref() == frozen.signature()
                && execution.inventory_digest == inventory.digest
                && execution.generation == inventory.generation
                && execution.gaps.is_empty()
                && execution.pending_host.is_empty(),
            "original execution incomplete or detached",
        );
    } else {
        problems.push("native execution returned error".into());
    }
    if let Some(entry) = result {
        require(
            &mut problems,
            entry.provider == PROVIDER
                && !entry.skipped
                && entry.result.validate().is_ok()
                && entry.result.complete
                && entry.result.coverage_gaps.is_empty(),
            "registered provider incomplete (inspect original frozen denominator & result)",
        );
        require(
            &mut problems,
            entry
                .result
                .details
                .get("producer")
                .and_then(|v| v.get("mode"))
                == Some(&json!("tool")),
            "native selfproducer evidence absent",
        );
        let analysis = entry
            .result
            .details
            .get("analysis")
            .cloned()
            .unwrap_or(Value::Null);
        let rules_digest = digest(format!(".semgrep.yml\0{}\0", source[".semgrep.yml"]).as_bytes());
        require(
            &mut problems,
            analysis["binding"]["digest"] == inventory.digest
                && analysis["binding"]["repositoryRevision"] == inventory.generation
                && analysis["ruleset"]["path"] == ".semgrep.yml"
                && analysis["ruleset"]["digest"] == rules_digest
                && analysis["ruleset"]["source"] == "repository-local",
            "selfproducer inventory or local-rule identity differs",
        );
        require(
            &mut problems,
            entry.result.coverage.as_ref().is_some_and(|coverage| {
                coverage.expected == 3
                    && coverage.examined == 3
                    && coverage.gaps.is_empty()
                    && provider.configuration["denominatorCount"] == 3
                    && provider.configuration["denominatorDigest"].as_str()
                        == Some(coverage.denominator_digest.as_str())
            }),
            "full registered denominator is not completely accounted for",
        );
    } else {
        problems.push("actual provider result absent".into());
    }
    let mut diagnostics = Vec::new();
    if let Ok(entries) = fs::read_dir(run.join("native-diagnostics")) {
        for entry in entries {
            let path = entry.unwrap().path();
            let raw = bytes(&path, 128 * 1024 * 1024);
            let value: Value = serde_json::from_slice(&raw).unwrap();
            require(
                &mut problems,
                path.file_name().and_then(|name| name.to_str())
                    == Some(
                        format!(
                            "{PROVIDER}-{}.json",
                            digest(&raw).trim_start_matches("sha256:")
                        )
                        .as_str(),
                    ),
                "diagnostic content-address differs",
            );
            let receipt = &value["receipt"];
            let projection = result.and_then(|entry| entry.result.details.get("executionReceipt"));
            require(
                &mut problems,
                value["schema"] == "legion-native-scanner-diagnostic/1"
                    && value["provider"] == PROVIDER
                    && value["inventoryDigest"] == inventory.digest
                    && receipt["providerId"] == PROVIDER
                    && receipt["planId"] == inventory.digest
                    && receipt["requestId"]
                        == format!("security-producer:{PROVIDER}:{}", inventory.digest)
                    && receipt["state"] == "completed"
                    && receipt["complete"] == true
                    && receipt["processTree"]["started"] == true
                    && receipt["processTree"]["terminated"] == true
                    && receipt["processTree"]["reaped"] == true
                    && receipt["gaps"].as_array().is_some_and(Vec::is_empty)
                    && receipt["policy"]["allowed"] == true
                    && receipt["policy"]["id"] == POLICY
                    && receipt["policy"]["version"] == 1
                    && receipt["policy"]["digest"]
                        == digest(&serde_json::to_vec(&policy.definition()).unwrap())
                    && receipt["executable"]["canonicalPath"] == wrapper.to_string_lossy().as_ref()
                    && receipt["executable"]["digest"] == policy.wrapper_digest
                    && receipt["executable"]["version"]["qualified"] == true
                    && receipt["executable"]["version"]["exitCode"] == 0
                    && receipt["executable"]["version"]["skippedByPolicy"] == false
                    && receipt["executable"]["version"]["output"]
                        .as_str()
                        .is_some_and(|v| v.split_whitespace().any(|token| token == "1.31.0"))
                    && receipt["sandbox"]["required"] == true
                    && matches!(receipt["exitCode"].as_i64(), Some(0 | 1))
                    && projection.is_some_and(|p| {
                        p["receiptId"] == receipt["receiptId"]
                            && p["complete"] == true
                            && p["tool"]["executableDigest"] == pinned_digest()
                    }),
                "original SDK receipt invalid, refused or detached",
            );
            require(
                &mut problems,
                decisions.first().is_some_and(|decision| {
                    receipt["command"]["args"] == decision["args"]
                        && receipt["executable"]["version"]["args"] == decision["versionArgs"]
                }) && receipt["cwd"] == root.to_string_lossy().as_ref()
                    && receipt["sandbox"]["receiptId"]
                        == format!(
                            "sandbox:macos:{}",
                            digest(policy.profile().as_bytes()).trim_start_matches("sha256:")
                        ),
                "SDK command/version probe or sandbox differs from admitted request",
            );
            for stream in ["stdout", "stderr"] {
                let retained_stream = &value[stream];
                let parsed: Result<Vec<u8>, _> =
                    serde_json::from_value(retained_stream["rawBytes"].clone());
                require(
                    &mut problems,
                    parsed.is_ok(),
                    "retained original stream bytes absent or invalid",
                );
                let actual = parsed.unwrap_or_default();
                let record = &receipt[stream];
                require(
                    &mut problems,
                    record["immutable"] == true
                        && retained_stream["immutable"] == true
                        && actual.len() <= LIMIT
                        && record["bytes"].as_u64() == Some(actual.len() as u64)
                        && record["digest"] == digest(&actual)
                        && retained_stream["digest"] == record["digest"]
                        && retained_stream["bytes"] == record["bytes"]
                        && retained_stream["originalPath"] == record["path"],
                    "original raw stream descriptor differs",
                );
                if stream == "stdout" {
                    let output: Value = serde_json::from_slice(&actual).unwrap_or(Value::Null);
                    let scanned: BTreeSet<_> = output["paths"]["scanned"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(|path| path.strip_prefix("./").unwrap_or(path))
                        .collect();
                    require(
                        &mut problems,
                        output["errors"].as_array().is_some_and(Vec::is_empty)
                            && output["results"]
                                .as_array()
                                .is_some_and(|rows| rows.len() == 2)
                            && output["paths"]["scanned"]
                                .as_array()
                                .is_some_and(|rows| rows.len() == 3)
                            && labels(&output["results"]) == expected_labels()
                            && scanned == PYTHON.into_iter().collect(),
                        "raw scanner output or three-Python coverage differs",
                    );
                    require(
                        &mut problems,
                        projection.is_some_and(|p| {
                            p["stdoutDigest"] == record["digest"]
                                && p["stdoutBytes"] == record["bytes"]
                        }),
                        "raw stdout differs from provider projection",
                    );
                }
            }
            diagnostics.push(
                json!({"path":path,"digest":digest(&raw),"bytes":raw.len(),"original":value}),
            );
        }
    }
    require(
        &mut problems,
        diagnostics.len() == 1,
        "exactly one retained original scanner diagnostic required",
    );
    json!({"run":id,"passed":problems.is_empty(),"problems":problems,"sourceRoot":root,
        "sourceBefore":before,"sourceAfter":after,"originalSourceBefore":original_before,"originalSourceAfter":original_after,
        "inventory":inventory,"providerSpec":spec,
        "frozenPlan":frozen.plan(),"planDigest":frozen.digest(),"planSignature":frozen.signature(),
        "execution":execution_json,"executionArtifact":execution_binding,"policy":policy.definition(),"policyDecisions":decisions,
        "nativeDiagnostics":diagnostics,"actualCandidates":candidates,"actualCandidateCount":candidates.len(),
        "modelCalls":0,"semanticAdjudicationStatus":"unadjudicated","semanticQualification":false,"productionQualification":false})
}

#[test]
#[ignore = "Root-owned native macOS OpenGrep 1.31.0; managed pinned tool & explicit scratch/receipts required; no model calls"]
fn real_security_controls_scanner_population() {
    let repo = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")).unwrap();
    assert_eq!(
        bytes(&repo.join(CORPUS).join("cases.json"), 64 * 1024),
        CASES
    );
    assert_eq!(
        bytes(&repo.join(CORPUS).join("schema.json"), 64 * 1024),
        SCHEMA
    );
    let corpus: Value = serde_json::from_slice(CASES).unwrap();
    assert_eq!(corpus["schema"], "legion-audit-security-controls/1");
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let mut projects = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut controls = BTreeSet::new();
    for case in cases {
        assert!(controls.insert(case["control"].as_str().unwrap()));
        let id = case["run"].as_str().unwrap();
        assert!(["positive", "absence"].contains(&id));
        let files: BTreeMap<String, String> =
            serde_json::from_value(case["sourceFiles"].clone()).unwrap();
        assert_eq!(files.keys().map(String::as_str).collect::<Vec<_>>(), FILES);
        if let Some(existing) = projects.insert(id.into(), files.clone()) {
            assert_eq!(existing, files);
        }
        assert_eq!(case["candidate"]["provider"], PROVIDER);
        assert_eq!(case["candidate"]["rule"], RULE);
    }
    assert_eq!(
        controls,
        [
            "adjudication-survivor",
            "adjudication-dismissal",
            "variant-positive",
            "variant-absence"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(projects.len(), 2);
    for file in [".semgrep.yml", "seed.py", "literal.py"] {
        assert_eq!(projects["positive"][file], projects["absence"][file]);
    }
    assert_ne!(
        projects["positive"]["variant.py"],
        projects["absence"]["variant.py"]
    );
    let work_parent = directory("LEGION_SECURITY_CONTROLS_SCRATCH", &repo);
    let retained_parent = directory("LEGION_SECURITY_CONTROLS_RECEIPTS", &repo);
    assert!(
        !work_parent.starts_with(&retained_parent) && !retained_parent.starts_with(&work_parent)
    );
    let label = format!(
        "security-controls-scanner-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let work = fresh(&work_parent, &label);
    let retained = fresh(&retained_parent, &label);
    let tool = fs::canonicalize(
        resolve_request(&work, "opengrep", &[])
            .expect("managed pinned native OpenGrep required")
            .executable,
    )
    .unwrap();
    assert!(!tool.starts_with(&repo) && !tool.starts_with(&work));
    assert_eq!(digest(&bytes(&tool, 256 * 1024 * 1024)), pinned_digest());
    assert_eq!(
        fs::canonicalize(tool.parent().unwrap().join("opengrep")).unwrap(),
        tool
    );
    let registry: Value = serde_json::from_slice(&bytes(
        &repo.join("src/registry/providers.json"),
        2 * 1024 * 1024,
    ))
    .unwrap();
    let registered = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|provider| provider["id"] == PROVIDER)
        .unwrap()
        .clone();
    let spec: ProviderSpec = serde_json::from_value(registered.clone()).unwrap();
    let rows: Vec<_> = ["positive", "absence"]
        .into_iter()
        .map(|id| run_case(&repo, &work, &retained, id, &projects[id], &tool, &spec))
        .collect();
    assert_eq!(
        bytes(&repo.join(CORPUS).join("cases.json"), 64 * 1024),
        CASES
    );
    assert_eq!(
        bytes(&repo.join(CORPUS).join("schema.json"), 64 * 1024),
        SCHEMA
    );
    let passed = rows.iter().all(|row| row["passed"] == true);
    let report = json!({"kind":"legion-security-controls-scanner-preflight/1","passed":passed,
        "corpusDigest":digest(CASES),"schemaDigest":digest(SCHEMA),"registeredProvider":registered,
        "nativeTool":{"path":tool,"digest":pinned_digest(),"version":"1.31.0"},"projects":rows,
        "modelCalls":0,"semanticAdjudicationStatus":"unadjudicated","semanticQualification":false,
        "productionQualification":false,"registryPromotion":false});
    let binding = retain(&retained, "preflight.json", &report);
    println!("SECURITY_CONTROLS_SCANNER_PREFLIGHT {binding}");
    assert!(
        passed,
        "native scanner prerequisite failed; retained original evidence: {binding}"
    );
}
