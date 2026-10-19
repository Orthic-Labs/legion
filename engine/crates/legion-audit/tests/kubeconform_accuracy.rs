//! Real kubeconform controls. Provision upstream schema bytes via
//! LEGION_KUBECONFORM_SCHEMA_DIR; this test never downloads or generates schemas.
//! See SCHEMA_URL for exact asset provenance. macOS native sandbox is mandatory.
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

const ID: &str = "security.scanner-kubeconform";
const SOURCE: &str = "engine/crates/legion-audit/tests/kubeconform_accuracy.rs";
const POLICY: &str = "legion-real-kubeconform-benchmark-v1";
const TIMEOUT: u64 = 30_000;
const LIMIT: usize = 1024 * 1024;
const KUBERNETES: &str = "1.32.0";
const SCHEMA_PATH: &str = "pod-v1.json";
const SCHEMA_COMMIT: &str = "074539312bcc717d5492d1448be088d7549c042b";
const SCHEMA_URL: &str = "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/074539312bcc717d5492d1448be088d7549c042b/v1.32.0-standalone-strict/pod-v1.json";
const SCHEMA_DIGEST: &str =
    "sha256:4912d4d8c79fd1e31cc8553cceecbf4dea2111b652e8ba6b8e0fee7bb7880b66";
const SCHEMA_BYTES: usize = 645686;
// kubeconform's upstream pkg/config/config.go registers -v, not --version.
const VERSION_ARG: &str = "-v";

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

#[derive(Clone)]
struct Schemas {
    root: PathBuf,
    tree_digest: String,
}
impl Schemas {
    fn provisioned() -> Self {
        let supplied = PathBuf::from(
            std::env::var_os("LEGION_KUBECONFORM_SCHEMA_DIR")
                .expect("provision exact offline upstream Pod schema directory"),
        );
        assert!(supplied.is_absolute() && !supplied.is_symlink());
        let root = fs::canonicalize(supplied).unwrap();
        // Exactly one standalone upstream file: no generated substitute, links,
        // supplementary refs, project schemas, mutable default or remote fallback.
        let entries: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        let path = root.join(SCHEMA_PATH);
        assert_eq!(entries[0], path);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes.len(), SCHEMA_BYTES);
        assert_eq!(
            digest(&bytes),
            SCHEMA_DIGEST,
            "upstream schema bytes must match reviewed pin"
        );
        let schema: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["spec"]["properties"]["containers"]["type"],
            "array"
        );
        let tree_digest =
            digest(&serde_json::to_vec(&json!([[SCHEMA_PATH, SCHEMA_DIGEST]])).unwrap());
        Self { root, tree_digest }
    }
    fn unchanged(&self) {
        assert_eq!(Self::provisioned().binding(), self.binding());
    }
    fn binding(&self) -> Value {
        json!({"directory": self.root, "digest": self.tree_digest, "template": SCHEMA_PATH,
            "kubernetesVersion": KUBERNETES, "sourceRepository": "https://github.com/yannh/kubernetes-json-schema",
            "sourceCommit": SCHEMA_COMMIT, "sourceUrl": SCHEMA_URL,
            "provenanceScope": "kubeconform upstream conversion of Kubernetes OpenAPI; not server-side validation",
            "files": [{"path": SCHEMA_PATH, "digest": SCHEMA_DIGEST, "bytes": SCHEMA_BYTES}]})
    }
    fn argv(&self) -> Vec<String> {
        let location = self.root.join(SCHEMA_PATH);
        [
            "-output",
            "json",
            "-strict",
            "-summary",
            "-verbose",
            "-kubernetes-version",
            KUBERNETES,
            "-schema-location",
            location.to_str().unwrap(),
            "--",
            "./pod.yaml",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
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
        .find(|p| p["id"] == ID)
        .unwrap()
        .clone();
    (serde_json::from_value(entry.clone()).unwrap(), entry)
}

struct Fixture(PathBuf);
impl Fixture {
    fn new(planted: bool) -> Self {
        let scratch = std::env::var_os("LEGION_REAL_SCANNER_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = scratch.join(format!(
            "legion-kubeconform-{planted}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(path.join("source")).unwrap();
        fs::create_dir_all(path.join("run")).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Exact trusted benchmark admission, separate from production authority.
struct ScopedPolicy {
    root: PathBuf,
    run: PathBuf,
    inventory: String,
    schemas: Schemas,
    tool: PathBuf,
    tool_digest: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn new(root: &Path, run: &Path, inventory: &str, schemas: &Schemas) -> Self {
        let resolved = resolve_request(root, "kubeconform", &[])
            .unwrap_or_else(|e| panic!("provision real kubeconform: {}", e.message()));
        let tool = fs::canonicalize(&resolved.executable).unwrap();
        assert!(!tool.starts_with(root) && !tool.starts_with(run));
        assert!(!schemas.root.starts_with(root) && !schemas.root.starts_with(run));
        let bytes = fs::read(&tool).unwrap();
        assert!(!bytes.starts_with(b"#!"), "script substitutes forbidden");
        assert_eq!(digest(&bytes), resolved.digest);
        let wrapper =
            fs::canonicalize("/usr/bin/sandbox-exec").expect("native macOS sandbox required");
        let wrapper_digest = digest(&fs::read(&wrapper).unwrap());
        Self {
            root: root.into(),
            run: run.into(),
            inventory: inventory.into(),
            schemas: schemas.clone(),
            tool,
            tool_digest: resolved.digest,
            wrapper,
            wrapper_digest,
            decisions: Mutex::new(vec![]),
        }
    }
    fn definition(&self) -> Value {
        json!({"id": POLICY, "version": 1, "provider": ID, "root": self.root, "runDirectory": self.run,
            "inventoryDigest": self.inventory, "tool": {"path": self.tool, "digest": self.tool_digest},
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest}, "scannerArgv": self.schemas.argv(),
            "versionArgv": [VERSION_ARG], "schemas": self.schemas.binding(),
            "timeoutMsMaximum": TIMEOUT, "outputBytesMaximum": LIMIT,
            "sandbox": "native-macos-deny-network-deny-project-write"})
    }
    fn permits(&self, request: &ExternalToolRequest) -> bool {
        let scan = request.task_id.as_deref() == Some("kubeconform");
        let probe = request.task_id.as_deref() == Some("kubeconform-version-probe");
        if !(scan || probe)
            || request.provider_id != ID
            || request.plan_id != self.inventory
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
            || fs::read(&self.wrapper).ok().map(|v| digest(&v)).as_deref()
                != Some(self.wrapper_digest.as_str())
            || !request.sensitive_argument_indexes.is_empty()
            || !request.sensitive_environment_names.is_empty()
            || request.args.len() < 5
            || request.args[0] != "-f"
            || request.args[2] != "--"
            || fs::canonicalize(&request.args[3]).ok().as_ref() != Some(&self.tool)
            || fs::read(&self.tool).ok().map(|v| digest(&v)).as_deref()
                != Some(self.tool_digest.as_str())
        {
            return false;
        }
        let mut version = request.args[..4].to_vec();
        version.push(VERSION_ARG.into());
        let suffix = if scan {
            self.schemas.argv()
        } else {
            vec![VERSION_ARG.into()]
        };
        let accepted: BTreeSet<i32> = if scan {
            [0, 1].into_iter().collect()
        } else {
            [0].into_iter().collect()
        };
        if request.version_args != version
            || request.args[4..] != suffix
            || request.accepted_exit_codes != accepted
        {
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
        if request.environment.keys().any(|k| !allowed.contains(k))
            || request.environment.keys().cloned().collect::<BTreeSet<_>>()
                != request.environment_allowlist
            || (probe && !request.environment.is_empty())
        {
            return false;
        }
        if scan {
            for (key, value) in [
                ("NO_COLOR", "1"),
                ("SEMGREP_SEND_METRICS", "off"),
                ("SEMGREP_ENABLE_VERSION_CHECK", "0"),
                ("SYFT_CHECK_FOR_APP_UPDATE", "false"),
                ("GOTOOLCHAIN", "local"),
                ("GOPROXY", "off"),
                ("GOSUMDB", "off"),
                ("GOWORK", "off"),
                ("CGO_ENABLED", "0"),
            ] {
                if request.environment.get(key).map(String::as_str) != Some(value) {
                    return false;
                }
            }
            for key in ["HOME", "USERPROFILE", "GOCACHE", "GOLANGCI_LINT_CACHE"] {
                if !request
                    .environment
                    .get(key)
                    .is_some_and(|p| Path::new(p).starts_with(&self.run))
                {
                    return false;
                }
            }
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
        let expected = format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
        let Ok(profile) = fs::read(profile_path) else {
            return false;
        };
        self.schemas.unchanged();
        profile == expected.as_bytes()
            && sandbox.id
                == format!(
                    "sandbox:macos:{}",
                    digest(&profile).trim_start_matches("sha256:")
                )
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let allowed = self.permits(request);
        self.decisions.lock().unwrap().push(json!({"allowed": allowed, "requestId": request.request_id,
            "providerId": request.provider_id, "planId": request.plan_id, "taskId": request.task_id,
            "executable": request.executable, "expectedDigest": request.expected_digest, "args": request.args,
            "versionArgs": request.version_args, "cwd": request.cwd, "timeoutMs": request.timeout_ms,
            "stdoutLimit": request.stdout_limit, "stderrLimit": request.stderr_limit, "acceptedExitCodes": request.accepted_exit_codes,
            "environmentNames": request.environment_allowlist, "requiresNetworkSandbox": request.requires_network_sandbox}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&serde_json::to_vec(&self.definition()).unwrap()),
            reason: Some(
                if allowed {
                    "exact real kubeconform fixture"
                } else {
                    "outside exact benchmark policy"
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

fn artifact_json(root: &Path, artifact: &legion_effects::ArtifactRecord) -> Value {
    let bytes = fs::read(root.join(&artifact.path)).unwrap();
    assert!(artifact.immutable);
    assert_eq!(digest(&bytes), artifact.digest);
    assert_eq!(bytes.len(), artifact.bytes);
    json!({"path": artifact.path, "digest": artifact.digest, "bytes": artifact.bytes, "immutable": artifact.immutable,
        "raw": String::from_utf8(bytes).unwrap()})
}

fn version_probe(policy: Arc<ScopedPolicy>) -> Value {
    let auth = legion_effects::authenticate_sandbox(
        &policy.tool.to_string_lossy(),
        &[VERSION_ARG.into()],
        &policy.root.to_string_lossy(),
        legion_effects::SandboxMode::DenyNetworkDenyProjectWrite,
        &policy.run.join("version-sandbox"),
    )
    .unwrap();
    let request = ExternalToolRequest {
        request_id: "real-kubeconform-version".into(),
        provider_id: ID.into(),
        plan_id: policy.inventory.clone(),
        policy_id: legion_audit::execution_policy::POLICY_ID.into(),
        task_id: Some("kubeconform-version-probe".into()),
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
    let artifacts = policy.run.join("version-artifacts");
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
    assert_eq!(receipt.policy_id, POLICY);
    assert!(receipt.sandbox.required && receipt.sandbox.network_enabled);
    let exe = receipt.executable.as_ref().unwrap();
    assert_eq!(exe.digest.as_deref(), Some(policy.wrapper_digest.as_str()));
    assert!(exe.version.qualified && !exe.version.skipped_by_policy);
    assert_eq!(exe.version.exit_code, Some(0));
    let stdout = artifact_json(&artifacts, receipt.stdout.as_ref().unwrap());
    let stderr = artifact_json(&artifacts, receipt.stderr.as_ref().unwrap());
    let version = exe.version.output.as_deref().unwrap();
    assert!(!version.trim().is_empty());
    assert_eq!(stdout["raw"].as_str().unwrap().trim(), version.trim());
    assert!(stderr["raw"].as_str().unwrap().is_empty());
    json!({"rawVersionOutput": version, "receipt": {"schemaVersion": receipt.schema_version, "receiptId": receipt.receipt_id,
        "requestId": receipt.request_id, "providerId": receipt.provider_id, "planId": receipt.plan_id, "taskId": receipt.task_id,
        "policyId": receipt.policy_id, "policy": receipt.policy.as_ref().map(|p| json!({"id": p.id, "version": p.version, "digest": p.digest, "allowed": p.allowed, "reason": p.reason})),
        "state": receipt.state.as_str(), "complete": receipt.complete, "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "executable": {"path": exe.canonical_path, "digest": exe.digest, "version": {"args": exe.version.args, "output": version,
            "exitCode": exe.version.exit_code, "qualified": exe.version.qualified, "skippedByPolicy": exe.version.skipped_by_policy}},
        "sandbox": {"required": receipt.sandbox.required, "receiptId": receipt.sandbox.receipt_id, "networkEnabled": receipt.sandbox.network_enabled},
        "processTree": {"started": receipt.process_tree.started, "terminated": receipt.process_tree.terminated, "hardKilled": receipt.process_tree.hard_killed,
            "reaped": receipt.process_tree.reaped, "detail": receipt.process_tree.detail},
        "timing": {"startedAtMs": receipt.timing.started_at_ms, "completedAtMs": receipt.timing.completed_at_ms, "durationMs": receipt.timing.duration_ms},
        "stdout": stdout, "stderr": stderr, "exitCode": receipt.exit_code, "signal": receipt.signal,
        "parser": {"attempted": receipt.parser.attempted, "succeeded": receipt.parser.succeeded, "error": receipt.parser.error}, "gaps": receipt.gaps}})
}

fn case(schemas: &Schemas, planted: bool) -> Value {
    let fixture = Fixture::new(planted);
    let root = fixture.0.join("source");
    let run = fixture.0.join("run");
    // One schema violation: containers must be an array, not a string.
    let source = format!(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: accuracy-control\nspec:\n  containers: {}\n",
        if planted {
            "invalid-container-list"
        } else {
            "[{name: app, image: 'example.invalid/app:1'}]"
        }
    );
    fs::write(root.join("pod.yaml"), &source).unwrap();
    let source_digest = digest(source.as_bytes());
    let case_id = if planted {
        "kubeconform-planted"
    } else {
        "kubeconform-clean"
    };
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(case_id)
        .unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(
        inventory.entries[0].digest.as_deref(),
        Some(source_digest.as_str())
    );
    let mut plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec().0]).unwrap();
    // Host asset configuration is frozen before execution; shipped selector/role remain intact.
    assert_eq!(plan.providers.len(), 1);
    plan.providers[0]
        .configuration
        .insert("scannerSchemas".into(), schemas.binding());
    let frozen = plan
        .freeze(Some(b"real-kubeconform-benchmark-key"))
        .unwrap();
    let provider = frozen.provider(ID).unwrap();
    assert_eq!(provider.configuration["denominatorCount"], 1);
    assert_eq!(provider.configuration["scannerSchemas"], schemas.binding());
    let policy = Arc::new(ScopedPolicy::new(&root, &run, &inventory.digest, schemas));
    let version = version_probe(policy.clone());
    let mut registry = NativeProviderRegistry::new(&root);
    registry.security = registry.security.with_producer(
        ArtifactProducer::new(&root)
            .with_run_dir(&run)
            .with_bounds(TIMEOUT, LIMIT)
            .with_policy_authorizer(policy.clone()),
    );
    let execution = execute(&frozen, &inventory, &registry).unwrap();
    assert_eq!(execution.planned_providers, vec![ID.to_string()]);
    assert_eq!(execution.results.len(), 1);
    let entry = &execution.results[0];
    assert_eq!(entry.provider, ID);
    assert!(!entry.skipped);
    let result = &entry.result;
    eprintln!(
        "REAL_SCANNER_CASE_DIAGNOSTIC {}",
        serde_json::to_string(&json!({
            "providerId": ID, "planted": planted, "actualProviderResult": result
        }))
        .unwrap()
    );
    assert!(result.applicable && result.details.get("availability").is_none());
    assert!(
        result.findings.is_empty(),
        "scanner output remains candidates"
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
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
    assert_eq!(receipt["tool"]["name"], "kubeconform");
    assert_eq!(receipt["executableDigest"], policy.tool_digest);
    assert_eq!(receipt["tool"]["executableDigest"], policy.tool_digest);
    assert_eq!(
        receipt["tool"]["version"],
        version["rawVersionOutput"].as_str().unwrap().trim()
    );
    assert_eq!(receipt["sandbox"]["required"], true);
    assert!(receipt["sandbox"]["receiptId"]
        .as_str()
        .unwrap()
        .starts_with("sandbox:macos:"));
    assert!(receipt["stdoutDigest"]
        .as_str()
        .is_some_and(|s| s.starts_with("sha256:") && s.len() == 71));
    assert!(receipt["stdoutBytes"].as_u64().is_some_and(|n| n > 0));
    assert_eq!(receipt["exitCode"], if planted { 1 } else { 0 });
    assert_eq!(result.details["producer"]["mode"], "tool");
    assert_eq!(result.details["producer"]["offline"], true);
    let ledger = result.details["analysis"]["lossLedger"].as_array().unwrap();
    assert_eq!(ledger.len(), 1, "exactly one Pod resource must be reported");
    assert_eq!(ledger[0]["path"], "pod.yaml");
    assert_eq!(
        ledger[0]["disposition"],
        if planted {
            "candidate"
        } else {
            "resource-valid"
        }
    );
    let schema_rows: Vec<_> = result.details["analysis"]["selectionLedger"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["kind"] == "offline-schema-identity")
        .collect();
    assert_eq!(schema_rows.len(), 1);
    assert_eq!(schema_rows[0]["digest"], schemas.tree_digest);
    assert_eq!(schema_rows[0]["kubernetesVersion"], KUBERNETES);
    let candidates = result.details["candidates"].as_array().unwrap();
    let actual: Vec<String> = candidates
        .iter()
        .map(|candidate| {
            assert_eq!(candidate["source"]["tool"], "kubeconform");
            assert_eq!(candidate["adjudication"], "required");
            assert!(candidate["line"].is_null() && candidate["evidence"][0]["line"].is_null());
            assert_eq!(candidate["anchorKind"], "file");
            assert_eq!(candidate["anchorStatus"], "scanner-reported");
            assert_eq!(candidate["source"]["sourceDigest"], source_digest);
            assert_eq!(candidate["source"]["frozenSourceDigest"], source_digest);
            assert_eq!(candidate["evidence"][0]["sourceDigest"], source_digest);
            let raw = &candidate["source"]["raw"];
            assert_eq!(raw["status"], "statusInvalid");
            assert!(raw["msg"].as_str().unwrap().contains("containers"));
            assert_eq!(
                candidate["source"]["rawFindingDigest"],
                digest(&serde_json::to_vec(raw).unwrap())
            );
            format!(
                "{}|{}|unresolved",
                candidate["ruleId"].as_str().unwrap(),
                candidate["path"].as_str().unwrap()
            )
        })
        .collect();
    let expected: Vec<String> = if planted {
        vec!["schema|pod.yaml|unresolved".into()]
    } else {
        vec![]
    };
    let gaps: Vec<Value> = result
        .coverage_gaps
        .iter()
        .map(|g| serde_json::from_str(g).unwrap())
        .collect();
    let coverage_matched = gaps.is_empty()
        && coverage.gaps == result.coverage_gaps
        && result.degradation.is_empty()
        && result.complete;
    assert_eq!(fs::read(root.join("pod.yaml")).unwrap(), source.as_bytes());
    schemas.unchanged();
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(
        decisions.len(),
        2,
        "one real version probe & one native producer scan"
    );
    assert!(decisions.iter().all(|d| d["allowed"] == true));
    json!({"caseId": case_id, "source": {"path": "pod.yaml", "bytes": source, "digest": source_digest},
        "expected": expected, "actual": actual, "controlMatched": actual == expected, "coverageContractMatched": coverage_matched,
        "complete": result.complete, "coverageGaps": gaps, "expectedCoverageGaps": [], "coverage": result.coverage,
        "planDigest": frozen.digest(), "inventoryDigest": inventory.digest, "schemas": schemas.binding(),
        "toolIdentity": {"path": policy.tool, "executableDigest": policy.tool_digest, "version": version},
        "policy": policy.definition(), "policyDecisions": *decisions, "executionReceipt": receipt, "actualProviderResult": result,
        "receiptRetentionLimit": "Native producer retains reduced scan receipt, normalized raw invalid resources & stdout digest; full scan stdout/process receipt is not retained. Real version output & full version receipt are retained."})
}

fn implementation_binding(root: &Path) -> Value {
    fn bind(root: &Path, path: &Path, files: &mut Vec<(String, String)>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                bind(root, &entry.unwrap().path(), files);
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
    let roots = [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
    ];
    let mut files = vec![];
    for tree in roots {
        bind(root, &root.join(tree), &mut files);
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
        bind(root, &root.join(file), &mut files);
    }
    files.sort();
    json!({"roots": roots, "fileCount": files.len(), "digest": digest(&serde_json::to_vec(&files).unwrap())})
}

#[test]
#[ignore = "requires real kubeconform, exact pinned upstream Pod schema & native macOS sandbox"]
fn real_scanner_accuracy_kubeconform() {
    let schemas = Schemas::provisioned();
    let cases = vec![case(&schemas, true), case(&schemas, false)];
    let controls_matched = cases
        .iter()
        .all(|c| c["controlMatched"] == true && c["coverageContractMatched"] == true);
    let complete = cases
        .iter()
        .all(|c| c["complete"] == true && c["coverageGaps"].as_array().unwrap().is_empty());
    let eligible = controls_matched && complete;
    let (mut tp, mut fp, mut missed) = (0usize, 0usize, 0usize);
    for case in &cases {
        let expected: BTreeSet<&str> = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let actual = case["actual"].as_array().unwrap();
        let unique: BTreeSet<&str> = actual.iter().map(|v| v.as_str().unwrap()).collect();
        tp += expected.intersection(&unique).count();
        fp += unique.difference(&expected).count() + actual.len() - unique.len();
        missed += expected.difference(&unique).count();
    }
    let (_, mut provider) = spec();
    provider.as_object_mut().unwrap().remove("benchmark");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let gaps: Vec<Value> = cases
        .iter()
        .flat_map(|c| {
            c["coverageGaps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| json!({"caseId": c["caseId"], "gap": g}))
        })
        .collect();
    let mut record = json!({"schema": "legion-external-provider-accuracy/1", "provider": ID, "stage": "candidate",
        "scope": "Constructed Pod schema type violation & clean control; not population accuracy, server-side validation or production admission",
        "modelCalls": 0, "executionPath": "native-sdk-frozen-plan-real-external-scanner", "qualificationEligible": eligible,
        "coverageState": if complete { "complete" } else { "partial" }, "coverageGaps": gaps,
        "binding": {"providerSpecDigest": digest(&serde_json::to_vec(&provider).unwrap()), "harnessPath": SOURCE,
            "harnessDigest": digest(&fs::read(root.join(SOURCE)).unwrap()), "implementation": implementation_binding(&root), "schemas": schemas.binding()},
        "metrics": {"truePositives": tp, "falsePositives": fp, "falseNegatives": missed,
            "precision": if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 },
            "recall": if tp + missed > 0 { tp as f64 / (tp + missed) as f64 } else { 0.0 }, "positiveCases": 1, "cleanCases": 1},
        "cases": cases, "status": if !controls_matched { "fail" } else if eligible { "pass" } else { "partial" }});
    record["qualificationDigest"] = json!(digest(&serde_json::to_vec(&record).unwrap()));
    if let Some(directory) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("security_scanner-kubeconform.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
    }
    println!(
        "EXTERNAL_PROVIDER_ACCURACY {}",
        serde_json::to_string(&record).unwrap()
    );
    assert!(
        controls_matched,
        "real controls & exact production coverage must match"
    );
    assert!(
        eligible,
        "both controls require complete native candidate-generator coverage"
    );
}
