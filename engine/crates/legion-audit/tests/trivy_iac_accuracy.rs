//! Real pinned Trivy embedded-check controls; no DB/policy download or image
//! build. Native macOS sandbox & official Trivy 0.69.3 are mandatory.
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
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const ID: &str = "container.iac";
const SOURCE: &str = "engine/crates/legion-audit/tests/trivy_iac_accuracy.rs";
const POLICY: &str = "legion-real-trivy-iac-benchmark-v1";
const TIMEOUT: u64 = 30_000;
const LIMIT: usize = 1024 * 1024;
const VERSION: &str = "0.69.3";
const VERSION_ARG: &str = "--version";
const CHECKS_COMMIT: &str = "79d27547baf5b14407d99ff3d90a46b235ed96dd";

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn scanner_argv() -> Vec<String> {
    [
        "config",
        "--format",
        "json",
        "--quiet",
        "--no-progress",
        "--skip-check-update",
        "--skip-version-check",
        ".",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn scan_environment() -> BTreeMap<String, String> {
    // Exact common run_tool environment. container_iac supplies no extra_env.
    let mut values: BTreeMap<_, _> = [
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
    .filter_map(|name| {
        std::env::var(name)
            .ok()
            .map(|value| (name.to_owned(), value))
    })
    .collect();
    for (name, value) in [
        ("NO_COLOR", "1"),
        ("SEMGREP_SEND_METRICS", "off"),
        ("SEMGREP_ENABLE_VERSION_CHECK", "0"),
        ("SYFT_CHECK_FOR_APP_UPDATE", "false"),
    ] {
        values.insert(name.into(), value.into());
    }
    values
}

fn embedded_checks_binding() -> Value {
    json!({"trivyVersion": VERSION, "trivySource": "https://github.com/aquasecurity/trivy/tree/v0.69.3",
        "officialRelease": {"url": "https://github.com/aquasecurity/trivy/releases/tag/v0.69.3",
            "macOS-ARM64": {"archive": "trivy_0.69.3_macOS-ARM64.tar.gz", "digest": "sha256:a2f2179afd4f8bb265ca3c7aefb56a666bc4a9a411663bc0f22c3549fbc643a5"},
            "macOS-64bit": {"archive": "trivy_0.69.3_macOS-64bit.tar.gz", "digest": "sha256:fec4a9f7569b624dd9d044fca019e5da69e032700edbb1d7318972c448ec2f4e"},
            "provisioningScope": "Host verifies official archive before provisioning; actual executable digest is measured separately"},
        "goMod": {"url": "https://raw.githubusercontent.com/aquasecurity/trivy/v0.69.3/go.mod",
            "digest": "sha256:425a4f4d49b480d35b043639b3ee6a8e0ae9e9d3916e75e33e6ab5c37ccf8f19", "bytes": 27232},
        "checksModule": "github.com/aquasecurity/trivy-checks", "checksCommit": CHECKS_COMMIT,
        "checksVersion": "v1.12.2-0.20251219190323-79d27547baf5",
        "controlRules": [
            {"path": "checks/docker/root_user.rego", "ruleId": "DS-0002", "avdId": "AVD-DS-0002", "digest": "sha256:ffc33d1985ef79c30d2e74858a5955231007536b597a8cac75d94da03d86926d", "bytes": 1893},
            {"path": "checks/docker/no_healthcheck_instruction.rego", "ruleId": "DS-0026", "avdId": "AVD-DS-0026", "digest": "sha256:c9b7059fb85ada3b2bd6ac8835fdd0bb065a2a81a7888c643c9f9ce877552461", "bytes": 810},
            {"path": "checks/docker/latest_tag.rego", "ruleId": "DS-0001", "avdId": "AVD-DS-0001", "digest": "sha256:363a828451f00d364c53db583fb3973d9415adbb0f44d1018307ad157b5bd7f0", "bytes": 3629}],
        "identityLimit": "Official release executable digest plus pinned source identities; native databaseDigest is version-derived, not an extracted bundle hash"})
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
            "legion-trivy-iac-{planted}-{}-{}",
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
    scan_environment: BTreeMap<String, String>,
    tool: PathBuf,
    tool_digest: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn new(root: &Path, run: &Path, inventory: &str) -> Self {
        let resolved = resolve_request(root, "trivy", &[])
            .unwrap_or_else(|e| panic!("provision real pinned Trivy: {}", e.message()));
        let tool = fs::canonicalize(&resolved.executable).unwrap();
        assert!(!tool.starts_with(root) && !tool.starts_with(run));
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
            scan_environment: scan_environment(),
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
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest}, "scannerArgv": scanner_argv(),
            "versionArgv": [VERSION_ARG], "embeddedChecks": embedded_checks_binding(),
            "scanEnvironmentNames": self.scan_environment.keys().collect::<Vec<_>>(),
            "scanEnvironmentDigest": digest(&serde_json::to_vec(&self.scan_environment).unwrap()),
            "timeoutMsMaximum": TIMEOUT, "outputBytesMaximum": LIMIT,
            "sandbox": "native-macos-deny-network-deny-project-write"})
    }
    fn permits(&self, request: &ExternalToolRequest) -> bool {
        let scan = request.task_id.as_deref() == Some("trivy");
        let probe = request.task_id.as_deref() == Some("trivy-version-probe");
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
            scanner_argv()
        } else {
            vec![VERSION_ARG.into()]
        };
        let accepted: BTreeSet<i32> = [0].into_iter().collect();
        if request.version_args != version
            || request.args[4..] != suffix
            || request.accepted_exit_codes != accepted
        {
            return false;
        }
        if request.environment.keys().cloned().collect::<BTreeSet<_>>()
            != request.environment_allowlist
            || (probe && !request.environment.is_empty())
            || (scan && request.environment != self.scan_environment)
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
        let expected = format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n");
        let Ok(profile) = fs::read(profile_path) else {
            return false;
        };
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
                    "exact real Trivy IaC fixture"
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
        request_id: "real-trivy-version".into(),
        provider_id: ID.into(),
        plan_id: policy.inventory.clone(),
        policy_id: legion_audit::execution_policy::POLICY_ID.into(),
        task_id: Some("trivy-version-probe".into()),
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
    assert_eq!(
        version.trim(),
        format!("Version: {VERSION}"),
        "pinned official release required"
    );
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

fn case(planted: bool) -> Value {
    let fixture = Fixture::new(planted);
    let root = fixture.0.join("source");
    let run = fixture.0.join("run");
    // Upstream DS-0001 & DS-0026 are satisfied in both controls. Only DS-0002
    // changes; config scanning does not pull/build this image or execute commands.
    let source = format!(
        "FROM alpine:3.21\nHEALTHCHECK CMD [\"/bin/true\"]\n{}CMD [\"/bin/true\"]\n",
        if planted { "" } else { "USER 1000\n" }
    );
    fs::write(root.join("Dockerfile"), &source).unwrap();
    let source_digest = digest(source.as_bytes());
    let case_id = if planted {
        "trivy-iac-planted"
    } else {
        "trivy-iac-clean"
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
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec().0]).unwrap();
    assert_eq!(plan.providers.len(), 1);
    let frozen = plan.freeze(Some(b"real-trivy-iac-benchmark-key")).unwrap();
    let provider = frozen.provider(ID).unwrap();
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
    assert_eq!(execution.planned_providers, vec![ID.to_string()]);
    assert_eq!(execution.results.len(), 1);
    let entry = &execution.results[0];
    assert_eq!(entry.provider, ID);
    assert!(!entry.skipped);
    let result = &entry.result;
    assert!(result.applicable && result.details.get("availability").is_none());
    assert_eq!(result.findings.len(), usize::from(planted));
    assert!(result.details["candidates"].as_array().unwrap().is_empty());
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    // Production retains this reduced actual EffectExecutor receipt in producer.
    // Never replace it with a caller-created executionReceipt or receipt booleans.
    let receipt = &result.details["producer"];
    assert_eq!(receipt["state"], "completed");
    assert_eq!(receipt["complete"], true);
    assert_eq!(receipt["policyId"], POLICY);
    assert_eq!(receipt["tool"], "trivy");
    assert_eq!(receipt["executableDigest"], policy.tool_digest);
    assert_eq!(
        receipt["version"],
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
    assert_eq!(
        receipt["exitCode"], 0,
        "Trivy default exit code is zero even with misconfigurations"
    );
    assert_eq!(result.details["producer"]["mode"], "tool");
    assert_eq!(result.details["producer"]["offline"], true);
    assert_eq!(
        result.details["analysis"]["status"],
        if planted { "fail" } else { "pass" }
    );
    assert_eq!(result.details["analysis"]["denominator"]["expected"], 2);
    assert_eq!(result.details["analysis"]["denominator"]["examined"], 2);
    let normalized = result.details["analysis"]["findings"].as_array().unwrap();
    assert_eq!(normalized.len(), usize::from(planted));
    let actual: Vec<String> = normalized
        .iter()
        .map(|finding| {
            let expected = json!({"schemaVersion": 1, "kind": "legion-iac-finding", "provider": "container-iac.trivy",
                "providerVersion": format!("Version: {VERSION}"), "ruleId": "DS-0002", "severity": "HIGH", "target": "Dockerfile",
                "resource": null, "message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
                "toolDb": null, "evidenceRefs": []});
            assert_eq!(finding, &expected);
            let excerpt = digest(&serde_json::to_vec(&expected).unwrap());
            // Adapter supplies its documented summary line1; Trivy raw locations
            // are not retained by this production normalizer. No line accuracy claim.
            let finding_id = digest(format!("{ID}\0DS-0002\0Dockerfile\0{}\0{excerpt}", 1).as_bytes());
            assert_eq!(result.findings[0].id.as_str(), finding_id);
            assert_eq!(result.findings[0].severity, "HIGH");
            assert_eq!(result.details["findingEvidence"][&finding_id]["ruleId"], "DS-0002");
            assert_eq!(result.details["findingEvidence"][&finding_id]["path"], "Dockerfile");
            assert_eq!(result.details["findingEvidence"][&finding_id]["excerptDigest"], excerpt);
            format!("{}|{}", finding["ruleId"].as_str().unwrap(), finding["target"].as_str().unwrap())
        })
        .collect();
    let expected: Vec<String> = if planted {
        vec!["DS-0002|Dockerfile".into()]
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
    assert_eq!(
        fs::read(root.join("Dockerfile")).unwrap(),
        source.as_bytes()
    );
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(
        decisions.len(),
        2,
        "one real version probe & one native producer scan"
    );
    assert!(decisions.iter().all(|d| d["allowed"] == true));
    json!({"caseId": case_id, "source": {"path": "Dockerfile", "bytes": source, "digest": source_digest},
        "expected": expected, "actual": actual, "controlMatched": actual == expected, "coverageContractMatched": coverage_matched,
        "complete": result.complete, "coverageGaps": gaps, "expectedCoverageGaps": [], "coverage": result.coverage,
        "planDigest": frozen.digest(), "inventoryDigest": inventory.digest, "embeddedChecks": embedded_checks_binding(),
        "expectedNativeDatabaseLabel": {"digest": digest(format!("trivy-builtin-checks\0Version: {VERSION}").as_bytes()), "kind": "shipped-producer-formula-version-derived-not-extracted-bundle-hash"},
        "toolIdentity": {"path": policy.tool, "executableDigest": policy.tool_digest, "version": version},
        "policy": policy.definition(), "policyDecisions": *decisions, "executionReceipt": receipt, "actualProviderResult": result,
        "receiptRetentionLimit": "Native producer retains reduced actual scan receipt, normalized findings & stdout digest. Full scanner JSON/raw cause locations/process receipt are not retained. Full actual version receipt retained; no scanner line accuracy claim."})
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
#[ignore = "requires official Trivy 0.69.3 & native macOS sandbox"]
fn real_scanner_accuracy_trivy_iac() {
    let cases = vec![case(true), case(false)];
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
    let mut record = json!({"schema": "legion-external-provider-accuracy/1", "provider": ID, "stage": "finding", "outputKind": "findings",
        "scope": "Constructed missing non-root USER & clean Dockerfile controls; actual Trivy config observations, not deployment rendering; no image/runtime/container-escape or population-accuracy claim; not production admission",
        "modelCalls": 0, "executionPath": "native-sdk-frozen-plan-real-external-scanner", "qualificationEligible": eligible,
        "coverageState": if complete { "complete" } else { "partial" }, "coverageGaps": gaps,
        "binding": {"providerSpecDigest": digest(&serde_json::to_vec(&provider).unwrap()), "harnessPath": SOURCE,
            "harnessDigest": digest(&fs::read(root.join(SOURCE)).unwrap()), "implementation": implementation_binding(&root), "embeddedChecks": embedded_checks_binding()},
        "metrics": {"truePositives": tp, "falsePositives": fp, "falseNegatives": missed,
            "precision": if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 },
            "recall": if tp + missed > 0 { tp as f64 / (tp + missed) as f64 } else { 0.0 }, "positiveCases": 1, "cleanCases": 1},
        "cases": cases, "status": if !controls_matched { "fail" } else if eligible { "pass" } else { "partial" }});
    record["qualificationDigest"] = json!(digest(&serde_json::to_vec(&record).unwrap()));
    if let Some(directory) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("container_iac.json"),
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
        "both controls require complete native deterministic finding coverage"
    );
}
