//! Real, offline golangci-lint controls through the frozen production provider.
//! Provision pinned Go + golangci-lint & native macOS sandbox before running.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute,
    native_providers::{
        legacy_checks::AuditExternalProjectTool, security::producer::ArtifactProducer,
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

const SOURCE: &str = "engine/crates/legion-audit/tests/golangci_accuracy.rs";
const PROVIDER: &str = "security.scanner-golangci-lint";
const TOOL: &str = "golangci-lint";
const POLICY: &str = "legion-golangci-real-scanner-benchmark-v1";
const VERSION_PREFIX: &str = "golangci-lint has version 2.15.0";
const GO_VERSION: &str = "go1.26.7";
const TIMEOUT: u64 = 120_000;
const LIMIT: usize = 1024 * 1024;
const MODULE: &str = "module example.invalid/legion-golangci-fixture\n\ngo 1.26.0\n";
const PLANTED: &str = "package main\n\nfunc main() {\n\tpassword := \"f62e5bcda4fae4f82370da0c6f20697b8f8447ef\"\n\t_ = password\n}\n";
const CLEAN: &str = "package main\n\nfunc main() {\n\tpassword := \"secret\"\n\t_ = password\n}\n";
const EXPECTED: &str = "gosec|main.go|4";

fn digest(bytes: &[u8]) -> String {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

fn scanner_argv() -> Vec<String> {
    [
        "run",
        "--no-config",
        "--modules-download-mode=readonly",
        "--path-mode=abs",
        "--output.json.path=stdout",
        "--show-stats=false",
        "--enable=gosec",
        "./...",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
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
        .find(|provider| provider["id"] == PROVIDER)
        .expect("shipped golangci-lint provider")
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
            "legion-real-golangci-{planted}-{}-{}",
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

/// This benchmark-only authorizer admits the exact real binary, immutable
/// fixture, producer argv, offline Go env & native sandbox profile.
struct ScopedPolicy {
    root: PathBuf,
    run: PathBuf,
    inventory: String,
    tool: PathBuf,
    tool_digest: String,
    go_root: PathBuf,
    go_binary: PathBuf,
    go_digest: String,
    go_path: String,
    tool_archive: PathBuf,
    go_archive: PathBuf,
    tool_archive_sha: String,
    go_archive_sha: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    decisions: Mutex<Vec<Value>>,
}

fn release_archive_digests() -> (String, String) {
    match std::env::consts::ARCH {
        "aarch64" => (
            "sha256:d1e409481a8ca846c4bc97e781eb5cb1bd5c23353a0b3977a1cbda1b1b6447d5".into(),
            "sha256:020a1e8224811be75163e920bc77e0926a1390a6aeea19bdcf23f74b9d749f6d".into(),
        ),
        "x86_64" => (
            "sha256:767b899a28285e88ded2823d5dcc4bc5ef681173eb2d80f029a7b17ee4ece3b8".into(),
            "sha256:92e8b34bff3c89ab16404c595669ac8cb004cc2f676dcbd1f5b87a6b8def3b47".into(),
        ),
        other => panic!("unsupported pinned macOS architecture: {other}"),
    }
}

fn release_assets() -> (&'static str, &'static str) {
    match std::env::consts::ARCH {
        "aarch64" => (
            "golangci-lint-2.15.0-darwin-arm64.tar.gz",
            "go1.26.7.darwin-arm64.tar.gz",
        ),
        "x86_64" => (
            "golangci-lint-2.15.0-darwin-amd64.tar.gz",
            "go1.26.7.darwin-amd64.tar.gz",
        ),
        other => panic!("unsupported pinned macOS architecture: {other}"),
    }
}

impl ScopedPolicy {
    fn new(root: &Path, run: &Path, inventory: &str) -> Self {
        let tool_archive = fs::canonicalize(
            std::env::var_os("LEGION_GOLANGCI_LINT_ARCHIVE")
                .expect("set verified LEGION_GOLANGCI_LINT_ARCHIVE"),
        )
        .expect("golangci-lint release archive must exist");
        let go_archive = fs::canonicalize(
            std::env::var_os("LEGION_GO_ARCHIVE").expect("set verified LEGION_GO_ARCHIVE"),
        )
        .expect("Go release archive must exist");
        assert!(!tool_archive.starts_with(root) && !tool_archive.starts_with(run));
        assert!(!go_archive.starts_with(root) && !go_archive.starts_with(run));
        let (tool_archive_sha, go_archive_sha) = release_archive_digests();
        let (tool_asset, go_asset) = release_assets();
        assert_eq!(
            tool_archive.file_name().and_then(|name| name.to_str()),
            Some(tool_asset)
        );
        assert_eq!(
            go_archive.file_name().and_then(|name| name.to_str()),
            Some(go_asset)
        );
        assert_eq!(digest(&fs::read(&tool_archive).unwrap()), tool_archive_sha);
        assert_eq!(digest(&fs::read(&go_archive).unwrap()), go_archive_sha);
        let tool = fs::canonicalize(
            std::env::var_os("LEGION_GOLANGCI_LINT_BIN")
                .expect("provision golangci-lint 2.15.0; set LEGION_GOLANGCI_LINT_BIN"),
        )
        .expect("real golangci-lint binary must exist");
        assert_eq!(tool.file_name().and_then(|name| name.to_str()), Some(TOOL));
        assert_eq!(
            tool.parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str()),
            Some(if std::env::consts::ARCH == "aarch64" {
                "golangci-lint-2.15.0-darwin-arm64"
            } else {
                "golangci-lint-2.15.0-darwin-amd64"
            })
        );
        assert!(!tool.starts_with(root) && !tool.starts_with(run));
        let tool_bytes = fs::read(&tool).expect("read scanner binary");
        assert!(
            !tool_bytes.starts_with(b"#!"),
            "script substitutes forbidden"
        );
        let tool_digest = digest(&tool_bytes);
        let go_root = fs::canonicalize(
            std::env::var_os("LEGION_GO_ROOT").expect("provision Go 1.26.7; set LEGION_GO_ROOT"),
        )
        .expect("pinned Go root must exist");
        let runner_temp =
            fs::canonicalize(std::env::var_os("RUNNER_TEMP").expect("CI must provide RUNNER_TEMP"))
                .expect("CI runner temp must exist");
        let provisioned_go_root = runner_temp.join("legion-go-toolchain/go");
        assert_eq!(go_root, provisioned_go_root);
        assert!(!go_root.starts_with(root) && !go_root.starts_with(run));
        assert!(
            go_root.join("pkg/tool").is_dir(),
            "complete Go toolchain required"
        );
        let go_binary = fs::canonicalize(go_root.join("bin/go")).expect("pinned Go binary");
        assert!(go_binary.starts_with(go_root.join("bin")));
        assert!(!go_binary.starts_with(root) && !go_binary.starts_with(run));
        let go_bytes = fs::read(&go_binary).expect("read Go binary");
        assert!(!go_bytes.starts_with(b"#!"), "Go binary must be native");
        let go_digest = digest(&go_bytes);
        let expected_path = format!("{}:/usr/bin:/bin", go_root.join("bin").display());
        let path = std::env::var("PATH").expect("PATH must select pinned Go first");
        assert_eq!(
            path, expected_path,
            "benchmark requires an exact pinned PATH"
        );
        let wrapper = fs::canonicalize("/usr/bin/sandbox-exec")
            .expect("native macOS sandbox executable required");
        let wrapper_digest = digest(&fs::read(&wrapper).unwrap());
        Self {
            root: root.into(),
            run: run.into(),
            inventory: inventory.into(),
            tool,
            tool_digest,
            go_root,
            go_binary,
            go_digest,
            go_path: path,
            tool_archive,
            go_archive,
            tool_archive_sha,
            go_archive_sha,
            wrapper,
            wrapper_digest,
            decisions: Mutex::new(Vec::new()),
        }
    }

    fn definition(&self) -> Value {
        json!({
            "id": POLICY,
            "version": 1,
            "provider": PROVIDER,
            "root": self.root,
            "runDirectory": self.run,
            "inventoryDigest": self.inventory,
            "tool": {"path": self.tool, "digest": self.tool_digest,
                "versionPrefix": VERSION_PREFIX,
                "officialRelease": "https://github.com/golangci/golangci-lint/releases/tag/v2.15.0",
                "archive": self.tool_archive, "archiveDigest": self.tool_archive_sha,
                "asset": release_assets().0},
            "goToolchain": {"root": self.go_root, "binary": self.go_binary, "digest": self.go_digest,
                "version": GO_VERSION, "path": self.go_path,
                "officialRelease": "https://go.dev/dl/", "archive": self.go_archive,
                "archiveDigest": self.go_archive_sha, "asset": release_assets().1},
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest},
            "scannerArgv": scanner_argv(),
            "versionArgv": ["<native-sandbox-prefix>", "--version"],
            "timeoutMsMaximum": TIMEOUT,
            "outputBytesMaximum": LIMIT,
            "sandbox": "native-macos-deny-network-deny-project-write",
            "offlineEnvironment": {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off",
                "GOWORK": "off", "CGO_ENABLED": "0"}
        })
    }

    fn permits(&self, request: &ExternalToolRequest) -> bool {
        if request.task_id.as_deref() == Some("go-version-probe") {
            if request.provider_id != PROVIDER
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
                || request.args.len() != 5
                || request.args[0] != "-f"
                || request.args[2] != "--"
                || fs::canonicalize(&request.args[3]).ok().as_ref() != Some(&self.go_binary)
                || request.args[4] != "version"
                || request.version_args != request.args
                || request.accepted_exit_codes != [0].into_iter().collect()
                || !request.environment.is_empty()
                || !request.environment_allowlist.is_empty()
            {
                return false;
            }
            return self.valid_sandbox_profile(request);
        }
        let expected_version_args = request
            .args
            .iter()
            .take(4)
            .cloned()
            .chain(std::iter::once("--version".to_owned()))
            .collect::<Vec<_>>();
        if request.task_id.as_deref() != Some(TOOL)
            || request.provider_id != PROVIDER
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
            || fs::read(&self.wrapper)
                .ok()
                .map(|bytes| digest(&bytes))
                .as_deref()
                != Some(self.wrapper_digest.as_str())
            || !request.sensitive_argument_indexes.is_empty()
            || !request.sensitive_environment_names.is_empty()
            || request.args.len() != 12
            || request.args[0] != "-f"
            || request.args[2] != "--"
            || fs::canonicalize(&request.args[3]).ok().as_ref() != Some(&self.tool)
            || fs::read(&self.tool)
                .ok()
                .map(|bytes| digest(&bytes))
                .as_deref()
                != Some(self.tool_digest.as_str())
            || request.args[4..] != scanner_argv()
            || request.version_args != expected_version_args
            || request.accepted_exit_codes != [0, 1].into_iter().collect()
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
        if request.environment.keys().any(|key| !allowed.contains(key))
            || request.environment.keys().cloned().collect::<BTreeSet<_>>()
                != request.environment_allowlist
            || request.environment.get("PATH").map(String::as_str) != Some(self.go_path.as_str())
        {
            return false;
        }
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
                .is_some_and(|path| Path::new(path).starts_with(&self.run))
            {
                return false;
            }
        }
        self.valid_sandbox_profile(request)
    }

    fn valid_sandbox_profile(&self, request: &ExternalToolRequest) -> bool {
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
        let expected_profile = format!(
            "(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n"
        );
        let Ok(profile) = fs::read(profile_path) else {
            return false;
        };
        profile == expected_profile.as_bytes()
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
        self.decisions.lock().unwrap().push(json!({
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
            "timeoutMs": request.timeout_ms,
            "stdoutLimit": request.stdout_limit,
            "stderrLimit": request.stderr_limit,
            "acceptedExitCodes": request.accepted_exit_codes,
            "environmentNames": request.environment_allowlist,
            "environment": request.environment,
            "requiresNetworkSandbox": request.requires_network_sandbox,
        }));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&serde_json::to_vec(&self.definition()).unwrap()),
            reason: Some(
                if allowed {
                    "fixture-scoped real offline golangci-lint benchmark"
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

fn go_version_probe(policy: &Arc<ScopedPolicy>) -> Value {
    let auth = legion_effects::authenticate_sandbox(
        &policy.go_binary.to_string_lossy(),
        &["version".into()],
        &policy.root.to_string_lossy(),
        legion_effects::SandboxMode::DenyNetworkDenyProjectWrite,
        &policy.run.join("go-version-sandbox"),
    )
    .expect("native sandbox for pinned Go version probe");
    let request = ExternalToolRequest {
        request_id: "real-golangci-go-version".into(),
        provider_id: PROVIDER.into(),
        plan_id: policy.inventory.clone(),
        policy_id: legion_audit::execution_policy::POLICY_ID.into(),
        task_id: Some("go-version-probe".into()),
        executable: auth.wrapped_executable,
        args: auth.wrapped_args.clone(),
        version_args: auth.wrapped_args.clone(),
        cwd: policy.root.to_string_lossy().into_owned(),
        origin: ToolOrigin::System,
        expected_digest: Some(policy.wrapper_digest.clone()),
        requires_network_sandbox: true,
        sandbox: Some(legion_effects::SandboxReceipt {
            id: auth.id,
            network: auth.network,
            filesystem_scope: auth.filesystem_scope,
        }),
        timeout_ms: TIMEOUT,
        stdout_limit: LIMIT,
        stderr_limit: LIMIT,
        accepted_exit_codes: [0].into_iter().collect(),
        ..ExternalToolRequest::default()
    };
    let artifacts = policy.run.join("go-version-artifacts");
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
    assert!(receipt.sandbox.required && receipt.sandbox.network_enabled);
    let artifact = receipt.stdout.as_ref().expect("Go version stdout artifact");
    let bytes = fs::read(artifacts.join(&artifact.path)).expect("read actual Go version output");
    assert!(artifact.immutable);
    assert_eq!(digest(&bytes), artifact.digest);
    let output = String::from_utf8(bytes).expect("Go version output is UTF-8");
    assert!(
        output
            .trim()
            .starts_with(&format!("go version {GO_VERSION} darwin/")),
        "{output:?}"
    );
    let version = output.trim().to_owned();
    json!({
        "version": version,
        "receipt": {
            "schemaVersion": receipt.schema_version,
            "receiptId": receipt.receipt_id,
            "requestId": receipt.request_id,
            "providerId": receipt.provider_id,
            "planId": receipt.plan_id,
            "taskId": receipt.task_id,
            "policyId": receipt.policy_id,
            "state": receipt.state.as_str(),
            "complete": receipt.complete,
            "cwd": receipt.cwd,
            "executable": receipt.executable.as_ref().map(|exe| json!({"path":exe.canonical_path,"digest":exe.digest})),
            "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
            "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"reaped":receipt.process_tree.reaped},
            "exitCode": receipt.exit_code,
            "stdout": {"path":artifact.path,"digest":artifact.digest,"bytes":artifact.bytes,"immutable":artifact.immutable,"raw":version}
        }
    })
}

fn case(planted: bool) -> Value {
    let fixture = Fixture::new(planted);
    let root = fixture.0.join("source");
    let run = fixture.0.join("run");
    let source = if planted { PLANTED } else { CLEAN };
    fs::write(root.join("go.mod"), MODULE).unwrap();
    fs::write(root.join("main.go"), source).unwrap();
    let source_digest = digest(source.as_bytes());
    let module_digest = digest(MODULE.as_bytes());
    let case_id = if planted {
        "golangci-planted"
    } else {
        "golangci-clean"
    };
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(case_id)
        .unwrap();
    assert_eq!(inventory.entries.len(), 2);
    assert_eq!(
        inventory
            .entries
            .iter()
            .find(|entry| entry.path == "main.go")
            .unwrap()
            .digest
            .as_deref(),
        Some(source_digest.as_str())
    );
    let (provider_spec, _) = spec();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[provider_spec])
        .unwrap()
        .freeze(Some(b"golangci-real-scanner-benchmark-key"))
        .unwrap();
    assert_eq!(frozen.providers().len(), 1);
    assert_eq!(frozen.providers()[0].id, PROVIDER);
    let provider = frozen.provider(PROVIDER).expect("frozen selected provider");
    assert_eq!(provider.configuration["denominatorCount"], 1);
    let policy = Arc::new(ScopedPolicy::new(&root, &run, &inventory.digest));
    let go_version = go_version_probe(&policy);
    let mut registry = NativeProviderRegistry::new(&root);
    registry.security = registry.security.with_producer(
        ArtifactProducer::new(&root)
            .with_run_dir(&run)
            .with_search_path(vec![policy.tool.parent().unwrap().to_path_buf()])
            .with_bounds(TIMEOUT, LIMIT)
            .with_policy_authorizer(policy.clone()),
    );
    let execution = execute(&frozen, &inventory, &registry).unwrap();
    assert_eq!(execution.planned_providers, vec![PROVIDER]);
    assert_eq!(execution.results.len(), 1);
    let entry = &execution.results[0];
    assert_eq!(entry.provider, PROVIDER);
    assert!(!entry.skipped);
    let result = &entry.result;
    eprintln!(
        "REAL_SCANNER_CASE_DIAGNOSTIC {}",
        serde_json::to_string(&json!({
            "providerId": PROVIDER, "planted": planted, "actualProviderResult": result
        }))
        .unwrap()
    );
    assert!(result.applicable);
    assert!(result.details.get("availability").is_none());
    assert!(result.findings.is_empty(), "scanner output is candidates");
    let coverage = result.coverage.as_ref().expect("frozen coverage");
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
    assert_eq!(receipt["tool"]["name"], TOOL);
    assert_eq!(receipt["executableDigest"], policy.tool_digest);
    assert_eq!(receipt["tool"]["executableDigest"], policy.tool_digest);
    let version = receipt["tool"]["version"]
        .as_str()
        .expect("native version probe");
    assert!(
        version.starts_with(VERSION_PREFIX),
        "unexpected real version: {version}"
    );
    assert_eq!(receipt["sandbox"]["required"], true);
    assert!(receipt["sandbox"]["receiptId"]
        .as_str()
        .unwrap()
        .starts_with("sandbox:macos:"));
    assert_eq!(receipt["exitCode"], if planted { 1 } else { 0 });
    assert!(receipt["stdoutDigest"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71));
    assert!(receipt["stdoutBytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
    assert!(
        result.complete,
        "native scanner result incomplete: {result:?}"
    );
    assert!(
        result.coverage_gaps.is_empty(),
        "native scan has gaps: {:?}",
        result.coverage_gaps
    );
    assert!(result.degradation.is_empty());

    let candidates = result.details["candidates"]
        .as_array()
        .expect("candidate array");
    let actual: Vec<String> = candidates
        .iter()
        .map(|candidate| {
            assert_eq!(candidate["source"]["tool"], TOOL);
            assert_eq!(candidate["adjudication"], "required");
            assert_eq!(candidate["anchorKind"], "line");
            assert_eq!(candidate["anchorStatus"], "scanner-reported");
            assert_eq!(candidate["source"]["raw"]["FromLinter"], "gosec");
            assert_eq!(candidate["source"]["raw"]["Pos"]["Line"], 4);
            assert_eq!(
                candidate["source"]["raw"]["Pos"]["Filename"],
                root.join("main.go").to_string_lossy().as_ref()
            );
            format!(
                "{}|{}|{}",
                candidate["ruleId"].as_str().unwrap(),
                candidate["path"].as_str().unwrap_or("unresolved"),
                candidate["line"]
                    .as_u64()
                    .map(|line| line.to_string())
                    .unwrap_or_else(|| "unresolved".into())
            )
        })
        .collect();
    let expected = if planted {
        vec![EXPECTED.to_owned()]
    } else {
        Vec::new()
    };
    let actual_gaps: Vec<Value> = result
        .coverage_gaps
        .iter()
        .map(|gap| serde_json::from_str(gap).unwrap())
        .collect();
    let coverage_matched = coverage.complete() && actual_gaps.is_empty() && result.complete;
    assert_eq!(fs::read(root.join("main.go")).unwrap(), source.as_bytes());
    assert_eq!(
        digest(&fs::read(root.join("main.go")).unwrap()),
        source_digest
    );
    assert_eq!(fs::read(root.join("go.mod")).unwrap(), MODULE.as_bytes());
    assert_eq!(
        digest(&fs::read(root.join("go.mod")).unwrap()),
        module_digest
    );
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(
        decisions.len(),
        2,
        "one real Go version probe & scanner execution"
    );
    assert!(decisions.iter().all(|decision| decision["allowed"] == true));
    json!({
        "caseId": case_id,
        "source": {"path":"main.go", "bytes":source, "digest":source_digest},
        "goModule": {"path":"go.mod", "bytes":MODULE, "digest":module_digest},
        "expected": expected,
        "actual": actual,
        "controlMatched": actual == expected,
        "coverageContractMatched": coverage_matched,
        "complete": result.complete,
        "coverageGaps": actual_gaps,
        "planDigest": frozen.digest(),
        "inventoryDigest": inventory.digest,
        "coverage": coverage,
        "toolIdentity": {"path":policy.tool, "executableDigest":policy.tool_digest, "version":version},
        "goToolchain": {"root":policy.go_root, "binary":policy.go_binary, "digest":policy.go_digest, "requiredVersion":GO_VERSION, "actualVersion":go_version},
        "policy": policy.definition(),
        "policyDecisions": *decisions,
        "executionReceipt": receipt,
        "actualProviderResult": result,
        "receiptRetentionLimit": "production retains reduced native scanner receipt and stdout digest, not full scanner process-tree receipt"
    })
}

fn implementation_binding(root: &Path) -> Value {
    fn bind(root: &Path, path: &Path, files: &mut Vec<(String, String)>) {
        assert!(
            !path.is_symlink(),
            "implementation binding refuses symlinks"
        );
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
    let mut files = Vec::new();
    for path in roots {
        bind(root, &root.join(path), &mut files);
    }
    for path in [
        "engine/Cargo.lock",
        "engine/Cargo.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
    ] {
        bind(root, &root.join(path), &mut files);
    }
    files.sort();
    json!({"roots":roots, "fileCount":files.len(), "digest":digest(&serde_json::to_vec(&files).unwrap())})
}

#[test]
#[ignore = "requires pinned Go 1.26.7, golangci-lint 2.15.0 & native macOS sandbox"]
fn real_scanner_accuracy_golangci_lint() {
    let cases = [case(true), case(false)];
    let controls_matched = cases
        .iter()
        .all(|case| case["controlMatched"] == true && case["coverageContractMatched"] == true);
    let complete = cases.iter().all(|case| {
        case["complete"] == true && case["coverageGaps"].as_array().unwrap().is_empty()
    });
    let eligible = controls_matched && complete;
    let (mut tp, mut fp, mut fn_) = (0usize, 0usize, 0usize);
    for case in &cases {
        let expected = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .unwrap();
        let actual = case["actual"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .unwrap();
        let mut matched = vec![false; actual.len()];
        for expectation in expected {
            if let Some((index, _)) = actual
                .iter()
                .enumerate()
                .find(|(index, actual)| !matched[*index] && **actual == expectation)
            {
                matched[index] = true;
                tp += 1;
            } else {
                fn_ += 1;
            }
        }
        fp += matched.iter().filter(|value| !**value).count();
    }
    let (_, mut provider) = spec();
    provider.as_object_mut().unwrap().remove("benchmark");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut record = json!({
        "schema":"legion-external-provider-accuracy/1",
        "provider":PROVIDER,
        "stage":"candidate",
        "scope":"Constructed planted & clean Go controls; not population accuracy or production admission",
        "modelCalls":0,
        "executionPath":"native-sdk-frozen-plan-real-external-scanner",
        "qualificationEligible":eligible,
        "coverageState":if complete {"complete"} else {"partial"},
        "coverageGaps":cases.iter().flat_map(|case| case["coverageGaps"].as_array().unwrap().iter().map(|gap| json!({"caseId":case["caseId"],"gap":gap}))).collect::<Vec<_>>(),
        "binding":{"providerSpecDigest":digest(&serde_json::to_vec(&provider).unwrap()), "harnessPath":SOURCE,
            "harnessDigest":digest(&fs::read(root.join(SOURCE)).unwrap()), "implementation":implementation_binding(&root)},
        "expectationSources":["https://securego.io/docs/rules/g101"],
        "metrics":{"truePositives":tp,"falsePositives":fp,"falseNegatives":fn_,
            "precision":if tp + fp > 0 {tp as f64 / (tp + fp) as f64} else {0.0},
            "recall":if tp + fn_ > 0 {tp as f64 / (tp + fn_) as f64} else {0.0},
            "positiveCases":1,"cleanCases":1},
        "cases":cases,
        "status":if !controls_matched {"fail"} else if eligible {"pass"} else {"partial"}
    });
    record["qualificationDigest"] = json!(digest(&serde_json::to_vec(&record).unwrap()));
    if let Some(directory) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("security_scanner-golangci-lint.json"),
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
        "real gosec candidate & clean control must match exactly"
    );
    assert!(
        eligible,
        "both cases need complete frozen native scanner coverage"
    );
}
