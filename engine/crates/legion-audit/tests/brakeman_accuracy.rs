//! Real Brakeman gem CLI controls through shipped frozen provider & native SDK.
//! CI provisions Ruby >= 3.2 & Brakeman 8.1.0, sets LEGION_BRAKEMAN_GEM_ROOT,
//! then prepends that gem's bin directory to PATH. No Rails boot/install occurs.
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

const SOURCE: &str = "engine/crates/legion-audit/tests/brakeman_accuracy.rs";
const PROVIDER: &str = "security.scanner-brakeman";
const TOOL: &str = "brakeman";
const VERSION: &str = "brakeman 8.1.0";
const POLICY: &str = "legion-brakeman-real-scanner-benchmark-v1";
const CONTROLLER: &str = "app/controllers/users_controller.rb";
const CONFIG: &str = "--- {}\n";
const TIMEOUT: u64 = 30_000;
const LIMIT: usize = 1024 * 1024;
// Exact published v8.1.0 gem entrypoint, rather than a substitute tool shim.
const ENTRYPOINT: &str = "#!/usr/bin/env ruby\n#Adjust path in case called directly and not through gem\n$:.unshift \"#{File.expand_path(File.dirname(__FILE__))}/../lib\"\n\nEncoding.default_external = 'UTF-8'\n\nrequire 'brakeman'\nrequire 'brakeman/commandline'\n\nBrakeman::Commandline.start\n";
const PLANTED: &str = "class UsersController < ApplicationController\n  def index\n    @users = User.where(\"name = '#{params[:name]}'\")\n  end\nend\n";
const CLEAN: &str = "class UsersController < ApplicationController\n  def index\n    @users = User.where(\"name = ?\", params[:name])\n  end\nend\n";
const SUPPORT: &[(&str, &str)] = &[
    ("Gemfile", "source 'https://rubygems.org'\ngem 'rails', '8.1.0'\n"),
    ("config/application.rb", "require 'rails/all'\nmodule BrakemanFixture\n  class Application < Rails::Application\n    config.load_defaults 8.1\n  end\nend\n"),
    ("config/routes.rb", "Rails.application.routes.draw do\n  get '/users', to: 'users#index'\nend\n"),
    ("app/controllers/application_controller.rb", "class ApplicationController < ActionController::Base\n  protect_from_forgery with: :exception\nend\n"),
    ("app/models/user.rb", "class User < ActiveRecord::Base\nend\n"),
];
const EXPECTATION_SOURCES: &[&str] = &[
    "https://brakemanscanner.org/docs/warning_types/sql_injection/",
    "https://brakemanscanner.org/docs/options/",
    "https://raw.githubusercontent.com/presidentbeef/brakeman/v8.1.0/bin/brakeman",
    "https://raw.githubusercontent.com/presidentbeef/brakeman/v8.1.0/lib/brakeman/checks/check_sql.rb",
    "https://raw.githubusercontent.com/presidentbeef/brakeman/v8.1.0/lib/brakeman/warning.rb",
    "https://raw.githubusercontent.com/presidentbeef/brakeman/v8.1.0/lib/brakeman/report/report_json.rb",
    "https://raw.githubusercontent.com/presidentbeef/brakeman/v8.1.0/lib/brakeman/commandline.rb",
];

fn digest(bytes: &[u8]) -> String {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

fn tree_binding(root: &Path) -> Value {
    fn visit(root: &Path, path: &Path, files: &mut Vec<(String, String)>) {
        assert!(!path.is_symlink(), "binding refuses symlinks");
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), files);
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
    let mut files = vec![];
    visit(root, root, &mut files);
    files.sort();
    json!({"fileCount": files.len(), "digest": digest(&serde_json::to_vec(&files).unwrap())})
}

fn scanner_argv(config: &str) -> Vec<String> {
    [
        "-c",
        config,
        "-q",
        "-f",
        "json",
        "--no-progress",
        "--no-exit-on-warn",
        "--no-exit-on-error",
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
            "legion-real-brakeman-{planted}-{}-{}",
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

/// Exact official gem entrypoint, installed gem bytes, Ruby executable & PATH.
/// Ruby is resolved through this PATH by the entrypoint's /usr/bin/env shebang.
struct RuntimeIdentity {
    gem: PathBuf,
    gem_binding: Value,
    ruby: PathBuf,
    ruby_digest: String,
    env_digest: String,
    path: String,
}
impl RuntimeIdentity {
    fn new(root: &Path, run: &Path, tool: &Path) -> Self {
        let gem = fs::canonicalize(
            std::env::var_os("LEGION_BRAKEMAN_GEM_ROOT")
                .expect("CI must identify provisioned Brakeman 8.1.0 gem directory"),
        )
        .unwrap();
        assert!(!gem.starts_with(root) && !gem.starts_with(run));
        assert_eq!(
            tool,
            fs::canonicalize(gem.join("bin/brakeman"))
                .unwrap()
                .as_path()
        );
        assert_eq!(
            fs::read(tool).unwrap(),
            ENTRYPOINT.as_bytes(),
            "only official gem entrypoint is admitted"
        );
        assert!(gem.join("lib/brakeman/checks/check_sql.rb").is_file());
        let resolved =
            resolve_request(root, "ruby", &[]).expect("real provisioned Ruby >= 3.2 required");
        let ruby = fs::canonicalize(&resolved.executable).unwrap();
        assert!(!ruby.starts_with(root) && !ruby.starts_with(run));
        let ruby_bytes = fs::read(&ruby).unwrap();
        assert!(!ruby_bytes.starts_with(b"#!"), "Ruby shims are forbidden");
        assert_eq!(digest(&ruby_bytes), resolved.digest);
        Self {
            gem_binding: tree_binding(&gem),
            gem,
            ruby,
            ruby_digest: resolved.digest,
            env_digest: digest(&fs::read("/usr/bin/env").unwrap()),
            path: std::env::var("PATH").unwrap(),
        }
    }
    fn definition(&self) -> Value {
        json!({"gemRoot": self.gem, "gemBinding": self.gem_binding,
            "ruby": {"path": self.ruby, "digest": self.ruby_digest},
            "shebangInterpreter": {"path": "/usr/bin/env", "digest": self.env_digest}, "path": self.path})
    }
    fn unchanged(&self, root: &Path) -> bool {
        let Ok(resolved) = resolve_request(root, "ruby", &[]) else {
            return false;
        };
        std::env::var("PATH").ok().as_deref() == Some(self.path.as_str())
            && fs::canonicalize(&resolved.executable).ok().as_ref() == Some(&self.ruby)
            && resolved.digest == self.ruby_digest
            && fs::read(&self.ruby)
                .ok()
                .map(|bytes| digest(&bytes))
                .as_deref()
                == Some(self.ruby_digest.as_str())
            && fs::read("/usr/bin/env")
                .ok()
                .map(|bytes| digest(&bytes))
                .as_deref()
                == Some(self.env_digest.as_str())
            && tree_binding(&self.gem) == self.gem_binding
    }
}

/// Fixture-only trusted policy; does not grant production scanner admission.
struct ScopedPolicy {
    root: PathBuf,
    run: PathBuf,
    inventory: String,
    tool: PathBuf,
    tool_digest: String,
    runtime: RuntimeIdentity,
    wrapper: PathBuf,
    wrapper_digest: String,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn new(root: &Path, run: &Path, inventory: &str) -> Self {
        let resolved = resolve_request(root, TOOL, &[]).unwrap_or_else(|error| {
            panic!("provisioned real Brakeman required: {}", error.message())
        });
        let tool = fs::canonicalize(&resolved.executable).unwrap();
        assert!(!tool.starts_with(root) && !tool.starts_with(run));
        assert_eq!(digest(&fs::read(&tool).unwrap()), resolved.digest);
        let runtime = RuntimeIdentity::new(root, run, &tool);
        let wrapper =
            fs::canonicalize("/usr/bin/sandbox-exec").expect("native macOS sandbox required");
        let wrapper_digest = digest(&fs::read(&wrapper).unwrap());
        Self {
            root: root.into(),
            run: run.into(),
            inventory: inventory.into(),
            tool,
            tool_digest: resolved.digest,
            runtime,
            wrapper,
            wrapper_digest,
            decisions: Mutex::new(vec![]),
        }
    }
    fn definition(&self) -> Value {
        json!({"id": POLICY, "version": 1, "provider": PROVIDER, "root": self.root,
            "runDirectory": self.run, "inventoryDigest": self.inventory,
            "tool": {"path": self.tool, "digest": self.tool_digest}, "runtime": self.runtime.definition(),
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest},
            "scannerArgv": scanner_argv("<owned-config-under-run>"),
            "ownedConfig": {"bytes": CONFIG, "digest": digest(CONFIG.as_bytes())}, "versionArgv": ["--version"],
            "timeoutMsMaximum": TIMEOUT, "outputBytesMaximum": LIMIT,
            "sandbox": "native-macos-deny-network-deny-project-write"})
    }
    fn permits(&self, request: &ExternalToolRequest) -> bool {
        let scan = request.task_id.as_deref() == Some(TOOL);
        let probe = request.task_id.as_deref() == Some("brakeman-version-probe");
        if !(scan || probe)
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
            || request.args.len() < 5
            || request.args[0] != "-f"
            || request.args[2] != "--"
            || fs::canonicalize(&request.args[3]).ok().as_ref() != Some(&self.tool)
            || fs::read(&self.tool)
                .ok()
                .map(|bytes| digest(&bytes))
                .as_deref()
                != Some(self.tool_digest.as_str())
            || !self.runtime.unchanged(&self.root)
        {
            return false;
        }
        let mut version = request.args[..4].to_vec();
        version.push("--version".into());
        if request.version_args != version {
            return false;
        }
        let suffix = if scan {
            let Some(path) = request.args.get(5) else {
                return false;
            };
            let Ok(config) = fs::canonicalize(path) else {
                return false;
            };
            if !config.starts_with(&self.run)
                || config.file_name().and_then(|name| name.to_str())
                    != Some("brakeman-owned-config")
                || fs::read(config).ok().as_deref() != Some(CONFIG.as_bytes())
            {
                return false;
            }
            scanner_argv(path)
        } else {
            vec!["--version".into()]
        };
        if request.args[4..] != suffix
            || request.accepted_exit_codes != [0].into_iter().collect::<BTreeSet<_>>()
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
            || request.environment.get("PATH") != Some(&self.runtime.path)
            || (probe && request.environment.len() != 1)
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
                    .is_some_and(|path| Path::new(path).starts_with(&self.run))
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
        self.decisions.lock().unwrap().push(json!({"allowed": allowed,
            "requestId": request.request_id, "providerId": request.provider_id, "planId": request.plan_id,
            "taskId": request.task_id, "executable": request.executable, "expectedDigest": request.expected_digest,
            "args": request.args, "versionArgs": request.version_args, "cwd": request.cwd,
            "timeoutMs": request.timeout_ms, "stdoutLimit": request.stdout_limit, "stderrLimit": request.stderr_limit,
            "acceptedExitCodes": request.accepted_exit_codes, "environmentNames": request.environment_allowlist,
            "requiresNetworkSandbox": request.requires_network_sandbox}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&serde_json::to_vec(&self.definition()).unwrap()),
            reason: Some(
                if allowed {
                    "fixture-scoped real Brakeman benchmark"
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
    json!({"path": artifact.path, "digest": artifact.digest, "bytes": artifact.bytes,
        "immutable": artifact.immutable, "raw": String::from_utf8(bytes).unwrap()})
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
        request_id: "real-brakeman-version".into(),
        provider_id: PROVIDER.into(),
        plan_id: policy.inventory.clone(),
        policy_id: legion_audit::execution_policy::POLICY_ID.into(),
        task_id: Some("brakeman-version-probe".into()),
        executable: auth.wrapped_executable,
        args: auth.wrapped_args.clone(),
        version_args: auth.wrapped_args,
        cwd: policy.root.to_string_lossy().into_owned(),
        origin: ToolOrigin::System,
        environment: BTreeMap::from([("PATH".into(), policy.runtime.path.clone())]),
        environment_allowlist: BTreeSet::from(["PATH".into()]),
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
    let out = stdout["raw"].as_str().unwrap();
    let err = stderr["raw"].as_str().unwrap();
    let combined = if out.is_empty() {
        err.to_owned()
    } else if err.is_empty() {
        out.to_owned()
    } else {
        format!("{out}{}{err}", if out.ends_with('\n') { "" } else { "\n" })
    };
    let version = exe.version.output.as_deref().unwrap();
    assert_eq!(version.trim(), VERSION, "provision pinned real gem");
    assert_eq!(combined.trim(), version.trim());
    json!({"rawVersionOutput": version, "receipt": {"schemaVersion": receipt.schema_version,
        "receiptId": receipt.receipt_id, "requestId": receipt.request_id, "providerId": receipt.provider_id,
        "planId": receipt.plan_id, "taskId": receipt.task_id, "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id": p.id, "version": p.version, "digest": p.digest, "allowed": p.allowed, "reason": p.reason})),
        "state": receipt.state.as_str(), "complete": receipt.complete, "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "executable": {"path": exe.canonical_path, "digest": exe.digest, "version": {"args": exe.version.args,
            "output": version, "exitCode": exe.version.exit_code, "qualified": exe.version.qualified, "skippedByPolicy": exe.version.skipped_by_policy}},
        "sandbox": {"required": receipt.sandbox.required, "receiptId": receipt.sandbox.receipt_id, "networkEnabled": receipt.sandbox.network_enabled},
        "processTree": {"started": receipt.process_tree.started, "terminated": receipt.process_tree.terminated,
            "hardKilled": receipt.process_tree.hard_killed, "reaped": receipt.process_tree.reaped, "detail": receipt.process_tree.detail},
        "timing": {"startedAtMs": receipt.timing.started_at_ms, "completedAtMs": receipt.timing.completed_at_ms, "durationMs": receipt.timing.duration_ms},
        "stdout": stdout, "stderr": stderr, "exitCode": receipt.exit_code, "signal": receipt.signal,
        "parser": {"attempted": receipt.parser.attempted, "succeeded": receipt.parser.succeeded, "error": receipt.parser.error}, "gaps": receipt.gaps}})
}

fn case(planted: bool) -> Value {
    let fixture = Fixture::new(planted);
    let root = fixture.0.join("source");
    let run = fixture.0.join("run");
    let source = if planted { PLANTED } else { CLEAN };
    let mut files = SUPPORT.to_vec();
    files.push((CONTROLLER, source));
    files.sort_by_key(|(path, _)| *path);
    for (path, bytes) in &files {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), bytes).unwrap();
    }
    let case_id = if planted {
        "brakeman-planted"
    } else {
        "brakeman-clean"
    };
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(case_id)
        .unwrap();
    let fixture_files: Vec<Value> = files
        .iter()
        .map(|(path, bytes)| {
            let expected = digest(bytes.as_bytes());
            assert_eq!(
                inventory
                    .entries
                    .iter()
                    .find(|entry| entry.path == *path)
                    .unwrap()
                    .digest
                    .as_deref(),
                Some(expected.as_str())
            );
            json!({"path": path, "bytes": bytes, "digest": expected})
        })
        .collect();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec().0])
        .unwrap()
        .freeze(Some(b"brakeman-real-scanner-benchmark-key"))
        .unwrap();
    let provider = frozen
        .provider(PROVIDER)
        .expect("applicable shipped provider");
    // Five Ruby source files; Gemfile is bound context outside shipped selector.
    assert_eq!(provider.configuration["denominatorCount"], 5);
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
    assert_eq!(execution.planned_providers, vec![PROVIDER.to_owned()]);
    assert_eq!(execution.results.len(), 1);
    let entry = &execution.results[0];
    assert_eq!(entry.provider, PROVIDER);
    assert!(!entry.skipped);
    let result = &entry.result;
    assert!(result.applicable && result.details.get("availability").is_none());
    assert!(
        result.findings.is_empty(),
        "scanner warnings remain unadjudicated candidates"
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (5, 5));
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
    assert_eq!(receipt["tool"]["version"], VERSION);
    assert_eq!(receipt["sandbox"]["required"], true);
    assert!(receipt["sandbox"]["receiptId"]
        .as_str()
        .unwrap()
        .starts_with("sandbox:macos:"));
    assert!(receipt["stdoutDigest"]
        .as_str()
        .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71));
    assert!(receipt["stdoutBytes"]
        .as_u64()
        .is_some_and(|bytes| bytes > 0));
    assert_eq!(
        receipt["exitCode"], 0,
        "production disables warning/error exit statuses; coverage still rejects errors"
    );
    let candidates = result.details["candidates"].as_array().unwrap();
    let actual: Vec<String> = candidates
        .iter()
        .map(|candidate| {
            assert_eq!(candidate["source"]["tool"], TOOL);
            assert_eq!(candidate["adjudication"], "required");
            let raw = &candidate["source"]["raw"];
            assert_eq!(
                candidate["source"]["rawFindingDigest"],
                digest(&serde_json::to_vec(raw).unwrap())
            );
            assert_eq!(raw["check_name"], "SQL");
            assert_eq!(raw["warning_type"], "SQL Injection");
            assert_eq!(raw["message"], "Possible SQL injection");
            assert_eq!(raw["file"], CONTROLLER);
            assert_eq!(raw["line"], 3);
            assert_eq!(candidate["evidence"][0]["path"], CONTROLLER);
            assert_eq!(candidate["evidence"][0]["line"], 3);
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
    // Independent source-fixed oracle: check_sql emits CheckSQL, warning.rb
    // strips Brakeman::Check to SQL & takes user-input's one-based Ruby line.
    let expected: Vec<String> = if planted {
        vec!["SQL|app/controllers/users_controller.rb|3".into()]
    } else {
        vec![]
    };
    let expected_gaps: Vec<Value> = vec![];
    let gaps: Vec<Value> = result
        .coverage_gaps
        .iter()
        .map(|gap| serde_json::from_str(gap).unwrap())
        .collect();
    let coverage_matched = gaps == expected_gaps
        && coverage.gaps == result.coverage_gaps
        && result.degradation.is_empty()
        && result.complete;
    for (path, bytes) in &files {
        assert_eq!(fs::read(root.join(path)).unwrap(), bytes.as_bytes());
    }
    assert!(policy.runtime.unchanged(&root));
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(
        decisions.len(),
        2,
        "one real native version probe & one production scan"
    );
    assert!(decisions.iter().all(|decision| decision["allowed"] == true));
    json!({"caseId": case_id, "source": {"path": CONTROLLER, "bytes": source, "digest": digest(source.as_bytes())},
        "fixture": {"files": fixture_files, "digest": digest(&serde_json::to_vec(&fixture_files).unwrap())},
        "expected": expected, "actual": actual, "controlMatched": actual == expected, "coverageContractMatched": coverage_matched,
        "complete": result.complete, "coverageGaps": gaps, "expectedCoverageGaps": expected_gaps,
        "planDigest": frozen.digest(), "inventoryDigest": inventory.digest, "coverage": result.coverage,
        "toolIdentity": {"path": policy.tool, "executableDigest": policy.tool_digest, "version": version, "runtime": policy.runtime.definition()},
        "policy": policy.definition(), "policyDecisions": *decisions, "executionReceipt": receipt, "actualProviderResult": result,
        "receiptRetentionLimit": "Scanner producer retains its actual reduced receipt, normalized raw findings & stdout digest; full scanner stdout/process-tree receipt is not retained. Separate real native version output & receipt are retained."})
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
#[ignore = "requires real Brakeman 8.1.0 gem, Ruby >= 3.2 & native macOS sandbox"]
fn real_scanner_accuracy_brakeman() {
    let cases = vec![case(true), case(false)];
    let controls_matched = cases
        .iter()
        .all(|case| case["controlMatched"] == true && case["coverageContractMatched"] == true);
    let complete = cases.iter().all(|case| {
        case["complete"] == true && case["coverageGaps"].as_array().unwrap().is_empty()
    });
    let eligible = controls_matched && complete;
    let (mut tp, mut fp, mut missed) = (0usize, 0usize, 0usize);
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
    let (_, mut provider) = spec();
    provider.as_object_mut().unwrap().remove("benchmark");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let gaps: Vec<Value> = cases
        .iter()
        .flat_map(|case| {
            case["coverageGaps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|gap| json!({"caseId": case["caseId"], "gap": gap}))
        })
        .collect();
    let mut record = json!({"schema": "legion-external-provider-accuracy/1", "provider": PROVIDER, "stage": "candidate",
        "scope": "Constructed planted & clean controls; not population accuracy or production admission", "modelCalls": 0,
        "executionPath": "native-sdk-frozen-plan-real-external-scanner", "qualificationEligible": eligible,
        "coverageState": if complete { "complete" } else { "partial" }, "coverageGaps": gaps,
        "binding": {"providerSpecDigest": digest(&serde_json::to_vec(&provider).unwrap()), "harnessPath": SOURCE,
            "harnessDigest": digest(&fs::read(root.join(SOURCE)).unwrap()), "implementation": implementation_binding(&root)},
        "expectationSources": EXPECTATION_SOURCES,
        "metrics": {"truePositives": tp, "falsePositives": fp, "falseNegatives": missed,
            "precision": if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 },
            "recall": if tp + missed > 0 { tp as f64 / (tp + missed) as f64 } else { 0.0 }, "positiveCases": 1, "cleanCases": 1},
        "cases": cases, "status": if !controls_matched { "fail" } else if eligible { "pass" } else { "partial" }});
    record["qualificationDigest"] = json!(digest(&serde_json::to_vec(&record).unwrap()));
    if let Some(directory) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("security_scanner-brakeman.json"),
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
        "real controls & exact production gaps must match"
    );
    assert!(
        eligible,
        "both controls need complete native candidate-generator coverage"
    );
}
