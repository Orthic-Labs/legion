//! Self-sourcing artifact producer for the security-family providers.
//!
//! The adapter in [`super::adapter`] only analyses artifacts; without a producer
//! every provider in the family reports `unavailable:artifact-not-produced`.
//! This module builds those artifacts when the host injected none.
//!
//! Evidence comes from exactly one of two sources, and the producer metadata
//! (`details.producer`) says which:
//!
//! * `tool` — a scanner found on `PATH` ran through the same authorized process
//!   route the legacy checks use (`AuditExternalProjectTool` over
//!   `EffectExecutor`): argv-only, sealed executable digest, scrubbed
//!   environment allowlist, timeout and output caps, authenticated network
//!   sandbox. Scratch output lives in a directory outside the audited tree.
//! * `native-fallback` — a cheap, conservative Rust implementation (lockfile
//!   inventory for the SBOM provider, a known-prefix/high-entropy scan for
//!   secrets). It never claims more than it examined.
//!
//! The producer makes no network request. Tools run offline (`--offline`,
//! `--skip-check-update`, metrics off) inside a network-denying sandbox, and the
//! receipt records `offline: true`. A provider whose input cannot be produced
//! yields a typed reason (`tool-missing:<tool>`, `ruleset-missing:<id>`,
//! `offline-database-missing:<tool>`, `sandbox-missing:<tool>`,
//! `sarif-not-present:<id>`, ...) which the adapter turns into
//! `unavailable:<reason>` for that provider only.
//!
//! Conventional inputs (all relative to the audited root unless stated):
//!
//! * SARIF import (`imported.sarif`): `*.sarif` / `*.sarif.json` directly in the
//!   root, in `.sarif/`, `sarif/`, `reports/`, and in the run directory (the
//!   `--out` directory) or its `sarif/` subdirectory.
//! * OpenGrep/Semgrep rules: `.opengrep/`, `.semgrep/`, `opengrep-rules/`,
//!   `.opengrep.yml|yaml`, `.semgrep.yml|yaml`, `opengrep.yml`, `semgrep.yml`.
//! * ast-grep rules: `sgconfig.yml|yaml`.
//! * OSV offline database: `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` (or
//!   `OSV_SCANNER_OFFLINE_DB`) in the environment, or `with_osv_database`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_provider_sdk::{ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest};
use regex::Regex;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

use super::{
    ast_grep,
    common::{digest, digest_json},
    container_iac, dependency_osv, opengrep,
};
use crate::{
    inventory::{InventoryEntry, InventoryEnvelope},
    native_providers::legacy_checks::AuditExternalProjectTool,
    plan::AuditProvider,
};

const POLICY_ID: &str = "audit-security-producer-v1";
const SARIF_FILE_LIMIT: usize = 16;
const SARIF_BYTE_LIMIT: u64 = 8 * 1024 * 1024;
const SECRET_FILE_LIMIT: u64 = 2 * 1024 * 1024;
const ENVIRONMENT_NAMES: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "COMSPEC",
    "HOME",
    "USERPROFILE",
    "TEMP",
    "TMP",
];

static SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Whether scanners must run inside an authenticated OS sandbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxPolicy {
    /// Default. A tool on a host with no sandbox authenticator is refused and
    /// reported as `sandbox-missing:<tool>`, exactly as the legacy checks are.
    Required,
    /// Run without the OS sandbox (offline flags only). Never the default.
    Disabled,
}

/// What the producer could make for a provider.
#[derive(Clone, Debug)]
pub enum Production {
    /// The per-provider input object the adapter analyses.
    Artifact(Value),
    /// Typed reason; the adapter reports `unavailable:<reason>`.
    Unavailable(String),
}

#[derive(Clone, Debug)]
pub struct ArtifactProducer {
    root: PathBuf,
    run_dir: Option<PathBuf>,
    search_path: Option<Vec<PathBuf>>,
    sandbox: SandboxPolicy,
    osv_database: Option<PathBuf>,
    timeout_ms: u64,
    output_limit: usize,
}

impl ArtifactProducer {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let osv_database = ["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "OSV_SCANNER_OFFLINE_DB"]
            .iter()
            .filter_map(|name| std::env::var_os(name))
            .map(PathBuf::from)
            .find(|path| !path.as_os_str().is_empty());
        Self {
            root: root.into(),
            run_dir: None,
            search_path: None,
            sandbox: SandboxPolicy::Required,
            osv_database,
            timeout_ms: 120_000,
            output_limit: 8 * 1024 * 1024,
        }
    }

    /// The run's `--out` directory: scratch parent and an extra SARIF location.
    pub fn with_run_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.run_dir = Some(dir.into());
        self
    }

    /// Directories searched for scanners instead of the process `PATH`.
    pub fn with_search_path(mut self, dirs: Vec<PathBuf>) -> Self {
        self.search_path = Some(dirs);
        self
    }

    pub fn with_sandbox(mut self, policy: SandboxPolicy) -> Self {
        self.sandbox = policy;
        self
    }

    pub fn with_osv_database(mut self, dir: impl Into<PathBuf>) -> Self {
        self.osv_database = Some(dir.into());
        self
    }

    pub fn with_bounds(mut self, timeout_ms: u64, output_limit: usize) -> Self {
        self.timeout_ms = timeout_ms;
        self.output_limit = output_limit;
        self
    }

    pub fn produce(&self, provider: &AuditProvider, inventory: &InventoryEnvelope) -> Production {
        let scratch = match Scratch::create(self.run_dir.as_deref()) {
            Ok(scratch) => scratch,
            Err(_) => return Production::Unavailable("scratch-unavailable".into()),
        };
        let run = Run {
            producer: self,
            provider,
            inventory,
            scratch,
        };
        match provider.id.as_str() {
            "security.opengrep" => run.opengrep(),
            "structural.ast-grep" => run.ast_grep(),
            "container.iac" => run.container_iac(),
            "dependency.osv" => run.dependency_osv(),
            "secrets.current-history" => run.secrets(),
            "supply-chain.license-sbom-provenance" => run.supply_chain(),
            "imported.sarif" => run.imported_sarif(),
            other => Production::Unavailable(format!("unsupported-provider:{other}")),
        }
    }

    fn find_tool(&self, names: &[&str]) -> Option<(String, PathBuf)> {
        let dirs: Vec<PathBuf> = match &self.search_path {
            Some(dirs) => dirs.clone(),
            None => std::env::var_os("PATH")
                .map(|path| std::env::split_paths(&path).collect())
                .unwrap_or_default(),
        };
        for name in names {
            for dir in &dirs {
                let mut candidates = vec![dir.join(name)];
                if cfg!(windows) {
                    for extension in ["exe", "cmd", "bat", "com"] {
                        candidates.push(dir.join(format!("{name}.{extension}")));
                    }
                }
                if let Some(found) = candidates.into_iter().find(|path| is_executable(path)) {
                    return Some(((*name).to_owned(), found));
                }
            }
        }
        None
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Scratch directory outside the audited tree, removed on drop.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn create(parent: Option<&Path>) -> std::io::Result<Self> {
        let sequence = SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let base = parent
            .map(Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "legion-audit-security-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ToolRun {
    tool: String,
    version: String,
    executable_digest: String,
    stdout: Vec<u8>,
    receipt: Value,
}

impl ToolRun {
    fn tool_identity(&self) -> Value {
        json!({"name":self.tool,"version":self.version,"executableDigest":self.executable_digest})
    }

    fn producer(&self) -> Value {
        let mut value = self.receipt.clone();
        value["mode"] = json!("tool");
        value
    }
}

struct Run<'a> {
    producer: &'a ArtifactProducer,
    provider: &'a AuditProvider,
    inventory: &'a InventoryEnvelope,
    scratch: Scratch,
}

fn unavailable(reason: impl Into<String>) -> Production {
    Production::Unavailable(reason.into())
}

fn relative_path(root: &Path, raw: &str) -> String {
    let path = Path::new(raw);
    let relative = path.strip_prefix(root).unwrap_or(path);
    let text = relative.to_string_lossy().replace('\\', "/");
    text.strip_prefix("./").unwrap_or(&text).to_owned()
}

impl<'a> Run<'a> {
    fn root(&self) -> &Path {
        &self.producer.root
    }

    fn binding(&self) -> Value {
        json!({"repositoryRevision":self.inventory.generation,"digest":self.inventory.digest})
    }

    fn entries(&self) -> impl Iterator<Item = &InventoryEntry> {
        self.inventory.entries.iter()
    }

    fn source_paths(&self) -> Vec<String> {
        self.entries()
            .filter(|entry| entry.source_file)
            .map(|entry| entry.path.clone())
            .collect()
    }

    fn input(&self, files: &[String], artifacts: Value, producer: Value) -> Value {
        json!({
            "plan": {
                "binding": self.binding(),
                "repositoryBinding": {"revision": self.inventory.generation, "root": self.root().to_string_lossy()},
                "denominator": {"pathCount": files.len()},
            },
            "projection": {"files": files.iter().map(|path| json!({"path": path})).collect::<Vec<_>>()},
            "artifacts": artifacts,
            "producer": producer,
        })
    }

    fn execution_receipt(&self, run: &ToolRun) -> Value {
        let mut receipt = run.receipt.clone();
        receipt["tool"] = run.tool_identity();
        receipt["stdoutArtifact"] = json!({"digest": digest(&run.stdout), "bytes": run.stdout.len()});
        receipt
    }

    /// Runs one scanner through the authorized process route.
    fn run_tool(
        &self,
        names: &[&str],
        args: Vec<String>,
        accepted: &[i32],
        extra_env: &[(&str, String)],
    ) -> Result<ToolRun, String> {
        let primary = names.first().copied().unwrap_or("tool");
        let Some((tool, executable)) = self.producer.find_tool(names) else {
            return Err(format!("tool-missing:{primary}"));
        };
        let canonical = fs::canonicalize(&executable).unwrap_or(executable);
        let executable_text = canonical.to_string_lossy().into_owned();
        let executable_bytes =
            fs::read(&canonical).map_err(|_| format!("tool-missing:{primary}"))?;
        let executable_digest = digest(&executable_bytes);
        let root_text = self.root().to_string_lossy().into_owned();

        let mut environment: BTreeMap<String, String> = ENVIRONMENT_NAMES
            .iter()
            .filter_map(|name| std::env::var(name).ok().map(|v| ((*name).to_owned(), v)))
            .collect();
        for (name, value) in [
            ("NO_COLOR", "1".to_owned()),
            ("SEMGREP_SEND_METRICS", "off".to_owned()),
            ("SEMGREP_ENABLE_VERSION_CHECK", "0".to_owned()),
            ("SYFT_CHECK_FOR_APP_UPDATE", "false".to_owned()),
        ] {
            environment.insert(name.to_owned(), value);
        }
        for (name, value) in extra_env {
            environment.insert((*name).to_owned(), value.clone());
        }
        let allowlist: BTreeSet<String> = environment.keys().cloned().collect();

        let (launch_executable, launch_args, sandbox, version_args, requires_sandbox) =
            match self.producer.sandbox {
                SandboxPolicy::Disabled => {
                    (executable_text.clone(), args.clone(), None, None, false)
                }
                SandboxPolicy::Required => {
                    match legion_effects::authenticate_sandbox(
                        &executable_text,
                        &args,
                        &root_text,
                        legion_effects::SandboxMode::DenyNetwork,
                        &self.scratch.path.join("sandbox"),
                    ) {
                        Ok(auth) => {
                            // Probe the real tool's version through the same
                            // wrapper prefix (`-f profile -- tool`).
                            let mut probe: Vec<String> =
                                auth.wrapped_args.iter().take(4).cloned().collect();
                            probe.push("--version".into());
                            (
                                auth.wrapped_executable,
                                auth.wrapped_args,
                                Some(legion_effects::SandboxReceipt {
                                    id: auth.id,
                                    network: auth.network,
                                    filesystem_scope: auth.filesystem_scope,
                                }),
                                Some(probe),
                                true,
                            )
                        }
                        // No authenticator: leave the receipt absent so the
                        // executor refuses (typed degradation, never unsandboxed).
                        Err(_) => (executable_text.clone(), args.clone(), None, None, true),
                    }
                }
            };

        let request = ExternalToolRequest {
            request_id: format!("security-producer:{}:{}", self.provider.id, self.inventory.digest),
            provider_id: self.provider.id.clone(),
            plan_id: self.inventory.digest.clone(),
            policy_id: POLICY_ID.into(),
            task_id: Some(tool.clone()),
            executable: launch_executable,
            args: launch_args,
            cwd: root_text.clone(),
            origin: legion_effects::ToolOrigin::System,
            shell: false,
            expected_digest: None,
            accepted_exit_codes: accepted.iter().copied().collect(),
            environment,
            environment_allowlist: allowlist,
            requires_network_sandbox: requires_sandbox,
            sandbox,
            timeout_ms: self.producer.timeout_ms,
            stdout_limit: self.producer.output_limit,
            stderr_limit: self.producer.output_limit,
            version_args: version_args.unwrap_or_else(|| vec!["--version".into()]),
            ..ExternalToolRequest::default()
        };
        let receipt = self.execute(request)?;
        match receipt.state {
            ExecutionState::Completed => {}
            ExecutionState::MissingExecutable => return Err(format!("tool-missing:{primary}")),
            ExecutionState::SandboxMissing => return Err(format!("sandbox-missing:{primary}")),
            ExecutionState::Timeout => return Err(format!("tool-timeout:{primary}")),
            ExecutionState::OutputLimited => return Err(format!("output-limited:{primary}")),
            other => return Err(format!("tool-failed:{primary}:{}", other.as_str())),
        }
        let stdout = receipt
            .stdout
            .as_ref()
            .and_then(|artifact| read_artifact(&self.scratch.path, artifact))
            .ok_or_else(|| format!("tool-output-unreadable:{primary}"))?;
        let version = receipt
            .executable
            .as_ref()
            .and_then(|identity| identity.version.output.as_deref())
            .and_then(|output| output.lines().find(|line| !line.trim().is_empty()))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let argv: Vec<String> = std::iter::once(tool.clone()).chain(args.iter().cloned()).collect();
        let receipt_value = json!({
            "tool": tool,
            "version": version,
            "executableDigest": executable_digest,
            "argv": argv,
            "exitCode": receipt.exit_code,
            "offline": true,
            "complete": receipt.complete,
            "state": receipt.state.as_str(),
            "receiptId": receipt.receipt_id,
            "policyId": receipt.policy_id,
            "stdoutDigest": digest(&stdout),
            "stdoutBytes": stdout.len(),
            "sandbox": {
                "required": receipt.sandbox.required,
                "receiptId": receipt.sandbox.receipt_id,
                "networkEnabled": receipt.sandbox.network_enabled,
            },
            "environmentNames": receipt.environment_names,
            "evidence": "tool",
        });
        Ok(ToolRun {
            tool,
            version,
            executable_digest,
            stdout,
            receipt: receipt_value,
        })
    }

    /// Bridges the async effect executor from the sync provider interface on a
    /// dedicated thread so it never nests inside a caller's runtime.
    fn execute(&self, request: ExternalToolRequest) -> Result<ExecutionReceipt, String> {
        #[cfg(unix)]
        let process = legion_effects::platform::unix::UnixProcess::new();
        #[cfg(windows)]
        let process = legion_effects::platform::windows::WindowsProcess::default();
        let effects = legion_effects::EffectExecutor::new(
            process,
            legion_effects::ArtifactWriter::new(&self.scratch.path),
            legion_effects::StaticPolicy {
                decision: legion_effects::PolicyDecision {
                    allowed: true,
                    policy_id: POLICY_ID.into(),
                    policy_version: 1,
                    policy_digest: format!("sha256:{POLICY_ID}"),
                    reason: None,
                },
            },
        );
        let tool = AuditExternalProjectTool::new(effects);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Runtime::new().ok()?;
                    Some(runtime.block_on(tool.execute(request, CancellationToken::new())))
                })
                .join()
                .ok()
                .flatten()
        })
        .ok_or_else(|| "executor-unavailable".to_owned())
    }

    // ---------------------------------------------------------------- opengrep

    fn opengrep(&self) -> Production {
        let rules = ruleset_paths(
            self.root(),
            &[
                ".opengrep",
                ".semgrep",
                "opengrep-rules",
                ".opengrep.yml",
                ".opengrep.yaml",
                ".semgrep.yml",
                ".semgrep.yaml",
                "opengrep.yml",
                "semgrep.yml",
            ],
        );
        if self.producer.find_tool(&["opengrep", "semgrep"]).is_none() {
            return unavailable("tool-missing:opengrep");
        }
        if rules.is_empty() {
            return unavailable("ruleset-missing:security.opengrep");
        }
        let mut args: Vec<String> = [
            "scan",
            "--json",
            "--quiet",
            "--metrics",
            "off",
            "--disable-version-check",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        for rule in &rules {
            args.push("--config".into());
            args.push(rule.clone());
        }
        args.push(".".into());
        let run = match self.run_tool(&["opengrep", "semgrep"], args, &[0, 1], &[]) {
            Ok(run) => run,
            Err(reason) => return unavailable(reason),
        };
        let Ok(output) = serde_json::from_slice::<Value>(&run.stdout) else {
            return unavailable(format!("tool-output-invalid:{}", run.tool));
        };
        let sources = self.source_paths();
        let scanned: BTreeSet<String> = output
            .get("paths")
            .and_then(|p| p.get("scanned"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|p| relative_path(self.root(), p))
            .collect();
        let examined = sources.iter().filter(|p| scanned.contains(*p)).count();
        let denominator_digest = digest_json(&json!(sources));
        let ruleset = opengrep::ruleset_identity(
            Some(rules.join(",").as_str()),
            Some(ruleset_digest(self.root(), &rules).as_str()),
            None,
            Some("repository-local"),
            None,
        );
        let candidates: Vec<Value> = output
            .get("results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|result| {
                let mut result = result.clone();
                if let Some(path) = result.get("path").and_then(Value::as_str) {
                    result["path"] = json!(relative_path(self.root(), path));
                }
                let finding = opengrep::normalize_finding(
                    &result,
                    Some("security.opengrep"),
                    Some(run.version.as_str()),
                    Some(&ruleset),
                );
                opengrep::to_candidate(
                    &finding,
                    Some("security.opengrep"),
                    Some(run.version.as_str()),
                    Some(denominator_digest.as_str()),
                )
            })
            .collect();
        let evidence = json!({
            "binding": self.binding(),
            "denominator": {"digest": denominator_digest, "expected": sources.len(), "examined": examined},
            "ruleset": ruleset,
            "tool": run.tool_identity(),
            "executionReceipt": self.execution_receipt(&run),
            "candidates": candidates,
        });
        Production::Artifact(self.input(&sources, json!({"opengrep": evidence}), run.producer()))
    }

    // ---------------------------------------------------------------- ast-grep

    fn ast_grep(&self) -> Production {
        if self.producer.find_tool(&["ast-grep"]).is_none() {
            return unavailable("tool-missing:ast-grep");
        }
        if !["sgconfig.yml", "sgconfig.yaml"]
            .iter()
            .any(|name| self.root().join(name).is_file())
        {
            return unavailable("ruleset-missing:structural.ast-grep");
        }
        let run = match self.run_tool(
            &["ast-grep"],
            vec!["scan".into(), "--json=stream".into()],
            &[0, 1],
            &[],
        ) {
            Ok(run) => run,
            Err(reason) => return unavailable(reason),
        };
        let sources = self.source_paths();
        let mut supported = Vec::new();
        let mut unsupported = BTreeSet::new();
        for path in &sources {
            let extension = Path::new(path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if AST_GREP_EXTENSIONS.contains(&extension.as_str()) {
                supported.push(path.clone());
            } else {
                unsupported.insert(if extension.is_empty() {
                    "unknown".to_owned()
                } else {
                    extension
                });
            }
        }
        // ast-grep reports 0-based lines; the shared match shape is 1-based.
        let lines: Vec<Value> = String::from_utf8_lossy(&run.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .map(|mut line| {
                if let Some(file) = line.get("file").and_then(Value::as_str) {
                    line["file"] = json!(relative_path(self.root(), file));
                }
                for edge in ["start", "end"] {
                    if let Some(value) = line.pointer_mut(&format!("/range/{edge}/line")) {
                        if let Some(n) = value.as_u64() {
                            *value = json!(n + 1);
                        }
                    }
                }
                line
            })
            .collect();
        let matches = ast_grep::normalize_stream(&lines, "ast-grep.rule");
        let artifacts = json!({
            "astGrepTool": run.tool_identity(),
            "examinedPaths": supported,
            "unsupportedGrammars": unsupported.into_iter().collect::<Vec<_>>(),
            "structuralMatches": matches,
        });
        Production::Artifact(self.input(&sources, artifacts, run.producer()))
    }

    // ------------------------------------------------------------ container.iac

    fn container_iac(&self) -> Production {
        let run = match self.run_tool(
            &["trivy"],
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
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
            &[0],
            &[],
        ) {
            Ok(run) => run,
            Err(reason) => return unavailable(reason),
        };
        let Ok(output) = serde_json::from_slice::<Value>(&run.stdout) else {
            return unavailable(format!("tool-output-invalid:{}", run.tool));
        };
        let files: Vec<String> = self.entries().map(|entry| entry.path.clone()).collect();
        let source: BTreeSet<String> = files.iter().filter(|p| is_iac_path(p)).cloned().collect();
        let mut rendered = Vec::new();
        let mut covered_sources = 0usize;
        let mut findings = Vec::new();
        for result in output
            .get("Results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if result.get("Class").and_then(Value::as_str) != Some("config") {
                continue;
            }
            let target = relative_path(
                self.root(),
                result.get("Target").and_then(Value::as_str).unwrap_or_default(),
            );
            if source.contains(&target) {
                covered_sources += 1;
            }
            rendered.push(json!({"target": target, "type": result.get("Type")}));
            for misconfiguration in result
                .get("Misconfigurations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                findings.push(container_iac::normalize_iac_finding(
                    &json!({
                        "ID": misconfiguration.get("ID"),
                        "Severity": misconfiguration.get("Severity"),
                        "Target": target,
                        "resource": misconfiguration.get("CauseMetadata").and_then(|c| c.get("Resource")),
                        "message": misconfiguration.get("Message"),
                    }),
                    Some("container-iac.trivy"),
                    Some(run.version.as_str()),
                ));
            }
        }
        let examined = covered_sources + rendered.len();
        let evidence = json!({
            "binding": self.binding(),
            "executionReceipt": self.execution_receipt(&run),
            // Trivy's embedded check bundle ships with the binary: the version
            // is the closest identity available offline.
            "databaseDigest": digest(format!("trivy-builtin-checks\0{}", run.version).as_bytes()),
            "examined": examined,
            "findings": findings,
        });
        let artifacts = json!({"renderedInfrastructure": rendered, "iacEvidence": evidence});
        Production::Artifact(self.input(&files, artifacts, run.producer()))
    }

    // ----------------------------------------------------------- dependency.osv

    fn dependency_osv(&self) -> Production {
        if self.producer.find_tool(&["osv-scanner"]).is_none() {
            return unavailable("tool-missing:osv-scanner");
        }
        // osv-scanner queries api.osv.dev unless it has a local database.
        let Some(database) = self
            .producer
            .osv_database
            .clone()
            .filter(|dir| dir.is_dir())
        else {
            return unavailable("offline-database-missing:osv-scanner");
        };
        let database_text = database.to_string_lossy().into_owned();
        let run = match self.run_tool(
            &["osv-scanner"],
            ["scan", "source", "--offline", "--format", "json", "-r", "."]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            &[0, 1],
            &[("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", database_text)],
        ) {
            Ok(run) => run,
            Err(reason) => return unavailable(reason),
        };
        let Ok(output) = serde_json::from_slice::<Value>(&run.stdout) else {
            return unavailable(format!("tool-output-invalid:{}", run.tool));
        };
        let (database_digest, database_files) = directory_identity(&database);
        let database = json!({
            "digest": database_digest,
            "version": format!("local-cache:{database_files}-files"),
            "status": "offline",
        });
        let execution_receipt = self.execution_receipt(&run);
        let mut receipts = Vec::new();
        for result in output
            .get("results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let manifest = relative_path(
                self.root(),
                result
                    .get("source")
                    .and_then(|s| s.get("path"))
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            );
            let mut paths = Vec::new();
            let mut findings = Vec::new();
            for source in result
                .get("packages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let package = source.get("package").cloned().unwrap_or(Value::Null);
                // No call analysis here: presence in the resolved dependency
                // graph is reported as reachable (conservative upper bound).
                paths.push(json!({
                    "package": format!(
                        "{}@{}",
                        package.get("name").and_then(Value::as_str).unwrap_or_default(),
                        package.get("version").and_then(Value::as_str).unwrap_or_default()
                    ),
                    "reachability": "reachable",
                    "basis": "dependency-graph",
                }));
                for vulnerability in source
                    .get("vulnerabilities")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let mut vulnerability = vulnerability.clone();
                    vulnerability["package"] = package.clone();
                    findings.push(dependency_osv::normalize_vulnerability(
                        &vulnerability,
                        Some("osv.scanner"),
                        Some(run.version.as_str()),
                    ));
                }
            }
            if paths.is_empty() {
                paths.push(json!({"package": manifest, "reachability": "unreachable", "basis": "no-packages"}));
            }
            receipts.push(json!({
                "manifest": manifest,
                "binding": self.binding(),
                "executionReceipt": execution_receipt,
                "database": database,
                "paths": paths,
                "findings": findings,
            }));
        }
        let files: Vec<String> = self.entries().map(|entry| entry.path.clone()).collect();
        Production::Artifact(self.input(&files, json!({"dependencyReceipts": receipts}), run.producer()))
    }

    // ------------------------------------------------------------------ secrets

    fn secrets(&self) -> Production {
        let files: Vec<String> = self.entries().map(|entry| entry.path.clone()).collect();
        let mut fallback_reason = None;
        if self.producer.find_tool(&["gitleaks"]).is_some() {
            match self.run_tool(
                &["gitleaks"],
                [
                    "dir",
                    ".",
                    "--report-format",
                    "json",
                    "--report-path",
                    "-",
                    "--redact",
                    "--no-banner",
                ]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
                &[0, 1],
                &[],
            ) {
                Ok(run) => {
                    if let Ok(report) = serde_json::from_slice::<Value>(&run.stdout) {
                        return Production::Artifact(self.gitleaks_input(&files, &run, &report));
                    }
                    fallback_reason = Some(format!("tool-output-invalid:{}", run.tool));
                }
                Err(reason) => fallback_reason = Some(reason),
            }
        }
        Production::Artifact(self.native_secrets_input(&files, fallback_reason))
    }

    fn gitleaks_input(&self, files: &[String], run: &ToolRun, report: &Value) -> Value {
        let findings: Vec<Value> = report
            .as_array()
            .into_iter()
            .flatten()
            .map(|item| {
                let file = relative_path(
                    self.root(),
                    item.get("File").and_then(Value::as_str).unwrap_or_default(),
                );
                let line = item.get("StartLine").and_then(Value::as_u64).unwrap_or(1);
                let rule = item.get("RuleID").and_then(Value::as_str).unwrap_or("secret.unknown");
                let fingerprint = item
                    .get("Fingerprint")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| format!("{file}:{line}:{rule}"));
                json!({
                    "RuleID": rule,
                    "File": file,
                    "StartLine": line,
                    "EndLine": item.get("EndLine").cloned().unwrap_or(Value::Null),
                    "SecretDigest": digest(fingerprint.as_bytes()),
                    "Match": "REDACTED",
                })
            })
            .collect();
        let evidence = json!({
            "denominator": secret_denominator(files.len()),
            "findings": findings,
            "examined": files.len(),
            "tool": run.tool_identity(),
            "rulesetDigest": digest(format!("gitleaks-builtin\0{}", run.version).as_bytes()),
        });
        let mut producer = run.producer();
        // `gitleaks dir` scans the working tree; commit history is not walked.
        producer["scope"] = json!("current-tree");
        self.input(files, json!({"secretEvidence": evidence}), producer)
    }

    fn native_secrets_input(&self, files: &[String], fallback_reason: Option<String>) -> Value {
        let rules = secret_rules();
        let generic = generic_secret_rule();
        let mut findings = Vec::new();
        let mut examined = 0usize;
        for path in files {
            let full = self.root().join(path);
            let Ok(meta) = fs::symlink_metadata(&full) else {
                continue;
            };
            if !meta.is_file() {
                // Symlinks are inventoried by target text; nothing to read.
                examined += 1;
                continue;
            }
            if meta.len() > SECRET_FILE_LIMIT {
                continue;
            }
            let Ok(bytes) = fs::read(&full) else {
                continue;
            };
            examined += 1;
            if bytes.iter().take(8192).any(|b| *b == 0) {
                continue;
            }
            let text = String::from_utf8_lossy(&bytes);
            let lockfile = is_lockfile(path);
            let mut seen = BTreeSet::new();
            for (index, line) in text.lines().enumerate() {
                if line.len() > 4096 {
                    continue;
                }
                let line_number = index as u64 + 1;
                for (rule, regex) in &rules {
                    if let Some(found) = regex.find(line) {
                        if seen.insert((line_number, *rule)) {
                            findings.push(native_secret_finding(path, line_number, rule, found.as_str()));
                        }
                    }
                }
                if !lockfile {
                    if let Some(captures) = generic.captures(line) {
                        let value = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
                        if looks_like_secret(value) && seen.insert((line_number, "generic.high-entropy")) {
                            findings.push(native_secret_finding(path, line_number, "generic.high-entropy", value));
                        }
                    }
                }
            }
        }
        let evidence = json!({
            "denominator": secret_denominator(files.len()),
            "findings": findings,
            "examined": examined,
            "tool": {"name": "legion-native-secret-scan", "version": "1"},
            "rulesetDigest": secret_ruleset_digest(),
        });
        let producer = json!({
            "mode": "native-fallback",
            "evidence": "native-fallback",
            "offline": true,
            "scope": "current-tree",
            "fallbackReason": fallback_reason.unwrap_or_else(|| "tool-missing:gitleaks".into()),
            "examined": examined,
            "expected": files.len(),
        });
        self.input(files, json!({"secretEvidence": evidence}), producer)
    }

    // ------------------------------------------------------------- supply chain

    fn supply_chain(&self) -> Production {
        let paths: Vec<String> = self.entries().map(|entry| entry.path.clone()).collect();
        let lock_packages = lockfile_inventory(self.root(), &paths);
        let mut syft = None;
        let mut fallback_reason = "tool-missing:syft".to_owned();
        if self.producer.find_tool(&["syft"]).is_some() {
            let cyclonedx = self.run_tool(
                &["syft"],
                ["scan", "dir:.", "-o", "cyclonedx-json", "-q"]
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                &[0],
                &[],
            );
            let spdx = self.run_tool(
                &["syft"],
                ["scan", "dir:.", "-o", "spdx-json", "-q"]
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                &[0],
                &[],
            );
            match (cyclonedx, spdx) {
                (Ok(cyclonedx), Ok(spdx)) => syft = Some((cyclonedx, spdx)),
                (Err(reason), _) | (_, Err(reason)) => fallback_reason = reason,
            }
        }
        let (sbom_packages, cyclonedx_digest, spdx_digest, producer) = match &syft {
            Some((cyclonedx, spdx)) => {
                let document: Value = serde_json::from_slice(&cyclonedx.stdout).unwrap_or(Value::Null);
                let packages: Vec<String> = document
                    .get("components")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c.get("purl").and_then(Value::as_str))
                    .map(|purl| purl.split(['?', '#']).next().unwrap_or(purl).to_owned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let mut producer = cyclonedx.producer();
                producer["spdx"] = spdx.receipt.clone();
                (packages, json!(digest(&cyclonedx.stdout)), json!(digest(&spdx.stdout)), producer)
            }
            None => {
                // Native SBOM: a CycloneDX document derived from the same
                // lockfile inventory. It reconciles by construction, so the
                // evidence is labelled and no SPDX/provenance is claimed.
                let components: Vec<Value> = lock_packages.iter().map(|purl| json!({"type":"library","purl":purl})).collect();
                let document = json!({"bomFormat":"CycloneDX","specVersion":"1.5","components":components});
                (
                    lock_packages.clone(),
                    json!(digest_json(&document)),
                    Value::Null,
                    json!({
                        "mode": "native-fallback",
                        "evidence": "native-fallback",
                        "offline": true,
                        "fallbackReason": fallback_reason,
                        "lockfiles": lockfile_paths(&paths),
                    }),
                )
            }
        };
        let chain = json!({
            "lockPackages": lock_packages,
            "sbomPackages": sbom_packages,
            "cycloneDxDigest": cyclonedx_digest,
            "spdxDigest": spdx_digest,
            // Build provenance (an attestation of how the artifact was built)
            // cannot be produced from a source tree; the gap stays visible.
        });
        Production::Artifact(self.input(&paths, json!({"supplyChain": chain}), producer))
    }

    // ----------------------------------------------------------- imported.sarif

    fn imported_sarif(&self) -> Production {
        let mut locations = vec![
            self.root().to_path_buf(),
            self.root().join(".sarif"),
            self.root().join("sarif"),
            self.root().join("reports"),
        ];
        if let Some(run_dir) = &self.producer.run_dir {
            locations.push(run_dir.clone());
            locations.push(run_dir.join("sarif"));
        }
        let mut found = BTreeSet::new();
        for location in locations {
            let Ok(entries) = fs::read_dir(&location) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_file()
                    && meta.len() <= SARIF_BYTE_LIMIT
                    && (name.ends_with(".sarif") || name.ends_with(".sarif.json"))
                {
                    found.insert(path);
                }
            }
        }
        if found.is_empty() {
            return unavailable("sarif-not-present:imported.sarif");
        }
        let root_text = self.root().to_string_lossy().into_owned();
        let mut items = Vec::new();
        let mut sources = Vec::new();
        for path in found.into_iter().take(SARIF_FILE_LIMIT) {
            let Ok(raw) = fs::read_to_string(&path) else {
                continue;
            };
            let source = relative_path(self.root(), &path.to_string_lossy());
            sources.push(source.clone());
            let mut item = json!({
                "rawBytes": raw,
                "binding": {"revision": self.inventory.generation, "root": root_text},
                // Self-attested: no external digest exists for a repo-local file.
                "expectedDigest": digest(raw.as_bytes()),
                "source": source,
            });
            if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
                let runs: Vec<Value> = parsed.get("runs").and_then(Value::as_array).cloned().unwrap_or_default();
                let driver = runs.first().and_then(|r| r.get("tool")).and_then(|t| t.get("driver"));
                let results: Vec<Value> = runs
                    .iter()
                    .flat_map(|run| run.get("results").and_then(Value::as_array).cloned().unwrap_or_default())
                    .collect();
                item["artifact"] = json!({
                    "schemaVersion": "2.1.0",
                    "revision": self.inventory.generation,
                    "baseUri": root_text,
                    "results": results,
                });
                item["toolIdentity"] = json!({
                    "name": driver.and_then(|d| d.get("name")),
                    "version": driver.and_then(|d| d.get("semanticVersion").or_else(|| d.get("version"))),
                });
            }
            items.push(item);
        }
        let producer = json!({
            "mode": "file",
            "evidence": "repository-file",
            "offline": true,
            "sarifFiles": sources,
            "binding": "inventory-revision (SARIF origin revision is not verified)",
        });
        let files: Vec<String> = self.entries().map(|entry| entry.path.clone()).collect();
        Production::Artifact(self.input(&files, json!({"importedSarif": items}), producer))
    }
}

fn read_artifact(root: &Path, artifact: &legion_effects::ArtifactRecord) -> Option<Vec<u8>> {
    if !artifact.immutable {
        return None;
    }
    let path = Path::new(&artifact.path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let bytes = fs::read(path).ok()?;
    (bytes.len() == artifact.bytes && digest(&bytes) == artifact.digest).then_some(bytes)
}

const AST_GREP_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "java", "c", "h", "cpp", "cc", "cxx",
    "hpp", "cs", "rb", "php", "swift", "kt", "kts", "scala", "lua", "sh", "bash", "html", "css",
    "json", "yaml", "yml", "ex", "exs", "nix",
];

fn is_iac_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("dockerfile")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".tf")
        || lower.contains("compose")
}

/// Existing conventional ruleset locations, relative to `root`, sorted.
fn ruleset_paths(root: &Path, candidates: &[&str]) -> Vec<String> {
    candidates
        .iter()
        .filter(|name| root.join(name).exists())
        .map(|name| (*name).to_owned())
        .collect()
}

/// Digest over every rule file (path and bytes) under the given roots.
fn ruleset_digest(root: &Path, rules: &[String]) -> String {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for rule in rules {
        let base = root.join(rule);
        for entry in WalkDir::new(&base).follow_links(false).into_iter().flatten() {
            if entry.file_type().is_file() {
                if let Ok(bytes) = fs::read(entry.path()) {
                    entries.push((relative_path(root, &entry.path().to_string_lossy()), bytes));
                }
            }
        }
    }
    entries.sort();
    let mut material = Vec::new();
    for (path, bytes) in entries {
        material.extend_from_slice(path.as_bytes());
        material.push(0);
        material.extend_from_slice(digest(&bytes).as_bytes());
        material.push(0);
    }
    digest(&material)
}

/// Stable identity of a directory tree (relative path and length per file).
fn directory_identity(dir: &Path) -> (String, usize) {
    let mut entries: Vec<(String, u64)> = WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .flatten()
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            (
                relative_path(dir, &entry.path().to_string_lossy()),
                entry.metadata().map(|m| m.len()).unwrap_or(0),
            )
        })
        .collect();
    entries.sort();
    (digest_json(&json!(entries)), entries.len())
}

// ------------------------------------------------------------------- secrets

fn secret_denominator(tracked: usize) -> Value {
    json!({
        "mode": "current",
        "trackedFiles": tracked,
        "untrackedFiles": 0,
        "ignoredFiles": 0,
        "generatedFiles": 0,
        "releaseArtifacts": 0,
        "historyRefs": 0,
    })
}

const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("aws.access-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github.token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("github.fine-grained-pat", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    ("slack.token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    ("stripe.live-key", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    ("google.api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("npm.access-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("private-key.pem", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
];

fn secret_rules() -> Vec<(&'static str, Regex)> {
    SECRET_PATTERNS
        .iter()
        .filter_map(|(id, pattern)| Regex::new(pattern).ok().map(|regex| (*id, regex)))
        .collect()
}

fn generic_secret_rule() -> Regex {
    Regex::new(
        r#"(?i)(?:secret|token|api[_-]?key|passwd|password|private[_-]?key|credential)[A-Za-z0-9_\-]*["']?\s*[:=]\s*["']([A-Za-z0-9+/_\-=.]{20,})["']"#,
    )
    .expect("generic secret pattern")
}

fn secret_ruleset_digest() -> String {
    let mut material = String::from("legion-native-secret-scan/1\n");
    for (id, pattern) in SECRET_PATTERNS.iter() {
        material.push_str(&format!("{id}\t{pattern}\n"));
    }
    material.push_str("generic.high-entropy\tentropy>=3.5\n");
    digest(material.as_bytes())
}

fn native_secret_finding(path: &str, line: u64, rule: &str, secret: &str) -> Value {
    // The secret itself is never stored: only a digest and a redacted marker.
    json!({
        "RuleID": rule,
        "File": path,
        "StartLine": line,
        "EndLine": line,
        "SecretDigest": digest(secret.as_bytes()),
        "Match": "REDACTED",
    })
}

fn is_lockfile(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    name.ends_with(".lock")
        || name.ends_with(".sum")
        || name.ends_with(".min.js")
        || matches!(name.as_str(), "package-lock.json" | "pnpm-lock.yaml" | "npm-shrinkwrap.json")
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for character in value.chars() {
        *counts.entry(character).or_default() += 1;
    }
    let length = value.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / length;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "example", "placeholder", "changeme", "xxxxx", "your_", "your-", "dummy", "sample", "redacted",
    ];
    !PLACEHOLDERS.iter().any(|p| lower.contains(p))
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic())
        && shannon_entropy(value) >= 3.5
}

// ------------------------------------------------------------------ lockfiles

fn lockfile_kind(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name {
        "Cargo.lock" => Some("cargo"),
        "poetry.lock" => Some("poetry"),
        "package-lock.json" | "npm-shrinkwrap.json" => Some("npm-lock"),
        "pnpm-lock.yaml" => Some("pnpm"),
        "yarn.lock" => Some("yarn"),
        "go.sum" => Some("go"),
        _ if name.starts_with("requirements") && name.ends_with(".txt") => Some("pip"),
        _ => None,
    }
}

fn lockfile_paths(paths: &[String]) -> Vec<String> {
    paths.iter().filter(|p| lockfile_kind(p).is_some()).cloned().collect()
}

fn purl(kind: &str, name: &str, version: &str) -> String {
    format!("pkg:{kind}/{}@{version}", name.replace('@', "%40"))
}

/// Package-URL inventory (`pkg:<type>/<name>@<version>`) of every recognised
/// lockfile among `paths` (relative to `root`): Cargo.lock, poetry.lock,
/// package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, go.sum
/// and requirements*.txt. Sorted and unique. Parsing is shallow by design:
/// names and versions only, no resolution and no vulnerability knowledge.
pub fn lockfile_inventory(root: &Path, paths: &[String]) -> Vec<String> {
    let mut packages = BTreeSet::new();
    for path in paths {
        let Some(kind) = lockfile_kind(path) else {
            continue;
        };
        let Ok(text) = fs::read_to_string(root.join(path)) else {
            continue;
        };
        match kind {
            "cargo" => packages.extend(toml_packages(&text, "cargo", false)),
            "poetry" => packages.extend(toml_packages(&text, "pypi", true)),
            "npm-lock" => packages.extend(npm_lock_packages(&text)),
            "pnpm" => packages.extend(pnpm_packages(&text)),
            "yarn" => packages.extend(yarn_packages(&text)),
            "go" => packages.extend(go_sum_packages(&text)),
            _ => packages.extend(requirements_packages(&text)),
        }
    }
    packages.into_iter().collect()
}

fn pypi_name(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}

fn toml_value(line: &str, key: &str) -> Option<String> {
    let rest = line.trim().strip_prefix(key)?.trim_start().strip_prefix('=')?;
    Some(rest.trim().trim_matches('"').to_owned())
}

fn toml_packages(text: &str, kind: &str, normalize: bool) -> Vec<String> {
    let mut packages = Vec::new();
    let (mut name, mut version) = (None::<String>, None::<String>);
    let mut flush = |name: &mut Option<String>, version: &mut Option<String>| {
        if let (Some(n), Some(v)) = (name.take(), version.take()) {
            let n = if normalize { pypi_name(&n) } else { n };
            packages.push(purl(kind, &n, &v));
        }
    };
    for line in text.lines() {
        if line.trim() == "[[package]]" {
            flush(&mut name, &mut version);
        } else if line.starts_with('[') {
            // Another table (for example `[package.dependencies]`) ends the
            // identifying keys of the current package.
            continue;
        } else if let Some(value) = toml_value(line, "name") {
            name.get_or_insert(value);
        } else if let Some(value) = toml_value(line, "version") {
            version.get_or_insert(value);
        }
    }
    flush(&mut name, &mut version);
    packages
}

fn npm_lock_packages(text: &str) -> Vec<String> {
    let Ok(document) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    if let Some(map) = document.get("packages").and_then(Value::as_object) {
        for (key, entry) in map {
            let name = match key.rfind("node_modules/") {
                Some(index) => &key[index + "node_modules/".len()..],
                None => continue,
            };
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                packages.push(purl("npm", name, version));
            }
        }
    } else if let Some(map) = document.get("dependencies").and_then(Value::as_object) {
        fn walk(map: &serde_json::Map<String, Value>, out: &mut Vec<String>) {
            for (name, entry) in map {
                if let Some(version) = entry.get("version").and_then(Value::as_str) {
                    out.push(purl("npm", name, version));
                }
                if let Some(inner) = entry.get("dependencies").and_then(Value::as_object) {
                    walk(inner, out);
                }
            }
        }
        walk(map, &mut packages);
    }
    packages
}

fn pnpm_packages(text: &str) -> Vec<String> {
    let mut packages = Vec::new();
    let mut in_packages = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if !in_packages || indent != 2 || !line.trim_end().ends_with(':') {
            continue;
        }
        let key = line
            .trim()
            .trim_end_matches(':')
            .trim_matches(|c| c == '\'' || c == '"')
            .trim_start_matches('/');
        let key = key.split('(').next().unwrap_or(key);
        // v6+: `name@1.2.3`; v5: `name/1.2.3`.
        let split = key
            .rfind('@')
            .filter(|index| *index > 0)
            .or_else(|| key.rfind('/'));
        if let Some(index) = split {
            let (name, version) = (&key[..index], &key[index + 1..]);
            if !name.is_empty() && version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                packages.push(purl("npm", name, version));
            }
        }
    }
    packages
}

fn yarn_packages(text: &str) -> Vec<String> {
    let mut packages = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') && line.trim_end().ends_with(':') {
            let first = line
                .trim_end()
                .trim_end_matches(':')
                .split(',')
                .next()
                .unwrap_or_default()
                .trim()
                .trim_matches('"');
            name = first.rfind('@').filter(|i| *i > 0).map(|i| first[..i].to_owned());
        } else if let Some(current) = &name {
            let trimmed = line.trim();
            let version = trimmed
                .strip_prefix("version ")
                .or_else(|| trimmed.strip_prefix("version:"));
            if let Some(version) = version {
                packages.push(purl("npm", current, version.trim().trim_matches('"')));
                name = None;
            }
        }
    }
    packages
}

fn go_sum_packages(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let (module, version) = (parts.next()?, parts.next()?);
            let version = version.strip_suffix("/go.mod").unwrap_or(version);
            Some(purl("golang", module, version))
        })
        .collect()
}

fn requirements_packages(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or_default().split(';').next()?.trim();
            let (name, version) = line.split_once("==")?;
            let name = name.split('[').next()?.trim();
            let version = version.trim().split_whitespace().next()?;
            (!name.is_empty() && !version.is_empty()).then(|| purl("pypi", &pypi_name(name), version))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_filter_rejects_placeholders() {
        assert!(!looks_like_secret("your_api_key_goes_here_1234"));
        assert!(!looks_like_secret("aaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(looks_like_secret("q8Zr3Kd91LmXw07VbN4tY2sHc6Pj"));
    }

    #[test]
    fn purl_encodes_scope_marker() {
        assert_eq!(purl("npm", "@a/b", "1.0.0"), "pkg:npm/%40a/b@1.0.0");
    }
}
