//! Native execution for the frozen `legacy-check` provider surface.
//!
//! The registry contains two kinds of legacy checks.  Checks whose historical
//! boundary was filesystem analysis are implemented in Rust below.  Checks
//! which deliberately name a project tool require the application's authorized
//! `ExternalProjectTool` capability. Resolution and execution remain behind
//! that typed boundary; missing host tools return typed degradation without
//! starting a process. Neither a tool name nor parser success is evidence.

mod attested_runs;
mod contracts;
mod disposable_copy;
mod node_outdated;
pub(crate) mod parsers;
mod python_requirements;
mod registry;
mod resolver;
mod runtime_capture;
mod rust_outdated;
pub(crate) mod semgrep;

pub use attested_runs::{AdapterEnrollment, AttestedRunsEnrollment, EnrollmentError};
pub use contracts::{
    CommandShape, LegacyCheckError, LegacyCheckExecution, LegacyCheckInput, LegacyCheckOutput,
    LegacyCheckProcessRequest, LegacyCheckProcessState, LegacyCheckSpec, CONTRACT_SCHEMA_VERSION,
    REQUEST_KIND,
};
pub use registry::{spec, specs, LEGACY_CHECK_SPECS};
pub use resolver::{
    resolve_command, resolve_request, resolve_test_command, resolve_test_command_with_enrollment,
    ResolveError, ResolvedCommand,
};
pub use runtime_capture::runtime_inputs;

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use legion_provider_sdk::{ExternalProjectTool, ExternalToolRequest};
use registry::AbsenceOutcome;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio_util::sync::CancellationToken;

use crate::{
    error::AuditError,
    execution::ProviderExecutor,
    inventory::{InventoryEntry, InventoryEnvelope},
    plan::AuditProvider,
};

/// Production Audit adapter that rewrites registry request ids into a
/// scratch-relative artifact location. The artifact sink the adapter wraps must
/// be rooted at an [`AuditScratch`] artifacts directory, never at the audited
/// tree. Registry request ids contain punctuation (including `:`), which is
/// not a valid Windows path component; receipts retain provider/plan ids.
pub struct AuditExternalProjectTool<T> {
    inner: T,
}

impl<T> AuditExternalProjectTool<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<T> ExternalProjectTool for AuditExternalProjectTool<T>
where
    T: ExternalProjectTool,
{
    async fn execute(
        &self,
        mut request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> legion_provider_sdk::ExecutionReceipt {
        let requested_executable = request.executable.clone();
        let resolved = match resolve_request(
            &PathBuf::from(&request.cwd),
            &requested_executable,
            &request.args,
        ) {
            Ok(value) => value,
            Err(error) => {
                let state = match error {
                    // Nothing to run (no tool, or the project declares no
                    // script/linter/type checker): surfaced as an absent
                    // tool, not an internal failure.
                    ResolveError::MissingExecutable(_) | ResolveError::NotConfigured(_) => {
                        legion_provider_sdk::ExecutionState::MissingExecutable
                    }
                    ResolveError::Unavailable(_) => legion_provider_sdk::ExecutionState::Internal,
                };
                return legion_provider_sdk::ExecutionReceipt::failure(
                    &request,
                    state,
                    error.message(),
                );
            }
        };
        if request
            .expected_digest
            .as_deref()
            .is_some_and(|expected| expected != resolved.digest)
        {
            return legion_provider_sdk::ExecutionReceipt::failure(
                &request,
                legion_provider_sdk::ExecutionState::Internal,
                "external-project-tool resolved executable does not match caller digest pin",
            );
        }
        request.executable = resolved.executable.to_string_lossy().into_owned();
        request.args = resolved.args;
        request.expected_digest = request.expected_digest.or(Some(resolved.digest));
        request.cwd = resolved.cwd.to_string_lossy().into_owned();
        request.request_id = audit_artifact_request_id(&request.request_id);
        self.inner.execute(request, cancellation).await
    }
}

/// Gap text the effect layer attaches to a refused network-sandbox request
/// (`legion-effects` executor). Matched, never produced, by this crate.
const SANDBOX_RECEIPT_REQUIRED: &str = "network sandbox receipt is required";

/// Where a legacy check's machine-readable output actually lands. Most tools
/// print JSON (or JSON-ish text) on stdout, but a minority disagree: `cargo
/// deny --format json check` streams its JSONL diagnostics on **stderr**,
/// `jscpd` writes its JSON report to a file under its `--output` directory
/// rather than printing anything parseable at all. `execution_from_receipt`
/// reads whichever stream/file this says to, instead of always assuming
/// stdout. (`gitleaks` also needs an explicit report destination, but it takes
/// `--report-path -` and prints to stdout, so it stays `Stdout`.)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReportSource {
    Stdout,
    Stderr,
    /// Candidate report paths (relative to the per-run report temp dir), tried
    /// in order; the first one that exists is the report.
    File(&'static [&'static str]),
}

fn report_source_for(check: &str) -> ReportSource {
    match check {
        "cargo_deny" => ReportSource::Stderr,
        // jscpd's json reporter writes `<--output>/jscpd-report.json`. The
        // historical JS collector passed `--output <outDir>/_jscpd` and read
        // `<outDir>/_jscpd/jscpd-report.json`; the nested spelling is kept as
        // a fallback so either layout is read, but the Rust launch passes the
        // temp dir itself, so the flat name is the one that is produced.
        "duplication" => ReportSource::File(&["jscpd-report.json", "_jscpd/jscpd-report.json"]),
        _ => ReportSource::Stdout,
    }
}

/// Tool arguments that point a file-backed report at the per-run temp dir.
fn report_args(dir: &Path) -> Vec<String> {
    vec!["--output".into(), dir.to_string_lossy().into_owned()]
}

/// A per-check directory under the audit scratch root for checks whose tool
/// writes its report to disk (`ReportSource::File`). Removed unconditionally
/// on drop so a check never leaves report files behind, whether or not the
/// report was read successfully.
struct ReportTempDir {
    path: PathBuf,
}

impl ReportTempDir {
    fn create(base: &Path, check: &str) -> std::io::Result<Self> {
        let sequence = AUDIT_ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("report-{check}-{sequence}"));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for ReportTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A report file read back from a `ReportTempDir`, bounded and digested the
/// same way stdout/stderr artifacts are.
struct ReportArtifact {
    name: &'static str,
    bytes: Vec<u8>,
    digest: String,
}

/// Report files are bounded like stdout/stderr (see `ExternalToolRequest`'s
/// default limits); an oversized report is treated the same as unreadable
/// artifact bytes rather than silently truncated into invalid JSON.
const REPORT_ARTIFACT_LIMIT: usize = 8 * 1024 * 1024;

fn read_report_artifact(dir: &Path, source: ReportSource) -> Option<ReportArtifact> {
    let ReportSource::File(names) = source else {
        return None;
    };
    let (name, bytes) = names.iter().find_map(|name| {
        std::fs::read(dir.join(name))
            .ok()
            .map(|bytes| (*name, bytes))
    })?;
    if bytes.len() > REPORT_ARTIFACT_LIMIT {
        return None;
    }
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    Some(ReportArtifact {
        name,
        bytes,
        digest,
    })
}

static AUDIT_ARTIFACT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn audit_artifact_request_id(request_id: &str) -> String {
    let sequence = AUDIT_ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let material = format!("{request_id}:{now}:{sequence}");
    // Relative to the artifact sink root, which is an `AuditScratch`
    // artifacts directory outside the audited tree.
    format!(
        "legion-audit/{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

static AUDIT_SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Per-run scratch space for everything an audit writes while executing
/// checks: sandbox profiles, effect artifacts (stdout/stderr), file-backed tool
/// reports, temp files and tool caches. It always lives outside the audited
/// tree and is removed on drop (best effort) when the executor created it.
#[derive(Debug)]
pub struct AuditScratch {
    root: PathBuf,
    remove_on_drop: bool,
    retained: std::sync::atomic::AtomicBool,
    pending_attested: std::sync::atomic::AtomicUsize,
}

impl AuditScratch {
    /// Create a unique owner-only scratch directory under the system temp dir.
    /// Fails when no candidate location lies outside `audited_root`.
    pub fn create(audited_root: &Path) -> Result<Self, AuditError> {
        let mut candidates = vec![std::env::temp_dir()];
        if cfg!(unix) {
            candidates.push(PathBuf::from("/var/tmp"));
        }
        let mut last = "no scratch location candidates".to_owned();
        for base in candidates {
            if path_inside(&base, audited_root) {
                last = format!(
                    "scratch base {} lies inside the audited root {}",
                    base.display(),
                    audited_root.display()
                );
                continue;
            }
            let sequence = AUDIT_SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let root = base.join(format!(
                "legion-audit-{}-{sequence}-{nanos}",
                std::process::id()
            ));
            match Self::prepare(&root) {
                Ok(()) => {
                    return Ok(Self {
                        root,
                        remove_on_drop: true,
                        retained: std::sync::atomic::AtomicBool::new(false),
                        pending_attested: std::sync::atomic::AtomicUsize::new(0),
                    });
                }
                Err(error) => last = format!("cannot create {}: {error}", root.display()),
            }
        }
        Err(AuditError::Provider(format!(
            "audit-scratch-unavailable: {last}"
        )))
    }

    /// Use a caller-chosen directory (for example the run's `--out`
    /// directory). It is created if absent, must lie outside `audited_root`,
    /// and is never removed by this value.
    pub fn with_scratch_dir(
        audited_root: &Path,
        dir: impl Into<PathBuf>,
    ) -> Result<Self, AuditError> {
        let root = dir.into();
        if path_inside(&root, audited_root) {
            return Err(AuditError::Provider(format!(
                "audit-scratch-unavailable: scratch dir {} lies inside the audited root {}",
                root.display(),
                audited_root.display()
            )));
        }
        Self::prepare(&root).map_err(|error| {
            AuditError::Provider(format!(
                "audit-scratch-unavailable: cannot create {}: {error}",
                root.display()
            ))
        })?;
        Ok(Self {
            root,
            remove_on_drop: false,
            retained: std::sync::atomic::AtomicBool::new(false),
            pending_attested: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn prepare(root: &Path) -> std::io::Result<()> {
        make_private_dir(root)?;
        for child in ["sandbox", "artifacts", "reports", "tmp", "cache"] {
            make_private_dir(&root.join(child))?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn retain_after_drop(&self) {
        self.retained.store(true, Ordering::Release);
    }

    pub(super) fn begin_attested_request(&self) {
        self.pending_attested.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn finish_attested_request(&self) {
        let previous = self.pending_attested.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "attested request completion must be paired");
    }

    /// Sandbox profiles.
    pub fn sandbox_dir(&self) -> PathBuf {
        self.root.join("sandbox")
    }

    /// Root of the effect artifact sink; request ids are relative to it.
    pub fn artifacts_dir(&self) -> PathBuf {
        self.root.join("artifacts")
    }

    fn reports_dir(&self) -> PathBuf {
        self.root.join("reports")
    }

    pub(crate) fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub(crate) fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }
}

impl Drop for AuditScratch {
    fn drop(&mut self) {
        if self.remove_on_drop
            && !self.retained.load(Ordering::Acquire)
            && self.pending_attested.load(Ordering::Acquire) == 0
        {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn make_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// True when `path` is `root` or lies beneath it, comparing canonical forms
/// of the deepest existing ancestors so symlinked temp dirs (`/tmp` ->
/// `/private/tmp`) are seen through.
fn path_inside(path: &Path, root: &Path) -> bool {
    fn canonical(path: &Path) -> PathBuf {
        let mut missing = Vec::new();
        let mut current = path.to_path_buf();
        loop {
            if let Ok(real) = std::fs::canonicalize(&current) {
                return missing.iter().rev().fold(real, |acc, part| acc.join(part));
            }
            match (current.file_name().map(|n| n.to_owned()), current.parent()) {
                (Some(name), Some(parent)) => {
                    missing.push(name);
                    current = parent.to_path_buf();
                }
                _ => return path.to_path_buf(),
            }
        }
    }
    canonical(path).starts_with(canonical(root))
}

/// Immutable request builder for the legacy provider boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct LegacyCheckDispatcher;

impl LegacyCheckDispatcher {
    pub const fn new() -> Self {
        Self
    }

    pub fn contains(&self, provider_id: &str) -> bool {
        spec(provider_id).is_some()
    }

    pub fn contract(&self, provider_id: &str) -> Option<&'static LegacyCheckSpec> {
        spec(provider_id)
    }

    pub fn request(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: impl Into<PathBuf>,
        binding: Option<&Value>,
        projection: Option<&Value>,
        artifacts: &Value,
    ) -> Result<LegacyCheckProcessRequest, LegacyCheckError> {
        let contract = spec(&provider.id).ok_or_else(|| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: provider.id.clone(),
            state: LegacyCheckProcessState::Failed,
            message: "provider is not one of the frozen legacy-check contracts".into(),
        })?;
        contracts::validate_provider(provider, contract)?;
        let root = root.into();
        if !root.is_absolute() {
            return Err(LegacyCheckError {
                provider_id: provider.id.clone(),
                check: contract.check.into(),
                state: LegacyCheckProcessState::Failed,
                message: "legacy-check cwd must be absolute".into(),
            });
        }
        let selector = provider
            .configuration
            .get("selector")
            .ok_or_else(|| LegacyCheckError {
                provider_id: provider.id.clone(),
                check: contract.check.into(),
                state: LegacyCheckProcessState::Failed,
                message: "provider selector is missing".into(),
            })?;
        let denominator =
            inventory
                .denominator_entries(selector)
                .map_err(|error| LegacyCheckError {
                    provider_id: provider.id.clone(),
                    check: contract.check.into(),
                    state: LegacyCheckProcessState::Failed,
                    message: error.to_string(),
                })?;
        Ok(LegacyCheckProcessRequest {
            schema_version: CONTRACT_SCHEMA_VERSION,
            kind: REQUEST_KIND,
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            cwd: root,
            binding: binding.cloned(),
            denominator,
            projection: projection.cloned(),
            artifacts: artifacts.clone(),
            command: contract.command,
        })
    }

    pub fn input(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: impl Into<PathBuf>,
        binding: Option<&Value>,
        projection: Option<&Value>,
        artifacts: &Value,
    ) -> Result<LegacyCheckInput, LegacyCheckError> {
        let request = self.request(provider, inventory, root, binding, projection, artifacts)?;
        Ok(LegacyCheckInput {
            provider_id: request.provider_id,
            check: request.check,
            root: request.cwd,
            inventory_generation: inventory.generation.clone(),
            inventory_digest: inventory.digest.clone(),
            denominator: request.denominator,
            binding: request.binding,
            projection: request.projection,
            artifacts: request.artifacts,
        })
    }

    pub fn request_for_path(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: &Path,
    ) -> Result<LegacyCheckProcessRequest, LegacyCheckError> {
        self.request(provider, inventory, root, None, None, &Value::Null)
    }

    /// Project terminal process metadata into the validated common result.
    pub fn project_result(
        &self,
        provider: &AuditProvider,
        input: &LegacyCheckInput,
        execution: LegacyCheckExecution,
    ) -> Result<ProviderResult, LegacyCheckError> {
        let contract = spec(&provider.id).ok_or_else(|| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: provider.id.clone(),
            state: LegacyCheckProcessState::Failed,
            message: "provider is not one of the frozen legacy-check contracts".into(),
        })?;
        contracts::validate_provider(provider, contract)?;
        let provider_id = ProviderId::new(&provider.id).map_err(|error| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            state: LegacyCheckProcessState::Failed,
            message: error.to_string(),
        })?;
        let mut execution = execution;
        let mut output = execution.output.take().unwrap_or_default();
        let process_ok = execution.state == LegacyCheckProcessState::Completed;
        // The network-sandbox refusal reaches here as `unauthorized_effect`
        // (the effect layer's `SandboxMissing` state maps to `Unauthorized`).
        // It is a typed unavailable check only when no process started and the
        // receipt names the sandbox requirement; every other unauthorized cause
        // stays a failure.
        let process_started = output
            .details
            .get("executionReceipt")
            .and_then(|receipt| receipt.pointer("/processTree/started"))
            .and_then(Value::as_bool);
        let sandbox_refused = execution.state == LegacyCheckProcessState::Unauthorized
            && process_started == Some(false)
            && output
                .coverage_gaps
                .iter()
                .chain(output.degradation.iter())
                .chain(execution.error.iter().map(|error| &error.message))
                .any(|gap| gap.contains(SANDBOX_RECEIPT_REQUIRED));
        let admission_refused = execution.state == LegacyCheckProcessState::Unauthorized
            && process_started == Some(false)
            && output
                .details
                .get("executionReceipt")
                .is_some_and(|receipt| {
                    receipt.pointer("/policy/id").and_then(Value::as_str)
                        == Some(crate::execution_policy::POLICY_ID)
                        && receipt.pointer("/policy/allowed").and_then(Value::as_bool)
                            == Some(false)
                        && receipt.pointer("/policy/reason").and_then(Value::as_str)
                            == Some(crate::execution_policy::ADMISSION_UNAVAILABLE)
                });
        let read_only_test_owner_unavailable = execution.state
            == LegacyCheckProcessState::MissingExecutable
            && output
                .details
                .get("testCommandResolution")
                .and_then(|resolution| resolution.get("reason"))
                .and_then(Value::as_str)
                .is_some_and(|reason| reason.starts_with("read-only-test-owner-unavailable:"));
        let managed_test_runner_unavailable =
            managed_test_refusal(&provider.id, &execution, &output);
        let managed_test_unavailable_claim = output
            .details
            .get("testCommandResolution")
            .and_then(|resolution| resolution.get("reason"))
            .and_then(Value::as_str)
            .is_some_and(|reason| reason.starts_with("managed-test-"));
        if managed_test_unavailable_claim && !managed_test_runner_unavailable {
            output
                .details
                .remove(super::availability::AVAILABILITY_DETAIL);
            output
                .coverage_gaps
                .retain(|gap| !gap.starts_with("unavailable:managed-test-"));
            if let Some(coverage) = output.coverage.as_mut() {
                coverage
                    .gaps
                    .retain(|gap| !gap.starts_with("unavailable:managed-test-"));
            }
            output
                .degradation
                .retain(|gap| !gap.starts_with("unavailable:managed-test-"));
        }
        // A declared scanner that is absent resolves to its class outcome. Only
        // a missing tool with a declared class is affected; everything else keeps
        // the existing typed behaviour.
        let declared_absence = (execution.state == LegacyCheckProcessState::MissingExecutable
            && !read_only_test_owner_unavailable
            && !managed_test_runner_unavailable
            && !managed_test_unavailable_claim)
            .then(|| registry::absence_outcome(contract.tool))
            .flatten();
        let mut gaps = output.coverage_gaps.clone();
        let mut degradation = output.degradation.clone();
        if !process_ok
            && !sandbox_refused
            && !admission_refused
            && !read_only_test_owner_unavailable
            && !managed_test_runner_unavailable
            && !matches!(declared_absence, Some(AbsenceOutcome::NonBlocking(_)))
        {
            gaps.push(format!("external-process:{}", execution.state.as_str()));
            degradation.push(format!("external-process:{}", execution.state.as_str()));
        }
        if let Some(error) = &execution.error {
            gaps.push(format!("external-error:{}", error.message));
            degradation.push(format!("external-error:{}", error.message));
        }
        // A tool or project configuration that is simply absent is a typed
        // `unavailable:<reason>` gap, never a failed provider: nothing ran and
        // nothing broke.
        let unavailable_reason = if read_only_test_owner_unavailable {
            Some("read-only-test-owner-unavailable:test".to_owned())
        } else if managed_test_runner_unavailable {
            output
                .details
                .get("testCommandResolution")
                .and_then(|resolution| resolution.get("reason"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        } else {
            (execution.state == LegacyCheckProcessState::MissingExecutable
                && !managed_test_unavailable_claim
                && declared_absence.is_none())
            .then(|| {
                let gap_text = output
                    .coverage_gaps
                    .iter()
                    .chain(output.degradation.iter())
                    .find(|gap| {
                        gap.starts_with("missing executable: ")
                            || gap.contains("is not configured")
                            || gap.starts_with("no configured project")
                            || gap.contains("metadata is unavailable")
                    })
                    .cloned();
                match gap_text {
                    Some(gap) if gap.starts_with("missing executable: ") => {
                        format!("tool-missing:{}", &gap["missing executable: ".len()..])
                    }
                    Some(_) => format!("not-configured:{}", contract.check),
                    None => format!("tool-missing:{}", contract.tool),
                }
            })
        }
        .or_else(|| sandbox_refused.then(|| format!("sandbox-missing:{}", contract.tool)))
        .or_else(|| {
            admission_refused.then(|| crate::execution_policy::ADMISSION_UNAVAILABLE.into())
        });
        let unavailable_reason = match declared_absence.clone() {
            Some(AbsenceOutcome::Blocking(reason)) => Some(reason),
            _ => unavailable_reason,
        };
        if let Some(AbsenceOutcome::NonBlocking(note)) = &declared_absence {
            output.details.insert(
                "capabilityAbsence".into(),
                json!({
                    "tool": contract.tool,
                    "note": note,
                    "blocking": false,
                    "substitute": registry::host_capability(contract.tool)
                        .and_then(|capability| capability.class.substitute()),
                }),
            );
        }
        if let Some(reason) = &unavailable_reason {
            gaps.push(super::availability::unavailable_gap(reason));
            output.details.insert(
                super::availability::AVAILABILITY_DETAIL.into(),
                super::availability::unavailable_detail(reason),
            );
        }
        let mut coverage = output.coverage.take().unwrap_or_else(|| Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected: input.denominator.entries.len() as u64,
            examined: 0,
            gaps: gaps.clone(),
        });
        if coverage.denominator_digest != input.denominator.digest {
            gaps.push("denominator-digest-mismatch".into());
        }
        gaps.extend(coverage.gaps.iter().cloned());
        if matches!(declared_absence, Some(AbsenceOutcome::NonBlocking(_))) {
            // The absent declared tool is recorded only as its note. The process
            // text it produced is not a blocking gap or degradation; other
            // failures keep their gaps.
            let is_absence_text = |gap: &String| {
                gap.starts_with("missing executable: ")
                    || gap.starts_with("external-process:missing_executable")
                    || gap.starts_with("external-error:missing executable: ")
            };
            gaps.retain(|gap| !is_absence_text(gap));
            degradation.retain(|gap| !is_absence_text(gap));
            coverage.gaps.retain(|gap| !is_absence_text(gap));
        }
        gaps.sort();
        gaps.dedup();
        degradation.sort();
        degradation.dedup();
        let complete = process_ok && output.complete && gaps.is_empty() && coverage.complete();
        output
            .details
            .insert("check".into(), Value::String(contract.check.into()));
        output
            .details
            .insert("tool".into(), Value::String(contract.tool.into()));
        output.details.insert(
            "processState".into(),
            Value::String(execution.state.as_str().into()),
        );
        output.details.insert(
            "exitCode".into(),
            execution.exit_code.map(Value::from).unwrap_or(Value::Null),
        );
        output.details.insert(
            "stdoutBytes".into(),
            Value::from(execution.stdout.len() as u64),
        );
        output.details.insert(
            "stderrBytes".into(),
            Value::from(execution.stderr.len() as u64),
        );
        // Structural guarantee: a candidate-generator never emits findings.
        // Anything a parser routed there is demoted to an unadjudicated
        // candidate carrying its evidence, so the result stays valid.
        if contract.role.contains("candidate") && !output.findings.is_empty() {
            for finding in std::mem::take(&mut output.findings) {
                let id = finding.id.to_string();
                let evidence = output
                    .details
                    .get_mut("findingEvidence")
                    .and_then(Value::as_object_mut)
                    .and_then(|items| items.remove(&id))
                    .unwrap_or(Value::Null);
                if let Some(items) = output
                    .details
                    .get_mut("findingLocations")
                    .and_then(Value::as_object_mut)
                {
                    items.remove(&id);
                }
                output.candidates.push(json!({
                    "id": id,
                    "role": "candidate-generator",
                    "severityHint": finding.severity,
                    "evidence": evidence,
                    "evidenceStrength": "candidate",
                    "verdict": "UNADJUDICATED",
                    "adjudicationRequired": true,
                }));
            }
        }
        let candidates = std::mem::take(&mut output.candidates);
        output
            .details
            .insert("candidates".into(), Value::Array(candidates));
        output.details.insert(
            "commandShape".into(),
            Value::String(command_name(contract.command).into()),
        );
        if let Some(receipt_id) = execution.receipt_id {
            output
                .details
                .insert("receiptId".into(), Value::String(receipt_id));
        }
        if let Some(error) = execution.error {
            output.details.insert(
                "executionError".into(),
                json!({"state": error.state.as_str(), "message": error.message}),
            );
        }
        let status = if complete {
            if matches!(output.status, ProviderStatus::Ok) {
                ProviderStatus::Ok
            } else {
                ProviderStatus::Complete
            }
        } else if process_ok {
            output.status
        } else if unavailable_reason.is_some() || declared_absence.is_some() {
            ProviderStatus::Partial
        } else {
            ProviderStatus::Failed
        };
        let result = ProviderResult {
            schema_version: 1,
            provider: provider_id,
            applicable: true,
            required: provider.required,
            status,
            complete,
            coverage: Some(Coverage {
                denominator_digest: coverage.denominator_digest,
                expected: coverage.expected,
                examined: coverage.examined,
                gaps: gaps.clone(),
            }),
            findings: output.findings,
            coverage_gaps: gaps,
            degradation,
            details: output.details,
        };
        result.validate().map_err(|error| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            state: LegacyCheckProcessState::Failed,
            message: error.to_string(),
        })?;
        Ok(result)
    }
}

/// Native Rust owner for all 33 frozen legacy provider IDs.
#[derive(Clone)]
pub struct NativeLegacyCheckExecutor {
    root: PathBuf,
    external_project_tool: Option<Arc<dyn ExternalProjectTool>>,
    fixture_policy_authorizer: Option<Arc<dyn legion_effects::PolicyAuthorizer>>,
    attested_runs: Option<Arc<AttestedRunsEnrollment>>,
    /// Shared across clones; created lazily under the system temp dir unless
    /// the host supplied one with `with_scratch`.
    scratch: Arc<Mutex<Option<Arc<AuditScratch>>>>,
}

impl std::fmt::Debug for NativeLegacyCheckExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeLegacyCheckExecutor")
            .field("root", &self.root)
            .field(
                "external_project_tool",
                &self.external_project_tool.is_some(),
            )
            .field("attested_runs", &self.attested_runs.is_some())
            .finish()
    }
}

impl NativeLegacyCheckExecutor {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            external_project_tool: None,
            fixture_policy_authorizer: None,
            attested_runs: None,
            scratch: Arc::new(Mutex::new(None)),
        }
    }

    /// Route all audit scratch (sandbox profiles, artifacts, reports, temp and
    /// cache files) into a host-provided directory outside the audited root.
    pub fn with_scratch(self, scratch: Arc<AuditScratch>) -> Self {
        *self.scratch.lock().expect("scratch lock") = Some(scratch);
        self
    }

    pub(crate) fn scratch(&self) -> Result<Arc<AuditScratch>, AuditError> {
        let mut slot = self.scratch.lock().expect("scratch lock");
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.clone());
        }
        let created = Arc::new(AuditScratch::create(&self.root)?);
        *slot = Some(created.clone());
        Ok(created)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn with_external_project_tool(mut self, tool: Arc<dyn ExternalProjectTool>) -> Self {
        self.external_project_tool = Some(tool);
        self
    }

    /// Explicit trusted in-process SDK fixture/managed-preparation seam;
    /// never exposed by CLI/MCP.
    pub fn with_fixture_policy_authorizer(
        mut self,
        authorizer: Arc<dyn legion_effects::PolicyAuthorizer>,
    ) -> Self {
        self.fixture_policy_authorizer = Some(authorizer);
        self
    }

    /// Enable verified managed test runs using an explicitly loaded host pin.
    pub fn with_attested_runs(mut self, enrollment: AttestedRunsEnrollment) -> Self {
        self.attested_runs = Some(Arc::new(enrollment));
        self
    }

    pub async fn execute_async(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ProviderResult, AuditError> {
        let dispatcher = LegacyCheckDispatcher::new();
        let mut input = dispatcher
            .input(
                provider,
                inventory,
                self.root.clone(),
                None,
                None,
                &Value::Null,
            )
            .map_err(|error| AuditError::Provider(error.to_string()))?;
        let contract = spec(&provider.id).expect("validated above");
        if matches!(contract.command, CommandShape::Native { .. }) {
            return self.execute(provider, inventory);
        }
        // Runtime capture runs one browser invocation per requested surface
        // and builds its own evidence; it never goes through the single-run
        // parser path below.
        if contract.check == "outdated" {
            return node_outdated::execute(self, plan, provider, &input, cancellation).await;
        }
        if contract.check == "runtime" {
            return runtime_capture::execute(self, plan, provider, &input, cancellation).await;
        }
        if contract.check == "test" {
            if let Some(enrollment) = self.attested_runs.as_deref() {
                if let Err(error) = enrollment.validate() {
                    let execution =
                        invalid_test_enrollment(&input, contract.command, &error.to_string());
                    return dispatcher
                        .project_result(provider, &input, execution)
                        .map_err(|error| AuditError::Provider(error.to_string()));
                }
            }
        }
        let mut test_command = None;
        let mut test_command_source = None;
        if contract.check == "test" {
            if self.attested_runs.is_none() {
                let execution = unavailable_test_refusal(
                    &input,
                    "managed-test-trust-not-configured",
                    json!({"assurance":"attested-runs-required"}),
                );
                return dispatcher
                    .project_result(provider, &input, execution)
                    .map_err(|error| AuditError::Provider(error.to_string()));
            }
            match resolve_test_command_with_enrollment(
                &self.root,
                inventory,
                self.attested_runs.as_deref(),
            ) {
                Ok((resolved, source)) => {
                    test_command = Some(resolved);
                    test_command_source = Some(source);
                }
                Err(error) => {
                    if let ResolveError::NotConfigured(reason) = &error {
                        if reason.starts_with("managed-test-") {
                            let execution = unavailable_test_refusal(
                                &input,
                                reason,
                                json!({"assurance":"attested-runs-required","source":"frozen-test-command-resolution"}),
                            );
                            return dispatcher
                                .project_result(provider, &input, execution)
                                .map_err(|error| AuditError::Provider(error.to_string()));
                        }
                    }
                    let unavailable = matches!(
                        &error,
                        ResolveError::MissingExecutable(_) | ResolveError::NotConfigured(_)
                    );
                    let state = if unavailable {
                        LegacyCheckProcessState::MissingExecutable
                    } else {
                        LegacyCheckProcessState::Failed
                    };
                    let message = if matches!(&error, ResolveError::NotConfigured(_)) {
                        error.message()
                    } else {
                        error.message()
                    };
                    let gap = if unavailable {
                        message.clone()
                    } else {
                        format!("test-source-input-invalid:{message}")
                    };
                    let mut output = empty_output(vec![gap.clone()]);
                    output.details.insert(
                        "testCommandResolution".into(),
                        json!({"status":"unavailable","reason":message.clone()}),
                    );
                    output.coverage = Some(Coverage {
                        denominator_digest: input.denominator.digest.clone(),
                        expected: input.denominator.entries.len() as u64,
                        examined: 0,
                        gaps: vec![gap.clone()],
                    });
                    let execution = terminal_execution(
                        &input,
                        contract.command,
                        state,
                        None,
                        Vec::new(),
                        Vec::new(),
                        output,
                        vec![gap],
                        now_ms(),
                        false,
                        Some(&message),
                    );
                    return dispatcher
                        .project_result(provider, &input, execution)
                        .map_err(|error| AuditError::Provider(error.to_string()));
                }
            }
        }
        if test_command_source.is_some() {
            let Some(tool) = &self.external_project_tool else {
                let mut execution = execute_external(&input, contract.command, now_ms());
                attach_test_command_source(&mut execution, test_command_source.as_ref());
                return dispatcher
                    .project_result(provider, &input, execution)
                    .map_err(|error| AuditError::Provider(error.to_string()));
            };
            let resolved = test_command.as_ref().expect("resolved Rust command");
            let scratch = self.scratch()?;
            let timeout = provider
                .bounds
                .get("timeoutMs")
                .and_then(Value::as_u64)
                .unwrap_or(120_000);
            let execution = disposable_copy::execute(
                tool.as_ref(),
                plan.digest(),
                self.fixture_policy_authorizer.as_deref(),
                &self.root,
                resolved,
                test_command_source
                    .as_ref()
                    .expect("resolved test source metadata"),
                provider,
                inventory,
                &input,
                &scratch,
                cancellation,
                timeout,
                self.attested_runs.as_deref(),
            )
            .await;
            return dispatcher
                .project_result(provider, &input, execution)
                .map_err(|error| AuditError::Provider(error.to_string()));
        }
        let Some(tool) = &self.external_project_tool else {
            let mut execution = execute_external(&input, contract.command, now_ms());
            attach_test_command_source(&mut execution, test_command_source.as_ref());
            return dispatcher
                .project_result(provider, &input, execution)
                .map_err(|error| AuditError::Provider(error.to_string()));
        };
        let (executable, mut args) = test_command.as_ref().map_or_else(
            || {
                let (executable, args) = command_parts(contract.command);
                (executable.to_owned(), args)
            },
            |resolved| {
                (
                    resolved.executable.to_string_lossy().into_owned(),
                    resolved.args.clone(),
                )
            },
        );
        if contract.check == "ci_lint" {
            if input.denominator.entries.is_empty() {
                return Err(AuditError::Provider("ci-lint-denominator-empty".into()));
            }
            // Explicit frozen workflows also work in exported/snapshot trees
            // without .git. No repository discovery can widen this denominator.
            args.push("--".into());
            args.extend(
                input
                    .denominator
                    .entries
                    .iter()
                    .map(|entry| format!("./{}", entry.path)),
            );
        }
        // `gitleaks git` scans commit history and needs a repository. A tree
        // without `.git` (an exported archive, a fixture) is scanned as a
        // plain directory instead of failing with no report.
        if contract.check == "secrets" && !self.root.join(".git").exists() {
            if let Some(first) = args.first_mut() {
                if first.as_str() == "git" {
                    *first = "dir".into();
                }
            }
        }
        let scratch = self.scratch()?;
        let python_requirements = if contract.check == "py_deps_cve" {
            match python_requirements::prepare(&input, &scratch) {
                Ok(prepared) => {
                    args = prepared.args.clone();
                    input.artifacts = json!({(python_requirements::KEY):prepared.binding});
                    Some(prepared)
                }
                Err(reason) => {
                    let execution = python_input_refusal(&input, contract.command, &reason);
                    return dispatcher
                        .project_result(provider, &input, execution)
                        .map_err(|error| AuditError::Provider(error.to_string()));
                }
            }
        } else {
            None
        };
        if contract.check == "sast" {
            match semgrep::prepare(&input, provider, &scratch, &args) {
                Ok(prepared) => args = prepared,
                Err(execution) => {
                    return dispatcher
                        .project_result(provider, &input, execution)
                        .map_err(|error| AuditError::Provider(error.to_string()))
                }
            }
        }
        let report_source = report_source_for(contract.check);
        // A file-backed report is never written into the project tree: the
        // executor owns a scratch dir for the run's lifetime and the tool is
        // pointed at it explicitly.
        let report_temp_dir = match report_source {
            ReportSource::File(_) => Some(
                ReportTempDir::create(&scratch.reports_dir(), contract.check).map_err(|error| {
                    AuditError::Provider(format!(
                        "failed to create report temp dir for {}: {error}",
                        contract.check
                    ))
                })?,
            ),
            ReportSource::Stdout | ReportSource::Stderr => None,
        };
        if let Some(dir) = &report_temp_dir {
            args.extend(report_args(&dir.path));
        }
        let request_id = format!(
            "audit:{}:{}:{}",
            provider.id,
            plan.digest(),
            inventory.digest
        );
        let (environment, environment_allowlist) = audit_environment(&scratch);
        let needs_sandbox = sandbox_required_check(contract.check);
        // Cargo uses 101 for denied lint diagnostics as well as launch/compiler
        // failures. Admit that raw exit only for the resolved frozen clippy
        // invocation; execution_from_receipt still requires diagnostic evidence.
        let mut exit_codes = accepted_exit_codes(contract.check);
        if contract.check == "lint"
            && resolve_request(&self.root, &executable, &args).is_ok_and(|resolved| {
                cargo_clippy_args(&resolved.args)
                    && resolve_request(&self.root, "cargo", &[]).is_ok_and(|cargo| {
                        cargo.executable == resolved.executable && cargo.digest == resolved.digest
                    })
            })
        {
            exit_codes.insert(101);
        }
        // Once the sandbox wrapper is the executable the adapter can no longer
        // see the tool it wraps, so the working directory the tool needs (a
        // nested Cargo workspace, `src-tauri`) is resolved here.
        let mut tool_cwd: Option<PathBuf> =
            test_command.as_ref().map(|resolved| resolved.cwd.clone());
        let (executable, args, sandbox_receipt, version_args) = if needs_sandbox {
            let mode = sandbox_mode_for_check(contract.check);
            let profile_dir = scratch.sandbox_dir();
            // `executable` here is still the bare tool name (e.g. "jscpd").
            // sandbox-exec runs the wrapped command with a scrubbed
            // environment, so a bare name relying on PATH lookup inside the
            // sandbox is not guaranteed to resolve (node_modules/.bin tools
            // in particular are not on PATH at all). Resolve to the same
            // sealed absolute path `AuditExternalProjectTool::execute` would
            // resolve later, and wrap *that* path so both the sandboxed run
            // and its `--version` probe target a real, fixed executable.
            // Only macOS wraps in sandbox-exec, which scrubs PATH, so resolve
            // the tool to its sealed absolute path there.
            // If the tool cannot be resolved (for example `project-types` in a
            // tree with no tsconfig.json), do not wrap the bare symbolic name:
            // `sandbox-exec -- project-types` would fail its version probe and
            // be misreported as an unqualified executable. Leaving the request
            // unwrapped lets `AuditExternalProjectTool` report the real
            // resolution failure as a typed gap.
            let wrap_target: Option<(String, Vec<String>)> = if cfg!(target_os = "macos") {
                resolve_request(&self.root, &executable, &args)
                    .ok()
                    .map(|resolved| {
                        tool_cwd = Some(resolved.cwd.clone());
                        (
                            resolved.executable.to_string_lossy().into_owned(),
                            resolved.args,
                        )
                    })
            } else {
                Some((executable.to_string(), args.clone()))
            };
            let authenticated = wrap_target.map(|(resolved_executable, resolved_args)| {
                legion_effects::authenticate_sandbox(
                    &resolved_executable,
                    &resolved_args,
                    &self.root.to_string_lossy(),
                    mode,
                    &profile_dir,
                )
            });
            match authenticated {
                Some(Ok(auth)) => {
                    // The executor's identity check re-invokes the resolved
                    // `executable` with `--version` to confirm it is the
                    // real tool (executor.rs's version-probe qualification).
                    // Once `executable` is `sandbox-exec`, bare `--version`
                    // is not a valid `sandbox-exec` invocation (it requires
                    // `-f <profile> -- <command>` first) and the probe
                    // fails as an unqualified/unsealed executable even
                    // though the wrapped command itself is fine. Route the
                    // probe through the same wrapper prefix so it actually
                    // exercises the real tool's `--version`.
                    // `wrapped_args` is `["-f", profile, "--", executable,
                    // ...check_args]` (see `legion_effects::sandbox`); keep
                    // only the fixed sandbox-invocation prefix (the first
                    // four elements) plus the real executable, so the probe
                    // asks the actual tool for its version rather than
                    // re-running the check's own argv with `--version`
                    // tacked on.
                    let mut probe_args: Vec<String> =
                        auth.wrapped_args.iter().take(4).cloned().collect();
                    probe_args.push(legacy_version_probe_flag(contract.check).into());
                    (
                        auth.wrapped_executable,
                        auth.wrapped_args,
                        Some(legion_effects::SandboxReceipt {
                            id: auth.id,
                            network: auth.network,
                            filesystem_scope: auth.filesystem_scope,
                        }),
                        Some(probe_args),
                    )
                }
                Some(Err(_)) | None => {
                    // Typed degradation: no authenticator is available on
                    // this host/platform. Leave sandbox unset so the
                    // effects executor keeps refusing rather than run the
                    // check unsandboxed.
                    (executable.to_string(), args, None, None)
                }
            }
        } else {
            (executable.to_string(), args, None, None)
        };
        if let Some(resolved) = &test_command {
            // Sandbox wrapping can resolve an absolute executable relative to
            // the repository root; preserve the frozen runner's selected cwd.
            tool_cwd = Some(resolved.cwd.clone());
        }
        // `cargo-outdated` is a cargo subcommand binary: its identity probe
        // is `cargo-outdated outdated --version`, not `cargo-outdated --version`.
        let version_args = if contract.check == "cargo_outdated" {
            Some(match version_args {
                Some(mut probe) => {
                    let at = probe.len().saturating_sub(1);
                    probe.insert(at, "outdated".into());
                    probe
                }
                None => vec!["outdated".into(), "--version".into()],
            })
        } else {
            version_args
        };
        let request_cwd = tool_cwd.unwrap_or_else(|| self.root.clone());
        let request = ExternalToolRequest {
            request_id,
            provider_id: provider.id.clone(),
            plan_id: plan.digest().into(),
            policy_id: provider
                .configuration
                .get("policyId")
                .and_then(Value::as_str)
                .unwrap_or("audit")
                .into(),
            task_id: Some(contract.check.into()),
            executable,
            args,
            cwd: request_cwd.to_string_lossy().into_owned(),
            shell: false,
            expected_digest: None,
            accepted_exit_codes: exit_codes,
            version_requirement: test_command_source
                .as_ref()
                .and_then(|source| source.get("versionRequirement"))
                .and_then(Value::as_str)
                .map(|version| {
                    if contract.check == "test" {
                        format!("exact:{version}")
                    } else {
                        version.to_owned()
                    }
                })
                .or_else(|| (contract.check == "sast").then(|| "exact:1.141.0".into())),
            environment,
            environment_allowlist,
            // Checks in `sandbox_required_check` now carry an authenticated
            // `sandbox-exec` receipt on macOS (see `legion_effects::sandbox`).
            // On hosts/platforms without an authenticator, `sandbox_receipt`
            // stays `None` and the effects executor refuses the check as
            // typed degradation. Safe read-only git and gitleaks checks
            // remain executable under the explicit Audit policy without a
            // sandbox.
            requires_network_sandbox: needs_sandbox,
            sandbox: sandbox_receipt,
            timeout_ms: provider
                .bounds
                .get("timeoutMs")
                .and_then(Value::as_u64)
                .unwrap_or(120_000),
            stdout_limit: provider
                .bounds
                .get("stdoutLimit")
                .and_then(Value::as_u64)
                .unwrap_or(8 * 1024 * 1024) as usize,
            stderr_limit: provider
                .bounds
                .get("stderrLimit")
                .and_then(Value::as_u64)
                .unwrap_or(8 * 1024 * 1024) as usize,
            version_args: version_args
                .unwrap_or_else(|| vec![legacy_version_probe_flag(contract.check).into()]),
            ..ExternalToolRequest::default()
        };
        let outdated_input = (contract.check == "cargo_outdated")
            .then(|| rust_outdated::capture(&input, inventory, Path::new(&request.cwd)));
        let receipt = tool.execute(request, cancellation).await;
        let report_artifact = report_temp_dir
            .as_ref()
            .and_then(|dir| read_report_artifact(&dir.path, report_source));
        // Drop (and remove) the scratch dir now that the report has been
        // read back into memory, rather than leaving it until the process
        // exits.
        drop(report_temp_dir);
        let python_sources_unchanged = python_requirements
            .as_ref()
            .is_none_or(|prepared| prepared.unchanged(&input));
        let mut execution = execution_from_receipt(
            &input,
            contract.command,
            &[scratch.artifacts_dir().as_path(), self.root.as_path()],
            receipt,
            report_source,
            report_artifact,
            test_command_source,
        );
        if !python_sources_unchanged {
            if let Some(output) = execution.output.as_mut() {
                output.complete = false;
                output.findings.clear();
                output.candidates.clear();
                output.details.insert("findingsCount".into(), Value::Null);
                output
                    .coverage_gaps
                    .push("python-requirements-input-drift".into());
                if let Some(coverage) = output.coverage.as_mut() {
                    coverage.examined = 0;
                    coverage.gaps.push("python-requirements-input-drift".into());
                }
            }
        }
        if let Some(before) = outdated_input {
            rust_outdated::reconcile(&input, inventory, before, &mut execution);
        }
        dispatcher
            .project_result(provider, &input, execution)
            .map_err(|error| AuditError::Provider(error.to_string()))
    }

    pub fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let dispatcher = LegacyCheckDispatcher::new();
        let input = dispatcher
            .input(
                provider,
                inventory,
                self.root.clone(),
                None,
                None,
                &Value::Null,
            )
            .map_err(|error| AuditError::Provider(error.to_string()))?;
        let contract = spec(&provider.id).expect("validated above");
        let execution = if contract.check == "test" {
            match self
                .attested_runs
                .as_deref()
                .map(AttestedRunsEnrollment::validate)
                .transpose()
            {
                Err(error) => invalid_test_enrollment(&input, contract.command, &error.to_string()),
                Ok(None) => unavailable_test_refusal(
                    &input,
                    "managed-test-trust-not-configured",
                    json!({"assurance":"attested-runs-required","entry":"native-sync"}),
                ),
                Ok(Some(())) => unavailable_test_refusal(
                    &input,
                    "managed-test-attested-executor-unavailable",
                    json!({"assurance":"attested-runs-required","entry":"native-sync"}),
                ),
            }
        } else {
            execute_input(&input, contract)
        };
        dispatcher
            .project_result(provider, &input, execution)
            .map_err(|error| AuditError::Provider(error.to_string()))
    }
}

fn python_input_refusal(
    input: &LegacyCheckInput,
    command: CommandShape,
    reason: &str,
) -> LegacyCheckExecution {
    let reason = format!("python-requirements-input-unavailable:{reason}");
    let gap = super::availability::unavailable_gap(&reason);
    let mut output = empty_output(vec![gap.clone()]);
    output.details.insert(
        python_requirements::KEY.into(),
        json!({"status":"unavailable","reason":reason}),
    );
    output.details.insert(
        super::availability::AVAILABILITY_DETAIL.into(),
        super::availability::unavailable_detail(&reason),
    );
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: 0,
        gaps: vec![gap.clone()],
    });
    let mut execution = terminal_execution(
        input,
        command,
        LegacyCheckProcessState::Failed,
        None,
        vec![],
        vec![],
        output,
        vec![gap],
        now_ms(),
        false,
        Some(&reason),
    );
    if let Some(output) = execution.output.as_mut() {
        if let Some(receipt) = output.details.get_mut("executionReceipt") {
            receipt["parser"]["attempted"] = json!(false);
        }
    }
    execution
}

fn sandbox_required_check(check: &str) -> bool {
    matches!(
        check,
        "build"
            | "test"
            | "lint"
            | "types"
            | "dead_code"
            | "duplication"
            | "ci_lint"
            | "docker"
            | "sast"
            | "swift_lint"
            | "js_licenses"
            | "cargo_unsafe"
            | "cargo_unused_deps"
            | "deps_cve"
            | "py_deps_cve"
            | "cargo_audit"
            | "cargo_deny"
            | "outdated"
            | "cargo_outdated"
    )
}

/// Network-dependent advisory checks query a registry or vulnerability
/// database and must keep network access; the sandbox instead denies writes
/// under the project root so they cannot execute or mutate project code.
/// Every other sandboxed check executes target-project code, so network is
/// denied instead. Tests also deny writes beneath the audited root.
fn sandbox_mode_for_check(check: &str) -> legion_effects::SandboxMode {
    if check == "test" {
        legion_effects::SandboxMode::DenyNetworkDenyProjectWrite
    } else if matches!(
        check,
        "deps_cve" | "py_deps_cve" | "cargo_audit" | "cargo_deny" | "outdated" | "cargo_outdated"
    ) {
        legion_effects::SandboxMode::AllowNetworkDenyProjectWrite
    } else {
        legion_effects::SandboxMode::DenyNetwork
    }
}

#[cfg(test)]
mod sandbox_policy_tests {
    use super::*;

    #[test]
    fn project_tests_use_read_only_network_denied_sandbox() {
        assert_eq!(
            sandbox_mode_for_check("test"),
            legion_effects::SandboxMode::DenyNetworkDenyProjectWrite
        );
        assert!(sandbox_required_check("test"));
    }

    #[test]
    fn pinned_manager_versions_match_as_exact_tokens() {
        assert!(exact_version_token_matches("9.1.0\n", "9.1.0"));
        assert!(exact_version_token_matches("pnpm v9.1.0\n", "9.1.0"));
        assert!(!exact_version_token_matches("19.1.0\n", "9.1.0"));
        assert!(!exact_version_token_matches("9.1.0-rc.1\n", "9.1.0"));
    }
}

fn accepted_exit_codes(check: &str) -> BTreeSet<i32> {
    match check {
        "repo" | "build" | "sast" | "cargo_outdated" => [0].into_iter().collect(),
        // A normally exited test runner with non-zero code is a completed
        // test result with a failing-test finding, not a launch failure.
        "test" => (0..=255).collect(),
        // cargo-deny exposes a four-check bitset; completion is reconciled below.
        "cargo_deny" => (0..=15).collect(),
        "debt_markers" | "secrets" | "deps_cve" | "cargo_unused_deps" => {
            [0, 1].into_iter().collect()
        }
        _ => [0, 1, 2].into_iter().collect(),
    }
}

fn cargo_clippy_args(args: &[String]) -> bool {
    args.iter().map(String::as_str).eq([
        "clippy",
        "--all-targets",
        "--message-format=json",
        "--",
        "-D",
        "warnings",
    ])
}

pub(crate) fn audit_environment(
    scratch: &AuditScratch,
) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let names = [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
    ];
    let mut environment: BTreeMap<String, String> = names
        .iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| ((*name).to_owned(), value))
        })
        .collect();
    // Temp files and tool caches belong to the run, never to the audited
    // tree or the operator's home: point every conventional location into
    // scratch.
    let tmp = scratch.tmp_dir().to_string_lossy().into_owned();
    let cache = scratch.cache_dir();
    let cache_path = |name: &str| cache.join(name).to_string_lossy().into_owned();
    let overrides: [(&str, String); 13] = [
        ("TMPDIR", tmp.clone()),
        ("TEMP", tmp.clone()),
        ("TMP", tmp),
        ("XDG_CACHE_HOME", cache_path("xdg")),
        ("CARGO_TARGET_DIR", cache_path("cargo-target")),
        ("npm_config_cache", cache_path("npm")),
        ("RUFF_CACHE_DIR", cache_path("ruff")),
        ("MYPY_CACHE_DIR", cache_path("mypy")),
        ("PYTHONPYCACHEPREFIX", cache_path("pycache")),
        ("PYTHONDONTWRITEBYTECODE", "1".into()),
        ("PYTHONNOUSERSITE", "1".into()),
        ("GOCACHE", cache_path("go-build")),
        ("GIT_CONFIG_NOSYSTEM", "1".into()),
    ];
    let mut allowlist: BTreeSet<String> = names.into_iter().map(str::to_owned).collect();
    for (name, value) in overrides {
        allowlist.insert(name.to_owned());
        environment.insert(name.to_owned(), value);
    }
    (environment, allowlist)
}

#[async_trait::async_trait]
impl ProviderExecutor for NativeLegacyCheckExecutor {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        Self::execute(self, provider, inventory)
    }

    async fn execute_async(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ProviderResult, AuditError> {
        self.execute_async(plan, provider, inventory, cancellation)
            .await
    }
}

// license-checker 25.0.1's published CLI exits 1 for --version, but its
// successful --help prints license-checker@<package version>. Keep SDK probe
// success & real executable/script identity requirements unchanged (#71).
fn legacy_version_probe_flag(check: &str) -> &'static str {
    if check == "js_licenses" {
        "--help"
    } else {
        "--version"
    }
}

// The official CLI logs this exact line for read errors, yet can emit JSON &
// exit 0. Neither JSON syntax nor successful process exit proves a scan (#73).
fn license_checker_reported_error(check: &str, stderr: &[u8]) -> bool {
    check == "js_licenses"
        && stderr
            .split(|byte| *byte == b'\n')
            .any(|line| line.strip_suffix(b"\r").unwrap_or(line) == b"Found error")
}

fn execution_from_receipt(
    input: &LegacyCheckInput,
    command: CommandShape,
    roots: &[&Path],
    receipt: legion_provider_sdk::ExecutionReceipt,
    report_source: ReportSource,
    report_artifact: Option<ReportArtifact>,
    test_command_source: Option<Value>,
) -> LegacyCheckExecution {
    let state = match receipt.state {
        legion_provider_sdk::ExecutionState::Completed => LegacyCheckProcessState::Completed,
        legion_provider_sdk::ExecutionState::MissingExecutable => {
            LegacyCheckProcessState::MissingExecutable
        }
        legion_provider_sdk::ExecutionState::UnauthorizedEffect
        | legion_provider_sdk::ExecutionState::Blocked
        | legion_provider_sdk::ExecutionState::SandboxMissing
        | legion_provider_sdk::ExecutionState::UnsealedExecutable => {
            LegacyCheckProcessState::Unauthorized
        }
        legion_provider_sdk::ExecutionState::Timeout => LegacyCheckProcessState::Timeout,
        legion_provider_sdk::ExecutionState::Cancelled => LegacyCheckProcessState::Cancelled,
        legion_provider_sdk::ExecutionState::OutputLimited => {
            LegacyCheckProcessState::OutputLimited
        }
        legion_provider_sdk::ExecutionState::KillFailed
        | legion_provider_sdk::ExecutionState::ArtifactFailed => {
            LegacyCheckProcessState::CleanupUnconfirmed
        }
        _ => LegacyCheckProcessState::Failed,
    };
    let mut output = empty_output(receipt.gaps.clone());
    if input.check == "py_deps_cve" {
        output.details.insert(
            python_requirements::KEY.into(),
            input.artifacts[python_requirements::KEY].clone(),
        );
    }
    if input.check == "sast" && !semgrep::receipt_rules_valid(&receipt) {
        output
            .coverage_gaps
            .push("semgrep-rules-or-exit-unproven".into());
    }
    let stdout = receipt
        .stdout
        .as_ref()
        .and_then(|a| readable_artifact(roots, a));
    let stderr = receipt
        .stderr
        .as_ref()
        .and_then(|a| readable_artifact(roots, a));
    let mut parsed =
        input.check == "test" && receipt.complete && state == LegacyCheckProcessState::Completed;
    // Build diagnostics commonly land on stderr (notably rustc). Preserve both
    // original artifacts in the receipt while parsing their combined bytes.
    // A missing/unreadable stream cannot become a clean empty build report.
    let build_report = if input.check == "build" {
        stdout.as_deref().zip(stderr.as_deref()).map(|(out, err)| {
            let mut bytes = out.to_vec();
            bytes.push(b'\n');
            bytes.extend_from_slice(err);
            bytes
        })
    } else {
        None
    };
    let parse_bytes: Option<&[u8]> = if input.check == "build" {
        build_report.as_deref()
    } else {
        match report_source {
            ReportSource::Stdout => stdout.as_deref(),
            ReportSource::Stderr => stderr.as_deref(),
            ReportSource::File(_) => report_artifact
                .as_ref()
                .map(|report| report.bytes.as_slice()),
        }
    };
    let cargo_deny_completion_unproven = input.check == "cargo_deny"
        && !parse_bytes
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(parsers::cargo_deny_completion)
            .is_some_and(|(_, exit)| receipt.exit_code == Some(exit));
    let clippy_exit_unproven = input.check == "lint"
        && receipt.exit_code == Some(101)
        && !receipt.command.as_ref().is_some_and(|command| {
            let args = &command.args;
            let clippy_args = if args.len() == 10 && args[0] == "-f" && args[2] == "--" {
                &args[4..]
            } else {
                args.as_slice()
            };
            cargo_clippy_args(clippy_args)
                && stdout
                    .as_deref()
                    .zip(stderr.as_deref())
                    .is_some_and(|(out, err)| parsers::clippy_diagnostic_exit(out, err))
        });
    let exact_test_version_unproven = if input.check == "test"
        && (receipt.executable.is_some() || state == LegacyCheckProcessState::Completed)
    {
        test_command_source
            .as_ref()
            .and_then(|source| source.get("versionRequirement"))
            .and_then(Value::as_str)
            .filter(|required| {
                !receipt
                    .executable
                    .as_ref()
                    .and_then(|identity| identity.version.output.as_deref())
                    .is_some_and(|output| exact_version_token_matches(output, required))
            })
    } else {
        None
    };
    // cargo-machete may print a clean summary & exit zero after a per-manifest
    // metadata failure. Only a complete known report, not exit status alone,
    // proves analysis. Preserve actual receipt/streams when rejecting it.
    let cargo_machete_unproven = input.check == "cargo_unused_deps"
        && !stdout
            .as_deref()
            .zip(stderr.as_deref())
            .is_some_and(|(out, err)| {
                parsers::cargo_machete_report_complete(out, err, receipt.exit_code)
            });
    if cargo_deny_completion_unproven {
        output
            .coverage_gaps
            .push("cargo-deny-completion-unproven".into());
        output.status = ProviderStatus::Partial;
        output.details.insert("findingsCount".into(), Value::Null);
        parsed = true; // Don't treat operational failures or truncated reports as findings.
    } else if stderr
        .as_deref()
        .is_some_and(|bytes| license_checker_reported_error(&input.check, bytes))
    {
        output
            .coverage_gaps
            .push("legacy-tool-reported-error:js_licenses".into());
        output.status = ProviderStatus::Partial;
        output.details.insert("findingsCount".into(), Value::Null);
        parsed = true; // Classified incomplete; do not convert partial JSON into findings/clean.
    } else if cargo_machete_unproven {
        output
            .coverage_gaps
            .push("cargo-machete-analysis-unproven".into());
        output.status = ProviderStatus::Partial;
        output.complete = false;
        output.details.insert("findingsCount".into(), Value::Null);
        parsed = true;
    } else if clippy_exit_unproven {
        output
            .coverage_gaps
            .push("cargo-clippy-diagnostic-exit-unproven".into());
        output.status = ProviderStatus::Partial;
        output.details.insert("findingsCount".into(), Value::Null);
        parsed = true; // Classified incomplete; do not parse failure text as findings.
    } else if let Some(required) = exact_test_version_unproven {
        let reason = "test-runner-version-mismatch:test";
        let gap = super::availability::unavailable_gap(reason);
        output.coverage_gaps.push(gap.clone());
        output.status = ProviderStatus::Partial;
        output.details.insert(
            super::availability::AVAILABILITY_DETAIL.into(),
            super::availability::unavailable_detail(reason),
        );
        output.details.insert(
            "testOutcome".into(),
            json!({"status":"unavailable","requiredVersion":required}),
        );
    } else if input.check == "test" {
        // Test runners produce human-readable logs, not a required JSON
        // envelope. A completed receipt is the proof; stdout/stderr digests
        // remain bound in the receipt below.
    } else if let Some(bytes) = parse_bytes {
        if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
            parsed = parse_external_value(input, &value, &mut output);
        }
        if !parsed {
            let empty = bytes.iter().all(u8::is_ascii_whitespace);
            if json_document_required(input.check.as_str(), empty, receipt.exit_code) {
                // The tool always prints a JSON document and this was not
                // one (empty or free text): not proven, never a clean pass.
                output
                    .coverage_gaps
                    .push(format!("legacy-tool-output-unparseable:{}", input.check));
                output.details.insert("findingsCount".into(), Value::Null);
                parsed = true;
            }
        }
        if !parsed {
            parsed = parse_text_output(input, bytes, &mut output);
        }
    } else if matches!(report_source, ReportSource::File(_)) && receipt.complete {
        output
            .coverage_gaps
            .push("report-artifact-unreadable".into());
    }
    if receipt.complete && parsed && output.coverage.is_none() {
        output.coverage = Some(Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected: input.denominator.entries.len() as u64,
            examined: if input.check == "py_deps_cve" && !output.coverage_gaps.is_empty() {
                0
            } else {
                input.denominator.entries.len() as u64
            },
            gaps: output.coverage_gaps.clone(),
        });
    }
    let (_, args) = command_parts(command);
    let mut receipt_value = json!({
        "schemaVersion": receipt.schema_version, "receiptId": receipt.receipt_id,
        "requestId": receipt.request_id, "providerId": receipt.provider_id,
        "planId": receipt.plan_id, "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}", e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}", e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode": receipt.exit_code, "signal": receipt.signal,
        "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error}, "gaps": receipt.gaps,
        "requestArgs": args,
        "testCommandSource": test_command_source,
        "reportSource": match report_source { ReportSource::Stdout => "stdout", ReportSource::Stderr => "stderr", ReportSource::File(_) => "file" },
        "report": report_artifact.as_ref().map(|r| json!({"path":r.name,"digest":r.digest,"bytes":r.bytes.len(),"immutable":true})),
    });
    crate::execution_policy::project_binding(&mut receipt_value);
    if input.check == "test" {
        if let Some(source) = test_command_source.as_ref() {
            output
                .details
                .insert("testCommandSource".into(), source.clone());
        }
        if exact_test_version_unproven.is_none()
            && state == LegacyCheckProcessState::Completed
            && receipt.exit_code.is_some_and(|exit_code| exit_code != 0)
        {
            let exit_code = receipt.exit_code.unwrap_or_default();
            let material = format!(
                "{}\0{}\0{}\0{}",
                input.provider_id, input.inventory_digest, "test-run-failed", exit_code
            );
            let id = format!(
                "sha256:{}",
                hex::encode(Sha256::digest(material.as_bytes()))
            );
            let finding = FindingRef {
                id: FindingId::new(id.clone()).expect("derived finding id is valid"),
                severity: "medium".into(),
            };
            output.findings.push(finding);
            output.details.insert(
                "findingEvidence".into(),
                json!({(id.clone()): {
                    "kind":"project-test-failure",
                    "exitCode":exit_code,
                    "inventoryDigest":input.inventory_digest,
                    "testCommandSource":test_command_source,
                    "executionReceipt":receipt_value,
                }}),
            );
            output
                .details
                .insert("findingLocations".into(), json!({(id.clone()): []}));
            output.details.insert(
                "findingTitles".into(),
                json!({(id.clone()): "Test command exited nonzero"}),
            );
            output.details.insert(
                "findingMessages".into(),
                json!({(id.clone()): format!("Declared test command exited with code {exit_code}; failure cause is unclassified")}),
            );
            if let Some(location) = test_declaration_location(test_command_source.as_ref(), input) {
                output
                    .details
                    .insert("findingLocations".into(), json!({(id.clone()): [location]}));
                output.status = ProviderStatus::Complete;
            } else {
                output.findings.clear();
                output.details.remove("findingEvidence");
                output.details.remove("findingTitles");
                output.details.remove("findingMessages");
                output
                    .coverage_gaps
                    .push("test-command-declaration-outside-denominator".into());
                output.status = ProviderStatus::Partial;
                output.complete = false;
            }
            output.details.insert(
                "testOutcome".into(),
                json!({"passed":false,"exitCode":exit_code,"complete":receipt.complete}),
            );
        } else if exact_test_version_unproven.is_none()
            && state == LegacyCheckProcessState::Completed
            && receipt.exit_code == Some(0)
        {
            output.status = ProviderStatus::Ok;
            output.details.insert(
                "testOutcome".into(),
                json!({"passed":true,"exitCode":0,"complete":receipt.complete}),
            );
        }
    }
    output
        .details
        .insert("executionReceipt".into(), receipt_value);
    if !parsed && receipt.complete {
        output
            .coverage_gaps
            .push("artifact-bytes-unreadable".into());
    }
    if let Some(coverage) = output.coverage.as_mut() {
        coverage.gaps = output.coverage_gaps.clone();
    }
    output.complete = receipt.complete && parsed && output.coverage_gaps.is_empty();
    LegacyCheckExecution {
        state,
        exit_code: receipt.exit_code,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
        receipt_id: Some(receipt.receipt_id),
        output: Some(output),
        error: None,
    }
}

fn exact_version_token_matches(output: &str, required: &str) -> bool {
    output
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+' | '_'))
        })
        .any(|token| token == required || token.strip_prefix('v') == Some(required))
}

fn test_declaration_location(source: Option<&Value>, input: &LegacyCheckInput) -> Option<String> {
    if let Some(path) = source
        .and_then(|value| value.get("testDeclarationPath"))
        .and_then(Value::as_str)
        .filter(|path| {
            input
                .denominator
                .entries
                .iter()
                .any(|entry| entry.path == *path)
        })
    {
        return Some(path.to_owned());
    }
    let sources = source?.get("sources")?.as_array()?;
    sources
        .iter()
        .filter_map(|source| source.get("path")?.as_str())
        .find(|path| {
            (*path == "package.json" || path.ends_with("Cargo.toml"))
                && input
                    .denominator
                    .entries
                    .iter()
                    .any(|entry| entry.path == *path)
        })
        .map(ToOwned::to_owned)
}

/// Checks whose tool always prints one JSON document on a healthy run. Empty
/// or non-JSON output from these is an unparseable result. `outdated` prints
/// nothing when every package is current, so empty output is only clean there
/// when the tool also exited 0.
fn json_document_required(check: &str, empty: bool, exit_code: Option<i32>) -> bool {
    match check {
        "dead_code" | "duplication" | "sast" | "ci_lint" | "docker" | "swift_lint"
        | "js_licenses" | "deps_cve" | "py_deps_cve" | "cargo_audit" | "cargo_unsafe"
        | "cargo_outdated" => true,
        "outdated" => !(empty && exit_code == Some(0)),
        _ => false,
    }
}

fn readable_artifact(
    roots: &[&Path],
    artifact: &legion_effects::artifact::ArtifactRecord,
) -> Option<Vec<u8>> {
    if !artifact.immutable {
        return None;
    }
    // Relative artifact paths are relative to the artifact sink root: the
    // scratch artifacts dir in production; hosts that wire their own sink
    // (tests) may root it at the project instead.
    let path = Path::new(&artifact.path);
    let bytes = if path.is_absolute() {
        std::fs::read(path).ok()?
    } else {
        roots
            .iter()
            .find_map(|root| std::fs::read(root.join(path)).ok())?
    };
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    (bytes.len() == artifact.bytes && digest == artifact.digest).then_some(bytes)
}

fn execute_input(input: &LegacyCheckInput, contract: &LegacyCheckSpec) -> LegacyCheckExecution {
    let started = now_ms();
    if input.denominator.entries.is_empty() {
        let message = "frozen selector denominator is empty";
        let gaps = vec!["denominator-empty".to_owned()];
        return terminal_execution(
            input,
            contract.command,
            LegacyCheckProcessState::Failed,
            None,
            Vec::new(),
            Vec::new(),
            empty_output(gaps.clone()),
            gaps,
            started,
            false,
            Some(message),
        );
    }
    match contract.command {
        CommandShape::Native { operation } => {
            let output = native_operation(input, operation);
            let gaps = output.coverage_gaps.clone();
            // The analysis itself ran. A file that is too large or not text is
            // a bounded coverage limit (partial, gap named), not a broken
            // analyzer; only integrity or unimplemented-operation gaps fail.
            let hard_gap = gaps.iter().any(|gap| {
                !(gap.starts_with("source-file-byte-limit:")
                    || gap.starts_with("source-total-byte-limit:")
                    || gap.starts_with("source-invalid-utf8:"))
            });
            let state = if !hard_gap {
                LegacyCheckProcessState::Completed
            } else {
                LegacyCheckProcessState::Failed
            };
            let error = hard_gap.then(|| "native source analysis was incomplete");
            terminal_execution(
                input,
                contract.command,
                state,
                Some(0),
                Vec::new(),
                Vec::new(),
                output,
                gaps,
                started,
                true,
                error,
            )
        }
        command => execute_external(input, command, started),
    }
}

fn native_operation(input: &LegacyCheckInput, operation: &str) -> LegacyCheckOutput {
    let (files, mut gaps) = read_denominator(input);
    let mut output = empty_output(Vec::new());
    output
        .details
        .insert("implementation".into(), Value::String("native-rust".into()));
    output
        .details
        .insert("operation".into(), Value::String(operation.into()));
    if files.is_empty() {
        gaps.push("denominator-unreadable".into());
    }
    match input.check.as_str() {
        "apple_platform" => native_apple(&files, &mut output),
        "decomposition" => native_decomposition(input, &files, &mut output),
        "negative_space" => native_negative_space(&files, &mut output),
        "tool_coverage" => native_tool_coverage(input, &files, &mut output),
        "react_hooks" => native_react_hooks(&files, &mut output),
        "binary_pins" => native_binary_pins(&files, &mut output),
        "dep_pinning" => native_dependency_pinning(input, &files, &mut output),
        "vendored_deps" => native_vendored(&files, &mut output),
        "tauri_capabilities" => native_tauri_capabilities(&files, &mut output),
        "contract_mirror" => native_contract_mirror(&files, &mut output),
        _ => gaps.push(format!("native-operation-unimplemented:{}", input.check)),
    }
    output.coverage_gaps.extend(gaps);
    output.coverage_gaps.sort();
    output.coverage_gaps.dedup();
    output.complete = output.coverage_gaps.is_empty();
    if !output.coverage_gaps.is_empty() {
        output.status = ProviderStatus::Partial;
    }
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: files.len() as u64,
        gaps: output.coverage_gaps.clone(),
    });
    output
}

fn execute_external(
    input: &LegacyCheckInput,
    command: CommandShape,
    started: u64,
) -> LegacyCheckExecution {
    // Raw Command::output would bypass provider authorization, timeout/output
    // bounds and process-tree cleanup. Do not revive it as an implicit fallback.
    let (program, args) = command_parts(command);
    let gap = "external-project-tool-capability-unavailable".to_owned();
    let message = "legacy external check requires the application-owned authorized ExternalProjectTool capability";
    let mut output = empty_output(vec![gap.clone()]);
    output.degradation.push(message.into());
    output.details.insert(
        "implementation".into(),
        json!("native-external-capability-unavailable"),
    );
    output.details.insert("executable".into(), json!(program));
    output.details.insert("arguments".into(), json!(args));
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: 0,
        gaps: vec![gap.clone()],
    });
    let mut execution = terminal_execution(
        input,
        command,
        LegacyCheckProcessState::Unauthorized,
        None,
        Vec::new(),
        Vec::new(),
        output,
        vec![gap],
        started,
        false,
        Some(message),
    );
    // This is refusal evidence, not a policy grant or a process receipt from a
    // tool we did not run. Preserve explicit not-started/not-attempted facts.
    if let Some(output) = execution.output.as_mut() {
        let receipt = output
            .details
            .get_mut("executionReceipt")
            .expect("terminal receipt");
        receipt["policy"] = Value::Null;
        receipt["policyId"] = json!("unresolved-external-capability");
        receipt["executable"]["digestState"] = json!("not-checked");
        receipt["executable"]["version"]["qualified"] = json!(false);
        receipt["processTree"] = json!({"started":false,"terminated":false,"hardKilled":false,"reaped":false,"detail":"process not started: external capability unavailable"});
        // stdout/stderr are already null for non-native receipts: indexing a
        // null receipt field would resurrect an artifact object with a null
        // path, which the frozen external-receipt validator rejects.
        receipt["parser"]["attempted"] = json!(false);
    }
    execution
}

/// A managed test runner that cannot be safely enrolled is a pre-start
/// capability gap, not a failed or unclean process. Keep one receipt shape for
/// refusals at both the registry boundary and disposable-copy boundary.
pub(super) fn unavailable_test_refusal(
    input: &LegacyCheckInput,
    reason: &str,
    details: Value,
) -> LegacyCheckExecution {
    debug_assert!(reason.starts_with("managed-test-"));
    let gap = super::availability::unavailable_gap(reason);
    let mut output = empty_output(vec![gap.clone()]);
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: 0,
        gaps: vec![gap.clone()],
    });
    output.details.insert(
        super::availability::AVAILABILITY_DETAIL.into(),
        super::availability::unavailable_detail(reason),
    );
    output.details.insert(
        "testCommandResolution".into(),
        json!({"status":"unavailable","reason":reason}),
    );
    output.details.insert("disposableCopy".into(), details);
    let command = spec(&input.provider_id)
        .expect("managed test refusal uses a frozen provider contract")
        .command;
    let mut execution = terminal_execution(
        input,
        command,
        LegacyCheckProcessState::MissingExecutable,
        None,
        Vec::new(),
        Vec::new(),
        output,
        vec![gap],
        now_ms(),
        false,
        None,
    );
    if let Some(receipt) = execution
        .output
        .as_mut()
        .and_then(|output| output.details.get_mut("executionReceipt"))
    {
        receipt["policy"] = Value::Null;
        receipt["executable"]["digestState"] = json!("not-checked");
        receipt["executable"]["version"]["qualified"] = json!(false);
        receipt["processTree"] = json!({
            "started":false,
            "terminated":false,
            "hardKilled":false,
            "reaped":false,
            "detail":"managed test capability unavailable; no process or copy started"
        });
        receipt["parser"]["attempted"] = json!(false);
        receipt["parser"]["succeeded"] = json!(false);
        receipt["parser"]["error"] = Value::Null;
    }
    execution
}

pub(super) fn invalid_test_enrollment(
    input: &LegacyCheckInput,
    command: CommandShape,
    validation_error: &str,
) -> LegacyCheckExecution {
    let message = format!("test-enrollment-invalid:{validation_error}");
    let gap = message.clone();
    let mut output = empty_output(vec![gap.clone()]);
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: 0,
        gaps: vec![gap.clone()],
    });
    output.details.insert(
        "testCommandResolution".into(),
        json!({"status":"invalid","reason":message}),
    );
    let mut execution = terminal_execution(
        input,
        command,
        LegacyCheckProcessState::Failed,
        None,
        Vec::new(),
        Vec::new(),
        output,
        vec![gap],
        now_ms(),
        false,
        Some(&message),
    );
    if let Some(receipt) = execution
        .output
        .as_mut()
        .and_then(|output| output.details.get_mut("executionReceipt"))
    {
        receipt["parser"]["attempted"] = json!(false);
        receipt["parser"]["succeeded"] = json!(false);
        receipt["processTree"] = json!({
            "started":false,
            "terminated":false,
            "hardKilled":false,
            "reaped":false,
            "detail":"invalid managed-test enrollment; no process started"
        });
    }
    execution
}

fn managed_test_refusal(
    provider_id: &str,
    execution: &LegacyCheckExecution,
    output: &LegacyCheckOutput,
) -> bool {
    if execution.state != LegacyCheckProcessState::MissingExecutable || execution.error.is_some() {
        return false;
    }
    let Some(reason) = output
        .details
        .get("testCommandResolution")
        .filter(|resolution| {
            resolution.get("status").and_then(Value::as_str) == Some("unavailable")
        })
        .and_then(|resolution| resolution.get("reason"))
        .and_then(Value::as_str)
        .filter(|reason| reason.starts_with("managed-test-"))
    else {
        return false;
    };
    if crate::execution::validate_external_receipt_projection(
        provider_id,
        &output.details,
        output.complete,
    )
    .is_err()
    {
        return false;
    }
    let receipt = output.details.get("executionReceipt");
    let availability = output.details.get(super::availability::AVAILABILITY_DETAIL);
    availability
        .and_then(|detail| detail.get("state"))
        .and_then(Value::as_str)
        == Some("unavailable")
        && availability
            .and_then(|detail| detail.get("reason"))
            .and_then(Value::as_str)
            == Some(reason)
        && receipt
            .and_then(|value| value.get("kind"))
            .and_then(Value::as_str)
            == Some("external-tool-refusal-receipt")
        && receipt
            .and_then(|value| value.get("state"))
            .and_then(Value::as_str)
            == Some("missing_executable")
        && receipt
            .and_then(|value| value.get("complete"))
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .and_then(|value| value.pointer("/processTree/started"))
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .and_then(|value| value.pointer("/parser/attempted"))
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .and_then(|value| value.pointer("/parser/succeeded"))
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .and_then(|value| value.get("policy"))
            .is_some_and(Value::is_null)
        && receipt
            .and_then(|value| value.pointer("/executable/digestState"))
            .and_then(Value::as_str)
            == Some("not-checked")
        && receipt
            .and_then(|value| value.pointer("/executable/version/qualified"))
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .and_then(|value| value.get("stdout"))
            .is_some_and(Value::is_null)
        && receipt
            .and_then(|value| value.get("stderr"))
            .is_some_and(Value::is_null)
}

fn terminal_execution(
    input: &LegacyCheckInput,
    command: CommandShape,
    state: LegacyCheckProcessState,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    mut output: LegacyCheckOutput,
    gaps: Vec<String>,
    started: u64,
    parser_ok: bool,
    error: Option<&str>,
) -> LegacyCheckExecution {
    let completed = now_ms().max(started);
    let receipt_id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            format!(
                "{}:{}:{}",
                input.provider_id, input.inventory_digest, started
            )
            .as_bytes()
        ))
    );
    let receipt = execution_receipt(
        input,
        command,
        state,
        exit_code,
        &stdout,
        &stderr,
        started,
        completed,
        &gaps,
        parser_ok && error.is_none(),
        error,
    );
    output.details.insert("executionReceipt".into(), receipt);
    LegacyCheckExecution {
        state,
        exit_code,
        stdout,
        stderr,
        receipt_id: Some(receipt_id),
        output: Some(output),
        error: error.map(|message| LegacyCheckError {
            provider_id: input.provider_id.clone(),
            check: input.check.clone(),
            state,
            message: message.to_owned(),
        }),
    }
}

fn execution_receipt(
    input: &LegacyCheckInput,
    command: CommandShape,
    state: LegacyCheckProcessState,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    started: u64,
    completed: u64,
    gaps: &[String],
    parser_ok: bool,
    error: Option<&str>,
) -> Value {
    let (executable, args) = command_parts(command);
    let executable_path = format!("native://legion-audit/{}", input.check);
    let requested = if executable == "native" {
        executable_path
    } else {
        executable.to_owned()
    };
    let native = matches!(command, CommandShape::Native { .. });
    json!({
        "schemaVersion": 1,
        "kind": if native { "native-legacy-check-receipt" } else { "external-tool-refusal-receipt" },
        "receiptId": format!("native-receipt:{}:{}", input.provider_id, started),
        "requestId": format!("native-request:{}:{}", input.provider_id, input.inventory_generation),
        "providerId": input.provider_id,
        "planId": input.inventory_digest,
        "policyId": "native-legacy-check-v1",
        "policy": null,
        "taskId": input.check,
        "state": state.as_str(),
        "complete": state == LegacyCheckProcessState::Completed && gaps.is_empty(),
        // The frozen external-receipt validator reads a non-null executable
        // object as a real executable identity, so an unverified external tool
        // must carry an explicit unverified signature rather than null.
        "executable": {"requestedPath":requested,"canonicalPath":Value::Null,"digest":Value::Null,"digestState":"not-applicable","signature":if native { Value::Null } else { json!("unverified") },"version":{"args":args,"output":Value::Null,"exitCode":exit_code,"qualified":false}},
        "command": {"executable":executable,"args":args,"environmentNames":[],"redactedArgumentIndexes":[],"redactedEnvironmentNames":[]},
        "cwd": input.root.to_string_lossy(),
        "environmentNames": [],
        "sandbox": {"required":false,"networkEnabled":false,"receiptId":Value::Null},
        "processTree": {"started":false,"terminated":false,"hardKilled":false,"reaped":false,"detail":if native { "in-process Rust analysis; no external process" } else { "external capability unavailable; no process started" }},
        "timing": {"startedAtMs":started,"completedAtMs":completed,"durationMs":completed-started},
        "exitCode": exit_code,
        "signal": Value::Null,
        // No process started means no captured streams: the receipt must not
        // present an artifact object whose path is null, because the frozen
        // external-receipt validator reads a non-null object as a real capture.
        "stdout": if native { json!({"path":null,"digest":format!("sha256:{}",hex::encode(Sha256::digest(stdout))),"bytes":stdout.len(),"immutable":false}) } else { Value::Null },
        "stderr": if native { json!({"path":null,"digest":format!("sha256:{}",hex::encode(Sha256::digest(stderr))),"bytes":stderr.len(),"immutable":false}) } else { Value::Null },
        "parser": {"attempted":true,"succeeded":parser_ok,"error":error},
        "gaps":gaps,
    })
}

fn command_parts(command: CommandShape) -> (&'static str, Vec<String>) {
    match command {
        CommandShape::Native { .. } => ("native", Vec::new()),
        CommandShape::Fixed { executable, args }
        | CommandShape::Named {
            tool: executable,
            args,
        } => (
            executable,
            args.iter().map(|arg| (*arg).to_owned()).collect(),
        ),
    }
}

fn attach_test_command_source(execution: &mut LegacyCheckExecution, source: Option<&Value>) {
    let Some(source) = source else {
        return;
    };
    let Some(output) = execution.output.as_mut() else {
        return;
    };
    output
        .details
        .insert("testCommandSource".into(), source.clone());
    if let Some(receipt) = output
        .details
        .get_mut("executionReceipt")
        .and_then(Value::as_object_mut)
    {
        receipt.insert("testCommandSource".into(), source.clone());
    }
}

fn empty_output(gaps: Vec<String>) -> LegacyCheckOutput {
    LegacyCheckOutput {
        status: if gaps.is_empty() {
            ProviderStatus::Ok
        } else {
            ProviderStatus::Partial
        },
        complete: false,
        coverage: None,
        findings: Vec::new(),
        candidates: Vec::new(),
        coverage_gaps: gaps,
        degradation: Vec::new(),
        details: BTreeMap::new(),
    }
}

fn read_denominator(input: &LegacyCheckInput) -> (Vec<(InventoryEntry, String)>, Vec<String>) {
    let mut files = Vec::new();
    let mut gaps = Vec::new();
    const MAX_FILE_BYTES: u64 = 1_048_576;
    const MAX_TOTAL_BYTES: u64 = 33_554_432;
    let root = match std::fs::canonicalize(&input.root) {
        Ok(root) => root,
        Err(error) => return (files, vec![format!("source-root-unavailable:{error}")]),
    };
    let mut total = 0_u64;
    for entry in &input.denominator.entries {
        let read = (|| -> Result<String, String> {
            let relative = entry.path.replace('\\', "/");
            if relative.contains(':')
                || relative
                    .split('/')
                    .any(|part| matches!(part, "" | "." | ".."))
            {
                return Err("unsafe-source-path".into());
            }
            let mut path = root.clone();
            for part in relative.split('/') {
                path.push(part);
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|error| format!("source-unavailable:{error}"))?;
                if metadata.file_type().is_symlink() {
                    return Err("source-link-not-followed".into());
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err("source-reparse-point-not-followed".into());
                    }
                }
            }
            let resolved = std::fs::canonicalize(&path)
                .map_err(|error| format!("source-unavailable:{error}"))?;
            if !resolved.starts_with(&root) {
                return Err("source-escaped-root".into());
            }
            let file = std::fs::File::open(&path)
                .map_err(|error| format!("source-unavailable:{error}"))?;
            let metadata = file
                .metadata()
                .map_err(|error| format!("source-unavailable:{error}"))?;
            if !metadata.is_file() {
                return Err("source-not-regular-file".into());
            }
            if metadata.len() > MAX_FILE_BYTES {
                return Err("source-file-byte-limit".into());
            }
            let mut bytes = Vec::new();
            file.take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("source-unavailable:{error}"))?;
            if bytes.len() as u64 > MAX_FILE_BYTES {
                return Err("source-file-byte-limit".into());
            }
            if let Some(expected) = &entry.digest {
                let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
                if *expected != actual {
                    return Err("source-digest-drift".into());
                }
            }
            // Only text counts toward the source budget: binary assets
            // (images, fonts, models) are rejected here anyway, and letting
            // them consume the budget first starved real source files.
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) => {
                    // A binary asset is accounted as examined but contributes no
                    // text and no gap. Only a non-UTF-8 source file stays a gap.
                    if entry.source_file && !error.as_bytes().contains(&0) {
                        return Err(String::from("source-invalid-utf8"));
                    }
                    String::new()
                }
            };
            total = total.saturating_add(text.len() as u64);
            if total > MAX_TOTAL_BYTES {
                return Err("source-total-byte-limit".into());
            }
            Ok(text)
        })();
        match read {
            Ok(text) => files.push((entry.clone(), text)),
            Err(gap) => gaps.push(format!("{gap}:{}", entry.path)),
        }
    }
    (files, gaps)
}

fn native_apple(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        if contains_any(
            text,
            &["import UIKit", "import AppKit", "import SwiftUI", "@objc"],
        ) {
            push_candidate(
                output,
                "apple.platform-api",
                "medium",
                &entry.path,
                first_line(
                    text,
                    &["import UIKit", "import AppKit", "import SwiftUI", "@objc"],
                ),
                "Apple platform API usage requires platform-target confirmation.",
            );
        }
    }
}

/// Threshold resolution mirrors `decompositionReviewLoc()` in
/// `tools/audit/collect-facts.mjs`: `CORTEX_DECOMPOSITION_REVIEW_LOC` env var
/// first, then `.agent/config.json` `hygiene.decompositionReviewLoc`, else the
/// workspace default of 400. An invalid configured value is surfaced, never
/// silently dropped.
fn decomposition_review_loc(root: &std::path::Path) -> (u64, &'static str, Vec<String>) {
    let mut ignored = Vec::new();
    let valid = |n: i64| n >= 100;
    if let Ok(raw) = std::env::var("CORTEX_DECOMPOSITION_REVIEW_LOC") {
        if !raw.is_empty() {
            match raw.parse::<i64>() {
                Ok(n) if valid(n) => return (n as u64, "blueprint-config", ignored),
                _ => ignored.push(format!(
                    "CORTEX_DECOMPOSITION_REVIEW_LOC={raw}: must be an integer >= 100"
                )),
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(root.join(".agent").join("config.json")) {
        if let Ok(config) = serde_json::from_str::<Value>(&text) {
            if let Some(configured) = config
                .get("hygiene")
                .and_then(|h| h.get("decompositionReviewLoc"))
            {
                if let Some(n) = configured.as_i64() {
                    if valid(n) {
                        return (n as u64, ".agent/config.json", ignored);
                    }
                }
                ignored.push(format!(
                    ".agent/config.json hygiene.decompositionReviewLoc={configured}: must be an integer >= 100"
                ));
            }
        }
    }
    (400, "workspace-default", ignored)
}

/// A tracked code file's role, matching `classifyFile()` in collect-facts.mjs.
/// Conservative: only clearly-test and clearly-config classify as
/// non-runtime; anything ambiguous stays `runtime`.
fn classify_decomposition_file(path: &str) -> &'static str {
    let lower = format!("/{}", path.to_ascii_lowercase());
    let base = lower.rsplit('/').next().unwrap_or("");
    let test_dir = [
        "test",
        "tests",
        "spec",
        "specs",
        "__tests__",
        "__mocks__",
        "e2e",
        "fixture",
        "fixtures",
        "__fixtures__",
        "cypress",
        "playwright",
        ".storybook",
    ];
    if test_dir
        .iter()
        .any(|seg| lower.contains(&format!("/{seg}/")))
        || [".test.", ".spec.", ".stories.", ".bench.", ".e2e.", ".cy."]
            .iter()
            .any(|suffix| base.contains(suffix))
        || base.ends_with("_test.rs")
        || base.ends_with("_test.py")
        || base.ends_with("_test.go")
        || base.starts_with("test_") && base.ends_with(".py")
        || base == "conftest.py"
    {
        return "test";
    }
    if lower.contains("/.github/")
        || base.ends_with(".config.js")
        || base.ends_with(".config.ts")
        || base.ends_with(".config.mjs")
        || base.ends_with(".config.cjs")
        || base.ends_with(".setup.js")
        || base.ends_with(".teardown.js")
        || base == "dockerfile"
        || base == "makefile"
    {
        return "tooling";
    }
    "runtime"
}

const DECOMPOSITION_CODE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "rs", "java", "rb", "php", "c", "cc",
    "cpp", "h", "hpp", "cs", "swift", "kt", "scala", "sh", "sql",
];

fn is_decomposition_code_file(path: &str) -> bool {
    match path.rsplit('.').next() {
        Some(ext) => DECOMPOSITION_CODE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

fn is_generated_or_vendored(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.starts_with("vendor/")
        || p.starts_with("qwik/")
        || p.starts_with("dist/")
        || p.starts_with("src-tauri/gen/")
        || p.starts_with("src/generated/")
        || p.contains("/src/generated/")
        || p.contains("/drizzle/")
}

/// Native mirror of the `decomposition` check in collect-facts.mjs: size is a
/// deterministic REVIEW TRIGGER over the configured threshold (workspace
/// default 400 LOC), never proof that decomposition is needed, so review
/// candidates are emitted as adjudication-required candidates rather than
/// findings. Runtime/test/tooling classification and mechanical-split
/// detection (parts stitched under a `*_parts/`/`partNN` naming convention)
/// mirror the JS implementation's grouping logic.
fn native_decomposition(
    input: &LegacyCheckInput,
    files: &[(InventoryEntry, String)],
    output: &mut LegacyCheckOutput,
) {
    let (threshold, threshold_source, threshold_ignored) = decomposition_review_loc(&input.root);

    let mut loc_by_file: BTreeMap<&str, u64> = BTreeMap::new();
    let mut oversized: Vec<(&str, u64, &'static str)> = Vec::new();
    for (entry, text) in files {
        if !is_decomposition_code_file(&entry.path) || is_generated_or_vendored(&entry.path) {
            continue;
        }
        let loc = text.lines().count() as u64;
        loc_by_file.insert(entry.path.as_str(), loc);
        if loc > threshold {
            oversized.push((
                entry.path.as_str(),
                loc,
                classify_decomposition_file(&entry.path),
            ));
        }
    }
    oversized.sort_by(|a, b| b.1.cmp(&a.1));

    // Mechanical-split detection: group `*_parts/`-dir or `partNN.<ext>`-named
    // files by containing directory and reconstruct the logical-unit LOC.
    let mut groups: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (entry, _text) in files {
        if !is_decomposition_code_file(&entry.path) || is_generated_or_vendored(&entry.path) {
            continue;
        }
        let segs: Vec<&str> = entry.path.split(['\\', '/']).collect();
        if segs.len() < 2 {
            continue;
        }
        let base = segs[segs.len() - 1];
        let parent = segs[segs.len() - 2];
        let parent_lower = parent.to_ascii_lowercase();
        let is_parts_dir = parent_lower == "parts" || parent_lower.ends_with("_parts");
        let is_part_file = {
            let name = base.to_ascii_lowercase();
            name.starts_with("part")
                && name
                    .trim_start_matches("part")
                    .trim_start_matches(['.', '_', '-'])
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
        };
        if !is_parts_dir && !is_part_file {
            continue;
        }
        let dir = segs[..segs.len() - 1].join("/");
        groups.entry(dir).or_default().push(entry.path.as_str());
    }
    let mut mechanical_splits: Vec<(String, usize, u64, &'static str)> = Vec::new();
    for (dir, gfiles) in &groups {
        if gfiles.len() < 2 {
            continue;
        }
        let logical_loc: u64 = gfiles
            .iter()
            .map(|f| loc_by_file.get(f).copied().unwrap_or(0))
            .sum();
        if logical_loc <= threshold {
            continue;
        }
        let classes: Vec<&'static str> = gfiles
            .iter()
            .map(|f| classify_decomposition_file(f))
            .collect();
        let class = if classes.contains(&"runtime") {
            "runtime"
        } else if classes.contains(&"test") {
            "test"
        } else {
            "tooling"
        };
        mechanical_splits.push((dir.clone(), gfiles.len(), logical_loc, class));
    }
    mechanical_splits.sort_by(|a, b| b.2.cmp(&a.2));

    let runtime_count = oversized.iter().filter(|(_, _, c)| *c == "runtime").count()
        + mechanical_splits
            .iter()
            .filter(|(_, _, _, c)| *c == "runtime")
            .count();
    let test_count = oversized.iter().filter(|(_, _, c)| *c == "test").count()
        + mechanical_splits
            .iter()
            .filter(|(_, _, _, c)| *c == "test")
            .count();
    let tooling_count = oversized.iter().filter(|(_, _, c)| *c == "tooling").count()
        + mechanical_splits
            .iter()
            .filter(|(_, _, _, c)| *c == "tooling")
            .count();

    for (path, loc, class) in &oversized {
        push_candidate(
            output,
            "architecture.decomposition-review-trigger",
            if *class == "runtime" { "medium" } else { "low" },
            path,
            1,
            &format!(
                "{loc} LOC exceeds the {threshold} LOC review trigger ({class}); inspect responsibilities, state, callers, dependencies, and tests before treating this as decomposition debt."
            ),
        );
    }
    for (dir, parts, logical_loc, class) in &mechanical_splits {
        push_candidate(
            output,
            "architecture.decomposition-mechanical-split",
            if *class == "runtime" { "medium" } else { "low" },
            dir,
            1,
            &format!(
                "{parts} part files under {dir} reconstruct to {logical_loc} logical LOC ({class}), above the {threshold} LOC review trigger — possible mechanical split evading per-file review."
            ),
        );
    }

    output
        .details
        .insert("threshold".into(), Value::from(threshold));
    output.details.insert(
        "thresholdKind".into(),
        Value::String("review-trigger".into()),
    );
    output.details.insert(
        "thresholdSource".into(),
        Value::String(threshold_source.into()),
    );
    if !threshold_ignored.is_empty() {
        output.details.insert(
            "thresholdIgnored".into(),
            Value::Array(threshold_ignored.into_iter().map(Value::String).collect()),
        );
    }
    output.details.insert(
        "byClass".into(),
        json!({"runtime": runtime_count, "test": test_count, "tooling": tooling_count}),
    );
    output
        .details
        .insert("runtimeReviewCandidates".into(), Value::from(runtime_count));
}

fn native_negative_space(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        if text.trim().is_empty() {
            push_finding(
                output,
                "quality.empty-source-file",
                "warning",
                &entry.path,
                1,
                "denominator contains an empty source file",
            );
        }
    }
}

fn native_tool_coverage(
    _input: &LegacyCheckInput,
    files: &[(InventoryEntry, String)],
    output: &mut LegacyCheckOutput,
) {
    let paths = files
        .iter()
        .map(|(entry, _)| entry.path.clone())
        .collect::<Vec<_>>();
    let manifests = paths.iter().filter(|path| is_manifest(path)).count();
    output.details.insert("toolCoverage".into(), json!({"files":paths,"manifestCount":manifests,"sourceCount":files.iter().filter(|(entry, _)| entry.source_file).count()}));
}

fn native_react_hooks(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        if contains_any(text, &["import React", "from 'react'", "from \"react\""]) {
            for hook in [
                "useState(",
                "useEffect(",
                "useMemo(",
                "useCallback(",
                "useContext(",
            ] {
                for offset in occurrences(text, hook) {
                    let prefix = &text[..offset];
                    if prefix
                        .rfind("if (")
                        .is_some_and(|index| index > prefix.rfind('}').unwrap_or(0))
                    {
                        push_finding(
                            output,
                            "react.hooks.conditional-call",
                            "warning",
                            &entry.path,
                            line_at(text, offset),
                            "React hook appears in a conditional block",
                        );
                    }
                }
            }
        }
    }
}

/// Shell/PowerShell download syntax is evidence; a URL by itself is not.
fn download_asset(command: &str) -> Option<String> {
    static OUTPUT_PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    let output = OUTPUT_PATTERN.get_or_init(|| {
        regex::Regex::new(
            r#"(?:^|\s)(?:-o|-O|--output|--output-document|-OutFile)(?:=|\s+)['"]?([^\s'";|]+)"#,
        )
        .expect("download output pattern is valid")
    });
    output
        .captures(command)
        .map(|capture| capture[1].to_owned())
        .filter(|asset| !asset.starts_with("https://") && !asset.starts_with("http://"))
        .or_else(|| {
            // wget defaults to the URL basename; curl does so only with -O.
            if !command.contains("wget")
                && !command
                    .split_whitespace()
                    .any(|arg| arg == "-O" || arg == "--remote-name")
            {
                return None;
            }
            let url = command
                .split_whitespace()
                .find(|arg| arg.starts_with("https://") || arg.starts_with("http://"))?;
            let name = url
                .trim_matches(['\'', '"'])
                .split('?')
                .next()?
                .rsplit('/')
                .next()?;
            (!name.is_empty()).then(|| name.to_owned())
        })
}

fn executable_download(command: &str, following: &str) -> Option<Option<String>> {
    static DOWNLOADER_PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    static PIPED_PATTERN: OnceLock<regex::Regex> = OnceLock::new();

    let trimmed = command.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }
    let downloader = DOWNLOADER_PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(?:^|[;&|]|\brun:)\s*(?:sudo\s+)?(?:curl|wget|Invoke-WebRequest|iwr)\b",
        )
        .expect("downloader pattern is valid")
    });
    if !downloader.is_match(command) || !contains_any(command, &["https://", "http://"]) {
        return None;
    }
    let piped = PIPED_PATTERN
        .get_or_init(|| {
            regex::Regex::new(
                r"(?i)\|\s*(?:sudo\s+)?(?:sh|bash|zsh|pwsh|powershell|iex|Invoke-Expression)\b",
            )
            .expect("piped execution pattern is valid")
        })
        .is_match(command);
    let asset = download_asset(command);
    if piped {
        return Some(asset);
    }
    let asset = asset?;
    let basename = asset.rsplit('/').next().unwrap_or(&asset);
    // Require the downloaded path in the executable/install sink itself.
    let quoted = regex::escape(&asset);
    let base = regex::escape(basename);
    let combined = format!("{command}\n{following}");
    let sink = regex::Regex::new(&format!(r#"(?im)(?:^|[;\n&])\s*(?:sudo\s+)?(?:(?:sh|bash|zsh|pwsh|powershell|msiexec|installer|dpkg|rpm)\b[^\n;]*['"]?{quoted}(?:['"\s;]|$)|(?:\./|&\s*['"]?){base}(?:['"\s;]|$))"#)).ok()?;
    let installation = regex::Regex::new(&format!(
        r#"(?im)\b(?:install|chmod)\s+[^\n;]*['"]?{quoted}(?:['"\s;]|$)"#
    ))
    .ok()?;
    (sink.is_match(&combined) || installation.is_match(&combined)).then_some(Some(asset))
}

fn bound_integrity(asset: Option<&str>, command: &str, following: &str, preceding: &str) -> bool {
    let Some(asset) = asset else {
        return false;
    }; // A pipe executes before later verification.
       // A literal immutable checksum must name this exact downloaded asset.
       // Mentions of integrity, an unrelated SHA, or a URL's @ do not bind it.
    let asset = regex::escape(asset);
    let checksum = regex::Regex::new(&format!(
        r#"(?im)^\s*(?:echo|printf)\s+['"][0-9a-f]{{64}}[ \t]+\*?{asset}['"][^\n]*\|\s*(?:sha256sum\s+(?:-c|--check)|shasum\s+-a\s+256\s+-c)\b"#
    ));
    let Ok(checksum) = checksum else {
        return false;
    };
    let all = format!("{command}\n{following}");
    let Some(verification) = checksum.find(&all) else {
        return false;
    };
    let verification_tail = all[verification.end()..]
        .split('\n')
        .next()
        .unwrap_or_default();
    let failure_exits = regex::Regex::new(r"^\s*(?:-\s*)?\|\|\s*(?:exit|return)\b")
        .is_ok_and(|pattern| pattern.is_match(verification_tail));
    let errexit = preceding
        .lines()
        .rev()
        .find_map(|line| {
            let line = line.trim();
            if line.starts_with("set +e") {
                Some(false)
            } else if line.starts_with("set -")
                && line
                    .split_whitespace()
                    .nth(1)
                    .is_some_and(|flags| flags.contains('e'))
            {
                Some(true)
            } else {
                None
            }
        })
        .unwrap_or(false)
        && !verification_tail.contains("||");
    // Verification after execution offers no protection. Fail closed where
    // ordering cannot establish a bound integrity check before the sink.
    let execution = regex::Regex::new(&format!(r#"(?im)(?:^|[;\n&])\s*(?:sudo\s+)?(?:sh|bash|zsh|pwsh|powershell|msiexec|installer|dpkg|rpm|install|chmod)\b[^\n;]*{asset}(?:['"\s;]|$)|(?:^|[;\n&])\s*\./{asset}(?:['"\s;]|$)"#)).ok();
    execution
        .and_then(|pattern| pattern.find(&all))
        .is_some_and(|sink| {
            if verification.end() > sink.start() {
                return false;
            }
            let bound_chain = regex::Regex::new(r"^\s*(?:-\s*)?&&\s*$")
                .is_ok_and(|pattern| pattern.is_match(&all[verification.end()..sink.start()]));
            failure_exits || errexit || bound_chain
        })
}

fn native_binary_pins(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, text) in files {
        let lines = text.lines().collect::<Vec<_>>();
        for (index, command) in lines.iter().enumerate() {
            let following = lines
                .iter()
                .skip(index + 1)
                .take(20)
                .copied()
                .collect::<Vec<_>>()
                .join("\n");
            let Some(asset) = executable_download(command, &following) else {
                continue;
            };
            let preceding = lines[..index].join("\n");
            if !bound_integrity(asset.as_deref(), command, &following, &preceding) {
                push_candidate(output, "security.binary-unpinned", "high", &entry.path, index + 1,
                    "Executable download reaches an install or execution sink without a bound immutable digest.");
                if let Some(candidate) = output.candidates.last_mut() {
                    candidate["applicability"] = json!({"status":"applicable","sink":"executable-download","asset":asset,"integrity":"unbound-or-unknown"});
                }
            }
        }
    }
}

fn native_dependency_pinning(
    input: &LegacyCheckInput,
    files: &[(InventoryEntry, String)],
    output: &mut LegacyCheckOutput,
) {
    let paths = input
        .denominator
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    for (entry, text) in files {
        let lockfiles: &[&str] = match entry.path.rsplit('/').next() {
            Some("package.json") => &["package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
            Some("Cargo.toml") => &["Cargo.lock"],
            _ => continue,
        };
        let mut directory = entry.path.rsplit_once('/').map_or("", |(parent, _)| parent);
        // Only sibling or ancestor locks in the frozen scope can cover a manifest.
        let has_lockfile = loop {
            if lockfiles.iter().any(|name| {
                let lock = if directory.is_empty() {
                    (*name).to_owned()
                } else {
                    format!("{directory}/{name}")
                };
                paths.contains(lock.as_str())
            }) {
                break true;
            }
            if directory.is_empty() {
                break false;
            }
            directory = directory.rsplit_once('/').map_or("", |(parent, _)| parent);
        };
        if !has_lockfile {
            push_candidate(
                output,
                "security.dependency-unpinned",
                "medium",
                &entry.path,
                first_nonempty_line(text),
                "manifest has no corresponding lockfile in the frozen repository",
            );
        }
    }
}

fn native_vendored(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    for (entry, _text) in files {
        if entry.path.split('/').any(|part| {
            matches!(
                part.to_ascii_lowercase().as_str(),
                "vendor" | "vendored" | "third_party" | "third-party"
            )
        }) {
            push_candidate(
                output,
                "security.vendored-manifest",
                "low",
                &entry.path,
                1,
                "vendored dependency material is present in the frozen scope",
            );
        }
    }
}

fn native_tauri_capabilities(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    let mut has_config = false;
    let mut frontend = BTreeSet::new();
    let mut backend = BTreeSet::new();
    for (entry, text) in files {
        if entry.path.ends_with("tauri.conf.json")
            || entry.path.ends_with("tauri.conf.json5")
            || entry.path.ends_with("Tauri.toml")
        {
            has_config = true;
        }
        if contains_any(
            text,
            &[
                "shell:allow-execute",
                "shell:allow-spawn",
                "fs:allow-write",
                "fs:allow-remove",
            ],
        ) && !contains_any(text, &["windows", "webviews", "platforms"])
        {
            push_candidate(
                output,
                "tauri.broad-capability",
                "medium",
                &entry.path,
                1,
                "powerful Tauri capability is not visibly platform or window scoped",
            );
        }
        for command in quoted_invocations(text, "invoke(") {
            frontend.insert(command);
        }
        for command in annotated_rust_functions(text) {
            backend.insert(command);
        }
    }
    if !has_config {
        push_candidate(
            output,
            "tauri.config-missing",
            "high",
            "src-tauri",
            1,
            "Tauri source is present but no supported configuration file is visible",
        );
    }
    for command in frontend.difference(&backend) {
        push_candidate(
            output,
            "tauri.unregistered-command",
            "high",
            "src-tauri",
            1,
            &format!("frontend invokes {command} without a matching Tauri command"),
        );
    }
}

fn native_contract_mirror(files: &[(InventoryEntry, String)], output: &mut LegacyCheckOutput) {
    let mut frontend = BTreeSet::new();
    let mut backend = BTreeSet::new();
    for (entry, text) in files {
        for command in quoted_invocations(text, "invoke(") {
            frontend.insert(command);
        }
        for command in annotated_rust_functions(text) {
            backend.insert(command);
        }
        if entry.path.ends_with("tauri.conf.json") && text.contains("allow-all") {
            push_candidate(
                output,
                "tauri.contract-broad-permission",
                "medium",
                &entry.path,
                1,
                "Tauri configuration contains a broad permission marker",
            );
        }
    }
    for command in frontend.difference(&backend) {
        push_candidate(
            output,
            "tauri.contract-missing",
            "high",
            "src-tauri",
            1,
            &format!("frontend contract has no backend command: {command}"),
        );
    }
}

/// Fold a per-tool `parsers::ParseOutcome` into `LegacyCheckOutput`, using
/// the same finding/evidence shape as `push_finding` elsewhere in this file.
/// Malformed output is coverage-gapped rather than silently treated as a
/// clean zero-finding scan — same rule the frozen `secrets` handling already
/// applies below.
fn apply_parse_outcome(
    input: &LegacyCheckInput,
    outcome: parsers::ParseOutcome,
    output: &mut LegacyCheckOutput,
) -> bool {
    output.details.insert(
        "findingsCount".into(),
        outcome
            .findings_count
            .map(|count| json!(count))
            .unwrap_or(Value::Null),
    );
    for (key, value) in outcome.meta {
        output.details.insert(key.into(), value);
    }
    if outcome.malformed {
        output
            .coverage_gaps
            .push(format!("legacy-tool-output-unparseable:{}", input.check));
        output.complete = false;
        return true;
    }
    if let Some(count) = outcome.findings_count {
        if count > 0 {
            let path = input
                .denominator
                .entries
                .first()
                .map(|entry| entry.path.as_str())
                .unwrap_or("provider-artifacts");
            let claim = format!("{} reported {} finding(s)", input.check, count);
            // A candidate-generator carries unadjudicated claims in
            // `details.candidates`; only deterministic checks emit findings.
            if is_candidate_provider(input.provider_id.as_str()) {
                push_candidate(output, outcome.rule, outcome.severity, path, 1, &claim);
            } else {
                push_finding(output, outcome.rule, outcome.severity, path, 1, &claim);
            }
        }
    }
    output.complete = true;
    true
}

fn parse_external_value(
    input: &LegacyCheckInput,
    value: &Value,
    output: &mut LegacyCheckOutput,
) -> bool {
    if input.check == "py_deps_cve"
        && python_requirements::reconcile(&input.artifacts[python_requirements::KEY], value)
            .is_none()
    {
        output.complete = false;
        output.details.insert("findingsCount".into(), Value::Null);
        output
            .coverage_gaps
            .push("python-requirements-response-incomplete".into());
        return true;
    }
    if input.check == "sast" {
        return semgrep::parse(input, value, output);
    }
    if let Some(outcome) = parsers::dispatch_json(input.check.as_str(), value) {
        return apply_parse_outcome(input, outcome, output);
    }
    // gitleaks writes `[]` for a clean scan; some versions write `null`. Both
    // are a complete, empty report rather than an unparseable one.
    if input.check == "secrets" && (value.is_array() || value.is_null()) {
        let items = value.as_array().map(Vec::as_slice).unwrap_or(&[]);
        let mut redacted = Vec::with_capacity(items.len());
        for item in items {
            let rule = item.get("RuleID").and_then(Value::as_str);
            let file = item.get("File").and_then(Value::as_str);
            let line = item.get("StartLine").and_then(Value::as_u64);
            let digest = item
                .get("Fingerprint")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    format!(
                        "sha256:{}",
                        hex::encode(Sha256::digest(
                            format!(
                                "{}\0{}\0{}",
                                rule.unwrap_or_default(),
                                file.unwrap_or_default(),
                                line.map(|value| value.to_string()).unwrap_or_default()
                            )
                            .as_bytes()
                        ))
                    )
                });
            redacted.push(json!({
                "digest": digest,
                "rule": rule,
                "file": file,
                "line": line,
            }));
        }
        output.candidates.extend(redacted.iter().cloned());
        output
            .details
            .insert("secretCandidates".into(), Value::Array(redacted));
        output.complete = true;
        return true;
    }
    let object = match value.as_object() {
        Some(value) => value,
        None => return false,
    };
    let Some(complete) = object.get("complete").and_then(Value::as_bool) else {
        output
            .coverage_gaps
            .push("external-output-envelope-invalid".into());
        output.complete = false;
        return true;
    };
    output.details.insert("toolOutput".into(), value.clone());
    if let Some(gaps) = object.get("coverageGaps").and_then(Value::as_array) {
        output.coverage_gaps.extend(gaps.iter().map(|gap| {
            gap.as_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| gap.to_string())
        }));
    }
    if let Some(findings) = object.get("findings").and_then(Value::as_array) {
        for finding in findings {
            add_external_finding(input, finding, output);
        }
    }
    if let Some(candidates) = object.get("candidates").and_then(Value::as_array) {
        output.candidates.extend(candidates.iter().cloned());
    }
    output.complete = complete;
    if object.get("status").and_then(Value::as_str) == Some("error") {
        output.complete = false;
    }
    true
}

fn parse_text_output(
    input: &LegacyCheckInput,
    bytes: &[u8],
    output: &mut LegacyCheckOutput,
) -> bool {
    let text = String::from_utf8_lossy(bytes);
    if let Some(outcome) = parsers::dispatch_text(input.check.as_str(), text.as_ref()) {
        return apply_parse_outcome(input, outcome, output);
    }
    let mut parsed = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        parsed = true;
        let (path, line_number) = parse_tool_location(line, input.denominator.entries.first());
        if input.check == "repo" {
            output
                .details
                .insert("repositoryStatus".into(), Value::String(line.into()));
        } else if is_candidate_provider(input.provider_id.as_str()) {
            push_candidate(
                output,
                "legacy.tool-output",
                "medium",
                &path,
                line_number,
                line,
            );
        } else {
            let finding = finding_ref(input, "legacy.tool-output", &path, line_number, "warning");
            output.findings.push(finding.clone());
            add_evidence(
                output,
                input,
                &finding,
                &safe_location(input, &path),
                line_number,
                line,
            );
        }
    }
    output.complete = parsed || bytes.is_empty();
    parsed || bytes.is_empty()
}

fn add_external_finding(input: &LegacyCheckInput, value: &Value, output: &mut LegacyCheckOutput) {
    if is_candidate_provider(&input.provider_id) {
        output.candidates.push(value.clone());
        return;
    }
    let path = value
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            input
                .denominator
                .entries
                .first()
                .map(|entry| entry.path.as_str())
                .unwrap_or("provider-artifacts")
        });
    let line = value.get("line").and_then(Value::as_u64).unwrap_or(1) as usize;
    let rule = value
        .get("ruleId")
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("legacy.tool-finding");
    let severity = value
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("warning");
    let finding = finding_ref(input, rule, path, line, severity);
    output.findings.push(finding.clone());
    add_evidence(
        output,
        input,
        &finding,
        &safe_location(input, path),
        line,
        &value.to_string(),
    );
}

fn add_evidence(
    output: &mut LegacyCheckOutput,
    input: &LegacyCheckInput,
    finding: &FindingRef,
    path: &str,
    line: usize,
    raw: &str,
) {
    let id = finding.id.to_string();
    let evidence = output
        .details
        .entry("findingEvidence".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(items) = evidence {
        items.insert(
            id.clone(),
            json!({"provider":input.provider_id,"path":path,"line":line,"detail":raw}),
        );
    }
    let locations = output
        .details
        .entry("findingLocations".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(items) = locations {
        items.insert(id, json!([format!("{path}:{line}")]));
    }
}

fn finding_ref(
    input: &LegacyCheckInput,
    rule: &str,
    path: &str,
    line: usize,
    severity: &str,
) -> FindingRef {
    let id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            format!("{}\0{}\0{}\0{}", input.provider_id, rule, path, line).as_bytes()
        ))
    );
    FindingRef {
        id: FindingId::new(id).expect("derived finding id is valid"),
        severity: severity.into(),
    }
}

fn push_finding(
    output: &mut LegacyCheckOutput,
    rule: &str,
    severity: &str,
    path: &str,
    line: usize,
    message: &str,
) {
    let id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(format!("{rule}\0{path}\0{line}").as_bytes()))
    );
    let finding = FindingRef {
        id: FindingId::new(id).expect("derived finding id is valid"),
        severity: severity.into(),
    };
    let finding_id = finding.id.to_string();
    output.findings.push(finding);
    output
        .details
        .entry("findingEvidence".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(Value::Object(items)) = output.details.get_mut("findingEvidence") {
        items.insert(
            finding_id.clone(),
            json!({"ruleId":rule,"path":path,"line":line,"message":message}),
        );
    }
    output
        .details
        .entry("findingLocations".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(Value::Object(items)) = output.details.get_mut("findingLocations") {
        items.insert(finding_id, json!([format!("{path}:{line}")]));
    }
}

fn push_candidate(
    output: &mut LegacyCheckOutput,
    rule: &str,
    severity: &str,
    path: &str,
    line: usize,
    claim: &str,
) {
    let id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(format!("{rule}\0{path}\0{line}").as_bytes()))
    );
    output.candidates.push(json!({"id":id,"ruleId":rule,"role":"candidate-generator","claim":claim,"severityHint":severity,"evidence":[{"file":path,"line":line}],"evidenceStrength":"candidate","verdict":"UNADJUDICATED","adjudicationRequired":true}));
}

fn safe_location(input: &LegacyCheckInput, path: &str) -> String {
    input
        .denominator
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.path.clone())
        .or_else(|| {
            input
                .denominator
                .entries
                .first()
                .map(|entry| entry.path.clone())
        })
        .unwrap_or_else(|| "provider-artifacts".into())
}

fn parse_tool_location(line: &str, fallback: Option<&InventoryEntry>) -> (String, usize) {
    if let Some((path, rest)) = line.split_once(':') {
        if let Some((number, _)) = rest.split_once(':') {
            if let Ok(line_number) = number.parse::<usize>() {
                return (path.to_owned(), line_number);
            }
        }
    }
    (
        fallback
            .map(|entry| entry.path.clone())
            .unwrap_or_else(|| "provider-artifacts".into()),
        1,
    )
}

fn is_candidate_provider(provider: &str) -> bool {
    spec(provider).is_some_and(|contract| contract.role.contains("candidate"))
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn occurrences(text: &str, needle: &str) -> Vec<usize> {
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(index) = text[offset..].find(needle) {
        let absolute = offset + index;
        result.push(absolute);
        offset = absolute + needle.len();
        if offset >= text.len() {
            break;
        }
    }
    result
}

fn first_line(text: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .filter_map(|needle| text.find(needle).map(|index| line_at(text, index)))
        .min()
        .unwrap_or(1)
}
fn first_nonempty_line(text: &str) -> usize {
    text.lines()
        .position(|line| !line.trim().is_empty())
        .map(|line| line + 1)
        .unwrap_or(1)
}
fn line_at(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
fn is_manifest(path: &str) -> bool {
    matches!(
        path.rsplit('/').next(),
        Some(
            "package.json"
                | "Cargo.toml"
                | "pyproject.toml"
                | "go.mod"
                | "pom.xml"
                | "composer.json"
        )
    )
}

fn quoted_invocations(text: &str, marker: &str) -> Vec<String> {
    occurrences(text, marker)
        .into_iter()
        .filter_map(|offset| {
            let remainder = &text[offset + marker.len()..];
            let quote = remainder.chars().next()?;
            if quote != '\'' && quote != '"' {
                return None;
            }
            let value = remainder[1..].split(quote).next()?.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect()
}

fn annotated_rust_functions(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for offset in occurrences(text, "#[tauri::command]") {
        if let Some(function) = text[offset..].find("fn ") {
            let rest = &text[offset + function + 3..];
            let name = rest
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .next()
                .unwrap_or_default();
            if !name.is_empty() {
                names.push(name.to_owned());
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    #[test]
    fn license_checker_probe_and_error_classification_preserve_fail_closed_contract() {
        assert_eq!(super::legacy_version_probe_flag("js_licenses"), "--help");
        assert_eq!(super::legacy_version_probe_flag("docker"), "--version");
        assert!(super::license_checker_reported_error(
            "js_licenses",
            b"Found error\nError: No packages found\n"
        ));
        assert!(super::license_checker_reported_error(
            "js_licenses",
            b"Found error\r\n"
        ));
        assert!(!super::license_checker_reported_error(
            "docker",
            b"Found error\n"
        ));
        assert!(!super::license_checker_reported_error(
            "js_licenses",
            b"Not Found error\n"
        ));
        assert!(!super::license_checker_reported_error("js_licenses", b""));
    }

    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn provider(id: &str, selector: Value) -> AuditProvider {
        let contract = spec(id).expect("frozen provider");
        AuditProvider {
            id: id.into(),
            version: "2.0.0".into(),
            role: contract.role.into(),
            phase: contract.phase.into(),
            lens_ids: Vec::new(),
            dependencies: Vec::new(),
            kind: crate::plan::ProviderKind::TypedExternalProjectTool,
            configuration: BTreeMap::from([
                ("selector".into(), selector),
                (
                    "runner".into(),
                    json!({"kind":"legacy-check","check":contract.check}),
                ),
            ]),
            bounds: BTreeMap::new(),
            clean_claim: "evidence-only".into(),
            benchmark_status: "unproven".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: false,
        }
    }

    fn temp_root() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("legion-native-legacy-{suffix}"));
        fs::create_dir_all(root.join("src-tauri")).unwrap();
        root
    }

    #[test]
    fn native_provider_emits_real_candidate_and_frozen_denominator() {
        let root = temp_root();
        fs::write(
            root.join("src-tauri/frontend.ts"),
            "invoke('missing_command');",
        )
        .unwrap();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "generation",
            vec![InventoryEntry {
                path: "src-tauri/frontend.ts".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            }],
        )
        .unwrap();
        let selected = inventory
            .denominator_entries(&json!({"op":"anyPath","patterns":["src-tauri/**"]}))
            .unwrap();
        let provider = provider(
            "legacy.tauri.contract-mirror",
            json!({"op":"anyPath","patterns":["src-tauri/**"]}),
        );
        let result = NativeLegacyCheckExecutor::new(&root)
            .execute(&provider, &inventory)
            .unwrap();
        assert_eq!(result.provider.to_string(), provider.id);
        assert_eq!(
            result.coverage.as_ref().unwrap().denominator_digest,
            selected.digest
        );
        assert!(result.complete);
        assert!(!result
            .details
            .get("candidates")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_external_tool_is_an_incomplete_typed_result() {
        let root = temp_root();
        fs::write(root.join("package.json"), "{}").unwrap();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "generation",
            vec![InventoryEntry {
                path: "package.json".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: false,
                digest: None,
            }],
        )
        .unwrap();
        let provider = provider(
            "legacy.quality.build",
            json!({"op":"anyPath","patterns":["**/package.json"]}),
        );
        let result = NativeLegacyCheckExecutor::new(&root)
            .execute(&provider, &inventory)
            .unwrap();
        assert!(!result.complete);
        assert!(result
            .details
            .get("processState")
            .and_then(Value::as_str)
            .is_some());
        assert!(result.coverage.as_ref().unwrap().expected > 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_managed_refusal_receipts_are_not_projected_as_unavailable() {
        let root = temp_root();
        fs::write(root.join("package.json"), "{}\n").unwrap();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "generation",
            vec![InventoryEntry {
                path: "package.json".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: false,
                digest: None,
            }],
        )
        .unwrap();
        let provider = provider("legacy.quality.test", json!({"op":"always"}));
        let dispatcher = LegacyCheckDispatcher;
        let input = dispatcher
            .input(&provider, &inventory, &root, None, None, &Value::Null)
            .unwrap();

        for malformed in ["missing-schema-version", "missing-receipt"] {
            let mut execution = unavailable_test_refusal(
                &input,
                "managed-test-trust-not-configured",
                json!({"assurance":"attested-runs-required"}),
            );
            let output = execution.output.as_mut().unwrap();
            if malformed == "missing-schema-version" {
                output
                    .details
                    .get_mut("executionReceipt")
                    .and_then(Value::as_object_mut)
                    .unwrap()
                    .remove("schemaVersion");
            } else {
                output.details.remove("executionReceipt");
            }

            let result = dispatcher
                .project_result(&provider, &input, execution)
                .unwrap();
            assert_eq!(result.status, ProviderStatus::Failed);
            assert!(!result
                .coverage_gaps
                .iter()
                .any(|gap| gap == "unavailable:managed-test-trust-not-configured"));
            assert!(!result
                .details
                .contains_key(crate::native_providers::availability::AVAILABILITY_DETAIL));
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_backed_report_points_the_tool_at_the_temp_dir() {
        assert_eq!(
            report_args(Path::new("report-dir")),
            vec!["--output".to_string(), "report-dir".to_string()]
        );
        assert!(matches!(
            report_source_for("duplication"),
            ReportSource::File(_)
        ));
        assert_eq!(report_source_for("secrets"), ReportSource::Stdout);
    }

    #[test]
    fn jscpd_report_is_read_from_flat_or_nested_layout() {
        for relative in ["jscpd-report.json", "_jscpd/jscpd-report.json"] {
            let root = temp_root();
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"{}").unwrap();
            let artifact = read_report_artifact(&root, report_source_for("duplication"))
                .expect("report found");
            assert_eq!(artifact.name, relative);
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn gitleaks_null_report_is_a_complete_empty_scan() {
        let root = temp_root();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "generation",
            vec![InventoryEntry {
                path: "app.js".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            }],
        )
        .unwrap();
        let provider = provider("legacy.security.secrets", json!({"op":"always"}));
        let input = LegacyCheckDispatcher::new()
            .input(
                &provider,
                &inventory,
                root.clone(),
                None,
                None,
                &Value::Null,
            )
            .unwrap();
        let mut output = empty_output(Vec::new());
        assert!(parse_external_value(&input, &Value::Null, &mut output));
        assert!(output.complete);
        assert!(output.candidates.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn unique_fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "legion-scratch-fixture-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn listing(root: &Path) -> Vec<String> {
        fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                out.push(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
                if path.is_dir() {
                    walk(&path, root, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    #[test]
    fn legacy_check_execution_leaves_the_audited_tree_unchanged() {
        let root = unique_fixture();
        fs::write(root.join("package.json"), "{}").unwrap();
        let inventory = InventoryEnvelope::new(
            "fixture",
            "generation",
            vec![InventoryEntry {
                path: "package.json".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: false,
                digest: None,
            }],
        )
        .unwrap();
        let provider = provider(
            "legacy.quality.build",
            json!({"op":"anyPath","patterns":["**/package.json"]}),
        );
        let before = listing(&root);
        let _ = NativeLegacyCheckExecutor::new(&root)
            .execute(&provider, &inventory)
            .unwrap();
        assert_eq!(listing(&root), before);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scratch_lives_outside_the_audited_root_and_is_removed_on_drop() {
        let root = unique_fixture();
        let scratch = AuditScratch::create(&root).unwrap();
        let scratch_root = scratch.root().to_path_buf();
        assert!(!path_inside(&scratch_root, &root));
        for dir in [scratch.sandbox_dir(), scratch.artifacts_dir()] {
            assert!(dir.is_dir());
        }
        let (environment, allowlist) = audit_environment(&scratch);
        for name in [
            "TMPDIR",
            "TEMP",
            "TMP",
            "XDG_CACHE_HOME",
            "CARGO_TARGET_DIR",
        ] {
            assert!(allowlist.contains(name));
            assert!(Path::new(&environment[name]).starts_with(&scratch_root));
        }
        assert!(audit_artifact_request_id("audit:x").starts_with("legion-audit/"));
        drop(scratch);
        assert!(!scratch_root.exists());
        assert!(AuditScratch::with_scratch_dir(&root, root.join("inner")).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn successful_sibling_cannot_clear_unverified_request_retention() {
        let root = unique_fixture();
        let scratch = AuditScratch::create(&root).unwrap();
        let scratch_root = scratch.root().to_path_buf();
        scratch.begin_attested_request();
        scratch.begin_attested_request();
        scratch.retain_after_drop();
        scratch.finish_attested_request();
        drop(scratch);
        assert!(scratch_root.exists());
        let _ = fs::remove_dir_all(scratch_root);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn every_frozen_legacy_id_is_dispatchable() {
        let dispatcher = LegacyCheckDispatcher::new();
        assert_eq!(specs().len(), 33);
        for contract in specs() {
            assert!(dispatcher.contains(contract.provider_id));
        }
    }
}

fn command_name(command: CommandShape) -> &'static str {
    match command {
        CommandShape::Native { .. } => "native",
        CommandShape::Fixed { .. } => "fixed",
        CommandShape::Named { .. } => "named",
    }
}

#[cfg(test)]
mod binary_integrity_tests {
    use super::*;

    fn candidates(path: &str, source: &str) -> Vec<Value> {
        let entry = serde_json::from_value(json!({"path":path,"sourceFile":true})).unwrap();
        let mut output = LegacyCheckOutput::default();
        native_binary_pins(&[(entry, source.into())], &mut output);
        output.candidates
    }

    #[test]
    fn executable_download_requires_bound_asset_integrity_before_execution() {
        let hash = "a".repeat(64);
        let download = "curl -fsSL https://example.invalid/tool -o tool";
        for source in [
            format!("{download}\nchmod +x tool\n./tool\n"),
            format!("{download}\necho '{hash} other-tool' | sha256sum -c -\n./tool\n"),
            format!("{download}\necho '{hash} tool' | sha256sum -c -\n./tool\n"),
            format!("{download}\n./tool\necho '{hash} tool' | sha256sum -c -\n"),
            "curl -fsSL https://example.invalid/@latest/install.sh | sh\n".into(),
        ] {
            let rows = candidates("tests/fixtures/install.sh", &source);
            assert_eq!(rows.len(), 1, "{source}");
            assert_eq!(rows[0]["ruleId"], "security.binary-unpinned");
            assert_eq!(rows[0]["severityHint"], "high");
        }
        let verified = format!("set -e\n{download}\necho '{hash} tool' | sha256sum -c -\n./tool\n");
        assert!(candidates("install.sh", &verified).is_empty());
    }

    #[test]
    fn ordinary_urls_documentation_images_and_comment_mentions_are_not_binaries() {
        for (path, source) in [
            (
                "README.md",
                "Documentation: https://example.invalid/guide\n",
            ),
            (
                "src/view.ts",
                "const image = 'https://example.invalid/logo.png';\n",
            ),
            (
                "notes/install.sh",
                "# curl https://example.invalid/install.sh | sh\n",
            ),
            (
                "fetch.sh",
                "curl https://example.invalid/readme.txt -o readme.txt\ncat readme.txt\n",
            ),
            (
                "fetch.sh",
                "curl https://example.invalid/image.png -o image.png\n",
            ),
            (
                "notes.ts",
                "console.log('curl https://example.invalid/install.sh | sh');\n",
            ),
        ] {
            assert!(candidates(path, source).is_empty(), "{source}");
        }
    }
}
