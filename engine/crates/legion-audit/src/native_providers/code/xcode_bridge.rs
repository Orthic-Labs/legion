//! `OwnedXcodeBridge`: the host-owned Apple bridge for `code.apple.targets`.
//!
//! Runs only `xcodebuild build|test` (signing disabled, destination exactly
//! from the obligation, result bundle and derived data inside the owner output
//! root) and `xcrun xcresulttool get test-results summary`, both as
//! owner-admitted requests through an [`ExternalProjectTool`] built over the
//! host-policy owner (`HostPolicyOwner` + contained runtime). Each executable
//! must be pinned for this provider in the host policy as `project-executing`;
//! the executor verifies the bytes against that pin before launch.
//!
//! The result is *host-executed* evidence: a [`HostExecutionReceipt`] built from
//! the owner's own execution receipts (state, executable digest, containment
//! id, process-tree reaping, stdout digest), never from tool claims or an
//! imported attestation. Its digest is the owner receipt digest the evidence is
//! bound to; `discharge_via_bridge` re-verifies it independently.
//!
//! Nothing here runs unless the code adapter was given an owner-backed bridge
//! (adapter-scoped injection; there is no process-global bridge). Without one
//! the provider keeps the unconfigured gap and the obligation stays unmet.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use legion_effects::owner_process::InvocationClass;
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::xcode_targets::{
    destination_string, parse_xcresult_summary, validate_xcodebuild_argv, xcodebuild_argv,
    AppleBridgeResult, AppleOperation, AppleOperationRequest, AppleTargetBridge, Gap,
    HostExecutedEvidence, HostExecutionReceipt, OwnerRunRef, EVIDENCE_BASIS_HOST_EXECUTED,
    PROVIDER_ID, ROLE_TEST_SUMMARY, ROLE_XCRESULT,
};
use crate::artifact_evidence::{ArtifactBinding, EvidenceOutcome};
use crate::execution_policy::OWNER_POLICY_ID;
use crate::host_owner::{OwnerRequestContext, OWNER_ID};

pub const DEFAULT_XCODEBUILD: &str = "/usr/bin/xcodebuild";
pub const DEFAULT_XCRUN: &str = "/usr/bin/xcrun";
const BUILD_TIMEOUT_MS: u64 = 25 * 60 * 1000;
const SUMMARY_TIMEOUT_MS: u64 = 2 * 60 * 1000;
const BUILD_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const SUMMARY_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 50_000;
const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn gap(code: &str, detail: impl Into<String>) -> Gap {
    Gap {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub struct OwnedXcodeBridge {
    tool: Arc<dyn ExternalProjectTool>,
    owner: Arc<OwnerRequestContext>,
    plan_id: String,
    frozen_root: PathBuf,
    output_root: PathBuf,
    /// Root of the executor's artifact sink (stdout/stderr records are
    /// relative to it).
    artifacts_root: PathBuf,
    xcodebuild: PathBuf,
    xcrun: PathBuf,
    cancellation: CancellationToken,
}

impl OwnedXcodeBridge {
    /// `tool` must be the owner-backed executor (`EffectExecutor` over the host
    /// owner's contained process and authorizer); `owner` is the request
    /// context of that same owner. `output_root` is the owner scratch root: it
    /// is the only writable location of the contained run.
    pub fn new(
        tool: Arc<dyn ExternalProjectTool>,
        owner: Arc<OwnerRequestContext>,
        plan_id: impl Into<String>,
        frozen_root: &Path,
        output_root: &Path,
        artifacts_root: &Path,
    ) -> Result<Self, Gap> {
        let canon = |path: &Path, what: &str| {
            std::fs::canonicalize(path)
                .map_err(|error| gap("apple-bridge-root-unavailable", format!("{what}: {error}")))
        };
        let plan_id = plan_id.into();
        if plan_id.trim().is_empty() {
            return Err(gap("apple-bridge-plan-missing", "frozen plan id required"));
        }
        Ok(Self {
            tool,
            owner,
            plan_id,
            frozen_root: canon(frozen_root, "frozen root")?,
            output_root: canon(output_root, "output root")?,
            artifacts_root: canon(artifacts_root, "artifacts root")?,
            xcodebuild: PathBuf::from(DEFAULT_XCODEBUILD),
            xcrun: PathBuf::from(DEFAULT_XCRUN),
            cancellation: CancellationToken::new(),
        })
    }

    /// Select a specific Xcode's `xcodebuild`. Only `/usr/bin/xcodebuild` or a
    /// `Contents/Developer/usr/bin/xcodebuild` inside an `.app` bundle is
    /// accepted; the host policy must still pin it by digest.
    pub fn with_xcodebuild(mut self, path: impl Into<PathBuf>) -> Result<Self, Gap> {
        let path = path.into();
        let shaped = path.is_absolute()
            && (path == Path::new(DEFAULT_XCODEBUILD)
                || (path.file_name().is_some_and(|n| n == "xcodebuild")
                    && path.ends_with("Contents/Developer/usr/bin/xcodebuild")
                    && path
                        .components()
                        .any(|c| c.as_os_str().to_string_lossy().ends_with(".app"))));
        if !shaped {
            return Err(gap(
                "xcodebuild-path-not-admitted",
                path.to_string_lossy().into_owned(),
            ));
        }
        self.xcodebuild = path;
        Ok(self)
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation = token;
        self
    }

    fn pin(&self, executable: &Path) -> Result<crate::host_owner::ToolPin, Gap> {
        match self.owner.pin_for(PROVIDER_ID, executable) {
            Some(pin) if pin.class == InvocationClass::ProjectExecuting => Ok(pin.clone()),
            Some(_) => Err(gap(
                "owner-policy-class-mismatch",
                format!("{} must be pinned project-executing", executable.display()),
            )),
            None => Err(gap(
                "owner-policy-missing-tool",
                format!("{} is not pinned for {PROVIDER_ID}", executable.display()),
            )),
        }
    }

    fn container_path(&self, container: &str) -> Result<PathBuf, Gap> {
        let relative = Path::new(container);
        if container.is_empty()
            || relative.is_absolute()
            || !relative
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
        {
            return Err(gap("container-path-unsafe", container));
        }
        let full = std::fs::canonicalize(self.frozen_root.join(relative))
            .map_err(|_| gap("container-missing", container))?;
        if !full.starts_with(&self.frozen_root) {
            return Err(gap("container-path-unsafe", container));
        }
        Ok(full)
    }

    fn environment(
        &self,
        pin: &crate::host_owner::ToolPin,
    ) -> (BTreeMap<String, String>, std::collections::BTreeSet<String>) {
        let mut environment = BTreeMap::new();
        for name in &pin.environment_names {
            let value = match name.as_str() {
                "HOME" => Some(self.output_root.join("home")),
                "TMPDIR" => Some(self.output_root.join("tmp")),
                "PATH" | "DEVELOPER_DIR" | "LANG" => std::env::var_os(name).map(PathBuf::from),
                _ => None,
            };
            if let Some(value) = value {
                if matches!(name.as_str(), "HOME" | "TMPDIR") {
                    let _ = std::fs::create_dir_all(&value);
                }
                environment.insert(name.clone(), value.to_string_lossy().into_owned());
            }
        }
        let allowlist = environment.keys().cloned().collect();
        (environment, allowlist)
    }

    #[allow(clippy::too_many_arguments)]
    fn owner_request(
        &self,
        pin: &crate::host_owner::ToolPin,
        label: &str,
        run_id: &str,
        args: Vec<String>,
        timeout_ms: u64,
        stdout_limit: usize,
    ) -> ExternalToolRequest {
        let (environment, environment_allowlist) = self.environment(pin);
        ExternalToolRequest {
            request_id: format!("audit:{PROVIDER_ID}:{}:{run_id}:{label}", self.plan_id),
            provider_id: PROVIDER_ID.into(),
            plan_id: self.plan_id.clone(),
            policy_id: OWNER_POLICY_ID.into(),
            task_id: Some(label.into()),
            executable: pin.executable.to_string_lossy().into_owned(),
            args,
            cwd: self.frozen_root.to_string_lossy().into_owned(),
            expected_digest: Some(pin.digest.clone()),
            skip_version_probe: true,
            // xcodebuild exits 65 on test/build failure; that is evidence
            // (outcome failed), not an execution fault.
            accepted_exit_codes: [0, 65].into_iter().collect(),
            environment,
            environment_allowlist,
            requires_network_sandbox: true,
            sandbox: Some(self.owner.sandbox_receipt()),
            timeout_ms,
            stdout_limit,
            stderr_limit: BUILD_OUTPUT_LIMIT,
            ..ExternalToolRequest::default()
        }
    }

    fn run(&self, request: ExternalToolRequest) -> Result<ExecutionReceipt, Gap> {
        let tool = self.tool.clone();
        let token = self.cancellation.clone();
        block_on(async move { tool.execute(request, token).await }).ok_or_else(|| {
            gap(
                "apple-bridge-runtime-unavailable",
                "no runtime for owner run",
            )
        })
    }

    fn read_stdout(&self, receipt: &ExecutionReceipt) -> Result<Vec<u8>, Gap> {
        let record = receipt
            .stdout
            .as_ref()
            .ok_or_else(|| gap("owner-stdout-missing", "no stdout artifact record"))?;
        let path = Path::new(&record.path);
        if path.is_absolute() || !path.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(gap("owner-stdout-path-unsafe", record.path.clone()));
        }
        let bytes = std::fs::read(self.artifacts_root.join(path))
            .map_err(|error| gap("owner-stdout-unreadable", error.to_string()))?;
        if sha256_bytes(&bytes) != record.digest {
            return Err(gap(
                "owner-stdout-digest-mismatch",
                "retained stdout differs from the owner receipt",
            ));
        }
        Ok(bytes)
    }

    fn manifest(&self, bundle: &Path) -> Result<Vec<u8>, Gap> {
        let mut files = BTreeMap::new();
        let mut total = 0u64;
        let mut stack = vec![bundle.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .map_err(|error| gap("xcresult-unreadable", error.to_string()))?;
            for entry in entries {
                let entry = entry.map_err(|error| gap("xcresult-unreadable", error.to_string()))?;
                let meta = std::fs::symlink_metadata(entry.path())
                    .map_err(|error| gap("xcresult-unreadable", error.to_string()))?;
                if meta.file_type().is_symlink() {
                    return Err(gap("xcresult-symlink", entry.path().display().to_string()));
                }
                if meta.is_dir() {
                    stack.push(entry.path());
                } else if meta.is_file() {
                    total += meta.len();
                    if files.len() >= MAX_BUNDLE_FILES || total > MAX_BUNDLE_BYTES {
                        return Err(gap("xcresult-too-large", "bundle exceeds retention bound"));
                    }
                    let bytes = std::fs::read(entry.path())
                        .map_err(|error| gap("xcresult-unreadable", error.to_string()))?;
                    let relative = entry
                        .path()
                        .strip_prefix(bundle)
                        .map(|p| p.to_string_lossy().into_owned())
                        .map_err(|_| gap("xcresult-unreadable", "path escapes bundle"))?;
                    files.insert(
                        relative,
                        json!({"digest": sha256_bytes(&bytes), "bytes": bytes.len()}),
                    );
                }
            }
        }
        if files.is_empty() {
            return Err(gap("xcresult-empty", "result bundle has no files"));
        }
        serde_json::to_vec(&json!({"bundle": "xcresult", "files": files}))
            .map_err(|error| gap("xcresult-unreadable", error.to_string()))
    }
}

fn run_ref(receipt: &ExecutionReceipt, args: &[String]) -> OwnerRunRef {
    OwnerRunRef {
        receipt_id: receipt.receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        executable: receipt
            .executable
            .as_ref()
            .and_then(|e| e.canonical_path.as_ref())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        executable_digest: receipt
            .executable
            .as_ref()
            .and_then(|e| e.digest.clone())
            .unwrap_or_default(),
        argv_digest: crate::integrity::digest(&args).unwrap_or_default(),
        state: format!("{:?}", receipt.state),
        exit_code: receipt.exit_code,
        stdout_digest: receipt.stdout.as_ref().map(|a| a.digest.clone()),
        stderr_digest: receipt.stderr.as_ref().map(|a| a.digest.clone()),
        sandbox_id: receipt.sandbox.receipt_id.clone(),
        started_at_ms: receipt.timing.started_at_ms,
        completed_at_ms: receipt.timing.completed_at_ms,
        tree_reaped: receipt.process_tree.started
            && receipt.process_tree.terminated
            && receipt.process_tree.reaped,
    }
}

fn completed_or_gap(receipt: &ExecutionReceipt, what: &str) -> Result<(), Gap> {
    let reaped = receipt.process_tree.started
        && receipt.process_tree.terminated
        && receipt.process_tree.reaped;
    if receipt.state == ExecutionState::Completed && receipt.complete && reaped {
        return Ok(());
    }
    Err(gap(
        &format!("{what}-not-completed:{:?}", receipt.state),
        receipt.gaps.join("; "),
    ))
}

pub(super) fn block_on<F>(future: F) -> Option<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    // A dedicated thread keeps this safe when the caller already runs inside a
    // tokio runtime (block_on there would panic).
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()
                    .map(|runtime| runtime.block_on(future))
            })
            .join()
            .ok()
            .flatten()
    })
}

impl AppleTargetBridge for OwnedXcodeBridge {
    fn bridge_id(&self) -> &str {
        "owned-xcode-bridge"
    }

    fn host_binding(&self) -> Option<(String, String)> {
        let pin = self.pin(&self.xcodebuild.clone()).ok()?;
        Some((pin.version, pin.digest))
    }

    fn execute(&self, request: &AppleOperationRequest) -> Result<AppleBridgeResult, Gap> {
        // Static refusal first: nothing is admitted for an unrepresentable
        // destination or a request that does not disable signing.
        destination_string(&request.destination)?;
        let container = self.container_path(&request.container)?;
        let xcodebuild_pin = self.pin(&self.xcodebuild.clone())?;
        let xcrun_pin = self.pin(&self.xcrun.clone())?;
        self.owner
            .plan()
            .bind(&self.plan_id)
            .map_err(|error| gap("owner-plan-binding-conflict", error))?;

        let run_id = format!(
            "{}-{}",
            &sha256_bytes(
                format!("{}|{}", request.expected_target, request.expected_variant).as_bytes()
            )[7..23],
            RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let run_dir = self.output_root.join("xcode").join(&run_id);
        std::fs::create_dir_all(&run_dir)
            .map_err(|error| gap("apple-bridge-output-unavailable", error.to_string()))?;
        let bundle = run_dir.join("result.xcresult");
        let derived = run_dir.join("DerivedData");
        let args = xcodebuild_argv(request, &container, &bundle, &derived)?;
        validate_xcodebuild_argv(request, &args, &self.output_root)?;

        let build_receipt = self.run(self.owner_request(
            &xcodebuild_pin,
            "xcodebuild",
            &run_id,
            args.clone(),
            BUILD_TIMEOUT_MS,
            BUILD_OUTPUT_LIMIT,
        ))?;
        completed_or_gap(&build_receipt, "xcodebuild")?;
        let build_exit = build_receipt.exit_code;
        if !bundle.is_dir() {
            return Err(gap(
                "xcresult-missing",
                "xcodebuild produced no result bundle",
            ));
        }
        let manifest = self.manifest(&bundle)?;
        let mut raw_artifacts = BTreeMap::new();
        let mut artifacts = Vec::new();
        let manifest_path = format!("results/{run_id}.xcresult.manifest.json");
        artifacts.push(ArtifactBinding {
            path: manifest_path.clone(),
            digest: sha256_bytes(&manifest),
            bytes: manifest.len() as u64,
            role: ROLE_XCRESULT.into(),
        });
        raw_artifacts.insert(manifest_path, manifest);

        let mut outcome = if build_exit == Some(0) {
            EvidenceOutcome::Passed
        } else {
            EvidenceOutcome::Failed
        };
        let mut summary_run = None;
        if request.operation == AppleOperation::Test {
            let summary_args: Vec<String> =
                ["xcresulttool", "get", "test-results", "summary", "--path"]
                    .into_iter()
                    .map(String::from)
                    .chain([
                        bundle.to_string_lossy().into_owned(),
                        "--format".into(),
                        "json".into(),
                    ])
                    .collect();
            let receipt = self.run(self.owner_request(
                &xcrun_pin,
                "xcresulttool",
                &run_id,
                summary_args.clone(),
                SUMMARY_TIMEOUT_MS,
                SUMMARY_OUTPUT_LIMIT,
            ))?;
            completed_or_gap(&receipt, "xcresulttool")?;
            if receipt.exit_code != Some(0) {
                return Err(gap(
                    "xcresulttool-failed",
                    format!("exit {:?}", receipt.exit_code),
                ));
            }
            let bytes = self.read_stdout(&receipt)?;
            let summary = parse_xcresult_summary(&bytes)
                .map_err(|error| gap("xcresult-summary-unparseable", error))?;
            if build_exit != Some(0)
                || summary.total_tests == 0
                || summary.failed_tests > 0
                || !summary.result.eq_ignore_ascii_case("passed")
            {
                outcome = EvidenceOutcome::Failed;
            }
            let summary_path = format!("results/{run_id}.summary.json");
            artifacts.push(ArtifactBinding {
                path: summary_path.clone(),
                digest: sha256_bytes(&bytes),
                bytes: bytes.len() as u64,
                role: ROLE_TEST_SUMMARY.into(),
            });
            raw_artifacts.insert(summary_path, bytes);
            summary_run = Some(run_ref(&receipt, &summary_args));
        }

        let receipt = HostExecutionReceipt {
            schema_version: 1,
            basis: EVIDENCE_BASIS_HOST_EXECUTED.into(),
            owner_id: OWNER_ID.into(),
            plan_id: self.plan_id.clone(),
            operation: request.operation,
            target: request.expected_target.clone(),
            variant: request.expected_variant.clone(),
            toolchain: super::xcode_targets::toolchain_label(
                &xcodebuild_pin.version,
                &request.destination,
            ),
            output_root: self.output_root.to_string_lossy().into_owned(),
            args: args.clone(),
            build_run: run_ref(&build_receipt, &args),
            summary_run,
            artifacts,
            outcome,
        };
        let receipt_digest = receipt
            .digest()
            .map_err(|error| gap("host-receipt-digest-unavailable", error.to_string()))?;
        Ok(AppleBridgeResult::HostExecuted(HostExecutedEvidence {
            receipt,
            receipt_digest,
            raw_artifacts,
        }))
    }
}
