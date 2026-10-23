//! Containment bridge for an external trusted process owner.
//!
//! This module is *not* a second launcher or broker. It is a thin
//! `PlatformProcess` adapter that (1) refuses any launch that does not match a
//! frozen `ContainmentProfile`, for the version probe and the main command
//! alike, (2) delegates the actual spawn, confinement and child-tree
//! termination to a `ContainedRuntime` supplied by the trusted owner, and
//! (3) refuses to let an owner's report claim a clean result that contradicts
//! its own lifecycle evidence. It never fabricates a `ProcessOutput`: with no
//! runtime there is no `OwnerProcess`.
//!
//! Admission (who may run what) lives in `legion-audit::owner_admission`; OS
//! containment lives here and in the owner; tool integrity is the executor's
//! digest check; attestation is a separate signed receipt. None implies another.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{
    error::EffectError,
    platform::{PlatformProcess, ProcessFuture, ProcessLaunch, ProcessOutput},
    request::SandboxReceipt,
};

/// What the invocation is allowed to do to the audited project.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InvocationClass {
    /// Reads the frozen input only. Network denied, project read-only.
    ReadOnlyStatic,
    /// Executes target-project code. Network denied, project read-only, scratch writable.
    ProjectExecuting,
    /// Reads the frozen input and may reach a metadata/advisory endpoint. Project read-only.
    NetworkMetadata,
}

impl InvocationClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnlyStatic => "read-only-static",
            Self::ProjectExecuting => "project-executing",
            Self::NetworkMetadata => "network-metadata",
        }
    }
    pub fn network_allowed(self) -> bool {
        matches!(self, Self::NetworkMetadata)
    }
}

/// Frozen containment contract the owner must enforce for one invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainmentProfile {
    pub owner_id: String,
    /// Identifier recorded in receipts as the sandbox/containment id.
    pub containment_id: String,
    pub class: InvocationClass,
    /// Frozen input roots; mounted read-only.
    pub read_only_roots: Vec<PathBuf>,
    /// The only writable location. Must not be inside a read-only root.
    pub scratch_root: PathBuf,
    /// Exact canonical executables that may launch (target and version probe).
    pub allowed_executables: BTreeSet<PathBuf>,
    /// Environment names the child may receive; values are scrubbed to these.
    pub environment_names: BTreeSet<String>,
    pub max_timeout_ms: u64,
    pub max_stdout: usize,
    pub max_stderr: usize,
}

impl ContainmentProfile {
    pub fn validate(&self) -> Result<(), EffectError> {
        let bad =
            |detail: &str| EffectError::SandboxMissing(format!("containment profile: {detail}"));
        if self.owner_id.trim().is_empty() || self.containment_id.trim().is_empty() {
            return Err(bad("owner and containment ids are required"));
        }
        if self.read_only_roots.is_empty()
            || self.read_only_roots.iter().any(|root| !root.is_absolute())
        {
            return Err(bad("read-only roots must be absolute and non-empty"));
        }
        if !self.scratch_root.is_absolute() || self.scratch_root.parent().is_none() {
            return Err(bad(
                "scratch root must be absolute and not a filesystem root",
            ));
        }
        if self
            .read_only_roots
            .iter()
            .any(|root| self.scratch_root.starts_with(root) || root.starts_with(&self.scratch_root))
        {
            return Err(bad("scratch root must be disjoint from read-only roots"));
        }
        if self.allowed_executables.is_empty()
            || self
                .allowed_executables
                .iter()
                .any(|path| !path.is_absolute())
        {
            return Err(bad("allowed executables must be absolute and non-empty"));
        }
        if self.max_timeout_ms == 0 || self.max_stdout == 0 || self.max_stderr == 0 {
            return Err(bad("limits must be positive"));
        }
        Ok(())
    }

    /// Receipt value recorded on the request. `network: true` follows the
    /// existing `SandboxReceipt` convention: an owner-enforced network policy
    /// exists for this run. It does not mean network access is enabled; see
    /// `InvocationClass::network_allowed`.
    pub fn sandbox_receipt(&self) -> SandboxReceipt {
        SandboxReceipt {
            id: self.containment_id.clone(),
            network: true,
            filesystem_scope: self
                .read_only_roots
                .first()
                .map(|root| root.to_string_lossy().into_owned()),
        }
    }
}

/// Implemented only by a trusted owner's adapter (for example the pinned
/// rightkit-sandbox owner). Must confine, bound output, and terminate and reap
/// the whole child tree on timeout/cancel/limit. It receives the profile it
/// must enforce; it must not widen it.
pub trait ContainedRuntime: Send + Sync {
    fn owner_id(&self) -> &str;
    fn run_contained<'a>(
        &'a self,
        launch: ProcessLaunch,
        profile: &'a ContainmentProfile,
    ) -> ProcessFuture<'a>;
}

/// `PlatformProcess` that only ever runs through a trusted contained runtime.
pub struct OwnerProcess<R> {
    runtime: R,
    profile: ContainmentProfile,
}

impl<R: ContainedRuntime> OwnerProcess<R> {
    /// Fails closed when the profile is malformed or names a different owner.
    pub fn new(runtime: R, profile: ContainmentProfile) -> Result<Self, EffectError> {
        profile.validate()?;
        if runtime.owner_id() != profile.owner_id {
            return Err(EffectError::SandboxMissing(
                "containment profile owner does not match runtime owner".into(),
            ));
        }
        Ok(Self { runtime, profile })
    }
    pub fn profile(&self) -> &ContainmentProfile {
        &self.profile
    }
}

impl<R: ContainedRuntime> PlatformProcess for OwnerProcess<R> {
    fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a> {
        Box::pin(async move {
            check_launch(&self.profile, &launch)?;
            let output = self
                .runtime
                .run_contained(launch.clone(), &self.profile)
                .await?;
            Ok(distrust_output(output, &launch))
        })
    }
}

fn unauthorized(detail: impl Into<String>) -> EffectError {
    EffectError::UnauthorizedEffect(format!("owner launch refused: {}", detail.into()))
}

/// Runs before any owner call, for version probes and target launches alike.
fn check_launch(profile: &ContainmentProfile, launch: &ProcessLaunch) -> Result<(), EffectError> {
    let executable = Path::new(&launch.executable);
    if !executable.is_absolute() {
        return Err(unauthorized("executable is not absolute"));
    }
    let canonical = std::fs::canonicalize(executable)
        .map_err(|error| EffectError::MissingExecutable(error.to_string()))?;
    if canonical != executable || !profile.allowed_executables.contains(&canonical) {
        return Err(unauthorized(
            "executable is not the admitted canonical path",
        ));
    }
    let cwd = std::fs::canonicalize(&launch.cwd)
        .map_err(|error| unauthorized(format!("cwd unresolved: {error}")))?;
    if !profile
        .read_only_roots
        .iter()
        .chain(std::iter::once(&profile.scratch_root))
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .any(|root| cwd.starts_with(root))
    {
        return Err(unauthorized("cwd escapes admitted roots"));
    }
    if launch.args.iter().any(|arg| arg.contains('\0')) {
        return Err(unauthorized("argument contains NUL"));
    }
    if let Some(name) = launch.environment.keys().find(|name| {
        !profile.environment_names.contains(*name) || name.is_empty() || name.contains(['=', '\0'])
    }) {
        return Err(unauthorized(format!(
            "environment name {name:?} is not admitted"
        )));
    }
    if launch
        .environment
        .values()
        .any(|value| value.contains('\0'))
    {
        return Err(unauthorized("environment value contains NUL"));
    }
    if launch.timeout_ms == 0
        || launch.timeout_ms > profile.max_timeout_ms
        || launch.stdout_limit == 0
        || launch.stdout_limit > profile.max_stdout
        || launch.stderr_limit == 0
        || launch.stderr_limit > profile.max_stderr
    {
        return Err(unauthorized("resource limits exceed admitted bounds"));
    }
    Ok(())
}

/// Owner reports are evidence, not truth. Contradictions downgrade to failure
/// states the executor already maps; nothing is ever upgraded to success.
fn distrust_output(mut output: ProcessOutput, launch: &ProcessLaunch) -> ProcessOutput {
    if output.stdout.len() > launch.stdout_limit || output.stderr.len() > launch.stderr_limit {
        output.output_limited = true;
    }
    let interrupted = output.timed_out || output.cancelled || output.output_limited;
    let tree = &output.process_tree;
    let tree_closed = tree.started && tree.terminated && tree.reaped;
    let reported_exit = output.exit_code.is_some() || output.signal.is_some();
    if (interrupted && !tree_closed) || (reported_exit && !tree.started) {
        // Survivor or unprovable lifecycle: executor maps this to KillFailed.
        output.kill_succeeded = false;
        output.process_tree.detail.get_or_insert_with(|| {
            "owner lifecycle evidence is incomplete; child tree not proven reaped".into()
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::ProcessTreeEvidence;
    use tokio_util::sync::CancellationToken;

    fn launch(executable: &str, cwd: &str) -> ProcessLaunch {
        ProcessLaunch {
            executable: executable.into(),
            args: vec![],
            cwd: cwd.into(),
            environment: Default::default(),
            stdout_limit: 10,
            stderr_limit: 10,
            timeout_ms: 1_000,
            termination_grace_ms: 10,
            cancellation: CancellationToken::new(),
        }
    }
    fn output(tree: ProcessTreeEvidence) -> ProcessOutput {
        ProcessOutput {
            stdout: vec![],
            stderr: vec![],
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            cancelled: false,
            output_limited: false,
            kill_succeeded: true,
            process_tree: tree,
            started_at_ms: 1,
            completed_at_ms: 2,
        }
    }
    fn tree(started: bool, terminated: bool, reaped: bool) -> ProcessTreeEvidence {
        ProcessTreeEvidence {
            started,
            terminated,
            hard_killed: false,
            reaped,
            detail: None,
        }
    }

    #[test]
    fn survivor_after_timeout_is_never_reported_as_killed() {
        let mut out = output(tree(true, false, false));
        out.timed_out = true;
        out.exit_code = None;
        let out = distrust_output(out, &launch("/bin/x", "/"));
        assert!(!out.kill_succeeded);
    }

    #[test]
    fn exit_without_started_tree_is_not_trusted() {
        let out = distrust_output(output(tree(false, true, true)), &launch("/bin/x", "/"));
        assert!(!out.kill_succeeded);
    }

    #[test]
    fn oversize_owner_output_becomes_output_limited() {
        let mut out = output(tree(true, true, true));
        out.stdout = vec![0; 11];
        let out = distrust_output(out, &launch("/bin/x", "/"));
        assert!(out.output_limited);
    }

    #[test]
    fn clean_closed_tree_is_unchanged() {
        let out = distrust_output(output(tree(true, true, true)), &launch("/bin/x", "/"));
        assert!(out.kill_succeeded && !out.output_limited);
    }

    #[test]
    fn profile_rejects_scratch_inside_read_only_root() {
        let profile = ContainmentProfile {
            owner_id: "o".into(),
            containment_id: "c".into(),
            class: InvocationClass::ReadOnlyStatic,
            read_only_roots: vec!["/frozen".into()],
            scratch_root: "/frozen/scratch".into(),
            allowed_executables: ["/bin/x".into()].into_iter().collect(),
            environment_names: Default::default(),
            max_timeout_ms: 1,
            max_stdout: 1,
            max_stderr: 1,
        };
        assert!(profile.validate().is_err());
    }
}
