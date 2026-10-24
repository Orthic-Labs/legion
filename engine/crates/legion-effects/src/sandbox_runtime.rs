//! `ContainedRuntime` backed by the pinned RightKit sandbox (`rightkit-sandbox` 0.6.1).
//!
//! macOS: Seatbelt (`sandbox_init` in the forked child before exec). Linux:
//! Landlock + seccomp. Windows: AppContainer inside a kill-on-close Job Object.
//! This type only adapts a frozen [`ContainmentProfile`] to a `SandboxPolicy`
//! and maps the outcome to the executor's existing lifecycle evidence; it never
//! widens the profile and never reports a result when confinement could not be
//! applied (`SandboxError::Unsupported`/`InvalidPolicy` -> `SandboxMissing`).
//!
//! Policy mapping:
//! * reads: `read_only_roots`, the admitted executable, and host `toolchain_roots`
//!   (read + exec). `ProjectExecuting` may also execute from the read-only roots.
//! * writes: exactly `scratch_root`.
//! * network: denied unless both the profile class and the executable's own class
//!   (`with_executable_classes`, which can only narrow) allow it.
//! * environment: cleared; only the launch's already allow-listed variables are set
//!   (parent environment is never inherited, `keep` is empty).
//! * limits: wall-clock timeout, per-stream byte cap and cancellation each kill and
//!   reap the whole child tree; the tree's reap result feeds `ProcessTreeEvidence`.
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rightkit_sandbox::{
    EnvPolicy, NetworkPolicy, ResourceAuthority, ResourceProfile, Sandbox, SandboxCommand,
    SandboxError, SandboxPolicy,
};

use crate::{
    error::EffectError,
    owner_process::{ContainedRuntime, ContainmentProfile, InvocationClass},
    platform::{ProcessFuture, ProcessLaunch, ProcessOutput},
    receipt::ProcessTreeEvidence,
};

/// Gap reported when the OS backend cannot deny executing interpreter binaries.
pub const GAP_INTERPRETER_EXEC: &str = "sandbox-cannot-deny-interpreter-exec";
/// Gap reported when the OS backend cannot deny Unix-domain socket connects.
pub const GAP_UNIX_SOCKETS: &str = "sandbox-cannot-deny-unix-sockets";

/// Interpreter/package-runner basenames denied under `no-node-python`.
/// Enforced as absolute `deny_read` globs (`/**/<name>`), which on macOS also
/// blocks exec of the image. Name-based, so it is a second layer behind the
/// primary control: no exec grant on audited roots.
pub const DENIED_INTERPRETER_NAMES: &[&str] = &[
    "node",
    "nodejs",
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "yarn",
    "yarnpkg",
    "bun",
    "bunx",
    "deno",
    "corepack",
    "python",
    "python2",
    "python2.*",
    "python3",
    "python3.*",
    "pythonw",
    "Python",
    "Python3",
    "pip",
    "pip3",
    "pip3.*",
    "pipx",
    "uv",
    "uvx",
];

/// Execution hardening applied on top of the frozen containment profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecHardening {
    /// `no-node-python`: no exec from audited roots, interpreter binaries
    /// denied, Unix-domain sockets unavailable to project-executing tools.
    pub deny_interpreters: bool,
}

/// What the hardening enforces on this host; recorded beside the containment
/// receipt so a receipt never claims more than the sandbox applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcedExecPolicy {
    pub audited_root_exec_granted: bool,
    pub interpreter_exec_denied: bool,
    pub denied_interpreter_names: Vec<String>,
    /// `allowed` | `unavailable-for-project-executing` (launch refused).
    pub unix_sockets: &'static str,
    pub gaps: Vec<&'static str>,
}

impl EnforcedExecPolicy {
    pub fn summary(&self) -> String {
        format!(
            "audited-root-exec={};interpreter-exec-denied={};unix-sockets={};gaps=[{}]",
            self.audited_root_exec_granted,
            self.interpreter_exec_denied,
            self.unix_sockets,
            self.gaps.join(",")
        )
    }
}

impl ExecHardening {
    pub fn enforced(self) -> EnforcedExecPolicy {
        if !self.deny_interpreters {
            return EnforcedExecPolicy {
                audited_root_exec_granted: true,
                interpreter_exec_denied: false,
                denied_interpreter_names: Vec::new(),
                unix_sockets: "allowed",
                gaps: Vec::new(),
            };
        }
        // RightKit (bogusyogi/rightkit#943): deny_read globs are NOT an exec
        // block. Interpreter exec is therefore never claimed as denied; only
        // the launched executable is checked (owner admission), and
        // project-executing launches stay refused below.
        let deny = false;
        let mut gaps = vec![GAP_INTERPRETER_EXEC];
        // rightkit-sandbox 0.6.1 always allows connect to any Unix socket when
        // the network is denied on macOS; there is no deny knob.
        gaps.push(GAP_UNIX_SOCKETS);
        EnforcedExecPolicy {
            audited_root_exec_granted: false,
            interpreter_exec_denied: deny,
            denied_interpreter_names: if deny {
                DENIED_INTERPRETER_NAMES
                    .iter()
                    .map(|n| n.to_string())
                    .collect()
            } else {
                Vec::new()
            },
            unix_sockets: "unavailable-for-project-executing",
            gaps,
        }
    }
}

/// Fixed search path for contained launches: the executable's directory and
/// system directories only (never inherited, never repository-relative).
fn trusted_search_path(executable: &str) -> String {
    let mut dirs: Vec<PathBuf> = Path::new(executable)
        .parent()
        .filter(|dir| dir.is_absolute())
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    if cfg!(windows) {
        if let Some(root) = std::env::var_os("SystemRoot") {
            let root = PathBuf::from(root);
            dirs.push(root.join("System32"));
            dirs.push(root);
        }
    } else {
        for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
            dirs.push(PathBuf::from(dir));
        }
    }
    std::env::join_paths(dirs)
        .map(|joined| joined.to_string_lossy().into_owned())
        .unwrap_or_default()
}

const POLL: Duration = Duration::from_millis(5);
const READER_DRAIN_GRACE: Duration = Duration::from_millis(1_000);

/// Effective uid of this process (Unix). Used by owners to check file ownership.
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() as u32 }
}

/// `O_NOFOLLOW` open flag (Unix), for owners that open trusted files.
#[cfg(unix)]
pub fn o_nofollow() -> i32 {
    libc::O_NOFOLLOW as i32
}

struct Inner {
    owner_id: String,
    sandbox: Sandbox,
    toolchain_roots: Vec<PathBuf>,
    executable_classes: BTreeMap<PathBuf, InvocationClass>,
    hardening: ExecHardening,
}

#[derive(Clone)]
pub struct RightKitSandboxRuntime {
    inner: Arc<Inner>,
}

impl RightKitSandboxRuntime {
    /// Fails closed when this host has no confinement backend.
    pub fn new(owner_id: impl Into<String>) -> Result<Self, EffectError> {
        Self::availability()?;
        let owner_id = owner_id.into();
        if owner_id.trim().is_empty() {
            return Err(EffectError::SandboxMissing("owner id is required".into()));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                owner_id,
                sandbox: Sandbox::new(ResourceAuthority::new(ResourceProfile::Expanded)),
                toolchain_roots: Vec::new(),
                executable_classes: BTreeMap::new(),
                hardening: ExecHardening::default(),
            }),
        })
    }

    /// Whether this host can apply OS confinement at all.
    pub fn availability() -> Result<(), EffectError> {
        #[cfg(any(target_os = "macos", windows))]
        {
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            if rightkit_sandbox::is_landlock_available() {
                Ok(())
            } else {
                Err(EffectError::SandboxMissing(
                    "Landlock is unavailable on this kernel".into(),
                ))
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            Err(EffectError::SandboxMissing(
                "no confinement backend on this platform".into(),
            ))
        }
    }

    /// Extra read+exec roots (interpreters/JDKs) frozen by the host owner.
    pub fn with_toolchain_roots(mut self, roots: Vec<PathBuf>) -> Result<Self, EffectError> {
        if roots.iter().any(|root| !root.is_absolute()) {
            return Err(EffectError::SandboxMissing(
                "toolchain roots must be absolute".into(),
            ));
        }
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| EffectError::Internal("runtime already shared".into()))?;
        inner.toolchain_roots = roots;
        Ok(self)
    }

    /// Apply `no-node-python` execution hardening (see [`ExecHardening`]).
    pub fn with_exec_hardening(mut self, hardening: ExecHardening) -> Result<Self, EffectError> {
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| EffectError::Internal("runtime already shared".into()))?;
        inner.hardening = hardening;
        Ok(self)
    }

    /// Per-executable class. Can only narrow the profile (never grant network
    /// the profile class denies).
    pub fn with_executable_classes(
        mut self,
        classes: BTreeMap<PathBuf, InvocationClass>,
    ) -> Result<Self, EffectError> {
        let inner = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| EffectError::Internal("runtime already shared".into()))?;
        inner.executable_classes = classes;
        Ok(self)
    }
}

impl Inner {
    fn policy(&self, profile: &ContainmentProfile, launch: &ProcessLaunch) -> SandboxPolicy {
        let executable = PathBuf::from(&launch.executable);
        let class = self
            .executable_classes
            .get(&executable)
            .copied()
            .unwrap_or(profile.class);
        let network = if profile.class.network_allowed() && class.network_allowed() {
            NetworkPolicy::Allow
        } else {
            NetworkPolicy::Deny
        };
        let mut environment = launch.environment.clone();
        // PATH is never caller- or repository-controlled: the pinned tool's own
        // directory plus fixed system directories, so a planted `git` (or any
        // helper) earlier on a caller PATH is never what a scanner runs.
        environment.insert("PATH".into(), trusted_search_path(&launch.executable));
        let mut policy = SandboxPolicy::new().network(network).env(EnvPolicy {
            inherit: false,
            keep: Vec::new(),
            set: environment,
        });
        for root in &profile.read_only_roots {
            policy = policy.allow_read(root);
            if profile.class == InvocationClass::ProjectExecuting
                && class == InvocationClass::ProjectExecuting
                && !self.hardening.deny_interpreters
            {
                policy = policy.allow_exec(root);
            }
        }
        for root in &self.toolchain_roots {
            policy = policy.allow_read(root).allow_exec(root);
        }
        policy = policy
            .allow_read(&executable)
            .allow_exec(&executable)
            .allow_write(&profile.scratch_root);
        if self.hardening.deny_interpreters && rightkit_sandbox::deny_read_enforced() {
            // deny rules are emitted after every allow, so they win.
            for name in DENIED_INTERPRETER_NAMES {
                policy = policy.deny_read_glob(format!("/**/{name}"));
            }
        }
        policy
    }

    /// Hardening that the backend cannot apply for this launch: never run it.
    fn hardening_gap(
        &self,
        profile: &ContainmentProfile,
        launch: &ProcessLaunch,
    ) -> Option<&'static str> {
        if !self.hardening.deny_interpreters {
            return None;
        }
        if !rightkit_sandbox::deny_read_enforced() {
            return Some(GAP_INTERPRETER_EXEC);
        }
        let class = self
            .executable_classes
            .get(&PathBuf::from(&launch.executable))
            .copied()
            .unwrap_or(profile.class);
        if profile.class == InvocationClass::ProjectExecuting
            || class == InvocationClass::ProjectExecuting
        {
            return Some(GAP_UNIX_SOCKETS);
        }
        None
    }

    fn run(
        &self,
        launch: ProcessLaunch,
        profile: &ContainmentProfile,
    ) -> Result<ProcessOutput, EffectError> {
        // Defence in depth: OwnerProcess already checked these.
        if !profile
            .allowed_executables
            .contains(Path::new(&launch.executable))
        {
            return Err(EffectError::UnauthorizedEffect(
                "executable is not in the containment profile".into(),
            ));
        }
        if let Some(name) = launch
            .environment
            .keys()
            .find(|name| !profile.environment_names.contains(*name))
        {
            return Err(EffectError::UnauthorizedEffect(format!(
                "environment name {name:?} is not admitted"
            )));
        }
        if let Some(gap) = self.hardening_gap(profile, &launch) {
            return Err(EffectError::SandboxMissing(format!(
                "confinement not applied: {gap}"
            )));
        }
        let policy = self.policy(profile, &launch);
        let command = SandboxCommand::new(&launch.executable)
            .args(&launch.args)
            .cwd(&launch.cwd);
        let started_at_ms = now_ms();
        let mut child = self
            .sandbox
            .spawn(&policy, command)
            .map_err(map_sandbox_error)?;
        drop(child.take_stdin());
        let limited = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        for (stream, cap, reader) in [
            (0u8, launch.stdout_limit, child.take_stdout()),
            (1u8, launch.stderr_limit, child.take_stderr()),
        ] {
            let (tx, limited) = (tx.clone(), limited.clone());
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                if let Some(mut reader) = reader {
                    let mut chunk = [0u8; 8192];
                    loop {
                        match reader.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                let room = cap.saturating_sub(bytes.len());
                                bytes.extend_from_slice(&chunk[..n.min(room)]);
                                if n > room {
                                    limited.store(true, Ordering::SeqCst);
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(_) => break,
                        }
                    }
                }
                let _ = tx.send((stream, bytes));
            });
        }
        drop(tx);

        let deadline = Instant::now() + Duration::from_millis(launch.timeout_ms);
        let (mut timed_out, mut cancelled, mut output_limited) = (false, false, false);
        let mut lifecycle_error = None;
        loop {
            match child.has_exited() {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    lifecycle_error = Some(error.to_string());
                    break;
                }
            }
            if launch.cancellation.is_cancelled() {
                cancelled = true;
                break;
            }
            if limited.load(Ordering::SeqCst) {
                output_limited = true;
                break;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            std::thread::sleep(POLL);
        }
        let interrupted = timed_out || cancelled || output_limited || lifecycle_error.is_some();
        // Always sweep the tree, including after a natural exit: descendants
        // must not outlive the invocation, and the leader is reaped here.
        let mut detail = lifecycle_error.map(|e| format!("lifecycle poll failed: {e}"));
        let (status, mut kill_ok) = match child.terminate_tree() {
            Ok(status) => (Some(status), true),
            Err(error) => {
                detail = Some(format!("tree termination failed: {error}"));
                (child.try_wait().ok().flatten(), false)
            }
        };
        let (mut stdout, mut stderr) = (None, None);
        let grace_end = Instant::now() + READER_DRAIN_GRACE;
        for _ in 0..2 {
            match rx.recv_timeout(grace_end.saturating_duration_since(Instant::now())) {
                Ok((0, bytes)) => stdout = Some(bytes),
                Ok((_, bytes)) => stderr = Some(bytes),
                Err(_) => break,
            }
        }
        if stdout.is_none() || stderr.is_none() {
            // A survivor outside the tree still holds a pipe: not provably reaped.
            kill_ok = false;
            detail.get_or_insert_with(|| "output pipe held open after tree kill".into());
        }
        if limited.load(Ordering::SeqCst) {
            output_limited = true;
        }
        let (exit_code, signal) = match status {
            Some(status) => (status.code(), exit_signal(&status)),
            None => (None, None),
        };
        Ok(ProcessOutput {
            stdout: stdout.unwrap_or_default(),
            stderr: stderr.unwrap_or_default(),
            exit_code,
            signal,
            timed_out,
            cancelled,
            output_limited,
            kill_succeeded: kill_ok,
            process_tree: ProcessTreeEvidence {
                started: true,
                terminated: kill_ok,
                hard_killed: interrupted,
                reaped: status.is_some(),
                detail,
            },
            started_at_ms,
            completed_at_ms: now_ms(),
        })
    }
}

fn map_sandbox_error(error: SandboxError) -> EffectError {
    match error {
        // Confinement could not be applied: never run unconfined.
        SandboxError::Unsupported(detail) | SandboxError::InvalidPolicy(detail) => {
            EffectError::SandboxMissing(format!("confinement not applied: {detail}"))
        }
        other => EffectError::SpawnFailed(other.to_string()),
    }
}

#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(status)
}
#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

impl ContainedRuntime for RightKitSandboxRuntime {
    fn owner_id(&self) -> &str {
        &self.inner.owner_id
    }

    fn run_contained<'a>(
        &'a self,
        launch: ProcessLaunch,
        profile: &'a ContainmentProfile,
    ) -> ProcessFuture<'a> {
        let inner = self.inner.clone();
        let profile = profile.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || inner.run(launch, &profile))
                .await
                .map_err(|error| EffectError::Internal(format!("sandbox runner failed: {error}")))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(class: InvocationClass) -> ContainmentProfile {
        ContainmentProfile {
            owner_id: "o".into(),
            containment_id: "c".into(),
            class,
            read_only_roots: vec!["/frozen".into()],
            scratch_root: "/scratch".into(),
            allowed_executables: ["/opt/tool".into()].into_iter().collect(),
            environment_names: ["HOME".to_string()].into_iter().collect(),
            max_timeout_ms: 1_000,
            max_stdout: 10,
            max_stderr: 10,
        }
    }

    fn launch() -> ProcessLaunch {
        ProcessLaunch {
            executable: "/opt/tool".into(),
            args: vec![],
            cwd: "/frozen".into(),
            environment: [("HOME".to_string(), "/scratch".to_string())].into(),
            stdout_limit: 10,
            stderr_limit: 10,
            timeout_ms: 1_000,
            termination_grace_ms: 10,
            cancellation: Default::default(),
        }
    }

    fn inner() -> Inner {
        Inner {
            owner_id: "o".into(),
            sandbox: Sandbox::new(ResourceAuthority::new(ResourceProfile::Expanded)),
            toolchain_roots: vec![],
            executable_classes: BTreeMap::new(),
            hardening: ExecHardening::default(),
        }
    }

    #[test]
    fn network_is_denied_unless_profile_and_executable_both_allow() {
        let mut inner = inner();
        let denied = inner.policy(&profile(InvocationClass::ReadOnlyStatic), &launch());
        assert_eq!(denied.network, NetworkPolicy::Deny);
        let allowed = inner.policy(&profile(InvocationClass::NetworkMetadata), &launch());
        assert_eq!(allowed.network, NetworkPolicy::Allow);
        inner
            .executable_classes
            .insert("/opt/tool".into(), InvocationClass::ReadOnlyStatic);
        let narrowed = inner.policy(&profile(InvocationClass::NetworkMetadata), &launch());
        assert_eq!(narrowed.network, NetworkPolicy::Deny);
    }

    #[test]
    fn policy_has_one_writable_root_and_no_inherited_environment() {
        let policy = inner().policy(&profile(InvocationClass::ReadOnlyStatic), &launch());
        assert_eq!(policy.write_paths, vec![PathBuf::from("/scratch")]);
        assert!(!policy.env.inherit && policy.env.keep.is_empty());
        // The admitted HOME plus the pinned, never-inherited PATH.
        assert_eq!(policy.env.set.len(), 2);
        let path = policy.env.set.get("PATH").expect("pinned PATH");
        assert!(std::env::split_paths(path).all(|dir| dir.is_absolute()));
        let platform_dir = if cfg!(windows) {
            "System32"
        } else {
            "/usr/bin"
        };
        assert!(path.contains(platform_dir));
    }

    #[test]
    fn no_node_python_drops_audited_root_exec_and_denies_interpreters() {
        let mut inner = inner();
        let p = profile(InvocationClass::ProjectExecuting);
        assert!(inner
            .policy(&p, &launch())
            .exec_paths
            .contains(&"/frozen".into()));
        inner.hardening.deny_interpreters = true;
        let hardened = inner.policy(&p, &launch());
        assert!(!hardened.exec_paths.contains(&"/frozen".into()));
        assert!(hardened.exec_paths.contains(&"/opt/tool".into()));
        if rightkit_sandbox::deny_read_enforced() {
            assert!(hardened.deny_read.len() >= DENIED_INTERPRETER_NAMES.len());
            assert_eq!(inner.hardening_gap(&p, &launch()), Some(GAP_UNIX_SOCKETS));
        } else {
            assert_eq!(
                inner.hardening_gap(&p, &launch()),
                Some(GAP_INTERPRETER_EXEC)
            );
        }
        // Never claimed as an exec block (rightkit#943).
        let enforced = inner.hardening.enforced();
        assert!(!enforced.interpreter_exec_denied);
        assert!(enforced.gaps.contains(&GAP_INTERPRETER_EXEC));
    }

    #[test]
    fn unsupported_confinement_is_sandbox_missing_never_success() {
        let error = map_sandbox_error(SandboxError::Unsupported("x".into()));
        assert!(matches!(error, EffectError::SandboxMissing(_)));
    }
}
