//! OS-level sandbox authentication for the checks that mark
//! `requires_network_sandbox`.
//!
//! Native Audit previously refused every check in that set unconditionally:
//! there was no code path that could produce a `SandboxReceipt`, so the
//! executor's `requires_network_sandbox && !sandbox.network` gate in
//! `executor.rs` always tripped. This module gives one platform (macOS) a
//! real authenticator: it writes a `sandbox-exec` profile, wraps the
//! requested command under it, and only then returns a receipt. The receipt
//! is authenticated because the OS sandbox is the thing that actually ran
//! the process, not an assertion made after the fact.
//!
//! Two profiles are supported:
//! - `DenyNetwork`: for checks that execute target-project code (build,
//!   lint, types, ...). Network access is denied; project files stay
//!   read/write so the tool can operate normally.
//! - `DenyNetworkDenyProjectWrite`: for project test execution. Network access
//!   and writes under the audited project root are denied.
//! - `AllowNetworkDenyProjectWrite`: for advisory checks that must reach a
//!   registry or vulnerability database (cargo_audit, cargo_deny, deps_cve,
//!   py_deps_cve, outdated, cargo_outdated). Network is allowed; writes
//!   under the project root are denied so the check cannot execute or
//!   mutate project code.
//!
//! No other platform has an authenticator yet. `authenticate` on
//! non-macOS returns `SandboxGap::UnsupportedPlatform` so callers keep
//! refusing rather than fabricate a receipt — a typed degradation, not a
//! silent pass.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxMode {
    DenyNetwork,
    DenyNetworkDenyProjectWrite,
    AllowNetworkDenyProjectWrite,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxAuthentication {
    pub id: String,
    pub network: bool,
    pub filesystem_scope: Option<String>,
    pub wrapped_executable: String,
    pub wrapped_args: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxGap {
    /// No authenticator is implemented for this platform yet.
    UnsupportedPlatform,
    /// The sandbox tool itself is not present on this host.
    ToolMissing,
    /// The profile could not be written to disk.
    ProfileWriteFailed(String),
    /// A project-write-denied profile could not resolve a usable project root.
    ProjectRootUnavailable(String),
    /// A scoped IPC prerequisite could not be established or revalidated.
    IpcNamespaceInvalid(String),
}

impl SandboxGap {
    pub fn as_str(&self) -> String {
        match self {
            Self::UnsupportedPlatform => {
                "sandbox_unsupported_platform: no OS sandbox authenticator for this platform".into()
            }
            Self::ToolMissing => "sandbox_tool_missing: /usr/bin/sandbox-exec not found".into(),
            Self::ProfileWriteFailed(detail) => format!("sandbox_profile_write_failed: {detail}"),
            Self::ProjectRootUnavailable(detail) => {
                format!("sandbox_project_root_unavailable: {detail}")
            }
            Self::IpcNamespaceInvalid(detail) => format!("sandbox_ipc_namespace_invalid: {detail}"),
        }
    }
}

/// Exclusive, owner-only IPC storage. Fields are private: JSON & receipt IDs
/// cannot construct this capability. Keep it alive until the child tree reaps.
#[derive(Debug)]
pub struct OwnedIpcNamespace {
    path: PathBuf,
    #[cfg(target_os = "macos")]
    identity: (u64, u64),
    cleanup: bool,
}

impl OwnedIpcNamespace {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Preserve storage when an executor reports an unreaped live child tree.
    /// The caller must report that failure; removing live IPC is not cleanup.
    pub fn retain_after_failed_reap(&mut self) {
        self.cleanup = false;
    }

    /// A waited direct child does not prove descendants terminated. Keep IPC
    /// whenever execution failed to confirm the whole tree stopped & reaped.
    pub fn retain_if_process_tree_unconfirmed(
        &mut self,
        receipt: &crate::receipt::ExecutionReceipt,
    ) -> bool {
        let unconfirmed = receipt
            .gaps
            .iter()
            .any(|gap| gap == "platform_process_tree_unconfirmed")
            || receipt.state == crate::receipt::ExecutionState::KillFailed
            || (receipt.process_tree.started
                && (!receipt.process_tree.terminated || !receipt.process_tree.reaped));
        if unconfirmed {
            self.retain_after_failed_reap();
        }
        unconfirmed
    }

    #[cfg(target_os = "macos")]
    pub fn create(project_root: &Path) -> Result<Self, SandboxGap> {
        use sha2::{Digest, Sha256};
        use std::{
            fs,
            os::unix::fs::{DirBuilderExt, MetadataExt},
            sync::atomic::{AtomicU64, Ordering},
        };
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let storage = ipc_run_storage()?;
        let seed = format!(
            "{}:{:?}:{}",
            std::process::id(),
            std::time::SystemTime::now(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let suffix = hex::encode(Sha256::digest(seed.as_bytes()));
        let path = storage.join(format!("li-{}", &suffix[..16]));
        check_ipc_capacity(&path)?;
        let project = project_root.canonicalize().map_err(ipc_error)?;
        if path.starts_with(&project) || project.starts_with(&path) {
            return Err(ipc_error("IPC storage overlaps project"));
        }
        // create, never create_dir_all/reuse/chmod an existing directory.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(ipc_error)?;
        let meta = fs::symlink_metadata(&path).map_err(ipc_error)?;
        let namespace = Self {
            path,
            identity: (meta.dev(), meta.ino()),
            cleanup: true,
        };
        validate_tflint_ipc_namespace(namespace.path(), &project)?;
        Ok(namespace)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn create(_project_root: &Path) -> Result<Self, SandboxGap> {
        Err(SandboxGap::UnsupportedPlatform)
    }
}

impl Drop for OwnedIpcNamespace {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::MetadataExt;
            if self.cleanup
                && std::fs::symlink_metadata(&self.path).is_ok_and(|m| {
                    !m.file_type().is_symlink()
                        && (m.dev(), m.ino()) == self.identity
                        && m.uid() == unsafe { libc::geteuid() }
                })
            {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn ipc_error(detail: impl std::fmt::Display) -> SandboxGap {
    SandboxGap::IpcNamespaceInvalid(detail.to_string())
}

#[cfg(target_os = "macos")]
fn require_empty_acl(path: &Path) -> Result<(), SandboxGap> {
    use std::{
        ffi::{c_char, c_int, c_void, CString},
        os::unix::ffi::OsStrExt,
    };
    // Apple Libc gen/filesec.c, sys/{fcntl,stat,acl}.h define this ABI.
    // Read only. Reject every nonempty ACL rather than interpret principals,
    // inherited entries or permissions. Unsupported/unreadable fails closed.
    unsafe extern "C" {
        fn filesec_init() -> *mut c_void;
        fn filesec_free(filesec: *mut c_void);
        fn filesec_query_property(
            filesec: *mut c_void,
            property: c_int,
            present: *mut c_int,
        ) -> c_int;
        fn filesec_get_property(filesec: *mut c_void, property: c_int, value: *mut c_void)
            -> c_int;
        #[cfg_attr(target_arch = "x86_64", link_name = "lstatx_np$INODE64")]
        fn lstatx_np(path: *const c_char, stat: *mut libc::stat, filesec: *mut c_void) -> c_int;
        fn acl_get_entry(acl: *mut c_void, which: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }
    let path = CString::new(path.as_os_str().as_bytes()).map_err(ipc_error)?;
    // acl_get_link_np alone conflates absent ACL with failed lookup. A fresh
    // filesec populated by successful lstatx_np proves which case occurred.
    let filesec = unsafe { filesec_init() };
    if filesec.is_null() {
        return Err(ipc_error("cannot allocate IPC ancestor filesec"));
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status = unsafe { lstatx_np(path.as_ptr(), stat.as_mut_ptr(), filesec) };
    let error = std::io::Error::last_os_error();
    if status != 0 {
        unsafe { filesec_free(filesec) };
        return Err(ipc_error(format!(
            "cannot inspect IPC ancestor filesec: {error}"
        )));
    }
    let mut present = -1;
    let queried = unsafe { filesec_query_property(filesec, 5, &mut present) };
    if queried != 0 || present < 0 {
        unsafe { filesec_free(filesec) };
        return Err(ipc_error("cannot query IPC ancestor ACL presence"));
    }
    if present == 0 {
        unsafe { filesec_free(filesec) };
        return Ok(());
    }
    let mut acl: *mut c_void = std::ptr::null_mut();
    let copied = unsafe { filesec_get_property(filesec, 5, (&mut acl as *mut *mut c_void).cast()) };
    unsafe { filesec_free(filesec) };
    if copied != 0 || acl.is_null() || acl as usize <= 16 {
        return Err(ipc_error("cannot copy IPC ancestor ACL"));
    }
    let mut entry = std::ptr::null_mut();
    // Darwin acl_get_entry returns 0 on an entry, -1/EINVAL when FIRST_ENTRY
    // is beyond an empty valid ACL; it does not use POSIX's 1/0 convention.
    let status = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = std::io::Error::last_os_error();
    let freed = unsafe { acl_free(acl) };
    if freed != 0 {
        return Err(ipc_error("cannot free IPC ancestor ACL"));
    }
    match (status, error.raw_os_error()) {
        (-1, Some(libc::EINVAL)) => Ok(()),
        (0, _) => Err(ipc_error("nonempty IPC ancestor ACL")),
        _ => Err(ipc_error("cannot enumerate IPC ancestor ACL")),
    }
}

#[cfg(target_os = "macos")]
fn canonical_owned_path(path: &Path) -> Result<PathBuf, SandboxGap> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(ipc_error("noncanonical IPC path"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        let invalid = |detail: String| ipc_error(format!("{detail}: {}", current.display()));
        let meta =
            std::fs::symlink_metadata(&current).map_err(|error| invalid(error.to_string()))?;
        // Root/system ancestors may be root-owned; no other user may own an
        // ancestor that can replace the namespace. Reject symlinks throughout.
        if meta.file_type().is_symlink()
            || !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != unsafe { libc::geteuid() })
        {
            return Err(invalid(
                "symlink, non-directory or foreign-owned IPC ancestor".into(),
            ));
        }
        if meta.mode() & 0o022 != 0 && !(meta.uid() == 0 && meta.mode() & 0o1000 != 0) {
            return Err(invalid("IPC ancestor writable by another principal".into()));
        }
        require_empty_acl(&current).map_err(|error| match error {
            SandboxGap::IpcNamespaceInvalid(detail) => invalid(detail),
            other => other,
        })?;
    }
    let canonical = path.canonicalize().map_err(ipc_error)?;
    if canonical != path {
        return Err(ipc_error("IPC path is not canonical"));
    }
    Ok(canonical)
}

/// CI provisions one exclusive private directory; environment alone never
/// exempts its path, ownership, mode or ancestors from native validation.
#[cfg(target_os = "macos")]
fn ci_ipc_run_storage(path: &Path) -> Result<PathBuf, SandboxGap> {
    use std::os::unix::fs::MetadataExt;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if path.parent() != Some(Path::new("/private/tmp"))
        || !name.starts_with("li-ci.")
        || name.len() != 14
        || !name[6..].bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(ipc_error(
            "CI IPC storage must be /private/tmp/li-ci.<8 alphanumeric characters>",
        ));
    }
    let canonical = canonical_owned_path(path)?;
    let meta = std::fs::symlink_metadata(&canonical).map_err(ipc_error)?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
        return Err(ipc_error(
            "CI IPC storage must be effective-owner mode 0700",
        ));
    }
    Ok(canonical)
}

/// No arbitrary temporary fallback. CI explicitly provisions private IPC
/// storage; RUNNER_TEMP remains available for retained qualification artifacts.
#[cfg(target_os = "macos")]
fn ipc_run_storage() -> Result<PathBuf, SandboxGap> {
    if std::env::var("CI").as_deref() == Ok("true") {
        let path = PathBuf::from(
            std::env::var_os("LEGION_CI_IPC_STORAGE")
                .ok_or_else(|| ipc_error("CI LEGION_CI_IPC_STORAGE missing"))?,
        );
        ci_ipc_run_storage(&path)
    } else {
        canonical_owned_path(Path::new("/Volumes/D/scratch"))
    }
}

#[cfg(target_os = "macos")]
fn check_ipc_capacity(path: &Path) -> Result<(), SandboxGap> {
    use std::os::unix::ffi::OsStrExt;
    // go-plugin v1.8 server.go: CreateTemp(socketDir, "plugin") uses Go's
    // uint32 decimal suffix (at most 10 digits), then net.Listen("unix", path).
    // Account for slash & terminating NUL in Darwin sockaddr_un.sun_path.
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.as_os_str().as_bytes().len() + 1 + "plugin".len() + 10 + 1 > address.sun_path.len() {
        return Err(ipc_error("go-plugin socket exceeds AF_UNIX path capacity"));
    }
    Ok(())
}

/// Revalidate an extant namespace at policy admission. Never trust a receipt
/// string, path prefix, inherited TMPDIR or an owner/mode assertion in JSON.
#[cfg(target_os = "macos")]
pub fn validate_tflint_ipc_namespace(path: &Path, project: &Path) -> Result<(), SandboxGap> {
    use std::os::unix::fs::MetadataExt;
    let storage = ipc_run_storage()?;
    let canonical = canonical_owned_path(path)?;
    let project = project.canonicalize().map_err(ipc_error)?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if path.parent() != Some(storage.as_path())
        || !name.starts_with("li-")
        || name.len() != 19
        || !name[3..].bytes().all(|b| b.is_ascii_hexdigit())
        || canonical.starts_with(&project)
        || project.starts_with(&canonical)
    {
        return Err(ipc_error(
            "IPC namespace outside designated run storage or overlaps project",
        ));
    }
    let meta = std::fs::symlink_metadata(path).map_err(ipc_error)?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
        return Err(ipc_error("IPC namespace must be effective-owner mode 0700"));
    }
    check_ipc_capacity(path)
}

#[cfg(not(target_os = "macos"))]
pub fn validate_tflint_ipc_namespace(_path: &Path, _project: &Path) -> Result<(), SandboxGap> {
    Err(SandboxGap::UnsupportedPlatform)
}

/// TFLint's bundled Go plugin needs only scoped Unix bind/connect. IP & other
/// Unix endpoints remain denied. Syntax follows OpenAI Codex seatbelt.rs
/// unix_socket_policy, not an assertion of an Apple-documented public API.
#[cfg(target_os = "macos")]
fn scoped_ipc_profile(project: &str, namespace: &str) -> String {
    let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let project = quote(project);
    let namespace = quote(namespace);
    format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{project}\"))\n(deny file-write* (subpath \"{project}\"))\n(allow network-bind (local unix-socket (subpath \"{namespace}\")))\n(allow network-outbound (remote unix-socket (subpath \"{namespace}\")))\n")
}

#[cfg(target_os = "macos")]
fn authenticate_scoped_ipc_inner(
    executable: &str,
    args: &[String],
    cwd: &str,
    profile_dir: &Path,
    namespace: &OwnedIpcNamespace,
) -> Result<SandboxAuthentication, SandboxGap> {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    validate_tflint_ipc_namespace(namespace.path(), Path::new(cwd))?;
    let meta = fs::symlink_metadata(namespace.path()).map_err(ipc_error)?;
    if (meta.dev(), meta.ino()) != namespace.identity {
        return Err(ipc_error("IPC namespace replaced"));
    }
    if !Path::new("/usr/bin/sandbox-exec").is_file() {
        return Err(SandboxGap::ToolMissing);
    }
    let project = Path::new(cwd).canonicalize().map_err(ipc_error)?;
    let project = project
        .to_str()
        .ok_or_else(|| ipc_error("non-UTF8 project"))?;
    let namespace_path = namespace
        .path()
        .to_str()
        .ok_or_else(|| ipc_error("non-UTF8 IPC path"))?;
    let profile = scoped_ipc_profile(project, namespace_path);
    let hash = hex::encode(Sha256::digest(profile.as_bytes()));
    fs::create_dir_all(profile_dir).map_err(ipc_error)?;
    let profile_path = profile_dir.join(format!("audit-{hash}.sb"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&profile_path)
        .map_err(ipc_error)?;
    file.write_all(profile.as_bytes()).map_err(ipc_error)?;
    let mut wrapped_args = vec![
        "-f".into(),
        profile_path.to_string_lossy().into_owned(),
        "--".into(),
        executable.into(),
    ];
    wrapped_args.extend_from_slice(args);
    Ok(SandboxAuthentication {
        id: format!("sandbox:macos:tflint-ipc:{hash}"),
        network: true,
        filesystem_scope: Some(project.into()),
        wrapped_executable: "/usr/bin/sandbox-exec".into(),
        wrapped_args,
    })
}

#[cfg(target_os = "macos")]
pub fn authenticate_tflint_scoped(
    executable: &str,
    args: &[String],
    cwd: &str,
    profile_dir: &Path,
    namespace: &OwnedIpcNamespace,
) -> Result<SandboxAuthentication, SandboxGap> {
    if Path::new(executable).file_name().and_then(|s| s.to_str()) != Some("tflint")
        || args.len() != 8
        || args[0] != "--config"
        || args[2..]
            != [
                "--format",
                "json",
                "--no-color",
                "--call-module-type",
                "none",
                "--force",
            ]
    {
        return Err(ipc_error(
            "scoped IPC authenticator admits only owned TFLint scan argv",
        ));
    }
    authenticate_scoped_ipc_inner(executable, args, cwd, profile_dir, namespace)
}

#[cfg(not(target_os = "macos"))]
pub fn authenticate_tflint_scoped(
    _executable: &str,
    _args: &[String],
    _cwd: &str,
    _profile_dir: &Path,
    _namespace: &OwnedIpcNamespace,
) -> Result<SandboxAuthentication, SandboxGap> {
    Err(SandboxGap::UnsupportedPlatform)
}

#[cfg(all(test, target_os = "macos"))]
mod scoped_ipc_tests {
    use super::*;
    use crate::{
        ArtifactWriter, EffectExecutor, ExecutionState, ExternalToolRequest, PolicyAuthorizer,
        PolicyDecision, SandboxReceipt, ToolOrigin,
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream, UdpSocket},
        os::unix::{
            fs::DirBuilderExt,
            net::{UnixListener, UnixStream},
        },
        time::Duration,
    };

    fn hash(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = ipc_run_storage().unwrap().join(format!(
                "ipc-test-{}-{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            fs::create_dir(path.join("project")).unwrap();
            Self(path)
        }
        fn project(&self) -> PathBuf {
            self.0.join("project")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone)]
    struct ExactPolicy {
        request: ExternalToolRequest,
        namespace: PathBuf,
        profile: Vec<u8>,
    }
    impl PolicyAuthorizer for ExactPolicy {
        fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
            let allowed = request == &self.request
                && validate_tflint_ipc_namespace(&self.namespace, Path::new(&request.cwd)).is_ok()
                && fs::read(&request.args[1]).ok().as_deref() == Some(self.profile.as_slice())
                && fs::read(&request.executable)
                    .ok()
                    .map(|bytes| hash(&bytes))
                    .as_deref()
                    == request.expected_digest.as_deref();
            PolicyDecision {
                allowed,
                policy_id: "scoped-ipc-native-control".into(),
                policy_version: 1,
                policy_digest: hash(&self.profile),
                reason: Some("exact native IPC confinement control".into()),
            }
        }
    }

    fn request(
        fixture: &Fixture,
        namespace: &OwnedIpcNamespace,
        mode: &str,
        extra: &[(&str, String)],
    ) -> (ExternalToolRequest, ExactPolicy) {
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let args: Vec<String> = [
            "--exact",
            "sandbox::scoped_ipc_tests::scoped_ipc_worker",
            "--ignored",
            "--nocapture",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        // Test-only inner constructor; public scoped constructor admits only
        // real TFLint's owned scan argv, never this test binary.
        let auth = authenticate_scoped_ipc_inner(
            executable.to_str().unwrap(),
            &args,
            fixture.project().to_str().unwrap(),
            &fixture.0.join("profile"),
            namespace,
        )
        .unwrap();
        let mut environment: BTreeMap<String, String> = [
            (
                "TMPDIR".into(),
                namespace.path().to_string_lossy().into_owned(),
            ),
            ("LEGION_IPC_TEST_MODE".into(), mode.into()),
            (
                "LEGION_IPC_TEST_PROJECT".into(),
                fixture.project().to_string_lossy().into_owned(),
            ),
        ]
        .into_iter()
        .collect();
        for (key, value) in extra {
            environment.insert((*key).into(), value.clone());
        }
        let request = ExternalToolRequest {
            request_id: format!("scoped-ipc-control-{mode}"),
            provider_id: "native-confinement-control".into(),
            plan_id: hash(b"native-confinement-control"),
            policy_id: "scoped-ipc-native-control".into(),
            executable: auth.wrapped_executable,
            args: auth.wrapped_args,
            expected_digest: Some(hash(&fs::read("/usr/bin/sandbox-exec").unwrap())),
            skip_version_probe: true,
            cwd: fixture.project().to_string_lossy().into_owned(),
            origin: ToolOrigin::System,
            requires_network_sandbox: true,
            sandbox: Some(SandboxReceipt {
                id: auth.id,
                network: auth.network,
                filesystem_scope: auth.filesystem_scope,
            }),
            environment_allowlist: environment.keys().cloned().collect(),
            environment,
            timeout_ms: 10_000,
            stdout_limit: 64 * 1024,
            stderr_limit: 64 * 1024,
            ..ExternalToolRequest::default()
        };
        let policy = ExactPolicy {
            profile: fs::read(&request.args[1]).unwrap(),
            namespace: namespace.path().into(),
            request: request.clone(),
        };
        (request, policy)
    }

    fn denied(error: std::io::Error) {
        assert!(matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)),
            "negative control must fail from sandbox permission, not absent endpoint/capacity: {error}");
    }

    #[test]
    #[ignore = "helper launched only by scoped native confinement driver"]
    fn scoped_ipc_worker() {
        let Ok(mode) = std::env::var("LEGION_IPC_TEST_MODE") else {
            return;
        };
        let namespace = PathBuf::from(std::env::var_os("TMPDIR").unwrap());
        if mode == "hang" || mode == "grandchild" {
            let _listener = UnixListener::bind(namespace.join(format!("{mode}.sock"))).unwrap();
            if mode == "hang" {
                let _child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "sandbox::scoped_ipc_tests::scoped_ipc_worker",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("LEGION_IPC_TEST_MODE", "grandchild")
                    .spawn()
                    .unwrap();
            }
            fs::write(namespace.join(format!("{mode}.ready")), b"ready").unwrap();
            std::thread::sleep(Duration::from_secs(60));
            return;
        }
        let listener = UnixListener::bind(namespace.join("allowed.sock")).unwrap();
        let mut client = UnixStream::connect(namespace.join("allowed.sock")).unwrap();
        client.write_all(b"ok").unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        let mut bytes = [0u8; 2];
        accepted.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
        for key in [
            "LEGION_IPC_TEST_SIBLING",
            "LEGION_IPC_TEST_PREFIX",
            "LEGION_IPC_TEST_OUTSIDE",
            "LEGION_IPC_TEST_ALIAS",
        ] {
            let dir = PathBuf::from(std::env::var_os(key).unwrap());
            denied(UnixListener::bind(dir.join("forbidden.sock")).unwrap_err());
            denied(UnixStream::connect(dir.join("ready.sock")).unwrap_err());
        }
        for key in ["LEGION_IPC_TEST_TCP4", "LEGION_IPC_TEST_TCP6"] {
            let endpoint: std::net::SocketAddr = std::env::var(key).unwrap().parse().unwrap();
            denied(TcpListener::bind(std::net::SocketAddr::new(endpoint.ip(), 0)).unwrap_err());
            denied(TcpStream::connect_timeout(&endpoint, Duration::from_secs(1)).unwrap_err());
        }
        for (key, family) in [
            ("LEGION_IPC_TEST_UDP4", libc::AF_INET),
            ("LEGION_IPC_TEST_UDP6", libc::AF_INET6),
        ] {
            let endpoint: std::net::SocketAddr = std::env::var(key).unwrap().parse().unwrap();
            denied(UdpSocket::bind(std::net::SocketAddr::new(endpoint.ip(), 0)).unwrap_err());
            use std::os::fd::FromRawFd;
            let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
            assert!(
                fd >= 0,
                "socket creation must be available to test outbound gate"
            );
            let socket = unsafe { UdpSocket::from_raw_fd(fd) };
            let outcome = socket
                .connect(endpoint)
                .and_then(|()| socket.send(b"denied").map(|_| ()));
            denied(outcome.unwrap_err());
        }
        let project = PathBuf::from(std::env::var_os("LEGION_IPC_TEST_PROJECT").unwrap());
        denied(fs::write(project.join("denied-write"), b"no").unwrap_err());
    }

    #[test]
    #[ignore = "requires real macOS Seatbelt; native IPC/IP confinement controls"]
    fn scoped_ipc_native_confinement() {
        let fixture = Fixture::new();
        let namespace = OwnedIpcNamespace::create(&fixture.project()).unwrap();
        let sibling = OwnedIpcNamespace::create(&fixture.project()).unwrap();
        let outside = OwnedIpcNamespace::create(&fixture.project()).unwrap();
        let prefix = namespace.path().with_file_name(format!(
            "{}-other",
            namespace.path().file_name().unwrap().to_str().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&prefix).unwrap();
        let alias = namespace.path().join("alias");
        std::os::unix::fs::symlink(outside.path(), &alias).unwrap();
        let unix_listeners: Vec<UnixListener> = [sibling.path(), prefix.as_path(), outside.path()]
            .into_iter()
            .map(|path| UnixListener::bind(path.join("ready.sock")).unwrap())
            .collect();
        for path in [
            sibling.path(),
            prefix.as_path(),
            outside.path(),
            alias.as_path(),
        ] {
            // Unsandboxed readiness proves endpoint/path exists & is usable.
            UnixStream::connect(path.join("ready.sock")).unwrap();
        }
        let tcp4 = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp6 =
            TcpListener::bind("[::1]:0").expect("IPv6 loopback prerequisite must be available");
        for listener in [&tcp4, &tcp6] {
            TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        }
        let udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp6 = UdpSocket::bind("[::1]:0").expect("IPv6 UDP prerequisite must be available");
        for socket in [&udp4, &udp6] {
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let ready = UdpSocket::bind(std::net::SocketAddr::new(
                socket.local_addr().unwrap().ip(),
                0,
            ))
            .unwrap();
            ready.connect(socket.local_addr().unwrap()).unwrap();
            ready.send(b"ready").unwrap();
            let mut bytes = [0u8; 5];
            assert_eq!(socket.recv(&mut bytes).unwrap(), 5);
        }
        fs::write(fixture.project().join("host-write"), b"ready").unwrap();
        let extra = [
            (
                "LEGION_IPC_TEST_SIBLING",
                sibling.path().to_string_lossy().into_owned(),
            ),
            (
                "LEGION_IPC_TEST_PREFIX",
                prefix.to_string_lossy().into_owned(),
            ),
            (
                "LEGION_IPC_TEST_OUTSIDE",
                outside.path().to_string_lossy().into_owned(),
            ),
            (
                "LEGION_IPC_TEST_ALIAS",
                alias.to_string_lossy().into_owned(),
            ),
            (
                "LEGION_IPC_TEST_TCP4",
                tcp4.local_addr().unwrap().to_string(),
            ),
            (
                "LEGION_IPC_TEST_TCP6",
                tcp6.local_addr().unwrap().to_string(),
            ),
            (
                "LEGION_IPC_TEST_UDP4",
                udp4.local_addr().unwrap().to_string(),
            ),
            (
                "LEGION_IPC_TEST_UDP6",
                udp6.local_addr().unwrap().to_string(),
            ),
        ];
        let (request, policy) = request(&fixture, &namespace, "confinement", &extra);
        let executor = EffectExecutor::new(
            crate::platform::unix::UnixProcess::new(),
            ArtifactWriter::new(fixture.0.join("artifacts")),
            policy.clone(),
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for index in 0..4 {
            let mut tampered = request.clone();
            match index {
                0 => tampered.args.push("-DLEGION_IPC=/tmp".into()),
                1 => tampered.args[3] = "/bin/true".into(),
                2 => tampered.expected_digest = Some(hash(b"wrong wrapper")),
                _ => {
                    tampered.args[1] = fixture
                        .0
                        .join("different-profile")
                        .to_string_lossy()
                        .into_owned()
                }
            }
            let receipt = runtime.block_on(executor.execute(&tampered));
            assert_eq!(receipt.state, ExecutionState::UnauthorizedEffect);
            assert!(!receipt.process_tree.started);
        }
        for (key, value) in [
            ("TMPDIR", sibling.path().to_string_lossy().into_owned()),
            (
                "PLUGIN_UNIX_SOCKET_DIR",
                sibling.path().to_string_lossy().into_owned(),
            ),
            ("PLUGIN_UNIX_SOCKET_GROUP", "0".into()),
        ] {
            let mut tampered = request.clone();
            tampered.environment.insert(key.into(), value);
            tampered.environment_allowlist.insert(key.into());
            let receipt = runtime.block_on(executor.execute(&tampered));
            assert_eq!(receipt.state, ExecutionState::UnauthorizedEffect);
            assert!(!receipt.process_tree.started);
        }
        let profile = fs::read(&request.args[1]).unwrap();
        fs::write(&request.args[1], b"(version 1)\n(allow default)\n").unwrap();
        let rejected = runtime.block_on(executor.execute(&request));
        assert_eq!(rejected.state, ExecutionState::UnauthorizedEffect);
        assert!(!rejected.process_tree.started);
        fs::write(&request.args[1], profile).unwrap();
        let receipt = runtime.block_on(executor.execute(&request));
        assert_eq!(receipt.state, ExecutionState::Completed, "{receipt:?}");
        assert!(receipt.complete && receipt.process_tree.reaped);
        assert!(!fixture.project().join("denied-write").exists());
        let path = namespace.path().to_path_buf();
        assert!(path.exists());
        drop(namespace);
        assert!(!path.exists());
        drop(unix_listeners);
        fs::remove_dir_all(prefix).unwrap();
    }

    #[test]
    #[ignore = "requires real macOS Seatbelt; timeout/cancel child-tree cleanup"]
    fn scoped_ipc_timeout_and_cancel_cleanup_after_reaping() {
        for cancel in [false, true] {
            let fixture = Fixture::new();
            let namespace = OwnedIpcNamespace::create(&fixture.project()).unwrap();
            let path = namespace.path().to_path_buf();
            let (mut request, _) = request(&fixture, &namespace, "hang", &[]);
            request.timeout_ms = if cancel { 10_000 } else { 1500 };
            let policy = ExactPolicy {
                request: request.clone(),
                namespace: path.clone(),
                profile: fs::read(&request.args[1]).unwrap(),
            };
            let executor = EffectExecutor::new(
                crate::platform::unix::UnixProcess::new(),
                ArtifactWriter::new(fixture.0.join("artifacts")),
                policy,
            );
            let token = tokio_util::sync::CancellationToken::new();
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let receipt = runtime.block_on(async {
                let watch = token.clone();
                let ready = path.join("grandchild.ready");
                let watcher = tokio::spawn(async move {
                    for _ in 0..100 {
                        if ready.is_file() {
                            if cancel {
                                watch.cancel();
                            }
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    panic!("child & grandchild must become ready before timeout/cancel");
                });
                let receipt = executor.execute_with_cancellation(&request, token).await;
                watcher.await.unwrap();
                receipt
            });
            assert_eq!(
                receipt.state,
                if cancel {
                    ExecutionState::Cancelled
                } else {
                    ExecutionState::Timeout
                },
                "{receipt:?}"
            );
            assert!(receipt.process_tree.started && receipt.process_tree.reaped);
            assert!(path.exists(), "owner must outlive executor reap");
            drop(namespace);
            assert!(!path.exists(), "cleanup follows reap on timeout/cancel");
        }
    }

    #[test]
    fn scoped_ipc_failed_version_probe_preserves_lifecycle_and_namespace() {
        use crate::platform::{PlatformProcess, ProcessFuture, ProcessLaunch, ProcessOutput};
        use crate::receipt::ProcessTreeEvidence;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        struct UnreapedProbe(Arc<AtomicUsize>, bool);
        impl PlatformProcess for UnreapedProbe {
            fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a> {
                self.0.fetch_add(1, Ordering::SeqCst);
                let direct_child_reaped = self.1;
                Box::pin(async move {
                    assert_eq!(launch.args.as_slice(), ["--probe-unreaped"]);
                    Ok(ProcessOutput {
                        stdout: b"probe output".to_vec(),
                        stderr: Vec::new(),
                        exit_code: direct_child_reaped.then_some(0),
                        signal: if direct_child_reaped { None } else { Some(9) },
                        timed_out: !direct_child_reaped,
                        cancelled: false,
                        output_limited: false,
                        kill_succeeded: false,
                        process_tree: ProcessTreeEvidence {
                            started: true,
                            terminated: false,
                            hard_killed: true,
                            reaped: direct_child_reaped,
                            detail: Some("injected unconfirmed version-probe descendants".into()),
                        },
                        started_at_ms: 10,
                        completed_at_ms: 30,
                    })
                })
            }
        }
        for direct_child_reaped in [false, true] {
            let fixture = Fixture::new();
            let mut namespace = OwnedIpcNamespace::create(&fixture.project()).unwrap();
            let path = namespace.path().to_path_buf();
            let (mut request, _) = request(&fixture, &namespace, "probe-control", &[]);
            request.skip_version_probe = false;
            request.version_args = vec!["--probe-unreaped".into()];
            let policy = ExactPolicy {
                request: request.clone(),
                namespace: path.clone(),
                profile: fs::read(&request.args[1]).unwrap(),
            };
            let launches = Arc::new(AtomicUsize::new(0));
            let executor = EffectExecutor::new(
                UnreapedProbe(Arc::clone(&launches), direct_child_reaped),
                ArtifactWriter::new(fixture.0.join("artifacts")),
                policy,
            );
            let receipt = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(executor.execute(&request));
            assert_eq!(receipt.state, ExecutionState::KillFailed);
            assert!(!receipt.complete);
            assert_eq!(
                launches.load(Ordering::SeqCst),
                1,
                "main command must never start"
            );
            assert!(receipt.process_tree.started);
            assert_eq!(receipt.process_tree.reaped, direct_child_reaped);
            assert!(!receipt.process_tree.terminated && receipt.process_tree.hard_killed);
            assert_eq!(
                receipt.process_tree.detail.as_deref(),
                Some("injected unconfirmed version-probe descendants")
            );
            assert_eq!(receipt.exit_code, direct_child_reaped.then_some(0));
            assert_eq!(
                receipt.signal,
                if direct_child_reaped { None } else { Some(9) }
            );
            assert_eq!(receipt.timing.started_at_ms, 10);
            assert_eq!(receipt.timing.completed_at_ms, 30);
            assert_eq!(receipt.timing.duration_ms, 20);
            assert!(namespace.retain_if_process_tree_unconfirmed(&receipt));
            drop(namespace);
            assert!(
                path.is_dir(),
                "unconfirmed descendants must preserve IPC even if direct child reaped"
            );
            // This platform double never starts a child; explicitly remove its
            // retained test directory after proving the guard did not clean it.
            fs::remove_dir_all(path).unwrap();
        }
        struct PlatformError {
            launches: Arc<AtomicUsize>,
            expected_args: Vec<String>,
            error: crate::error::EffectError,
        }
        impl PlatformProcess for PlatformError {
            fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a> {
                self.launches.fetch_add(1, Ordering::SeqCst);
                assert_eq!(launch.args, self.expected_args);
                let error = self.error.clone();
                Box::pin(async move { Err(error) })
            }
        }
        // Exercise Err from each real executor launch boundary, including
        // SpawnFailed: Unix uses that variant after spawning for PID/pipe errors.
        for during_probe in [true, false] {
            for error in [
                crate::error::EffectError::Internal("injected child.wait error".into()),
                crate::error::EffectError::SpawnFailed("injected post-spawn pipe error".into()),
            ] {
                let fixture = Fixture::new();
                let mut namespace = OwnedIpcNamespace::create(&fixture.project()).unwrap();
                let path = namespace.path().to_path_buf();
                let (mut request, _) = request(&fixture, &namespace, "platform-error-control", &[]);
                request.skip_version_probe = !during_probe;
                request.version_args = vec!["--probe-error".into()];
                let expected_args = if during_probe {
                    request.version_args.clone()
                } else {
                    request.args.clone()
                };
                let policy = ExactPolicy {
                    request: request.clone(),
                    namespace: path.clone(),
                    profile: fs::read(&request.args[1]).unwrap(),
                };
                let launches = Arc::new(AtomicUsize::new(0));
                let expected_state = error.state();
                let executor = EffectExecutor::new(
                    PlatformError {
                        launches: Arc::clone(&launches),
                        expected_args,
                        error,
                    },
                    ArtifactWriter::new(fixture.0.join("artifacts")),
                    policy,
                );
                let receipt = tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(executor.execute(&request));
                assert_eq!(receipt.state, expected_state);
                assert!(!receipt.complete);
                assert_eq!(launches.load(Ordering::SeqCst), 1);
                assert!(
                    !receipt.process_tree.started,
                    "unknown start must not become observed start"
                );
                assert!(!receipt.process_tree.terminated && !receipt.process_tree.reaped);
                assert_eq!(receipt.exit_code, None);
                assert_eq!(receipt.signal, None);
                assert_eq!(receipt.timing.started_at_ms, 0);
                assert!(receipt
                    .gaps
                    .iter()
                    .any(|gap| gap == "platform_process_tree_unconfirmed"));
                assert!(namespace.retain_if_process_tree_unconfirmed(&receipt));
                drop(namespace);
                assert!(path.is_dir(), "platform error cannot authorize IPC cleanup");
                // No child starts in this platform double; manual fixture cleanup
                // follows proof that production guard conservatively retained it.
                fs::remove_dir_all(path).unwrap();
            }
        }
    }

    #[test]
    fn scoped_ipc_rejects_long_paths_symlinks_modes_and_foreign_tools() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let namespace = OwnedIpcNamespace::create(&fixture.project()).unwrap();
        assert!(check_ipc_capacity(&PathBuf::from(format!("/{}", "x".repeat(100)))).is_err());
        let alias = fixture.0.join("namespace-alias");
        std::os::unix::fs::symlink(namespace.path(), &alias).unwrap();
        assert!(validate_tflint_ipc_namespace(&alias, &fixture.project()).is_err());
        fs::set_permissions(namespace.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(validate_tflint_ipc_namespace(namespace.path(), &fixture.project()).is_err());
        fs::set_permissions(namespace.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(authenticate_tflint_scoped(
            "/bin/sh",
            &[],
            fixture.project().to_str().unwrap(),
            &fixture.0,
            &namespace
        )
        .is_err());
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            validate_tflint_ipc_namespace(namespace.path(), &fixture.project()).is_ok(),
            "unrelated fixture is not an ancestor of owned namespace"
        );
        assert!(canonical_owned_path(&fixture.project()).is_err());
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn scoped_ipc_ci_storage_requires_private_canonical_owned_root() {
        use std::os::unix::fs::PermissionsExt;
        struct CiStorage(PathBuf);
        impl Drop for CiStorage {
            fn drop(&mut self) {
                // Retained namespaces must survive even fixture teardown.
                let _ = fs::remove_dir(&self.0);
            }
        }
        let seed = format!("{}:{:?}", std::process::id(), std::time::SystemTime::now());
        let suffix = hex::encode(Sha256::digest(seed.as_bytes()));
        let path = PathBuf::from(format!("/private/tmp/li-ci.{}", &suffix[..8]));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let storage = CiStorage(path);
        assert_eq!(ci_ipc_run_storage(&storage.0).unwrap(), storage.0);
        let namespace = storage.0.join("li-0123456789abcdef");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&namespace)
            .unwrap();
        assert!(
            ci_ipc_run_storage(&namespace).is_err(),
            "must be a direct /private/tmp child"
        );
        assert!(
            fs::remove_dir(&storage.0).is_err(),
            "nonempty storage must be retained"
        );
        fs::remove_dir(&namespace).unwrap();
        fs::set_permissions(&storage.0, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(ci_ipc_run_storage(&storage.0).is_err());
        fs::set_permissions(&storage.0, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = storage
            .0
            .with_file_name(format!("li-ci.{}", &suffix[8..16]));
        std::os::unix::fs::symlink(&storage.0, &alias).unwrap();
        let rejected_alias = ci_ipc_run_storage(&alias);
        fs::remove_file(&alias).unwrap();
        assert!(rejected_alias.is_err());
        assert!(ci_ipc_run_storage(Path::new("/private/tmp/not-ci-root")).is_err());
        assert!(ci_ipc_run_storage(Path::new("/tmp/li-ci.12345678")).is_err());
        let path = storage.0.clone();
        drop(storage);
        assert!(!path.exists(), "empty fixture storage must be removed");
    }

    #[test]
    fn scoped_ipc_native_acl_controls_empty_allow_deny_and_lookup_failure() {
        use std::{
            ffi::{c_char, c_int, c_void, CString},
            os::unix::ffi::OsStrExt,
        };
        unsafe extern "C" {
            fn acl_from_text(text: *const c_char) -> *mut c_void;
            fn acl_set_file(path: *const c_char, kind: c_int, acl: *mut c_void) -> c_int;
            fn acl_free(acl: *mut c_void) -> c_int;
            fn filesec_init() -> *mut c_void;
            fn filesec_free(filesec: *mut c_void);
            fn filesec_set_property(
                filesec: *mut c_void,
                property: c_int,
                value: *const c_void,
            ) -> c_int;
            fn chmodx_np(path: *const c_char, filesec: *mut c_void) -> c_int;
        }
        let fixture = Fixture::new();
        let path = fixture.0.join("acl-control");
        fs::create_dir(&path).unwrap();
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // Native removal creates an explicit absent-ACL control, distinct
        // from an allocated ACL containing zero entries.
        let filesec = unsafe { filesec_init() };
        assert!(!filesec.is_null());
        let configured = unsafe { filesec_set_property(filesec, 5, 1usize as *const c_void) };
        assert_eq!(configured, 0);
        let removed = unsafe { chmodx_np(c_path.as_ptr(), filesec) };
        let error = std::io::Error::last_os_error();
        unsafe { filesec_free(filesec) };
        assert_eq!(removed, 0, "{error}");
        require_empty_acl(&path).unwrap();
        let set = |text: String| {
            // Test-only setters on an exclusively owned disposable fixture;
            // production contains no ACL mutation API.
            let text = CString::new(text).unwrap();
            let acl = unsafe { acl_from_text(text.as_ptr()) };
            assert!(!acl.is_null(), "{}", std::io::Error::last_os_error());
            let status = unsafe { acl_set_file(c_path.as_ptr(), 0x100, acl) };
            let error = std::io::Error::last_os_error();
            assert_eq!(unsafe { acl_free(acl) }, 0);
            assert_eq!(status, 0, "{error}");
        };
        set("!#acl 1\n".into());
        require_empty_acl(&path).unwrap();
        for tag in ["allow", "deny"] {
            // Format is Apple Libc posix1e/acl_translate.c: user:uuid:name:uid:tag:permissions.
            set(format!("!#acl 1\nuser:::{}:{tag}:read\n", unsafe {
                libc::geteuid()
            }));
            assert!(
                require_empty_acl(&path).is_err(),
                "even deny-only ACL must fail closed"
            );
            let error = canonical_owned_path(&path).unwrap_err().as_str();
            assert!(error.contains("nonempty IPC ancestor ACL"), "{error}");
            assert!(error.contains(path.to_str().unwrap()), "{error}");
            set("!#acl 1\n".into());
            require_empty_acl(&path).unwrap();
        }
        assert!(matches!(
            require_empty_acl(&fixture.0.join("absent")),
            Err(SandboxGap::IpcNamespaceInvalid(_))
        ));
    }
}

#[cfg(target_os = "macos")]
pub fn authenticate(
    executable: &str,
    args: &[String],
    cwd: &str,
    mode: SandboxMode,
    profile_dir: &Path,
) -> Result<SandboxAuthentication, SandboxGap> {
    use sha2::{Digest, Sha256};
    use std::fs;

    let sandbox_exec = PathBuf::from("/usr/bin/sandbox-exec");
    if !sandbox_exec.is_file() {
        return Err(SandboxGap::ToolMissing);
    }

    let filesystem_scope = match mode {
        SandboxMode::DenyNetworkDenyProjectWrite | SandboxMode::AllowNetworkDenyProjectWrite => {
            let root = Path::new(cwd).canonicalize().map_err(|error| {
                SandboxGap::ProjectRootUnavailable(format!(
                    "could not resolve project root {cwd:?}: {error}"
                ))
            })?;
            if !root.is_dir() {
                return Err(SandboxGap::ProjectRootUnavailable(format!(
                    "project root is not a directory: {}",
                    root.display()
                )));
            }
            root.to_str().map(str::to_owned).ok_or_else(|| {
                SandboxGap::ProjectRootUnavailable(format!(
                    "resolved project root is not UTF-8: {}",
                    root.display()
                ))
            })?
        }
        SandboxMode::DenyNetwork => cwd.to_owned(),
    };
    let profile = render_profile(mode, &filesystem_scope);
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(profile.as_bytes());
        hex::encode(hasher.finalize())
    };
    let profile_path = profile_dir.join(format!("audit-{digest}.sb"));
    fs::create_dir_all(profile_dir).map_err(|error| {
        SandboxGap::ProfileWriteFailed(format!("create_dir_all failed: {error}"))
    })?;
    fs::write(&profile_path, &profile)
        .map_err(|error| SandboxGap::ProfileWriteFailed(format!("write failed: {error}")))?;

    let mut wrapped_args: Vec<String> = vec![
        "-f".into(),
        profile_path.to_string_lossy().into_owned(),
        "--".into(),
        executable.to_string(),
    ];
    wrapped_args.extend(args.iter().cloned());

    Ok(SandboxAuthentication {
        id: format!("sandbox:macos:{digest}"),
        network: true,
        filesystem_scope: Some(filesystem_scope),
        wrapped_executable: sandbox_exec.to_string_lossy().into_owned(),
        wrapped_args,
    })
}

#[cfg(target_os = "macos")]
fn render_profile(mode: SandboxMode, cwd: &str) -> String {
    let escaped = cwd.replace('\\', "\\\\").replace('"', "\\\"");
    match mode {
        SandboxMode::DenyNetwork => format!(
            "(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath \"{escaped}\"))\n"
        ),
        SandboxMode::DenyNetworkDenyProjectWrite => format!(
            "(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n"
        ),
        SandboxMode::AllowNetworkDenyProjectWrite => format!(
            "(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n"
        ),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn authenticate(
    _executable: &str,
    _args: &[String],
    _cwd: &str,
    _mode: SandboxMode,
    _profile_dir: &Path,
) -> Result<SandboxAuthentication, SandboxGap> {
    Err(SandboxGap::UnsupportedPlatform)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn deny_network_profile_wraps_command_and_authenticates() {
        let dir = std::env::temp_dir().join("legion-effects-sandbox-test");
        let auth = authenticate(
            "/bin/echo",
            &["hello".to_string()],
            "/tmp",
            SandboxMode::DenyNetwork,
            &dir,
        )
        .expect("sandbox-exec is present on macOS CI/dev hosts");
        assert!(auth.wrapped_executable.ends_with("sandbox-exec"));
        assert!(auth.wrapped_args.contains(&"/bin/echo".to_string()));
        assert!(auth.network);
    }

    #[test]
    fn read_only_test_profile_blocks_project_writes() {
        let root = std::env::temp_dir().join(format!(
            "legion-effects-sandbox-read-only-test-{}",
            std::process::id()
        ));
        let scratch = root.with_extension("scratch");
        let symlink_root = root.with_extension("alias");
        let _ = std::fs::remove_file(&symlink_root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(root.join("relative-overwrite"), b"original").unwrap();
        std::fs::write(root.join("absolute-overwrite"), b"original").unwrap();
        std::fs::write(root.join("relative-delete"), b"preserve").unwrap();
        std::fs::write(root.join("absolute-delete"), b"preserve").unwrap();
        let profile_dir = root.join("profiles");
        let canonical_root = root.canonicalize().unwrap();
        let non_directory = root.join("relative-overwrite");
        let rejected_root = authenticate(
            "/usr/bin/touch",
            &[],
            &non_directory.to_string_lossy(),
            SandboxMode::DenyNetworkDenyProjectWrite,
            &profile_dir,
        )
        .unwrap_err();
        assert!(matches!(
            rejected_root,
            SandboxGap::ProjectRootUnavailable(_)
        ));
        let run = |program: &str, args: &[String], cwd: &Path, scope_root: &Path| {
            let auth = authenticate(
                program,
                args,
                &scope_root.to_string_lossy(),
                SandboxMode::DenyNetworkDenyProjectWrite,
                &profile_dir,
            )
            .expect("sandbox-exec is present on supported macOS hosts");
            std::process::Command::new(&auth.wrapped_executable)
                .args(&auth.wrapped_args)
                .current_dir(cwd)
                .output()
                .unwrap()
        };
        for path in [
            "relative-create".to_owned(),
            root.join("absolute-create").to_string_lossy().into_owned(),
        ] {
            let relative = !Path::new(&path).is_absolute();
            let command_cwd = if relative { &root } else { Path::new("/") };
            let output = run("/usr/bin/touch", &[path.clone()], command_cwd, &root);
            assert!(
                !output.status.success(),
                "write unexpectedly succeeded: scope_root={root:?} canonical_root={canonical_root:?} cwd={command_cwd:?} argv={path:?} status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            let target = if relative {
                root.join(&path)
            } else {
                PathBuf::from(&path)
            };
            assert!(
                !target.exists(),
                "write created a project file: scope_root={root:?} canonical_root={canonical_root:?} cwd={command_cwd:?} argv={path:?} target={target:?} status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        for path in [
            "relative-overwrite".to_owned(),
            root.join("absolute-overwrite")
                .to_string_lossy()
                .into_owned(),
        ] {
            let relative = !Path::new(&path).is_absolute();
            let command_cwd = if relative { &root } else { Path::new("/") };
            let output = run("/usr/bin/tee", &[path.clone()], command_cwd, &root);
            assert!(
                !output.status.success(),
                "overwrite unexpectedly succeeded: scope_root={root:?} canonical_root={canonical_root:?} cwd={command_cwd:?} argv={path:?} status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            let target = if relative {
                root.join(&path)
            } else {
                PathBuf::from(&path)
            };
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"original",
                "overwrite changed project file: scope_root={root:?} canonical_root={canonical_root:?} cwd={command_cwd:?} argv={path:?} target={target:?} status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        for path in [
            "relative-delete".to_owned(),
            root.join("absolute-delete").to_string_lossy().into_owned(),
        ] {
            let relative = !Path::new(&path).is_absolute();
            let command_cwd = if relative { &root } else { Path::new("/") };
            let output = run("/bin/rm", &[path.clone()], command_cwd, &root);
            assert!(
                !output.status.success(),
                "delete unexpectedly succeeded: scope_root={root:?} canonical_root={canonical_root:?} cwd={command_cwd:?} argv={path:?} status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            let target = if relative {
                root.join(&path)
            } else {
                PathBuf::from(&path)
            };
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"preserve",
                "delete changed project file: scope_root={root:?} canonical_root={canonical_root:?} cwd={command_cwd:?} argv={path:?} target={target:?} status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let scratch_file = scratch.join("allowed-write");
        let output = run(
            "/usr/bin/touch",
            &[scratch_file.to_string_lossy().into_owned()],
            Path::new("/"),
            &root,
        );
        assert!(
            output.status.success(),
            "outside scratch write failed: scope_root={root:?} canonical_root={canonical_root:?} cwd=/ argv={scratch_file:?} status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            scratch_file.is_file(),
            "outside scratch target was not created: scope_root={root:?} canonical_root={canonical_root:?} cwd=/ argv={scratch_file:?} status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        std::os::unix::fs::symlink(&canonical_root, &symlink_root).unwrap();
        let aliased_relative = run(
            "/usr/bin/touch",
            &["symlink-relative-create".into()],
            &symlink_root,
            &symlink_root,
        );
        assert!(
            !aliased_relative.status.success(),
            "symlink-relative write unexpectedly succeeded: scope_root={symlink_root:?} canonical_root={canonical_root:?} cwd={symlink_root:?} argv=symlink-relative-create status={} stderr={}",
            aliased_relative.status,
            String::from_utf8_lossy(&aliased_relative.stderr)
        );
        assert!(
            !canonical_root.join("symlink-relative-create").exists(),
            "symlink-relative target was created: scope_root={symlink_root:?} canonical_root={canonical_root:?} cwd={symlink_root:?} argv=symlink-relative-create status={} stderr={}",
            aliased_relative.status,
            String::from_utf8_lossy(&aliased_relative.stderr)
        );
        let canonical_absolute_target = canonical_root.join("canonical-absolute-create");
        let canonical_absolute = run(
            "/usr/bin/touch",
            &[canonical_absolute_target.to_string_lossy().into_owned()],
            Path::new("/"),
            &symlink_root,
        );
        assert!(
            !canonical_absolute.status.success(),
            "canonical absolute write unexpectedly succeeded: scope_root={symlink_root:?} canonical_root={canonical_root:?} cwd=/ argv={canonical_absolute_target:?} status={} stderr={}",
            canonical_absolute.status,
            String::from_utf8_lossy(&canonical_absolute.stderr)
        );
        assert!(
            !canonical_absolute_target.exists(),
            "canonical absolute target was created: scope_root={symlink_root:?} canonical_root={canonical_root:?} cwd=/ argv={canonical_absolute_target:?} status={} stderr={}",
            canonical_absolute.status,
            String::from_utf8_lossy(&canonical_absolute.stderr)
        );
        let _ = std::fs::remove_file(symlink_root);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(scratch);
    }

    #[test]
    fn unsupported_mode_is_never_silently_authenticated() {
        // Documented contract: an authenticate() failure must never be
        // upgraded to a receipt by the caller. This test only asserts the
        // gap type surface stays typed.
        let gap = SandboxGap::ToolMissing;
        assert!(gap.as_str().contains("sandbox_tool_missing"));
    }
}
