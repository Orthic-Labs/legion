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
pub(super) fn canonical_owned_path(path: &Path) -> Result<PathBuf, SandboxGap> {
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
#[cfg(all(test, target_os = "macos"))]
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
#[cfg(all(test, target_os = "macos"))]
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

#[cfg(all(test, target_os = "macos"))]
mod storage_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::DirBuilderExt};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT_FIXTURE: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let storage = ipc_run_storage().unwrap();
            let created = (0..32).find_map(|_| {
                let sequence = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = storage.join(format!(
                    "ipc-test-{}-{:x}-{:x}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                    sequence
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => Some(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("create private storage test fixture: {error}"),
                }
            });
            Self(created.expect("unable to allocate unique private storage test fixture"))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ci_storage_requires_private_canonical_owned_root() {
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
    fn native_acl_controls_empty_allow_deny_and_lookup_failure() {
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
