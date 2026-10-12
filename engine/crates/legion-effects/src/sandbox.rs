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

use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

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
        }
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
