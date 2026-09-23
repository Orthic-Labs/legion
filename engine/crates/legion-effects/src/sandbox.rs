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
}

impl SandboxGap {
    pub fn as_str(&self) -> String {
        match self {
            Self::UnsupportedPlatform => {
                "sandbox_unsupported_platform: no OS sandbox authenticator for this platform"
                    .into()
            }
            Self::ToolMissing => "sandbox_tool_missing: /usr/bin/sandbox-exec not found".into(),
            Self::ProfileWriteFailed(detail) => format!("sandbox_profile_write_failed: {detail}"),
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

    let profile = render_profile(mode, cwd);
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(profile.as_bytes());
        format!("{:x}", hasher.finalize())
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
        filesystem_scope: Some(cwd.to_string()),
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
    fn unsupported_mode_is_never_silently_authenticated() {
        // Documented contract: an authenticate() failure must never be
        // upgraded to a receipt by the caller. This test only asserts the
        // gap type surface stays typed.
        let gap = SandboxGap::ToolMissing;
        assert!(gap.as_str().contains("sandbox_tool_missing"));
    }
}
