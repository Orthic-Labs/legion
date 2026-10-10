//! Per-user, per-repository receipts root shared by the hook and Arcane.
//!
//! Receipts live in one per-user state directory keyed by repository identity,
//! never beneath whatever directory a process happened to start in.

use crate::canonical::canonical_digest;
use std::path::{Path, PathBuf};

/// Environment override honoured by every receipt writer.
pub const STATE_ROOT_ENV: &str = "LEGION_STATE_ROOT";

/// The per-user receipts directory for this platform, before repository keying.
pub fn user_state_receipts_root(
    macos: bool,
    windows: bool,
    home: Option<PathBuf>,
    user_profile: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    xdg_state_home: Option<PathBuf>,
) -> Option<PathBuf> {
    let non_empty = |value: Option<PathBuf>| value.filter(|path| !path.as_os_str().is_empty());
    if macos {
        return Some(
            non_empty(home)?
                .join("Library")
                .join("Application Support")
                .join("Orthic Labs")
                .join("Legion")
                .join("state")
                .join("receipts"),
        );
    }
    if windows {
        let base = non_empty(local_app_data).or_else(|| {
            non_empty(user_profile).map(|profile| profile.join("AppData").join("Local"))
        })?;
        return Some(
            base.join("Orthic Labs")
                .join("Legion")
                .join("state")
                .join("receipts"),
        );
    }
    let base = non_empty(xdg_state_home)
        .or_else(|| non_empty(home).map(|home| home.join(".local").join("state")))?;
    Some(base.join("legion").join("receipts"))
}

/// Receipts root for a repository identity (its cwd) under the per-user state
/// directory for the running platform.
pub fn per_user_repository_receipts_root(identity: &str) -> Option<PathBuf> {
    let digest = canonical_digest(&identity.to_string()).ok()?;
    let key = digest.trim_start_matches("sha256:");
    let key = key.get(..16).unwrap_or(key);
    let base = user_state_receipts_root(
        cfg!(target_os = "macos"),
        cfg!(windows),
        std::env::var_os("HOME").map(PathBuf::from),
        std::env::var_os("USERPROFILE").map(PathBuf::from),
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
    )?;
    Some(base.join(key))
}

/// Receipts root for `cwd`: `$LEGION_STATE_ROOT/receipts` when set, otherwise
/// the per-user, per-repository directory.
pub fn receipts_root_for_cwd(cwd: &Path) -> Option<PathBuf> {
    if let Some(root) = std::env::var_os(STATE_ROOT_ENV).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(root).join("receipts"));
    }
    per_user_repository_receipts_root(&cwd.to_string_lossy())
}
