use crate::error::HarnessError;
use std::path::{Path, PathBuf};

pub fn resolve_legion_root() -> Result<PathBuf, HarnessError> {
    let candidates = legion_root_candidates();
    for root in candidates {
        if root.join("skills").is_dir() || root.join("plugin").join("skills").is_dir() {
            if root.join("plugin").join("skills").is_dir() {
                return Ok(root.join("plugin"));
            }
            return Ok(root);
        }
        if root.join("src").join("registry").join("host-projection.json").is_file() {
            return Ok(root);
        }
    }
    Err(HarnessError::internal(
        "Legion product root is unavailable from the installed release binding",
    ))
}

pub fn host_projection_path(legion_root: &Path) -> PathBuf {
    let direct = legion_root.join("src").join("registry").join("host-projection.json");
    if direct.is_file() {
        return direct;
    }
    legion_root
        .join("share")
        .join("legion")
        .join("src")
        .join("registry")
        .join("host-projection.json")
}

fn legion_root_candidates() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(installed) = legion_runtime::release_binding::load_installed_release() {
        if let Some(parent) = installed.manifest_path.parent() {
            roots.push(parent.to_path_buf());
            roots.push(parent.join("plugin"));
            roots.push(parent.join("share").join("legion"));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            roots.push(parent.to_path_buf());
            roots.push(parent.join("..").join("plugin").canonicalize().unwrap_or(parent.join("..").join("plugin")));
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(repo_root) = manifest_dir.ancestors().nth(3) {
        roots.push(repo_root.to_path_buf());
    }
    roots
}
