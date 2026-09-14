use crate::error::MinimizeError;
use crate::review::MinimizePaths;
use std::path::{Path, PathBuf};

pub fn resolve_minimize_paths() -> Result<MinimizePaths, MinimizeError> {
    let (policy, validator) = resolve_asset_pair()?;
    Ok(MinimizePaths {
        policy_path: policy,
        validator_path: validator,
    })
}

fn resolve_asset_pair() -> Result<(PathBuf, PathBuf), MinimizeError> {
    let policy_name = Path::new("lib/cognitive/arcane/policy/minimize-policy.md");
    let validator_name = Path::new("lib/cognitive/arcane/minimize.mjs");
    let candidates = release_roots();
    for root in candidates {
        let policy = root.join(policy_name);
        let validator = root.join(validator_name);
        if policy.is_file() && validator.is_file() {
            return Ok((policy, validator));
        }
    }
    Err(MinimizeError::new(
        "minimize policy and validator assets are unavailable from the installed release root",
    ))
}

fn release_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(installed) = legion_runtime::release_binding::load_installed_release() {
        if let Some(parent) = installed.manifest_path.parent() {
            roots.push(parent.to_path_buf());
            roots.push(parent.join("share").join("legion"));
            roots.push(parent.join("assets"));
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(repo_root) = manifest_dir.ancestors().nth(3) {
        roots.push(repo_root.join("src"));
        roots.push(repo_root.to_path_buf());
    }
    roots
}
