use super::{CommandError, CommandResult};
use crate::cli::RootArgs;
use legion_topology::{
    inspect_components, inspect_controls, inspect_repository, inspect_stacks, inspect_targets,
    load_control_packs,
};
use std::path::PathBuf;

pub fn run_inspect(args: RootArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let packs = topology_packs()?;
    let mut value = inspect_repository(&root, &packs).map_err(CommandError::incomplete)?;
    value["__compact"] = serde_json::json!(true);
    Ok(value)
}

pub fn run_targets(args: RootArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let packs = topology_packs()?;
    let mut value = inspect_targets(&root, &packs).map_err(CommandError::incomplete)?;
    value["__compact"] = serde_json::json!(true);
    Ok(value)
}

pub fn run_components(args: RootArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let packs = topology_packs()?;
    let mut value = inspect_components(&root, &packs).map_err(CommandError::incomplete)?;
    value["__compact"] = serde_json::json!(true);
    Ok(value)
}

pub fn run_stacks(args: RootArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let packs = topology_packs()?;
    let mut value = inspect_stacks(&root, &packs).map_err(CommandError::incomplete)?;
    value["__compact"] = serde_json::json!(true);
    Ok(value)
}

pub fn run_controls(args: RootArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let packs = topology_packs()?;
    let mut value = inspect_controls(&root, &packs).map_err(CommandError::incomplete)?;
    value["__compact"] = serde_json::json!(true);
    Ok(value)
}

fn topology_packs() -> Result<Vec<serde_json::Value>, CommandError> {
    Ok(load_control_packs(&topology_assets_root()?))
}

fn topology_assets_root() -> Result<PathBuf, CommandError> {
    if let Ok(installed) = legion_runtime::release_binding::load_installed_release() {
        if let Some(parent) = installed.manifest_path.parent() {
            let assets = parent.join("assets");
            if assets.join("registry/controls/packs/index.json").is_file() {
                return Ok(assets);
            }
            let src = parent.join("src");
            if src.join("registry/controls/packs/index.json").is_file() {
                return Ok(src);
            }
        }
    }
    // A developer checkout is intentionally not a product asset source. If
    // no installed release is bound, topology remains empty/unproven.
    Ok(PathBuf::from("."))
}
