use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use legion_arcane::{
    BudgetGovernanceStore, KeyRing, TaskBudgetSealStore, inspect_projection, state_root,
};
use serde_json::json;
use std::path::PathBuf;

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if argv.first().map(String::as_str) != Some("inspect") {
        return Err(CommandError::usage(format!(
            "budget requires inspect (got {})",
            argv.first().map(String::as_str).unwrap_or("<none>")
        )));
    }
    let mut contract: Option<String> = None;
    let mut version: Option<u32> = None;
    let mut task: Option<String> = None;
    let mut run: Option<String> = None;
    let mut index = 1;
    while index < argv.len() {
        match argv[index].as_str() {
            "--contract" => {
                index += 1;
                contract = argv.get(index).cloned();
            }
            "--version" => {
                index += 1;
                version = argv
                    .get(index)
                    .and_then(|value| value.parse::<u32>().ok());
            }
            "--task" => {
                index += 1;
                task = argv.get(index).cloned();
            }
            "--run" => {
                index += 1;
                run = argv.get(index).cloned();
            }
            flag => return Err(CommandError::usage(format!("unknown budget option: {flag}"))),
        }
        index += 1;
    }
    let contract = contract.filter(|value| !value.is_empty()).ok_or_else(|| {
        CommandError::usage("budget inspect requires --contract <EC-#>")
    })?;
    if !contract.starts_with("EC-") {
        return Err(CommandError::usage("budget inspect requires --contract <EC-#>"));
    }
    let version = version.filter(|value| *value >= 1).ok_or_else(|| {
        CommandError::usage("budget inspect requires --version <positive integer>")
    })?;
    let task = task.filter(|value| !value.is_empty()).ok_or_else(|| {
        CommandError::usage("budget inspect requires --task <T-#(.#)*>")
    })?;
    if !task.starts_with("T-") {
        return Err(CommandError::usage("budget inspect requires --task <T-#(.#)*>"));
    }
    if std::env::var_os("ARCANE_KEY_DIR").is_none() {
        return Err(CommandError::incomplete(
            "ARC_AUTH_KEY_UNAVAILABLE: budget inspect requires ARCANE_KEY_DIR",
        ));
    }
    let key_dir = PathBuf::from(std::env::var_os("ARCANE_KEY_DIR").expect("checked above"));
    let cwd = std::env::current_dir().map_err(super::io_error)?;
    let arcane_root = state_root(&cwd);
    let key_ring = KeyRing::load_dir(&key_dir).map_err(map_arcane_error)?;
    let budget_store = BudgetGovernanceStore::new(
        arcane_root.join("budget-governance"),
        key_ring.clone(),
    );
    let task_store = TaskBudgetSealStore::new(
        arcane_root.join("task-budget-seals"),
        key_ring,
    );
    let budget = budget_store
        .require(&contract, version)
        .map_err(map_arcane_error)?;
    let task_record = task_store
        .require(&contract, &task)
        .map_err(map_arcane_error)?;
    if task_record
        .get("contractVersion")
        .and_then(|value| value.as_u64())
        != Some(version as u64)
        || task_record.get("contractDigest").is_none()
    {
        return Err(CommandError::incomplete(
            "ARC_BINDING_MISMATCH: task budget differs from requested contract version",
        ));
    }
    let projection = inspect_projection(&contract, version, &task, run.as_deref());
    if projection.get("allowed").and_then(|value| value.as_bool()) == Some(false) {
        return Err(CommandError::incomplete("budget projection is not allowed"));
    }
    Ok(json!({
        "kind": "legion-budget-inspection",
        "readOnly": true,
        "contract": budget,
        "task": task_record,
        "projection": projection,
    }))
}

fn map_arcane_error(error: legion_arcane::ArcaneError) -> CommandError {
    match error.code() {
        "ARC_AUTH_KEY_UNAVAILABLE" => CommandError::incomplete(error.to_string()),
        "ARC_BINDING_MISMATCH" | "ARC_STORE_MISSING" | "ARC_STORE_CORRUPT" => {
            CommandError::incomplete(format!("{}: {}", error.code(), error))
        }
        _ => CommandError::incomplete(format!(
            "{}: budget inspection unavailable",
            error.code()
        )),
    }
}
