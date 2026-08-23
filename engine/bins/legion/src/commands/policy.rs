use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;
#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[arg(long)]
    pub file: Option<PathBuf>,
    #[arg(long)]
    pub effect: Option<String>,
    #[arg(long)]
    pub json: bool,
}
pub fn run(args: PolicyArgs) -> CommandResult {
    let Some(path) = args.file else {
        return Err(CommandError::usage("policy requires --file <policy.json>"));
    };
    let bytes = std::fs::read(&path).map_err(super::io_error)?;
    let pack: legion_policy::PolicyPack = serde_json::from_slice(&bytes)
        .map_err(|error| CommandError::policy(format!("invalid policy: {error}")))?;
    let digest = pack
        .digest()
        .map_err(|error| CommandError::policy(error.to_string()))?;
    Ok(
        json!({"schemaVersion": 1, "kind": "legion-policy", "policyId": pack.policy_id, "valid": true, "digest": digest, "effect": args.effect}),
    )
}
