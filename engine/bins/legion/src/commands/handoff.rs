use super::CommandResult;
use clap::Args;
use serde_json::json;
use std::path::PathBuf;
#[derive(Debug, Args)]
pub struct HandoffArgs {
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}
pub fn run(args: HandoffArgs) -> CommandResult {
    let Some(path) = args.input else {
        return Ok(
            json!({"schemaVersion": 1, "kind": "legion-handoff", "valid": false, "reason": "input is required"}),
        );
    };
    let bytes = std::fs::read(path).map_err(super::io_error)?;
    let packet: legion_handoff::HandoffPacket =
        serde_json::from_slice(&bytes).map_err(super::io_error)?;
    // Only the JSON structure is checked here. Semantic validation lives in the
    // `handoff/validate-handoff` script.
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-handoff",
        "valid": true,
        "validated": "structure-only",
        "validationCommand": "legion script handoff/validate-handoff",
        "packet": packet,
    }))
}
