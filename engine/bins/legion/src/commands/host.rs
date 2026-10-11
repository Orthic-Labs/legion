use super::CommandResult;
use clap::Args;
use serde_json::json;
use std::path::PathBuf;
#[derive(Debug, Args)]
pub struct HostArgs {
    #[arg(default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub descriptor: Option<PathBuf>,
}
pub fn run(args: HostArgs) -> CommandResult {
    // Client detection is not wired to this command, so it reports that
    // instead of an empty list that reads as "no clients detected".
    let mut result = json!({
        "schemaVersion": 1,
        "kind": "legion-host",
        "root": args.root,
        "detected": null,
        "status": "not-implemented",
        "surfaces": legion_host::SURFACES
    });
    if let Some(path) = args.descriptor {
        let bytes = std::fs::read(path).map_err(super::io_error)?;
        let descriptor = legion_host::HostDescriptor::from_json(&bytes).map_err(super::io_error)?;
        result["descriptor"] = serde_json::to_value(descriptor).map_err(super::io_error)?;
    }
    Ok(result)
}
