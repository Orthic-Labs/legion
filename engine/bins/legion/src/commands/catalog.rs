use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;
#[derive(Debug, Args)]
pub struct CatalogArgs {
    #[arg(default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub json: bool,
}
pub fn run(args: CatalogArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let catalog = legion_catalog::discover(&root)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok(
        json!({"schemaVersion": 1, "kind": "legion-catalog", "root": root, "entries": catalog.entries}),
    )
}
