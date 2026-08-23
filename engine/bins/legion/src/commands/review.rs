use super::CommandResult;
use clap::Args;
use serde_json::json;
use std::fs;
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct ReviewArgs {
    #[arg(long)]
    pub input: Option<String>,
    #[arg(long)]
    pub json: bool,
}
pub fn run(args: ReviewArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(super::CommandError::cancelled());
    }
    let input = args
        .input
        .ok_or_else(|| super::CommandError::usage("review requires --input <request.json>"))?;
    let bytes = fs::read(&input).map_err(super::io_error)?;
    let request: legion_review::AdjudicationRequest = serde_json::from_slice(&bytes)
        .map_err(|error| super::CommandError::usage(format!("invalid review request: {error}")))?;
    let (normalized, receipt) = legion_review::review(request, Vec::new())
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    if cancellation.is_cancelled() {
        return Err(super::CommandError::cancelled());
    }
    let status = if normalized.complete {
        "complete"
    } else {
        "incomplete"
    };
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-review",
        "status": status,
        "review": normalized,
        "receipt": receipt
    }))
}
