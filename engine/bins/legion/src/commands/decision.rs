use super::CommandResult;
use clap::Args;
use serde_json::json;
#[derive(Debug, Args)]
pub struct DecisionArgs {
    #[arg(long, default_value = "repository")]
    pub repository: String,
    #[arg(long, default_value = "workspace")]
    pub scope: String,
    #[arg(long)]
    pub task: String,
    #[arg(long)]
    pub rationale: String,
}
pub fn run(args: DecisionArgs) -> CommandResult {
    let record = legion_decisions::DecisionRecord::new(
        args.repository,
        args.scope,
        args.task,
        args.rationale,
        legion_decisions::DecisionStatus::Proposed,
    );
    Ok(json!({"schemaVersion": 1, "kind": "legion-decision", "record": record}))
}
