use super::CommandResult;
use clap::Args;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct ResearchArgs {
    #[arg(long)]
    pub query: String,
    #[arg(long, value_delimiter = ',')]
    pub provider: Vec<String>,
    #[arg(long, default_value_t = 5)]
    pub max_hits: u32,
}
pub fn run(args: ResearchArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(super::CommandError::cancelled());
    }
    let providers = if args.provider.is_empty() {
        vec!["native".to_owned()]
    } else {
        args.provider
    };
    let request = legion_research::WorkflowRequest {
        schema_version: 1,
        query: args.query,
        source_providers: providers,
        max_hits_per_provider: args.max_hits,
        max_source_bytes: 1_000_000,
    };
    request
        .validate()
        .map_err(|error| super::CommandError::usage(error.to_string()))?;
    let workflow_cancellation = legion_research::Cancellation::new();
    let monitor_cancellation = workflow_cancellation.clone();
    let monitor_stop = monitor_cancellation.clone();
    let process_cancellation = cancellation.clone();
    let cancellation_monitor = std::thread::spawn(move || {
        while !process_cancellation.is_cancelled() && !monitor_stop.is_cancelled() {
            std::thread::sleep(Duration::from_millis(5));
        }
        if process_cancellation.is_cancelled() {
            monitor_stop.cancel();
        }
    });
    let workflow = legion_research::ResearchWorkflow::new(
        legion_research::BudgetLimits::default(),
        Instant::now() + Duration::from_secs(30),
        workflow_cancellation,
    );
    let outcome = workflow.run(request.clone());
    monitor_cancellation.cancel();
    let _ = cancellation_monitor.join();
    let outcome = outcome.map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    if cancellation.is_cancelled() {
        return Err(super::CommandError::cancelled());
    }
    let status = serde_json::to_value(outcome.status).map_err(super::io_error)?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-research",
        "status": status,
        "request": request,
        "report": outcome.report,
        "failures": outcome.failures,
        "budget": outcome.budget,
        "stages": outcome.stages
    }))
}
