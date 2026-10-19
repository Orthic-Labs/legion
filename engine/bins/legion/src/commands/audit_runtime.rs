//! Native controlled reasoning route shared by interactive Audit & audit-bench.
use super::{CommandError, CommandResult};
use clap::Args;
use legion_audit::{
    native_providers::reasoning::followup,
    review_runtime::{self, RuntimeOptions},
};
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Debug, Clone, Args)]
pub struct RunReasoningArgs {
    #[arg(long)]
    pub run: PathBuf,
    /// Trusted installed native Claude executable (defaults to PATH resolution).
    #[arg(long)]
    pub claude: Option<PathBuf>,
    #[arg(long)]
    pub model: Option<String>,
    /// Pin native reasoning effort; unsupported hosts stop before generation.
    #[arg(long, value_parser = ["low", "medium", "high"])]
    pub reasoning_effort: Option<String>,
    /// Maximum native reviewer calls for each packet, including repairs.
    #[arg(long, default_value_t = 12, value_parser = clap::value_parser!(u32).range(1..=12))]
    pub max_calls_per_packet: u32,
    /// Generate once per source seat & once for fresh verification; never retry,
    /// repair, or request further context. Remains required after a strict call.
    #[arg(long)]
    pub strict_no_retry: bool,
}

/// Produces JSON result, always reconciles report.json/report.sarif, & runs
/// required security variants through the same controller. Incomplete is data,
/// not success: callers must check complete plus final report status/gaps.
pub async fn run(args: RunReasoningArgs) -> CommandResult {
    tokio::task::spawn_blocking(move || run_blocking(args))
        .await
        .map_err(|error| {
            CommandError::incomplete(format!("reviewer runtime task failed:{error}"))
        })?
}
fn run_blocking(args: RunReasoningArgs) -> CommandResult {
    let options = RuntimeOptions {
        claude: args.claude,
        model: args.model,
        reasoning_effort: args.reasoning_effort,
        max_calls_per_packet: args.max_calls_per_packet,
        strict_no_retry: args.strict_no_retry,
        ..Default::default()
    };
    let run = std::fs::canonicalize(&args.run)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let runtime = review_runtime::run(&run, &options);
    // Preserve accepted findings & usage even when transport/budget stops.
    let mut reconciled = review_runtime::recompute_with_partial_results(&run)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let mut output = match runtime {
        Ok(value) => value,
        Err(error) => {
            json!({"schemaVersion":1,"kind":"legion-audit-runtime","run":run,"complete":false,"status":"incomplete:reviewer-runtime","error":error.to_string()})
        }
    };
    review_runtime::project_runtime_state(&mut reconciled, &output);
    super::audit::write_run_reports(&run, &reconciled.report, 2)?;
    let mut variant = Value::Null;
    if output["dispatchStatus"] == "done"
        && matches!(
            output["status"].as_str(),
            Some("done" | "incomplete:required-evidence")
        )
        && !reconciled.confirmed_security.is_empty()
    {
        let spec = super::audit::registry_provider_spec(followup::VARIANT_PROVIDER_ID)?;
        if let Some(planned) = followup::compile_followup(&run, &spec)
            .map_err(|error| CommandError::incomplete(error.to_string()))?
        {
            let child = planned
                .plan_path
                .parent()
                .ok_or_else(|| CommandError::incomplete("follow-up directory missing"))?;
            variant = match review_runtime::run(
                child,
                &RuntimeOptions {
                    budget_run: Some(run.clone()),
                    ..options.clone()
                },
            ) {
                Ok(value) => value,
                Err(error) => {
                    json!({"complete":false,"status":"incomplete:followup-runtime","error":error.to_string()})
                }
            };
            let mut child_report = review_runtime::recompute_with_partial_results(child)
                .map_err(|error| CommandError::incomplete(error.to_string()))?;
            review_runtime::project_runtime_state(&mut child_report, &variant);
            super::audit::write_run_reports(child, &child_report.report, 2)?;
            reconciled = review_runtime::recompute_with_partial_results(&run)
                .map_err(|error| CommandError::incomplete(error.to_string()))?;
            for finding in &child_report.report.findings {
                if !reconciled
                    .report
                    .findings
                    .iter()
                    .any(|existing| existing.id == finding.id)
                {
                    reconciled.report.findings.push(finding.clone());
                }
            }
            review_runtime::project_runtime_state(&mut reconciled, &output);
            review_runtime::project_runtime_state(&mut reconciled, &variant);
            super::audit::write_run_reports(&run, &reconciled.report, 2)?;
        }
    }
    let complete = matches!(
        reconciled.report.status,
        legion_contracts::ReportStatus::Clean | legion_contracts::ReportStatus::Findings
    ) && reconciled.report.gaps.is_empty()
        && reconciled.pending.is_empty();
    output["complete"] = json!(complete);
    if complete {
        output["status"] = json!("done");
    } else if output["status"] == "done" {
        output["status"] = json!("incomplete:required-evidence");
    }
    output["followup"] = variant;
    // Follow-up transports spend against this parent ledger. Read final
    // reconciled claims rather than retaining pre-follow-up runtime totals.
    output["budget"] = reconciled
        .report
        .claims
        .get("reasoningBudget")
        .cloned()
        .unwrap_or(Value::Null);
    output["report"] = json!(run.join("report.json"));
    output["reportStatus"] = json!(reconciled.report.status);
    output["gaps"] = json!(reconciled.report.gaps);
    if complete {
        let plan: Value = serde_json::from_slice(
            &std::fs::read(run.join("plan.json"))
                .map_err(|error| CommandError::incomplete(error.to_string()))?,
        )
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
        if let Some(path) = plan
            .pointer("/reviewContext/snapshotManifest")
            .and_then(Value::as_str)
        {
            let snapshot = legion_audit::snapshot::FrozenSnapshot::open(std::path::Path::new(path))
                .map_err(|error| CommandError::incomplete(error.to_string()))?;
            let digest = plan
                .pointer("/seal/digest")
                .and_then(Value::as_str)
                .ok_or_else(|| CommandError::incomplete("plan digest missing"))?;
            legion_audit::snapshot::record_completed(&snapshot, digest, &run.join("report.json"))
                .map_err(|error| CommandError::incomplete(error.to_string()))?;
        }
    }
    let bytes = serde_json::to_vec_pretty(&output).map_err(super::io_error)?;
    std::fs::write(run.join("review-runtime.json"), bytes).map_err(super::io_error)?;
    if !complete {
        output["__json_exit_code"] = json!(2);
    }
    Ok(output)
}
