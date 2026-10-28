//! Native engineering diagnostics. Assessment is separate from execution and authority.
use super::{CommandError, CommandResult};
use clap::{Args, Subcommand, ValueEnum};
use legion_audit::quality_observation::{summarize_quality, QualityObservationInput};
use legion_review::rounds::{assess_review_loop, ReviewLoopInput};
use legion_runtime::{
    delivery::{assess_delivery, DeliveryAssessmentRequest, TerminalGoal},
    workplan::{parse_work_plan_json, validate_work_plan},
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

pub(super) const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Args)]
pub struct InputArgs {
    /// Versioned JSON evidence; input remains an imported assertion.
    #[arg(long)]
    pub input: PathBuf,
    /// Accepted for compatibility; these commands always emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct WorkPlanArgs {
    #[command(subcommand)]
    pub command: WorkPlanCommand,
}
#[derive(Debug, Subcommand)]
pub enum WorkPlanCommand {
    Validate(InputArgs),
}

#[derive(Debug, Args)]
pub struct ReviewLoopArgs {
    #[command(subcommand)]
    pub command: ReviewLoopCommand,
}
#[derive(Debug, Subcommand)]
pub enum ReviewLoopCommand {
    Assess(InputArgs),
}

#[derive(Debug, Args)]
pub struct DeliveryArgs {
    #[command(subcommand)]
    pub command: DeliveryCommand,
}
#[derive(Debug, Subcommand)]
pub enum DeliveryCommand {
    /// Assess one imported observation. This never merges a pull request.
    Assess(InputArgs),
    /// Perform one bounded, read-only GitHub observation; no polling or mutation.
    Observe(ObserveArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DeliveryGoal {
    UserHandoff,
    MergeRequested,
}
impl From<DeliveryGoal> for TerminalGoal {
    fn from(value: DeliveryGoal) -> Self {
        match value {
            DeliveryGoal::UserHandoff => Self::UserHandoff,
            DeliveryGoal::MergeRequested => Self::MergeRequested,
        }
    }
}

#[derive(Debug, Args)]
pub struct ObserveArgs {
    /// Explicit GitHub owner/name; credentials are never sent to another host.
    #[arg(long)]
    pub repository: String,
    #[arg(long)]
    pub pr: u64,
    #[arg(long, value_enum, default_value_t = DeliveryGoal::UserHandoff)]
    pub goal: DeliveryGoal,
    /// Frozen task head. Omit to bind this observation to the first observed head.
    #[arg(long)]
    pub head: Option<String>,
    /// Frozen task base. Omit to bind this observation to the first observed base.
    #[arg(long)]
    pub base: Option<String>,
    /// Imported, revision-bound verification and independent review evidence.
    #[arg(long)]
    pub proofs: Option<PathBuf>,
    /// Per-collection page cap. Hitting it leaves completeness false.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u16).range(1..=20))]
    pub max_pages: u16,
    /// Total observation deadline, including response bodies and pagination.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u32).range(1..=300))]
    pub timeout_seconds: u32,
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u32).range(1..=86400))]
    pub max_age_seconds: u32,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct QualityArgs {
    #[command(subcommand)]
    pub command: QualityCommand,
}
#[derive(Debug, Subcommand)]
pub enum QualityCommand {
    Summarize(QualitySummarizeArgs),
}
#[derive(Debug, Args)]
pub struct QualitySummarizeArgs {
    #[command(flatten)]
    pub input: InputArgs,
    /// Original provider report. Its actual bytes must match reportDigest.
    #[arg(long)]
    pub report: PathBuf,
}

pub(super) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, CommandError> {
    let file = File::open(path).map_err(super::io_error)?;
    if !file.metadata().map_err(super::io_error)?.is_file() {
        return Err(CommandError::usage("input must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(super::io_error)?;
    if bytes.len() as u64 > limit {
        return Err(CommandError::usage(format!("input exceeds {limit} bytes")));
    }
    Ok(bytes)
}

pub(super) fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CommandError> {
    serde_json::from_slice(bytes)
        .map_err(|error| CommandError::usage(format!("invalid engineering input: {error}")))
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// ADAPT can consume this evidence envelope without importing Legion internals.
/// Hashes bind bytes, not truth; they do not upgrade imported assertions to proof.
pub(super) fn imported(kind: &str, bytes: &[u8], assessment: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": kind,
        "provenance": {"origin": "imported", "inputDigest": digest(bytes), "authenticated": false},
        "effectAuthority": "none",
        "assessment": assessment
    })
}

pub fn work_plan(args: WorkPlanArgs) -> CommandResult {
    let WorkPlanCommand::Validate(args) = args.command;
    let bytes = read_bounded(&args.input, MAX_INPUT_BYTES)?;
    let result = parse_work_plan_json(&bytes).and_then(|plan| validate_work_plan(&plan));
    match result {
        Ok(assessment) => Ok(imported(
            "legion-work-plan-assessment",
            &bytes,
            json!(assessment),
        )),
        Err(error) => {
            let mut value = imported(
                "legion-work-plan-assessment",
                &bytes,
                json!({"error": error}),
            );
            value["valid"] = json!(false);
            Ok(value)
        }
    }
}

pub fn review_loop(args: ReviewLoopArgs) -> CommandResult {
    let ReviewLoopCommand::Assess(args) = args.command;
    let bytes = read_bounded(&args.input, MAX_INPUT_BYTES)?;
    let input: ReviewLoopInput = parse(&bytes)?;
    let assessment =
        assess_review_loop(&input).map_err(|error| CommandError::usage(error.to_string()))?;
    Ok(imported(
        "legion-review-loop-assessment",
        &bytes,
        json!(assessment),
    ))
}

pub async fn delivery(args: DeliveryArgs, cancellation: CancellationToken) -> CommandResult {
    match args.command {
        DeliveryCommand::Assess(args) => {
            let bytes = read_bounded(&args.input, MAX_INPUT_BYTES)?;
            let input: DeliveryAssessmentRequest = parse(&bytes)?;
            let assessment =
                assess_delivery(&input).map_err(|error| CommandError::usage(error.to_string()))?;
            Ok(imported(
                "legion-delivery-assessment",
                &bytes,
                json!(assessment),
            ))
        }
        DeliveryCommand::Observe(args) => super::github_observer::run(args, cancellation).await,
    }
}

pub fn quality(args: QualityArgs) -> CommandResult {
    let QualityCommand::Summarize(args) = args.command;
    let bytes = read_bounded(&args.input.input, MAX_INPUT_BYTES)?;
    let input: QualityObservationInput = parse(&bytes)?;
    let report = read_bounded(&args.report, MAX_REPORT_BYTES)?;
    if digest(&report) != input.report.report_digest {
        return Err(CommandError::integrity(
            "raw report bytes do not match reportDigest",
        ));
    }
    let summary =
        summarize_quality(&input).map_err(|error| CommandError::usage(error.to_string()))?;
    let mut value = imported("legion-quality-observation", &bytes, json!(summary));
    value["provenance"]["reportBytesMatched"] = json!(true);
    Ok(value)
}

/// Exit status reflects the diagnostic verdict, never authorization to act.
pub fn diagnostic_exit_code(value: &Value) -> Option<i32> {
    match value.get("kind")?.as_str()? {
        "legion-work-plan-assessment" => Some(if value["valid"] == false { 1 } else { 0 }),
        "legion-review-loop-assessment" => Some(match value["assessment"]["status"].as_str()? {
            "approved" => 0,
            "needs_revision" | "exhausted" => 1,
            _ => 2,
        }),
        "legion-delivery-assessment" | "legion-delivery-observation" => {
            Some(match value["assessment"]["status"].as_str()? {
                "ready_for_handoff" | "ready_for_merge_request" | "observed_merged" => 0,
                "closed_without_merge" => 1,
                _ => 2,
            })
        }
        "legion-quality-observation" => Some(match value["assessment"]["state"].as_str()? {
            "measured" => 0,
            "policyAttention" => 1,
            _ => 2,
        }),
        _ => None,
    }
}
