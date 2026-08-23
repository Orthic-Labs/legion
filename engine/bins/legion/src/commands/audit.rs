use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct AuditArgs {
    #[arg(default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub plan_only: bool,
    #[arg(long)]
    pub json: bool,
}
pub async fn run(args: AuditArgs, cancellation: CancellationToken) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let application = super::native_application_for(&root.to_string_lossy())?;
    let operation = if args.plan_only {
        legion_application::NativeOperation::Plan {
            repository_id: root.to_string_lossy().into_owned(),
            providers: application.provider_specs(),
            signing_key: None,
        }
    } else {
        legion_application::NativeOperation::Audit {
            repository_id: root.to_string_lossy().into_owned(),
            providers: application.provider_specs(),
            signing_key: None,
        }
    };
    let result = application
        .invoke_with_cancellation(operation, cancellation)
        .await
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    match result {
        legion_application::NativeOperationResult::Plan {
            repository_id,
            plan_digest,
            providers,
        } => Ok(json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": repository_id,
            "planDigest": plan_digest,
            "providers": providers,
            "auditStatus": "complete"
        })),
        legion_application::NativeOperationResult::Audit(report) => Ok(json!({
            "schemaVersion": 1,
            "kind": "repository-audit-report",
            "root": root,
            "planDigest": report.plan_digest,
            "generation": report.generation,
            "resultCount": report.results.len(),
            "gaps": report.gaps,
            "auditStatus": if report.gaps.is_empty() { "pass" } else { "incomplete" }
        })),
        _ => Err(CommandError::internal(
            "native audit application returned an incompatible result",
        )),
    }
}
