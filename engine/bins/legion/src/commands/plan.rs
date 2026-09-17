use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// Compile and seal the provider composition without executing providers.
/// Kept separate from `audit` so callers can persist a frozen plan and run it
/// in a later process.
#[derive(Debug, Args)]
pub struct PlanArgs {
    #[arg(default_value = ".", allow_hyphen_values = true)]
    pub root: PathBuf,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    pub profile: String,
}

pub async fn run(args: PlanArgs, cancellation: CancellationToken) -> CommandResult {
    if args.root.to_string_lossy().starts_with('-') {
        return Err(CommandError::usage(format!(
            "Unknown option '{}'. To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- \"{}\"",
            args.root.display(), args.root.display()
        )));
    }
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    // Without the native composition this process cannot honestly compile a
    // plan. Fail closed with a machine-readable incomplete envelope rather
    // than a stderr-only error; the exit taxonomy maps `status: incomplete`
    // to exit 2.
    let application = match super::native_application_for(&root.to_string_lossy()) {
        Ok(application) => application,
        Err(error) => {
            return Ok(json!({
                "schemaVersion": 1,
                "kind": "audit-provider-plan",
                "status": "incomplete",
                "repository": {"root": root},
                "gaps": [error.message],
            }));
        }
    };
    let signing_key = super::audit_signing_key()?;
    let result = application
        .invoke_with_cancellation(
            legion_application::NativeOperation::Plan {
                repository_id: root.to_string_lossy().into_owned(),
                providers: application.provider_specs(),
                signing_key: Some(signing_key),
            },
            cancellation,
        )
        .await
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let output = match result {
        legion_application::NativeOperationResult::Plan {
            repository_id,
            plan_digest,
            plan_signature,
            providers,
        } => json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": repository_id,
            "profile": args.profile,
            "seal": {"digest": plan_digest, "authenticity": "hmac-sha256", "signature": plan_signature},
            "providers": providers,
            "status": "complete"
        }),
        _ => {
            return Err(CommandError::internal(
                "native plan returned an incompatible result",
            ))
        }
    };
    if let Some(path) = args.out {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&output).map_err(super::io_error)?,
        )
        .map_err(super::io_error)?;
    }
    Ok(output)
}
