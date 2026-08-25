use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::json;
use std::{path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct AuditArgs {
    #[arg(default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub plan_only: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long, default_value = "standard")]
    pub profile: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long = "blueprint-packet")]
    pub blueprint_packet: Option<PathBuf>,
    #[arg(long = "expected-generation")]
    pub expected_generation: Option<String>,
    #[arg(long = "provider-plan")]
    pub provider_plan: Option<PathBuf>,
    #[arg(long = "provider-result")]
    pub provider_results: Vec<PathBuf>,
}
pub async fn run(args: AuditArgs, cancellation: CancellationToken) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let direct = args.blueprint_packet.is_some()
        || args.provider_plan.is_some()
        || !args.provider_results.is_empty();
    if !direct && std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_none() {
        return Ok(json!({
            "schemaVersion": 1,
            "kind": if args.plan_only { "audit-provider-plan" } else { "repository-audit-report" },
            "root": root,
            "providers": [],
            "resultCount": 0,
            "gaps": ["native frozen provider composition is not connected"],
            "auditStatus": "incomplete",
        }));
    }
    let signing_key = super::audit_signing_key()?;
    let (application, context_notices) = if direct {
        let (application, notices) = direct_application(&args, &root)?;
        (Arc::new(application), notices)
    } else {
        (
            super::native_application_for(&root.to_string_lossy())?,
            Vec::new(),
        )
    };
    let operation = if args.plan_only {
        legion_application::NativeOperation::Plan {
            repository_id: root.to_string_lossy().into_owned(),
            providers: application.provider_specs(),
            signing_key: Some(signing_key.clone()),
        }
    } else {
        legion_application::NativeOperation::Audit {
            repository_id: root.to_string_lossy().into_owned(),
            providers: application.provider_specs(),
            signing_key: Some(signing_key),
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
            plan_signature,
            providers,
        } => {
            let output = json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": repository_id,
            "profile": args.profile,
            "planDigest": plan_digest,
                "planSignature": plan_signature,
                "providers": providers,
                "contextNotices": context_notices,
                "auditStatus": "complete"
            });
            if let Some(out) = &args.out {
                write_artifact(
                    out,
                    "plan.json",
                    &serde_json::to_vec_pretty(&output).map_err(super::io_error)?,
                )?;
            }
            Ok(output)
        }
        legion_application::NativeOperationResult::Audit(execution) => {
            let mut report = legion_audit::canonical_report(&root.to_string_lossy(), &execution)
                .map_err(|error| CommandError::integrity(error.to_string()))?;
            if !context_notices.is_empty() {
                report
                    .claims
                    .insert("contextNotices".into(), json!(context_notices));
            }
            let report_json = legion_report::render_json(&report).map_err(super::io_error)?;
            let report_sarif = legion_report::render_sarif(&report).map_err(super::io_error)?;
            if let Some(out) = &args.out {
                write_artifact(out, "report.json", report_json.as_bytes())?;
                write_artifact(out, "report.sarif", report_sarif.as_bytes())?;
                write_artifact(
                    out,
                    "execution.json",
                    &serde_json::to_vec_pretty(&execution).map_err(super::io_error)?,
                )?;
            }
            let status = match report.status {
                legion_contracts::ReportStatus::Clean => "pass",
                legion_contracts::ReportStatus::Findings => "findings",
                legion_contracts::ReportStatus::Incomplete => "incomplete",
                legion_contracts::ReportStatus::Failed => "failed",
                legion_contracts::ReportStatus::Blocked => "blocked",
            };
            Ok(json!({
                "schemaVersion": 1,
                "kind": "repository-audit-report",
                "root": root,
                "profile": args.profile,
                "planDigest": execution.plan_digest,
                "planSignature": execution.plan_signature,
                "generation": execution.generation,
                "plannedProviders": execution.planned_providers,
                "resultCount": execution.results.len(),
                "findingCount": report.findings.len(),
                "selectedLenses": execution.selected_lenses,
                "lensesRan": execution.lenses_ran,
                "contextNotices": context_notices,
                "gaps": report.gaps,
                "artifacts": args.out.as_ref().map(|out| json!({
                    "reportJson": out.join("report.json"),
                    "reportSarif": out.join("report.sarif"),
                    "execution": out.join("execution.json")
                })),
                "auditStatus": status
            }))
        }
        _ => Err(CommandError::internal(
            "native audit application returned an incompatible result",
        )),
    }
}

fn direct_application(
    args: &AuditArgs,
    root: &std::path::Path,
) -> Result<(legion_application::NativeApplication, Vec<String>), CommandError> {
    let plan = args
        .provider_plan
        .as_ref()
        .ok_or_else(|| CommandError::usage("direct Audit requires --provider-plan"))?;
    if args.provider_results.is_empty() {
        return Err(CommandError::usage(
            "direct Audit requires at least one --provider-result",
        ));
    }
    let (source, context_notices) = super::audit_inventory_source(
        root,
        args.blueprint_packet.as_deref(),
        args.expected_generation.clone(),
    )?;
    let specifications = read_provider_plan(plan)?;
    let results = args
        .provider_results
        .iter()
        .map(|path| read_provider_result(path))
        .collect::<Result<Vec<_>, _>>()?;
    let application = legion_application::NativeApplicationConfig::for_audit_artifacts(
        root.to_string_lossy().into_owned(),
        source,
        specifications,
        results,
    )
    .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok((application, context_notices))
}

fn read_provider_plan(
    path: &std::path::Path,
) -> Result<Vec<legion_contracts::ProviderSpec>, CommandError> {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).map_err(super::io_error)?)
            .map_err(|error| CommandError::usage(format!("invalid provider plan: {error}")))?;
    let providers = value
        .as_array()
        .or_else(|| value.get("providers").and_then(serde_json::Value::as_array))
        .ok_or_else(|| {
            CommandError::usage("provider plan must be an array or contain providers")
        })?;
    providers
        .iter()
        .cloned()
        .map(|provider| {
            serde_json::from_value(provider).map_err(|error| {
                CommandError::usage(format!("invalid provider specification: {error}"))
            })
        })
        .collect()
}

fn read_provider_result(
    path: &std::path::Path,
) -> Result<legion_contracts::ProviderResult, CommandError> {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).map_err(super::io_error)?)
            .map_err(|error| CommandError::usage(format!("invalid provider result: {error}")))?;
    let result = value.get("providerResult").cloned().unwrap_or(value);
    serde_json::from_value(result)
        .map_err(|error| CommandError::usage(format!("invalid provider result contract: {error}")))
}

fn write_artifact(root: &std::path::Path, name: &str, bytes: &[u8]) -> Result<(), CommandError> {
    std::fs::create_dir_all(root).map_err(super::io_error)?;
    let destination = root.join(name);
    let temporary = root.join(format!(".{name}.tmp-{}", std::process::id()));
    std::fs::write(&temporary, bytes).map_err(super::io_error)?;
    std::fs::rename(&temporary, destination).map_err(super::io_error)
}
