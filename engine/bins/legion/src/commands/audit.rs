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
    #[arg(long = "native-rule-manifest")]
    pub native_rule_manifest: Option<PathBuf>,
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_bytes: u64,
}
pub async fn run(args: AuditArgs, cancellation: CancellationToken) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let direct = args.blueprint_packet.is_some()
        || args.provider_plan.is_some()
        || !args.provider_results.is_empty();
    let signing_key = super::audit_signing_key()?;
    let native_provider_subset =
        !direct && std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_none();
    let (application, context_notices) = if direct {
        let (application, notices) = direct_application(&args, &root)?;
        (Arc::new(application), notices)
    } else if std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_some() {
        (
            super::native_application_for(&root.to_string_lossy())?,
            Vec::new(),
        )
    } else {
        let (application, notices) = native_rule_application(&args, &root)?;
        (Arc::new(application), notices)
    };
    let selected_specs = application.provider_specs();
    let blueprint_dependent = selected_specs.iter().any(|provider| {
        provider
            .consumes
            .iter()
            .any(|item| item == "blueprint-packet")
    });
    let blueprint_degradations = if context_notices.is_empty() || !blueprint_dependent {
        Vec::new()
    } else {
        let reason = if context_notices
            .iter()
            .any(|notice| notice.contains("was not provided"))
        {
            "blueprint-unavailable"
        } else {
            "blueprint-invalid"
        };
        super::audit_blueprint_degradations(&selected_specs, "audit", reason)
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
                "providerSpecs": selected_specs,
                "contextNotices": context_notices,
                "auditStatus": "incomplete",
                "qualityGate": "unproven",
                "processExecution": "not-run",
                "processState": "not-run",
                "completionValidation": "not-run",
                "gaps": ["plan-only"],
                "blueprintDegradations": blueprint_degradations
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
            if native_provider_subset {
                report
                    .gaps
                    .push("native-provider-composition-partial".into());
                report.gaps.sort();
                report.gaps.dedup();
                report.status = legion_contracts::ReportStatus::Incomplete;
                report.claims.insert(
                    "providerCoverage".into(),
                    json!({
                        "scope": "native-security-rules",
                        "fullAudit": false,
                        "plannedProviders": execution.planned_providers.clone(),
                    }),
                );
            }
            if !context_notices.is_empty() {
                report
                    .claims
                    .insert("contextNotices".into(), json!(context_notices));
            }
            if !blueprint_degradations.is_empty() {
                report.claims.insert(
                    "blueprintDegradations".into(),
                    json!(blueprint_degradations),
                );
                report.gaps.push("blueprint-degradation".into());
                report.gaps.sort();
                report.gaps.dedup();
                report.status = legion_contracts::ReportStatus::Incomplete;
            }
            let report_status = match report.status {
                legion_contracts::ReportStatus::Clean => "pass",
                legion_contracts::ReportStatus::Findings => "findings",
                legion_contracts::ReportStatus::Incomplete => "incomplete",
                legion_contracts::ReportStatus::Failed => "failed",
                legion_contracts::ReportStatus::Blocked => "blocked",
            };
            report
                .claims
                .insert("auditStatus".into(), json!(report_status));
            report.claims.insert(
                "qualityGate".into(),
                json!(if report.status == legion_contracts::ReportStatus::Clean {
                    "proven"
                } else {
                    "unproven"
                }),
            );
            report
                .claims
                .insert("processExecution".into(), json!("complete"));
            report
                .claims
                .insert("processState".into(), json!("complete"));
            report
                .claims
                .insert("completionValidation".into(), json!("not-run"));
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
                "inventoryDigest": execution.inventory_digest,
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
                "auditStatus": if !report.gaps.is_empty() { "incomplete" } else { status },
                "qualityGate": if report.gaps.is_empty() { "proven" } else { "unproven" },
                "processExecution": "complete",
                "processState": "complete",
                "completionValidation": "not-run",
                "blueprintDegradations": blueprint_degradations
            }))
        }
        _ => Err(CommandError::internal(
            "native audit application returned an incompatible result",
        )),
    }
}

fn native_rule_application(
    args: &AuditArgs,
    root: &std::path::Path,
) -> Result<(legion_application::NativeApplication, Vec<String>), CommandError> {
    let manifest = match &args.native_rule_manifest {
        Some(path) => std::fs::canonicalize(path).map_err(super::io_error)?,
        None => {
            let composition = crate::cli::installed_m1_composition()?;
            let release_root = composition.parent().ok_or_else(|| {
                CommandError::incomplete("installed composition has no release root")
            })?;
            std::fs::canonicalize(release_root.join("assets/packs/native/manifest.v1.json"))
                .map_err(|error| {
                    CommandError::incomplete(format!(
                        "installed native Audit manifest is unavailable: {error}; run legion setup repair --confirm"
                    ))
                })?
        }
    };
    let manifest_bytes = std::fs::read(&manifest).map_err(super::io_error)?;
    let manifest_digest = sha256_hex(&manifest_bytes);
    legion_rules::RuleCompiler::compile_manifest_json(
        std::str::from_utf8(&manifest_bytes).map_err(|error| {
            CommandError::usage(format!("native rule manifest is not UTF-8: {error}"))
        })?,
    )
    .map_err(|error| CommandError::usage(error.to_string()))?;
    let specification: legion_contracts::ProviderSpec = serde_json::from_value(json!({
        "schemaVersion": 2,
        "id": "security.native-rules",
        "providerVersion": "1.0.0",
        "family": "security",
        "lensIds": [],
        "role": "deterministic",
        "phase": "source",
        "dependsOn": [],
        "consumes": ["repository-inventory"],
        "produces": ["provider-result"],
        "selector": {"op": "always"},
        "denominatorKind": "repository-inventory",
        "runner": {
            "kind": "built-in",
            "implementation": "native-rule-manifest",
            "manifestDigest": format!("sha256:{manifest_digest}")
        },
        "hostCapabilities": [],
        "execution": {
            "scheduleClass": "parallel-safe",
            "resourceClaims": {"cpu": 1, "memoryMb": 256, "io": 1, "projectExecution": 0, "browser": 0, "nativeSurface": 0, "virtualMachine": 0, "simulator": 0, "physicalDevice": 0, "externalSystem": 0, "reviewer": 0, "signer": 0},
            "concurrencyKey": null,
            "maxParallelism": 1,
            "orderSensitive": false,
            "interruptible": true,
            "cachePolicy": "content-addressed",
            "failurePolicy": "block-dependents",
            "required": true
        },
        "reasoning": {"requirement": "none", "trigger": "none", "subjectKind": "provider-result", "freshContext": true, "producerSeparation": true},
        "benchmark": {"status": "source-tested", "requiredForCleanClaim": false, "qualificationDigest": format!("sha256:{manifest_digest}")},
        "cleanClaim": "finding-producing",
        "controlIds": ["security.source-assurance"],
        "scopes": ["family:security"],
        "selectable": true
    }))
    .map_err(|error| CommandError::internal(format!("native Audit provider invalid: {error}")))?;
    specification
        .validate()
        .map_err(|error| CommandError::internal(error.to_string()))?;
    let (source, notices) = super::audit_inventory_source(
        root,
        args.blueprint_packet.as_deref(),
        args.expected_generation.clone(),
    )?;
    let executor = super::rules::NativeRuleProviderExecutor::new(
        root.to_path_buf(),
        manifest,
        args.max_file_bytes,
    )
    .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let application = legion_application::NativeApplicationConfig::for_audit_executor(
        root.to_string_lossy().into_owned(),
        source,
        vec![specification],
        Arc::new(executor),
    )
    .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok((application, notices))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
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
