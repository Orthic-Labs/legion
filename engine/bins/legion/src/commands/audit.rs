use super::{CommandError, CommandResult};
use clap::Args;
use legion_audit::InventorySource as _;
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct AuditArgs {
    #[arg(default_value = ".", allow_hyphen_values = true)]
    pub root: PathBuf,
    #[arg(long)]
    pub plan_only: bool,
    #[arg(long)]
    pub quiet: bool,
    #[arg(long = "only")]
    pub only: Vec<String>,
    #[arg(long = "skip")]
    pub skip: Vec<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub surfaces: Option<String>,
    #[arg(long = "visual-spec")]
    pub visual_spec: Option<PathBuf>,
    #[arg(long = "visual-baselines")]
    pub visual_baselines: Option<PathBuf>,
    #[arg(long, default_value_t = 1280)]
    pub width: u32,
    #[arg(long, default_value_t = 800)]
    pub height: u32,
    #[arg(long)]
    pub r#type: Option<String>,
    #[arg(long)]
    pub base: Option<String>,
    #[arg(long = "base-commit")]
    pub base_commit: Option<String>,
    #[arg(long)]
    pub dir: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
    #[arg(long, default_value = "standard")]
    pub profile: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long = "provider-plan")]
    pub provider_plan: Option<PathBuf>,
    #[arg(long = "provider-result")]
    pub provider_results: Vec<PathBuf>,
    /// Run only the explicitly supplied native rule manifest as an incomplete
    /// source diagnostic. This is never a fallback for a missing full registry.
    #[arg(long = "native-rule-manifest", conflicts_with_all = ["provider_plan", "provider_results"])]
    pub native_rule_manifest: Option<PathBuf>,
    /// `legion audit ingest --run <dir> --provider <id> --result <file>`: ingest a
    /// reasoning-lens result into a frozen run (see `ingest_command`).
    #[arg(long = "run", hide = true)]
    pub ingest_run: Option<PathBuf>,
    #[arg(long = "provider", hide = true)]
    pub ingest_provider: Option<String>,
    #[arg(long = "result", hide = true)]
    pub ingest_result: Option<PathBuf>,
    /// `legion audit ingest --run <dir> --followup`: (re)compile the security
    /// variant-analysis follow-up plan under `<dir>/followup/` for the run's
    /// confirmed findings. With `--provider`/`--result` the result is ingested
    /// into that follow-up instead (see `ingest_command`).
    #[arg(long = "followup", hide = true)]
    pub followup: bool,
}
pub async fn run(args: AuditArgs, cancellation: CancellationToken) -> CommandResult {
    if args.root.as_os_str() == "ingest"
        && (args.ingest_run.is_some()
            || args.ingest_provider.is_some()
            || args.ingest_result.is_some()
            || args.followup)
    {
        return ingest_command(&args);
    }
    if args.root.to_string_lossy().starts_with('-') {
        return Err(CommandError::usage(format!(
            "Unknown option '{}'. To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- \"{}\"",
            args.root.display(), args.root.display()
        )));
    }
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    // Node parity: diff scope (--type/--base/--base-commit/--dir) is resolved
    // exactly like tools/audit/collect-facts.mjs scopeFor/changedFiles and
    // recorded in the plan and facts documents. It never changes the frozen
    // provider denominator — matching Node, where scope annotates facts
    // instead of filtering. A ref Node's gitRef would reject is recorded raw in
    // the plan; the facts document then omits scope and the run is incomplete,
    // mirroring Node's crashed facts collection without a CLI-level error.
    let scope = audit_scope(&root, &args);
    let direct = args.provider_plan.is_some() || !args.provider_results.is_empty();
    // Digest of the run's epoch key when that key (not a host-injected one)
    // also signs the plan; `legion verify` reloads it from `<out>/epoch.key`.
    let mut run_epoch_digest: Option<String> = None;
    let signing_key = if args.plan_only {
        Some(super::audit_signing_key()?)
    } else {
        match std::env::var_os("AUDIT_PLAN_SIGNING_KEY").filter(|value| !value.is_empty()) {
            Some(value) => Some(value.to_string_lossy().as_bytes().to_vec()),
            // A run written to `--out` is signed with the run's epoch key
            // (persisted 0600 as `epoch.key`), so lens packets can be ingested
            // and the run verified later without any extra environment.
            None => match args.out.as_ref() {
                Some(out) => {
                    let ingest =
                        legion_audit::native_providers::reasoning::ingest::create_epoch(out)
                            .and_then(|_| {
                                legion_audit::native_providers::reasoning::ingest::load_epoch(out)
                            })
                            .map_err(|error| {
                                CommandError::incomplete(format!(
                                    "could not create the run epoch key: {error}"
                                ))
                            })?;
                    run_epoch_digest = Some(ingest.1);
                    Some(ingest.0)
                }
                None => None,
            },
        }
    };
    let (application, context_notices) = if direct {
        let (application, notices) = direct_application(&args, &root)?;
        (Arc::new(application), notices)
    } else if let Some(manifest) = &args.native_rule_manifest {
        let (application, notices) = native_rule_diagnostic_application(&args, &root, manifest)?;
        (Arc::new(application), notices)
    } else if std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_some() {
        (
            super::native_application_for(&root.to_string_lossy())?,
            Vec::new(),
        )
    } else {
        let (application, notices) = native_registry_application(&root)?;
        (Arc::new(application), notices)
    };
    let mut selected_specs = application.provider_specs();
    let configured_ids = selected_specs
        .iter()
        .map(|provider| provider.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for requested in args.only.iter().chain(args.skip.iter()) {
        if !configured_ids.contains(requested.as_str()) {
            return Err(CommandError::usage(format!(
                "unknown provider: {requested}"
            )));
        }
    }
    // Keep provider selection deterministic and equivalent to audit-run's
    // repeated --only/--skip flags. Filtering happens before plan compilation,
    // therefore excluded providers cannot affect frozen denominators or DAG.
    selected_specs = filter_provider_specs(selected_specs, &args);
    if selected_specs.is_empty() {
        return Err(CommandError::usage(
            "provider selection produced an empty plan",
        ));
    }
    let review_context = review_context(&root, &scope);
    for provider in &mut selected_specs {
        if let Some(reasoning) = provider.reasoning.as_object_mut() {
            reasoning.insert("reviewContext".into(), review_context.clone());
        } else {
            let source = provider.reasoning.clone();
            provider.reasoning = json!({
                "source": source,
                "reviewContext": review_context.clone(),
            });
        }
    }
    let operation = if args.plan_only {
        legion_application::NativeOperation::Plan {
            repository_id: root.to_string_lossy().into_owned(),
            providers: selected_specs.clone(),
            signing_key: signing_key.clone(),
        }
    } else {
        legion_application::NativeOperation::Audit {
            repository_id: root.to_string_lossy().into_owned(),
            providers: selected_specs.clone(),
            signing_key: signing_key.clone(),
        }
    };
    // Freeze the lens basis (plan + inventory) before any scanner runs, so lens
    // packets are built from the exact inventory the executed plan was frozen over
    // rather than a re-walk that scanner scratch output could perturb.
    let lens_basis = freeze_lens_basis(&root, &selected_specs, signing_key.as_deref());
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
            let binding = native_inventory_binding(&root, &args)?;
            let (lens_work, lens_work_gaps) = lens_work_items(
                &root,
                &lens_basis,
                plan_digest.as_str(),
                args.out.as_deref(),
                None,
            );
            let mut input_gaps = native_audit_input_gaps(&args);
            input_gaps.extend(lens_work_gaps);
            let output = json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": repository_id,
            "profile": args.profile,
            "scope": scope.plan_json(),
            "planDigest": plan_digest.clone(),
                "planSignature": plan_signature.clone(),
                "seal": {"digest": plan_digest, "authenticity": "hmac-sha256", "signature": plan_signature},
                "binding": binding,
                "providers": providers,
                "providerSpecs": selected_specs,
                "contextNotices": context_notices,
                "auditStatus": "incomplete",
                "qualityGate": "unproven",
                "processExecution": "not-run",
                "processState": "not-run",
                "completionValidation": "not-run",
                "gaps": ["plan-only"],
                "lensWork": lens_work,
                "inputGaps": input_gaps
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
            let parity_gaps = native_audit_parity_gaps(
                execution.planned_providers.len(),
                execution.results.len(),
                &execution.plan_digest,
                execution.plan_signature.as_deref(),
            );
            report.gaps.extend(parity_gaps);
            report.gaps.extend(native_audit_input_gaps(&args));
            // Reasoning lenses no in-process host executed are `pending-host`
            // work: emit their packets for the invoking session to run.
            let (lens_work, lens_work_gaps) = if execution.pending_host.is_empty() {
                (Vec::new(), Vec::new())
            } else {
                lens_work_items(
                    &root,
                    &lens_basis,
                    execution.plan_digest.as_str(),
                    args.out.as_deref(),
                    Some(&execution),
                )
            };
            report.gaps.extend(lens_work_gaps);
            report.claims.insert("lensWork".into(), json!(lens_work));
            // The CLI process is the trusted reasoning host for ingest: generate this
            // run's epoch key (0600, never in a report) and record only its digest.
            let epoch_digest = match (&args.out, execution.pending_host.is_empty()) {
                // The epoch key already signs this run's plan; regenerating it
                // would orphan the plan signature.
                (Some(_), false) if run_epoch_digest.is_some() => run_epoch_digest.clone(),
                (Some(out), false) => {
                    match legion_audit::native_providers::reasoning::ingest::create_epoch(out) {
                        Ok(digest) => Some(digest),
                        Err(error) => {
                            report.gaps.push(format!("lens-epoch-unavailable:{error}"));
                            None
                        }
                    }
                }
                _ => None,
            };
            if let Some(digest) = &epoch_digest {
                report
                    .claims
                    .insert("reasoningEpochDigest".into(), json!(digest));
            }
            if scope.facts_unavailable {
                // Node: collect-facts crashes on a gitRef-rejected ref, facts are
                // written without scope, and the run is incomplete (exit 2).
                report.gaps.push("audit-scope-facts-unavailable".into());
            }
            report.gaps.sort();
            report.gaps.dedup();
            if !report.gaps.is_empty() {
                report.status = legion_contracts::ReportStatus::Incomplete;
            }
            report.claims.insert(
                "providerCoverage".into(),
                json!({
                    "scope": "frozen-native-provider-plan",
                    "fullAudit": report.gaps.is_empty(),
                    "plannedProviders": execution.planned_providers.clone(),
                    "executedProviders": execution.results.len(),
                    "sourcePort": ["tools/audit/audit-complete.mjs", "tools/audit/audit-run.mjs", "tools/audit/audit-finalize.mjs"],
                }),
            );
            if !context_notices.is_empty() {
                report
                    .claims
                    .insert("contextNotices".into(), json!(context_notices));
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
                let plan = json!({
                    "schemaVersion": 1,
                    "kind": "audit-provider-plan",
                    "repository": root,
                    "profile": args.profile,
                    "scope": scope.plan_json(),
                    "binding": {
                        "repositoryRevision": execution.generation,
                        "inventoryDigest": execution.inventory_digest,
                    },
                    "seal": {
                        "digest": execution.plan_digest,
                        "authenticity": if execution.plan_signature.is_some() { "hmac-sha256" } else { "unsigned" },
                        "signature": execution.plan_signature,
                    },
                    "providers": execution.planned_providers,
                    "epoch": epoch_digest.as_ref().map(|digest| json!({"digest": digest, "keyFile": "epoch.key"})),
                });
                let facts = native_facts_document(&root, &plan, &execution, &report, &scope);
                write_artifact(
                    out,
                    "plan.json",
                    &serde_json::to_vec_pretty(&plan).map_err(super::io_error)?,
                )?;
                write_artifact(out, "report.json", report_json.as_bytes())?;
                write_artifact(out, "report.sarif", report_sarif.as_bytes())?;
                write_artifact(
                    out,
                    "facts.json",
                    &serde_json::to_vec_pretty(&facts).map_err(super::io_error)?,
                )?;
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
                "scope": scope.plan_json(),
                "planDigest": execution.plan_digest,
                "planSignature": execution.plan_signature,
                "generation": execution.generation,
                "inventoryDigest": execution.inventory_digest,
                "plannedProviders": execution.planned_providers,
                "resultCount": execution.results.len(),
                "findingCount": report.findings.len(),
                "selectedLenses": execution.selected_lenses,
                "lensesRan": execution.lenses_ran,
                "reasoningLensesRan": execution.lenses_ran,
                "reasoningLensesPending": execution.pending_host,
                "coverageNotes": execution.coverage_notes,
                "reasoningEpochDigest": epoch_digest,
                "deterministicLensTagCounts": execution.deterministic_lens_tags,
                "lensWork": lens_work,
                "contextNotices": context_notices,
                "gaps": report.gaps,
                "artifacts": args.out.as_ref().map(|out| json!({
                    "plan": out.join("plan.json"),
                    "reportJson": out.join("report.json"),
                    "reportSarif": out.join("report.sarif"),
                    "facts": out.join("facts.json"),
                    "execution": out.join("execution.json")
                })),
                "auditStatus": if !report.gaps.is_empty() { "incomplete" } else { status },
                "qualityGate": if status == "pass" && report.gaps.is_empty() { "proven" } else { "unproven" },
                "processExecution": "complete",
                "processState": "complete",
                "completionValidation": "not-run"
            }))
        }
        _ => Err(CommandError::internal(
            "native audit application returned an incompatible result",
        )),
    }
}

/// `legion audit ingest --run <dir> --provider <id> --result <file>`.
///
/// The CLI process is the trusted reasoning host: it validates the subagent's
/// lens result against the frozen run (packet, plan, verbatim code anchors),
/// mints a MAC'd receipt under the run's epoch key, and rewrites the run's
/// report with the recomputed verdict.
///
/// Security variant analysis cannot run inside the parent plan (its
/// denominator is frozen empty), so when the ingest leaves confirmed security
/// findings the CLI also compiles the follow-up plan under `<run>/followup/`
/// and emits the variant lens packet (`followup` in the output). Then:
///
/// * `legion audit ingest --run <dir> --followup` (re)compiles that follow-up
///   explicitly and ingests nothing;
/// * `legion audit ingest --run <dir> --followup --provider
///   legacy.security.variant-analysis --result <file>` ingests the variant
///   result into the follow-up and recomputes the parent report, whose
///   `security-variant-analysis-pending` gap clears only when the follow-up is
///   complete and its digest chain verifies.
fn ingest_command(args: &AuditArgs) -> CommandResult {
    use legion_audit::native_providers::reasoning::{followup, ingest};
    let run = args
        .ingest_run
        .clone()
        .ok_or_else(|| CommandError::usage("legion audit ingest requires --run <dir>"))?;
    let absolute = |path: PathBuf| -> Result<PathBuf, CommandError> {
        if path.is_absolute() {
            Ok(path)
        } else {
            Ok(std::env::current_dir().map_err(super::io_error)?.join(path))
        }
    };
    let run = absolute(run)?;
    let into_followup = args.followup && args.ingest_provider.is_some();
    if args.followup && args.ingest_provider.is_none() && args.ingest_result.is_none() {
        // Explicit follow-up (re)compilation.
        let follow = plan_followup(&run);
        let recomputed = ingest::recompute_run(&run)
            .map_err(|error| CommandError::integrity(error.to_string()))?;
        write_run_reports(&run, &recomputed.report)?;
        return Ok(ingest_output(&run, None, &recomputed, follow));
    }
    let provider = args
        .ingest_provider
        .clone()
        .ok_or_else(|| CommandError::usage("legion audit ingest requires --provider <id>"))?;
    let result = args
        .ingest_result
        .clone()
        .ok_or_else(|| CommandError::usage("legion audit ingest requires --result <file>"))?;
    let result = absolute(result)?;
    if into_followup {
        if provider != followup::VARIANT_PROVIDER_ID {
            return Err(CommandError::usage(format!(
                "--followup ingests {} results only",
                followup::VARIANT_PROVIDER_ID
            )));
        }
        let dir = run.join(followup::FOLLOWUP_DIR);
        if !followup::exists(&run) {
            return Err(CommandError::usage(
                "this run has no follow-up plan; run `legion audit ingest --run <dir> --followup` first",
            ));
        }
        let ingested = ingest::ingest_lens_result_file(&dir, &provider, &result)
            .map_err(|error| CommandError::usage(error.to_string()))?;
        let inner = ingest::recompute_run(&dir)
            .map_err(|error| CommandError::integrity(error.to_string()))?;
        write_run_reports(&dir, &inner.report)?;
        let recomputed = ingest::recompute_run(&run)
            .map_err(|error| CommandError::integrity(error.to_string()))?;
        write_run_reports(&run, &recomputed.report)?;
        let follow = json!({
            "status": recomputed.report.claims.get("securityVariantFollowup")
                .and_then(|claim| claim.get("status")).cloned().unwrap_or(Value::Null),
            "claim": recomputed.report.claims.get("securityVariantFollowup"),
            "run": dir,
            "ingested": ingested,
            "gaps": inner.report.gaps,
        });
        return Ok(ingest_output(&run, None, &recomputed, follow));
    }
    let ingested = ingest::ingest_lens_result_file(&run, &provider, &result)
        .map_err(|error| CommandError::usage(error.to_string()))?;
    // Confirmed findings from this ingest get their follow-up compiled now.
    let follow = plan_followup(&run);
    let recomputed =
        ingest::recompute_run(&run).map_err(|error| CommandError::integrity(error.to_string()))?;
    write_run_reports(&run, &recomputed.report)?;
    Ok(ingest_output(&run, Some(ingested), &recomputed, follow))
}

fn write_run_reports(
    dir: &std::path::Path,
    report: &legion_contracts::ReportV1,
) -> Result<(), CommandError> {
    let report_json = legion_report::render_json(report).map_err(super::io_error)?;
    let report_sarif = legion_report::render_sarif(report).map_err(super::io_error)?;
    write_artifact(dir, "report.json", report_json.as_bytes())?;
    write_artifact(dir, "report.sarif", report_sarif.as_bytes())
}

/// Compiles the variant-analysis follow-up when the run has confirmed security
/// findings. Never fails the caller: the parent report keeps its
/// `security-variant-analysis-pending` gap and `status: error` says why.
fn plan_followup(run: &std::path::Path) -> Value {
    use legion_audit::native_providers::reasoning::followup;
    // No confirmed finding, no follow-up (and no registry lookup).
    match legion_audit::native_providers::reasoning::ingest::recompute_run(run) {
        Ok(recomputed) if recomputed.confirmed_security.is_empty() => {
            return json!({"status": "none", "reason": "no confirmed security finding"});
        }
        Ok(_) => {}
        Err(error) => return json!({"status": "error", "reason": error.to_string()}),
    }
    let planned = registry_provider_spec(followup::VARIANT_PROVIDER_ID)
        .map_err(|error| error.message)
        .and_then(|spec| followup::compile_followup(run, &spec).map_err(|error| error.to_string()));
    match planned {
        Ok(Some(planned)) => json!({
            "status": if planned.reused { "reused" } else { "planned" },
            "plan": planned.plan_path,
            "planDigest": planned.plan_digest,
            "parentPlanDigest": planned.parent_plan_digest,
            "confirmedPaths": planned.confirmed_paths,
            "seeds": planned.seeds,
            "provider": planned.provider,
            "packet": planned.packet,
            "packetDigest": planned.packet_digest,
            "next": format!(
                "run the variant-analysis lens packet, then: legion audit ingest --run {} --followup --provider {} --result <file>",
                run.display(),
                planned.provider
            ),
        }),
        Ok(None) => json!({"status": "none", "reason": "no confirmed security finding"}),
        Err(reason) => json!({"status": "error", "reason": reason}),
    }
}

fn ingest_output(
    run: &std::path::Path,
    ingested: Option<legion_audit::native_providers::reasoning::ingest::IngestedLens>,
    recomputed: &legion_audit::native_providers::reasoning::ingest::Recomputed,
    followup: Value,
) -> Value {
    let status = match recomputed.report.status {
        legion_contracts::ReportStatus::Clean => "pass",
        legion_contracts::ReportStatus::Findings => "findings",
        legion_contracts::ReportStatus::Incomplete => "incomplete",
        legion_contracts::ReportStatus::Failed => "failed",
        legion_contracts::ReportStatus::Blocked => "blocked",
    };
    json!({
        "schemaVersion": 1,
        "kind": "audit-lens-ingest",
        "run": run,
        "ingested": ingested,
        "ingestedLenses": recomputed.ingested,
        "reasoningLensesPending": recomputed.pending,
        "confirmedSecurity": recomputed.confirmed_security,
        "followup": followup,
        "findingCount": recomputed.report.findings.len(),
        "gaps": recomputed.report.gaps,
        "coverageNotes": recomputed.execution.coverage_notes,
        "auditStatus": status,
        "qualityGate": if status == "pass" { "proven" } else { "unproven" },
        "report": run.join("report.json"),
    })
}

/// A provider spec from the native registry by id (no application is built).
fn registry_provider_spec(id: &str) -> Result<legion_contracts::ProviderSpec, CommandError> {
    let registry = native_provider_registry_path()
        .ok_or_else(|| CommandError::incomplete("native Audit provider registry is unavailable"))?;
    let value: Value = serde_json::from_slice(&std::fs::read(&registry).map_err(super::io_error)?)
        .map_err(|error| CommandError::usage(format!("invalid provider registry: {error}")))?;
    let spec = value
        .get("providers")
        .and_then(Value::as_array)
        .and_then(|providers| {
            providers
                .iter()
                .find(|provider| provider.get("id").and_then(Value::as_str) == Some(id))
        })
        .cloned()
        .ok_or_else(|| CommandError::usage(format!("provider {id} is not in the registry")))?;
    serde_json::from_value(spec)
        .map_err(|error| CommandError::usage(format!("invalid provider specification: {error}")))
}

/// Frozen plan and the inventory it was compiled over, captured before execution.
type LensBasis = Result<(legion_audit::FrozenPlan, legion_audit::InventoryEnvelope), String>;

fn freeze_lens_basis(
    root: &std::path::Path,
    specs: &[legion_contracts::ProviderSpec],
    signing_key: Option<&[u8]>,
) -> LensBasis {
    let source = super::audit_inventory_source(root).map_err(|error| error.message)?;
    let inventory = source
        .inventory(&root.to_string_lossy())
        .map_err(|error| error.to_string())?;
    let pending = legion_audit::AuditPlan::compile_with_root(Some(root), &inventory, specs)
        .map_err(|error| error.to_string())?;
    let plan = match signing_key {
        Some(key) => pending.freeze(Some(key)),
        None => pending.freeze_source_diagnostic(),
    }
    .map_err(|error| error.to_string())?;
    Ok((plan, inventory))
}

/// `pending-host` reasoning-lens work items for the frozen plan, with the full
/// lens packet written to `<out>/lens-packets/<provider>.json` when `--out` is
/// given. A packet failure is returned as a gap, never as a command error.
fn lens_work_items(
    root: &std::path::Path,
    basis: &LensBasis,
    executed_plan_digest: &str,
    out: Option<&std::path::Path>,
    execution: Option<&legion_audit::ExecutionReport>,
) -> (Vec<Value>, Vec<String>) {
    let built = (|| -> Result<Vec<Value>, String> {
        let (plan, inventory) = basis.as_ref().map_err(Clone::clone)?;
        if executed_plan_digest != plan.digest() {
            return Err("plan digest differs from the executed plan".into());
        }
        // The security adjudicator closes scanner candidates, so it needs the
        // executed scanner results; a plan-only run has none (`None`).
        let candidates = execution.map(|execution| {
            legion_audit::native_providers::reasoning::scanner_candidates_from_execution(
                root, plan, execution,
            )
        });
        let work = legion_audit::native_providers::reasoning::pending_lens_work_with_candidates(
            root,
            plan,
            inventory,
            candidates.as_deref(),
        )
        .map_err(|error| error.to_string())?;
        let mut items = Vec::new();
        for item in work {
            let file = format!("{}.json", item.provider_id);
            let packet_digest = legion_contracts::canonical_digest(&item.request.packet)
                .map_err(|error| error.to_string())?;
            let packet = out.map(|out| out.join("lens-packets").join(&file));
            if let Some(out) = out {
                let bytes = serde_json::to_vec_pretty(&item).map_err(|error| error.to_string())?;
                write_artifact(&out.join("lens-packets"), &file, &bytes)
                    .map_err(|error| error.message)?;
            }
            items.push(json!({
                "provider": item.provider_id,
                "lensIds": item.lens_ids,
                "status": "pending-host",
                "packet": packet,
                "packetDigest": packet_digest,
                "planDigest": item.request.plan_digest,
            }));
        }
        Ok(items)
    })();
    match built {
        Ok(items) => (items, Vec::new()),
        Err(message) => (
            Vec::new(),
            vec![format!("lens-packets-unavailable:{message}")],
        ),
    }
}

fn validate_output_dir(
    root: &std::path::Path,
    requested: &std::path::Path,
) -> Result<(), CommandError> {
    let base = std::env::current_dir().map_err(super::io_error)?;
    let output = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        base.join(requested)
    };
    let output = lexical_normalize(&output);
    let scope = lexical_normalize(&root.join(".audit"));
    if output == scope || !output.starts_with(&scope) {
        return Err(CommandError::usage(format!(
            "--out must stay under the run-owned .audit scope ({}); received {}",
            scope.display(),
            output.display()
        )));
    }
    Ok(())
}

fn lexical_normalize(path: &std::path::Path) -> std::path::PathBuf {
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn native_inventory_binding(
    root: &std::path::Path,
    _args: &AuditArgs,
) -> Result<Value, CommandError> {
    let source = super::audit_inventory_source(root)?;
    let inventory = source
        .inventory(&root.to_string_lossy())
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok(json!({
        "repositoryRevision": inventory.generation,
        "inventoryDigest": inventory.digest,
    }))
}

fn native_facts_document(
    root: &std::path::Path,
    plan: &Value,
    execution: &legion_audit::ExecutionReport,
    report: &legion_contracts::ReportV1,
    scope: &AuditScope,
) -> Value {
    let provider_results = execution
        .results
        .iter()
        .map(|entry| {
            json!({
                "provider": entry.provider,
                "status": provider_status_name(&entry.result.status),
                "complete": entry.result.complete,
                "findings": entry.result.findings,
                "coverage": entry.result.coverage,
                "coverageGaps": entry.result.coverage_gaps,
                "degradation": entry.result.degradation,
            })
        })
        .collect::<Vec<_>>();
    let checks = execution
        .results
        .iter()
        .map(|entry| {
            json!({
                "check": entry.provider,
                "status": provider_status_name(&entry.result.status),
                "execution_status": if !entry.result.applicable || entry.result.details.contains_key("notApplicable") {
                    "not-applicable"
                } else if entry.skipped {
                    "skipped"
                } else {
                    "ran"
                },
                "verdict": if entry.result.complete {
                    "pass"
                } else if entry.result.details.contains_key("notApplicable") {
                    "not-applicable"
                } else {
                    "unproven"
                },
            })
        })
        .collect::<Vec<_>>();
    let mut facts = json!({
        "schemaVersion": 1,
        "kind": "audit-facts",
        "workspace": root,
        "out_dir": null,
        "plan": plan,
        "checks": checks,
        "lenses_ran": execution.lenses_ran,
        "incomplete": !report.gaps.is_empty(),
        "provider_reconciliation": {
            "valid": report.gaps.is_empty(),
            "providerResults": provider_results,
            "missingChecks": [],
            "unplannedChecks": [],
            "unresolvedCoverage": report.gaps,
            "missingRuntimeProviders": [],
            "denominatorMismatches": []
        },
        "network_policy": {"mode": "deny", "environment": []}
    });
    // Node's collect-facts crashes before writing scope when a ref fails gitRef;
    // mirror that by omitting the scope key entirely.
    if !scope.facts_unavailable {
        facts["scope"] = scope.facts_json();
    }
    facts
}

fn provider_status_name(status: &legion_contracts::ProviderStatus) -> &'static str {
    match status {
        legion_contracts::ProviderStatus::Ok | legion_contracts::ProviderStatus::Complete => "pass",
        legion_contracts::ProviderStatus::Partial => "partial",
        legion_contracts::ProviderStatus::Failed => "fail",
        legion_contracts::ProviderStatus::Cancelled => "skipped",
    }
}

fn native_audit_parity_gaps(
    planned_provider_count: usize,
    result_count: usize,
    plan_digest: &str,
    plan_signature: Option<&str>,
) -> Vec<String> {
    let mut gaps = Vec::new();
    if planned_provider_count == 0 || result_count != planned_provider_count {
        gaps.push("native-provider-plan-not-fully-executed".into());
    }
    if !plan_digest.starts_with("sha256:")
        || plan_signature.map_or(true, |signature| signature.trim().is_empty())
    {
        gaps.push("native-provider-plan-not-signed-and-sealed".into());
    }
    gaps
}

fn native_audit_input_gaps(args: &AuditArgs) -> Vec<String> {
    let mut gaps = Vec::new();
    if args.native_rule_manifest.is_some() {
        gaps.push("native-provider-composition-partial".into());
    }
    // Visual options (--url/--surfaces/--visual-spec/--visual-baselines/--width/
    // --height) stay accepted-and-inert without a gap record: Node's bare CLI
    // behaves the same way (the frozen registry has no visual.core provider),
    // so recording a gap here would diverge from Node by forcing Incomplete
    // where Node completes.
    gaps
}

fn filter_provider_specs(
    mut providers: Vec<legion_contracts::ProviderSpec>,
    args: &AuditArgs,
) -> Vec<legion_contracts::ProviderSpec> {
    if !args.only.is_empty() {
        providers.retain(|provider| args.only.iter().any(|id| id == provider.id.as_str()));
    }
    if !args.skip.is_empty() {
        providers.retain(|provider| !args.skip.iter().any(|id| id == provider.id.as_str()));
    }
    providers
}

/// Node-parity audit scope (tools/audit/collect-facts.mjs `scopeFor` +
/// `changedFiles`). Refs are recorded raw exactly as Node's plan does; the
/// `gitRef` regex decides whether facts collection can succeed at all.
struct AuditScope {
    mode: &'static str,
    scope_type: String,
    base: Option<String>,
    base_commit: Option<String>,
    dir: Option<String>,
    changed_files: Vec<String>,
    facts_unavailable: bool,
}

impl AuditScope {
    fn plan_json(&self) -> Value {
        json!({
            "mode": self.mode,
            "type": self.scope_type,
            "base": self.base,
            "baseCommit": self.base_commit,
            "dir": self.dir,
        })
    }

    fn facts_json(&self) -> Value {
        json!({
            "mode": self.mode,
            "type": self.scope_type,
            "base": self.base,
            "base_commit": self.base_commit,
            "dir": self.dir,
            "changed_files": self.changed_files,
        })
    }

    fn ref_is_valid(reference: &Option<String>) -> bool {
        crate::commands::audit::git_ref_is_valid(reference)
    }
}

fn clean_path(input: &str) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    let mut path = input.replace('\\', "/");
    if let Some(rest) = path.strip_prefix('.') {
        path = rest.trim_start_matches('/').to_string();
    }
    while path.ends_with('/') {
        path.pop();
    }
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

fn in_scope(file: &str, dir: Option<&str>) -> bool {
    match dir {
        None => true,
        Some(dir) => file == dir || file.starts_with(&format!("{dir}/")),
    }
}

fn validate_git_ref(reference: &str) -> bool {
    !reference.is_empty()
        && reference
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && reference.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '/' | '@' | '-')
        })
}

fn git_ref_is_valid(reference: &Option<String>) -> bool {
    reference
        .as_deref()
        .map_or(true, |reference| validate_git_ref(reference))
}

fn git_stdout(root: &std::path::Path, git_args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(git_args)
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn push_changed_files(files: &mut Vec<String>, root: &std::path::Path, git_args: &[&str]) {
    if let Some(stdout) = git_stdout(root, git_args) {
        files.extend(stdout.split('\n').filter_map(clean_path));
    }
}

fn audit_changed_files(
    root: &std::path::Path,
    scope_type: &str,
    scope_base: Option<&str>,
    scope_base_commit: Option<&str>,
    scope_dir: Option<&str>,
) -> Vec<String> {
    let mut files = Vec::new();
    if scope_type == "local" {
        push_changed_files(&mut files, root, &["diff", "--name-only", "HEAD"]);
        push_changed_files(
            &mut files,
            root,
            &["ls-files", "--others", "--exclude-standard"],
        );
        let upstream = git_stdout(
            root,
            &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        )
        .map(|reference| reference.trim().to_string())
        .filter(|reference| !reference.is_empty());
        if let Some(upstream) = upstream {
            let range = format!("{upstream}..HEAD");
            push_changed_files(&mut files, root, &["diff", "--name-only", &range]);
        }
        files.retain(|file| !file.starts_with(".audit/") && !is_generated_or_vendored_path(file));
    } else if let Some(commit) = scope_base_commit {
        push_changed_files(&mut files, root, &["diff", "--name-only", commit]);
    } else if let Some(base) = scope_base {
        let range = format!("{base}...HEAD");
        push_changed_files(&mut files, root, &["diff", "--name-only", &range]);
    } else if scope_type == "uncommitted" {
        push_changed_files(&mut files, root, &["diff", "--name-only"]);
    } else if scope_type == "committed" {
        push_changed_files(&mut files, root, &["diff", "--name-only", "HEAD~1..HEAD"]);
    }
    files.retain(|file| in_scope(file, scope_dir));
    files.sort();
    files.dedup();
    files
}

/// Node collect-facts isGeneratedOrVendoredPath: applied only to the `local`
/// scope's changed-file set, exactly as Node does.
fn is_generated_or_vendored_path(file: &str) -> bool {
    file.starts_with("vendor/")
        || file.starts_with("qwik/")
        || file.starts_with("dist/")
        || file.starts_with("src-tauri/gen/")
        || file.starts_with("src/generated/")
        || file.contains("/src/generated/")
        || file.contains("/drizzle/")
}

fn audit_scope(root: &std::path::Path, args: &AuditArgs) -> AuditScope {
    let scope_type = args.r#type.clone().unwrap_or_else(|| "all".into());
    let scope_dir = args
        .dir
        .as_ref()
        .and_then(|dir| clean_path(&dir.to_string_lossy()));
    let scope_base = args.base.clone();
    let scope_base_commit = args.base_commit.clone();
    let refs_valid =
        AuditScope::ref_is_valid(&scope_base) && AuditScope::ref_is_valid(&scope_base_commit);
    let scoped = scope_dir.is_some()
        || scope_base.is_some()
        || scope_base_commit.is_some()
        || scope_type != "all";
    let changed_files = if refs_valid {
        audit_changed_files(
            root,
            &scope_type,
            scope_base.as_deref(),
            scope_base_commit.as_deref(),
            scope_dir.as_deref(),
        )
    } else {
        Vec::new()
    };
    AuditScope {
        mode: if scoped { "diff" } else { "whole-repo" },
        scope_type,
        base: scope_base,
        base_commit: scope_base_commit,
        dir: scope_dir,
        changed_files,
        facts_unavailable: !refs_valid,
    }
}

fn review_context(root: &std::path::Path, scope: &AuditScope) -> Value {
    let mut context = json!({
        "mode": scope.mode,
        "type": scope.scope_type,
        "rawRefs": {
            "base": scope.base,
            "baseCommit": scope.base_commit,
            "dir": scope.dir,
        },
        "changedPaths": scope.changed_files,
        "baseline": {
            "status": "unavailable",
            "kind": "none",
            "commit": Value::Null,
            "mergeBase": Value::Null,
        },
    });
    if scope.mode == "whole-repo"
        || (scope.dir.is_some()
            && scope.base.is_none()
            && scope.base_commit.is_none()
            && scope.scope_type == "all")
    {
        context["baseline"]["status"] = json!("not-applicable");
        return context;
    }
    if scope.facts_unavailable {
        return context;
    }

    let head = git_stdout(root, &["rev-parse", "HEAD"]).map(|value| value.trim().to_owned());
    let Some(head) = head.filter(|value| !value.is_empty()) else {
        return context;
    };
    let mut baseline_kind = "commit";
    let mut baseline_commit = None;
    let mut merge_base = None;
    match scope.scope_type.as_str() {
        "local" => {
            let upstream = git_stdout(
                root,
                &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
            )
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
            let Some(upstream) = upstream else {
                return context;
            };
            merge_base = git_stdout(root, &["merge-base", &upstream, &head])
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty());
            let Some(base) = merge_base.clone() else {
                return context;
            };
            baseline_kind = "merge-base-with-worktree";
            baseline_commit = Some(base.clone());
        }
        _ if scope.base_commit.is_some() => {
            let raw = scope.base_commit.as_deref().unwrap_or_default();
            baseline_commit = git_stdout(root, &["rev-parse", &format!("{raw}^{{commit}}")])
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty());
            let Some(_base) = baseline_commit.clone() else {
                return context;
            };
            baseline_kind = "commit-to-worktree";
        }
        _ if scope.base.is_some() => {
            let raw = scope.base.as_deref().unwrap_or_default();
            merge_base = git_stdout(root, &["merge-base", raw, &head])
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty());
            let Some(base) = merge_base.clone() else {
                return context;
            };
            baseline_kind = "merge-base";
            baseline_commit = Some(base.clone());
        }
        "uncommitted" => {
            baseline_kind = "index";
        }
        "committed" => {
            baseline_commit = git_stdout(root, &["rev-parse", "HEAD~1"])
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty());
            let Some(_base) = baseline_commit.clone() else {
                return context;
            };
        }
        _ => return context,
    }
    context["baseline"] = json!({
        "status": "resolved",
        "kind": baseline_kind,
        "commit": baseline_commit,
        "mergeBase": merge_base,
        "head": head,
    });
    context
}

fn native_rule_diagnostic_application(
    args: &AuditArgs,
    root: &std::path::Path,
    manifest: &std::path::Path,
) -> Result<(legion_application::NativeApplication, Vec<String>), CommandError> {
    let provider: legion_contracts::ProviderSpec = serde_json::from_value(json!({
        "schemaVersion": 2,
        "id": "security.native-rules",
        "providerVersion": "1",
        "family": "security",
        "role": "deterministic",
        "phase": "source",
        "lensIds": [], "dependsOn": [],
        "consumes": ["repository-inventory"],
        "produces": ["provider-result"],
        "selector": {"op":"always"},
        "denominatorKind": "repository-inventory",
        "runner": {"kind":"built-in","implementation":"native-rule-manifest"},
        "hostCapabilities": [], "execution": {}, "reasoning": {},
        "benchmark": {"status":"unproven","requiredForCleanClaim":false},
        "cleanClaim": "finding-producing",
        "controlIds": [], "scopes": [], "selectable": true
    }))
    .map_err(|error| CommandError::internal(error.to_string()))?;
    let source = super::audit_inventory_source(root)?;
    let executor = super::rules::NativeRuleProviderExecutor::new(
        root.to_path_buf(),
        manifest.to_path_buf(),
        1_048_576,
    )
    .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let application = legion_application::NativeApplicationConfig::for_audit_executor(
        root.to_string_lossy().into_owned(),
        source,
        vec![provider],
        Arc::new(executor),
        Some(root.to_path_buf()),
    )
    .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok((application, Vec::new()))
}

/// Application for operating on an existing audit run (e.g. `verify`): honours
/// `LEGION_NATIVE_APPLICATION_CONFIG`, otherwise builds the same canonical
/// provider registry `legion audit` builds for `repository_id` (its root).
pub(super) fn audit_application_for(
    repository_id: &str,
) -> Result<Arc<legion_application::NativeApplication>, CommandError> {
    let root = std::path::Path::new(repository_id);
    if std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_some() || !root.is_dir() {
        return super::native_application_for(repository_id);
    }
    native_registry_application(root).map(|(application, _)| Arc::new(application))
}

fn native_registry_application(
    root: &std::path::Path,
) -> Result<(legion_application::NativeApplication, Vec<String>), CommandError> {
    // The command must execute the frozen native provider composition. Do not
    // silently replace it with a one-rule project scan when the release
    // registry is absent: that would make a successful command look like a
    // complete Audit while bypassing the provider plan and its gaps.
    let registry = native_provider_registry_path().ok_or_else(|| {
        CommandError::incomplete(
            "native Audit provider registry is unavailable; install or configure the native provider composition",
        )
    })?;
    let bytes = std::fs::read(&registry).map_err(super::io_error)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| CommandError::usage(format!("invalid provider registry: {error}")))?;
    let providers = value
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CommandError::usage("provider registry must contain providers"))?
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<Vec<legion_contracts::ProviderSpec>, _>>()
        .map_err(|error| CommandError::usage(format!("invalid provider specification: {error}")))?;
    let source = super::audit_inventory_source(root)?;
    let external_tool = native_audit_external_tool(root);
    let executor = std::sync::Arc::new(
        legion_audit::NativeProviderRegistry::new(root.to_path_buf())
            .with_external_project_tool(external_tool),
    );
    let application = legion_application::NativeApplicationConfig::for_audit_executor(
        root.to_string_lossy().into_owned(),
        source,
        providers,
        executor,
        Some(root.to_path_buf()),
    )
    .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok((application, Vec::new()))
}

fn native_audit_external_tool(
    root: &std::path::Path,
) -> std::sync::Arc<dyn legion_provider_sdk::ExternalProjectTool> {
    let policy = legion_effects::StaticPolicy {
        decision: legion_effects::PolicyDecision {
            allowed: true,
            policy_id: "native-audit-external-tools-v1".into(),
            policy_version: 1,
            policy_digest: format!("sha256:{}", sha256_hex(b"native-audit-external-tools-v1")),
            reason: None,
        },
    };
    #[cfg(windows)]
    let process = legion_effects::platform::windows::WindowsProcess;
    #[cfg(unix)]
    let process = legion_effects::platform::unix::UnixProcess::new();
    let effects = legion_effects::EffectExecutor::new(
        process,
        legion_effects::ArtifactWriter::new(root),
        policy,
    );
    std::sync::Arc::new(
        legion_audit::native_providers::legacy_checks::AuditExternalProjectTool::new(effects),
    )
}

fn native_provider_registry_path() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("LEGION_PROVIDER_REGISTRY") {
        let path = std::path::PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let composition = crate::cli::installed_m1_composition().ok()?;
    let share = composition.parent()?;
    let path = share.join("assets/registry/providers.json");
    path.is_file().then_some(path)
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
    let source = super::audit_inventory_source(root)?;
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
        Some(root.to_path_buf()),
    )
    .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok((application, Vec::new()))
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

#[cfg(test)]
mod closure_tests {
    use super::*;

    #[test]
    fn leg_016_native_audit_requires_complete_signed_plan_before_parity_claim() {
        assert!(native_audit_parity_gaps(
            3,
            3,
            &format!("sha256:{}", "a".repeat(64)),
            Some("hmac")
        )
        .is_empty());
        assert!(!native_audit_parity_gaps(3, 2, "missing", None).is_empty());
    }

    #[test]
    fn audit_scope_defaults_to_whole_repo_with_no_scope_key_drift() {
        let args = AuditArgs {
            root: std::path::PathBuf::from("."),
            plan_only: false,
            quiet: false,
            only: Vec::new(),
            skip: Vec::new(),
            url: None,
            surfaces: None,
            visual_spec: None,
            visual_baselines: None,
            width: 1280,
            height: 800,
            r#type: None,
            base: None,
            base_commit: None,
            dir: None,
            json: false,
            profile: "standard".into(),
            out: None,
            provider_plan: None,
            provider_results: Vec::new(),
            native_rule_manifest: None,
            ingest_run: None,
            ingest_provider: None,
            ingest_result: None,
            followup: false,
        };
        let scope = audit_scope(std::path::Path::new("."), &args);
        assert_eq!(scope.mode, "whole-repo");
        assert_eq!(scope.scope_type, "all");
        assert!(scope.changed_files.is_empty());
        assert!(!scope.facts_unavailable);
        let plan = scope.plan_json();
        assert_eq!(plan["mode"], "whole-repo");
        assert_eq!(plan["type"], "all");
        assert_eq!(plan["base"], Value::Null);
        assert_eq!(plan["baseCommit"], Value::Null);
        assert_eq!(plan["dir"], Value::Null);
    }

    #[test]
    fn audit_scope_records_raw_refs_and_degrades_facts_for_invalid_refs() {
        let mut args = AuditArgs {
            root: std::path::PathBuf::from("."),
            r#type: None,
            base: Some("bad ref".into()),
            dir: Some(std::path::PathBuf::from("engine")),
            ..minimal_audit_args()
        };
        args.width = 1280;
        args.height = 800;
        let scope = audit_scope(std::path::Path::new("."), &args);
        // Node records the raw ref in plan.scope (verified live: exit 2, no error).
        assert_eq!(scope.plan_json()["base"], "bad ref");
        assert_eq!(scope.mode, "diff");
        // Facts collection equivalent crashes in Node, so facts omit scope entirely.
        assert!(scope.facts_unavailable);
        assert!(scope.changed_files.is_empty());
    }

    #[test]
    fn audit_scope_dir_filters_without_creating_a_diff() {
        let mut args = AuditArgs {
            dir: Some(std::path::PathBuf::from("engine")),
            ..minimal_audit_args()
        };
        args.width = 1280;
        args.height = 800;
        let scope = audit_scope(std::path::Path::new("."), &args);
        // Node truth (verified live): --dir engine records mode diff with an empty
        // changed_files set — dir filters, it never constructs a diff range.
        assert_eq!(scope.mode, "diff");
        assert_eq!(scope.dir.as_deref(), Some("engine"));
        assert!(scope.changed_files.is_empty());
        assert!(!scope.facts_unavailable);
    }

    #[test]
    fn audit_scope_matches_node_scope_json_shapes() {
        let mut args = AuditArgs {
            base: Some("origin/main".into()),
            ..minimal_audit_args()
        };
        args.width = 1280;
        args.height = 800;
        let scope = audit_scope(std::path::Path::new("."), &args);
        let plan = scope.plan_json();
        assert_eq!(plan["baseCommit"], Value::Null);
        let facts = scope.facts_json();
        assert!(facts.get("base_commit").is_some());
        assert!(facts.get("changed_files").is_some());
        // camelCase in plan, snake_case in facts — both shapes verified in Node.
        assert!(plan.get("baseCommit").is_some());
        assert!(plan.get("base_commit").is_none());
    }

    #[test]
    fn whole_repo_review_context_is_explicitly_not_applicable() {
        let scope = AuditScope {
            mode: "whole-repo",
            scope_type: "all".into(),
            base: None,
            base_commit: None,
            dir: None,
            changed_files: Vec::new(),
            facts_unavailable: false,
        };
        let context = review_context(std::path::Path::new("."), &scope);
        assert_eq!(context["baseline"]["status"], "not-applicable");
        assert!(context.get("changedPaths").is_some());
    }

    #[test]
    fn documented_scope_types_do_not_filter_provider_families() {
        let provider: legion_contracts::ProviderSpec = serde_json::from_value(json!({
            "schemaVersion": 2,
            "id": "security.opengrep",
            "providerVersion": "1",
            "family": "security",
            "lensIds": [],
            "role": "deterministic",
            "phase": "source",
            "dependsOn": [],
            "consumes": ["repository-inventory"],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "repository-inventory",
            "runner": {"kind": "built-in"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {},
            "cleanClaim": "finding-producing",
            "controlIds": [],
            "scopes": [],
            "selectable": true
        }))
        .unwrap();
        for scope_type in ["all", "local", "committed", "uncommitted"] {
            let mut args = minimal_audit_args();
            args.r#type = Some(scope_type.into());
            let selected = filter_provider_specs(vec![provider.clone()], &args);
            assert_eq!(selected.len(), 1, "scope type {scope_type}");
        }
    }

    fn minimal_audit_args() -> AuditArgs {
        AuditArgs {
            root: std::path::PathBuf::from("."),
            plan_only: false,
            quiet: false,
            only: Vec::new(),
            skip: Vec::new(),
            url: None,
            surfaces: None,
            visual_spec: None,
            visual_baselines: None,
            width: 1280,
            height: 800,
            r#type: None,
            base: None,
            base_commit: None,
            dir: None,
            json: false,
            profile: "standard".into(),
            out: None,
            provider_plan: None,
            provider_results: Vec::new(),
            native_rule_manifest: None,
            ingest_run: None,
            ingest_provider: None,
            ingest_result: None,
            followup: false,
        }
    }
}
