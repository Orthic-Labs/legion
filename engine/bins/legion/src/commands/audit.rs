use super::{CommandError, CommandResult};
use clap::Args;
use legion_audit::{
    parse_effect_artifact_ref, read_effect_artifact, validate_effect_artifact_path,
    InventorySource as _,
};
use legion_effects::artifact::ArtifactRecord as EffectArtifactRef;
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
    /// `legion audit findings <list|resolve|dismiss|reopen|supersede> [<finding-id>|<repo-root>]`:
    /// finding-store lifecycle (see `findings_command`). The trailing root is
    /// accepted by `list` only.
    #[arg(hide = true)]
    pub findings_args: Vec<String>,
    /// Repository whose `.audit/audit/findings.jsonl` the `findings` actions use
    /// (default: the current directory). Mutually exclusive with a positional
    /// root given to `list`.
    #[arg(long = "repo", hide = true)]
    pub findings_repo: Option<PathBuf>,
    /// `findings supersede`: JSON file holding the successor finding record.
    #[arg(long = "by", hide = true)]
    pub findings_by: Option<PathBuf>,
    /// `findings resolve|dismiss`: generation that closed the finding.
    #[arg(long = "generation", hide = true)]
    pub findings_generation: Option<String>,
    /// `findings list`: only `open` findings.
    #[arg(long = "active", hide = true)]
    pub findings_active: bool,
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
    if args.root.as_os_str() == "findings" && !args.findings_args.is_empty() {
        return findings_command(&args);
    }
    if !args.findings_args.is_empty() {
        return Err(CommandError::usage(format!(
            "unexpected arguments: {}",
            args.findings_args.join(" ")
        )));
    }
    if args.root.to_string_lossy().starts_with('-') {
        return Err(CommandError::usage(format!(
            "Unknown option '{}'. To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- \"{}\"",
            args.root.display(),
            args.root.display()
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
    // Gaps the direct route adds when its provider plan could not be bound
    // (for example `unsealed-plan`); empty for every other route.
    let mut direct_gaps: Vec<String> = Vec::new();
    let (application, context_notices, effect_artifact_scratch) = if direct {
        let (application, notices, gaps) = direct_application(&args, &root)?;
        direct_gaps = gaps;
        (Arc::new(application), notices, None)
    } else if let Some(manifest) = &args.native_rule_manifest {
        let (application, notices) = native_rule_diagnostic_application(&args, &root, manifest)?;
        (Arc::new(application), notices, None)
    } else if std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_some() {
        (
            super::native_application_for(&root.to_string_lossy())?,
            Vec::new(),
            None,
        )
    } else {
        let (application, notices, scratch) = native_registry_application(&root)?;
        (Arc::new(application), notices, Some(scratch))
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
    // Key creation removes the run's prior epoch key and lens receipts, so it
    // runs only after every argument and provider-ID check above has passed.
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
    // Runtime capture inputs are frozen into the provider's runner so the plan
    // seal covers them; inputs that cannot reach a provider are named gaps.
    let (runtime_gaps, runtime_injected) =
        apply_runtime_inputs(&args, &mut selected_specs, direct)?;
    // `--visual-spec`/`--visual-baselines` freeze into the visual provider the
    // same way; both binders' declared gaps are reported with the run.
    let (visual_gaps, visual_injected) = apply_visual_inputs(&args, &mut selected_specs, direct)?;
    if !direct {
        bind_runtime_visual_capture_source(&mut selected_specs);
    }
    let declared_input_gaps = [runtime_gaps, visual_gaps].concat();
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
            let mut input_gaps = native_audit_input_gaps(&args, &declared_input_gaps);
            input_gaps.extend(lens_work_gaps);
            let mut plan_gaps = vec!["plan-only".to_owned()];
            plan_gaps.extend(direct_gaps.iter().cloned());
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
                "gaps": plan_gaps,
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
        legion_application::NativeOperationResult::Audit(mut execution) => {
            let effect_artifact_root =
                if let (Some(out), Some(scratch)) = (&args.out, effect_artifact_scratch.as_ref()) {
                    let gaps = retain_effect_artifacts(out, scratch, &mut execution);
                    if !gaps.is_empty() {
                        execution.gaps.extend(gaps);
                        execution.gaps.sort();
                        execution.gaps.dedup();
                    }
                    Some("artifacts")
                } else {
                    None
                };
            let mut report = legion_audit::canonical_report(&root.to_string_lossy(), &execution)
                .map_err(|error| CommandError::integrity(error.to_string()))?;
            let parity_gaps = native_audit_parity_gaps(
                execution.planned_providers.len(),
                execution.results.len(),
                &execution.plan_digest,
                execution.plan_signature.as_deref(),
            );
            report.gaps.extend(parity_gaps);
            report
                .gaps
                .extend(native_audit_input_gaps(&args, &declared_input_gaps));
            if runtime_injected
                && !execution
                    .results
                    .iter()
                    .any(|item| item.provider == RUNTIME_PROVIDER_ID)
            {
                // The provider was selected but is not applicable to this
                // repository (no dev/start/preview/qa:browser script), so it
                // never ran and the supplied URL was not consumed.
                report
                    .gaps
                    .push("runtime-inputs-not-consumed:provider-not-applicable".into());
            }
            if visual_injected
                && !execution
                    .results
                    .iter()
                    .any(|item| item.provider == VISUAL_PROVIDER_ID)
            {
                // The visual provider was selected but never ran (not applicable
                // to this repository), so the supplied spec was not consumed.
                report
                    .gaps
                    .push("visual-inputs-not-consumed:provider-not-applicable".into());
            }
            report.gaps.extend(direct_gaps.iter().cloned());
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
            if let Some(effect_artifact_root) = effect_artifact_root {
                report
                    .claims
                    .insert("effectArtifactsRoot".into(), json!(effect_artifact_root));
            }
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
                let native_plan = native_plan_document(
                    &lens_basis,
                    execution.plan_digest.as_str(),
                    execution.plan_signature.as_deref(),
                )
                .map_err(CommandError::integrity)?;
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
                    "providerSpecs": selected_specs,
                    "nativePlan": native_plan,
                    "effectArtifactsRoot": effect_artifact_root,
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
                "effectArtifactsRoot": effect_artifact_root,
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

/// `legion audit findings <list|resolve|dismiss|reopen|supersede> ...`: the
/// finding-store lifecycle over `<repo>/.audit/audit/findings.jsonl`.
///
/// * `findings list [<repo-root>] [--active] [--repo <dir>]`
/// * `findings resolve <id> [--generation <g>] [--repo <dir>]`, `findings dismiss <id> [--generation <g>] [--repo <dir>]`
/// * `findings reopen <id> [--repo <dir>]`
/// * `findings supersede <old-id> --by <successor-record.json> [--repo <dir>]`
///
/// The repository defaults to the current directory. `list` also accepts the
/// repository root as a trailing positional; every other action takes the
/// finding id positionally, so its root can only be given with `--repo`. The
/// two forms together are refused rather than guessed.
///
/// Invalid transitions (unknown id, superseding via a status change, a
/// successor equal to the retired finding) are refused with exit code 4.
fn findings_command(args: &AuditArgs) -> CommandResult {
    use legion_audit::p12_pipeline::store::{FindingStore, StoreError};
    let store_error = |error: StoreError| match error {
        StoreError::Io(message) => CommandError::internal(message),
        other => CommandError::usage(other.to_string()),
    };
    let action = args.findings_args[0].as_str();
    let trailing = &args.findings_args[1..];
    let (id, positional_root): (Option<&str>, Option<PathBuf>) = if action == "list" {
        match trailing {
            [] => (None, None),
            [root] => (None, Some(PathBuf::from(root.as_str()))),
            _ => {
                return Err(CommandError::usage(
                    "findings list takes at most one repository root",
                ));
            }
        }
    } else {
        match trailing {
            [] => (None, None),
            [id] => (Some(id.as_str()), None),
            _ => {
                return Err(CommandError::usage(
                    "findings takes an action and at most one finding id",
                ));
            }
        }
    };
    if positional_root.is_some() && args.findings_repo.is_some() {
        return Err(CommandError::usage(
            "findings takes the repository root either positionally (list only) or with --repo, not both",
        ));
    }
    let repo_arg = positional_root
        .or_else(|| args.findings_repo.clone())
        .unwrap_or_else(|| PathBuf::from("."));
    let repo = std::fs::canonicalize(repo_arg).map_err(super::io_error)?;
    let store = FindingStore::new(&repo);
    let require_id = || {
        id.ok_or_else(|| CommandError::usage(format!("findings {action} requires a finding id")))
    };
    let generation = args.findings_generation.as_deref();
    let updated = match action {
        "list" => {
            let loaded = if args.findings_active {
                store.active(None)
            } else {
                store.load()
            };
            let findings = loaded.map_err(store_error)?;
            return Ok(json!({
                "schemaVersion": 1,
                "kind": "audit-findings",
                "store": store.path(),
                "count": findings.len(),
                "findings": findings,
            }));
        }
        "resolve" => store
            .set_status(require_id()?, "resolved", generation, None)
            .map_err(store_error)?,
        "dismiss" => store
            .set_status(require_id()?, "dismissed", generation, None)
            .map_err(store_error)?,
        "reopen" => store
            .set_status(require_id()?, "open", None, None)
            .map_err(store_error)?,
        "supersede" => {
            let old_id = require_id()?;
            let by = args.findings_by.as_ref().ok_or_else(|| {
                CommandError::usage("findings supersede requires --by <successor-record.json>")
            })?;
            let successor: Value = serde_json::from_slice(
                &std::fs::read(by).map_err(super::io_error)?,
            )
            .map_err(|error| CommandError::usage(format!("invalid successor record: {error}")))?;
            store
                .supersede(old_id, &successor, None)
                .map_err(store_error)?
        }
        other => {
            return Err(CommandError::usage(format!(
                "unknown findings action: {other} (expected list, resolve, dismiss, reopen or supersede)"
            )));
        }
    };
    Ok(json!({
        "schemaVersion": 1,
        "kind": "audit-finding-update",
        "action": action,
        "store": store.path(),
        "finding": updated,
    }))
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
            "packet": planned.packets.first(),
            "packets": planned.packets,
            "packetDigest": planned.packet_digests.first(),
            "packetDigests": planned.packet_digests,
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

/// Adds the exact plan compiled before execution to the persisted normal-run
/// plan document. This is a projection of the plan already bound by execution,
/// never a reconstruction from the current provider registry.
fn native_plan_document(
    basis: &LensBasis,
    executed_plan_digest: &str,
    executed_plan_signature: Option<&str>,
) -> Result<Value, String> {
    let (plan, _) = basis.as_ref().map_err(Clone::clone)?;
    if plan.digest() != executed_plan_digest {
        return Err("frozen native plan digest differs from executed plan".into());
    }
    if plan.signature() != executed_plan_signature {
        return Err("frozen native plan signature differs from executed plan".into());
    }
    let plan_value = serde_json::to_value(plan.plan()).map_err(|error| error.to_string())?;
    Ok(json!({
        "schemaVersion": 1,
        "plan": plan_value,
        "digest": plan.digest(),
        "signature": plan.signature(),
    }))
}

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
        // A provider whose denominator does not fit one packet is split into
        // parts; the writer names each part file and the provider index.
        let items = match out {
            Some(out) => legion_audit::native_providers::reasoning::ingest::write_lens_packets(
                &out.join("lens-packets"),
                &work,
            ),
            None => {
                legion_audit::native_providers::reasoning::ingest::lens_packet_items(&work, None)
            }
        }
        .map_err(|error| error.to_string())?;
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

const RUNTIME_PROVIDER_ID: &str = "legacy.runtime.app";
const VISUAL_PROVIDER_ID: &str = "legacy.visual.core";

fn native_audit_input_gaps(args: &AuditArgs, declared_gaps: &[String]) -> Vec<String> {
    let mut gaps = Vec::new();
    if args.native_rule_manifest.is_some() {
        gaps.push("native-provider-composition-partial".into());
    }
    // Frozen-input binders (`apply_runtime_inputs`, `apply_visual_inputs`) name
    // whatever could not reach its provider; consumed inputs add no gap.
    gaps.extend(declared_gaps.iter().cloned());
    gaps.sort();
    gaps.dedup();
    gaps
}

/// Freeze `--visual-spec` and `--visual-baselines` into the visual provider's
/// `runner.visual` object, so the plan seal covers them. The spec is read and
/// shape-checked here (a malformed spec is a usage error, never a silent
/// skip); the baselines path must be an existing directory and is frozen as a
/// canonical path with a sorted per-file sha256 listing. Returns the input gaps
/// for anything that cannot reach the provider and whether they were injected.
fn apply_visual_inputs(
    args: &AuditArgs,
    specs: &mut [legion_contracts::ProviderSpec],
    direct: bool,
) -> Result<(Vec<String>, bool), CommandError> {
    if args.visual_spec.is_none() && args.visual_baselines.is_none() {
        return Ok((Vec::new(), false));
    }
    let mut visual = json!({});
    if let Some(path) = &args.visual_spec {
        let bytes = std::fs::read(path).map_err(|error| {
            CommandError::usage(format!(
                "cannot read --visual-spec {}: {error}",
                path.display()
            ))
        })?;
        visual = legion_audit::native_providers::legacy::visual::freeze_spec(&bytes)
            .map_err(|reason| CommandError::usage(format!("invalid --visual-spec: {reason}")))?;
    }
    if let Some(dir) = &args.visual_baselines {
        visual["baselines"] = legion_audit::native_providers::legacy::visual::freeze_baselines(dir)
            .map_err(|reason| {
                CommandError::usage(format!("invalid --visual-baselines: {reason}"))
            })?;
    }
    if direct {
        return Ok((
            vec!["visual-inputs-not-consumed:provider-plan-supplied".to_owned()],
            false,
        ));
    }
    if !specs
        .iter()
        .any(|provider| provider.id.as_str() == VISUAL_PROVIDER_ID)
    {
        return Ok((
            vec!["visual-inputs-not-consumed:provider-not-selected".to_owned()],
            false,
        ));
    }
    for provider in specs.iter_mut() {
        if provider.id.as_str() == VISUAL_PROVIDER_ID {
            if let Some(runner) = provider.runner.as_object_mut() {
                runner.insert("visual".into(), visual.clone());
            }
        }
    }
    Ok((Vec::new(), true))
}

/// Freeze the runtime-to-visual handoff as an ordering-only source. Explicit
/// visual specifications remain authoritative and never receive inferred
/// runtime captures.
fn bind_runtime_visual_capture_source(specs: &mut [legion_contracts::ProviderSpec]) {
    let runtime_url = specs
        .iter()
        .find(|provider| provider.id.as_str() == RUNTIME_PROVIDER_ID)
        .and_then(|provider| provider.runner.get("runtime"))
        .and_then(|runtime| runtime.get("url"))
        .and_then(serde_json::Value::as_str)
        .filter(|url| !url.trim().is_empty());
    if runtime_url.is_none()
        || !specs
            .iter()
            .any(|provider| provider.id.as_str() == VISUAL_PROVIDER_ID)
    {
        return;
    }
    let Some(visual_provider) = specs
        .iter_mut()
        .find(|provider| provider.id.as_str() == VISUAL_PROVIDER_ID)
    else {
        return;
    };
    let Some(runner) = visual_provider.runner.as_object_mut() else {
        return;
    };
    let visual = runner.entry("visual").or_insert_with(|| json!({}));
    if !visual.is_object() || visual.get("spec").is_some() {
        return;
    }
    visual["captureSource"] = json!({
        "kind": "runtime-provider",
        "providerId": RUNTIME_PROVIDER_ID,
    });
}

/// Bind `--url`, `--surfaces`, `--width` and `--height` to the runtime
/// provider by freezing them into its `runner.runtime` object. Returns the
/// input gaps for anything that cannot reach the provider and whether the
/// inputs were injected.
fn apply_runtime_inputs(
    args: &AuditArgs,
    specs: &mut [legion_contracts::ProviderSpec],
    direct: bool,
) -> Result<(Vec<String>, bool), CommandError> {
    let mut gaps = Vec::new();
    let Some(url) = args.url.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
        if args
            .surfaces
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            gaps.push("runtime-surfaces-ignored:runtime-url-not-supplied".into());
        }
        if args.width != 1280 || args.height != 800 {
            gaps.push("runtime-viewport-ignored:runtime-url-not-supplied".into());
        }
        return Ok((gaps, false));
    };
    if direct {
        gaps.push("runtime-inputs-not-consumed:provider-plan-supplied".into());
        return Ok((gaps, false));
    }
    if !specs
        .iter()
        .any(|provider| provider.id.as_str() == RUNTIME_PROVIDER_ID)
    {
        gaps.push("runtime-inputs-not-consumed:provider-not-selected".into());
        return Ok((gaps, false));
    }
    let (surfaces, unsupported) = runtime_surface_inputs(args, url)?;
    let artifact_dir = match &args.out {
        Some(out) => {
            let absolute = if out.is_absolute() {
                out.clone()
            } else {
                std::env::current_dir().map_err(super::io_error)?.join(out)
            };
            Some(absolute.join("runtime").to_string_lossy().into_owned())
        }
        None => None,
    };
    let inputs = legion_audit::native_providers::legacy_checks::runtime_inputs(
        url,
        &surfaces,
        &unsupported,
        args.width,
        args.height,
        artifact_dir.as_deref(),
    )
    .map_err(|reason| CommandError::usage(format!("invalid runtime inputs: {reason}")))?;
    for provider in specs.iter_mut() {
        if provider.id.as_str() == RUNTIME_PROVIDER_ID {
            if let Some(runner) = provider.runner.as_object_mut() {
                runner.insert("runtime".into(), inputs.clone());
            }
        }
    }
    Ok((gaps, true))
}

/// `--surfaces` is either a comma-separated list of origin-relative paths
/// (`/settings`) or absolute http(s) URLs, or a JSON array file whose entries
/// carry `url` or `route`/`path` (with an optional `label`). Entries that name
/// only a click target (`selector`/`text`) cannot be captured by navigation
/// and are returned by label as unsupported.
fn runtime_surface_inputs(
    args: &AuditArgs,
    base_url: &str,
) -> Result<(Vec<(String, String)>, Vec<String>), CommandError> {
    let Some(raw) = args
        .surfaces
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut surfaces: Vec<(String, String)> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
    let path = std::path::Path::new(raw);
    if path.is_file() {
        let bytes = std::fs::read(path).map_err(super::io_error)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| CommandError::usage(format!("invalid --surfaces file: {error}")))?;
        let items = value
            .as_array()
            .ok_or_else(|| CommandError::usage("--surfaces file must contain a JSON array"))?;
        for (index, item) in items.iter().enumerate() {
            let text = |key: &str| item.get(key).and_then(serde_json::Value::as_str);
            let label = text("label")
                .or_else(|| text("text"))
                .or_else(|| text("selector"))
                .map(str::to_owned)
                .unwrap_or_else(|| format!("surface-{index}"));
            match text("url")
                .or_else(|| text("route"))
                .or_else(|| text("path"))
            {
                Some(target) => {
                    surfaces.push((label, resolve_surface_url(base_url, target.trim())?))
                }
                None => unsupported.push(label),
            }
        }
    } else {
        for target in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            surfaces.push((target.to_owned(), resolve_surface_url(base_url, target)?));
        }
    }
    Ok((surfaces, unsupported))
}

fn resolve_surface_url(base_url: &str, target: &str) -> Result<String, CommandError> {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok(target.to_owned());
    }
    if target.starts_with('/') && !target.starts_with("//") {
        if let Some(scheme_end) = base_url.find("://").map(|at| at + 3) {
            let rest = &base_url[scheme_end..];
            let origin_len = rest
                .find(|c| c == '/' || c == '?' || c == '#')
                .unwrap_or(rest.len());
            return Ok(format!(
                "{}{}{}",
                &base_url[..scheme_end],
                &rest[..origin_len],
                target
            ));
        }
    }
    Err(CommandError::usage(format!(
        "unsupported --surfaces target '{target}': use an origin-relative path (/settings), an http(s) URL, or a JSON file"
    )))
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
    native_registry_application(root).map(|(application, _, _scratch)| Arc::new(application))
}

fn native_registry_application(
    root: &std::path::Path,
) -> Result<
    (
        legion_application::NativeApplication,
        Vec<String>,
        std::sync::Arc<legion_audit::native_providers::legacy_checks::AuditScratch>,
    ),
    CommandError,
> {
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
    // All audit scratch lives outside the audited tree and is removed when the
    // registry (the last holder) is dropped.
    let scratch = std::sync::Arc::new(
        legion_audit::native_providers::legacy_checks::AuditScratch::create(root)
            .map_err(|error| CommandError::incomplete(error.to_string()))?,
    );
    let external_tool = native_audit_external_tool(&scratch);
    let executor = std::sync::Arc::new(
        legion_audit::NativeProviderRegistry::new(root.to_path_buf())
            .with_scratch(scratch.clone())
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
    Ok((application, Vec::new(), scratch))
}

fn native_audit_external_tool(
    scratch: &legion_audit::native_providers::legacy_checks::AuditScratch,
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
        legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
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

fn retain_effect_artifacts(
    out: &std::path::Path,
    scratch: &legion_audit::native_providers::legacy_checks::AuditScratch,
    execution: &mut legion_audit::ExecutionReport,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut provider_failures = std::collections::BTreeMap::<usize, Vec<String>>::new();
    let mut requested =
        std::collections::BTreeMap::<String, (EffectArtifactRef, Vec<usize>)>::new();
    let mut conflicting_paths = std::collections::BTreeSet::new();

    for (index, provider) in execution.results.iter().enumerate() {
        let receipt = provider
            .result
            .details
            .get("executionReceipt")
            .or_else(|| provider.result.details.get("receipt"));
        let Some(receipt) = receipt.and_then(Value::as_object) else {
            continue;
        };
        // Native legacy checks report in-memory stream summaries with
        // `path: null` and `immutable: false`; those summaries are not captured
        // artifacts and must not be retained as if they were external refs.
        if receipt.get("kind").and_then(Value::as_str) == Some("native-legacy-check-receipt") {
            continue;
        }
        for stream in ["stdout", "stderr", "brokerStatus"] {
            let Some(value) = receipt.get(stream).filter(|value| !value.is_null()) else {
                continue;
            };
            let record = match parse_effect_artifact_ref(value) {
                Ok(record) => record,
                Err(reason) => {
                    record_retention_failure(
                        &mut failures,
                        &mut provider_failures,
                        index,
                        &provider.provider,
                        stream,
                        reason,
                    );
                    continue;
                }
            };
            match requested.entry(record.path.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((record, vec![index]));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let (existing, owners) = entry.get_mut();
                    owners.push(index);
                    if existing != &record {
                        conflicting_paths.insert(record.path.clone());
                        for owner in owners.iter().copied() {
                            let owner_id = &execution.results[owner].provider;
                            record_retention_failure(
                                &mut failures,
                                &mut provider_failures,
                                owner,
                                owner_id,
                                stream,
                                "conflicting artifact records share one path".into(),
                            );
                        }
                    } else if conflicting_paths.contains(&record.path) {
                        record_retention_failure(
                            &mut failures,
                            &mut provider_failures,
                            index,
                            &provider.provider,
                            stream,
                            "conflicting artifact records share one path".into(),
                        );
                    }
                }
            }
        }
    }

    let destination_root = match prepare_effect_artifact_root(out) {
        Ok(root) => Some(root),
        Err(reason) => {
            for (record, owners) in requested.values() {
                let _ = record;
                for owner in owners.iter().copied() {
                    let provider = &execution.results[owner].provider;
                    record_retention_failure(
                        &mut failures,
                        &mut provider_failures,
                        owner,
                        provider,
                        "output",
                        reason.clone(),
                    );
                }
            }
            None
        }
    };

    if let Some(destination_root) = destination_root {
        let source_root = scratch.artifacts_dir();
        for (record, owners) in requested.values() {
            if conflicting_paths.contains(&record.path) {
                continue;
            }
            let copied = read_effect_artifact(&source_root, record)
                .and_then(|bytes| write_effect_artifact(&destination_root, record, &bytes));
            if let Err(reason) = copied {
                for owner in owners.iter().copied() {
                    let provider = &execution.results[owner].provider;
                    record_retention_failure(
                        &mut failures,
                        &mut provider_failures,
                        owner,
                        provider,
                        "persistence",
                        reason.clone(),
                    );
                }
            }
        }
    }

    for (index, gaps) in provider_failures {
        let result = &mut execution.results[index].result;
        result.complete = false;
        if result.status != legion_contracts::ProviderStatus::Failed {
            result.status = legion_contracts::ProviderStatus::Partial;
        }
        result.coverage_gaps.extend(gaps.iter().cloned());
        result.coverage_gaps.sort();
        result.coverage_gaps.dedup();
        if let Some(coverage) = &mut result.coverage {
            coverage.gaps.extend(gaps.iter().cloned());
            coverage.gaps.sort();
            coverage.gaps.dedup();
        }
        result.details.insert(
            "effectArtifactRetention".into(),
            json!({"complete":false,"gaps":gaps}),
        );
    }
    failures.sort();
    failures.dedup();
    failures
}

fn prepare_effect_artifact_root(out: &std::path::Path) -> Result<std::path::PathBuf, String> {
    std::fs::create_dir_all(out).map_err(|error| format!("output root unavailable: {error}"))?;
    let output_root =
        std::fs::canonicalize(out).map_err(|error| format!("output root unavailable: {error}"))?;
    if !std::fs::symlink_metadata(&output_root)
        .map_err(|error| format!("output root unavailable: {error}"))?
        .is_dir()
    {
        return Err("output root is not a directory".into());
    }
    let artifact_root = output_root.join("artifacts");
    match std::fs::symlink_metadata(&artifact_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err("artifact output root is not a real directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&artifact_root)
                .map_err(|error| format!("artifact output root unavailable: {error}"))?;
        }
        Err(error) => return Err(format!("artifact output root unavailable: {error}")),
    }
    std::fs::canonicalize(&artifact_root)
        .map_err(|error| format!("artifact output root unavailable: {error}"))
}

fn write_effect_artifact(
    root: &std::path::Path,
    record: &EffectArtifactRef,
    bytes: &[u8],
) -> Result<(), String> {
    let relative = validate_effect_artifact_path(&record.path)?;
    let components = relative.components().collect::<Vec<_>>();
    let mut parent = root.to_path_buf();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        parent.push(component.as_os_str());
        match std::fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err("artifact output path contains a non-directory or symlink".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&parent)
                    .map_err(|error| format!("artifact output directory unavailable: {error}"))?;
            }
            Err(error) => return Err(format!("artifact output directory unavailable: {error}")),
        }
    }
    let destination = root.join(&relative);
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("artifact destination is not a regular file".into());
            }
            let existing = read_effect_artifact(root, record)
                .map_err(|reason| format!("artifact destination collision: {reason}"))?;
            if existing != bytes {
                return Err("artifact destination collision".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            legion_effects::ArtifactWriter::new(root)
                .write_immutable(&record.path, bytes)
                .map_err(|error| format!("artifact persistence failed: {error}"))?;
        }
        Err(error) => return Err(format!("artifact destination unavailable: {error}")),
    }
    let persisted = read_effect_artifact(root, record)?;
    if persisted != bytes {
        return Err("persisted artifact bytes differ from source".into());
    }
    Ok(())
}

fn record_retention_failure(
    failures: &mut Vec<String>,
    provider_failures: &mut std::collections::BTreeMap<usize, Vec<String>>,
    index: usize,
    provider: &str,
    stream: &str,
    reason: String,
) {
    let gap = format!("effect-artifact-retention:{provider}:{stream}:{reason}");
    failures.push(gap.clone());
    provider_failures.entry(index).or_default().push(gap);
}

fn direct_application(
    args: &AuditArgs,
    root: &std::path::Path,
) -> Result<
    (
        legion_application::NativeApplication,
        Vec<String>,
        Vec<String>,
    ),
    CommandError,
> {
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
    let plan_value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(plan).map_err(super::io_error)?)
            .map_err(|error| CommandError::usage(format!("invalid provider plan: {error}")))?;
    let specifications = parse_provider_plan_value(&plan_value)?;
    let mut read_results = Vec::new();
    for path in &args.provider_results {
        read_results.push(read_provider_result(path)?);
    }
    // A plan that carries a seal, signature or binding claims to be the frozen
    // plan of an earlier run: prove it against the current repository before
    // any provider result is trusted. A bare spec list makes no such claim and
    // stays accepted, but the run is marked so it cannot read as bound.
    let mut gaps = Vec::new();
    if plan_is_sealed(&plan_value) {
        let claimed_signature = plan_claimed_signature(&plan_value);
        let key = if claimed_signature.is_some() {
            Some(plan_verification_key(plan)?)
        } else {
            None
        };
        let sealed_digest =
            verify_sealed_plan(&plan_value, root, &*source, &specifications, key.as_deref())?;
        for (index, (_, named)) in read_results.iter().enumerate() {
            if let Some(named) = named {
                if *named != sealed_digest {
                    return Err(CommandError::integrity(format!(
                        "provider result {} names plan digest {named}, which differs from the plan digest {sealed_digest}",
                        args.provider_results[index].display()
                    )));
                }
            }
        }
        if claimed_signature.is_none() {
            gaps.push("unsigned-plan-seal".to_owned());
        }
    } else {
        gaps.push("unsealed-plan".to_owned());
    }
    let results = read_results
        .into_iter()
        .map(|(result, _)| result)
        .collect::<Vec<_>>();
    let application = legion_application::NativeApplicationConfig::for_audit_artifacts(
        root.to_string_lossy().into_owned(),
        source,
        specifications,
        results,
        Some(root.to_path_buf()),
    )
    .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok((application, Vec::new(), gaps))
}

/// True when the plan document carries any seal material (`planDigest`,
/// `planSignature`, `seal` or `binding`). A bare array or a bare spec list does
/// not.
fn plan_is_sealed(value: &serde_json::Value) -> bool {
    ["planDigest", "planSignature", "seal", "binding"]
        .iter()
        .any(|key| value.get(*key).is_some_and(|field| !field.is_null()))
}

fn plan_claimed_digest(value: &serde_json::Value) -> Option<&str> {
    value
        .get("planDigest")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .get("seal")
                .and_then(|seal| seal.get("digest"))
                .and_then(serde_json::Value::as_str)
        })
}

fn plan_claimed_signature(value: &serde_json::Value) -> Option<&str> {
    value
        .get("planSignature")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .get("seal")
                .and_then(|seal| seal.get("signature"))
                .and_then(serde_json::Value::as_str)
        })
}

/// Key that verifies a sealed plan, resolved like `legion verify` does: an
/// explicit `AUDIT_PLAN_SIGNING_KEY` wins, else the `epoch.key` stored next to
/// the plan file.
fn plan_verification_key(plan_path: &std::path::Path) -> Result<Vec<u8>, CommandError> {
    if let Some(value) = std::env::var_os("AUDIT_PLAN_SIGNING_KEY").filter(|v| !v.is_empty()) {
        return Ok(value.to_string_lossy().as_bytes().to_vec());
    }
    let directory = plan_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let key_file =
        directory.join(legion_audit::native_providers::reasoning::ingest::EPOCH_KEY_FILE);
    if !key_file.is_file() {
        return Err(CommandError::usage(format!(
            "the provider plan is signed but its key is unavailable: {} is missing and AUDIT_PLAN_SIGNING_KEY is not set",
            key_file.display()
        )));
    }
    legion_audit::native_providers::reasoning::ingest::load_epoch(directory)
        .map(|(key, _)| key)
        .map_err(|error| {
            CommandError::usage(format!(
                "cannot load plan signing key {}: {error}",
                key_file.display()
            ))
        })
}

/// Re-freezes the plan from its provider specifications over the current
/// inventory and compares it with the seal the plan file claims, using the same
/// routine (`legion_audit::verify`) that checks a plan at run time. Returns the
/// verified plan digest.
fn verify_sealed_plan(
    value: &serde_json::Value,
    root: &std::path::Path,
    source: &dyn legion_audit::InventorySource,
    specifications: &[legion_contracts::ProviderSpec],
    key: Option<&[u8]>,
) -> Result<String, CommandError> {
    let claimed_digest = plan_claimed_digest(value).ok_or_else(|| {
        CommandError::integrity("sealed provider plan carries no plan digest; refusing it")
    })?;
    if let (Some(top), Some(seal)) = (
        value.get("planDigest").and_then(serde_json::Value::as_str),
        value
            .get("seal")
            .and_then(|seal| seal.get("digest"))
            .and_then(serde_json::Value::as_str),
    ) {
        if top != seal {
            return Err(CommandError::integrity(
                "provider plan planDigest differs from its seal digest",
            ));
        }
    }
    let inventory = source
        .inventory(&root.to_string_lossy())
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    if let Some(binding) = value.get("binding").filter(|binding| !binding.is_null()) {
        let bound_digest = binding
            .get("inventoryDigest")
            .and_then(serde_json::Value::as_str);
        if bound_digest != Some(inventory.digest.as_str()) {
            return Err(CommandError::integrity(
                "provider plan binding does not match the current repository inventory",
            ));
        }
        let bound_revision = binding
            .get("repositoryRevision")
            .and_then(serde_json::Value::as_str);
        if bound_revision != Some(inventory.generation.as_str()) {
            return Err(CommandError::integrity(
                "provider plan binding repositoryRevision does not match the current inventory",
            ));
        }
    }
    let pending =
        legion_audit::AuditPlan::compile_with_root(Some(root), &inventory, specifications)
            .map_err(|error| CommandError::integrity(error.to_string()))?;
    legion_audit::verify(&pending, claimed_digest, plan_claimed_signature(value), key).map_err(
        |error| CommandError::integrity(format!("provider plan seal verification failed: {error}")),
    )?;
    Ok(claimed_digest.to_owned())
}

/// Accepts the shapes a provider plan can take: a bare array of provider
/// objects, a `providerSpecs` array (what `--plan-only` writes alongside its
/// provider ids), or a `providers` array of provider objects. A `providers`
/// array of ids alone carries no specifications and is rejected explicitly.
fn parse_provider_plan_value(
    value: &serde_json::Value,
) -> Result<Vec<legion_contracts::ProviderSpec>, CommandError> {
    let providers = if let Some(array) = value.as_array() {
        array
    } else if let Some(array) = value
        .get("providerSpecs")
        .and_then(serde_json::Value::as_array)
    {
        array
    } else if let Some(array) = value.get("providers").and_then(serde_json::Value::as_array) {
        if array.iter().any(|item| !item.is_object()) {
            return Err(CommandError::usage(
                "provider plan carries provider ids only; it has no provider specifications. Use the plan written with providerSpecs (for example the plan.json from --plan-only), or a plan whose providers are objects",
            ));
        }
        array
    } else {
        return Err(CommandError::usage(
            "provider plan must be an array or contain providerSpecs or providers",
        ));
    };
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

/// Reads a provider result file and the plan digest it names, if any. The
/// digest may sit beside a `providerResult` wrapper, inside the result, or in
/// `details.planDigest`.
fn read_provider_result(
    path: &std::path::Path,
) -> Result<(legion_contracts::ProviderResult, Option<String>), CommandError> {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).map_err(super::io_error)?)
            .map_err(|error| CommandError::usage(format!("invalid provider result: {error}")))?;
    let named = named_plan_digest(&value);
    let mut result = value.get("providerResult").cloned().unwrap_or(value);
    if let Some(object) = result.as_object_mut() {
        object.remove("planDigest");
    }
    let result = serde_json::from_value(result).map_err(|error| {
        CommandError::usage(format!("invalid provider result contract: {error}"))
    })?;
    Ok((result, named))
}

fn named_plan_digest(value: &serde_json::Value) -> Option<String> {
    let inner = value.get("providerResult").unwrap_or(value);
    value
        .get("planDigest")
        .and_then(serde_json::Value::as_str)
        .or_else(|| inner.get("planDigest").and_then(serde_json::Value::as_str))
        .or_else(|| {
            inner
                .get("details")
                .and_then(|details| details.get("planDigest"))
                .and_then(serde_json::Value::as_str)
        })
        .map(ToOwned::to_owned)
}

fn write_artifact(root: &std::path::Path, name: &str, bytes: &[u8]) -> Result<(), CommandError> {
    std::fs::create_dir_all(root).map_err(super::io_error)?;
    let destination = root.join(name);
    let temporary = root.join(format!(".{name}.tmp-{}", std::process::id()));
    std::fs::write(&temporary, bytes).map_err(super::io_error)?;
    std::fs::rename(&temporary, destination).map_err(super::io_error)
}

#[cfg(test)]
mod provider_plan_reader_tests {
    use super::*;

    #[test]
    fn provider_plan_prefers_provider_specs_over_provider_ids() {
        // `--plan-only` writes provider ids under `providers` and the full
        // specifications under `providerSpecs`; the reader must use the latter.
        let plan = json!({
            "providers": ["reasoning.security", "reasoning.data-safety"],
            "providerSpecs": []
        });
        let specs = parse_provider_plan_value(&plan).expect("providerSpecs is readable");
        assert!(specs.is_empty());
    }

    #[test]
    fn provider_plan_with_ids_only_is_a_clear_usage_error() {
        let plan = json!({"providers": ["reasoning.security"]});
        match parse_provider_plan_value(&plan) {
            Ok(_) => panic!("ids-only plan must be rejected"),
            Err(error) => {
                assert_eq!(error.code, 4);
                assert!(
                    error.message.contains("provider ids only"),
                    "{}",
                    error.message
                );
            }
        }
    }

    #[test]
    fn provider_plan_rejects_documents_without_any_provider_list() {
        match parse_provider_plan_value(&json!({"kind": "audit-provider-plan"})) {
            Ok(_) => panic!("plan without providers must be rejected"),
            Err(error) => assert_eq!(error.code, 4),
        }
    }
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
            findings_args: Vec::new(),
            findings_repo: None,
            findings_by: None,
            findings_generation: None,
            findings_active: false,
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

    fn runtime_spec() -> legion_contracts::ProviderSpec {
        serde_json::from_value(json!({
            "schemaVersion": 2,
            "id": "legacy.runtime.app",
            "providerVersion": "2.0.0",
            "family": "performance",
            "lensIds": ["runtime"],
            "role": "deterministic",
            "phase": "runtime",
            "dependsOn": [],
            "consumes": [],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "runnable app",
            "runner": {"kind": "legacy-check", "check": "runtime"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {"status": "unproven", "requiredForCleanClaim": false},
            "cleanClaim": "evidence-only",
            "controlIds": [],
            "scopes": [],
            "selectable": true
        }))
        .unwrap()
    }

    #[test]
    fn runtime_inputs_reach_the_runtime_provider_runner() {
        let mut args = minimal_audit_args();
        args.url = Some("http://127.0.0.1:1422/?qa=1".into());
        args.surfaces = Some("/settings, https://example.test/other".into());
        args.width = 390;
        args.height = 844;
        let mut specs = vec![runtime_spec()];
        let (gaps, injected) = apply_runtime_inputs(&args, &mut specs, false).unwrap();
        assert!(injected);
        assert!(gaps.is_empty(), "{gaps:?}");
        let runtime = &specs[0].runner["runtime"];
        assert_eq!(runtime["url"], "http://127.0.0.1:1422/?qa=1");
        assert_eq!(runtime["width"], 390);
        assert_eq!(runtime["height"], 844);
        assert_eq!(
            runtime["surfaces"],
            json!([
                {"label": "/settings", "url": "http://127.0.0.1:1422/settings"},
                {"label": "https://example.test/other", "url": "https://example.test/other"},
            ])
        );
    }

    #[test]
    fn runtime_visual_capture_source_is_frozen_only_without_explicit_spec() {
        let mut args = minimal_audit_args();
        args.url = Some("https://example.test/".into());
        let mut specs = vec![runtime_spec(), visual_spec_provider()];
        apply_runtime_inputs(&args, &mut specs, false).unwrap();
        apply_visual_inputs(&args, &mut specs, false).unwrap();
        bind_runtime_visual_capture_source(&mut specs);
        assert_eq!(
            specs[1].runner["visual"]["captureSource"],
            json!({"kind":"runtime-provider","providerId":RUNTIME_PROVIDER_ID})
        );

        let (spec_path, _) = visual_fixture("capture-source-explicit");
        args.visual_spec = Some(spec_path);
        let mut explicit = vec![runtime_spec(), visual_spec_provider()];
        apply_runtime_inputs(&args, &mut explicit, false).unwrap();
        apply_visual_inputs(&args, &mut explicit, false).unwrap();
        bind_runtime_visual_capture_source(&mut explicit);
        assert!(explicit[1].runner["visual"].get("captureSource").is_none());
    }

    #[test]
    fn runtime_inputs_without_a_consumer_or_a_url_are_named_gaps() {
        // No URL: nothing is injected; stray surfaces/viewport are named.
        let mut args = minimal_audit_args();
        args.surfaces = Some("/a".into());
        args.width = 800;
        let mut specs = vec![runtime_spec()];
        let (gaps, injected) = apply_runtime_inputs(&args, &mut specs, false).unwrap();
        assert!(!injected);
        assert_eq!(
            gaps,
            vec![
                "runtime-surfaces-ignored:runtime-url-not-supplied".to_owned(),
                "runtime-viewport-ignored:runtime-url-not-supplied".to_owned(),
            ]
        );
        assert!(specs[0].runner.get("runtime").is_none());

        // URL but the provider was not selected, or the plan is pre-frozen.
        let mut args = minimal_audit_args();
        args.url = Some("http://127.0.0.1:1/".into());
        let (gaps, injected) = apply_runtime_inputs(
            &args,
            &mut Vec::<legion_contracts::ProviderSpec>::new(),
            false,
        )
        .unwrap();
        assert!(!injected);
        assert_eq!(
            gaps,
            vec!["runtime-inputs-not-consumed:provider-not-selected".to_owned()]
        );
        let (gaps, injected) =
            apply_runtime_inputs(&args, &mut vec![runtime_spec()], true).unwrap();
        assert!(!injected);
        assert_eq!(
            gaps,
            vec!["runtime-inputs-not-consumed:provider-plan-supplied".to_owned()]
        );
    }

    #[test]
    fn invalid_runtime_url_is_a_usage_error() {
        let mut args = minimal_audit_args();
        args.url = Some("file:///etc/hosts".into());
        let error = apply_runtime_inputs(&args, &mut vec![runtime_spec()], false).unwrap_err();
        assert!(
            error.message.contains("invalid runtime inputs"),
            "{}",
            error.message
        );
    }

    fn visual_spec_provider() -> legion_contracts::ProviderSpec {
        serde_json::from_value(json!({
            "schemaVersion": 2,
            "id": "legacy.visual.core",
            "providerVersion": "2.0.0",
            "family": "visual",
            "lensIds": ["visual"],
            "role": "deterministic",
            "phase": "runtime",
            "dependsOn": [],
            "consumes": [],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "selected-scope",
            "runner": {"kind": "runtime-script", "module": "legacy.visual.core"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {"status": "unproven", "requiredForCleanClaim": false},
            "cleanClaim": "evidence-only",
            "controlIds": [],
            "scopes": [],
            "selectable": true
        }))
        .unwrap()
    }

    /// A visual spec file and a baselines directory with one baseline.
    fn visual_fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("legion-bins-visual-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let baselines = dir.join("baselines");
        std::fs::create_dir_all(&baselines).unwrap();
        std::fs::write(baselines.join("home.png"), b"baseline-home").unwrap();
        let spec = dir.join("visual-spec.json");
        std::fs::write(
            &spec,
            br#"{"expected":{"routes":["/"]},"captures":[{"id":"home","path":"shots/home.png","baseline":"home.png"}]}"#,
        )
        .unwrap();
        (spec, baselines)
    }

    #[test]
    fn visual_inputs_freeze_into_the_visual_runner_without_gaps() {
        let (spec_path, baselines) = visual_fixture("freeze");
        let mut args = minimal_audit_args();
        args.visual_spec = Some(spec_path.clone());
        args.visual_baselines = Some(baselines);
        let mut specs = vec![visual_spec_provider()];

        let (gaps, injected) = apply_visual_inputs(&args, &mut specs, false).unwrap();

        assert!(gaps.is_empty(), "consumed inputs add no gap: {gaps:?}");
        assert!(injected);
        let visual = &specs[0].runner["visual"];
        let spec_bytes = std::fs::read(&spec_path).unwrap();
        assert_eq!(
            visual["specDigest"],
            legion_audit::native_providers::legacy::common::digest_bytes(&spec_bytes)
        );
        assert_eq!(visual["spec"]["captures"][0]["id"], "home");
        assert_eq!(visual["baselines"]["files"][0]["path"], "home.png");
        assert!(visual["baselines"]["digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:")));
    }

    #[test]
    fn visual_inputs_without_a_consumer_are_named_gaps() {
        let (spec_path, _) = visual_fixture("gaps");
        let mut args = minimal_audit_args();
        args.visual_spec = Some(spec_path);

        let (gaps, injected) =
            apply_visual_inputs(&args, &mut vec![runtime_spec()], false).unwrap();
        assert_eq!(
            gaps,
            vec!["visual-inputs-not-consumed:provider-not-selected".to_owned()]
        );
        assert!(!injected);

        let (gaps, injected) =
            apply_visual_inputs(&args, &mut vec![visual_spec_provider()], true).unwrap();
        assert_eq!(
            gaps,
            vec!["visual-inputs-not-consumed:provider-plan-supplied".to_owned()]
        );
        assert!(!injected);
    }

    #[test]
    fn no_visual_inputs_add_no_gap_or_injection() {
        let args = minimal_audit_args();
        let mut specs = vec![visual_spec_provider()];
        let (gaps, injected) = apply_visual_inputs(&args, &mut specs, false).unwrap();
        assert!(gaps.is_empty());
        assert!(!injected);
        assert!(specs[0].runner.get("visual").is_none());
        assert!(native_audit_input_gaps(&args, &[]).is_empty());
    }

    #[test]
    fn malformed_visual_spec_is_a_usage_error_naming_the_problem() {
        let (spec_path, _) = visual_fixture("malformed");
        let mut args = minimal_audit_args();
        args.visual_spec = Some(spec_path.clone());

        std::fs::write(&spec_path, b"[1,2]").unwrap();
        let error =
            apply_visual_inputs(&args, &mut vec![visual_spec_provider()], false).unwrap_err();
        assert!(
            error.message.contains("invalid --visual-spec"),
            "{}",
            error.message
        );
        assert!(error.message.contains("JSON object"), "{}", error.message);

        std::fs::write(
            &spec_path,
            br#"{"captures":[{"id":"a","path":"../escape.png"}]}"#,
        )
        .unwrap();
        let error =
            apply_visual_inputs(&args, &mut vec![visual_spec_provider()], false).unwrap_err();
        assert!(error.message.contains("relative path"), "{}", error.message);
    }

    #[test]
    fn visual_baselines_must_be_an_existing_directory() {
        let (_, baselines) = visual_fixture("not-a-dir");
        let mut args = minimal_audit_args();
        args.visual_baselines = Some(baselines.join("home.png"));
        let error =
            apply_visual_inputs(&args, &mut vec![visual_spec_provider()], false).unwrap_err();
        assert!(
            error.message.contains("invalid --visual-baselines"),
            "{}",
            error.message
        );

        args.visual_baselines = Some(baselines.join("missing"));
        let error =
            apply_visual_inputs(&args, &mut vec![visual_spec_provider()], false).unwrap_err();
        assert!(
            error.message.contains("invalid --visual-baselines"),
            "{}",
            error.message
        );
    }

    #[test]
    fn surface_targets_resolve_against_the_entry_origin() {
        assert_eq!(
            resolve_surface_url("http://127.0.0.1:1422/app?qa=1#top", "/x?y=1").unwrap(),
            "http://127.0.0.1:1422/x?y=1"
        );
        assert_eq!(resolve_surface_url("http://h", "/x").unwrap(), "http://h/x");
        assert_eq!(
            resolve_surface_url("http://h/", "HTTPS://o/p").unwrap(),
            "HTTPS://o/p"
        );
        assert!(resolve_surface_url("http://h/", "relative").is_err());
        assert!(resolve_surface_url("http://h/", "//evil/x").is_err());
    }

    #[test]
    fn surfaces_file_separates_navigable_and_click_only_targets() {
        let dir = std::env::temp_dir().join(format!("legion-surfaces-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("targets.json");
        std::fs::write(
            &file,
            br##"[{"label":"prefs","route":"/prefs"},{"label":"editor","text":"New text"},{"selector":"#go"}]"##,
        )
        .unwrap();
        let mut args = minimal_audit_args();
        args.surfaces = Some(file.to_string_lossy().into_owned());
        let (surfaces, unsupported) = runtime_surface_inputs(&args, "http://127.0.0.1:9/").unwrap();
        assert_eq!(
            surfaces,
            vec![("prefs".to_owned(), "http://127.0.0.1:9/prefs".to_owned())]
        );
        assert_eq!(unsupported, vec!["editor".to_owned(), "#go".to_owned()]);
        std::fs::remove_dir_all(dir).unwrap();
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
            findings_args: Vec::new(),
            findings_repo: None,
            findings_by: None,
            findings_generation: None,
            findings_active: false,
        }
    }
}

#[cfg(test)]
mod sealed_plan_tests {
    use super::*;
    use legion_audit::InventorySource as _;

    const KEY: &[u8] = b"sealed-plan-test-key";

    fn spec() -> legion_contracts::ProviderSpec {
        serde_json::from_value(json!({
            "schemaVersion": 2,
            "id": "fixture-provider",
            "providerVersion": "1",
            "family": "fixture",
            "lensIds": [],
            "role": "deterministic",
            "phase": "source",
            "dependsOn": [],
            "consumes": ["repository-inventory"],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "selected-scope",
            "runner": {"kind": "built-in"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {
                "status": "qualified",
                "requiredForCleanClaim": true,
                "qualificationDigest": "sha256:fixture"
            },
            "cleanClaim": "finding-producing",
            "controlIds": [],
            "scopes": [],
            "selectable": true
        }))
        .expect("fixture provider spec")
    }

    fn fixture_root(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("legion-sealed-plan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        std::fs::canonicalize(root).unwrap()
    }

    /// A sealed plan document exactly as `--plan-only` shapes it.
    fn sealed_plan(root: &std::path::Path) -> serde_json::Value {
        let source = crate::commands::audit_inventory_source(root).unwrap();
        let inventory = source.inventory(&root.to_string_lossy()).unwrap();
        let specs = vec![spec()];
        let frozen = legion_audit::AuditPlan::compile_with_root(Some(root), &inventory, &specs)
            .unwrap()
            .freeze(Some(KEY))
            .unwrap();
        json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "planDigest": frozen.digest(),
            "planSignature": frozen.signature(),
            "seal": {
                "digest": frozen.digest(),
                "authenticity": "hmac-sha256",
                "signature": frozen.signature(),
            },
            "binding": {
                "repositoryRevision": inventory.generation,
                "inventoryDigest": inventory.digest,
            },
            "providers": ["fixture-provider"],
            "providerSpecs": specs,
        })
    }

    fn frozen_basis(root: &std::path::Path) -> LensBasis {
        let source = crate::commands::audit_inventory_source(root).unwrap();
        let inventory = source.inventory(&root.to_string_lossy()).unwrap();
        let frozen = legion_audit::AuditPlan::compile_with_root(Some(root), &inventory, &[spec()])
            .unwrap()
            .freeze(Some(KEY))
            .unwrap();
        Ok((frozen, inventory))
    }

    #[test]
    fn normal_native_plan_projects_exact_frozen_plan_and_binding() {
        let root = fixture_root("native-plan-projection");
        let basis = frozen_basis(&root);
        let (frozen, _) = basis.as_ref().unwrap();
        let digest = frozen.digest().to_owned();
        let signature = frozen.signature().map(ToOwned::to_owned);
        let expected_plan = serde_json::to_value(frozen.plan()).unwrap();

        let native = native_plan_document(&basis, &digest, signature.as_deref()).unwrap();

        assert_eq!(native["schemaVersion"], 1);
        assert_eq!(native["plan"], expected_plan);
        assert_eq!(native["digest"], digest);
        assert_eq!(native["signature"], signature.unwrap());
    }

    #[test]
    fn normal_native_plan_rejects_digest_or_signature_drift() {
        let root = fixture_root("native-plan-mismatch");
        let basis = frozen_basis(&root);
        let (frozen, _) = basis.as_ref().unwrap();
        let digest = frozen.digest().to_owned();
        let signature = frozen.signature().map(ToOwned::to_owned).unwrap();

        assert!(native_plan_document(&basis, "sha256:wrong", Some(&signature)).is_err());
        assert!(native_plan_document(&basis, &digest, Some("wrong-signature")).is_err());
    }

    fn verify(
        plan: &serde_json::Value,
        root: &std::path::Path,
        key: Option<&[u8]>,
    ) -> Result<String, CommandError> {
        let source = crate::commands::audit_inventory_source(root).unwrap();
        let specs = parse_provider_plan_value(plan).unwrap();
        verify_sealed_plan(plan, root, &*source, &specs, key)
    }

    #[test]
    fn sealed_plan_is_accepted_and_returns_its_digest() {
        let root = fixture_root("accepted");
        let plan = sealed_plan(&root);
        assert!(plan_is_sealed(&plan));
        let digest = verify(&plan, &root, Some(KEY)).expect("sealed plan verifies");
        assert_eq!(Some(digest.as_str()), plan["planDigest"].as_str());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_sealed_plan_is_refused() {
        let root = fixture_root("tampered");
        let mut plan = sealed_plan(&root);
        // Specs edited after sealing: the recompiled digest no longer matches.
        plan["providerSpecs"][0]["providerVersion"] = json!("2");
        let error = verify(&plan, &root, Some(KEY)).expect_err("tampered specs refused");
        assert_eq!(error.code, 5, "{}", error.message);

        // Digest and signature edited: the claimed digest no longer matches.
        let mut plan = sealed_plan(&root);
        let forged = format!("sha256:{}", "0".repeat(64));
        plan["planDigest"] = json!(forged);
        plan["seal"]["digest"] = json!(forged);
        assert_eq!(verify(&plan, &root, Some(KEY)).unwrap_err().code, 5);

        // Wrong key: the HMAC no longer verifies.
        let plan = sealed_plan(&root);
        assert_eq!(
            verify(&plan, &root, Some(b"another-key")).unwrap_err().code,
            5
        );

        // Binding to a different inventory is refused with a clear message.
        let mut plan = sealed_plan(&root);
        plan["binding"]["inventoryDigest"] = json!(format!("sha256:{}", "1".repeat(64)));
        let error = verify(&plan, &root, Some(KEY)).unwrap_err();
        assert!(error.message.contains("binding"), "{}", error.message);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repository_drift_after_sealing_is_refused() {
        let root = fixture_root("drift");
        let plan = sealed_plan(&root);
        std::fs::write(root.join("src/extra.rs"), "pub fn extra() {}\n").unwrap();
        assert_eq!(verify(&plan, &root, Some(KEY)).unwrap_err().code, 5);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_spec_lists_are_unsealed() {
        assert!(!plan_is_sealed(&json!([])));
        assert!(!plan_is_sealed(&json!({"providers": [{"id": "x"}]})));
        assert!(!plan_is_sealed(
            &json!({"providers": [], "planDigest": null, "seal": null})
        ));
        assert!(plan_is_sealed(&json!({"providers": [], "binding": {}})));
    }

    #[test]
    fn result_plan_digest_is_read_from_every_supported_place() {
        assert_eq!(
            named_plan_digest(&json!({"providerResult": {}, "planDigest": "sha256:a"})),
            Some("sha256:a".to_owned())
        );
        assert_eq!(
            named_plan_digest(&json!({"providerResult": {"planDigest": "sha256:b"}})),
            Some("sha256:b".to_owned())
        );
        assert_eq!(
            named_plan_digest(&json!({"details": {"planDigest": "sha256:c"}})),
            Some("sha256:c".to_owned())
        );
        assert_eq!(named_plan_digest(&json!({"details": {}})), None);
    }

    /// The frozen `runner.visual` object is part of the compiled plan, so the
    /// sealed digest changes when the frozen visual spec digest changes.
    #[test]
    fn sealed_plan_covers_the_frozen_visual_inputs() {
        let root = fixture_root("visual-seal");
        let source = crate::commands::audit_inventory_source(&root).unwrap();
        let inventory = source.inventory(&root.to_string_lossy()).unwrap();
        let sealed_digest = |spec_digest: &str| {
            let mut provider = spec();
            provider
                .runner
                .as_object_mut()
                .expect("fixture runner is an object")
                .insert(
                    "visual".into(),
                    json!({"spec": {"expected": {"routes": ["/"]}}, "specDigest": spec_digest}),
                );
            legion_audit::AuditPlan::compile_with_root(
                Some(root.as_path()),
                &inventory,
                &[provider],
            )
            .unwrap()
            .freeze(Some(KEY))
            .unwrap()
            .digest()
            .to_owned()
        };
        let first = sealed_digest("sha256:first");
        assert_eq!(first, sealed_digest("sha256:first"));
        assert_ne!(first, sealed_digest("sha256:second"));
    }
}

#[cfg(test)]
mod effect_artifact_retention_tests {
    use super::*;

    fn root(label: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "legion-effect-retention-{label}-{}-{suffix}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn record(path: &str, bytes: &[u8]) -> Value {
        json!({
            "path": path,
            "digest": format!("sha256:{}", sha256_hex(bytes)),
            "bytes": bytes.len(),
            "immutable": true
        })
    }

    fn execution(stdout: Option<Value>, stderr: Option<Value>) -> legion_audit::ExecutionReport {
        let mut receipt = serde_json::Map::new();
        if let Some(stdout) = stdout {
            receipt.insert("stdout".into(), stdout);
        }
        if let Some(stderr) = stderr {
            receipt.insert("stderr".into(), stderr);
        }
        let result = legion_contracts::ProviderResult {
            schema_version: 1,
            provider: legion_contracts::ProviderId::new("fixture.external").unwrap(),
            applicable: true,
            required: true,
            status: legion_contracts::ProviderStatus::Complete,
            complete: true,
            coverage: None,
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: std::collections::BTreeMap::from([(
                "executionReceipt".into(),
                Value::Object(receipt),
            )]),
        };
        legion_audit::ExecutionReport {
            results: vec![legion_audit::ProviderExecution {
                provider: "fixture.external".into(),
                result,
                skipped: false,
            }],
            ..Default::default()
        }
    }

    fn scratch(
        root: &std::path::Path,
    ) -> legion_audit::native_providers::legacy_checks::AuditScratch {
        legion_audit::native_providers::legacy_checks::AuditScratch::create(root).unwrap()
    }

    fn write_source(
        scratch: &legion_audit::native_providers::legacy_checks::AuditScratch,
        path: &str,
        bytes: &[u8],
    ) {
        legion_effects::ArtifactWriter::new(scratch.artifacts_dir())
            .write_immutable(path, bytes)
            .unwrap();
    }

    #[test]
    fn referenced_stdout_and_stderr_survive_scratch_cleanup() {
        let base = root("survive");
        let repository = base.join("repo");
        let out = base.join("run");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let stdout = b"test stdout";
        let stderr = b"test stderr";
        let scratch = scratch(&repository);
        write_source(&scratch, "fixture/stdout", stdout);
        write_source(&scratch, "fixture/stderr", stderr);
        let mut execution = execution(
            Some(record("fixture/stdout", stdout)),
            Some(record("fixture/stderr", stderr)),
        );

        assert!(retain_effect_artifacts(&out, &scratch, &mut execution).is_empty());
        assert!(execution.results[0].result.complete);
        drop(scratch);
        assert_eq!(
            std::fs::read(out.join("artifacts/fixture/stdout")).unwrap(),
            stdout
        );
        assert_eq!(
            std::fs::read(out.join("artifacts/fixture/stderr")).unwrap(),
            stderr
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn failed_process_output_is_retained_with_its_receipt() {
        let base = root("failed-process");
        let repository = base.join("repo");
        let out = base.join("run");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let scratch = scratch(&repository);
        let stdout = b"assertion failed";
        let stderr = b"diagnostic output";
        write_source(&scratch, "fixture/stdout", stdout);
        write_source(&scratch, "fixture/stderr", stderr);
        let mut execution = execution(
            Some(record("fixture/stdout", stdout)),
            Some(record("fixture/stderr", stderr)),
        );
        execution.results[0].result.complete = false;
        execution.results[0].result.status = legion_contracts::ProviderStatus::Failed;

        assert!(retain_effect_artifacts(&out, &scratch, &mut execution).is_empty());
        assert!(!execution.results[0].result.complete);
        assert_eq!(
            std::fs::read(out.join("artifacts/fixture/stdout")).unwrap(),
            stdout
        );
        assert_eq!(
            std::fs::read(out.join("artifacts/fixture/stderr")).unwrap(),
            stderr
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn native_summary_streams_are_skipped_while_external_artifacts_are_retained() {
        let base = root("mixed-receipts");
        let repository = base.join("repo");
        let out = base.join("run");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let scratch = scratch(&repository);
        let stdout = b"external command output";
        write_source(&scratch, "fixture/stdout", stdout);
        let mut execution = execution(Some(record("fixture/stdout", stdout)), None);

        let summary = json!({
            "kind": "native-legacy-check-receipt",
            "stdout": {"path": null, "digest": format!("sha256:{}", sha256_hex(b"summary")), "bytes": 7, "immutable": false},
            "stderr": {"path": null, "digest": format!("sha256:{}", sha256_hex(b"")), "bytes": 0, "immutable": false}
        });
        let mut native_result = execution.results[0].result.clone();
        native_result.provider =
            legion_contracts::ProviderId::new("legacy.native.fixture").unwrap();
        native_result
            .details
            .insert("executionReceipt".into(), summary);
        execution.results.push(legion_audit::ProviderExecution {
            provider: "legacy.native.fixture".into(),
            result: native_result,
            skipped: false,
        });

        assert!(retain_effect_artifacts(&out, &scratch, &mut execution).is_empty());
        assert!(execution.results.iter().all(|item| item.result.complete));
        assert_eq!(
            std::fs::read(out.join("artifacts/fixture/stdout")).unwrap(),
            stdout
        );
        assert!(!out.join("artifacts/null").exists());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn missing_tampered_and_escaped_sources_are_incomplete() {
        let base = root("source-invalid");
        let repository = base.join("repo");
        let out = base.join("run");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let scratch = scratch(&repository);

        let mut missing = execution(Some(record("missing/stdout", b"expected")), None);
        let gaps = retain_effect_artifacts(&out, &scratch, &mut missing);
        assert!(!gaps.is_empty());
        assert!(!missing.results[0].result.complete);

        write_source(&scratch, "fixture/tampered", b"tamper!!");
        let mut tampered = execution(Some(record("fixture/tampered", b"expected")), None);
        let gaps = retain_effect_artifacts(&out, &scratch, &mut tampered);
        assert!(gaps.iter().any(|gap| gap.contains("digest or size")));
        assert!(!tampered.results[0].result.complete);

        let mut escaped = execution(Some(record("../outside", b"expected")), None);
        let gaps = retain_effect_artifacts(&out, &scratch, &mut escaped);
        assert!(gaps.iter().any(|gap| gap.contains("escapes")));
        assert!(!escaped.results[0].result.complete);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn conflicting_destination_is_not_overwritten() {
        let base = root("collision");
        let repository = base.join("repo");
        let out = base.join("run");
        std::fs::create_dir_all(&repository).unwrap();
        let scratch = scratch(&repository);
        let expected = b"expected bytes";
        write_source(&scratch, "fixture/stdout", expected);
        let destination = out.join("artifacts/fixture");
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(destination.join("stdout"), b"preexisting different bytes").unwrap();
        let mut execution = execution(Some(record("fixture/stdout", expected)), None);

        let gaps = retain_effect_artifacts(&out, &scratch, &mut execution);
        assert!(gaps.iter().any(|gap| gap.contains("collision")));
        assert!(!execution.results[0].result.complete);
        assert_eq!(
            std::fs::read(destination.join("stdout")).unwrap(),
            b"preexisting different bytes"
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn oversized_existing_destination_is_rejected_before_read() {
        let base = root("oversized-destination");
        let repository = base.join("repo");
        let out = base.join("run");
        std::fs::create_dir_all(&repository).unwrap();
        let scratch = scratch(&repository);
        let expected = b"small output";
        write_source(&scratch, "fixture/stdout", expected);
        let destination = out.join("artifacts/fixture/stdout");
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::File::create(&destination)
            .unwrap()
            .set_len(8 * 1024 * 1024 + 1)
            .unwrap();
        let mut execution = execution(Some(record("fixture/stdout", expected)), None);

        let gaps = retain_effect_artifacts(&out, &scratch, &mut execution);
        assert!(gaps.iter().any(|gap| gap.contains("collision")));
        assert!(!execution.results[0].result.complete);
        assert_eq!(
            std::fs::metadata(&destination).unwrap().len(),
            8 * 1024 * 1024 + 1
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn every_owner_of_a_conflicting_path_is_incomplete() {
        let base = root("conflicting-references");
        let out = base.join("run");
        std::fs::create_dir_all(&out).unwrap();
        let scratch = scratch(&base);
        let mut execution = execution(Some(record("fixture/stdout", b"first")), None);

        let mut conflicting = execution.results[0].clone();
        conflicting.provider = "fixture.conflicting".into();
        conflicting.result.provider =
            legion_contracts::ProviderId::new("fixture.conflicting").unwrap();
        conflicting.result.details.insert(
            "executionReceipt".into(),
            json!({"stdout": record("fixture/stdout", b"second")}),
        );
        let mut original_again = execution.results[0].clone();
        original_again.provider = "fixture.original-again".into();
        original_again.result.provider =
            legion_contracts::ProviderId::new("fixture.original-again").unwrap();
        execution.results.push(conflicting);
        execution.results.push(original_again);

        let gaps = retain_effect_artifacts(&out, &scratch, &mut execution);
        assert!(!gaps.is_empty());
        assert!(execution.results.iter().all(|item| !item.result.complete));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_output_parent_is_rejected_without_escape() {
        use std::os::unix::fs::symlink;

        let base = root("containment");
        let repository = base.join("repo");
        let out = base.join("run");
        let outside = base.join("outside");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&out.join("artifacts")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, out.join("artifacts/fixture")).unwrap();
        let scratch = scratch(&repository);
        let expected = b"expected bytes";
        write_source(&scratch, "fixture/stdout", expected);
        let mut execution = execution(Some(record("fixture/stdout", expected)), None);

        let gaps = retain_effect_artifacts(&out, &scratch, &mut execution);
        assert!(gaps.iter().any(|gap| gap.contains("symlink")));
        assert!(!execution.results[0].result.complete);
        assert!(!outside.join("stdout").exists());
        std::fs::remove_dir_all(base).unwrap();
    }
}
