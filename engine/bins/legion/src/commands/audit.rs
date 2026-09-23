use super::{CommandError, CommandResult};
use clap::Args;
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
}
pub async fn run(args: AuditArgs, cancellation: CancellationToken) -> CommandResult {
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
    let direct = args.provider_plan.is_some()
        || !args.provider_results.is_empty();
    let signing_key = if args.plan_only {
        Some(super::audit_signing_key()?)
    } else {
        std::env::var_os("AUDIT_PLAN_SIGNING_KEY")
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string_lossy().as_bytes().to_vec())
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
        let (application, notices) = native_registry_application(&args, &root)?;
        (Arc::new(application), notices)
    };
    let mut selected_specs = application.provider_specs();
    let configured_ids = selected_specs.iter().map(|provider| provider.id.as_str()).collect::<std::collections::BTreeSet<_>>();
    for requested in args.only.iter().chain(args.skip.iter()) {
        if !configured_ids.contains(requested.as_str()) {
            return Err(CommandError::usage(format!("unknown provider: {requested}")));
        }
    }
    // Keep provider selection deterministic and equivalent to audit-run's
    // repeated --only/--skip flags. Filtering happens before plan compilation,
    // therefore excluded providers cannot affect frozen denominators or DAG.
    if !args.only.is_empty() {
        selected_specs.retain(|provider| args.only.iter().any(|id| id == provider.id.as_str()));
    }
    if !args.skip.is_empty() {
        selected_specs.retain(|provider| !args.skip.iter().any(|id| id == provider.id.as_str()));
    }
    if let Some(family) = &args.r#type {
        selected_specs.retain(|provider| provider.family == *family);
    }
    if selected_specs.is_empty() {
        return Err(CommandError::usage("provider selection produced an empty plan"));
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
            signing_key,
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
            let binding = native_inventory_binding(&root, &args)?;
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
                "inputGaps": native_audit_input_gaps(&args)
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

fn validate_output_dir(root: &std::path::Path, requested: &std::path::Path) -> Result<(), CommandError> {
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
                "execution_status": if entry.skipped { "skipped" } else { "ran" },
                "verdict": if entry.result.complete { "pass" } else { "unproven" },
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
    if args.native_rule_manifest.is_some() { gaps.push("native-provider-composition-partial".into()); }
    // Visual options (--url/--surfaces/--visual-spec/--visual-baselines/--width/
    // --height) stay accepted-and-inert without a gap record: Node's bare CLI
    // behaves the same way (the frozen registry has no visual.core provider),
    // so recording a gap here would diverge from Node by forcing Incomplete
    // where Node completes.
    gaps
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
        && reference
            .chars()
            .all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '_' | '/' | '@' | '-')
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
        files.retain(|file| {
            !file.starts_with(".audit/") && !is_generated_or_vendored_path(file)
        });
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
    let refs_valid = AuditScope::ref_is_valid(&scope_base)
        && AuditScope::ref_is_valid(&scope_base_commit);
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
    })).map_err(|error| CommandError::internal(error.to_string()))?;
    let source = super::audit_inventory_source(root)?;
    let executor = super::rules::NativeRuleProviderExecutor::new(root.to_path_buf(), manifest.to_path_buf(), 1_048_576)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let application = legion_application::NativeApplicationConfig::for_audit_executor(
        root.to_string_lossy().into_owned(), source, vec![provider], Arc::new(executor), Some(root.to_path_buf()),
    ).map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok((application, Vec::new()))
}

fn native_registry_application(
    args: &AuditArgs,
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
    std::sync::Arc::new(legion_audit::native_providers::legacy_checks::AuditExternalProjectTool::new(effects))
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
        }
    }
}
