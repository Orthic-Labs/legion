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
    /// Explicit host enrollment for RustRight attested test-run execution.
    /// Supported only by the native provider registry route.
    #[arg(long = "rightkit-trust")]
    pub rightkit_trust: Option<PathBuf>,
    /// Frozen, declarative browser-probe descriptors (JSON array). Descriptors
    /// are authorization requests only; runtime probes remain unavailable until
    /// a trusted host isolation verifier is configured.
    #[arg(long = "runtime-interactions")]
    pub runtime_interactions: Option<PathBuf>,
    /// Frozen fixture mapping referenced by `--runtime-interactions`.
    #[arg(long = "runtime-fixtures")]
    pub runtime_fixtures: Option<PathBuf>,
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
    /// Largest estimated token count (packet JSON bytes / 4) one reasoning
    /// seat (packet part) may carry before the plan refuses to freeze.
    #[arg(long = "seat-token-budget", default_value_t = legion_audit::native_providers::reasoning::ingest::DEFAULT_SEAT_TOKEN_BUDGET)]
    pub seat_token_budget: u64,
    /// Wave width (host child-agent cap): seats run in waves of this size.
    #[arg(long = "max-lens-seats", default_value_t = legion_audit::native_providers::reasoning::ingest::DEFAULT_MAX_SEATS)]
    pub max_lens_seats: u64,
    /// Freeze the plan even though lens packets exceed the per-seat token
    /// budget or the run budget (the report still records the overrun).
    #[arg(long = "allow-oversize-lenses")]
    pub allow_oversize_lenses: bool,
    /// Lens coverage: `auto` reviews every file when it fits the run budget and
    /// otherwise runs a whole-repository risk-sampled audit; `exhaustive`
    /// never samples and refuses to freeze when it cannot fit; `risk-sampled`
    /// always samples.
    #[arg(long = "coverage", default_value = "auto", value_parser = ["auto", "exhaustive", "risk-sampled"])]
    pub coverage: String,
    /// Total token admission budget across all model calls: input estimate plus output reserve.
    /// Actual input counts cached tokens once; retry usage is reconciled & unknown usage stays unknown.
    #[arg(long = "run-token-budget", default_value_t = legion_audit::native_providers::reasoning::ingest::DEFAULT_RUN_TOKEN_BUDGET)]
    pub run_token_budget: u64,
    /// Most seats across all waves; the plan refuses to freeze past it.
    #[arg(long = "max-total-seats", default_value_t = legion_audit::native_providers::reasoning::ingest::DEFAULT_MAX_TOTAL_SEATS)]
    pub max_total_seats: u64,
    /// Report schema written to `report.json`: `2` (default, confidence/anchor/
    /// attribution fields) or `1` (a projection for consumers pinned to v1; v2-only
    /// fields travel under `finding.evidence.legionV2`). Status is identical.
    #[arg(long = "report-schema", default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=2))]
    pub report_schema: u32,
    #[arg(long = "provider-plan")]
    pub provider_plan: Option<PathBuf>,
    #[arg(long = "provider-result")]
    pub provider_results: Vec<PathBuf>,
    /// Run only the explicitly supplied native rule manifest as an incomplete
    /// source diagnostic. This is never a fallback for a missing full registry.
    #[arg(long = "native-rule-manifest", conflicts_with_all = ["provider_plan", "provider_results"])]
    pub native_rule_manifest: Option<PathBuf>,
    /// `legion audit ingest --run <dir> --result <file> [--result <file> ...]`: ingest
    /// reasoning-lens results into a frozen run in one pass (see `ingest_command`).
    /// `--provider <id>` names the provider of every result; without it each
    /// result file names its own.
    #[arg(long = "run", hide = true)]
    pub ingest_run: Option<PathBuf>,
    #[arg(long = "provider", hide = true)]
    pub ingest_provider: Option<String>,
    #[arg(long = "result", hide = true)]
    pub ingest_result: Vec<PathBuf>,
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

#[derive(Debug, Clone, Args)]
pub struct ContinueAuditArgs {
    #[arg(long)]
    pub run: PathBuf,
    #[arg(long)]
    pub out: PathBuf,
    /// Exact explicit resume instruction authorizing this linked recovery.
    #[arg(long = "operator-instruction")]
    pub operator_instruction: String,
}

/// Stage a separate frozen-source recipe, then bind its inherited accounting.
/// This command starts no model or scanner & never rewrites parent evidence.
pub fn continue_command(args: ContinueAuditArgs) -> CommandResult {
    use legion_audit::native_providers::reasoning::{self, ingest};
    if args.operator_instruction.trim().is_empty() {
        return Err(CommandError::usage(
            "audit continue requires an explicit operator instruction",
        ));
    }
    let parent = std::fs::canonicalize(&args.run).map_err(super::io_error)?;
    let child = continuation_output_path(&parent, &args.out)?;
    if let Ok(metadata) = std::fs::symlink_metadata(&child) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(CommandError::integrity(
                "continuation output must not be a symlink or non-directory",
            ));
        }
        // Only finish an already bound same-child crash recovery. Never adopt
        // an existing unbound directory or overwrite its staged recipe.
        if child
            .join(legion_audit::continuation::CONTINUATION_FILE)
            .is_file()
        {
            return legion_audit::continuation::prepare(
                &parent,
                &child,
                &args.operator_instruction,
            )
            .map_err(|error| CommandError::integrity(error.to_string()));
        }
        return Err(CommandError::usage(
            "audit continue requires a new output directory",
        ));
    }
    reject_accepted_continuation_receipts(&parent)?;
    let allowance = legion_audit::continuation::planning_budget(&parent)
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    let (plan, inventory, execution) = ingest::frozen_reasoning_basis(&parent)
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    // Validate retained deterministic evidence before copying it. Recompute is
    // read-only; it does not execute providers or acquire new source inventory.
    ingest::recompute_run(&parent).map_err(|error| CommandError::integrity(error.to_string()))?;
    let number = |field: &str| -> Result<u64, CommandError> {
        allowance.get(field).and_then(Value::as_u64).ok_or_else(|| {
            CommandError::integrity(format!("continuation allowance missing {field}"))
        })
    };
    let limits = ingest::DispatchLimits {
        run_token_budget: number("remainingTokens")?,
        seat_token_budget: number("perCallTokens")?,
        max_total_seats: number("remainingCalls")?,
        wave_width: number("waveWidth")?,
    };
    if limits.max_total_seats < 2
        || limits.run_token_budget < limits.seat_token_budget.saturating_mul(2)
    {
        return Err(CommandError::incomplete(
            "continuation cannot reserve an author plus fresh verifier within remaining budget",
        ));
    }
    let root = std::path::Path::new(&plan.plan().repository_id);
    let candidates = reasoning::scanner_candidates_from_execution(root, &plan, &execution);
    let work =
        reasoning::pending_lens_work_with_candidates(root, &plan, &inventory, Some(&candidates))
            .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let mut dispatch = ingest::lens_dispatch_plan(&work, &limits);
    if dispatch["withinLimits"] != true
        || dispatch["followupReserveCalls"].as_u64().unwrap_or(0) < 1
        || dispatch["reasoningBudget"]["outputTokens"] != allowance["outputTokens"]
    {
        return Err(CommandError::incomplete(format!(
            "continuation recipe cannot fit preserved call/output/reserve limits: {}",
            dispatch["violations"]
        )));
    }
    let namespace = legion_audit::digest(&(parent.as_path(), child.as_path()))
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    for (index, seat) in dispatch["seats"]
        .as_array_mut()
        .ok_or_else(|| CommandError::integrity("continuation dispatch has no seats"))?
        .iter_mut()
        .enumerate()
    {
        seat["seatId"] = json!(format!(
            "continuation-{}-{:03}",
            namespace.trim_start_matches("sha256:"),
            index + 1
        ));
    }
    // Planning subtracts charged history once. Admission retains original
    // ceilings & inherits original counters, so it cannot subtract twice.
    dispatch["continuationPlanningBudget"] = allowance.clone();
    dispatch["reasoningBudget"] = allowance["originalReasoningBudget"].clone();
    dispatch["continuationRecipe"] =
        json!({"schemaVersion":1,"kind":"frozen-source-rematerialization","modelsStarted":0});
    std::fs::create_dir(&child).map_err(super::io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700))
            .map_err(super::io_error)?;
    }
    for name in [
        "plan.json",
        "facts.json",
        "execution.json",
        reasoning::INVENTORY_SNAPSHOT_FILE,
        "report.json",
    ] {
        copy_continuation_file(&parent, &child, name)?;
    }
    for name in [
        "report.sarif",
        reasoning::candidate_routing::ROUTING_SNAPSHOT_FILE,
    ] {
        if parent.join(name).try_exists().map_err(super::io_error)? {
            copy_continuation_file(&parent, &child, name)?;
        }
    }
    copy_continuation_file(&parent, &child, ingest::EPOCH_KEY_FILE)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            child.join(ingest::EPOCH_KEY_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(super::io_error)?;
    }
    stage_continuation_effect_artifacts(&parent, &child, &execution)?;
    ingest::write_lens_packets(&child.join(ingest::LENS_PACKET_DIR), &work)
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    write_control_artifact(&child, legion_audit::next::DISPATCH_FILE, &dispatch)?;
    // Last effect: core rechecks parent history, source & every staged byte
    // under its root lock before publishing lineage or admitting any future call.
    legion_audit::continuation::prepare(&parent, &child, &args.operator_instruction).map_err(
        |error| {
            CommandError::integrity(format!(
                "continuation staging at {} was not admitted: {error}",
                child.display()
            ))
        },
    )
}

#[cfg(test)]
mod continuation_staging_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "legion-continuation-staging-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            Self(std::fs::canonicalize(root).unwrap())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_overlapping_traversal_and_existing_unbound_output() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        std::fs::create_dir(&parent).unwrap();
        let separator = std::path::MAIN_SEPARATOR;
        let mut traversal = fixture.0.as_os_str().to_owned();
        traversal.push(format!("{separator}other{separator}..{separator}child"));
        for output in [
            parent.clone(),
            parent.join("child"),
            fixture.0.clone(),
            PathBuf::from(traversal),
        ] {
            assert!(
                continuation_output_path(&parent, &output).is_err(),
                "overlapping output path: {}",
                output.display()
            );
        }
        let child = fixture.0.join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("existing-file"), b"unchanged").unwrap();
        assert!(continue_command(ContinueAuditArgs {
            run: parent,
            out: child.clone(),
            operator_instruction: "resume within same budget".into()
        })
        .is_err());
        assert_eq!(
            std::fs::read(child.join("existing-file")).unwrap(),
            b"unchanged"
        );
        assert!(!child.join(legion_audit::next::STATE_FILE).exists());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_raw_parent_segments_in_verbatim_windows_output_before_resolution() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        std::fs::create_dir(&parent).unwrap();
        // canonicalize returns a verbatim root; its component parser treats
        // forward slashes in joined text as normal filename characters.
        for suffix in ["other/../child", r"other\..\child", "../child", r"..\child"] {
            // Keep CLI's raw spelling: PathBuf::join can normalize verbatim
            // backslash traversal before continuation receives it.
            let mut raw = fixture.0.as_os_str().to_os_string();
            raw.push(r"\");
            raw.push(suffix);
            let error = continuation_output_path(&parent, &PathBuf::from(raw)).unwrap_err();
            assert!(error.message.contains("cannot contain parent traversal"));
        }
    }

    #[test]
    fn requires_explicit_instruction_before_staging_or_loading_parent() {
        let fixture = Fixture::new();
        let child = fixture.0.join("child");
        assert!(continue_command(ContinueAuditArgs {
            run: fixture.0.join("missing"),
            out: child.clone(),
            operator_instruction: " \n ".into()
        })
        .is_err());
        assert!(!child.exists());
    }

    #[test]
    fn copying_is_exclusive_and_accepted_semantic_receipts_stop_version_one() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        let child = fixture.0.join("child");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&child).unwrap();
        std::fs::write(parent.join("plan.json"), b"frozen").unwrap();
        copy_continuation_file(&parent, &child, "plan.json").unwrap();
        std::fs::write(parent.join("plan.json"), b"changed").unwrap();
        assert!(copy_continuation_file(&parent, &child, "plan.json").is_err());
        assert_eq!(std::fs::read(child.join("plan.json")).unwrap(), b"frozen");
        std::fs::create_dir(parent.join("lens-receipts")).unwrap();
        assert!(reject_accepted_continuation_receipts(&parent).is_ok());
        std::fs::write(parent.join("lens-receipts/accepted.json"), b"receipt").unwrap();
        assert!(reject_accepted_continuation_receipts(&parent).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_sources_and_outputs_and_keeps_copied_key_private() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        let child = fixture.0.join("child");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&child).unwrap();
        std::fs::write(parent.join("opaque"), b"fixture-only").unwrap();
        symlink(parent.join("opaque"), parent.join("plan.json")).unwrap();
        assert!(copy_continuation_file(&parent, &child, "plan.json").is_err());
        copy_continuation_file(&parent, &child, "opaque").unwrap();
        assert_eq!(
            std::fs::metadata(child.join("opaque"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        let alias = fixture.0.join("alias");
        symlink(&child, &alias).unwrap();
        assert!(continue_command(ContinueAuditArgs {
            run: parent,
            out: alias,
            operator_instruction: "resume".into()
        })
        .is_err());
    }
}

fn continuation_output_path(
    parent: &std::path::Path,
    requested: &std::path::Path,
) -> Result<PathBuf, CommandError> {
    // Windows verbatim components do not split `/`, so inspect raw Windows
    // separators before any path normalization can hide caller traversal.
    let raw_windows_parent = cfg!(windows)
        && requested
            .as_os_str()
            .to_string_lossy()
            .split(['/', '\\'])
            .any(|part| part == "..");
    if raw_windows_parent
        || requested
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(CommandError::usage(
            "continuation output cannot contain parent traversal",
        ));
    }
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(super::io_error)?
            .join(requested)
    };
    let name = absolute
        .file_name()
        .ok_or_else(|| CommandError::usage("continuation output requires a directory name"))?;
    let directory = std::fs::canonicalize(
        absolute
            .parent()
            .ok_or_else(|| CommandError::usage("continuation output parent missing"))?,
    )
    .map_err(super::io_error)?;
    let child = directory.join(name);
    if child == parent || child.starts_with(parent) || parent.starts_with(&child) {
        return Err(CommandError::usage(
            "continuation parent & child must be separate directories",
        ));
    }
    Ok(child)
}

fn reject_accepted_continuation_receipts(parent: &std::path::Path) -> Result<(), CommandError> {
    let receipts = parent.join("lens-receipts");
    if receipts.try_exists().map_err(super::io_error)? {
        if std::fs::symlink_metadata(&receipts)
            .map_err(super::io_error)?
            .file_type()
            .is_symlink()
            || std::fs::read_dir(receipts)
                .map_err(super::io_error)?
                .next()
                .is_some()
        {
            return Err(CommandError::incomplete(
                "continuation version 1 cannot rematerialize accepted semantic receipts",
            ));
        }
    }
    Ok(())
}

fn copy_continuation_file(
    parent: &std::path::Path,
    child: &std::path::Path,
    name: &str,
) -> Result<(), CommandError> {
    use std::io::Write;
    let source = parent.join(name);
    let metadata = std::fs::symlink_metadata(&source).map_err(super::io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(CommandError::integrity(format!(
            "continuation refuses non-regular artifact {name}"
        )));
    }
    let mut input = std::fs::File::open(source).map_err(super::io_error)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(child.join(name)).map_err(super::io_error)?;
    std::io::copy(&mut input, &mut output).map_err(super::io_error)?;
    output
        .flush()
        .and_then(|_| output.sync_all())
        .map_err(super::io_error)
}

fn stage_continuation_effect_artifacts(
    parent: &std::path::Path,
    child: &std::path::Path,
    execution: &legion_audit::ExecutionReport,
) -> Result<(), CommandError> {
    use std::io::Write;
    let mut records = std::collections::BTreeMap::<String, EffectArtifactRef>::new();
    for entry in &execution.results {
        let mut references = Vec::new();
        let receipt = entry
            .result
            .details
            .get("executionReceipt")
            .filter(|value| !value.is_null())
            .or_else(|| {
                entry
                    .result
                    .details
                    .get("receipt")
                    .filter(|value| !value.is_null())
            });
        if let Some(receipt) = receipt {
            if receipt.get("kind").and_then(Value::as_str) != Some("native-legacy-check-receipt") {
                for field in ["stdout", "stderr", "brokerStatus"] {
                    if let Some(value) = receipt.get(field).filter(|value| !value.is_null()) {
                        references.push(value);
                    }
                }
            }
        }
        for field in legion_audit::DETAILS_ARTIFACT_REF_KEYS {
            if let Some(value) = entry
                .result
                .details
                .get(*field)
                .filter(|value| !value.is_null())
            {
                references.push(value);
            }
        }
        for reference in references {
            let record = parse_effect_artifact_ref(reference).map_err(CommandError::integrity)?;
            if let Some(previous) = records.insert(record.path.clone(), record.clone()) {
                if previous != record {
                    return Err(CommandError::integrity(
                        "conflicting frozen effect artifact identity",
                    ));
                }
            }
        }
    }
    for record in records.values() {
        let bytes = read_effect_artifact(&parent.join("artifacts"), record)
            .map_err(CommandError::integrity)?;
        let relative =
            validate_effect_artifact_path(&record.path).map_err(CommandError::integrity)?;
        let destination = child.join("artifacts").join(relative);
        std::fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| CommandError::integrity("effect artifact parent missing"))?,
        )
        .map_err(super::io_error)?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(super::io_error)?;
        output
            .write_all(&bytes)
            .and_then(|_| output.sync_all())
            .map_err(super::io_error)?;
    }
    Ok(())
}
pub async fn run(args: AuditArgs, cancellation: CancellationToken) -> CommandResult {
    if args.rightkit_trust.is_some() {
        if let Some(route) = rightkit_trust_early_subcommand(&args) {
            return Err(CommandError::usage(format!(
                "--rightkit-trust is unsupported for the audit {route} subcommand",
            )));
        }
    }
    if args.root.as_os_str() == "ingest"
        && (args.ingest_run.is_some()
            || args.ingest_provider.is_some()
            || !args.ingest_result.is_empty()
            || args.followup)
    {
        return ingest_command(&args);
    }
    if args.root.as_os_str() == "next" && args.ingest_run.is_some() {
        return next_command(&args);
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
    let source_root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let scope_spec = if let Some(base) = &args.base_commit {
        legion_audit::scope::ScopeSpec::Range {
            base: base.clone(),
            head: "WORKTREE".into(),
        }
    } else if let Some(base) = &args.base {
        legion_audit::scope::ScopeSpec::Branch(base.clone())
    } else {
        legion_audit::scope::ScopeSpec::parse(args.r#type.as_deref().unwrap_or("repo"))
            .map_err(|error| CommandError::usage(error.to_string()))?
    };
    let resolved_scope = legion_audit::scope::ResolvedScope::resolve(
        &source_root,
        scope_spec,
        args.dir
            .as_ref()
            .and_then(|dir| clean_path(&dir.to_string_lossy())),
    )
    .map_err(|error| {
        let message = error.to_string();
        if message.contains("blocked:") {
            CommandError::internal(message)
        } else {
            CommandError::incomplete(message)
        }
    })?;
    let frozen_snapshot = legion_audit::snapshot::FrozenSnapshot::capture(resolved_scope)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let frozen_snapshot = imported_direct_snapshot(&args, frozen_snapshot)?;
    let root = frozen_snapshot.manifest.execution_root.clone();
    let inventory_filter = frozen_snapshot.manifest.scope.inventory_filter();
    let scope = AuditScope {
        mode: if frozen_snapshot.manifest.scope.spec.is_diff() {
            "diff"
        } else {
            "whole-repo"
        },
        scope_type: args.r#type.clone().unwrap_or_else(|| "all".into()),
        base: args.base.clone(),
        base_commit: args.base_commit.clone(),
        dir: frozen_snapshot.manifest.scope.path_prefix.clone(),
        changed_files: frozen_snapshot
            .manifest
            .scope
            .changed_paths
            .iter()
            .cloned()
            .collect(),
        changed_hunks: std::collections::BTreeMap::new(),
        head: Some(frozen_snapshot.manifest.scope.selected_oid.clone()),
        facts_unavailable: false,
        snapshot: Some(frozen_snapshot.manifest.clone()),
    };
    let direct = args.provider_plan.is_some() || !args.provider_results.is_empty();
    let native_application_configured =
        std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_some();
    if args.rightkit_trust.is_some()
        && !rightkit_trust_route_is_supported(
            direct,
            args.native_rule_manifest.is_some(),
            native_application_configured,
        )
    {
        return Err(CommandError::usage(
            "--rightkit-trust is supported only by the native provider registry route",
        ));
    }
    // Gaps the direct route adds when its provider plan could not be bound
    // (for example `unsealed-plan`); empty for every other route.
    let mut direct_gaps: Vec<String> = Vec::new();
    let (application, mut context_notices, effect_artifact_scratch, trusted_scope_universe) =
        if direct {
            let (application, notices, gaps) =
                direct_application(&args, &root, inventory_filter.as_ref())?;
            direct_gaps = gaps;
            (Arc::new(application), notices, None, false)
        } else if let Some(manifest) = &args.native_rule_manifest {
            let (application, notices) = native_rule_diagnostic_application(
                &args,
                &root,
                manifest,
                inventory_filter.as_ref(),
            )?;
            (Arc::new(application), notices, None, false)
        } else if native_application_configured {
            (
                super::native_application_for(&root.to_string_lossy())?,
                Vec::new(),
                None,
                false,
            )
        } else {
            let (application, notices, scratch) = native_registry_application(
                &root,
                args.rightkit_trust.as_deref(),
                inventory_filter.as_ref(),
            )?;
            (Arc::new(application), notices, Some(scratch), true)
        };
    if args.out.is_some() {
        if let Some(notice) = audit_dir_ignore_notice(&source_root) {
            context_notices.push(notice);
        }
    }
    let all_specs = application.provider_specs();
    let mut selected_specs = all_specs.clone();
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
    let signing_key = match std::env::var_os("AUDIT_PLAN_SIGNING_KEY")
        .filter(|value| !value.is_empty())
    {
        // A host-injected key always wins, plan-only or not.
        Some(value) => Some(value.to_string_lossy().as_bytes().to_vec()),
        // A run written to `--out` (including `--plan-only --out`) is signed
        // with the run's epoch key (persisted 0600 as `epoch.key`), so lens
        // packets can be ingested and the run verified later without any
        // extra environment.
        None => match args.out.as_ref() {
            Some(out) => {
                let ingest = legion_audit::native_providers::reasoning::ingest::create_epoch(out)
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
            // A plan with nowhere to keep a run key still needs the host key.
            None if args.plan_only => Some(super::audit_signing_key()?),
            None => None,
        },
    };
    let mut review_context = review_context(&root, &scope);
    review_context["snapshotManifest"] = json!(frozen_snapshot.manifest_path);
    review_context["snapshot"] = json!({
        "schemaVersion": frozen_snapshot.manifest.schema_version,
        "headKind": frozen_snapshot.manifest.scope.head_kind,
        "head": frozen_snapshot.manifest.scope.selected_oid,
        "sourceRepository": source_root,
        "executionRoot": frozen_snapshot.manifest.execution_root,
        "baselineRoot": frozen_snapshot.manifest.baseline_root,
        "executionPolicy": frozen_snapshot.manifest.execution_policy,
        "gaps": frozen_snapshot.manifest.gaps,
    });
    review_context["snapshotKey"] = json!(frozen_snapshot.manifest.key);
    review_context["sourceRepository"] = json!(source_root);
    let frozen_sources = frozen_snapshot
        .manifest
        .files
        .keys()
        .map(|path| {
            frozen_snapshot
                .read(
                    path,
                    legion_audit::snapshot::SnapshotSide::Selected,
                    32 * 1024 * 1024,
                )
                .map(|bytes| (path.clone(), bytes))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    let resolver_files = frozen_snapshot
        .manifest
        .files
        .iter()
        .filter(|(path, _)| {
            path.ends_with("Cargo.toml")
                || path.ends_with("package.json")
                || path.contains("tsconfig")
                || path.ends_with("jsconfig.json")
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let resolver_digest = legion_audit::digest(&resolver_files)
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    let cache_root =
        legion_audit::source_cache::audit_cache_root(&source_root).map_err(super::io_error)?;
    let mut graph_cache = legion_audit::source_cache::SourceCache::open(
        cache_root.join("audit-source"),
        legion_audit::source_cache::DEFAULT_MAX_BYTES,
    )
    .map_err(super::io_error)?;
    let graph_input = std::env::var_os("LEGION_AUDIT_GRAPH_ARTIFACT")
        .map(|path| {
            legion_audit::graph_context::load_host_artifact(
                std::path::Path::new(&path),
                &[source_root.as_path(), root.as_path()],
            )
        })
        .transpose();
    let mut graph_context = legion_audit::graph_context::build_graph_context_cached(
        &frozen_sources,
        graph_input.as_ref().ok().and_then(Option::as_ref),
        &resolver_digest,
        &mut graph_cache,
    );
    if let Err(cause) = graph_input.as_ref() {
        graph_context.freshness = "artifact-input-rejected".into();
        graph_context
            .unknowns
            .push(legion_audit::graph_context::GraphUnknown {
                path: None,
                cause: cause.clone(),
            });
        direct_gaps.push(cause.clone());
    }
    if graph_context.freshness == "artifact-rejected-unbound-or-stale" {
        direct_gaps.push("blueprint-artifact-unbound-or-stale".into());
    }
    let graph_paths: Vec<_> = if frozen_snapshot.manifest.scope.spec.is_diff() {
        frozen_snapshot
            .manifest
            .scope
            .changed_paths
            .iter()
            .cloned()
            .collect()
    } else {
        frozen_snapshot.manifest.files.keys().cloned().collect()
    };
    let graph_artifact = frozen_snapshot
        .manifest_path
        .parent()
        .ok_or_else(|| CommandError::integrity("snapshot parent missing"))?
        .join("graph-context.json");
    frozen_snapshot
        .write_context_artifact(
            "graph-context.json",
            &serde_json::to_vec(&graph_context).map_err(super::io_error)?,
        )
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    review_context["graphContext"] = json!({
        "contractVersion": graph_context.contract_version,
        "blueprintVersion": graph_context.blueprint_version,
        "scopedBytesDigest": graph_context.scoped_bytes_digest,
        "coveredFilesDigest": graph_context.covered_files_digest,
        "resolverConfigDigest": graph_context.resolver_config_digest,
        "coverageFloor": graph_context.coverage_floor,
        "input": if graph_input.as_ref().ok().is_some_and(Option::is_some) { "host-supplied-data" } else { "lexical-fallback" },
        "freshness": graph_context.freshness,
        "unknowns": graph_context.unknowns,
        "artifact": graph_artifact,
        "blastRadius": graph_context.compact_blast_radius(&graph_paths, 256),
        "truncated": graph_context.truncated,
    });
    let graph_cache_stats = graph_cache.stats.clone();
    drop(graph_cache);
    drop(frozen_sources);
    // The coverage request freezes with the provider spec (like the review
    // context), so the executed plan and the lens basis plan, which compile
    // independently, derive the same review sets.
    let coverage_request = coverage_request(&args);
    for provider in &mut selected_specs {
        if let Some(reasoning) = provider.reasoning.as_object_mut() {
            reasoning.insert("reviewContext".into(), review_context.clone());
            reasoning.insert("coverageRequest".into(), coverage_request.clone());
        } else {
            let source = provider.reasoning.clone();
            provider.reasoning = json!({
                "source": source,
                "reviewContext": review_context.clone(),
                "coverageRequest": coverage_request.clone(),
            });
        }
    }
    // Runtime capture inputs are frozen into the provider's runner so the plan
    // seal covers them; inputs that cannot reach a provider are named gaps.
    let (runtime_gaps, runtime_injected) =
        apply_runtime_inputs(&args, &root, &mut selected_specs, direct)?;
    // `--visual-spec`/`--visual-baselines` freeze into the visual provider the
    // same way; both binders' declared gaps are reported with the run.
    let (visual_gaps, visual_injected) = apply_visual_inputs(&args, &mut selected_specs, direct)?;
    if !direct {
        bind_runtime_visual_capture_source(&mut selected_specs);
    }
    let mut declared_input_gaps = [runtime_gaps, visual_gaps].concat();
    declared_input_gaps.extend(frozen_snapshot.manifest.gaps.iter().cloned());
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
    let lens_basis = freeze_lens_basis(
        &root,
        &selected_specs,
        signing_key.as_deref(),
        inventory_filter.as_ref(),
    );
    // Size gate: report every lens's packet bytes, estimated tokens, parts and
    // required seats, and refuse to freeze an oversize plan without an
    // explicit override. Runs before any scanner executes.
    let (lens_size, size_gate_work) = lens_size_gate(&root, &lens_basis, &args)?;
    let provider_selection = if !provider_scope_claims_allowed(trusted_scope_universe) {
        // Imported provider specs describe only the selected execution set.
        // They cannot establish the repository's full applicable universe, so
        // do not bless them by re-signing them as a scope plan.
        Value::Null
    } else {
        match lens_basis.as_ref() {
            Ok((selected_plan, inventory)) => provider_selection_coverage(
                &root,
                inventory,
                &all_specs,
                &args,
                signing_key.as_deref(),
                selected_plan.digest(),
            ),
            Err(error) => json!({
                "complete": false,
                "fullScope": false,
                "error": error,
                "requestedOnly": args.only,
                "requestedSkip": args.skip,
            }),
        }
    };
    // The plan and inventory are built once per run (`freeze_lens_basis`): a
    // plan-only run answers from that plan, and an executed run binds the same
    // frozen plan to a fresh execution inventory instead of walking and
    // compiling a second time. Without a usable basis the application builds
    // its own and surfaces the same error.
    let result = match &lens_basis {
        Ok((plan, _)) if args.plan_only => legion_application::NativeOperationResult::Plan {
            repository_id: root.to_string_lossy().into_owned(),
            plan_digest: plan.digest().into(),
            plan_signature: plan.signature().map(ToOwned::to_owned),
            providers: plan
                .providers()
                .iter()
                .map(|provider| provider.id.clone())
                .collect(),
        },
        Ok((plan, _)) => application
            .invoke_with_cancellation(
                legion_application::NativeOperation::AuditFrozen {
                    repository_id: root.to_string_lossy().into_owned(),
                    plan: plan.clone(),
                    signing_key: signing_key.clone(),
                },
                cancellation,
            )
            .await
            .map_err(|error| CommandError::incomplete(error.to_string()))?,
        Err(_) => application
            .invoke_with_cancellation(operation, cancellation)
            .await
            .map_err(|error| CommandError::incomplete(error.to_string()))?,
    };
    match result {
        legion_application::NativeOperationResult::Plan {
            repository_id,
            plan_digest,
            plan_signature,
            providers,
        } => {
            let binding = match &lens_basis {
                // The basis inventory is the one the plan was frozen over.
                Ok((_, inventory)) => json!({
                    "repositoryRevision": inventory.generation,
                    "inventoryDigest": inventory.digest,
                }),
                Err(_) => native_inventory_binding(&root, inventory_filter.as_ref())?,
            };
            let (lens_work, lens_work_gaps, lens_dispatch) = lens_work_items(
                &root,
                &lens_basis,
                plan_digest.as_str(),
                args.out.as_deref(),
                None,
                &args,
                size_gate_work.as_deref(),
            );
            let (lens_coverage, sampled_run) = lens_coverage_summary(&lens_basis);
            let mut input_gaps = native_audit_input_gaps(&args, &declared_input_gaps);
            input_gaps.extend(lens_work_gaps);
            let mut plan_gaps = vec!["plan-only".to_owned()];
            plan_gaps.extend(direct_gaps.iter().cloned());
            if provider_scope_claims_allowed(trusted_scope_universe)
                && provider_selection.get("complete").and_then(Value::as_bool) != Some(true)
            {
                plan_gaps.push("provider-scope-universe-unavailable".into());
            }
            let native_plan =
                native_plan_document(&lens_basis, plan_digest.as_str(), plan_signature.as_deref())
                    .map_err(CommandError::integrity)?;
            let mut output = json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": repository_id,
            "sourceRepository": source_root,
            "snapshotManifest": frozen_snapshot.manifest_path,
            "profile": args.profile,
            "scope": scope.plan_json(),
            "reviewContext": review_context,
            "sourcePerformance": {"snapshot": frozen_snapshot.manifest.source_cache, "graph": graph_cache_stats},
            "planDigest": plan_digest.clone(),
                "planSignature": plan_signature.clone(),
                "seal": {"digest": plan_digest, "authenticity": "hmac-sha256", "signature": plan_signature},
                "binding": binding,
                "providers": providers,
                "providerSpecs": selected_specs,
                "nativePlan": native_plan,
                "providerSelection": provider_selection,
                "contextNotices": context_notices,
                "auditStatus": "incomplete",
                "qualityGate": "unproven",
                "processExecution": "not-run",
                "processState": "not-run",
                "completionValidation": "not-run",
                "gaps": plan_gaps,
                "lensWork": lens_work,
                "lensSize": lens_size,
                "lensDispatch": lens_dispatch,
                "coverageMode": if sampled_run { "sampled" } else { "exhaustive" },
                "auditLabel": if sampled_run { json!(legion_audit::native_providers::reasoning::ingest::SAMPLED_AUDIT_LABEL) } else { Value::Null },
                "lensCoverage": lens_coverage,
                "inputGaps": input_gaps
            });
            if !provider_scope_claims_allowed(trusted_scope_universe) {
                if let Some(object) = output.as_object_mut() {
                    object.remove("providerSelection");
                }
            }
            if let Some(out) = &args.out {
                write_control_artifact(out, "plan.json", &output)?;
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
            let mut report =
                legion_audit::canonical_report(&source_root.to_string_lossy(), &execution)
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
            if provider_scope_claims_allowed(trusted_scope_universe)
                && provider_selection.get("complete").and_then(Value::as_bool) != Some(true)
            {
                report
                    .gaps
                    .push("provider-scope-universe-unavailable".into());
            }
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
            let (lens_work, lens_work_gaps, lens_dispatch) = if execution.pending_host.is_empty() {
                (Vec::new(), Vec::new(), None)
            } else {
                lens_work_items(
                    &root,
                    &lens_basis,
                    execution.plan_digest.as_str(),
                    args.out.as_deref(),
                    Some(&execution),
                    &args,
                    None,
                )
            };
            report.gaps.extend(lens_work_gaps);
            let (lens_coverage, sampled_run) = lens_coverage_summary(&lens_basis);
            report.claims.insert("lensWork".into(), json!(lens_work));
            if let Some(dispatch) = &lens_dispatch {
                report
                    .claims
                    .insert("lensDispatch".into(), dispatch.clone());
            }
            report.claims.insert(
                "coverageMode".into(),
                json!(if sampled_run { "sampled" } else { "exhaustive" }),
            );
            if sampled_run {
                report.claims.insert(
                    "auditLabel".into(),
                    json!(legion_audit::native_providers::reasoning::ingest::SAMPLED_AUDIT_LABEL),
                );
            }
            if lens_coverage.as_object().is_some_and(|map| !map.is_empty()) {
                report
                    .claims
                    .insert("lensCoverage".into(), lens_coverage.clone());
            }
            if let Some(size) = &lens_size {
                report.claims.insert("lensSize".into(), size.clone());
            }
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
            // Initial reports & later receipt reconciliation use one budget view.
            // Dispatch without an admission ledger has unknown usage until the
            // host records calls; publishing must retain that same explicit gap.
            if let Some(out) = &args.out {
                if let Some(budget) = legion_audit::next::persisted_budget_report(out)
                    .map_err(|error| CommandError::integrity(error.to_string()))?
                {
                    report
                        .claims
                        .insert("reasoningBudget".into(), budget["budget"].clone());
                    report.gaps.extend(
                        budget["gaps"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .map(ToOwned::to_owned),
                    );
                }
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
            if provider_scope_claims_allowed(trusted_scope_universe) {
                report.claims.insert(
                    "providerCoverage".into(),
                    json!({
                    "scope": "frozen-native-provider-plan",
                    "planComplete": report.gaps.is_empty(),
                    "fullScope": provider_selection.get("fullScope").cloned().unwrap_or(json!(false)),
                    "applicableProviders": provider_selection.get("applicableProviders").cloned().unwrap_or(json!([])),
                    "selectedApplicableProviders": provider_selection.get("selectedApplicableProviders").cloned().unwrap_or(json!([])),
                    "excludedApplicableProviders": provider_selection.get("excludedApplicableProviders").cloned().unwrap_or(json!([])),
                    "requestedOnly": args.only.clone(),
                    "requestedSkip": args.skip.clone(),
                    "plannedProviders": execution.planned_providers.clone(),
                    "executedProviders": execution.results.len(),
                    "sourcePort": ["tools/audit/audit-complete.mjs", "tools/audit/audit-run.mjs", "tools/audit/audit-finalize.mjs"],
                    }),
                );
            }
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
                json!(if report.status != legion_contracts::ReportStatus::Clean {
                    "unproven"
                } else if sampled_run {
                    "sampled"
                } else {
                    "proven"
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
            let report_json = render_report_json(
                &report,
                run_report_scope(
                    &report,
                    &frozen_snapshot.manifest.scope.spec.label(),
                    &root,
                    &review_context,
                    &execution.inventory_digest,
                ),
                args.report_schema,
            )?;
            let report_sarif = legion_report::render_sarif(&report).map_err(super::io_error)?;
            if let Some(out) = &args.out {
                let native_plan = native_plan_document(
                    &lens_basis,
                    execution.plan_digest.as_str(),
                    execution.plan_signature.as_deref(),
                )
                .map_err(CommandError::integrity)?;
                let mut plan = json!({
                    "schemaVersion": 1,
                    "kind": "audit-provider-plan",
                    "repository": root,
                    "sourceRepository": source_root,
                    "snapshotManifest": frozen_snapshot.manifest_path,
                    "profile": args.profile,
                    "scope": scope.plan_json(),
                    "reviewContext": review_context,
                    "sourcePerformance": {"snapshot": frozen_snapshot.manifest.source_cache, "graph": graph_cache_stats},
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
                    "providerSelection": provider_selection,
                    "nativePlan": native_plan,
                    "effectArtifactsRoot": effect_artifact_root,
                    "epoch": epoch_digest.as_ref().map(|digest| json!({"digest": digest, "keyFile": "epoch.key"})),
                });
                if !provider_scope_claims_allowed(trusted_scope_universe) {
                    if let Some(object) = plan.as_object_mut() {
                        object.remove("providerSelection");
                    }
                }
                let facts = native_facts_document(&root, &plan, &execution, &report, &scope);
                write_control_artifact(out, "plan.json", &plan)?;
                write_artifact(out, "report.json", report_json.as_bytes())?;
                write_artifact(out, "report.sarif", report_sarif.as_bytes())?;
                write_control_artifact(out, "facts.json", &facts)?;
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
                "root": source_root,
                "executionRoot": root,
                "snapshotManifest": frozen_snapshot.manifest_path,
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
                "lensDispatch": lens_dispatch,
                "coverageMode": if sampled_run { "sampled" } else { "exhaustive" },
                "auditLabel": if sampled_run { json!(legion_audit::native_providers::reasoning::ingest::SAMPLED_AUDIT_LABEL) } else { Value::Null },
                "lensCoverage": lens_coverage,
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
                "qualityGate": if status == "pass" && report.gaps.is_empty() { if sampled_run { "sampled" } else { "proven" } } else { "unproven" },
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
/// `legion audit next --run <dir>`: the resumable dispatch driver (see
/// `legion_audit::next`). Lease length defaults to 20 minutes;
/// `LEGION_AUDIT_LEASE_MINUTES` overrides it.
fn next_command(args: &AuditArgs) -> CommandResult {
    let run = args
        .ingest_run
        .clone()
        .ok_or_else(|| CommandError::usage("legion audit next requires --run <dir>"))?;
    let run = if run.is_absolute() {
        run
    } else {
        std::env::current_dir().map_err(super::io_error)?.join(run)
    };
    let lease_ms = std::env::var("LEGION_AUDIT_LEASE_MINUTES")
        .ok()
        .and_then(|minutes| minutes.trim().parse::<u64>().ok())
        .filter(|minutes| *minutes > 0)
        .map_or(legion_audit::next::DEFAULT_LEASE_MS, |minutes| {
            minutes.saturating_mul(60_000)
        });
    legion_audit::next::next(&run, &legion_audit::next::NextOptions::now(lease_ms))
        .map_err(|error| CommandError::usage(error.to_string()))
}

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
    if args.followup && args.ingest_provider.is_none() && args.ingest_result.is_empty() {
        // Explicit follow-up (re)compilation.
        let (recomputed, follow) = plan_followup_recompute(&run)?;
        write_run_reports(&run, &recomputed.report, args.report_schema)?;
        return Ok(ingest_output(&run, Vec::new(), &recomputed, follow));
    }
    if args.ingest_result.is_empty() {
        return Err(CommandError::usage(
            "legion audit ingest requires --result <file>",
        ));
    }
    let results = args
        .ingest_result
        .iter()
        .cloned()
        .map(absolute)
        .collect::<Result<Vec<_>, _>>()?;
    // Every result is bound to a provider: the explicit `--provider`, else the
    // `provider` the result file itself names.
    let mut targets: Vec<(String, PathBuf)> = Vec::with_capacity(results.len());
    for result in &results {
        let provider = match &args.ingest_provider {
            Some(provider) => provider.clone(),
            None => {
                let value: Value =
                    serde_json::from_slice(&std::fs::read(result).map_err(super::io_error)?)
                        .map_err(|error| {
                            CommandError::usage(format!(
                                "{} is not valid JSON: {error}",
                                result.display()
                            ))
                        })?;
                value
                    .get("provider")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| {
                        CommandError::usage(format!(
                            "{} names no provider; pass --provider <id>",
                            result.display()
                        ))
                    })?
            }
        };
        targets.push((provider, result.clone()));
    }
    if into_followup {
        if let Some((provider, _)) = targets
            .iter()
            .find(|(provider, _)| provider != followup::VARIANT_PROVIDER_ID)
        {
            return Err(CommandError::usage(format!(
                "--followup ingests {} results only (got {provider})",
                followup::VARIANT_PROVIDER_ID
            )));
        }
        let dir = run.join(followup::FOLLOWUP_DIR);
        if !followup::exists(&run) {
            return Err(CommandError::usage(
                "this run has no follow-up plan; run `legion audit ingest --run <dir> --followup` first",
            ));
        }
        let (ingested, failures) = ingest_results(&dir, &targets);
        if ingested.is_empty() {
            return Err(ingest_failure(&failures));
        }
        let inner = ingest::recompute_run(&dir)
            .map_err(|error| CommandError::integrity(error.to_string()))?;
        write_run_reports(&dir, &inner.report, args.report_schema)?;
        let recomputed = ingest::recompute_run(&run)
            .map_err(|error| CommandError::integrity(error.to_string()))?;
        write_run_reports(&run, &recomputed.report, args.report_schema)?;
        let follow = json!({
            "status": recomputed.report.claims.get("securityVariantFollowup")
                .and_then(|claim| claim.get("status")).cloned().unwrap_or(Value::Null),
            "claim": recomputed.report.claims.get("securityVariantFollowup"),
            "run": dir,
            "ingested": ingested,
            "gaps": inner.report.gaps,
        });
        let mut output = ingest_output(&run, ingested, &recomputed, follow);
        attach_ingest_failures(&mut output, &failures);
        return finish_ingest(output, &failures);
    }
    let (ingested, failures) = ingest_results(&run, &targets);
    if ingested.is_empty() {
        return Err(ingest_failure(&failures));
    }
    // One recompute for the whole batch; a second only when confirmed findings
    // just got their follow-up compiled (the report must show that claim).
    let (recomputed, follow) = plan_followup_recompute(&run)?;
    write_run_reports(&run, &recomputed.report, args.report_schema)?;
    let mut output = ingest_output(&run, ingested, &recomputed, follow);
    attach_ingest_failures(&mut output, &failures);
    finish_ingest(output, &failures)
}

/// Ingests each `(provider, result)` into `run` in order. A failing result
/// does not stop the rest: the ones that verified stay ingested, exactly as if
/// each had been ingested by its own command.
fn ingest_results(
    run: &std::path::Path,
    targets: &[(String, PathBuf)],
) -> (
    Vec<legion_audit::native_providers::reasoning::ingest::IngestedLens>,
    Vec<(PathBuf, String)>,
) {
    use legion_audit::native_providers::reasoning::{ingest, ADJUDICATOR_PROVIDER_ID};
    let mut ingested = Vec::new();
    let mut failures = Vec::new();
    // Staged adjudication results are cumulative: all of them are merged into
    // one ingest of the adjudicator instead of overwriting each other.
    let adjudication: Vec<PathBuf> = targets
        .iter()
        .filter(|(provider, _)| provider == ADJUDICATOR_PROVIDER_ID)
        .map(|(_, result)| result.clone())
        .collect();
    let merge_adjudication = adjudication.len() > 1;
    if merge_adjudication {
        match ingest::ingest_adjudication_result_files(run, &adjudication) {
            Ok(done) => ingested.push(done),
            Err(error) => {
                for result in &adjudication {
                    failures.push((result.clone(), error.to_string()));
                }
            }
        }
    }
    for (provider, result) in targets {
        if merge_adjudication && provider == ADJUDICATOR_PROVIDER_ID {
            continue;
        }
        match ingest::ingest_lens_result_file(run, provider, result) {
            Ok(done) => ingested.push(done),
            Err(error) => failures.push((result.clone(), error.to_string())),
        }
    }
    (ingested, failures)
}

fn ingest_failure(failures: &[(PathBuf, String)]) -> CommandError {
    CommandError::usage(
        failures
            .iter()
            .map(|(result, error)| format!("{}: {error}", result.display()))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn attach_ingest_failures(output: &mut Value, failures: &[(PathBuf, String)]) {
    if failures.is_empty() {
        return;
    }
    output["failedResults"] = json!(failures
        .iter()
        .map(|(result, error)| json!({"result": result, "error": error}))
        .collect::<Vec<_>>());
}

/// The report is already rewritten for the results that verified; a batch with
/// any rejected result still exits non-zero and names each failure.
fn finish_ingest(output: Value, failures: &[(PathBuf, String)]) -> CommandResult {
    if failures.is_empty() {
        Ok(output)
    } else {
        Err(ingest_failure(failures))
    }
}

/// Recomputes the run once and, when confirmed security findings exist,
/// compiles the variant follow-up and recomputes again so the report carries
/// the follow-up claim. Returns the final recompute and the follow-up status.
fn plan_followup_recompute(
    run: &std::path::Path,
) -> Result<
    (
        legion_audit::native_providers::reasoning::ingest::Recomputed,
        Value,
    ),
    CommandError,
> {
    let recomputed = legion_audit::native_providers::reasoning::ingest::recompute_run(run)
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    let follow = plan_followup(run, &recomputed);
    if follow["status"] == "planned" || follow["status"] == "reused" {
        let refreshed = legion_audit::native_providers::reasoning::ingest::recompute_run(run)
            .map_err(|error| CommandError::integrity(error.to_string()))?;
        return Ok((refreshed, follow));
    }
    Ok((recomputed, follow))
}

/// Scope of a freshly executed run: commit identities & snapshot key come
/// from frozen review context. Legacy imported plans retain inventory fallback.
fn run_report_scope(
    report: &legion_contracts::ReportV1,
    spec: &str,
    root: &std::path::Path,
    review_context: &Value,
    inventory_digest: &str,
) -> legion_contracts::ReportScope {
    let mut scope = report_scope(report, spec);
    let oid = |pointer: &str| {
        review_context
            .pointer(pointer)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    scope.base_ref_oid = oid("/baseline/baseRefOid").or_else(|| oid("/baseline/commit"));
    scope.merge_base_oid = oid("/baseline/mergeBase");
    if let Some(head) = oid("/head").or_else(|| {
        git_stdout(root, &["rev-parse", "HEAD"])
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }) {
        scope.head = head;
    }
    if let Some(key) = oid("/snapshotKey") {
        scope.snapshot_key = Some(key);
        scope.index_schema_version = Some(legion_audit::scope::SCOPE_SCHEMA_VERSION);
    } else if !inventory_digest.is_empty() {
        scope.snapshot_key = Some(inventory_digest.to_owned());
    }
    scope
}

fn report_scope(report: &legion_contracts::ReportV1, spec: &str) -> legion_contracts::ReportScope {
    legion_contracts::ReportScope {
        spec: spec.into(),
        base_ref_oid: None,
        merge_base_oid: None,
        head: report
            .claims
            .get("inventoryGeneration")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        snapshot_key: None,
        index_schema_version: None,
    }
}

/// Renders `report.json` at the requested schema (`--report-schema`): the v1
/// report is lifted to v2 (deterministic anchor positioning, confidence,
/// status rules) and written natively as 2 or as the v1 projection.
fn render_report_json(
    report: &legion_contracts::ReportV1,
    scope: legion_contracts::ReportScope,
    schema: u32,
) -> Result<String, CommandError> {
    let v2 = legion_audit::lift_report_v2(report, scope)
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    legion_report::render_json_schema(&v2, schema).map_err(super::io_error)
}

pub(super) fn write_run_reports(
    dir: &std::path::Path,
    report: &legion_contracts::ReportV1,
    schema: u32,
) -> Result<(), CommandError> {
    // A re-written run keeps the scope its first report recorded.
    let scope = std::fs::read(dir.join("report.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| legion_contracts::Report::read_any(&value).ok())
        .map(|stored| stored.scope)
        .unwrap_or_else(|| report_scope(report, "whole"));
    let report_json = render_report_json(report, scope, schema)?;
    let report_sarif = legion_report::render_sarif(report).map_err(super::io_error)?;
    write_artifact(dir, "report.json", report_json.as_bytes())?;
    write_artifact(dir, "report.sarif", report_sarif.as_bytes())
}

/// Compiles the variant-analysis follow-up when the run has confirmed security
/// findings. Never fails the caller: the parent report keeps its
/// `security-variant-analysis-pending` gap and `status: error` says why.
fn plan_followup(
    run: &std::path::Path,
    recomputed: &legion_audit::native_providers::reasoning::ingest::Recomputed,
) -> Value {
    use legion_audit::native_providers::reasoning::followup;
    // No confirmed finding, no follow-up (and no registry lookup).
    if recomputed.confirmed_security.is_empty() {
        return json!({"status": "none", "reason": "no confirmed security finding"});
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
    mut ingested: Vec<legion_audit::native_providers::reasoning::ingest::IngestedLens>,
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
        // One result keeps the single-object shape; a batch lists each.
        "ingested": match ingested.len() {
            0 => Value::Null,
            1 => json!(ingested.remove(0)),
            _ => json!(ingested),
        },
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
pub(super) fn registry_provider_spec(
    id: &str,
) -> Result<legion_contracts::ProviderSpec, CommandError> {
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

/// Projects the exact frozen plan into both plan-only & executed artifacts.
/// Its digest & signature must match the artifact seal; packet context
/// references resolve this body, never mutable top-level review context.
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
    only_paths: Option<&std::collections::BTreeSet<String>>,
) -> LensBasis {
    let source =
        super::audit_inventory_source_scoped(root, only_paths).map_err(|error| error.message)?;
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

/// The frozen coverage request for `args` (`--coverage`, `--run-token-budget`,
/// `--max-total-seats`, `--seat-token-budget`).
fn coverage_request(args: &AuditArgs) -> Value {
    use legion_audit::native_providers::reasoning::coverage_plan::{CoverageMode, CoverageRequest};
    CoverageRequest {
        mode: CoverageMode::parse(&args.coverage).unwrap_or(CoverageMode::Auto),
        run_token_budget: args.run_token_budget.max(1),
        max_total_seats: args.max_total_seats.max(1),
        seat_token_budget: args.seat_token_budget.max(1),
    }
    .to_value()
}

fn dispatch_limits(
    args: &AuditArgs,
) -> legion_audit::native_providers::reasoning::ingest::DispatchLimits {
    legion_audit::native_providers::reasoning::ingest::DispatchLimits {
        seat_token_budget: args.seat_token_budget,
        wave_width: args.max_lens_seats,
        run_token_budget: args.run_token_budget,
        max_total_seats: args.max_total_seats,
    }
}

/// `lensCoverage` claims, `coverageMode`, and whether the plan is risk-sampled,
/// from the frozen lens basis (nothing ingested yet).
fn lens_coverage_summary(basis: &LensBasis) -> (Value, bool) {
    match basis {
        Ok((plan, _)) => legion_audit::native_providers::reasoning::ingest::lens_coverage_claims(
            plan.plan(),
            &[],
        ),
        Err(_) => (Value::Null, false),
    }
}

/// Seat/wave labels for each provider of `dispatch`, merged into the
/// `lensWork` items so the output lists work by bundle and wave.
fn annotate_lens_work(items: &mut [Value], dispatch: &Value) {
    for item in items {
        let Some(provider) = item
            .get("provider")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let seats: Vec<Value> = dispatch["seats"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|seat| {
                seat["providers"].as_array().is_some_and(|providers| {
                    providers
                        .iter()
                        .any(|p| p.as_str() == Some(provider.as_str()))
                })
            })
            .map(|seat| {
                json!({
                    "seat": seat["seat"],
                    "wave": seat["wave"],
                    "part": seat["part"],
                    "bundle": seat["bundle"],
                    "tier": seat["tier"],
                })
            })
            .collect();
        if let Some(object) = item.as_object_mut() {
            if let Some(first) = seats.first() {
                object.insert("bundle".into(), first["bundle"].clone());
                object.insert("tier".into(), first["tier"].clone());
            }
            object.insert("seats".into(), Value::Array(seats));
            let deferred: Vec<Value> = dispatch["deferredWork"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| row["providerId"].as_str() == Some(provider.as_str()))
                .cloned()
                .collect();
            let selected = dispatch["seats"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|seat| seat["packets"].as_array().into_iter().flatten())
                .filter_map(Value::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            let packet_selected = |packet: &Value, part: Option<u64>| {
                let basename = packet
                    .as_str()
                    .and_then(|path| {
                        std::path::Path::new(path)
                            .file_name()
                            .and_then(|name| name.to_str())
                    })
                    .map(str::to_owned)
                    .unwrap_or_else(|| match part {
                        Some(number) => format!("{provider}.part-{number:04}.json"),
                        None => format!("{provider}.json"),
                    });
                selected.contains(basename.as_str())
            };
            let mut selected_count = 0;
            if let Some(parts) = object.get_mut("parts").and_then(Value::as_array_mut) {
                for part in parts {
                    let admitted = packet_selected(&part["packet"], part["part"].as_u64());
                    selected_count += usize::from(admitted);
                    part["status"] = json!(if admitted {
                        "pending-host"
                    } else {
                        "deferred-budget"
                    });
                }
            } else if packet_selected(object.get("packet").unwrap_or(&Value::Null), None) {
                selected_count = 1;
            }
            object.insert("selectedParts".into(), json!(selected_count));
            object.insert("deferredParts".into(), json!(deferred.len()));
            if selected_count == 0 && !deferred.is_empty() {
                object.insert("status".into(), json!("deferred-budget"));
            }
            object.insert("deferredWork".into(), json!(deferred));
        }
    }
}

/// Size-gate result: the dispatch report and the packets it was planned from.
type LensSizeGate = (
    Option<Value>,
    Option<Vec<legion_audit::native_providers::reasoning::PendingLensWork>>,
);

/// Bundled dispatch gate. Builds the lens packets the frozen plan implies (no
/// scanner results yet), plans bundled seats and waves from them, and refuses
/// to freeze when a seat exceeds the per-seat budget, the run exceeds its
/// token budget or total-seat cap (printing how far over each bundle is), or
/// `--coverage exhaustive` cannot fit; `--allow-oversize-lenses` overrides.
/// `Ok(None)` when there is no lens work or the packets cannot be built (the
/// later packet step reports that as `lens-packets-unavailable`).
fn lens_size_gate(
    root: &std::path::Path,
    basis: &LensBasis,
    args: &AuditArgs,
) -> Result<LensSizeGate, CommandError> {
    use legion_audit::native_providers::reasoning as reasoning_lens;
    let Ok((plan, inventory)) = basis.as_ref() else {
        return Ok((None, None));
    };
    let Ok(work) = reasoning_lens::pending_lens_work_with_candidates(root, plan, inventory, None)
    else {
        return Ok((None, None));
    };
    if work.is_empty() {
        return Ok((None, None));
    }
    let mut report = reasoning_lens::ingest::lens_dispatch_plan(&work, &dispatch_limits(args));
    let violations: Vec<String> = report["violations"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let overridden = !violations.is_empty() && args.allow_oversize_lenses;
    report["overridden"] = json!(overridden);
    if !violations.is_empty() && !overridden {
        if let Some(out) = &args.out {
            if let Ok(bytes) = serde_json::to_vec_pretty(&report) {
                let _ = write_artifact(out, "lens-size.json", &bytes);
                let _ = write_artifact(out, "lens-dispatch.json", &bytes);
            }
        }
        let per_bundle = report["bundles"]
            .as_array()
            .map(|bundles| {
                bundles
                    .iter()
                    .map(|bundle| {
                        format!(
                            "  bundle {}: {} seat(s), ~{} tokens (estimate), {} over its share",
                            bundle["bundle"].as_str().unwrap_or("?"),
                            bundle["seats"],
                            bundle["estimatedTokens"],
                            bundle["overBy"]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let hint = if args.coverage == "exhaustive" {
            "--coverage exhaustive cannot fit this repository; use --coverage auto or risk-sampled"
        } else {
            "Narrow the scope (--base-commit/--base/--dir/--only/--skip), raise --seat-token-budget/--run-token-budget/--max-total-seats, or pass --allow-oversize-lenses to freeze anyway"
        };
        return Err(CommandError::incomplete(format!(
            "refusing to freeze the plan: lens seats do not fit the run budget\n{per_bundle}\n{}\n{hint}",
            violations.join("\n")
        )));
    }
    // The packets built here (no scanner results) are what a plan-only run
    // emits, so it reuses them instead of rebuilding.
    Ok((Some(report), Some(work)))
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
    args: &AuditArgs,
    size_gate_work: Option<&[legion_audit::native_providers::reasoning::PendingLensWork]>,
) -> (Vec<Value>, Vec<String>, Option<Value>) {
    let mut dispatch_gap: Option<String> = None;
    let mut promotion_gaps: Vec<String> = Vec::new();
    let built = (|| -> Result<(Vec<Value>, Value), String> {
        let (plan, inventory) = basis.as_ref().map_err(Clone::clone)?;
        if executed_plan_digest != plan.digest() {
            return Err("plan digest differs from the executed plan".into());
        }
        // Lens packets reference one shared inventory artifact in the run
        // directory instead of embedding the inventory in every packet.
        if let Some(out) = out {
            let snapshot = serde_json::to_vec(inventory).map_err(|error| error.to_string())?;
            write_artifact(
                out,
                legion_audit::native_providers::reasoning::INVENTORY_SNAPSHOT_FILE,
                &snapshot,
            )
            .map_err(|error| error.message)?;
        }
        // The security adjudicator closes scanner candidates, so it needs the
        // executed scanner results; a plan-only run has none (`None`).
        let candidates = execution.map(|execution| {
            legion_audit::native_providers::reasoning::scanner_candidates_from_execution(
                root, plan, execution,
            )
        });
        if let Some(candidates) = candidates.as_deref() {
            let accounting =
                legion_audit::native_providers::reasoning::candidate_routing::accounting(
                    plan, candidates,
                );
            if let Some(out) = out {
                write_artifact(
                    out,
                    legion_audit::native_providers::reasoning::candidate_routing::ROUTING_SNAPSHOT_FILE,
                    &serde_json::to_vec_pretty(&accounting).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.message)?;
            }
            promotion_gaps.extend(
                legion_audit::native_providers::reasoning::candidate_routing::unavailable_gaps(
                    &accounting,
                ),
            );
        }
        // Without scanner results the packets equal the size gate's: reuse
        // them. With results (promotion, adjudicator candidates) rebuild.
        let rebuilt;
        let work: &[legion_audit::native_providers::reasoning::PendingLensWork] =
            match (size_gate_work, candidates.as_deref()) {
                (Some(work), None) => work,
                (_, candidates) => {
                    rebuilt =
                    legion_audit::native_providers::reasoning::pending_lens_work_with_candidates(
                        root, plan, inventory, candidates,
                    )
                    .map_err(|error| error.to_string())?;
                    &rebuilt
                }
            };
        // A provider whose denominator does not fit one packet is split into
        // parts; the writer names each part file and the provider index.
        let mut items = match out {
            Some(out) => legion_audit::native_providers::reasoning::ingest::write_lens_packets(
                &out.join("lens-packets"),
                work,
            ),
            None => {
                legion_audit::native_providers::reasoning::ingest::lens_packet_items(work, None)
            }
        }
        .map_err(|error| error.to_string())?;
        // Bundled seats and waves over the packets actually written (after
        // findings promotion), written as `lens-dispatch.json`.
        let limits = dispatch_limits(args);
        let dispatch = match out {
            Some(out) => legion_audit::native_providers::reasoning::ingest::write_lens_dispatch(
                out, work, &limits,
            )
            .map_err(|error| error.to_string())?,
            None => {
                legion_audit::native_providers::reasoning::ingest::lens_dispatch_plan(work, &limits)
            }
        };
        annotate_lens_work(&mut items, &dispatch);
        // Findings promotion the run budget capped: one named gap per count,
        // never a silent drop.
        let capped: std::collections::BTreeSet<u64> = work
            .iter()
            .filter_map(|item| {
                item.request
                    .packet
                    .pointer("/excerptCoverage/unpromotedCount")
                    .and_then(Value::as_u64)
            })
            .filter(|count| *count > 0)
            .collect();
        for count in capped {
            promotion_gaps.push(format!("lens-promotion-capped:{count}"));
        }
        Ok((items, dispatch))
    })();
    match built {
        Ok((items, dispatch)) => {
            if dispatch["withinLimits"].as_bool() == Some(false) && !args.allow_oversize_lenses {
                // Findings promotion added files after the freeze-time gate:
                // the run is over budget and says so instead of passing quietly.
                dispatch_gap = Some(format!(
                    "lens-dispatch-over-budget:{}",
                    dispatch["violations"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
            let mut gaps: Vec<String> = dispatch_gap.into_iter().collect();
            gaps.extend(promotion_gaps);
            gaps.extend(
                dispatch["deferredWork"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|row| {
                        format!(
                            "lens-budget-deferred:{}:{}:{}",
                            row["providerId"].as_str().unwrap_or("unknown"),
                            row["part"].as_u64().unwrap_or(1),
                            row["reason"].as_str().unwrap_or("budget")
                        )
                    }),
            );
            (items, gaps, Some(dispatch))
        }
        Err(message) => (
            Vec::new(),
            vec![format!("lens-packets-unavailable:{message}")],
            None,
        ),
    }
}

/// A run dir lives under `<root>/.audit/`; in a git work tree where that path
/// is not ignored, say so (add `.audit/` to `.gitignore`) instead of silently
/// letting run artifacts show up as untracked files.
fn audit_dir_ignore_notice(root: &std::path::Path) -> Option<String> {
    git_stdout(root, &["rev-parse", "--is-inside-work-tree"])?;
    let ignored = legion_audit::scope::GitRunner::new(root)
        .run(&["check-ignore", "-q", ".audit/"])
        .is_ok();
    (!ignored).then(|| {
        "audit-run-dir-not-ignored: add `.audit/` to .gitignore (or .git/info/exclude); run directories under .audit/ are otherwise reported as untracked files"
            .to_owned()
    })
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
    only_paths: Option<&std::collections::BTreeSet<String>>,
) -> Result<Value, CommandError> {
    let source = super::audit_inventory_source_scoped(root, only_paths)?;
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
    root: &std::path::Path,
    specs: &mut [legion_contracts::ProviderSpec],
    direct: bool,
) -> Result<(Vec<String>, bool), CommandError> {
    let mut gaps = Vec::new();
    let Some(url) = args.url.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
        if args.runtime_interactions.is_some() {
            gaps.push("runtime-interactions-not-consumed:runtime-url-not-supplied".into());
        }
        if args.runtime_fixtures.is_some() {
            gaps.push("runtime-fixtures-not-consumed:runtime-url-not-supplied".into());
        }
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
        if args.runtime_interactions.is_some() {
            gaps.push("runtime-interactions-not-consumed:provider-plan-supplied".into());
        }
        if args.runtime_fixtures.is_some() {
            gaps.push("runtime-fixtures-not-consumed:provider-plan-supplied".into());
        }
        return Ok((gaps, false));
    }
    if !specs
        .iter()
        .any(|provider| provider.id.as_str() == RUNTIME_PROVIDER_ID)
    {
        gaps.push("runtime-inputs-not-consumed:provider-not-selected".into());
        if args.runtime_interactions.is_some() {
            gaps.push("runtime-interactions-not-consumed:provider-not-selected".into());
        }
        if args.runtime_fixtures.is_some() {
            gaps.push("runtime-fixtures-not-consumed:provider-not-selected".into());
        }
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
    let mut inputs = legion_audit::native_providers::legacy_checks::runtime_inputs(
        url,
        &surfaces,
        &unsupported,
        args.width,
        args.height,
        artifact_dir.as_deref(),
    )
    .map_err(|reason| CommandError::usage(format!("invalid runtime inputs: {reason}")))?;
    let interactions = read_runtime_interactions(args, root, url, &surfaces)?;
    if let Some(object) = inputs.as_object_mut() {
        object.insert("interactions".into(), Value::Array(interactions));
    }
    for provider in specs.iter_mut() {
        if provider.id.as_str() == RUNTIME_PROVIDER_ID {
            if let Some(runner) = provider.runner.as_object_mut() {
                runner.insert("runtime".into(), inputs.clone());
            }
        }
    }
    Ok((gaps, true))
}

const MAX_RUNTIME_INTERACTIONS: usize = 8;
const MAX_RUNTIME_INTERACTION_ACTIONS: usize = 32;
const MAX_ACTIONS_PER_RUNTIME_INTERACTION: usize = 8;
const MAX_RUNTIME_INTERACTION_STRING: usize = 2048;
const MAX_RUNTIME_FIXTURE_FILES: usize = 64;
const MAX_RUNTIME_FIXTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RUNTIME_FROZEN_CONFIG_BYTES: usize = 16 * 1024 * 1024;

/// Read & validate requested probe descriptors before freezing them into the
/// runtime provider. These descriptors never grant execution authority; the
/// runtime independently returns `NotConfigured` until host isolation is
/// verified.
fn read_runtime_interactions(
    args: &AuditArgs,
    root: &std::path::Path,
    entry_url: &str,
    surfaces: &[(String, String)],
) -> Result<Vec<Value>, CommandError> {
    let Some(path) = args.runtime_interactions.as_ref() else {
        if args.runtime_fixtures.is_some() {
            return Err(CommandError::usage(
                "--runtime-fixtures requires --runtime-interactions",
            ));
        }
        return Ok(Vec::new());
    };
    let fixture_path = args
        .runtime_fixtures
        .as_ref()
        .ok_or_else(|| CommandError::usage("--runtime-interactions requires --runtime-fixtures"))?;
    let bytes = std::fs::read(path).map_err(super::io_error)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        CommandError::usage(format!("invalid --runtime-interactions file: {error}"))
    })?;
    let items = value.as_array().ok_or_else(|| {
        CommandError::usage("--runtime-interactions file must contain a JSON array")
    })?;
    if items.is_empty() || items.len() > MAX_RUNTIME_INTERACTIONS {
        return Err(CommandError::usage(
            "--runtime-interactions must contain 1 to 8 descriptors",
        ));
    }
    let known_surfaces = std::iter::once(("entry".to_owned(), entry_url.to_owned()))
        .chain(surfaces.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>();
    let mut ids = std::collections::BTreeSet::new();
    let mut action_count = 0usize;
    let mut referenced_fixtures = std::collections::BTreeMap::new();
    for item in items {
        if !json_exact_keys(
            item,
            &[
                "id",
                "surface",
                "fixture",
                "probe",
                "isolationBindingId",
                "expiresAfterMs",
                "actions",
            ],
        ) {
            return Err(CommandError::usage(
                "runtime interaction has missing or unknown fields",
            ));
        }
        let id = json_text(item, "id")
            .filter(|text| runtime_id(text))
            .ok_or_else(|| CommandError::usage("runtime interaction id is invalid"))?;
        if !ids.insert(id.to_owned()) {
            return Err(CommandError::usage("runtime interaction id is duplicated"));
        }
        let binding = json_text(item, "isolationBindingId")
            .filter(|text| runtime_id(text))
            .ok_or_else(|| {
                CommandError::usage("runtime interaction isolationBindingId is invalid")
            })?;
        let _ = binding;
        let expiry = item
            .get("expiresAfterMs")
            .and_then(Value::as_u64)
            .filter(|expiry| (1..=30_000).contains(expiry))
            .ok_or_else(|| {
                CommandError::usage("runtime interaction expiresAfterMs must be 1 to 30000")
            })?;
        let _ = expiry;
        let surface = item
            .get("surface")
            .ok_or_else(|| CommandError::usage("runtime interaction surface is missing"))?;
        if !json_exact_keys(surface, &["label", "url"]) {
            return Err(CommandError::usage(
                "runtime interaction surface must contain only label and url",
            ));
        }
        let label = json_text(surface, "label")
            .filter(|text| !text.trim().is_empty() && text.len() <= MAX_RUNTIME_INTERACTION_STRING)
            .ok_or_else(|| CommandError::usage("runtime interaction surface label is invalid"))?;
        let url = json_text(surface, "url")
            .filter(|text| text.len() <= MAX_RUNTIME_INTERACTION_STRING)
            .ok_or_else(|| {
                CommandError::usage("runtime interaction surface URL must be an exact loopback URL")
            })?;
        let fixture_url_path = exact_fixture_url_path(url).ok_or_else(|| {
            CommandError::usage("runtime interaction surface URL must be an exact fixture URL")
        })?;
        if !known_surfaces.contains(&(label.to_owned(), url.to_owned())) {
            return Err(CommandError::usage(
                "runtime interaction surface does not match frozen runtime inputs",
            ));
        }
        let fixture = item
            .get("fixture")
            .ok_or_else(|| CommandError::usage("runtime interaction fixture is missing"))?;
        if !json_exact_keys(fixture, &["id", "sourceDigest"])
            || !json_text(fixture, "id").is_some_and(runtime_id)
            || !json_text(fixture, "sourceDigest").is_some_and(runtime_sha256)
        {
            return Err(CommandError::usage(
                "runtime interaction fixture identity is invalid",
            ));
        }
        let probe = item
            .get("probe")
            .ok_or_else(|| CommandError::usage("runtime interaction probe is missing"))?;
        if !json_exact_keys(probe, &["id", "actionsDigest"])
            || !json_text(probe, "id").is_some_and(runtime_id)
            || !json_text(probe, "actionsDigest").is_some_and(runtime_sha256)
        {
            return Err(CommandError::usage(
                "runtime interaction probe identity is invalid",
            ));
        }
        let actions = item
            .get("actions")
            .and_then(Value::as_array)
            .ok_or_else(|| CommandError::usage("runtime interaction actions must be an array"))?;
        action_count = action_count.saturating_add(actions.len());
        if actions.is_empty()
            || actions.len() > MAX_ACTIONS_PER_RUNTIME_INTERACTION
            || action_count > MAX_RUNTIME_INTERACTION_ACTIONS
            || !actions.iter().all(valid_runtime_probe_action)
        {
            return Err(CommandError::usage(
                "runtime interaction actions are invalid or exceed bounds",
            ));
        }
        let expected = json_text(probe, "actionsDigest").unwrap_or_default();
        let action_digest = legion_contracts::canonical_digest(actions).map_err(|error| {
            CommandError::usage(format!(
                "runtime interaction actions cannot be canonicalized: {error}"
            ))
        })?;
        if action_digest != expected {
            return Err(CommandError::usage(
                "runtime interaction actionsDigest does not match actions",
            ));
        }
        let fixture_id = json_text(fixture, "id").unwrap_or_default().to_owned();
        let fixture_digest = json_text(fixture, "sourceDigest")
            .unwrap_or_default()
            .to_owned();
        if referenced_fixtures
            .insert(
                fixture_id,
                (fixture_digest.clone(), fixture_url_path.to_owned()),
            )
            .is_some_and(|existing| existing != (fixture_digest, fixture_url_path.to_owned()))
        {
            return Err(CommandError::usage(
                "runtime interaction fixture id has conflicting source digests",
            ));
        }
    }
    let source = super::audit_inventory_source(root)?;
    let inventory = source.inventory(&root.to_string_lossy()).map_err(|error| {
        CommandError::usage(format!(
            "could not freeze runtime fixture inventory: {error}"
        ))
    })?;
    let fixtures =
        read_runtime_fixture_manifest(fixture_path, root, &inventory, &referenced_fixtures)?;
    let mut frozen = Vec::with_capacity(items.len());
    let mut expanded_size = 2usize.saturating_add(items.len().saturating_sub(1));
    for item in items {
        let fixture = item.get("fixture").expect("validated runtime fixture");
        let id = json_text(fixture, "id").expect("validated fixture id");
        let bundle = fixtures.get(id).ok_or_else(|| {
            CommandError::usage(format!("runtime fixture is not present in manifest: {id}"))
        })?;
        let old_fixture_size = json_encoded_len(fixture)
            .ok_or_else(|| CommandError::usage("runtime fixture size overflow"))?;
        let descriptor_size = json_encoded_len(item)
            .ok_or_else(|| CommandError::usage("runtime interaction size overflow"))?;
        let bundle_size = json_encoded_len(bundle)
            .ok_or_else(|| CommandError::usage("frozen runtime fixture size overflow"))?;
        expanded_size = expanded_size
            .checked_add(descriptor_size.saturating_sub(old_fixture_size))
            .and_then(|size| size.checked_add(bundle_size))
            .ok_or_else(|| CommandError::usage("expanded runtime fixture size overflow"))?;
        if expanded_size > MAX_RUNTIME_FROZEN_CONFIG_BYTES {
            return Err(CommandError::usage(
                "expanded runtime fixture descriptors exceed 16 MiB frozen-config limit",
            ));
        }
        let mut item = item.clone();
        item["fixture"] = bundle.clone();
        frozen.push(item);
    }
    Ok(frozen)
}

fn json_encoded_len(value: &Value) -> Option<usize> {
    match value {
        Value::Null => Some(4),
        Value::Bool(value) => Some(if *value { 4 } else { 5 }),
        Value::Number(value) => Some(value.to_string().len()),
        Value::String(value) => serde_json::to_string(value).ok().map(|text| text.len()),
        Value::Array(values) => values.iter().try_fold(
            2usize.saturating_add(values.len().saturating_sub(1)),
            |size, value| size.checked_add(json_encoded_len(value)?),
        ),
        Value::Object(values) => values.iter().try_fold(
            2usize.saturating_add(values.len().saturating_sub(1)),
            |size, (key, value)| {
                size.checked_add(serde_json::to_string(key).ok()?.len())?
                    .checked_add(1)?
                    .checked_add(json_encoded_len(value)?)
            },
        ),
    }
}

fn read_runtime_fixture_manifest(
    manifest_path: &std::path::Path,
    root: &std::path::Path,
    inventory: &legion_audit::InventoryEnvelope,
    referenced: &std::collections::BTreeMap<String, (String, String)>,
) -> Result<std::collections::BTreeMap<String, Value>, CommandError> {
    let metadata = std::fs::metadata(manifest_path).map_err(super::io_error)?;
    if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Err(CommandError::usage(
            "--runtime-fixtures must be a regular manifest no larger than 4 MiB",
        ));
    }
    let bytes = std::fs::read(manifest_path).map_err(super::io_error)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        CommandError::usage(format!("invalid --runtime-fixtures file: {error}"))
    })?;
    if !json_exact_keys(&value, &["schemaVersion", "fixtures"])
        || value.get("schemaVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err(CommandError::usage(
            "--runtime-fixtures must use schemaVersion 1 and exact manifest fields",
        ));
    }
    let rows = value
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| CommandError::usage("runtime fixture manifest fixtures must be an array"))?;
    if rows.is_empty() || rows.len() > MAX_RUNTIME_INTERACTIONS {
        return Err(CommandError::usage(
            "runtime fixture manifest must contain 1 to 8 fixtures",
        ));
    }
    let mut fixtures = std::collections::BTreeMap::new();
    let mut total_bytes = 0usize;
    for row in rows {
        if !json_exact_keys(row, &["id", "files"]) {
            return Err(CommandError::usage(
                "runtime fixture must contain only id and files",
            ));
        }
        let id = json_text(row, "id")
            .filter(|text| runtime_id(text))
            .ok_or_else(|| CommandError::usage("runtime fixture id is invalid"))?;
        if !referenced.contains_key(id) {
            return Err(CommandError::usage(format!(
                "runtime fixture is not referenced by an interaction: {id}"
            )));
        }
        let file_rows = row
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| CommandError::usage("runtime fixture files must be an array"))?;
        if file_rows.is_empty() || file_rows.len() > MAX_RUNTIME_FIXTURE_FILES {
            return Err(CommandError::usage(
                "runtime fixture must contain 1 to 64 files",
            ));
        }
        let mut url_paths = std::collections::BTreeSet::new();
        let mut source_paths = std::collections::BTreeSet::new();
        let mut digest_files = Vec::with_capacity(file_rows.len());
        let mut frozen_files = Vec::with_capacity(file_rows.len());
        let mut fixture_bytes = 0usize;
        for file in file_rows {
            if !json_exact_keys(file, &["sourcePath", "path", "contentType"]) {
                return Err(CommandError::usage(
                    "runtime fixture file must contain only sourcePath, path and contentType",
                ));
            }
            let source_path = json_text(file, "sourcePath")
                .filter(|path| safe_inventory_path(path))
                .ok_or_else(|| CommandError::usage("runtime fixture sourcePath is invalid"))?;
            let url_path = json_text(file, "path")
                .filter(|path| valid_fixture_url_path(path))
                .ok_or_else(|| CommandError::usage("runtime fixture URL path is invalid"))?;
            let content_type = json_text(file, "contentType")
                .filter(|value| valid_fixture_content_type(value))
                .ok_or_else(|| CommandError::usage("runtime fixture contentType is invalid"))?;
            if !url_paths.insert(url_path.to_owned())
                || !source_paths.insert(source_path.to_owned())
            {
                return Err(CommandError::usage(
                    "runtime fixture contains duplicate URL or source mappings",
                ));
            }
            let inventory_entry = inventory
                .entries
                .iter()
                .find(|entry| entry.path == source_path)
                .ok_or_else(|| {
                    CommandError::usage(format!(
                        "runtime fixture source is outside frozen Audit inventory: {source_path}"
                    ))
                })?;
            let source_bytes = read_inventory_regular_file(root, source_path)?;
            let source_digest = format!("sha256:{}", sha256_hex(&source_bytes));
            if inventory_entry.digest.as_deref() != Some(source_digest.as_str()) {
                return Err(CommandError::usage(format!(
                    "runtime fixture source changed since Audit inventory: {source_path}"
                )));
            }
            fixture_bytes = fixture_bytes
                .checked_add(source_bytes.len())
                .ok_or_else(|| CommandError::usage("runtime fixture byte count overflow"))?;
            total_bytes = total_bytes.checked_add(source_bytes.len()).ok_or_else(|| {
                CommandError::usage("runtime fixture manifest byte count overflow")
            })?;
            if fixture_bytes > MAX_RUNTIME_FIXTURE_BYTES || total_bytes > MAX_RUNTIME_FIXTURE_BYTES
            {
                return Err(CommandError::usage(
                    "runtime fixture bodies exceed 16 MiB frozen-input limit",
                ));
            }
            let body = serde_json::to_value(&source_bytes).map_err(super::io_error)?;
            digest_files.push(json!({"body":body,"contentType":content_type,"path":url_path}));
            frozen_files.push(json!({
                "sourcePath":source_path,
                "sourceDigest":source_digest,
                "path":url_path,
                "contentType":content_type,
                "body":body,
            }));
        }
        digest_files.sort_by(|left, right| {
            left.get("path")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .as_bytes()
                .cmp(
                    right
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .as_bytes(),
                )
        });
        let source_digest = legion_contracts::canonical_digest(&json!({"files":digest_files}))
            .map_err(|error| {
                CommandError::usage(format!("runtime fixture cannot be canonicalized: {error}"))
            })?;
        let (expected_digest, exact_path) = referenced.get(id).expect("referenced fixture");
        if &source_digest != expected_digest {
            return Err(CommandError::usage(format!(
                "runtime fixture digest does not match frozen bundle: {id}"
            )));
        }
        if !url_paths.contains(exact_path) {
            return Err(CommandError::usage(format!(
                "runtime fixture exact URL path does not match a manifest file: {id}"
            )));
        }
        if fixtures
            .insert(
                id.to_owned(),
                json!({
                    "id":id,
                    "sourceDigest":source_digest,
                    "inventoryDigest":inventory.digest,
                    "files":frozen_files,
                }),
            )
            .is_some()
        {
            return Err(CommandError::usage("runtime fixture id is duplicated"));
        }
    }
    if fixtures.len() != referenced.len() {
        return Err(CommandError::usage(
            "runtime interaction references a fixture missing from manifest",
        ));
    }
    Ok(fixtures)
}

fn safe_inventory_path(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_RUNTIME_INTERACTION_STRING || value.contains('\\') {
        return false;
    }
    let path = std::path::Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        && path.to_string_lossy().replace('\\', "/") == value
}

fn valid_fixture_url_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAX_RUNTIME_INTERACTION_STRING
        && value.is_ascii()
        && !value
            .chars()
            .any(|character| matches!(character, '\\' | '?' | '#' | '%') || character.is_control())
        && !value
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        && value.bytes().all(|byte| {
            byte == b'/' || byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=@:".contains(&byte)
        })
}

fn exact_fixture_url_path(value: &str) -> Option<&str> {
    let remainder = value.strip_prefix("http://")?;
    let authority_end = remainder.find('/').unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let port = authority.strip_prefix("127.0.0.1:")?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port_number = port.parse::<u16>().ok()?;
    if port_number == 0 {
        return None;
    }
    let raw_path = if authority_end == remainder.len() {
        "/"
    } else {
        &remainder[authority_end..]
    };
    if !valid_fixture_url_path(raw_path) {
        return None;
    }
    Some(raw_path)
}

fn valid_fixture_content_type(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_RUNTIME_INTERACTION_STRING
        && value.is_ascii()
        && !value
            .chars()
            .any(|character| matches!(character, '\r' | '\n'))
}

fn read_inventory_regular_file(
    root: &std::path::Path,
    source_path: &str,
) -> Result<Vec<u8>, CommandError> {
    let relative = std::path::Path::new(source_path);
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(CommandError::usage("runtime fixture source path is unsafe"));
        };
        current.push(name);
        let metadata = std::fs::symlink_metadata(&current).map_err(super::io_error)?;
        if metadata.file_type().is_symlink()
            || if index + 1 == components.len() {
                !metadata.is_file()
            } else {
                !metadata.is_dir()
            }
        {
            return Err(CommandError::usage(format!(
                "runtime fixture source must be a regular non-symlink file: {source_path}"
            )));
        }
    }
    let canonical = std::fs::canonicalize(&current).map_err(super::io_error)?;
    let canonical_root = std::fs::canonicalize(root).map_err(super::io_error)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(CommandError::usage(
            "runtime fixture source resolves outside Audit root",
        ));
    }
    let mut file = std::fs::File::open(&canonical).map_err(super::io_error)?;
    if !file.metadata().map_err(super::io_error)?.is_file() {
        return Err(CommandError::usage(
            "runtime fixture source is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    let mut limited = std::io::Read::take(&mut file, (MAX_RUNTIME_FIXTURE_BYTES + 1) as u64);
    std::io::Read::read_to_end(&mut limited, &mut bytes).map_err(super::io_error)?;
    if bytes.len() > MAX_RUNTIME_FIXTURE_BYTES {
        return Err(CommandError::usage(
            "runtime fixture source exceeds 16 MiB frozen-input limit",
        ));
    }
    let after = std::fs::symlink_metadata(&current).map_err(super::io_error)?;
    if after.file_type().is_symlink() || !after.is_file() {
        return Err(CommandError::usage(
            "runtime fixture source changed file type while freezing",
        ));
    }
    Ok(bytes)
}

fn json_exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && object.keys().all(|key| keys.contains(&key.as_str()))
    })
}

fn json_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn runtime_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn runtime_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn runtime_action_text<'a>(action: &'a Value, key: &str) -> Option<&'a str> {
    action
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty() && text.len() <= MAX_RUNTIME_INTERACTION_STRING)
}

fn valid_runtime_probe_action(action: &Value) -> bool {
    let Some(kind) = json_text(action, "type") else {
        return false;
    };
    let has_exact = |required: &[&str], optional: &[&str]| {
        action.as_object().is_some_and(|object| {
            required.iter().all(|key| object.contains_key(*key))
                && object
                    .keys()
                    .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
        })
    };
    match kind {
        "click" => {
            has_exact(&["type", "selector"], &[])
                && runtime_action_text(action, "selector").is_some()
        }
        "type" => {
            has_exact(&["type", "text"], &[]) && runtime_action_text(action, "text").is_some()
        }
        "press" => {
            has_exact(&["type", "key"], &[])
                && json_text(action, "key").is_some_and(|key| {
                    matches!(
                        key,
                        "Tab" | "Escape" | "ArrowUp" | "ArrowDown" | "ArrowLeft" | "ArrowRight"
                    )
                })
        }
        "assertVisible" => {
            has_exact(&["type", "selector"], &["timeout"])
                && runtime_action_text(action, "selector").is_some()
                && action.get("timeout").is_none_or(|timeout| {
                    timeout
                        .as_u64()
                        .is_some_and(|value| (1..=5000).contains(&value))
                })
        }
        "assertText" => {
            has_exact(&["type", "selector", "text"], &[])
                && runtime_action_text(action, "selector").is_some()
                && runtime_action_text(action, "text").is_some()
        }
        _ => false,
    }
}

fn loopback_http_url(value: &str) -> bool {
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    let authority = if lower.starts_with("http://") {
        &value[7..]
    } else if lower.starts_with("https://") {
        &value[8..]
    } else {
        return false;
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let suffix = &rest[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else if let Some(port) = suffix.strip_prefix(':') {
            Some(port)
        } else {
            return false;
        };
        (&rest[..end], port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            Some(_) => return false,
            None => (authority, None),
        }
    };
    if port.is_some_and(|port| {
        port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().is_err()
    }) {
        return false;
    }
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
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

/// Freeze the repository's applicable provider universe independently from
/// user filters. Providers with empty denominators are not omissions.
fn provider_selection_coverage(
    root: &std::path::Path,
    inventory: &legion_audit::InventoryEnvelope,
    all_specs: &[legion_contracts::ProviderSpec],
    args: &AuditArgs,
    signing_key: Option<&[u8]>,
    selected_plan_digest: &str,
) -> Value {
    let result = (|| -> Result<Value, String> {
        let pending = legion_audit::AuditPlan::compile_provider_universe(
            Some(root),
            inventory,
            all_specs,
            selected_plan_digest,
        )
        .map_err(|error| error.to_string())?;
        let scope_plan = match signing_key {
            Some(key) => pending.freeze(Some(key)),
            None => pending.freeze_source_diagnostic(),
        }
        .map_err(|error| error.to_string())?;
        let plan = scope_plan.plan();
        let applicable = plan
            .providers
            .iter()
            .filter(|provider| {
                let declared = provider
                    .configuration
                    .get("hostDeclaration")
                    .and_then(|value| value.get("declared"))
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let denominator_count = provider
                    .configuration
                    .get("denominatorCount")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let selector = provider.configuration.get("selector");
                let always = selector.is_some_and(|selector| {
                    selector.as_str() == Some("always")
                        || selector.get("op").and_then(Value::as_str) == Some("always")
                });
                declared && (denominator_count > 0 || always)
            })
            .map(|provider| provider.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let selected = filter_provider_specs(all_specs.to_vec(), args)
            .into_iter()
            .map(|provider| provider.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        let selected_ids = selected.iter().cloned().collect::<Vec<_>>();
        let mut claim = provider_selection_claim(
            &applicable,
            &selected,
            &args.only,
            &args.skip,
            &inventory.digest,
        );
        let object = claim
            .as_object_mut()
            .ok_or_else(|| "provider selection claim is malformed".to_owned())?;
        object.insert("selectedProviderIds".into(), json!(selected_ids));
        object.insert(
            "excludedConditionalProviders".into(),
            json!(scope_plan.plan().excluded_conditional_providers),
        );
        object.insert(
            "scopePlan".into(),
            json!({
                "digest": scope_plan.digest(),
                "signature": scope_plan.signature(),
                "plan": scope_plan.plan(),
            }),
        );
        object.insert("complete".into(), json!(scope_plan.signature().is_some()));
        if scope_plan.signature().is_none() {
            object.insert(
                "error".into(),
                json!("applicable provider universe is not signed"),
            );
        }
        Ok(claim)
    })();
    result.unwrap_or_else(|error| {
        json!({
            "complete": false,
            "fullScope": false,
            "error": error,
            "requestedOnly": args.only.clone(),
            "requestedSkip": args.skip.clone(),
        })
    })
}

fn provider_selection_claim(
    applicable: &std::collections::BTreeSet<String>,
    selected: &std::collections::BTreeSet<String>,
    requested_only: &[String],
    requested_skip: &[String],
    inventory_digest: &str,
) -> Value {
    let selected_applicable = applicable
        .intersection(selected)
        .cloned()
        .collect::<Vec<_>>();
    let excluded = applicable.difference(selected).cloned().collect::<Vec<_>>();
    let full_scope = excluded.is_empty();
    json!({
        "complete": true,
        "inventoryDigest": inventory_digest,
        "applicableProviders": applicable.iter().cloned().collect::<Vec<_>>(),
        "selectedApplicableProviders": selected_applicable,
        "excludedApplicableProviders": excluded,
        "requestedOnly": requested_only,
        "requestedSkip": requested_skip,
        "fullScope": full_scope,
    })
}

fn provider_scope_claims_allowed(trusted_scope_universe: bool) -> bool {
    trusted_scope_universe
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
    /// New-file line ranges of every changed hunk, per path (diff-scoped
    /// audits only; empty otherwise). Paths without hunks are reviewed whole.
    changed_hunks: std::collections::BTreeMap<String, Vec<(usize, usize)>>,
    /// `HEAD` at scope resolution (diff-scoped audits only).
    head: Option<String>,
    facts_unavailable: bool,
    snapshot: Option<legion_audit::snapshot::SnapshotManifest>,
}

/// Scope types that name a changed-file set on their own.
fn scope_type_selects_changes(scope_type: &str) -> bool {
    matches!(scope_type, "local" | "uncommitted" | "committed")
}

impl AuditScope {
    /// True when the run is a real diff: a base ref/commit or a change-set
    /// scope type was given and the refs resolved. `--dir` alone only filters
    /// and never narrows the denominator.
    fn narrows_inventory(&self) -> bool {
        !self.facts_unavailable
            && (self
                .snapshot
                .as_ref()
                .is_some_and(|s| s.scope.spec.is_diff())
                || self.base.is_some()
                || self.base_commit.is_some()
                || scope_type_selects_changes(&self.scope_type))
    }

    /// The changed-file set the frozen denominator is restricted to, or
    /// `None` for a whole-repository (or `--dir`-only) run.
    fn inventory_filter(&self) -> Option<std::collections::BTreeSet<String>> {
        self.narrows_inventory()
            .then(|| self.changed_files.iter().cloned().collect())
    }

    fn plan_json(&self) -> Value {
        let mut scope = json!({
            "mode": self.mode,
            "type": self.scope_type,
            "base": self.base,
            "baseCommit": self.base_commit,
            "dir": self.dir,
            "snapshot": self.snapshot,
        });
        if self.narrows_inventory() {
            scope["head"] = json!(self.head);
            scope["changedFileCount"] = json!(self.changed_files.len());
            scope["denominator"] = json!("changed-files");
        }
        scope
    }

    fn facts_json(&self) -> Value {
        let mut scope = json!({
            "mode": self.mode,
            "type": self.scope_type,
            "base": self.base,
            "base_commit": self.base_commit,
            "dir": self.dir,
            "changed_files": self.changed_files,
            "snapshot": self.snapshot,
        });
        if self.narrows_inventory() {
            scope["head"] = json!(self.head);
            scope["changed_file_count"] = json!(self.changed_files.len());
            scope["denominator"] = json!("changed-files");
        }
        scope
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
    // Strip only a leading `./` (or a lone `.`); a dotfile such as
    // `.github/ci.yml` must keep its dot or it would drop out of a diff
    // denominator that is matched against inventory paths.
    if path == "." {
        return None;
    }
    while let Some(rest) = path.strip_prefix("./") {
        path = rest.to_string();
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
    legion_audit::scope::GitRunner::new(root)
        .text(git_args)
        .ok()
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
    let narrows = refs_valid
        && (scope_base.is_some()
            || scope_base_commit.is_some()
            || scope_type_selects_changes(&scope_type));
    let changed_hunks = if narrows {
        audit_changed_hunks(
            root,
            &scope_type,
            scope_base.as_deref(),
            scope_base_commit.as_deref(),
            scope_dir.as_deref(),
        )
    } else {
        std::collections::BTreeMap::new()
    };
    let head = if narrows {
        git_stdout(root, &["rev-parse", "HEAD"])
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    } else {
        None
    };
    AuditScope {
        mode: if scoped { "diff" } else { "whole-repo" },
        scope_type,
        base: scope_base,
        base_commit: scope_base_commit,
        dir: scope_dir,
        changed_files,
        changed_hunks,
        head,
        facts_unavailable: !refs_valid,
        snapshot: None,
    }
}

/// The inventory restriction a persisted run's facts record: `Some(changed
/// files)` when `facts.scope` describes a real diff, else `None`. Lets
/// `legion verify` rebuild the same narrowed denominator the run froze.
pub(super) fn inventory_filter_from_facts(
    facts: &Value,
) -> Option<std::collections::BTreeSet<String>> {
    let scope = facts.get("scope").filter(|scope| scope.is_object())?;
    let present = |key: &str| scope.get(key).is_some_and(|value| !value.is_null());
    let scope_type = scope.get("type").and_then(Value::as_str).unwrap_or("all");
    if !(present("base") || present("base_commit") || scope_type_selects_changes(scope_type)) {
        return None;
    }
    Some(
        scope
            .get("changed_files")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
    )
}

/// Merges `git diff -U0` hunk headers (`@@ -a,b +c,d @@` under `+++ b/path`)
/// into per-path new-file line ranges. A pure deletion (`d == 0`) is anchored
/// at the line it follows. Pure function over the diff text.
fn parse_diff_hunks(
    diff: &str,
    hunks: &mut std::collections::BTreeMap<String, Vec<(usize, usize)>>,
) {
    let mut current: Option<String> = None;
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            current = path
                .strip_prefix("b/")
                .and_then(clean_path)
                .filter(|_| path != "/dev/null");
        } else if line.starts_with("@@ ") {
            let Some(path) = current.as_ref() else {
                continue;
            };
            let Some(new) = line.split_whitespace().find(|part| part.starts_with('+')) else {
                continue;
            };
            let mut numbers = new[1..].split(',');
            let start = numbers.next().and_then(|n| n.parse::<usize>().ok());
            let count = numbers.next().map_or(Some(1), |n| n.parse::<usize>().ok());
            if let (Some(start), Some(count)) = (start, count) {
                let start = start.max(1);
                let end = if count == 0 { start } else { start + count - 1 };
                hunks.entry(path.clone()).or_default().push((start, end));
            }
        }
    }
}

fn audit_changed_hunks(
    root: &std::path::Path,
    scope_type: &str,
    scope_base: Option<&str>,
    scope_base_commit: Option<&str>,
    scope_dir: Option<&str>,
) -> std::collections::BTreeMap<String, Vec<(usize, usize)>> {
    let mut hunks = std::collections::BTreeMap::new();
    let mut add = |git_args: &[&str]| {
        if let Some(diff) = git_stdout(root, git_args) {
            parse_diff_hunks(&diff, &mut hunks);
        }
    };
    if scope_type == "local" {
        add(&["diff", "-U0", "--no-color", "--no-ext-diff", "HEAD"]);
        let upstream = git_stdout(
            root,
            &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        )
        .map(|reference| reference.trim().to_string())
        .filter(|reference| !reference.is_empty());
        if let Some(upstream) = upstream {
            let range = format!("{upstream}..HEAD");
            add(&["diff", "-U0", "--no-color", "--no-ext-diff", &range]);
        }
    } else if let Some(commit) = scope_base_commit {
        add(&["diff", "-U0", "--no-color", "--no-ext-diff", commit]);
    } else if let Some(base) = scope_base {
        let range = format!("{base}...HEAD");
        add(&["diff", "-U0", "--no-color", "--no-ext-diff", &range]);
    } else if scope_type == "uncommitted" {
        add(&["diff", "-U0", "--no-color", "--no-ext-diff"]);
    } else if scope_type == "committed" {
        add(&["diff", "-U0", "--no-color", "--no-ext-diff", "HEAD~1..HEAD"]);
    }
    hunks.retain(|path, ranges| {
        ranges.sort_unstable();
        ranges.dedup();
        in_scope(path, scope_dir)
    });
    hunks
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
    if let Some(snapshot) = &scope.snapshot {
        context["head"] = json!(snapshot.scope.selected_oid);
        context["sourceRepository"] = json!(snapshot.scope.source_root);
        context["baseline"] = json!({
            "status": if snapshot.scope.baseline_oid.is_some() || snapshot.scope.head_kind == "index" || matches!(snapshot.scope.spec, legion_audit::scope::ScopeSpec::Uncommitted) { "resolved" } else { "not-applicable" },
            "kind": "immutable-snapshot",
            "commit": snapshot.scope.baseline_oid,
            "baseRefOid": snapshot.scope.base_ref_oid,
            "mergeBase": snapshot.scope.merge_base_oid,
            "root": snapshot.baseline_root,
        });
        return context;
    }
    if scope.narrows_inventory() {
        context["changedHunks"] = json!(scope.changed_hunks);
        context["head"] = json!(scope.head);
    }
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
    only_paths: Option<&std::collections::BTreeSet<String>>,
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
    let source = super::audit_inventory_source_scoped(root, only_paths)?;
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
    only_paths: Option<&std::collections::BTreeSet<String>>,
) -> Result<Arc<legion_application::NativeApplication>, CommandError> {
    let root = std::path::Path::new(repository_id);
    if std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_some() || !root.is_dir() {
        return super::native_application_for(repository_id);
    }
    native_registry_application(root, None, only_paths)
        .map(|(application, _, _scratch)| Arc::new(application))
}

fn rightkit_trust_early_subcommand(args: &AuditArgs) -> Option<&'static str> {
    if args.root.as_os_str() == "ingest"
        && (args.ingest_run.is_some()
            || args.ingest_provider.is_some()
            || !args.ingest_result.is_empty()
            || args.followup)
    {
        Some("ingest")
    } else if args.root.as_os_str() == "next" && args.ingest_run.is_some() {
        Some("next")
    } else if args.root.as_os_str() == "findings" && !args.findings_args.is_empty() {
        Some("findings")
    } else {
        None
    }
}

const MAX_RIGHTKIT_TRUST_FILE_BYTES: u64 = 1024 * 1024;

fn validate_rightkit_trust_path(
    path: &std::path::Path,
    audited_root: &std::path::Path,
    scratch_root: &std::path::Path,
) -> Result<PathBuf, CommandError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(CommandError::usage(
            "--rightkit-trust must be an absolute path without parent traversal",
        ));
    }

    let mut file_metadata = None;
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(super::io_error)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(CommandError::usage(
                "--rightkit-trust path cannot contain symlink or reparse components",
            ));
        }
        if ancestor == path {
            file_metadata = Some(metadata);
        } else if !metadata.is_dir() {
            return Err(CommandError::usage(
                "--rightkit-trust parent components must be directories",
            ));
        }
    }
    let metadata = file_metadata.ok_or_else(|| {
        CommandError::usage("--rightkit-trust must name a regular enrollment file")
    })?;
    if !metadata.is_file() {
        return Err(CommandError::usage(
            "--rightkit-trust must name a regular enrollment file",
        ));
    }
    if metadata.len() > MAX_RIGHTKIT_TRUST_FILE_BYTES {
        return Err(CommandError::usage(
            "--rightkit-trust enrollment exceeds 1 MiB",
        ));
    }

    let canonical_path = std::fs::canonicalize(path).map_err(super::io_error)?;
    let canonical_audit_root = std::fs::canonicalize(audited_root).map_err(super::io_error)?;
    let canonical_scratch_root = std::fs::canonicalize(scratch_root).map_err(super::io_error)?;
    if canonical_path.starts_with(&canonical_audit_root)
        || canonical_path.starts_with(&canonical_scratch_root)
    {
        return Err(CommandError::usage(
            "--rightkit-trust enrollment must be outside the audited and scratch roots",
        ));
    }
    Ok(canonical_path)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod rightkit_trust_cli_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_root() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "legion-rightkit-trust-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
    }

    #[test]
    fn rightkit_trust_path_rejects_relative_paths() {
        let error = validate_rightkit_trust_path(
            std::path::Path::new("relative-enrollment.json"),
            std::path::Path::new("/audit"),
            std::path::Path::new("/scratch"),
        )
        .unwrap_err();
        assert!(error.message.contains("absolute path"));
    }

    #[test]
    fn rightkit_trust_path_rejects_files_inside_audit_or_scratch_roots() {
        let base = test_root();
        let audited = base.join("repo");
        let scratch = base.join("scratch");
        std::fs::create_dir_all(&audited).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        let in_audit = audited.join("enrollment.json");
        let in_scratch = scratch.join("enrollment.json");
        std::fs::write(&in_audit, b"{}").unwrap();
        std::fs::write(&in_scratch, b"{}").unwrap();

        for path in [&in_audit, &in_scratch] {
            let error = validate_rightkit_trust_path(path, &audited, &scratch).unwrap_err();
            assert!(error
                .message
                .contains("outside the audited and scratch roots"));
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rightkit_trust_path_rejects_symlink_components() {
        use std::os::unix::fs::symlink;

        let base = test_root();
        let audited = base.join("repo");
        let scratch = base.join("scratch");
        let trusted = base.join("trusted");
        std::fs::create_dir_all(&audited).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::create_dir_all(&trusted).unwrap();
        let target = trusted.join("enrollment.json");
        let link = base.join("enrollment.json");
        std::fs::write(&target, b"{}").unwrap();
        symlink(&target, &link).unwrap();

        let error = validate_rightkit_trust_path(&link, &audited, &scratch).unwrap_err();
        assert!(error.message.contains("symlink or reparse"));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rightkit_trust_rejects_alternate_provider_routes() {
        assert!(rightkit_trust_route_is_supported(false, false, false));
        assert!(!rightkit_trust_route_is_supported(true, false, false));
        assert!(!rightkit_trust_route_is_supported(false, true, false));
        assert!(!rightkit_trust_route_is_supported(false, false, true));
    }
}

fn rightkit_trust_route_is_supported(
    direct: bool,
    native_rule_manifest: bool,
    native_application_configured: bool,
) -> bool {
    !direct && !native_rule_manifest && !native_application_configured
}

fn native_registry_application(
    root: &std::path::Path,
    rightkit_trust: Option<&std::path::Path>,
    only_paths: Option<&std::collections::BTreeSet<String>>,
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
    let source = super::audit_inventory_source_scoped(root, only_paths)?;
    // All audit scratch lives outside the audited tree and is removed when the
    // registry (the last holder) is dropped.
    let scratch = std::sync::Arc::new(
        legion_audit::native_providers::legacy_checks::AuditScratch::create(root)
            .map_err(|error| CommandError::incomplete(error.to_string()))?,
    );
    let enrollment = rightkit_trust
        .map(|path| validate_rightkit_trust_path(path, root, scratch.root()))
        .transpose()?
        .map(|path| {
            legion_audit::native_providers::legacy_checks::AttestedRunsEnrollment::load(&path)
                .map_err(|error| CommandError::usage(error.to_string()))
        })
        .transpose()?;
    let external_tool = native_audit_external_tool(&scratch);
    let mut registry = legion_audit::NativeProviderRegistry::new(root.to_path_buf())
        .with_scratch(scratch.clone())
        .with_external_project_tool(external_tool);
    if root.join(".legion-audit-snapshot").is_file() {
        let manifest = root
            .parent()
            .ok_or_else(|| CommandError::integrity("snapshot parent missing"))?
            .join("manifest.json");
        let snapshot = legion_audit::snapshot::FrozenSnapshot::open(&manifest)
            .map_err(|error| CommandError::integrity(error.to_string()))?;
        if snapshot.manifest.execution_root != root {
            return Err(CommandError::integrity("snapshot root binding mismatch"));
        }
        registry.security = registry.security.with_snapshot_manifest(manifest);
    }
    if let Some(enrollment) = enrollment {
        registry = registry.with_attested_runs(enrollment);
    }
    let executor = std::sync::Arc::new(registry);
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
        // Native legacy checks report in-memory stream summaries with
        // `path: null` and `immutable: false`; those summaries are not captured
        // artifacts and must not be retained as if they were external refs.
        let receipt = receipt.and_then(Value::as_object).filter(|receipt| {
            receipt.get("kind").and_then(Value::as_str) != Some("native-legacy-check-receipt")
        });
        let mut refs: Vec<(&str, &Value)> = Vec::new();
        if let Some(receipt) = receipt {
            for stream in ["stdout", "stderr", "brokerStatus"] {
                if let Some(value) = receipt.get(stream).filter(|value| !value.is_null()) {
                    refs.push((stream, value));
                }
            }
        }
        // Immutable artifact refs the provider records directly in its details
        // (for example the signed broker status read back after submit).
        for key in legion_audit::DETAILS_ARTIFACT_REF_KEYS {
            if let Some(value) = provider.result.details.get(*key).filter(|v| !v.is_null()) {
                refs.push((*key, value));
            }
        }
        for (stream, value) in refs {
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

fn read_provider_plan_document(path: &std::path::Path) -> Result<Value, CommandError> {
    use std::io::Read;
    const LIMIT: u64 = 64 * 1024 * 1024;
    let file = std::fs::File::open(path).map_err(super::io_error)?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(super::io_error)?;
    if bytes.len() as u64 > LIMIT {
        return Err(CommandError::usage("provider plan exceeds byte limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| CommandError::usage(format!("invalid provider plan: {error}")))
}

/// Imported results retain their original execution-root identity only after
/// matching an independently captured current source scope. Signed inputs also
/// authenticate their exact specs & context before their snapshot is selected.
fn imported_direct_snapshot(
    args: &AuditArgs,
    fresh: legion_audit::snapshot::FrozenSnapshot,
) -> Result<legion_audit::snapshot::FrozenSnapshot, CommandError> {
    let Some(path) = args.provider_plan.as_ref() else {
        return Ok(fresh);
    };
    let value = read_provider_plan_document(path)?;
    let sealed = plan_is_sealed(&value);
    let Some(manifest) = value
        .pointer("/reviewContext/snapshotManifest")
        .and_then(Value::as_str)
    else {
        if sealed {
            return Err(CommandError::integrity(
                "sealed provider plan requires frozen snapshot context",
            ));
        }
        return Ok(fresh);
    };
    let imported = legion_audit::snapshot::FrozenSnapshot::open(std::path::Path::new(manifest))
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    if value
        .pointer("/reviewContext/snapshotKey")
        .and_then(Value::as_str)
        != Some(imported.manifest.key.as_str())
        || imported.manifest.key != fresh.manifest.key
        || imported.manifest.scope.source_root != fresh.manifest.scope.source_root
    {
        return Err(CommandError::integrity(
            "imported provider snapshot differs from current requested source scope",
        ));
    }
    imported
        .verify_source_current()
        .map_err(|error| CommandError::integrity(error.to_string()))?;
    if sealed {
        let specifications = parse_provider_plan_value(&value)?;
        for spec in &specifications {
            if spec.reasoning.get("reviewContext") != value.get("reviewContext") {
                return Err(CommandError::integrity(
                    "imported snapshot context differs from sealed provider specification",
                ));
            }
        }
        let root = &imported.manifest.execution_root;
        let filter = imported.manifest.scope.inventory_filter();
        let source = super::audit_inventory_source_scoped(root, filter.as_ref())?;
        let key = plan_claimed_signature(&value)
            .map(|_| plan_verification_key(path))
            .transpose()?;
        verify_sealed_plan(&value, root, &*source, &specifications, key.as_deref())?;
    }
    Ok(imported)
}

fn direct_application(
    args: &AuditArgs,
    root: &std::path::Path,
    only_paths: Option<&std::collections::BTreeSet<String>>,
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
    let source = super::audit_inventory_source_scoped(root, only_paths)?;
    let plan_value = read_provider_plan_document(plan)?;
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

fn write_control_artifact(
    root: &std::path::Path,
    name: &str,
    value: &Value,
) -> Result<(), CommandError> {
    // Frozen controls are machine inputs. Pretty-printing their nested plan
    // copies can exceed the runtime's bounded JSON reader without adding data.
    write_artifact(
        root,
        name,
        &serde_json::to_vec(value).map_err(super::io_error)?,
    )
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
mod provider_scope_coverage_tests {
    use super::provider_selection_claim;
    use serde_json::json;
    use std::collections::BTreeSet;

    fn ids(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn non_applicable_providers_do_not_appear_as_scope_omissions() {
        let claim = provider_selection_claim(
            &ids(&["security.source"]),
            &ids(&["security.source", "legacy.runtime"]),
            &[],
            &[],
            "sha256:inventory",
        );

        assert_eq!(claim["fullScope"], json!(true));
        assert_eq!(claim["excludedApplicableProviders"], json!([]));
        assert_eq!(claim["applicableProviders"], json!(["security.source"]));
    }

    #[test]
    fn explicit_filter_records_each_omitted_applicable_provider() {
        let claim = provider_selection_claim(
            &ids(&["security.source", "security.secrets"]),
            &ids(&["security.source"]),
            &["security.source".into()],
            &[],
            "sha256:inventory",
        );

        assert_eq!(claim["fullScope"], json!(false));
        assert_eq!(
            claim["excludedApplicableProviders"],
            json!(["security.secrets"])
        );
        assert_eq!(claim["requestedOnly"], json!(["security.source"]));
    }

    #[test]
    fn imported_or_custom_provider_specs_cannot_mint_a_scope_universe() {
        assert!(!super::provider_scope_claims_allowed(false));
        assert!(super::provider_scope_claims_allowed(true));
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
            rightkit_trust: None,
            runtime_interactions: None,
            runtime_fixtures: None,
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
            ingest_result: Vec::new(),
            followup: false,
            findings_args: Vec::new(),
            findings_repo: None,
            findings_by: None,
            findings_generation: None,
            findings_active: false,
            seat_token_budget: 150_000,
            max_lens_seats: 16,
            allow_oversize_lenses: false,
            coverage: "auto".into(),
            run_token_budget: 6_000_000,
            max_total_seats: 48,
            report_schema: 2,
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
    fn diff_hunks_parse_new_file_ranges_and_anchor_pure_deletions() {
        let diff = "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -10,2 +10,3 @@ fn x()\n@@ -40 +41 @@\n@@ -60,4 +60,0 @@\ndiff --git a/gone.rs b/gone.rs\n--- a/gone.rs\n+++ /dev/null\n@@ -1,5 +0,0 @@\n";
        let mut hunks = std::collections::BTreeMap::new();
        parse_diff_hunks(diff, &mut hunks);
        assert_eq!(hunks.len(), 1, "deleted files carry no hunks: {hunks:?}");
        assert_eq!(hunks["src/a.rs"], vec![(10, 12), (41, 41), (60, 60)]);
    }

    #[test]
    fn facts_scope_restores_the_diff_denominator_filter_only_for_real_diffs() {
        let diff = json!({"scope": {
            "mode": "diff", "type": "all", "base": null, "base_commit": "abc123",
            "dir": null, "changed_files": ["src/b.rs", "src/a.rs"]
        }});
        let filter = inventory_filter_from_facts(&diff).expect("diff filter");
        assert_eq!(
            filter.into_iter().collect::<Vec<_>>(),
            vec!["src/a.rs".to_owned(), "src/b.rs".to_owned()]
        );
        // `--dir` alone records mode diff with no changed files: no narrowing.
        let dir_only = json!({"scope": {
            "mode": "diff", "type": "all", "base": null, "base_commit": null,
            "dir": "engine", "changed_files": []
        }});
        assert!(inventory_filter_from_facts(&dir_only).is_none());
        assert!(inventory_filter_from_facts(&json!({})).is_none());
    }

    #[test]
    fn base_commit_scope_narrows_the_denominator_and_records_hunks() {
        let root = std::env::temp_dir().join(format!(
            "legion-audit-diff-scope-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("src")).unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(args)
                .current_dir(&root)
                .output()
                .unwrap();
            assert!(output.status.success(), "git {args:?}: {output:?}");
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        };
        git(&["init", "-q"]);
        let body: String = (1..=100).map(|n| format!("let v{n} = {n};\n")).collect();
        for name in ["a", "b", "c"] {
            std::fs::write(root.join(format!("src/{name}.rs")), &body).unwrap();
        }
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "base"]);
        let base = git(&["rev-parse", "HEAD"]);
        let changed = body.replace("let v50 = 50;", "let v50 = 5000;");
        std::fs::write(root.join("src/b.rs"), changed).unwrap();
        git(&["commit", "-qam", "change b"]);
        let head = git(&["rev-parse", "HEAD"]);

        let args = AuditArgs {
            base_commit: Some(base.clone()),
            ..minimal_audit_args()
        };
        let scope = audit_scope(&root, &args);
        assert!(scope.narrows_inventory());
        assert_eq!(scope.changed_files, vec!["src/b.rs".to_owned()]);
        assert_eq!(scope.head.as_deref(), Some(head.as_str()));
        assert_eq!(scope.changed_hunks["src/b.rs"], vec![(50, 50)]);
        let plan = scope.plan_json();
        assert_eq!(plan["head"], json!(head));
        assert_eq!(plan["changedFileCount"], json!(1));
        assert_eq!(plan["denominator"], "changed-files");

        // The frozen denominator is the changed set only.
        let filter = scope.inventory_filter();
        let source = super::super::audit_inventory_source_scoped(&root, filter.as_ref()).unwrap();
        let inventory = source.inventory(&root.to_string_lossy()).unwrap();
        assert_eq!(inventory.paths().collect::<Vec<_>>(), ["src/b.rs"]);
        let whole = super::super::audit_inventory_source(&root).unwrap();
        assert_eq!(
            whole
                .inventory(&root.to_string_lossy())
                .unwrap()
                .paths()
                .count(),
            3
        );
        // The frozen review context carries the hunks for lens packets.
        let context = review_context(&root, &scope);
        assert_eq!(context["changedHunks"]["src/b.rs"], json!([[50, 50]]));
        assert_eq!(context["head"], json!(head));
        std::fs::remove_dir_all(&root).unwrap();
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
            changed_hunks: std::collections::BTreeMap::new(),
            head: None,
            facts_unavailable: false,
            snapshot: None,
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
        let (gaps, injected) = apply_runtime_inputs(&args, &args.root, &mut specs, false).unwrap();
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
    fn runtime_interaction_descriptors_are_frozen_only_after_exact_scope_and_digest_checks() {
        let dir = std::env::temp_dir().join(format!(
            "legion-runtime-interactions-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("interactions.json");
        let fixture_file = dir.join("runtime-fixtures.json");
        let source_path = dir.join("index.html");
        let body_bytes = b"<main data-testid='ready'>ready</main>";
        std::fs::write(&source_path, body_bytes).unwrap();
        let body = serde_json::to_value(body_bytes.as_slice()).unwrap();
        let fixture_digest = legion_contracts::canonical_digest(&json!({
            "files":[{"body":body,"contentType":"text/html","path":"/index.html"}]
        }))
        .unwrap();
        let write_manifest = |source_path: &str, url_path: &str| {
            std::fs::write(
                &fixture_file,
                serde_json::to_vec(&json!({
                    "schemaVersion":1,
                    "fixtures":[{
                        "id":"settings-fixture",
                        "files":[{
                            "sourcePath":source_path,
                            "path":url_path,
                            "contentType":"text/html"
                        }]
                    }]
                }))
                .unwrap(),
            )
            .unwrap();
        };
        write_manifest("index.html", "/index.html");
        let actions = json!([{"type":"assertVisible","selector":"[data-testid='ready']"}]);
        let actions_digest = legion_contracts::canonical_digest(&actions).unwrap();
        let descriptor = |surface: Value, actions: Value, digest: &str, fixture_digest: &str| {
            json!([{
                "id": "settings-ready",
                "surface": surface,
                "fixture": {"id":"settings-fixture", "sourceDigest":fixture_digest},
                "probe": {"id":"settings-ready-probe", "actionsDigest":digest},
                "isolationBindingId":"test-isolation-binding",
                "expiresAfterMs":30000,
                "actions":actions
            }])
        };
        let url = "http://127.0.0.1:1422/index.html";
        let mut args = minimal_audit_args();
        args.root = dir.clone();
        args.url = Some(url.into());
        args.runtime_interactions = Some(file.clone());
        args.runtime_fixtures = Some(fixture_file.clone());
        let mut specs = vec![runtime_spec()];

        std::fs::write(
            &file,
            serde_json::to_vec(&descriptor(
                json!({"label":"entry", "url":url}),
                actions.clone(),
                &actions_digest,
                &fixture_digest,
            ))
            .unwrap(),
        )
        .unwrap();
        let (gaps, injected) = apply_runtime_inputs(&args, &args.root, &mut specs, false).unwrap();
        assert!(gaps.is_empty());
        assert!(injected);
        assert_eq!(
            specs[0].runner["runtime"]["interactions"][0]["probe"]["actionsDigest"],
            actions_digest
        );
        assert_eq!(
            specs[0].runner["runtime"]["interactions"][0]["surface"],
            json!({"label":"entry", "url":url})
        );
        assert_eq!(
            specs[0].runner["runtime"]["interactions"][0]["fixture"]["sourceDigest"],
            fixture_digest
        );
        assert_eq!(
            specs[0].runner["runtime"]["interactions"][0]["fixture"]["files"][0]["body"],
            body
        );

        let mut invalid_expiry = descriptor(
            json!({"label":"entry", "url":url}),
            actions.clone(),
            &actions_digest,
            &fixture_digest,
        )[0]
        .clone();
        invalid_expiry["expiresAfterMs"] = json!(30001);
        std::fs::write(&file, serde_json::to_vec(&json!([invalid_expiry])).unwrap()).unwrap();
        assert!(read_runtime_interactions(&args, &args.root, url, &[]).is_err());

        let source = super::super::audit_inventory_source(&dir).unwrap();
        let inventory = source.inventory(&dir.to_string_lossy()).unwrap();
        let referenced = std::collections::BTreeMap::from([(
            "settings-fixture".to_owned(),
            (fixture_digest.clone(), "/index.html".to_owned()),
        )]);
        std::fs::write(&source_path, b"changed after frozen inventory").unwrap();
        assert!(
            read_runtime_fixture_manifest(&fixture_file, &dir, &inventory, &referenced).is_err()
        );
        std::fs::write(&source_path, body_bytes).unwrap();

        // Fixture URL path must be byte-for-byte present in the frozen bundle.
        let mismatched_path = std::collections::BTreeMap::from([(
            "settings-fixture".to_owned(),
            (fixture_digest.clone(), "/other.html".to_owned()),
        )]);
        assert!(
            read_runtime_fixture_manifest(&fixture_file, &dir, &inventory, &mismatched_path)
                .is_err()
        );

        // A caller cannot point an action descriptor at a surface that was not
        // part of the frozen navigation inventory.
        std::fs::write(
            &file,
            serde_json::to_vec(&descriptor(
                json!({"label":"unfrozen", "url":"http://127.0.0.1:1422/admin"}),
                actions.clone(),
                &actions_digest,
                &fixture_digest,
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(read_runtime_interactions(&args, &args.root, url, &[]).is_err());

        write_manifest("missing.html", "/index.html");
        assert!(read_runtime_interactions(&args, &args.root, url, &[]).is_err());
        write_manifest("index.html", "/index.html");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let external = dir.join("outside.html");
            std::fs::write(&external, body_bytes).unwrap();
            symlink(&external, dir.join("linked.html")).unwrap();
            write_manifest("linked.html", "/index.html");
            assert!(read_runtime_interactions(&args, &args.root, url, &[]).is_err());
            std::fs::remove_file(dir.join("linked.html")).unwrap();
            std::fs::remove_file(external).unwrap();
        }

        let too_many_files = (0..=MAX_RUNTIME_FIXTURE_FILES)
            .map(|_| json!({"sourcePath":"index.html", "path":"/duplicate.html", "contentType":"text/html"}))
            .collect::<Vec<_>>();
        std::fs::write(
            &fixture_file,
            serde_json::to_vec(&json!({"schemaVersion":1,"fixtures":[{"id":"settings-fixture","files":too_many_files}]})).unwrap(),
        )
        .unwrap();
        assert!(read_runtime_interactions(&args, &args.root, url, &[]).is_err());
        write_manifest("index.html", "/index.html");

        // The allow-list excludes script/eval and action mutations without a
        // probe-declared, verified digest.
        let script_actions = json!([{"type":"eval", "expression":"window.localStorage.clear()"}]);
        let script_digest = legion_contracts::canonical_digest(&script_actions).unwrap();
        std::fs::write(
            &file,
            serde_json::to_vec(&descriptor(
                json!({"label":"entry", "url":url}),
                script_actions,
                &script_digest,
                &fixture_digest,
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(read_runtime_interactions(&args, &args.root, url, &[]).is_err());

        std::fs::write(
            &file,
            serde_json::to_vec(&descriptor(
                json!({"label":"entry", "url":url}),
                actions,
                &format!("sha256:{}", "0".repeat(64)),
                &fixture_digest,
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(read_runtime_interactions(&args, &args.root, url, &[]).is_err());
        let unsupported_actions = json!([{"type":"assertStyle","selector":"button","property":"display","value":"block"}]);
        let unsupported_digest = legion_contracts::canonical_digest(&unsupported_actions).unwrap();
        std::fs::write(
            &file,
            serde_json::to_vec(&descriptor(
                json!({"label":"entry", "url":url}),
                unsupported_actions,
                &unsupported_digest,
                &fixture_digest,
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(read_runtime_interactions(&args, &args.root, url, &[]).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_interaction_urls_must_be_exact_loopback_hosts() {
        for url in [
            "http://localhost:3000/",
            "https://127.0.0.1/probe",
            "http://[::1]:8080/",
        ] {
            assert!(loopback_http_url(url), "{url}");
        }
        for url in [
            "http://example.test/",
            "http://localhost.example.test/",
            "http://127.0.0.2/",
            "http://localhost@evil.test/",
            "file:///tmp/fixture",
        ] {
            assert!(!loopback_http_url(url), "{url}");
        }
    }

    #[test]
    fn runtime_fixture_url_paths_are_exact_and_unencoded() {
        assert_eq!(
            exact_fixture_url_path("http://127.0.0.1:1422/index.html"),
            Some("/index.html")
        );
        for url in [
            "http://127.0.0.1:1422/",
            "http://127.0.0.1:1422/%69ndex.html",
            "http://127.0.0.1:1422/index.html?x=1",
            "http://127.0.0.1:1422/index.html#top",
            "http://127.0.0.1:0/index.html",
        ] {
            assert_eq!(exact_fixture_url_path(url), None, "{url}");
        }
    }

    #[test]
    fn expanded_runtime_fixture_config_has_a_cumulative_serialized_cap() {
        let repeated_body = serde_json::to_value(vec![120_u8; 600_000]).unwrap();
        let repeated_file = json!({
            "sourcePath":"index.html",
            "sourceDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "path":"/index.html",
            "contentType":"text/html",
            "body":repeated_body,
        });
        let descriptors = (0..MAX_RUNTIME_INTERACTIONS)
            .map(|index| {
                json!({
                    "id":format!("probe-{index}"),
                    "fixture":{"id":"fixture","sourceDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inventoryDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","files":[repeated_file.clone()]},
                })
            })
            .collect::<Vec<_>>();
        assert!(json_encoded_len(&json!(descriptors)).unwrap() > MAX_RUNTIME_FROZEN_CONFIG_BYTES);
    }

    #[test]
    fn runtime_visual_capture_source_is_frozen_only_without_explicit_spec() {
        let mut args = minimal_audit_args();
        args.url = Some("https://example.test/".into());
        let mut specs = vec![runtime_spec(), visual_spec_provider()];
        apply_runtime_inputs(&args, &args.root, &mut specs, false).unwrap();
        apply_visual_inputs(&args, &mut specs, false).unwrap();
        bind_runtime_visual_capture_source(&mut specs);
        assert_eq!(
            specs[1].runner["visual"]["captureSource"],
            json!({"kind":"runtime-provider","providerId":RUNTIME_PROVIDER_ID})
        );

        let (spec_path, _) = visual_fixture("capture-source-explicit");
        args.visual_spec = Some(spec_path);
        let mut explicit = vec![runtime_spec(), visual_spec_provider()];
        apply_runtime_inputs(&args, &args.root, &mut explicit, false).unwrap();
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
        let (gaps, injected) = apply_runtime_inputs(&args, &args.root, &mut specs, false).unwrap();
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
            &args.root,
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
            apply_runtime_inputs(&args, &args.root, &mut vec![runtime_spec()], true).unwrap();
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
        let error =
            apply_runtime_inputs(&args, &args.root, &mut vec![runtime_spec()], false).unwrap_err();
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
            rightkit_trust: None,
            runtime_interactions: None,
            runtime_fixtures: None,
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
            ingest_result: Vec::new(),
            followup: false,
            findings_args: Vec::new(),
            findings_repo: None,
            findings_by: None,
            findings_generation: None,
            findings_active: false,
            seat_token_budget: 150_000,
            max_lens_seats: 16,
            allow_oversize_lenses: false,
            coverage: "auto".into(),
            run_token_budget: 6_000_000,
            max_total_seats: 48,
            report_schema: 2,
        }
    }

    #[test]
    fn rightkit_trust_refuses_ingest_subcommand() {
        let mut args = minimal_audit_args();
        args.root = PathBuf::from("ingest");
        args.rightkit_trust = Some(PathBuf::from("/external/enrollment.json"));
        args.ingest_run = Some(PathBuf::from("/run"));

        assert_eq!(rightkit_trust_early_subcommand(&args), Some("ingest"));
    }

    #[test]
    fn rightkit_trust_refuses_findings_subcommand_but_allows_plain_directory() {
        let mut args = minimal_audit_args();
        args.root = PathBuf::from("findings");
        args.rightkit_trust = Some(PathBuf::from("/external/enrollment.json"));
        args.findings_args = vec!["list".to_owned()];

        assert_eq!(rightkit_trust_early_subcommand(&args), Some("findings"));

        args.findings_args.clear();
        assert_eq!(rightkit_trust_early_subcommand(&args), None);
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
        let native = native_plan_document(
            &Ok((frozen.clone(), inventory.clone())),
            frozen.digest(),
            frozen.signature(),
        )
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
            "nativePlan": native,
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

    #[test]
    fn compact_control_artifacts_preserve_large_frozen_plan_integrity() {
        const RUNTIME_JSON_LIMIT: usize = 16 * 1024 * 1024;
        let root = fixture_root("compact-controls");
        let source = crate::commands::audit_inventory_source(&root).unwrap();
        let inventory = source.inventory(&root.to_string_lossy()).unwrap();
        let mut metadata = Value::Array(vec![json!(0); 125_000]);
        for _ in 0..32 {
            metadata = json!({"scope": metadata});
        }
        let mut provider = spec();
        provider.reasoning["serializationFixture"] = metadata;
        let frozen = legion_audit::AuditPlan::compile_with_root(
            Some(&root),
            &inventory,
            &[provider.clone()],
        )
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
        let native = native_plan_document(
            &Ok((frozen.clone(), inventory.clone())),
            frozen.digest(),
            frozen.signature(),
        )
        .unwrap();
        let plan = json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "planDigest": frozen.digest(),
            "planSignature": frozen.signature(),
            "seal": {"digest": frozen.digest(), "signature": frozen.signature(), "authenticity": "hmac-sha256"},
            "binding": {"repositoryRevision": inventory.generation, "inventoryDigest": inventory.digest},
            "providerSpecs": [provider],
            "nativePlan": native
        });
        let facts = json!({"schemaVersion": 1, "kind": "audit-facts", "plan": plan});
        let out = root.join("out");
        for (name, document, plan_pointer) in
            [("plan.json", &plan, ""), ("facts.json", &facts, "/plan")]
        {
            assert!(serde_json::to_vec_pretty(document).unwrap().len() > RUNTIME_JSON_LIMIT);
            let expected_digest = legion_contracts::canonical_digest(document).unwrap();
            write_control_artifact(&out, name, document).unwrap();
            let bytes = std::fs::read(out.join(name)).unwrap();
            assert!(bytes.len() < RUNTIME_JSON_LIMIT);
            let restored: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(&restored, document);
            assert_eq!(
                legion_contracts::canonical_digest(&restored).unwrap(),
                expected_digest
            );
            let restored_plan = restored.pointer(plan_pointer).unwrap();
            assert_eq!(restored_plan["seal"], plan["seal"]);
            assert_eq!(restored_plan["binding"], plan["binding"]);
            let native: legion_audit::AuditPlan =
                serde_json::from_value(restored_plan["nativePlan"]["plan"].clone()).unwrap();
            assert_eq!(native, *frozen.plan());
            assert_eq!(native.providers[0].configuration["denominatorCount"], 1);
            legion_audit::verify(&native, frozen.digest(), frozen.signature(), Some(KEY)).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plan_only_and_executed_artifacts_resolve_frozen_graph_context() {
        let root = fixture_root("graph-context-artifacts");
        let source = crate::commands::audit_inventory_source(&root).unwrap();
        let inventory = source.inventory(&root.to_string_lossy()).unwrap();
        let graph = json!({"coverageFloor":"lexical-js-ts-relative-imports-only",
            "unknowns":[{"path":"src/lib.rs","cause":"unresolved-import"}],
            "blastRadius":{"certain":[],"inferred":[],"provesDeadCode":false}});
        let mut provider = spec();
        provider.reasoning["reviewContext"] = json!({"graphContext":graph});
        let frozen =
            legion_audit::AuditPlan::compile_with_root(Some(&root), &inventory, &[provider])
                .unwrap()
                .freeze(Some(KEY))
                .unwrap();
        let basis = Ok((frozen.clone(), inventory));
        // Both production branches persist this same seal-checked document:
        // plan-only also exposes top-level planDigest/planSignature, while
        // execution binds nativePlan via seal without those duplicate fields.
        let native = native_plan_document(&basis, frozen.digest(), frozen.signature()).unwrap();
        let mut plan_only = sealed_plan(&root);
        plan_only["planDigest"] = json!(frozen.digest());
        plan_only["planSignature"] = json!(frozen.signature());
        plan_only["seal"] = json!({"digest":frozen.digest(),"signature":frozen.signature()});
        plan_only["nativePlan"] = native.clone();
        let executed = json!({"schemaVersion":1,"kind":"audit-provider-plan",
            "seal":{"digest":frozen.digest(),"signature":frozen.signature()},
            "nativePlan":native});
        let pointer =
            "/nativePlan/plan/providers/0/configuration/reasoning/reviewContext/graphContext";
        let expected_digest = legion_contracts::canonical_digest(&graph).unwrap();
        for mut artifact in [plan_only, executed] {
            artifact["reviewContext"] = json!({"graphContext":{"tampered":true}});
            let resolved = artifact.pointer(pointer).unwrap();
            assert_eq!(resolved, &graph);
            assert_eq!(
                legion_contracts::canonical_digest(resolved).unwrap(),
                expected_digest
            );
            assert_eq!(artifact["nativePlan"]["digest"], artifact["seal"]["digest"]);
            assert_eq!(
                artifact["nativePlan"]["signature"],
                artifact["seal"]["signature"]
            );
        }
        std::fs::remove_dir_all(root).unwrap();
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
    fn details_level_broker_status_ref_is_retained() {
        let base = root("details-status");
        let repository = base.join("repo");
        let out = base.join("run");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let scratch = scratch(&repository);
        let status = b"signed broker status";
        write_source(&scratch, "fixture/status", status);
        let mut present = execution(None, None);
        present.results[0].result.details.insert(
            "rustRightBrokerStatus".into(),
            record("fixture/status", status),
        );

        assert!(retain_effect_artifacts(&out, &scratch, &mut present).is_empty());
        assert_eq!(
            std::fs::read(out.join("artifacts/fixture/status")).unwrap(),
            status
        );

        let mut missing = {
            let mut e = execution(None, None);
            e.results[0].result.details.insert(
                "rustRightBrokerStatus".into(),
                record("missing/status", status),
            );
            e
        };
        let gaps = retain_effect_artifacts(&out, &scratch, &mut missing);
        assert!(!gaps.is_empty());
        assert!(!missing.results[0].result.complete);
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

#[cfg(test)]
mod bounded_dispatch_projection_tests {
    use super::*;

    #[test]
    fn selected_and_deferred_parts_remain_distinct_in_output() {
        let mut items = vec![
            json!({"provider":"reasoning.schema", "status":"pending-host",
            "parts":[{"packet":"lens-packets/schema.part1.json", "status":"pending-host"},
                     {"packet":"lens-packets/schema.part2.json", "status":"pending-host"}]}),
            json!({"provider":"reasoning.naming", "status":"pending-host", "packet":"lens-packets/naming.json"}),
        ];
        let dispatch = json!({"seats":[{"seat":1,"wave":1,"part":1,"bundle":"mixed",
            "tier":"judgment","providers":["reasoning.schema"],"packets":["schema.part1.json"]}],
            "deferredWork":[{"providerId":"reasoning.schema","packet":"schema.part2.json","part":2,"reason":"fresh-verification-reserve"},
                            {"providerId":"reasoning.naming","packet":"naming.json","part":1,"reason":"fresh-verification-reserve"}]});
        annotate_lens_work(&mut items, &dispatch);
        assert_eq!(items[0]["selectedParts"], 1);
        assert_eq!(items[0]["deferredParts"], 1);
        assert_eq!(items[0]["status"], "pending-host");
        assert_eq!(items[0]["parts"][0]["status"], "pending-host");
        assert_eq!(items[0]["parts"][1]["status"], "deferred-budget");
        assert_eq!(items[1]["status"], "deferred-budget");
        assert_eq!(items[1]["selectedParts"], 0);
        assert_eq!(items[1]["seats"], json!([]));
        assert_eq!(items[1]["deferredWork"].as_array().unwrap().len(), 1);
    }
}
