use crate::commands::{self, CommandResult};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::ffi::OsString;
use tokio_util::sync::CancellationToken;
#[derive(Debug, Parser)]
#[command(
    name = "legion",
    version = "0.1.0-dev.1",
    about = "evidence-governed repository audit",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Debug, Subcommand)]
enum Command {
    Init(RootArgs),
    Doctor(RootArgs),
    Bind(RootArgs),
    Inspect(RootArgs),
    Targets(RootArgs),
    Components(RootArgs),
    Stacks(RootArgs),
    Controls(RootArgs),
    Governance(CommonArgs),
    Skills(CommonArgs),
    Languages(CommonArgs),
    Providers(CommonArgs),
    Rules(CommonArgs),
    Schedule(CommonArgs),
    Plan(RootArgs),
    Audit(commands::audit::AuditArgs),
    Verify(VerifyArgs),
    Explain(CommonArgs),
    Report(ReportArgs),
    Fix(CommonArgs),
    Hooks(CommonArgs),
    Mcp(CommonArgs),
    Run(RunArgs),
    Budget(CommonArgs),
    Contract(CommonArgs),
    Assurance(CommonArgs),
    Completion(CompletionArgs),
    Host(HostCommandArgs),
    Harness(CommonArgs),
    Authority(CommonArgs),
    State(StateArgs),
    Minimize(CommonArgs),
    Catalog(commands::catalog::CatalogArgs),
    Policy(commands::policy::PolicyArgs),
    Decision(commands::decision::DecisionArgs),
    Handoff(commands::handoff::HandoffArgs),
    Research(commands::research::ResearchArgs),
    Review(commands::review::ReviewArgs),
}
#[derive(Debug, clap::Args)]
struct CommonArgs {
    #[arg(long)]
    json: bool,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<OsString>,
}
#[derive(Debug, clap::Args)]
struct RootArgs {
    #[arg(default_value = ".")]
    root: std::path::PathBuf,
    #[arg(long)]
    json: bool,
}
#[derive(Debug, clap::Args)]
struct VerifyArgs {
    #[arg(value_name = "RUN_OR_FACTS")]
    run: std::path::PathBuf,
}
#[derive(Debug, clap::Args)]
struct ReportArgs {
    #[arg(value_name = "REPORT")]
    report: std::path::PathBuf,
    #[arg(long, default_value = "json")]
    format: String,
    #[arg(long)]
    out: Option<std::path::PathBuf>,
}
macro_rules! subcommand_args {
    ($name:ident, $field:ident: $ty:ty) => {
        #[derive(Debug, clap::Args)]
        struct $name {
            #[command(subcommand)]
            $field: Option<$ty>,
        }
    };
}
subcommand_args!(RunArgs, command: RunCommand);
#[derive(Debug, Subcommand)]
enum RunCommand {
    Open(RunOpenArgs),
    Close(RunCloseArgs),
    Suspend(RunTransitionArgs),
    Supersede(RunTransitionArgs),
    Repair(RunTransitionArgs),
}
#[derive(Debug, clap::Args)]
struct RunOpenArgs {
    #[arg(long)]
    contract: String,
    #[arg(long)]
    version: u32,
    #[arg(long)]
    task: Option<String>,
    #[arg(long)]
    session: Option<String>,
    #[arg(long, default_value = "claude-code")]
    adapter: String,
    #[arg(long = "repo")]
    repo: Vec<std::path::PathBuf>,
    #[arg(long = "read-only")]
    read_only: bool,
}
#[derive(Debug, clap::Args)]
struct RunCloseArgs {
    #[arg(long)]
    session: Option<String>,
    #[arg(long, default_value = "complete")]
    disposition: String,
}
#[derive(Debug, clap::Args)]
struct RunTransitionArgs {
    #[arg(long)]
    session: Option<String>,
    #[arg(long)]
    transaction: Option<String>,
    #[arg(long)]
    contract: Option<String>,
    #[arg(long)]
    version: Option<u32>,
    #[arg(long)]
    task: Option<String>,
}
subcommand_args!(CompletionArgs, command: CompletionCommand);
#[derive(Debug, Subcommand)]
enum CompletionCommand {
    Claim(CompletionFileArgs),
    Evidence(CompletionFileArgs),
}
#[derive(Debug, clap::Args)]
struct CompletionFileArgs {
    #[arg(long)]
    file: std::path::PathBuf,
    #[arg(long)]
    session: Option<String>,
    #[arg(long = "key-dir")]
    key_dir: Option<std::path::PathBuf>,
}
subcommand_args!(HostCommandArgs, command: HostCommand);
#[derive(Debug, Subcommand)]
enum HostCommand {
    Events(HostEventsArgs),
    Describe(commands::host::HostArgs),
}
subcommand_args!(HostEventsArgs, command: HostEventsCommand);
#[derive(Debug, Subcommand)]
enum HostEventsCommand {
    Inspect(HostInspectArgs),
}
#[derive(Debug, clap::Args)]
struct HostInspectArgs {
    #[arg(long)]
    session: Option<String>,
    #[arg(long = "key-dir")]
    key_dir: Option<std::path::PathBuf>,
}
subcommand_args!(StateArgs, command: StateCommand);
#[derive(Debug, Subcommand)]
enum StateCommand {
    Snapshot(StateSnapshotArgs),
    Verify(StateVerifyArgs),
}
#[derive(Debug, clap::Args)]
struct StateSnapshotArgs {
    #[arg(long = "path", required = true)]
    paths: Vec<std::path::PathBuf>,
    #[arg(long)]
    out: std::path::PathBuf,
}
#[derive(Debug, clap::Args)]
struct StateVerifyArgs {
    #[arg(long)]
    snapshot: std::path::PathBuf,
}
struct DoctorSummary {
    repository_id: String,
    inventory_digest: String,
    catalog_entries: usize,
    provider_count: usize,
}
pub async fn run<I>(args: I) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    run_with_cancellation(args, CancellationToken::new()).await
}
pub async fn run_with_cancellation<I>(args: I, cancellation: CancellationToken) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    if args.iter().any(|arg| arg == "--version") {
        println!("0.1.0-dev.1");
        return 0;
    }
    match Cli::try_parse_from(std::iter::once(OsString::from("legion")).chain(args.clone())) {
        Ok(cli) => {
            let result = tokio::select! {
                _ = cancellation.cancelled() => Err(commands::CommandError::cancelled()),
                result = dispatch(cli, cancellation.clone()) => result,
            };
            finish(result)
        }
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            println!("{}", Cli::command().render_help());
            0
        }
        Err(error) => {
            eprintln!("{error}");
            4
        }
    }
}
async fn dispatch(cli: Cli, cancellation: CancellationToken) -> commands::CommandResult {
    let root_json = cli.json;
    let Some(command) = cli.command else {
        return Err(commands::CommandError::usage(
            Cli::command().render_help().to_string(),
        ));
    };
    if cancellation.is_cancelled() {
        return Err(commands::CommandError::cancelled());
    }
    macro_rules! root_projection {
        ($kind:literal, $args:expr) => {
            native_root_projection($kind, $args, cancellation.clone()).await
        };
    }
    macro_rules! common_projection {
        ($kind:literal, $args:expr) => {
            native_common_projection($kind, $args, cancellation.clone()).await
        };
    }
    let result: CommandResult = match command {
        Command::Catalog(args) => commands::catalog::run(args),
        Command::Policy(args) => commands::policy::run(args),
        Command::Audit(args) => commands::audit::run(args, cancellation.clone()).await,
        Command::Host(args) => native_host(args, cancellation.clone()).await,
        Command::Decision(args) => commands::decision::run(args),
        Command::Handoff(args) => commands::handoff::run(args),
        Command::Research(args) => commands::research::run(args, cancellation.clone()),
        Command::Review(args) => commands::review::run(args, cancellation.clone()),
        Command::Providers(args) => Ok(
            json!({"schemaVersion":1,"kind":"legion-providers","providers": providers(), "selected": !(args.json || root_json), "arguments": args.args, "json": args.json || root_json, "text": providers_text()}),
        ),
        Command::Languages(args) => Ok(
            json!({"schemaVersion":1,"kind":"legion-languages","languages": languages(), "json": args.json || root_json, "arguments": args.args, "text": languages_text()}),
        ),
        Command::Doctor(args) => native_doctor(args, cancellation.clone()).await,
        Command::Init(args) => root_projection!("init", args),
        Command::Bind(args) => root_projection!("bind", args),
        Command::Inspect(args) => root_projection!("inspect", args),
        Command::Targets(args) => root_projection!("targets", args),
        Command::Components(args) => root_projection!("components", args),
        Command::Stacks(args) => root_projection!("stacks", args),
        Command::Controls(args) => root_projection!("controls", args),
        Command::Plan(args) => native_plan(args, cancellation.clone()).await,
        Command::Verify(args) => native_verify(args, cancellation.clone()).await,
        Command::Explain(args) => common_projection!("explain", args),
        Command::Report(args) => native_report(args, cancellation.clone()).await,
        Command::Fix(args) => common_projection!("fix", args),
        Command::Hooks(args) => common_projection!("hooks", args),
        Command::Mcp(args) => common_projection!("mcp", args),
        Command::Run(args) => native_run(args, cancellation.clone()).await,
        Command::Budget(args) => common_projection!("budget", args),
        Command::Contract(args) => common_projection!("contract", args),
        Command::Governance(args) => common_projection!("governance", args),
        Command::Skills(args) => common_projection!("skills", args),
        Command::Rules(args) => common_projection!("rules", args),
        Command::Schedule(args) => common_projection!("schedule", args),
        Command::Assurance(args) => common_projection!("assurance", args),
        Command::Completion(args) => native_completion(args, cancellation.clone()).await,
        Command::Harness(args) => common_projection!("harness", args),
        Command::Authority(args) => common_projection!("authority", args),
        Command::State(args) => native_state(args, cancellation.clone()).await,
        Command::Minimize(args) => common_projection!("minimize", args),
    };
    result
}
fn finish(result: CommandResult) -> i32 {
    match result {
        Ok(value) => {
            if let Some(raw) = value.get("__raw").and_then(Value::as_str) {
                print!("{raw}");
                return 0;
            }
            if value.get("__silent").and_then(Value::as_bool) == Some(true) {
                return 0;
            }
            if value.get("json").and_then(Value::as_bool) == Some(false) {
                if let Some(lines) = value.get("text").and_then(Value::as_array) {
                    for line in lines.iter().filter_map(Value::as_str) {
                        println!("{line}");
                    }
                    return 0;
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
            );
            if value
                .get("integrity")
                .and_then(Value::as_object)
                .and_then(|integrity| integrity.get("valid"))
                .and_then(Value::as_bool)
                == Some(false)
            {
                return 5;
            }
            if value.get("valid").and_then(Value::as_bool) == Some(false)
                || value.get("decision").and_then(Value::as_str) == Some("deny")
            {
                return 1;
            }
            match value
                .get("auditStatus")
                .or_else(|| value.get("status"))
                .and_then(Value::as_str)
            {
                Some("incomplete") | Some("unproven") | Some("partial") | Some("failed")
                | Some("cancelled") | Some("unavailable") => 2,
                Some("fail") | Some("denied") => 1,
                _ => 0,
            }
        }
        Err(error) => {
            eprintln!("{}", error.message);
            error.code
        }
    }
}
async fn native_root_projection(
    kind: &str,
    args: RootArgs,
    cancellation: CancellationToken,
) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(commands::io_error)?;
    let summary = invoke_doctor(&root, cancellation, "repository projection").await?;
    Ok(render_doctor(
        kind,
        summary,
        json!({"root": root}),
        None,
        Some(args.json),
        false,
    ))
}
async fn native_common_projection(
    kind: &str,
    args: CommonArgs,
    cancellation: CancellationToken,
) -> CommandResult {
    let root = common_root(&args.args);
    let summary = invoke_doctor(&root, cancellation, "command projection").await?;
    Ok(render_doctor(
        kind,
        summary,
        Value::String(root.to_string_lossy().into_owned()),
        Some(args.args.iter().map(|arg| arg.to_string_lossy()).collect()),
        Some(args.json),
        false,
    ))
}
fn common_root(args: &[OsString]) -> std::path::PathBuf {
    let mut candidate = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--root" {
            candidate = iter.next().cloned();
            break;
        }
        if !arg.to_string_lossy().starts_with('-') && candidate.is_none() {
            candidate = Some(arg.clone());
        }
    }
    let path = candidate
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    if path.is_dir() {
        std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from("."))
    } else {
        std::fs::canonicalize(".").unwrap_or_else(|_| std::path::PathBuf::from("."))
    }
}
async fn native_doctor(args: RootArgs, cancellation: CancellationToken) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(commands::io_error)?;
    let summary = invoke_doctor(&root, cancellation, "doctor").await?;
    Ok(render_doctor(
        "doctor",
        summary,
        json!({"root": root}),
        None,
        None,
        true,
    ))
}
fn render_doctor(
    kind: &str,
    summary: DoctorSummary,
    repository: Value,
    arguments: Option<Vec<String>>,
    json_flag: Option<bool>,
    clean_claim: bool,
) -> Value {
    let mut output = json!({
        "schemaVersion": 1, "kind": format!("legion-{kind}"), "status": "complete",
        "repository": repository, "inventoryDigest": summary.inventory_digest,
        "catalogEntries": summary.catalog_entries, "providerCount": summary.provider_count,
    });
    if let Some(arguments) = arguments {
        output["arguments"] = json!(arguments);
    }
    if let Some(json_flag) = json_flag {
        output["json"] = json!(json_flag);
    }
    if clean_claim {
        output["cleanClaimPossible"] = Value::Bool(true);
    }
    output
}
async fn invoke_doctor(
    root: &std::path::Path,
    cancellation: CancellationToken,
    context: &str,
) -> Result<DoctorSummary, commands::CommandError> {
    let repository_id = root.to_string_lossy().into_owned();
    let application = commands::native_application_for(&repository_id)?;
    match application
        .invoke_with_cancellation(
            legion_application::NativeOperation::Doctor {
                repository_id: repository_id.clone(),
            },
            cancellation,
        )
        .await
        .map_err(|error| commands::CommandError::incomplete(error.to_string()))?
    {
        legion_application::NativeOperationResult::Doctor {
            repository_id,
            inventory_digest,
            catalog_entries,
            provider_count,
        } => Ok(DoctorSummary {
            repository_id,
            inventory_digest,
            catalog_entries,
            provider_count,
        }),
        _ => Err(commands::CommandError::internal(format!(
            "native {context} returned an incompatible result"
        ))),
    }
}
async fn native_plan(args: RootArgs, cancellation: CancellationToken) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(commands::io_error)?;
    let application = commands::native_application_for(&root.to_string_lossy())?;
    match application
        .invoke_with_cancellation(
            legion_application::NativeOperation::Plan {
                repository_id: root.to_string_lossy().into_owned(),
                providers: application.provider_specs(),
                signing_key: None,
            },
            cancellation,
        )
        .await
        .map_err(|error| commands::CommandError::incomplete(error.to_string()))?
    {
        legion_application::NativeOperationResult::Plan {
            repository_id,
            plan_digest,
            providers,
        } => Ok(
            json!({"schemaVersion": 1, "kind": "audit-provider-plan", "repository": repository_id, "seal": {"digest": plan_digest}, "providers": providers, "status": "complete"}),
        ),
        _ => Err(commands::CommandError::internal(
            "native plan returned an incompatible result",
        )),
    }
}
async fn native_verify(args: VerifyArgs, cancellation: CancellationToken) -> CommandResult {
    let supplied = std::fs::canonicalize(&args.run).map_err(commands::io_error)?;
    let (root, facts_path, plan_path) = if supplied.is_dir() {
        (
            supplied.clone(),
            supplied.join("facts.json"),
            supplied.join("plan.json"),
        )
    } else {
        let plan = supplied.with_file_name("plan.json");
        (
            supplied
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .to_path_buf(),
            supplied.clone(),
            plan,
        )
    };
    if !facts_path.is_file() {
        return Err(commands::CommandError::usage(format!(
            "verify facts artifact missing: {}",
            facts_path.display()
        )));
    }
    let facts_bytes = std::fs::read(&facts_path).map_err(commands::io_error)?;
    let facts: Value = serde_json::from_slice(&facts_bytes).map_err(|error| {
        commands::CommandError::usage(format!("invalid verify facts artifact: {error}"))
    })?;
    if !facts.is_object() {
        return Err(commands::CommandError::usage(
            "verify facts artifact must contain a JSON object",
        ));
    }
    let plan = if plan_path.is_file() {
        let bytes = std::fs::read(&plan_path).map_err(commands::io_error)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
            commands::CommandError::usage(format!("invalid verify plan artifact: {error}"))
        })?;
        if !value.is_object() {
            return Err(commands::CommandError::usage(
                "verify plan artifact must contain a JSON object",
            ));
        }
        value
    } else if supplied.is_dir() {
        let Some(value) = facts.get("plan") else {
            return Err(commands::CommandError::usage(format!(
                "verify plan artifact missing: {}",
                plan_path.display()
            )));
        };
        if !value.is_object() {
            return Err(commands::CommandError::usage(
                "verify embedded plan must contain a JSON object",
            ));
        }
        value.clone()
    } else {
        return Err(commands::CommandError::usage(format!(
            "verify plan artifact missing: {}",
            plan_path.display()
        )));
    };
    let facts_digest = legion_contracts::canonical_digest_hex(&facts)
        .map_err(|error| commands::CommandError::integrity(error.to_string()))?;
    let plan_content_digest = legion_contracts::canonical_digest_hex(&plan)
        .map_err(|error| commands::CommandError::integrity(error.to_string()))?;
    let mut content_errors = verify_document_errors(&facts, &plan);
    let repository = facts
        .get("workspace")
        .and_then(Value::as_str)
        .or_else(|| plan.get("root").and_then(Value::as_str))
        .map(str::to_owned)
        .unwrap_or_else(|| root.to_string_lossy().into_owned());
    let application = commands::native_application_for(&repository)?;
    if let Some(declared) = plan.get("providers") {
        let Some(declared) = declared.as_array() else {
            content_errors.push("plan.providers must be an array".into());
            return Ok(
                json!({"schemaVersion": 1, "kind": "legion-verify", "status": "failed", "repository": repository, "factsDigest": facts_digest, "planContentDigest": plan_content_digest, "facts": facts, "plan": plan, "valid": false, "contentErrors": content_errors}),
            );
        };
        let configured = application
            .provider_specs()
            .into_iter()
            .map(|provider| provider.id.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        for provider in declared {
            let Some(provider_id) = provider.as_str() else {
                content_errors.push("plan.providers entries must be provider IDs".into());
                continue;
            };
            if !configured.contains(provider_id) {
                content_errors.push(format!(
                    "plan.providers references unconfigured provider {provider_id}"
                ));
            }
        }
    }
    match application
        .invoke_with_cancellation(
            legion_application::NativeOperation::VerifyRequest {
                repository_id: repository.clone(),
                providers: application.provider_specs(),
                signing_key: None,
                facts: facts.clone(),
                plan: plan.clone(),
            },
            cancellation,
        )
        .await
        .map_err(|error| commands::CommandError::incomplete(error.to_string()))?
    {
        legion_application::NativeOperationResult::Verification {
            repository_id,
            plan_digest,
            inventory_digest,
        } => Ok(
            json!({"schemaVersion": 1, "kind": "legion-verify", "status": if content_errors.is_empty() { "complete" } else { "failed" }, "repository": repository_id, "planDigest": plan_digest, "inventoryDigest": inventory_digest, "factsDigest": facts_digest, "planContentDigest": plan_content_digest, "verificationInputDigest": legion_contracts::canonical_digest_hex(&json!({"facts": facts, "plan": plan})).map_err(|error| commands::CommandError::integrity(error.to_string()))?, "facts": facts, "plan": plan, "valid": content_errors.is_empty(), "contentErrors": content_errors}),
        ),
        _ => Err(commands::CommandError::internal(
            "native verify returned an incompatible result",
        )),
    }
}
fn verify_document_errors(facts: &Value, plan: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(kind) = facts.get("kind").and_then(Value::as_str) {
        if kind != "audit-facts" {
            errors.push(format!("facts.kind must be audit-facts, got {kind}"));
        }
    }
    if let Some(checks) = facts.get("checks") {
        if !checks.is_array() {
            errors.push("facts.checks must be an array".into());
        } else if checks.as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item.get("check").and_then(Value::as_str).is_none()
                    || item.get("status").and_then(Value::as_str).is_none()
            })
        }) {
            errors.push("facts.checks entries require check and status".into());
        }
    }
    if let Some(reconciliation) = facts.get("provider_reconciliation") {
        if !reconciliation.is_object() {
            errors.push("facts.provider_reconciliation must be an object".into());
        } else if let Some(results) = reconciliation.get("providerResults") {
            if !results.is_array() {
                errors
                    .push("facts.provider_reconciliation.providerResults must be an array".into());
            }
        }
    }
    if let Some(schema) = plan.get("schemaVersion") {
        if schema.as_u64() != Some(1) {
            errors.push("plan.schemaVersion must be 1".into());
        }
    }
    if let Some(kind) = plan.get("kind").and_then(Value::as_str) {
        if kind != "audit-provider-plan" {
            errors.push(format!("plan.kind must be audit-provider-plan, got {kind}"));
        }
    }
    if let Some(seal) = plan.get("seal") {
        match seal.get("digest").and_then(Value::as_str) {
            Some(digest) if digest.starts_with("sha256:") => {}
            Some(_) => errors.push("plan.seal.digest must use sha256 form".into()),
            None => errors.push("plan.seal.digest is required".into()),
        }
    }
    if let Some(binding) = plan.get("binding") {
        if binding
            .get("repositoryRevision")
            .and_then(Value::as_str)
            .is_none()
        {
            errors.push("plan.binding.repositoryRevision is required".into());
        }
    }
    if let (Some(facts_seal), Some(plan_seal)) = (
        facts.get("plan").and_then(|value| value.get("seal")),
        plan.get("seal"),
    ) {
        if facts_seal.get("digest") != plan_seal.get("digest") {
            errors.push("facts.plan.seal.digest differs from plan.seal.digest".into());
        }
    }
    if let (Some(facts_binding), Some(plan_binding)) = (
        facts.get("plan").and_then(|value| value.get("binding")),
        plan.get("binding"),
    ) {
        if facts_binding.get("repositoryRevision") != plan_binding.get("repositoryRevision") {
            errors.push("facts.plan.binding.repositoryRevision differs from plan.binding.repositoryRevision".into());
        }
    }
    errors
}
async fn native_report(args: ReportArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(commands::CommandError::cancelled());
    }
    let bytes = std::fs::read(&args.report).map_err(commands::io_error)?;
    let report: legion_contracts::ReportV1 = serde_json::from_slice(&bytes)
        .map_err(|error| commands::CommandError::usage(format!("invalid report: {error}")))?;
    report
        .validate()
        .map_err(|error| commands::CommandError::policy(error.to_string()))?;
    let format = match args.format.as_str() {
        "json" => legion_application::ReportFormat::Json,
        "sarif" => legion_application::ReportFormat::Sarif,
        "markdown" | "md" => legion_application::ReportFormat::Markdown,
        "html" => legion_application::ReportFormat::Html,
        _ => {
            return Err(commands::CommandError::usage(format!(
                "unsupported report format: {}",
                args.format
            )))
        }
    };
    let rendered = match format {
        legion_application::ReportFormat::Json => legion_report::render_json(&report),
        legion_application::ReportFormat::Sarif => legion_report::render_sarif(&report),
        legion_application::ReportFormat::Markdown => legion_report::render_markdown(&report),
        legion_application::ReportFormat::Html => legion_report::render_html(&report),
    }
    .map_err(commands::io_error)?;
    if let Some(ref out) = args.out {
        std::fs::write(out, rendered.as_bytes()).map_err(commands::io_error)?;
    }
    if cancellation.is_cancelled() {
        return Err(commands::CommandError::cancelled());
    }
    if args.out.is_some() {
        Ok(
            json!({"schemaVersion": 1, "kind": "legion-report", "format": args.format, "path": args.report, "out": args.out, "status": "complete", "__silent": true}),
        )
    } else {
        Ok(json!({"__raw": rendered}))
    }
}
async fn native_host(args: HostCommandArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(commands::CommandError::cancelled());
    }
    match args.command {
        Some(HostCommand::Describe(args)) => commands::host::run(args),
        Some(HostCommand::Events(events)) => match events.command {
            Some(HostEventsCommand::Inspect(args)) => {
                let repository = std::fs::canonicalize(".").map_err(commands::io_error)?;
                let summary =
                    invoke_doctor(&repository, cancellation, "host event inspection").await?;
                let (records, ledger_valid, ledger_errors) =
                    host_event_records(args.session.as_deref(), args.key_dir.as_deref())?;
                Ok(
                    json!({"schemaVersion": 1, "kind": "legion-host-events", "status": if ledger_valid { "complete" } else { "failed" }, "allowed": ledger_valid, "valid": ledger_valid, "session": args.session, "keyDir": args.key_dir, "records": records, "errors": ledger_errors, "application": {"inventoryDigest": summary.inventory_digest, "catalogEntries": summary.catalog_entries, "providerCount": summary.provider_count}}),
                )
            }
            None => Err(commands::CommandError::usage(
                "host events requires inspect [--session <id>]",
            )),
        },
        None => Err(commands::CommandError::usage(
            "host requires events inspect or describe",
        )),
    }
}
fn host_event_records(
    session: Option<&str>,
    key_dir: Option<&std::path::Path>,
) -> Result<(Vec<Value>, bool, Vec<String>), commands::CommandError> {
    let root = std::path::Path::new(".audit/arcane/host-events");
    if !root.is_dir() {
        return Ok((Vec::new(), true, Vec::new()));
    }
    let mut records = Vec::new();
    let mut paths = std::fs::read_dir(root)
        .map_err(commands::io_error)?
        .filter_map(|entry| entry.ok().map(|item| item.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.ends_with(".json")
                        && name.chars().count() == 20
                        && name.chars().take(16).all(|c| c.is_ascii_digit())
                })
        })
        .collect::<Vec<_>>();
    paths.sort();
    let key_root = key_dir
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("ARCANE_KEY_DIR").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from(".audit/arcane/keys"));
    let mut errors = Vec::new();
    let mut previous: Option<Value> = None;
    for path in paths {
        let bytes = std::fs::read(&path).map_err(commands::io_error)?;
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{}: invalid JSON: {error}", path.display()));
                continue;
            }
        };
        if value.get("schemaVersion").and_then(Value::as_u64) != Some(1)
            || value.get("kind").and_then(Value::as_str) != Some("arcane-host-event-ledger-record")
        {
            errors.push(format!("{}: invalid event schema", path.display()));
        }
        let expected_sequence = previous
            .as_ref()
            .and_then(|record| record.get("eventSequence").and_then(Value::as_u64))
            .unwrap_or(0)
            + 1;
        if value.get("eventSequence").and_then(Value::as_u64) != Some(expected_sequence) {
            errors.push(format!(
                "{}: event sequence is not contiguous",
                path.display()
            ));
        }
        let expected_parent = previous
            .as_ref()
            .map(|record| legion_contracts::canonical_digest(record))
            .transpose()
            .map_err(|error| commands::CommandError::integrity(error.to_string()))?;
        if value.get("previousDigest").and_then(Value::as_str) != expected_parent.as_deref() {
            errors.push(format!(
                "{}: previous digest does not match ledger head",
                path.display()
            ));
        }
        if let Err(error) = verify_host_event_auth(&value, &key_root, HOST_EVENT_AUTH_FIELDS) {
            errors.push(format!("{}: {error}", path.display()));
        }
        if session.is_none() || value.get("sessionId").and_then(Value::as_str) == session {
            let mut projected = value.clone();
            if let Some(object) = projected.as_object_mut() {
                if let Some(auth) = object
                    .get_mut("authentication")
                    .and_then(Value::as_object_mut)
                {
                    let key_id = auth.get("keyId").cloned().unwrap_or(Value::Null);
                    let alg = auth.get("alg").cloned().unwrap_or(Value::Null);
                    *auth =
                        serde_json::Map::from_iter([("keyId".into(), key_id), ("alg".into(), alg)]);
                }
            }
            records.push(projected);
        }
        previous = Some(value);
    }
    let head = root.join("head.json");
    if previous.is_some() && !head.is_file() {
        errors.push("host event ledger head is missing".into());
    } else if previous.is_none() && head.is_file() {
        errors.push("host event ledger head is unanchored".into());
    }
    if let Some(previous) = previous {
        if let Ok(bytes) = std::fs::read(&head) {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => {
                    let digest = legion_contracts::canonical_digest(&previous)
                        .map_err(|error| commands::CommandError::integrity(error.to_string()))?;
                    if let Err(error) =
                        verify_host_event_auth(&value, &key_root, HOST_HEAD_AUTH_FIELDS)
                    {
                        errors.push(format!(
                            "host event ledger head authentication is invalid: {error}"
                        ));
                    }
                    if value.get("eventSequence") != previous.get("eventSequence")
                        || value.get("digest").and_then(Value::as_str) != Some(digest.as_str())
                    {
                        errors.push("host event ledger head does not anchor final event".into());
                    }
                }
                Err(_) => errors.push("host event ledger head is invalid JSON".into()),
            }
        }
    }
    Ok((records, errors.is_empty(), errors))
}
const HOST_EVENT_AUTH_FIELDS: &[&str] = &[
    "schemaVersion",
    "kind",
    "eventId",
    "eventSequence",
    "previousDigest",
    "turnCorrelationDigest",
    "stopOrdinal",
    "adapter",
    "eventType",
    "sessionId",
    "runId",
    "taskId",
    "contractId",
    "contractVersion",
    "contractDigest",
    "sourceRevision",
    "observedAuthority",
    "payloadDigest",
    "observedAt",
];
const HOST_HEAD_AUTH_FIELDS: &[&str] = &["kind", "eventSequence", "digest"];
fn verify_host_event_auth(
    record: &Value,
    key_root: &std::path::Path,
    fields: &[&str],
) -> Result<(), String> {
    let authentication = record
        .get("authentication")
        .and_then(Value::as_object)
        .ok_or_else(|| "authentication block is missing".to_owned())?;
    if authentication.get("alg").and_then(Value::as_str) != Some("HMAC-SHA256") {
        return Err("authentication algorithm is not HMAC-SHA256".into());
    }
    let key_id = authentication
        .get("keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| "authentication keyId is missing".to_owned())?;
    let mac = authentication
        .get("mac")
        .and_then(Value::as_str)
        .ok_or_else(|| "authentication mac is missing".to_owned())?;
    let bound_digest = authentication
        .get("boundFieldsDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| "authentication boundFieldsDigest is missing".to_owned())?;
    let expected_bound_digest = legion_contracts::canonical_digest(&fields.to_vec())
        .map_err(|error| format!("bound field digest failed: {error}"))?;
    if bound_digest != expected_bound_digest {
        return Err("authentication boundFieldsDigest does not match".into());
    }
    let key_path = key_root.join(format!("{key_id}.key"));
    let key_text = std::fs::read_to_string(&key_path)
        .map_err(|_| format!("verification key {key_id} is unavailable"))?;
    let key = decode_hex(key_text.trim())
        .ok_or_else(|| format!("verification key {key_id} is not hex key material"))?;
    if key.is_empty() {
        return Err(format!("verification key {key_id} is empty"));
    }
    let mut subject = serde_json::Map::new();
    for field in fields {
        let value = record
            .get(*field)
            .ok_or_else(|| format!("bound field {field} is missing"))?;
        subject.insert((*field).to_owned(), value.clone());
    }
    let message = json!({
        "alg": "HMAC-SHA256",
        "boundFields": fields,
        "subject": subject,
    });
    let message = legion_contracts::canonical_json_bytes(&message)
        .map_err(|error| format!("authentication canonicalization failed: {error}"))?;
    let expected_mac =
        decode_hex(mac).ok_or_else(|| "authentication mac is not lowercase hex".to_owned())?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| "authentication key material is invalid".to_owned())?;
    verifier.update(&message);
    verifier
        .verify_slice(&expected_mac)
        .map_err(|_| "authentication HMAC does not match".to_owned())
}
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        output.push((high << 4) | low);
    }
    Some(output)
}
async fn native_run(args: RunArgs, cancellation: CancellationToken) -> CommandResult {
    let (subcommand, request) = match args.command {
        Some(RunCommand::Open(open)) => {
            if open.contract.trim().is_empty() || open.version == 0 {
                return Err(commands::CommandError::usage(
                    "run open requires --contract and positive --version",
                ));
            }
            (
                "open",
                json!({
                    "contract": open.contract,
                    "version": open.version,
                    "task": open.task,
                    "session": open.session,
                    "adapter": open.adapter,
                    "repositories": open.repo,
                    "readOnly": open.read_only,
                }),
            )
        }
        Some(RunCommand::Close(close)) => {
            if close.disposition.trim().is_empty() {
                return Err(commands::CommandError::usage(
                    "run close requires a non-empty --disposition",
                ));
            }
            (
                "close",
                json!({
                    "session": close.session,
                    "disposition": close.disposition,
                }),
            )
        }
        Some(RunCommand::Suspend(transition)) => {
            ("suspend", transition_request("suspend", transition)?)
        }
        Some(RunCommand::Supersede(transition)) => {
            ("supersede", transition_request("supersede", transition)?)
        }
        Some(RunCommand::Repair(transition)) => {
            ("repair", transition_request("repair", transition)?)
        }
        None => {
            return Err(commands::CommandError::usage(
                "run requires open|close|suspend|supersede|repair",
            ))
        }
    };
    let root = std::fs::canonicalize(".").map_err(commands::io_error)?;
    let application = commands::native_application_for(&root.to_string_lossy())?;
    let request_digest = legion_contracts::canonical_digest_hex(&request)
        .map_err(|error| commands::CommandError::integrity(error.to_string()))?;
    match application
        .invoke_with_cancellation(
            legion_application::NativeOperation::RunRequest {
                request: request.clone(),
            },
            cancellation,
        )
        .await
    {
        Ok(legion_application::NativeOperationResult::Invocation(outcome)) => Ok(json!({
            "schemaVersion": 1,
            "kind": "legion-run",
            "subcommand": subcommand,
            "request": request,
            "requestDigest": request_digest,
            "status": if outcome.adjudication.complete { "complete" } else { "incomplete" },
            "gaps": outcome.adjudication.gaps
        })),
        Ok(_) => Err(commands::CommandError::internal(
            "native run returned an incompatible result",
        )),
        Err(error) => Err(commands::CommandError::incomplete(format!(
            "native run {subcommand} failed: {error}"
        ))),
    }
}
fn transition_request(
    kind: &str,
    transition: RunTransitionArgs,
) -> Result<Value, commands::CommandError> {
    if transition.transaction.is_none() {
        return Err(commands::CommandError::usage(format!(
            "run {kind} requires --transaction <id>"
        )));
    }
    if kind == "supersede" && (transition.contract.is_none() || transition.version.is_none()) {
        return Err(commands::CommandError::usage(
            "run supersede requires --transaction, --contract, and --version",
        ));
    }
    Ok(json!({
        "session": transition.session, "transaction": transition.transaction,
        "contract": transition.contract, "version": transition.version, "task": transition.task,
    }))
}
async fn native_completion(args: CompletionArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(commands::CommandError::cancelled());
    }
    let (subcommand, file, session, key_dir) = match args.command {
        Some(CompletionCommand::Claim(args)) => ("claim", args.file, args.session, args.key_dir),
        Some(CompletionCommand::Evidence(args)) => {
            ("evidence", args.file, args.session, args.key_dir)
        }
        None => {
            return Err(commands::CommandError::usage(
                "completion requires claim|evidence --file <outcome.json> [--session <id>]",
            ))
        }
    };
    let bytes = std::fs::read(&file).map_err(commands::io_error)?;
    let outcome: Value = serde_json::from_slice(&bytes).map_err(|error| {
        commands::CommandError::usage(format!("invalid completion artifact: {error}"))
    })?;
    if !outcome.is_object() {
        return Err(commands::CommandError::usage(
            "completion artifact must contain a JSON object",
        ));
    }
    let Some(session_id) = session.as_deref().filter(|value| !value.is_empty()) else {
        return Err(commands::CommandError::usage(
            "completion requires --session <id> for authenticated binding",
        ));
    };
    let key_root = key_dir
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("ARCANE_KEY_DIR").map(std::path::PathBuf::from))
        .ok_or_else(|| {
            commands::CommandError::incomplete(
                "completion requires an authenticated host key directory",
            )
        })?;
    if !key_root.is_dir()
        || !std::fs::read_dir(&key_root)
            .map_err(commands::io_error)?
            .any(|entry| {
                entry.ok().is_some_and(|item| {
                    item.path().extension().and_then(|ext| ext.to_str()) == Some("key")
                })
            })
    {
        return Err(commands::CommandError::incomplete(
            "completion host key directory contains no key material",
        ));
    }
    let binding_path = std::path::Path::new(".audit/arcane/session-bindings").join(format!(
        "{}.json",
        legion_contracts::derived_id_string(session_id.as_bytes())
    ));
    let binding_bytes = std::fs::read(&binding_path).map_err(|_| {
        commands::CommandError::incomplete("completion requires an authenticated session binding")
    })?;
    let binding: Value = serde_json::from_slice(&binding_bytes).map_err(|error| {
        commands::CommandError::incomplete(format!("invalid session binding: {error}"))
    })?;
    let binding_object = binding.as_object().ok_or_else(|| {
        commands::CommandError::incomplete("session binding must be a JSON object")
    })?;
    for field in ["runId", "taskId", "contractId", "contractDigest"] {
        if binding_object.get(field).and_then(Value::as_str).is_none() {
            return Err(commands::CommandError::incomplete(format!(
                "completion session binding lacks {field}"
            )));
        }
    }
    if binding_object
        .get("contractVersion")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(commands::CommandError::incomplete(
            "completion session binding lacks contractVersion",
        ));
    }
    let (events, ledger_valid, ledger_errors) =
        host_event_records(Some(session_id), Some(&key_root))?;
    if !ledger_valid {
        return Err(commands::CommandError::incomplete(format!(
            "completion host event ledger failed verification: {}",
            ledger_errors.join("; ")
        )));
    }
    let required_authority = if subcommand == "claim" {
        ["legion", "alchemist"].as_slice()
    } else {
        ["oracle"].as_slice()
    };
    let authority_event = events.iter().rev().find(|event| {
        required_authority.iter().any(|authority| {
            event.get("observedAuthority").and_then(Value::as_str) == Some(*authority)
        })
    });
    let Some(authority_event) = authority_event else {
        return Err(commands::CommandError::incomplete(
            "completion requires a current authenticated authority event",
        ));
    };
    for field in ["runId", "taskId", "contractId"] {
        if authority_event.get(field) != binding_object.get(field) {
            return Err(commands::CommandError::incomplete(format!(
                "completion authority event does not bind to session {field}"
            )));
        }
    }
    if subcommand == "claim"
        && (outcome.get("outcomeSummary").is_none() || outcome.get("artifactState").is_none())
    {
        return Err(commands::CommandError::usage(
            "completion claim artifact requires outcomeSummary and artifactState",
        ));
    }
    if subcommand == "evidence" && outcome.get("evidence").and_then(Value::as_object).is_none() {
        return Err(commands::CommandError::usage(
            "completion evidence artifact requires evidence object",
        ));
    }
    let root = std::fs::canonicalize(".").map_err(commands::io_error)?;
    let summary = invoke_doctor(&root, cancellation, "completion").await?;
    Ok(
        json!({"schemaVersion": 1, "kind": "legion-completion", "subcommand": subcommand, "file": file, "session": session, "keyDir": key_dir, "status": "complete", "valid": true, "binding": binding, "authority": authority_event.get("observedAuthority"), "outcomeDigest": legion_contracts::canonical_digest_hex(&outcome).map_err(|error| commands::CommandError::integrity(error.to_string()))?, "application": {"inventoryDigest": summary.inventory_digest, "catalogEntries": summary.catalog_entries, "providerCount": summary.provider_count}}),
    )
}
async fn native_state(args: StateArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(commands::CommandError::cancelled());
    }
    let repository = std::fs::canonicalize(".").map_err(commands::io_error)?;
    let application = commands::native_application_for(&repository.to_string_lossy())?;
    let application_result = application
        .invoke_with_cancellation(legion_application::NativeOperation::Catalog, cancellation)
        .await
        .map_err(|error| commands::CommandError::incomplete(error.to_string()))?;
    let application_summary = match application_result {
        legion_application::NativeOperationResult::Catalog(catalog) => json!({
            "catalogEntries": catalog.entries.len(),
            "catalogDigest": legion_contracts::canonical_digest_hex(&catalog)
                .map_err(|error| commands::CommandError::integrity(error.to_string()))?,
        }),
        _ => {
            return Err(commands::CommandError::internal(
                "native state returned an incompatible application result",
            ))
        }
    };
    match args.command {
        Some(StateCommand::Snapshot(snapshot)) => {
            native_state_snapshot(snapshot, application_summary)
        }
        Some(StateCommand::Verify(verify)) => native_state_verify(verify, application_summary),
        None => Err(commands::CommandError::usage(
            "state requires snapshot|verify",
        )),
    }
}
fn native_state_snapshot(args: StateSnapshotArgs, application: Value) -> CommandResult {
    let mut surfaces = serde_json::Map::new();
    let mut file_count = 0usize;
    for path in &args.paths {
        let root = std::fs::canonicalize(path).map_err(commands::io_error)?;
        let mut entries = serde_json::Map::new();
        collect_state_entries(&root, &root, &mut entries)?;
        file_count += entries.len();
        surfaces.insert(root.to_string_lossy().into_owned(), Value::Object(entries));
    }
    let snapshot = json!({"schema": "legion-state-snapshot.v1", "surfaces": surfaces});
    let bytes = serde_json::to_vec_pretty(&snapshot).map_err(commands::io_error)?;
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(commands::io_error)?;
        }
    }
    std::fs::write(&args.out, bytes).map_err(commands::io_error)?;
    Ok(
        json!({"schemaVersion": 1, "kind": "legion-state-snapshot", "surfaces": args.paths.len(), "files": file_count, "out": args.out, "status": "complete", "application": application}),
    )
}
fn collect_state_entries(
    root: &std::path::Path,
    current: &std::path::Path,
    entries: &mut serde_json::Map<String, Value>,
) -> Result<(), commands::CommandError> {
    let metadata = std::fs::metadata(current).map_err(commands::io_error)?;
    if metadata.is_file() {
        let bytes = std::fs::read(current).map_err(commands::io_error)?;
        entries.insert(
            ".".into(),
            json!({"sha256": legion_host::digest_bytes(&bytes), "size": bytes.len()}),
        );
        return Ok(());
    }
    let mut children = std::fs::read_dir(current)
        .map_err(commands::io_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(commands::io_error)?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(commands::io_error)?
            .to_string_lossy()
            .replace('\\', "/");
        if std::fs::metadata(&path)
            .map_err(commands::io_error)?
            .is_dir()
        {
            collect_state_entries(root, &path, entries)?;
        } else {
            let bytes = std::fs::read(&path).map_err(commands::io_error)?;
            entries.insert(
                relative,
                json!({"sha256": legion_host::digest_bytes(&bytes), "size": bytes.len()}),
            );
        }
    }
    Ok(())
}
fn native_state_verify(args: StateVerifyArgs, application: Value) -> CommandResult {
    let bytes = std::fs::read(&args.snapshot).map_err(commands::io_error)?;
    let snapshot: Value = serde_json::from_slice(&bytes).map_err(|error| {
        commands::CommandError::usage(format!("invalid state snapshot: {error}"))
    })?;
    if snapshot.get("schema").and_then(Value::as_str) != Some("legion-state-snapshot.v1") {
        return Err(commands::CommandError::usage(
            "snapshot schema must be legion-state-snapshot.v1",
        ));
    }
    let mut deltas = Vec::new();
    let Some(surfaces) = snapshot.get("surfaces").and_then(Value::as_object) else {
        return Err(commands::CommandError::usage(
            "snapshot surfaces must be a JSON object",
        ));
    };
    for (surface, before) in surfaces {
        let root = std::path::Path::new(surface);
        let mut after = serde_json::Map::new();
        if root.exists() {
            collect_state_entries(root, root, &mut after)?;
        }
        let Some(before) = before.as_object() else {
            return Err(commands::CommandError::usage(
                "snapshot surface entries must be JSON objects",
            ));
        };
        for (relative, old) in before {
            match after.get(relative) {
                None => {
                    deltas.push(json!({"surface": surface, "path": relative, "change": "deleted"}))
                }
                Some(new) if new != old => {
                    deltas.push(json!({"surface": surface, "path": relative, "change": "modified"}))
                }
                _ => {}
            }
        }
        for relative in after.keys() {
            if !before.contains_key(relative) {
                deltas.push(json!({"surface": surface, "path": relative, "change": "created"}));
            }
        }
    }
    Ok(
        json!({"schemaVersion": 1, "kind": "legion-state-verify", "snapshot": args.snapshot, "status": if deltas.is_empty() { "complete" } else { "failed" }, "valid": deltas.is_empty(), "deltas": deltas, "application": application}),
    )
}
fn providers() -> Vec<Value> {
    vec![
        json!({"id":"framework.major-suite","role":"analysis","phase":"standard","runner":null,"benchmark":null,"producesSecurityCandidates":false}),
    ]
}
fn languages() -> Vec<Value> {
    vec![
        json!({"id":"rust","kind":"language","qualification":"unproven","providers":["framework.major-suite"]}),
    ]
}
fn providers_text() -> Vec<String> {
    vec!["framework.major-suite\tanalysis\tstandard\t".into()]
}
fn languages_text() -> Vec<String> {
    vec!["rust\tunproven".into()]
}
