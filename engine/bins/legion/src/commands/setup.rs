use super::{io_error, CommandError, CommandResult};
use clap::{Args, Subcommand, ValueEnum};
use legion_effects::{PlatformProcess, ProcessLaunch, ProcessOutput};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const QUALIFICATION_SCHEMA_VERSION: u32 = 2;
const QUALIFICATION_MECHANISM: &str = "agent-plugins-bare-command";
const QUALIFICATION_TOOL: &str = "legion_m1_status";
const QUALIFICATION_SERVER: &str = "legion";
const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(180);
/// Host plugin CLIs (notably `codex plugin list`) normally answer in about a
/// second but stall for tens of seconds while the host app is busy; a stall
/// rolled back whole installs. Allow 90 s and retry a timed-out call once.
const MARKETPLACE_TIMEOUT: Duration = Duration::from_secs(90);
const MARKETPLACE_ATTEMPTS: u32 = 2;
const MARKETPLACE_REFRESH_SCHEMA_VERSION: u32 = 1;
const QUALIFICATION_MCP_ARGS: [&str; 2] = ["serve", "--stdio"];
const EXPECTED_RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");
const PLUGIN_MANIFEST_PATHS: [&str; 2] = ["plugin.json", ".claude-plugin/plugin.json"];
const CANONICAL_NATIVE_RELEASE_IDENTITY_PATH: &str = "release.json";
const PLUGIN_RELEASE_IDENTITY_PATHS: [&str; 2] = [
    "share/legion/release-binding.json",
    "share/legion/identity/release-identity.json",
];

/// `legion setup [--dry-run] [--client]` is the installed-product lifecycle
/// surface; lifecycle subcommands include `legion setup purge --confirm`.
/// Native machine setup is intentionally a small grammar over the frozen host
/// registry: previews are materialized as files, then mutations require that
/// exact preview plus an explicit confirmation flag.
#[derive(Debug, Args)]
pub struct SetupArgs {
    /// Preview the selected lifecycle action without changing durable state.
    #[arg(long)]
    dry_run: bool,
    /// Restrict setup to one supported client.
    #[arg(long)]
    client: Option<String>,
    /// Confirm the generated preview for the default setup action.
    #[arg(long)]
    confirm: bool,
    /// Verify installed host projections without changing durable state.
    #[arg(long)]
    check: bool,
    #[command(subcommand)]
    command: Option<SetupCommand>,
    #[command(flatten)]
    context: SetupExecutionArgs,
}

#[derive(Clone, Debug, Args)]
struct SetupExecutionArgs {
    /// Opt into repository-backed development setup. Installed remains default.
    #[arg(long)]
    development: bool,
    /// Repository root supplying development plugin/assets.
    #[arg(long, requires = "development")]
    development_root: Option<PathBuf>,
    /// Isolated development state root; required with --development.
    #[arg(long, requires = "development")]
    state_root: Option<PathBuf>,
    /// Development MCP/process port identity.
    #[arg(long, requires = "development")]
    port: Option<u16>,
    /// Explicit process identity used by development status/qualification.
    #[arg(long, requires = "development")]
    process_identity: Option<String>,
    /// Client override as client=source-root,target-root (repeatable).
    #[arg(long = "client-override", requires = "development")]
    client_override: Vec<String>,
}

fn development_context(
    args: &SetupExecutionArgs,
) -> Result<Option<legion_host::DevelopmentSetupContext>, CommandError> {
    if !args.development {
        if args.development_root.is_some()
            || args.state_root.is_some()
            || args.port.is_some()
            || args.process_identity.is_some()
            || !args.client_override.is_empty()
        {
            return Err(CommandError::usage(
                "development options require --development",
            ));
        }
        return Ok(None);
    }
    let repository_root = args
        .development_root
        .clone()
        .unwrap_or(std::env::current_dir().map_err(io_error)?);
    let state_root = args
        .state_root
        .clone()
        .ok_or_else(|| CommandError::usage("--development requires --state-root"))?;
    let process_identity = args
        .process_identity
        .clone()
        .unwrap_or_else(|| format!("legion-dev-{}", std::process::id()));
    let mut client_overrides = BTreeMap::new();
    for raw in &args.client_override {
        let (client, roots) = raw.split_once('=').ok_or_else(|| {
            CommandError::usage("--client-override must be client=source-root,target-root")
        })?;
        let (source_root, target_root) = roots.split_once(',').ok_or_else(|| {
            CommandError::usage("--client-override must be client=source-root,target-root")
        })?;
        client_overrides.insert(
            client.into(),
            legion_host::setup_registry::DevelopmentClientOverride {
                source_root: PathBuf::from(source_root),
                target_root: PathBuf::from(target_root),
            },
        );
    }
    let context = legion_host::DevelopmentSetupContext {
        repository_root,
        state_root,
        port: args.port,
        process_identity,
        client_overrides,
    };
    Ok(Some(context))
}

#[derive(Debug, Subcommand)]
enum SetupCommand {
    Preview(SetupPreviewArgs),
    Apply(SetupMutationArgs),
    Status(SetupClientArgs),
    Qualify(SetupClientArgs),
    Repair(SetupLifecycleArgs),
    Disable(SetupLifecycleArgs),
    Remove(SetupLifecycleArgs),
    Purge(SetupLifecycleArgs),
}

#[derive(Clone, Debug, ValueEnum)]
enum SetupActionArg {
    Apply,
    Repair,
    Disable,
    Remove,
    Purge,
}

impl From<SetupActionArg> for legion_host::SetupAction {
    fn from(action: SetupActionArg) -> Self {
        match action {
            SetupActionArg::Apply => Self::Apply,
            SetupActionArg::Repair => Self::Repair,
            SetupActionArg::Disable => Self::Disable,
            SetupActionArg::Remove => Self::Remove,
            SetupActionArg::Purge => Self::Purge,
        }
    }
}

#[derive(Debug, Args)]
struct SetupPreviewArgs {
    /// Lifecycle action to plan. Preview itself never mutates state.
    #[arg(long, value_enum, default_value_t = SetupActionArg::Apply)]
    action: SetupActionArg,
    #[command(flatten)]
    request: SetupRequestArgs,
    /// Optional durable JSON plan file for a later explicit mutation.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SetupRequestArgs {
    /// JSON array of ClientEvidence collected by the installed launcher.
    #[arg(long = "client-evidence")]
    client_evidence: Option<PathBuf>,
    /// Restrict a preview to one supported client; default is all supported clients.
    #[arg(long)]
    client: Option<String>,
    /// Ask the host to keep the planned operation dry-run only.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct SetupClientArgs {
    /// Restrict status to one supported client; default is all supported clients.
    #[arg(long)]
    client: Option<String>,
}

#[derive(Debug, Args)]
struct SetupMutationArgs {
    /// JSON SetupPreview generated by `legion setup preview`.
    #[arg(long)]
    plan: PathBuf,
    /// Explicitly confirm the plan ID and digest recorded in --plan.
    #[arg(long)]
    confirm: bool,
}

#[derive(Debug, Args)]
struct SetupLifecycleArgs {
    /// JSON array of verified ClientEvidence collected from supported clients.
    #[arg(long = "client-evidence")]
    client_evidence: Option<PathBuf>,
    /// Restrict lifecycle action to one supported client.
    #[arg(long)]
    client: Option<String>,
    /// Preview only; never mutate durable state.
    #[arg(long)]
    dry_run: bool,
    /// Explicitly confirm the generated plan before mutation.
    #[arg(long)]
    confirm: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientCommandProof {
    schema_version: u32,
    kind: String,
    client_id: String,
    mechanism: String,
    release: legion_host::BoundRelease,
    launcher_path: String,
    launcher_sha256: String,
    command: String,
    resolved: bool,
    exit_code: i32,
    output_sha256: String,
    legion_command: String,
    legion_launcher_path: String,
    legion_launcher_sha256: String,
    legion_resolved: bool,
    legion_exit_code: i32,
    legion_output_sha256: String,
    mcp_command: String,
    mcp_args: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientQualificationProof {
    schema_version: u32,
    kind: String,
    client_id: String,
    mechanism: String,
    release: legion_host::BoundRelease,
    launcher_path: String,
    mcp_server: String,
    mcp_tool: String,
    invocation_status: String,
    observed_release_version: String,
    capability_count: usize,
    host_requirements: Vec<Value>,
    capabilities: Vec<Value>,
    degraded_count: usize,
    completed: bool,
    output_sha256: String,
    legion_launcher_path: String,
    legion_launcher_sha256: String,
    mcp_command: String,
    mcp_args: Vec<String>,
}

pub async fn run(args: SetupArgs, cancellation: CancellationToken) -> CommandResult {
    let context = development_context(&args.context)?;
    if args.check {
        if args.command.is_some() || args.dry_run || args.confirm {
            return Err(CommandError::usage(
                "setup --check cannot be combined with lifecycle commands, --dry-run, or --confirm",
            ));
        }
        return status(
            SetupClientArgs {
                client: args.client,
            },
            context,
            cancellation,
        )
        .await;
    }
    match args.command {
        Some(SetupCommand::Preview(args)) => preview(args, context, cancellation).await,
        Some(SetupCommand::Apply(args)) => {
            execute(args, legion_host::SetupAction::Apply, cancellation).await
        }
        Some(SetupCommand::Status(args)) => status(args, context, cancellation).await,
        Some(SetupCommand::Qualify(args)) => qualify(args, context, cancellation).await,
        Some(SetupCommand::Repair(args)) => {
            lifecycle(
                args,
                legion_host::SetupAction::Repair,
                context,
                cancellation,
            )
            .await
        }
        Some(SetupCommand::Disable(args)) => {
            lifecycle(
                args,
                legion_host::SetupAction::Disable,
                context,
                cancellation,
            )
            .await
        }
        Some(SetupCommand::Remove(args)) => {
            lifecycle(
                args,
                legion_host::SetupAction::Remove,
                context,
                cancellation,
            )
            .await
        }
        Some(SetupCommand::Purge(args)) => {
            lifecycle(args, legion_host::SetupAction::Purge, context, cancellation).await
        }
        None => {
            lifecycle(
                SetupLifecycleArgs {
                    client_evidence: None,
                    client: args.client,
                    dry_run: args.dry_run,
                    confirm: args.confirm,
                },
                legion_host::SetupAction::Apply,
                context,
                cancellation,
            )
            .await
        }
    }
}

async fn lifecycle(
    args: SetupLifecycleArgs,
    action: legion_host::SetupAction,
    context: Option<legion_host::DevelopmentSetupContext>,
    cancellation: CancellationToken,
) -> CommandResult {
    if matches!(action, legion_host::SetupAction::Purge) && !args.confirm && !args.dry_run {
        return Err(CommandError::usage(
            "setup purge requires --confirm for the exact generated plan",
        ));
    }
    let release = bound_release_for_context(context.as_ref())?;
    let request = SetupRequestArgs {
        client_evidence: args.client_evidence,
        client: args.client,
        dry_run: args.dry_run,
    };
    let request =
        request_from_release(request, action, release, context, cancellation.clone()).await?;
    let mut registry = open_registry(&request)?;
    let recovery = registry.recover().map_err(setup_error)?;
    reject_empty_lifecycle_with_pending_refresh(&request, &registry)?;
    let host_integrations = preview_host_integrations(&request, cancellation.clone()).await?;
    let identity_context = request.development.clone();
    let health_action = request.action.clone();
    let preview = registry.preview(request).map_err(setup_error)?;
    let preview_value = serde_json::to_value(&preview)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let live_identity = inspect_live_identity(&host_integrations, identity_context.as_ref())?;
    let (status, remediation) = setup_health_for_action(
        &preview_value["clients"],
        &host_integrations,
        &live_identity,
        &health_action,
    );
    if !args.confirm || args.dry_run {
        return Ok(json!({
            "schemaVersion": 1,
            "kind": "legion-setup-preview",
            "status": status,
            "origin": live_identity.get("origin").cloned(),
            "executable": live_identity.get("executablePath").cloned(),
            "installRoot": live_identity.get("installRoot").cloned(),
            "stableCurrentRoot": live_identity.get("stableCurrentRoot").cloned(),
            "stableCurrent": live_identity.get("stableCurrent").cloned(),
            "resolvedExecutable": live_identity.get("resolvedExecutable").cloned(),
            "resolvedInstallRoot": live_identity.get("resolvedInstallRoot").cloned(),
            "generation": live_identity.get("generation").cloned(),
            "remediation": remediation,
            "recovery": recovery,
            "preview": preview,
            "hostIntegrations": host_integrations,
            "liveIdentity": live_identity,
        }));
    }
    let confirmation = legion_host::PlanConfirmation {
        plan_id: preview.plan_id.clone(),
        plan_digest: preview.plan_digest.clone(),
    };
    let confirmed = registry
        .confirm(preview, confirmation)
        .map_err(setup_error)?;
    let integration_request = confirmed.preview.request.clone();
    // Reconcile production client bindings before durable registry mutation.
    // This keeps an escaped projection from leaving a partially applied plan.
    preview_host_integrations(&integration_request, cancellation.clone()).await?;
    let execution = registry.execute(confirmed).map_err(setup_error)?;
    let host_integrations =
        apply_host_integrations(&integration_request, cancellation.clone()).await?;
    let authenticated_live_qualification = inspect_stored_live_qualification(
        &execution.clients,
        &integration_request.release,
        &integration_request.platform_state_root,
    );
    let execution_value = serde_json::to_value(&execution)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let live_identity =
        inspect_live_identity(&host_integrations, integration_request.development.as_ref())?;
    let execution_value = enrich_client_statuses(execution_value, &live_identity);
    let (status, remediation) = setup_health_for_action(
        &execution_value["clients"],
        &host_integrations,
        &live_identity,
        &integration_request.action,
    );
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-setup-execution",
        "status": status,
        "origin": live_identity.get("origin").cloned(),
        "executable": live_identity.get("executablePath").cloned(),
        "installRoot": live_identity.get("installRoot").cloned(),
        "stableCurrentRoot": live_identity.get("stableCurrentRoot").cloned(),
        "stableCurrent": live_identity.get("stableCurrent").cloned(),
        "resolvedExecutable": live_identity.get("resolvedExecutable").cloned(),
        "resolvedInstallRoot": live_identity.get("resolvedInstallRoot").cloned(),
        "generation": live_identity.get("generation").cloned(),
        "remediation": remediation,
        "recovery": recovery,
        "execution": execution_value,
        "authenticatedLiveQualification": authenticated_live_qualification,
        "hostIntegrations": host_integrations,
        "liveIdentity": live_identity,
    }))
}

async fn preview(
    args: SetupPreviewArgs,
    context: Option<legion_host::DevelopmentSetupContext>,
    cancellation: CancellationToken,
) -> CommandResult {
    let request = request(
        args.request,
        args.action.into(),
        context,
        false,
        cancellation.clone(),
    )
    .await?;
    let mut registry = open_registry(&request)?;
    let recovery = registry.recover().map_err(setup_error)?;
    let host_integrations = preview_host_integrations(&request, cancellation.clone()).await?;
    let identity_context = request.development.clone();
    let health_action = request.action.clone();
    let preview = registry.preview(request).map_err(setup_error)?;
    let preview_value = serde_json::to_value(&preview)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let live_identity = inspect_live_identity(&host_integrations, identity_context.as_ref())?;
    let (status, remediation) = setup_health_for_action(
        &preview_value["clients"],
        &host_integrations,
        &live_identity,
        &health_action,
    );
    if let Some(path) = args.out {
        write_json(&path, &preview)?;
    }
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-setup-preview",
        "status": status,
        "origin": live_identity.get("origin").cloned(),
        "executable": live_identity.get("executablePath").cloned(),
        "installRoot": live_identity.get("installRoot").cloned(),
        "stableCurrentRoot": live_identity.get("stableCurrentRoot").cloned(),
        "stableCurrent": live_identity.get("stableCurrent").cloned(),
        "resolvedExecutable": live_identity.get("resolvedExecutable").cloned(),
        "resolvedInstallRoot": live_identity.get("resolvedInstallRoot").cloned(),
        "generation": live_identity.get("generation").cloned(),
        "remediation": remediation,
        "recovery": recovery,
        "preview": preview,
        "hostIntegrations": host_integrations,
        "liveIdentity": live_identity,
    }))
}

async fn status(
    args: SetupClientArgs,
    context: Option<legion_host::DevelopmentSetupContext>,
    cancellation: CancellationToken,
) -> CommandResult {
    if let Some(context) = context {
        return development_status(args, context, cancellation).await;
    }
    let installed = match installed_release() {
        Ok(installed) => installed,
        Err(error) => {
            let evidence = legion_runtime::release_binding::detect_runtime_origin().map_err(
                |origin_error| {
                    CommandError::incomplete(format!(
                        "{}; runtime origin unavailable: {origin_error}",
                        error.message
                    ))
                },
            )?;
            let origin = match &evidence.origin {
                legion_runtime::release_binding::RuntimeOrigin::Installed => {
                    legion_host::setup_registry::ORIGIN_INSTALLED
                }
                legion_runtime::release_binding::RuntimeOrigin::Development => {
                    legion_host::setup_registry::ORIGIN_DEVELOPMENT
                }
            };
            let resolved_executable = std::fs::canonicalize(&evidence.executable).ok();
            let stable_current_root = evidence
                .install_root
                .as_ref()
                .map(|path| path.join("current"));
            let resolved_install_root = evidence
                .install_root
                .as_ref()
                .map(|path| path.join("current"))
                .and_then(|path| std::fs::canonicalize(path).ok());
            return Ok(json!({
                "schemaVersion": 1,
                "kind": "legion-setup-status",
                "status": "failed",
                "origin": origin,
                "executable": evidence.executable,
                "installRoot": evidence.install_root,
                "stableCurrentRoot": stable_current_root,
                "resolvedExecutable": resolved_executable,
                "resolvedInstallRoot": resolved_install_root,
                "generation": evidence.generation,
                "stableCurrent": evidence.stable_current,
                "clients": [],
                "remediation": [error.message],
            }));
        }
    };
    let release = bound_release(&installed.manifest);
    let selector = selector(args.client);
    let mut registry =
        legion_host::SetupRegistry::open_platform(release.clone()).map_err(setup_error)?;
    let recovery = registry.recover().map_err(setup_error)?;
    let clients = registry.status(&selector).map_err(setup_error)?;
    let mut host_integrations =
        inspect_host_integrations(&selector, &release, cancellation).await?;
    supersede_legacy_marketplace_observations(&mut host_integrations);
    let platform_state_root = legion_host::platform_state_root().map_err(setup_error)?;
    let authenticated_live_qualification =
        inspect_stored_live_qualification(&clients, &release, &platform_state_root);
    let clients_value = serde_json::to_value(&clients)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let live_identity = inspect_live_identity(&host_integrations, None)?;
    let clients_value = enrich_client_statuses(clients_value, &live_identity);
    let (status, remediation) = setup_health_for_action(
        &clients_value,
        &host_integrations,
        &live_identity,
        &legion_host::SetupAction::Status,
    );
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-setup-status",
        "status": status,
        "origin": live_identity.get("origin").cloned(),
        "executable": live_identity.get("executablePath").cloned(),
        "installRoot": live_identity.get("installRoot").cloned(),
        "stableCurrentRoot": live_identity.get("stableCurrentRoot").cloned(),
        "stableCurrent": live_identity.get("stableCurrent").cloned(),
        "resolvedExecutable": live_identity.get("resolvedExecutable").cloned(),
        "resolvedInstallRoot": live_identity.get("resolvedInstallRoot").cloned(),
        "generation": live_identity.get("generation").cloned(),
        "remediation": remediation,
        "recovery": recovery,
        "clients": clients_value,
        "authenticatedLiveQualification": authenticated_live_qualification,
        "hostIntegrations": host_integrations,
        "liveIdentity": live_identity,
    }))
}

async fn qualify(
    args: SetupClientArgs,
    context: Option<legion_host::DevelopmentSetupContext>,
    cancellation: CancellationToken,
) -> CommandResult {
    if context.is_some() {
        return Err(CommandError::usage(
            "authenticated live qualification is available only for installed Legion",
        ));
    }
    let release = installed_bound_release()?;
    let platform_state_root = legion_host::platform_state_root().map_err(setup_error)?;
    let selected = args.client.as_deref();
    let (evidence, clients) = qualify_discovered_clients(
        selected,
        &release,
        &platform_state_root,
        cancellation.clone(),
    )
    .await?;
    validate_client_evidence(
        &evidence,
        selected,
        &release,
        &platform_state_root,
        false,
        cancellation.clone(),
    )
    .await?;
    let applicable = clients
        .iter()
        .filter(|client| client["status"] != "not_supported")
        .collect::<Vec<_>>();
    let status = if applicable.is_empty() {
        "not_applicable"
    } else if applicable
        .iter()
        .all(|client| client["status"] == "qualified")
    {
        "qualified"
    } else {
        "blocked"
    };
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-setup-authenticated-live-qualification",
        "status": status,
        "releaseVersion": release.release_version,
        "clients": clients,
        "activationRequired": false,
    }))
}

async fn execute(
    args: SetupMutationArgs,
    expected: legion_host::SetupAction,
    cancellation: CancellationToken,
) -> CommandResult {
    if !args.confirm {
        return Err(CommandError::usage(
            "setup mutation requires --confirm for the exact supplied --plan",
        ));
    }
    let preview: legion_host::SetupPreview = read_json(&args.plan, "SetupPreview")?;
    if preview.request.action != expected {
        return Err(CommandError::usage(
            "setup command does not match the action recorded in --plan",
        ));
    }
    let selected = match &preview.request.selector {
        legion_host::ClientSelector::AllSupported => None,
        legion_host::ClientSelector::ClientId(client_id) => Some(client_id.as_str()),
    };
    validate_client_evidence(
        &preview.request.client_evidence,
        selected,
        &preview.request.release,
        &preview.request.platform_state_root,
        false,
        cancellation.clone(),
    )
    .await?;
    let mut registry = open_registry(&preview.request)?;
    let recovery = registry.recover().map_err(setup_error)?;
    reject_empty_lifecycle_with_pending_refresh(&preview.request, &registry)?;
    let integration_request = preview.request.clone();
    let confirmation = legion_host::PlanConfirmation {
        plan_id: preview.plan_id.clone(),
        plan_digest: preview.plan_digest.clone(),
    };
    let confirmed = registry
        .confirm(preview, confirmation)
        .map_err(setup_error)?;
    // Reconcile production client bindings before durable registry mutation.
    // This keeps an escaped projection from leaving a partially applied plan.
    preview_host_integrations(&integration_request, cancellation.clone()).await?;
    let execution = registry.execute(confirmed).map_err(setup_error)?;
    let host_integrations =
        apply_host_integrations(&integration_request, cancellation.clone()).await?;
    let authenticated_live_qualification = inspect_stored_live_qualification(
        &execution.clients,
        &integration_request.release,
        &integration_request.platform_state_root,
    );
    let execution_value = serde_json::to_value(&execution)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let live_identity =
        inspect_live_identity(&host_integrations, integration_request.development.as_ref())?;
    let execution_value = enrich_client_statuses(execution_value, &live_identity);
    let (status, remediation) = setup_health_for_action(
        &execution_value["clients"],
        &host_integrations,
        &live_identity,
        &integration_request.action,
    );
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-setup-execution",
        "status": status,
        "origin": live_identity.get("origin").cloned(),
        "executable": live_identity.get("executablePath").cloned(),
        "installRoot": live_identity.get("installRoot").cloned(),
        "stableCurrentRoot": live_identity.get("stableCurrentRoot").cloned(),
        "stableCurrent": live_identity.get("stableCurrent").cloned(),
        "resolvedExecutable": live_identity.get("resolvedExecutable").cloned(),
        "resolvedInstallRoot": live_identity.get("resolvedInstallRoot").cloned(),
        "generation": live_identity.get("generation").cloned(),
        "remediation": remediation,
        "recovery": recovery,
        "execution": execution_value,
        "authenticatedLiveQualification": authenticated_live_qualification,
        "hostIntegrations": host_integrations,
        "liveIdentity": live_identity,
    }))
}

async fn request(
    args: SetupRequestArgs,
    action: legion_host::SetupAction,
    context: Option<legion_host::DevelopmentSetupContext>,
    live_validation: bool,
    cancellation: CancellationToken,
) -> Result<legion_host::SetupRequest, CommandError> {
    let client = args.client.clone();
    let release = bound_release_for_context(context.as_ref())?;
    let platform_state_root = context
        .as_ref()
        .map(|c| c.state_root.clone())
        .unwrap_or(legion_host::platform_state_root().map_err(setup_error)?);
    let client_evidence = client_evidence(
        args.client_evidence,
        client.as_deref(),
        &release,
        &platform_state_root,
        live_validation,
        cancellation,
    )
    .await?;
    let client_evidence = if context.is_some() && client_evidence.is_empty() {
        development_client_evidence(client.as_deref())
    } else {
        client_evidence
    };
    Ok(legion_host::SetupRequest {
        action,
        selector: selector(client.clone()),
        release,
        platform_state_root,
        client_evidence,
        dry_run: args.dry_run,
        origin: if context.is_some() {
            legion_host::setup_registry::ORIGIN_DEVELOPMENT.into()
        } else {
            legion_host::setup_registry::ORIGIN_INSTALLED.into()
        },
        development: context,
    })
}

async fn request_from_release(
    args: SetupRequestArgs,
    action: legion_host::SetupAction,
    release: legion_host::BoundRelease,
    context: Option<legion_host::DevelopmentSetupContext>,
    cancellation: CancellationToken,
) -> Result<legion_host::SetupRequest, CommandError> {
    let platform_state_root = context
        .as_ref()
        .map(|c| c.state_root.clone())
        .unwrap_or(legion_host::platform_state_root().map_err(setup_error)?);
    let client_evidence = client_evidence(
        args.client_evidence,
        args.client.as_deref(),
        &release,
        &platform_state_root,
        false,
        cancellation,
    )
    .await?;
    let client_evidence = if context.is_some() && client_evidence.is_empty() {
        development_client_evidence(args.client.as_deref())
    } else {
        client_evidence
    };
    Ok(legion_host::SetupRequest {
        action,
        selector: selector(args.client.clone()),
        release,
        platform_state_root,
        client_evidence,
        dry_run: args.dry_run,
        origin: if context.is_some() {
            legion_host::setup_registry::ORIGIN_DEVELOPMENT.into()
        } else {
            legion_host::setup_registry::ORIGIN_INSTALLED.into()
        },
        development: context,
    })
}
async fn client_evidence(
    evidence_path: Option<PathBuf>,
    selected: Option<&str>,
    release: &legion_host::BoundRelease,
    platform_state_root: &std::path::Path,
    live_validation: bool,
    cancellation: CancellationToken,
) -> Result<Vec<legion_host::ClientEvidence>, CommandError> {
    let evidence = match evidence_path {
        Some(path) => read_json(&path, "ClientEvidence array")?,
        None => discovered_client_evidence(selected),
    };
    if live_validation {
        validate_live_evidence_refs(&evidence, selected)?;
    }
    validate_client_evidence(
        &evidence,
        selected,
        release,
        platform_state_root,
        live_validation,
        cancellation,
    )
    .await?;
    Ok(evidence)
}
async fn validate_client_evidence(
    evidence: &[legion_host::ClientEvidence],
    selected: Option<&str>,
    release: &legion_host::BoundRelease,
    platform_state_root: &std::path::Path,
    live_validation: bool,
    cancellation: CancellationToken,
) -> Result<(), CommandError> {
    if live_validation {
        validate_live_evidence_refs(evidence, selected)?;
    }
    let mut qualification_root = None;
    for client in evidence {
        if !client.detected {
            continue;
        }
        if !legion_host::setup_registry::client_supports_live_qualification(&client.client_id) {
            continue;
        }
        let Some(command_ref) = client.command_proof_ref.as_deref() else {
            continue;
        };
        let Some(qualification_ref) = client.qualification_evidence_ref.as_deref() else {
            continue;
        };
        let qualification_root = match &qualification_root {
            Some(root) => root,
            None => qualification_root.insert(
                std::fs::canonicalize(platform_state_root.join("qualification"))
                    .map_err(io_error)?,
            ),
        };
        let command_path = std::fs::canonicalize(command_ref).map_err(io_error)?;
        let qualification_path = std::fs::canonicalize(qualification_ref).map_err(io_error)?;
        if command_path == qualification_path
            || !command_path.starts_with(&qualification_root)
            || !qualification_path.starts_with(&qualification_root)
        {
            return Err(CommandError::usage(
                "client command and qualification proofs must be distinct files inside Legion platform state",
            ));
        }
        let command_proof: ClientCommandProof =
            read_json(&command_path, "client command resolution proof")?;
        let qualification_proof: ClientQualificationProof =
            read_json(&qualification_path, "real-client qualification proof")?;
        validate_proof_pair(
            client,
            release,
            &command_path,
            &qualification_path,
            &command_proof,
            &qualification_proof,
        )?;
        if live_validation {
            let (fresh_command, fresh_qualification) = qualify_client(
                &client.client_id,
                release,
                platform_state_root,
                cancellation.clone(),
            )
            .await?;
            if fresh_command.launcher_path != command_proof.launcher_path
                || fresh_command.legion_launcher_path != command_proof.legion_launcher_path
                || fresh_command.mcp_command != command_proof.mcp_command
                || fresh_command.mcp_args != command_proof.mcp_args
                || fresh_qualification.observed_release_version
                    != qualification_proof.observed_release_version
                || fresh_qualification.host_requirements != qualification_proof.host_requirements
                || fresh_qualification.capabilities != qualification_proof.capabilities
                || fresh_qualification.degraded_count != qualification_proof.degraded_count
                || !fresh_qualification.completed
            {
                return Err(CommandError::incomplete(format!(
                    "live client qualification changed for {}; run legion setup repair --confirm",
                    client.client_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_live_evidence_refs(
    evidence: &[legion_host::ClientEvidence],
    selected: Option<&str>,
) -> Result<(), CommandError> {
    for client in evidence {
        if !client.detected || selected.is_some_and(|id| id != client.client_id.as_str()) {
            continue;
        }
        if !legion_host::setup_registry::client_supports_live_qualification(&client.client_id) {
            continue;
        }
        if client.command_proof_ref.is_none() || client.qualification_evidence_ref.is_none() {
            return Err(CommandError::incomplete(format!(
                "authenticated live qualification evidence is unavailable for detected client {}; authenticate client, then run legion setup qualify",
                client.client_id
            )));
        }
    }
    Ok(())
}

fn validate_proof_pair(
    client: &legion_host::ClientEvidence,
    release: &legion_host::BoundRelease,
    command_path: &Path,
    qualification_path: &Path,
    command: &ClientCommandProof,
    qualification: &ClientQualificationProof,
) -> Result<(), CommandError> {
    let launcher = std::fs::canonicalize(&command.launcher_path).map_err(io_error)?;
    let launcher_digest = legion_catalog::hex_digest(&std::fs::read(&launcher).map_err(io_error)?);
    let installed = installed_release()?;
    let installed_launcher = std::fs::canonicalize(&installed.executable_path).map_err(io_error)?;
    let legion_launcher = std::fs::canonicalize(&command.legion_launcher_path).map_err(io_error)?;
    let resolved_legion = resolve_command("legion")?;
    let resolved_legion_digest =
        legion_catalog::hex_digest(&std::fs::read(&resolved_legion).map_err(io_error)?);
    let expected_mcp_args = QUALIFICATION_MCP_ARGS
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    let valid = command.schema_version == QUALIFICATION_SCHEMA_VERSION
        && command.kind == "legion-command-resolution-proof"
        && command.client_id == client.client_id
        && command.mechanism == QUALIFICATION_MECHANISM
        && client
            .mechanisms
            .iter()
            .any(|item| item == &command.mechanism)
        && &command.release == release
        && command.resolved
        && command.exit_code == 0
        && command.launcher_path == launcher.to_string_lossy()
        && command.launcher_sha256 == launcher_digest
        && is_sha256(&command.output_sha256)
        && command.legion_command == "legion --version"
        && command.legion_resolved
        && command.legion_exit_code == 0
        && command.legion_launcher_path == legion_launcher.to_string_lossy()
        && command.legion_launcher_path == installed_launcher.to_string_lossy()
        && command.legion_launcher_path == resolved_legion.to_string_lossy()
        && command.legion_launcher_sha256 == release.runtime_digest
        && command.legion_launcher_sha256 == resolved_legion_digest
        && is_sha256(&command.legion_output_sha256)
        && command.mcp_command == QUALIFICATION_SERVER
        && command.mcp_args == expected_mcp_args
        && qualification.schema_version == QUALIFICATION_SCHEMA_VERSION
        && qualification.kind == "legion-real-client-qualification"
        && qualification.client_id == client.client_id
        && qualification.mechanism == command.mechanism
        && &qualification.release == release
        && qualification.launcher_path == command.launcher_path
        && qualification.legion_launcher_path == command.legion_launcher_path
        && qualification.legion_launcher_sha256 == command.legion_launcher_sha256
        && qualification.mcp_server == QUALIFICATION_SERVER
        && qualification.mcp_tool == QUALIFICATION_TOOL
        && qualification.mcp_command == command.mcp_command
        && qualification.mcp_args == command.mcp_args
        && qualification.invocation_status == "complete"
        && qualification.observed_release_version == release.release_version
        && qualification.capability_count > 0
        && qualification.capabilities.len() == qualification.capability_count
        && qualification.host_requirements.iter().all(Value::is_object)
        && qualification.capabilities.iter().all(Value::is_object)
        && qualification.degraded_count <= qualification.capability_count
        && qualification.completed
        && is_sha256(&qualification.output_sha256)
        && command_path.is_file()
        && qualification_path.is_file();
    if !valid {
        return Err(CommandError::incomplete(format!(
            "client qualification evidence does not bind {} to a resolved launcher, completed MCP call, and installed release; run legion setup repair --confirm",
            client.client_id
        )));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn qualify_discovered_clients(
    selected: Option<&str>,
    release: &legion_host::BoundRelease,
    platform_state_root: &Path,
    cancellation: CancellationToken,
) -> Result<(Vec<legion_host::ClientEvidence>, Vec<Value>), CommandError> {
    let discovered = discovered_client_evidence(selected);
    if discovered.is_empty() {
        return Ok((discovered, Vec::new()));
    }
    let mut qualified = Vec::with_capacity(discovered.len());
    let mut health = Vec::with_capacity(discovered.len());
    for client in discovered {
        if !client.detected {
            health.push(json!({
                "clientId": client.client_id,
                "status": "not_detected",
                "commandProofRef": Value::Null,
                "qualificationEvidenceRef": Value::Null,
                "detail": "client configuration root was not detected",
            }));
            qualified.push(client);
            continue;
        }
        if !legion_host::setup_registry::client_supports_live_qualification(&client.client_id) {
            health.push(json!({
                "clientId": client.client_id,
                "status": "not_supported",
                "commandProofRef": Value::Null,
                "qualificationEvidenceRef": Value::Null,
                "detail": "authenticated live qualification is not defined for this client",
            }));
            qualified.push(client);
            continue;
        }
        let result = qualify_client(
            &client.client_id,
            release,
            platform_state_root,
            cancellation.clone(),
        )
        .await;
        let (command, qualification) = match result {
            Ok(result) => result,
            Err(error) if error.code == 2 && !cancellation.is_cancelled() => {
                health.push(json!({
                    "clientId": client.client_id,
                    "status": "blocked",
                    "commandProofRef": Value::Null,
                    "qualificationEvidenceRef": Value::Null,
                    "detail": error.message,
                }));
                qualified.push(client);
                continue;
            }
            Err(error) => return Err(error),
        };
        let root = platform_state_root.join("qualification");
        std::fs::create_dir_all(&root).map_err(io_error)?;
        let command_path = root.join(format!("{}-command.json", client.client_id));
        let qualification_path = root.join(format!("{}-qualification.json", client.client_id));
        write_json(&command_path, &command)?;
        write_json(&qualification_path, &qualification)?;
        let qualified_client = legion_host::ClientEvidence {
            command_proof_ref: Some(command_path.to_string_lossy().into_owned()),
            qualification_evidence_ref: Some(qualification_path.to_string_lossy().into_owned()),
            ..client
        };
        health.push(json!({
            "clientId": qualified_client.client_id,
            "status": "qualified",
            "commandProofRef": qualified_client.command_proof_ref,
            "qualificationEvidenceRef": qualified_client.qualification_evidence_ref,
            "detail": "authenticated MCP qualification completed",
        }));
        qualified.push(qualified_client);
    }
    Ok((qualified, health))
}

async fn qualify_client(
    client_id: &str,
    release: &legion_host::BoundRelease,
    _platform_state_root: &Path,
    cancellation: CancellationToken,
) -> Result<(ClientCommandProof, ClientQualificationProof), CommandError> {
    let launcher = resolve_launcher(client_id)?;
    let installed = installed_release()?;
    let installed_launcher = std::fs::canonicalize(&installed.executable_path).map_err(io_error)?;
    let legion_launcher = resolve_command("legion")?;
    if legion_launcher != installed_launcher {
        return Err(CommandError::incomplete(format!(
            "bare legion resolved to {}, not installed release {}",
            legion_launcher.display(),
            installed_launcher.display()
        )));
    }
    let legion_launcher_digest =
        legion_catalog::hex_digest(&std::fs::read(&legion_launcher).map_err(io_error)?);
    let legion_version_output = run_client_command(
        &legion_launcher,
        vec!["--version".into()],
        client_id,
        "Legion command resolution",
        cancellation.clone(),
    )
    .await?;
    let legion_version_bytes = output_bytes(&legion_version_output);
    let legion_version_text = String::from_utf8_lossy(&legion_version_output.stdout);
    if legion_version_output.exit_code != Some(0)
        || !legion_version_text
            .lines()
            .any(|line| line.trim() == release.release_version)
    {
        return Err(CommandError::incomplete(format!(
            "bare legion did not resolve installed release {} for {client_id}",
            release.release_version
        )));
    }
    let version_output = run_client_command(
        &launcher,
        vec!["--version".into()],
        client_id,
        "command resolution",
        cancellation.clone(),
    )
    .await?;
    if version_output.exit_code != Some(0) {
        return Err(CommandError::incomplete(format!(
            "{client_id} launcher {} did not resolve successfully",
            launcher.display()
        )));
    }
    let version_bytes = output_bytes(&version_output);
    let launcher_digest = legion_catalog::hex_digest(&std::fs::read(&launcher).map_err(io_error)?);
    let command = ClientCommandProof {
        schema_version: QUALIFICATION_SCHEMA_VERSION,
        kind: "legion-command-resolution-proof".into(),
        client_id: client_id.into(),
        mechanism: QUALIFICATION_MECHANISM.into(),
        release: release.clone(),
        launcher_path: std::fs::canonicalize(&launcher)
            .map_err(io_error)?
            .to_string_lossy()
            .into_owned(),
        launcher_sha256: launcher_digest,
        command: format!("{} --version", launcher.display()),
        resolved: true,
        exit_code: version_output.exit_code.unwrap_or(-1),
        output_sha256: legion_catalog::hex_digest(&version_bytes),
        legion_command: "legion --version".into(),
        legion_launcher_path: legion_launcher.to_string_lossy().into_owned(),
        legion_launcher_sha256: legion_launcher_digest,
        legion_resolved: true,
        legion_exit_code: legion_version_output.exit_code.unwrap_or(-1),
        legion_output_sha256: legion_catalog::hex_digest(&legion_version_bytes),
        mcp_command: QUALIFICATION_SERVER.into(),
        mcp_args: QUALIFICATION_MCP_ARGS
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    };

    let mcp_config = serde_json::to_string(&json!({
        "mcpServers": {
            QUALIFICATION_SERVER: {
                "command": QUALIFICATION_SERVER,
                "args": QUALIFICATION_MCP_ARGS,
            }
        }
    }))
    .map_err(io_error)?;
    let prompt = format!(
        "Call the Legion MCP tool {QUALIFICATION_TOOL} now. Return its complete structured result as JSON; do not infer or paraphrase it."
    );
    let output = match client_id {
        "claude-code" => {
            run_client_command(
                &launcher,
                vec![
                    "-p".into(),
                    "--output-format".into(),
                    "json".into(),
                    "--bare".into(),
                    "--no-session-persistence".into(),
                    "--strict-mcp-config".into(),
                    "--mcp-config".into(),
                    mcp_config.clone(),
                    "--".into(),
                    prompt.clone(),
                ],
                client_id,
                "real-client MCP qualification",
                cancellation.clone(),
            )
            .await?
        }
        "codex" => {
            run_client_command(
                &launcher,
                vec![
                    "exec".into(),
                    "--ephemeral".into(),
                    "--json".into(),
                    "--dangerously-bypass-approvals-and-sandbox".into(),
                    "--skip-git-repo-check".into(),
                    "--ignore-user-config".into(),
                    "-c".into(),
                    "mcp_servers.legion.command=\"legion\"".into(),
                    "-c".into(),
                    "mcp_servers.legion.args=[\"serve\",\"--stdio\"]".into(),
                    prompt.clone(),
                ],
                client_id,
                "real-client MCP qualification",
                cancellation.clone(),
            )
            .await?
        }
        other => {
            return Err(CommandError::usage(format!(
                "unsupported client qualification target {other}"
            )))
        }
    };
    if output.exit_code != Some(0) {
        let detail = process_output_detail(&output);
        return Err(CommandError::incomplete(format!(
            "{client_id} real-client qualification exited with {}{}",
            output.exit_code.unwrap_or(-1),
            detail
                .as_deref()
                .map(|value| format!(": {value}"))
                .unwrap_or_default()
        )));
    }
    let output_bytes = output_bytes(&output);
    let parsed = parse_client_result(client_id, &output_bytes, &release.release_version)?;
    let ParsedClientResult {
        observed_release_version,
        capability_count,
        host_requirements,
        capabilities,
        degraded_count,
    } = parsed;
    let qualification = ClientQualificationProof {
        schema_version: QUALIFICATION_SCHEMA_VERSION,
        kind: "legion-real-client-qualification".into(),
        client_id: client_id.into(),
        mechanism: QUALIFICATION_MECHANISM.into(),
        release: release.clone(),
        launcher_path: command.launcher_path.clone(),
        mcp_server: QUALIFICATION_SERVER.into(),
        mcp_tool: QUALIFICATION_TOOL.into(),
        invocation_status: "complete".into(),
        observed_release_version,
        capability_count,
        host_requirements,
        capabilities,
        degraded_count,
        completed: true,
        output_sha256: legion_catalog::hex_digest(&output_bytes),
        legion_launcher_path: command.legion_launcher_path.clone(),
        legion_launcher_sha256: command.legion_launcher_sha256.clone(),
        mcp_command: command.mcp_command.clone(),
        mcp_args: command.mcp_args.clone(),
    };
    Ok((command, qualification))
}

fn resolve_launcher(client_id: &str) -> Result<PathBuf, CommandError> {
    let command = match client_id {
        "claude-code" => "claude",
        "codex" => "codex",
        other => {
            return Err(CommandError::usage(format!(
                "unsupported client qualification target {other}"
            )))
        }
    };
    resolve_command(command)
}

fn resolve_command(command: &str) -> Result<PathBuf, CommandError> {
    let mut directories = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    if let Some(home) =
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
    {
        directories.push(home.join(".local/bin"));
        if cfg!(windows) {
            directories.push(home.join("AppData/Roaming/npm"));
        }
    }
    #[cfg(target_os = "macos")]
    directories.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ]);
    let mut seen = BTreeSet::new();
    directories.retain(|directory| seen.insert(directory.clone()));
    let suffixes: Vec<OsString> = if cfg!(windows) {
        vec![
            OsString::from(".exe"),
            OsString::from(".cmd"),
            OsString::from(".bat"),
        ]
    } else {
        vec![OsString::new()]
    };
    for suffix in &suffixes {
        for directory in &directories {
            let candidate = directory.join(format!("{command}{}", suffix.to_string_lossy()));
            if candidate.is_file() {
                return std::fs::canonicalize(candidate).map_err(io_error);
            }
        }
    }
    Err(CommandError::incomplete(format!(
        "cannot resolve {command} on PATH"
    )))
}

async fn run_client_command(
    executable: &Path,
    args: Vec<String>,
    client_id: &str,
    operation: &str,
    cancellation: CancellationToken,
) -> Result<ProcessOutput, CommandError> {
    let launch = ProcessLaunch {
        executable: executable.to_string_lossy().into_owned(),
        args,
        cwd: std::env::current_dir()
            .map_err(io_error)?
            .to_string_lossy()
            .into_owned(),
        environment: std::env::vars().collect::<BTreeMap<_, _>>(),
        stdout_limit: 8 * 1024 * 1024,
        stderr_limit: 8 * 1024 * 1024,
        timeout_ms: QUALIFICATION_TIMEOUT.as_millis() as u64,
        termination_grace_ms: 5_000,
        cancellation,
    };
    #[cfg(unix)]
    let output = legion_effects::platform::unix::UnixProcess
        .run(launch)
        .await;
    #[cfg(windows)]
    let output = legion_effects::platform::windows::WindowsProcess
        .run(launch)
        .await;
    let output = output.map_err(|error| {
        CommandError::incomplete(format!("{client_id} {operation} could not run: {error}"))
    })?;
    if output.timed_out {
        return Err(CommandError::incomplete(format!(
            "{client_id} {operation} exceeded {} seconds",
            QUALIFICATION_TIMEOUT.as_secs()
        )));
    }
    if output.cancelled {
        return Err(CommandError::cancelled());
    }
    if output.output_limited {
        return Err(CommandError::incomplete(format!(
            "{client_id} {operation} exceeded output limits"
        )));
    }
    if !output.kill_succeeded
        || !output.process_tree.started
        || !output.process_tree.terminated
        || !output.process_tree.reaped
    {
        return Err(CommandError::incomplete(format!(
            "{client_id} {operation} did not prove process-tree cleanup"
        )));
    }
    Ok(output)
}

fn output_bytes(output: &ProcessOutput) -> Vec<u8> {
    let mut bytes = output.stdout.clone();
    bytes.push(0);
    bytes.extend_from_slice(&output.stderr);
    bytes
}

fn process_output_detail(output: &ProcessOutput) -> Option<String> {
    concise_client_output_detail(&output.stderr, &output.stdout)
}

fn concise_client_output_detail(stderr: &[u8], stdout: &[u8]) -> Option<String> {
    let combined = [stderr, stdout]
        .into_iter()
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join("\n");
    let normalized = combined.to_ascii_lowercase();
    if normalized.contains("not logged in") || normalized.contains("please run /login") {
        return Some("client is not logged in; run /login, then retry legion setup qualify".into());
    }
    let text = [stderr, stdout]
        .into_iter()
        .flat_map(|bytes| {
            String::from_utf8_lossy(bytes)
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .map(|line| line.trim().to_owned())
        .find(|line| !line.is_empty() && !line.starts_with('{'))?;
    let mut detail = text.chars().take(240).collect::<String>();
    if text.chars().count() > 240 {
        detail.push('…');
    }
    Some(detail)
}

#[derive(Debug)]
struct ParsedClientResult {
    observed_release_version: String,
    capability_count: usize,
    host_requirements: Vec<Value>,
    capabilities: Vec<Value>,
    degraded_count: usize,
}

fn parse_client_result(
    client_id: &str,
    bytes: &[u8],
    release_version: &str,
) -> Result<ParsedClientResult, CommandError> {
    let text = String::from_utf8_lossy(bytes);
    match client_id {
        "codex" => {
            for line in text.lines() {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let item = value.get("item").unwrap_or(&value);
                if item.get("type").and_then(Value::as_str) != Some("mcp_tool_call")
                    || item.get("server").and_then(Value::as_str) != Some(QUALIFICATION_SERVER)
                    || item.get("tool").and_then(Value::as_str) != Some(QUALIFICATION_TOOL)
                    || item.get("status").and_then(Value::as_str) != Some("completed")
                {
                    continue;
                }
                let data = item
                    .get("result")
                    .and_then(|result| result.get("structured_content"))
                    .and_then(|content| content.get("data"))
                    .ok_or_else(|| {
                        CommandError::incomplete("Codex MCP result lacked structured data")
                    })?;
                if let Some(parsed) = parse_m1_status_data(client_id, data, release_version)? {
                    return Ok(parsed);
                }
            }
        }
        "claude-code" => {
            for line in text.lines().rev() {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if value.get("is_error").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                if let Some(result) = value.get("result").and_then(Value::as_str) {
                    if let Some(structured) = parse_embedded_json(result) {
                        let data = structured.get("data").unwrap_or(&structured);
                        if let Some(parsed) =
                            parse_m1_status_data(client_id, data, release_version)?
                        {
                            return Ok(parsed);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Err(CommandError::incomplete(format!(
        "{client_id} did not return completed {QUALIFICATION_TOOL} result for {release_version}"
    )))
}

fn parse_m1_status_data(
    client_id: &str,
    data: &Value,
    release_version: &str,
) -> Result<Option<ParsedClientResult>, CommandError> {
    let observed = data
        .get("releaseVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let count = data
        .get("capabilityCount")
        .and_then(Value::as_u64)
        .unwrap_or_default() as usize;
    if observed != release_version
        || data.get("status").and_then(Value::as_str) != Some("complete")
        || count == 0
    {
        return Ok(None);
    }
    let host_requirements = data
        .get("hostRequirements")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| {
            CommandError::incomplete(format!(
                "{client_id} MCP result lacked host requirement results"
            ))
        })?;
    let capabilities = data
        .get("capabilities")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| {
            CommandError::incomplete(format!(
                "{client_id} MCP result lacked capability availability results"
            ))
        })?;
    let degraded_count = data
        .get("degradedCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CommandError::incomplete(format!(
                "{client_id} MCP result lacked degraded capability count"
            ))
        })? as usize;
    if capabilities.len() != count || degraded_count > count {
        return Err(CommandError::incomplete(format!(
            "{client_id} MCP result has inconsistent capability availability results"
        )));
    }
    Ok(Some(ParsedClientResult {
        observed_release_version: observed.into(),
        capability_count: count,
        host_requirements,
        capabilities,
        degraded_count,
    }))
}

fn parse_embedded_json(text: &str) -> Option<Value> {
    serde_json::from_str(text.trim()).ok().or_else(|| {
        let start = text.find('{')?;
        let end = text.rfind('}')?;
        serde_json::from_str(&text[start..=end]).ok()
    })
}

fn inspect_live_identity(
    host_integrations: &Value,
    development: Option<&legion_host::DevelopmentSetupContext>,
) -> Result<Value, CommandError> {
    if let Some(context) = development {
        let executable = std::env::current_exe().map_err(io_error)?;
        let generation = format!("development:{}", context.process_identity);
        return Ok(json!({
            "origin": legion_host::setup_registry::ORIGIN_DEVELOPMENT,
            "executablePath": executable,
            "installRoot": Value::Null,
            "stableCurrentRoot": Value::Null,
            "stableCurrent": false,
            "resolvedExecutable": std::fs::canonicalize(&executable).ok(),
            "resolvedInstallRoot": Value::Null,
            "generation": generation,
            "port": context.port,
            "processIdentity": context.process_identity,
            "stateRoot": context.state_root,
            "repositoryRoot": context.repository_root,
            "executable": {"path": executable, "origin": legion_host::setup_registry::ORIGIN_DEVELOPMENT, "state": "development", "generation": generation},
            "plugin": Value::Null,
            "projections": host_integrations,
        }));
    }
    let installed = installed_release()?;
    let origin = installed.origin_evidence();
    let executable_path = origin.executable.clone();
    let install_root = origin.install_root.clone().ok_or_else(|| {
        CommandError::incomplete("installed release has no stable product install root")
    })?;
    let stable_current_root = install_root.join("current");
    let resolved_executable = installed
        .resolved_executable_path()
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let resolved_install_root = installed
        .resolved_install_root()
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let generation = format!(
        "{}:{}",
        installed.manifest.release_version, installed.manifest.declarative_assets_sha256
    );
    let executable_state = if installed.manifest.release_version == EXPECTED_RELEASE_VERSION {
        "current"
    } else {
        "stale"
    };
    let executable = json!({
        "path": executable_path.clone(),
        "manifestPath": installed.manifest_path.clone(),
        "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
        "installRoot": install_root.clone(),
        "stableCurrentRoot": stable_current_root.clone(),
        "resolvedExecutable": resolved_executable.clone(),
        "resolvedInstallRoot": resolved_install_root.clone(),
        "generation": generation.clone(),
        "releaseVersion": installed.manifest.release_version.clone(),
        "expectedReleaseVersion": EXPECTED_RELEASE_VERSION,
        "state": executable_state,
        "runtimeDigest": installed.manifest.runtime.sha256.clone(),
        "runtimePlatform": installed.manifest.runtime.platform.clone(),
        "runtimeArchitecture": installed.manifest.runtime.architecture.clone(),
    });
    let plugin = inspect_live_plugin(&installed, host_integrations);
    let projections = inspect_live_projections(&installed, host_integrations);
    Ok(json!({
        "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
        "executablePath": executable_path,
        "installRoot": install_root,
        "stableCurrentRoot": stable_current_root,
        "stableCurrent": origin.stable_current,
        "resolvedExecutable": resolved_executable,
        "resolvedInstallRoot": resolved_install_root,
        "generation": generation,
        "executable": executable,
        "plugin": plugin,
        "projections": projections,
    }))
}

fn inspect_live_plugin(
    installed: &legion_runtime::release_binding::InstalledRelease,
    host_integrations: &Value,
) -> Value {
    if let Some(marketplace) = host_integrations.get("claudeMarketplace") {
        return json!({
            "state": marketplace.get("state"),
            "expectedReleaseVersion": marketplace.get("expectedReleaseVersion"),
            "activeReleaseVersion": marketplace.get("cachedRelease").and_then(|value| value.get("releaseVersion")),
            "nativeMarketplaceRegistered": marketplace.get("nativeMarketplaceRegistered"),
            "nativePlugin": marketplace.get("nativePlugin"),
            "cachedRelease": marketplace.get("cachedRelease"),
            "trust": marketplace.get("trust"),
            "marketplaceRoot": marketplace.get("marketplaceRoot"),
            "detail": marketplace.get("detail"),
        });
    }
    let Some(claude) = integration_inspection(host_integrations, "claudeCodeLegacy") else {
        return json!({
            "state": "not_selected",
            "expectedReleaseVersion": EXPECTED_RELEASE_VERSION,
            "activeReleaseVersion": installed.manifest.release_version,
            "roots": [],
            "cacheMutation": "never",
        });
    };
    let mut roots = BTreeMap::new();
    if let Some(root) = installed.manifest_path.parent().and_then(Path::parent) {
        roots.insert(root.to_path_buf(), ());
    }
    if let Some(root) = installed.manifest_path.parent() {
        roots.insert(root.to_path_buf(), ());
    }
    if let Some(generations) = claude
        .get("pluginCacheGenerations")
        .and_then(Value::as_array)
    {
        for generation in generations {
            if let Some(path) = generation.get("installPath").and_then(Value::as_str) {
                roots.insert(PathBuf::from(path), ());
            }
        }
    }
    let records = roots
        .keys()
        .map(|root| {
            inspect_plugin_root(root, installed.manifest_path.parent(), &installed.manifest)
        })
        .collect::<Vec<_>>();
    let state = if records.iter().any(|record| record["state"] == "current") {
        "current"
    } else if records.iter().any(|record| record["state"] == "stale") {
        "stale"
    } else if records.iter().any(|record| record["state"] == "foreign") {
        "foreign"
    } else {
        "incomplete"
    };
    json!({
        "state": state,
        "expectedReleaseVersion": EXPECTED_RELEASE_VERSION,
        "activeReleaseVersion": installed.manifest.release_version,
        "roots": records,
        "cacheMutation": "never",
    })
}

fn inspect_plugin_root(
    root: &Path,
    canonical_root: Option<&Path>,
    active_manifest: &legion_runtime::ReleaseManifest,
) -> Value {
    let is_canonical_root = canonical_root.is_some_and(|path| path == root);
    let mut manifests = Vec::new();
    let mut manifest_seen = false;
    let mut manifest_matches = false;
    let mut manifest_foreign = false;
    let mut manifest_mismatch = false;
    let mut manifest_invalid = false;
    for relative in PLUGIN_MANIFEST_PATHS {
        let path = root.join(relative);
        if !path.is_file() {
            continue;
        }
        manifest_seen = true;
        match std::fs::read(&path) {
            Ok(bytes) => {
                let digest = legion_catalog::hex_digest(&bytes);
                match serde_json::from_slice::<Value>(&bytes) {
                    Ok(value) => {
                        let name = value.get("name").and_then(Value::as_str);
                        let version = value.get("version").and_then(Value::as_str);
                        let name_ok = name == Some("legion");
                        let version_ok = version == Some(active_manifest.release_version.as_str());
                        if !name_ok {
                            manifest_foreign = true;
                        } else if version_ok {
                            manifest_matches = true;
                        } else if version.is_some_and(|value| !value.trim().is_empty()) {
                            manifest_mismatch = true;
                        } else {
                            manifest_invalid = true;
                        }
                        manifests.push(json!({
                            "path": path,
                            "present": true,
                            "digest": digest,
                            "name": name,
                            "version": version,
                            "expectedVersion": EXPECTED_RELEASE_VERSION,
                            "matchesActiveRelease": name_ok && version_ok,
                        }));
                    }
                    Err(error) => {
                        manifest_invalid = true;
                        manifests.push(json!({
                            "path": path,
                            "present": true,
                            "digest": digest,
                            "error": error.to_string(),
                        }));
                    }
                }
            }
            Err(error) => {
                manifest_invalid = true;
                manifests.push(json!({
                    "path": path,
                    "present": true,
                    "error": error.to_string(),
                }));
            }
        }
    }

    let mut identities = Vec::new();
    let mut identity_seen = false;
    let mut identity_mismatch = false;
    let mut identity_invalid = false;
    let mut canonical_identity_seen = false;
    let mut canonical_identity_matches = false;
    let mut identity_paths = Vec::new();
    if is_canonical_root {
        identity_paths.push((
            "canonical",
            root.join(CANONICAL_NATIVE_RELEASE_IDENTITY_PATH),
        ));
    }
    identity_paths.extend(
        PLUGIN_RELEASE_IDENTITY_PATHS
            .into_iter()
            .map(|relative| ("plugin", root.join(relative))),
    );
    for (kind, path) in identity_paths {
        if !path.is_file() {
            continue;
        }
        identity_seen = true;
        if kind == "canonical" {
            canonical_identity_seen = true;
        }
        match std::fs::read(&path) {
            Ok(bytes) => {
                let digest = legion_catalog::hex_digest(&bytes);
                match legion_runtime::load_release_manifest(&path) {
                    Ok(manifest) => {
                        let matches_active = manifest == *active_manifest;
                        if kind == "canonical" && matches_active {
                            canonical_identity_matches = true;
                        }
                        if !matches_active {
                            identity_mismatch = true;
                        }
                        identities.push(json!({
                            "kind": kind,
                            "path": path,
                            "present": true,
                            "digest": digest,
                            "releaseVersion": manifest.release_version,
                            "matchesActiveRelease": matches_active,
                        }));
                    }
                    Err(error) => {
                        identity_invalid = true;
                        identities.push(json!({
                            "kind": kind,
                            "path": path,
                            "present": true,
                            "digest": digest,
                            "error": error.to_string(),
                        }));
                    }
                }
            }
            Err(error) => {
                identity_invalid = true;
                identities.push(json!({
                    "kind": kind,
                    "path": path,
                    "present": true,
                    "error": error.to_string(),
                }));
            }
        }
    }
    let state = if is_canonical_root {
        if !canonical_identity_seen || manifest_invalid || identity_invalid {
            "incomplete"
        } else if !canonical_identity_matches
            || identity_mismatch
            || active_manifest.release_version != EXPECTED_RELEASE_VERSION
            || manifest_foreign
            || manifest_mismatch
            || (manifest_seen && !manifest_matches)
        {
            "stale"
        } else {
            "current"
        }
    } else if manifest_foreign && !manifest_matches && !manifest_invalid && !identity_seen {
        "foreign"
    } else if !manifest_seen || manifest_invalid || identity_invalid {
        "incomplete"
    } else if !manifest_matches
        || manifest_mismatch
        || identity_mismatch
        || active_manifest.release_version != EXPECTED_RELEASE_VERSION
    {
        "stale"
    } else {
        "current"
    };
    json!({
        "root": root,
        "canonicalNativeRoot": is_canonical_root,
        "state": state,
        "manifests": manifests,
        "releaseIdentities": identities,
        "cacheMutation": "never",
    })
}

fn inspect_live_projections(
    installed: &legion_runtime::release_binding::InstalledRelease,
    host_integrations: &Value,
) -> Value {
    let manifest = &installed.manifest;
    let origin = installed.origin_evidence();
    let executable = origin.executable.clone();
    let install_root = origin.install_root.clone();
    let stable_current_root = install_root.as_ref().map(|path| path.join("current"));
    let resolved_executable = installed.resolved_executable_path().ok();
    let resolved_install_root = installed.resolved_install_root().ok();
    let generation = format!(
        "{}:{}",
        EXPECTED_RELEASE_VERSION, manifest.declarative_assets_sha256
    );
    let mut projections = serde_json::Map::new();
    if let Some(claude) = integration_inspection(host_integrations, "claudeCodeLegacy") {
        let canonical_trusted = claude
            .get("canonicalSkillsRootTrusted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let missing = claude
            .get("canonicalMissingSkillIds")
            .and_then(Value::as_array)
            .map(|values| values.len())
            .unwrap_or(0);
        let cache_error = claude
            .get("pluginCacheError")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let cache_generations = claude
            .get("pluginCacheGenerations")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        let version = value.get("version").and_then(Value::as_str);
                        let canonical = value
                            .get("canonicalGeneration")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let install_exists = value
                            .get("installPathExists")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let manifest_present = value
                            .get("legionPluginManifest")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let state = if !install_exists || !manifest_present {
                            "incomplete"
                        } else if version != Some(EXPECTED_RELEASE_VERSION)
                            || manifest.release_version != EXPECTED_RELEASE_VERSION
                            || !canonical
                        {
                            "stale"
                        } else {
                            "current"
                        };
                        json!({
                            "generation": value.get("generation"),
                            "version": version,
                            "expectedVersion": EXPECTED_RELEASE_VERSION,
                            "canonicalGeneration": canonical,
                            "state": state,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let standalone = claude
            .get("standaloneProjections")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        let ownership = value.get("ownership").cloned().unwrap_or(Value::Null);
                        let unproven = ownership == Value::String("unproven".into());
                        let state = if unproven { "preserved" } else { "stale" };
                        json!({
                            "id": value.get("id"),
                            "path": value.get("path"),
                            "ownership": ownership,
                            "state": state,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let observed_state = if cache_error.is_some() || !canonical_trusted {
            "incomplete"
        } else if missing > 0
            || manifest.release_version != EXPECTED_RELEASE_VERSION
            || cache_generations
                .iter()
                .any(|item| item["state"] == "stale")
            || standalone.iter().any(|item| item["state"] == "stale")
        {
            "stale"
        } else {
            "current"
        };
        let superseded = native_marketplace_owns_components(host_integrations, "claudeMarketplace");
        let state = if superseded {
            "superseded"
        } else {
            observed_state
        };
        projections.insert(
            "claudeCodeLegacy".into(),
            json!({
                "state": state,
                "supersededBy": superseded.then_some("claudeMarketplace"),
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable": executable.clone(),
                "installRoot": install_root.clone(),
                "stableCurrentRoot": stable_current_root.clone(),
                "resolvedExecutable": resolved_executable.clone(),
                "resolvedInstallRoot": resolved_install_root.clone(),
                "generation": generation.clone(),
                "expectedGeneration": generation.clone(),
                "canonicalSkillsRootTrusted": canonical_trusted,
                "canonicalMissingSkillCount": missing,
                "pluginCacheError": cache_error,
                "pluginCacheGenerations": cache_generations,
                "standaloneProjections": standalone,
                "cacheMutation": "never",
            }),
        );
    }
    if let Some(codex) = integration_inspection(host_integrations, "codexSkills") {
        let ledger_error = codex.get("ledgerError").and_then(Value::as_str);
        let statuses = codex
            .get("statuses")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| {
                        let state = value
                            .get("state")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown");
                        json!({
                            "id": value.get("id"),
                            "path": value.get("path"),
                            "state": state,
                            "ledgerGeneration": value.get("ledgerGeneration"),
                            "sourceDigest": value.get("sourceDigest"),
                            "destinationDigest": value.get("destinationDigest"),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let observed_state = if ledger_error.is_some()
            || statuses.iter().any(|item| {
                matches!(
                    item["state"].as_str(),
                    Some("conflict") | Some("foreign") | Some("retired_conflict")
                )
            }) {
            "incomplete"
        } else if manifest.release_version != EXPECTED_RELEASE_VERSION
            || statuses.iter().any(|item| {
                matches!(
                    item["state"].as_str(),
                    Some("missing") | Some("stale") | Some("retired_owned")
                )
            })
        {
            "stale"
        } else {
            "current"
        };
        let superseded = native_marketplace_owns_components(host_integrations, "codexMarketplace");
        let state = if superseded {
            "superseded"
        } else {
            observed_state
        };
        projections.insert(
            "codexSkills".into(),
            json!({
                "state": state,
                "supersededBy": superseded.then_some("codexMarketplace"),
                "explicitOnly": codex
                    .get("explicitOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable": executable.clone(),
                "installRoot": install_root.clone(),
                "stableCurrentRoot": stable_current_root.clone(),
                "resolvedExecutable": resolved_executable.clone(),
                "resolvedInstallRoot": resolved_install_root.clone(),
                "generation": generation.clone(),
                "expectedGeneration": generation.clone(),
                "ledgerError": ledger_error,
                "statuses": statuses,
            }),
        );
    }
    for (client_id, key) in [
        (legion_host::setup_registry::CLIENT_CLAUDE, "claudePlugin"),
        (legion_host::setup_registry::CLIENT_CODEX, "codexPlugin"),
        (legion_host::setup_registry::CLIENT_CURSOR, "cursorPlugin"),
        (legion_host::setup_registry::CLIENT_PI, "piSkills"),
        (
            legion_host::setup_registry::CLIENT_ANTIGRAVITY,
            "antigravityPlugin",
        ),
    ] {
        let Some(projection) = integration_inspection(host_integrations, key) else {
            continue;
        };
        let state = projection
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        projections.insert(
            key.into(),
            json!({
                "clientId": client_id,
                "selectedMechanism": projection.get("selectedMechanism"),
                "projection": projection.get("projection"),
                "state": state,
                "origin": projection
                    .get("origin")
                    .cloned()
                    .unwrap_or_else(|| Value::String(legion_host::setup_registry::ORIGIN_INSTALLED.into())),
                "ownership": projection.get("ownership"),
                "executable": projection
                    .get("executable")
                    .cloned()
                    .unwrap_or_else(|| json!(executable.clone())),
                "installRoot": projection
                    .get("installRoot")
                    .cloned()
                    .unwrap_or_else(|| json!(install_root.clone())),
                "stableCurrentRoot": projection
                    .get("stableCurrentRoot")
                    .cloned()
                    .unwrap_or_else(|| json!(stable_current_root.clone())),
                "resolvedExecutable": projection
                    .get("resolvedExecutable")
                    .cloned()
                    .unwrap_or_else(|| json!(resolved_executable.clone())),
                "resolvedInstallRoot": projection
                    .get("resolvedInstallRoot")
                    .cloned()
                    .unwrap_or_else(|| json!(resolved_install_root.clone())),
                "targetRoot": projection.get("targetRoot"),
                "expectedGeneration": projection.get("expectedGeneration"),
                "generation": projection.get("generation"),
                "executableRegistration": projection.get("executableRegistration"),
                "explicitOnly": projection.get("explicitOnly"),
                "missingSurfaces": projection.get("missingSurfaces"),
                "preserved": projection.get("preserved"),
                "conflicts": projection.get("conflicts"),
            }),
        );
    }
    for (client_id, key) in [
        (
            legion_host::setup_registry::CLIENT_CLAUDE,
            "claudeMarketplace",
        ),
        (
            legion_host::setup_registry::CLIENT_CODEX,
            "codexMarketplace",
        ),
    ] {
        let Some(marketplace) = host_integrations.get(key) else {
            continue;
        };
        projections.insert(
            key.into(),
            json!({
                "clientId": client_id,
                "state": marketplace.get("state"),
                "marketplaceName": marketplace.get("marketplaceName"),
                "pluginName": marketplace.get("pluginName"),
                "nativeMarketplaceRegistered": marketplace.get("nativeMarketplaceRegistered"),
                "nativePlugin": marketplace.get("nativePlugin"),
                "cachedRelease": marketplace.get("cachedRelease"),
                "trust": marketplace.get("trust"),
                "expectedReleaseVersion": marketplace.get("expectedReleaseVersion"),
                "expectedRuntimeSha256": marketplace.get("expectedRuntimeSha256"),
                "marketplaceRoot": marketplace.get("marketplaceRoot"),
                "detail": marketplace.get("detail"),
            }),
        );
    }
    Value::Object(projections)
}

fn integration_inspection<'a>(integrations: &'a Value, key: &str) -> Option<&'a Value> {
    let value = integrations.get(key)?;
    if value.get("canonicalSkillsRootTrusted").is_some()
        || value.get("destinationRoot").is_some()
        || value.get("targetRoot").is_some()
        || value.get("projection").is_some()
    {
        return Some(value);
    }
    value.get("inspection").or_else(|| {
        value
            .get("preview")
            .and_then(|preview| preview.get("inspection"))
    })
}

fn native_marketplace_owns_components(integrations: &Value, key: &str) -> bool {
    let Some(marketplace) = integrations.get(key) else {
        return false;
    };
    matches!(
        marketplace.get("state").and_then(Value::as_str),
        Some("current" | "disabled")
    ) && marketplace
        .get("marketplaceSourceCurrent")
        .and_then(Value::as_bool)
        == Some(true)
        && marketplace
            .get("nativeMarketplaceRegistered")
            .and_then(Value::as_bool)
            == Some(true)
        && marketplace
            .get("nativePlugin")
            .and_then(|plugin| plugin.get("installed"))
            .and_then(Value::as_bool)
            == Some(true)
        && marketplace
            .get("cachedRelease")
            .is_some_and(|release| release.is_object())
}

fn supersede_legacy_marketplace_observations(integrations: &mut Value) {
    for (legacy_key, native_key) in [
        ("claudeCodeLegacy", "claudeMarketplace"),
        ("codexSkills", "codexMarketplace"),
        ("claudePlugin", "claudeMarketplace"),
        ("codexPlugin", "codexMarketplace"),
    ] {
        if !native_marketplace_owns_components(integrations, native_key) {
            continue;
        }
        let Some(legacy) = integrations
            .get_mut(legacy_key)
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let old_state = legacy
            .get("state")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(old_state) = old_state {
            legacy.insert("legacyState".into(), Value::String(old_state));
        }
        legacy.insert("state".into(), Value::String("superseded".into()));
        legacy.insert("supersededBy".into(), Value::String(native_key.into()));

        if let Some(remediation) = legacy.get_mut("remediation").and_then(Value::as_array_mut) {
            remediation.retain(|message| {
                let Some(message) = message.as_str() else {
                    return true;
                };
                match legacy_key {
                    "claudeCodeLegacy" => {
                        !message.contains("non-canonical Legion plugin cache generation")
                    }
                    "codexSkills" => {
                        let stale_plain_skill = message.contains("Codex plain skill")
                            && (message.contains("is missing")
                                || message.contains(
                                    "is an unchanged Legion projection from an older generation",
                                ));
                        let retired_owned_skill = message
                            .starts_with("Retired Legion Codex skill ")
                            && message.contains("is intact and can be removed safely");
                        !stale_plain_skill && !retired_owned_skill
                    }
                    "claudePlugin" | "codexPlugin" => {
                        !message.contains("legion setup repair --confirm")
                    }
                    _ => true,
                }
            });
        }
    }

    if native_marketplace_owns_components(integrations, "codexMarketplace") {
        if let Some(statuses) = integrations
            .get_mut("codexSkills")
            .and_then(|value| value.get_mut("statuses"))
            .and_then(Value::as_array_mut)
        {
            for status in statuses {
                let Some(object) = status.as_object_mut() else {
                    continue;
                };
                let old_state = object.get("state").and_then(Value::as_str);
                if matches!(old_state, Some("missing" | "stale" | "retired_owned")) {
                    object.insert(
                        "legacyState".into(),
                        Value::String(old_state.unwrap().to_owned()),
                    );
                    object.insert("state".into(), Value::String("superseded".into()));
                }
            }
        }
    }
}

fn setup_health(
    clients: &Value,
    host_integrations: &Value,
    live_identity: &Value,
) -> (&'static str, Vec<String>) {
    setup_health_for_action(
        clients,
        host_integrations,
        live_identity,
        &legion_host::SetupAction::Repair,
    )
}

fn setup_health_for_action(
    clients: &Value,
    host_integrations: &Value,
    live_identity: &Value,
    action: &legion_host::SetupAction,
) -> (&'static str, Vec<String>) {
    let mut remediation = Vec::new();
    let destructive_lifecycle = matches!(
        action,
        legion_host::SetupAction::Disable
            | legion_host::SetupAction::Remove
            | legion_host::SetupAction::Purge
    );
    // Advisory notes about projections Legion deliberately declines to create.
    // They are reported, but an operator's opt-out is not an incomplete setup.
    let mut opt_in_notes: Vec<String> = Vec::new();
    let active_clients = clients
        .as_array()
        .into_iter()
        .flatten()
        .filter(|client| client.get("installed").and_then(Value::as_bool) == Some(true))
        .filter_map(|client| {
            client
                .get("clientId")
                .or_else(|| client.get("client_id"))
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let optional_baseline_clients = clients
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|client| {
            let client_id = client
                .get("clientId")
                .or_else(|| client.get("client_id"))
                .and_then(Value::as_str)?;
            let fidelity = client.get("fidelity").and_then(Value::as_str)?;
            let profile = legion_host::setup_registry::client_boundary(client_id)?;
            (client.get("installed").and_then(Value::as_bool) == Some(true)
                && fidelity == "Baseline"
                && profile.explicit_only)
                .then_some(client_id)
        })
        .collect::<BTreeSet<_>>();
    let has_full_supported_client = clients.as_array().into_iter().flatten().any(|client| {
        client.get("installed").and_then(Value::as_bool) == Some(true)
            && client.get("fidelity").and_then(Value::as_str) == Some("Full")
            && client
                .get("clientId")
                .or_else(|| client.get("client_id"))
                .and_then(Value::as_str)
                .is_some_and(|client_id| {
                    client_id != legion_host::setup_registry::CLIENT_PI
                        && legion_host::setup_registry::client_boundary(client_id)
                            .is_some_and(|profile| profile.executable_registration)
                })
    });
    let installed = live_identity.get("origin").and_then(Value::as_str)
        == Some(legion_host::setup_registry::ORIGIN_INSTALLED);
    let repair_command = if installed {
        "run legion setup repair --confirm"
    } else {
        "rerun setup --development with identical context and repair --confirm"
    };
    if installed && live_identity.get("stableCurrent").and_then(Value::as_bool) != Some(true) {
        remediation.push("production executable is not bound to stable current; run legion setup repair --confirm".into());
    }
    let executable_path = live_identity.get("executablePath").or_else(|| {
        live_identity
            .get("executable")
            .and_then(|value| value.get("path"))
    });
    if installed
        && !binding_fields_current(
            live_identity.get("origin").and_then(Value::as_str),
            executable_path,
            live_identity.get("installRoot"),
        )
    {
        remediation.push("production executable binding escaped stable current; run legion setup repair --confirm".into());
    }
    if installed
        && !resolved_binding_current(
            live_identity.get("origin").and_then(Value::as_str),
            executable_path,
            live_identity.get("installRoot"),
            live_identity.get("resolvedExecutable"),
            live_identity.get("resolvedInstallRoot"),
        )
    {
        remediation.push(
            "production executable resolved target escaped active release; run legion setup repair --confirm"
                .into(),
        );
    }
    if installed
        && live_identity
            .get("generation")
            .and_then(Value::as_str)
            .is_none()
    {
        remediation.push(
            "production executable generation is unavailable; run legion setup repair --confirm"
                .into(),
        );
    }
    if installed && live_identity["executable"]["state"] != "current" {
        remediation.push(format!(
            "live Legion executable is stale ({}; expected {})",
            live_identity["executable"]["releaseVersion"]
                .as_str()
                .unwrap_or("unknown"),
            EXPECTED_RELEASE_VERSION
        ));
    }
    if !destructive_lifecycle && !optional_baseline_clients.is_empty() && !has_full_supported_client
    {
        remediation
            .push("optional Pi Baseline is present but no Full supported client is active".into());
    }
    match clients.as_array() {
        Some(values) if values.is_empty() && !destructive_lifecycle => {
            let unobserved = ["claudeMarketplace", "codexMarketplace"].iter().all(|key| {
                matches!(
                    live_identity["projections"][key]["state"].as_str(),
                    Some("client_unavailable" | "not_selected")
                )
            });
            if unobserved {
                opt_in_notes.push(
                    "native client integrations are unobserved because no supported client is installed".into(),
                );
            } else {
                remediation
                    .push("no supported client is registered with complete setup evidence".into());
            }
        }
        Some(values) if destructive_lifecycle => {
            for client in values {
                let client_id = client
                    .get("clientId")
                    .or_else(|| client.get("client_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if !active_clients.contains(client_id) {
                    opt_in_notes.push(format!(
                        "client {client_id} was already absent during requested lifecycle action"
                    ));
                }
            }
        }
        Some(values) => {
            for client in values {
                let installed = client
                    .get("installed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let fidelity = client
                    .get("fidelity")
                    .and_then(Value::as_str)
                    .unwrap_or("Unavailable");
                let client_id = client
                    .get("clientId")
                    .or_else(|| client.get("client_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let pi_baseline =
                    client_id == legion_host::setup_registry::CLIENT_PI && fidelity == "Baseline";
                if installed
                    && (optional_baseline_clients.contains(client_id)
                        || (pi_baseline
                            && legion_host::setup_registry::client_boundary(client_id)
                                .is_some_and(|profile| profile.explicit_only)))
                {
                    let missing = client
                        .get("missingSurfaces")
                        .or_else(|| client.get("missing_surfaces"))
                        .and_then(Value::as_array)
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| "skills-only host surface".into());
                    opt_in_notes.push(format!(
                        "client {client_id} is optional (Baseline); missing {missing}; default setup leaves it unselected"
                    ));
                    continue;
                }
                if !installed || (fidelity != "Full" && !pi_baseline) {
                    remediation.push(format!(
                        "client {} is incomplete ({fidelity}); {repair_command}",
                        client_id
                    ));
                }
            }
        }
        None if destructive_lifecycle => opt_in_notes
            .push("no registered clients were observed during requested lifecycle action".into()),
        None => remediation.push("setup client status is unavailable".into()),
    }
    if let Some(plugin_state) = live_identity["plugin"]["state"].as_str() {
        let action_state_ok = match action {
            legion_host::SetupAction::Disable => {
                matches!(
                    plugin_state,
                    "disabled" | "absent" | "not_selected" | "client_unavailable"
                )
            }
            legion_host::SetupAction::Remove | legion_host::SetupAction::Purge => {
                matches!(
                    plugin_state,
                    "absent" | "not_selected" | "client_unavailable"
                )
            }
            _ => matches!(
                plugin_state,
                "current" | "disabled" | "not_selected" | "client_unavailable"
            ),
        };
        if !action_state_ok {
            remediation.push(format!(
                "Claude plugin identity is {plugin_state}; repair observes cache and preserves its files"
            ));
        }
    }
    for (client_id, key) in [
        (
            legion_host::setup_registry::CLIENT_CLAUDE,
            "claudeMarketplace",
        ),
        (
            legion_host::setup_registry::CLIENT_CODEX,
            "codexMarketplace",
        ),
    ] {
        let Some(marketplace) = live_identity["projections"].get(key) else {
            continue;
        };
        let state = marketplace
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unavailable");
        if matches!(state, "client_unavailable" | "not_selected") {
            opt_in_notes.push(format!(
                "{client_id} native marketplace is {state}; client integration was not claimed"
            ));
        } else if active_clients.contains(client_id)
            && !match action {
                legion_host::SetupAction::Disable => matches!(state, "disabled" | "absent"),
                legion_host::SetupAction::Remove | legion_host::SetupAction::Purge => {
                    state == "absent"
                }
                _ => matches!(state, "current" | "disabled"),
            }
        {
            remediation.push(format!(
                "{client_id} native marketplace is {state}; {repair_command}"
            ));
        }
    }
    if let Some(projections) = live_identity["projections"].as_object() {
        for (client, projection) in projections {
            // Native marketplace state is evaluated below with action-aware
            // rules. It is not a legacy file projection and disabled/removed
            // states must not be reclassified as stale copy projections here.
            if matches!(client.as_str(), "claudeMarketplace" | "codexMarketplace") {
                continue;
            }
            let projection_client =
                projection
                    .get("clientId")
                    .and_then(Value::as_str)
                    .or_else(|| match client.as_str() {
                        "claudeCodeLegacy" | "claudePlugin" => {
                            Some(legion_host::setup_registry::CLIENT_CLAUDE)
                        }
                        "codexSkills" | "codexPlugin" => {
                            Some(legion_host::setup_registry::CLIENT_CODEX)
                        }
                        "cursorPlugin" => Some(legion_host::setup_registry::CLIENT_CURSOR),
                        "piSkills" => Some(legion_host::setup_registry::CLIENT_PI),
                        "antigravityPlugin" => {
                            Some(legion_host::setup_registry::CLIENT_ANTIGRAVITY)
                        }
                        _ => None,
                    });
            if projection_client.is_some_and(|id| !active_clients.contains(id)) {
                if projection_client == Some(legion_host::setup_registry::CLIENT_PI)
                    && projection.get("explicitOnly").and_then(Value::as_bool) == Some(true)
                {
                    let state = projection
                        .get("state")
                        .and_then(Value::as_str)
                        .unwrap_or("unavailable");
                    let missing = projection
                        .get("missingSurfaces")
                        .and_then(Value::as_array)
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| {
                            "executableToolSurface, mcpLifecycle, releaseBinding, executableResolution, hostEnforcement".into()
                        });
                    opt_in_notes.push(format!(
                        "pi projection is {state}; client is optional Baseline with missing {missing}; default setup leaves it unselected"
                    ));
                }
                continue;
            }
            let retired_native_projection = match client.as_str() {
                "claudeCodeLegacy" | "claudePlugin" => Some("claudeMarketplace"),
                "codexSkills" | "codexPlugin" => Some("codexMarketplace"),
                _ => None,
            }
            .is_some_and(|key| {
                let state = live_identity["projections"][key]["state"].as_str();
                matches!(state, Some("current" | "disabled"))
                    || (destructive_lifecycle && state == Some("absent"))
            });
            if retired_native_projection {
                continue;
            }
            if projection_client.is_some_and(|id| optional_baseline_clients.contains(id)) {
                if let Some(state) = projection.get("state").and_then(Value::as_str) {
                    opt_in_notes.push(format!(
                        "{client} projection is {state}; client is optional Baseline and default setup leaves it unselected"
                    ));
                }
                continue;
            }
            let projection_state = projection.get("state").and_then(Value::as_str);
            let opt_in = projection
                .get("explicitOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let no_projection_ownership = projection
                .get("ownership")
                .and_then(Value::as_str)
                .is_some_and(|ownership| ownership == "available");
            let no_codex_skill_projection = projection
                .get("statuses")
                .and_then(Value::as_array)
                .is_some_and(|statuses| {
                    !statuses.is_empty()
                        && statuses.iter().all(|status| {
                            status.get("state").and_then(Value::as_str) == Some("missing")
                                && status
                                    .get("ledgerGeneration")
                                    .and_then(Value::as_str)
                                    .is_none()
                                && status.get("destinationDigest").is_none_or(Value::is_null)
                        })
                });
            // An opt-in projection with no generation & no recorded Legion
            // ownership has never been created. Its installed binding fields
            // are inherited identity, not evidence that an opt-in projection
            // escaped the active release.
            let opt_in_never_created = opt_in
                && projection_state != Some("current")
                && projection
                    .get("generation")
                    .and_then(Value::as_str)
                    .is_none()
                && (no_projection_ownership || no_codex_skill_projection);
            if let Some(state) = projection.get("state").and_then(Value::as_str) {
                if state != "current" {
                    // An opt-in client is maintained only where a projection
                    // already exists and is never created, so naming the repair
                    // command here sends the operator to a command that will
                    // deliberately do nothing.
                    if opt_in {
                        opt_in_notes.push(format!(
                            "{client} projection is {state}; this client is opt-in, so repair leaves it alone. Create its projection deliberately, or ignore this."
                        ));
                    } else {
                        remediation
                            .push(format!("{client} projection is {state}; {repair_command}"));
                    }
                }
            }
            if installed
                && !opt_in_never_created
                && projection.get("origin").is_some()
                && !binding_fields_current(
                    projection.get("origin").and_then(Value::as_str),
                    projection.get("executable"),
                    projection.get("installRoot"),
                )
            {
                remediation.push(format!(
                    "{client} production binding escaped stable current; run legion setup repair --confirm"
                ));
            }
            if installed
                && !opt_in_never_created
                && projection.get("origin").is_some()
                && !resolved_binding_current(
                    projection.get("origin").and_then(Value::as_str),
                    projection.get("executable"),
                    projection.get("installRoot"),
                    projection.get("resolvedExecutable"),
                    projection.get("resolvedInstallRoot"),
                )
            {
                remediation.push(format!(
                    "{client} resolved target escaped active release; run legion setup repair --confirm"
                ));
            }
            if installed
                && !opt_in_never_created
                && projection.get("origin").is_some()
                && projection
                    .get("generation")
                    .and_then(Value::as_str)
                    .is_none()
            {
                remediation.push(format!(
                    "{client} production generation is unavailable; run legion setup repair --confirm"
                ));
            }
            if let (Some(expected), Some(actual)) = (
                live_identity.get("generation").and_then(Value::as_str),
                projection.get("generation").and_then(Value::as_str),
            ) {
                if expected != actual {
                    let message =
                        format!("{client} generation {actual} is stale; {repair_command}");
                    if opt_in {
                        opt_in_notes.push(format!(
                            "{client} generation {actual} is stale; this client is opt-in, so repair leaves it alone. Create its projection deliberately, or ignore this."
                        ));
                    } else {
                        remediation.push(message);
                    }
                }
            }
        }
    }
    // Keep direct host observations in output-derived health so repair result
    // shapes (inspection nested under `preview`) remain truthful too.
    if active_clients.contains(legion_host::setup_registry::CLIENT_CODEX)
        && integration_inspection(host_integrations, "codexSkills")
            .and_then(|value| value.get("ledgerError"))
            .is_some_and(|value| !value.is_null())
    {
        remediation.push(
            "Codex ownership ledger is invalid; conflicting projections are preserved".into(),
        );
    }
    remediation.sort();
    remediation.dedup();
    let status = if remediation.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    opt_in_notes.sort();
    opt_in_notes.dedup();
    remediation.extend(opt_in_notes);
    (status, remediation)
}

fn binding_fields_current(
    origin: Option<&str>,
    executable: Option<&Value>,
    install_root: Option<&Value>,
) -> bool {
    if origin != Some(legion_host::setup_registry::ORIGIN_INSTALLED) {
        return false;
    }
    let Some(executable) = executable.and_then(Value::as_str) else {
        return false;
    };
    let Some(install_root) = install_root.and_then(Value::as_str) else {
        return false;
    };
    let executable = Path::new(executable);
    let install_root = Path::new(install_root);
    if !executable.is_absolute()
        || !install_root.is_absolute()
        || executable
            .components()
            .chain(install_root.components())
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    if executable.components().any(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        matches!(
            name.to_string_lossy().to_ascii_lowercase().as_str(),
            "repo" | "dist" | "target" | "node_modules"
        )
    }) || install_root.components().any(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        matches!(
            name.to_string_lossy().to_ascii_lowercase().as_str(),
            "repo" | "dist" | "target" | "node_modules"
        )
    }) {
        return false;
    }
    let Some(bin) = executable.parent() else {
        return false;
    };
    let Some(root) = bin.parent() else {
        return false;
    };
    let stable_current_root = install_root.join("current");
    let executable_name_matches = executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            if cfg!(windows) {
                name.eq_ignore_ascii_case("legion.exe")
            } else {
                name == "legion"
            }
        });
    path_name_is(bin, "bin")
        && path_name_is(root, "current")
        && (paths_equal(root, &stable_current_root)
            || windows_localcache_equivalent(&stable_current_root, root, install_root))
        && executable_name_matches
}

fn resolved_binding_current(
    origin: Option<&str>,
    executable: Option<&Value>,
    install_root: Option<&Value>,
    resolved_executable: Option<&Value>,
    resolved_install_root: Option<&Value>,
) -> bool {
    if !binding_fields_current(origin, executable, install_root) {
        return false;
    }
    let Some(install_root) = install_root.and_then(Value::as_str) else {
        return false;
    };
    let Some(resolved_executable) = resolved_executable.and_then(Value::as_str) else {
        return false;
    };
    let Some(resolved_install_root) = resolved_install_root.and_then(Value::as_str) else {
        return false;
    };
    let install_root = Path::new(install_root);
    let resolved_executable = Path::new(resolved_executable);
    let resolved_install_root = Path::new(resolved_install_root);
    let Ok(canonical_install_root) = std::fs::canonicalize(install_root) else {
        return false;
    };
    if !resolved_executable.is_absolute()
        || !resolved_install_root.is_absolute()
        || resolved_executable
            .components()
            .chain(resolved_install_root.components())
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    if resolved_executable
        .components()
        .chain(resolved_install_root.components())
        .any(|component| {
            let Component::Normal(name) = component else {
                return false;
            };
            matches!(
                name.to_string_lossy().to_ascii_lowercase().as_str(),
                "repo" | "dist" | "target" | "node_modules"
            )
        })
    {
        return false;
    }
    let stable_current_root = install_root.join("current");
    let resolved_root_matches = path_starts_with(resolved_install_root, &canonical_install_root)
        || windows_localcache_equivalent(&stable_current_root, resolved_install_root, install_root);
    let resolved_current = resolved_executable.parent().and_then(Path::parent);
    let under_resolved_root = path_starts_with(resolved_executable, resolved_install_root)
        || resolved_current.is_some_and(|current| {
            path_starts_with(current, resolved_install_root)
                || windows_localcache_equivalent(resolved_install_root, current, install_root)
        });
    let resolved_executable_matches = under_resolved_root
        && (path_starts_with(resolved_executable, &canonical_install_root)
            || windows_localcache_equivalent(
                Path::new(
                    executable
                        .and_then(Value::as_str)
                        .expect("binding field checked"),
                ),
                resolved_executable,
                install_root,
            )
            || windows_localcache_within(&stable_current_root, resolved_executable, install_root));
    resolved_root_matches
        && resolved_executable_matches
        && resolved_executable
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                if cfg!(windows) {
                    name.eq_ignore_ascii_case("legion.exe")
                } else {
                    name == "legion"
                }
            })
}

/// Windows packaged hosts may resolve `%LOCALAPPDATA%` through
/// `Packages/<family>/LocalCache/Local`. Accept that OS virtualization only
/// when removing its exact prefix recreates the already-validated lexical
/// stable-current path.
fn windows_localcache_within(lexical: &Path, resolved: &Path, install_root: &Path) -> bool {
    if windows_localcache_equivalent(lexical, resolved, install_root) {
        return true;
    }
    let Some(local_app_data) = install_root.parent().and_then(Path::parent) else {
        return false;
    };
    let normalize = |path: &Path| {
        let normalized = path.to_string_lossy().replace('\\', "/");
        let normalized = normalized.strip_prefix("//?/").unwrap_or(&normalized);
        normalized
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
            .map(|component| component.to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let local = normalize(local_app_data);
    let lexical = normalize(lexical);
    let resolved = normalize(resolved);
    if lexical.len() <= local.len()
        || resolved.len() <= local.len() + 4
        || lexical[..local.len()] != local
        || resolved[..local.len()] != local
    {
        return false;
    }
    let virtual_prefix = &resolved[local.len()..local.len() + 4];
    if virtual_prefix[0] != "packages"
        || virtual_prefix[1].is_empty()
        || virtual_prefix[2] != "localcache"
        || virtual_prefix[3] != "local"
    {
        return false;
    }
    let lexical_suffix = &lexical[local.len()..];
    let resolved_suffix = &resolved[local.len() + 4..];
    resolved_suffix.len() >= lexical_suffix.len()
        && resolved_suffix[..lexical_suffix.len()] == lexical_suffix[..]
}

fn windows_localcache_equivalent(lexical: &Path, resolved: &Path, install_root: &Path) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let Some(local_app_data) = install_root.parent().and_then(Path::parent) else {
        return false;
    };
    let normalize = |path: &Path| {
        let normalized = path.to_string_lossy().replace('\\', "/");
        let normalized = normalized.strip_prefix("//?/").unwrap_or(&normalized);
        normalized
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
            .map(|component| component.to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let local = normalize(local_app_data);
    let lexical = normalize(lexical);
    let resolved = normalize(resolved);
    if lexical.len() <= local.len()
        || resolved.len() <= local.len() + 4
        || lexical[..local.len()] != local
        || resolved[..local.len()] != local
    {
        return false;
    }
    let virtual_prefix = &resolved[local.len()..local.len() + 4];
    virtual_prefix[0] == "packages"
        && !virtual_prefix[1].is_empty()
        && virtual_prefix[2] == "localcache"
        && virtual_prefix[3] == "local"
        && resolved[local.len() + 4..] == lexical[local.len()..]
}

fn path_name_is(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|actual| {
            if cfg!(windows) {
                actual.eq_ignore_ascii_case(expected)
            } else {
                actual == expected
            }
        })
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        (path_starts_with(left, right) && path_starts_with(right, left))
            || match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
                (Ok(left), Ok(right)) => {
                    path_starts_with(&left, &right) && path_starts_with(&right, &left)
                }
                _ => false,
            }
    } else {
        left == right
    }
}

fn path_starts_with(path: &Path, root: &Path) -> bool {
    if !cfg!(windows) {
        return path.starts_with(root);
    }
    let normalize = |path: &Path| {
        let normalized = path.to_string_lossy().replace('\\', "/");
        let normalized = normalized.strip_prefix("//?/").unwrap_or(&normalized);
        let normalized = normalized.strip_prefix("UNC/").unwrap_or(normalized);
        normalized
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
            .map(|component| component.to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let lexical_starts_with = |path: &Path, root: &Path| {
        let path = normalize(path);
        let root = normalize(root);
        path.len() >= root.len()
            && path
                .iter()
                .zip(root.iter())
                .all(|(path, root)| path == root)
    };
    lexical_starts_with(path, root)
        || match (std::fs::canonicalize(path), std::fs::canonicalize(root)) {
            (Ok(path), Ok(root)) => lexical_starts_with(&path, &root),
            _ => false,
        }
}

fn enrich_client_statuses(mut clients: Value, live_identity: &Value) -> Value {
    let Some(values) = clients.as_array_mut() else {
        return clients;
    };
    let origin = live_identity
        .get("origin")
        .cloned()
        .unwrap_or_else(|| Value::String(legion_host::setup_registry::ORIGIN_INSTALLED.into()));
    let executable = live_identity
        .get("executablePath")
        .cloned()
        .or_else(|| {
            live_identity
                .get("executable")
                .and_then(|value| value.get("path"))
                .cloned()
        })
        .unwrap_or(Value::Null);
    let install_root = live_identity
        .get("installRoot")
        .cloned()
        .unwrap_or(Value::Null);
    let stable_current_root = live_identity
        .get("stableCurrentRoot")
        .cloned()
        .unwrap_or(Value::Null);
    let resolved_executable = live_identity
        .get("resolvedExecutable")
        .cloned()
        .unwrap_or(Value::Null);
    let resolved_install_root = live_identity
        .get("resolvedInstallRoot")
        .cloned()
        .unwrap_or(Value::Null);
    let generation = live_identity
        .get("generation")
        .cloned()
        .unwrap_or(Value::Null);
    for value in values {
        let Some(object) = value.as_object_mut() else {
            continue;
        };
        let Some(client_id) = object
            .get("clientId")
            .or_else(|| object.get("client_id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let Some(profile) = legion_host::setup_registry::client_boundary(&client_id) else {
            continue;
        };
        object.insert("clientId".into(), Value::String(client_id));
        object.insert(
            "selectedMechanism".into(),
            Value::String(profile.selected_mechanism),
        );
        object.insert("projection".into(), Value::String(profile.projection));
        object.insert(
            "executableRegistration".into(),
            Value::Bool(profile.executable_registration),
        );
        object.insert("explicitOnly".into(), Value::Bool(profile.explicit_only));
        object.insert("origin".into(), origin.clone());
        object.insert("executable".into(), executable.clone());
        object.insert("installRoot".into(), install_root.clone());
        object.insert("stableCurrentRoot".into(), stable_current_root.clone());
        object.insert("resolvedExecutable".into(), resolved_executable.clone());
        object.insert("resolvedInstallRoot".into(), resolved_install_root.clone());
        object.insert("generation".into(), generation.clone());
    }
    clients
}

fn inspect_stored_live_qualification(
    clients: &[legion_host::ClientStatus],
    release: &legion_host::BoundRelease,
    platform_state_root: &Path,
) -> Value {
    let mut reports = Vec::new();
    for client in clients.iter().filter(|client| {
        client.installed
            && legion_host::setup_registry::client_supports_live_qualification(&client.client_id)
    }) {
        let root = platform_state_root.join("qualification");
        let command_path = root.join(format!("{}-command.json", client.client_id));
        let qualification_path = root.join(format!("{}-qualification.json", client.client_id));
        let command_ref = command_path.to_string_lossy().into_owned();
        let qualification_ref = qualification_path.to_string_lossy().into_owned();
        if !command_path.is_file() || !qualification_path.is_file() {
            reports.push(json!({
                "clientId": client.client_id,
                "status": "not_run",
                "commandProofRef": Value::Null,
                "qualificationEvidenceRef": Value::Null,
                "detail": "run legion setup qualify after authenticating this client",
            }));
            continue;
        }
        let parsed = std::fs::read(&command_path)
            .map_err(io_error)
            .and_then(|bytes| {
                serde_json::from_slice::<ClientCommandProof>(&bytes).map_err(io_error)
            });
        let qualification = std::fs::read(&qualification_path)
            .map_err(io_error)
            .and_then(|bytes| {
                serde_json::from_slice::<ClientQualificationProof>(&bytes).map_err(io_error)
            });
        let validation = match (parsed, qualification) {
            (Ok(command), Ok(qualification)) => validate_proof_pair(
                &legion_host::ClientEvidence {
                    client_id: client.client_id.clone(),
                    detected: true,
                    mechanisms: vec![QUALIFICATION_MECHANISM.into()],
                    command_proof_ref: Some(command_ref.clone()),
                    qualification_evidence_ref: Some(qualification_ref.clone()),
                },
                release,
                &command_path,
                &qualification_path,
                &command,
                &qualification,
            ),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        match validation {
            Ok(()) => reports.push(json!({
                "clientId": client.client_id,
                "status": "qualified",
                "commandProofRef": command_ref,
                "qualificationEvidenceRef": qualification_ref,
                "detail": "stored authenticated MCP qualification matches installed release",
            })),
            Err(error) => reports.push(json!({
                "clientId": client.client_id,
                "status": "stale",
                "commandProofRef": command_ref,
                "qualificationEvidenceRef": qualification_ref,
                "detail": error.message,
            })),
        }
    }
    let qualified = reports
        .iter()
        .filter(|report| report["status"] == "qualified")
        .count();
    let status = if reports.is_empty() {
        "not_applicable"
    } else if qualified == reports.len() {
        "qualified"
    } else if reports.iter().any(|report| report["status"] == "stale") {
        "stale"
    } else if qualified > 0 {
        "partial"
    } else {
        "not_run"
    };
    json!({
        "status": status,
        "clients": reports,
        "activationRequired": false,
    })
}

struct HostIntegrationInputs {
    claude: Option<legion_host::ClaudeLegacyInput>,
    codex: Option<legion_host::CodexSkillsInput>,
    marketplaces: Vec<legion_host::MarketplaceBinding>,
    client_projections: Vec<legion_host::setup_registry::ClientProjectionInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MarketplaceRefreshTransaction {
    kind: String,
    schema_version: u32,
    client_id: String,
    was_installed: bool,
    was_enabled: Option<bool>,
    prior_version: Option<String>,
    prior_cache_path: Option<String>,
    prior_cached_release: Value,
    original_marketplace_root: String,
    prior_plugin_sha256: String,
    snapshot_root: String,
    stage: String,
}

const MARKETPLACE_REFRESH_KIND: &str = "legion-native-marketplace-refresh-v1";

fn marketplace_refresh_root(request: &legion_host::SetupRequest) -> PathBuf {
    request
        .platform_state_root
        .join("integrations/native-refresh/claude")
}

fn load_marketplace_refresh(
    request: &legion_host::SetupRequest,
) -> Result<Option<MarketplaceRefreshTransaction>, CommandError> {
    let root = marketplace_refresh_root(request);
    let marker = root.join("pending.json");
    let bytes = match std::fs::read(&marker) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    let record: MarketplaceRefreshTransaction =
        serde_json::from_slice(&bytes).map_err(|error| {
            CommandError::incomplete(format!(
                "native marketplace recovery marker is invalid at {}: {error}",
                marker.display()
            ))
        })?;
    let snapshot_root = PathBuf::from(&record.snapshot_root);
    if record.kind != MARKETPLACE_REFRESH_KIND
        || record.schema_version != MARKETPLACE_REFRESH_SCHEMA_VERSION
        || record.client_id != legion_host::setup_registry::CLIENT_CLAUDE
        || snapshot_root.parent() != Some(root.as_path())
        || !snapshot_root.is_dir()
    {
        return Err(CommandError::incomplete(
            "native marketplace recovery marker identity does not match its owned path",
        ));
    }
    Ok(Some(record))
}

fn persist_marketplace_refresh(record: &MarketplaceRefreshTransaction) -> Result<(), CommandError> {
    let snapshot_root = PathBuf::from(&record.snapshot_root);
    let root = snapshot_root
        .parent()
        .ok_or_else(|| CommandError::incomplete("native marketplace snapshot has no parent"))?;
    std::fs::create_dir_all(root).map_err(io_error)?;
    let marker = root.join("pending.json");
    let bytes = serde_json::to_vec_pretty(record).map_err(io_error)?;
    let temporary = root.join(format!(".pending-{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)
        .map_err(io_error)?;
    use std::io::Write;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(io_error(error));
    }
    std::fs::rename(&temporary, marker).map_err(io_error)
}

fn snapshot_claude_cache(
    request: &legion_host::SetupRequest,
    binding: &legion_host::MarketplaceBinding,
    before: &Value,
) -> Result<MarketplaceRefreshTransaction, CommandError> {
    let native = &before["nativePlugin"];
    let was_enabled = native["enabled"].as_bool().ok_or_else(|| {
        CommandError::incomplete(
            "Claude native plugin omitted enabled state; preserving existing cache",
        )
    })?;
    let cache_path = native["path"].as_str().ok_or_else(|| {
        CommandError::incomplete(
            "Claude native plugin list omitted cache path; cannot snapshot safely",
        )
    })?;
    let source = PathBuf::from(cache_path);
    if !source.is_absolute() {
        return Err(CommandError::incomplete(
            "Claude native cache path is not absolute; cannot snapshot safely",
        ));
    }
    let prior_plugin_sha256 = legion_host::marketplace::claude_cache_plugin_tree_sha256(&source)
        .map_err(CommandError::incomplete)?;
    let transaction_id = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io_error)?
            .as_nanos()
    );
    let snapshot_root = marketplace_refresh_root(request).join(transaction_id);
    if let Err(error) = copy_plugin_tree(&source, &snapshot_root.join("plugin")) {
        let _ = std::fs::remove_dir_all(&snapshot_root);
        return Err(error);
    }
    let catalog_bytes = serde_json::to_vec_pretty(&json!({
        "name": legion_host::marketplace::MARKETPLACE_NAME,
        "owner": {"name": "Orthic Labs"},
        "plugins": [{"name": legion_host::marketplace::PLUGIN_NAME, "source": "./plugin"}]
    }))
    .map_err(io_error)?;
    let catalog_path = snapshot_root.join(".claude-plugin/marketplace.json");
    std::fs::create_dir_all(catalog_path.parent().expect("marketplace parent"))
        .map_err(io_error)?;
    std::fs::write(catalog_path, catalog_bytes).map_err(io_error)?;
    if legion_host::marketplace::claude_cache_plugin_tree_sha256(&snapshot_root.join("plugin"))
        .map_err(CommandError::incomplete)?
        != prior_plugin_sha256
    {
        let _ = std::fs::remove_dir_all(&snapshot_root);
        return Err(CommandError::incomplete(
            "Claude plugin cache changed while its rollback snapshot was created",
        ));
    }
    let transaction = MarketplaceRefreshTransaction {
        kind: MARKETPLACE_REFRESH_KIND.into(),
        schema_version: MARKETPLACE_REFRESH_SCHEMA_VERSION,
        client_id: legion_host::setup_registry::CLIENT_CLAUDE.into(),
        was_installed: native["installed"] == true,
        was_enabled: Some(was_enabled),
        prior_version: native["version"].as_str().map(str::to_owned),
        prior_cache_path: Some(cache_path.into()),
        prior_cached_release: before["cachedRelease"].clone(),
        original_marketplace_root: binding.current_root.to_string_lossy().into_owned(),
        prior_plugin_sha256,
        snapshot_root: snapshot_root.to_string_lossy().into_owned(),
        stage: "snapshot-ready".into(),
    };
    if let Err(error) = persist_marketplace_refresh(&transaction) {
        let _ = std::fs::remove_dir_all(&snapshot_root);
        return Err(error);
    }
    Ok(transaction)
}

fn copy_plugin_tree(source: &Path, destination: &Path) -> Result<(), CommandError> {
    let metadata = std::fs::symlink_metadata(source).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CommandError::incomplete(
            "Claude native cache is not a regular plugin directory",
        ));
    }
    std::fs::create_dir_all(destination).map_err(io_error)?;
    for entry in std::fs::read_dir(source).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&from).map_err(io_error)?;
        if metadata.file_type().is_symlink() {
            return Err(CommandError::incomplete(
                "Claude native cache contains a symlink; rollback snapshot refused",
            ));
        }
        if metadata.is_dir() {
            copy_plugin_tree(&from, &to)?;
            std::fs::set_permissions(&to, metadata.permissions()).map_err(io_error)?;
        } else if metadata.is_file() {
            std::fs::copy(&from, &to).map_err(io_error)?;
        } else {
            return Err(CommandError::incomplete(
                "Claude native cache contains a non-regular entry; rollback snapshot refused",
            ));
        }
    }
    std::fs::set_permissions(destination, metadata.permissions()).map_err(io_error)?;
    Ok(())
}

fn clear_marketplace_refresh(
    request: &legion_host::SetupRequest,
    record: &MarketplaceRefreshTransaction,
) -> Result<(), CommandError> {
    let snapshot_root = PathBuf::from(&record.snapshot_root);
    if snapshot_root.parent() != Some(marketplace_refresh_root(request).as_path()) {
        return Err(CommandError::incomplete(
            "native marketplace snapshot path escaped product state",
        ));
    }
    match std::fs::remove_file(marketplace_refresh_root(request).join("pending.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(error)),
    };
    // Remove marker first: interruption can leave an orphan snapshot, but can
    // never leave recovery pointing at an already-deleted snapshot.
    std::fs::remove_dir_all(&snapshot_root).map_err(io_error)
}

async fn inspect_host_integrations(
    selector: &legion_host::ClientSelector,
    release: &legion_host::BoundRelease,
    cancellation: CancellationToken,
) -> Result<Value, CommandError> {
    let inputs = host_integration_inputs_installed(selector, release)?;
    let mut integrations = serde_json::Map::new();
    if let Some(input) = &inputs.claude {
        integrations.insert(
            "claudeCodeLegacy".into(),
            serde_json::to_value(legion_host::inspect_claude_legacy(input).map_err(host_error)?)
                .map_err(|error| CommandError::incomplete(error.to_string()))?,
        );
    }
    if let Some(input) = &inputs.codex {
        integrations.insert(
            "codexSkills".into(),
            serde_json::to_value(legion_host::inspect_codex_skills(input).map_err(host_error)?)
                .map_err(|error| CommandError::incomplete(error.to_string()))?,
        );
    }
    for input in &inputs.marketplaces {
        integrations.insert(
            marketplace_key(input.client).into(),
            inspect_native_marketplace(input, release, cancellation.clone()).await?,
        );
    }
    for input in &inputs.client_projections {
        let key = projection_key(&input.client_id);
        integrations.insert(
            key.into(),
            serde_json::to_value(
                legion_host::setup_registry::inspect_client_projection(input)
                    .map_err(setup_error)?,
            )
            .map_err(|error| CommandError::incomplete(error.to_string()))?,
        );
    }
    Ok(Value::Object(integrations))
}

fn marketplace_client_id(client: legion_host::MarketplaceClient) -> &'static str {
    match client {
        legion_host::MarketplaceClient::ClaudeCode => legion_host::setup_registry::CLIENT_CLAUDE,
        legion_host::MarketplaceClient::Codex => legion_host::setup_registry::CLIENT_CODEX,
    }
}

fn marketplace_key(client: legion_host::MarketplaceClient) -> &'static str {
    match client {
        legion_host::MarketplaceClient::ClaudeCode => "claudeMarketplace",
        legion_host::MarketplaceClient::Codex => "codexMarketplace",
    }
}

async fn inspect_native_marketplace(
    binding: &legion_host::MarketplaceBinding,
    release: &legion_host::BoundRelease,
    cancellation: CancellationToken,
) -> Result<Value, CommandError> {
    let executable = match resolve_command(binding.client.executable()) {
        Ok(path) => path,
        Err(error) => {
            return Ok(json!({
                "clientId": marketplace_client_id(binding.client),
                "state": "client_unavailable",
                "marketplaceName": legion_host::marketplace::MARKETPLACE_NAME,
                "pluginName": legion_host::marketplace::PLUGIN_NAME,
                "nativeMarketplaceRegistered": false,
                "marketplaceSourceCurrent": false,
                "nativePlugin": {"installed": false, "enabled": null, "version": null, "path": null, "marketplace": null},
                "cachedRelease": null,
                "trust": "host-managed",
                "expectedReleaseVersion": release.release_version,
                "expectedRuntimeSha256": release.runtime_digest,
                "detail": error.message,
            }));
        }
    };
    let binding_valid = binding.validate_payload();
    let market_output = run_marketplace_cli(
        &executable,
        binding.client.marketplace_list_args(),
        binding.client,
        "marketplace list",
        cancellation.clone(),
    )
    .await?;
    let marketplace_value = parse_marketplace_json(&market_output.stdout, binding.client)?;
    let source_current = marketplace_root_registered(
        &marketplace_value,
        &binding.current_root,
        legion_host::marketplace::MARKETPLACE_NAME,
    );
    let registered = marketplace_named_registered(
        &marketplace_value,
        legion_host::marketplace::MARKETPLACE_NAME,
    );
    let mut native_plugin = read_native_plugin_entry(binding.client, cancellation.clone())
        .await
        .map_err(CommandError::incomplete)?;
    let home = installed_host_home()?;
    if binding.client == legion_host::MarketplaceClient::Codex {
        let configured_enabled =
            legion_host::marketplace::codex_enabled(&codex_home(&home).join("config.toml"))
                .map_err(CommandError::incomplete)?;
        native_plugin.enabled = Some(codex_effective_enabled(
            native_plugin.enabled,
            configured_enabled,
        ));
    }
    let cached_result = if native_plugin.installed {
        binding_valid.and_then(|()| {
            legion_host::marketplace::verify_cached_release(
                &native_plugin,
                binding.client,
                &binding.plugin_root,
                &release.release_version,
                &release.runtime_digest,
            )
        })
    } else {
        Err("native plugin is not installed".into())
    };
    let cached = cached_result.as_ref().ok();
    let cached_value = serde_json::to_value(cached)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let state = if !native_plugin.installed {
        "absent"
    } else if !source_current || cached.is_none() {
        "stale"
    } else if native_plugin.enabled == Some(false) {
        "disabled"
    } else {
        "current"
    };
    Ok(json!({
        "clientId": marketplace_client_id(binding.client),
        "state": state,
        "marketplaceName": legion_host::marketplace::MARKETPLACE_NAME,
        "pluginName": legion_host::marketplace::PLUGIN_NAME,
        "nativeMarketplaceRegistered": registered,
        "marketplaceSourceCurrent": source_current,
        "nativePlugin": native_plugin,
        "cachedRelease": cached_value,
        "trust": "host-managed",
        "expectedReleaseVersion": release.release_version,
        "expectedRuntimeSha256": release.runtime_digest,
        "marketplaceRoot": binding.current_root,
        "detail": cached_result.err(),
    }))
}

/// Read one native installed-plugin record using the host's list command and
/// documented deterministic cache root when JSON omits an installed path.
/// This is shared with doctor/hooks so they never inspect native DB files.
pub async fn read_native_plugin_entry(
    client: legion_host::MarketplaceClient,
    cancellation: CancellationToken,
) -> Result<legion_host::NativePluginEntry, String> {
    let executable = resolve_command(client.executable()).map_err(|error| error.message)?;
    let output = run_marketplace_cli(
        &executable,
        client.plugin_list_args(),
        client,
        "plugin list",
        cancellation,
    )
    .await
    .map_err(|error| error.message)?;
    let value = parse_marketplace_json(&output.stdout, client).map_err(|error| error.message)?;
    let mut entry = legion_host::native_plugin_entry_scoped(
        &value,
        (client == legion_host::MarketplaceClient::ClaudeCode).then_some("user"),
    );
    if entry.installed && entry.path.is_none() {
        let home = installed_host_home().map_err(|error| error.message)?;
        match client {
            legion_host::MarketplaceClient::Codex => {
                let codex_home = codex_home(&home);
                match legion_host::marketplace::find_codex_plugin_cache_version(
                    &codex_home.join("config.toml"),
                    &codex_home,
                    entry.version.as_deref(),
                )
                .map_err(|error| format!("cannot resolve Codex native cache: {error}"))?
                {
                    legion_host::marketplace::CodexCacheLookup::Found(path) => {
                        entry.path = Some(path.to_string_lossy().into_owned());
                    }
                    legion_host::marketplace::CodexCacheLookup::Ambiguous(_) => {
                        return Err("Codex native plugin cache is ambiguous".into());
                    }
                    legion_host::marketplace::CodexCacheLookup::NotConfigured
                    | legion_host::marketplace::CodexCacheLookup::Missing => {}
                }
            }
            legion_host::MarketplaceClient::ClaudeCode => {
                let cache_root =
                    client.installed_cache_root(&claude_home(&home), entry.version.as_deref());
                if cache_root.is_dir() {
                    entry.path = Some(cache_root.to_string_lossy().into_owned());
                }
            }
        }
    }
    Ok(entry)
}

async fn read_owned_legacy_claude_disabled(
    request: &legion_host::SetupRequest,
    cli: &Path,
    cancellation: CancellationToken,
) -> Result<bool, CommandError> {
    let inputs = host_integration_inputs(request)?;
    let Some(projection) = inputs
        .client_projections
        .iter()
        .find(|input| input.client_id == legion_host::setup_registry::CLIENT_CLAUDE)
    else {
        return Ok(false);
    };
    let inspection =
        legion_host::setup_registry::inspect_client_projection(projection).map_err(setup_error)?;
    if inspection.ownership != "legion" {
        return Ok(false);
    }
    let client = legion_host::MarketplaceClient::ClaudeCode;
    let output = run_marketplace_cli(
        cli,
        client.plugin_list_args(),
        client,
        "legacy plugin list",
        cancellation,
    )
    .await?;
    let listed = parse_marketplace_json(&output.stdout, client)?;
    let legacy = legion_host::marketplace::claude_legacy_plugin_entry(&listed);
    if !legacy.installed {
        return Ok(false);
    }
    let Some(path) = legacy.path else {
        return Err(CommandError::incomplete(
            "owned legacy Claude plugin has no native path readback; preserving legacy files",
        ));
    };
    let actual = std::fs::canonicalize(&path).unwrap_or_else(|_| PathBuf::from(path));
    let expected = std::fs::canonicalize(&projection.target_root)
        .unwrap_or_else(|_| projection.target_root.clone());
    if actual != expected {
        return Ok(false);
    }
    match legacy.enabled {
        Some(enabled) => Ok(!enabled),
        None => Err(CommandError::incomplete(
            "owned legacy Claude plugin omitted enabled state; preserving legacy files",
        )),
    }
}

async fn reconcile_native_marketplace(
    binding: &legion_host::MarketplaceBinding,
    request: &legion_host::SetupRequest,
    cancellation: CancellationToken,
) -> Result<Value, CommandError> {
    let cli = match resolve_command(binding.client.executable()) {
        Ok(path) => path,
        Err(error) => {
            if matches!(request.selector, legion_host::ClientSelector::ClientId(_)) {
                return Err(CommandError::incomplete(format!(
                    "{} was selected but its native CLI is unavailable: {}",
                    marketplace_client_id(binding.client),
                    error.message
                )));
            }
            return Ok(client_unavailable_value(
                binding.client,
                &request.release,
                error.message,
            ));
        }
    };
    if let Err(error) = binding.validate_payload() {
        return Err(CommandError::incomplete(error));
    }

    let before =
        inspect_native_marketplace(binding, &request.release, cancellation.clone()).await?;
    let was_installed = before["nativePlugin"]["installed"] == true;
    let pending_refresh = if binding.client == legion_host::MarketplaceClient::ClaudeCode {
        load_marketplace_refresh(request)?
    } else {
        None
    };
    let mut refresh_cleared = false;
    let legacy_claude_disabled = if binding.client == legion_host::MarketplaceClient::ClaudeCode {
        read_owned_legacy_claude_disabled(request, &cli, cancellation.clone()).await?
    } else {
        false
    };
    let codex_config_disabled = if binding.client == legion_host::MarketplaceClient::Codex {
        let home = installed_host_home()?;
        !legion_host::marketplace::codex_enabled(&codex_home(&home).join("config.toml"))
            .map_err(CommandError::incomplete)?
    } else {
        false
    };
    let was_disabled = before["nativePlugin"]["enabled"] == false
        || legacy_claude_disabled
        || codex_config_disabled
        || pending_refresh
            .as_ref()
            .is_some_and(|record| record.was_enabled == Some(false));
    if binding.client == legion_host::MarketplaceClient::ClaudeCode
        && !was_installed
        && pending_refresh.is_some()
        && matches!(
            request.action,
            legion_host::SetupAction::Apply | legion_host::SetupAction::Repair
        )
    {
        return resume_interrupted_claude_refresh(
            &cli,
            binding,
            request,
            pending_refresh.as_ref().expect("checked pending refresh"),
            cancellation,
        )
        .await;
    }
    let registered = before["nativeMarketplaceRegistered"] == true;
    let source_current = before["marketplaceSourceCurrent"] == true;
    let legacy_owned = binding.client == legion_host::MarketplaceClient::Codex
        && !was_installed
        && codex_legacy_projection_owned(request)?;
    if binding.client == legion_host::MarketplaceClient::Codex
        && matches!(
            &request.action,
            legion_host::SetupAction::Apply | legion_host::SetupAction::Repair
        )
        && matches!(request.selector, legion_host::ClientSelector::AllSupported)
        && !was_installed
        && !legacy_owned
    {
        return Ok(json!({
            "clientId": marketplace_client_id(binding.client),
            "state": "not_selected",
            "marketplaceName": legion_host::marketplace::MARKETPLACE_NAME,
            "pluginName": legion_host::marketplace::PLUGIN_NAME,
            "nativeMarketplaceRegistered": registered,
            "marketplaceSourceCurrent": source_current,
            "nativePlugin": before["nativePlugin"],
            "cachedRelease": before["cachedRelease"],
            "trust": "host-managed",
            "expectedReleaseVersion": request.release.release_version,
            "expectedRuntimeSha256": request.release.runtime_digest,
        }));
    }
    let disabled_absent = request.action == legion_host::SetupAction::Disable && !was_installed;
    if marketplace_should_register(
        &request.action,
        binding.client,
        matches!(request.selector, legion_host::ClientSelector::AllSupported),
        source_current,
        was_installed,
        legacy_owned,
    ) {
        run_marketplace_cli(
            &cli,
            binding.client.marketplace_add_args(&binding.current_root),
            binding.client,
            "marketplace add",
            cancellation.clone(),
        )
        .await?;
    }
    let current = before["state"] == "current" || before["state"] == "disabled";
    if marketplace_should_install_or_refresh(&request.action, current) && !disabled_absent {
        if was_installed {
            match binding.client {
                legion_host::MarketplaceClient::ClaudeCode => {
                    run_marketplace_cli(
                        &cli,
                        vec![
                            "plugin".into(),
                            "marketplace".into(),
                            "update".into(),
                            legion_host::marketplace::MARKETPLACE_NAME.into(),
                            "--json".into(),
                        ],
                        binding.client,
                        "marketplace update",
                        cancellation.clone(),
                    )
                    .await?;
                    run_marketplace_cli(
                        &cli,
                        vec![
                            "plugin".into(),
                            "update".into(),
                            format!(
                                "{}@{}",
                                legion_host::marketplace::PLUGIN_NAME,
                                legion_host::marketplace::MARKETPLACE_NAME
                            ),
                            "--scope".into(),
                            "user".into(),
                            "--json".into(),
                        ],
                        binding.client,
                        "plugin update",
                        cancellation.clone(),
                    )
                    .await?;
                    let refreshed =
                        inspect_native_marketplace(binding, &request.release, cancellation.clone())
                            .await?;
                    let expected = if was_disabled { "disabled" } else { "current" };
                    if refreshed["state"] != expected {
                        let transaction = match pending_refresh.clone() {
                            Some(record) => record,
                            None => snapshot_claude_cache(request, binding, &refreshed)?,
                        };
                        refresh_claude_plugin(
                            &cli,
                            binding,
                            request,
                            was_disabled,
                            &refreshed,
                            &transaction,
                            cancellation.clone(),
                        )
                        .await?;
                        clear_marketplace_refresh(request, &transaction)?;
                        refresh_cleared = true;
                    }
                }
                legion_host::MarketplaceClient::Codex => {
                    // Local Codex marketplaces are refreshed by plugin add;
                    // marketplace upgrade only updates configured Git sources.
                    run_marketplace_cli(
                        &cli,
                        binding.client.plugin_add_args(),
                        binding.client,
                        "plugin refresh",
                        cancellation.clone(),
                    )
                    .await?;
                }
            }
        } else {
            run_marketplace_cli(
                &cli,
                binding.client.plugin_add_args(),
                binding.client,
                "plugin add",
                cancellation.clone(),
            )
            .await?;
        }
    }

    match request.action {
        legion_host::SetupAction::Apply | legion_host::SetupAction::Repair => {
            if was_disabled {
                set_marketplace_enabled(binding.client, false, &cli, cancellation.clone()).await?;
            }
        }
        legion_host::SetupAction::Disable => {
            if was_installed {
                set_marketplace_enabled(binding.client, false, &cli, cancellation.clone()).await?;
            }
        }
        legion_host::SetupAction::Remove | legion_host::SetupAction::Purge => {
            if was_installed {
                run_marketplace_cli(
                    &cli,
                    binding.client.plugin_remove_args(),
                    binding.client,
                    "plugin remove",
                    cancellation.clone(),
                )
                .await?;
            }
            if registered {
                run_marketplace_cli(
                    &cli,
                    binding.client.marketplace_remove_args(),
                    binding.client,
                    "marketplace remove",
                    cancellation.clone(),
                )
                .await?;
            }
        }
        _ => {}
    }
    let mut after = inspect_native_marketplace(binding, &request.release, cancellation).await?;
    let expected_state = marketplace_expected_state(&request.action, was_disabled, was_installed);
    if request.action == legion_host::SetupAction::Remove
        || request.action == legion_host::SetupAction::Purge
    {
        if !marketplace_removal_proven(&after) {
            return Err(CommandError::incomplete(format!(
                "{} native plugin removal readback did not prove plugin and marketplace absence",
                marketplace_client_id(binding.client)
            )));
        }
        after["state"] = Value::String("absent".into());
        if !refresh_cleared {
            if let Some(record) = pending_refresh.as_ref() {
                clear_marketplace_refresh(request, record)?;
            }
        }
    } else if after["state"] != expected_state {
        return Err(CommandError::incomplete(format!(
            "{} native marketplace readback did not prove {expected_state}",
            marketplace_client_id(binding.client)
        )));
    } else if !refresh_cleared {
        if let Some(record) = pending_refresh.as_ref() {
            clear_marketplace_refresh(request, record)?;
        }
    }
    Ok(after)
}

async fn refresh_claude_plugin(
    cli: &Path,
    binding: &legion_host::MarketplaceBinding,
    request: &legion_host::SetupRequest,
    was_disabled: bool,
    stale_readback: &Value,
    transaction: &MarketplaceRefreshTransaction,
    cancellation: CancellationToken,
) -> Result<(), CommandError> {
    let attempt = async {
        run_marketplace_cli(
            cli,
            binding.client.plugin_remove_args(),
            binding.client,
            "plugin refresh uninstall",
            cancellation.clone(),
        )
        .await?;
        run_marketplace_cli(
            cli,
            binding.client.plugin_add_args(),
            binding.client,
            "plugin refresh install",
            cancellation.clone(),
        )
        .await?;
        if was_disabled {
            set_marketplace_enabled(binding.client, false, cli, cancellation.clone()).await?;
        }
        let readback =
            inspect_native_marketplace(binding, &request.release, cancellation.clone()).await?;
        let expected = if was_disabled { "disabled" } else { "current" };
        if readback["state"] != expected {
            return Err(CommandError::incomplete(format!(
                "Claude native refresh did not prove {expected}; cache remains {}",
                readback["state"].as_str().unwrap_or("unknown")
            )));
        }
        Ok(())
    }
    .await;
    match attempt {
        Ok(()) => Ok(()),
        Err(original) => {
            let rollback = rollback_claude_snapshot(cli, binding, request, transaction).await;
            match rollback {
                Ok(()) => Err(CommandError::incomplete(format!(
                    "Claude native refresh failed ({}); rollback restored prior cached payload and stable marketplace source",
                    original.message
                ))),
                Err(rollback_error) => Err(CommandError::incomplete(format!(
                    "Claude native refresh failed ({}); rollback incomplete, snapshot retained: {}; previous cache: {}",
                    original.message,
                    rollback_error.message,
                    stale_readback["nativePlugin"]["path"].as_str().unwrap_or("unknown")
                ))),
            }
        }
    }
}

async fn resume_interrupted_claude_refresh(
    cli: &Path,
    binding: &legion_host::MarketplaceBinding,
    request: &legion_host::SetupRequest,
    transaction: &MarketplaceRefreshTransaction,
    cancellation: CancellationToken,
) -> Result<Value, CommandError> {
    let attempt = async {
        run_marketplace_cli(
            cli,
            binding.client.marketplace_add_args(&binding.current_root),
            binding.client,
            "recover stable marketplace source",
            cancellation.clone(),
        )
        .await?;
        run_marketplace_cli(
            cli,
            binding.client.plugin_add_args(),
            binding.client,
            "recover plugin install",
            cancellation.clone(),
        )
        .await?;
        if let Some(enabled) = transaction.was_enabled {
            set_marketplace_enabled(binding.client, enabled, cli, cancellation.clone()).await?;
        }
        let readback =
            inspect_native_marketplace(binding, &request.release, cancellation.clone()).await?;
        let expected = if transaction.was_enabled == Some(false) {
            "disabled"
        } else {
            "current"
        };
        if readback["state"] != expected {
            return Err(CommandError::incomplete(format!(
                "interrupted Claude refresh recovery did not prove {expected}; state is {}",
                readback["state"].as_str().unwrap_or("unknown")
            )));
        }
        clear_marketplace_refresh(request, transaction)?;
        Ok(readback)
    }
    .await;

    match attempt {
        Ok(readback) => Ok(readback),
        Err(original) => match rollback_claude_snapshot(cli, binding, request, transaction).await {
            Ok(()) => Err(CommandError::incomplete(format!(
                "interrupted Claude refresh recovery failed ({}); rollback restored prior cached payload and stable marketplace source",
                original.message
            ))),
            Err(rollback_error) => Err(CommandError::incomplete(format!(
                "interrupted Claude refresh recovery failed ({}); rollback incomplete, snapshot retained: {}",
                original.message, rollback_error.message
            ))),
        },
    }
}

async fn rollback_claude_snapshot(
    cli: &Path,
    binding: &legion_host::MarketplaceBinding,
    request: &legion_host::SetupRequest,
    transaction: &MarketplaceRefreshTransaction,
) -> Result<(), CommandError> {
    let cancellation = CancellationToken::new();
    let snapshot_root = PathBuf::from(&transaction.snapshot_root);
    let snapshot_plugin = snapshot_root.join("plugin");
    let prior_payload_sha256 = validated_claude_snapshot_payload_sha256(
        &snapshot_plugin,
        &transaction.prior_plugin_sha256,
    )?;
    let root_result = run_marketplace_cli(
        cli,
        binding.client.marketplace_add_args(&snapshot_root),
        binding.client,
        "rollback marketplace add",
        cancellation.clone(),
    )
    .await;
    if let Err(error) = root_result {
        return Err(CommandError::incomplete(error.message));
    }
    let entries = read_native_plugin_entry(binding.client, cancellation.clone())
        .await
        .map_err(CommandError::incomplete)?;
    if entries.installed {
        run_marketplace_cli(
            cli,
            binding.client.plugin_remove_args(),
            binding.client,
            "rollback plugin remove",
            cancellation.clone(),
        )
        .await?;
    }
    run_marketplace_cli(
        cli,
        binding.client.plugin_add_args(),
        binding.client,
        "rollback plugin install",
        cancellation.clone(),
    )
    .await?;
    if let Some(enabled) = transaction.was_enabled {
        set_marketplace_enabled(binding.client, enabled, cli, cancellation.clone()).await?;
    }
    let installed = read_native_plugin_entry(binding.client, cancellation.clone())
        .await
        .map_err(CommandError::incomplete)?;
    let installed_path = installed
        .path
        .as_deref()
        .ok_or_else(|| CommandError::incomplete("rollback plugin list omitted cache path"))?;
    let installed_path = PathBuf::from(installed_path);
    if installed_path.starts_with(&snapshot_root)
        || legion_host::marketplace::claude_cache_plugin_tree_sha256(&installed_path)
            .map_err(CommandError::incomplete)?
            != prior_payload_sha256
        || installed.enabled != transaction.was_enabled
    {
        return Err(CommandError::incomplete(
            "native rollback cache digest, enabled state, or cache location did not match snapshot",
        ));
    }
    let original_root = PathBuf::from(&transaction.original_marketplace_root);
    let recorded_root = std::fs::canonicalize(&original_root).unwrap_or(original_root.clone());
    let active_root = std::fs::canonicalize(&binding.current_root)
        .unwrap_or_else(|_| binding.current_root.clone());
    if recorded_root != active_root {
        return Err(CommandError::incomplete(
            "native marketplace recovery source is not active stable current",
        ));
    }
    run_marketplace_cli(
        cli,
        binding.client.marketplace_add_args(&original_root),
        binding.client,
        "restore stable marketplace source",
        cancellation.clone(),
    )
    .await?;
    let output = run_marketplace_cli(
        cli,
        binding.client.marketplace_list_args(),
        binding.client,
        "verify stable marketplace source",
        cancellation,
    )
    .await?;
    let listed = parse_marketplace_json(&output.stdout, binding.client)?;
    if !marketplace_root_registered(
        &listed,
        &original_root,
        legion_host::marketplace::MARKETPLACE_NAME,
    ) {
        return Err(CommandError::incomplete(
            "native marketplace source did not return to stable current",
        ));
    }
    let verified = read_native_plugin_entry(binding.client, CancellationToken::new())
        .await
        .map_err(CommandError::incomplete)?;
    let verified_path = verified
        .path
        .as_deref()
        .ok_or_else(|| CommandError::incomplete("restored plugin list omitted cache path"))?;
    if Path::new(verified_path).starts_with(&snapshot_root)
        || legion_host::marketplace::claude_cache_plugin_tree_sha256(Path::new(verified_path))
            .map_err(CommandError::incomplete)?
            != prior_payload_sha256
        || verified.enabled != transaction.was_enabled
    {
        return Err(CommandError::incomplete(
            "stable-source rebind changed prior cache digest or enabled state",
        ));
    }
    clear_marketplace_refresh(request, transaction)
}

fn validated_claude_snapshot_payload_sha256(
    snapshot_plugin: &Path,
    recorded_sha256: &str,
) -> Result<String, CommandError> {
    let strict_sha256 =
        legion_host::plugin_tree_sha256(snapshot_plugin).map_err(CommandError::incomplete)?;
    let payload_sha256 = legion_host::marketplace::claude_cache_plugin_tree_sha256(snapshot_plugin)
        .map_err(CommandError::incomplete)?;
    if strict_sha256 == recorded_sha256 || payload_sha256 == recorded_sha256 {
        Ok(payload_sha256)
    } else {
        Err(CommandError::incomplete("rollback snapshot digest changed"))
    }
}

fn marketplace_should_register(
    action: &legion_host::SetupAction,
    client: legion_host::MarketplaceClient,
    all_supported: bool,
    registered: bool,
    installed: bool,
    legacy_owned: bool,
) -> bool {
    let needs_plugin = matches!(
        action,
        legion_host::SetupAction::Apply | legion_host::SetupAction::Repair
    );
    needs_plugin
        && !registered
        && !(client == legion_host::MarketplaceClient::Codex
            && all_supported
            && !installed
            && !legacy_owned)
}

fn marketplace_should_install_or_refresh(action: &legion_host::SetupAction, current: bool) -> bool {
    matches!(
        action,
        legion_host::SetupAction::Apply | legion_host::SetupAction::Repair
    ) && !current
}

fn reject_empty_lifecycle_with_pending_refresh(
    request: &legion_host::SetupRequest,
    registry: &legion_host::SetupRegistry<legion_host::setup_registry::OnDiskSetupStore>,
) -> Result<(), CommandError> {
    if !matches!(request.selector, legion_host::ClientSelector::AllSupported)
        || !matches!(
            request.action,
            legion_host::SetupAction::Apply
                | legion_host::SetupAction::Repair
                | legion_host::SetupAction::Disable
                | legion_host::SetupAction::Remove
                | legion_host::SetupAction::Purge
        )
    {
        return Ok(());
    }
    if registry
        .detect(&request.selector, &request.client_evidence)
        .map_err(setup_error)?
        .is_empty()
        && load_marketplace_refresh(request)?.is_some()
    {
        return Err(CommandError::incomplete(
            "a pending Claude native refresh requires a detected client for recovery; preserving its snapshot",
        ));
    }
    Ok(())
}

fn marketplace_expected_state(
    action: &legion_host::SetupAction,
    was_disabled: bool,
    was_installed: bool,
) -> &'static str {
    match action {
        legion_host::SetupAction::Disable if was_installed => "disabled",
        legion_host::SetupAction::Disable
        | legion_host::SetupAction::Remove
        | legion_host::SetupAction::Purge => "absent",
        _ if was_disabled => "disabled",
        _ => "current",
    }
}

fn marketplace_removal_proven(readback: &Value) -> bool {
    readback["nativePlugin"]["installed"] == false
        && readback["nativeMarketplaceRegistered"] == false
}

fn codex_effective_enabled(native_enabled: Option<bool>, configured_enabled: bool) -> bool {
    native_enabled != Some(false) && configured_enabled
}

fn marketplace_cleanup_proven(state: &str) -> bool {
    matches!(state, "current" | "disabled" | "absent")
}

fn client_unavailable_value(
    client: legion_host::MarketplaceClient,
    release: &legion_host::BoundRelease,
    detail: String,
) -> Value {
    json!({
        "clientId": marketplace_client_id(client),
        "state": "client_unavailable",
        "marketplaceName": legion_host::marketplace::MARKETPLACE_NAME,
        "pluginName": legion_host::marketplace::PLUGIN_NAME,
        "nativeMarketplaceRegistered": false,
        "nativePlugin": {"installed": false, "enabled": null, "version": null, "path": null, "marketplace": null},
        "cachedRelease": null,
        "trust": "host-managed",
        "expectedReleaseVersion": release.release_version,
        "expectedRuntimeSha256": release.runtime_digest,
        "detail": detail,
    })
}

fn client_not_selected_value(
    client: legion_host::MarketplaceClient,
    release: &legion_host::BoundRelease,
) -> Value {
    json!({
        "clientId": marketplace_client_id(client),
        "state": "not_selected",
        "marketplaceName": legion_host::marketplace::MARKETPLACE_NAME,
        "pluginName": legion_host::marketplace::PLUGIN_NAME,
        "nativeMarketplaceRegistered": false,
        "nativePlugin": {"installed": false, "enabled": null, "version": null, "path": null, "marketplace": null},
        "cachedRelease": null,
        "trust": "host-managed",
        "expectedReleaseVersion": release.release_version,
        "expectedRuntimeSha256": release.runtime_digest,
    })
}

fn codex_home(home: &Path) -> PathBuf {
    std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".codex"))
}

fn claude_home(home: &Path) -> PathBuf {
    std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".claude"))
}

async fn set_marketplace_enabled(
    client: legion_host::MarketplaceClient,
    enabled: bool,
    cli: &Path,
    cancellation: CancellationToken,
) -> Result<(), CommandError> {
    match client {
        legion_host::MarketplaceClient::ClaudeCode => {
            let args = client
                .plugin_toggle_args(enabled)
                .expect("Claude has native enable and disable commands");
            run_marketplace_cli(cli, args, client, "plugin state change", cancellation)
                .await
                .map(|_| ())
        }
        legion_host::MarketplaceClient::Codex => {
            let home = installed_host_home()?;
            legion_host::marketplace::set_codex_enabled(
                &codex_home(&home).join("config.toml"),
                enabled,
            )
            .map_err(CommandError::incomplete)
        }
    }
}

async fn run_marketplace_cli(
    executable: &Path,
    args: Vec<String>,
    client: legion_host::MarketplaceClient,
    operation: &str,
    cancellation: CancellationToken,
) -> Result<ProcessOutput, CommandError> {
    let cwd = std::env::current_dir()
        .map_err(io_error)?
        .to_string_lossy()
        .into_owned();
    let mut attempt = 0;
    let output = loop {
        attempt += 1;
        let launch = ProcessLaunch {
            executable: executable.to_string_lossy().into_owned(),
            args: args.clone(),
            cwd: cwd.clone(),
            environment: std::env::vars().collect::<BTreeMap<_, _>>(),
            stdout_limit: 1024 * 1024,
            stderr_limit: 1024 * 1024,
            timeout_ms: MARKETPLACE_TIMEOUT.as_millis() as u64,
            termination_grace_ms: 2_000,
            cancellation: cancellation.clone(),
        };
        #[cfg(unix)]
        let output = legion_effects::platform::unix::UnixProcess
            .run(launch)
            .await;
        #[cfg(windows)]
        let output = legion_effects::platform::windows::WindowsProcess
            .run(launch)
            .await;
        let output = output.map_err(|error| {
            CommandError::incomplete(format!(
                "{} {operation} failed to start: {error}",
                client.executable()
            ))
        })?;
        if output.timed_out && !output.cancelled && attempt < MARKETPLACE_ATTEMPTS {
            continue;
        }
        break output;
    };
    if output.cancelled {
        return Err(CommandError::cancelled());
    }
    if output.timed_out {
        return Err(CommandError::incomplete(format!(
            "{} {operation} exceeded {} seconds on each of {MARKETPLACE_ATTEMPTS} attempts",
            client.executable(),
            MARKETPLACE_TIMEOUT.as_secs()
        )));
    }
    if output.output_limited
        || !output.kill_succeeded
        || !output.process_tree.started
        || !output.process_tree.terminated
        || !output.process_tree.reaped
    {
        return Err(CommandError::incomplete(format!(
            "{} {operation} did not prove bounded process completion",
            client.executable()
        )));
    }
    if output.exit_code != Some(0) {
        return Err(CommandError::incomplete(format!(
            "{} {operation} exited with {}; {}",
            client.executable(),
            output.exit_code.unwrap_or(-1),
            process_output_detail(&output).unwrap_or_else(|| "native CLI reported failure".into())
        )));
    }
    Ok(output)
}

fn parse_marketplace_json(
    bytes: &[u8],
    client: legion_host::MarketplaceClient,
) -> Result<Value, CommandError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        CommandError::incomplete(format!(
            "{} returned non-UTF8 JSON: {error}",
            client.executable()
        ))
    })?;
    if let Ok(value) = serde_json::from_str(text.trim()) {
        return Ok(value);
    }
    for line in text.lines().rev() {
        if let Ok(value) = serde_json::from_str(line.trim()) {
            return Ok(value);
        }
    }
    Err(CommandError::incomplete(format!(
        "{} did not return valid JSON for native plugin readback",
        client.executable()
    )))
}

fn marketplace_root_registered(value: &Value, expected_root: &Path, expected_name: &str) -> bool {
    fn normalized(path: &str) -> PathBuf {
        std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path))
    }
    fn visit(value: &Value, expected_root: &Path, expected_name: &str) -> bool {
        match value {
            Value::Array(items) => items
                .iter()
                .any(|item| visit(item, expected_root, expected_name)),
            Value::Object(object) => {
                let name = ["name", "id", "marketplace"]
                    .iter()
                    .filter_map(|key| object.get(*key).and_then(Value::as_str))
                    .any(|name| name == expected_name);
                let root = object.values().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|path| normalized(path) == expected_root)
                });
                (name && root)
                    || object
                        .values()
                        .any(|item| visit(item, expected_root, expected_name))
            }
            _ => false,
        }
    }
    let root = normalized(&expected_root.to_string_lossy());
    visit(value, &root, expected_name)
}

fn marketplace_named_registered(value: &Value, expected_name: &str) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| marketplace_named_registered(item, expected_name)),
        Value::Object(object) => {
            ["name", "id", "marketplace"]
                .iter()
                .filter_map(|key| object.get(*key).and_then(Value::as_str))
                .any(|name| name == expected_name)
                || object
                    .values()
                    .any(|item| marketplace_named_registered(item, expected_name))
        }
        _ => false,
    }
}

async fn preview_host_integrations(
    request: &legion_host::SetupRequest,
    cancellation: CancellationToken,
) -> Result<Value, CommandError> {
    let inputs = host_integration_inputs(request)?;
    let mut integrations = serde_json::Map::new();
    if should_process_client(request, legion_host::setup_registry::CLIENT_CLAUDE) {
        if let Some(input) = &inputs.claude {
            integrations.insert(
                "claudeCodeLegacy".into(),
                serde_json::to_value(
                    legion_host::inspect_claude_legacy(input).map_err(host_error)?,
                )
                .map_err(|error| CommandError::incomplete(error.to_string()))?,
            );
        }
    }
    if should_process_client(request, legion_host::setup_registry::CLIENT_CODEX) {
        if let Some(input) = &inputs.codex {
            match request.action {
                legion_host::SetupAction::Remove | legion_host::SetupAction::Purge => {
                    let preview =
                        legion_host::preview_remove_codex_skills(input).map_err(host_error)?;
                    integrations.insert(
                        "codexSkills".into(),
                        serde_json::to_value(preview)
                            .map_err(|error| CommandError::incomplete(error.to_string()))?,
                    );
                }
                legion_host::SetupAction::Apply | legion_host::SetupAction::Repair => {
                    let preview = legion_host::preview_codex_skills(input).map_err(host_error)?;
                    integrations.insert(
                        "codexSkills".into(),
                        serde_json::to_value(preview)
                            .map_err(|error| CommandError::incomplete(error.to_string()))?,
                    );
                }
                _ => {
                    let inspection =
                        legion_host::inspect_codex_skills(input).map_err(host_error)?;
                    integrations.insert(
                        "codexSkills".into(),
                        serde_json::to_value(inspection)
                            .map_err(|error| CommandError::incomplete(error.to_string()))?,
                    );
                }
            }
        }
    }
    for input in &inputs.marketplaces {
        if !should_process_client(request, marketplace_client_id(input.client)) {
            integrations.insert(
                marketplace_key(input.client).into(),
                client_not_selected_value(input.client, &request.release),
            );
            continue;
        }
        integrations.insert(
            marketplace_key(input.client).into(),
            inspect_native_marketplace(input, &request.release, cancellation.clone()).await?,
        );
    }
    for input in &inputs.client_projections {
        if !should_process_client(request, &input.client_id) {
            continue;
        }
        let key = projection_key(&input.client_id);
        integrations.insert(
            key.into(),
            serde_json::to_value(
                legion_host::setup_registry::inspect_client_projection(input)
                    .map_err(setup_error)?,
            )
            .map_err(|error| CommandError::incomplete(error.to_string()))?,
        );
    }
    Ok(Value::Object(integrations))
}

async fn apply_host_integrations(
    request: &legion_host::SetupRequest,
    cancellation: CancellationToken,
) -> Result<Value, CommandError> {
    let inputs = host_integration_inputs(request)?;
    let mut integrations = serde_json::Map::new();
    let mut marketplace_states = BTreeMap::new();
    for input in &inputs.marketplaces {
        if !should_process_client(request, marketplace_client_id(input.client)) {
            integrations.insert(
                marketplace_key(input.client).into(),
                client_not_selected_value(input.client, &request.release),
            );
            continue;
        }
        let value = reconcile_native_marketplace(input, request, cancellation.clone()).await?;
        marketplace_states.insert(marketplace_client_id(input.client), value["state"].clone());
        integrations.insert(marketplace_key(input.client).into(), value);
    }
    let verified_cutover = |client_id: &str| {
        marketplace_states
            .get(client_id)
            .and_then(Value::as_str)
            .is_some_and(marketplace_cleanup_proven)
    };
    if should_process_client(request, legion_host::setup_registry::CLIENT_CLAUDE)
        && verified_cutover(legion_host::setup_registry::CLIENT_CLAUDE)
    {
        if let Some(input) = &inputs.claude {
            let value = match request.action {
                legion_host::SetupAction::Apply
                | legion_host::SetupAction::Repair
                | legion_host::SetupAction::Remove
                | legion_host::SetupAction::Purge => serde_json::to_value(
                    legion_host::repair_claude_legacy(input).map_err(host_error)?,
                ),
                _ => serde_json::to_value(
                    legion_host::inspect_claude_legacy(input).map_err(host_error)?,
                ),
            }
            .map_err(|error| CommandError::incomplete(error.to_string()))?;
            integrations.insert("claudeCodeLegacy".into(), value);
        }
    }
    if should_process_client(request, legion_host::setup_registry::CLIENT_CODEX)
        && verified_cutover(legion_host::setup_registry::CLIENT_CODEX)
    {
        if let Some(input) = &inputs.codex {
            let value = match request.action {
                legion_host::SetupAction::Apply
                | legion_host::SetupAction::Repair
                | legion_host::SetupAction::Remove
                | legion_host::SetupAction::Purge => serde_json::to_value(
                    legion_host::remove_codex_skills(input).map_err(host_error)?,
                ),
                _ => serde_json::to_value(
                    legion_host::inspect_codex_skills(input).map_err(host_error)?,
                ),
            }
            .map_err(|error| CommandError::incomplete(error.to_string()))?;
            integrations.insert("codexSkills".into(), value);
        }
    }
    if let Some(value) = refresh_codex_role_projections(request, &inputs) {
        integrations.insert("codexRoleProjections".into(), value);
    }
    for input in &inputs.client_projections {
        if !should_process_client(request, &input.client_id) {
            continue;
        }
        if matches!(
            input.client_id.as_str(),
            legion_host::setup_registry::CLIENT_CLAUDE | legion_host::setup_registry::CLIENT_CODEX
        ) && !verified_cutover(&input.client_id)
        {
            continue;
        }
        let key = projection_key(&input.client_id);
        let value = match request.action {
            legion_host::SetupAction::Apply | legion_host::SetupAction::Repair
                if matches!(
                    input.client_id.as_str(),
                    legion_host::setup_registry::CLIENT_CLAUDE
                        | legion_host::setup_registry::CLIENT_CODEX
                ) =>
            {
                serde_json::to_value(
                    legion_host::setup_registry::remove_client_projection(input)
                        .map_err(setup_error)?,
                )
            }
            legion_host::SetupAction::Apply | legion_host::SetupAction::Repair => {
                if should_mutate_client(request, &input.client_id) {
                    serde_json::to_value(
                        legion_host::setup_registry::repair_client_projection(input)
                            .map_err(setup_error)?,
                    )
                } else {
                    serde_json::to_value(
                        legion_host::setup_registry::inspect_client_projection(input)
                            .map_err(setup_error)?,
                    )
                }
            }
            legion_host::SetupAction::Remove | legion_host::SetupAction::Purge => {
                serde_json::to_value(
                    legion_host::setup_registry::remove_client_projection(input)
                        .map_err(setup_error)?,
                )
            }
            _ => serde_json::to_value(
                legion_host::setup_registry::inspect_client_projection(input)
                    .map_err(setup_error)?,
            ),
        }
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
        integrations.insert(key.into(), value);
    }
    Ok(Value::Object(integrations))
}

/// Refresh the user-scope Codex role projections (`<codex home>/agents/*.toml` and the Legion
/// managed block in `config.toml`) on apply and repair, so a new build's roles reach Codex
/// without a manual `legion bind`. Codex absent is a skipped step, and a failure is reported in
/// the result without failing setup: the plugin and registry state are authoritative, and the
/// role files are a host projection that the next repair retries.
fn refresh_codex_role_projections(
    request: &legion_host::SetupRequest,
    inputs: &HostIntegrationInputs,
) -> Option<Value> {
    if !matches!(
        request.action,
        legion_host::SetupAction::Apply | legion_host::SetupAction::Repair
    ) {
        return None;
    }
    let skipped = |reason: &str| json!({"state":"skipped","reason":reason});
    let Some(codex) = inputs.codex.as_ref() else {
        return Some(skipped("codex-not-selected"));
    };
    if !should_process_client(request, legion_host::setup_registry::CLIENT_CODEX) {
        return Some(skipped("codex-absent"));
    }
    // Development contexts substitute their own home; only an installed run follows CODEX_HOME.
    let home = codex.home.clone();
    let codex_dir = if request.origin == legion_host::setup_registry::ORIGIN_DEVELOPMENT {
        home.join(".codex")
    } else {
        codex_home(&home)
    };
    Some(
        super::bind::refresh_codex_user_projections(&home, &codex_dir, true).unwrap_or_else(
            |error| json!({"state":"failed","codexHome":codex_dir,"error":error.message}),
        ),
    )
}

fn should_process_client(request: &legion_host::SetupRequest, client_id: &str) -> bool {
    match &request.selector {
        legion_host::ClientSelector::ClientId(selected) => selected == client_id,
        legion_host::ClientSelector::AllSupported => request
            .client_evidence
            .iter()
            .any(|evidence| evidence.client_id == client_id && evidence.detected),
    }
}

fn codex_legacy_projection_owned(
    request: &legion_host::SetupRequest,
) -> Result<bool, CommandError> {
    let inputs = host_integration_inputs(request)?;
    let projection_owned = inputs
        .client_projections
        .iter()
        .find(|input| input.client_id == legion_host::setup_registry::CLIENT_CODEX)
        .map(|input| {
            legion_host::setup_registry::inspect_client_projection(input)
                .map(|inspection| inspection.ownership == "legion")
                .map_err(setup_error)
        })
        .transpose()?
        .unwrap_or(false);
    let skill_ledger_owned = inputs
        .codex
        .as_ref()
        .map(|input| {
            legion_host::inspect_codex_skills(input)
                .map(|inspection| inspection.ledger_present && inspection.ledger_error.is_none())
                .map_err(host_error)
        })
        .transpose()?
        .unwrap_or(false);
    Ok(projection_owned || skill_ledger_owned)
}

fn should_mutate_client(request: &legion_host::SetupRequest, client_id: &str) -> bool {
    if !should_process_client(request, client_id) {
        return false;
    }
    if !matches!(
        request.action,
        legion_host::SetupAction::Apply | legion_host::SetupAction::Repair
    ) {
        return true;
    }
    !(matches!(&request.selector, legion_host::ClientSelector::AllSupported)
        && client_id == legion_host::setup_registry::CLIENT_PI)
}

fn host_integration_inputs(
    request: &legion_host::SetupRequest,
) -> Result<HostIntegrationInputs, CommandError> {
    if request.origin == legion_host::setup_registry::ORIGIN_DEVELOPMENT {
        let context = request.development.as_ref().ok_or_else(|| {
            CommandError::usage("development setup requires an explicit execution context")
        })?;
        return development_host_integration_inputs(&request.selector, &request.release, context);
    }
    host_integration_inputs_installed(&request.selector, &request.release)
}

fn host_integration_inputs_installed(
    selector: &legion_host::ClientSelector,
    release: &legion_host::BoundRelease,
) -> Result<HostIntegrationInputs, CommandError> {
    let installed = installed_release()?;
    if installed.manifest.release_version != release.release_version
        || installed.manifest.declarative_assets_sha256 != release.declarative_asset_schema_hash
    {
        return Err(CommandError::incomplete(
            "installed release changed while setup request was active",
        ));
    }
    let origin = installed.origin_evidence();
    let executable = origin.executable.clone();
    let install_root = origin.install_root.clone().ok_or_else(|| {
        CommandError::incomplete("installed release has no stable product install root")
    })?;
    let plugin_source_root = installed_plugin_source_root(&executable)?;
    let release_root = installed.manifest_path.parent().ok_or_else(|| {
        CommandError::incomplete("installed release manifest has no parent directory")
    })?;
    let assets_root = release_root.join("assets");
    let catalog =
        legion_catalog::load_compact(&assets_root, "registry/index.json").map_err(|error| {
            CommandError::incomplete(format!("installed catalog unavailable: {error}"))
        })?;
    let current_skill_ids = catalog
        .entries
        .into_iter()
        .map(|entry| entry.canonical_id)
        .collect::<Vec<_>>();
    let home = installed_host_home()?;
    let platform_state_root = legion_host::platform_state_root().map_err(setup_error)?;
    let skills_root = assets_root.join("skills");
    let claude =
        selector_includes(selector, "claude-code").then(|| legion_host::ClaudeLegacyInput {
            home: home.clone(),
            canonical_skills_root: skills_root.clone(),
            current_skill_ids: current_skill_ids.clone(),
        });
    let codex = selector_includes(selector, "codex").then(|| legion_host::CodexSkillsInput {
        home: home.clone(),
        assets_skills_root: skills_root,
        platform_state_root,
        current_skill_ids: current_skill_ids.clone(),
        retired_skill_ids: legion_host::RETIRED_SKILL_IDS
            .iter()
            .map(|id| (*id).into())
            .collect(),
        explicit_only: true,
        generation: format!(
            "{}:{}",
            release.release_version, release.declarative_asset_schema_hash
        ),
    });
    let generation = format!(
        "{}:{}",
        release.release_version, release.declarative_asset_schema_hash
    );
    let current_root = executable.parent().and_then(Path::parent).ok_or_else(|| {
        CommandError::incomplete("installed executable has no stable current root")
    })?;
    let marketplaces = [
        ("claude-code", legion_host::MarketplaceClient::ClaudeCode),
        ("codex", legion_host::MarketplaceClient::Codex),
    ]
    .into_iter()
    .filter(|(client_id, _)| selector_includes(selector, client_id))
    .map(|(_, client)| legion_host::MarketplaceBinding::new(client, current_root))
    .collect::<Vec<_>>();
    let client_projections = [
        (
            legion_host::setup_registry::CLIENT_CLAUDE,
            "native-plugin",
            // `~/.claude/plugins` is Claude Code's own state directory (its
            // marketplace cache, installed_plugins.json and blocklist); a
            // directory dropped there is never discovered, which is why Legion
            // projected 27 skills that no session could see while
            // `claude plugin list` showed nothing. A skills-directory plugin is
            // the documented way to install from a local path with no
            // marketplace: a directory under ~/.claude/skills carrying
            // .claude-plugin/plugin.json loads as `legion@skills-dir`.
            home.join(".claude/skills/legion"),
            true,
            false,
            plugin_source_root.clone(),
        ),
        (
            legion_host::setup_registry::CLIENT_CODEX,
            "agent-plugins-with-explicit-sidecar",
            home.join(".codex/plugins/legion"),
            true,
            true,
            plugin_source_root.clone(),
        ),
        (
            legion_host::setup_registry::CLIENT_CURSOR,
            "agent-plugins-with-thin-sidecar",
            home.join(".cursor/plugins/legion"),
            true,
            false,
            plugin_source_root.clone(),
        ),
        (
            legion_host::setup_registry::CLIENT_PI,
            "skills-only",
            home.join(".agents/skills"),
            false,
            true,
            assets_root.join("skills"),
        ),
        (
            legion_host::setup_registry::CLIENT_ANTIGRAVITY,
            "agent-plugins-portable-core",
            home.join(".antigravity/plugins/legion"),
            true,
            false,
            plugin_source_root.clone(),
        ),
        (
            legion_host::setup_registry::CLIENT_DEVIN,
            "devin-user",
            devin_config_root(&home),
            true,
            false,
            plugin_source_root,
        ),
    ]
    .into_iter()
    .filter(|(client_id, ..)| selector_includes(selector, client_id))
    .map(
        |(
            client_id,
            projection,
            target_root,
            executable_registration,
            explicit_only,
            source_root,
        )| {
            Ok(legion_host::setup_registry::ClientProjectionInput {
                client_id: client_id.into(),
                projection: projection.into(),
                source_root,
                target_root,
                state_root: legion_host::platform_state_root().map_err(setup_error)?,
                origin: legion_host::setup_registry::ORIGIN_INSTALLED.into(),
                executable: Some(executable.clone()),
                install_root: Some(install_root.clone()),
                generation: generation.clone(),
                executable_registration,
                explicit_only,
                skill_ids: current_skill_ids.clone(),
                host_config_root: installed_host_home().ok(),
            })
        },
    )
    .collect::<Result<Vec<_>, CommandError>>()?;
    Ok(HostIntegrationInputs {
        claude,
        codex,
        marketplaces,
        client_projections,
    })
}

fn installed_plugin_source_root(executable: &Path) -> Result<PathBuf, CommandError> {
    executable
        .parent()
        .and_then(Path::parent)
        .map(|current| current.join("plugin"))
        .ok_or_else(|| CommandError::incomplete("installed executable has no stable current root"))
}

/// Devin's user configuration root — `%APPDATA%\devin` on Windows and
/// `~/.config/devin` elsewhere — resolved relative to the inspected home so
/// development contexts substitute their own client root.
fn devin_config_root(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("AppData").join("Roaming").join("devin")
    } else {
        home.join(".config").join("devin")
    }
}

fn installed_host_home() -> Result<PathBuf, CommandError> {
    let home = if cfg!(windows) {
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| {
                let drive = std::env::var_os("HOMEDRIVE")?;
                let path = std::env::var_os("HOMEPATH")?;
                Some(PathBuf::from(drive).join(path))
            })
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    .ok_or_else(|| CommandError::incomplete("native host home directory is unavailable"))?;
    if !home.is_absolute()
        || home
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(CommandError::incomplete(
            "native host home directory is not an absolute platform path",
        ));
    }
    Ok(home)
}

fn development_host_integration_inputs(
    selector: &legion_host::ClientSelector,
    release: &legion_host::BoundRelease,
    context: &legion_host::DevelopmentSetupContext,
) -> Result<HostIntegrationInputs, CommandError> {
    let repo_assets = context.repository_root.join("engine/assets/legion-plugin");
    let state_root = context.state_root.clone();
    let home = state_root.join("clients");
    let source = |client_id: &str, fallback: PathBuf| {
        context
            .client_overrides
            .get(client_id)
            .map(|item| item.source_root.clone())
            .unwrap_or(fallback)
    };
    let target = |client_id: &str, fallback: PathBuf| {
        context
            .client_overrides
            .get(client_id)
            .map(|item| item.target_root.clone())
            .unwrap_or(fallback)
    };
    let plugin_source = source("claude-code", repo_assets.clone());
    let skills_source = source("pi", repo_assets.join("skills"));
    let current_skill_ids = Vec::new();
    let claude =
        selector_includes(selector, "claude-code").then(|| legion_host::ClaudeLegacyInput {
            home: home.clone(),
            canonical_skills_root: plugin_source.join("skills"),
            current_skill_ids: current_skill_ids.clone(),
        });
    let codex = selector_includes(selector, "codex").then(|| legion_host::CodexSkillsInput {
        home: home.clone(),
        assets_skills_root: skills_source.clone(),
        platform_state_root: state_root.clone(),
        current_skill_ids: current_skill_ids.clone(),
        retired_skill_ids: legion_host::RETIRED_SKILL_IDS
            .iter()
            .map(|id| (*id).into())
            .collect(),
        explicit_only: true,
        generation: format!(
            "{}:{}",
            release.release_version, release.declarative_asset_schema_hash
        ),
    });
    let generation = format!(
        "{}:{}",
        release.release_version, release.declarative_asset_schema_hash
    );
    let definitions = [
        (
            legion_host::setup_registry::CLIENT_CLAUDE,
            "native-plugin",
            true,
            false,
            repo_assets.clone(),
            // Mirrors the installed target: a skills-directory plugin, the only
            // documented local-path install for Claude Code.
            home.join("claude/skills/legion"),
        ),
        (
            legion_host::setup_registry::CLIENT_CODEX,
            "agent-plugins-with-explicit-sidecar",
            true,
            true,
            repo_assets.clone(),
            home.join("codex/plugins/legion"),
        ),
        (
            legion_host::setup_registry::CLIENT_CURSOR,
            "agent-plugins-with-thin-sidecar",
            true,
            false,
            repo_assets.clone(),
            home.join("cursor/plugins/legion"),
        ),
        (
            legion_host::setup_registry::CLIENT_PI,
            "skills-only",
            false,
            true,
            repo_assets.join("skills"),
            home.join("agents/skills"),
        ),
        (
            legion_host::setup_registry::CLIENT_ANTIGRAVITY,
            "agent-plugins-portable-core",
            true,
            false,
            repo_assets.clone(),
            home.join("antigravity/plugins/legion"),
        ),
        (
            legion_host::setup_registry::CLIENT_DEVIN,
            "devin-user",
            true,
            false,
            repo_assets,
            devin_config_root(&home),
        ),
    ];
    let client_projections = definitions
        .into_iter()
        .filter(|(id, ..)| selector_includes(selector, id))
        .map(
            |(
                client_id,
                projection,
                executable_registration,
                explicit_only,
                fallback_source,
                fallback_target,
            )| {
                let source_root = source(client_id, fallback_source);
                let target_root = target(client_id, fallback_target);
                Ok(legion_host::setup_registry::ClientProjectionInput {
                    client_id: client_id.into(),
                    projection: projection.into(),
                    source_root,
                    target_root,
                    state_root: state_root.clone(),
                    origin: legion_host::setup_registry::ORIGIN_DEVELOPMENT.into(),
                    executable: Some(std::env::current_exe().map_err(io_error)?),
                    install_root: None,
                    generation: generation.clone(),
                    executable_registration,
                    explicit_only,
                    skill_ids: current_skill_ids.clone(),
                    host_config_root: Some(home.clone()),
                })
            },
        )
        .collect::<Result<Vec<_>, CommandError>>()?;
    Ok(HostIntegrationInputs {
        claude,
        codex,
        marketplaces: Vec::new(),
        client_projections,
    })
}

fn projection_key(client_id: &str) -> &'static str {
    match client_id {
        legion_host::setup_registry::CLIENT_CLAUDE => "claudePlugin",
        legion_host::setup_registry::CLIENT_CODEX => "codexPlugin",
        legion_host::setup_registry::CLIENT_CURSOR => "cursorPlugin",
        legion_host::setup_registry::CLIENT_PI => "piSkills",
        legion_host::setup_registry::CLIENT_ANTIGRAVITY => "antigravityPlugin",
        legion_host::setup_registry::CLIENT_DEVIN => "devinUserSurfaces",
        _ => "unknownPlugin",
    }
}

fn selector_includes(selector: &legion_host::ClientSelector, client_id: &str) -> bool {
    match selector {
        legion_host::ClientSelector::AllSupported => true,
        legion_host::ClientSelector::ClientId(selected) => selected == client_id,
    }
}

fn host_error(error: legion_host::HostError) -> CommandError {
    CommandError::incomplete(format!("host integration failed: {error}"))
}

fn installed_bound_release() -> Result<legion_host::BoundRelease, CommandError> {
    let installed = installed_release()?;
    Ok(bound_release(&installed.manifest))
}

fn bound_release(manifest: &legion_runtime::ReleaseManifest) -> legion_host::BoundRelease {
    legion_host::BoundRelease {
        release_version: manifest.release_version.clone(),
        runtime_digest: manifest.runtime.sha256.clone(),
        capability_catalog_hash: manifest.capability_catalog_sha256.clone(),
        mcp_tool_schema_hash: manifest.mcp_tool_schema_sha256.clone(),
        declarative_asset_schema_hash: manifest.declarative_assets_sha256.clone(),
        state_compatibility: manifest.state_schema_version.to_string(),
    }
}

fn installed_release() -> Result<legion_runtime::release_binding::InstalledRelease, CommandError> {
    legion_runtime::release_binding::load_installed_release().map_err(|error| {
        CommandError::incomplete(format!(
            "installed release binding unavailable: {error}; run legion setup repair --confirm"
        ))
    })
}

fn discovered_client_evidence(selected: Option<&str>) -> Vec<legion_host::ClientEvidence> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    let clients = [
        (
            legion_host::setup_registry::CLIENT_CLAUDE,
            ".claude",
            vec!["claude-native-plugin", QUALIFICATION_MECHANISM],
        ),
        (
            legion_host::setup_registry::CLIENT_CODEX,
            ".codex",
            vec!["codex-agent-plugins", QUALIFICATION_MECHANISM],
        ),
        (
            legion_host::setup_registry::CLIENT_CURSOR,
            ".cursor",
            vec!["cursor-agent-plugins"],
        ),
        (
            legion_host::setup_registry::CLIENT_PI,
            ".agents",
            vec!["pi-skills-only"],
        ),
        (
            legion_host::setup_registry::CLIENT_ANTIGRAVITY,
            ".antigravity",
            vec!["antigravity-agent-plugins-portable-core"],
        ),
        (
            legion_host::setup_registry::CLIENT_DEVIN,
            if cfg!(windows) {
                "AppData/Roaming/devin"
            } else {
                ".config/devin"
            },
            vec!["devin-user-surfaces"],
        ),
    ];
    clients
        .into_iter()
        .filter_map(|(client_id, relative, mechanisms)| {
            if selected.is_some_and(|value| value != client_id) {
                return None;
            }
            let detected = home
                .as_ref()
                .map(|path| path.join(relative).is_dir())
                .unwrap_or(false);
            if selected.is_none() && !detected {
                return None;
            }
            Some(legion_host::ClientEvidence {
                client_id: client_id.into(),
                detected,
                mechanisms: mechanisms.into_iter().map(String::from).collect(),
                command_proof_ref: None,
                qualification_evidence_ref: None,
            })
        })
        .collect()
}

fn development_client_evidence(selected: Option<&str>) -> Vec<legion_host::ClientEvidence> {
    [
        legion_host::setup_registry::CLIENT_CLAUDE,
        legion_host::setup_registry::CLIENT_CODEX,
        legion_host::setup_registry::CLIENT_CURSOR,
        legion_host::setup_registry::CLIENT_PI,
        legion_host::setup_registry::CLIENT_ANTIGRAVITY,
        legion_host::setup_registry::CLIENT_DEVIN,
    ]
    .into_iter()
    .filter(|id| selected.is_none_or(|value| value == *id))
    .map(|client_id| legion_host::ClientEvidence {
        client_id: client_id.into(),
        detected: true,
        mechanisms: vec!["development-explicit-context".into()],
        command_proof_ref: None,
        qualification_evidence_ref: None,
    })
    .collect()
}

fn open_registry(
    request: &legion_host::SetupRequest,
) -> Result<legion_host::SetupRegistry<legion_host::OnDiskSetupStore>, CommandError> {
    if request.origin == legion_host::setup_registry::ORIGIN_DEVELOPMENT {
        let context = request.development.as_ref().ok_or_else(|| {
            CommandError::usage("development setup requires an explicit execution context")
        })?;
        if request.release != bound_release_for_context(Some(context))? {
            return Err(setup_error(legion_host::SetupError {
                code: legion_host::SetupErrorCode::ReleaseBindingMismatch,
                remediation: "development setup plan release differs from its explicit context; regenerate the plan".into(),
            }));
        }
        return legion_host::SetupRegistry::open_development(request.release.clone(), context)
            .map_err(setup_error);
    }
    let release = installed_bound_release()?;
    if request.release != release {
        return Err(setup_error(legion_host::SetupError {
            code: legion_host::SetupErrorCode::ReleaseBindingMismatch,
            remediation:
                "setup plan release differs from installed release; run legion setup repair --confirm"
                    .into(),
        }));
    }
    legion_host::SetupRegistry::open_platform(release).map_err(setup_error)
}

fn selector(client: Option<String>) -> legion_host::ClientSelector {
    client
        .filter(|client| !client.trim().is_empty())
        .map(legion_host::ClientSelector::ClientId)
        .unwrap_or(legion_host::ClientSelector::AllSupported)
}

fn bound_release_for_context(
    context: Option<&legion_host::DevelopmentSetupContext>,
) -> Result<legion_host::BoundRelease, CommandError> {
    if context.is_none() {
        return installed_bound_release();
    }
    Ok(legion_host::BoundRelease {
        release_version: format!("development-{}", EXPECTED_RELEASE_VERSION),
        runtime_digest: "development".into(),
        capability_catalog_hash: "development".into(),
        mcp_tool_schema_hash: "development".into(),
        declarative_asset_schema_hash: "development".into(),
        state_compatibility: "development".into(),
    })
}

async fn development_status(
    args: SetupClientArgs,
    context: legion_host::DevelopmentSetupContext,
    cancellation: CancellationToken,
) -> CommandResult {
    let release = bound_release_for_context(Some(&context))?;
    let selector = selector(args.client);
    let platform_state_root = context.state_root.clone();
    let evidence = discovered_client_evidence(None);
    let request = legion_host::SetupRequest {
        action: legion_host::SetupAction::Status,
        selector: selector.clone(),
        release: release.clone(),
        platform_state_root,
        client_evidence: evidence,
        dry_run: true,
        origin: legion_host::setup_registry::ORIGIN_DEVELOPMENT.into(),
        development: Some(context.clone()),
    };
    let mut registry =
        legion_host::SetupRegistry::open_development(release, &context).map_err(setup_error)?;
    let recovery = registry.recover().map_err(setup_error)?;
    let clients = registry.status(&selector).map_err(setup_error)?;
    let integrations = preview_host_integrations(&request, cancellation).await?;
    let clients_value = serde_json::to_value(&clients)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let identity = inspect_live_identity(&integrations, request.development.as_ref())?;
    let clients_value = enrich_client_statuses(clients_value, &identity);
    let (status, remediation) = setup_health(&clients_value, &integrations, &identity);
    Ok(json!({
        "schemaVersion": 1, "kind": "legion-setup-status", "status": status,
        "origin": legion_host::setup_registry::ORIGIN_DEVELOPMENT,
        "executable": identity.get("executablePath"), "installRoot": Value::Null,
        "generation": identity.get("generation"), "development": context,
        "port": identity.get("port"), "processIdentity": identity.get("processIdentity"),
        "remediation": remediation, "recovery": recovery, "clients": clients_value,
        "hostIntegrations": integrations, "liveIdentity": identity,
    }))
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: impl AsRef<std::path::Path>,
    kind: &str,
) -> Result<T, CommandError> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(io_error)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CommandError::usage(format!("invalid {kind} at {}: {error}", path.display()))
    })
}

fn write_json<T: Serialize>(path: &PathBuf, value: &T) -> Result<(), CommandError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(io_error)?;
    std::fs::write(path, bytes).map_err(io_error)
}

fn setup_error(error: legion_host::SetupError) -> CommandError {
    CommandError::incomplete(format!("{:?}: {}", error.code, error.remediation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "legion-setup-live-{}-{}-{}-{}",
                std::process::id(),
                label,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).expect("temporary setup root");
            Self(root)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_release_manifest() -> legion_runtime::ReleaseManifest {
        let digest = "0".repeat(64);
        legion_runtime::ReleaseManifest {
            release_version: EXPECTED_RELEASE_VERSION.into(),
            runtime: legion_runtime::RuntimeIdentity {
                platform: std::env::consts::OS.into(),
                architecture: legion_runtime::release_binding::current_runtime_architecture()
                    .into(),
                sha256: digest.clone(),
                provenance: "rightkit-release://setup-live-test".into(),
            },
            capability_catalog_sha256: digest.clone(),
            mcp_tool_schema_sha256: digest.clone(),
            declarative_assets_sha256: digest,
            state_schema_version: 1,
            rightkit_ax: legion_runtime::RightkitAxIdentity {
                version: "0.2.1".into(),
                source_commit: "4c1a414269d8ffdb95b4b1e685440bd34784b41b".into(),
            },
            portable_core_sha256: None,
            plugin_sha256: None,
            native_marketplaces: None,
        }
    }

    fn write_release(path: &Path, manifest: &legion_runtime::ReleaseManifest) {
        fs::create_dir_all(path.parent().expect("release parent")).expect("release directory");
        fs::write(
            path,
            serde_json::to_vec(manifest).expect("release manifest JSON"),
        )
        .expect("release manifest");
    }

    fn write_plugin_manifest(root: &Path, version: &str) {
        let path = root.join(".claude-plugin/plugin.json");
        fs::create_dir_all(path.parent().expect("plugin manifest parent"))
            .expect("plugin manifest directory");
        fs::write(
            path,
            serde_json::to_vec(&json!({"name": "legion", "version": version}))
                .expect("plugin manifest JSON"),
        )
        .expect("plugin manifest");
    }

    fn installed_health_identity(root: &Path) -> Value {
        let install_root = root.join("Legion");
        let current_root = install_root.join("current");
        let executable = current_root.join(if cfg!(windows) {
            "bin/legion.exe"
        } else {
            "bin/legion"
        });
        fs::create_dir_all(executable.parent().expect("health executable parent"))
            .expect("health executable directory");
        fs::write(&executable, b"legion").expect("health executable");
        let resolved_install_root = fs::canonicalize(&current_root).expect("health current root");
        let resolved_executable = fs::canonicalize(&executable).expect("health executable path");
        json!({
            "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
            "stableCurrent": true,
            "installRoot": install_root.clone(),
            "stableCurrentRoot": current_root,
            "resolvedExecutable": resolved_executable,
            "resolvedInstallRoot": resolved_install_root,
            "generation": "active-generation",
            "executable": {
                "state": "current",
                "path": executable,
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "installRoot": install_root,
            },
            "plugin": {"state": "current"},
        })
    }

    #[test]
    fn m1_result_parser_preserves_host_requirements_and_degradation() {
        let value = json!({
            "releaseVersion": "1.0.0",
            "capabilityCount": 2,
            "status": "complete",
            "hostRequirements": [{
                "id": "python-runtime",
                "availability": "unavailable",
                "degradation": "worker unavailable",
                "remedy": "install Python",
                "probe": {"kind": "command-any", "commands": ["python3", "python"]}
            }],
            "capabilities": [
                {"capabilityId": "seo", "availability": "unavailable", "degraded": true, "requirements": []},
                {"capabilityId": "writing", "availability": "available", "degraded": false, "requirements": []}
            ],
            "degradedCount": 1
        });
        let parsed = parse_m1_status_data("codex", &value, "1.0.0")
            .expect("parse")
            .expect("matching status");
        assert_eq!(parsed.capability_count, 2);
        assert_eq!(parsed.host_requirements.len(), 1);
        assert_eq!(parsed.capabilities.len(), 2);
        assert_eq!(parsed.degraded_count, 1);
        assert_eq!(
            parsed.host_requirements[0]["degradation"],
            "worker unavailable"
        );
    }

    #[tokio::test]
    async fn structural_validation_accepts_null_proof_refs_without_live_calls() {
        let temp = TempRoot::new("missing-proof-refs");
        let manifest = test_release_manifest();
        let release = bound_release(&manifest);
        for (command_proof_ref, qualification_evidence_ref) in [
            (None, Some("qualification.json")),
            (Some("command.json"), None),
            (None, None),
        ] {
            let evidence = vec![legion_host::ClientEvidence {
                client_id: "codex".into(),
                detected: true,
                mechanisms: vec![QUALIFICATION_MECHANISM.into()],
                command_proof_ref: command_proof_ref.map(str::to_owned),
                qualification_evidence_ref: qualification_evidence_ref.map(str::to_owned),
            }];
            validate_client_evidence(
                &evidence,
                Some("codex"),
                &release,
                &temp.0,
                false,
                CancellationToken::new(),
            )
            .await
            .expect("structural setup must not require authenticated proof refs");

            let live = validate_live_evidence_refs(&evidence, Some("codex"))
                .expect_err("explicit live qualification still requires both proof refs");
            assert_eq!(live.code, 2);
            assert!(live.message.contains("legion setup qualify"));
        }
    }

    #[test]
    fn setup_status_separates_not_run_live_qualification_from_activation() {
        let temp = TempRoot::new("qualification-not-run");
        let manifest = test_release_manifest();
        let release = bound_release(&manifest);
        let clients = vec![legion_host::ClientStatus {
            client_id: "codex".into(),
            installed: true,
            fidelity: "Full".into(),
            bound_release: Some(release.clone()),
            missing_surfaces: Vec::new(),
            remediation: Vec::new(),
        }];

        let health = inspect_stored_live_qualification(&clients, &release, &temp.0);

        assert_eq!(health["status"], "not_run");
        assert_eq!(health["activationRequired"], false);
        assert_eq!(health["clients"][0]["clientId"], "codex");
        assert_eq!(health["clients"][0]["status"], "not_run");
    }

    #[test]
    fn installed_plugin_projection_reads_stable_current_payload_root() {
        let executable =
            PathBuf::from("product")
                .join("current")
                .join("bin")
                .join(if cfg!(windows) {
                    "legion.exe"
                } else {
                    "legion"
                });

        let root = installed_plugin_source_root(&executable).expect("stable plugin root");

        assert_eq!(
            root,
            PathBuf::from("product").join("current").join("plugin")
        );
    }

    #[test]
    fn qualification_output_reports_auth_without_session_payload() {
        let detail = concise_client_output_detail(
            br#"{"session_id":"private","result":"Not logged in - Please run /login"}"#,
            b"",
        )
        .expect("auth detail");

        assert_eq!(
            detail,
            "client is not logged in; run /login, then retry legion setup qualify"
        );
        assert!(!detail.contains("session_id"));
    }

    #[test]
    fn live_plugin_identity_accepts_native_release_and_current_claude_cache() {
        let temp = TempRoot::new("current");
        let native_root = temp.0.join("native/share/legion");
        let current_cache = temp.0.join("cache/0.1.0");
        let old_cache = temp.0.join("cache/0.1.0-dev.3");
        let manifest = test_release_manifest();
        write_release(&native_root.join("release.json"), &manifest);
        write_plugin_manifest(&current_cache, EXPECTED_RELEASE_VERSION);
        write_plugin_manifest(&old_cache, "0.1.0-dev.3");

        let installed = legion_runtime::release_binding::InstalledRelease {
            manifest: manifest.clone(),
            manifest_path: native_root.join("release.json"),
            executable_path: temp.0.join("bin/legion.exe"),
        };
        let integrations = json!({
            "claudeCodeLegacy": {
                "inspection": {
                    "pluginCacheGenerations": [
                        {"installPath": current_cache.clone(), "version": EXPECTED_RELEASE_VERSION},
                        {"installPath": old_cache.clone(), "version": "0.1.0-dev.3"}
                    ]
                }
            }
        });

        let inspected = inspect_live_plugin(&installed, &integrations);
        assert_eq!(inspected["state"], "current");
        let roots = inspected["roots"].as_array().expect("plugin roots");
        let native = roots
            .iter()
            .find(|root| root["canonicalNativeRoot"] == true)
            .expect("native release root");
        assert_eq!(native["state"], "current");
        assert!(native["releaseIdentities"]
            .as_array()
            .expect("native identities")
            .iter()
            .any(|identity| {
                identity["kind"] == "canonical" && identity["matchesActiveRelease"] == true
            }));
        let cache_state = |path: &Path| {
            roots
                .iter()
                .find(|root| root["root"].as_str() == path.to_str())
                .and_then(|root| root["state"].as_str())
        };
        assert_eq!(cache_state(&current_cache), Some("current"));
        assert_eq!(cache_state(&old_cache), Some("stale"));
    }

    #[test]
    fn live_plugin_identity_marks_mismatched_native_release_stale() {
        let temp = TempRoot::new("mismatch");
        let native_root = temp.0.join("native/share/legion");
        let active = test_release_manifest();
        let mut mismatched = active.clone();
        mismatched.release_version = "0.1.0-dev.3".into();
        write_release(&native_root.join("release.json"), &mismatched);

        let inspected = inspect_plugin_root(&native_root, Some(&native_root), &active);

        assert_eq!(inspected["state"], "stale");
        assert_eq!(
            inspected["releaseIdentities"]
                .as_array()
                .expect("native identities")
                .len(),
            1
        );
        assert_eq!(
            inspected["releaseIdentities"][0]["matchesActiveRelease"],
            false
        );
    }

    #[test]
    fn setup_health_uses_supported_repair_command() {
        let clients = json!([{
            "clientId": "codex",
            "installed": false,
            "fidelity": "Unavailable"
        }]);
        let live_identity = json!({
            "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
            "executable": {"state": "current"},
            "plugin": {"state": "current"},
            "projections": {"codexSkills": {"state": "stale"}}
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);

        assert_eq!(status, "incomplete");
        assert!(remediation.iter().any(|item| {
            item == "client codex is incomplete (Unavailable); run legion setup repair --confirm"
        }));
        assert!(remediation
            .iter()
            .all(|item| !item.starts_with("codexSkills projection")));
        assert!(remediation
            .iter()
            .all(|item| !item.contains("legion setup --repair")));
    }

    #[test]
    fn setup_health_completes_requested_clients_with_optional_pi_baseline() {
        let temp = TempRoot::new("mixed-optional-pi");
        let clients = json!([
            {"clientId": "claude-code", "installed": true, "fidelity": "Full"},
            {"clientId": "codex", "installed": true, "fidelity": "Full"},
            {
                "clientId": "pi",
                "installed": true,
                "fidelity": "Baseline",
                "missingSurfaces": [
                    "executableToolSurface",
                    "mcpLifecycle",
                    "releaseBinding",
                    "executableResolution",
                    "hostEnforcement"
                ],
                "explicitOnly": true
            }
        ]);
        let mut live_identity = installed_health_identity(&temp.0);
        live_identity["projections"] = json!({
            "claudePlugin": {"clientId": "claude-code", "state": "current"},
            "codexPlugin": {"clientId": "codex", "state": "current"},
            "piSkills": {
                "clientId": "pi",
                "state": "stale",
                "explicitOnly": true,
                "generation": "old-generation",
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable": "/outside/current/bin/legion",
                "installRoot": "/outside"
            }
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);

        assert_eq!(status, "complete");
        assert!(remediation.iter().any(|item| {
            item.contains("client pi is optional (Baseline)")
                && item.contains("executableToolSurface")
        }));
        assert!(remediation
            .iter()
            .all(|item| !item.contains("piSkills resolved target escaped active release")));
    }

    #[test]
    fn setup_health_rejects_pi_baseline_without_full_supported_client() {
        let clients = json!([{
            "clientId": "pi",
            "installed": true,
            "fidelity": "Baseline",
            "missingSurfaces": ["executableToolSurface"],
            "explicitOnly": true
        }]);
        let live_identity = json!({
            "origin": legion_host::setup_registry::ORIGIN_DEVELOPMENT,
            "executable": {"state": "current"}
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);

        assert_eq!(status, "incomplete");
        assert!(remediation.iter().any(|item| {
            item == "optional Pi Baseline is present but no Full supported client is active"
        }));

        let uninstalled = json!([{
            "clientId": "pi",
            "installed": false,
            "fidelity": "Baseline",
            "explicitOnly": true
        }]);
        let (status, remediation) = setup_health(&uninstalled, &json!({}), &live_identity);
        assert_eq!(status, "incomplete");
        assert!(remediation
            .iter()
            .any(|item| item == "client pi is incomplete (Baseline); rerun setup --development with identical context and repair --confirm"));
    }

    #[test]
    fn global_apply_and_repair_skip_pi_but_scoped_non_pi_repairs_mutate() {
        let evidence = vec![
            legion_host::ClientEvidence {
                client_id: legion_host::setup_registry::CLIENT_PI.into(),
                detected: true,
                mechanisms: vec!["pi-skills-only".into()],
                command_proof_ref: None,
                qualification_evidence_ref: None,
            },
            legion_host::ClientEvidence {
                client_id: legion_host::setup_registry::CLIENT_CODEX.into(),
                detected: true,
                mechanisms: vec!["codex-agent-plugins".into()],
                command_proof_ref: None,
                qualification_evidence_ref: None,
            },
        ];
        for action in [
            legion_host::SetupAction::Apply,
            legion_host::SetupAction::Repair,
        ] {
            let request = legion_host::SetupRequest {
                action: action.clone(),
                selector: legion_host::ClientSelector::AllSupported,
                release: bound_release(&test_release_manifest()),
                platform_state_root: PathBuf::from("/tmp/legion-setup-test-state"),
                client_evidence: evidence.clone(),
                dry_run: false,
                origin: legion_host::setup_registry::ORIGIN_DEVELOPMENT.into(),
                development: None,
            };
            assert!(!should_mutate_client(
                &request,
                legion_host::setup_registry::CLIENT_PI
            ));
            assert!(should_mutate_client(
                &request,
                legion_host::setup_registry::CLIENT_CODEX
            ));
        }
    }

    #[test]
    fn codex_role_projection_refresh_follows_detection_and_is_idempotent() {
        let root = TempRoot::new("codex-roles");
        let home = root.0.join("home");
        let state = root.0.join("state");
        let request = |action: legion_host::SetupAction, detected: bool| legion_host::SetupRequest {
            action,
            selector: legion_host::ClientSelector::AllSupported,
            release: bound_release(&test_release_manifest()),
            platform_state_root: state.clone(),
            client_evidence: vec![legion_host::ClientEvidence {
                client_id: legion_host::setup_registry::CLIENT_CODEX.into(),
                detected,
                mechanisms: vec!["codex-agent-plugins".into()],
                command_proof_ref: None,
                qualification_evidence_ref: None,
            }],
            dry_run: false,
            origin: legion_host::setup_registry::ORIGIN_DEVELOPMENT.into(),
            development: None,
        };
        let inputs = |with_codex: bool| HostIntegrationInputs {
            claude: None,
            codex: with_codex.then(|| legion_host::CodexSkillsInput {
                home: home.clone(),
                assets_skills_root: root.0.join("skills"),
                platform_state_root: state.clone(),
                current_skill_ids: Vec::new(),
                retired_skill_ids: Vec::new(),
                explicit_only: true,
                generation: "test".into(),
            }),
            marketplaces: Vec::new(),
            client_projections: Vec::new(),
        };
        let codex_dir = home.join(".codex");

        // Not an apply or repair: nothing is reported or written.
        assert!(refresh_codex_role_projections(
            &request(legion_host::SetupAction::Status, true),
            &inputs(true)
        )
        .is_none());
        // Codex absent or unselected: a typed skip, and nothing is created.
        let absent = refresh_codex_role_projections(
            &request(legion_host::SetupAction::Repair, false),
            &inputs(true),
        )
        .unwrap();
        assert_eq!(absent["state"], "skipped");
        assert_eq!(absent["reason"], "codex-absent");
        let unselected = refresh_codex_role_projections(
            &request(legion_host::SetupAction::Repair, true),
            &inputs(false),
        )
        .unwrap();
        assert_eq!(unselected["reason"], "codex-not-selected");
        assert!(!codex_dir.exists());

        // Codex present: every role including the Alchemist specialist is written.
        let first = refresh_codex_role_projections(
            &request(legion_host::SetupAction::Repair, true),
            &inputs(true),
        )
        .unwrap();
        assert_eq!(first["state"], "refreshed");
        assert!(codex_dir.join("agents/alchemist-specialist.toml").is_file());
        let config = fs::read_to_string(codex_dir.join("config.toml")).unwrap();
        assert!(config.contains("[agents.alchemist-specialist]"));
        // A rerun changes nothing.
        let second = refresh_codex_role_projections(
            &request(legion_host::SetupAction::Apply, true),
            &inputs(true),
        )
        .unwrap();
        assert_eq!(second["state"], "current");
        assert_eq!(
            fs::read_to_string(codex_dir.join("config.toml")).unwrap(),
            config
        );
    }

    #[test]
    fn setup_health_ignores_unregistered_client_projections() {
        let clients = json!([{
            "clientId": "codex",
            "installed": true,
            "fidelity": "Full"
        }]);
        let live_identity = json!({
            "origin": legion_host::setup_registry::ORIGIN_DEVELOPMENT,
            "executable": {"state": "current"},
            "plugin": {"state": "not_selected"},
            "projections": {
                "codexPlugin": {"clientId": "codex", "state": "current"},
                "cursorPlugin": {"clientId": "cursor", "state": "unavailable"}
            }
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);

        assert_eq!(status, "complete");
        assert!(remediation.is_empty());
    }

    #[test]
    fn setup_health_advises_but_completes_for_absent_opt_in_projections() {
        let temp = TempRoot::new("opt-in-absent");
        let clients = json!([{
            "clientId": "codex",
            "installed": true,
            "fidelity": "Full"
        }]);
        let mut live_identity = installed_health_identity(&temp.0);
        live_identity["projections"] = json!({
            "codexPlugin": {
                "clientId": "codex",
                "state": "stale",
                "explicitOnly": true,
                "ownership": "available",
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable": live_identity["executable"]["path"].clone(),
                "installRoot": live_identity["executable"]["installRoot"].clone(),
            },
            "codexSkills": {
                "clientId": "codex",
                "state": "stale",
                "explicitOnly": true,
                "ownership": "available",
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable": live_identity["executable"]["path"].clone(),
                "installRoot": live_identity["executable"]["installRoot"].clone(),
            }
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);

        assert_eq!(status, "complete");
        assert_eq!(remediation.len(), 2);
        assert!(remediation
            .iter()
            .all(|item| item.contains("opt-in, so repair leaves it alone")));
    }

    #[test]
    fn setup_health_advises_but_completes_for_stale_opt_in_generation() {
        let temp = TempRoot::new("opt-in-stale-generation");
        let clients = json!([{
            "clientId": "pi",
            "installed": true,
            "fidelity": "Full"
        }]);
        let mut live_identity = installed_health_identity(&temp.0);
        live_identity["generation"] = json!("0.3.19:current");
        live_identity["projections"] = json!({
            "piSkills": {
                "clientId": "pi",
                "state": "stale",
                "explicitOnly": true,
                "generation": "0.3.13:old",
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable": live_identity["executable"]["path"].clone(),
                "installRoot": live_identity["executable"]["installRoot"].clone(),
                // This scenario varies only the generation. The active binding
                // still needs the same resolved-path evidence as production.
                "resolvedExecutable": live_identity["resolvedExecutable"].clone(),
                "resolvedInstallRoot": live_identity["resolvedInstallRoot"].clone(),
            }
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);

        assert_eq!(status, "complete");
        assert!(remediation
            .iter()
            .any(|item| item.contains("piSkills generation 0.3.13:old is stale")));
        assert!(remediation
            .iter()
            .all(|item| item.contains("opt-in, so repair leaves it alone")));
    }

    #[test]
    fn setup_health_does_not_excuse_unproven_binding_for_opt_in_projection() {
        let temp = TempRoot::new("opt-in-unproven-binding");
        let clients = json!([{"clientId":"pi", "installed":true, "fidelity":"Full"}]);
        let mut live_identity = installed_health_identity(&temp.0);
        live_identity["projections"] = json!({
            "piSkills": {
                "clientId":"pi", "state":"stale", "explicitOnly":true,
                "generation":"old-generation",
                "origin":legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable":live_identity["executable"]["path"].clone(),
                "installRoot":live_identity["executable"]["installRoot"].clone()
            }
        });
        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);
        assert_eq!(status, "incomplete");
        assert!(remediation
            .iter()
            .any(|item| item.contains("piSkills resolved target escaped active release")));
    }

    #[test]
    fn setup_health_keeps_stale_non_opt_in_projection_incomplete() {
        let temp = TempRoot::new("non-opt-in-stale");
        let clients = json!([{
            "clientId": "cursor",
            "installed": true,
            "fidelity": "Full"
        }]);
        let mut live_identity = installed_health_identity(&temp.0);
        live_identity["projections"] = json!({
            "cursorPlugin": {
                "clientId": "cursor",
                "state": "stale",
                "explicitOnly": false,
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable": live_identity["executable"]["path"].clone(),
                "installRoot": live_identity["executable"]["installRoot"].clone(),
                "resolvedExecutable": live_identity["resolvedExecutable"].clone(),
                "resolvedInstallRoot": live_identity["resolvedInstallRoot"].clone(),
                "generation": "old-generation"
            }
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);

        assert_eq!(status, "incomplete");
        assert!(remediation
            .iter()
            .any(|item| item.starts_with("cursorPlugin projection is stale;")));
    }

    #[test]
    fn setup_health_blocks_escaped_binding_on_current_explicit_projection() {
        let temp = TempRoot::new("current-explicit-binding");
        let clients = json!([{
            "clientId": "codex",
            "installed": true,
            "fidelity": "Full"
        }]);
        let mut live_identity = installed_health_identity(&temp.0);
        let escaped = temp.0.join("outside/current/bin").join(if cfg!(windows) {
            "legion.exe"
        } else {
            "legion"
        });
        live_identity["projections"] = json!({
            "codexPlugin": {
                "clientId": "codex",
                "state": "current",
                "explicitOnly": true,
                "ownership": "legion",
                "origin": legion_host::setup_registry::ORIGIN_INSTALLED,
                "executable": escaped,
                "installRoot": live_identity["executable"]["installRoot"].clone(),
                "resolvedExecutable": live_identity["resolvedExecutable"].clone(),
                "resolvedInstallRoot": live_identity["resolvedInstallRoot"].clone(),
                "generation": "active-generation"
            }
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &live_identity);

        assert_eq!(status, "incomplete");
        assert!(remediation.iter().any(|item| {
            item == "codexPlugin production binding escaped stable current; run legion setup repair --confirm"
        }));
    }

    #[test]
    fn resolved_binding_accepts_canonical_installed_root() {
        let temp = TempRoot::new("resolved-binding");
        let install_root = temp.0.join("Orthic Labs/Legion");
        let current = install_root.join("current");
        let executable = current.join(if cfg!(windows) {
            "bin/legion.exe"
        } else {
            "bin/legion"
        });
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("create bin");
        std::fs::write(&executable, b"legion").expect("write executable");
        let resolved_install_root = std::fs::canonicalize(&current).expect("resolve current");
        let resolved_executable = std::fs::canonicalize(&executable).expect("resolve executable");

        assert!(resolved_binding_current(
            Some(legion_host::setup_registry::ORIGIN_INSTALLED),
            Some(&Value::String(executable.to_string_lossy().into_owned())),
            Some(&Value::String(install_root.to_string_lossy().into_owned())),
            Some(&Value::String(
                resolved_executable.to_string_lossy().into_owned(),
            )),
            Some(&Value::String(
                resolved_install_root.to_string_lossy().into_owned(),
            )),
        ));
    }

    #[cfg(windows)]
    #[test]
    fn binding_health_accepts_existing_windows_short_long_aliases() {
        use std::os::windows::process::CommandExt;

        let temp = TempRoot::new("binding-short-alias");
        let install_root = temp.0.join("Orthic Labs/Legion");
        let executable = install_root.join("current/bin/legion.exe");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("create bin");
        std::fs::write(&executable, b"legion").expect("write executable");
        let short = std::process::Command::new("cmd.exe")
            .args(["/d", "/c"])
            .raw_arg("for %I in (\"%LEGION_ALIAS_PATH%\") do @echo %~sI")
            .env("LEGION_ALIAS_PATH", &install_root)
            .output()
            .expect("query short alias");
        assert!(short.status.success());
        let short_install_root =
            PathBuf::from(String::from_utf8(short.stdout).expect("utf8 alias").trim());

        assert!(binding_fields_current(
            Some(legion_host::setup_registry::ORIGIN_INSTALLED),
            Some(&Value::String(executable.to_string_lossy().into_owned())),
            Some(&Value::String(
                short_install_root.to_string_lossy().into_owned(),
            )),
        ));
        assert!(path_starts_with(&executable, &short_install_root));
        assert!(!path_starts_with(
            &temp.0.join("outside"),
            &short_install_root
        ));
    }

    #[cfg(windows)]
    #[test]
    fn resolved_binding_accepts_windows_localcache_virtualization() {
        let install_root = PathBuf::from(r"C:\Users\operator\AppData\Local\Orthic Labs\Legion");
        let executable = install_root.join(r"current\bin\legion.exe");
        let virtual_root = PathBuf::from(
            r"\\?\C:\Users\operator\AppData\Local\Packages\OpenAI.Codex_example\LocalCache\Local\Orthic Labs\Legion\current",
        );
        let virtual_executable = virtual_root.join(r"bin\legion.exe");

        assert!(windows_localcache_equivalent(
            &install_root.join("current"),
            &virtual_root,
            &install_root,
        ));
        assert!(windows_localcache_equivalent(
            &executable,
            &virtual_executable,
            &install_root,
        ));
        assert!(!windows_localcache_equivalent(
            &executable,
            &PathBuf::from(
                r"C:\Users\operator\AppData\Local\Packages\OpenAI.Codex_example\LocalCache\Local\Other\legion.exe",
            ),
            &install_root,
        ));
    }

    #[test]
    fn rollback_snapshot_accepts_legacy_strict_digest_but_refuses_payload_tampering() {
        let temp = TempRoot::new("legacy-native-snapshot-digest");
        let snapshot_plugin = temp.0.join("plugin");
        fs::create_dir_all(snapshot_plugin.join(".in_use")).expect("marker directory");
        fs::write(snapshot_plugin.join("payload.txt"), b"sealed payload").expect("payload file");
        fs::write(snapshot_plugin.join(".in_use/33644"), b"pid marker").expect("legacy PID marker");

        let legacy_strict_sha256 = legion_host::plugin_tree_sha256(&snapshot_plugin)
            .expect("legacy strict snapshot digest");
        let filtered_sha256 =
            legion_host::marketplace::claude_cache_plugin_tree_sha256(&snapshot_plugin)
                .expect("filtered payload digest");
        assert_ne!(legacy_strict_sha256, filtered_sha256);
        assert_eq!(
            validated_claude_snapshot_payload_sha256(&snapshot_plugin, &legacy_strict_sha256)
                .expect("legacy snapshot validation"),
            filtered_sha256
        );
        assert_eq!(
            validated_claude_snapshot_payload_sha256(&snapshot_plugin, &filtered_sha256)
                .expect("current snapshot validation"),
            filtered_sha256
        );

        fs::write(snapshot_plugin.join("payload.txt"), b"tampered payload")
            .expect("tamper payload");
        assert!(
            validated_claude_snapshot_payload_sha256(&snapshot_plugin, &legacy_strict_sha256)
                .is_err(),
            "legacy transaction digest must refuse a changed snapshot"
        );
    }

    #[test]
    fn marketplace_plan_refreshes_stale_but_preserves_disabled_state() {
        let action = legion_host::SetupAction::Repair;
        assert!(marketplace_should_register(
            &action,
            legion_host::MarketplaceClient::ClaudeCode,
            false,
            false,
            true,
            false,
        ));
        assert!(marketplace_should_install_or_refresh(&action, false));
        assert!(!marketplace_should_install_or_refresh(&action, true));
        assert_eq!(marketplace_expected_state(&action, true, true), "disabled");
    }

    #[test]
    fn native_marketplace_list_variants_prove_name_and_current_root() {
        let temp = TempRoot::new("marketplace-list-json");
        let root = temp.0.to_string_lossy().into_owned();
        let claude = json!([{
            "name":"legion-installed",
            "source":"directory",
            "path":root,
            "installLocation":"user"
        }]);
        assert!(marketplace_named_registered(&claude, "legion-installed"));
        assert!(marketplace_root_registered(
            &claude,
            &temp.0,
            "legion-installed"
        ));

        let codex = json!({"marketplaces":[{
            "name":"legion-installed",
            "root":root,
            "marketplaceSource":{"sourceType":"local", "source":root}
        }]});
        assert!(marketplace_named_registered(&codex, "legion-installed"));
        assert!(marketplace_root_registered(
            &codex,
            &temp.0,
            "legion-installed"
        ));
    }

    #[test]
    fn marketplace_remove_and_disable_never_install_or_register() {
        for action in [
            legion_host::SetupAction::Remove,
            legion_host::SetupAction::Purge,
            legion_host::SetupAction::Disable,
        ] {
            assert!(!marketplace_should_register(
                &action,
                legion_host::MarketplaceClient::ClaudeCode,
                false,
                false,
                false,
                false,
            ));
            assert!(!marketplace_should_install_or_refresh(&action, false));
        }
        assert_eq!(
            marketplace_expected_state(&legion_host::SetupAction::Disable, false, false),
            "absent"
        );
        assert_eq!(
            marketplace_expected_state(&legion_host::SetupAction::Remove, false, false),
            "absent"
        );
    }

    #[test]
    fn marketplace_remove_requires_plugin_and_registration_absence() {
        assert!(marketplace_removal_proven(&json!({
            "nativePlugin": {"installed": false},
            "nativeMarketplaceRegistered": false
        })));
        assert!(!marketplace_removal_proven(&json!({
            "nativePlugin": {"installed": true},
            "nativeMarketplaceRegistered": false
        })));
        assert!(!marketplace_removal_proven(&json!({
            "nativePlugin": {"installed": false},
            "nativeMarketplaceRegistered": true
        })));
        assert!(!marketplace_removal_proven(
            &json!({"state":"client_unavailable"})
        ));
    }

    #[test]
    fn codex_effective_enablement_preserves_native_and_config_disabled_state() {
        for (native_enabled, configured_enabled, expected) in [
            (Some(true), true, true),
            (Some(true), false, false),
            (Some(false), true, false),
            (Some(false), false, false),
            (None, true, true),
            (None, false, false),
        ] {
            assert_eq!(
                codex_effective_enabled(native_enabled, configured_enabled),
                expected,
                "native={native_enabled:?}, config={configured_enabled}"
            );
        }
    }

    #[test]
    fn native_cutover_health_ignores_retired_copies_and_accepts_disabled_plugins() {
        let temp = TempRoot::new("native-marketplace-health");
        let clients = json!([
            {"clientId":"claude-code", "installed":true, "fidelity":"Full"},
            {"clientId":"codex", "installed":true, "fidelity":"Full"}
        ]);
        let mut identity = installed_health_identity(&temp.0);
        identity["projections"] = json!({
            "claudeMarketplace": {"clientId":"claude-code", "state":"disabled"},
            "codexMarketplace": {"clientId":"codex", "state":"current"},
            "claudePlugin": {"clientId":"claude-code", "state":"stale", "explicitOnly":false},
            "codexPlugin": {"clientId":"codex", "state":"missing", "explicitOnly":true},
            "claudeCodeLegacy": {"state":"stale"},
            "codexSkills": {"state":"stale", "statuses":[]}
        });

        let (status, remediation) = setup_health(&clients, &json!({}), &identity);

        assert_eq!(status, "complete");
        assert!(remediation.is_empty());
    }

    #[test]
    fn native_client_absence_is_reported_as_unobserved_degradation() {
        let temp = TempRoot::new("native-client-absent-health");
        let clients = json!([]);
        let mut identity = installed_health_identity(&temp.0);
        identity["projections"] = json!({
            "claudeMarketplace": {"clientId":"claude-code", "state":"client_unavailable"},
            "codexMarketplace": {"clientId":"codex", "state":"not_selected"}
        });

        let (status, notes) = setup_health(&clients, &json!({}), &identity);

        assert_eq!(status, "complete");
        assert!(notes.iter().any(|note| note.contains("unobserved")));
    }

    #[test]
    fn unselected_native_marketplaces_have_explicit_non_mutating_state() {
        let release = legion_host::BoundRelease {
            release_version: "1.2.3".into(),
            runtime_digest: "runtime-digest".into(),
            capability_catalog_hash: "catalog".into(),
            mcp_tool_schema_hash: "schema".into(),
            declarative_asset_schema_hash: "assets".into(),
            state_compatibility: "1".into(),
        };
        for client in [
            legion_host::MarketplaceClient::ClaudeCode,
            legion_host::MarketplaceClient::Codex,
        ] {
            let value = client_not_selected_value(client, &release);
            assert_eq!(value["state"], "not_selected");
            assert_eq!(value["nativeMarketplaceRegistered"], false);
            assert_eq!(value["nativePlugin"]["installed"], false);
            assert_eq!(value["expectedReleaseVersion"], "1.2.3");
        }
    }

    #[test]
    fn disable_and_remove_health_accept_action_specific_native_states() {
        let temp = TempRoot::new("native-lifecycle-health");
        let clients = json!([
            {"clientId":"claude-code", "installed":true, "fidelity":"Full"},
            {"clientId":"codex", "installed":true, "fidelity":"Full"}
        ]);
        let mut identity = installed_health_identity(&temp.0);
        identity["plugin"]["state"] = Value::String("absent".into());
        identity["projections"] = json!({
            "claudeMarketplace": {"clientId":"claude-code", "state":"absent"},
            "codexMarketplace": {"clientId":"codex", "state":"absent"},
            "claudePlugin": {"clientId":"claude-code", "state":"absent"},
            "codexPlugin": {"clientId":"codex", "state":"absent"}
        });
        let (remove_status, remove_notes) = setup_health_for_action(
            &clients,
            &json!({}),
            &identity,
            &legion_host::SetupAction::Remove,
        );
        assert_eq!(remove_status, "complete");
        assert!(remove_notes.is_empty());

        identity["plugin"]["state"] = Value::String("disabled".into());
        identity["projections"]["claudeMarketplace"]["state"] = Value::String("disabled".into());
        identity["projections"]["codexMarketplace"]["state"] = Value::String("disabled".into());
        let (disable_status, disable_notes) = setup_health_for_action(
            &clients,
            &json!({}),
            &identity,
            &legion_host::SetupAction::Disable,
        );
        assert_eq!(disable_status, "complete");
        assert!(disable_notes.is_empty());
    }

    #[test]
    fn all_supported_codex_skips_new_install_but_migrates_owned_copy() {
        let action = legion_host::SetupAction::Repair;
        assert!(!marketplace_should_register(
            &action,
            legion_host::MarketplaceClient::Codex,
            true,
            false,
            false,
            false,
        ));
        assert!(marketplace_should_register(
            &action,
            legion_host::MarketplaceClient::Codex,
            true,
            false,
            false,
            true,
        ));
    }

    #[test]
    fn failed_or_unavailable_marketplace_readback_never_authorizes_legacy_cleanup() {
        for state in ["stale", "client_unavailable", "incomplete", "not_selected"] {
            assert!(!marketplace_cleanup_proven(state));
        }
        for state in ["current", "disabled", "absent"] {
            assert!(marketplace_cleanup_proven(state));
        }
    }
}
