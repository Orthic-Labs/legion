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
        );
    }
    match args.command {
        Some(SetupCommand::Preview(args)) => preview(args, context, cancellation).await,
        Some(SetupCommand::Apply(args)) => {
            execute(args, legion_host::SetupAction::Apply, cancellation).await
        }
        Some(SetupCommand::Status(args)) => status(args, context),
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
    let request = request_from_release(request, action, release, context, cancellation).await?;
    let mut registry = open_registry(&request)?;
    let recovery = registry.recover().map_err(setup_error)?;
    let host_integrations = preview_host_integrations(&request)?;
    let identity_context = request.development.clone();
    let preview = registry.preview(request).map_err(setup_error)?;
    let preview_value = serde_json::to_value(&preview)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let live_identity = inspect_live_identity(&host_integrations, identity_context.as_ref())?;
    let (status, remediation) = setup_health(
        &preview_value["clients"],
        &host_integrations,
        &live_identity,
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
    preview_host_integrations(&integration_request)?;
    let execution = registry.execute(confirmed).map_err(setup_error)?;
    let host_integrations = apply_host_integrations(&integration_request)?;
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
    let (status, remediation) = setup_health(
        &execution_value["clients"],
        &host_integrations,
        &live_identity,
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
        cancellation,
    )
    .await?;
    let mut registry = open_registry(&request)?;
    let recovery = registry.recover().map_err(setup_error)?;
    let host_integrations = preview_host_integrations(&request)?;
    let identity_context = request.development.clone();
    let preview = registry.preview(request).map_err(setup_error)?;
    let preview_value = serde_json::to_value(&preview)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let live_identity = inspect_live_identity(&host_integrations, identity_context.as_ref())?;
    let (status, remediation) = setup_health(
        &preview_value["clients"],
        &host_integrations,
        &live_identity,
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

fn status(
    args: SetupClientArgs,
    context: Option<legion_host::DevelopmentSetupContext>,
) -> CommandResult {
    if let Some(context) = context {
        return development_status(args, context);
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
    let host_integrations = inspect_host_integrations(&selector, &release)?;
    let platform_state_root = legion_host::platform_state_root().map_err(setup_error)?;
    let authenticated_live_qualification =
        inspect_stored_live_qualification(&clients, &release, &platform_state_root);
    let clients_value = serde_json::to_value(&clients)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let live_identity = inspect_live_identity(&host_integrations, None)?;
    let clients_value = enrich_client_statuses(clients_value, &live_identity);
    let (status, remediation) = setup_health(&clients_value, &host_integrations, &live_identity);
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
        cancellation,
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
        cancellation,
    )
    .await?;
    let mut registry = open_registry(&preview.request)?;
    let recovery = registry.recover().map_err(setup_error)?;
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
    preview_host_integrations(&integration_request)?;
    let execution = registry.execute(confirmed).map_err(setup_error)?;
    let host_integrations = apply_host_integrations(&integration_request)?;
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
    let (status, remediation) = setup_health(
        &execution_value["clients"],
        &host_integrations,
        &live_identity,
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
    let path = std::env::var_os("PATH").ok_or_else(|| {
        CommandError::incomplete(format!("PATH is unavailable while resolving {command}"))
    })?;
    let directories = std::env::split_paths(&path).collect::<Vec<_>>();
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
        let state = if cache_error.is_some() || !canonical_trusted {
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
        projections.insert(
            "claudeCodeLegacy".into(),
            json!({
                "state": state,
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
        let state = if ledger_error.is_some()
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
        projections.insert(
            "codexSkills".into(),
            json!({
                "state": state,
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

fn setup_health(
    clients: &Value,
    host_integrations: &Value,
    live_identity: &Value,
) -> (&'static str, Vec<String>) {
    let mut remediation = Vec::new();
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
    match clients.as_array() {
        Some(values) if values.is_empty() => remediation
            .push("no supported client is registered with complete setup evidence".into()),
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
                if !installed || (fidelity != "Full" && !pi_baseline) {
                    remediation.push(format!(
                        "client {} is incomplete ({fidelity}); {repair_command}",
                        client_id
                    ));
                }
            }
        }
        None => remediation.push("setup client status is unavailable".into()),
    }
    if let Some(plugin_state) = live_identity["plugin"]["state"].as_str() {
        if !matches!(plugin_state, "current" | "not_selected") {
            remediation.push(format!(
                "Claude plugin identity is {plugin_state}; repair observes cache and preserves its files"
            ));
        }
    }
    if let Some(projections) = live_identity["projections"].as_object() {
        for (client, projection) in projections {
            let projection_client = projection
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
                continue;
            }
            if let Some(state) = projection.get("state").and_then(Value::as_str) {
                if state != "current" {
                    remediation.push(format!("{client} projection is {state}; {repair_command}"));
                }
            }
            if installed
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
                    remediation.push(format!(
                        "{client} generation {actual} is stale; {repair_command}"
                    ));
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
    if remediation.is_empty() {
        ("complete", remediation)
    } else {
        ("incomplete", remediation)
    }
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
        && paths_equal(root, &stable_current_root)
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
    path_starts_with(resolved_install_root, &canonical_install_root)
        && path_starts_with(resolved_executable, resolved_install_root)
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
        path_starts_with(left, right) && path_starts_with(right, left)
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
    let path = normalize(path);
    let root = normalize(root);
    path.len() >= root.len()
        && path
            .iter()
            .zip(root.iter())
            .all(|(path, root)| path == root)
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
    client_projections: Vec<legion_host::setup_registry::ClientProjectionInput>,
}

fn inspect_host_integrations(
    selector: &legion_host::ClientSelector,
    release: &legion_host::BoundRelease,
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

fn preview_host_integrations(request: &legion_host::SetupRequest) -> Result<Value, CommandError> {
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

fn apply_host_integrations(request: &legion_host::SetupRequest) -> Result<Value, CommandError> {
    let inputs = host_integration_inputs(request)?;
    let mut integrations = serde_json::Map::new();
    if should_process_client(request, legion_host::setup_registry::CLIENT_CLAUDE) {
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
    if should_process_client(request, legion_host::setup_registry::CLIENT_CODEX) {
        if let Some(input) = &inputs.codex {
            let value = match request.action {
                legion_host::SetupAction::Apply => serde_json::to_value(
                    legion_host::apply_codex_skills(input).map_err(host_error)?,
                ),
                legion_host::SetupAction::Repair => serde_json::to_value(
                    legion_host::repair_codex_skills(input).map_err(host_error)?,
                ),
                legion_host::SetupAction::Remove | legion_host::SetupAction::Purge => {
                    serde_json::to_value(
                        legion_host::remove_codex_skills(input).map_err(host_error)?,
                    )
                }
                _ => serde_json::to_value(
                    legion_host::inspect_codex_skills(input).map_err(host_error)?,
                ),
            }
            .map_err(|error| CommandError::incomplete(error.to_string()))?;
            integrations.insert("codexSkills".into(), value);
        }
    }
    for input in &inputs.client_projections {
        if !should_process_client(request, &input.client_id) {
            continue;
        }
        let key = projection_key(&input.client_id);
        let value = match request.action {
            legion_host::SetupAction::Apply | legion_host::SetupAction::Repair => {
                serde_json::to_value(
                    legion_host::setup_registry::repair_client_projection(input)
                        .map_err(setup_error)?,
                )
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

fn should_process_client(request: &legion_host::SetupRequest, client_id: &str) -> bool {
    match &request.selector {
        legion_host::ClientSelector::ClientId(selected) => selected == client_id,
        legion_host::ClientSelector::AllSupported => request
            .client_evidence
            .iter()
            .any(|evidence| evidence.client_id == client_id && evidence.detected),
    }
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
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| CommandError::incomplete("host home directory is unavailable"))?;
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
        generation: format!(
            "{}:{}",
            release.release_version, release.declarative_asset_schema_hash
        ),
    });
    let generation = format!(
        "{}:{}",
        release.release_version, release.declarative_asset_schema_hash
    );
    let client_projections = [
        (
            legion_host::setup_registry::CLIENT_CLAUDE,
            "native-plugin",
            home.join(".claude/plugins/legion"),
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
            "native-plugin",
            home.join(".antigravity/plugins/legion"),
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
            })
        },
    )
    .collect::<Result<Vec<_>, CommandError>>()?;
    Ok(HostIntegrationInputs {
        claude,
        codex,
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
            home.join("claude/plugins/legion"),
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
            "native-plugin",
            true,
            false,
            repo_assets,
            home.join("antigravity/plugins/legion"),
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
                })
            },
        )
        .collect::<Result<Vec<_>, CommandError>>()?;
    Ok(HostIntegrationInputs {
        claude,
        codex,
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
            vec!["antigravity-native-plugin"],
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

fn development_status(
    args: SetupClientArgs,
    context: legion_host::DevelopmentSetupContext,
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
    let integrations = preview_host_integrations(&request)?;
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
                {"capabilityId": "coder", "availability": "unavailable", "degraded": true, "requirements": []},
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
        let executable = PathBuf::from("product")
            .join("current")
            .join("bin")
            .join(if cfg!(windows) { "legion.exe" } else { "legion" });

        let root = installed_plugin_source_root(&executable).expect("stable plugin root");

        assert_eq!(root, PathBuf::from("product").join("current").join("plugin"));
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
    fn resolved_binding_accepts_canonical_installed_root() {
        let temp = TempRoot::new("resolved-binding");
        let install_root = temp.0.join("Orthic Labs/Legion");
        let current = install_root.join("current");
        let executable = current.join("bin/legion.exe");
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
}
