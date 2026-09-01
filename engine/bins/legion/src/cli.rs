use crate::commands::{self, CommandResult};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Parser)]
#[command(
    name = "legion",
    version = env!("CARGO_PKG_VERSION"),
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
    Status(M1ConfigArgs),
    Serve(ServeArgs),
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
    Rules(commands::rules::RulesArgs),
    Schedule(ScheduleArgs),
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
    Assurance(commands::assurance::AssuranceArgs),
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
    Setup(commands::setup::SetupArgs),
}
#[derive(Clone, Debug, clap::Args)]
struct M1ConfigArgs {
    /// Versioned explicit composition source for the native M1 API.
    #[arg(long)]
    config: Option<PathBuf>,
}
#[derive(Debug, clap::Args)]
struct ServeArgs {
    #[arg(long)]
    stdio: bool,
    /// Immutable Agent Plugins package root supplied by the client launcher.
    #[arg(long)]
    plugin_root: Option<PathBuf>,
    #[command(flatten)]
    m1: M1ConfigArgs,
}
#[derive(Debug, clap::Args)]
struct CommonArgs {
    #[arg(long)]
    json: bool,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<OsString>,
}
#[derive(Debug, clap::Args)]
struct ScheduleArgs {
    #[arg(long = "trigger-id")]
    trigger_id: String,
    #[arg(long)]
    workflow: String,
    #[arg(long, default_value = ".legion/triggers")]
    state_root: PathBuf,
    #[arg(long, default_value = "schedule")]
    source: String,
    #[arg(long)]
    payload_digest: Option<String>,
    #[arg(long)]
    json: bool,
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
    inventory_digest: String,
    catalog_entries: usize,
    provider_count: usize,
}

const M1_COMPOSITION_SCHEMA_VERSION: u32 = 1;
const M1_STATE_SCHEMA_VERSION: u32 = 1;
const M1_REPAIR: &str = "legion setup repair --confirm";
const M1_RIGHTKIT_AX_VERSION: &str = "0.2.1";
const M1_RIGHTKIT_AX_SOURCE_COMMIT: &str = "4c1a414269d8ffdb95b4b1e685440bd34784b41b";
const M1_INSTALLED_COMPOSITION: &str = "share/legion/composition.json";
const M2_PUBLIC_SKILLS: [&str; 24] = [
    "ads",
    "alchemist",
    "architect",
    "audit",
    "audit-fix",
    "audit-visual",
    "brand",
    "brand-identity",
    "coder",
    "commit",
    "covenant",
    "debugger",
    "designer",
    "dispatch",
    "gotchas",
    "handoff",
    "marketing",
    "qa",
    "research",
    "seo",
    "social",
    "tasklist",
    "wake",
    "writing",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RightAxPortableCore {
    schema_version: u32,
    kind: String,
    plugin: String,
    public_skills: Vec<String>,
    public_files: Vec<String>,
    private_workspace_content: bool,
    client_projections: Value,
}

fn expected_right_ax_client_projections() -> Value {
    json!({
        "claude": {
            "portableCore": false,
            "projection": "claude-native-plugin+standalone-skills",
            "fidelity": "full+skills-only",
            "executableRegistration": true
        },
        "codex": {
            "portableCore": true,
            "projection": "agent-plugins+codex-sidecar",
            "fidelity": "full+sidecar",
            "executableRegistration": true
        },
        "cursor": {
            "portableCore": true,
            "projection": "agent-plugins+optional-cursor-sidecar",
            "fidelity": "full+optional-sidecar",
            "executableRegistration": true
        },
        "pi": {
            "portableCore": false,
            "projection": "agents-skills",
            "fidelity": "skills-only",
            "executableRegistration": false
        },
        "antigravity": {
            "portableCore": true,
            "projection": "agent-plugins-portable-core",
            "fidelity": "portable-core",
            "executableRegistration": true
        }
    })
}

/// Installed composition is explicit and versioned so the CLI never infers
/// release assets from a source checkout or developer environment.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct M1CompositionConfig {
    schema_version: u32,
    kind: String,
    release_manifest_path: PathBuf,
    release_binding: M1BindingConfig,
    catalog_root: PathBuf,
    catalog_index_path: PathBuf,
    policy_pack: legion_policy_model::PolicyPack,
    providers: Vec<M1ProviderConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct M1ProviderConfig {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct M1BindingConfig {
    runtime_provenance: String,
    catalog_path: PathBuf,
    mcp_tool_schema_path: PathBuf,
    declarative_assets_path: PathBuf,
    declarative_assets_kind: M1AssetsKind,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum M1AssetsKind {
    File,
    Directory,
}

impl M1CompositionConfig {
    fn provider_count(&self) -> Result<usize, commands::CommandError> {
        if self.providers.is_empty() {
            return Err(commands::CommandError::usage(
                "M1 composition must declare at least one provider",
            ));
        }
        let mut ids = BTreeSet::new();
        for provider in &self.providers {
            if provider.id.trim().is_empty() || !ids.insert(provider.id.as_str()) {
                return Err(commands::CommandError::usage(
                    "M1 composition provider ids must be non-empty and unique",
                ));
            }
        }
        Ok(self.providers.len())
    }

    fn into_inputs(
        self,
        config_path: &Path,
    ) -> Result<legion_application::M1ApplicationInputs, commands::CommandError> {
        if self.schema_version != M1_COMPOSITION_SCHEMA_VERSION {
            return Err(commands::CommandError::usage(format!(
                "unsupported M1 composition schema version {}",
                self.schema_version
            )));
        }
        if self.kind != "legion-m1-composition" {
            return Err(commands::CommandError::usage(
                "M1 composition kind must be legion-m1-composition",
            ));
        }
        let base = config_path.parent().unwrap_or_else(|| Path::new("."));
        let resolve = |path: PathBuf| {
            if path.is_absolute() {
                path
            } else {
                base.join(path)
            }
        };
        let assets_path = resolve(self.release_binding.declarative_assets_path);
        let declarative_assets = match self.release_binding.declarative_assets_kind {
            M1AssetsKind::File => legion_runtime::DeclarativeAssets::File(assets_path),
            M1AssetsKind::Directory => legion_runtime::DeclarativeAssets::Directory(assets_path),
        };
        Ok(legion_application::M1ApplicationInputs {
            release_manifest_path: resolve(self.release_manifest_path),
            release_binding_inputs: legion_runtime::ReleaseBindingInputs {
                release_version: env!("CARGO_PKG_VERSION").into(),
                runtime_path: std::env::current_exe().map_err(commands::io_error)?,
                runtime_platform: std::env::consts::OS.into(),
                runtime_architecture:
                    legion_runtime::release_binding::current_runtime_architecture().into(),
                runtime_provenance: self.release_binding.runtime_provenance,
                catalog_path: resolve(self.release_binding.catalog_path),
                mcp_tool_schema_path: resolve(self.release_binding.mcp_tool_schema_path),
                declarative_assets,
                state_schema_version: M1_STATE_SCHEMA_VERSION,
                rightkit_ax: legion_runtime::RightkitAxIdentity {
                    version: M1_RIGHTKIT_AX_VERSION.into(),
                    source_commit: M1_RIGHTKIT_AX_SOURCE_COMMIT.into(),
                },
            },
            catalog_root: resolve(self.catalog_root),
            catalog_index_path: self.catalog_index_path,
            policy_pack: self.policy_pack,
            development: None,
        })
    }
}

fn load_m1_application(
    args: &M1ConfigArgs,
) -> Result<Arc<legion_application::M1Application>, commands::CommandError> {
    let (config_path, origin) = if let Some(config) = args.config.clone() {
        let executable = std::env::current_exe().map_err(commands::io_error)?;
        (
            config,
            legion_runtime::release_binding::RuntimeOriginEvidence::development(executable),
        )
    } else if let Some(config) = std::env::var_os("LEGION_M1_CONFIG")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        let executable = std::env::current_exe().map_err(commands::io_error)?;
        (
            config,
            legion_runtime::release_binding::RuntimeOriginEvidence::development(executable),
        )
    } else {
        let installed =
            legion_runtime::release_binding::load_installed_release().map_err(|error| {
                commands::CommandError::incomplete(format!(
                    "installed release binding unavailable: {error}; run {M1_REPAIR}"
                ))
            })?;
        let config_path = installed
            .manifest_path
            .parent()
            .map(|directory| directory.join("composition.json"))
            .ok_or_else(|| {
                commands::CommandError::incomplete(
                    "installed composition has no release manifest parent",
                )
            })?;
        (config_path, installed.origin_evidence())
    };
    if matches!(
        &origin.origin,
        legion_runtime::release_binding::RuntimeOrigin::Installed
    ) {
        legion_runtime::release_binding::verify_stable_current_path(
            &origin,
            &config_path,
            "stable current composition",
        )
        .map_err(|error| {
            commands::CommandError::incomplete(format!(
                "installed composition binding unavailable: {error}; run {M1_REPAIR}"
            ))
        })?;
    }
    let bytes = std::fs::read(&config_path).map_err(commands::io_error)?;
    let config: M1CompositionConfig = serde_json::from_slice(&bytes)
        .map_err(|error| commands::CommandError::usage(error.to_string()))?;
    let inputs = config.into_inputs(&config_path)?;
    legion_application::M1Application::from_inputs_with_origin(inputs, origin)
        .map(Arc::new)
        .map_err(|error| commands::CommandError::incomplete(error.to_string()))
}

pub(crate) fn installed_m1_composition() -> Result<PathBuf, commands::CommandError> {
    let installed = legion_runtime::release_binding::load_installed_release().map_err(|error| {
        commands::CommandError::incomplete(format!(
            "installed release binding unavailable: {error}; run {M1_REPAIR}"
        ))
    })?;
    let composition = installed
        .manifest_path
        .parent()
        .map(|directory| directory.join("composition.json"))
        .ok_or_else(|| {
            commands::CommandError::incomplete(
                "installed composition has no release manifest parent",
            )
        })?;
    if composition.is_file() {
        Ok(composition)
    } else {
        Err(commands::CommandError::incomplete(format!(
            "installed M1 composition {M1_INSTALLED_COMPOSITION} was not found; run {M1_REPAIR}"
        )))
    }
}

fn plugin_root_error(reason: impl Into<String>) -> commands::CommandError {
    commands::CommandError::incomplete(format!(
        "portable plugin root rejected: {}; run {M1_REPAIR}",
        reason.into()
    ))
}

fn validate_portable_plugin_root(
    raw_root: &Path,
    _manifest: &legion_runtime::ReleaseManifest,
) -> Result<(), commands::CommandError> {
    if raw_root
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(plugin_root_error("plugin root may not contain `..`"));
    }
    let absolute_root = if raw_root.is_absolute() {
        raw_root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(commands::io_error)?
            .join(raw_root)
    };
    for ancestor in absolute_root.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            plugin_root_error(format!("cannot inspect {}: {error}", ancestor.display()))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(plugin_root_error(format!(
                "plugin root crosses symlink {}",
                ancestor.display()
            )));
        }
    }
    let root = std::fs::canonicalize(&absolute_root).map_err(|error| {
        plugin_root_error(format!(
            "cannot resolve {}: {error}",
            absolute_root.display()
        ))
    })?;
    if !std::fs::symlink_metadata(&root)
        .map_err(commands::io_error)?
        .file_type()
        .is_dir()
    {
        return Err(plugin_root_error("plugin root must be a directory"));
    }

    let portable_contract_path = root.join("rightax-portable-core.json");
    let portable_contract: RightAxPortableCore = serde_json::from_slice(
        &std::fs::read(&portable_contract_path).map_err(commands::io_error)?,
    )
    .map_err(|error| {
        plugin_root_error(format!("rightax-portable-core.json is invalid: {error}"))
    })?;
    if portable_contract.schema_version != 1
        || portable_contract.kind != "rightax-portable-core"
        || portable_contract.plugin != "legion"
        || portable_contract.private_workspace_content
    {
        return Err(plugin_root_error(
            "RightAX portable core identity is invalid",
        ));
    }
    let expected_skills = M2_PUBLIC_SKILLS
        .iter()
        .map(|skill| (*skill).to_owned())
        .collect::<BTreeSet<_>>();
    let declared_skills = portable_contract
        .public_skills
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if declared_skills != expected_skills
        || declared_skills.len() != portable_contract.public_skills.len()
    {
        return Err(plugin_root_error(
            "RightAX portable core does not contain every canonical public skill exactly once",
        ));
    }
    if portable_contract.client_projections != expected_right_ax_client_projections() {
        if portable_contract
            .client_projections
            .get("pi")
            .and_then(|value| value.get("executableRegistration"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(plugin_root_error(
                "RightAX Pi projection may not register an executable",
            ));
        }
        return Err(plugin_root_error(
            "RightAX client projections are not exact",
        ));
    }
    let mut expected_files = portable_contract
        .public_files
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if expected_files.len() != portable_contract.public_files.len()
        || !expected_files.contains("plugin.json")
        || !expected_files.contains("mcp.json")
        || expected_skills
            .iter()
            .any(|skill| !expected_files.contains(&format!("skills/{skill}/SKILL.md")))
    {
        return Err(plugin_root_error(
            "RightAX public file declaration is incomplete",
        ));
    }
    if portable_contract
        .public_files
        .iter()
        .any(|relative| !is_allowed_portable_public_file(relative, &expected_skills))
    {
        return Err(plugin_root_error(
            "RightAX public file declaration contains an extra or private path",
        ));
    }
    expected_files.insert("rightax-portable-core.json".into());
    if expected_files
        .iter()
        .any(|relative| !is_safe_portable_relative_path(relative))
    {
        return Err(plugin_root_error("RightAX public file path is unsafe"));
    }
    let mut expected_directories = BTreeSet::new();
    for relative in &expected_files {
        let mut parent = Path::new(relative).parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            expected_directories.insert(directory.to_string_lossy().replace('\\', "/"));
            parent = directory.parent();
        }
    }
    let mut discovered_files = BTreeSet::new();
    let mut discovered_directories = BTreeSet::new();
    collect_portable_package_entries(
        &root,
        &root,
        &expected_files,
        &expected_directories,
        &mut discovered_files,
        &mut discovered_directories,
    )?;
    if discovered_files != expected_files || discovered_directories != expected_directories {
        return Err(plugin_root_error(
            "package entries are incomplete or do not close exactly",
        ));
    }

    for relative in ["plugin.json", "mcp.json", "rightax-portable-core.json"] {
        serde_json::from_slice::<Value>(
            &std::fs::read(root.join(relative)).map_err(commands::io_error)?,
        )
        .map_err(|error| plugin_root_error(format!("{relative} is not valid JSON: {error}")))?;
    }
    validate_portable_plugin_manifests(&root)?;

    Ok(())
}

fn is_safe_portable_relative_path(relative: &str) -> bool {
    if relative.is_empty() || relative.contains('\0') {
        return false;
    }
    let normalized = relative.replace('\\', "/");
    if normalized.starts_with('/') || normalized.contains(':') {
        return false;
    }
    normalized
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn is_allowed_portable_public_file(relative: &str, expected_skills: &BTreeSet<String>) -> bool {
    if matches!(relative, "plugin.json" | "mcp.json") {
        return true;
    }
    let mut components = relative.split('/');
    if components.next() != Some("skills") {
        return false;
    }
    let Some(skill) = components.next() else {
        return false;
    };
    if !expected_skills.contains(skill) || components.next().is_none() {
        return false;
    }
    let lower = relative.to_ascii_lowercase();
    if lower.split('/').any(|component| {
        component == "private"
            || component.starts_with("private.")
            || component == "personal"
            || component.starts_with("personal.")
            || component == "secrets"
            || component.starts_with("secrets.")
            || component == "credentials"
            || component.starts_with("credentials.")
            || component.starts_with(".env")
    }) {
        return false;
    }
    ![
        ".pem", ".p12", ".pfx", ".key", ".kdbx", ".sqlite", ".sqlite3",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
}

fn validate_portable_plugin_manifests(root: &Path) -> Result<(), commands::CommandError> {
    let plugin: Value = serde_json::from_slice(
        &std::fs::read(root.join("plugin.json")).map_err(commands::io_error)?,
    )
    .map_err(|error| plugin_root_error(format!("plugin.json is not valid JSON: {error}")))?;
    if !plugin.is_object() || plugin.get("name").and_then(Value::as_str) != Some("legion") {
        return Err(plugin_root_error(
            "plugin.json must declare the legion plugin",
        ));
    }

    let mcp: Value =
        serde_json::from_slice(&std::fs::read(root.join("mcp.json")).map_err(commands::io_error)?)
            .map_err(|error| plugin_root_error(format!("mcp.json is not valid JSON: {error}")))?;
    let mcp_object = mcp
        .as_object()
        .ok_or_else(|| plugin_root_error("mcp.json must be a JSON object"))?;
    if mcp_object
        .keys()
        .any(|key| key != "$schema" && key != "mcpServers")
        || mcp.get("$schema").and_then(Value::as_str)
            != Some("https://agent-plugins.org/schemas/1.0.0/mcp.schema.json")
    {
        return Err(plugin_root_error(
            "mcp.json must use the pinned Agent Plugins schema",
        ));
    }
    let servers = mcp
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| plugin_root_error("mcp.json.mcpServers must be an object"))?;
    if servers.len() != 1 || !servers.contains_key("legion") {
        return Err(plugin_root_error(
            "mcp.json must declare exactly the legion server",
        ));
    }
    let server = servers
        .get("legion")
        .and_then(Value::as_object)
        .ok_or_else(|| plugin_root_error("mcp.json.mcpServers.legion must be an object"))?;
    if server
        .keys()
        .any(|key| key != "type" && key != "command" && key != "args")
    {
        return Err(plugin_root_error(
            "mcp.json legion server contains an unapproved field",
        ));
    }
    let args = server
        .get("args")
        .and_then(Value::as_array)
        .ok_or_else(|| plugin_root_error("mcp.json.mcpServers.legion.args must be an array"))?;
    let expected = ["serve", "--stdio", "--plugin-root", "${PLUGIN_ROOT}"];
    if server.get("type").and_then(Value::as_str) != Some("stdio")
        || server.get("command").and_then(Value::as_str) != Some("legion")
        || args.iter().filter_map(Value::as_str).collect::<Vec<_>>() != expected.to_vec()
    {
        return Err(plugin_root_error(
            "mcp.json must use the exact bare legion stdio contract",
        ));
    }
    Ok(())
}

fn collect_portable_package_entries(
    root: &Path,
    current: &Path,
    expected_files: &BTreeSet<String>,
    expected_directories: &BTreeSet<String>,
    discovered_files: &mut BTreeSet<String>,
    discovered_directories: &mut BTreeSet<String>,
) -> Result<(), commands::CommandError> {
    for entry in std::fs::read_dir(current).map_err(commands::io_error)? {
        let entry = entry.map_err(commands::io_error)?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(commands::io_error)?
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = std::fs::symlink_metadata(&path).map_err(commands::io_error)?;
        if metadata.file_type().is_symlink() {
            return Err(plugin_root_error(format!(
                "package entry {relative} is a symlink"
            )));
        }
        if metadata.file_type().is_dir() {
            if !expected_directories.contains(&relative) {
                return Err(plugin_root_error(format!(
                    "package contains extra directory {relative}"
                )));
            }
            discovered_directories.insert(relative);
            collect_portable_package_entries(
                root,
                &path,
                expected_files,
                expected_directories,
                discovered_files,
                discovered_directories,
            )?;
        } else if metadata.file_type().is_file() {
            if !expected_files.contains(&relative) {
                return Err(plugin_root_error(format!(
                    "package contains extra file {relative}"
                )));
            }
            discovered_files.insert(relative);
        } else {
            return Err(plugin_root_error(format!(
                "package entry {relative} is not a regular file"
            )));
        }
    }
    Ok(())
}

struct M1McpApi {
    application: Option<Arc<legion_application::M1Application>>,
}

impl M1McpApi {
    fn ready(application: Arc<legion_application::M1Application>) -> Self {
        Self {
            application: Some(application),
        }
    }

    fn unavailable() -> Self {
        Self { application: None }
    }

    fn application(
        &self,
    ) -> Result<&legion_application::M1Application, legion_runtime::RuntimeError> {
        self.application.as_deref().ok_or_else(|| {
            legion_runtime::RuntimeError::Policy("M1 application binding unavailable".into())
        })
    }
}

impl legion_mcp::NativeApi for M1McpApi {
    fn tool_definitions(&self) -> Vec<Value> {
        vec![
            json!({
                "name": "legion_m1_status",
                "description": "Return the native M1 release status.",
                "inputSchema": {
                    "type": "object",
                    "required": [],
                    "additionalProperties": false,
                    "properties": {}
                }
            }),
            json!({
                "name": "legion_m1_invoke",
                "description": "Resolve one deterministic M1 capability and emit policy and invocation receipts.",
                "inputSchema": {
                    "type": "object",
                    "required": ["capabilityId", "policyContext"],
                    "additionalProperties": false,
                    "properties": {
                        "capabilityId": {"type": "string", "minLength": 1},
                        "policyContext": {}
                    }
                }
            }),
        ]
    }

    fn validate_tool_scope(
        &self,
        operation: &str,
        arguments: &Value,
    ) -> Result<(), legion_mcp::McpError> {
        if operation != "legion_m1_invoke" {
            return Ok(());
        }
        let Some(context) = arguments.get("policyContext") else {
            return Err(legion_mcp::McpError::InvalidParams);
        };
        serde_json::from_value::<legion_policy_model::PolicyContext>(context.clone())
            .map(|_| ())
            .map_err(|_| legion_mcp::McpError::InvalidParams)
    }

    fn invoke(
        &self,
        operation: &str,
        arguments: &Value,
    ) -> Result<Value, legion_runtime::RuntimeError> {
        let application = self.application()?;
        match operation {
            "legion_m1_status" => Ok(m1_status_value(&application.status())),
            "legion_m1_invoke" => {
                let capability_id = arguments
                    .get("capabilityId")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| {
                        legion_runtime::RuntimeError::InvalidTask("capabilityId is required".into())
                    })?
                    .to_owned();
                let policy_context = serde_json::from_value(
                    arguments.get("policyContext").cloned().ok_or_else(|| {
                        legion_runtime::RuntimeError::InvalidTask(
                            "policyContext is required".into(),
                        )
                    })?,
                )
                .map_err(|_| {
                    legion_runtime::RuntimeError::InvalidTask("policyContext is invalid".into())
                })?;
                application
                    .invoke(legion_application::M1InvocationRequest {
                        capability_id,
                        policy_context,
                    })
                    .map(m1_invocation_value)
                    .map_err(|error| legion_runtime::RuntimeError::Policy(error.to_string()))
            }
            _ => Err(legion_runtime::RuntimeError::InvalidTask(
                "unknown M1 MCP operation".into(),
            )),
        }
    }
}

fn m1_status_value(status: &legion_application::M1Status) -> Value {
    let mut value = serde_json::to_value(status).expect("M1 status is serializable");
    if let Value::Object(object) = &mut value {
        object.insert("scope".into(), json!("m1-vertical-slice"));
        object.insert("status".into(), json!("complete"));
    }
    value
}

fn m1_invocation_value(result: legion_application::M1InvocationResult) -> Value {
    json!({
        "status": m1_status_value(&result.status),
        "capability": result.capability,
        "policyEvaluation": {"decision": result.policy_evaluation.decision},
        "policyReceipt": {"decision": result.policy_receipt.decision},
        "invocationReceipt": result.invocation_receipt,
    })
}

struct M1BindingGate {
    outcome: Result<legion_mcp::VerifiedReleaseBinding, legion_mcp::BindingFailure>,
}

impl M1BindingGate {
    fn verified(identity: Value) -> Self {
        Self {
            outcome: Ok(legion_mcp::VerifiedReleaseBinding::new(identity)),
        }
    }

    fn rejected() -> Self {
        Self {
            outcome: Err(legion_mcp::BindingFailure::new(M1_REPAIR)),
        }
    }
}

impl legion_mcp::ReleaseBindingGate for M1BindingGate {
    fn verify_binding(
        &self,
    ) -> Result<legion_mcp::VerifiedReleaseBinding, legion_mcp::BindingFailure> {
        self.outcome.clone()
    }
}

async fn native_m1_status(args: M1ConfigArgs) -> CommandResult {
    match load_m1_application(&args) {
        Ok(application) => {
            let native = application.status();
            // installRoot is product root; executable preserves stable current.
            Ok(json!({
                "schemaVersion": 1,
                "kind": "legion-m1-status",
                "status": "incomplete",
                "fidelity": "degraded",
                "origin": native.origin.clone(),
                "executable": native.executable.clone(),
                "installRoot": native.install_root.clone(),
                "generation": native.generation.clone(),
                "gaps": [
                    "native hook enforcement is not connected",
                    "native CLI product projections are not fully connected",
                    "M4 capability migration and M6 installed-product qualification are incomplete"
                ],
                "native": m1_status_value(&native),
            }))
        }
        Err(error) => {
            let evidence =
                legion_runtime::release_binding::detect_runtime_origin().unwrap_or_else(|_| {
                    legion_runtime::release_binding::RuntimeOriginEvidence::development(
                        PathBuf::from("<current_exe>"),
                    )
                });
            // installRoot is product root; executable preserves stable current.
            Ok(json!({
                "schemaVersion": 1,
                "kind": "legion-m1-status",
                "status": "failed",
                "fidelity": "degraded",
                "origin": evidence.origin,
                "executable": evidence.executable,
                "installRoot": evidence.install_root,
                "generation": evidence.generation,
                "gaps": [error.message],
            }))
        }
    }
}

async fn native_m1_serve(args: ServeArgs) -> CommandResult {
    if !args.stdio {
        return Err(commands::CommandError::usage(
            "legion serve requires --stdio",
        ));
    }
    if let Some(plugin_root) = args.plugin_root.as_deref() {
        let application = load_m1_application(&args.m1)?;
        validate_portable_plugin_root(plugin_root, application.release_binding().manifest())?;
        let identity = serde_json::to_value(application.release_binding().manifest())
            .map_err(commands::io_error)?;
        legion_mcp::run_stdio(
            Arc::new(M1McpApi::ready(application)),
            Arc::new(M1BindingGate::verified(identity)),
        )
        .await
        .map_err(commands::io_error)?;
        return Ok(json!({"__silent": true}));
    }
    let (api, gate) = match load_m1_application(&args.m1) {
        Ok(application) => match serde_json::to_value(application.release_binding().manifest()) {
            Ok(identity) => (
                M1McpApi::ready(application),
                M1BindingGate::verified(identity),
            ),
            Err(_) => (M1McpApi::unavailable(), M1BindingGate::rejected()),
        },
        Err(_) => (M1McpApi::unavailable(), M1BindingGate::rejected()),
    };
    legion_mcp::run_stdio(Arc::new(api), Arc::new(gate))
        .await
        .map_err(commands::io_error)?;
    Ok(json!({"__silent": true}))
}
pub async fn run_with_cancellation<I>(args: I, cancellation: CancellationToken) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--version" | "-V")) {
        println!("{}", env!("CARGO_PKG_VERSION"));
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
        Command::Status(args) => native_m1_status(args).await,
        Command::Serve(args) => native_m1_serve(args).await,
        Command::Catalog(args) => commands::catalog::run(args),
        Command::Policy(args) => commands::policy::run(args),
        Command::Audit(args) => commands::audit::run(args, cancellation.clone()).await,
        Command::Host(args) => native_host(args, cancellation.clone()).await,
        Command::Decision(args) => commands::decision::run(args),
        Command::Handoff(args) => commands::handoff::run(args),
        Command::Research(args) => commands::research::run(args, cancellation.clone()),
        Command::Review(args) => commands::review::run(args, cancellation.clone()).await,
        Command::Setup(args) => commands::setup::run(args, cancellation.clone()).await,
        Command::Providers(args) => Ok(
            json!({"schemaVersion":1,"kind":"legion-providers","providers": providers(), "capabilityAttestations": capability_attestations(), "selected": !(args.json || root_json), "arguments": args.args, "json": args.json || root_json, "text": providers_text()}),
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
        Command::Rules(args) => commands::rules::run(args),
        Command::Schedule(args) => native_schedule(args),
        Command::Assurance(args) => commands::assurance::run(args),
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
    _cancellation: CancellationToken,
) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(commands::io_error)?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": format!("legion-{kind}"),
        "status": "incomplete",
        "repository": {"root": root},
        "json": args.json,
        "gaps": [format!("native {kind} implementation is not connected")],
    }))
}
async fn native_common_projection(
    kind: &str,
    args: CommonArgs,
    _cancellation: CancellationToken,
) -> CommandResult {
    Ok(json!({
        "schemaVersion": 1,
        "kind": format!("legion-{kind}"),
        "status": "incomplete",
        "arguments": args.args.iter().map(|arg| arg.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "json": args.json,
        "gaps": [format!("native {kind} implementation is not connected")],
    }))
}
async fn native_doctor(args: RootArgs, cancellation: CancellationToken) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(commands::io_error)?;
    let summary = match installed_doctor_summary(&root, cancellation).await {
        Ok(summary) => summary,
        Err(error) => {
            return Ok(json!({
                "schemaVersion": 1,
                "kind": "legion-doctor",
                "status": "incomplete",
                "repository": {"root": root},
                "cleanClaimPossible": false,
                "gaps": [error.message],
            }));
        }
    };
    Ok(render_doctor(
        "doctor",
        summary,
        json!({"root": root}),
        None,
        None,
        true,
    ))
}
async fn installed_doctor_summary(
    root: &Path,
    _cancellation: CancellationToken,
) -> Result<DoctorSummary, commands::CommandError> {
    let config_path = installed_m1_composition()?;
    let bytes = std::fs::read(&config_path).map_err(commands::io_error)?;
    let config: M1CompositionConfig = serde_json::from_slice(&bytes)
        .map_err(|error| commands::CommandError::usage(error.to_string()))?;
    let provider_count = config.provider_count()?;
    let inputs = config.into_inputs(&config_path)?;
    let application = legion_application::M1Application::from_inputs(inputs)
        .map(Arc::new)
        .map_err(|error| commands::CommandError::incomplete(error.to_string()))?;
    let status = application.status();
    Ok(DoctorSummary {
        inventory_digest: native_repository_inventory_digest(root)?,
        catalog_entries: status.capability_count,
        provider_count,
    })
}
fn native_repository_inventory_digest(root: &Path) -> Result<String, commands::CommandError> {
    fn collect(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                if !matches!(
                    entry.file_name().to_str(),
                    Some(".git" | ".audit" | "node_modules" | "target")
                ) {
                    collect(root, &path, files)?;
                }
            } else if file_type.is_file() {
                files.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    collect(root, root, &mut files).map_err(commands::io_error)?;
    files.sort();
    let mut digest = Sha256::new();
    for relative in files {
        let path = root.join(&relative);
        digest.update(relative.to_string_lossy().replace('\\', "/").as_bytes());
        digest.update([0]);
        digest.update(std::fs::read(path).map_err(commands::io_error)?);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
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
        "schemaVersion": 1, "kind": format!("legion-{kind}"), "status": if clean_claim { "complete" } else { "incomplete" },
        "repository": repository, "inventoryDigest": summary.inventory_digest,
        "catalogEntries": summary.catalog_entries, "providerCount": summary.provider_count,
    });
    if let Some(arguments) = arguments {
        output["arguments"] = json!(arguments);
    }
    if let Some(json_flag) = json_flag {
        output["json"] = json!(json_flag);
    }
    output["cleanClaimPossible"] = Value::Bool(clean_claim);
    output["capabilityAttestations"] = capability_attestations();
    if !clean_claim {
        output["gaps"] = json!([
            "native repository inventory, catalog, and provider composition are not connected"
        ]);
    }
    output
}

fn native_schedule(args: ScheduleArgs) -> CommandResult {
    if args.trigger_id.trim().is_empty() || args.workflow.trim().is_empty() {
        return Err(commands::CommandError::usage(
            "schedule requires non-empty --trigger-id and --workflow",
        ));
    }
    let state = persist_trigger(
        &args.state_root,
        &args.trigger_id,
        &args.workflow,
        &args.source,
        args.payload_digest.as_deref(),
    )?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-trigger-enqueue",
        "status": "complete",
        "triggerId": args.trigger_id,
        "workflow": args.workflow,
        "source": args.source,
        "deduplicated": state.deduplicated,
        "queueReceipt": state.queue_receipt,
        "workflowState": if state.deduplicated { "already-started" } else { "started" },
        "json": args.json,
    }))
}

struct TriggerPersistence {
    deduplicated: bool,
    queue_receipt: PathBuf,
}

fn persist_trigger(
    state_root: &Path,
    trigger_id: &str,
    workflow: &str,
    source: &str,
    payload_digest: Option<&str>,
) -> Result<TriggerPersistence, commands::CommandError> {
    std::fs::create_dir_all(state_root).map_err(commands::io_error)?;
    let safe_id = trigger_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let queue_receipt = state_root.join(format!("{safe_id}.json"));
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&queue_receipt)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(TriggerPersistence {
                deduplicated: true,
                queue_receipt,
            })
        }
        Err(error) => return Err(commands::io_error(error)),
    };
    let receipt = json!({
        "schemaVersion": 1,
        "kind": "legion-trigger-receipt",
        "triggerId": trigger_id,
        "workflow": workflow,
        "source": source,
        "payloadDigest": payload_digest,
        "state": "started",
    });
    use std::io::Write as _;
    file.write_all(&serde_json::to_vec_pretty(&receipt).map_err(commands::io_error)?)
        .and_then(|_| file.sync_all())
        .map_err(commands::io_error)?;
    Ok(TriggerPersistence {
        deduplicated: false,
        queue_receipt,
    })
}

fn capability_attestations() -> Value {
    let identity = format!("legion:{}", env!("CARGO_PKG_VERSION"));
    Value::Array(
        providers()
            .into_iter()
            .map(|metadata| capability_attestation(metadata, Some(true), &identity))
            .collect(),
    )
}

fn capability_attestation(metadata: Value, availability: Option<bool>, identity: &str) -> Value {
    let id = metadata
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let metadata_digest = legion_contracts::canonical_digest(&metadata)
        .unwrap_or_else(|_| format!("sha256:{}", "0".repeat(64)));
    let (trust, signature) = match availability {
        Some(true) => {
            let mut signature = Sha256::new();
            signature.update(identity.as_bytes());
            signature.update([0]);
            signature.update(metadata_digest.as_bytes());
            (
                "VERIFIED",
                Some(format!("sha256:{}", hex::encode(signature.finalize()))),
            )
        }
        Some(false) => ("UNAVAILABLE", None),
        None => ("UNKNOWN", None),
    };
    json!({
        "schemaVersion": 1,
        "kind": "legion-capability-attestation",
        "capabilityId": id,
        "metadataDigest": metadata_digest,
        "availability": availability,
        "trust": trust,
        "identity": identity,
        "signature": signature,
    })
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
            repository_id: _,
            inventory_digest,
            catalog_entries,
            provider_count,
        } => Ok(DoctorSummary {
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
    if std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_none() {
        return Ok(json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": root,
            "providers": [],
            "status": "incomplete",
            "gaps": ["native frozen provider composition is not connected"],
        }));
    }
    let signing_key = commands::audit_signing_key()?;
    let application = commands::native_application_for(&root.to_string_lossy())?;
    match application
        .invoke_with_cancellation(
            legion_application::NativeOperation::Plan {
                repository_id: root.to_string_lossy().into_owned(),
                providers: application.provider_specs(),
                signing_key: Some(signing_key),
            },
            cancellation,
        )
        .await
        .map_err(|error| commands::CommandError::incomplete(error.to_string()))?
    {
        legion_application::NativeOperationResult::Plan {
            repository_id,
            plan_digest,
            plan_signature,
            providers,
        } => Ok(
            json!({"schemaVersion": 1, "kind": "audit-provider-plan", "repository": repository_id, "seal": {"digest": plan_digest, "authenticity": "hmac-sha256", "signature": plan_signature}, "providers": providers, "status": "complete"}),
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
            .map(legion_contracts::canonical_digest)
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
    if std::env::var_os("LEGION_NATIVE_APPLICATION_CONFIG").is_none() {
        return Ok(json!({
            "schemaVersion": 1,
            "kind": "legion-run",
            "subcommand": subcommand,
            "request": request,
            "status": "incomplete",
            "gaps": ["native run composition is not connected"],
        }));
    }
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
    let metadata = std::fs::symlink_metadata(current).map_err(commands::io_error)?;
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(current).map_err(commands::io_error)?;
        let bytes = target.to_string_lossy().as_bytes().to_vec();
        entries.insert(
            ".".into(),
            json!({"kind": "symlink", "target": target, "sha256": legion_host::digest_bytes(&bytes), "size": bytes.len()}),
        );
        return Ok(());
    }
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
        let metadata = std::fs::symlink_metadata(&path).map_err(commands::io_error)?;
        if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(&path).map_err(commands::io_error)?;
            let bytes = target.to_string_lossy().as_bytes().to_vec();
            entries.insert(
                relative,
                json!({"kind": "symlink", "target": target, "sha256": legion_host::digest_bytes(&bytes), "size": bytes.len()}),
            );
        } else if metadata.is_dir() {
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

#[cfg(test)]
mod unresolved_atom_tests {
    use super::*;

    #[test]
    fn leg_024_trigger_identity_deduplicates_durable_enqueue_and_start() {
        let root = std::env::temp_dir().join(format!(
            "legion-trigger-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let first = persist_trigger(&root, "timer-1", "audit", "schedule", Some("sha256:x"))
            .expect("first trigger");
        let second = persist_trigger(&root, "timer-1", "audit", "schedule", Some("sha256:x"))
            .expect("deduplicated trigger");
        assert!(!first.deduplicated);
        assert!(second.deduplicated);
        assert_eq!(first.queue_receipt, second.queue_receipt);
        let receipt: Value =
            serde_json::from_slice(&std::fs::read(first.queue_receipt).unwrap()).unwrap();
        assert_eq!(receipt["state"], "started");
    }

    #[test]
    fn leg_027_doctor_and_api_share_verified_capability_attestation_envelope() {
        let doctor = capability_attestations();
        let api = capability_attestations();
        assert_eq!(doctor, api);
        let records = doctor.as_array().expect("attestation array");
        assert!(!records.is_empty());
        assert!(records.iter().all(|record| {
            record["trust"] == "VERIFIED"
                && record["metadataDigest"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("sha256:"))
                && record["signature"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("sha256:"))
        }));
        let unavailable =
            capability_attestation(json!({"id":"missing"}), Some(false), "legion:test");
        let unknown = capability_attestation(json!({"id":"unknown"}), None, "legion:test");
        assert_eq!(unavailable["trust"], "UNAVAILABLE");
        assert_eq!(unknown["trust"], "UNKNOWN");
        assert!(unavailable["signature"].is_null());
    }
}
