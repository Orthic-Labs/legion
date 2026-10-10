use crate::commands::{self, CommandResult};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
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
    /// Native Apple tools, documentation, diagnostics & App Store Connect.
    Apple(commands::apple::AppleArgs),
    /// Report the native M1 installed-release status.
    Status(M1ConfigArgs),
    /// Serve the Legion MCP server over stdio for a plugin host.
    Serve(ServeArgs),
    /// Initialize Legion evidence scaffolding in a repository.
    Init(commands::init::InitArgs),
    /// Check the installed product and repository for gaps.
    Doctor(RootArgs),
    /// Bind a repository to the frozen release composition.
    Bind(commands::bind::BindArgs),
    /// Inspect the resolved repository composition.
    Inspect(RootArgs),
    /// List the audit targets discovered for a repository.
    Targets(RootArgs),
    /// List the capability components available to a repository.
    Components(RootArgs),
    /// List the technology stacks detected for a repository.
    Stacks(RootArgs),
    /// List the policy controls in force for a repository.
    Controls(RootArgs),
    /// Evaluate governance execution, delivery or judgment from a JSON request.
    Governance(CommonArgs),
    /// List the skills packaged with this Legion release.
    Skills(CommonArgs),
    /// List the languages this Legion release can qualify.
    Languages(CommonArgs),
    /// List the audit providers this Legion release composes.
    Providers(CommonArgs),
    /// Render the workspace and package rule set.
    Rules(commands::rules::RulesArgs),
    /// Durably enqueue and start a workflow trigger.
    Schedule(commands::schedule::ScheduleArgs),
    /// Produce the frozen audit provider plan for a repository.
    Plan(commands::plan::PlanArgs),
    /// Run an evidence-governed repository audit.
    Audit(commands::audit::AuditArgs),
    /// Verify audit facts against a sealed provider plan.
    Verify(commands::verify::VerifyArgs),
    /// Explain an audit finding or capability.
    Explain(CommonArgs),
    /// Render a stored audit report in another format.
    Report(commands::report::ReportArgs),
    /// List repair classes (dry-run), or apply them with --apply.
    ///
    /// Usage: legion fix [--apply] [--class <id>] [--client <id>]. Each applier
    /// is existing machinery (`legion setup repair --confirm`); classes with no
    /// applier are listed as manual with the command to run. `legion fix --plan
    /// <sealed-remediation-plan>` validates a sealed plan (digest and shape);
    /// applying it is manual (Alchemist).
    Fix(CommonArgs),
    /// Show, install or remove Legion hooks registered in host configs.
    ///
    /// Usage: legion hooks status | install [--client <id>] [--confirm] | remove
    /// [--client <id>] [--confirm]. Install and remove delegate to the setup
    /// registry (`legion setup repair|remove`) and preview unless --confirm.
    Hooks(CommonArgs),
    /// Print the Legion MCP server config, or register it with a host.
    ///
    /// Usage: legion mcp print-config | legion mcp install [--client <id>]
    /// [--preview] [--confirm]. Install previews unless --confirm, then
    /// registers through `legion setup repair`; it refuses when a registration
    /// already exists at another scope.
    Mcp(CommonArgs),
    /// Manage contracted run transactions.
    ///
    /// Usage: legion run open|close|suspend|supersede|repair ...
    Run(CommonArgs),
    /// Inspect a contract budget.
    ///
    /// Usage: legion budget inspect --contract <id> --version <n> --task <id> [--run <id>]
    Budget(CommonArgs),
    /// Seal an executable contract.
    ///
    /// Usage: legion contract seal --file <executable-contract.json> [--session <id>]
    Contract(CommonArgs),
    /// Record an authenticated completion claim or evidence artifact.
    ///
    /// Usage: legion completion claim|evidence --file <outcome.json> --session <id>
    Completion(CommonArgs),
    /// Inspect host lifecycle events or describe a host.
    ///
    /// Usage: legion host events inspect [--session <id>] | legion host describe [<root>] [--descriptor <path>]
    Host(CommonArgs),
    /// List, detect, verify, install or remove host harness adapters.
    ///
    /// Usage: legion harness list|detect|capabilities|matrix|install|verify|uninstall
    Harness(CommonArgs),
    /// Inspect authority invocation proofs.
    ///
    /// Usage: legion authority proof inspect [--invocation <id>]
    Authority(CommonArgs),
    /// Snapshot or verify repository working-tree state.
    ///
    /// Usage: legion state snapshot --path <dir> --out <file> | legion state verify --snapshot <file>
    State(CommonArgs),
    /// Record Minimize commits and decisions.
    ///
    /// Usage: legion minimize commit|decision ...
    Minimize(CommonArgs),
    /// Inspect the native capability catalog.
    Catalog(commands::catalog::CatalogArgs),
    /// Inspect the native policy pack.
    Policy(commands::policy::PolicyArgs),
    /// Record or inspect a routing decision.
    Decision(commands::decision::DecisionArgs),
    /// Prepare or validate a cold-start handoff packet.
    Handoff(commands::handoff::HandoffArgs),
    /// Route an evidence research request.
    Research(commands::research::ResearchArgs),
    /// Run an independent completion-validation review.
    Review(commands::review::ReviewArgs),
    /// Install, check, or purge the installed Legion product.
    Setup(commands::setup::SetupArgs),
    /// Dispatch to the Rust port of a `skills/**/scripts/**` CLI (`--list` to enumerate).
    Script(commands::script::ScriptArgs),
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
pub(crate) struct CommonArgs {
    #[arg(long)]
    pub(crate) json: bool,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<OsString>,
}
#[derive(Debug, clap::Args)]
pub(crate) struct RootArgs {
    #[arg(default_value = ".")]
    pub(crate) root: std::path::PathBuf,
    #[arg(long)]
    pub(crate) json: bool,
}
const M1_COMPOSITION_SCHEMA_VERSION: u32 = 1;
const M1_STATE_SCHEMA_VERSION: u32 = 1;
const M1_REPAIR: &str = "legion setup repair --confirm";
const M1_RIGHTKIT_AX_VERSION: &str = "0.2.1";
const M1_RIGHTKIT_AX_SOURCE_COMMIT: &str = "4c1a414269d8ffdb95b4b1e685440bd34784b41b";
const M1_INSTALLED_COMPOSITION: &str = "share/legion/composition.json";
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RightAxPortableCore {
    schema_version: u32,
    kind: String,
    plugin: String,
    public_skills: Vec<String>,
    /// Agents the core carries. Older cores predate the field, so it defaults
    /// to empty rather than making the binary reject a package it can still
    /// validate. The closure check below is what actually proves the declared
    /// agents exist on disk.
    #[serde(default)]
    public_agents: Vec<String>,
    public_files: Vec<String>,
    private_workspace_content: bool,
    client_projections: Value,
}

/// Validate the structure of the RightAX client-projection map without
/// re-asserting a frozen copy of it. `rightax-portable-core.json` is authored
/// by the release build and is the contract; a later release that adds a
/// client or changes a projection string must not make the shipped binary
/// reject its own core. The one invariant enforced here is a safety one: the
/// Pi projection is skills-only and must never be granted an executable
/// registration.
fn validate_right_ax_client_projections(value: &Value) -> Result<(), commands::CommandError> {
    let clients = value
        .as_object()
        .ok_or_else(|| plugin_root_error("RightAX client projections are not an object"))?;
    if clients.is_empty() {
        return Err(plugin_root_error("RightAX client projections are empty"));
    }
    for (client, projection) in clients {
        let fields = projection.as_object().ok_or_else(|| {
            plugin_root_error(format!("RightAX {client} projection is not an object"))
        })?;
        let bool_field = |name: &str| -> Result<bool, commands::CommandError> {
            fields.get(name).and_then(Value::as_bool).ok_or_else(|| {
                plugin_root_error(format!(
                    "RightAX {client} projection is missing boolean {name}"
                ))
            })
        };
        let string_field = |name: &str| -> Result<(), commands::CommandError> {
            match fields.get(name).and_then(Value::as_str) {
                Some(text) if !text.trim().is_empty() => Ok(()),
                _ => Err(plugin_root_error(format!(
                    "RightAX {client} projection is missing string {name}"
                ))),
            }
        };
        bool_field("portableCore")?;
        string_field("projection")?;
        string_field("fidelity")?;
        let executable_registration = bool_field("executableRegistration")?;
        if client == "pi" && executable_registration {
            return Err(plugin_root_error(
                "RightAX Pi projection may not register an executable",
            ));
        }
    }
    Ok(())
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

/// A symlink, or (on Windows) a directory junction / mount point — anything
/// whose traversal silently redirects to another location.
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn validate_portable_plugin_root(
    raw_root: &Path,
    manifest: &legion_runtime::ReleaseManifest,
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
    // Scan the path *as given* (before canonicalize, which resolves every
    // symlink and junction and would leave nothing to inspect). Reject any
    // ancestor that is a symlink or junction, with one exception: the stable
    // `current` junction of the installed layout, recognised by its file name
    // being exactly `current` and its parent holding a `versions` directory.
    for ancestor in absolute_root.ancestors() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(plugin_root_error(format!(
                    "cannot inspect {}: {error}",
                    ancestor.display()
                )))
            }
        };
        if is_reparse_point(&metadata) {
            let is_stable_current = ancestor.file_name().and_then(|name| name.to_str())
                == Some("current")
                && ancestor
                    .parent()
                    .map(|parent| parent.join("versions").is_dir())
                    .unwrap_or(false);
            if !is_stable_current {
                return Err(plugin_root_error(format!(
                    "plugin root crosses symlink {}",
                    ancestor.display()
                )));
            }
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
    let portable_contract_bytes =
        std::fs::read(&portable_contract_path).map_err(commands::io_error)?;
    // Independent anchor: the portable core is trusted only if its bytes hash to
    // the digest the release build recorded in the manifest. Without this the
    // validator would be checking the core against fields drawn from that same
    // (potentially tampered) file.
    let actual_core_digest = {
        let mut hasher = Sha256::new();
        hasher.update(&portable_contract_bytes);
        hex::encode(hasher.finalize())
    };
    match &manifest.portable_core_sha256 {
        None => {
            return Err(plugin_root_error(
                "this release predates the portable-core anchor (manifest has no portableCoreSha256)",
            ))
        }
        Some(expected) if expected.eq_ignore_ascii_case(&actual_core_digest) => {}
        Some(expected) => {
            return Err(plugin_root_error(format!(
                "portable core digest mismatch: manifest declares {expected} but package hashes to {actual_core_digest}"
            )))
        }
    }
    let portable_contract: RightAxPortableCore = serde_json::from_slice(&portable_contract_bytes)
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
    // Derive the canonical skill set from the release-authored contract itself
    // rather than a constant that drifts every time a skill is added; the exact
    // correspondence to the files on disk is still enforced by the closure
    // check below and by `is_allowed_portable_public_file`.
    let expected_skills = portable_contract
        .public_skills
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if expected_skills.len() != portable_contract.public_skills.len() {
        return Err(plugin_root_error(
            "RightAX portable core lists a public skill more than once",
        ));
    }
    if portable_contract
        .public_skills
        .iter()
        .any(|skill| skill.contains('/') || !is_safe_portable_relative_path(skill))
    {
        return Err(plugin_root_error(
            "RightAX portable core public skill id is unsafe",
        ));
    }
    let expected_agents = portable_contract
        .public_agents
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if expected_agents.len() != portable_contract.public_agents.len()
        || portable_contract
            .public_agents
            .iter()
            .any(|agent| agent.contains('/') || !is_safe_portable_relative_path(agent))
    {
        return Err(plugin_root_error(
            "RightAX portable core public agent id is unsafe or repeated",
        ));
    }
    validate_right_ax_client_projections(&portable_contract.client_projections)?;
    let mut expected_files = portable_contract
        .public_files
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if expected_files.len() != portable_contract.public_files.len()
        || !expected_files.contains("plugin.json")
        || !expected_files.contains("mcp.json")
        // Hooks are surface, not decoration: a core that declares none
        // leaves every guard event unregistered in the host.
        || !expected_files.contains("hooks/hooks.json")
        || expected_skills
            .iter()
            .any(|skill| !expected_files.contains(&format!("skills/{skill}/SKILL.md")))
        // Every declared agent must be a declared file too, so a core cannot
        // advertise an agent it does not carry: shipping skills while silently
        // dropping the agents is exactly how sage, alchemist and the covenant
        // seat stayed unreachable from every client.
        || portable_contract
            .public_agents
            .iter()
            .any(|agent| !expected_files.contains(&format!("agents/{agent}.md")))
    {
        return Err(plugin_root_error(
            "RightAX public file declaration is incomplete",
        ));
    }
    if portable_contract.public_files.iter().any(|relative| {
        !is_allowed_portable_public_file(relative, &expected_skills, &expected_agents)
    }) {
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
    // Known per-client projection additions written on purpose by the setup
    // registry: the Claude native-plugin manifest copy and the Antigravity MCP
    // config copy. These aliases preserve the portable-core original; Claude's
    // MCP descriptor additionally has one exact host-specific argument projection.
    let claude_projection = root.join(".claude-plugin").join("plugin.json");
    if claude_projection.is_file() {
        let projected = std::fs::read(&claude_projection).map_err(commands::io_error)?;
        let original = std::fs::read(root.join("plugin.json")).map_err(commands::io_error)?;
        if projected != original {
            return Err(plugin_root_error(
                ".claude-plugin/plugin.json does not match plugin.json",
            ));
        }
        expected_files.insert(".claude-plugin/plugin.json".into());
    }
    let antigravity_projection = root.join("mcp_config.json");
    if antigravity_projection.is_file() {
        let projected = std::fs::read(&antigravity_projection).map_err(commands::io_error)?;
        let original = std::fs::read(root.join("mcp.json")).map_err(commands::io_error)?;
        if projected != original {
            return Err(plugin_root_error("mcp_config.json does not match mcp.json"));
        }
        expected_files.insert("mcp_config.json".into());
    }
    // Claude Code reads a plugin's MCP server from `.mcp.json`, so the Claude
    // projection writes that descriptor beside the portable `mcp.json`.
    // Claude does not expand ${PLUGIN_ROOT}; assembly removes only that pair
    // from its native descriptor. Everything else must match the portable one.
    let claude_mcp_projection = root.join(".mcp.json");
    if claude_mcp_projection.is_file() {
        let projected = std::fs::read(&claude_mcp_projection).map_err(commands::io_error)?;
        let original = std::fs::read(root.join("mcp.json")).map_err(commands::io_error)?;
        if !matches_claude_mcp_projection(&original, &projected) {
            return Err(plugin_root_error(
                ".mcp.json does not match the approved Claude projection of mcp.json",
            ));
        }
        expected_files.insert(".mcp.json".into());
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

    for relative in [
        "plugin.json",
        "mcp.json",
        "hooks/hooks.json",
        "rightax-portable-core.json",
    ] {
        serde_json::from_slice::<Value>(
            &std::fs::read(root.join(relative)).map_err(commands::io_error)?,
        )
        .map_err(|error| plugin_root_error(format!("{relative} is not valid JSON: {error}")))?;
    }
    validate_portable_plugin_manifests(&root)?;

    Ok(())
}

fn matches_claude_mcp_projection(original: &[u8], projected: &[u8]) -> bool {
    if original == projected {
        return true;
    }
    let Ok(mut expected) = serde_json::from_slice::<Value>(original) else {
        return false;
    };
    let Some(args) = expected.pointer_mut("/mcpServers/legion/args") else {
        return false;
    };
    if *args != json!(["serve", "--stdio", "--plugin-root", "${PLUGIN_ROOT}"]) {
        return false;
    }
    *args = json!(["serve", "--stdio"]);
    serde_json::from_slice::<Value>(projected).is_ok_and(|value| value == expected)
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

fn is_allowed_portable_public_file(
    relative: &str,
    expected_skills: &BTreeSet<String>,
    expected_agents: &BTreeSet<String>,
) -> bool {
    // Client descriptor aliases now ship in the core so every client's plugin
    // root is byte-identical to one installed tree.
    if matches!(
        relative,
        "plugin.json"
            | "mcp.json"
            | "hooks/hooks.json"
            | ".mcp.json"
            | "mcp_config.json"
            | ".claude-plugin/plugin.json"
    ) {
        return true;
    }
    // The assembled plugin root carries the generated host projection under
    // share/legion; the contract declares it and only this exact path is
    // permitted — no other share/ content is public plugin surface.
    if relative == "share/legion/src/registry/host-projection.json" {
        return true;
    }
    // agents/<name>.md, for a name the contract declares.
    if let Some(agent) = relative
        .strip_prefix("agents/")
        .and_then(|rest| rest.strip_suffix(".md"))
    {
        return !agent.is_empty()
            && expected_agents.contains(agent)
            && is_safe_portable_relative_path(relative);
    }
    let mut components = relative.split('/');
    if components.next() != Some("skills") {
        return false;
    }
    let Some(skill) = components.next() else {
        return false;
    };
    // `skills/_shared/<file>` carries the shared craft guides that Writing,
    // Designer, Marketing & Social require beside the catalog skills.
    let shared = skill == "_shared";
    if (!shared && !expected_skills.contains(skill)) || components.next().is_none() {
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

/// Python bytecode written next to a skill's own scripts when the skill runs.
/// It is never part of the shipped package, so it neither satisfies nor
/// violates the package contract.
fn is_generated_bytecode(relative: &str) -> bool {
    relative.split('/').any(|segment| segment == "__pycache__")
        || relative.ends_with(".pyc")
        || relative.ends_with(".pyo")
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
        // Running a Python-backed skill writes bytecode beside its source, so a
        // projection that has simply been used no longer matches the shipped
        // contract and every later MCP start is refused (observed on the
        // installed 0.3.13: skills/alchemist, coder and seo each grew a
        // __pycache__ after use). Bytecode is generated, never authored, so it
        // is ignored rather than treated as tampering.
        if is_generated_bytecode(&relative) {
            continue;
        }
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
        let mut tools = vec![
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
        ];
        tools.extend(crate::apple_mcp::tool_definitions());
        tools
    }

    fn validate_tool_scope(
        &self,
        operation: &str,
        arguments: &Value,
    ) -> Result<(), legion_mcp::McpError> {
        if operation == "legion_apple" {
            return crate::apple_mcp::validate_scope(arguments)
                .map_err(|_| legion_mcp::McpError::InvalidParams);
        }
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
        if operation == "legion_apple" {
            return Err(legion_runtime::RuntimeError::Policy(
                "Apple operation requires async dispatch".into(),
            ));
        }
        let application = self.application()?;
        match operation {
            "legion_m1_status" => {
                // The application can prove its native M1 slice, but it has
                // no evidence for the product-wide Codex/host surfaces.
                Ok(m1_product_status_value(&application.status()))
            }
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

    fn invoke_async<'a>(
        &'a self,
        operation: &'a str,
        arguments: &'a Value,
    ) -> legion_mcp::NativeFuture<'a> {
        if operation == "legion_apple" {
            return Box::pin(async move { crate::apple_mcp::invoke(arguments).await });
        }
        Box::pin(async move { self.invoke(operation, arguments) })
    }
}

/// The product-level gaps M1 does not close. One owner, because the CLI and the
/// MCP tool must not be able to disagree about them.
const M1_UNVERIFIED_CHECKS: [&str; 3] = [
    "Codex hook enforcement qualification has not been observed",
    "native CLI projection qualification has not been observed",
    "installed product qualification has not been observed",
];

fn m1_product_status_value(status: &legion_application::M1Status) -> Value {
    let mut value = m1_status_value(status);
    if let Value::Object(object) = &mut value {
        object.insert("scope".into(), json!("legion-product"));
        // Transport and native-slice evidence do not establish a global
        // completion or fidelity claim. Keep known gaps visible and name the
        // product-level result as unknown until host qualification supplies
        // that evidence.
        object.insert("status".into(), json!("unknown"));
        object.insert("fidelity".into(), json!("unknown"));
        object.insert("unverifiedChecks".into(), json!(M1_UNVERIFIED_CHECKS));
    }
    value
}

fn m1_status_value(status: &legion_application::M1Status) -> Value {
    let mut value = serde_json::to_value(status).expect("M1 status is serializable");
    if let Value::Object(object) = &mut value {
        object.insert("scope".into(), json!("m1-vertical-slice"));
        // This says the M1 vertical slice is complete, which is true, and says
        // nothing about the product. Nested under "native" that was clear, but
        // the MCP tool returns this value at the top level, where a bare
        // "status": "complete" reads as product status while the CLI answers
        // "incomplete" with three named gaps. Name the scope it belongs to.
        object.insert("sliceStatus".into(), json!("complete"));
        object.remove("status");
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
                "status": "unknown",
                "fidelity": "unknown",
                "scope": "legion-product",
                "origin": native.origin.clone(),
                "executable": native.executable.clone(),
                "installRoot": native.install_root.clone(),
                "generation": native.generation.clone(),
                "unverifiedChecks": M1_UNVERIFIED_CHECKS,
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
                "fidelity": "unknown",
                "scope": "legion-product",
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
    let is_help_flag = |value: &OsString| matches!(value.to_str(), Some("--help" | "-h"));
    // With no command supplied, print the native root help (clap-generated from
    // the command enum, so it can never drift from the real command set) on
    // stdout and exit 4, keeping the established "usage on stdout" channel.
    if args.is_empty() || args == [OsString::from("--json")] {
        print!("{}", Cli::command().render_help());
        return 4;
    }
    if args.len() == 1 && matches!(args[0].to_str(), Some("--version" | "-V")) {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if args.len() == 1
        && !is_help_flag(&args[0])
        && args[0].to_str().is_some_and(|value| value.starts_with('-'))
    {
        eprintln!(
            "Unknown option '{}'. Run `legion --help` for the list of commands.",
            args[0].to_string_lossy(),
        );
        return 4;
    }
    if args.len() == 2
        && args[0].to_str() == Some("doctor")
        && !is_help_flag(&args[1])
        && args[1]
            .to_str()
            .is_some_and(|value| value.starts_with('-') && value != "--json")
    {
        eprintln!(
            "Unknown option '{}'. Run `legion doctor --help` for usage.",
            args[1].to_string_lossy()
        );
        return 4;
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
            // clap has already selected the requested command's help. Rendering
            // the root here loses subcommand options and even replaces version
            // output with help.
            if error.kind() == ErrorKind::DisplayVersion {
                println!("{}", env!("CARGO_PKG_VERSION"));
            } else {
                print!("{error}");
            }
            0
        }
        Err(error) => {
            let root_command = args
                .iter()
                .find(|arg| !arg.to_string_lossy().starts_with('-'));
            if error.kind() == ErrorKind::InvalidSubcommand
                && root_command.is_some_and(|name| {
                    !Cli::command()
                        .get_subcommands()
                        .any(|command| name.to_str() == Some(command.get_name()))
                })
            {
                eprintln!(
                    "unknown command: {}",
                    root_command.unwrap().to_string_lossy()
                );
            } else {
                eprintln!("{error}");
            }
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
    let result: CommandResult = match command {
        Command::Apple(args) => commands::apple::run(args, cancellation.clone()).await,
        Command::Status(args) => native_m1_status(args).await,
        Command::Serve(args) => native_m1_serve(args).await,
        Command::Catalog(args) => commands::catalog::run(args),
        Command::Policy(args) => commands::policy::run(args),
        Command::Audit(args) => commands::audit::run(args, cancellation.clone()).await,
        Command::Host(args) => commands::host_runtime::run(args),
        Command::Decision(args) => commands::decision::run(args),
        Command::Handoff(args) => commands::handoff::run(args),
        Command::Research(args) => commands::research::run(args, cancellation.clone()),
        Command::Review(args) => commands::review::run(args, cancellation.clone()).await,
        Command::Setup(args) => commands::setup::run(args, cancellation.clone()).await,
        Command::Providers(args) => commands::providers::run(args),
        Command::Languages(args) => commands::languages::run(args),
        Command::Doctor(mut args) => {
            if root_json {
                args.json = true;
            }
            commands::doctor::run(args, cancellation.clone()).await
        }
        Command::Init(args) => commands::init::run(args),
        Command::Bind(args) => commands::bind::run(args),
        Command::Inspect(args) => commands::topology::run_inspect(args),
        Command::Targets(args) => commands::topology::run_targets(args),
        Command::Components(args) => commands::topology::run_components(args),
        Command::Stacks(args) => commands::topology::run_stacks(args),
        Command::Controls(args) => commands::topology::run_controls(args),
        Command::Plan(args) => commands::plan::run(args, cancellation.clone()).await,
        Command::Verify(args) => commands::verify::run(args, cancellation.clone()).await,
        Command::Explain(args) => commands::explain::run(args),
        Command::Report(args) => commands::report::run(args, cancellation.clone()).await,
        Command::Fix(args) => commands::fix::run(args, cancellation.clone()).await,
        Command::Hooks(args) => commands::hooks::run(args, cancellation.clone()).await,
        Command::Mcp(args) => commands::mcp_config::run(args, cancellation.clone()).await,
        Command::Run(args) => commands::run::run(args, cancellation.clone()).await,
        Command::Budget(args) => commands::budget::run(args),
        Command::Contract(args) => commands::contract::run(args),
        Command::Governance(args) => commands::governance::run(args),
        Command::Skills(args) => commands::skills::run(args),
        Command::Rules(args) => commands::rules::run(args),
        Command::Schedule(args) => commands::schedule::run(args),
        Command::Completion(args) => commands::completion::run(args),
        Command::Harness(args) => commands::harness::run(args),
        Command::Authority(args) => commands::authority::run(args),
        Command::State(args) => commands::state::run(args),
        Command::Minimize(args) => commands::minimize::run(args),
        Command::Script(args) => commands::script::run(args),
    };
    result
}
fn finish(result: CommandResult) -> i32 {
    match result {
        Ok(mut value) => {
            if let Some(code) = value.get("__exit_code").and_then(Value::as_i64) {
                return code as i32;
            }
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
            let compact = value.get("__compact").and_then(Value::as_bool) == Some(true);
            if compact {
                if let Some(object) = value.as_object_mut() {
                    object.shift_remove("__compact");
                }
            }
            let rendered = if compact {
                serde_json::to_string(&value)
            } else {
                serde_json::to_string_pretty(&value)
            };
            println!("{}", rendered.unwrap_or_else(|_| "{}".into()));
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
            if value.get("kind").and_then(Value::as_str) == Some("legion-explain")
                && value.get("found").and_then(Value::as_bool) == Some(false)
            {
                return 4;
            }
            if value.get("kind").and_then(Value::as_str) == Some("legion-harness-verify")
                && value.get("ok").and_then(Value::as_bool) == Some(false)
            {
                return 2;
            }
            if value.get("kind").and_then(Value::as_str) == Some("legion-state-verify")
                && value.get("verdict").and_then(Value::as_str) == Some("breach")
            {
                return 1;
            }
            if value.get("status").and_then(Value::as_str) == Some("fail")
                && value.get("findings").and_then(Value::as_array).is_some()
                && value.get("count").and_then(Value::as_u64).is_some()
            {
                return 5;
            }
            if value.get("kind").and_then(Value::as_str) == Some("legion-bind-registrations")
                && value
                    .get("duplicates")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty())
            {
                return 1;
            }
            if value.get("kind").and_then(Value::as_str)
                == Some("arcane-execution-control-decision")
                && value
                    .get("result")
                    .and_then(|result| result.get("allowed"))
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                return 2;
            }
            if value.get("consumable").and_then(Value::as_bool) == Some(true) {
                return 0;
            }
            if value.get("code").and_then(Value::as_str) == Some("ARC_OPERATION_UNKNOWN")
                || value.get("code").and_then(Value::as_str) == Some("ARC_DIAGNOSTIC_ONLY")
            {
                return 2;
            }
            if value.get("allowed").and_then(Value::as_bool) == Some(false)
                && value.get("kind").is_none()
                && (value.get("code").is_some() || value.get("detail").is_some())
            {
                return 2;
            }
            if value.get("complete").and_then(Value::as_bool) == Some(false) {
                return 2;
            }
            if value.get("artifact").is_some()
                && value.get("selectionTrace").is_some()
                && value.get("complete").is_none()
            {
                return 2;
            }
            if value.get("artifact").is_some()
                && value.pointer("/artifact/kind").and_then(Value::as_str)
                    == Some("legion-control-baseline")
                && value.get("selectionTrace").is_none()
            {
                return 2;
            }
            if value.get("outcome").is_some()
                && value.get("consumable").and_then(Value::as_bool) != Some(true)
            {
                return 2;
            }
            match value
                .get("auditStatus")
                .or_else(|| value.get("status"))
                .and_then(Value::as_str)
            {
                Some("incomplete") | Some("unproven") | Some("partial") | Some("failed")
                | Some("cancelled") | Some("unavailable") | Some("unknown") => 2,
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
