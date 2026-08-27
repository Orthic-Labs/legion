#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;

use legion_audit::{
    execute, verify_binding, verify_execution, AuditError, AuditPlan, AuditProvider,
    BlueprintInventorySource, ExecutionReport, FileBlueprintInventorySource, InventoryEnvelope,
    ProviderExecutor,
};
use legion_catalog::{Catalog, CatalogError};
use legion_contracts::task::RequestEnvelope;
use legion_contracts::{
    AgentDefinition, AgentId, BudgetCeiling, Coverage, EffectRequest, InvocationGrant,
    InvocationId, Latitude, PolicyPack, ProviderId, ProviderResult, ProviderSpec, ProviderStatus,
    ReportId, ReportStatus, ReportV1, RequestId, RoutingCeiling, TaskSpec, TaskStatus, ToolCeiling,
};
use legion_provider_sdk::{
    EffectInterface, ExternalProjectTool, ImplementationRegistry, Provider, ProviderContext,
    ProviderDefinition, ProviderError, ProviderErrorKind, ProviderRegistry,
    ProviderRegistryDocument, SourceInterface,
};
use legion_report::ReportError;
use legion_runtime::{
    ContextRequest, EffectPolicy, EngineOutcome, Invocation, LegionEngine, RouteCandidate,
    RuntimeError,
};
use thiserror::Error;

use legion_policy::{PolicyEvaluation, PolicyEvaluator, PolicyReceipt};
use legion_policy_model::{DecisionOutcome, PolicyContext, PolicyPack as ArcanePolicyPack};

/// Read-only catalog access supplied by the composition owner.
pub trait CatalogSource: Send + Sync {
    fn catalog(&self) -> Result<Catalog, CatalogError>;
}

/// Read-only report access supplied by the composition owner.
pub trait ReportSource: Send + Sync {
    fn report(&self) -> Result<ReportV1, ReportError>;
}

/// Run state access supplied by the composition owner.
pub trait RunSource: Send + Sync {
    fn invocation(&self) -> Result<Invocation, RuntimeError>;

    /// Build one invocation from parsed lifecycle request data. Existing
    /// sources retain their legacy default while native CLI composition can
    /// pass the exact typed request through the same runtime context.
    fn invocation_for(&self, _request: &serde_json::Value) -> Result<Invocation, RuntimeError> {
        self.invocation()
    }
}

/// Native renderer selected by a report operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    Json,
    Sarif,
    Markdown,
    Html,
}

/// Bounded work exposed by the native application seam.
#[allow(clippy::large_enum_variant)]
pub enum NativeOperation {
    /// Execute one already-authorized runtime invocation.
    Invoke(Invocation),
    /// Obtain one invocation from the injected run source, then execute it.
    Run,
    /// Obtain one invocation from the injected run source using parsed CLI
    /// lifecycle request data, then execute it.
    RunRequest { request: serde_json::Value },
    /// Validate one repository's configured inventory/catalog without running providers.
    Doctor { repository_id: String },
    /// Compile and freeze one plan from explicit provider specifications.
    Plan {
        repository_id: String,
        providers: Vec<ProviderSpec>,
        signing_key: Option<Vec<u8>>,
    },
    /// Compile, freeze, bind, execute, and verify one audit plan.
    Audit {
        repository_id: String,
        providers: Vec<ProviderSpec>,
        signing_key: Option<Vec<u8>>,
    },
    /// Rebuild one plan and verify its binding against current inventory.
    Verify {
        repository_id: String,
        providers: Vec<ProviderSpec>,
        signing_key: Option<Vec<u8>>,
    },
    /// Verify one CLI-supplied facts/plan pair against the configured native
    /// plan path after validating both artifacts as canonical objects.
    VerifyRequest {
        repository_id: String,
        providers: Vec<ProviderSpec>,
        signing_key: Option<Vec<u8>>,
        facts: serde_json::Value,
        plan: serde_json::Value,
    },
    /// Return the immutable catalog supplied by the catalog source.
    Catalog,
    /// Render the immutable report supplied by the report source.
    Report(ReportFormat),
}

/// Results preserve the underlying typed crate result; no empty success is synthesized.
pub enum NativeOperationResult {
    Invocation(EngineOutcome),
    Doctor {
        repository_id: String,
        inventory_digest: String,
        catalog_entries: usize,
        provider_count: usize,
    },
    Plan {
        repository_id: String,
        plan_digest: String,
        plan_signature: Option<String>,
        providers: Vec<String>,
    },
    Audit(ExecutionReport),
    Verification {
        repository_id: String,
        plan_digest: String,
        inventory_digest: String,
    },
    Catalog(Catalog),
    Report(String),
}

#[derive(Debug, Error)]
pub enum NativeApplicationError {
    #[error("required application component is missing: {component}")]
    MissingComponent { component: &'static str },
    #[error("runtime operation failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("audit operation failed: {0}")]
    Audit(#[from] AuditError),
    #[error("catalog operation failed: {0}")]
    Catalog(#[from] CatalogError),
    #[error("report operation failed: {0}")]
    Report(#[from] ReportError),
    #[error("invalid versioned application configuration: {0}")]
    Configuration(String),
    #[error("provider composition failed: {0}")]
    Provider(String),
}

/// Explicit, process-free composition inputs for the shared M1 application surface.
/// Both the CLI and MCP library construct this same type before serving requests.
#[derive(Clone, Debug)]
pub struct M1ApplicationInputs {
    pub release_manifest_path: std::path::PathBuf,
    pub release_binding_inputs: legion_runtime::ReleaseBindingInputs,
    pub catalog_root: std::path::PathBuf,
    pub catalog_index_path: std::path::PathBuf,
    pub policy_pack: ArcanePolicyPack,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum M1Availability {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct M1HostRequirementStatus {
    pub id: String,
    pub availability: M1Availability,
    pub available: Option<bool>,
    pub degradation: String,
    pub remedy: String,
    pub probe: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct M1CapabilityStatus {
    pub capability_id: String,
    pub availability: M1Availability,
    pub degraded: bool,
    pub requirements: Vec<M1HostRequirementStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct M1Status {
    pub release_version: String,
    pub capability_count: usize,
    pub availability: M1Availability,
    pub degraded_count: usize,
    pub host_requirements: Vec<M1HostRequirementStatus>,
    pub capabilities: Vec<M1CapabilityStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DeterministicCapabilityResult {
    pub capability_id: String,
    pub source_path: String,
    pub body_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct M1InvocationRequest {
    pub capability_id: String,
    pub policy_context: PolicyContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct M1InvocationResult {
    pub status: M1Status,
    pub capability: DeterministicCapabilityResult,
    pub policy_evaluation: PolicyEvaluation,
    pub policy_receipt: PolicyReceipt,
    pub invocation_receipt: legion_contracts::InvocationReceipt,
}

#[derive(Debug, Error)]
pub enum M1ApplicationError {
    #[error("release binding failed: {0}")]
    ReleaseBinding(#[from] legion_runtime::ReleaseBindingError),
    #[error("catalog operation failed: {0}")]
    Catalog(#[from] legion_catalog::CatalogError),
    #[error("Arcane policy pack failed validation: {0}")]
    Policy(#[from] legion_policy::PolicyEvaluationError),
    #[error("typed invocation receipt could not be constructed: {0}")]
    Contract(#[from] legion_contracts::ContractError),
    #[error("canonical invocation identity could not be encoded: {0}")]
    Canonical(#[from] legion_contracts::canonical::CanonicalError),
}

/// Native M1 API shared by standalone CLI and reusable stdio MCP transports.
/// It has no interpreter, shell, or child-process dependency.
#[derive(Debug)]
pub struct M1Application {
    binding: legion_runtime::VerifiedReleaseBinding,
    catalog: legion_catalog::CompactCatalog,
    evaluator: PolicyEvaluator,
}

impl M1Application {
    pub fn from_inputs(inputs: M1ApplicationInputs) -> Result<Self, M1ApplicationError> {
        let manifest = legion_runtime::load_release_manifest(&inputs.release_manifest_path)?;
        let binding =
            legion_runtime::verify_release_binding(&manifest, &inputs.release_binding_inputs)?;
        let catalog =
            legion_catalog::CompactCatalog::load(&inputs.catalog_root, &inputs.catalog_index_path)?;
        let evaluator = PolicyEvaluator::new(inputs.policy_pack)?;
        Ok(Self {
            binding,
            catalog,
            evaluator,
        })
    }

    pub fn status(&self) -> M1Status {
        let mut host_requirements = BTreeMap::new();
        let capabilities = self
            .catalog
            .entries
            .iter()
            .map(|entry| {
                let requirements = entry
                    .host_requirement_details
                    .iter()
                    .map(host_requirement_status)
                    .collect::<Vec<_>>();
                for requirement in &requirements {
                    host_requirements
                        .entry(requirement.id.clone())
                        .or_insert_with(|| requirement.clone());
                }
                let availability = aggregate_availability(&requirements);
                M1CapabilityStatus {
                    capability_id: entry.canonical_id.clone(),
                    degraded: availability != M1Availability::Available,
                    availability,
                    requirements,
                }
            })
            .collect::<Vec<_>>();
        let degraded_count = capabilities.iter().filter(|entry| entry.degraded).count();
        let host_requirements = host_requirements.into_values().collect::<Vec<_>>();
        M1Status {
            release_version: self.binding.release_version().into(),
            capability_count: self.catalog.entries.len(),
            availability: aggregate_availability(&host_requirements),
            degraded_count,
            host_requirements,
            capabilities,
        }
    }

    /// Exposes the complete identity already verified at composition time for
    /// MCP's initialization gate; callers must not reconstruct it from status.
    pub fn release_binding(&self) -> &legion_runtime::VerifiedReleaseBinding {
        &self.binding
    }

    /// Resolve exactly one selected capability body, evaluate its explicit Arcane
    /// context, and return one deterministic typed invocation receipt.
    pub fn invoke(
        &self,
        request: M1InvocationRequest,
    ) -> Result<M1InvocationResult, M1ApplicationError> {
        let entry = self.catalog.get(&request.capability_id).ok_or_else(|| {
            legion_catalog::CatalogError::InvalidCatalog {
                path: request.capability_id.clone(),
                reason: "unknown compact catalog id".into(),
            }
        })?;
        let body = self.catalog.resolve_body(&request.capability_id)?;
        let capability = DeterministicCapabilityResult {
            capability_id: entry.canonical_id.clone(),
            source_path: entry.source_path.clone(),
            body_sha256: legion_catalog::hex_digest(&body),
        };
        let policy_evaluation = self.evaluator.evaluate(&request.policy_context);
        let policy_receipt = policy_evaluation.receipt.clone();
        let invocation_receipt = self.invocation_receipt(&capability, &policy_evaluation)?;
        Ok(M1InvocationResult {
            status: self.status(),
            capability,
            policy_evaluation,
            policy_receipt,
            invocation_receipt,
        })
    }

    fn invocation_receipt(
        &self,
        capability: &DeterministicCapabilityResult,
        evaluation: &PolicyEvaluation,
    ) -> Result<legion_contracts::InvocationReceipt, M1ApplicationError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Identity<'a> {
            release_version: &'a str,
            capability: &'a DeterministicCapabilityResult,
            policy: &'a legion_policy_model::PolicyDecision,
        }
        let identity = Identity {
            release_version: self.binding.release_version(),
            capability,
            policy: &evaluation.decision,
        };
        let bytes = legion_contracts::canonical_json_bytes(&identity)?;
        let status = if evaluation.decision.outcome == DecisionOutcome::Allow {
            legion_contracts::InvocationStatus::Ok
        } else {
            legion_contracts::InvocationStatus::Failed
        };
        let complete = status == legion_contracts::InvocationStatus::Ok;
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "capabilityBodySha256".into(),
            capability.body_sha256.clone(),
        );
        artifacts.insert("policyReceiptSha256".into(), evaluation.receipt.digest()?);
        artifacts.insert(
            "releaseVersion".into(),
            self.binding.release_version().into(),
        );
        let receipt = legion_contracts::InvocationReceipt {
            schema_version: 1,
            receipt_id: legion_contracts::derived_id(&bytes)?,
            invocation_id: legion_contracts::derived_id(&bytes)?,
            request_id: legion_contracts::derived_id(&bytes)?,
            task_id: legion_contracts::derived_id(&bytes)?,
            plan_id: legion_contracts::derived_id(&bytes)?,
            provider: legion_contracts::ProviderId::new("m1-native-capability")?,
            status,
            complete,
            findings: Vec::new(),
            gaps: if complete {
                Vec::new()
            } else {
                vec![format!(
                    "Arcane policy outcome: {:?}",
                    evaluation.decision.outcome
                )]
            },
            artifacts,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

fn host_requirement_status(
    requirement: &legion_catalog::HostRequirementDetail,
) -> M1HostRequirementStatus {
    let availability = probe_host_requirement(requirement.probe.as_ref());
    M1HostRequirementStatus {
        id: requirement.id.clone(),
        available: match availability {
            M1Availability::Available => Some(true),
            M1Availability::Unavailable => Some(false),
            M1Availability::Unknown => None,
        },
        availability,
        degradation: requirement.degradation.clone(),
        remedy: requirement.remedy.clone(),
        probe: requirement.probe.clone(),
    }
}

fn aggregate_availability(requirements: &[M1HostRequirementStatus]) -> M1Availability {
    if requirements
        .iter()
        .any(|requirement| requirement.availability == M1Availability::Unavailable)
    {
        M1Availability::Unavailable
    } else if requirements
        .iter()
        .any(|requirement| requirement.availability == M1Availability::Unknown)
    {
        M1Availability::Unknown
    } else {
        M1Availability::Available
    }
}

/// Probe host requirements without invoking a child process. PATH probes inspect
/// candidate files directly; env/path probes only read process state.
fn probe_host_requirement(probe: Option<&serde_json::Value>) -> M1Availability {
    let Some(probe) = probe.and_then(serde_json::Value::as_object) else {
        return M1Availability::Unknown;
    };
    match probe.get("kind").and_then(serde_json::Value::as_str) {
        Some("env") => probe
            .get("env")
            .and_then(serde_json::Value::as_str)
            .map(|name| {
                if std::env::var_os(name).is_some_and(|value| !value.is_empty()) {
                    M1Availability::Available
                } else {
                    M1Availability::Unavailable
                }
            })
            .unwrap_or(M1Availability::Unknown),
        Some("command") => probe
            .get("command")
            .and_then(serde_json::Value::as_str)
            .map(|command| {
                if command_on_path(command) {
                    M1Availability::Available
                } else {
                    M1Availability::Unavailable
                }
            })
            .unwrap_or(M1Availability::Unknown),
        Some("command-any") => {
            let Some(commands) = probe.get("commands").and_then(serde_json::Value::as_array) else {
                return M1Availability::Unknown;
            };
            let commands = commands
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>();
            if commands.is_empty() {
                M1Availability::Unknown
            } else if commands.iter().any(|command| command_on_path(command)) {
                M1Availability::Available
            } else {
                M1Availability::Unavailable
            }
        }
        Some("path") => probe
            .get("path")
            .and_then(serde_json::Value::as_str)
            .map(|path| {
                if Path::new(path).exists() {
                    M1Availability::Available
                } else {
                    M1Availability::Unavailable
                }
            })
            .unwrap_or(M1Availability::Unknown),
        _ => M1Availability::Unknown,
    }
}

fn command_on_path(command: &str) -> bool {
    let command_path = Path::new(command);
    if command_path.is_absolute() || command_path.components().count() > 1 {
        return is_executable_file(command_path);
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let suffixes: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    std::env::split_paths(&path).any(|directory| {
        suffixes
            .iter()
            .any(|suffix| is_executable_file(&directory.join(format!("{command}{suffix}"))))
    })
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        return std::fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Explicit dependency set for one in-process native application.
#[derive(Default)]
pub struct NativeApplicationConfig {
    profile: Option<legion_runtime::AgentProfile>,
    registry: Option<Arc<ProviderRegistry>>,
    policy: Option<Arc<dyn EffectPolicy>>,
    inventory_source: Option<Arc<dyn BlueprintInventorySource>>,
    provider_executor: Option<Arc<dyn ProviderExecutor>>,
    catalog_source: Option<Arc<dyn CatalogSource>>,
    report_source: Option<Arc<dyn ReportSource>>,
    run_source: Option<Arc<dyn RunSource>>,
    external_project_tool: Option<Arc<dyn ExternalProjectTool>>,
    provider_specs: Vec<ProviderSpec>,
}

impl NativeApplicationConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compose native audit, policy, catalog, and report dependencies from one
    /// schema-versioned JSON document. RunSource remains optional and is
    /// required only by the separate `Run` operation.
    pub fn from_versioned_json(input: &str) -> Result<Self, NativeApplicationError> {
        let document: VersionedApplicationConfig = serde_json::from_str(input)
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        document.into_runtime_config()
    }

    /// Load a versioned configuration from inline JSON or an explicit file
    /// path. Installed adapters use the file form so packaging never depends
    /// on shell-sized environment payloads or source-tree symlinks.
    pub fn from_versioned_source(source: &str) -> Result<Self, NativeApplicationError> {
        if source.trim_start().starts_with('{') {
            return Self::from_versioned_json(source);
        }
        let input = std::fs::read_to_string(source).map_err(|error| {
            NativeApplicationError::Configuration(format!(
                "could not read native application config {source}: {error}"
            ))
        })?;
        Self::from_versioned_json(&input)
    }

    /// Build the installed CLI's safe default composition. The default run is
    /// a real bounded native invocation backed by one deterministic provider;
    /// no external process, Node runtime, or Python runtime is required.
    pub fn default_for_repository(
        repository_id: impl Into<String>,
    ) -> Result<NativeApplication, NativeApplicationError> {
        let repository_id = repository_id.into();
        let profile = legion_runtime::AgentProfile::new(
            AgentDefinition::new(
                AgentId::new("legion")
                    .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?,
                "Legion",
                "native standalone Legion application",
                BudgetCeiling {
                    max_active_time_ms: 30_000,
                    max_cost_micros: 1,
                    max_output_bytes: 1_024,
                },
                ToolCeiling::default(),
                RoutingCeiling::default(),
            )
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?,
        )
        .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        let provider_id = ProviderId::new("native-default")
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        let default_result = ProviderResult {
            schema_version: 1,
            provider: provider_id.clone(),
            applicable: true,
            required: true,
            status: ProviderStatus::Complete,
            complete: true,
            coverage: Some(Coverage {
                denominator_digest: "native-default".into(),
                expected: 1,
                examined: 1,
                gaps: Vec::new(),
            }),
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::new(),
        };
        let provider_definition = ProviderDefinition {
            schema_version: 1,
            id: provider_id.clone(),
            provider_version: "1".into(),
            implementation_key: "native-default".into(),
            capabilities: Vec::new(),
            depends_on: Vec::new(),
            required: true,
            permissions: Vec::new(),
            source_provenance: BTreeMap::new(),
        };
        let mut implementations = ImplementationRegistry::new();
        let configured_result = default_result.clone();
        implementations
            .register("native-default", "1", move |definition| {
                Ok(Arc::new(ConfiguredProvider {
                    definition: definition.clone(),
                    result: configured_result.clone(),
                }) as Arc<dyn Provider>)
            })
            .map_err(|error| NativeApplicationError::Provider(error.to_string()))?;
        let registry = ProviderRegistry::load(
            ProviderRegistryDocument {
                schema_version: 1,
                providers: vec![provider_definition],
            },
            &implementations,
        )
        .map_err(|error| NativeApplicationError::Provider(error.to_string()))?;
        let inventory =
            InventoryEnvelope::new(repository_id.clone(), "native-default", Vec::new())?;
        let catalog = Catalog::new(Vec::new())?;
        let report = ReportV1 {
            schema_version: 1,
            report_id: ReportId::new("native-default")
                .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?,
            status: ReportStatus::Incomplete,
            findings: Vec::new(),
            gaps: Vec::new(),
            claims: BTreeMap::new(),
            targets: Vec::new(),
            extensions: BTreeMap::new(),
        };
        NativeApplicationConfig::new()
            .with_profile(profile)
            .with_registry(Arc::new(registry))
            .with_policy(Arc::new(CanonicalEffectPolicy {
                pack: PolicyPack {
                    schema_version: 1,
                    id: "native-default".into(),
                    version: 1,
                    rules: Vec::new(),
                    extensions: BTreeMap::new(),
                },
            }))
            .with_inventory_source(Arc::new(StaticInventorySource {
                snapshots: vec![inventory],
            }))
            .with_provider_executor(Arc::new(StaticProviderExecutor {
                results: [(provider_id.to_string(), default_result.clone())]
                    .into_iter()
                    .collect(),
            }))
            .with_catalog_source(Arc::new(StaticCatalogSource { catalog }))
            .with_report_source(Arc::new(StaticReportSource { report }))
            .with_run_source(Arc::new(DefaultRunSource {
                repository_id,
                agent_id: AgentId::new("legion")
                    .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?,
                provider_id,
                budget: BudgetCeiling {
                    max_active_time_ms: 30_000,
                    max_cost_micros: 1,
                    max_output_bytes: 1_024,
                },
            }))
            .build()
    }

    /// Compose one standalone Audit from an inventory source, an exact selected
    /// provider plan, and typed host-injected results. Inventory may come from
    /// Blueprint or Audit's read-only filesystem fallback.
    pub fn for_audit_artifacts(
        repository_id: impl Into<String>,
        inventory_source: Arc<dyn BlueprintInventorySource>,
        provider_specs: Vec<ProviderSpec>,
        provider_results: Vec<ProviderResult>,
    ) -> Result<NativeApplication, NativeApplicationError> {
        let repository_id = repository_id.into();
        let inventory = inventory_source.inventory(&repository_id)?;
        if provider_specs.is_empty() {
            return Err(NativeApplicationError::Configuration(
                "standalone Audit requires selected provider specifications".into(),
            ));
        }
        let frozen_plan = AuditPlan::compile(&inventory, &provider_specs)
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        let mut results = BTreeMap::new();
        for result in provider_results {
            result
                .validate()
                .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
            if result.complete {
                let provider = frozen_plan
                    .providers
                    .iter()
                    .find(|provider| provider.id == result.provider.to_string())
                    .ok_or_else(|| {
                        NativeApplicationError::Configuration(format!(
                            "complete provider result {} is not in frozen plan",
                            result.provider
                        ))
                    })?;
                let expected_digest = provider
                    .configuration
                    .get("denominatorDigest")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        NativeApplicationError::Configuration(format!(
                            "provider {} is missing frozen denominator",
                            provider.id
                        ))
                    })?;
                let expected_count = provider
                    .configuration
                    .get("denominatorCount")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        NativeApplicationError::Configuration(format!(
                            "provider {} is missing frozen denominator count",
                            provider.id
                        ))
                    })?;
                let coverage = result.coverage.as_ref().ok_or_else(|| {
                    NativeApplicationError::Configuration(format!(
                        "complete provider result {} is missing coverage",
                        result.provider
                    ))
                })?;
                if coverage.denominator_digest != expected_digest
                    || coverage.expected != expected_count
                    || coverage.examined != coverage.expected
                {
                    return Err(NativeApplicationError::Configuration(format!(
                        "complete provider result {} is not bound to frozen selector denominator",
                        result.provider
                    )));
                }
            }
            let provider_id = result.provider.to_string();
            if results.insert(provider_id.clone(), result).is_some() {
                return Err(NativeApplicationError::Configuration(format!(
                    "duplicate provider result: {provider_id}"
                )));
            }
        }
        let planned = provider_specs
            .iter()
            .map(|specification| specification.id.to_string())
            .collect::<BTreeSet<_>>();
        let supplied = results.keys().cloned().collect::<BTreeSet<_>>();
        if planned != supplied {
            return Err(NativeApplicationError::Configuration(
                "selected provider specifications and supplied results do not reconcile".into(),
            ));
        }
        for specification in &provider_specs {
            specification
                .validate()
                .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        }

        let profile_definition = AgentDefinition::new(
            AgentId::new("legion")
                .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?,
            "Legion",
            "native standalone Audit",
            BudgetCeiling {
                max_active_time_ms: 300_000,
                max_cost_micros: 1,
                max_output_bytes: 64 * 1024 * 1024,
            },
            ToolCeiling::default(),
            RoutingCeiling::default(),
        )
        .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        let profile = legion_runtime::AgentProfile::new(profile_definition)
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        let definitions = provider_specs
            .iter()
            .map(|specification| ProviderDefinition {
                schema_version: 1,
                id: specification.id.clone(),
                provider_version: specification.provider_version.clone(),
                implementation_key: "host-injected-audit-result".into(),
                capabilities: specification.control_ids.clone(),
                depends_on: specification.depends_on.clone(),
                required: true,
                permissions: Vec::new(),
                source_provenance: BTreeMap::from([(
                    "kind".into(),
                    "host-injected-audit-result".into(),
                )]),
            })
            .collect::<Vec<_>>();
        let mut implementations = ImplementationRegistry::new();
        let configured_results = results.clone();
        implementations
            .register("host-injected-audit-result", "*", move |definition| {
                let result = configured_results
                    .get(&definition.id.to_string())
                    .cloned()
                    .ok_or_else(|| {
                        ProviderError::new(
                            ProviderErrorKind::MissingTool,
                            format!("no host-injected result for provider {}", definition.id),
                        )
                    })?;
                Ok(Arc::new(ConfiguredProvider {
                    definition: definition.clone(),
                    result,
                }) as Arc<dyn Provider>)
            })
            .map_err(|error| NativeApplicationError::Provider(error.to_string()))?;
        let registry = ProviderRegistry::load(
            ProviderRegistryDocument {
                schema_version: 1,
                providers: definitions,
            },
            &implementations,
        )
        .map_err(|error| NativeApplicationError::Provider(error.to_string()))?;
        let catalog = Catalog::new(Vec::new())?;
        let report = ReportV1 {
            schema_version: 1,
            report_id: ReportId::new("native-audit")
                .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?,
            status: ReportStatus::Incomplete,
            findings: Vec::new(),
            gaps: vec!["not-executed".into()],
            claims: BTreeMap::new(),
            targets: vec![repository_id],
            extensions: BTreeMap::new(),
        };
        NativeApplicationConfig::new()
            .with_profile(profile)
            .with_registry(Arc::new(registry))
            .with_policy(Arc::new(CanonicalEffectPolicy {
                pack: PolicyPack {
                    schema_version: 1,
                    id: "native-audit".into(),
                    version: 1,
                    rules: Vec::new(),
                    extensions: BTreeMap::new(),
                },
            }))
            .with_inventory_source(inventory_source)
            .with_provider_executor(Arc::new(StaticProviderExecutor { results }))
            .with_catalog_source(Arc::new(StaticCatalogSource { catalog }))
            .with_report_source(Arc::new(StaticReportSource { report }))
            .with_provider_specs(provider_specs)
            .build()
    }

    pub fn with_profile(mut self, profile: legion_runtime::AgentProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn with_registry(mut self, registry: Arc<ProviderRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn with_policy(mut self, policy: Arc<dyn EffectPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_inventory_source(mut self, source: Arc<dyn BlueprintInventorySource>) -> Self {
        self.inventory_source = Some(source);
        self
    }

    pub fn with_provider_executor(mut self, executor: Arc<dyn ProviderExecutor>) -> Self {
        self.provider_executor = Some(executor);
        self
    }

    pub fn with_catalog_source(mut self, source: Arc<dyn CatalogSource>) -> Self {
        self.catalog_source = Some(source);
        self
    }

    pub fn with_report_source(mut self, source: Arc<dyn ReportSource>) -> Self {
        self.report_source = Some(source);
        self
    }

    pub fn with_run_source(mut self, source: Arc<dyn RunSource>) -> Self {
        self.run_source = Some(source);
        self
    }

    pub fn with_external_project_tool(mut self, tool: Arc<dyn ExternalProjectTool>) -> Self {
        self.external_project_tool = Some(tool);
        self
    }

    pub fn with_provider_specs(mut self, providers: Vec<ProviderSpec>) -> Self {
        self.provider_specs = providers;
        self
    }

    pub fn build(self) -> Result<NativeApplication, NativeApplicationError> {
        let profile = self
            .profile
            .ok_or(NativeApplicationError::MissingComponent {
                component: "AgentProfile",
            })?;
        let registry = self
            .registry
            .ok_or(NativeApplicationError::MissingComponent {
                component: "ProviderRegistry",
            })?;
        let policy = self
            .policy
            .ok_or(NativeApplicationError::MissingComponent {
                component: "EffectPolicy",
            })?;
        let inventory_source =
            self.inventory_source
                .ok_or(NativeApplicationError::MissingComponent {
                    component: "BlueprintInventorySource",
                })?;
        let provider_executor =
            self.provider_executor
                .ok_or(NativeApplicationError::MissingComponent {
                    component: "ProviderExecutor",
                })?;
        let catalog_source =
            self.catalog_source
                .ok_or(NativeApplicationError::MissingComponent {
                    component: "CatalogSource",
                })?;
        let report_source = self
            .report_source
            .ok_or(NativeApplicationError::MissingComponent {
                component: "ReportSource",
            })?;
        Ok(NativeApplication {
            engine: LegionEngine::new(profile, registry).with_policy(policy),
            inventory_source,
            provider_executor,
            catalog_source,
            report_source,
            run_source: self.run_source,
            external_project_tool: self.external_project_tool,
            provider_specs: self.provider_specs,
        })
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionedApplicationConfig {
    schema_version: u32,
    profile: AgentDefinition,
    policy: PolicyPack,
    provider_specs: Vec<ProviderSpec>,
    providers: Vec<ConfiguredProviderDocument>,
    #[serde(default)]
    inventory: Vec<InventoryEnvelope>,
    #[serde(default)]
    blueprint_packet_path: Option<String>,
    #[serde(default)]
    blueprint_expected_generation: Option<String>,
    catalog: Catalog,
    report: ReportV1,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfiguredProviderDocument {
    definition: ProviderDefinition,
    result: ProviderResult,
}

impl VersionedApplicationConfig {
    fn into_runtime_config(self) -> Result<NativeApplicationConfig, NativeApplicationError> {
        if self.schema_version != 1 {
            return Err(NativeApplicationError::Configuration(format!(
                "unsupported application schema version {}",
                self.schema_version
            )));
        }
        self.policy
            .validate()
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        self.catalog
            .validate()
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        self.report
            .validate()
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        let has_static_inventory = !self.inventory.is_empty();
        let has_blueprint_packet = self.blueprint_packet_path.is_some();
        if has_static_inventory == has_blueprint_packet {
            return Err(NativeApplicationError::Configuration(
                "configure exactly one inventory source: inventory or blueprintPacketPath".into(),
            ));
        }
        if !has_blueprint_packet && self.blueprint_expected_generation.is_some() {
            return Err(NativeApplicationError::Configuration(
                "blueprintExpectedGeneration requires blueprintPacketPath".into(),
            ));
        }
        for inventory in &self.inventory {
            inventory
                .validate()
                .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        }
        for provider in &self.provider_specs {
            provider
                .validate()
                .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        }

        let mut implementations = ImplementationRegistry::new();
        let mut definitions = Vec::with_capacity(self.providers.len());
        let mut registered_keys = BTreeSet::new();
        let configured_results: BTreeMap<_, _> = self
            .providers
            .iter()
            .map(|provider| (provider.definition.id.clone(), provider.result.clone()))
            .collect();
        for configured in &self.providers {
            if configured.definition.id != configured.result.provider {
                return Err(NativeApplicationError::Configuration(format!(
                    "provider result identity does not match {}",
                    configured.definition.id
                )));
            }
            let key = configured.definition.implementation_key.clone();
            let version = configured.definition.provider_version.clone();
            if registered_keys.insert(key.clone()) {
                let configured_results = configured_results.clone();
                implementations
                    .register(key, version, move |definition| {
                        let result =
                            configured_results
                                .get(&definition.id)
                                .cloned()
                                .ok_or_else(|| {
                                    ProviderError::new(
                                        ProviderErrorKind::MissingTool,
                                        format!(
                                            "no configured result for provider {}",
                                            definition.id
                                        ),
                                    )
                                })?;
                        Ok(Arc::new(ConfiguredProvider {
                            definition: definition.clone(),
                            result,
                        }) as Arc<dyn Provider>)
                    })
                    .map_err(|error| NativeApplicationError::Provider(error.to_string()))?;
            }
            definitions.push(configured.definition.clone());
        }
        let registry = ProviderRegistry::load(
            ProviderRegistryDocument {
                schema_version: 1,
                providers: definitions,
            },
            &implementations,
        )
        .map_err(|error| NativeApplicationError::Provider(error.to_string()))?;
        let profile_id = self.profile.id.clone();
        let profile_budget = self.profile.budget.clone();
        let configured_repository = self
            .inventory
            .first()
            .map(|inventory| inventory.repository_id.clone())
            .unwrap_or_else(|| ".".into());
        let configured_provider = self
            .providers
            .first()
            .map(|provider| provider.definition.id.clone());
        let profile = legion_runtime::AgentProfile::new(self.profile)
            .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
        let inventory_source: Arc<dyn BlueprintInventorySource> = if let Some(packet_path) =
            self.blueprint_packet_path
        {
            Arc::new(
                FileBlueprintInventorySource::new(packet_path, self.blueprint_expected_generation)
                    .map_err(NativeApplicationError::Audit)?,
            )
        } else {
            Arc::new(StaticInventorySource {
                snapshots: self.inventory,
            })
        };
        let results = self
            .providers
            .iter()
            .map(|provider| (provider.definition.id.to_string(), provider.result.clone()))
            .collect();
        let executor = StaticProviderExecutor { results };
        let mut config = NativeApplicationConfig::new()
            .with_profile(profile)
            .with_registry(Arc::new(registry))
            .with_policy(Arc::new(CanonicalEffectPolicy { pack: self.policy }))
            .with_inventory_source(inventory_source)
            .with_provider_executor(Arc::new(executor))
            .with_catalog_source(Arc::new(StaticCatalogSource {
                catalog: self.catalog,
            }))
            .with_report_source(Arc::new(StaticReportSource {
                report: self.report,
            }))
            .with_provider_specs(self.provider_specs);
        if let Some(provider_id) = configured_provider {
            config = config.with_run_source(Arc::new(DefaultRunSource {
                repository_id: configured_repository,
                agent_id: profile_id,
                provider_id,
                budget: profile_budget,
            }));
        }
        Ok(config)
    }
}

fn validate_verify_artifacts(
    facts: &serde_json::Value,
    plan: &serde_json::Value,
    providers: &[ProviderSpec],
) -> Result<(), NativeApplicationError> {
    if facts.get("kind").and_then(serde_json::Value::as_str) != Some("audit-facts") {
        return Err(NativeApplicationError::Configuration(
            "verify facts artifact kind must be audit-facts".into(),
        ));
    }
    if !facts.get("checks").is_some_and(serde_json::Value::is_array)
        || !facts
            .get("provider_reconciliation")
            .and_then(serde_json::Value::as_object)
            .and_then(|reconciliation| reconciliation.get("providerResults"))
            .is_some_and(serde_json::Value::is_array)
    {
        return Err(NativeApplicationError::Configuration(
            "verify facts must contain checks and provider reconciliation results".into(),
        ));
    }
    if plan
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || plan.get("kind").and_then(serde_json::Value::as_str) != Some("audit-provider-plan")
    {
        return Err(NativeApplicationError::Configuration(
            "verify plan artifact must be schemaVersion 1 audit-provider-plan".into(),
        ));
    }
    let plan_providers = plan
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            NativeApplicationError::Configuration(
                "verify plan artifact providers must be an array".into(),
            )
        })?;
    let mut supplied_provider_ids = plan_providers
        .iter()
        .map(|provider| {
            provider.as_str().map(str::to_owned).ok_or_else(|| {
                NativeApplicationError::Configuration(
                    "verify plan provider entries must be strings".into(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    supplied_provider_ids.sort();
    supplied_provider_ids.dedup();
    let mut configured_provider_ids = providers
        .iter()
        .map(|provider| provider.id.to_string())
        .collect::<Vec<_>>();
    configured_provider_ids.sort();
    configured_provider_ids.dedup();
    if supplied_provider_ids != configured_provider_ids {
        return Err(NativeApplicationError::Configuration(
            "verify plan providers do not match configured native providers".into(),
        ));
    }
    let plan_seal = plan
        .get("seal")
        .and_then(serde_json::Value::as_object)
        .and_then(|seal| seal.get("digest"))
        .and_then(serde_json::Value::as_str)
        .filter(|digest| digest.starts_with("sha256:") && digest.len() == 71)
        .ok_or_else(|| {
            NativeApplicationError::Configuration(
                "verify plan seal must contain a canonical sha256 digest".into(),
            )
        })?;
    let plan_binding = plan
        .get("binding")
        .and_then(serde_json::Value::as_object)
        .and_then(|binding| binding.get("repositoryRevision"))
        .and_then(serde_json::Value::as_str)
        .filter(|revision| !revision.trim().is_empty())
        .ok_or_else(|| {
            NativeApplicationError::Configuration(
                "verify plan binding must contain repositoryRevision".into(),
            )
        })?;
    let facts_plan = facts
        .get("plan")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            NativeApplicationError::Configuration(
                "verify facts must embed the supplied plan binding".into(),
            )
        })?;
    let facts_seal = facts_plan
        .get("seal")
        .and_then(serde_json::Value::as_object)
        .and_then(|seal| seal.get("digest"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            NativeApplicationError::Configuration(
                "verify facts embedded plan must contain seal digest".into(),
            )
        })?;
    let facts_revision = facts_plan
        .get("binding")
        .and_then(serde_json::Value::as_object)
        .and_then(|binding| binding.get("repositoryRevision"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            NativeApplicationError::Configuration(
                "verify facts embedded plan must contain repositoryRevision".into(),
            )
        })?;
    if facts_seal != plan_seal || facts_revision != plan_binding {
        return Err(NativeApplicationError::Configuration(
            "verify facts and plan bindings do not match".into(),
        ));
    }
    legion_contracts::canonical_digest_hex(facts)
        .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
    legion_contracts::canonical_digest_hex(plan)
        .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
    Ok(())
}

#[derive(Clone)]
struct StaticInventorySource {
    snapshots: Vec<InventoryEnvelope>,
}

impl BlueprintInventorySource for StaticInventorySource {
    fn inventory(&self, repository_id: &str) -> Result<InventoryEnvelope, AuditError> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.repository_id == repository_id)
            .cloned()
            .ok_or_else(|| {
                AuditError::SourceDrift(format!(
                    "no configured inventory for repository {repository_id}"
                ))
            })
    }
}

#[derive(Clone)]
struct StaticProviderExecutor {
    results: BTreeMap<String, ProviderResult>,
}

impl ProviderExecutor for StaticProviderExecutor {
    fn execute(
        &self,
        provider: &AuditProvider,
        _: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        self.results.get(&provider.id).cloned().ok_or_else(|| {
            AuditError::Provider(format!("no configured result for provider {}", provider.id))
        })
    }
}

#[derive(Clone)]
struct StaticCatalogSource {
    catalog: Catalog,
}
impl CatalogSource for StaticCatalogSource {
    fn catalog(&self) -> Result<Catalog, CatalogError> {
        Ok(self.catalog.clone())
    }
}

#[derive(Clone)]
struct StaticReportSource {
    report: ReportV1,
}
impl ReportSource for StaticReportSource {
    fn report(&self) -> Result<ReportV1, ReportError> {
        Ok(self.report.clone())
    }
}

#[derive(Clone)]
struct DefaultRunSource {
    repository_id: String,
    agent_id: AgentId,
    provider_id: ProviderId,
    budget: BudgetCeiling,
}

impl RunSource for DefaultRunSource {
    fn invocation(&self) -> Result<Invocation, RuntimeError> {
        self.invocation_for(&serde_json::json!({}))
    }

    fn invocation_for(&self, request: &serde_json::Value) -> Result<Invocation, RuntimeError> {
        let agent_id = self.agent_id.clone();
        let request_id = RequestId::new("native-run")
            .map_err(|error| RuntimeError::InvalidTask(error.to_string()))?;
        let task_id = "native-run"
            .parse::<legion_contracts::TaskId>()
            .map_err(|error| RuntimeError::InvalidTask(error.to_string()))?;
        let invocation_id = InvocationId::new("native-run")
            .map_err(|error| RuntimeError::InvalidTask(error.to_string()))?;
        let grant = InvocationGrant::new(agent_id.clone(), task_id.clone(), self.budget.clone())
            .map_err(|error| RuntimeError::GrantExceedsCeiling(error.to_string()))?;
        let task = TaskSpec {
            schema_version: 1,
            task_id: task_id.clone(),
            request_id: request_id.clone(),
            title: "native Legion run".into(),
            description: Some("bounded native CLI run request".into()),
            own_scope: vec![self.repository_id.clone()],
            read_scope: vec![self.repository_id.clone()],
            depends_on: Vec::new(),
            implements_decisions: Vec::new(),
            latitude: Latitude::Bounded,
            declared_checks: vec!["native-provider".into()],
            evidence_requirements: vec!["provider-result".into()],
            status: TaskStatus::Complete,
            assigned_authority: agent_id,
        };
        let cli_fields: Vec<_> = std::env::args()
            .skip_while(|argument| argument != "run")
            .skip(1)
            .collect();
        let envelope = RequestEnvelope {
            schema_version: 1,
            request_id,
            task_id: Some(task_id),
            payload: serde_json::json!({
                "command": "run",
                "repository": &self.repository_id,
                "provider": &self.provider_id,
                "request": request,
                "cliFields": cli_fields,
            }),
            extensions: BTreeMap::new(),
        };
        let context = ContextRequest::new(
            envelope,
            self.repository_id.clone(),
            0,
            Instant::now() + Duration::from_millis(self.budget.max_active_time_ms),
            tokio_util::sync::CancellationToken::new(),
            Arc::new(DefaultSourceInterface),
            Arc::new(DefaultEffectInterface),
        )?;
        Ok(Invocation {
            invocation_id,
            task,
            grant,
            context,
            routes: vec![RouteCandidate {
                id: "native-default".into(),
                providers: vec![self.provider_id.clone()],
                required_capabilities: Vec::new(),
                worst_case_cost_micros: 1,
            }],
        })
    }
}

struct DefaultSourceInterface;

impl SourceInterface for DefaultSourceInterface {
    fn read(
        &self,
        _source: &str,
        _query: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        Err(ProviderError::new(
            ProviderErrorKind::MissingTool,
            "default run has no external source access",
        ))
    }
}

struct DefaultEffectInterface;

impl EffectInterface for DefaultEffectInterface {
    fn request(&self, _effect: &EffectRequest) -> Result<serde_json::Value, ProviderError> {
        Err(ProviderError::new(
            ProviderErrorKind::PolicyDenied,
            "default run has no effect authority",
        ))
    }
}

struct CanonicalEffectPolicy {
    pack: PolicyPack,
}
impl EffectPolicy for CanonicalEffectPolicy {
    fn authorize(&self, request: &EffectRequest) -> Result<(), RuntimeError> {
        let matching: Vec<_> = self
            .pack
            .rules
            .iter()
            .filter(|rule| {
                rule.effect_class == request.effect_class
                    && rule
                        .targets
                        .iter()
                        .any(|target| target == "*" || target == &request.target)
            })
            .collect();
        if matching.iter().any(|rule| !rule.allowed) {
            return Err(RuntimeError::Policy(
                "canonical policy denied effect".into(),
            ));
        }
        let Some(rule) = matching.first() else {
            return Err(RuntimeError::Policy(
                "canonical policy has no matching rule".into(),
            ));
        };
        if !matches!(
            rule.approval,
            legion_contracts::policy::ApprovalRequirement::None
        ) || request.approval_required
        {
            return Err(RuntimeError::Policy(
                "canonical policy requires an approval boundary".into(),
            ));
        }
        if rule.required_trust.is_some() || !rule.required_enforcement.is_empty() {
            return Err(RuntimeError::Policy(
                "canonical policy trust/enforcement inputs are not present".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ConfiguredProvider {
    definition: ProviderDefinition,
    result: ProviderResult,
}

#[async_trait]
impl Provider for ConfiguredProvider {
    fn definition(&self) -> &ProviderDefinition {
        &self.definition
    }
    async fn execute(&self, _: &ProviderContext) -> Result<ProviderResult, ProviderError> {
        Ok(self.result.clone())
    }
}

/// In-process composition root. Policy and provider state live in LegionEngine only.
pub struct NativeApplication {
    engine: LegionEngine,
    inventory_source: Arc<dyn BlueprintInventorySource>,
    provider_executor: Arc<dyn ProviderExecutor>,
    catalog_source: Arc<dyn CatalogSource>,
    report_source: Arc<dyn ReportSource>,
    run_source: Option<Arc<dyn RunSource>>,
    external_project_tool: Option<Arc<dyn ExternalProjectTool>>,
    provider_specs: Vec<ProviderSpec>,
}

impl NativeApplication {
    /// Authorize one typed effect through the injected policy boundary.
    pub fn authorize_hook(&self, request: &EffectRequest) -> Result<(), NativeApplicationError> {
        self.engine
            .authorize_effect(request)
            .map_err(NativeApplicationError::from)
    }

    fn verify_operation(
        &self,
        repository_id: String,
        providers: Vec<ProviderSpec>,
        signing_key: Option<Vec<u8>>,
    ) -> Result<NativeOperationResult, NativeApplicationError> {
        let inventory = self.inventory_source.inventory(&repository_id)?;
        let plan = AuditPlan::compile(&inventory, &providers)?.freeze(signing_key.as_deref())?;
        verify_binding(&plan, &inventory, signing_key.as_deref())?;
        Ok(NativeOperationResult::Verification {
            repository_id,
            plan_digest: plan.digest().into(),
            inventory_digest: inventory.digest,
        })
    }

    fn bind_external_project_tool(&self, mut invocation: Invocation) -> Invocation {
        if let Some(tool) = self.external_project_tool.clone() {
            invocation.context = invocation.context.with_external_project_tool(tool);
        }
        invocation
    }

    pub async fn invoke(
        &self,
        operation: NativeOperation,
    ) -> Result<NativeOperationResult, NativeApplicationError> {
        match operation {
            NativeOperation::Invoke(invocation) => Ok(NativeOperationResult::Invocation(
                self.engine
                    .execute(self.bind_external_project_tool(invocation))
                    .await?,
            )),
            NativeOperation::Run => {
                let invocation = self
                    .run_source
                    .as_ref()
                    .ok_or(NativeApplicationError::MissingComponent {
                        component: "RunSource",
                    })?
                    .invocation()?;
                Ok(NativeOperationResult::Invocation(
                    self.engine
                        .execute(self.bind_external_project_tool(invocation))
                        .await?,
                ))
            }
            NativeOperation::RunRequest { request } => {
                let invocation = self
                    .run_source
                    .as_ref()
                    .ok_or(NativeApplicationError::MissingComponent {
                        component: "RunSource",
                    })?
                    .invocation_for(&request)?;
                Ok(NativeOperationResult::Invocation(
                    self.engine
                        .execute(self.bind_external_project_tool(invocation))
                        .await?,
                ))
            }
            NativeOperation::Doctor { repository_id } => {
                let inventory = self.inventory_source.inventory(&repository_id)?;
                let catalog = self.catalog_source.catalog()?;
                catalog.validate()?;
                Ok(NativeOperationResult::Doctor {
                    repository_id,
                    inventory_digest: inventory.digest,
                    catalog_entries: catalog.entries.len(),
                    provider_count: self.engine.registry().providers().count(),
                })
            }
            NativeOperation::Plan {
                repository_id,
                providers,
                signing_key,
            } => {
                let inventory = self.inventory_source.inventory(&repository_id)?;
                let plan =
                    AuditPlan::compile(&inventory, &providers)?.freeze(signing_key.as_deref())?;
                Ok(NativeOperationResult::Plan {
                    repository_id,
                    plan_digest: plan.digest().into(),
                    plan_signature: plan.signature().map(ToOwned::to_owned),
                    providers: plan
                        .providers()
                        .iter()
                        .map(|provider| provider.id.clone())
                        .collect(),
                })
            }
            NativeOperation::Audit {
                repository_id,
                providers,
                signing_key,
            } => {
                let plan_inventory: InventoryEnvelope =
                    self.inventory_source.inventory(&repository_id)?;
                let plan = AuditPlan::compile(&plan_inventory, &providers)?
                    .freeze(signing_key.as_deref())?;
                let execution_inventory = self.inventory_source.inventory(&repository_id)?;
                verify_binding(&plan, &execution_inventory, signing_key.as_deref())?;
                let report = execute(&plan, &execution_inventory, self.provider_executor.as_ref())?;
                verify_execution(&report)?;
                Ok(NativeOperationResult::Audit(report))
            }
            NativeOperation::Verify {
                repository_id,
                providers,
                signing_key,
            } => self.verify_operation(repository_id, providers, signing_key),
            NativeOperation::VerifyRequest {
                repository_id,
                providers,
                signing_key,
                facts,
                plan,
            } => {
                validate_verify_artifacts(&facts, &plan, &providers)?;
                self.verify_operation(repository_id, providers, signing_key)
            }
            NativeOperation::Catalog => Ok(NativeOperationResult::Catalog(
                self.catalog_source.catalog()?,
            )),
            NativeOperation::Report(format) => {
                let report = self.report_source.report()?;
                let rendered = match format {
                    ReportFormat::Json => legion_report::render_json(&report)?,
                    ReportFormat::Sarif => legion_report::render_sarif(&report)?,
                    ReportFormat::Markdown => legion_report::render_markdown(&report)?,
                    ReportFormat::Html => legion_report::render_html(&report)?,
                };
                Ok(NativeOperationResult::Report(rendered))
            }
        }
    }

    /// Execute one operation under the caller-owned process cancellation.
    /// The token is not replaced or forked, preserving one request lifetime
    /// from CLI signal handling through runtime scheduling.
    pub async fn invoke_with_cancellation(
        &self,
        operation: NativeOperation,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<NativeOperationResult, NativeApplicationError> {
        let operation = match operation {
            NativeOperation::Invoke(mut invocation) => {
                invocation.context.cancellation = cancellation.clone();
                NativeOperation::Invoke(invocation)
            }
            NativeOperation::Run => {
                let mut invocation = self
                    .run_source
                    .as_ref()
                    .ok_or(NativeApplicationError::MissingComponent {
                        component: "RunSource",
                    })?
                    .invocation()?;
                invocation.context.cancellation = cancellation.clone();
                NativeOperation::Invoke(invocation)
            }
            NativeOperation::RunRequest { request } => {
                let mut invocation = self
                    .run_source
                    .as_ref()
                    .ok_or(NativeApplicationError::MissingComponent {
                        component: "RunSource",
                    })?
                    .invocation_for(&request)?;
                invocation.context.cancellation = cancellation.clone();
                NativeOperation::Invoke(invocation)
            }
            operation => operation,
        };
        if matches!(&operation, NativeOperation::Invoke(_)) {
            // Runtime owns provider cancellation and bounded cleanup. Keeping this future
            // awaited lets its scheduler retain terminal provider evidence.
            self.invoke(operation).await
        } else if cancellation.is_cancelled() {
            Err(NativeApplicationError::Runtime(RuntimeError::Cancelled))
        } else {
            tokio::select! {
                _ = cancellation.cancelled() => Err(NativeApplicationError::Runtime(RuntimeError::Cancelled)),
                result = self.invoke(operation) => result,
            }
        }
    }

    pub fn profile(&self) -> &legion_runtime::AgentProfile {
        self.engine.profile()
    }
    pub fn registry(&self) -> &ProviderRegistry {
        self.engine.registry()
    }
    pub fn provider_specs(&self) -> Vec<ProviderSpec> {
        self.provider_specs.clone()
    }
}

#[cfg(test)]
mod m1_tests {
    use super::*;
    use legion_policy_model::{
        ApprovalState, CanonicalPath, CapabilityCeiling, CapabilityGrant, ContractVersion,
        EffectClass as ArcaneEffectClass, EnforcementLevel, HostEnforcement, LeasePolicy,
        LeaseState, PathOperation, PathScope, PolicyRule as ArcanePolicyRule, ReceiptRequirements,
        ReceiptState, RuleDecision, RulePredicate, SymlinkState, TrustLevel, TrustMinima,
        UnclassifiedEffect, POLICY_SCHEMA_VERSION,
    };
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "legion-m1-application-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(root.join("registry")).expect("registry directory");
        root
    }

    fn values<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeSet<T> {
        values.into_iter().collect()
    }

    fn policy_pack() -> ArcanePolicyPack {
        ArcanePolicyPack {
            schema_version: POLICY_SCHEMA_VERSION,
            kind: "arcane-policy-pack".into(),
            policy_id: "m1-test-policy".into(),
            version: 1,
            contract_versions: vec![ContractVersion {
                name: "m1".into(),
                major: 1,
                minor: 0,
            }],
            unclassified_effect: UnclassifiedEffect::Deny,
            effect_rules: vec![ArcanePolicyRule {
                schema_version: POLICY_SCHEMA_VERSION,
                id: "allow-m1-capability".into(),
                effect_class: ArcaneEffectClass::FileWrite,
                rule: RuleDecision::Allow,
                predicate: RulePredicate::default(),
                approval_required: false,
                trust_minimum: TrustLevel::CapabilitySignature,
                required_enforcement: EnforcementLevel::Strong,
                receipt_required: false,
                exception_capable: false,
                note: Some("M1 deterministic capability fixture".into()),
            }],
            capability: CapabilityCeiling {
                effects: values([ArcaneEffectClass::FileWrite]),
                operations: values(["write".into()]),
                targets: BTreeSet::new(),
                max_ttl_seconds: 60,
                max_uses: 1,
                delegable: false,
                trust: TrustLevel::CapabilitySignature,
            },
            leases: LeasePolicy {
                max_ttl_seconds: 60,
                max_uses: 1,
                delegable: false,
            },
            trust_minima: TrustMinima {
                mutation: TrustLevel::CapabilitySignature,
                read_only: TrustLevel::Unauthenticated,
                claim_release: TrustLevel::CapabilitySignature,
                legacy_import: TrustLevel::CapabilitySignature,
            },
            host_enforcement: HostEnforcement {
                required_for_mutation: EnforcementLevel::Strong,
                required_for_read_only: EnforcementLevel::ReadOnly,
            },
            receipt_requirements: ReceiptRequirements {
                effect_receipt: false,
                bind_policy_digest: true,
                bind_capability_id: true,
            },
        }
    }

    fn request() -> M1InvocationRequest {
        let repository = "repo".to_string();
        let worktree = "main".to_string();
        M1InvocationRequest {
            capability_id: "demo".into(),
            policy_context: PolicyContext {
                schema_version: POLICY_SCHEMA_VERSION,
                contract: ContractVersion {
                    name: "m1".into(),
                    major: 1,
                    minor: 0,
                },
                effect_class: ArcaneEffectClass::FileWrite,
                operation: PathOperation::Write,
                path: Some(
                    CanonicalPath::from_relative(
                        "m1-test-root",
                        PathScope {
                            repository: repository.clone(),
                            worktree: worktree.clone(),
                        },
                        "skills/demo/SKILL.md",
                        SymlinkState::NotFollowed,
                    )
                    .expect("canonical path"),
                ),
                repository,
                worktree,
                trust: TrustLevel::CapabilitySignature,
                enforcement: EnforcementLevel::Strong,
                approval: ApprovalState::None,
                lease: LeaseState::Active,
                receipt: ReceiptState::NotRequired,
                grant: Some(CapabilityGrant {
                    schema_version: POLICY_SCHEMA_VERSION,
                    id: "m1-grant".into(),
                    effects: values([ArcaneEffectClass::FileWrite]),
                    operations: values(["write".into()]),
                    targets: BTreeSet::new(),
                    ttl_seconds: 60,
                    max_uses: 1,
                    delegable: false,
                    trust: TrustLevel::CapabilitySignature,
                    lease_id: Some("m1-lease".into()),
                }),
                tags: BTreeSet::new(),
            },
        }
    }

    fn inputs(root: &Path, write_body: bool) -> M1ApplicationInputs {
        fs::write(
            root.join("registry/index.json"),
            r#"{"schemaVersion":2,"bundles":[{"id":"demo","source":"skills/demo/SKILL.md","description":"M1 fixture"}]}"#,
        )
        .expect("compact catalog");
        if write_body {
            fs::create_dir_all(root.join("skills/demo")).expect("skill directory");
            fs::write(root.join("skills/demo/SKILL.md"), "deterministic body").expect("skill body");
        }
        fs::write(root.join("runtime"), "native runtime").expect("runtime");
        fs::write(root.join("mcp-schema.json"), "mcp schema").expect("schema");
        fs::write(root.join("assets.json"), "assets").expect("assets");
        let digest = |name: &str| {
            legion_catalog::hex_digest(&fs::read(root.join(name)).expect("digest source"))
        };
        let manifest = legion_runtime::ReleaseManifest {
            release_version: "1.0.0".into(),
            runtime: legion_runtime::RuntimeIdentity {
                platform: "linux".into(),
                architecture: "x86_64".into(),
                sha256: digest("runtime"),
                provenance: "rightkit-release://m1-fixture".into(),
            },
            capability_catalog_sha256: digest("registry/index.json"),
            mcp_tool_schema_sha256: digest("mcp-schema.json"),
            declarative_assets_sha256: digest("assets.json"),
            state_schema_version: 1,
            rightkit_ax: legion_runtime::RightkitAxIdentity {
                version: "0.2.0".into(),
                source_commit: "01f52555202da3dffc6b649ca44e803b55238081".into(),
            },
        };
        let manifest_path = root.join("release.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("manifest JSON"),
        )
        .expect("manifest");
        M1ApplicationInputs {
            release_manifest_path: manifest_path,
            release_binding_inputs: legion_runtime::ReleaseBindingInputs {
                release_version: "1.0.0".into(),
                runtime_path: root.join("runtime"),
                runtime_platform: "linux".into(),
                runtime_architecture: "x86_64".into(),
                runtime_provenance: "rightkit-release://m1-fixture".into(),
                catalog_path: root.join("registry/index.json"),
                mcp_tool_schema_path: root.join("mcp-schema.json"),
                declarative_assets: legion_runtime::DeclarativeAssets::File(
                    root.join("assets.json"),
                ),
                state_schema_version: 1,
                rightkit_ax: legion_runtime::RightkitAxIdentity {
                    version: "0.2.0".into(),
                    source_commit: "01f52555202da3dffc6b649ca44e803b55238081".into(),
                },
            },
            catalog_root: root.into(),
            catalog_index_path: PathBuf::from("registry/index.json"),
            policy_pack: policy_pack(),
        }
    }

    #[test]
    fn m1_operation_is_deterministic_and_emits_real_arcane_receipts() {
        let root = temp_root();
        let app = M1Application::from_inputs(inputs(&root, true)).expect("application");
        let first = app.invoke(request()).expect("first result");
        let second = app.invoke(request()).expect("second result");

        assert_eq!(first, second);
        assert_eq!(first.status.release_version, "1.0.0");
        assert_eq!(first.status.capability_count, 1);
        assert_eq!(
            first.policy_evaluation.decision.outcome,
            DecisionOutcome::Allow
        );
        assert_eq!(first.policy_receipt, first.policy_evaluation.receipt);
        first.invocation_receipt.validate().expect("typed receipt");
        assert!(first.invocation_receipt.complete);
        assert!(first
            .invocation_receipt
            .artifacts
            .contains_key("policyReceiptSha256"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn application_defers_capability_body_reads_until_invocation() {
        let root = temp_root();
        let app =
            M1Application::from_inputs(inputs(&root, false)).expect("metadata-only composition");
        fs::create_dir_all(root.join("skills/demo")).expect("skill directory");
        fs::write(root.join("skills/demo/SKILL.md"), "late body").expect("late body");

        let result = app.invoke(request()).expect("lazy invocation");
        assert_eq!(
            result.capability.body_sha256,
            legion_catalog::hex_digest(b"late body")
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn release_binding_mismatch_fails_before_capability_execution() {
        let root = temp_root();
        let mut inputs = inputs(&root, true);
        inputs.release_binding_inputs.state_schema_version = 2;

        match M1Application::from_inputs(inputs).expect_err("mismatch must fail closed") {
            M1ApplicationError::ReleaseBinding(legion_runtime::ReleaseBindingError::Mismatch {
                remediation,
                ..
            }) => assert_eq!(remediation, legion_runtime::REPAIR_COMMAND),
            error => panic!("wrong failure: {error:?}"),
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn host_requirement_probe_is_typed_without_process_spawn() {
        assert_eq!(super::probe_host_requirement(None), M1Availability::Unknown);
        assert_eq!(
            super::probe_host_requirement(Some(&serde_json::json!({
                "kind": "command",
                "command": "__legion_requirement_is_not_installed__"
            }))),
            M1Availability::Unavailable
        );
        assert_eq!(
            super::probe_host_requirement(Some(&serde_json::json!({
                "kind": "env",
                "env": "__LEGION_REQUIREMENT_IS_NOT_SET__"
            }))),
            M1Availability::Unavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_probe_requires_executable_permission_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root();
        let candidate = root.join("candidate");
        fs::write(&candidate, "not executable").expect("candidate");
        assert!(!super::is_executable_file(&candidate));

        let mut permissions = fs::metadata(&candidate).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&candidate, permissions).expect("executable permissions");
        assert!(super::is_executable_file(&candidate));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
