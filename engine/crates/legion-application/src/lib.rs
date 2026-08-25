#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
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
    EffectInterface, ImplementationRegistry, Provider, ProviderContext, ProviderDefinition,
    ProviderError, ProviderErrorKind, ProviderRegistry, ProviderRegistryDocument, SourceInterface,
};
use legion_report::ReportError;
use legion_runtime::{
    ContextRequest, EffectPolicy, EngineOutcome, Invocation, LegionEngine, RouteCandidate,
    RuntimeError,
};
use thiserror::Error;

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
        let mut results = BTreeMap::new();
        for result in provider_results {
            result
                .validate()
                .map_err(|error| NativeApplicationError::Configuration(error.to_string()))?;
            if result.complete
                && result
                    .coverage
                    .as_ref()
                    .is_none_or(|coverage| coverage.denominator_digest != inventory.digest)
            {
                return Err(NativeApplicationError::Configuration(format!(
                    "complete provider result {} is not bound to the selected inventory digest",
                    result.provider
                )));
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

    pub async fn invoke(
        &self,
        operation: NativeOperation,
    ) -> Result<NativeOperationResult, NativeApplicationError> {
        match operation {
            NativeOperation::Invoke(invocation) => Ok(NativeOperationResult::Invocation(
                self.engine.execute(invocation).await?,
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
                    self.engine.execute(invocation).await?,
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
                    self.engine.execute(invocation).await?,
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
        tokio::select! {
            _ = cancellation.cancelled() => Err(NativeApplicationError::Runtime(RuntimeError::Cancelled)),
            result = self.invoke(operation) => result,
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
