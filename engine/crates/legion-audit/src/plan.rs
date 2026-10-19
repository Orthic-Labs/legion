use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use legion_contracts::ProviderSpec;

use crate::{
    dag::topological,
    error::AuditError,
    integrity::{plan_digest, sign},
    inventory::{InventoryDenominator, InventoryEnvelope},
    native_providers::reasoning::{coverage_plan, lens_plan, triggers},
};

/// `AuditPlan::bounds` key carrying the parent-run binding of a follow-up plan.
pub const FOLLOWUP_BOUND: &str = "followup";
/// Signed purpose marker distinguishing the full provider universe from an
/// ordinary selected execution plan. This marker is valid only in the
/// provider-selection scope plan, never in an executable native plan.
pub const PROVIDER_UNIVERSE_BOUND: &str = "providerUniverse";

/// A conditional-lens provider excluded from a frozen plan because its
/// deterministic trigger was checked over the frozen inventory and did not
/// fire. Recorded so the exclusion is provably-checked, not silently
/// dropped or gated on external Blueprint provenance (Legion has none).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExcludedConditionalProvider {
    pub id: String,
    pub lens: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    BuiltIn,
    EffectExecutor,
    #[serde(rename = "rust-algorithm")]
    RustAlgorithm,
    #[serde(rename = "typed-external-project-tool")]
    TypedExternalProjectTool,
    #[serde(rename = "host-service")]
    HostService,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditProvider {
    pub id: String,
    pub version: String,
    pub role: String,
    pub phase: String,
    #[serde(default)]
    pub lens_ids: Vec<String>,
    pub dependencies: Vec<String>,
    pub kind: ProviderKind,
    #[serde(default)]
    pub configuration: BTreeMap<String, Value>,
    #[serde(default)]
    pub bounds: BTreeMap<String, Value>,
    pub clean_claim: String,
    pub benchmark_status: String,
    pub benchmark_required_for_clean_claim: bool,
    pub qualification_digest: Option<String>,
    pub required: bool,
}

impl AuditProvider {
    /// True when the frozen selector matched nothing in the inventory and the
    /// selector is not the unconditional `always` selector. Such a provider
    /// does not apply to this repository: it is excluded from the required
    /// set and never executed, instead of failing on an empty denominator.
    pub fn not_applicable(&self) -> bool {
        if self.host_declaration_absent() {
            return true;
        }
        self.configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            == Some(0)
            && !self
                .configuration
                .get("selector")
                .is_some_and(selector_is_always)
    }
}

impl AuditProvider {
    /// True when the registry makes this provider conditional on a trusted-host
    /// declaration (`runner.hostDeclaration`) and the host declared nothing.
    /// Absence is never clean: the provider is reported not-applicable.
    pub fn host_declaration_absent(&self) -> bool {
        self.configuration
            .get("hostDeclaration")
            .and_then(|value| value.get("declared"))
            .and_then(Value::as_bool)
            == Some(false)
    }
}

/// Resolve a provider's `runner.hostDeclaration` against the trusted-host
/// environment at planning time. The result is frozen into the plan so a
/// later change of declaration is detected as drift.
fn resolve_host_declaration(runner: &Value) -> Option<Value> {
    let declaration = runner.get("hostDeclaration")?;
    let env_name = declaration.get("env").and_then(Value::as_str)?;
    let raw = std::env::var(env_name).unwrap_or_default();
    let declared = !raw.trim().is_empty();
    let required = declaration
        .get("requiredEnv")
        .and_then(Value::as_str)
        .and_then(|name| std::env::var(name).ok())
        .is_some_and(|value| matches!(value.trim(), "1" | "true"));
    Some(serde_json::json!({
        "env": env_name,
        "declared": declared,
        "required": declared && required,
        "commandDigest": if declared {
            Value::String(crate::native_providers::legacy::common::digest_text(&raw))
        } else {
            Value::Null
        },
    }))
}

/// Plans coverage for every applicable coverage-planned lens provider in
/// `specs`. The request (`reasoning.coverageRequest`) and diff scope come from
/// the specs themselves, so the executed plan and the lens basis plan, which
/// compile independently, freeze identical review sets.
fn plan_lens_coverage(
    root: &Path,
    inventory: &InventoryEnvelope,
    specs: &[ProviderSpec],
    candidates: &[InventoryDenominator],
    trigger_evidence: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, AuditError> {
    let mut lenses = Vec::new();
    let mut request = coverage_plan::CoverageRequest::default();
    let mut changed: BTreeSet<String> = BTreeSet::new();
    for spec in specs {
        if !lens_plan::is_coverage_planned_provider(spec.id.as_str()) {
            continue;
        }
        let denominator =
            inventory.denominator_entries_with_candidates(&spec.selector, candidates)?;
        if denominator.entries.is_empty() {
            continue;
        }
        if lenses.is_empty() {
            request = coverage_plan::CoverageRequest::from_reasoning(&spec.reasoning);
            changed = coverage_plan::changed_paths_from_reasoning(&spec.reasoning);
        }
        lenses.push(coverage_plan::LensInput {
            provider_id: spec.id.to_string(),
            paths: denominator
                .entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect(),
        });
    }
    if lenses.is_empty() {
        return Ok(BTreeMap::new());
    }
    let facts = coverage_plan::gather_facts(root, inventory, &changed);
    let witnesses = trigger_evidence
        .iter()
        .map(|(provider, evidence)| {
            let paths = evidence
                .get("mandatoryWitnessPaths")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            (provider.clone(), paths)
        })
        .collect();
    coverage_plan::plan_coverage_with_witnesses(
        &serde_json::json!({
            "repositoryId": inventory.repository_id,
            "inventoryDigest": inventory.digest,
        }),
        &facts,
        &lenses,
        &request,
        &witnesses,
    )
}

fn selector_is_always(selector: &Value) -> bool {
    selector.as_str() == Some("always")
        || selector.get("op").and_then(Value::as_str) == Some("always")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditPlan {
    pub schema_version: u32,
    pub repository_id: String,
    pub inventory_generation: String,
    pub inventory_digest: String,
    pub providers: Vec<AuditProvider>,
    #[serde(default)]
    pub bounds: BTreeMap<String, Value>,
    /// Conditional-lens providers excluded because their trigger was
    /// checked and did not fire. Empty when `compile` was called without a
    /// filesystem root (trigger evaluation needs real file contents) or
    /// when every conditional trigger fired.
    #[serde(default)]
    pub excluded_conditional_providers: Vec<ExcludedConditionalProvider>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenPlan {
    plan: AuditPlan,
    digest: String,
    signature: Option<String>,
}

impl AuditPlan {
    /// Compiles a frozen plan without evaluating conditional-lens triggers
    /// (`excluded_conditional_providers` is always empty). Trigger
    /// evaluation needs real file contents for two of the five conditional
    /// lenses, which this entry point has no filesystem root to read.
    /// Prefer `compile_with_root` wherever a root is available.
    pub fn compile(
        inventory: &InventoryEnvelope,
        specs: &[ProviderSpec],
    ) -> Result<Self, AuditError> {
        Self::compile_with_root(None, inventory, specs)
    }

    /// Compiles a frozen plan, additionally gating conditional-lens
    /// providers (`reasoning.a11y`, `reasoning.data-safety`,
    /// `reasoning.resilience`, `reasoning.platform-parity`,
    /// `reasoning.release-readiness`) on their deterministic trigger: each
    /// is checked with `reasoning::triggers::evaluate_trigger` over the
    /// frozen inventory's paths, and one that is checked-and-not-fired is
    /// excluded from the plan with its reason recorded in
    /// `excluded_conditional_providers`, never silently dropped. This is
    /// the only exclusion `compile` performs; nothing here (or anywhere in
    /// Rust) excludes or degrades a provider for missing Blueprint — Legion
    /// has no dependency on it.
    pub fn compile_with_root(
        root: Option<&Path>,
        inventory: &InventoryEnvelope,
        specs: &[ProviderSpec],
    ) -> Result<Self, AuditError> {
        inventory.validate()?;
        if specs.is_empty() {
            return Err(AuditError::Invalid(
                "audit plan requires at least one frozen provider".into(),
            ));
        }
        let trigger_source = root.map(triggers::TriggerSource::new).transpose()?;
        let source_sides = match &trigger_source {
            Some(source) => source.source_sides(),
            None => BTreeMap::new(),
        };
        let source_sides: BTreeMap<_, _> = source_sides
            .into_iter()
            .filter(|(path, _)| inventory.entries.iter().any(|entry| &entry.path == path))
            .collect();
        let mut excluded_conditional_providers = Vec::new();
        let mut trigger_evidence = BTreeMap::new();
        let mut filtered_specs = Vec::new();
        let specs: &[ProviderSpec] = if let Some(source) = &trigger_source {
            let paths: Vec<String> = inventory.paths().map(str::to_owned).collect();
            for spec in specs {
                let evaluation = lens_plan::lens_id_for_provider(spec.id.as_str())
                    .and_then(|lens| source.evaluate(lens, &paths));
                let Some(evaluation) = evaluation else {
                    filtered_specs.push(spec.clone());
                    continue;
                };
                if !evaluation.fired && evaluation.unavailable_paths.is_empty() {
                    excluded_conditional_providers.push(ExcludedConditionalProvider {
                        id: spec.id.to_string(),
                        lens: evaluation.lens.to_owned(),
                        reason: evaluation.reason,
                    });
                    continue;
                }
                let witnesses = evaluation.applicable_paths();
                trigger_evidence.insert(
                    spec.id.to_string(),
                    evaluation.snapshot_with_source_sides(
                        &inventory.digest,
                        &paths,
                        &source_sides,
                    )?,
                );
                let mut applicable = spec.clone();
                // Trigger witnesses must belong to the same selector-bound
                // denominator used by execution, resume & ingest. Never issue
                // a conditional lens with an empty successful review set.
                if !witnesses.is_empty() {
                    applicable.selector = serde_json::json!({
                        "op": "any",
                        "selectors": [spec.selector, {"op": "paths", "paths": witnesses}],
                    });
                }
                filtered_specs.push(applicable);
            }
            filtered_specs.as_slice()
        } else {
            specs
        };
        if specs.is_empty() {
            return Err(AuditError::Invalid(
                "audit plan requires at least one frozen provider".into(),
            ));
        }
        let candidate_denominators = specs
            .iter()
            .filter(|spec| spec.role == "candidate-generator")
            .map(|spec| inventory.denominator_entries(&spec.selector))
            .collect::<Result<Vec<InventoryDenominator>, _>>()?;
        // Frozen lens coverage plans (review sets) per coverage-planned lens
        // provider. Needs a filesystem root (sizes, churn); without one every
        // lens keeps the exhaustive, selector-bound behaviour.
        let coverage_configs = match root {
            Some(root) => plan_lens_coverage(
                root,
                inventory,
                specs,
                &candidate_denominators,
                &trigger_evidence,
            )?,
            None => BTreeMap::new(),
        };
        let providers = specs
            .iter()
            .map(|spec| {
                spec.validate()?;
                let mut lens_ids = spec.lens_ids.clone();
                lens_ids.sort();
                lens_ids.dedup();
                let runner_kind = spec
                    .runner
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let kind = match runner_kind {
                    // Every production runtime-script provider is now backed
                    // by the in-process native provider registry.
                    "runtime-script" => ProviderKind::RustAlgorithm,
                    "legacy-check" => {
                        // Legacy is the public registry identity, not proof of
                        // an external process. In-process Rust checks must not
                        // fabricate process-start/cleanup receipts to pass the
                        // external-tool validator.
                        let contract =
                            crate::native_providers::legacy_checks::spec(spec.id.as_str())
                                .ok_or_else(|| {
                                    AuditError::Invalid(format!(
                                        "unknown legacy provider {}",
                                        spec.id
                                    ))
                                })?;
                        if spec.runner.get("check").and_then(Value::as_str) != Some(contract.check)
                        {
                            return Err(AuditError::Invalid(format!(
                                "legacy provider {} check does not match frozen contract",
                                spec.id
                            )));
                        }
                        match contract.command {
                            crate::native_providers::legacy_checks::CommandShape::Native {
                                ..
                            } => ProviderKind::RustAlgorithm,
                            _ => ProviderKind::TypedExternalProjectTool,
                        }
                    }
                    "reasoning-contract" => ProviderKind::HostService,
                    "external-process" => ProviderKind::TypedExternalProjectTool,
                    "built-in" | "declarative-rule" => ProviderKind::RustAlgorithm,
                    _ => {
                        return Err(AuditError::Invalid(format!(
                            "provider {} has unsupported runner kind {runner_kind}",
                            spec.id
                        )))
                    }
                };
                let denominator = inventory
                    .denominator_entries_with_candidates(&spec.selector, &candidate_denominators)?;
                let denominator_count = denominator.entries.len();
                let denominator_digest = denominator.digest;
                let host_declaration = resolve_host_declaration(&spec.runner);
                let mut configuration = BTreeMap::from([
                    (
                        "schemaVersion".into(),
                        serde_json::json!(spec.schema_version),
                    ),
                    ("family".into(), serde_json::json!(spec.family)),
                    ("consumes".into(), serde_json::json!(spec.consumes)),
                    ("produces".into(), serde_json::json!(spec.produces)),
                    ("selector".into(), spec.selector.clone()),
                    (
                        "denominatorKind".into(),
                        serde_json::json!(spec.denominator_kind),
                    ),
                    ("runner".into(), spec.runner.clone()),
                    (
                        "hostCapabilities".into(),
                        serde_json::json!(spec.host_capabilities),
                    ),
                    ("execution".into(), spec.execution.clone()),
                    ("reasoning".into(), spec.reasoning.clone()),
                    ("benchmark".into(), spec.benchmark.clone()),
                    ("controlIds".into(), serde_json::json!(spec.control_ids)),
                    ("scopes".into(), serde_json::json!(spec.scopes)),
                    ("selectable".into(), serde_json::json!(spec.selectable)),
                    (
                        "runnerClass".into(),
                        serde_json::json!(match kind {
                            ProviderKind::RustAlgorithm => "rust-algorithm",
                            ProviderKind::TypedExternalProjectTool => "typed-external-project-tool",
                            ProviderKind::HostService => "host-service",
                            ProviderKind::EffectExecutor => "effect-executor",
                            ProviderKind::BuiltIn => "built-in",
                        }),
                    ),
                    (
                        "denominatorDigest".into(),
                        serde_json::json!(denominator_digest),
                    ),
                    (
                        "denominatorCount".into(),
                        serde_json::json!(denominator_count),
                    ),
                ]);
                if spec.id.as_str() == "legacy.security.sast" {
                    configuration.insert(
                        "semgrepContract".into(),
                        crate::native_providers::legacy_checks::semgrep::contract(),
                    );
                }
                let host_declared = host_declaration
                    .as_ref()
                    .and_then(|value| value.get("declared"))
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let host_required = host_declaration
                    .as_ref()
                    .and_then(|value| value.get("required"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(value) = host_declaration {
                    configuration.insert("hostDeclaration".into(), value);
                }
                // Review set, strata, seed and budget share: covered by the
                // plan digest and signature. The selector-bound denominator
                // above is unchanged.
                if let Some(coverage) = coverage_configs.get(spec.id.as_str()) {
                    configuration.insert("coverage".into(), coverage.clone());
                }
                if let Some(evidence) = trigger_evidence.get(spec.id.as_str()) {
                    configuration.insert("triggerEvidence".into(), evidence.clone());
                }
                let provider_sides: BTreeMap<_, _> = source_sides
                    .iter()
                    .filter(|(path, _)| {
                        denominator.entries.iter().any(|entry| &entry.path == *path)
                    })
                    .map(|(path, side)| (path.clone(), side.clone()))
                    .collect();
                configuration.insert("sourceSides".into(), serde_json::json!(provider_sides));
                // A provider whose selector matches nothing does not apply to
                // this repository, so it is never `required`.
                let applicable =
                    host_declared && (denominator_count > 0 || selector_is_always(&spec.selector));
                let required = applicable
                    && (host_required
                        || spec
                            .execution
                            .get("required")
                            .and_then(Value::as_bool)
                            .unwrap_or(true));
                let bounds = BTreeMap::from([
                    ("required".into(), serde_json::json!(required)),
                    ("cleanClaim".into(), serde_json::json!(spec.clean_claim)),
                ]);
                Ok::<_, AuditError>(AuditProvider {
                    id: spec.id.to_string(),
                    version: spec.provider_version.clone(),
                    role: spec.role.clone(),
                    phase: spec.phase.clone(),
                    lens_ids,
                    dependencies: spec.depends_on.iter().map(ToString::to_string).collect(),
                    kind,
                    configuration,
                    bounds,
                    clean_claim: spec.clean_claim.clone(),
                    benchmark_status: spec
                        .benchmark
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("unproven")
                        .to_owned(),
                    benchmark_required_for_clean_claim: host_required
                        || spec
                            .benchmark
                            .get("requiredForCleanClaim")
                            .and_then(Value::as_bool)
                            .unwrap_or(true),
                    qualification_digest: spec
                        .benchmark
                        .get("qualificationDigest")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    required,
                })
            })
            .collect::<Result<Vec<_>, AuditError>>()?;
        let order = topological(&providers)?;
        let mut by_id: BTreeMap<_, _> = providers
            .into_iter()
            .map(|provider| (provider.id.clone(), provider))
            .collect();
        let providers = order
            .into_iter()
            .map(|id| by_id.remove(&id).expect("validated provider id"))
            .collect();
        if let Some(source) = &trigger_source {
            source.revalidate()?;
        }
        Ok(Self {
            schema_version: 1,
            repository_id: inventory.repository_id.clone(),
            inventory_generation: inventory.generation.clone(),
            inventory_digest: inventory.digest.clone(),
            providers,
            bounds: crate::execution_policy::binding()
                .as_object()
                .expect("static policy binding")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            excluded_conditional_providers,
        })
    }

    /// Compile the complete provider universe used to derive Audit coverage,
    /// and bind it to the exact selected execution-plan digest. Ordinary
    /// compilation deliberately does not add this marker, so a selected plan
    /// cannot be substituted as the full universe without changing signed
    /// bytes and purpose.
    pub fn compile_provider_universe(
        root: Option<&Path>,
        inventory: &InventoryEnvelope,
        all_specs: &[ProviderSpec],
        selected_plan_digest: &str,
    ) -> Result<Self, AuditError> {
        if !valid_sha256_label(selected_plan_digest) {
            return Err(AuditError::Invalid(
                "selected execution plan digest is invalid".into(),
            ));
        }
        let mut plan = Self::compile_with_root(root, inventory, all_specs)?;
        if plan.bounds.contains_key(PROVIDER_UNIVERSE_BOUND) {
            return Err(AuditError::Invalid(
                "provider universe marker is reserved for universe compilation".into(),
            ));
        }
        plan.bounds.insert(
            PROVIDER_UNIVERSE_BOUND.into(),
            serde_json::json!({
                "schemaVersion": 1,
                "purpose": "audit-provider-universe",
                "selectedPlanDigest": selected_plan_digest,
            }),
        );
        Ok(plan)
    }

    /// Compiles the follow-up plan for security variant analysis: a plan of
    /// exactly one provider (the `variant-analysis` spec) whose denominator
    /// contains confirmed finding files plus deterministic in-inventory sibling
    /// and caller context. Confirmed paths remain distinct seed evidence; the
    /// expanded analysis paths are frozen into the provider selector. The
    /// parent run is bound through `bounds.followup` (parent plan digest and
    /// the digest of the confirmed findings), so the plan digest and signature
    /// cover both.
    pub fn compile_followup(
        inventory: &InventoryEnvelope,
        variant_spec: &ProviderSpec,
        confirmed_paths: &[String],
        analysis_paths: &[String],
        scope_relations: &Value,
        parent_plan_digest: &str,
        confirmed_digest: &str,
    ) -> Result<Self, AuditError> {
        if variant_spec.role != "variant-analysis" {
            return Err(AuditError::Invalid(format!(
                "{} is not a variant-analysis provider",
                variant_spec.id
            )));
        }
        let paths = confirmed_paths
            .iter()
            .map(|path| path.replace('\\', "/"))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return Err(AuditError::Invalid(
                "a security follow-up plan needs at least one confirmed path".into(),
            ));
        }
        let analysis_paths = analysis_paths
            .iter()
            .map(|path| path.replace('\\', "/"))
            .collect::<std::collections::BTreeSet<_>>();
        if !paths.iter().all(|path| analysis_paths.contains(path)) {
            return Err(AuditError::Invalid(
                "variant analysis scope omits a confirmed finding seed".into(),
            ));
        }
        let selector = serde_json::json!({
            "op": "confirmedSecurityFinding",
            "paths": analysis_paths,
        });
        let expected = inventory.denominator_entries(&selector)?;
        let analysis_paths = expected
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if analysis_paths.len() != expected.entries.len()
            || expected.entries.len() != selector["paths"].as_array().map_or(0, Vec::len)
        {
            return Err(AuditError::SourceDrift(
                "a variant analysis path is not part of the frozen inventory".into(),
            ));
        }
        let mut spec = variant_spec.clone();
        spec.selector = selector;
        let mut plan = Self::compile_with_root(None, inventory, std::slice::from_ref(&spec))?;
        plan.bounds.insert(
            FOLLOWUP_BOUND.into(),
            serde_json::json!({
                "kind": "security-variant-analysis",
                "trigger": "confirmedSecurityFinding",
                "parentPlanDigest": parent_plan_digest,
                "confirmedDigest": confirmed_digest,
                "confirmedPaths": paths,
                "scopeVersion": 2,
                "analysisPaths": expected
                    .entries
                    .iter()
                    .map(|entry| entry.path.clone())
                    .collect::<Vec<_>>(),
                "scopeRelations": scope_relations,
            }),
        );
        Ok(plan)
    }

    /// The follow-up binding frozen by `compile_followup`, if this is one.
    pub fn followup_binding(&self) -> Option<&Value> {
        self.bounds.get(FOLLOWUP_BOUND)
    }

    pub(crate) fn validate_execution_policy(&self) -> Result<(), AuditError> {
        for (field, value) in crate::execution_policy::binding()
            .as_object()
            .expect("static policy binding")
        {
            if self.bounds.get(field) != Some(value) {
                return Err(AuditError::Invalid(format!(
                    "audit plan {field} binding is absent or unsupported; regenerate Audit plan with native owner admission policy"
                )));
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuditError> {
        self.validate_execution_policy()?;
        if self.schema_version != 1
            || self.repository_id.trim().is_empty()
            || self.inventory_generation.trim().is_empty()
            || self.providers.is_empty()
        {
            return Err(AuditError::Invalid("invalid audit plan envelope".into()));
        }
        if self.inventory_digest.trim().is_empty() {
            return Err(AuditError::Invalid(
                "audit plan inventory digest is required".into(),
            ));
        }
        if let Some(binding) = self.bounds.get(PROVIDER_UNIVERSE_BOUND) {
            let object = binding.as_object().ok_or_else(|| {
                AuditError::Invalid("provider universe bound is not an object".into())
            })?;
            if object.len() != 3
                || binding.get("schemaVersion").and_then(Value::as_u64) != Some(1)
                || binding.get("purpose").and_then(Value::as_str) != Some("audit-provider-universe")
                || !binding
                    .get("selectedPlanDigest")
                    .and_then(Value::as_str)
                    .is_some_and(valid_sha256_label)
            {
                return Err(AuditError::Invalid(
                    "provider universe bound is malformed or unsupported".into(),
                ));
            }
        }
        for provider in &self.providers {
            for field in [
                "schemaVersion",
                "family",
                "consumes",
                "produces",
                "selector",
                "denominatorKind",
                "runner",
                "hostCapabilities",
                "execution",
                "reasoning",
                "benchmark",
                "controlIds",
                "scopes",
                "selectable",
                "runnerClass",
                "denominatorDigest",
                "denominatorCount",
            ] {
                if !provider.configuration.contains_key(field) {
                    return Err(AuditError::Invalid(format!(
                        "provider {} is missing frozen ProviderSpec field {field}",
                        provider.id
                    )));
                }
            }
            if let Some(coverage) = provider.configuration.get("coverage") {
                let frozen =
                    coverage_plan::FrozenCoverage::from_value(coverage).ok_or_else(|| {
                        AuditError::Invalid(format!(
                            "provider {} has a malformed frozen coverage plan",
                            provider.id
                        ))
                    })?;
                let listed: Vec<&String> = frozen.review_set.iter().collect();
                let digest = legion_contracts::canonical_digest(&listed)
                    .map_err(|error| AuditError::Invalid(error.to_string()))?;
                let count = provider
                    .configuration
                    .get("denominatorCount")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                if digest != frozen.review_set_digest
                    || frozen.review_set.len() > count
                    || frozen.denominator != count
                {
                    return Err(AuditError::Invalid(format!(
                        "provider {} frozen coverage plan does not match its review set or denominator",
                        provider.id
                    )));
                }
            }
            if provider.configuration.get("selectable") == Some(&Value::Bool(false)) {
                return Err(AuditError::Invalid(format!(
                    "non-selectable provider {} was included in selected plan",
                    provider.id
                )));
            }
            if provider
                .configuration
                .get("runner")
                .and_then(Value::as_object)
                .and_then(|runner| runner.get("kind"))
                .and_then(Value::as_str)
                .is_none()
            {
                return Err(AuditError::Invalid(format!(
                    "provider {} is missing runner identity",
                    provider.id
                )));
            }
        }
        topological(&self.providers)?;
        let provider_positions = self
            .providers
            .iter()
            .enumerate()
            .map(|(index, provider)| (provider.id.as_str(), index))
            .collect::<BTreeMap<_, _>>();
        for provider in &self.providers {
            let Some(source_id) = crate::dag::capture_source_provider(provider)? else {
                continue;
            };
            let source = self
                .providers
                .iter()
                .find(|candidate| candidate.id == source_id)
                .ok_or_else(|| {
                    AuditError::Invalid(format!(
                        "visual capture source provider {source_id} is missing"
                    ))
                })?;
            let runtime = source
                .configuration
                .get("runner")
                .and_then(|runner| runner.get("runtime"))
                .ok_or_else(|| {
                    AuditError::Invalid(format!(
                        "visual capture source {source_id} has no frozen runtime inputs"
                    ))
                })?;
            if !runtime
                .get("url")
                .and_then(Value::as_str)
                .is_some_and(|url| !url.trim().is_empty())
            {
                return Err(AuditError::Invalid(format!(
                    "visual capture source {source_id} has no frozen runtime URL"
                )));
            }
            if provider_positions.get(source_id).copied()
                >= provider_positions.get(provider.id.as_str()).copied()
            {
                return Err(AuditError::Invalid(format!(
                    "visual provider {} precedes its capture source {source_id}",
                    provider.id
                )));
            }
        }
        if self
            .providers
            .iter()
            .any(|provider| provider.role != "deterministic" && provider.lens_ids.is_empty())
        {
            return Err(AuditError::Invalid(
                "reasoning providers require explicit lens identifiers".into(),
            ));
        }
        Ok(())
    }

    /// Diagnostic source scans may preserve an unsigned plan without claiming authority.
    /// Authenticated execution continues to use `freeze`.
    pub fn freeze_source_diagnostic(self) -> Result<FrozenPlan, AuditError> {
        self.validate()?;
        let digest = plan_digest(&self)?;
        Ok(FrozenPlan {
            plan: self,
            digest,
            signature: None,
        })
    }

    pub fn freeze(self, signing_key: Option<&[u8]>) -> Result<FrozenPlan, AuditError> {
        self.validate()?;
        let signing_key = signing_key
            .filter(|key| !key.is_empty())
            .ok_or_else(|| AuditError::Invalid("audit plan signing key is required".into()))?;
        let digest = plan_digest(&self)?;
        let signature = Some(sign(&self, signing_key)?);
        Ok(FrozenPlan {
            plan: self,
            digest,
            signature,
        })
    }
}

fn valid_sha256_label(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

impl FrozenPlan {
    /// Restore an existing seal without recompiling providers or coverage.
    /// No unchecked constructor exists: persisted identity must authenticate.
    pub(crate) fn restore_verified(
        plan: AuditPlan,
        digest: &str,
        signature: &str,
        key: &[u8],
    ) -> Result<Self, AuditError> {
        plan.validate()?;
        crate::integrity::verify(&plan, digest, Some(signature), Some(key))?;
        Ok(Self {
            plan,
            digest: digest.into(),
            signature: Some(signature.into()),
        })
    }

    pub fn plan(&self) -> &AuditPlan {
        &self.plan
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }
    pub fn providers(&self) -> &[AuditProvider] {
        &self.plan.providers
    }
    pub fn provider(&self, id: &str) -> Option<&AuditProvider> {
        self.plan
            .providers
            .iter()
            .find(|provider| provider.id == id)
    }
}

#[cfg(test)]
mod authenticated_restore_tests {
    use super::*;

    #[test]
    fn restore_keeps_exact_frozen_scope_and_rejects_forged_identity() {
        let mut configuration = [
            "schemaVersion",
            "family",
            "consumes",
            "produces",
            "selector",
            "denominatorKind",
            "hostCapabilities",
            "execution",
            "reasoning",
            "benchmark",
            "controlIds",
            "scopes",
            "selectable",
            "runnerClass",
            "denominatorDigest",
            "denominatorCount",
        ]
        .into_iter()
        .map(|field| (field.to_owned(), Value::Null))
        .collect::<BTreeMap<_, _>>();
        configuration.insert("runner".into(), serde_json::json!({"kind":"built-in"}));
        let plan = AuditPlan {
            schema_version: 1,
            repository_id: "/frozen/source".into(),
            inventory_generation: "frozen-generation".into(),
            inventory_digest: "frozen-inventory".into(),
            providers: vec![AuditProvider {
                id: "frozen.provider".into(),
                version: "1".into(),
                role: "deterministic".into(),
                phase: "scan".into(),
                lens_ids: Vec::new(),
                dependencies: Vec::new(),
                kind: ProviderKind::BuiltIn,
                configuration,
                bounds: BTreeMap::new(),
                clean_claim: "frozen-claim".into(),
                benchmark_status: "unqualified".into(),
                benchmark_required_for_clean_claim: false,
                qualification_digest: None,
                required: true,
            }],
            bounds: crate::execution_policy::binding()
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            excluded_conditional_providers: Vec::new(),
        };
        let key = b"restore-fixture-key";
        assert_eq!(
            plan.bounds["executionPolicy"],
            crate::execution_policy::resolved_policy()
        );
        let mut old_plan = plan.clone();
        old_plan.bounds.remove("executionPolicy");
        assert!(old_plan
            .validate()
            .unwrap_err()
            .to_string()
            .contains("regenerate Audit plan"));
        let old_digest = plan_digest(&old_plan).unwrap();
        let old_signature = sign(&old_plan, key).unwrap();
        assert!(
            crate::integrity::verify(&old_plan, &old_digest, Some(&old_signature), Some(key))
                .unwrap_err()
                .to_string()
                .contains("regenerate Audit plan")
        );
        let mut permissive = plan.clone();
        permissive.bounds.get_mut("executionPolicy").unwrap()["effectiveMode"] =
            serde_json::json!("allow-external");
        assert_ne!(
            plan_digest(&plan).unwrap(),
            plan_digest(&permissive).unwrap()
        );
        assert!(permissive.validate().is_err());
        let digest = plan_digest(&plan).unwrap();
        let signature = sign(&plan, key).unwrap();
        let restored =
            FrozenPlan::restore_verified(plan.clone(), &digest, &signature, key).unwrap();
        assert_eq!(restored.plan(), &plan);
        assert_eq!(restored.digest(), digest);
        assert_eq!(restored.signature(), Some(signature.as_str()));
        let mut changed = plan.clone();
        changed.providers[0].required = false;
        assert!(FrozenPlan::restore_verified(changed, &digest, &signature, key).is_err());
        assert!(
            FrozenPlan::restore_verified(plan.clone(), &digest, &signature, b"wrong-key").is_err()
        );
        assert!(FrozenPlan::restore_verified(plan, &digest, "forged-signature", key).is_err());
    }
}
