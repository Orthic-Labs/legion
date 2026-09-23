use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

use legion_contracts::ProviderSpec;

use crate::{
    dag::topological,
    error::AuditError,
    integrity::{plan_digest, sign},
    inventory::{InventoryDenominator, InventoryEnvelope},
    native_providers::reasoning::{lens_plan, triggers},
};

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
        let mut excluded_conditional_providers = Vec::new();
        let filtered_specs: Vec<ProviderSpec>;
        let specs: &[ProviderSpec] = if let Some(root) = root {
            let paths: Vec<String> = inventory.paths().map(str::to_owned).collect();
            filtered_specs = specs
                .iter()
                .filter(|spec| {
                    if !lens_plan::is_conditional_lens_provider(spec.id.as_str()) {
                        return true;
                    }
                    let Some(lens) = lens_plan::lens_id_for_provider(spec.id.as_str()) else {
                        return true;
                    };
                    let Some(evaluation) = triggers::evaluate_trigger(root, lens, &paths) else {
                        return true;
                    };
                    if evaluation.fired {
                        return true;
                    }
                    excluded_conditional_providers.push(ExcludedConditionalProvider {
                        id: spec.id.to_string(),
                        lens: lens.to_owned(),
                        reason: evaluation.reason,
                    });
                    false
                })
                .cloned()
                .collect();
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
                        let contract = crate::native_providers::legacy_checks::spec(spec.id.as_str())
                            .ok_or_else(|| AuditError::Invalid(format!("unknown legacy provider {}", spec.id)))?;
                        if spec.runner.get("check").and_then(Value::as_str) != Some(contract.check) {
                            return Err(AuditError::Invalid(format!("legacy provider {} check does not match frozen contract", spec.id)));
                        }
                        match contract.command {
                            crate::native_providers::legacy_checks::CommandShape::Native { .. } => ProviderKind::RustAlgorithm,
                            _ => ProviderKind::TypedExternalProjectTool,
                        }
                    },
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
                let configuration = BTreeMap::from([
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
                let bounds = BTreeMap::from([
                    (
                        "required".into(),
                        serde_json::json!(spec
                            .execution
                            .get("required")
                            .and_then(Value::as_bool)
                            .unwrap_or(true)),
                    ),
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
                    benchmark_required_for_clean_claim: spec
                        .benchmark
                        .get("requiredForCleanClaim")
                        .and_then(Value::as_bool)
                        .unwrap_or(true),
                    qualification_digest: spec
                        .benchmark
                        .get("qualificationDigest")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    required: spec
                        .execution
                        .get("required")
                        .and_then(Value::as_bool)
                        .unwrap_or(true),
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
        Ok(Self {
            schema_version: 1,
            repository_id: inventory.repository_id.clone(),
            inventory_generation: inventory.generation.clone(),
            inventory_digest: inventory.digest.clone(),
            providers,
            bounds: BTreeMap::new(),
            excluded_conditional_providers,
        })
    }

    pub fn validate(&self) -> Result<(), AuditError> {
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
        Ok(FrozenPlan { plan: self, digest, signature: None })
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

impl FrozenPlan {
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
