use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use legion_contracts::ProviderSpec;

use crate::{
    dag::topological,
    error::AuditError,
    integrity::{plan_digest, sign},
    inventory::{InventoryDenominator, InventoryEnvelope},
};

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
    #[serde(rename = "optional-blueprint-evidence")]
    OptionalBlueprintEvidence,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenPlan {
    plan: AuditPlan,
    digest: String,
    signature: Option<String>,
}

impl AuditPlan {
    pub fn compile(
        inventory: &InventoryEnvelope,
        specs: &[ProviderSpec],
    ) -> Result<Self, AuditError> {
        inventory.validate()?;
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
                    "runtime-script" => ProviderKind::RustAlgorithm,
                    "legacy-check" => ProviderKind::TypedExternalProjectTool,
                    "reasoning-contract" => ProviderKind::HostService,
                    "optional-blueprint-evidence" => ProviderKind::OptionalBlueprintEvidence,
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
                            ProviderKind::OptionalBlueprintEvidence =>
                                "optional-blueprint-evidence",
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
                    (
                        "blueprintDependent".into(),
                        serde_json::json!(spec
                            .consumes
                            .iter()
                            .any(|item| item == "blueprint-packet")),
                    ),
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
