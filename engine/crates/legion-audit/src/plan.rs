use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use legion_contracts::ProviderSpec;

use crate::{
    dag::topological,
    error::AuditError,
    integrity::{plan_digest, sign},
    inventory::InventoryEnvelope,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    BuiltIn,
    EffectExecutor,
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
        let providers = specs
            .iter()
            .map(|spec| {
                let mut lens_ids = spec.lens_ids.clone();
                lens_ids.sort();
                lens_ids.dedup();
                AuditProvider {
                    id: spec.id.to_string(),
                    version: spec.provider_version.clone(),
                    role: spec.role.clone(),
                    phase: spec.phase.clone(),
                    lens_ids,
                    dependencies: spec.depends_on.iter().map(ToString::to_string).collect(),
                    kind: if matches!(
                        spec.runner.get("kind").and_then(Value::as_str),
                        Some("external-process" | "legacy-check")
                    ) {
                        ProviderKind::EffectExecutor
                    } else {
                        ProviderKind::BuiltIn
                    },
                    configuration: BTreeMap::new(),
                    bounds: BTreeMap::new(),
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
                    required: true,
                }
            })
            .collect::<Vec<_>>();
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
