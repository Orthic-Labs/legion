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
    pub dependencies: Vec<String>,
    pub kind: ProviderKind,
    #[serde(default)]
    pub configuration: BTreeMap<String, Value>,
    #[serde(default)]
    pub bounds: BTreeMap<String, Value>,
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
        let mut providers = specs
            .iter()
            .map(|spec| AuditProvider {
                id: spec.id.to_string(),
                version: spec.provider_version.clone(),
                dependencies: spec.depends_on.iter().map(ToString::to_string).collect(),
                kind: if spec.implementation_key.starts_with("builtin:") {
                    ProviderKind::BuiltIn
                } else {
                    ProviderKind::EffectExecutor
                },
                configuration: BTreeMap::new(),
                bounds: BTreeMap::new(),
                required: spec.required,
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
        {
            return Err(AuditError::Invalid("invalid audit plan envelope".into()));
        }
        topological(&self.providers)?;
        Ok(())
    }

    pub fn freeze(self, signing_key: Option<&[u8]>) -> Result<FrozenPlan, AuditError> {
        self.validate()?;
        let digest = plan_digest(&self)?;
        let signature = signing_key.map(|key| sign(&self, key)).transpose()?;
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
