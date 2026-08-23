use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonical_digest,
    id::{NodeId, PlanId, ProviderId},
    require_version, ContractError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanNodeKind {
    Provider,
    Gate,
    Report,
    External,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanNode {
    pub id: NodeId,
    pub kind: PlanNodeKind,
    pub provider: Option<ProviderId>,
    pub depends_on: Vec<NodeId>,
    pub configuration: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub id: PlanId,
    pub nodes: Vec<PlanNode>,
    pub providers: Vec<ProviderId>,
    pub resources: BTreeMap<String, serde_json::Value>,
}

impl Plan {
    pub fn new(
        schema_version: u32,
        id: PlanId,
        nodes: Vec<PlanNode>,
        providers: Vec<ProviderId>,
    ) -> Result<Self, ContractError> {
        let plan = Self {
            schema_version,
            id,
            nodes,
            providers,
            resources: BTreeMap::new(),
        };
        plan.validate()?;
        Ok(plan)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        let mut ids = BTreeSet::new();
        for node in &self.nodes {
            if !ids.insert(node.id.clone()) {
                return Err(ContractError::InvalidContract {
                    path: "nodes.id".into(),
                    reason: "duplicate node id".into(),
                });
            }
        }
        let provider_ids: BTreeSet<_> = self.providers.iter().collect();
        if provider_ids.len() != self.providers.len() {
            return Err(ContractError::InvalidContract {
                path: "providers".into(),
                reason: "duplicate provider id".into(),
            });
        }
        for node in &self.nodes {
            if node.depends_on.iter().any(|dep| !ids.contains(dep)) {
                return Err(ContractError::InvalidContract {
                    path: "nodes.depends_on".into(),
                    reason: "unknown dependency".into(),
                });
            }
        }
        self.ordered_nodes().map(|_| ())
    }
    pub fn ordered_nodes(&self) -> Result<Vec<PlanNode>, ContractError> {
        let mut by_id = BTreeMap::new();
        for node in &self.nodes {
            by_id.insert(node.id.clone(), node.clone());
        }
        let mut remaining: BTreeSet<NodeId> = by_id.keys().cloned().collect();
        let mut done = BTreeSet::new();
        let mut output = Vec::with_capacity(self.nodes.len());
        while let Some(id) = remaining
            .iter()
            .find(|id| by_id[*id].depends_on.iter().all(|dep| done.contains(dep)))
            .cloned()
        {
            remaining.remove(&id);
            done.insert(id.clone());
            output.push(by_id[&id].clone());
        }
        if !remaining.is_empty() {
            return Err(ContractError::InvalidContract {
                path: "nodes".into(),
                reason: "cycle detected".into(),
            });
        }
        Ok(output)
    }
    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
}
