use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    id::{AgentId, TaskId},
    non_empty, require_version, ContractError,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetCeiling {
    pub max_active_time_ms: u64,
    pub max_cost_micros: u64,
    pub max_output_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCeiling {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingCeiling {
    pub model_tiers: Vec<String>,
    pub worker_profiles: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinition {
    #[serde(deserialize_with = "crate::deserialize_schema_version_2")]
    pub schema_version: u32,
    pub id: AgentId,
    pub name: String,
    pub description: String,
    pub model_ceiling: Option<String>,
    pub capabilities: Vec<String>,
    pub tools: ToolCeiling,
    pub budget: BudgetCeiling,
    pub routing: RoutingCeiling,
    pub escalation_graph: Vec<AgentId>,
}

impl AgentDefinition {
    pub fn new(
        id: AgentId,
        name: impl Into<String>,
        description: impl Into<String>,
        budget: BudgetCeiling,
        tools: ToolCeiling,
        routing: RoutingCeiling,
    ) -> Result<Self, ContractError> {
        let definition = Self {
            schema_version: 2,
            id,
            name: name.into(),
            description: description.into(),
            model_ceiling: None,
            capabilities: Vec::new(),
            tools,
            budget,
            routing,
            escalation_graph: Vec::new(),
        };
        definition.validate()?;
        Ok(definition)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 2)?;
        non_empty("name", &self.name)?;
        non_empty("description", &self.description)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationGrant {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub agent_id: AgentId,
    pub task_id: TaskId,
    pub capabilities: Vec<String>,
    pub tools: ToolCeiling,
    pub budget: BudgetCeiling,
    pub route: Option<String>,
    pub context: BTreeMap<String, serde_json::Value>,
}

impl InvocationGrant {
    pub fn new(
        agent_id: AgentId,
        task_id: TaskId,
        budget: BudgetCeiling,
    ) -> Result<Self, ContractError> {
        let grant = Self {
            schema_version: 1,
            agent_id,
            task_id,
            capabilities: Vec::new(),
            tools: ToolCeiling::default(),
            budget,
            route: None,
            context: BTreeMap::new(),
        };
        grant.validate()?;
        Ok(grant)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        if self.budget.max_active_time_ms == 0 {
            return Err(ContractError::InvalidContract {
                path: "budget.max_active_time_ms".into(),
                reason: "must be positive".into(),
            });
        }
        Ok(())
    }
}
