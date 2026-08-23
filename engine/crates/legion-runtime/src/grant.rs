use legion_contracts::{
    AgentDefinition, BudgetCeiling, InvocationGrant, RoutingCeiling, ToolCeiling,
};

use crate::error::RuntimeError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveGrant {
    pub agent_id: legion_contracts::AgentId,
    pub task_id: legion_contracts::TaskId,
    pub capabilities: Vec<String>,
    pub tools: ToolCeiling,
    pub budget: BudgetCeiling,
    pub route: Option<String>,
}

impl EffectiveGrant {
    pub fn from_definition(
        definition: &AgentDefinition,
        invocation: &InvocationGrant,
    ) -> Result<Self, RuntimeError> {
        if definition.id != invocation.agent_id {
            return Err(RuntimeError::GrantExceedsCeiling("agent mismatch".into()));
        }
        if invocation.budget.max_active_time_ms > definition.budget.max_active_time_ms
            || invocation.budget.max_cost_micros > definition.budget.max_cost_micros
            || invocation.budget.max_output_bytes > definition.budget.max_output_bytes
        {
            return Err(RuntimeError::GrantExceedsCeiling(
                "budget exceeds definition".into(),
            ));
        }
        let capabilities = if invocation.capabilities.is_empty() {
            definition.capabilities.clone()
        } else {
            if invocation
                .capabilities
                .iter()
                .any(|item| !definition.capabilities.contains(item))
            {
                return Err(RuntimeError::GrantExceedsCeiling(
                    "capabilities exceed definition".into(),
                ));
            }
            invocation.capabilities.clone()
        };
        let tools = intersect_tools(&definition.tools, &invocation.tools)?;
        let route = invocation.route.clone();
        if let Some(value) = &route {
            let routing: &RoutingCeiling = &definition.routing;
            if !routing.worker_profiles.is_empty()
                && !routing.worker_profiles.contains(value)
                && !routing.model_tiers.contains(value)
            {
                return Err(RuntimeError::GrantExceedsCeiling(
                    "route exceeds definition".into(),
                ));
            }
        }
        Ok(Self {
            agent_id: invocation.agent_id.clone(),
            task_id: invocation.task_id.clone(),
            capabilities,
            tools,
            budget: invocation.budget.clone(),
            route,
        })
    }
}

fn intersect_tools(
    definition: &ToolCeiling,
    invocation: &ToolCeiling,
) -> Result<ToolCeiling, RuntimeError> {
    if invocation
        .allow
        .iter()
        .any(|tool| !definition.allow.is_empty() && !definition.allow.contains(tool))
    {
        return Err(RuntimeError::GrantExceedsCeiling(
            "tool allow exceeds definition".into(),
        ));
    }
    let mut allow = if invocation.allow.is_empty() {
        definition.allow.clone()
    } else {
        invocation.allow.clone()
    };
    allow.sort();
    allow.dedup();
    let mut deny = definition.deny.clone();
    deny.extend(invocation.deny.clone());
    deny.sort();
    deny.dedup();
    Ok(ToolCeiling { allow, deny })
}
