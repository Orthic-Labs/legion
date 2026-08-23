use legion_contracts::{
    AgentDefinition, BudgetCeiling, InvocationGrant, RoutingCeiling, ToolCeiling,
};

use crate::error::RuntimeError;

/// Immutable definition-side profile. Invocation state is kept in a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProfile {
    definition: AgentDefinition,
}

impl AgentProfile {
    pub fn new(definition: AgentDefinition) -> Result<Self, RuntimeError> {
        definition
            .validate()
            .map_err(|error| RuntimeError::InvalidProfile(error.to_string()))?;
        Ok(Self { definition })
    }

    pub fn definition(&self) -> &AgentDefinition {
        &self.definition
    }
    pub fn id(&self) -> &legion_contracts::AgentId {
        &self.definition.id
    }
    pub fn budget(&self) -> &BudgetCeiling {
        &self.definition.budget
    }
    pub fn tools(&self) -> &ToolCeiling {
        &self.definition.tools
    }
    pub fn routing(&self) -> &RoutingCeiling {
        &self.definition.routing
    }

    pub fn authorize(&self, grant: InvocationGrant) -> Result<InvocationGrant, RuntimeError> {
        grant
            .validate()
            .map_err(|error| RuntimeError::GrantExceedsCeiling(error.to_string()))?;
        if grant.agent_id != self.definition.id {
            return Err(RuntimeError::GrantExceedsCeiling(
                "agent identity does not match definition".into(),
            ));
        }
        if grant.budget.max_active_time_ms > self.definition.budget.max_active_time_ms
            || grant.budget.max_cost_micros > self.definition.budget.max_cost_micros
            || grant.budget.max_output_bytes > self.definition.budget.max_output_bytes
        {
            return Err(RuntimeError::GrantExceedsCeiling(
                "budget exceeds definition".into(),
            ));
        }
        if grant
            .tools
            .allow
            .iter()
            .any(|tool| !self.definition.tools.allow.contains(tool))
        {
            return Err(RuntimeError::GrantExceedsCeiling(
                "tools exceed definition".into(),
            ));
        }
        if let Some(route) = &grant.route {
            let allowed = self.definition.routing.worker_profiles.is_empty()
                || self.definition.routing.worker_profiles.contains(route)
                || self.definition.routing.model_tiers.contains(route);
            if !allowed {
                return Err(RuntimeError::GrantExceedsCeiling(
                    "route exceeds definition".into(),
                ));
            }
        }
        if !self.definition.capabilities.is_empty()
            && grant
                .capabilities
                .iter()
                .any(|cap| !self.definition.capabilities.contains(cap))
        {
            return Err(RuntimeError::GrantExceedsCeiling(
                "capability exceeds definition".into(),
            ));
        }
        Ok(grant)
    }
}
