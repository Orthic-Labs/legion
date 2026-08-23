use std::collections::BTreeSet;

use legion_contracts::{AgentDefinition, AgentId};

use crate::error::RuntimeError;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EscalationGrant {
    pub permitted_targets: BTreeSet<AgentId>,
}

pub fn validate_target(
    definition: &AgentDefinition,
    target: &AgentId,
    grant: &EscalationGrant,
) -> Result<(), RuntimeError> {
    if !definition.escalation_graph.contains(target) {
        return Err(RuntimeError::Escalation(format!(
            "target {target} is absent from definition graph"
        )));
    }
    if !grant.permitted_targets.contains(target) {
        return Err(RuntimeError::Escalation(format!(
            "target {target} is not permitted by invocation"
        )));
    }
    Ok(())
}
