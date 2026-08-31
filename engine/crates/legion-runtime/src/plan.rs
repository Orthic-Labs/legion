use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{
    ExecutionCompletionCheck, ExecutionEscalationPolicy, ExecutionRequirementV1,
    ExecutionSemanticRequirement, ExecutorBindingOutcome, NodeId, Plan, PlanId, PlanNode,
    PlanNodeKind, ProviderId, TaskSpec,
};
use legion_provider_sdk::ProviderRegistry;

use crate::{error::RuntimeError, route::SelectedRoute};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenPlan {
    plan: Plan,
}

impl FrozenPlan {
    pub fn new(plan: Plan) -> Result<Self, RuntimeError> {
        plan.validate()
            .map_err(|error| RuntimeError::Plan(error.to_string()))?;
        Ok(Self { plan })
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn into_inner(self) -> Plan {
        self.plan
    }
}

pub fn compile_plan(
    task: &TaskSpec,
    registry: &ProviderRegistry,
    route: &SelectedRoute,
) -> Result<FrozenPlan, RuntimeError> {
    let allowed: BTreeSet<ProviderId> = if route.providers.is_empty() {
        registry.order().iter().cloned().collect()
    } else {
        route.providers.iter().cloned().collect()
    };
    let mut nodes = Vec::new();
    let mut provider_ids = Vec::new();
    for provider_id in registry.order() {
        if !allowed.contains(provider_id) {
            continue;
        }
        let definition = registry.definition(provider_id).ok_or_else(|| {
            RuntimeError::Plan(format!("provider {provider_id} missing definition"))
        })?;
        let id = NodeId::new(provider_id.as_str()).map_err(RuntimeError::from)?;
        let depends_on = definition
            .depends_on
            .iter()
            .filter(|dependency| allowed.contains(*dependency))
            .map(|dependency| NodeId::new(dependency.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(RuntimeError::from)?;
        let operations = values_with_prefix(&definition.permissions, "operation:");
        let effects = values_with_prefix(&definition.permissions, "effect:");
        let authority = values_with_prefix(&definition.permissions, "authority:");
        let requirement = ExecutionRequirementV1 {
            semantic_requirement: ExecutionSemanticRequirement::Required,
            capabilities: non_empty_or(
                definition.capabilities.clone(),
                format!("provider:{}", provider_id),
            ),
            operations: non_empty_or(operations, definition.implementation_key.clone()),
            effects: non_empty_or(effects, "PROVIDER_EXECUTION".into()),
            authority_ceiling: non_empty_or(authority, "ambient".into()),
            completion: vec![ExecutionCompletionCheck {
                kind: "provider-result".into(),
                id: format!("{}:complete", provider_id),
            }],
            escalation: ExecutionEscalationPolicy {
                permitted_on: vec![ExecutorBindingOutcome::Unsupported],
                forbidden_on: vec![ExecutorBindingOutcome::Denied],
            },
        };
        requirement.validate().map_err(RuntimeError::from)?;
        nodes.push(PlanNode {
            id,
            kind: PlanNodeKind::Provider,
            provider: Some(provider_id.clone()),
            depends_on,
            configuration: BTreeMap::new(),
            executor_requirement: Some(requirement),
        });
        provider_ids.push(provider_id.clone());
    }
    if nodes.is_empty() {
        return Err(RuntimeError::Plan(
            "route contains no registered providers".into(),
        ));
    }
    let plan_id = PlanId::new(format!("{}:{}", task.task_id, route.id))?;
    let plan = Plan::new(1, plan_id, nodes, provider_ids).map_err(RuntimeError::from)?;
    FrozenPlan::new(plan)
}

fn values_with_prefix(values: &[String], prefix: &str) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| value.strip_prefix(prefix).map(str::to_owned))
        .filter(|value| !value.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn non_empty_or(mut values: Vec<String>, fallback: String) -> Vec<String> {
    values.retain(|value| !value.trim().is_empty());
    values.sort();
    values.dedup();
    if values.is_empty() {
        vec![fallback]
    } else {
        values
    }
}

#[cfg(test)]
mod closure_tests {
    use super::*;

    #[test]
    fn leg_005_compiler_derives_operations_effects_and_authority_without_duplicates() {
        let permissions = vec![
            "operation:write".into(),
            "effect:FILE_WRITE".into(),
            "authority:ambient".into(),
            "operation:write".into(),
        ];
        assert_eq!(
            values_with_prefix(&permissions, "operation:"),
            vec!["write"]
        );
        assert_eq!(
            values_with_prefix(&permissions, "effect:"),
            vec!["FILE_WRITE"]
        );
        assert_eq!(
            values_with_prefix(&permissions, "authority:"),
            vec!["ambient"]
        );
        assert_eq!(
            non_empty_or(Vec::new(), "fallback".into()),
            vec!["fallback"]
        );
    }
}
