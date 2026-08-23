use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{NodeId, Plan, PlanId, PlanNode, PlanNodeKind, ProviderId, TaskSpec};
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
        nodes.push(PlanNode {
            id,
            kind: PlanNodeKind::Provider,
            provider: Some(provider_id.clone()),
            depends_on,
            configuration: BTreeMap::new(),
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
