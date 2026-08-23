use legion_contracts::{AgentDefinition, InvocationGrant, ProviderId};

use crate::error::RuntimeError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCandidate {
    pub id: String,
    pub providers: Vec<ProviderId>,
    pub required_capabilities: Vec<String>,
    pub worst_case_cost_micros: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedRoute {
    pub id: String,
    pub providers: Vec<ProviderId>,
    pub worst_case_cost_micros: u64,
}

/// Selects only from explicit candidates. Stable route ID is the final tie-break.
pub fn select_route(
    candidates: &[RouteCandidate],
    definition: &AgentDefinition,
    grant: &InvocationGrant,
) -> Result<SelectedRoute, RuntimeError> {
    let mut eligible: Vec<&RouteCandidate> = candidates
        .iter()
        .filter(|candidate| {
            candidate.required_capabilities.iter().all(|capability| {
                definition.capabilities.contains(capability)
                    && grant.capabilities.contains(capability)
            }) && grant.budget.max_cost_micros >= candidate.worst_case_cost_micros
                && grant
                    .route
                    .as_deref()
                    .is_none_or(|route| route == candidate.id)
        })
        .collect();
    eligible.sort_by(|left, right| {
        left.worst_case_cost_micros
            .cmp(&right.worst_case_cost_micros)
            .then_with(|| left.id.cmp(&right.id))
    });
    let Some(route) = eligible.first() else {
        return Err(RuntimeError::Route("route_capability_not_granted".into()));
    };
    Ok(SelectedRoute {
        id: route.id.clone(),
        providers: route.providers.clone(),
        worst_case_cost_micros: route.worst_case_cost_micros,
    })
}
