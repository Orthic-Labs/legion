use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonical_digest,
    id::{NodeId, PlanId, ProviderId},
    receipt::ExecutorBindingOutcome,
    require_version, ContractError,
};

/// The semantic interpretation required by an executor. The wire spelling
/// matches the `executorRequirement` object used by dispatch packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionSemanticRequirement {
    Forbidden,
    Conditional,
    Required,
}

/// One independently checkable completion condition for an executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCompletionCheck {
    pub kind: String,
    pub id: String,
}

/// Bounded escalation policy for an executor requirement.
///
/// Outcomes deliberately reuse the receipt vocabulary so a host can carry a
/// plan requirement into an `ExecutorBindingReceiptV1` without translating
/// outcome names. In particular, `Denied` is never an escalation trigger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecutionEscalationPolicy {
    pub permitted_on: Vec<ExecutorBindingOutcome>,
    pub forbidden_on: Vec<ExecutorBindingOutcome>,
}

/// Portable, host-neutral executor requirements for one materialized node.
///
/// This is the LEG-MR-4 Option B staging shape. Requirements live in a map on
/// `Plan`, keyed by `NodeId`, while `PlanNode` remains unchanged so existing
/// producers and consumers continue to compile. Option A can later move this
/// value onto `PlanNode` and retain this map as a compatibility projection;
/// the requirement's shape and digest semantics do not need to change again.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecutionRequirementV1 {
    pub semantic_requirement: ExecutionSemanticRequirement,
    pub capabilities: Vec<String>,
    pub effects: Vec<String>,
    pub authority_ceiling: Vec<String>,
    pub completion: Vec<ExecutionCompletionCheck>,
    pub escalation: ExecutionEscalationPolicy,
}

impl ExecutionRequirementV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        for (path, values) in [
            ("capabilities", &self.capabilities),
            ("effects", &self.effects),
            ("authority_ceiling", &self.authority_ceiling),
        ] {
            if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
                return Err(ContractError::InvalidContract {
                    path: path.into(),
                    reason: "must contain non-empty values".into(),
                });
            }
            let unique: BTreeSet<_> = values.iter().collect();
            if unique.len() != values.len() {
                return Err(ContractError::InvalidContract {
                    path: path.into(),
                    reason: "must not contain duplicate values".into(),
                });
            }
        }
        if self.completion.is_empty()
            || self
                .completion
                .iter()
                .any(|check| check.kind.trim().is_empty() || check.id.trim().is_empty())
        {
            return Err(ContractError::InvalidContract {
                path: "completion".into(),
                reason: "must contain checks with non-empty kind and id".into(),
            });
        }
        let completion_ids: BTreeSet<_> = self.completion.iter().map(|check| &check.id).collect();
        if completion_ids.len() != self.completion.len() {
            return Err(ContractError::InvalidContract {
                path: "completion".into(),
                reason: "check ids must be unique".into(),
            });
        }
        for (path, outcomes) in [
            ("escalation.permitted_on", &self.escalation.permitted_on),
            ("escalation.forbidden_on", &self.escalation.forbidden_on),
        ] {
            if outcomes
                .iter()
                .enumerate()
                .any(|(index, outcome)| outcomes[..index].contains(outcome))
            {
                return Err(ContractError::InvalidContract {
                    path: path.into(),
                    reason: "must not contain duplicate outcomes".into(),
                });
            }
        }
        if self
            .escalation
            .permitted_on
            .iter()
            .any(|outcome| self.escalation.forbidden_on.contains(outcome))
        {
            return Err(ContractError::InvalidContract {
                path: "escalation".into(),
                reason: "permitted and forbidden outcomes must not overlap".into(),
            });
        }
        if self
            .escalation
            .permitted_on
            .contains(&ExecutorBindingOutcome::Denied)
        {
            return Err(ContractError::InvalidContract {
                path: "escalation.permitted_on".into(),
                reason: "denied may never permit escalation".into(),
            });
        }
        if self.semantic_requirement == ExecutionSemanticRequirement::Forbidden
            && !self.escalation.permitted_on.is_empty()
        {
            return Err(ContractError::InvalidContract {
                path: "escalation.permitted_on".into(),
                reason: "forbidden semantic requirement cannot escalate".into(),
            });
        }
        if self.semantic_requirement == ExecutionSemanticRequirement::Conditional
            && self.escalation.permitted_on.is_empty()
        {
            return Err(ContractError::InvalidContract {
                path: "escalation.permitted_on".into(),
                reason: "conditional semantic requirement needs escalation outcomes".into(),
            });
        }
        Ok(())
    }
}

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
    /// Option B's additive requirement map. `default` keeps plans serialized
    /// before LEG-MR-4 readable and lets existing producers omit requirements.
    #[serde(default)]
    pub executor_requirements: BTreeMap<NodeId, ExecutionRequirementV1>,
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
            executor_requirements: BTreeMap::new(),
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
        for (node_id, requirement) in &self.executor_requirements {
            if !ids.contains(node_id) {
                return Err(ContractError::InvalidContract {
                    path: "executor_requirements".into(),
                    reason: "requirement references unknown node id".into(),
                });
            }
            requirement.validate().map_err(|error| match error {
                ContractError::InvalidContract { path, reason } => ContractError::InvalidContract {
                    path: format!("executor_requirements.{node_id}.{path}"),
                    reason,
                },
                other => other,
            })?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, depends_on: &[&str]) -> PlanNode {
        PlanNode {
            id: NodeId::new(id).unwrap(),
            kind: PlanNodeKind::Provider,
            provider: Some(ProviderId::new("provider-1").unwrap()),
            depends_on: depends_on
                .iter()
                .map(|dependency| NodeId::new(*dependency).unwrap())
                .collect(),
            configuration: BTreeMap::new(),
        }
    }

    fn requirement() -> ExecutionRequirementV1 {
        ExecutionRequirementV1 {
            semantic_requirement: ExecutionSemanticRequirement::Conditional,
            capabilities: vec!["filesystem".into()],
            effects: vec!["FILE_WRITE".into()],
            authority_ceiling: vec!["ambient".into()],
            completion: vec![ExecutionCompletionCheck {
                kind: "artifact".into(),
                id: "artifact-1".into(),
            }],
            escalation: ExecutionEscalationPolicy {
                permitted_on: vec![ExecutorBindingOutcome::Unreachable],
                forbidden_on: vec![ExecutorBindingOutcome::Denied],
            },
        }
    }

    fn sample() -> Plan {
        let mut executor_requirements = BTreeMap::new();
        executor_requirements.insert(NodeId::new("node-1").unwrap(), requirement());
        Plan {
            schema_version: 1,
            id: PlanId::new("plan-1").unwrap(),
            nodes: vec![node("node-1", &[]), node("node-2", &["node-1"])],
            providers: vec![ProviderId::new("provider-1").unwrap()],
            resources: BTreeMap::new(),
            executor_requirements,
        }
    }

    #[test]
    fn round_trips_a_plan_with_executor_requirements_through_json() {
        let plan = sample();
        plan.validate().expect("sample plan is valid");
        let json = serde_json::to_string(&plan).expect("serialize");
        let parsed: Plan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(plan, parsed);
        parsed
            .validate()
            .expect("round-tripped plan with requirements is valid");
    }

    #[test]
    fn legacy_plan_json_without_executor_requirements_defaults_to_empty() {
        let legacy_json = r#"
        {
            "schema_version": 1,
            "id": "legacy-plan",
            "nodes": [
                {
                    "id": "node-1",
                    "kind": "provider",
                    "provider": "provider-1",
                    "depends_on": [],
                    "configuration": {}
                }
            ],
            "providers": ["provider-1"],
            "resources": {}
        }
        "#;

        let plan: Plan = serde_json::from_str(legacy_json).expect("legacy plan parses");
        assert!(plan.executor_requirements.is_empty());
        plan.validate().expect("legacy plan remains valid");
    }

    #[test]
    fn accepts_a_well_formed_requirement_and_plan() {
        requirement().validate().expect("requirement is valid");
        sample().validate().expect("plan is valid");
    }

    #[test]
    fn rejects_empty_required_requirement_fields() {
        for field in ["capabilities", "effects", "authority_ceiling"] {
            let mut invalid = requirement();
            match field {
                "capabilities" => invalid.capabilities = vec![],
                "effects" => invalid.effects = vec![" ".into()],
                "authority_ceiling" => invalid.authority_ceiling = vec![],
                _ => unreachable!(),
            }
            assert!(invalid.validate().is_err(), "empty {field} must be rejected");
        }

        let mut empty_completion = requirement();
        empty_completion.completion = vec![];
        assert!(empty_completion.validate().is_err());

        let mut empty_kind = requirement();
        empty_kind.completion[0].kind = " ".into();
        assert!(empty_kind.validate().is_err());

        let mut empty_id = requirement();
        empty_id.completion[0].id = "".into();
        assert!(empty_id.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_requirement_values_and_completion_ids() {
        for field in ["capabilities", "effects", "authority_ceiling"] {
            let mut invalid = requirement();
            match field {
                "capabilities" => invalid.capabilities = vec!["same".into(), "same".into()],
                "effects" => invalid.effects = vec!["same".into(), "same".into()],
                "authority_ceiling" => {
                    invalid.authority_ceiling = vec!["same".into(), "same".into()]
                }
                _ => unreachable!(),
            }
            assert!(invalid.validate().is_err(), "duplicate {field} must be rejected");
        }

        let mut duplicate_ids = requirement();
        duplicate_ids.completion.push(ExecutionCompletionCheck {
            kind: "other-artifact".into(),
            id: "artifact-1".into(),
        });
        assert!(duplicate_ids.validate().is_err());
    }

    #[test]
    fn rejects_malformed_escalation_policies() {
        let mut duplicate_permitted = requirement();
        duplicate_permitted.escalation.permitted_on = vec![
            ExecutorBindingOutcome::Unreachable,
            ExecutorBindingOutcome::Unreachable,
        ];
        assert!(duplicate_permitted.validate().is_err());

        let mut duplicate_forbidden = requirement();
        duplicate_forbidden.escalation.forbidden_on = vec![
            ExecutorBindingOutcome::Denied,
            ExecutorBindingOutcome::Denied,
        ];
        assert!(duplicate_forbidden.validate().is_err());

        let mut overlap = requirement();
        overlap.escalation.forbidden_on = vec![ExecutorBindingOutcome::Unreachable];
        assert!(overlap.validate().is_err());

        let mut denied_permitted = requirement();
        denied_permitted.escalation.permitted_on = vec![ExecutorBindingOutcome::Denied];
        assert!(denied_permitted.validate().is_err());

        let mut forbidden_with_escalation = requirement();
        forbidden_with_escalation.semantic_requirement = ExecutionSemanticRequirement::Forbidden;
        assert!(forbidden_with_escalation.validate().is_err());

        let mut conditional_without_escalation = requirement();
        conditional_without_escalation.escalation.permitted_on = vec![];
        assert!(conditional_without_escalation.validate().is_err());
    }

    #[test]
    fn allows_a_forbidden_semantic_requirement_without_escalation() {
        let mut forbidden = requirement();
        forbidden.semantic_requirement = ExecutionSemanticRequirement::Forbidden;
        forbidden.escalation.permitted_on = vec![];
        forbidden.validate().expect("forbidden requirement is valid");
    }

    #[test]
    fn rejects_unknown_or_dangling_node_references() {
        let mut dangling_dependency = sample();
        dangling_dependency.nodes[1].depends_on = vec![NodeId::new("missing").unwrap()];
        assert!(dangling_dependency.validate().is_err());

        let mut unknown_requirement = sample();
        unknown_requirement
            .executor_requirements
            .insert(NodeId::new("missing").unwrap(), requirement());
        assert!(unknown_requirement.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_nodes_duplicate_providers_and_cycles() {
        let mut duplicate_nodes = sample();
        duplicate_nodes.nodes.push(node("node-1", &[]));
        assert!(duplicate_nodes.validate().is_err());

        let mut duplicate_providers = sample();
        duplicate_providers
            .providers
            .push(ProviderId::new("provider-1").unwrap());
        assert!(duplicate_providers.validate().is_err());

        let mut cycle = sample();
        cycle.nodes = vec![node("node-1", &["node-2"]), node("node-2", &["node-1"])];
        assert!(cycle.validate().is_err());
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let mut plan = sample();
        plan.schema_version = 2;
        assert!(plan.validate().is_err());

        let json = serde_json::to_string(&plan).expect("serialize");
        let parsed: Result<Plan, _> = serde_json::from_str(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn canonical_digest_is_stable_and_changes_for_a_material_difference() {
        let first = sample();
        let second = sample();
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());

        let mut different = sample();
        different
            .executor_requirements
            .get_mut(&NodeId::new("node-1").unwrap())
            .unwrap()
            .effects = vec!["FILE_DELETE".into()];
        assert_ne!(first.digest().unwrap(), different.digest().unwrap());
    }
}
