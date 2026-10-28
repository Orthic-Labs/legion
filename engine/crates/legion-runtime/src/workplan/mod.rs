//! Deterministic admission of bounded work declarations, not another scheduler.
//!
//! Evidence supplied here is an imported assertion. Validation never executes a
//! check, reads an artifact, authenticates a person, grants effects, or issues an
//! Oracle/Guard receipt. Hosts retain those responsibilities.

use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{AgentId, NodeId, Plan, PlanId, PlanNode, PlanNodeKind, TaskId};
use serde::{Deserialize, Serialize};

mod validation;
pub use validation::validate_work_plan;

pub const MAX_WORK_PLAN_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_WORK_UNITS: usize = 128;
pub const MAX_UNIT_ITEMS: usize = 32;
pub const MAX_FIELD_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkPlan {
    pub schema_version: u32,
    pub plan_id: PlanId,
    pub units: Vec<WorkUnit>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkUnit {
    pub id: TaskId,
    pub owner: AgentId,
    pub access: WorkUnitAccess,
    /// Changes whenever the unit's intended work changes.
    pub revision: String,
    pub write_scopes: Vec<WriteScope>,
    pub depends_on: Vec<TaskId>,
    pub completion: Vec<CompletionPredicate>,
    pub evidence_requirements: Vec<EvidenceRequirement>,
    pub status: WorkUnitStatus,
    pub evidence: Vec<CompletionEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkUnitAccess {
    ReadOnly,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkUnitStatus {
    Pending,
    Complete,
}

/// All scopes are exclusive. An owner shared by two units is not serialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteScope {
    pub path: String,
    pub kind: WriteScopeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteScopeKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRevision {
    pub path: String,
    pub revision: String,
    /// Lowercase hexadecimal SHA-256 supplied by the caller, not recomputed here.
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionPredicate {
    pub id: String,
    /// Observable acceptance criterion interpreted by the producing capability.
    pub description: String,
    pub artifact: ArtifactRevision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRequirement {
    pub name: String,
    pub predicate_id: String,
    pub independent_review: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionEvidence {
    pub name: String,
    pub predicate_id: String,
    pub unit_id: TaskId,
    pub unit_revision: String,
    pub artifact: ArtifactRevision,
    pub author: AgentId,
    pub reviewer: Option<AgentId>,
    pub outcome: EvidenceOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkPlanAssessment {
    pub schema_version: u32,
    pub plan_id: PlanId,
    /// Stable lexical tie-breaking, using the existing contract plan ordering.
    pub topological_order: Vec<TaskId>,
    pub ready_units: Vec<TaskId>,
    /// Completion asserted in input and consistent with its declared evidence.
    pub asserted_complete_units: Vec<TaskId>,
    pub evidence_assurance: EvidenceAssurance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAssurance {
    ImportedAssertionsOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkPlanReasonCode {
    InvalidJson,
    UnsupportedVersion,
    InputLimit,
    EmptyField,
    InvalidField,
    DuplicateUnit,
    DuplicateItem,
    MissingDependency,
    SelfDependency,
    DependencyCycle,
    UnsafePath,
    ScopeConflict,
    MissingPredicate,
    MissingEvidence,
    UnexpectedEvidence,
    StaleEvidence,
    FailedEvidence,
    IndependentReviewRequired,
    DependencyIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?} at {field} (unit {unit:?}): {message}")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkPlanValidationError {
    pub code: WorkPlanReasonCode,
    pub field: String,
    pub unit: Option<TaskId>,
    pub message: String,
}

fn failure(
    code: WorkPlanReasonCode,
    field: &str,
    unit: Option<&WorkUnit>,
    message: &str,
) -> WorkPlanValidationError {
    WorkPlanValidationError {
        code,
        field: field.into(),
        unit: unit.map(|unit| unit.id.clone()),
        message: message.into(),
    }
}

/// Size-bounded JSON entry point for untrusted files. Unknown fields fail closed.
/// Use this before validation instead of unbounded generic JSON decoding.
pub fn parse_work_plan_json(bytes: &[u8]) -> Result<WorkPlan, WorkPlanValidationError> {
    if bytes.len() > MAX_WORK_PLAN_BYTES {
        return Err(failure(
            WorkPlanReasonCode::InputLimit,
            "input",
            None,
            "work plan exceeds byte limit",
        ));
    }
    serde_json::from_slice(bytes).map_err(|_| {
        failure(
            WorkPlanReasonCode::InvalidJson,
            "input",
            None,
            "expected a work-plan object with known fields and valid typed values",
        )
    })
}

fn ordered(plan: &WorkPlan) -> Result<Vec<TaskId>, WorkPlanValidationError> {
    // IDs have already been validated as TaskIds; reuse the existing Plan DAG
    // implementation instead of introducing an execution/scheduling subsystem.
    let nodes = plan
        .units
        .iter()
        .map(|unit| {
            Ok(PlanNode {
                id: NodeId::new(unit.id.as_str()).map_err(|_| {
                    failure(WorkPlanReasonCode::InvalidField, "id", Some(unit), "invalid unit id")
                })?,
                kind: PlanNodeKind::External,
                provider: None,
                depends_on: unit
                    .depends_on
                    .iter()
                    .map(|id| NodeId::new(id.as_str()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| failure(WorkPlanReasonCode::InvalidField, "depends_on", Some(unit), "invalid dependency id"))?,
                configuration: BTreeMap::new(),
                executor_requirement: None,
            })
        })
        .collect::<Result<Vec<_>, WorkPlanValidationError>>()?;
    let graph = Plan {
        schema_version: 1,
        id: plan.plan_id.clone(),
        nodes,
        providers: vec![],
        resources: BTreeMap::new(),
        executor_requirements: BTreeMap::new(),
    };
    graph
        .ordered_nodes()
        .map_err(|_| failure(WorkPlanReasonCode::DependencyCycle, "units.depends_on", None, "dependency graph contains a cycle"))?
        .into_iter()
        .map(|node| TaskId::new(node.id.as_str()).map_err(|_| failure(WorkPlanReasonCode::InvalidField, "id", None, "invalid ordered unit id")))
        .collect()
}

fn ancestors(plan: &WorkPlan, order: &[TaskId]) -> BTreeMap<TaskId, BTreeSet<TaskId>> {
    let units: BTreeMap<_, _> = plan.units.iter().map(|unit| (unit.id.clone(), unit)).collect();
    let mut result: BTreeMap<TaskId, BTreeSet<TaskId>> = BTreeMap::new();
    for id in order {
        let mut dependencies = BTreeSet::new();
        for dependency in &units[id].depends_on {
            dependencies.insert(dependency.clone());
            if let Some(transitive) = result.get(dependency) {
                dependencies.extend(transitive.iter().cloned());
            }
        }
        result.insert(id.clone(), dependencies);
    }
    result
}
