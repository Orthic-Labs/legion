use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::{goalroute::GoalRoute, Diagnostic, ValidationReport};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub number: u32,
    pub route_step: String,
    pub action: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub advances_state_b: String,
    pub status: String,
    pub done_check: String,
    pub expected_result: String,
    pub evidence_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskList {
    pub schema_version: u32,
    pub tasklist_id: String,
    pub owner: String,
    pub canonical_path: String,
    pub goal_route_artifact: String,
    pub goal_route_receipt: String,
    pub route_revision: u64,
    pub selected_route: String,
    pub tasks: Vec<Task>,
    pub status: String,
}

pub fn validate_task_list(list: &TaskList, route: &GoalRoute) -> ValidationReport {
    let mut errors = Vec::new();
    let source = list.tasklist_id.as_str();
    if list.schema_version != 1
        || list.tasklist_id.trim().is_empty()
        || list.owner.trim().is_empty()
        || list.canonical_path.trim().is_empty()
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "schema_version/tasklist_id/owner/canonical_path",
            "INVALID_INPUT_OR_SCHEMA",
            "task-list identity fields are required",
        ));
    }
    if list.goal_route_artifact.trim().is_empty() || list.goal_route_receipt.trim().is_empty() {
        errors.push(Diagnostic::error(
            source,
            0,
            "goal_route_artifact/goal_route_receipt",
            "REFERENCE_RESOLUTION_FAILED",
            "task artifact and receipt paths are required",
        ));
    }
    if list.selected_route != route.selected_route_id
        || list.route_revision != route.invalidation.revision
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "selected_route/route_revision",
            "INTEGRITY_OR_HASH_MISMATCH",
            "task-list must mirror bound GoalRoute",
        ));
    }
    if !matches!(
        list.status.as_str(),
        "PLANNED" | "IN_PROGRESS" | "COMPLETE" | "TRUE_BLOCKER"
    ) {
        errors.push(Diagnostic::error(
            source,
            0,
            "status",
            "INVALID_INPUT_OR_SCHEMA",
            "invalid task-list status",
        ));
    }
    let Some(candidate) = route
        .candidates
        .iter()
        .find(|item| item.id == route.selected_route_id)
    else {
        errors.push(Diagnostic::error(
            source,
            0,
            "selected_route",
            "REFERENCE_RESOLUTION_FAILED",
            "selected route candidate is missing",
        ));
        return ValidationReport::from_diagnostics(errors);
    };
    if list.tasks.len() != candidate.steps.len() {
        errors.push(Diagnostic::error(
            source,
            0,
            "tasks",
            "SEMANTIC_BOUNDS_FAILED",
            "task count must equal selected route step count",
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, task) in list.tasks.iter().enumerate() {
        let Some(step) = candidate.steps.get(index) else {
            break;
        };
        if task.number != index as u32 + 1 {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "tasks.number",
                "DAG_ORDERING_FAILED",
                "task numbers must be contiguous from one",
            ));
        }
        if task.route_step != step.id
            || task.action != step.operation
            || task.advances_state_b != step.b_state_delta
        {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "tasks",
                "INTEGRITY_OR_HASH_MISMATCH",
                "task does not mirror selected route step",
            ));
        }
        if task.depends_on != step.depends_on {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "tasks.depends_on",
                "DAG_ORDERING_FAILED",
                "task dependency contract does not mirror route",
            ));
        }
        if task
            .depends_on
            .iter()
            .any(|dependency| !seen.contains(dependency))
        {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "tasks.depends_on",
                "DAG_ORDERING_FAILED",
                "task list is not topologically ordered",
            ));
        }
        seen.insert(step.id.clone());
        if !matches!(
            task.status.as_str(),
            "TODO" | "IN_PROGRESS" | "DONE" | "TRUE_BLOCKER"
        ) || task.done_check.trim().is_empty()
            || task.expected_result.trim().is_empty()
            || task.evidence_path.trim().is_empty()
        {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "tasks",
                "INVALID_INPUT_OR_SCHEMA",
                "task requires valid status, check, expected result, and evidence path",
            ));
        }
    }
    ValidationReport::from_diagnostics(errors)
}
