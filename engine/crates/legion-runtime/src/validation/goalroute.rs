use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::{Diagnostic, ValidationReport};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub locator: String,
    pub sha256: String,
    pub check: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateA {
    pub description: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub command: String,
    pub expected: String,
    pub evidence_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateB {
    pub description: String,
    pub proof: Vec<Proof>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraint {
    pub rule: String,
    pub evidence_locator: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteStep {
    pub id: String,
    pub operation: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub min_wall_ms: u64,
    pub kind: String,
    pub b_state_delta: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probabilities {
    pub retry: u32,
    pub terminal_failure: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCandidate {
    pub id: String,
    pub constraint_status: String,
    pub constraint_evidence: String,
    pub steps: Vec<RouteStep>,
    pub probabilities_bps: Probabilities,
    pub retry_cost_ms: u64,
    pub rework_cost_ms: u64,
    pub nominal_critical_path_ms: u64,
    pub expected_time_to_verified_b_ms: u64,
    pub cost_units: u64,
    pub risk_units: u64,
    pub rework_units: u64,
    pub status: String,
    #[serde(default)]
    pub dominance_reason: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParallelLane {
    pub id: String,
    pub steps: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bottleneck {
    pub step_id: String,
    pub bound_ms: u64,
    pub resource: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItem {
    pub item: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredItem {
    pub item: String,
    pub until: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invalidation {
    pub revision: u64,
    pub semantic_correction: String,
    pub invalidates: Vec<String>,
    pub source_fingerprint_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alchemist {
    pub required: bool,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub state_ref: Option<String>,
    #[serde(default)]
    pub checkpoint: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalRoute {
    pub schema: String,
    pub route_id: String,
    pub purpose: String,
    pub routine: bool,
    pub comparison_mode: String,
    pub state_a: StateA,
    pub state_b: StateB,
    pub constraints: BTreeMap<String, Constraint>,
    pub candidates: Vec<RouteCandidate>,
    pub selected_route_id: String,
    pub selected_critical_path: Vec<String>,
    pub parallel_lanes: Vec<ParallelLane>,
    pub bottleneck: Bottleneck,
    pub deleted_work: Vec<WorkItem>,
    pub deferred_work: Vec<DeferredItem>,
    #[serde(default)]
    pub single_feasible_evidence: Vec<String>,
    pub invalidation: Invalidation,
    #[serde(alias = "forge")]
    pub alchemist: Alchemist,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum RouteSelection {
    Exact(RouteCandidate),
    Invalid(ValidationReport),
    Ambiguous(Vec<String>),
}

pub fn validate_route(route: &GoalRoute) -> ValidationReport {
    let mut errors = Vec::new();
    let source = route.route_id.as_str();
    if route.schema != "goal-route.v2" {
        errors.push(Diagnostic::error(
            source,
            0,
            "schema",
            "INVALID_INPUT_OR_SCHEMA",
            "schema must equal goal-route.v2",
        ));
    }
    if route.route_id.trim().is_empty() {
        errors.push(Diagnostic::error(
            source,
            0,
            "route_id",
            "INVALID_INPUT_OR_SCHEMA",
            "route_id must be concrete",
        ));
    }
    if !matches!(route.purpose.as_str(), "DELIVERY" | "DIAGNOSTIC") {
        errors.push(Diagnostic::error(
            source,
            0,
            "purpose",
            "INVALID_INPUT_OR_SCHEMA",
            "purpose must be DELIVERY or DIAGNOSTIC",
        ));
    }
    if !matches!(
        route.comparison_mode.as_str(),
        "COMPARE" | "SINGLE_FEASIBLE"
    ) {
        errors.push(Diagnostic::error(
            source,
            0,
            "comparison_mode",
            "INVALID_INPUT_OR_SCHEMA",
            "comparison_mode must be COMPARE or SINGLE_FEASIBLE",
        ));
    }
    if route.state_a.description.trim().is_empty() || route.state_a.evidence.is_empty() {
        errors.push(Diagnostic::error(
            source,
            0,
            "state_a",
            "REFERENCE_RESOLUTION_FAILED",
            "state_a requires description and evidence",
        ));
    }
    for (index, evidence) in route.state_a.evidence.iter().enumerate() {
        if evidence.locator.trim().is_empty()
            || !valid_hex_digest(&evidence.sha256)
            || evidence.check.trim().is_empty()
        {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "state_a.evidence",
                "INTEGRITY_OR_HASH_MISMATCH",
                "evidence requires locator, lowercase SHA-256, and check",
            ));
        }
    }
    if route.state_b.description.trim().is_empty() || route.state_b.proof.is_empty() {
        errors.push(Diagnostic::error(
            source,
            0,
            "state_b",
            "REFERENCE_RESOLUTION_FAILED",
            "state_b requires description and proof",
        ));
    }
    for (index, proof) in route.state_b.proof.iter().enumerate() {
        if proof.command.trim().is_empty()
            || proof.expected.trim().is_empty()
            || proof.evidence_path.trim().is_empty()
        {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "state_b.proof",
                "REFERENCE_RESOLUTION_FAILED",
                "proof requires command, expected result, and evidence path",
            ));
        }
    }
    for key in ["authority", "safety", "scope", "quality", "cost"] {
        match route.constraints.get(key) {
            Some(value)
                if !value.rule.trim().is_empty() && !value.evidence_locator.trim().is_empty() => {}
            _ => errors.push(Diagnostic::error(
                source,
                0,
                format!("constraints.{key}"),
                "REFERENCE_RESOLUTION_FAILED",
                "constraint rule and evidence locator are required",
            )),
        }
    }
    for key in route.constraints.keys() {
        if !matches!(
            key.as_str(),
            "authority" | "safety" | "scope" | "quality" | "cost"
        ) {
            errors.push(Diagnostic::error(
                source,
                0,
                format!("constraints.{key}"),
                "INVALID_INPUT_OR_SCHEMA",
                "unknown constraint field",
            ));
        }
    }
    if route.comparison_mode == "COMPARE" && !(2..=3).contains(&route.candidates.len()) {
        errors.push(Diagnostic::error(
            source,
            0,
            "candidates",
            "SEMANTIC_BOUNDS_FAILED",
            "COMPARE requires two or three candidates",
        ));
    }
    if route.comparison_mode == "SINGLE_FEASIBLE"
        && (route.candidates.len() != 1 || route.single_feasible_evidence.is_empty())
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "single_feasible_evidence",
            "SEMANTIC_BOUNDS_FAILED",
            "SINGLE_FEASIBLE requires one candidate and infeasible-alternative evidence",
        ));
    }
    let mut ids = BTreeSet::new();
    for candidate in &route.candidates {
        if !ids.insert(candidate.id.clone()) {
            errors.push(Diagnostic::error(
                source,
                0,
                "candidates.id",
                "IDENTITY_NOT_UNIQUE",
                format!("duplicate candidate: {}", candidate.id),
            ));
        }
        validate_candidate(candidate, source, &mut errors);
    }
    let selected: Vec<_> = route
        .candidates
        .iter()
        .filter(|item| item.status == "SELECTED")
        .collect();
    if selected.len() != 1 {
        errors.push(Diagnostic::error(
            source,
            0,
            "candidates.status",
            "SEMANTIC_BOUNDS_FAILED",
            "exactly one candidate must be SELECTED",
        ));
    }
    if let Some(winner) = selected.first() {
        if route.selected_route_id != winner.id {
            errors.push(Diagnostic::error(
                source,
                0,
                "selected_route_id",
                "REFERENCE_RESOLUTION_FAILED",
                "selected_route_id must match SELECTED candidate",
            ));
        }
        validate_selected_path(route, winner, source, &mut errors);
        for candidate in route
            .candidates
            .iter()
            .filter(|item| item.constraint_status == "PASS" && item.id != winner.id)
        {
            if candidate.expected_time_to_verified_b_ms < winner.expected_time_to_verified_b_ms {
                errors.push(Diagnostic::error(
                    source,
                    0,
                    "selected_route_id",
                    "SEMANTIC_BOUNDS_FAILED",
                    format!("selected route is slower than {}", candidate.id),
                ));
            }
            if candidate.expected_time_to_verified_b_ms == winner.expected_time_to_verified_b_ms
                && dominates(candidate, winner)
            {
                errors.push(Diagnostic::error(
                    source,
                    0,
                    "selected_route_id",
                    "SEMANTIC_BOUNDS_FAILED",
                    format!("selected route is dominated by {}", candidate.id),
                ));
            }
        }
    }
    if route.invalidation.revision == 0
        || !valid_hex_digest(&route.invalidation.source_fingerprint_sha256)
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "invalidation",
            "INVALID_INPUT_OR_SCHEMA",
            "revision and lowercase SHA-256 source fingerprint are required",
        ));
    }
    if route.invalidation.revision > 1
        && (route.invalidation.semantic_correction != "RECOMPILED_FROM_ROOT"
            || route.invalidation.invalidates.is_empty())
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "invalidation",
            "SEMANTIC_BOUNDS_FAILED",
            "recompiled routes must identify invalidated routes",
        ));
    }
    if !route.routine && !route.alchemist.required {
        errors.push(Diagnostic::error(
            source,
            0,
            "alchemist",
            "SEMANTIC_BOUNDS_FAILED",
            "non-routine route requires Alchemist",
        ));
    }
    ValidationReport::from_diagnostics(errors)
}

pub fn select_route(route: &GoalRoute) -> RouteSelection {
    let report = validate_route(route);
    if !report.is_valid() {
        return RouteSelection::Invalid(report);
    }
    let mut eligible: Vec<_> = route
        .candidates
        .iter()
        .filter(|item| item.constraint_status == "PASS")
        .collect();
    eligible.sort_by_key(|item| {
        (
            item.expected_time_to_verified_b_ms,
            item.cost_units,
            item.risk_units,
            item.rework_units,
            item.id.clone(),
        )
    });
    if eligible.is_empty() {
        return RouteSelection::Invalid(ValidationReport::from_diagnostics(vec![
            Diagnostic::error(
                route.route_id.clone(),
                0,
                "candidates",
                "SEMANTIC_BOUNDS_FAILED",
                "no feasible route candidate",
            ),
        ]));
    }
    let best = eligible[0];
    let ties: Vec<_> = eligible
        .iter()
        .filter(|item| {
            item.expected_time_to_verified_b_ms == best.expected_time_to_verified_b_ms
                && item.cost_units == best.cost_units
                && item.risk_units == best.risk_units
                && item.rework_units == best.rework_units
        })
        .map(|item| item.id.clone())
        .collect();
    if ties.len() > 1 {
        return RouteSelection::Ambiguous(ties);
    }
    RouteSelection::Exact(best.clone())
}

fn validate_candidate(candidate: &RouteCandidate, source: &str, errors: &mut Vec<Diagnostic>) {
    if candidate.id.trim().is_empty() {
        errors.push(Diagnostic::error(
            source,
            0,
            "candidates.id",
            "INVALID_INPUT_OR_SCHEMA",
            "candidate id is required",
        ));
    }
    if !matches!(candidate.constraint_status.as_str(), "PASS" | "FAIL") {
        errors.push(Diagnostic::error(
            source,
            0,
            format!("candidates.{}.constraint_status", candidate.id),
            "INVALID_INPUT_OR_SCHEMA",
            "constraint status must PASS or FAIL",
        ));
    }
    if candidate.constraint_evidence.trim().is_empty()
        || candidate.evidence.is_empty()
        || candidate.evidence.iter().any(|item| item.trim().is_empty())
    {
        errors.push(Diagnostic::error(
            source,
            0,
            format!("candidates.{}.evidence", candidate.id),
            "REFERENCE_RESOLUTION_FAILED",
            "candidate constraint and evidence locators are required",
        ));
    }
    if candidate.probabilities_bps.retry + candidate.probabilities_bps.terminal_failure > 10_000 {
        errors.push(Diagnostic::error(
            source,
            0,
            format!("candidates.{}.probabilities_bps", candidate.id),
            "SEMANTIC_BOUNDS_FAILED",
            "probabilities exceed 10000 basis points",
        ));
    }
    let nominal = critical_path(&candidate.steps).unwrap_or(0);
    if nominal != candidate.nominal_critical_path_ms {
        errors.push(Diagnostic::error(
            source,
            0,
            format!("candidates.{}.nominal_critical_path_ms", candidate.id),
            "SEMANTIC_BOUNDS_FAILED",
            format!("must equal computed {nominal}"),
        ));
    }
    let expected = nominal
        .saturating_add(ceil_bps(
            candidate.probabilities_bps.retry,
            candidate.retry_cost_ms,
        ))
        .saturating_add(ceil_bps(
            candidate.probabilities_bps.terminal_failure,
            candidate.rework_cost_ms,
        ));
    if expected != candidate.expected_time_to_verified_b_ms {
        errors.push(Diagnostic::error(
            source,
            0,
            format!("candidates.{}.expected_time_to_verified_b_ms", candidate.id),
            "SEMANTIC_BOUNDS_FAILED",
            format!("must equal computed {expected}"),
        ));
    }
    for (index, step) in candidate.steps.iter().enumerate() {
        if step.id.trim().is_empty()
            || step.operation.trim().is_empty()
            || step.min_wall_ms == 0
            || step.b_state_delta.trim().is_empty()
        {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                format!("candidates.{}.steps", candidate.id),
                "INVALID_INPUT_OR_SCHEMA",
                "step requires id, operation, positive bound, and state delta",
            ));
        }
    }
    if candidate.status == "SELECTED" && candidate.constraint_status != "PASS" {
        errors.push(Diagnostic::error(
            source,
            0,
            format!("candidates.{}.status", candidate.id),
            "OWNERSHIP_OR_CAPABILITY_FAILED",
            "selected candidate must pass constraints",
        ));
    }
    if candidate.status == "REJECTED"
        && candidate.constraint_status == "PASS"
        && candidate
            .dominance_reason
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        errors.push(Diagnostic::error(
            source,
            0,
            format!("candidates.{}.dominance_reason", candidate.id),
            "SEMANTIC_BOUNDS_FAILED",
            "passing rejected candidate requires dominance reason",
        ));
    }
}

fn critical_path(steps: &[RouteStep]) -> Option<u64> {
    let by_id: BTreeMap<_, _> = steps.iter().map(|step| (step.id.as_str(), step)).collect();
    let mut values = BTreeMap::new();
    while values.len() < steps.len() {
        let ready = by_id
            .iter()
            .filter(|(id, step)| {
                !values.contains_key(*id)
                    && step
                        .depends_on
                        .iter()
                        .all(|dependency| values.contains_key(dependency.as_str()))
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return None;
        }
        for id in ready {
            let step = by_id[id];
            let prior = step
                .depends_on
                .iter()
                .filter_map(|dependency| values.get(dependency.as_str()).copied())
                .max()
                .unwrap_or(0);
            values.insert(id, step.min_wall_ms.saturating_add(prior));
        }
    }
    Some(values.values().copied().max().unwrap_or(0))
}

fn validate_selected_path(
    route: &GoalRoute,
    winner: &RouteCandidate,
    source: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if route.selected_critical_path.is_empty() {
        errors.push(Diagnostic::error(
            source,
            0,
            "selected_critical_path",
            "DAG_ORDERING_FAILED",
            "critical path must be non-empty",
        ));
        return;
    }
    let by_id: BTreeMap<_, _> = winner
        .steps
        .iter()
        .map(|step| (step.id.as_str(), step))
        .collect();
    let mut total = 0;
    for (index, id) in route.selected_critical_path.iter().enumerate() {
        let Some(step) = by_id.get(id.as_str()) else {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "selected_critical_path",
                "REFERENCE_RESOLUTION_FAILED",
                format!("unknown step {id}"),
            ));
            continue;
        };
        total += step.min_wall_ms;
        if index > 0
            && !step
                .depends_on
                .iter()
                .any(|dep| dep == &route.selected_critical_path[index - 1])
        {
            errors.push(Diagnostic::error(
                source,
                index as u32,
                "selected_critical_path",
                "DAG_ORDERING_FAILED",
                "path must follow direct dependency edges",
            ));
        }
    }
    if total != winner.nominal_critical_path_ms {
        errors.push(Diagnostic::error(
            source,
            0,
            "selected_critical_path",
            "SEMANTIC_BOUNDS_FAILED",
            "path total must equal nominal critical path",
        ));
    }
}

fn dominates(left: &RouteCandidate, right: &RouteCandidate) -> bool {
    [
        left.cost_units < right.cost_units,
        left.risk_units < right.risk_units,
        left.rework_units < right.rework_units,
    ]
    .iter()
    .any(|item| *item)
        && left.cost_units <= right.cost_units
        && left.risk_units <= right.risk_units
        && left.rework_units <= right.rework_units
}
fn ceil_bps(value: u32, cost: u64) -> u64 {
    (u64::from(value) * cost).div_ceil(10_000)
}
fn valid_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}
