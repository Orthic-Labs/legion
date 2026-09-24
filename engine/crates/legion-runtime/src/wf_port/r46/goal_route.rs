//! Port of `goal_route_errors()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~1489-1789).
//! Validates the `## 1C. Goal Route & Critical Path` section of a dispatch
//! document, cross-referencing a declared GoalRoute JSON artifact and
//! receipt via [`super::goal_route_validator`].

use super::goal_route_validator::{validate_receipt, validate_route};
use super::dependency::parse_dependency_contract;
use super::labels::{action_re, authority_label_value, bound_re, is_concrete, path_re};
use super::route_scan::label_value;
use super::tables::table_rows;
use crate::wf_port::w2_045::path_utils::resolve_declared_path;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

fn selected_route_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^SELECTED_ROUTE:\s*").unwrap())
}

fn steps_re(route_id: &str) -> Regex {
    let escaped = regex::escape(route_id);
    Regex::new(&format!(
        r"(?i)^STEPS:({escaped}/[A-Z][A-Z0-9_-]*(?:>{escaped}/[A-Z][A-Z0-9_-]*)*)$"
    ))
    .unwrap()
}

fn constraint_pass_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^PASS:\s*\S").unwrap())
}

fn constraint_fail_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^FAIL:\s*\S").unwrap())
}

fn dominance_re(selected_label: &str) -> Regex {
    Regex::new(&format!(
        r"(?i)^(?:DOMINATED_BY:{}|TRADEOFF:)\s*\S",
        regex::escape(selected_label)
    ))
    .unwrap()
}

fn only_feasible_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^ONLY_FEASIBLE:EVIDENCE:\s*\S").unwrap())
}

fn critical_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)^CRITICAL_PATH:([^;]+);\s*TOTAL_MIN_WALL_MS:(\d+)$").unwrap())
}

/// A single row of the `## 1C.` route comparison table, decoded from its
/// 11 Markdown table cells.
struct RouteRow {
    id: String,
    steps: Vec<String>,
    roots: BTreeSet<String>,
    edges: BTreeSet<(String, String)>,
    pass: bool,
    wall: i64,
    expected: i64,
    cost: i64,
    risk: i64,
    rework: i64,
    status: String,
}

/// Port of `goal_route_errors()`. `artifact_path` mirrors the Python
/// parameter of the same name: the dispatch document's own path, used to
/// resolve `route_path_value`/`receipt_path_value` relative to its
/// repository root. Pass `None` when no artifact path is available (the
/// GoalRoute artifact/receipt cross-check is then skipped, matching the
/// Python `artifact_path is not None` guard).
pub fn goal_route_errors(text: &str, allow_template: bool, artifact_path: Option<&Path>) -> Vec<String> {
    if allow_template {
        return Vec::new();
    }
    let mut errors: Vec<String> = Vec::new();

    let rules: [(&str, Regex); 12] = [
        ("**State A:**", Regex::new(r"(?i)^STATE_A:\s*\S").unwrap()),
        ("**State B:**", Regex::new(r"(?i)^STATE_B:\s*\S").unwrap()),
        ("**Goal success proof:**", Regex::new(r"(?i)^PROOF:\s*\S").unwrap()),
        (
            "**Hard route constraints:**",
            Regex::new(r"(?i)^CONSTRAINTS:\s*\S").unwrap(),
        ),
        ("**Goal route schema:**", Regex::new(r"(?i)^goal-route\.v2$").unwrap()),
        (
            "**Selected route:**",
            Regex::new(r"(?i)^SELECTED_ROUTE:\s*[A-Z][A-Z0-9_-]*$").unwrap(),
        ),
        (
            "**Expected time to verified B:**",
            Regex::new(r"(?i)^EXPECTED_TIME_TO_VERIFIED_B_MS:\d+$").unwrap(),
        ),
        (
            "**Route revision:**",
            Regex::new(r"(?i)^ROUTE_REVISION:[1-9]\d*$").unwrap(),
        ),
        (
            "**Why fastest valid:**",
            Regex::new(r"(?i)^EXPECTED_TIME_PROOF:\s*\S").unwrap(),
        ),
        ("**Bottleneck:**", Regex::new(r"(?i)^BOTTLENECK:\s*\S").unwrap()),
        (
            "**Parallel lanes:**",
            Regex::new(r"(?i)^(?:PARALLEL:\s*\S|NONE_DEPENDENCY_BOUND:\s*\S)").unwrap(),
        ),
        (
            "**Deleted / deferred work:**",
            Regex::new(r"(?is)^DELETE:\s*\S.+;\s*DEFER:\s*\S").unwrap(),
        ),
    ];
    for (label, pattern) in &rules {
        let value = label_value(text, label).unwrap_or_default();
        if !pattern.is_match(&value) {
            errors.push(format!("{label} lacks enforceable goal-route contract"));
        }
    }

    for label in ["**State A:**", "**State B:**"] {
        let raw = label_value(text, label).unwrap_or_default();
        let state = raw.splitn(2, ':').last().unwrap_or("");
        if !is_concrete(state) {
            errors.push(format!("{label} requires concrete state, not label-only value"));
        }
    }

    let proof = label_value(text, "**Goal success proof:**").unwrap_or_default();
    if !action_re().is_match(&proof) || !path_re().is_match(&proof) {
        errors.push("Goal success proof requires executable action + evidence path".to_string());
    }

    let constraints = label_value(text, "**Hard route constraints:**")
        .unwrap_or_default()
        .to_uppercase();
    for token in ["AUTHORITY", "SAFETY", "SCOPE", "COST", "QUALITY"] {
        if !constraints.contains(token) {
            errors.push(format!("Hard route constraints missing {token}"));
        }
    }

    if !bound_re().is_match(&label_value(text, "**Bottleneck:**").unwrap_or_default()) {
        errors.push("Bottleneck requires numeric critical-path bound".to_string());
    }

    let mode = label_value(text, "**Route mode:**")
        .unwrap_or_default()
        .trim_matches('`')
        .to_uppercase();
    if mode != "COMPARE" && mode != "SINGLE_FEASIBLE" {
        errors.push("Route mode must be COMPARE or SINGLE_FEASIBLE".to_string());
    }

    let route_path_value = label_value(text, "**Goal route artifact:**").unwrap_or_default();
    let receipt_path_value = label_value(text, "**Goal route receipt:**").unwrap_or_default();
    if route_path_value.is_empty() {
        errors.push("Goal route artifact path is required".to_string());
    }
    if receipt_path_value.is_empty() {
        errors.push("Goal route receipt path is required".to_string());
    }

    let mut route_document: Option<Value> = None;
    let mut route_candidates: BTreeMap<String, Value> = BTreeMap::new();
    if !route_path_value.is_empty() && !receipt_path_value.is_empty() {
        if let Some(artifact_path) = artifact_path {
            let route_path = resolve_declared_path(&route_path_value, artifact_path);
            let receipt_path = resolve_declared_path(&receipt_path_value, artifact_path);
            match std::fs::read(&route_path) {
                Ok(raw) => match std::str::from_utf8(&raw) {
                    Ok(raw_text) => match serde_json::from_str::<Value>(raw_text) {
                        Ok(parsed_route) => {
                            for error in validate_route(&parsed_route) {
                                errors.push(format!("GoalRoute artifact: {error}"));
                            }
                            for error in validate_receipt(&route_path, &receipt_path, &raw) {
                                errors.push(format!("GoalRoute receipt: {error}"));
                            }
                            if parsed_route.is_object() {
                                if let Some(candidates) = parsed_route.get("candidates").and_then(Value::as_array) {
                                    for candidate in candidates {
                                        if let Some(obj) = candidate.as_object() {
                                            let id = obj
                                                .get("id")
                                                .and_then(Value::as_str)
                                                .unwrap_or("")
                                                .to_string();
                                            route_candidates.insert(id, candidate.clone());
                                        }
                                    }
                                }
                                route_document = Some(parsed_route);
                            }
                        }
                        Err(exc) => errors.push(format!("GoalRoute artifact/receipt cannot be validated: {exc}")),
                    },
                    Err(exc) => errors.push(format!("GoalRoute artifact/receipt cannot be validated: {exc}")),
                },
                Err(exc) => errors.push(format!("GoalRoute artifact/receipt cannot be validated: {exc}")),
            }
        }
    }

    let table = table_rows(
        text,
        "## 1C. Goal Route & Critical Path",
        "## 1D. Experiment Topology & Workload Funnel",
    );
    let raw_rows: Vec<Vec<String>> = table.into_iter().skip(1).collect();
    for (index, row) in raw_rows.iter().enumerate() {
        if row.len() != 11 {
            errors.push(format!("goal route comparison row {} must contain 11 cells", index + 1));
        }
    }
    let rows: Vec<&Vec<String>> = raw_rows.iter().filter(|row| row.len() == 11).collect();
    if mode == "COMPARE" && !(2..=3).contains(&rows.len()) {
        errors.push("COMPARE route mode requires 2-3 candidate routes".to_string());
    }
    if mode == "SINGLE_FEASIBLE" && rows.len() != 1 {
        errors.push("SINGLE_FEASIBLE route mode requires exactly one candidate route".to_string());
    }

    let selected_label = selected_route_prefix_re()
        .replace(&label_value(text, "**Selected route:**").unwrap_or_default(), "")
        .trim_matches(|c: char| c == '`' || c == ' ')
        .to_string();

    let mut route_data: Vec<RouteRow> = Vec::new();
    let mut route_ids: Vec<String> = Vec::new();
    for row in &rows {
        let route_id = row[0].trim_matches('`').to_string();
        route_ids.push(route_id.clone());

        let step_ids: Vec<String>;
        if let Some(caps) = steps_re(&route_id).captures(&row[1]) {
            step_ids = caps[1].split('>').map(|s| s.to_uppercase()).collect();
        } else {
            errors.push(format!("route {route_id} requires ordered STEPS bound to route ID"));
            step_ids = Vec::new();
        }

        let (roots, edges) = match parse_dependency_contract(&row[2]) {
            Some((roots, edges)) => {
                let graph_steps: BTreeSet<String> = roots
                    .iter()
                    .cloned()
                    .chain(edges.iter().flat_map(|(a, b)| [a.clone(), b.clone()]))
                    .collect();
                if !step_ids.is_empty() {
                    let step_set: BTreeSet<String> = step_ids.iter().cloned().collect();
                    if graph_steps != step_set {
                        errors.push(format!(
                            "route {route_id} dependency graph must exactly cover ordered steps"
                        ));
                    }
                }
                (roots, edges)
            }
            None => {
                errors.push(format!("route {route_id} requires explicit dependency edges"));
                (BTreeSet::new(), BTreeSet::new())
            }
        };

        let constraint_pass = constraint_pass_re().is_match(&row[3]);
        let constraint_fail = constraint_fail_re().is_match(&row[3]);
        if !(constraint_pass || constraint_fail) {
            errors.push(format!("route {route_id} constraint result must be PASS or FAIL"));
        }

        let field_names = ["wall", "expected", "cost", "risk", "rework"];
        let mut numeric = [0i64; 5];
        for (offset, name) in field_names.iter().enumerate() {
            let cell = row[4 + offset].trim_matches(|c: char| c == '`' || c == ' ');
            let is_digits = !cell.is_empty() && cell.chars().all(|c| c.is_ascii_digit());
            if is_digits {
                numeric[offset] = cell.parse::<i64>().unwrap_or(0);
            } else {
                errors.push(format!("route {route_id} {name} units must be integer"));
                numeric[offset] = 0;
            }
        }

        let status = row[9].trim_matches('`').to_uppercase();
        if status != "SELECTED" && status != "REJECTED" {
            errors.push(format!("route {route_id} status must be SELECTED or REJECTED"));
        }
        if status == "SELECTED" && !constraint_pass {
            errors.push(format!("selected route {route_id} must pass hard constraints"));
        }
        if status == "REJECTED" && constraint_pass && !dominance_re(&selected_label).is_match(&row[10]) {
            errors.push(format!(
                "passing rejected route {route_id} requires dominance/tradeoff evidence"
            ));
        }
        if mode == "SINGLE_FEASIBLE" && !only_feasible_re().is_match(&row[10]) {
            errors.push("SINGLE_FEASIBLE route requires ONLY_FEASIBLE evidence".to_string());
        }
        if !row[10].to_uppercase().contains("EVIDENCE:") || !path_re().is_match(&row[10]) {
            errors.push(format!("route {route_id} requires evidence path"));
        }

        route_data.push(RouteRow {
            id: route_id,
            steps: step_ids,
            roots,
            edges,
            pass: constraint_pass,
            wall: numeric[0],
            expected: numeric[1],
            cost: numeric[2],
            risk: numeric[3],
            rework: numeric[4],
            status,
        });
    }

    let unique_ids: BTreeSet<&String> = route_ids.iter().collect();
    if unique_ids.len() != route_ids.len() {
        errors.push("goal route comparison contains duplicate route IDs".to_string());
    }
    let selected: Vec<&RouteRow> = route_data.iter().filter(|r| r.status == "SELECTED").collect();
    if selected.len() != 1 {
        errors.push("goal route comparison requires exactly one SELECTED route".to_string());
    } else if selected[0].id.to_lowercase() != selected_label.to_lowercase() {
        errors.push("Selected route label does not match SELECTED route row".to_string());
    }

    if let Some(route_document) = &route_document {
        let artifact_mode = route_document
            .get("comparison_mode")
            .and_then(Value::as_str)
            .unwrap_or("");
        if artifact_mode != mode {
            errors.push("Route mode must match GoalRoute artifact".to_string());
        }
        let route_id_set: BTreeSet<&String> = route_ids.iter().collect();
        let candidate_id_set: BTreeSet<&String> = route_candidates.keys().collect();
        if route_id_set != candidate_id_set {
            errors.push("route table IDs must exactly match GoalRoute artifact candidates".to_string());
        }
        let artifact_selected_id = route_document
            .get("selected_route_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if artifact_selected_id.to_lowercase() != selected_label.to_lowercase() {
            errors.push("Selected route must match GoalRoute artifact".to_string());
        }

        let expected_label = Regex::new(r"(?i)^EXPECTED_TIME_TO_VERIFIED_B_MS:")
            .unwrap()
            .replace(
                &label_value(text, "**Expected time to verified B:**").unwrap_or_default(),
                "",
            )
            .to_string();
        let revision_label = Regex::new(r"(?i)^ROUTE_REVISION:")
            .unwrap()
            .replace(&label_value(text, "**Route revision:**").unwrap_or_default(), "")
            .to_string();

        let invalidation = route_document.get("invalidation");
        let artifact_revision = invalidation.and_then(|i| i.get("revision"));
        let artifact_correction = invalidation
            .and_then(|i| i.get("semantic_correction"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let dispatch_correction = label_value(text, "**Correction state:**").unwrap_or_default();
        if artifact_correction == "NONE" && !Regex::new(r"(?i)^NONE:").unwrap().is_match(&dispatch_correction) {
            errors.push("dispatch correction state must match GoalRoute artifact".to_string());
        }
        if artifact_correction == "RECOMPILED_FROM_ROOT"
            && !Regex::new(r"(?i)^SEMANTIC_CORRECTION:")
                .unwrap()
                .is_match(&dispatch_correction)
        {
            errors.push("dispatch correction state must match GoalRoute artifact".to_string());
        }

        let selected_artifact = route_candidates.get(&artifact_selected_id);
        let artifact_expected = selected_artifact
            .and_then(|c| c.get("expected_time_to_verified_b_ms"))
            .map(json_scalar_to_string)
            .unwrap_or_default();
        if expected_label != artifact_expected {
            errors.push("Expected time label must match selected GoalRoute candidate".to_string());
        }
        let artifact_revision_str = artifact_revision.map(json_scalar_to_string).unwrap_or_else(|| "None".to_string());
        if revision_label != artifact_revision_str {
            errors.push("Route revision label must match GoalRoute artifact".to_string());
        }

        for route in &route_data {
            let artifact = match route_candidates.get(&route.id) {
                Some(a) => a,
                None => continue,
            };
            let artifact_steps: BTreeMap<String, &Value> = artifact
                .get("steps")
                .and_then(Value::as_array)
                .map(|steps| {
                    steps
                        .iter()
                        .filter_map(|step| {
                            let obj = step.as_object()?;
                            let id = obj.get("id").and_then(Value::as_str)?.to_uppercase();
                            Some((id, step))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let artifact_roots: BTreeSet<String> = artifact_steps
                .iter()
                .filter(|(_, step)| {
                    step.get("depends_on")
                        .and_then(Value::as_array)
                        .map(|d| d.is_empty())
                        .unwrap_or(true)
                })
                .map(|(id, _)| id.clone())
                .collect();
            let artifact_edges: BTreeSet<(String, String)> = artifact_steps
                .iter()
                .flat_map(|(id, step)| {
                    step.get("depends_on")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|source| source.as_str())
                        .map(move |source| (source.to_uppercase(), id.clone()))
                })
                .collect();

            let step_set: BTreeSet<String> = route.steps.iter().cloned().collect();
            let artifact_step_set: BTreeSet<String> = artifact_steps.keys().cloned().collect();
            if step_set != artifact_step_set {
                errors.push(format!("route {} steps must match GoalRoute artifact", route.id));
            }
            if route.roots != artifact_roots || route.edges != artifact_edges {
                errors.push(format!("route {} dependency DAG must match GoalRoute artifact", route.id));
            }

            let mirrors: [(i64, &str); 5] = [
                (route.wall, "nominal_critical_path_ms"),
                (route.expected, "expected_time_to_verified_b_ms"),
                (route.cost, "cost_units"),
                (route.risk, "risk_units"),
                (route.rework, "rework_units"),
            ];
            for (inline_value, artifact_key) in mirrors {
                if artifact.get(artifact_key).and_then(Value::as_i64) != Some(inline_value) {
                    let inline_key = match artifact_key {
                        "nominal_critical_path_ms" => "wall",
                        "expected_time_to_verified_b_ms" => "expected",
                        "cost_units" => "cost",
                        "risk_units" => "risk",
                        _ => "rework",
                    };
                    errors.push(format!("route {} {inline_key} must match GoalRoute artifact", route.id));
                }
            }
            if artifact.get("status").and_then(Value::as_str) != Some(route.status.as_str()) {
                errors.push(format!("route {} status must match GoalRoute artifact", route.id));
            }
        }
    }

    if let Some(winner) = selected.first() {
        let critical = label_value(text, "**Critical path:**").unwrap_or_default();
        match critical_path_re().captures(&critical) {
            None => errors.push("Critical path requires ordered steps + TOTAL_MIN_WALL_MS".to_string()),
            Some(caps) => {
                let critical_steps: Vec<String> = caps[1]
                    .split('>')
                    .map(|s| s.trim().to_uppercase())
                    .collect();
                let winner_steps: BTreeSet<&String> = winner.steps.iter().collect();
                let critical_set: BTreeSet<&String> = critical_steps.iter().collect();
                if critical_steps.is_empty() || !critical_set.is_subset(&winner_steps) {
                    errors.push("Critical path steps must belong to selected route".to_string());
                }
                let total: i64 = caps[2].parse().unwrap_or(0);
                if total != winner.wall {
                    errors.push("Critical path TOTAL_MIN_WALL_MS must equal selected route wall".to_string());
                }
                if let Some(route_document) = &route_document {
                    let artifact_path_steps: Vec<String> = route_document
                        .get("selected_critical_path")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .map(|item| item.as_str().unwrap_or("").to_uppercase())
                                .collect()
                        })
                        .unwrap_or_default();
                    if critical_steps != artifact_path_steps {
                        errors.push("Critical path must exactly match GoalRoute artifact".to_string());
                    }
                }
            }
        }
    }

    let alchemist_gate = authority_label_value(text, "**Alchemist gate:**").unwrap_or_default();
    let route_alchemist = authority_label_value(text, "**Route Alchemist binding:**").unwrap_or_default();
    let mut artifact_alchemist: Option<&Value> = None;
    let mut state_scheme = "alchemist";
    if let Some(route_document) = &route_document {
        if matches!(route_document.get("alchemist"), Some(Value::Object(_))) {
            artifact_alchemist = route_document.get("alchemist");
        } else if matches!(route_document.get("forge"), Some(Value::Object(_))) {
            artifact_alchemist = route_document.get("forge");
            state_scheme = "forge";
        }
    }
    let required = artifact_alchemist
        .and_then(|a| a.get("required"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if artifact_alchemist.is_some() && required {
        let run_id = artifact_alchemist
            .and_then(|a| a.get("run_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let expected = format!(
            "SCHEMA:goal-route.v2; RUN_ID:{run_id}; STATE:{state_scheme}://run/{run_id}/state; CHECKPOINT:GOAL_ROUTE_V2"
        );
        if route_alchemist.to_lowercase() != expected.to_lowercase() {
            errors.push("Route Alchemist binding must match GoalRoute artifact".to_string());
        }
        if !alchemist_gate.contains(&run_id) {
            errors.push("dispatch Alchemist gate must contain GoalRoute Alchemist run ID".to_string());
        }
    } else if !Regex::new(r"(?i)^SCHEMA:goal-route\.v2;\s*NOT_REQUIRED:\s*\S")
        .unwrap()
        .is_match(&route_alchemist)
    {
        errors.push("routine route Alchemist binding requires NOT_REQUIRED reason".to_string());
    }

    errors
}

/// Renders a JSON scalar (string/number/null) the way Python's implicit
/// `str(...)` coercion would for the label-comparison call sites above:
/// strings pass through unquoted, integers render without a trailing
/// `.0`, and a missing/`null` value renders as `"None"`.
fn json_scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Null => "None".to_string(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        other => other.to_string(),
    }
}
