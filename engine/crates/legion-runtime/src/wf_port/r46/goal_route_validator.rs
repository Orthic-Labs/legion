//! Port of the GoalRoute v2 artifact/receipt validator,
//! `src/lib/goalroute/scripts/validate-route.py` (`validate_route()`,
//! `validate_receipt()`, and their helpers). `goal_route_errors()` in
//! `goal_route.rs` calls [`validate_route`] and [`validate_receipt`] the
//! same way the Python `goal_route_errors()` dynamically loads and calls
//! this sibling module.
//!
//! **Resolved gap**: the Python `validator_sha256()` hashes
//! `Path(__file__).read_bytes()` — the bytes of `validate-route.py` itself
//! — and `validate_receipt()` compares a receipt's `validator_sha256`
//! field against that. There is no `__file__` equivalent for a compiled-in
//! Rust module, and hashing the sibling legacy Python script's bytes (the
//! prior approach here) ties every future receipt to a file the port brief
//! says will eventually be deleted. [`validator_sha256`] instead hashes
//! this Rust validator's own identity string
//! (`"legion-goal-route-validator:" + VALIDATOR_VERSION`), i.e. this
//! module's own compiled-in version — bump [`VALIDATOR_VERSION`]
//! whenever this validator's behaviour changes, exactly as the Python
//! digest changed whenever `validate-route.py`'s bytes changed. This is a
//! deliberate identity change (old receipts' `validator_sha256` no longer
//! matches), not a bug.
//!
//! **Known gap 2**: Python's `uuid.UUID(run_id)` accepts many input forms
//! (hyphenated, bare 32-hex, braced, `urn:uuid:` prefixed, mixed case).
//! [`is_uuid`] only accepts the canonical hyphenated 8-4-4-4-12 form
//! (case-insensitive), which is what every existing GoalRoute artifact in
//! this repository uses; the other forms are PORTED-PARTIAL.

use crate::wf_port::w2_045::path_utils::canonical_locator;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::OnceLock;

pub const SCHEMA: &str = "goal-route.v2";
pub const RECEIPT_SCHEMA: &str = "goal-route.receipt.v2";
pub const VALIDATOR_VERSION: &str = "2.1.0";

fn sha256_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^[0-9a-f]{64}$").unwrap())
}

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\{\{[^}]+\}\}|(?:^|\s)(?:TBD|TODO|PLACEHOLDER)(?:\s|$)").unwrap()
    })
}

fn vague_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:current state|target state|done|complete|best route|fastest route|same as above)$",
        )
        .unwrap()
    })
}

fn locator_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:[A-Za-z]:[\\/]|/|(?:alchemist|forge|https?)://|(?:\.\.?[\\/])?[\w.-]+[\\/])\S+")
            .unwrap()
    })
}

fn uuid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
    })
}

/// Port of `sha256_bytes()`.
pub fn sha256_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Port of `validator_sha256()`. Hashes this Rust validator's own
/// identity (crate name + [`VALIDATOR_VERSION`]) rather than the legacy
/// Python script's bytes — see the module doc's "Resolved gap" note.
/// `artifact` is accepted for call-site parity with the Python signature
/// (and every other sibling `validator_sha256`-style helper in this
/// crate) but is not used to compute the digest.
pub fn validator_sha256(_artifact: &Path) -> std::io::Result<String> {
    Ok(sha256_bytes(
        format!("legion-goal-route-validator:{VALIDATOR_VERSION}").as_bytes(),
    ))
}

/// Port of `concrete()` with the default `minimum=12`.
pub fn concrete(value: Option<&Value>) -> bool {
    concrete_min(value, 12)
}

/// Port of `concrete()` with an explicit `minimum`.
pub fn concrete_min(value: Option<&Value>, minimum: usize) -> bool {
    let text = match value.and_then(Value::as_str) {
        Some(s) => s,
        None => return false,
    };
    let trimmed = text.trim();
    trimmed.chars().count() >= minimum
        && !placeholder_re().is_match(trimmed)
        && !vague_re().is_match(trimmed)
}

/// Port of `locator()`.
pub fn locator(value: Option<&Value>) -> bool {
    match value.and_then(Value::as_str) {
        Some(s) => !placeholder_re().is_match(s) && locator_re().is_match(s.trim()),
        None => false,
    }
}

/// Port of `nonnegative_int()`. `serde_json` has no separate bool/int
/// tagging pitfall the way Python's `bool` subclasses `int` does, so this
/// only needs `Value::as_i64`.
pub fn nonnegative_int(value: Option<&Value>) -> bool {
    matches!(value.and_then(Value::as_i64), Some(v) if v >= 0)
}

/// Port of `positive_int()`.
pub fn positive_int(value: Option<&Value>) -> bool {
    matches!(value.and_then(Value::as_i64), Some(v) if v > 0)
}

fn is_uuid(value: &str) -> bool {
    uuid_re().is_match(value)
}

fn as_object(value: Option<&Value>) -> Option<&serde_json::Map<String, Value>> {
    value.and_then(Value::as_object)
}

fn as_array(value: Option<&Value>) -> Option<&Vec<Value>> {
    value.and_then(Value::as_array)
}

/// A step within one candidate's dependency graph, keyed by its normalized
/// (upper-cased) step id.
pub type StepGraph = std::collections::BTreeMap<String, Value>;

/// Port of `candidate_graph()`: validates `candidate.steps`, builds the
/// dependency graph, topologically checks for cycles, and returns
/// `(steps, nominal_critical_path_ms)`. Errors are appended to `errors`,
/// matching the Python function's side-effecting signature.
pub fn candidate_graph(candidate: &Value, errors: &mut Vec<String>) -> (StepGraph, i64) {
    let candidate_id = candidate
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    let raw_steps = match as_array(candidate.get("steps")) {
        Some(steps) if !steps.is_empty() => steps,
        _ => {
            errors.push(format!("candidate {candidate_id} requires non-empty steps"));
            return (StepGraph::new(), 0);
        }
    };

    let step_id_re = Regex::new(&format!(
        r"(?i)^{}/[A-Z][A-Z0-9_-]*$",
        regex::escape(&candidate_id)
    ))
    .unwrap();

    let mut steps: StepGraph = StepGraph::new();
    for (index, raw_step) in raw_steps.iter().enumerate() {
        let index = index + 1;
        let step_obj = match raw_step.as_object() {
            Some(obj) => obj,
            None => {
                errors.push(format!("candidate {candidate_id} step {index} must be object"));
                continue;
            }
        };
        let step_id = match step_obj.get("id").and_then(Value::as_str) {
            Some(id) if step_id_re.is_match(id) => id,
            _ => {
                errors.push(format!(
                    "candidate {candidate_id} step {index} id must be {candidate_id}/<STEP>"
                ));
                continue;
            }
        };
        let normalized = step_id.to_uppercase();
        if steps.contains_key(&normalized) {
            errors.push(format!("candidate {candidate_id} duplicate step {step_id}"));
            continue;
        }
        if !concrete(step_obj.get("operation")) {
            errors.push(format!("step {step_id} requires exact operation"));
        }
        if !positive_int(step_obj.get("min_wall_ms")) {
            errors.push(format!("step {step_id} min_wall_ms must be positive integer"));
        }
        let kind = step_obj.get("kind").and_then(Value::as_str);
        if !matches!(kind, Some("ADVANCE_B") | Some("SAFETY_DEPENDENCY")) {
            errors.push(format!("step {step_id} kind must be ADVANCE_B or SAFETY_DEPENDENCY"));
        }
        if !concrete_min(step_obj.get("b_state_delta"), 6) {
            errors.push(format!("step {step_id} requires observable b_state_delta"));
        }
        let deps_ok = match step_obj.get("depends_on") {
            Some(Value::Array(items)) => items.iter().all(Value::is_string),
            _ => false,
        };
        if !deps_ok {
            errors.push(format!("step {step_id} depends_on must be string array"));
        }
        steps.insert(normalized, raw_step.clone());
    }

    if steps.is_empty() {
        return (StepGraph::new(), 0);
    }

    let dependency_list = |step: &Value| -> Vec<String> {
        step.get("depends_on")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };

    let mut indegree: std::collections::BTreeMap<String, i64> =
        steps.keys().map(|id| (id.clone(), 0)).collect();
    let mut consumers: std::collections::BTreeMap<String, Vec<String>> =
        steps.keys().map(|id| (id.clone(), Vec::new())).collect();
    for (step_id, step) in &steps {
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for dependency in dependency_list(step) {
            let normalized = dependency.to_uppercase();
            if !steps.contains_key(&normalized) {
                errors.push(format!(
                    "step {step_id} references unknown dependency {dependency}"
                ));
                continue;
            }
            if normalized == *step_id {
                errors.push(format!("step {step_id} depends on itself"));
                continue;
            }
            if seen.contains(&normalized) {
                errors.push(format!("step {step_id} repeats dependency {dependency}"));
                continue;
            }
            seen.insert(normalized.clone());
            *indegree.get_mut(step_id).unwrap() += 1;
            consumers.get_mut(&normalized).unwrap().push(step_id.clone());
        }
    }

    let mut queue: Vec<String> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect();
    queue.sort();
    let mut order: Vec<String> = Vec::new();
    while !queue.is_empty() {
        let step_id = queue.remove(0);
        order.push(step_id.clone());
        let mut newly_ready: Vec<String> = Vec::new();
        let mut consumer_ids = consumers[&step_id].clone();
        consumer_ids.sort();
        for consumer in consumer_ids {
            let degree = indegree.get_mut(&consumer).unwrap();
            *degree -= 1;
            if *degree == 0 {
                newly_ready.push(consumer);
            }
        }
        queue.extend(newly_ready);
        queue.sort();
    }
    if order.len() != steps.len() {
        errors.push(format!("candidate {candidate_id} dependency graph contains cycle"));
        return (steps, 0);
    }

    let mut distance: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    for step_id in &order {
        let step = &steps[step_id];
        let duration = step.get("min_wall_ms").and_then(Value::as_i64).unwrap_or(0);
        let deps: Vec<String> = dependency_list(step)
            .into_iter()
            .map(|d| d.to_uppercase())
            .filter(|d| steps.contains_key(d))
            .collect();
        let base = deps
            .iter()
            .map(|d| distance[d])
            .max()
            .unwrap_or(0);
        distance.insert(step_id.clone(), duration + base);
    }
    let nominal = distance.values().copied().max().unwrap_or(0);
    (steps, nominal)
}

/// Port of `has_dependency_path()`.
pub fn has_dependency_path(ancestor: &str, descendant: &str, steps: &StepGraph) -> bool {
    let mut stack = vec![descendant.to_string()];
    let mut visited: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    while let Some(current) = stack.pop() {
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current.clone());
        let dependencies: Vec<String> = steps
            .get(&current)
            .and_then(|s| s.get("depends_on"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.to_uppercase())
                    .filter(|s| steps.contains_key(s))
                    .collect()
            })
            .unwrap_or_default();
        if dependencies.iter().any(|d| d == ancestor) {
            return true;
        }
        stack.extend(dependencies);
    }
    false
}

/// Port of `expected_time_ms()`. Returns `-1` on the same "not all
/// nonnegative" bail-out the Python function uses.
pub fn expected_time_ms(candidate: &Value, nominal_ms: i64) -> i64 {
    let probabilities = candidate.get("probabilities_bps");
    let retry = probabilities.and_then(|p| p.get("retry"));
    let terminal = probabilities.and_then(|p| p.get("terminal_failure"));
    let retry_cost = candidate.get("retry_cost_ms");
    let rework_cost = candidate.get("rework_cost_ms");
    if ![retry, terminal, retry_cost, rework_cost]
        .into_iter()
        .all(nonnegative_int)
    {
        return -1;
    }
    let retry_v = retry.and_then(Value::as_i64).unwrap_or(0);
    let terminal_v = terminal.and_then(Value::as_i64).unwrap_or(0);
    let retry_cost_v = retry_cost.and_then(Value::as_i64).unwrap_or(0);
    let rework_cost_v = rework_cost.and_then(Value::as_i64).unwrap_or(0);
    let retry_component = (retry_v * retry_cost_v + 9999) / 10000;
    let terminal_component = (terminal_v * rework_cost_v + 9999) / 10000;
    nominal_ms + retry_component + terminal_component
}

/// Port of `validate_route()`.
pub fn validate_route(data: &Value) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let root = match data.as_object() {
        Some(obj) => obj,
        None => return vec!["route root must be JSON object".to_string()],
    };

    if root.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        errors.push(format!("schema must equal {SCHEMA}"));
    }
    if !concrete_min(root.get("route_id"), 4) {
        errors.push("route_id must be concrete".to_string());
    }
    let purpose = root.get("purpose").and_then(Value::as_str);
    if !matches!(purpose, Some("DELIVERY") | Some("DIAGNOSTIC")) {
        errors.push("purpose must be DELIVERY or DIAGNOSTIC".to_string());
    }
    if root.get("routine").and_then(Value::as_bool).is_none() {
        errors.push("routine must be boolean".to_string());
    }
    let comparison_mode = root.get("comparison_mode").and_then(Value::as_str);
    if !matches!(comparison_mode, Some("COMPARE") | Some("SINGLE_FEASIBLE")) {
        errors.push("comparison_mode must be COMPARE or SINGLE_FEASIBLE".to_string());
    }

    match as_object(root.get("state_a")) {
        Some(state_a) if concrete(state_a.get("description")) => {
            match as_array(state_a.get("evidence")) {
                Some(evidence) if !evidence.is_empty() => {
                    for (index, item) in evidence.iter().enumerate() {
                        let index = index + 1;
                        match item.as_object() {
                            Some(item) => {
                                if !locator(item.get("locator")) {
                                    errors.push(format!("state_a evidence {index} requires locator"));
                                }
                                let sha_ok = item
                                    .get("sha256")
                                    .and_then(Value::as_str)
                                    .map(|s| sha256_re().is_match(s))
                                    .unwrap_or(false);
                                if !sha_ok {
                                    errors.push(format!("state_a evidence {index} requires sha256"));
                                }
                                if !concrete(item.get("check")) {
                                    errors.push(format!("state_a evidence {index} requires exact check"));
                                }
                            }
                            None => errors.push(format!("state_a evidence {index} must be object")),
                        }
                    }
                }
                _ => errors.push("state_a requires evidence".to_string()),
            }
        }
        _ => errors.push("state_a requires concrete description".to_string()),
    }

    match as_object(root.get("state_b")) {
        Some(state_b) if concrete(state_b.get("description")) => {
            match as_array(state_b.get("proof")) {
                Some(proofs) if !proofs.is_empty() => {
                    for (index, proof) in proofs.iter().enumerate() {
                        let index = index + 1;
                        match proof.as_object() {
                            Some(proof) => {
                                if !concrete(proof.get("command")) {
                                    errors.push(format!("state_b proof {index} requires command"));
                                }
                                if !concrete_min(proof.get("expected"), 6) {
                                    errors.push(format!("state_b proof {index} requires expected result"));
                                }
                                if !locator(proof.get("evidence_path")) {
                                    errors.push(format!("state_b proof {index} requires evidence_path"));
                                }
                            }
                            None => errors.push(format!("state_b proof {index} must be object")),
                        }
                    }
                }
                _ => errors.push("state_b requires executable proof".to_string()),
            }
        }
        _ => errors.push("state_b requires concrete description".to_string()),
    }

    match as_object(root.get("constraints")) {
        None => errors.push("constraints must be object".to_string()),
        Some(constraints) => {
            for key in ["authority", "safety", "scope", "quality", "cost"] {
                match as_object(constraints.get(key)) {
                    None => errors.push(format!("constraints.{key} must be object")),
                    Some(constraint) => {
                        if !concrete(constraint.get("rule")) {
                            errors.push(format!("constraints.{key}.rule must be concrete"));
                        }
                        if !locator(constraint.get("evidence_locator")) {
                            errors.push(format!("constraints.{key}.evidence_locator required"));
                        }
                    }
                }
            }
        }
    }

    let empty_vec: Vec<Value> = Vec::new();
    let raw_candidates: &Vec<Value> = match as_array(root.get("candidates")) {
        Some(candidates) => candidates,
        None => {
            errors.push("candidates must be array".to_string());
            &empty_vec
        }
    };
    let comparison_mode_str = comparison_mode.unwrap_or("");
    if comparison_mode_str == "COMPARE" && !(2..=3).contains(&raw_candidates.len()) {
        errors.push("COMPARE requires 2-3 candidates".to_string());
    }
    if comparison_mode_str == "SINGLE_FEASIBLE" {
        if raw_candidates.len() != 1 {
            errors.push("SINGLE_FEASIBLE requires exactly one candidate".to_string());
        }
        let singleton_ok = match as_array(root.get("single_feasible_evidence")) {
            Some(items) if !items.is_empty() => items.iter().all(|item| locator(Some(item))),
            _ => false,
        };
        if !singleton_ok {
            errors.push("SINGLE_FEASIBLE requires infeasible-alternative evidence".to_string());
        }
    }

    let candidate_id_re = Regex::new(r"(?i)^[A-Z][A-Z0-9_-]*$").unwrap();
    let mut candidate_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut candidates: Vec<(&Value, i64, i64)> = Vec::new(); // (raw candidate, computed_nominal, computed_expected)
    let mut graph_by_candidate: std::collections::BTreeMap<String, StepGraph> =
        std::collections::BTreeMap::new();

    for (index, raw_candidate) in raw_candidates.iter().enumerate() {
        let index = index + 1;
        let candidate_obj = match raw_candidate.as_object() {
            Some(obj) => obj,
            None => {
                errors.push(format!("candidate {index} must be object"));
                continue;
            }
        };
        let candidate_id = match candidate_obj.get("id").and_then(Value::as_str) {
            Some(id) if candidate_id_re.is_match(id) => id,
            _ => {
                errors.push(format!("candidate {index} id invalid"));
                continue;
            }
        };
        let normalized_id = candidate_id.to_uppercase();
        if candidate_ids.contains(&normalized_id) {
            errors.push(format!("duplicate candidate id {candidate_id}"));
            continue;
        }
        candidate_ids.insert(normalized_id.clone());

        let constraint_status = candidate_obj.get("constraint_status").and_then(Value::as_str);
        if !matches!(constraint_status, Some("PASS") | Some("FAIL")) {
            errors.push(format!("candidate {candidate_id} constraint_status must PASS or FAIL"));
        }
        if !locator(candidate_obj.get("constraint_evidence")) {
            errors.push(format!("candidate {candidate_id} requires constraint_evidence"));
        }

        let (steps, nominal) = candidate_graph(raw_candidate, &mut errors);
        graph_by_candidate.insert(normalized_id.clone(), steps);
        if candidate_obj.get("nominal_critical_path_ms").and_then(Value::as_i64) != Some(nominal) {
            errors.push(format!(
                "candidate {candidate_id} nominal_critical_path_ms must equal computed {nominal}"
            ));
        }

        match as_object(candidate_obj.get("probabilities_bps")) {
            None => errors.push(format!("candidate {candidate_id} probabilities_bps must be object")),
            Some(probabilities) => {
                let retry = probabilities.get("retry").and_then(Value::as_i64);
                let terminal = probabilities.get("terminal_failure").and_then(Value::as_i64);
                let in_range = |v: Option<i64>| matches!(v, Some(v) if (0..=10000).contains(&v));
                if !in_range(retry) || !in_range(terminal) {
                    errors.push(format!("candidate {candidate_id} probabilities must be 0..10000"));
                } else if retry.unwrap() + terminal.unwrap() > 10000 {
                    errors.push(format!(
                        "candidate {candidate_id} retry + terminal probability exceeds 10000"
                    ));
                }
            }
        }

        for field in [
            "retry_cost_ms",
            "rework_cost_ms",
            "cost_units",
            "risk_units",
            "rework_units",
        ] {
            if !nonnegative_int(candidate_obj.get(field)) {
                errors.push(format!("candidate {candidate_id} {field} must be nonnegative integer"));
            }
        }

        let computed_expected = expected_time_ms(raw_candidate, nominal);
        if candidate_obj
            .get("expected_time_to_verified_b_ms")
            .and_then(Value::as_i64)
            != Some(computed_expected)
        {
            errors.push(format!(
                "candidate {candidate_id} expected_time_to_verified_b_ms must equal computed {computed_expected}"
            ));
        }

        let status = candidate_obj.get("status").and_then(Value::as_str);
        if !matches!(status, Some("SELECTED") | Some("REJECTED")) {
            errors.push(format!("candidate {candidate_id} status must SELECTED or REJECTED"));
        }
        if status == Some("SELECTED") && constraint_status != Some("PASS") {
            errors.push(format!("selected candidate {candidate_id} must pass constraints"));
        }
        if status == Some("REJECTED")
            && constraint_status == Some("PASS")
            && !concrete(candidate_obj.get("dominance_reason"))
        {
            errors.push(format!(
                "passing rejected candidate {candidate_id} requires dominance_reason"
            ));
        }

        let evidence_ok = match as_array(candidate_obj.get("evidence")) {
            Some(items) if !items.is_empty() => items.iter().all(|item| locator(Some(item))),
            _ => false,
        };
        if !evidence_ok {
            errors.push(format!("candidate {candidate_id} requires evidence locators"));
        }

        candidates.push((raw_candidate, nominal, computed_expected));
    }

    let selected: Vec<&(&Value, i64, i64)> = candidates
        .iter()
        .filter(|(candidate, _, _)| candidate.get("status").and_then(Value::as_str) == Some("SELECTED"))
        .collect();
    if selected.len() != 1 {
        errors.push("exactly one candidate must be SELECTED".to_string());
    }
    let selected_candidate = if selected.len() == 1 { Some(selected[0]) } else { None };
    let selected_id_field = root
        .get("selected_route_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_uppercase();
    if let Some((candidate, _, _)) = selected_candidate {
        let candidate_id = candidate.get("id").and_then(Value::as_str).unwrap_or("").to_uppercase();
        if selected_id_field != candidate_id {
            errors.push("selected_route_id must match SELECTED candidate".to_string());
        }
    }

    if let Some((winner, winner_nominal, winner_expected)) = selected_candidate {
        let winner_id_raw = winner.get("id").and_then(Value::as_str).unwrap_or("");
        for (candidate, _, candidate_expected) in &candidates {
            if std::ptr::eq(*candidate, *winner) {
                continue;
            }
            if candidate.get("constraint_status").and_then(Value::as_str) != Some("PASS") {
                continue;
            }
            let candidate_id = candidate.get("id").and_then(Value::as_str).unwrap_or("");
            if *candidate_expected < *winner_expected {
                errors.push(format!(
                    "selected route {winner_id_raw} has slower expected time than {candidate_id}"
                ));
            }
            if *candidate_expected == *winner_expected {
                let field_le = |f: &str| {
                    candidate.get(f).and_then(Value::as_i64).unwrap_or(0)
                        <= winner.get(f).and_then(Value::as_i64).unwrap_or(0)
                };
                let field_lt = |f: &str| {
                    candidate.get(f).and_then(Value::as_i64).unwrap_or(0)
                        < winner.get(f).and_then(Value::as_i64).unwrap_or(0)
                };
                let fields = ["cost_units", "risk_units", "rework_units"];
                if fields.iter().all(|f| field_le(f)) && fields.iter().any(|f| field_lt(f)) {
                    errors.push(format!(
                        "selected route {winner_id_raw} is dominated at equal expected time by {candidate_id}"
                    ));
                }
            }
        }

        let winner_id = winner_id_raw.to_uppercase();
        let steps = graph_by_candidate.get(&winner_id).cloned().unwrap_or_default();

        match as_array(root.get("selected_critical_path")) {
            None => errors.push("selected_critical_path must be non-empty array".to_string()),
            Some(items) if items.is_empty() => {
                errors.push("selected_critical_path must be non-empty array".to_string())
            }
            Some(items) => {
                let normalized_path: Vec<String> = items
                    .iter()
                    .map(|item| item.as_str().map(str::to_uppercase).unwrap_or_default())
                    .collect();
                if normalized_path.iter().any(|item| !steps.contains_key(item)) {
                    errors.push("selected_critical_path contains non-selected/unknown step".to_string());
                } else {
                    let mut broke = false;
                    for pair in normalized_path.windows(2) {
                        let (previous, current) = (&pair[0], &pair[1]);
                        let dependencies: Vec<String> = steps[current]
                            .get("depends_on")
                            .and_then(Value::as_array)
                            .map(|items| {
                                items
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_uppercase)
                                    .collect()
                            })
                            .unwrap_or_default();
                        if !dependencies.contains(previous) {
                            errors.push(
                                "selected_critical_path must follow direct dependency edges"
                                    .to_string(),
                            );
                            broke = true;
                            break;
                        }
                    }
                    if !broke {
                        let path_total: i64 = normalized_path
                            .iter()
                            .map(|item| steps[item].get("min_wall_ms").and_then(Value::as_i64).unwrap_or(0))
                            .sum();
                        if path_total != *winner_nominal {
                            errors.push(
                                "selected_critical_path total must equal computed nominal critical path"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        }

        match as_array(root.get("parallel_lanes")) {
            None => errors.push("parallel_lanes must be array".to_string()),
            Some(lanes) => {
                let mut lane_steps_seen: std::collections::BTreeSet<String> =
                    std::collections::BTreeSet::new();
                for (index, lane) in lanes.iter().enumerate() {
                    let index = index + 1;
                    let lane_obj = match lane.as_object() {
                        Some(obj) => obj,
                        None => {
                            errors.push(format!("parallel lane {index} must be object"));
                            continue;
                        }
                    };
                    if !concrete_min(lane_obj.get("id"), 2) || !concrete_min(lane_obj.get("reason"), 6) {
                        errors.push(format!("parallel lane {index} requires id and reason"));
                    }
                    let items = match as_array(lane_obj.get("steps")) {
                        Some(items) if items.len() >= 2 => items,
                        _ => {
                            errors.push(format!("parallel lane {index} requires at least two steps"));
                            continue;
                        }
                    };
                    let normalized_items: Vec<String> = items
                        .iter()
                        .map(|item| item.as_str().map(str::to_uppercase).unwrap_or_default())
                        .collect();
                    if normalized_items.iter().any(|item| !steps.contains_key(item)) {
                        errors.push(format!(
                            "parallel lane {index} contains unknown/non-selected step"
                        ));
                        continue;
                    }
                    for item in &normalized_items {
                        if lane_steps_seen.contains(item) {
                            errors.push(format!("parallel step {item} appears in multiple lanes"));
                        }
                        lane_steps_seen.insert(item.clone());
                    }
                    for (left_index, left) in normalized_items.iter().enumerate() {
                        for right in &normalized_items[left_index + 1..] {
                            if has_dependency_path(left, right, &steps)
                                || has_dependency_path(right, left, &steps)
                            {
                                errors.push(format!(
                                    "parallel lane {index} falsely groups dependent steps {left} and {right}"
                                ));
                            }
                        }
                    }
                }
            }
        }

        match as_object(root.get("bottleneck")) {
            None => errors.push("bottleneck must be object".to_string()),
            Some(bottleneck) => {
                let bottleneck_id = bottleneck
                    .get("step_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_uppercase();
                match steps.get(&bottleneck_id) {
                    None => errors.push("bottleneck step must belong to selected route".to_string()),
                    Some(step) => {
                        if bottleneck.get("bound_ms").and_then(Value::as_i64)
                            != step.get("min_wall_ms").and_then(Value::as_i64)
                        {
                            errors.push(
                                "bottleneck bound_ms must equal selected step min_wall_ms".to_string(),
                            );
                        }
                    }
                }
                if !concrete_min(bottleneck.get("resource"), 4) {
                    errors.push("bottleneck requires resource/dependency".to_string());
                }
            }
        }
    }

    for (field, second) in [("deleted_work", "reason"), ("deferred_work", "until")] {
        match as_array(root.get(field)) {
            None => errors.push(format!("{field} must be array")),
            Some(items) => {
                for (index, item) in items.iter().enumerate() {
                    let index = index + 1;
                    match item.as_object() {
                        Some(item_obj) if concrete_min(item_obj.get("item"), 4) => {
                            if !concrete_min(item_obj.get(second), 6) {
                                errors.push(format!("{field} item {index} requires {second}"));
                            }
                        }
                        _ => errors.push(format!("{field} item {index} requires concrete item")),
                    }
                }
            }
        }
    }

    match as_object(root.get("invalidation")) {
        None => errors.push("invalidation must be object".to_string()),
        Some(invalidation) => {
            let revision = invalidation.get("revision");
            let correction = invalidation.get("semantic_correction").and_then(Value::as_str);
            if !positive_int(revision) {
                errors.push("invalidation.revision must be positive integer".to_string());
            }
            if !matches!(correction, Some("NONE") | Some("RECOMPILED_FROM_ROOT")) {
                errors.push("semantic_correction must be NONE or RECOMPILED_FROM_ROOT".to_string());
            }
            let fingerprint_ok = invalidation
                .get("source_fingerprint_sha256")
                .and_then(Value::as_str)
                .map(|s| sha256_re().is_match(s))
                .unwrap_or(false);
            if !fingerprint_ok {
                errors.push("invalidation requires source_fingerprint_sha256".to_string());
            }
            let invalidates = as_array(invalidation.get("invalidates"));
            if invalidates.is_none() {
                errors.push("invalidation.invalidates must be array".to_string());
            }
            if positive_int(revision) && revision.and_then(Value::as_i64).unwrap_or(0) > 1 {
                if correction != Some("RECOMPILED_FROM_ROOT") {
                    errors.push("revision > 1 requires RECOMPILED_FROM_ROOT".to_string());
                }
                if invalidates.map(|v| v.is_empty()).unwrap_or(true) {
                    errors.push("recompiled route must name invalidated route".to_string());
                }
            }
        }
    }

    let alchemist = root.get("alchemist");
    let legacy_forge = root.get("forge");
    let (binding, binding_name, state_scheme): (Option<&Value>, &str, &str) =
        match (alchemist, legacy_forge) {
            (Some(_), Some(_)) => {
                errors.push("route must not declare both alchemist and legacy forge bindings".to_string());
                (None, "alchemist", "alchemist")
            }
            (Some(a), None) => (Some(a), "alchemist", "alchemist"),
            _ => (legacy_forge, "legacy forge", "forge"),
        };
    match binding.and_then(Value::as_object) {
        None => errors.push("alchemist must declare required boolean".to_string()),
        Some(binding_obj) => {
            let required = binding_obj.get("required").and_then(Value::as_bool);
            if required.is_none() {
                errors.push("alchemist must declare required boolean".to_string());
            } else {
                let required = required.unwrap();
                if root.get("routine").and_then(Value::as_bool) == Some(false) && !required {
                    errors.push("non-routine route requires Alchemist".to_string());
                }
                if required {
                    let run_id = binding_obj.get("run_id").and_then(Value::as_str).unwrap_or("");
                    if !is_uuid(run_id) {
                        errors.push(format!("{binding_name}.run_id must be UUID"));
                    }
                    let expected_ref = format!("{state_scheme}://run/{run_id}/state");
                    if binding_obj.get("state_ref").and_then(Value::as_str) != Some(expected_ref.as_str()) {
                        errors.push(format!("{binding_name}.state_ref must match run_id"));
                    }
                    if binding_obj.get("checkpoint").and_then(Value::as_str) != Some("GOAL_ROUTE_V2") {
                        errors.push(format!("{binding_name}.checkpoint must equal GOAL_ROUTE_V2"));
                    }
                } else if !concrete_min(binding_obj.get("reason"), 8) {
                    errors.push("routine route without Alchemist requires reason".to_string());
                }
            }
        }
    }

    errors
}

/// Port of `validate_receipt()`. `route_path` is the resolved path used to
/// compute its canonical locator; `raw` is the exact bytes read from
/// `route_path`. `route_path` is accepted by [`validator_sha256`] for
/// signature parity but no longer drives the digest — see that function's
/// doc.
pub fn validate_receipt(route_path: &Path, receipt_path: &Path, raw: &[u8]) -> Vec<String> {
    let receipt_text = match std::fs::read_to_string(receipt_path) {
        Ok(text) => text,
        Err(exc) => return vec![format!("receipt unreadable: {exc}")],
    };
    let receipt: Value = match serde_json::from_str(&receipt_text) {
        Ok(value) => value,
        Err(exc) => return vec![format!("receipt unreadable: {exc}")],
    };

    let validator_hash = match validator_sha256(route_path) {
        Ok(hash) => hash,
        Err(exc) => return vec![format!("receipt unreadable: {exc}")],
    };

    let expected: Vec<(&str, String)> = vec![
        ("schema", RECEIPT_SCHEMA.to_string()),
        ("route_path", canonical_locator(route_path)),
        ("route_sha256", sha256_bytes(raw)),
        ("validator_version", VALIDATOR_VERSION.to_string()),
        ("validator_sha256", validator_hash),
    ];

    let mut errors = Vec::new();
    for (key, value) in expected {
        if receipt.get(key).and_then(Value::as_str) != Some(value.as_str()) {
            errors.push(format!("receipt {key} mismatch"));
        }
    }
    errors
}
