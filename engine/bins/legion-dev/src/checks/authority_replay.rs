//! Grades supplied observations, never routes prose or fabricates model runs.
use legion_contracts::{fold_role_adoption, AuthorityKind, RoleDecisionState, RouteOutcomeTrace};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Label {
    role: AuthorityKind,
    eligible: Option<bool>,
    allowed_states: Vec<RoleDecisionState>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    schema: String,
    id: String,
    prompt: String,
    provenance: Value,
    labels: Vec<Label>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    case_id: String,
    trace: RouteOutcomeTrace,
}

fn json_lines<T: for<'de> Deserialize<'de>>(text: &str) -> Result<Vec<T>, String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 1)))
        .collect()
}

fn evaluate(cases: Vec<Case>, observations: Vec<Observation>) -> Result<Value, String> {
    let mut ids = HashSet::new();
    for case in &cases {
        if case.schema != "role-adoption-replay.v1"
            || case.id.trim().is_empty()
            || case.prompt.trim().is_empty()
            || !case.provenance.is_object()
            || !ids.insert(case.id.clone())
            || case.labels.is_empty()
        {
            return Err(format!("invalid/duplicate case {}", case.id));
        }
        let mut roles = Vec::new();
        for label in &case.labels {
            if roles.contains(&label.role) || label.allowed_states.is_empty() {
                return Err(format!("invalid/duplicate role label in {}", case.id));
            }
            roles.push(label.role);
        }
    }
    let mut by_case: HashMap<String, Vec<RouteOutcomeTrace>> = HashMap::new();
    let mut request_cases = HashMap::new();
    let mut trace_ids = HashSet::new();
    for observation in observations {
        if !ids.contains(&observation.case_id) {
            return Err(format!("unknown case {}", observation.case_id));
        }
        observation
            .trace
            .validate()
            .map_err(|e| format!("{}: {e}", observation.case_id))?;
        if !trace_ids.insert(observation.trace.trace_id.to_string()) {
            return Err("duplicate trace id".into());
        }
        let request = observation.trace.request_id.to_string();
        if let Some(prior) = request_cases.insert(request, observation.case_id.clone()) {
            if prior != observation.case_id {
                return Err("request id crosses replay cases".into());
            }
        }
        by_case
            .entry(observation.case_id)
            .or_default()
            .push(observation.trace);
    }
    let mut failures = Vec::new();
    let mut missing_cases = Vec::new();
    let mut unknown_decisions = 0usize;
    let mut labelled_traces = Vec::new();
    let mut results: HashMap<String, usize> = HashMap::new();
    for case in &cases {
        let Some(traces) = by_case.get(&case.id) else {
            missing_cases.push(case.id.clone());
            continue;
        };
        // A case is one request with lifecycle updates in append order.
        if traces
            .iter()
            .map(|t| t.request_id.to_string())
            .collect::<HashSet<_>>()
            .len()
            != 1
        {
            return Err(format!("{} must describe one request", case.id));
        }
        for label in &case.labels {
            let latest = traces
                .iter()
                .rev()
                .filter_map(|t| t.role_decisions.as_ref())
                .flat_map(|ds| ds.iter())
                .find(|d| d.role == label.role);
            match latest {
                None => {
                    unknown_decisions += 1;
                    failures.push(
                        json!({"case":case.id,"role":label.role,"kind":"unobserved-role-decision"}),
                    );
                }
                Some(d) if !label.allowed_states.contains(&d.state) => {
                    failures.push(json!({"case":case.id,"role":label.role,"kind":"unexpected-state","observed":d.state,"allowed":label.allowed_states}));
                }
                _ => {}
            }
        }
        for trace in traces {
            let mut labelled = trace.clone();
            if let Some(decisions) = &mut labelled.role_decisions {
                for decision in decisions {
                    // Independent labels control eligibility, not the producer's self-label.
                    decision.eligible = case
                        .labels
                        .iter()
                        .find(|l| l.role == decision.role)
                        .and_then(|l| l.eligible);
                }
            }
            labelled_traces.push(labelled);
        }
        if let Some(last) = traces.last() {
            *results
                .entry(
                    serde_json::to_string(&last.result)
                        .unwrap()
                        .trim_matches('"')
                        .into(),
                )
                .or_default() += 1;
        }
    }
    let metrics = fold_role_adoption(&labelled_traces);
    let rate = (metrics.labelled_eligible != 0)
        .then(|| metrics.eligible_launches as f64 / metrics.labelled_eligible as f64);
    let mut roles = serde_json::Map::new();
    for role in [
        AuthorityKind::Sage,
        AuthorityKind::Alchemist,
        AuthorityKind::Oracle,
    ] {
        let traces = labelled_traces
            .iter()
            .map(|trace| {
                let mut trace = trace.clone();
                if let Some(decisions) = &mut trace.role_decisions {
                    decisions.retain(|d| d.role == role);
                }
                trace
            })
            .collect::<Vec<_>>();
        roles.insert(
            serde_json::to_value(role).unwrap().as_str().unwrap().into(),
            serde_json::to_value(fold_role_adoption(&traces)).unwrap(),
        );
    }
    Ok(
        json!({"schemaVersion":1,"kind":"legion-authority-replay","labelSource":"independent-cases",
        "cases":cases.len(),"observedCases":by_case.len(),"missingCases":missing_cases,
        "unobservedDecisions":unknown_decisions,"failures":failures,"metrics":metrics,"adoptionRate":rate,
        "roles":roles,"outcomes":results,"valid":!cases.is_empty() && missing_cases.is_empty() && failures.is_empty()}),
    )
}

pub fn run(root: &Path, cases: &Path, observations: &Path) -> bool {
    let result = fs::read_to_string(root.join(cases))
        .map_err(|e| e.to_string())
        .and_then(|text| json_lines::<Case>(&text))
        .and_then(|cases| {
            fs::read_to_string(root.join(observations))
                .map_err(|e| e.to_string())
                .and_then(|text| json_lines::<Observation>(&text))
                .and_then(|observations| evaluate(cases, observations))
        });
    match result {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            report["valid"] == true
        }
        Err(error) => {
            eprintln!("authority replay: {error}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CASES: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/evals/architecture/authority-adoption.jsonl"
    ));
    const OBSERVATIONS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/evals/architecture/authority-adoption-observations.jsonl"
    ));

    #[test]
    fn labelled_reference_observations_pass() {
        let report = evaluate(
            json_lines(CASES).unwrap(),
            json_lines(OBSERVATIONS).unwrap(),
        )
        .unwrap();
        assert_eq!(report["valid"], true);
        assert_eq!(report["metrics"]["eligible_skips"], 0);
        assert_eq!(report["metrics"]["unnecessary_launches"], 0);
        assert_eq!(report["roles"]["sage"]["eligible_launches"], 2);
        assert_eq!(report["roles"]["alchemist"]["pending_bound"], 1);
        assert!(report["adoptionRate"].as_f64().unwrap() <= 1.0);
    }

    #[test]
    fn replay_exposes_unnecessary_launch_without_trusting_producer_label() {
        let mut observations: Vec<Observation> = json_lines(OBSERVATIONS).unwrap();
        let decision = &mut observations[0].trace.role_decisions.as_mut().unwrap()[0];
        decision.state = RoleDecisionState::Launched;
        decision.eligible = Some(true);
        let report = evaluate(json_lines(CASES).unwrap(), observations).unwrap();
        assert_eq!(report["valid"], false);
        assert_eq!(report["metrics"]["unnecessary_launches"], 1);
    }

    #[test]
    fn incomplete_and_v1_data_does_not_become_invented_misses() {
        let cases: Vec<Case> = json_lines(CASES).unwrap();
        let mut observations: Vec<Observation> = json_lines(OBSERVATIONS).unwrap();
        observations[0].trace.schema_version = 1;
        observations[0].trace.role_decisions = None;
        observations.pop();
        let report = evaluate(cases, observations).unwrap();
        assert_eq!(report["valid"], false);
        assert_eq!(report["metrics"]["eligible_skips"], 0);
        assert!(report["unobservedDecisions"].as_u64().unwrap() > 0);
        assert!(!report["missingCases"].as_array().unwrap().is_empty());
    }

    #[test]
    fn eligible_skip_fails_and_lifecycle_update_counts_only_latest_launch() {
        let mut observations: Vec<Observation> = json_lines(OBSERVATIONS).unwrap();
        let decision = &mut observations[1].trace.role_decisions.as_mut().unwrap()[0];
        decision.state = RoleDecisionState::Skipped;
        decision.reason = Some("Host gate prevented launch".into());
        let report = evaluate(json_lines(CASES).unwrap(), observations).unwrap();
        assert_eq!(report["valid"], false);
        assert_eq!(report["metrics"]["eligible_skips"], 1);
        assert_eq!(report["metrics"]["pending_selected"], 0);
        assert_eq!(report["metrics"]["pending_bound"], 1);
        assert_eq!(report["metrics"]["unknown_launches"], 1);
        assert_eq!(report["metrics"]["labelled_eligible"], 6);
    }

    #[test]
    fn duplicate_observations_and_cross_case_requests_are_rejected() {
        let mut observations: Vec<Observation> = json_lines(OBSERVATIONS).unwrap();
        observations[1].trace.trace_id = observations[0].trace.trace_id.clone();
        assert!(evaluate(json_lines(CASES).unwrap(), observations).is_err());
        let mut observations: Vec<Observation> = json_lines(OBSERVATIONS).unwrap();
        observations[1].trace.request_id = observations[0].trace.request_id.clone();
        assert!(evaluate(json_lines(CASES).unwrap(), observations).is_err());
    }
}
