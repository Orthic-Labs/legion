//! Retained items of the ux port: `analyze_data_interactions` and
//! `create_flow_model` (no production caller) with their helpers. Other ux
//! providers reachable only from deleted tests were removed in the sweep.
use serde_json::Value;
use std::collections::HashSet;

fn arr<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|n| n != 0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(_)) => true,
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub fn analyze_data_interactions(input: &Value) -> Value {
    let interactions: Vec<Value> = arr(input, "interactions").into_iter().cloned().collect();
    let mut findings: Vec<Value> = Vec::new();
    let mut coverage_gaps: Vec<Value> = Vec::new();
    if interactions.is_empty() {
        coverage_gaps.push(Value::String("interaction-denominator-missing".into()));
    }
    let flags = [
        ("unstableSort", "ux.data-sort-unstable"),
        ("hiddenFilterState", "ux.data-filter-hidden"),
        ("unboundedList", "ux.data-list-unbounded"),
        ("lostSelection", "ux.data-selection-lost"),
        ("exportMismatch", "ux.data-export-mismatch"),
        ("missingSystemStates", "ux.data-system-states-missing"),
    ];
    for item in &interactions {
        let id = item.get("id").cloned().unwrap_or(Value::Null);
        let dataset = item.get("dataset").cloned().unwrap_or(Value::Null);
        let kind = item.get("kind").and_then(Value::as_str).unwrap_or_default();
        if truthy(item.get("largeDataClaim")) && !truthy(item.get("scaleEvidence")) {
            coverage_gaps.push(Value::String(format!(
                "scale-evidence-missing:{}",
                id.as_str().unwrap_or_default()
            )));
        }
        if kind == "table" && item.get("headersAccessible") == Some(&Value::Bool(false)) {
            findings.push(serde_json::json!({ "ruleId": "ux.data-table-headers", "interactionId": id, "dataset": dataset, "action": "read", "judgmentClass": "deterministic" }));
        }
        if kind == "chart" && truthy(item.get("misleadingEncoding")) {
            findings.push(serde_json::json!({ "ruleId": "ux.chart-encoding-candidate", "interactionId": id, "dataset": dataset, "action": "interpret", "judgmentClass": "interpretive" }));
        }
        if truthy(item.get("destructiveBulkAmbiguity")) {
            findings.push(serde_json::json!({ "ruleId": "ux.bulk-action-ambiguous", "interactionId": id, "dataset": dataset, "action": "bulk", "judgmentClass": "deterministic" }));
        }
        for (flag, rule_id) in flags {
            if truthy(item.get(flag)) {
                findings.push(serde_json::json!({ "ruleId": rule_id, "interactionId": id, "dataset": dataset, "action": kind, "judgmentClass": "deterministic" }));
            }
        }
    }
    let status = if !findings.is_empty() {
        "candidates"
    } else if !coverage_gaps.is_empty() {
        "unproven"
    } else {
        "pass"
    };
    serde_json::json!({ "provider": "ux.data-interaction", "status": status, "findings": findings, "coverageGaps": coverage_gaps })
}

pub fn create_flow_model(input: &Value) -> Value {
    let flows: Vec<Value> = arr(input, "flows").into_iter().cloned().collect();
    if flows.is_empty() {
        return serde_json::json!({ "provider": "ux.flow-model", "status": "unproven", "flows": [], "requiredGoals": [], "coverageGaps": ["zero-flow-denominator"] });
    }
    let required: HashSet<String> = strings(input.get("requiredGoalPolicy"))
        .into_iter()
        .collect();
    let required_goals: Vec<Value> = flows
        .iter()
        .filter(|flow| {
            !truthy(flow.get("goalInferred"))
                || flow
                    .get("goal")
                    .and_then(Value::as_str)
                    .map(|g| required.contains(g))
                    .unwrap_or(false)
        })
        .map(|flow| flow.get("goal").cloned().unwrap_or(Value::Null))
        .collect();
    let mut coverage_gaps: Vec<Value> = Vec::new();
    for flow in &flows {
        let id = flow.get("id").and_then(Value::as_str).unwrap_or_default();
        let terminal = flow.get("terminalState").and_then(Value::as_str);
        if terminal.is_none() || terminal == Some("unproven") {
            coverage_gaps.push(Value::String(format!("flow-unproven:{id}")));
        }
        if arr(flow, "steps").is_empty() {
            coverage_gaps.push(Value::String(format!("flow-empty:{id}")));
        }
    }
    serde_json::json!({
        "provider": "ux.flow-model", "status": if coverage_gaps.is_empty() { "pass" } else { "unproven" },
        "flows": flows, "requiredGoals": required_goals, "coverageGaps": coverage_gaps,
    })
}
