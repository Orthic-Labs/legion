//! Port of `src/providers/ux/*.mjs` plus `src/lib/design/surfaces.mjs`
//! (`buildSurfaceInventory`, used only by `ux/surface-inventory.mjs`).

use super::visual_core::sha256_digest;
use serde_json::{Map, Value};
use std::collections::HashSet;

fn arr<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value.get(key).and_then(Value::as_array).map(|items| items.iter().collect()).unwrap_or_default()
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
    value.and_then(Value::as_array).map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

// ---------------------------------------------------------------------
// ux/control-states.mjs
// ---------------------------------------------------------------------

pub fn analyze_control_states(input: &Value) -> Value {
    let controls: Vec<Value> = arr(input, "controls").into_iter().cloned().collect();
    if controls.is_empty() {
        return serde_json::json!({ "provider": "ux.control-states", "status": "unproven", "complete": false, "applicability": {}, "findings": [], "coverageGaps": ["zero-control-denominator"] });
    }
    let mut applicability = Map::new();
    let mut findings: Vec<Value> = Vec::new();
    for control in &controls {
        let id = control.get("id").cloned().unwrap_or(Value::Null);
        let role = control.get("role").cloned().unwrap_or(Value::Null);
        let accessible_name = control.get("accessibleName").cloned().unwrap_or(Value::Null);
        let applicable_raw = strings(control.get("applicableStates"));
        let applicable: Vec<String> = if applicable_raw.is_empty() { vec!["default".to_string()] } else {
            let mut seen = HashSet::new();
            applicable_raw.into_iter().filter(|s| seen.insert(s.clone())).collect()
        };
        let observed: HashSet<String> = strings(control.get("observedStates")).into_iter().collect();
        let missing_states: Vec<Value> = applicable.iter().filter(|s| !observed.contains(*s)).map(|s| Value::String(s.clone())).collect();
        applicability.insert(id.as_str().unwrap_or_default().to_string(), Value::Array(applicable.iter().map(|s| Value::String(s.clone())).collect()));
        if !missing_states.is_empty() {
            findings.push(serde_json::json!({ "ruleId": "ux.control-state-missing", "controlId": id, "role": role, "accessibleName": accessible_name, "missingStates": missing_states, "links": ["accessibility", "visual", "copy", "runtime"] }));
        }
        if truthy(control.get("disabledInteractive")) {
            findings.push(serde_json::json!({ "ruleId": "ux.control-disabled-interactive", "controlId": id, "role": role, "accessibleName": accessible_name }));
        }
        if truthy(control.get("doubleSubmitRisk")) {
            findings.push(serde_json::json!({ "ruleId": "ux.control-double-submit", "controlId": id, "role": role, "accessibleName": accessible_name }));
        }
    }
    let complete = findings.iter().all(|item| item.get("ruleId") != Some(&Value::String("ux.control-state-missing".into())));
    serde_json::json!({
        "provider": "ux.control-states", "status": if findings.is_empty() { "pass" } else { "candidates" },
        "complete": complete, "applicability": applicability, "findings": findings,
    })
}

// ---------------------------------------------------------------------
// ux/data-interaction.mjs
// ---------------------------------------------------------------------

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
            coverage_gaps.push(Value::String(format!("scale-evidence-missing:{}", id.as_str().unwrap_or_default())));
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
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({ "provider": "ux.data-interaction", "status": status, "findings": findings, "coverageGaps": coverage_gaps })
}

// ---------------------------------------------------------------------
// ux/flow-model.mjs
// ---------------------------------------------------------------------

pub fn create_flow_model(input: &Value) -> Value {
    let flows: Vec<Value> = arr(input, "flows").into_iter().cloned().collect();
    if flows.is_empty() {
        return serde_json::json!({ "provider": "ux.flow-model", "status": "unproven", "flows": [], "requiredGoals": [], "coverageGaps": ["zero-flow-denominator"] });
    }
    let required: HashSet<String> = strings(input.get("requiredGoalPolicy")).into_iter().collect();
    let required_goals: Vec<Value> = flows
        .iter()
        .filter(|flow| !truthy(flow.get("goalInferred")) || flow.get("goal").and_then(Value::as_str).map(|g| required.contains(g)).unwrap_or(false))
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

// ---------------------------------------------------------------------
// ux/forms.mjs
// ---------------------------------------------------------------------

pub fn analyze_forms(input: &Value) -> Value {
    let forms: Vec<Value> = arr(input, "forms").into_iter().cloned().collect();
    let fields: Vec<(Value, Value)> = forms
        .iter()
        .flat_map(|form| arr(form, "fields").into_iter().map(move |field| (form.clone(), field.clone())))
        .collect();
    if fields.is_empty() {
        return serde_json::json!({
            "provider": "ux.forms", "status": "unproven", "fieldDenominator": 0, "findings": [],
            "coverageGaps": ["zero-field-denominator"], "serverSecurityProven": false, "sensitiveFieldAssumptions": [],
        });
    }
    let mut findings: Vec<Value> = Vec::new();
    let field_flags = [
        ("prematureValidation", "ux.forms-premature-validation"),
        ("hiddenRequirement", "ux.forms-hidden-requirement"),
        ("inaccessibleError", "ux.forms-error-association"),
        ("ambiguousSelect", "ux.forms-select-ambiguous"),
    ];
    for (form, field) in &fields {
        let form_id = form.get("id").cloned().unwrap_or(Value::Null);
        let field_id = field.get("id").cloned().unwrap_or(Value::Null);
        if !truthy(field.get("label")) {
            findings.push(serde_json::json!({ "ruleId": "ux.forms-label-missing", "formId": form_id, "fieldId": field_id }));
        }
        let applicable: HashSet<String> = strings(field.get("applicableStates")).into_iter().collect();
        let observed: HashSet<String> = strings(field.get("observedStates")).into_iter().collect();
        let missing_states: Vec<Value> = applicable.difference(&observed).map(|s| Value::String(s.clone())).collect();
        if !missing_states.is_empty() {
            findings.push(serde_json::json!({ "ruleId": "ux.forms-state-missing", "formId": form_id, "fieldId": field_id, "missingStates": missing_states }));
        }
        if truthy(field.get("losesInput")) {
            findings.push(serde_json::json!({ "ruleId": "ux.forms-input-loss", "formId": form_id, "fieldId": field_id }));
        }
        for (flag, rule_id) in field_flags {
            if truthy(field.get(flag)) {
                findings.push(serde_json::json!({ "ruleId": rule_id, "formId": form_id, "fieldId": field_id }));
            }
        }
    }
    let form_flags = [
        ("destructiveReset", "ux.forms-destructive-reset"),
        ("doubleSubmit", "ux.forms-double-submit"),
        ("unrecoverableStep", "ux.forms-multistep-unrecoverable"),
    ];
    for form in &forms {
        let form_id = form.get("id").cloned().unwrap_or(Value::Null);
        for (flag, rule_id) in form_flags {
            if truthy(form.get(flag)) {
                findings.push(serde_json::json!({ "ruleId": rule_id, "formId": form_id, "fieldId": Value::Null }));
            }
        }
    }
    let server_security_proven = forms.iter().any(|form| truthy(form.get("serverValidationEvidence")))
        && forms.iter().all(|form| !truthy(form.get("clientValidation")) || truthy(form.get("serverValidationEvidence")));
    let sensitive_field_assumptions: Vec<Value> = forms.iter().flat_map(|form| arr(form, "sensitiveFieldAssumptions").into_iter().cloned()).collect();
    serde_json::json!({
        "provider": "ux.forms", "status": if findings.is_empty() { "pass" } else { "candidates" },
        "fieldDenominator": fields.len(), "findings": findings,
        "serverSecurityProven": server_security_proven, "sensitiveFieldAssumptions": sensitive_field_assumptions,
    })
}

// ---------------------------------------------------------------------
// ux/friction.mjs
// ---------------------------------------------------------------------

pub fn analyze_friction(input: &Value) -> Value {
    let flows: Vec<Value> = arr(input, "flows").into_iter().cloned().collect();
    let mut findings: Vec<Value> = Vec::new();
    let mut candidates: Vec<Value> = Vec::new();
    let coverage_gaps: Vec<Value> = if flows.is_empty() { vec![Value::String("flow-denominator-missing".into())] } else { vec![] };
    for flow in &flows {
        let flow_id = flow.get("id").cloned().unwrap_or(Value::Null);
        let policy_context = flow.get("policyContext").and_then(Value::as_str).unwrap_or("unknown");
        for step in arr(flow, "steps") {
            let step_id = step.get("id").cloned().unwrap_or(Value::Null);
            let evidence = step.get("evidence").cloned().unwrap_or_else(|| Value::String(format!("step:{}", step_id.as_str().unwrap_or_default())));
            let loops = step.get("loopTo") == step.get("id");
            if loops || truthy(step.get("unreachableHelp")) || truthy(step.get("contradictsControl")) || truthy(step.get("requiredInfoAfterDecision")) || truthy(step.get("unreachableReport")) || truthy(step.get("unreachableAppeal")) {
                findings.push(serde_json::json!({ "ruleId": "ux.friction-deterministic", "flowId": flow_id, "stepId": step_id, "policyContext": policy_context, "evidence": evidence, "judgmentClass": "deterministic" }));
            }
            if truthy(step.get("memoryBurden")) || truthy(step.get("distracting")) || truthy(step.get("timePressure")) || truthy(step.get("tooltipDependence")) || truthy(step.get("repeatedEntry")) {
                candidates.push(serde_json::json!({ "ruleId": "ux.friction-interpretive", "flowId": flow_id, "stepId": step_id, "policyContext": policy_context, "evidence": evidence, "judgmentClass": "interpretive" }));
            }
        }
    }
    let status = if !findings.is_empty() || !candidates.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({ "provider": "ux.friction", "status": status, "findings": findings, "candidates": candidates, "coverageGaps": coverage_gaps, "universalMaximumSteps": Value::Null })
}

// ---------------------------------------------------------------------
// ux/navigation.mjs
// ---------------------------------------------------------------------

pub fn analyze_navigation(input: &Value) -> Value {
    let routes: Vec<Value> = arr(input, "routes").into_iter().cloned().collect();
    let flows: Vec<Value> = arr(input, "flows").into_iter().cloned().collect();
    let coverage_gaps: Vec<Value> = if routes.is_empty() { vec![Value::String("navigation-routes-missing".into())] } else { vec![] };
    let used: HashSet<String> = flows.iter().flat_map(|flow| strings(flow.get("routes"))).collect();
    let mut findings: Vec<Value> = routes
        .iter()
        .filter(|route| route.get("path").and_then(Value::as_str).map(|p| !used.contains(p)).unwrap_or(true))
        .map(|route| {
            let path = route.get("path").cloned().unwrap_or(Value::Null);
            serde_json::json!({ "ruleId": "ux.navigation-unreachable", "route": path, "flowIds": [], "evidenceRefs": [format!("route:{}", path.as_str().unwrap_or_default())] })
        })
        .collect();
    let mut labels: std::collections::BTreeMap<String, Vec<Value>> = std::collections::BTreeMap::new();
    for route in &routes {
        if let Some(label) = route.get("label").and_then(Value::as_str) {
            labels.entry(label.to_string()).or_default().push(route.get("path").cloned().unwrap_or(Value::Null));
        }
    }
    for (label, paths) in &labels {
        if paths.len() > 1 {
            let evidence_refs: Vec<Value> = paths.iter().map(|p| Value::String(format!("route:{}", p.as_str().unwrap_or_default()))).collect();
            findings.push(serde_json::json!({ "ruleId": "ux.navigation-duplicate-label", "label": label, "routes": paths, "evidenceRefs": evidence_refs }));
        }
    }
    let route_flags = [
        ("missingActiveState", "ux.navigation-active-state-missing"),
        ("misleadingBack", "ux.navigation-back-misleading"),
        ("hiddenCritical", "ux.navigation-critical-hidden"),
        ("orientationMissing", "ux.navigation-orientation-missing"),
    ];
    for route in &routes {
        let path = route.get("path").cloned().unwrap_or(Value::Null);
        for (flag, rule_id) in route_flags {
            if truthy(route.get(flag)) {
                findings.push(serde_json::json!({ "ruleId": rule_id, "route": path, "evidenceRefs": [format!("route:{}", path.as_str().unwrap_or_default())] }));
            }
        }
    }
    for flow in &flows {
        let flow_routes = strings(flow.get("routes"));
        if flow_routes.len() > 4 {
            let flow_id = flow.get("id").cloned().unwrap_or(Value::Null);
            findings.push(serde_json::json!({ "ruleId": "ux.navigation-depth-candidate", "flowId": flow_id, "depth": flow_routes.len(), "evidenceRefs": [format!("flow:{}", flow_id.as_str().unwrap_or_default())], "judgmentClass": "candidate" }));
        }
    }
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({ "provider": "ux.navigation", "status": status, "findings": findings, "coverageGaps": coverage_gaps, "suggestions": [] })
}

// ---------------------------------------------------------------------
// ux/recovery.mjs
// ---------------------------------------------------------------------

pub fn analyze_recovery(input: &Value) -> Value {
    let actions: Vec<Value> = arr(input, "actions").into_iter().cloned().collect();
    let normalized: Vec<Value> = actions
        .iter()
        .map(|action| {
            let mut object = action.as_object().cloned().unwrap_or_default();
            let irreversible = if truthy(action.get("sideEffectEvidence")) {
                Value::Bool(truthy(action.get("claimedIrreversible")))
            } else {
                Value::String("unproven".into())
            };
            object.insert("irreversible".into(), irreversible);
            Value::Object(object)
        })
        .collect();
    let mut findings: Vec<Value> = Vec::new();
    let coverage_gaps: Vec<Value> = if actions.is_empty() { vec![Value::String("action-denominator-missing".into())] } else { vec![] };
    for action in &normalized {
        let id = action.get("id").cloned().unwrap_or(Value::Null);
        let risk = action.get("risk").cloned().unwrap_or(Value::Null);
        let recovery_path_missing = || action.get("undoEvidence").or_else(|| action.get("recoveryPath")).cloned().unwrap_or_else(|| Value::String("missing".into()));
        if action.get("risk") == Some(&Value::String("high".into())) && action.get("confirmation") != Some(&Value::Bool(true)) {
            findings.push(serde_json::json!({ "ruleId": "ux.recovery-confirmation-missing", "actionId": id, "actionRisk": risk, "recoveryEvidence": recovery_path_missing() }));
        }
        if truthy(action.get("progress")) && !truthy(action.get("terminalEvidence")) {
            findings.push(serde_json::json!({ "ruleId": "ux.recovery-terminal-state-missing", "actionId": id, "actionRisk": risk, "recoveryEvidence": action.get("recoveryPath").cloned().unwrap_or_else(|| Value::String("missing".into())) }));
        }
        if truthy(action.get("policyRequiresUndo")) && !truthy(action.get("undoEvidence")) {
            findings.push(serde_json::json!({ "ruleId": "ux.recovery-undo-missing", "actionId": id, "actionRisk": risk, "recoveryEvidence": "missing" }));
        }
        if action.get("feedbackAssistive") == Some(&Value::Bool(false)) {
            findings.push(serde_json::json!({ "ruleId": "ux.recovery-feedback-inaccessible", "actionId": id, "actionRisk": risk, "recoveryEvidence": action.get("recoveryPath").cloned().unwrap_or_else(|| Value::String("missing".into())) }));
        }
        if truthy(action.get("errorLosesWork")) {
            findings.push(serde_json::json!({ "ruleId": "ux.recovery-work-loss", "actionId": id, "actionRisk": risk, "recoveryEvidence": action.get("recoveryPath").cloned().unwrap_or_else(|| Value::String("missing".into())) }));
        }
    }
    let any_unproven = normalized.iter().any(|item| item.get("irreversible") == Some(&Value::String("unproven".into())));
    let status = if !findings.is_empty() { "candidates" } else if any_unproven || !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({ "provider": "ux.recovery", "status": status, "actions": normalized, "findings": findings, "coverageGaps": coverage_gaps })
}

// ---------------------------------------------------------------------
// lib/design/surfaces.mjs :: buildSurfaceInventory (ux/surface-inventory.mjs)
// ---------------------------------------------------------------------

pub fn inventory_surfaces(input: &Value) -> Value {
    let artifacts: Vec<Value> = arr(input, "artifacts").into_iter().cloned().collect();
    let binding = input.get("binding").cloned().unwrap_or(Value::Object(Map::new()));
    let surfaces: Vec<Value> = artifacts
        .iter()
        .map(|artifact| {
            let file = artifact.get("file").cloned().unwrap_or(Value::Null);
            let route = artifact.get("route").and_then(Value::as_str).unwrap_or("");
            let kind = artifact.get("type").and_then(Value::as_str).unwrap_or("surface");
            let id_source = format!("{}\0{}\0{}", file.as_str().unwrap_or_default(), route, kind);
            let states = artifact.get("states").cloned().unwrap_or_else(|| Value::Array(vec![Value::String("default".into())]));
            serde_json::json!({
                "id": sha256_digest(id_source.as_bytes()), "file": file,
                "route": artifact.get("route").cloned().unwrap_or(Value::Null),
                "type": kind, "framework": artifact.get("framework").cloned().unwrap_or(Value::Null),
                "states": states, "controls": artifact.get("controls").cloned().unwrap_or(Value::Array(vec![])),
                "protectedRegions": artifact.get("protectedRegions").cloned().unwrap_or(Value::Array(vec![])),
                "runtimeEligible": artifact.get("runtimeEligible") != Some(&Value::Bool(false)),
                "visibility": artifact.get("visibility").and_then(Value::as_str).unwrap_or("user-facing"),
            })
        })
        .collect();
    let complete = artifacts.iter().all(|artifact| truthy(artifact.get("file")));
    let coverage_gaps: Vec<Value> = artifacts.iter().filter(|artifact| !truthy(artifact.get("file"))).map(|_| Value::String("surface-source-missing".into())).collect();
    let denominator_digest = sha256_digest(serde_json::to_string(&Value::Array(surfaces.clone())).unwrap_or_default().as_bytes());
    serde_json::json!({
        "schemaVersion": 1, "kind": "legion-surface-inventory", "binding": binding, "surfaces": surfaces,
        "denominatorDigest": denominator_digest, "complete": complete, "coverageGaps": coverage_gaps,
    })
}

// ---------------------------------------------------------------------
// ux/system-states.mjs
// ---------------------------------------------------------------------

pub fn analyze_system_states(input: &Value) -> Value {
    let surfaces: Vec<Value> = arr(input, "surfaces").into_iter().cloned().collect();
    let mut findings: Vec<Value> = Vec::new();
    let mut coverage_gaps: Vec<Value> = Vec::new();
    let mut denominator: u64 = 0;
    let state_flags = [
        ("blankScreen", "ux.system-state-blank"),
        ("indefiniteSpinner", "ux.system-state-indefinite-loading"),
        ("genericSkeleton", "ux.system-state-generic-skeleton"),
        ("emptyActionMissing", "ux.system-state-empty-action"),
        ("offlineDeadEnd", "ux.system-state-offline-dead-end"),
        ("staleAmbiguity", "ux.system-state-stale-ambiguity"),
    ];
    for surface in &surfaces {
        let id = surface.get("id").cloned().unwrap_or(Value::Null);
        let declared: HashSet<String> = strings(surface.get("declaredStates")).into_iter().collect();
        let observed: HashSet<String> = strings(surface.get("observedStates")).into_iter().collect();
        for state in strings(surface.get("expectedStates")) {
            denominator += 1;
            if !declared.contains(&state) {
                coverage_gaps.push(Value::String(format!("state-absent:{}:{}", id.as_str().unwrap_or_default(), state)));
            } else if !observed.contains(&state) {
                coverage_gaps.push(Value::String(format!("state-untested:{}:{}", id.as_str().unwrap_or_default(), state)));
            }
        }
        let evidence_class = if truthy(surface.get("runtimeEvidence")) { "runtime" } else { "source" };
        if truthy(surface.get("falseSuccess")) {
            findings.push(serde_json::json!({ "ruleId": "ux.system-state-false-success", "surfaceId": id, "evidenceClass": evidence_class }));
        }
        if truthy(surface.get("errorWithoutRetry")) {
            findings.push(serde_json::json!({ "ruleId": "ux.system-state-retry-missing", "surfaceId": id, "evidenceClass": evidence_class }));
        }
        for (flag, rule_id) in state_flags {
            if truthy(surface.get(flag)) {
                findings.push(serde_json::json!({ "ruleId": rule_id, "surfaceId": id, "evidenceClass": evidence_class }));
            }
        }
    }
    if denominator == 0 {
        coverage_gaps.push(Value::String("state-denominator-missing".into()));
    }
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({ "provider": "ux.system-states", "status": status, "denominator": denominator, "findings": findings, "coverageGaps": coverage_gaps })
}
