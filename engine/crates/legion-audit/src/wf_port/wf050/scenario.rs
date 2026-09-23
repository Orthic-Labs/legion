//! Port of `src/providers/runtime/web/scenario/index.mjs`
//! (`runWebScenario`, plus its private `browserDiagnosticGaps` and
//! `serverAuthorizationGaps` helpers) — chunk wf050.
//!
//! Dependencies outside this chunk's owned paths:
//! - `WEB_JOURNEYS` / `WEB_PROTOCOLS` / `webRouteEvidenceMatches` from
//!   `../journey-plan.mjs`, backed by `registry/platform-scenarios/web.json`.
//!   Taken here as `journeys: &[Value]` / `protocols: &[Value]` plan
//!   tables plus a local port of `webRouteEvidenceMatches` (below), rather
//!   than loading the registry file, since the registry and its loader
//!   are not part of this chunk's file list.
//! - `sanitizeProducedArtifact` (`src/lib/platform/artifact-sanitize.mjs`)
//!   — taken as `sanitize_artifact`.
//! - `adapter.invoke` / `adapter.invokeProtocol` — taken as
//!   `journey_invoke` / `protocol_invoke` closures; the JS `adapter
//!   .invokeProtocol ?? adapter.invoke` fallback is the caller's
//!   responsibility (pass the resolved closure as `protocol_invoke`).
//!
//! See the wf050 report for this dependency.

use serde_json::{json, Value};

use super::shared::{canonicalize, denominator, exact_binding, finalize, redact, same_binding, unique_sorted};

const RESULT_STATUSES: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error"];
const BROWSER_DIAGNOSTICS: &[&str] =
    &["cache", "console", "cookies", "cors", "csp", "error", "headers", "hydration", "network"];

fn is_safe_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    value.len() <= 80 && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

fn unequal(expected: &Value, actual: &Value) -> bool {
    let e = serde_json::to_string(&canonicalize(expected)).unwrap_or_default();
    let a = serde_json::to_string(&canonicalize(actual)).unwrap_or_default();
    e != a
}

/// Port of `webRouteEvidenceMatches(row, evidence, bindingMatches)` from
/// `journey-plan.mjs` (see module docs for why this is duplicated here).
fn web_route_evidence_matches(row: &Value, evidence: &Value, binding: &Value) -> bool {
    evidence.get("kind").and_then(Value::as_str) == Some("web-route-navigation")
        && evidence.get("journeyId") == row.get("id")
        && evidence.get("routeId") == row.get("routeId")
        && evidence.get("control") == row.get("controlId")
        && evidence.get("actionId") == row.get("actionId")
        && evidence.get("route") == row.get("route")
        && evidence.get("stateId") == row.get("stateId")
        && evidence.get("matrixCombinationId") == row.get("matrixCombinationId")
        && same_binding(binding, evidence.get("binding").unwrap_or(&Value::Null))
}

/// Port of the module-private `artifactEvidence(values, binding)` helper.
fn artifact_evidence(
    values: Option<&Value>,
    binding: &Value,
    sanitize_artifact: &dyn Fn(&Value) -> (bool, bool, Value),
) -> (Vec<Value>, Vec<String>) {
    match values {
        None => (Vec::new(), Vec::new()),
        Some(Value::Array(items)) => {
            // Each entry: (valid && bound, sensitive, sanitized artifact value).
            let processed: Vec<(bool, bool, Value)> = items
                .iter()
                .map(|artifact| {
                    let (valid, sensitive, sanitized) = sanitize_artifact(artifact);
                    let bound = same_binding(binding, artifact.get("binding").unwrap_or(&json!({})));
                    (valid && bound, sensitive, sanitized)
                })
                .collect();
            let artifacts: Vec<Value> = processed
                .iter()
                .filter(|(valid_and_bound, _, _)| *valid_and_bound)
                .map(|(_, _, sanitized)| sanitized.clone())
                .collect();
            let mut gaps = Vec::new();
            if processed.iter().any(|(valid_and_bound, _, _)| !*valid_and_bound) {
                gaps.push("artifact-evidence-invalid".to_string());
            }
            if processed.iter().any(|(_, sensitive, _)| *sensitive) {
                gaps.push("artifact-sensitive-data".to_string());
            }
            (artifacts, gaps)
        }
        Some(_) => (Vec::new(), vec!["artifact-collection-invalid".to_string()]),
    }
}

/// Port of `browserDiagnosticGaps(value, binding)`.
fn browser_diagnostic_gaps(value: Option<&Value>, binding: &Value) -> Vec<String> {
    let value = match value {
        Some(v) if v.is_object() => v,
        _ => return vec!["browser-diagnostics-missing".to_string()],
    };
    let mut gaps = Vec::new();
    let denominator_ids: Vec<String> = value
        .get("denominator")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let mut deduped: Vec<String> = denominator_ids.iter().cloned().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    deduped.sort();
    let expected: Vec<String> = BROWSER_DIAGNOSTICS.iter().map(|s| s.to_string()).collect();
    if deduped != expected {
        gaps.push("browser-diagnostics-denominator-mismatch".to_string());
    }
    let facts: Vec<Value> = value.get("facts").and_then(Value::as_array).cloned().unwrap_or_default();
    for id in BROWSER_DIAGNOSTICS {
        let matches: Vec<&Value> = facts.iter().filter(|item| item.get("id").and_then(Value::as_str) == Some(*id)).collect();
        if matches.is_empty() {
            gaps.push(format!("browser-diagnostic-missing:{id}"));
        } else {
            if matches.len() > 1 {
                gaps.push(format!("browser-diagnostic-duplicate:{id}"));
            }
            let fact = matches[0];
            if fact.get("status").and_then(Value::as_str) != Some("pass") || fact.get("terminal") != Some(&Value::Bool(true)) {
                gaps.push(format!("browser-diagnostic-unproven:{id}"));
            }
            if !same_binding(binding, fact.get("binding").unwrap_or(&json!({}))) {
                gaps.push(format!("browser-diagnostic-binding-mismatch:{id}"));
            }
        }
    }
    for fact in &facts {
        let id = fact.get("id").and_then(Value::as_str);
        if id.map(|id| !BROWSER_DIAGNOSTICS.contains(&id)).unwrap_or(true) {
            gaps.push(format!("browser-diagnostic-unplanned:{}", id.unwrap_or("missing")));
        }
    }
    gaps
}

/// Port of `serverAuthorizationGaps(value, binding, controlId)`.
fn server_authorization_gaps(value: Option<&Value>, binding: &Value, control_id: &str) -> Vec<String> {
    let value = match value {
        Some(v) if v.is_object() => v,
        _ => return vec!["server-authorization-evidence-missing".to_string()],
    };
    let mut gaps = Vec::new();
    if value.get("kind").and_then(Value::as_str) != Some("server-authorization-evidence")
        || value.get("source").and_then(Value::as_str) != Some("server")
        || value.get("uiDerived") != Some(&Value::Bool(false))
    {
        gaps.push("server-authorization-kind-invalid".to_string());
    }
    if value.get("actorId") != binding.get("actorId") {
        gaps.push("server-authorization-actor-mismatch".to_string());
    }
    if value.get("tenantId") != binding.get("tenantId") {
        gaps.push("server-authorization-tenant-mismatch".to_string());
    }
    if value.get("controlId").and_then(Value::as_str) != Some(control_id) {
        gaps.push("server-authorization-control-mismatch".to_string());
    }
    if value.get("status").and_then(Value::as_str) != Some("pass") || value.get("terminal") != Some(&Value::Bool(true)) {
        gaps.push("server-authorization-unproven".to_string());
    }
    let ids = value.get("authorizationIds").and_then(Value::as_array);
    let ids_valid = ids.map(|a| !a.is_empty() && a.iter().all(|id| matches!(id, Value::String(s) if !s.is_empty()))).unwrap_or(false);
    if !ids_valid {
        gaps.push("server-authorization-denominator-empty".to_string());
    }
    if !same_binding(binding, value.get("binding").unwrap_or(&json!({}))) {
        gaps.push("server-authorization-binding-mismatch".to_string());
    }
    gaps
}

/// Result of an `adapter.invoke(...)` / `adapter.invokeProtocol(...)` call.
pub enum AdapterCallResult {
    Ok(Value),
    Err { name: String, message: String },
}

/// Port of `runWebScenario({ binding, adapter, controls, protocols,
/// expectedState })`.
///
/// `journeys` is the `applicable === true` subset of `WEB_JOURNEYS`
/// (`REQUIRED_JOURNEYS` in the JS), each a JSON object with at least `id`,
/// `controlId`, `routeId`, `actionId`, `route`, `stateId`,
/// `matrixCombinationId`, `directApplicable`, `deepApplicable`.
/// `protocol_plan` is `WEB_PROTOCOLS`, each with `id`, `protocolId`,
/// `applicable`, and (when not applicable) `reason`.
#[allow(clippy::too_many_arguments)]
pub fn run_web_scenario(
    binding: &Value,
    controls: &Value,
    protocols: &Value,
    expected_state: &Value,
    journeys: &[Value],
    protocol_plan: &[Value],
    sanitize_artifact: &dyn Fn(&Value) -> (bool, bool, Value),
    journey_invoke: Option<&dyn Fn(&str, &Value, &Value, &Value) -> AdapterCallResult>,
    protocol_invoke: Option<&dyn Fn(&str, &Value, &Value) -> AdapterCallResult>,
) -> Value {
    let required_controls: Vec<String> =
        journeys.iter().filter_map(|j| j.get("controlId").and_then(Value::as_str).map(str::to_string)).collect();
    let route_controls: std::collections::HashSet<String> = journeys
        .iter()
        .filter(|j| j.get("directApplicable") == Some(&Value::Bool(true)) || j.get("deepApplicable") == Some(&Value::Bool(true)))
        .filter_map(|j| j.get("controlId").and_then(Value::as_str).map(str::to_string))
        .collect();

    let controls_arr = controls.as_array();
    let protocols_arr = protocols.as_array();
    if controls_arr.is_none() || protocols_arr.is_none() || protocols_arr.unwrap().iter().any(|p| !p.is_object()) {
        return finalize(
            "legion-web-scenario",
            json!({
                "status": "error",
                "terminal": true,
                "binding": binding,
                "denominator": denominator(&[], &[], &[]).to_value(),
                "receipts": [],
                "coverageGaps": ["scenario-collections-invalid"],
            }),
        );
    }
    let controls_arr = controls_arr.unwrap();
    let protocols_arr = protocols_arr.unwrap();

    let controls_ids_invalid =
        controls_arr.iter().any(|id| id.as_str().map(|s| !is_safe_identifier(s)).unwrap_or(true));
    let protocols_ids_invalid = protocols_arr.iter().any(|item| {
        let name_ok = item.get("name").and_then(Value::as_str).map(is_safe_identifier).unwrap_or(false);
        let id_ok = match item.get("id") {
            None => true,
            Some(Value::String(s)) => is_safe_identifier(s),
            _ => false,
        };
        !name_ok || !id_ok
    });
    if controls_ids_invalid || protocols_ids_invalid {
        return finalize(
            "legion-web-scenario",
            json!({
                "status": "error",
                "terminal": true,
                "binding": binding,
                "denominator": denominator(&[], &[], &[]).to_value(),
                "receipts": [],
                "coverageGaps": ["scenario-identifiers-invalid"],
            }),
        );
    }

    let supplied_controls: Vec<String> = controls_arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let mut ids: Vec<String> = journeys.iter().filter_map(|j| j.get("id").and_then(Value::as_str).map(str::to_string)).collect();
    ids.extend(protocol_plan.iter().filter_map(|p| p.get("id").and_then(Value::as_str).map(str::to_string)));
    ids.sort();

    let binding_gaps = exact_binding(binding).gaps;

    if binding.get("environment").and_then(Value::as_str) == Some("production") {
        let receipts: Vec<Value> =
            ids.iter().map(|id| json!({ "id": id, "status": "blocked", "terminal": true, "reason": "production-effect-forbidden" })).collect();
        let receipt_ids = ids.clone();
        return finalize(
            "legion-web-scenario",
            json!({
                "status": "blocked",
                "terminal": true,
                "binding": binding,
                "denominator": denominator(&ids, &receipt_ids, &[]).to_value(),
                "receipts": receipts,
                "coverageGaps": ["production-effect-forbidden"],
            }),
        );
    }

    let mut receipts: Vec<Value> = Vec::new();
    let mut unrecognized_gaps: Vec<String> = Vec::new();

    let supplied_ids: Vec<String> = supplied_controls
        .iter()
        .map(|c| format!("control:{c}"))
        .chain(protocols_arr.iter().map(|p| format!("protocol:{}", p.get("name").and_then(Value::as_str).unwrap_or(""))))
        .collect();
    let mut duplicate_ids: Vec<String> = supplied_ids
        .iter()
        .enumerate()
        .filter(|(i, id)| supplied_ids.iter().position(|x| x == *id) != Some(*i))
        .map(|(_, id)| id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    duplicate_ids.sort();

    let supplied_set: std::collections::HashSet<&str> = supplied_controls.iter().map(String::as_str).collect();
    let mut protocols_by_name: std::collections::HashMap<String, &Value> = std::collections::HashMap::new();
    for item in protocols_arr {
        if let Some(name) = item.get("name").and_then(Value::as_str) {
            protocols_by_name.entry(name.to_string()).or_insert(item);
        }
    }

    let mut unplanned_controls: Vec<String> = supplied_controls
        .iter()
        .filter(|c| !required_controls.contains(c))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    unplanned_controls.sort();

    let mut unplanned_protocols: Vec<String> = protocols_arr
        .iter()
        .filter(|item| {
            let name = item.get("name").and_then(Value::as_str);
            !protocol_plan.iter().any(|row| row.get("protocolId").and_then(Value::as_str) == name)
        })
        .map(|item| item.get("name").and_then(Value::as_str).unwrap_or("missing").to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    unplanned_protocols.sort();

    let mut applicability_mismatches: Vec<String> = protocols_arr
        .iter()
        .filter(|item| {
            let name = item.get("name").and_then(Value::as_str);
            protocol_plan.iter().any(|row| {
                row.get("protocolId").and_then(Value::as_str) == name
                    && row.get("applicable") != item.get("applicable")
            })
        })
        .filter_map(|item| item.get("name").and_then(Value::as_str).map(str::to_string))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    applicability_mismatches.sort();

    let preflight_invalid = !binding_gaps.is_empty()
        || !unplanned_controls.is_empty()
        || !unplanned_protocols.is_empty()
        || !applicability_mismatches.is_empty()
        || !duplicate_ids.is_empty();

    for journey in journeys {
        let id = journey.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let control = journey.get("controlId").and_then(Value::as_str).unwrap_or("").to_string();
        if !supplied_set.contains(control.as_str()) {
            receipts.push(json!({ "id": id, "control": control, "journeyId": id, "status": "unproven", "terminal": true, "coverageGaps": ["journey-not-observed"] }));
            continue;
        }
        if preflight_invalid {
            let mut gaps = vec!["scenario-preflight-invalid".to_string()];
            if !binding_gaps.is_empty() {
                gaps.push("binding-unproven".to_string());
            }
            receipts.push(json!({ "id": id, "control": control, "journeyId": id, "status": "unproven", "terminal": true, "coverageGaps": gaps }));
            continue;
        }
        match journey_invoke {
            None => {
                receipts.push(json!({ "id": id, "control": control, "journeyId": id, "status": "unproven", "terminal": true, "coverageGaps": ["adapter-missing"] }));
            }
            Some(invoke) => match invoke(&control, journey, binding, expected_state) {
                AdapterCallResult::Err { name, message } => {
                    receipts.push(json!({ "id": id, "control": control, "journeyId": id, "status": "error", "terminal": true, "errors": [{ "name": name, "message": redact(&Value::String(message)) }] }));
                }
                AdapterCallResult::Ok(raw_observed) => {
                    let (artifacts, artifact_gaps) = artifact_evidence(raw_observed.get("artifacts"), binding, sanitize_artifact);
                    let mut observed_input = raw_observed.clone();
                    if let Value::Object(map) = &mut observed_input {
                        map.remove("artifacts");
                    }
                    let observed = redact(&observed_input);
                    let mut coverage_gaps: Vec<String> = Vec::new();
                    let adapter_status = raw_observed.get("status").and_then(Value::as_str);
                    let adapter_status_valid = adapter_status.is_none() || RESULT_STATUSES.contains(&adapter_status.unwrap());
                    if !adapter_status_valid {
                        coverage_gaps.push("adapter-status-invalid".to_string());
                    }
                    if adapter_status.is_some() && raw_observed.get("terminal") != Some(&Value::Bool(true)) {
                        coverage_gaps.push("adapter-result-nonterminal".to_string());
                    }
                    if adapter_status_valid {
                        if let Some(s) = adapter_status {
                            if s != "pass" {
                                coverage_gaps.push(format!("adapter-status-{s}"));
                            }
                        }
                    }
                    coverage_gaps.extend(artifact_gaps);
                    let observed_state = observed.get("observedState").cloned();
                    if observed_state.is_none() || observed_state == Some(Value::Null) {
                        coverage_gaps.push("observed-state-missing".to_string());
                    }
                    let durable_state = observed.get("durableState").cloned();
                    if durable_state.is_none() || durable_state == Some(Value::Null) {
                        coverage_gaps.push("durable-state-missing".to_string());
                    }
                    if let Some(os) = &observed_state {
                        if unequal(expected_state, os) {
                            coverage_gaps.push("observed-state-mismatch".to_string());
                        }
                    }
                    if let Some(ds) = &durable_state {
                        if unequal(expected_state, ds) {
                            coverage_gaps.push("durable-state-mismatch".to_string());
                        }
                    }
                    if route_controls.contains(&control) {
                        let route = observed.get("routeEvidence");
                        match route {
                            None => coverage_gaps.push("route-evidence-missing".to_string()),
                            Some(r) if r.get("kind").and_then(Value::as_str) != Some("web-route-navigation") => {
                                coverage_gaps.push("route-evidence-missing".to_string())
                            }
                            Some(r) => {
                                if !web_route_evidence_matches(journey, r, binding) {
                                    coverage_gaps.push("route-evidence-plan-mismatch".to_string());
                                }
                            }
                        }
                    }
                    coverage_gaps.extend(browser_diagnostic_gaps(observed.get("browserDiagnostics"), binding));
                    coverage_gaps.extend(server_authorization_gaps(observed.get("serverAuthorization"), binding, &control));

                    let status = if !adapter_status_valid || (adapter_status.is_some() && raw_observed.get("terminal") != Some(&Value::Bool(true))) {
                        "error".to_string()
                    } else if let Some(s) = adapter_status {
                        if s != "pass" { s.to_string() } else if coverage_gaps.is_empty() { "pass".to_string() } else { "unproven".to_string() }
                    } else if coverage_gaps.is_empty() {
                        "pass".to_string()
                    } else {
                        "unproven".to_string()
                    };

                    receipts.push(json!({
                        "id": id,
                        "control": control,
                        "journeyId": id,
                        "routeId": journey.get("routeId"),
                        "actionId": journey.get("actionId"),
                        "status": status,
                        "terminal": true,
                        "expectedState": expected_state,
                        "observedState": observed_state.unwrap_or(Value::Null),
                        "durableState": durable_state.unwrap_or(Value::Null),
                        "routeEvidence": observed.get("routeEvidence").cloned().unwrap_or(Value::Null),
                        "browserDiagnostics": observed.get("browserDiagnostics").cloned().unwrap_or(Value::Null),
                        "serverAuthorization": observed.get("serverAuthorization").cloned().unwrap_or(Value::Null),
                        "artifacts": artifacts,
                        "coverageGaps": coverage_gaps,
                    }));
                }
            },
        }
    }

    for control in &unplanned_controls {
        unrecognized_gaps.push(format!("control:{control}:unplanned"));
    }

    for plan_protocol in protocol_plan {
        let id = plan_protocol.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let protocol_name = plan_protocol.get("protocolId").and_then(Value::as_str).unwrap_or("").to_string();
        let protocol = protocols_by_name.get(&protocol_name).copied();
        let protocol = match protocol {
            None => {
                receipts.push(json!({ "id": id, "protocol": protocol_name, "status": "unproven", "terminal": true, "coverageGaps": ["protocol-not-observed"] }));
                continue;
            }
            Some(p) => p,
        };
        if preflight_invalid {
            let mut gaps = vec!["scenario-preflight-invalid".to_string()];
            if applicability_mismatches.contains(&protocol_name) {
                gaps.push("protocol-applicability-mismatch".to_string());
            }
            receipts.push(json!({ "id": id, "protocol": protocol_name, "status": "unproven", "terminal": true, "coverageGaps": gaps }));
            continue;
        }
        let plan_applicable = plan_protocol.get("applicable") == Some(&Value::Bool(true));
        let protocol_applicable = protocol.get("applicable") == Some(&Value::Bool(true));
        if protocol.get("applicable") != plan_protocol.get("applicable") {
            let mut gaps = vec!["protocol-applicability-mismatch".to_string()];
            if protocol_applicable {
                gaps.push("protocol-unexercised".to_string());
            }
            receipts.push(json!({ "id": id, "protocol": protocol_name, "status": "unproven", "terminal": true, "coverageGaps": gaps }));
            continue;
        }
        if !plan_applicable {
            let evidence = protocol.get("evidence");
            let reason_matches = protocol.get("reason") == plan_protocol.get("reason");
            let evidence_valid = evidence.map(|e| {
                e.get("kind").and_then(Value::as_str) == Some("configured-protocol-applicability")
                    && e.get("reason") == protocol.get("reason")
                    && e.get("source").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false)
                    && e.get("digest").and_then(Value::as_str).map(is_sha256_digest).unwrap_or(false)
                    && same_binding(binding, e.get("binding").unwrap_or(&json!({})))
            }).unwrap_or(false);
            let valid = reason_matches && evidence_valid;
            let coverage_gaps = if valid { vec!["protocol-excluded".to_string()] } else { vec!["protocol-excluded".to_string(), "protocol-exclusion-evidence-missing".to_string()] };
            receipts.push(json!({
                "id": id,
                "protocol": protocol_name,
                "status": if valid { "unsupported" } else { "unproven" },
                "terminal": true,
                "reason": protocol.get("reason").cloned().unwrap_or(Value::Null),
                "evidence": evidence.cloned().unwrap_or(Value::Null),
                "coverageGaps": coverage_gaps,
            }));
            continue;
        }
        match protocol_invoke {
            None => {
                receipts.push(json!({ "id": id, "protocol": protocol_name, "status": "unproven", "terminal": true, "coverageGaps": ["protocol-unexercised"] }));
            }
            Some(invoke) => match invoke(&protocol_name, binding, expected_state) {
                AdapterCallResult::Err { name, message } => {
                    receipts.push(json!({ "id": id, "protocol": protocol_name, "status": "error", "terminal": true, "errors": [{ "name": name, "message": redact(&Value::String(message)) }], "coverageGaps": ["protocol-exercise-error"] }));
                }
                AdapterCallResult::Ok(raw_observed) => {
                    let (artifacts, mut coverage_gaps) = artifact_evidence(raw_observed.get("artifacts"), binding, sanitize_artifact);
                    let mut observed_input = raw_observed.clone();
                    if let Value::Object(map) = &mut observed_input {
                        map.remove("artifacts");
                    }
                    let observed = redact(&observed_input);
                    let adapter_status = raw_observed.get("status").and_then(Value::as_str);
                    let adapter_status_valid = adapter_status.is_none() || RESULT_STATUSES.contains(&adapter_status.unwrap());
                    if !adapter_status_valid {
                        coverage_gaps.push("adapter-status-invalid".to_string());
                    }
                    if adapter_status.is_some() && raw_observed.get("terminal") != Some(&Value::Bool(true)) {
                        coverage_gaps.push("adapter-result-nonterminal".to_string());
                    }
                    if adapter_status_valid {
                        if let Some(s) = adapter_status {
                            if s != "pass" {
                                coverage_gaps.push(format!("adapter-status-{s}"));
                            }
                        }
                    }
                    let observed_state = observed.get("observedState").cloned();
                    let durable_state = observed.get("durableState").cloned();
                    let os_missing = observed_state.is_none() || observed_state == Some(Value::Null);
                    let ds_missing = durable_state.is_none() || durable_state == Some(Value::Null);
                    if os_missing || ds_missing {
                        coverage_gaps.push("protocol-unexercised".to_string());
                    }
                    if let Some(os) = &observed_state {
                        if unequal(expected_state, os) {
                            coverage_gaps.push("observed-state-mismatch".to_string());
                        }
                    }
                    if let Some(ds) = &durable_state {
                        if unequal(expected_state, ds) {
                            coverage_gaps.push("durable-state-mismatch".to_string());
                        }
                    }
                    let status = if !adapter_status_valid || (adapter_status.is_some() && raw_observed.get("terminal") != Some(&Value::Bool(true))) {
                        "error".to_string()
                    } else if let Some(s) = adapter_status {
                        if s != "pass" { s.to_string() } else if coverage_gaps.is_empty() { "pass".to_string() } else { "unproven".to_string() }
                    } else if coverage_gaps.is_empty() {
                        "pass".to_string()
                    } else {
                        "unproven".to_string()
                    };
                    receipts.push(json!({
                        "id": id,
                        "protocol": protocol_name,
                        "status": status,
                        "terminal": true,
                        "observedState": observed_state.unwrap_or(Value::Null),
                        "durableState": durable_state.unwrap_or(Value::Null),
                        "artifacts": artifacts,
                        "coverageGaps": coverage_gaps,
                    }));
                }
            },
        }
    }

    let receipt_ids: Vec<String> = receipts.iter().filter_map(|r| r.get("id").and_then(Value::as_str).map(str::to_string)).collect();
    let counts = denominator(&ids, &receipt_ids, &[]);

    let mut gaps: Vec<String> = binding_gaps.iter().map(|k| format!("binding-missing:{k}")).collect();
    if preflight_invalid {
        gaps.push("scenario-preflight-invalid".to_string());
    }
    if ids.is_empty() || (supplied_controls.is_empty() && protocols_arr.is_empty()) {
        gaps.push("scenario-denominator-empty".to_string());
    }
    gaps.extend(supplied_controls.iter().filter(|c| !required_controls.contains(c)).map(|c| format!("control-unrecognized:{c}")));
    gaps.extend(protocols_arr.iter().filter(|item| {
        let name = item.get("name").and_then(Value::as_str);
        !protocol_plan.iter().any(|row| row.get("protocolId").and_then(Value::as_str) == name)
    }).map(|item| format!("protocol-unrecognized:{}", item.get("name").and_then(Value::as_str).unwrap_or(""))));
    for journey in journeys {
        let control = journey.get("controlId").and_then(Value::as_str).unwrap_or("");
        if !supplied_set.contains(control) {
            gaps.push(format!("control-missing:{control}"));
            gaps.push(format!("journey-omitted:{}", journey.get("id").and_then(Value::as_str).unwrap_or("")));
        }
    }
    for row in protocol_plan {
        let protocol_id = row.get("protocolId").and_then(Value::as_str).unwrap_or("");
        if !protocols_by_name.contains_key(protocol_id) {
            gaps.push(format!("protocol-omitted:{}", row.get("id").and_then(Value::as_str).unwrap_or("")));
        }
    }
    gaps.extend(unrecognized_gaps);
    gaps.extend(duplicate_ids.iter().map(|id| format!("scenario-id-duplicate:{id}")));
    for item in &receipts {
        let item_id = item.get("id").and_then(Value::as_str).unwrap_or("");
        if let Some(item_gaps) = item.get("coverageGaps").and_then(Value::as_array) {
            for g in item_gaps {
                if let Some(g) = g.as_str() {
                    gaps.push(format!("{item_id}:{g}"));
                }
            }
        }
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        let no_gaps = item.get("coverageGaps").and_then(Value::as_array).map(|a| a.is_empty()).unwrap_or(true);
        if !["pass", "unsupported"].contains(&status) && no_gaps {
            gaps.push(format!("control-{status}:{item_id}"));
        }
    }
    gaps.extend(counts.missing.iter().map(|id| format!("receipt-missing:{id}")));

    let status = ["error", "fail", "blocked", "partial", "unproven"]
        .iter()
        .find(|candidate| receipts.iter().any(|item| item.get("status").and_then(Value::as_str) == Some(**candidate)))
        .map(|s| s.to_string())
        .unwrap_or_else(|| if !gaps.is_empty() { "partial".to_string() } else { "pass".to_string() });

    finalize(
        "legion-web-scenario",
        json!({
            "status": status,
            "terminal": true,
            "binding": binding,
            "planId": "web",
            "denominator": counts.to_value(),
            "receipts": receipts,
            "coverageGaps": unique_sorted(gaps),
        }),
    )
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").map(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())).unwrap_or(false)
}
