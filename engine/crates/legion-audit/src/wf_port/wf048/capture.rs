//! Port of `src/providers/runtime/web/capture/index.mjs`
//! (`captureWebEvidence`) — chunk wf048.
//!
//! The JS source also imports `WEB_JOURNEYS` / `webJourneySurfaceMatches`
//! from `../journey-plan.mjs` and `isWebMatrixCombinationId` from
//! `../matrix/index.mjs`. Neither file is in this chunk's owned list, and
//! both are themselves registry-driven (they load
//! `registry/platform-scenarios/web.json` and
//! `registry/platform-matrices/web.json` at import time) rather than
//! self-contained logic, so porting them here would duplicate whatever
//! chunk owns `src/providers/runtime/web/journey-plan.mjs` /
//! `src/providers/runtime/web/matrix/index.mjs`. This port takes the
//! equivalent data as parameters instead of re-deriving it from the
//! registry JSON:
//!   - `journeys`: the planned, `applicable: true` journey rows (the Rust
//!     shape of `WEB_JOURNEYS`).
//!   - `journey_surface_matches`: callback equivalent to
//!     `webJourneySurfaceMatches`.
//!   - `is_matrix_combination_id`: callback equivalent to
//!     `isWebMatrixCombinationId`.
//! Wire these to whatever module ends up porting `journey-plan.mjs` /
//! `matrix/index.mjs` (or to the registry JSON directly).

use serde_json::{json, Map, Value};
use std::collections::HashSet;

use super::sanitize::sanitize_sensitive_value;
use super::shared::{binding_missing_gaps, finalize, same_binding, sort_by_id, unique_sorted};

const REQUIRED: &[&str] = &["screenshot", "dom", "accessibilityTree", "style", "geometry", "trace", "performance"];
const PERFORMANCE_REQUIRED: &[&str] = &["longTasks", "layoutShifts", "paints", "memory", "userTimings"];

fn nonnegative_metric(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.as_f64().map(|f| f.is_finite() && f >= 0.0).unwrap_or(false),
        Value::Array(items) => !items.is_empty() && items.iter().all(|item| matches!(item, Value::Number(n) if n.as_f64().map(|f| f.is_finite() && f >= 0.0).unwrap_or(false))),
        _ => false,
    }
}

fn is_nonempty_string(value: &Value) -> bool {
    matches!(value, Value::String(s) if !s.is_empty())
}

/// One row of `WEB_JOURNEYS` (the `applicable: true` subset), as consumed
/// by this port. Field names mirror the JS registry row.
pub struct WebJourneyRow<'a> {
    pub id: &'a str,
    pub control_id: &'a str,
    pub route_id: &'a str,
    pub route: &'a str,
    pub state_id: &'a str,
    pub action_id: &'a str,
    pub protocol_ids: &'a [&'a str],
    pub direct_applicable: bool,
    pub deep_applicable: bool,
    pub matrix_combination_id: &'a str,
}

/// Port of `captureWebEvidence({ binding, surface, tool, captures })`.
///
/// `journeys` / `journey_surface_matches` / `is_matrix_combination_id` are
/// the injected equivalents of `journey-plan.mjs` / `matrix/index.mjs`
/// described in the module header.
pub fn capture_web_evidence(
    binding: &Value,
    surface: &Value,
    tool: &Value,
    captures: &Value,
    journeys: &[WebJourneyRow<'_>],
    journey_surface_matches: impl Fn(&Value) -> bool,
    is_matrix_combination_id: impl Fn(&str) -> bool,
) -> Value {
    if !surface.is_object() {
        return finalize(
            "legion-web-capture-evidence",
            json!({"status": "error", "terminal": true, "verdict": "unproven", "binding": binding, "captures": [], "coverageGaps": ["capture-surface-invalid"]}),
        );
    }
    if !tool.is_object() {
        return finalize(
            "legion-web-capture-evidence",
            json!({"status": "error", "terminal": true, "verdict": "unproven", "binding": binding, "captures": [], "coverageGaps": ["capture-tool-invalid"]}),
        );
    }
    let captures_arr = match captures {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        _ => {
            return finalize(
                "legion-web-capture-evidence",
                json!({"status": "error", "terminal": true, "verdict": "unproven", "binding": binding, "captures": [], "coverageGaps": ["capture-collection-invalid"]}),
            );
        }
    };
    if captures_arr.iter().any(|item| !item.is_object()) {
        return finalize(
            "legion-web-capture-evidence",
            json!({"status": "error", "terminal": true, "verdict": "unproven", "binding": binding, "captures": [], "coverageGaps": ["capture-collection-invalid"]}),
        );
    }

    let with_ids: Vec<Value> = captures_arr
        .iter()
        .map(|item| {
            let mut obj = item.as_object().cloned().unwrap_or_default();
            let repeat_str = obj.get("repeat").map(value_to_id_string).unwrap_or_else(|| "undefined".to_string());
            obj.insert("id".to_string(), Value::String(repeat_str));
            Value::Object(obj)
        })
        .collect();
    let ordered = sort_by_id(&with_ids);

    let mut gaps = binding_missing_gaps(binding);

    let sanitized = sanitize_sensitive_value(&json!({"binding": binding, "surface": surface, "tool": tool, "captures": ordered}));
    if sanitized.sensitive {
        gaps.push("capture-sensitive-data-sanitized".to_string());
    }
    let sanitized_binding = sanitized.value.get("binding").cloned().unwrap_or(Value::Null);
    let sanitized_surface = sanitized.value.get("surface").cloned().unwrap_or(Value::Null);
    let sanitized_tool = sanitized.value.get("tool").cloned().unwrap_or(Value::Null);
    let sanitized_captures = sanitized.value.get("captures").cloned().unwrap_or(json!([]));

    let component_ids_nonempty = surface
        .get("componentIds")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if !is_nonempty_string(surface.get("id").unwrap_or(&Value::Null))
        || !is_nonempty_string(surface.get("route").unwrap_or(&Value::Null))
        || !component_ids_nonempty
    {
        gaps.push("surface-binding-incomplete".to_string());
    }
    if !is_nonempty_string(surface.get("journeyId").unwrap_or(&Value::Null)) {
        gaps.push("capture-journey-id-missing".to_string());
    }
    if !is_nonempty_string(surface.get("stateId").unwrap_or(&Value::Null)) {
        gaps.push("capture-state-binding-missing".to_string());
    }
    let matrix_combination_id = surface.get("matrixCombinationId").and_then(Value::as_str);
    if matrix_combination_id.map(str::is_empty).unwrap_or(true) {
        gaps.push("capture-matrix-combination-binding-missing".to_string());
    }
    if let Some(id) = matrix_combination_id {
        if !id.is_empty() && !is_matrix_combination_id(id) {
            gaps.push("capture-matrix-combination-unplanned".to_string());
        }
    }
    let route = surface.get("route").and_then(Value::as_str);
    let state_id = surface.get("stateId").and_then(Value::as_str);
    if route.map(|s| !s.is_empty()).unwrap_or(false)
        && state_id.map(|s| !s.is_empty()).unwrap_or(false)
        && matrix_combination_id.map(|s| !s.is_empty()).unwrap_or(false)
        && !journey_surface_matches(surface)
    {
        gaps.push("capture-journey-binding-unplanned".to_string());
    }

    let journey_id = surface.get("journeyId").and_then(Value::as_str);
    let journey = journey_id.and_then(|jid| journeys.iter().find(|row| row.id == jid));
    if journey_id.map(|s| !s.is_empty()).unwrap_or(false) && journey.is_none() {
        gaps.push("capture-journey-id-unplanned".to_string());
    }
    if let Some(journey) = journey {
        if surface.get("id").and_then(Value::as_str) != Some(journey.id) {
            gaps.push("capture-surface-id-mismatch".to_string());
        }
        if surface.get("controlId").and_then(Value::as_str) != Some(journey.control_id) {
            gaps.push("capture-control-binding-mismatch".to_string());
        }
        if surface.get("routeId").and_then(Value::as_str) != Some(journey.route_id) {
            gaps.push("capture-route-id-binding-mismatch".to_string());
        }
        if surface.get("route").and_then(Value::as_str) != Some(journey.route) {
            gaps.push("capture-route-binding-mismatch".to_string());
        }
        if surface.get("stateId").and_then(Value::as_str) != Some(journey.state_id) {
            gaps.push("capture-state-binding-mismatch".to_string());
        }
        if surface.get("actionId").and_then(Value::as_str) != Some(journey.action_id) {
            gaps.push("capture-action-binding-mismatch".to_string());
        }
        let protocol_id = surface.get("protocolId").and_then(Value::as_str);
        if !protocol_id.map(|p| journey.protocol_ids.contains(&p)).unwrap_or(false) {
            gaps.push("capture-protocol-binding-mismatch".to_string());
        }
        if surface.get("directApplicable") != Some(&Value::Bool(journey.direct_applicable)) {
            gaps.push("capture-direct-applicability-mismatch".to_string());
        }
        if surface.get("deepApplicable") != Some(&Value::Bool(journey.deep_applicable)) {
            gaps.push("capture-deep-applicability-mismatch".to_string());
        }
        if surface.get("matrixCombinationId").and_then(Value::as_str) != Some(journey.matrix_combination_id) {
            gaps.push("capture-matrix-combination-binding-mismatch".to_string());
        }
        let surface_binding = surface.get("binding").cloned().unwrap_or_else(|| json!({}));
        if !same_binding(binding, &surface_binding) {
            gaps.push("capture-surface-binding-mismatch".to_string());
        }
    }

    if !is_nonempty_string(tool.get("name").unwrap_or(&Value::Null)) || !is_nonempty_string(tool.get("version").unwrap_or(&Value::Null)) {
        gaps.push("capture-tool-unversioned".to_string());
    }
    if !is_nonempty_string(tool.get("accessibilityEngine").unwrap_or(&Value::Null))
        || !is_nonempty_string(tool.get("accessibilityEngineVersion").unwrap_or(&Value::Null))
    {
        gaps.push("accessibility-engine-unversioned".to_string());
    }

    let repeat_ids: Vec<String> = ordered
        .iter()
        .filter_map(|item| item.get("repeat").or_else(|| item.get("sampleId")))
        .filter(|v| !v.is_null())
        .map(value_to_id_string)
        .collect();
    let unique_repeat_ids: HashSet<&String> = repeat_ids.iter().collect();
    if ordered.len() < 2 || unique_repeat_ids.len() < 2 {
        gaps.push("capture-repeats-insufficient".to_string());
    }
    if repeat_ids.len() != ordered.len() || unique_repeat_ids.len() != repeat_ids.len() {
        gaps.push("capture-repeat-identities-not-unique".to_string());
    }

    for capture in &ordered {
        let id = capture.get("id").and_then(Value::as_str).unwrap_or_default();
        for key in REQUIRED.iter().filter(|k| **k != "performance") {
            if !is_nonempty_string(capture.get(*key).unwrap_or(&Value::Null)) {
                gaps.push(format!("capture-{key}-invalid:{id}"));
            }
        }
        let performance = capture.get("performance");
        let performance_obj_valid = matches!(performance, Some(Value::Object(_)));
        if !performance_obj_valid {
            gaps.push(format!("capture-performance-invalid:{id}"));
        }
        for key in PERFORMANCE_REQUIRED.iter().filter(|k| **k != "memory") {
            let value = performance.and_then(|p| p.get(*key));
            match value {
                None | Some(Value::Null) => gaps.push(format!("capture-performance-{key}-missing:{id}")),
                Some(v) if !nonnegative_metric(v) => gaps.push(format!("capture-performance-{key}-invalid:{id}")),
                _ => {}
            }
        }
        for key in ["memory", "lcp"] {
            let value = performance.and_then(|p| p.get(key));
            match value {
                None | Some(Value::Null) => gaps.push(format!("capture-performance-{key}-missing:{id}")),
                Some(v) if !matches!(v, Value::Number(_)) || !nonnegative_metric(v) => {
                    gaps.push(format!("capture-performance-{key}-invalid:{id}"))
                }
                _ => {}
            }
        }
    }

    let evidence_ids: Vec<String> = ordered
        .iter()
        .map(|item| {
            let fields: Vec<Value> = ["screenshot", "dom", "accessibilityTree", "style", "geometry", "trace", "performance"]
                .iter()
                .map(|k| item.get(*k).cloned().unwrap_or(Value::Null))
                .collect();
            serde_json::to_string(&Value::Array(fields)).unwrap_or_default()
        })
        .collect();
    let unique_evidence_ids: HashSet<&String> = evidence_ids.iter().collect();
    if unique_evidence_ids.len() != evidence_ids.len() {
        gaps.push("capture-evidence-identities-not-unique".to_string());
    }

    let mut p75_inputs: Vec<f64> = ordered
        .iter()
        .filter_map(|item| item.get("performance").and_then(|p| p.get("lcp")).and_then(Value::as_f64))
        .filter(|f| f.is_finite())
        .collect();
    p75_inputs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p75 = if p75_inputs.is_empty() {
        None
    } else {
        let idx = ((p75_inputs.len() as f64) * 0.75).ceil() as usize;
        p75_inputs.get(idx.saturating_sub(1)).copied()
    };
    let variance = if p75_inputs.is_empty() {
        None
    } else {
        Some(p75_inputs.iter().cloned().fold(f64::MIN, f64::max) - p75_inputs.iter().cloned().fold(f64::MAX, f64::min))
    };
    if p75.is_none() {
        gaps.push("capture-performance-p75-missing".to_string());
    }

    let gaps = unique_sorted(gaps);
    let status = if gaps.is_empty() { "pass" } else { "partial" };

    let route_val = sanitized_surface.get("route").cloned().unwrap_or(Value::Null);
    let state_id_val = sanitized_surface.get("stateId").cloned().unwrap_or(Value::Null);
    let matrix_id_val = sanitized_surface.get("matrixCombinationId").cloned().unwrap_or(Value::Null);
    let mut capture_binding = Map::new();
    capture_binding.insert("route".to_string(), route_val);
    capture_binding.insert("stateId".to_string(), state_id_val);
    capture_binding.insert("matrixCombinationId".to_string(), matrix_id_val);

    finalize(
        "legion-web-capture-evidence",
        json!({
            "status": status,
            "terminal": true,
            "verdict": "unproven",
            "binding": sanitized_binding,
            "captureBinding": capture_binding,
            "surface": sanitized_surface,
            "tool": sanitized_tool,
            "captures": sanitized_captures,
            "performance": {"p75Inputs": p75_inputs, "p75": p75, "variance": variance},
            "coverageGaps": gaps,
        }),
    )
}

fn value_to_id_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}
