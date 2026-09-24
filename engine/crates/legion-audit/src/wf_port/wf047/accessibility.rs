//! Port of `src/providers/runtime/web/accessibility/index.mjs`
//! (`verifyWebAccessibility`).
//!
//! `verifyWebAccessibility` calls `captureWebEvidence` from
//! `src/providers/runtime/web/capture/index.mjs` for its `digest` and
//! `coverageGaps` (nothing else of that call's return value is used here).
//! `verify_web_accessibility` below still takes that as an injected
//! `CaptureEvidence` value (useful for fixture-driven tests, and this
//! file's own logic — the part actually assigned to wf047 — stays
//! independently testable that way), but `verify_web_accessibility_production`
//! at the end of this file wires it to the real
//! `wf048::capture_web_evidence_production` (which itself now wires the
//! real `wf049::journey_plan` / `wf049::matrix` ports) — that is the
//! production entry point callers should use.

use super::shared::{denominator, finalize, same_binding, sort_by_id};
use serde_json::{Map, Value};

/// The two fields of `captureWebEvidence`'s return value that
/// `verifyWebAccessibility` actually reads (`capture.digest` and
/// `capture.coverageGaps`). See the module doc comment.
pub struct CaptureEvidence {
    pub digest: Value,
    pub coverage_gaps: Vec<String>,
}

fn repeat_or_sample_id(item: &Value) -> String {
    let repeat = item.get("repeat");
    let sample = item.get("sampleId");
    match (repeat, sample) {
        (Some(r), _) if !r.is_null() => js_string(r),
        (_, Some(s)) => js_string(s),
        _ => "undefined".to_string(),
    }
}

fn js_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Port of `verifyWebAccessibility(input)`.
pub fn verify_web_accessibility(
    binding: &Value,
    captures: &Value,
    inspections: &Value,
    tool: &Value,
    capture: CaptureEvidence,
) -> Value {
    let binding_out = if binding.is_object() { binding.clone() } else { Value::Object(Map::new()) };

    let captures_valid = captures.is_array()
        && captures.as_array().unwrap().iter().all(|item| item.is_object());
    let inspections_valid = inspections.is_array()
        && inspections.as_array().unwrap().iter().all(|item| item.is_object());

    if !captures_valid || !inspections_valid {
        return finalize(
            "legion-web-accessibility-evidence",
            serde_json::json!({
                "provider": "runtime.web.accessibility",
                "status": "error",
                "terminal": true,
                "binding": binding_out,
                "denominator": denominator(&[], &[], &[]).to_value(),
                "inspections": [],
                "violationCount": 0,
                "coverageGaps": ["accessibility-collections-invalid"],
            }),
        );
    }

    let captures_arr = captures.as_array().unwrap();
    let inspections_arr = inspections.as_array().unwrap();

    let mut expected: Vec<String> = captures_arr.iter().map(repeat_or_sample_id).collect();
    expected.sort();
    expected.dedup();

    let inspections_with_id: Vec<Value> = inspections_arr
        .iter()
        .map(|item| {
            let mut obj = item.as_object().cloned().unwrap_or_default();
            obj.insert("id".to_string(), Value::String(repeat_or_sample_id(item)));
            Value::Object(obj)
        })
        .collect();
    let inspections_sorted = sort_by_id(&inspections_with_id);

    let inspection_ids: Vec<String> = inspections_sorted
        .iter()
        .map(|i| i.get("id").and_then(Value::as_str).unwrap_or("").to_string())
        .collect();
    let counts = denominator(&expected, &inspection_ids, &[]);

    let mut gaps: Vec<String> = capture.coverage_gaps.clone();
    gaps.extend(counts.missing.iter().map(|id| format!("accessibility-inspection-missing:{id}")));

    for id in inspection_ids.iter().collect::<std::collections::BTreeSet<_>>() {
        if inspection_ids.iter().filter(|v| *v == id).count() > 1 {
            gaps.push(format!("accessibility-inspection-duplicate:{id}"));
        }
    }
    for id in &inspection_ids {
        if !expected.contains(id) {
            gaps.push(format!("accessibility-inspection-unplanned:{id}"));
        }
    }

    for inspection in &inspections_sorted {
        let id = inspection.get("id").and_then(Value::as_str).unwrap_or("");
        if !inspection.get("violations").is_some_and(Value::is_array) {
            gaps.push(format!("violations-unbound:{id}"));
        }
        if !same_binding(&binding_out, inspection.get("binding").unwrap_or(&Value::Null)) {
            gaps.push(format!("accessibility-binding-mismatch:{id}"));
        }
        if inspection.get("terminal") != Some(&Value::Bool(true)) {
            gaps.push(format!("accessibility-nonterminal:{id}"));
        }
        let status = inspection.get("status").and_then(Value::as_str);
        if status != Some("pass") {
            gaps.push(format!("accessibility-status-{}:{id}", status.unwrap_or("missing")));
        }
        let screenshot_ok = inspection.get("screenshot").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        if !screenshot_ok {
            gaps.push(format!("accessibility-screenshot-invalid:{id}"));
        }
    }

    let violation_count: usize = inspections_sorted
        .iter()
        .map(|item| item.get("violations").and_then(Value::as_array).map_or(0, |v| v.len()))
        .sum();

    let mut sorted_gaps: Vec<String> = gaps;
    sorted_gaps.sort();
    sorted_gaps.dedup();

    let status = if violation_count > 0 {
        "fail"
    } else if !sorted_gaps.is_empty() {
        "unproven"
    } else {
        "pass"
    };

    finalize(
        "legion-web-accessibility-evidence",
        serde_json::json!({
            "provider": "runtime.web.accessibility",
            "status": status,
            "terminal": true,
            "claimLevel": "runtime",
            "evidenceClass": "measured",
            "binding": binding_out,
            "engine": {
                "name": tool.get("accessibilityEngine").cloned().unwrap_or(Value::Null),
                "version": tool.get("accessibilityEngineVersion").cloned().unwrap_or(Value::Null),
            },
            "denominator": counts.to_value(),
            "inspections": inspections_sorted,
            "violationCount": violation_count,
            "captureDigest": capture.digest,
            "coverageGaps": sorted_gaps,
        }),
    )
}

/// Production entry point: mirrors `verifyWebAccessibility(input)` calling
/// `captureWebEvidence(input)` on the same `{ binding, surface, tool,
/// captures }` input, using the real `wf048::capture_web_evidence_production`
/// (which itself resolves the real `journey-plan.mjs` / `matrix/index.mjs`
/// data via `wf049`) instead of an injected `CaptureEvidence` fixture.
pub fn verify_web_accessibility_production(
    binding: &Value,
    surface: &Value,
    captures: &Value,
    inspections: &Value,
    tool: &Value,
) -> Value {
    let capture_result =
        crate::wf_port::wf048::capture_web_evidence_production(binding, surface, tool, captures);
    let capture = CaptureEvidence {
        digest: capture_result.get("digest").cloned().unwrap_or(Value::Null),
        coverage_gaps: capture_result
            .get("coverageGaps")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
    };
    verify_web_accessibility(binding, captures, inspections, tool, capture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_entry_point_runs_against_real_capture_pipeline() {
        let out = verify_web_accessibility_production(
            &Value::Null,
            &Value::Null,
            &Value::Array(vec![]),
            &Value::Array(vec![]),
            &Value::Null,
        );
        // Real captures/inspections are empty arrays (valid collections),
        // so this exercises the full real capture pipeline rather than the
        // collections-invalid short-circuit, without panicking.
        assert!(out.get("status").is_some());
    }

    fn full_binding() -> Value {
        let mut m = Map::new();
        for key in super::super::shared::BINDING_KEYS {
            m.insert(key.to_string(), Value::String(format!("{key}-v")));
        }
        Value::Object(m)
    }

    #[test]
    fn invalid_collections_produce_error() {
        let out = verify_web_accessibility(
            &Value::Null,
            &Value::String("not-array".to_string()),
            &Value::Array(vec![]),
            &Value::Null,
            CaptureEvidence { digest: Value::Null, coverage_gaps: vec![] },
        );
        assert_eq!(out["status"], "error");
        assert_eq!(out["coverageGaps"][0], "accessibility-collections-invalid");
    }

    #[test]
    fn missing_inspection_is_unproven() {
        let binding = full_binding();
        let captures = serde_json::json!([{ "repeat": "1" }]);
        let inspections = serde_json::json!([]);
        let out = verify_web_accessibility(
            &binding,
            &captures,
            &inspections,
            &Value::Null,
            CaptureEvidence { digest: Value::String("sha256:abc".to_string()), coverage_gaps: vec![] },
        );
        assert_eq!(out["status"], "unproven");
        let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(gaps.contains(&"accessibility-inspection-missing:1"));
    }

    #[test]
    fn violations_cause_fail_status() {
        let binding = full_binding();
        let captures = serde_json::json!([{ "repeat": "1" }]);
        let inspections = serde_json::json!([{
            "repeat": "1", "violations": [{"id": "v1"}], "binding": binding, "terminal": true,
            "status": "pass", "screenshot": "shot.png",
        }]);
        let out = verify_web_accessibility(
            &binding,
            &captures,
            &inspections,
            &serde_json::json!({"accessibilityEngine": "axe", "accessibilityEngineVersion": "4.0"}),
            CaptureEvidence { digest: Value::String("sha256:abc".to_string()), coverage_gaps: vec![] },
        );
        assert_eq!(out["status"], "fail");
        assert_eq!(out["violationCount"], 1);
    }
}
