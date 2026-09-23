//! Packet P11c coverage: `native_providers::p11c_experience::{visual_core,
//! visual, ux, safety, performance}` — ports of
//! `src/providers/{visual/**,visual-core.mjs,ux/**,safety/**,performance/**}`.

use legion_audit::native_providers::p11c_experience::{performance, safety, ux, visual, visual_core};
use serde_json::json;

// ---------------------------------------------------------------------
// visual_core: PNG codec round-trip + compare + coverage matrix
// ---------------------------------------------------------------------

#[test]
fn png_round_trip_and_compare_matches_pixel_for_pixel() {
    let width = 4;
    let height = 3;
    let mut rgba = vec![0u8; (width * height * 4) as usize];
    for (index, byte) in rgba.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    let encoded = visual_core::encode_png(width, height, &rgba).expect("encode");
    let decoded = visual_core::decode_png(&encoded).expect("decode");
    assert_eq!(decoded.width, width);
    assert_eq!(decoded.height, height);
    assert_eq!(decoded.rgba, rgba);

    let compare = visual_core::compare_png(&encoded, &encoded, &json!({})).expect("compare");
    assert_eq!(compare["status"], "match");
    assert_eq!(compare["changedPixels"], 0);

    let mut altered = rgba.clone();
    altered[0] = altered[0].wrapping_add(50);
    let altered_png = visual_core::encode_png(width, height, &altered).expect("encode altered");
    let diff = visual_core::compare_png(&encoded, &altered_png, &json!({})).expect("compare diff");
    assert_eq!(diff["status"], "different");
    assert_eq!(diff["changedPixels"], 1);
}

#[test]
fn png_rejects_dimension_mismatch() {
    let error = visual_core::encode_png(2, 2, &[0u8; 4]).unwrap_err();
    assert!(error.contains("RGBA byte length"));
}

#[test]
fn coverage_matrix_reports_missing_cases() {
    let spec = json!({
        "expected": { "routes": ["/a", "/b"] },
        "captures": [{ "id": "cap-1", "route": "/a" }],
    });
    let matrix = visual_core::build_coverage_matrix(&spec).expect("matrix");
    assert_eq!(matrix["expectedCount"], 2);
    assert_eq!(matrix["coveredCount"], 1);
    assert_eq!(matrix["missingCount"], 1);
    assert_eq!(matrix["complete"], false);
}

#[test]
fn analyze_reports_unproven_when_visual_spec_missing() {
    let result = visual_core::analyze(std::path::Path::new("."), &json!({}));
    assert_eq!(result["status"], "unproven");
    assert_eq!(result["coverageGaps"][0]["kind"], "visual-spec-missing");
}

// ---------------------------------------------------------------------
// visual: color / geometry / geometry-tokens / hierarchy / motion /
// responsive / stacking / tokens / typography / diff
// ---------------------------------------------------------------------

#[test]
fn contrast_ratio_matches_wcag_black_on_white() {
    let ratio = visual::contrast_ratio("#000000", "#ffffff");
    assert!((ratio - 21.0).abs() < 0.01, "expected ~21.0, got {ratio}");
}

#[test]
fn analyze_color_pairs_flags_low_contrast() {
    let result = visual::analyze_color_pairs(&[json!({ "foreground": "#777777", "background": "#888888" })]);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn analyze_geometry_evidence_flags_viewport_overflow() {
    let input = json!({
        "surfaceId": "s1", "viewport": { "width": 100, "height": 100 },
        "elements": [{ "id": "e1", "x": 50.0, "y": 0.0, "width": 80.0, "height": 10.0 }],
    });
    let result = visual::analyze_geometry_evidence(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["ruleId"], "visual.geometry-viewport-overflow");
}

#[test]
fn analyze_geometry_tokens_flags_off_scale_values() {
    let input = json!({
        "instances": [
            { "component": "Card", "property": "padding", "value": 8 },
            { "component": "Card", "property": "padding", "value": 8 },
            { "component": "Modal", "property": "padding", "value": 13 },
        ],
    });
    let result = visual::analyze_geometry_tokens(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["scale"], json!([8]));
}

#[test]
fn analyze_hierarchy_flags_rank_mismatch() {
    let input = json!({ "signals": [{ "component": "Btn", "source": "s", "semanticRank": 1, "visualRank": 2 }] });
    let result = visual::analyze_hierarchy(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["ruleId"], "visual.hierarchy-rank-mismatch");
}

#[test]
fn analyze_motion_flags_budget_overrun() {
    let input = json!({ "transitions": [{ "id": "t1", "from": "a", "to": "b", "durationMs": 500, "budgetMs": 200 }], "reducedMotionExercised": true });
    let result = visual::analyze_motion(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["ruleId"], "visual.motion-budget");
}

#[test]
fn analyze_responsive_flags_overflow_and_untested_viewport() {
    let input = json!({
        "surfaces": [{ "id": "s1", "viewport": "mobile", "overflowX": true, "safeAreaMeasured": true }],
        "requiredViewports": ["mobile", "tablet"],
    });
    let result = visual::analyze_responsive(&input);
    assert_eq!(result["status"], "candidates");
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"viewport-untested:tablet".to_string()));
}

#[test]
fn analyze_stacking_flags_fragile_chain() {
    let input = json!({ "contexts": [{ "id": "c1", "zIndexChain": [1, 5000] }] });
    let result = visual::analyze_stacking(&input);
    assert_eq!(result["status"], "candidates");
}

#[test]
fn inventory_tokens_flags_duplicates_across_files() {
    let input = json!({ "files": [
        { "path": "a.css", "text": "--space-1: 4px;" },
        { "path": "b.css", "text": "--space-1: 4px;" },
    ] });
    let result = visual::inventory_tokens(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["candidates"][0]["ruleId"], "visual.token-duplicate");
}

#[test]
fn analyze_typography_flags_clipped_text() {
    let input = json!({ "textItems": [{ "id": "t1", "clipped": true, "viewport": "mobile", "locale": "en" }], "fontEvidence": {} });
    let result = visual::analyze_typography(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["ruleId"], "visual.typography-text-layout");
}

#[test]
fn compare_visual_evidence_unproven_without_baseline() {
    let result = visual::compare_visual_evidence(&json!({}));
    assert_eq!(result["status"], "unproven");
    assert_eq!(result["coverageGaps"][0], "baseline-missing");
}

#[test]
fn build_review_packet_is_deterministic() {
    let input = json!({ "surfaceId": "s1", "screenshots": ["sha256:aa"], "route": "/", "state": "default", "viewport": "desktop" });
    let a = visual::build_review_packet(&input);
    let b = visual::build_review_packet(&input);
    assert_eq!(a["digest"], b["digest"]);
}

#[test]
fn capture_visual_evidence_requires_core_fields() {
    let error = visual::capture_visual_evidence(&json!({}), &[]).unwrap_err();
    assert!(error.contains("required"));
}

// ---------------------------------------------------------------------
// ux
// ---------------------------------------------------------------------

#[test]
fn analyze_control_states_flags_missing_state() {
    let input = json!({ "controls": [{ "id": "btn1", "role": "button", "applicableStates": ["default", "hover"], "observedStates": ["default"] }] });
    let result = ux::analyze_control_states(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["ruleId"], "ux.control-state-missing");
}

#[test]
fn analyze_control_states_unproven_on_zero_denominator() {
    let result = ux::analyze_control_states(&json!({}));
    assert_eq!(result["status"], "unproven");
}

#[test]
fn analyze_forms_flags_missing_label() {
    let input = json!({ "forms": [{ "id": "f1", "fields": [{ "id": "field1" }] }] });
    let result = ux::analyze_forms(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["ruleId"], "ux.forms-label-missing");
}

#[test]
fn analyze_friction_separates_deterministic_from_interpretive() {
    let input = json!({ "flows": [{ "id": "flow1", "policyContext": "checkout", "steps": [
        { "id": "s1", "unreachableHelp": true },
        { "id": "s2", "memoryBurden": true },
    ] }] });
    let result = ux::analyze_friction(&input);
    assert_eq!(result["findings"].as_array().unwrap().len(), 1);
    assert_eq!(result["candidates"].as_array().unwrap().len(), 1);
}

#[test]
fn analyze_navigation_flags_unreachable_route() {
    let input = json!({ "routes": [{ "path": "/orphan" }], "flows": [] });
    let result = ux::analyze_navigation(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["ruleId"], "ux.navigation-unreachable");
}

#[test]
fn analyze_recovery_flags_missing_confirmation() {
    let input = json!({ "actions": [{ "id": "a1", "risk": "high", "confirmation": false }] });
    let result = ux::analyze_recovery(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["ruleId"], "ux.recovery-confirmation-missing");
}

#[test]
fn inventory_surfaces_reports_source_missing() {
    let input = json!({ "artifacts": [{ "route": "/x" }] });
    let result = ux::inventory_surfaces(&input);
    assert_eq!(result["complete"], false);
    assert_eq!(result["coverageGaps"][0], "surface-source-missing");
}

#[test]
fn analyze_system_states_flags_blank_screen() {
    let input = json!({ "surfaces": [{ "id": "s1", "expectedStates": ["loaded"], "declaredStates": ["loaded"], "observedStates": ["loaded"], "blankScreen": true }] });
    let result = ux::analyze_system_states(&input);
    assert_eq!(result["status"], "candidates");
}

// ---------------------------------------------------------------------
// safety
// ---------------------------------------------------------------------

#[test]
fn safety_scanner_flags_unmitigated_destructive_action() {
    let files = vec![("app.js".to_string(), "function run() { hardDelete(userId); }".to_string())];
    let hazards = safety::scan_safety_hazards(&files, &json!("digest-a")).expect("scan");
    assert_eq!(hazards.len(), 1);
    assert_eq!(hazards[0]["disposition"], "positive");
    assert_eq!(hazards[0]["reasoningRequirement"], "human-decision");
    assert_eq!(hazards[0]["certifiable"], false);
}

#[test]
fn safety_scanner_recognizes_mitigation_signal() {
    let files = vec![("app.js".to_string(), "if (interlockEnforced()) { factoryReset(deviceId); }".to_string())];
    let hazards = safety::scan_safety_hazards(&files, &json!("digest-b")).expect("scan");
    assert_eq!(hazards.len(), 1);
    assert_eq!(hazards[0]["disposition"], "mitigated");
}

#[test]
fn close_hazard_rejects_non_human_closure() {
    let files = vec![("app.js".to_string(), "truncateTable(name);".to_string())];
    let hazards = safety::scan_safety_hazards(&files, &json!("digest-c")).expect("scan");
    let error = safety::close_hazard(&hazards[0], "model-verdict", "reviewer", "closed", "looked fine").unwrap_err();
    assert!(error.contains("human-decision"));
    let closed = safety::close_hazard(&hazards[0], "human-decision", "reviewer", "closed", "manually verified").expect("close");
    assert_eq!(closed["method"], "human-decision");
}

#[test]
fn hazard_model_schema_matches_generated_enums() {
    let schema = safety::build_hazard_model_schema();
    assert_eq!(schema["properties"]["reasoningRequirement"]["const"], "human-decision");
    assert_eq!(schema["properties"]["certifiable"]["const"], false);
}

// ---------------------------------------------------------------------
// performance
// ---------------------------------------------------------------------

#[test]
fn analyze_bundle_evidence_requires_artifact_identity() {
    let result = performance::analyze_bundle_evidence(&json!({}));
    assert_eq!(result["status"], "unproven");
}

#[test]
fn analyze_bundle_evidence_flags_duplicate_module() {
    let input = json!({ "artifact": { "id": "a1", "digest": "sha256:x" }, "modules": [{ "name": "lodash", "bytes": 500, "duplicate": true }] });
    let result = performance::analyze_bundle_evidence(&input);
    assert_eq!(result["status"], "candidates");
}

#[test]
fn analyze_cache_evidence_flags_correctness_risk() {
    let input = json!({ "entries": [{ "id": "c1", "sensitive": true, "ttl": 60 }] });
    let result = performance::analyze_cache_evidence(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["candidates"][0]["ruleId"], "performance.cache-correctness-risk");
}

#[test]
fn assess_frontend_performance_flags_budget_breach() {
    let measurements = vec![json!({ "surfaceId": "s1", "lcp": 4000, "environment": "lab", "repeatCount": 3 })];
    let budgets = json!({ "lcp": 2500 });
    let result = performance::assess_frontend_performance(&measurements, &budgets);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"][0]["metric"], "lcp");
}

#[test]
fn analyze_network_evidence_flags_missing_timeout() {
    let input = json!({ "requests": [{ "id": "r1", "url": "/api", "timeoutMissing": true }] });
    let result = performance::analyze_network_evidence(&input);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["candidates"][0]["ruleId"], "performance.network-timeout-missing");
}
