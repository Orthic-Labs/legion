//! Integration tests porting the JS test coverage for
//! `src/lib/report/families/supply-chain.mjs`,
//! `src/lib/report/families/test-quality.mjs` (both re-export
//! `buildFamilySummary` from `families/shared.mjs`),
//! `src/lib/report/html/index.mjs` (see `../../../../tests/report/html.test.mjs`
//! in the JS tree), `src/lib/report/markdown/index.mjs`, and
//! `src/lib/report/model.mjs`.
//!
//! `model.mjs`, `markdown/index.mjs` and `families/shared.mjs` have no
//! dedicated JS test files in the tree at port time; this file adds direct
//! unit-style coverage for them alongside the ported `html.test.mjs`
//! assertions.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf021;`
//! inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf021::{
    build_family_summary, build_report_model, csp_meta, escape_html, escape_markdown,
    render_html_report, render_markdown_report, FamilySummaryOptions,
};
use serde_json::json;

// ---------------------------------------------------------------------
// html/index.mjs (ported from tests/report/html.test.mjs)
// ---------------------------------------------------------------------

#[test]
fn escape_html_escapes_all_dangerous_characters() {
    assert_eq!(
        escape_html("<script>alert(\"x\")&'y'</script>"),
        "&lt;script&gt;alert(&quot;x&quot;)&amp;&#39;y&#39;&lt;/script&gt;"
    );
    assert_eq!(escape_html("plain"), "plain");
}

#[test]
fn csp_meta_uses_restrictive_policy_with_generated_script_hash() {
    let meta = csp_meta("abc123");
    assert!(meta.contains("default-src 'none'"));
    assert!(meta.contains("script-src 'sha256-abc123'"));
    assert!(meta.contains("img-src data:"));
}

#[test]
fn render_html_report_produces_a_self_contained_document() {
    let html = render_html_report(&json!({
        "audit_status": "fail",
        "quality_gate": "blocked",
        "findings": [
            { "id": "f1", "ruleId": "r1", "severity": "high", "title": "<img onerror=x>", "file": "a.ts" },
        ],
        "coverage_gaps": [{ "kind": "provider-incomplete", "detail": { "provider": "x" } }],
    }));
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Content-Security-Policy"));
    // Untrusted content is escaped.
    assert!(!html.contains("<img onerror=x>"));
    assert!(html.contains("&lt;img onerror=x&gt;"));
    // No external resources.
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
    // Coverage gaps are visible.
    assert!(html.contains("provider-incomplete"));
}

#[test]
fn render_html_report_handles_empty_reports() {
    let html = render_html_report(&json!({ "audit_status": "pass", "findings": [], "coverage_gaps": [] }));
    assert!(html.contains("No findings"));
    assert!(html.contains("None"));
}

#[test]
fn render_html_report_defaults_missing_status_to_unknown() {
    let html = render_html_report(&json!({}));
    assert!(html.contains("Status: unknown"));
    assert!(html.contains("Quality gate: unknown"));
}

#[test]
fn render_html_report_dedupes_evidence_by_id_keeping_first_position_last_value() {
    let html = render_html_report(&json!({
        "findings": [
            {"id": "f1", "evidence": [{"id": "e1", "note": "first"}]},
            {"id": "f2", "evidence": [{"id": "e1", "note": "second"}]},
        ],
    }));
    // Only one evidence block for e1, and it carries the later value.
    assert_eq!(html.matches("id=\"evidence-e1\"").count(), 1);
    assert!(html.contains("second"));
    assert!(!html.contains("first"));
}

// ---------------------------------------------------------------------
// markdown/index.mjs
// ---------------------------------------------------------------------

#[test]
fn escape_markdown_escapes_pipes_backslashes_and_newlines() {
    assert_eq!(escape_markdown(&json!("a|b\\c\nd<e>&f")), "a\\|b\\\\c d&lt;e&gt;&amp;f");
    assert_eq!(escape_markdown(&json!(null)), "");
}

#[test]
fn render_markdown_report_sorts_findings_and_gaps_by_key() {
    let md = render_markdown_report(&json!({
        "audit_status": "fail",
        "quality_gate": "blocked",
        "findings": [
            {"id": "z1", "ruleId": "r1", "severity": "low", "title": "Z", "file": "z.ts"},
            {"id": "a1", "ruleId": "r2", "severity": "high", "title": "A", "file": "a.ts"},
        ],
        "coverage_gaps": [
            {"kind": "zeta"},
            {"kind": "alpha", "detail": {"x": 1}},
        ],
    }));
    let a_pos = md.find("| a1 |").unwrap();
    let z_pos = md.find("| z1 |").unwrap();
    assert!(a_pos < z_pos, "findings must be sorted by id");

    let alpha_pos = md.find("- alpha").unwrap();
    let zeta_pos = md.find("- zeta").unwrap();
    assert!(alpha_pos < zeta_pos, "gaps must be sorted by kind");
    assert!(md.contains("- alpha: {\"x\":1}") || md.contains("- alpha: {&quot;x&quot;:1}"));
}

#[test]
fn render_markdown_report_falls_back_to_detail_when_title_missing() {
    let md = render_markdown_report(&json!({
        "findings": [{"id": "f1", "ruleId": "r1", "severity": "low", "detail": "fallback text", "file": "f.ts"}],
    }));
    assert!(md.contains("fallback text"));
}

#[test]
fn render_markdown_report_handles_defaults_and_empty_collections() {
    let md = render_markdown_report(&json!({}));
    assert!(md.contains("- Status: unknown"));
    assert!(md.contains("- Quality gate: unknown"));
    assert!(md.contains("- Findings: 0"));
    assert!(md.contains("| — | — | — | No findings | — |"));
    assert!(md.contains("- None."));
    assert!(md.ends_with('\n') && !md.ends_with("\n\n"));
}

// ---------------------------------------------------------------------
// model.mjs — buildReportModel
// ---------------------------------------------------------------------

#[test]
fn build_report_model_defaults_empty_input() {
    let model = build_report_model(&json!({}));
    assert_eq!(model["schemaVersion"], 1);
    assert_eq!(model["kind"], "legion-report");
    assert_eq!(model["targets"], json!([]));
    assert_eq!(model["controls"], json!([]));
    // Empty targets/controls each push a missing-denominator gap.
    assert_eq!(
        model["gaps"],
        json!([
            {"kind": "missing-target-denominator"},
            {"kind": "missing-control-denominator"},
        ])
    );
    assert_eq!(model["auditStatus"], "incomplete");
    assert_eq!(model["integrity"], json!({"valid": false}));
    assert_eq!(model["completeness"], json!({"complete": false}));
    assert_eq!(model["denominators"], json!({"targets": [], "controls": []}));
}

#[test]
fn build_report_model_pass_when_no_gaps_and_no_findings() {
    let model = build_report_model(&json!({
        "targets": [{"id": "t1"}],
        "controls": [{"id": "c1"}],
    }));
    assert_eq!(model["gaps"], json!([]));
    assert_eq!(model["auditStatus"], "pass");
    assert_eq!(model["integrity"], json!({"valid": true}));
}

#[test]
fn build_report_model_fail_status_when_findings_present_and_no_gaps() {
    let model = build_report_model(&json!({
        "targets": [{"id": "t1"}],
        "controls": [{"id": "c1"}],
        "findings": [{"id": "f1", "ruleId": "r1"}],
    }));
    assert_eq!(model["auditStatus"], "fail");
}

#[test]
fn build_report_model_respects_explicit_audit_status_when_no_gaps() {
    let model = build_report_model(&json!({
        "targets": [{"id": "t1"}],
        "controls": [{"id": "c1"}],
        "auditStatus": "needs-review",
    }));
    assert_eq!(model["auditStatus"], "needs-review");
}

#[test]
fn build_report_model_gaps_force_incomplete_even_with_explicit_status() {
    let model = build_report_model(&json!({
        "targets": [{"id": "t1"}],
        "controls": [{"id": "c1"}],
        "auditStatus": "needs-review",
        "gaps": [{"kind": "custom-gap"}],
    }));
    assert_eq!(model["auditStatus"], "incomplete");
    assert_eq!(model["gaps"], json!([{"kind": "custom-gap"}]));
}

#[test]
fn build_report_model_denominators_dedupe_and_sort_ids() {
    let model = build_report_model(&json!({
        "targets": [{"id": "t2"}, {"id": "t1"}, {"id": "t1"}, {"id": ""}],
        "controls": [{"id": "c2"}, {"id": "c1"}],
    }));
    assert_eq!(model["denominators"]["targets"], json!(["t1", "t2"]));
    assert_eq!(model["denominators"]["controls"], json!(["c1", "c2"]));
}

#[test]
fn build_report_model_groups_findings_by_root_cause_then_rule_id_then_id() {
    let model = build_report_model(&json!({
        "targets": [{"id": "t1"}],
        "controls": [{"id": "c1"}],
        "findings": [
            {"id": "f1", "rootCause": "rc-1", "ruleId": "r1", "targetIds": ["t1", "t1"], "controlIds": ["c1"]},
            {"id": "f2", "ruleId": "r1", "targetIds": ["t2"]},
            {"id": "f3", "targetIds": ["t3"]},
        ],
    }));
    let groups = model["rootCauseGroups"].as_array().unwrap();
    assert_eq!(groups.len(), 3);
    assert_eq!(groups[0]["rootCause"], "rc-1");
    assert_eq!(groups[0]["findingIds"], json!(["f1"]));
    assert_eq!(groups[0]["targetIds"], json!(["t1"]));
    assert_eq!(groups[0]["controlIds"], json!(["c1"]));
    assert_eq!(groups[1]["rootCause"], "r1");
    assert_eq!(groups[1]["findingIds"], json!(["f2"]));
    assert_eq!(groups[2]["rootCause"], "f3");
}

#[test]
fn build_report_model_preserves_pass_through_fields() {
    let model = build_report_model(&json!({
        "components": [{"id": "comp1"}],
        "stacks": ["node"],
        "externalSystems": [{"id": "es1"}],
        "releaseContract": {"version": "1.0"},
        "productContext": {"name": "x"},
        "scenarios": [{"id": "sc1"}],
        "evidenceCapabilities": ["screenshot"],
        "claims": {"a": true},
        "targets": [{"id": "t1"}],
        "controls": [{"id": "c1"}],
    }));
    assert_eq!(model["components"], json!([{"id": "comp1"}]));
    assert_eq!(model["stacks"], json!(["node"]));
    assert_eq!(model["externalSystems"], json!([{"id": "es1"}]));
    assert_eq!(model["releaseContract"], json!({"version": "1.0"}));
    assert_eq!(model["productContext"], json!({"name": "x"}));
    assert_eq!(model["scenarios"], json!([{"id": "sc1"}]));
    assert_eq!(model["evidenceCapabilities"], json!(["screenshot"]));
    assert_eq!(model["claims"], json!({"a": true}));
}

// ---------------------------------------------------------------------
// families/shared.mjs — buildFamilySummary
// (families/supply-chain.mjs and families/test-quality.mjs both re-export
// this unchanged, so one port covers both call sites.)
// ---------------------------------------------------------------------

#[test]
fn build_family_summary_clean_when_all_required_providers_pass_complete() {
    let results = json!([
        {"id": "p1", "family": "supply-chain", "status": "pass", "complete": true, "denominator": {"expected": 3, "examined": 3}},
        {"id": "p2", "family": "supply-chain", "status": "pass", "complete": true, "denominator": {"expected": 1, "examined": 1}},
        {"id": "other", "family": "other-family", "status": "pass", "complete": true, "denominator": {"expected": 1, "examined": 1}},
    ]);
    let opts = FamilySummaryOptions {
        required_provider_ids: vec!["p1".into(), "p2".into()],
        selected_provider_ids: vec![],
    };
    let summary = build_family_summary(&results, Some("supply-chain"), &opts);
    assert_eq!(summary["status"], "complete");
    assert_eq!(summary["clean"], true);
    assert_eq!(summary["gaps"], json!([]));
    assert_eq!(summary["providers"].as_array().unwrap().len(), 2);
}

#[test]
fn build_family_summary_flags_missing_required_provider() {
    let results = json!([
        {"id": "p1", "family": "test-quality", "status": "pass", "complete": true, "denominator": {"expected": 1, "examined": 1}},
    ]);
    let opts = FamilySummaryOptions {
        required_provider_ids: vec!["p1".into(), "p2".into()],
        selected_provider_ids: vec![],
    };
    let summary = build_family_summary(&results, Some("test-quality"), &opts);
    assert_eq!(summary["status"], "incomplete");
    assert_eq!(summary["clean"], false);
    let gaps = summary["gaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g["kind"] == "required-provider-missing" && g["providerId"] == "p2"));
    assert_eq!(summary["incompleteProviders"], json!(["p2"]));
}

#[test]
fn build_family_summary_zero_denominator_when_nothing_selected() {
    let results = json!([]);
    let opts = FamilySummaryOptions::default();
    let summary = build_family_summary(&results, Some("supply-chain"), &opts);
    let gaps = summary["gaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g["kind"] == "family-denominator-zero"));
    assert_eq!(summary["status"], "incomplete");
}

#[test]
fn build_family_summary_incomplete_provider_result_flagged() {
    let results = json!([
        {"id": "p1", "family": "supply-chain", "status": "pass", "complete": true, "denominator": {"expected": 3, "examined": 2}},
    ]);
    let opts = FamilySummaryOptions {
        required_provider_ids: vec!["p1".into()],
        selected_provider_ids: vec![],
    };
    let summary = build_family_summary(&results, Some("supply-chain"), &opts);
    assert_eq!(summary["clean"], false);
    let gaps = summary["gaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g["kind"] == "provider-result-incomplete" && g["providerId"] == "p1"));
    assert_eq!(summary["incompleteProviders"], json!(["p1"]));
}

#[test]
fn build_family_summary_selected_provider_ids_narrow_selection_and_flag_selected_missing() {
    let results = json!([
        {"id": "p1", "family": "supply-chain", "status": "pass", "complete": true, "denominator": {"expected": 1, "examined": 1}},
    ]);
    let opts = FamilySummaryOptions {
        required_provider_ids: vec![],
        selected_provider_ids: vec!["p1".into(), "p2".into()],
    };
    let summary = build_family_summary(&results, Some("supply-chain"), &opts);
    let gaps = summary["gaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g["kind"] == "selected-provider-result-missing" && g["providerId"] == "p2"));
}

#[test]
fn build_family_summary_falls_back_to_provider_field_when_id_absent() {
    let results = json!([
        {"provider": "p1", "family": "supply-chain", "status": "pass", "complete": true, "denominator": {"expected": 1, "examined": 1}},
    ]);
    let opts = FamilySummaryOptions {
        required_provider_ids: vec!["p1".into()],
        selected_provider_ids: vec![],
    };
    let summary = build_family_summary(&results, Some("supply-chain"), &opts);
    assert_eq!(summary["clean"], true);
    assert_eq!(summary["providers"][0]["id"], "p1");
}
