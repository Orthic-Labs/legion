//! Integration tests exercising the wf064 port
//! (`tools/audit/audit-complete.mjs`, `audit-finalize.mjs`,
//! `audit-plan.mjs`, `audit-run.mjs`, `audit-runtime.mjs`) through its
//! public API, on top of the unit tests already inside each `wf_port/wf064`
//! submodule.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod
//! wf064;` inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf064::finalize::finalize_audit;
use legion_audit::wf_port::wf064::plan::{
    assert_supported_schema_version, normalized_scope, reconcile_plan_with_facts, seal_plan,
    stable_plan_digest, verify_plan_seal, verify_plan_signature, SchemaError,
};
use legion_audit::wf_port::wf064::run::{
    aggregate_security_candidates, assert_run_owned_out_scope, candidate_provider_ids, severity_hint,
};
use legion_audit::wf_port::wf064::runtime::{
    build_degraded_report, classify_runtime_failure, parse_surfaces_input,
};
use serde_json::json;
use std::path::Path;

#[test]
fn plan_schema_version_gate_refuses_future_versions() {
    assert_eq!(assert_supported_schema_version(1, "plan").unwrap(), 1);
    assert_eq!(
        assert_supported_schema_version(2, "plan").unwrap_err(),
        SchemaError::TooNew { label: "plan".to_string(), version: 2, supported: 1 }
    );
}

#[test]
fn plan_scope_defaults_to_whole_repo() {
    let scope = normalized_scope(&json!({}));
    assert_eq!(scope["mode"], json!("whole-repo"));
    assert_eq!(scope["type"], json!("all"));
}

#[test]
fn plan_seal_round_trips_and_detects_tampering() {
    let plan = json!({"kind": "audit-provider-plan"}).as_object().unwrap().clone();
    let sealed = seal_plan(&plan, Some("key-a"));
    assert!(verify_plan_seal(&sealed));
    assert!(verify_plan_signature(&sealed, Some("key-a")));
    assert!(!verify_plan_signature(&sealed, Some("key-b")));

    let mut tampered = sealed.clone();
    tampered.insert("kind".to_string(), json!("tampered"));
    assert!(!verify_plan_seal(&tampered));
}

#[test]
fn plan_digest_ignores_key_order() {
    let a = json!({"x": 1, "y": 2}).as_object().unwrap().clone();
    let b = json!({"y": 2, "x": 1}).as_object().unwrap().clone();
    assert_eq!(stable_plan_digest(&a), stable_plan_digest(&b));
}

#[test]
fn plan_reconciliation_flags_missing_checks() {
    let plan = json!({
        "denominator": {"expectedChecks": ["lint"]},
        "providers": [{"id": "p.lint", "phase": "facts", "runner": {"kind": "legacy-check", "check": "lint"}}],
    })
    .as_object()
    .unwrap()
    .clone();
    let facts = json!({"checks": []});
    let out = reconcile_plan_with_facts(&plan, &facts);
    assert_eq!(out["valid"], json!(false));
    assert_eq!(out["missingChecks"], json!(["lint"]));
}

// --- audit-finalize.mjs: finalizeAudit end-to-end ---

#[test]
fn finalize_audit_reports_pass_when_facts_clean_and_no_findings() {
    let facts = json!({
        "workspace": "/repo", "incomplete": false, "checks": [],
        "plan_binding_verification": {"valid": true, "drift": []},
        "plan": {"coverageGaps": [], "reasoningProviders": [], "selectedProviderIds": []},
        "network_policy": {"mode": "deny"},
        "provider_reconciliation": {
            "missingChecks": [], "unplannedChecks": [], "denominatorMismatches": [],
            "providerResults": [], "unresolvedCoverage": [], "missingRuntimeProviders": [],
        },
    });
    let candidates = json!({"candidates": []});
    let adjudication = json!({"complete": true, "verdicts": []});
    let report = finalize_audit(&facts, &candidates, &adjudication);
    assert_eq!(report["audit_status"], json!("pass"));
    assert_eq!(report["quality_gate"], json!("pass"));
}

// --- audit-run.mjs: pure helpers ---

#[test]
fn run_out_scope_stays_under_dot_audit() {
    assert!(assert_run_owned_out_scope(Path::new("/repo"), Path::new("/repo/.audit/x")).is_ok());
    assert!(assert_run_owned_out_scope(Path::new("/repo"), Path::new("/tmp/x")).is_err());
}

#[test]
fn run_severity_hint_matches_js() {
    assert_eq!(severity_hint("error"), "high");
    assert_eq!(severity_hint("warning"), "medium");
    assert_eq!(severity_hint("note"), "low");
}

#[test]
fn run_candidate_provider_ids_and_aggregation() {
    let plan = json!({"providers": [{"id": "security.secrets", "producesSecurityCandidates": true}]});
    let ids = candidate_provider_ids(&plan);
    assert!(ids.contains("security.secrets"));

    let internal = json!({"candidates": []});
    let results = vec![json!({
        "provider": "security.secrets", "findings": [],
        "candidates": [{"ruleId": "aws-key", "file": "a.rs", "line": 3}],
    })];
    let out = aggregate_security_candidates(&plan, &internal, &results).unwrap();
    let candidates = out["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["verdict"], json!("UNADJUDICATED"));
    assert_eq!(candidates[0]["adjudicationRequired"], json!(true));
}

// --- audit-runtime.mjs: typed degradation helpers ---

#[test]
fn runtime_degradation_pipeline() {
    let parsed = parse_surfaces_input(r#"[{"label":"editor","text":"New text"}]"#).unwrap();
    assert_eq!(parsed.targets.len(), 1);

    let kind = classify_runtime_failure("No Chrome/Edge found for the runtime pass.");
    assert_eq!(kind, "browser-unavailable");

    let denominator = json!({"kind": "runtime-surfaces", "expected": 0, "examined": 0});
    let gap = json!({"kind": kind, "detail": "no browser"});
    let report = build_degraded_report(&[gap], &denominator, None, 12);
    assert_eq!(report["incomplete"], json!(true));
    assert_eq!(report["url"], json!(null));
}
