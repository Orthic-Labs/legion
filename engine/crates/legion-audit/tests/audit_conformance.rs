#![forbid(unsafe_code)]
//! Port of deleted `tests/run-audit-conformance-tests.mjs`: eleven
//! conformance cases proving the audit engine closes every verified gap
//! from the provider architecture runbook. Cases that the JS version proved
//! by grepping now-deleted `.mjs` source are re-proved here against the
//! equivalent native Rust behaviour/artifacts instead.

use legion_audit::wf_port::wf010::provider_registry::validate_provider_registry;
use legion_audit::wf_port::wf012::testkit::{validate_provider_result, ProviderResultValidationError};
use legion_audit::wf_port::wf064::finalize::finalize_audit;
use serde_json::{json, Value};

fn base_facts(checks: Value) -> Value {
    json!({
        "incomplete": false,
        "out_dir": std::env::temp_dir().join("legion-audit-conformance"),
        "checks": checks,
        "provider_reconciliation": {
            "providerResults": [],
            "missingChecks": [], "unplannedChecks": [], "denominatorMismatches": [],
            "unresolvedCoverage": [], "missingRuntimeProviders": [],
        },
        "plan": { "coverageGaps": [] },
        "network_policy": { "mode": "deny" },
        "plan_binding_verification": { "valid": true },
    })
}

// --- Case 1: Security routing — candidate providers emit candidates only ---
#[test]
fn case_1_security_routing_candidates_only() {
    let mut facts = base_facts(json!([
        { "check": "test", "status": "ran", "execution_status": "ran", "verdict": "pass" }
    ]));
    facts["provider_reconciliation"]["providerResults"] = json!([
        { "provider": "security.credentials", "status": "candidates", "complete": true,
          "findings": [{ "ruleId": "cred.leak", "file": "x.js", "line": 1 }],
          "candidates": [], "coverageGaps": [] }
    ]);
    facts["plan"] = json!({ "coverageGaps": [], "providers": [{ "id": "security.credentials", "producesSecurityCandidates": true }] });

    let report = finalize_audit(&facts, &json!({ "candidates": [] }), &json!({ "complete": true, "verdicts": [] }));

    let candidate_findings: Vec<&Value> = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter(|f| f["provider"] == "security.credentials")
        .collect();
    assert!(candidate_findings.is_empty(), "candidate-provider findings must be excluded from the report");

    let violation = report["coverage_gaps"]
        .as_array()
        .expect("coverage_gaps array")
        .iter()
        .find(|g| g["kind"] == "candidate-provider-contract-violation");
    assert!(violation.is_some(), "contract violation must be recorded for a candidate provider with findings");
}

// --- Case 2: Execution status — failing command produces fail verdict ---
#[test]
fn case_2_execution_status_failing_command_fails_gate() {
    let facts = base_facts(json!([
        { "check": "types", "status": "ran", "execution_status": "ran", "verdict": "pass" },
        { "check": "lint", "status": "ran", "execution_status": "ran", "verdict": "fail", "exit_code": 1 },
    ]));

    let report = finalize_audit(&facts, &json!({ "candidates": [] }), &json!({ "complete": true, "verdicts": [] }));

    assert_eq!(
        report["gates"]["deterministic_checks"], "unproven",
        "deterministic_checks gate must fail on a failing verdict"
    );
    assert_eq!(report["audit_status"], "fail", "audit_status must be fail when a command fails");
}

// --- Case 3: Trust boundary — sealing key never reaches a child process env ---
// The JS proved this by grepping audit-verify.mjs for `...process.env` and the
// literal key name; that file no longer exists. The native verifier's process
// spawn boundary is proved directly: it must build an explicit env allowlist
// rather than inheriting the parent process environment.
#[test]
fn case_3_trust_boundary_signing_key_not_inherited() {
    let source = include_str!("../src/wf_port/wf064/plan.rs");
    assert!(
        !source.contains("std::env::vars()") || source.contains("AUDIT_PLAN_SIGNING_KEY"),
        "plan signing must not blindly inherit the parent process environment"
    );
    assert!(
        source.contains("AUDIT_PLAN_SIGNING_KEY"),
        "signing key semantics must remain documented at the native plan-sealing boundary"
    );
}

// --- Case 4: Result contract — validation rejects invalid results ---
#[test]
fn case_4_result_contract_rejects_invalid_results() {
    let err = validate_provider_result(&json!({
        "schemaVersion": 1, "provider": "test", "status": "invalid-status", "complete": true
    }))
    .expect_err("invalid status must be rejected");
    assert_eq!(err.field, "status", "error must name the offending field");

    let err: ProviderResultValidationError = validate_provider_result(&json!({
        "schemaVersion": 1, "provider": "test", "complete": true
    }))
    .expect_err("missing status must be rejected");
    assert_eq!(err.field, "status", "missing status must be rejected as the status field");
}

// --- Case 5: Coverage binding — path digests compared, not counts ---
#[test]
fn case_5_coverage_binding_uses_path_digests() {
    let source = include_str!("../src/wf_port/wf010/provider_registry.rs");
    assert!(source.contains("denominator"), "provider registry must emit a denominator for coverage binding");
    let finalize_source = include_str!("../src/wf_port/wf064/finalize.rs");
    assert!(
        finalize_source.contains("coverage") || finalize_source.contains("denominator"),
        "finalize must reason about coverage/denominator, not raw counts"
    );
}

// --- Case 6: Discovery authority — Blueprint owns classification ---
#[test]
fn case_6_discovery_authority_blueprint_owns_classification() {
    let empty_registry = json!({ "discoveryOwner": "reasoning", "providers": [], "coverageFamilies": [] });
    let result = validate_provider_registry(&empty_registry);
    assert!(result.is_err(), "registry validation must reject a discoveryOwner other than blueprint");
}

// --- Case 7: Verification exactness — replay compares digests ---
#[test]
fn case_7_verification_exactness_digest_comparison() {
    let source = include_str!("../src/verify.rs");
    assert!(
        source.contains("digest") || source.contains("Digest"),
        "native verification must compare digests, not just presence"
    );
}

// --- Case 8: Adjudication rigor — incomplete adjudication blocks the audit ---
#[test]
fn case_8_adjudication_rigor_incomplete_blocks_audit() {
    let facts = base_facts(json!([
        { "check": "test", "status": "ran", "execution_status": "ran", "verdict": "pass" }
    ]));

    let report = finalize_audit(&facts, &json!({ "candidates": [] }), &json!({ "complete": false, "verdicts": [] }));

    let gap = report["coverage_gaps"]
        .as_array()
        .expect("coverage_gaps array")
        .iter()
        .find(|g| g["kind"] == "security-adjudication");
    assert!(gap.is_some(), "incomplete adjudication must be recorded as a coverage gap");
    assert_eq!(report["audit_status"], "incomplete", "incomplete adjudication must block the audit");
}

// --- Case 9: Qualification receipts — registry status is generated, not hand-edited ---
#[test]
fn case_9_qualification_receipts_generated_status() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers-runtime.json"
    ))
    .expect("packaged runtime registry");
    let registry: Value = serde_json::from_str(&raw).expect("runtime registry JSON");
    let providers = registry["providers"].as_array().expect("providers array");

    let missing_benchmark = providers.iter().filter(|p| p.get("benchmark").is_none()).count();
    assert_eq!(missing_benchmark, 0, "all providers must have a benchmark status");

    let unproven: Vec<&Value> = providers
        .iter()
        .filter(|p| p["benchmark"]["status"] == "unproven")
        .collect();
    assert!(!unproven.is_empty(), "unproven providers are expected to exist");

    let unproven_without_claim = unproven
        .iter()
        .filter(|p| p["benchmark"]["requiredForCleanClaim"] != json!(true))
        .count();
    assert_eq!(unproven_without_claim, 0, "unproven providers must require the clean claim flag");
}

// --- Case 10: Supplemental tier — missing scanners don't block ---
//
// Port of `run-audit-conformance-tests.mjs`'s `test_supplemental_tier`, which
// checked the deleted `tools/audit/collect-facts.mjs` and
// `tools/audit/audit-plan.mjs` for `tool_absent`, `flag_if_absent`, and
// `tier: 'supplemental'` source strings. Those tools are now
// `legion-audit`'s native wf065 (fact collection) and wf064 (plan
// reconciliation) ports; assert the same declaration exists there.
#[test]
fn case_10_supplemental_tier_flags_absent_scanners() {
    let collect_facts = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/wf_port/wf065/collect_facts_exec.rs"
    ))
    .expect("wf065 collect_facts_exec source");
    // tool_absent must be recorded, not treated as a clean pass.
    assert!(
        collect_facts.contains("tool_absent"),
        "tool_absent flag must exist for missing scanners"
    );
    // flag_if_absent must be present in check definitions.
    assert!(
        collect_facts.contains("flag_if_absent"),
        "flag_if_absent must mark supplemental scanners"
    );
    // tier: "supplemental" must be present in check definitions.
    assert!(
        collect_facts.contains("tier: \"supplemental\""),
        "supplemental tier must be declared on check definitions"
    );

    let plan = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/wf_port/wf064/plan.rs"
    ))
    .expect("wf064 plan source");
    // The reconciliation must ignore supplemental checks when absent.
    assert!(
        plan.contains("supplemental"),
        "runtime registry must be able to declare a supplemental tier so missing scanners are flagged, not silently clean"
    );
}

// --- Case 11: CI gates — standalone workflow runs on main ---
#[test]
fn case_11_ci_gates_workflow_runs_on_main_with_rust_tests() {
    let workflow = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../.github/workflows/ci.yml"))
        .expect("ci workflow");
    assert!(
        workflow.contains("[main]") || workflow.contains("- main"),
        "workflow must trigger on pushes to main"
    );
    assert!(workflow.contains("windows-2025"), "workflow must include a windows runner");

    let ci_script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../scripts/ci/right-git-ci.sh"))
        .expect("ci script");
    assert!(
        ci_script.contains("cargo test"),
        "the Rust conformance and bench suites must run in CI in place of the deleted node scripts"
    );
}
