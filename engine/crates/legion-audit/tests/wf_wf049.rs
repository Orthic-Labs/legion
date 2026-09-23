//! Tests for wf049: `legion_audit::wf_port::wf049::{infrastructure, integration, journey_plan, matrix, operations}`.
//!
//! No JS test file exists for `src/providers/runtime/web/{infrastructure,
//! integration,journey-plan,matrix,operations}/index.mjs` in this checkout
//! (searched for `.test.mjs` files importing any of the five exports; none
//! found), so these tests are original, exercising the gap-reporting
//! behaviour described by the JS source directly.

use legion_audit::wf_port::wf049::infrastructure::{
    verify_infrastructure_exercise, SignatureVerifier, VerifyInfrastructureExerciseInput,
};
use legion_audit::wf_port::wf049::integration::integrate_web_evidence;
use legion_audit::wf_port::wf049::journey_plan::{web_journey_for_control, web_journeys, WebJourneySurfaceMatchesInput};
use legion_audit::wf_port::wf049::matrix::{compile_web_matrix, is_web_matrix_combination_id};
use legion_audit::wf_port::wf049::operations::{verify_operations_exercise, VerifyOperationsExerciseInput};
use serde_json::json;

fn binding() -> serde_json::Value {
    json!({
        "targetId": "target-1",
        "environment": "staging",
        "actorId": "actor-1",
        "tenantId": "tenant-1",
        "browser": "chromium",
        "browserVersion": "128",
        "viewport": "1440x900",
        "locale": "en-GB",
        "sourceRevision": "rev-1",
        "artifactDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000000000000000",
    })
}

// --- journey_plan -----------------------------------------------------

#[test]
fn journey_plan_loads_the_registry_fixture() {
    // Sanity check against the copied fixture: every journey row from the
    // real registry (embedded via include_str! in journey_plan.rs) must be
    // non-empty, matching `WEB_JOURNEYS = WEB_JOURNEY_PLAN.journeys`.
    assert!(!web_journeys().is_empty());
}

#[test]
fn web_journey_for_control_finds_a_known_row_and_none_for_unknown() {
    let known_id = web_journeys()[0].get("controlId").and_then(|v| v.as_str()).unwrap().to_string();
    assert!(web_journey_for_control(&known_id).is_some());
    assert!(web_journey_for_control("definitely-not-a-real-control-id").is_none());
}

#[test]
fn web_journey_surface_matches_requires_applicable_true_and_all_fields() {
    let row = web_journeys().iter().find(|r| r.get("applicable") == Some(&serde_json::Value::Bool(true))).unwrap();
    let route = row.get("route").and_then(|v| v.as_str());
    let state_id = row.get("stateId").and_then(|v| v.as_str());
    let matrix_combination_id = row.get("matrixCombinationId").and_then(|v| v.as_str());
    assert!(web_journey_surface_matches_wraps(route, state_id, matrix_combination_id));
    // Mismatched route never matches.
    assert!(!web_journey_surface_matches_wraps(Some("/definitely-not-a-real-route"), state_id, matrix_combination_id));
}

fn web_journey_surface_matches_wraps(route: Option<&str>, state_id: Option<&str>, matrix_combination_id: Option<&str>) -> bool {
    legion_audit::wf_port::wf049::journey_plan::web_journey_surface_matches(WebJourneySurfaceMatchesInput {
        journey_id: None,
        route,
        state_id,
        matrix_combination_id,
    })
}

// --- matrix -------------------------------------------------------------

#[test]
fn matrix_combination_ids_from_the_plan_are_recognized() {
    // The plan always contains the registry's mandatory combinations.
    assert!(is_web_matrix_combination_id("desktop-chromium"));
    assert!(!is_web_matrix_combination_id("not-a-real-combination-id"));
}

#[test]
fn compile_web_matrix_reports_collections_invalid_for_bad_policy() {
    let result = compile_web_matrix(binding(), json!("not-an-object"), vec![]);
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(result["status"], "error");
    assert!(gaps.contains(&"matrix-policy-invalid".to_string()));
    assert!(gaps.contains(&"matrix-collections-invalid".to_string()));
}

#[test]
fn compile_web_matrix_with_empty_policy_reports_denominator_empty() {
    let result = compile_web_matrix(binding(), json!({}), vec![]);
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"matrix-denominator-empty".to_string()));
    assert!(!result["combinations"].as_array().unwrap().is_empty());
}

// --- integration ----------------------------------------------------------

#[test]
fn integrate_web_evidence_reports_missing_terminal_receipts() {
    let result = integrate_web_evidence(binding(), vec![json!("tls"), json!("dns")], vec![]).unwrap();
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"missing-terminal-receipt:dns".to_string()));
    assert!(gaps.contains(&"missing-terminal-receipt:tls".to_string()));
    assert_eq!(result["status"], "partial");
}

#[test]
fn integrate_web_evidence_rejects_cross_target_receipts() {
    let mut other_binding = binding();
    other_binding["targetId"] = json!("other-target");
    let receipt = json!({ "controlId": "tls", "targetId": "other-target", "terminal": true, "status": "pass" });
    let err = integrate_web_evidence(binding(), vec![json!("tls")], vec![receipt]).unwrap_err();
    assert!(err.contains("cross-target evidence rejected: tls"));
}

#[test]
fn integrate_web_evidence_passes_with_clean_matching_receipts() {
    let receipt = json!({
        "controlId": "tls",
        "targetId": "target-1",
        "terminal": true,
        "status": "pass",
        "binding": binding(),
        "artifacts": [],
    });
    let result = integrate_web_evidence(binding(), vec![json!("tls")], vec![receipt]).unwrap();
    assert_eq!(result["status"], "pass");
    assert!(result["coverageGaps"].as_array().unwrap().is_empty());
}

// --- infrastructure -------------------------------------------------------

struct AlwaysValidVerifier;
impl SignatureVerifier for AlwaysValidVerifier {
    fn verify(&self, _public_key: &str, _signed_content: &[u8], _signature: &[u8]) -> bool {
        true
    }
}

struct AlwaysInvalidVerifier;
impl SignatureVerifier for AlwaysInvalidVerifier {
    fn verify(&self, _public_key: &str, _signed_content: &[u8], _signature: &[u8]) -> bool {
        false
    }
}

#[test]
fn verify_infrastructure_exercise_flags_untrusted_producer_collection() {
    let result = verify_infrastructure_exercise(VerifyInfrastructureExerciseInput {
        binding: binding(),
        evidence: None,
        trusted_producers: vec![json!({ "id": "" })],
        now: None,
        max_age_ms: None,
        signature_verifier: &AlwaysValidVerifier,
    });
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(result["status"], "error");
    assert!(gaps.contains(&"trusted-producers-invalid".to_string()));
}

#[test]
fn verify_infrastructure_exercise_rejects_invalid_signature() {
    let evidence = json!({ "producer": "prod-1", "signedContent": "{}", "signature": "AAAA" });
    let result = verify_infrastructure_exercise(VerifyInfrastructureExerciseInput {
        binding: binding(),
        evidence: Some(evidence),
        trusted_producers: vec![json!({ "id": "prod-1", "publicKey": "pem" })],
        now: None,
        max_age_ms: Some(1000.0),
        signature_verifier: &AlwaysInvalidVerifier,
    });
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"signature-invalid".to_string()));
    assert!(gaps.contains(&"deployed-proof-required".to_string()));
    assert!(gaps.contains(&"rollback-not-exercised".to_string()));
}

#[test]
fn verify_infrastructure_exercise_missing_evidence_reports_supplied_evidence_missing() {
    let result = verify_infrastructure_exercise(VerifyInfrastructureExerciseInput {
        binding: binding(),
        evidence: None,
        trusted_producers: vec![json!({ "id": "prod-1", "publicKey": "pem" })],
        now: None,
        max_age_ms: None,
        signature_verifier: &AlwaysValidVerifier,
    });
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"supplied-evidence-missing".to_string()));
    assert!(gaps.contains(&"producer-untrusted".to_string()));
}

// --- operations -------------------------------------------------------

#[test]
fn verify_operations_exercise_reports_collections_invalid_for_bad_input() {
    let result = verify_operations_exercise(VerifyOperationsExerciseInput {
        binding: binding(),
        exercises: vec![json!("not-an-object")],
        trusted_producers: vec![],
        now: None,
        max_age_ms: None,
        signature_verifier: &AlwaysValidVerifier,
    });
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(result["status"], "error");
    assert!(gaps.contains(&"operations-collections-invalid".to_string()));
}

#[test]
fn verify_operations_exercise_reports_identifiers_invalid_for_unsafe_ids() {
    let result = verify_operations_exercise(VerifyOperationsExerciseInput {
        binding: binding(),
        exercises: vec![json!({ "id": "not a safe id!" })],
        trusted_producers: vec![],
        now: None,
        max_age_ms: None,
        signature_verifier: &AlwaysValidVerifier,
    });
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"operations-identifiers-invalid".to_string()));
}

#[test]
fn verify_operations_exercise_marks_every_missing_operation_id() {
    let result = verify_operations_exercise(VerifyOperationsExerciseInput {
        binding: binding(),
        exercises: vec![],
        trusted_producers: vec![],
        now: None,
        max_age_ms: None,
        signature_verifier: &AlwaysValidVerifier,
    });
    let gaps: Vec<String> =
        result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"operations-denominator-empty".to_string()));
    assert!(gaps.contains(&"operation-omitted:alerts".to_string()));
    assert!(gaps.contains(&"operation-omitted:rto".to_string()));
    let receipts = result["receipts"].as_array().unwrap();
    assert_eq!(receipts.len(), 19); // OPERATION_IDS.len()
    assert!(receipts.iter().all(|r| r["status"] == "unproven"));
}
