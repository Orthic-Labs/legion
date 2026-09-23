//! Integration tests for chunk wf047 (`src/providers/runtime/{service,web}`)
//! against `legion_audit::wf_port::wf047::*`.
//!
//! No JS test file exercising `verifyServiceData`, `createFaultAdapter`,
//! `verifyWebAccessibility`, `buildActorFixtures`/`switchActor`, or
//! `verifyApiExercise` was found under the repository (`git grep`/`find`
//! for `.test.mjs` files referencing these names returned nothing), so
//! these are net-new coverage rather than ported assertions; unit tests
//! inside each `wf_port::wf047::*` submodule cover the individual
//! branches in more depth.

use legion_audit::wf_port::wf047::accessibility::{verify_web_accessibility, CaptureEvidence};
use legion_audit::wf_port::wf047::actors::{build_actor_fixtures, switch_actor};
use legion_audit::wf_port::wf047::api::verify_api_exercise;
use legion_audit::wf_port::wf047::data::{verify_service_data, DataAdapter};
use legion_audit::wf_port::wf047::faults::create_fault_adapter;
use serde_json::{json, Value};

fn full_binding() -> Value {
    json!({
        "targetId": "t1", "environment": "staging", "actorId": "a1", "tenantId": "tenant-1",
        "browser": "chromium", "browserVersion": "120", "viewport": "1280x800", "locale": "en-US",
        "sourceRevision": "sha256abc", "artifactDigest": "sha256:".to_owned() + &"a".repeat(64),
    })
}

#[test]
fn service_data_reports_unproven_with_no_adapter_and_wraps_with_service_provider_fields() {
    let binding = full_binding();
    let mut adapter = DataAdapter::default();
    let cases = json!(["case-1"]);
    let out = verify_service_data(&binding, Some("dataset-1"), Some("v1"), &mut adapter, &cases);
    assert_eq!(out["provider"], "runtime.service.data");
    assert_eq!(out["claimLevel"], "runtime");
    assert_eq!(out["kind"], "legion-service-data-provider", "finalize re-adds its own kind after verifyServiceData strips the inner one");
    assert!(out.get("digest").is_some(), "finalize re-adds its own digest");
    assert_eq!(out["status"], "unproven");
}

#[test]
fn service_fault_adapter_worker_restart_is_restartable_and_reports_cleanup_binding() {
    let mut adapter = create_fault_adapter("clean");
    let binding = json!({ "deployment": "d1", "region": "us-east", "datastore": "primary" });
    let out = adapter.execute("worker-restart", &binding);
    assert_eq!(out["status"], "pass");
    assert_eq!(out["terminal"], true);
    assert_eq!(out["restartable"], true);
    assert_eq!(out["cleanup"]["deployment"], "d1");
    assert_eq!(out["cleanup"]["region"], "us-east");
}

#[test]
fn service_fault_adapter_rejects_unsupported_scenario() {
    let mut adapter = create_fault_adapter("clean");
    let out = adapter.execute("not-a-real-scenario", &Value::Null);
    assert_eq!(out["status"], "error");
    assert_eq!(out["coverageGaps"][0], "unsupported-runtime-scenario");
}

#[test]
fn web_accessibility_passes_with_matching_clean_inspections() {
    let binding = full_binding();
    let captures = json!([{ "repeat": "1" }, { "repeat": "2" }]);
    let inspections = json!([
        { "repeat": "1", "violations": [], "binding": binding, "terminal": true, "status": "pass", "screenshot": "a.png" },
        { "repeat": "2", "violations": [], "binding": binding, "terminal": true, "status": "pass", "screenshot": "b.png" },
    ]);
    let tool = json!({ "accessibilityEngine": "axe-core", "accessibilityEngineVersion": "4.9" });
    let out = verify_web_accessibility(
        &binding,
        &captures,
        &inspections,
        &tool,
        CaptureEvidence { digest: Value::String("sha256:capture".to_string()), coverage_gaps: vec![] },
    );
    assert_eq!(out["status"], "pass");
    assert_eq!(out["violationCount"], 0);
    assert_eq!(out["denominator"]["total"], 2);
}

#[test]
fn web_accessibility_flags_missing_and_unplanned_inspections() {
    let binding = full_binding();
    let captures = json!([{ "repeat": "1" }, { "repeat": "2" }]);
    let inspections = json!([
        { "repeat": "1", "violations": [], "binding": binding, "terminal": true, "status": "pass", "screenshot": "a.png" },
        { "repeat": "3", "violations": [], "binding": binding, "terminal": true, "status": "pass", "screenshot": "c.png" },
    ]);
    let out = verify_web_accessibility(
        &binding,
        &captures,
        &inspections,
        &Value::Null,
        CaptureEvidence { digest: Value::Null, coverage_gaps: vec![] },
    );
    assert_eq!(out["status"], "unproven");
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"accessibility-inspection-missing:2"));
    assert!(gaps.contains(&"accessibility-inspection-unplanned:3"));
}

#[test]
fn actor_fixtures_pass_and_switch_actor_succeeds_within_same_tenant() {
    // `switchActor` requires `sameBinding(receipt.binding, sessionBinding)`
    // to hold across every `BINDING_KEYS` entry (`src/providers/runtime/web/
    // shared.mjs`, `sameBinding`), not just `actorId`/`tenantId`, so the
    // session binding must carry the full binding, and the binding's own
    // `actorId` must equal the switching actor's id since `sessionBinding.
    // actorId !== from` is also checked.
    let mut binding = full_binding();
    binding["actorId"] = json!("actor-a");
    let actors = json!([
        {
            "id": "actor-a", "identityId": "id-a", "credentialPolicyId": "cred-1", "sessionPolicyId": "sess-1",
            "role": "member", "tier": "standard", "tenantId": "tenant-1", "accountState": "active",
            "secretRef": "vault://actor-a-secret", "issuedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2030-01-01T00:00:00Z", "revokedAt": null,
            "serverAuthorizations": [], "uiVisibility": [], "transitionCapabilities": [],
        },
        {
            "id": "actor-b", "identityId": "id-a", "credentialPolicyId": "cred-1", "sessionPolicyId": "sess-1",
            "role": "member", "tier": "standard", "tenantId": "tenant-1", "accountState": "active",
            "secretRef": "vault://actor-b-secret", "issuedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2030-01-01T00:00:00Z", "revokedAt": null,
            "serverAuthorizations": [], "uiVisibility": [], "transitionCapabilities": [],
        },
    ]);
    let required = json!([
        { "role": "member", "tier": "standard", "tenantId": "tenant-1", "accountState": "active" },
    ]);
    let identity_capability = json!({ "status": "available" });
    let environment_capability = json!({ "status": "available" });
    let receipt = build_actor_fixtures(
        &binding,
        &actors,
        &required,
        Some("2026-06-01T00:00:00Z"),
        &identity_capability,
        &environment_capability,
    );
    assert_eq!(receipt["status"], "pass");
    assert_eq!(receipt["complete"], true);
    assert_eq!(receipt["proof"], true);

    let session_binding = receipt["binding"].clone();
    let result = switch_actor(&receipt, "actor-a", "actor-b", "actor-a", &session_binding, &[], None, &Value::Null);
    assert_eq!(result["status"], "pass");
    assert_eq!(result["from"], "actor-a");
    assert_eq!(result["to"], "actor-b");
}

#[test]
fn switch_actor_blocks_on_digest_mismatch() {
    let receipt = json!({ "digest": "sha256:not-real", "status": "pass", "terminal": true, "complete": true, "proof": true });
    let out = switch_actor(&receipt, "a", "b", "a", &Value::Null, &[], None, &Value::Null);
    assert_eq!(out["status"], "blocked");
    assert_eq!(out["reason"], "actor-fixture-digest-mismatch");
}

#[test]
fn api_exercise_reports_pass_for_empty_cases_with_valid_applicability() {
    let binding = full_binding();
    let applicability = json!({
        "status": "not-applicable",
        "reason": "no REST endpoints in this surface",
        "source": {
            "kind": "configured", "id": "surface-plan-1",
            "digest": format!("sha256:{}", "b".repeat(64)),
            "binding": binding,
        },
    });
    let out = verify_api_exercise(&binding, &json!([]), &applicability);
    assert_eq!(out["status"], "pass");
    assert_eq!(out["applicable"], false);
}

#[test]
fn api_exercise_rejects_unsafe_case_id() {
    let cases = json!([{ "id": "has spaces!" }]);
    let out = verify_api_exercise(&Value::Null, &cases, &Value::Null);
    assert_eq!(out["status"], "error");
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"api-case-id-invalid"));
}

#[test]
fn api_exercise_case_missing_every_required_proof_field_is_unproven_not_pass() {
    let binding = full_binding();
    let cases = json!([{
        "id": "case-1", "actorId": binding["actorId"], "tenantId": binding["tenantId"],
        "dataScope": "own", "lifecycle": "create", "protocol": "rest", "method": "GET", "path": "/x",
    }]);
    let out = verify_api_exercise(&binding, &cases, &Value::Null);
    assert_eq!(out["status"], "unproven");
    assert_eq!(out["receipts"][0]["status"], "unproven");
}
