//! Integration coverage for `legion_runtime::l4_platform` platform surface
//! (contracts, artifact sanitize, promotion equivalence, release candidate,
//! external evidence validation, faults, journeys, lifecycle), ported from
//! `src/lib/platform/**` in the JS legacy spec.

use legion_runtime::l4_platform::artifact_sanitize::sanitize_produced_artifact;
use legion_runtime::l4_platform::contracts::{capability_receipt, sha256_bytes, terminal_scenario_receipt};
use legion_runtime::l4_platform::external::{validate_external_evidence, ExpectedEvidence};
use legion_runtime::l4_platform::faults::{orchestrate_fault, validate_fault_injection, FaultAdapter};
use legion_runtime::l4_platform::journeys::{run_journey, JourneyAdapter};
use legion_runtime::l4_platform::lifecycle::{run_lifecycle_action, LifecycleAdapter};
use legion_runtime::l4_platform::promotion_equivalence::promotion_equivalence;
use legion_runtime::l4_platform::release_candidate::{create_release_candidate, verify_candidate_artifact};
use serde_json::{json, Value};

#[test]
fn capability_and_scenario_receipts_round_trip() {
    let receipt = capability_receipt(&json!({"id": "mic", "status": "available"}));
    assert_eq!(receipt["kind"], "legion-platform-capability");
    assert_eq!(receipt["status"], "available");

    let scenario = terminal_scenario_receipt(&json!({"scenarioId": "s1", "status": "pass"}));
    assert_eq!(scenario["terminal"], true);
    assert_eq!(scenario["status"], "pass");
}

#[test]
fn promotion_equivalence_and_release_candidate_are_consistent() {
    let candidate = create_release_candidate(&json!({
        "sourceRevision": "abc",
        "artifacts": [{"path": "dist/pkg", "digest": "sha256:x"}],
    }));
    assert_eq!(candidate["complete"], true);
    let verified = verify_candidate_artifact(&candidate, &json!({"path": "dist/pkg", "digest": "sha256:x"}));
    assert_eq!(verified["status"], "pass");

    let qa = json!({"digest": "sha256:qa", "artifacts": [{"id": "a1", "digest": "sha256:x"}]});
    let promoted = vec![json!({"sourceArtifactId": "a1", "digest": "sha256:x"})];
    assert_eq!(promotion_equivalence(Some(&qa), &promoted)["status"], "pass");
}

#[test]
fn produced_artifact_sanitization_round_trips() {
    let digest = sha256_bytes(b"hello world");
    let artifact = json!({"content": "hello world", "digest": digest});
    let result = sanitize_produced_artifact(&artifact, &[]);
    assert!(result.valid);
    assert!(!result.sensitive);
}

#[test]
fn external_evidence_without_producer_is_unproven() {
    let result = validate_external_evidence(None, &ExpectedEvidence::default());
    assert_eq!(result["status"], "unproven");
    assert!(result["gaps"].as_array().unwrap().iter().any(|g| g == "missing-producer"));
}

#[test]
fn fault_injection_requires_bounded_duration() {
    let cap = json!({"status": "available"});
    let unbounded = json!({"id": "f1"});
    assert_eq!(validate_fault_injection(Some(&unbounded), Some(&cap)).status, "blocked");
    let bounded = json!({"id": "f1", "durationMs": 50});
    assert_eq!(validate_fault_injection(Some(&bounded), Some(&cap)).status, "pass");
}

struct PassingFaultAdapter;
#[async_trait::async_trait]
impl FaultAdapter for PassingFaultAdapter {
    async fn inject(&self, _fault: &Value) -> Value {
        json!({"activated": true})
    }
    async fn observe(&self) -> Value {
        json!({"observed": true})
    }
    async fn recover(&self) -> Value {
        json!({"ok": true})
    }
}

#[tokio::test]
async fn fault_orchestration_passes_on_clean_recovery() {
    let cap = json!({"status": "available"});
    let fault = json!({"id": "f1", "durationMs": 100});
    let result = orchestrate_fault(Some(&fault), &PassingFaultAdapter, Some(&cap), Some(&json!("scenario-1")), &[]).await;
    assert_eq!(result["status"], "pass");
}

struct PassingJourneyAdapter;
#[async_trait::async_trait]
impl JourneyAdapter for PassingJourneyAdapter {
    async fn execute(&self, _step: &Value) -> Option<Value> {
        Some(json!({"status": "pass", "terminal": true, "durableState": {"ok": true}, "observedState": {"ready": true}}))
    }
}

#[tokio::test]
async fn journey_runs_to_completion_through_state_machine() {
    let cap = json!({"status": "available"});
    let scenario = json!({
        "id": "s1",
        "initialState": "idle",
        "machine": {"transitions": [{"from": "idle", "event": "go", "to": "done"}]},
        "steps": [{"id": "step1", "event": "go", "invariant": {"path": "ready", "equals": true}}],
    });
    let result = run_journey(Some(&scenario), Some(&PassingJourneyAdapter), Some(&cap), json!({})).await;
    assert_eq!(result["status"], "pass");
}

struct PassingLifecycleAdapter;
#[async_trait::async_trait]
impl LifecycleAdapter for PassingLifecycleAdapter {
    async fn run(&self, _action: &str) -> Option<Result<Value, String>> {
        Some(Ok(json!({"status": "pass"})))
    }
}

#[tokio::test]
async fn lifecycle_action_requires_available_capability() {
    let result = run_lifecycle_action("launch", Some(&PassingLifecycleAdapter), None, Value::Null, json!({}), false).await;
    assert_eq!(result["status"], "blocked");

    let cap = json!({"status": "available"});
    let result = run_lifecycle_action("launch", Some(&PassingLifecycleAdapter), Some(&cap), Value::Null, json!({}), false).await;
    assert_eq!(result["status"], "pass");
}
