//! Tests for the Rust port of the legacy JS browser/native-surface/service
//! runtime providers (see `src/native_providers/p10_runtime/browser_service.rs`
//! doc comment for the full list of ported files). No dedicated JS test
//! files existed for these seven small modules, so these tests exercise the
//! documented behaviour of each production entry point directly: status
//! transitions (pass/unproven/blocked), redaction, binding validation, the
//! worker-restart coverage gap, and each fixture status.

use legion_audit::native_providers::p10_runtime::browser_service::{
    assess_service_runtime, build_browser_surface_receipt, build_native_surface_receipt,
    console_error_observation, create_fault_adapter, create_service_fixture_adapter,
    performance_observation, runtime_receipt, verify_service_api, verify_service_data,
    ConsoleErrorObservationInput, PerformanceObservationInput, RuntimeReceiptInput,
    ServiceRuntimeTarget,
};
use serde_json::json;

/* ----------------------------- browser/adapter.mjs ---------------------------- */

#[test]
fn browser_surface_receipt_passes_when_ready_and_undeclared_free() {
    let spec = json!({
        "surfaceId": "settings",
        "route": "/settings",
        "allowedActions": ["click"],
        "allowedDestinations": ["api.example.com"],
        "binding": {"targetId": "t1"},
    });
    let observation = json!({
        "ready": true,
        "reachedMeaningfulState": true,
        "actions": ["click"],
        "requests": [{"destination": "api.example.com"}],
        "state": "loaded",
    });
    let receipt = build_browser_surface_receipt(&spec, &observation);
    assert_eq!(receipt["status"], "pass");
    assert_eq!(receipt["complete"], true);
    assert_eq!(receipt["shallow"], false);
    assert!(receipt["undeclaredActions"].as_array().unwrap().is_empty());
    assert!(receipt["undeclaredDestinations"].as_array().unwrap().is_empty());
}

#[test]
fn browser_surface_receipt_blocks_on_undeclared_action_and_destination() {
    let spec = json!({"surfaceId": "s", "allowedActions": ["click"], "allowedDestinations": ["a.com"]});
    let observation = json!({
        "ready": true,
        "reachedMeaningfulState": true,
        "actions": ["navigate"],
        "requests": [{"destination": "evil.com"}],
    });
    let receipt = build_browser_surface_receipt(&spec, &observation);
    assert_eq!(receipt["status"], "blocked");
    assert_eq!(receipt["undeclaredActions"], json!(["navigate"]));
    assert_eq!(receipt["undeclaredDestinations"], json!(["evil.com"]));
}

#[test]
fn browser_surface_receipt_unproven_when_shallow_or_not_ready() {
    let spec = json!({"surfaceId": "s"});
    let observation = json!({"ready": true, "reachedMeaningfulState": false});
    let receipt = build_browser_surface_receipt(&spec, &observation);
    assert_eq!(receipt["status"], "unproven");
    assert_eq!(receipt["shallow"], true);
    assert_eq!(receipt["coverageGaps"], json!(["shallow-traversal"]));

    let observation2 = json!({"ready": false, "reachedMeaningfulState": true});
    let receipt2 = build_browser_surface_receipt(&spec, &observation2);
    assert_eq!(receipt2["status"], "unproven");
    assert_eq!(receipt2["coverageGaps"], json!(["readiness-unproven"]));
}

#[test]
fn browser_surface_receipt_blocked_on_failed_launch_or_missing_credentials() {
    let spec = json!({"surfaceId": "s"});
    let observation = json!({"ready": true, "reachedMeaningfulState": true, "failedLaunch": true});
    assert_eq!(build_browser_surface_receipt(&spec, &observation)["status"], "blocked");

    let observation2 = json!({"ready": true, "reachedMeaningfulState": true, "credentialsMissing": true});
    assert_eq!(build_browser_surface_receipt(&spec, &observation2)["status"], "blocked");
}

#[test]
fn browser_surface_receipt_redacts_sensitive_console_and_request_fields() {
    let spec = json!({"surfaceId": "s"});
    let observation = json!({
        "ready": true,
        "reachedMeaningfulState": true,
        "console": [{"message": "hi", "authToken": "abc123"}],
        "requests": [{"destination": "a.com", "headers": {"Cookie": "session=1", "Authorization": "Bearer x"}}],
    });
    let receipt = build_browser_surface_receipt(&spec, &observation);
    assert_eq!(receipt["console"][0]["authToken"], "[REDACTED]");
    assert_eq!(receipt["console"][0]["message"], "hi");
    assert_eq!(receipt["requests"][0]["headers"]["Cookie"], "[REDACTED]");
    assert_eq!(receipt["requests"][0]["headers"]["Authorization"], "[REDACTED]");
}

/* ------------------------- native-surface/adapter.mjs -------------------------- */

#[test]
fn native_surface_receipt_pass_and_blocked_paths() {
    let spec = json!({"surfaceId": "app", "allowedActions": ["tap"]});
    let ok = json!({"ready": true, "reachedMeaningfulState": true, "actions": ["tap"], "bridgeAvailable": true});
    let receipt = build_native_surface_receipt(&spec, &ok);
    assert_eq!(receipt["status"], "pass");
    assert_eq!(receipt["complete"], true);

    let bridge_down = json!({"ready": true, "reachedMeaningfulState": true, "bridgeAvailable": false});
    let receipt2 = build_native_surface_receipt(&spec, &bridge_down);
    assert_eq!(receipt2["status"], "blocked");
    assert_eq!(receipt2["coverageGaps"], json!(["native-bridge-unavailable"]));

    let undeclared = json!({"ready": true, "reachedMeaningfulState": true, "actions": ["swipe"]});
    let receipt3 = build_native_surface_receipt(&spec, &undeclared);
    assert_eq!(receipt3["status"], "blocked");
    assert_eq!(receipt3["undeclaredActions"], json!(["swipe"]));
}

#[test]
fn native_surface_receipt_shallow_is_unproven() {
    let spec = json!({"surfaceId": "app"});
    let observation = json!({"ready": true, "reachedMeaningfulState": false});
    let receipt = build_native_surface_receipt(&spec, &observation);
    assert_eq!(receipt["status"], "unproven");
    assert_eq!(receipt["shallow"], true);
}

/* ------------------------------ browser/index.mjs ------------------------------ */

#[test]
fn runtime_receipt_complete_requires_all_surfaces_tested_and_nonzero_found() {
    let complete = runtime_receipt(RuntimeReceiptInput {
        surfaces_found: Some(3),
        surfaces_tested: Some(3),
        ..Default::default()
    });
    assert_eq!(complete["complete"], true);

    let zero_found = runtime_receipt(RuntimeReceiptInput {
        surfaces_found: Some(0),
        surfaces_tested: Some(0),
        ..Default::default()
    });
    assert_eq!(zero_found["complete"], false);

    let shallow = runtime_receipt(RuntimeReceiptInput {
        surfaces_found: Some(2),
        surfaces_tested: Some(1),
        shallow: Some(true),
        ..Default::default()
    });
    assert_eq!(shallow["complete"], false);
    assert_eq!(shallow["coverageGaps"], json!([{"kind": "runtime-shallow-traversal"}]));
}

#[test]
fn console_error_observation_carries_through_fields() {
    let observation = console_error_observation(ConsoleErrorObservationInput {
        file: Some("app.js".to_string()),
        message: Some("boom".to_string()),
        surface: Some("settings".to_string()),
    });
    assert_eq!(observation["kind"], "legion-console-error");
    assert_eq!(observation["file"], "app.js");
    assert_eq!(observation["message"], "boom");
}

#[test]
fn performance_observation_violated_on_long_tasks_or_latency_over_threshold() {
    let clean = performance_observation(PerformanceObservationInput {
        surface: json!("settings"),
        long_tasks: 0.0,
        interaction_latency_ms: 50.0,
        threshold_ms: None,
    });
    assert_eq!(clean["violated"], false);
    assert_eq!(clean["thresholdMs"], 200.0);

    let slow = performance_observation(PerformanceObservationInput {
        surface: json!("settings"),
        long_tasks: 0.0,
        interaction_latency_ms: 250.0,
        threshold_ms: None,
    });
    assert_eq!(slow["violated"], true);

    let long_task = performance_observation(PerformanceObservationInput {
        surface: json!("settings"),
        long_tasks: 1.0,
        interaction_latency_ms: 10.0,
        threshold_ms: Some(500.0),
    });
    assert_eq!(long_task["violated"], true);
}

/* --------------------------- service/api,data index.mjs ------------------------ */

#[test]
fn verify_service_api_relabels_and_finalizes_the_exercise_receipt() {
    // An empty `binding: {}` makes `finalize`'s `exactBinding` flag every
    // BINDING_KEYS entry as invalid, which unconditionally forces
    // `status: 'error'` (web/shared.mjs:31,83) regardless of the receipt's
    // own status — see `finalize_flags_invalid_binding_values` below, which
    // tests exactly that behavior. Use a fully valid binding here so this
    // test actually exercises the pass-relabeling path it names.
    let exercise_receipt = json!({
        "digest": "sha256:stale",
        "kind": "legion-web-api-exercise",
        "schemaVersion": 1,
        "status": "pass",
        "terminal": true,
        "binding": {
            "targetId": "t1", "environment": "sandbox", "actorId": "a1", "tenantId": "tenant1",
            "browser": "chrome", "browserVersion": "120", "viewport": "1920x1080",
            "locale": "en-US", "sourceRevision": "abc123", "artifactDigest": "sha256:aa",
        },
    });
    let result = verify_service_api(exercise_receipt);
    assert_eq!(result["kind"], "legion-service-api-provider");
    assert_eq!(result["provider"], "runtime.service.api");
    assert_eq!(result["status"], "pass");
    assert!(result["digest"].as_str().unwrap().starts_with("sha256:"));
    assert_ne!(result["digest"], "sha256:stale");
}

#[test]
fn verify_service_data_adds_runtime_claim_level() {
    let exercise_receipt = json!({"status": "pass", "terminal": true, "binding": {}});
    let result = verify_service_data(exercise_receipt);
    assert_eq!(result["kind"], "legion-service-data-provider");
    assert_eq!(result["provider"], "runtime.service.data");
    assert_eq!(result["claimLevel"], "runtime");
}

#[test]
fn finalize_flags_invalid_binding_values() {
    let exercise_receipt = json!({"status": "pass", "terminal": true, "binding": {"targetId": ""}});
    let result = verify_service_api(exercise_receipt);
    assert_eq!(result["status"], "error");
    let gaps = result["coverageGaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g == "binding-invalid:targetId"));
}

/* ------------------------------ service/core index.mjs ------------------------- */

#[test]
fn assess_service_runtime_pass_when_every_scenario_passes_and_restartable() {
    let adapter = create_service_fixture_adapter("clean");
    let target = ServiceRuntimeTarget {
        id: Some("svc-1".to_string()),
        deployment: Some("prod".to_string()),
        ..Default::default()
    };
    let result = tokio_test_block_on(assess_service_runtime(&target, &adapter, &[]));
    assert_eq!(result["status"], "pass");
    assert_eq!(result["claims"]["runtime"], "evidenced");
    assert_eq!(result["coverageGaps"], json!([]));
    assert_eq!(result["receipts"].as_array().unwrap().len(), 17);
}

#[test]
fn assess_service_runtime_partial_when_worker_restart_not_restartable() {
    struct NotRestartable;
    #[async_trait::async_trait]
    impl legion_audit::native_providers::p10_runtime::browser_service::ServiceRuntimeAdapter for NotRestartable {
        async fn execute(&self, id: &str, _binding: &serde_json::Value) -> Option<serde_json::Value> {
            Some(json!({"status": "pass", "terminal": true, "restartable": id != "worker-restart"}))
        }
    }
    let target = ServiceRuntimeTarget::default();
    let result = tokio_test_block_on(assess_service_runtime(&target, &NotRestartable, &[]));
    assert_eq!(result["status"], "partial");
    let restart_receipt = result["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "worker-restart")
        .unwrap();
    assert_eq!(restart_receipt["status"], "partial");
    assert_eq!(restart_receipt["coverageGaps"], json!(["worker-restartability-unproven"]));
}

#[test]
fn assess_service_runtime_fails_when_a_scenario_fails() {
    let adapter = create_service_fixture_adapter("defect");
    let target = ServiceRuntimeTarget::default();
    let result = tokio_test_block_on(assess_service_runtime(&target, &adapter, &[]));
    assert_eq!(result["status"], "fail");
    assert_eq!(result["claims"]["runtime"], "failed");
}

#[test]
fn assess_service_runtime_missing_execution_is_unproven_and_partial() {
    struct NoOp;
    #[async_trait::async_trait]
    impl legion_audit::native_providers::p10_runtime::browser_service::ServiceRuntimeAdapter for NoOp {
        async fn execute(&self, _id: &str, _binding: &serde_json::Value) -> Option<serde_json::Value> {
            None
        }
    }
    let target = ServiceRuntimeTarget::default();
    let result = tokio_test_block_on(assess_service_runtime(&target, &NoOp, &[]));
    assert_eq!(result["status"], "partial");
    let first = &result["receipts"][0];
    assert_eq!(first["status"], "unproven");
    assert_eq!(first["coverageGaps"], json!(["runtime-execution-missing"]));
}

#[test]
fn assess_service_runtime_carries_production_control_gaps() {
    let adapter = create_service_fixture_adapter("clean");
    let target = ServiceRuntimeTarget::default();
    let controls = vec!["pci".to_string()];
    let result = tokio_test_block_on(assess_service_runtime(&target, &adapter, &controls));
    assert_eq!(result["status"], "partial");
    assert_eq!(result["coverageGaps"], json!(["production-external-evidence-missing:pci"]));
}

/* ----------------------------- service/faults index.mjs ------------------------ */

#[test]
fn fixture_adapter_maps_each_fixture_to_its_status() {
    for (fixture, expected) in [
        ("clean", "pass"),
        ("defect", "fail"),
        ("partial", "partial"),
        ("stale-environment", "unproven"),
        ("unsupported-runtime", "blocked"),
        ("anything-else", "blocked"),
    ] {
        let adapter = create_service_fixture_adapter(fixture);
        let result = tokio_test_block_on(async {
            use legion_audit::native_providers::p10_runtime::browser_service::ServiceRuntimeAdapter;
            adapter.execute("api-contract", &json!({})).await
        })
        .unwrap();
        assert_eq!(result["status"], expected, "fixture {fixture}");
    }
}

#[test]
fn fixture_adapter_rejects_unsupported_scenario_ids() {
    use legion_audit::native_providers::p10_runtime::browser_service::ServiceRuntimeAdapter;
    let adapter = create_service_fixture_adapter("clean");
    let result = tokio_test_block_on(adapter.execute("not-a-real-scenario", &json!({}))).unwrap();
    assert_eq!(result["status"], "error");
    assert_eq!(result["coverageGaps"], json!(["unsupported-runtime-scenario"]));
}

#[test]
fn fixture_adapter_marks_worker_restart_as_restartable() {
    use legion_audit::native_providers::p10_runtime::browser_service::ServiceRuntimeAdapter;
    let adapter = create_service_fixture_adapter("clean");
    let result = tokio_test_block_on(adapter.execute("worker-restart", &json!({}))).unwrap();
    assert_eq!(result["restartable"], true);
    let other = tokio_test_block_on(adapter.execute("api-contract", &json!({}))).unwrap();
    assert_eq!(other["restartable"], false);
}

#[test]
fn create_fault_adapter_is_an_alias_of_create_service_fixture_adapter() {
    use legion_audit::native_providers::p10_runtime::browser_service::ServiceRuntimeAdapter;
    let adapter = create_fault_adapter("defect");
    let result = tokio_test_block_on(adapter.execute("api-contract", &json!({}))).unwrap();
    assert_eq!(result["status"], "fail");
}

/// Minimal single-threaded block-on helper so these tests do not need a
/// `#[tokio::test]` runtime attribute per case.
fn tokio_test_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}
