//! Tests for the native Rust port of `src/providers/runtime/mobile/**/index.mjs`
//! in `legion_audit::native_providers::p10_runtime::mobile`.
//!
//! There were no existing `.test.mjs` files for these JS modules to port
//! 1:1, so these tests exercise each production entry point directly against
//! the behavior documented in the JS source (pass/partial/fail status,
//! coverage-gap enumeration, and the notable edge cases called out in code).

use legion_audit::native_providers::p10_runtime::mobile::{
    assess_mobile_performance, compile_mobile_compatibility, mobile_device_capability,
    mobile_device_execute, plan_mobile_data_network, plan_mobile_hosts, plan_mobile_lifecycle,
    plan_mobile_platform_surfaces, verify_mobile_commerce_operations, verify_mobile_release,
    MobileDeviceExecutionOutcome, StepOutcome,
};
use serde_json::json;

// ---------------------------------------------------------------------
// commerce
// ---------------------------------------------------------------------

#[test]
fn commerce_all_gaps_when_empty() {
    let result = verify_mobile_commerce_operations(&json!({}));
    assert_eq!(result["status"], "fail");
    assert_eq!(result["terminal"], true);
    let gaps = result["coverageGaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g == "entitlement-state-coverage-missing"));
    assert!(gaps.iter().any(|g| g == "push-account-binding-missing"));
    assert!(gaps.iter().any(|g| g == "analytics-consent-missing"));
    assert!(gaps.iter().any(|g| g == "operations-readiness-missing"));
}

#[test]
fn commerce_pass_when_fully_covered() {
    let input = json!({
        "entitlement": { "serverVerified": true, "testedStates": ["purchase","restore","refund","revocation","account-switch"] },
        "push": { "accountBound": true, "privacySafe": true, "testedStates": ["token-rotation","terminated","replayed","logout"] },
        "analytics": { "consentBound": true, "releaseSegmented": true, "schemaValidated": true },
        "operations": { "runbook": true, "alerting": true, "restoreEvidence": true, "owner": "team-x" },
    });
    let result = verify_mobile_commerce_operations(&input);
    assert_eq!(result["status"], "pass");
    assert_eq!(result["coverageGaps"].as_array().unwrap().len(), 0);
}

#[test]
fn commerce_provider_gap_is_partial_not_fail() {
    let input = json!({
        "entitlement": { "serverVerified": true, "testedStates": ["purchase","restore","refund","revocation","account-switch"] },
        "push": { "accountBound": true, "privacySafe": true, "testedStates": ["token-rotation","terminated","replayed","logout"] },
        "analytics": { "consentBound": true, "releaseSegmented": true, "schemaValidated": true },
        "operations": { "runbook": true, "alerting": true, "restoreEvidence": true, "owner": "team-x" },
        "provider": { "required": true, "sandboxReceipt": false, "id": "iap-vendor" },
    });
    let result = verify_mobile_commerce_operations(&input);
    assert_eq!(result["status"], "partial");
    assert!(result["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "provider-evidence-missing:iap-vendor"));
}

#[test]
fn commerce_client_decision_without_server_verification_gaps() {
    let input = json!({ "entitlement": { "clientDecision": true, "serverVerified": false } });
    let result = verify_mobile_commerce_operations(&input);
    assert!(result["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "entitlement-server-verification-missing"));
}

// ---------------------------------------------------------------------
// compatibility
// ---------------------------------------------------------------------

#[test]
fn compatibility_pass_with_no_journeys_or_supported() {
    let result = compile_mobile_compatibility(&json!({}));
    assert_eq!(result["status"], "pass");
    assert_eq!(result["denominator"]["total"], 0);
}

#[test]
fn compatibility_journey_with_no_evidence_is_partial() {
    let input = json!({ "criticalJourneys": ["checkout"], "executed": [] });
    let result = compile_mobile_compatibility(&input);
    assert_eq!(result["status"], "partial");
    // 12 accessibility modes x 2 platforms = 24 omitted cells for one journey
    assert_eq!(result["omitted"].as_array().unwrap().len(), 24);
    assert!(result["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "accessibility-journey-missing:checkout"));
}

#[test]
fn compatibility_journey_marked_pass_clears_gap_but_platform_split_stays() {
    let input = json!({
        "criticalJourneys": ["checkout"],
        "executed": [
            { "dimension": "accessibility", "value": "voiceover", "journeyId": "checkout", "platform": "ios", "status": "pass" }
        ],
    });
    let result = compile_mobile_compatibility(&input);
    // the accessibility-journey-missing gap only requires ONE passing accessibility record for the journey
    assert!(result["coverageGaps"].as_array().unwrap().is_empty());
    // still partial: 23 of 24 accessibility cells remain omitted
    assert_eq!(result["status"], "partial");
    assert_eq!(result["omitted"].as_array().unwrap().len(), 23);
}

// ---------------------------------------------------------------------
// devices
// ---------------------------------------------------------------------

#[test]
fn device_capability_rejects_missing_id_or_bad_tier() {
    assert!(mobile_device_capability(&json!({ "tier": "physical" })).is_err());
    assert!(mobile_device_capability(&json!({ "id": "dev-1", "tier": "bogus" })).is_err());
}

#[test]
fn device_capability_marks_simulator_and_emulator_simulated() {
    let cap = mobile_device_capability(&json!({ "id": "dev-1", "tier": "simulator" })).unwrap();
    assert_eq!(cap["simulated"], true);
    let cap2 = mobile_device_capability(&json!({ "id": "dev-2", "tier": "physical" })).unwrap();
    assert_eq!(cap2["simulated"], false);
}

#[test]
fn device_execute_blocked_when_physical_only_on_simulator() {
    let input = json!({
        "id": "dev-1", "tier": "simulator", "target": { "id": "t1" },
        "scenarioId": "scn-1", "physicalOnly": true,
    });
    let result = mobile_device_execute(&input, None);
    assert_eq!(result["status"], "blocked");
    assert_eq!(
        result["coverageGaps"][0],
        "physical-device-required:scn-1"
    );
}

#[test]
fn device_execute_pass_with_clean_cleanup() {
    let input = json!({ "id": "dev-1", "tier": "physical", "target": {}, "scenarioId": "scn-1" });
    let outcome = MobileDeviceExecutionOutcome {
        phase_error: None,
        evidence: Some(json!({ "ok": true })),
        reset: StepOutcome::Pass,
        uninstall: StepOutcome::Pass,
        release: StepOutcome::Pass,
    };
    let result = mobile_device_execute(&input, Some(&outcome));
    assert_eq!(result["status"], "pass");
    assert!(result["coverageGaps"].as_array().unwrap().is_empty());
}

#[test]
fn device_execute_fail_downgrades_status_and_records_error() {
    let input = json!({ "id": "dev-1", "tier": "physical", "target": {}, "scenarioId": "scn-1" });
    let outcome = MobileDeviceExecutionOutcome {
        phase_error: Some("install-failed".to_string()),
        evidence: None,
        reset: StepOutcome::Pass,
        uninstall: StepOutcome::Pass,
        release: StepOutcome::Pass,
    };
    let result = mobile_device_execute(&input, Some(&outcome));
    assert_eq!(result["status"], "fail");
    assert_eq!(result["error"], "install-failed");
    assert_eq!(result["coverageGaps"][0], "device-execution-fail:scn-1");
}

#[test]
fn device_execute_cleanup_error_downgrades_pass_to_partial() {
    let input = json!({ "id": "dev-1", "tier": "physical", "target": {}, "scenarioId": "scn-1" });
    let outcome = MobileDeviceExecutionOutcome {
        phase_error: None,
        evidence: None,
        reset: StepOutcome::Error,
        uninstall: StepOutcome::Pass,
        release: StepOutcome::Pass,
    };
    let result = mobile_device_execute(&input, Some(&outcome));
    assert_eq!(result["status"], "partial");
}

// ---------------------------------------------------------------------
// host
// ---------------------------------------------------------------------

#[test]
fn host_plan_marks_requirement_unavailable_without_matching_device() {
    let input = json!({
        "target": { "id": "app" },
        "devices": [],
        "requirements": [{ "id": "req-1", "tier": "physical" }],
    });
    let result = plan_mobile_hosts(&input);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["requirements"][0]["status"], "unavailable");
    assert_eq!(result["requirements"][0]["gap"], "physical-device-unavailable");
    assert_eq!(result["coverageGaps"][0], "req-1:physical-device-unavailable");
}

#[test]
fn host_plan_binds_available_device_and_lists_exclusive_keys() {
    let input = json!({
        "target": { "id": "app" },
        "devices": [{ "id": "dev-1", "tier": "physical", "status": "available", "exclusiveKey": "farm-a" }],
        "requirements": [{ "id": "req-1", "tier": "physical" }],
    });
    let result = plan_mobile_hosts(&input);
    assert_eq!(result["status"], "pass");
    assert_eq!(result["requirements"][0]["deviceId"], "dev-1");
    assert_eq!(result["exclusiveDeviceKeys"][0], "farm-a");
}

#[test]
fn host_plan_drops_devices_with_unknown_tier() {
    let input = json!({
        "devices": [{ "id": "dev-1", "tier": "quantum" }],
        "requirements": [],
    });
    let result = plan_mobile_hosts(&input);
    assert_eq!(result["devices"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------

#[test]
fn lifecycle_blocked_without_available_device() {
    let result = plan_mobile_lifecycle(&json!({ "deviceCapability": { "status": "unavailable" } }));
    assert_eq!(result["status"], "blocked");
    assert_eq!(result["scenarios"][0]["status"], "blocked");
    assert_eq!(result["coverageGaps"][0], "device-capability-unavailable");
    assert_eq!(result["scenarios"].as_array().unwrap().len(), 26);
}

#[test]
fn lifecycle_unproven_with_available_device() {
    let result = plan_mobile_lifecycle(&json!({ "deviceCapability": { "status": "available" } }));
    assert_eq!(result["status"], "unproven");
    assert_eq!(result["coverageGaps"][0], "device-execution-not-run");
}

// ---------------------------------------------------------------------
// network
// ---------------------------------------------------------------------

#[test]
fn network_plan_enumerates_fixed_and_migration_scenarios() {
    let result = plan_mobile_data_network(&json!({ "actorId": "actor-1", "supportedSchemaVersions": [3, 4] }));
    assert_eq!(result["status"], "unproven");
    let scenarios = result["scenarios"].as_array().unwrap();
    // 15 network + 1 sync + 10 storage + 2 migration + 1 pressure + 1 cache = 30
    assert_eq!(scenarios.len(), 30);
    assert!(scenarios.iter().any(|s| s["id"] == "migration:3-to-current"));
    assert!(scenarios.iter().any(|s| s["id"] == "migration:4-to-current"));
    assert_eq!(result["denominator"]["total"], 30);
    assert_eq!(result["coverageGaps"].as_array().unwrap().len(), 30);
}

// ---------------------------------------------------------------------
// performance
// ---------------------------------------------------------------------

#[test]
fn performance_reports_all_gaps_when_no_measurements() {
    let result = assess_mobile_performance(&json!({}));
    assert_eq!(result["status"], "partial");
    let gaps = result["coverageGaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g == "physical-device-measurement-missing"));
    assert!(gaps.iter().any(|g| g == "artifact-identity-missing"));
    assert!(gaps.iter().any(|g| g == "metric-missing:cold-start"));
}

#[test]
fn performance_computes_percentiles_for_present_metric() {
    let input = json!({
        "artifactDigest": "sha256:abc",
        "measurements": [
            { "metric": "cold-start", "value": 100, "tier": "physical", "buildType": "release" },
            { "metric": "cold-start", "value": 200, "tier": "physical", "buildType": "release" },
            { "metric": "battery", "value": 5, "tier": "physical", "buildType": "release" },
            { "metric": "thermal", "value": 1, "tier": "physical", "buildType": "release" },
        ],
        "profiles": ["main-thread", "idle-background", "long-session", "low-resource"],
        "artifactInspection": {
            "architecture-slices": true, "resources-libraries": true,
            "symbols-media-locales": true, "delivery-update-size": true,
        },
    });
    let result = assess_mobile_performance(&input);
    assert_eq!(result["metrics"]["cold-start"]["repeats"], 2);
    assert_eq!(result["metrics"]["cold-start"]["p50"], 100.0);
    assert_eq!(result["claims"]["battery"], "measured");
    assert_eq!(result["claims"]["thermal"], "measured");
    assert_eq!(result["claims"]["releaseArtifact"], "measured");
    // still partial: most REQUIRED_METRICS are absent
    assert_eq!(result["status"], "partial");
}

// ---------------------------------------------------------------------
// platform-surfaces
// ---------------------------------------------------------------------

#[test]
fn platform_surfaces_enumerates_states_per_input() {
    let input = json!({
        "permissions": ["camera"],
        "links": ["deep-link"],
        "channels": ["widget"],
        "extensions": ["share-ext"],
    });
    let result = plan_mobile_platform_surfaces(&input);
    let scenarios = result["scenarios"].as_array().unwrap();
    // 9 permission states + 8 link states + 5 channel states + 7 webview + 6 ipc + 1 extension = 36
    assert_eq!(scenarios.len(), 36);
    assert!(scenarios
        .iter()
        .any(|s| s["id"] == "permission:camera:denied" && s["expected"] == "graceful-degradation"));
    assert_eq!(result["status"], "unproven");
}

// ---------------------------------------------------------------------
// release
// ---------------------------------------------------------------------

#[test]
fn release_privacy_declaration_mismatch_is_blocking_fail() {
    let input = json!({
        "runtimeDataTypes": ["location"],
        "declaredDataTypes": [],
    });
    let result = verify_mobile_release(&input);
    assert_eq!(result["status"], "fail");
    assert_eq!(result["releaseBlocked"], true);
    assert!(result["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "privacy-declaration-mismatch:location"));
}

#[test]
fn release_promotion_artifact_mismatch_is_blocking_fail() {
    let input = json!({
        "promotion": { "testedDigest": "sha:a", "promotedDigest": "sha:b" },
    });
    let result = verify_mobile_release(&input);
    assert_eq!(result["status"], "fail");
    assert!(result["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "promotion-artifact-mismatch"));
}

#[test]
fn release_non_blocking_gaps_yield_partial() {
    let input = json!({ "symbols": [] });
    let result = verify_mobile_release(&input);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["releaseBlocked"], false);
    assert!(result["coverageGaps"].as_array().unwrap().iter().any(|g| g == "symbols-missing"));
}

#[test]
fn release_pass_when_fully_declared() {
    let input = json!({
        "targetId": "app", "version": "1.0.0",
        "artifact": { "path": "/build/app.ipa", "digest": "sha256:zzz" },
        "runtimeDataTypes": ["location"], "declaredDataTypes": ["location"],
        "symbols": [{ "symbolicated": true }],
        "build": { "release": true, "toolchain": "xcode-16", "lockfileDigest": "sha:lock", "packageId": "com.app", "signingIdentity": "id-1" },
        "store": {
            "track": "production", "listing": "listing-1", "privacyUrl": "https://a", "supportUrl": "https://b",
            "declarations": ["ads"], "regionalVariants": ["us"],
        },
        "promotion": { "rolloutCriteria": "x", "rollbackCriteria": "y", "monitoring": "z" },
        "privacy": { "manifest": true, "requiredReasonApis": true },
    });
    let result = verify_mobile_release(&input);
    assert_eq!(result["status"], "pass");
    assert_eq!(result["releaseBlocked"], false);
    assert!(result["coverageGaps"].as_array().unwrap().is_empty());
}
