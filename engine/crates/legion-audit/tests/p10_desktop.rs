//! Tests for the native port of the legacy desktop-runtime JS provider spec
//! in `legion_audit::native_providers::p10_runtime::desktop`.
//!
//! These assert against the production entry points (`evaluate_*` /
//! `compile_*`), matching the JS source's own gap ids, denominators, and
//! status derivation.

use legion_audit::native_providers::p10_runtime::desktop::*;
use serde_json::json;

fn terminal_pass(id: &str) -> serde_json::Value {
    json!({ "id": id, "status": "pass", "terminal": true })
}

// ---------------------------------------------------------------------
// files/index.mjs
// ---------------------------------------------------------------------

#[test]
fn desktop_storage_reports_missing_cases_and_migration_denominator() {
    let out = evaluate_desktop_storage(&json!({}));
    assert_eq!(out["status"], "unproven");
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"migration-denominator-empty"));
    assert!(gaps.contains(&"native-storage-receipt-missing"));
    assert!(gaps.contains(&"storage-locations-incomplete"));
    assert!(gaps.iter().any(|g| g.starts_with("file-case-missing:")));
}

#[test]
fn desktop_storage_passes_with_full_evidence() {
    let cases: Vec<_> = FILE_CASES.iter().map(|id| terminal_pass(id)).collect();
    let migration = json!({ "id": "m1", "status": "pass", "terminal": true, "sourcePreserved": true });
    let input = json!({
        "cases": cases,
        "migrations": [migration],
        "locations": { "data": "d", "cache": "c", "logs": "l", "temp": "t" },
        "evidence": { "source": "native-host", "terminal": true },
    });
    let out = evaluate_desktop_storage(&input);
    assert_eq!(out["status"], "pass");
    assert_eq!(out["coverageGaps"].as_array().unwrap().len(), 0);
    assert_eq!(out["denominator"]["total"], FILE_CASES.len() + 1);
}

#[test]
fn desktop_storage_fails_when_migration_source_not_preserved() {
    let cases: Vec<_> = FILE_CASES.iter().map(|id| terminal_pass(id)).collect();
    let migration = json!({ "id": "m1", "status": "fail", "terminal": true, "sourcePreserved": false });
    let input = json!({
        "cases": cases,
        "migrations": [migration],
        "locations": { "data": "d", "cache": "c", "logs": "l", "temp": "t" },
        "evidence": { "source": "native-host", "terminal": true },
    });
    let out = evaluate_desktop_storage(&input);
    assert_eq!(out["status"], "fail");
}

#[test]
fn desktop_storage_flags_duplicate_locations() {
    let input = json!({ "locations": { "data": "same", "cache": "same", "logs": "l", "temp": "t" } });
    let out = evaluate_desktop_storage(&input);
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"storage-locations-not-separated"));
}

// ---------------------------------------------------------------------
// desktop/index.mjs
// ---------------------------------------------------------------------

#[test]
fn integrate_desktop_evidence_stop_ships_on_nonterminal_receipt() {
    let input = json!({
        "targetId": "t1",
        "controls": [],
        "scenarios": [],
        "receipts": [{ "targetId": "t1", "controlId": "c1", "terminal": false }],
        "platformMatrices": [],
    });
    let out = integrate_desktop_evidence(&input);
    assert_eq!(out["status"], "fail");
    assert_eq!(out["stopShip"], true);
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.iter().any(|g| g.starts_with("receipt-nonterminal:")));
}

#[test]
fn integrate_desktop_evidence_passes_with_closed_controls_and_families() {
    let mut receipts = vec![json!({
        "targetId": "t1", "controlId": "c1", "scenarioId": "s1", "terminal": true, "status": "pass",
        "kind": "legion-desktop-runtime",
    })];
    for (kind, extra) in [
        ("legion-desktop-ipc", json!({})),
        ("legion-desktop-files-storage", json!({})),
        ("legion-desktop-os-matrix", json!({})),
        ("legion-desktop-performance", json!({})),
        ("legion-desktop-installer-lifecycle", json!({})),
        ("legion-desktop-updater", json!({})),
        ("legion-desktop-windows", json!({})),
    ] {
        let mut r = json!({ "targetId": "t1", "terminal": true, "status": "pass", "kind": kind });
        r.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        receipts.push(r);
    }
    let input = json!({
        "targetId": "t1",
        "controls": ["c1"],
        "scenarios": ["s1"],
        "receipts": receipts,
        "platformMatrices": [{ "os": "linux", "status": "pass" }],
    });
    let out = integrate_desktop_evidence(&input);
    assert_eq!(out["status"], "pass");
    assert_eq!(out["coverageGaps"].as_array().unwrap().len(), 0);
}

#[test]
fn integrate_desktop_evidence_drops_source_regex_only_release_claims() {
    let input = json!({
        "targetId": "t1",
        "controls": ["release-signing"],
        "scenarios": [],
        "receipts": [{
            "targetId": "t1", "controlId": "release-signing", "terminal": true,
            "claimLevel": "source",
        }],
        "platformMatrices": [],
    });
    let out = integrate_desktop_evidence(&input);
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"native-release-evidence-missing:release-signing"));
    assert!(gaps.contains(&"control-missing:release-signing"));
}

// ---------------------------------------------------------------------
// installer/index.mjs
// ---------------------------------------------------------------------

#[test]
fn installer_lifecycle_rejects_destructive_target_outside_temp() {
    let input = json!({ "destructiveTarget": "/Users/me/project" });
    let err = evaluate_installer_lifecycle(&input).unwrap_err();
    assert!(err.contains("isolated temp target"));
}

#[test]
fn installer_lifecycle_allows_destructive_target_inside_temp() {
    let input = json!({ "destructiveTarget": "C:\\Temp\\legion-installer" });
    assert!(evaluate_installer_lifecycle(&input).is_ok());
}

#[test]
fn installer_lifecycle_unsafe_rollback_forces_fail() {
    let mut scenarios: Vec<_> = INSTALLER_CASES.iter().map(|id| terminal_pass(id)).collect();
    let idx = INSTALLER_CASES.iter().position(|id| *id == "rollback").unwrap();
    scenarios[idx] = json!({ "id": "rollback", "status": "pass", "terminal": true, "newerDataPreserved": false });
    let input = json!({
        "package": { "digest": format!("sha256:{}", "a".repeat(64)), "production": true, "signatureReceipt": { "status": "pass", "artifactDigest": format!("sha256:{}", "a".repeat(64)) } },
        "capability": { "status": "available" },
        "scenarios": scenarios,
    });
    let out = evaluate_installer_lifecycle(&input).unwrap();
    assert_eq!(out["status"], "fail");
}

#[test]
fn installer_lifecycle_passes_when_fully_evidenced() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let scenarios: Vec<_> = INSTALLER_CASES
        .iter()
        .map(|id| {
            let mut s = json!({ "id": id, "status": if ["interrupted-install", "offline-uninstall", "locked-files"].contains(id) { "fail" } else { "pass" }, "terminal": true });
            if *id == "rollback" {
                s["newerDataPreserved"] = json!(true);
            }
            if *id == "modes" {
                s["modes"] = json!(["silent"]);
            }
            if *id == "snapshots" {
                s["snapshotCount"] = json!(1);
            }
            if *id == "logs" {
                s["logFile"] = json!("install.log");
            }
            if *id == "changes" {
                s["changes"] = json!(["installed file"]);
            }
            s
        })
        .collect();
    let input = json!({
        "package": { "digest": digest, "production": true, "signatureReceipt": { "status": "pass", "artifactDigest": digest } },
        "capability": { "status": "available" },
        "scenarios": scenarios,
    });
    let out = evaluate_installer_lifecycle(&input).unwrap();
    assert_eq!(out["status"], "pass", "gaps: {:?}", out["coverageGaps"]);
}

// ---------------------------------------------------------------------
// ipc/index.mjs
// ---------------------------------------------------------------------

#[test]
fn desktop_ipc_blocks_unknown_command_and_denied_caller() {
    let input = json!({
        "commands": [{ "id": "cmd", "actors": ["renderer"], "capabilities": [], "schema": {}, "arguments": {}, "privilege": "user", "identity": "cmd" }],
        "attempts": [
            { "id": "allowed", "command": "missing-command", "actor": "renderer" },
            { "id": "denied", "command": "cmd", "actor": "other" },
        ],
    });
    let out = evaluate_desktop_ipc(&input);
    let receipts = out["receipts"].as_array().unwrap();
    assert_eq!(receipts[0]["reason"], "unknown-command");
    assert_eq!(receipts[1]["reason"], "caller-denied");
}

#[test]
fn desktop_ipc_flags_bypassed_denial() {
    let input = json!({
        "commands": [{ "id": "denied", "actors": ["renderer"], "capabilities": [], "schema": {}, "arguments": {}, "privilege": "user", "identity": "denied" }],
        "attempts": [{ "id": "denied", "command": "denied", "actor": "renderer", "observedDenied": false }],
    });
    let out = evaluate_desktop_ipc(&input);
    assert_eq!(out["receipts"][0]["reason"], "denial-bypassed");
}

// ---------------------------------------------------------------------
// linux/index.mjs & macos/index.mjs
// ---------------------------------------------------------------------

#[test]
fn linux_platform_requires_matrix_binding() {
    let out = evaluate_linux_platform(&json!({ "capability": { "status": "available" } }));
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"linux-matrix-incomplete"));
    assert!(gaps.iter().any(|g| g.starts_with("linux-case-missing:")));
}

#[test]
fn macos_platform_requires_final_artifact_for_notarization() {
    let checks: Vec<_> = MACOS_CASES.iter().map(|id| terminal_pass(id)).collect();
    let input = json!({
        "matrix": { "version": "14", "architecture": "arm64" },
        "capability": { "status": "available" },
        "checks": checks,
        "artifact": { "final": false },
    });
    let out = evaluate_macos_platform(&input);
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"macos-final-artifact-unproven:notarization"));
    assert!(gaps.contains(&"macos-final-artifact-unproven:gatekeeper"));
}

// ---------------------------------------------------------------------
// os-integration/index.mjs
// ---------------------------------------------------------------------

#[test]
fn compile_os_matrix_synthesizes_missing_cases() {
    let out = compile_desktop_os_matrix(&json!({}));
    assert_eq!(out["status"], "unproven");
    assert_eq!(out["denominator"]["synthesized"], DESKTOP_OS_CASES.len());
}

#[test]
fn compile_os_matrix_flags_caller_defined_extra_case() {
    let input = json!({ "required": ["single-instance"], "cases": [{ "id": "not-required" }] });
    let out = compile_desktop_os_matrix(&input);
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"caller-defined-matrix-case:not-required"));
}

#[test]
fn compile_os_matrix_passes_with_full_binding() {
    let case = json!({
        "id": "single-instance", "status": "pass", "terminal": true, "os": "linux", "version": "1", "architecture": "x64",
        "state": {}, "controlIds": ["c1"],
    });
    let input = json!({ "required": ["single-instance"], "cases": [case] });
    let out = compile_desktop_os_matrix(&input);
    assert_eq!(out["status"], "pass");
}

#[test]
fn compile_os_matrix_requires_host_unavailable_detail_for_unsupported() {
    let case = json!({
        "id": "screen-reader", "status": "unsupported", "terminal": true, "os": "linux", "version": "1", "architecture": "x64",
        "state": {}, "controlIds": ["c1"], "reason": "no reader installed",
        "hostUnavailable": { "type": "device-not-present" },
    });
    let input = json!({ "required": ["screen-reader"], "cases": [case] });
    let out = compile_desktop_os_matrix(&input);
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"host-unavailable-detail-missing:screen-reader"));
}

// ---------------------------------------------------------------------
// performance/index.mjs
// ---------------------------------------------------------------------

fn full_measurement(id: &str) -> serde_json::Value {
    json!({
        "id": id, "unit": "ms", "samples": [1.0, 2.0, 3.0], "percentiles": { "p95": 3.0 },
        "budget": 100.0, "profileArtifact": "trace.json", "variance": 0.1, "durationSeconds": 5.0,
    })
}

#[test]
fn desktop_performance_passes_with_full_evidence() {
    let measurements: Vec<_> = PERFORMANCE_CASES.iter().map(|id| full_measurement(id)).collect();
    let input = json!({
        "artifact": { "build": "release", "digest": format!("sha256:{}", "b".repeat(64)) },
        "environment": {
            "os": "linux", "hardware": "x64", "hardwareClass": "desktop", "cpuCores": 8, "ramMb": 16000,
            "diskType": "ssd", "profilingTool": "perf", "energyBudgetMw": 500,
        },
        "measurements": measurements,
        "soak": { "status": "pass", "hours": 10 },
    });
    let out = evaluate_desktop_performance(&input);
    assert_eq!(out["status"], "pass", "gaps: {:?}", out["coverageGaps"]);
}

#[test]
fn desktop_performance_soak_only_gaps_are_partial() {
    let measurements: Vec<_> = PERFORMANCE_CASES.iter().map(|id| full_measurement(id)).collect();
    let input = json!({
        "artifact": { "build": "release", "digest": format!("sha256:{}", "b".repeat(64)) },
        "environment": {
            "os": "linux", "hardware": "x64", "hardwareClass": "desktop", "cpuCores": 8, "ramMb": 16000,
            "diskType": "ssd", "profilingTool": "perf", "energyBudgetMw": 500,
        },
        "measurements": measurements,
        "soak": { "status": "pass", "hours": 1 },
    });
    let out = evaluate_desktop_performance(&input);
    assert_eq!(out["status"], "partial");
}

#[test]
fn desktop_performance_missing_environment_is_unproven() {
    let out = evaluate_desktop_performance(&json!({}));
    assert_eq!(out["status"], "unproven");
}

// ---------------------------------------------------------------------
// runner/index.mjs
// ---------------------------------------------------------------------

#[test]
fn collect_desktop_runtime_flags_unsupported_framework_and_missing_binding() {
    let out = collect_desktop_runtime(&json!({ "target": { "framework": "unknown" } }));
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"target-id-missing"));
    assert!(gaps.contains(&"framework-unsupported"));
    assert!(gaps.contains(&"artifact-binding-incomplete"));
}

#[test]
fn collect_desktop_runtime_passes_with_full_observation() {
    let digest = format!("sha256:{}", "c".repeat(64));
    let input = json!({
        "target": { "id": "t1", "framework": "tauri" },
        "artifact": { "path": "/bin/app", "digest": digest },
        "capability": { "status": "available", "receipt": { "cleanEnvironment": true, "nativeSurface": true } },
        "observations": {
            "source": "native-host", "receipt": { "terminal": true },
            "executable": { "path": "/bin/app", "digest": digest },
            "processes": [{ "pid": 1 }], "windows": [{ "id": "w1" }],
            "shutdown": { "clean": true }, "environment": { "isolated": true },
        },
    });
    let out = collect_desktop_runtime(&input);
    assert_eq!(out["status"], "pass", "gaps: {:?}", out["coverageGaps"]);
}

#[test]
fn collect_desktop_runtime_flags_executable_binding_mismatch() {
    let input = json!({
        "target": { "id": "t1", "framework": "electron" },
        "artifact": { "path": "/bin/app", "digest": format!("sha256:{}", "c".repeat(64)) },
        "capability": { "status": "available", "receipt": { "cleanEnvironment": true, "nativeSurface": true } },
        "observations": {
            "source": "native-host", "receipt": { "terminal": true },
            "executable": { "path": "/bin/other", "digest": format!("sha256:{}", "d".repeat(64)) },
            "processes": [{ "pid": 1 }], "windows": [{ "id": "w1" }],
            "shutdown": { "clean": true }, "environment": { "isolated": true },
        },
    });
    let out = collect_desktop_runtime(&input);
    assert_eq!(out["status"], "unproven");
}

// ---------------------------------------------------------------------
// updater/index.mjs
// ---------------------------------------------------------------------

#[test]
fn updater_evidence_flags_forged_caller_boolean() {
    let input = json!({ "artifact": { "forgedCaller": true } });
    let out = evaluate_updater_evidence(&input);
    assert_eq!(out["status"], "fail");
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"forged-caller-boolean:forgedCaller"));
}

#[test]
fn updater_evidence_flags_bypassed_verification() {
    let mut attempts: Vec<_> = UPDATE_CASES.iter().map(|id| terminal_pass(id)).collect();
    let idx = UPDATE_CASES.iter().position(|id| *id == "forged-payload").unwrap();
    attempts[idx] = json!({ "id": "forged-payload", "status": "fail", "terminal": true, "verificationPassed": false, "executed": true });
    let input = json!({ "attempts": attempts });
    let out = evaluate_updater_evidence(&input);
    assert_eq!(out["status"], "fail");
    assert_eq!(out["stopShip"], true);
}

#[test]
fn updater_evidence_flags_sensitive_log_line() {
    let digest = format!("sha256:{}", "e".repeat(64));
    let verification: serde_json::Value = json!({
        "application": { "status": "pass", "artifactDigest": digest },
        "metadata": { "status": "pass", "artifactDigest": digest },
        "payload": { "status": "pass", "artifactDigest": digest },
        "timestamp": { "status": "pass", "artifactDigest": digest },
    });
    let attempts: Vec<_> = UPDATE_CASES.iter().map(|id| terminal_pass(id)).collect();
    let input = json!({
        "artifact": { "digest": digest, "publisher": "Acme" },
        "verification": verification,
        "attempts": attempts,
        "promotion": {
            "qaDigest": digest, "updateDigest": digest, "distributedDigest": digest,
            "privilegedService": { "revalidated": true }, "channel": "stable", "rollout": "staged",
            "mandatory": true,
            "logs": ["update request Authorization: Bearer sekret123"],
        },
    });
    let out = evaluate_updater_evidence(&input);
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"updater-log-sensitive"));
}

#[test]
fn updater_evidence_passes_when_fully_verified() {
    let digest = format!("sha256:{}", "f".repeat(64));
    let verification: serde_json::Value = json!({
        "application": { "status": "pass", "artifactDigest": digest },
        "metadata": { "status": "pass", "artifactDigest": digest },
        "payload": { "status": "pass", "artifactDigest": digest },
        "timestamp": { "status": "pass", "artifactDigest": digest },
    });
    let attempts: Vec<_> = UPDATE_CASES.iter().map(|id| terminal_pass(id)).collect();
    let input = json!({
        "artifact": { "digest": digest, "publisher": "Acme" },
        "verification": verification,
        "attempts": attempts,
        "promotion": {
            "qaDigest": digest, "updateDigest": digest, "distributedDigest": digest,
            "privilegedService": { "revalidated": true }, "channel": "stable", "rollout": "staged",
            "mandatory": true, "logs": [],
        },
    });
    let out = evaluate_updater_evidence(&input);
    assert_eq!(out["status"], "pass", "gaps: {:?}", out["coverageGaps"]);
}

// ---------------------------------------------------------------------
// windows/index.mjs
// ---------------------------------------------------------------------

#[test]
fn windows_platform_requires_final_artifact_for_authenticode() {
    let checks: Vec<_> = WINDOWS_CASES.iter().map(|id| terminal_pass(id)).collect();
    let input = json!({
        "matrix": { "version": "11", "architecture": "x64" },
        "checks": checks,
        "artifact": { "final": false },
    });
    let out = evaluate_windows_platform(&input);
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.contains(&"windows-final-artifact-unproven:authenticode"));
    assert!(gaps.contains(&"windows-final-artifact-unproven:installer"));
}

#[test]
fn windows_platform_default_capability_is_available() {
    let out = evaluate_windows_platform(&json!({ "matrix": { "version": "11", "architecture": "x64" } }));
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(!gaps.iter().any(|g| g.starts_with("windows-capability-")));
}

// ---------------------------------------------------------------------
// worker/index.mjs
// ---------------------------------------------------------------------

#[test]
fn service_runtime_scenarios_constant_matches_spec() {
    assert_eq!(SERVICE_RUNTIME_SCENARIOS.len(), 17);
    assert!(SERVICE_RUNTIME_SCENARIOS.contains(&"api-contract"));
    assert!(SERVICE_RUNTIME_SCENARIOS.contains(&"observability"));
}

// ---------------------------------------------------------------------
// execute_* host wiring (no host / mock host)
// ---------------------------------------------------------------------

#[test]
fn execute_desktop_storage_without_host_falls_back_to_unproven_evaluate() {
    let out = execute_desktop_storage(None, &[]);
    assert_eq!(out["status"], "unproven");
}

#[test]
fn execute_desktop_runtime_without_host_reports_unavailable_capability() {
    let out = execute_desktop_runtime(None, &json!({ "id": "t1", "framework": "tauri" }), &json!({}), &json!({}), false);
    assert_eq!(out["binding"]["targetId"], "t1");
    let gaps: Vec<&str> = out["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(gaps.iter().any(|g| g.starts_with("native-capability-")));
}
