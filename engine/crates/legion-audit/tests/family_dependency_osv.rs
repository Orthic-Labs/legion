// Behavioural parity tests for the `dependency.osv` provider against
// src/providers/dependency/index.mjs and src/providers/osv/index.mjs.
use legion_audit::native_providers::security::dependency_osv::{
    analyze, normalize_scan_result, normalize_vulnerability, osv_command,
};
use serde_json::json;

#[test]
fn osv_command_builds_offline_scan_args() {
    let cmd = osv_command(
        "/usr/local/bin/osv-scanner",
        "/tmp/out.json",
        "/repo",
        None,
        Some("/tmp/offline-db"),
    );
    assert_eq!(cmd["executable"], "/usr/local/bin/osv-scanner");
    assert_eq!(
        cmd["args"],
        json!(["scan", "--format", "json", "--output", "/tmp/out.json", "/repo"])
    );
    assert_eq!(cmd["cwd"], "/repo");
    assert_eq!(cmd["timeoutMs"], 120_000);
    assert_eq!(cmd["maxOutputBytes"], 8_388_608);
    assert_eq!(cmd["env"]["OSV_SCANNER_OFFLINE_DB"], "/tmp/offline-db");
}

#[test]
fn osv_command_honors_policy_overrides() {
    let policy = json!({"providerTimeoutMs": 5000, "maxOutputBytes": 1024});
    let cmd = osv_command("osv-scanner", "/tmp/out.json", "/repo", Some(&policy), None);
    assert_eq!(cmd["timeoutMs"], 5000);
    assert_eq!(cmd["maxOutputBytes"], 1024);
    assert_eq!(cmd["env"], json!({}));
}

#[test]
fn normalize_vulnerability_prefers_related_over_aliases_and_caps_refs() {
    let refs: Vec<String> = (0..15).map(|i| format!("CVE-{i}")).collect();
    let vuln = json!({
        "id": "GHSA-xxxx",
        "package": {"name": "left-pad", "ecosystem": "npm", "purl": "pkg:npm/left-pad@1.0.0"},
        "summary": "test",
        "severity": "HIGH",
        "related": refs,
        "aliases": ["should-not-appear"],
    });
    let normalized = normalize_vulnerability(&vuln, None, None);
    assert_eq!(normalized["provider"], "osv.scanner");
    assert_eq!(normalized["providerVersion"], "2.0.0");
    assert_eq!(normalized["id"], "GHSA-xxxx");
    assert_eq!(normalized["package"]["purl"], "pkg:npm/left-pad@1.0.0");
    assert_eq!(normalized["reachability"], "unknown");
    // capped at 10 references, and 'related' wins over 'aliases'
    let references = normalized["references"].as_array().unwrap();
    assert_eq!(references.len(), 10);
    assert_eq!(references[0], "CVE-0");
}

#[test]
fn normalize_vulnerability_falls_back_to_database_specific_severity() {
    let vuln = json!({
        "package": {},
        "database_specific": {"severity": "MODERATE"},
    });
    let normalized = normalize_vulnerability(&vuln, None, None);
    assert_eq!(normalized["severity"], "MODERATE");
    assert_eq!(normalized["id"], serde_json::Value::Null);
}

#[test]
fn normalize_scan_result_flattens_findings_and_maps_incomplete_reasons() {
    let raw = json!({
        "results": [
            {"packages": [
                {"package": {"purl": "pkg:npm/a@1.0.0"}, "vulnerabilities": [{"id": "V1", "package": {"name": "a"}}]},
                {"package": {"name": "b"}, "vulnerabilities": []},
            ]},
        ],
        "scan_complete": false,
        "scan_incomplete_reasons": ["timeout"],
    });
    let result = normalize_scan_result(&raw, None, None, Some("/tmp/db"), Some("sha256:abc"));
    assert_eq!(result["kind"], "legion-osv-result");
    assert_eq!(result["offline"], true);
    assert_eq!(result["databaseDigest"], "sha256:abc");
    assert_eq!(result["packageCount"], 2);
    assert_eq!(result["vulnerabilities"].as_array().unwrap().len(), 1);
    assert_eq!(result["complete"], false);
    assert_eq!(
        result["coverageGaps"],
        json!([{"kind": "osv-incomplete", "reason": "timeout"}])
    );
}

#[test]
fn normalize_scan_result_defaults_complete_true_when_absent() {
    let raw = json!({});
    let result = normalize_scan_result(&raw, None, None, None, None);
    assert_eq!(result["complete"], true);
    assert_eq!(result["offline"], false);
    assert_eq!(result["databaseDigest"], serde_json::Value::Null);
    assert_eq!(result["coverageGaps"], json!([]));
}

#[test]
fn analyze_still_reports_manifest_denominator_zero_when_no_lockfiles() {
    let input = json!({"projection": {"files": []}, "artifacts": {}});
    let result = analyze(&input);
    assert_eq!(result["status"], "unproven");
    assert_eq!(
        result["coverageGaps"],
        json!([{"kind": "dependency-manifest-denominator-zero"}])
    );
}
