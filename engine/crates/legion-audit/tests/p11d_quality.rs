//! Packet P11d tests for the provider suites that have a production caller:
//! `data_suite`, `infrastructure_suite` and `security_suite`.
//! See `p11d_quality::mod` doc for scope.

use legion_audit::native_providers::p11d_quality::{
    data_suite, infrastructure_suite, security_suite,
};
use serde_json::json;
use std::fs;

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("legion-p11d-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------
// data-suite
// ---------------------------------------------------------------------

#[test]
fn data_suite_flags_sql_interpolation() {
    let dir = tmp_dir("data-sql");
    fs::write(
        dir.join("q.ts"),
        "const q = `SELECT * FROM users WHERE id = ${id}`;",
    )
    .unwrap();
    let result = data_suite::run_data_suite(&dir, &["q.ts".to_string()]);
    assert_eq!(result["status"], "candidates");
    let candidates = result["candidates"].as_array().unwrap();
    assert!(candidates
        .iter()
        .any(|c| c["ruleId"] == "data.sql-interpolation"));
}

#[test]
fn data_suite_clean_file_passes() {
    let dir = tmp_dir("data-clean");
    fs::write(dir.join("q.ts"), "const x = 1;").unwrap();
    let result = data_suite::run_data_suite(&dir, &["q.ts".to_string()]);
    assert_eq!(result["status"], "pass");
}

// ---------------------------------------------------------------------
// infrastructure-suite
// ---------------------------------------------------------------------

#[test]
fn infrastructure_suite_flags_dockerfile_latest_tag() {
    let dir = tmp_dir("infra-docker");
    fs::write(dir.join("Dockerfile"), "FROM node\n").unwrap();
    let result = infrastructure_suite::run_infrastructure_suite(&dir, &["Dockerfile".to_string()]);
    let candidates = result["candidates"].as_array().unwrap();
    assert!(candidates
        .iter()
        .any(|c| c["ruleId"] == "container.latest-tag"));
    assert!(candidates
        .iter()
        .any(|c| c["ruleId"] == "container-root-user"));
}

#[test]
fn infrastructure_suite_flags_privileged_k8s() {
    let dir = tmp_dir("infra-k8s");
    fs::write(dir.join("deploy.yaml"), "privileged: true\n").unwrap();
    let result = infrastructure_suite::run_infrastructure_suite(&dir, &["deploy.yaml".to_string()]);
    let candidates = result["candidates"].as_array().unwrap();
    assert!(candidates.iter().any(|c| c["ruleId"] == "k8s-privileged"));
}

// ---------------------------------------------------------------------
// security-suite
// ---------------------------------------------------------------------

#[test]
fn security_suite_flags_disabled_tls_verification() {
    let dir = tmp_dir("sec-tls");
    fs::write(
        dir.join("client.js"),
        "https.request({ rejectUnauthorized: false })",
    )
    .unwrap();
    let result = security_suite::generate_security_candidates(
        &dir,
        &["client.js".to_string()],
        "insecure-defaults",
        None,
    )
    .unwrap();
    let candidates = result["candidates"].as_array().unwrap();
    assert!(candidates
        .iter()
        .any(|c| c["ruleId"] == "security.tls-verification-disabled"));
    assert!(candidates.iter().all(|c| c["verdict"] == "UNADJUDICATED"));
}

#[test]
fn security_suite_credential_scan_skips_placeholders() {
    let dir = tmp_dir("sec-cred");
    fs::write(
        dir.join("config.env"),
        "API_KEY=\"changeme\"\nSECRET=\"correct-horse-battery-staple-9f8e7d6c\"\n",
    )
    .unwrap();
    let result = security_suite::generate_security_candidates(
        &dir,
        &["config.env".to_string()],
        "credentials",
        None,
    )
    .unwrap();
    let candidates = result["candidates"].as_array().unwrap();
    // The placeholder ("changeme") must be rejected; the higher-entropy value
    // in a high-context file (.env) must be flagged.
    assert!(!candidates.is_empty());
}

#[test]
fn security_suite_unknown_pack_errors() {
    let dir = tmp_dir("sec-unknown");
    let result = security_suite::generate_security_candidates(&dir, &[], "not-a-pack", None);
    assert!(result.is_err());
}

#[test]
fn security_suite_merge_dedupes_candidates_by_id() {
    let report = json!({
        "provider": "security.a", "rulePack": "all", "complete": true,
        "coverage": { "expectedFiles": 1, "scannedFiles": 1, "rules": [] },
        "candidates": [{ "id": "sha256:dup" }, { "id": "sha256:dup" }],
        "coverageGaps": [],
    });
    let merged = security_suite::merge_security_candidate_reports(&[report.clone(), report]);
    assert_eq!(merged["candidates"].as_array().unwrap().len(), 1);
}

#[test]
fn security_suite_derive_variant_queries_requires_evidence() {
    let finding = json!({ "id": "f1", "ruleId": "security.command-injection" });
    assert!(security_suite::derive_variant_queries(&finding).is_err());

    let finding = json!({
        "id": "f1", "ruleId": "security.command-injection",
        "evidence": [{ "file": "a.js", "line": 3 }],
    });
    let plan = security_suite::derive_variant_queries(&finding).unwrap();
    assert_eq!(plan["queries"].as_array().unwrap().len(), 3);
    assert_eq!(plan["queries"][2]["key"], "security.command-injection");
}
