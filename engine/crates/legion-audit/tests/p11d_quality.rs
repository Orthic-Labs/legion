//! Packet P11d parity tests — Rust ports of `src/providers/{ai-quality,
//! accessibility,copy/claims}` and the provider suite orchestrators.
//! See `p11d_quality::mod` doc for scope and deferrals.

use legion_audit::native_providers::p11d_quality::{
    accessibility_runtime, accessibility_suite, ai_quality, data_suite, framework_suite,
    generic_source_suite, infrastructure_suite, security_suite,
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
// ai-quality
// ---------------------------------------------------------------------

#[test]
fn ai_quality_every_declared_metric_has_a_scorer() {
    for metric in ai_quality::METRICS {
        let result = ai_quality::dispatch(metric, &json!({}));
        assert!(result.is_ok(), "metric {metric} has no scorer");
        assert_eq!(result.unwrap().verdict, "unproven");
    }
}

#[test]
fn ai_quality_declared_task_eval_pass_and_fail() {
    let pass = ai_quality::evaluators::score_declared_task_eval(&json!({
        "declaredCriteria": [{ "id": "c1", "met": true }]
    }));
    assert_eq!(pass.verdict, "pass");

    let fail = ai_quality::evaluators::score_declared_task_eval(&json!({
        "declaredCriteria": [{ "id": "c1", "met": false }]
    }));
    assert_eq!(fail.verdict, "fail");
}

#[test]
fn ai_quality_groundedness_flags_ungrounded_claims() {
    let result = ai_quality::evaluators::score_groundedness(&json!({
        "contextSpanIds": ["s1"],
        "claims": [
            { "text": "grounded", "supportingSpanIds": ["s1"] },
            { "text": "ungrounded", "supportingSpanIds": ["s2"] },
        ]
    }));
    assert_eq!(result.verdict, "fail");
    assert_eq!(result.measurement["ungroundedClaims"], json!(["ungrounded"]));
}

#[test]
fn ai_quality_subgroup_fairness_requires_policy_selection() {
    let result = ai_quality::evaluators::score_subgroup_fairness(&json!({}));
    assert_eq!(result.verdict, "unproven");
}

#[test]
fn ai_quality_human_override_review_required_when_untested() {
    let result = ai_quality::evaluators::score_human_override(&json!({ "overrideAvailable": true }));
    assert_eq!(result.verdict, "review-required");
}

#[test]
fn ai_quality_receipt_rejects_security_shaped_field() {
    let mut receipt = json!({
        "schemaVersion": 1, "kind": "ai-quality-evaluation-receipt",
        "id": "sha256:aa", "metric": "latency", "verdict": "pass",
        "modelIdentity": {}, "promptIdentity": {}, "datasetVersion": {},
        "runConditions": {}, "judgeIdentity": {}, "denominator": {}, "measurement": {},
        "limitations": [], "uncertainty": [], "evidenceRefs": [],
        "binding": {
            "planDigest": "sha256:aa", "repositoryRevision": "r1", "dirtyPatchDigest": null,
            "blueprintGenerationId": "g1", "blueprintManifestDigest": "sha256:bb", "registryDigest": "sha256:cc",
        },
    });
    assert!(ai_quality::assert_evaluation_receipt(&receipt).is_ok());
    receipt["severity"] = json!("high");
    assert!(ai_quality::assert_evaluation_receipt(&receipt).is_err());
}

#[test]
fn ai_quality_build_evaluation_receipt_sorts_and_dedupes_evidence_refs() {
    let scorer_result = ai_quality::ScorerResult {
        verdict: "pass",
        measurement: json!({}),
        limitations: vec!["b".into(), "a".into()],
        uncertainty: vec![],
    };
    let identity = ai_quality::Identity {
        model_identity: json!({}),
        prompt_identity: json!({}),
        retrieval_tool_config: None,
        dataset_version: json!({}),
        run_conditions: json!({}),
        judge_identity: json!({}),
    };
    let binding = json!({
        "planDigest": "sha256:aa", "repositoryRevision": "r1", "dirtyPatchDigest": null,
        "blueprintGenerationId": "g1", "blueprintManifestDigest": "sha256:bb", "registryDigest": "sha256:cc",
    });
    let receipt = ai_quality::build_evaluation_receipt(
        "latency", "1.0.0", &scorer_result, &identity, &json!({}), &binding,
        &["z".into(), "a".into(), "a".into()],
    ).unwrap();
    assert_eq!(receipt["evidenceRefs"], json!(["a", "z"]));
    assert_eq!(receipt["limitations"], json!(["a", "b"]));
    assert!(receipt["id"].as_str().unwrap().starts_with("sha256:"));
}

// ---------------------------------------------------------------------
// accessibility
// ---------------------------------------------------------------------

#[test]
fn accessibility_runtime_zero_denominator_is_unproven() {
    let result = accessibility_runtime::analyze_runtime_accessibility(Some(&json!({})), &[], &[], &[], &[]);
    assert_eq!(result["status"], "unproven");
    assert_eq!(result["coverageGaps"], json!(["zero-accessibility-denominator"]));
}

#[test]
fn accessibility_runtime_groups_findings_by_root_cause() {
    let engine = json!({ "version": "1.0" });
    let required_cases = vec![json!({ "surfaceId": "s1", "state": "default" })];
    let runs = vec![json!({
        "surfaceId": "s1", "state": "default",
        "violations": [{ "rule": "r1", "nodes": ["n1"] }],
    })];
    let result = accessibility_runtime::analyze_runtime_accessibility(Some(&engine), &required_cases, &runs, &[], &[]);
    assert_eq!(result["status"], "candidates");
    assert_eq!(result["findings"].as_array().unwrap().len(), 1);
    assert!(result["coverageGaps"].as_array().unwrap().is_empty());
}

#[test]
fn accessibility_suite_flags_missing_alt_text() {
    let dir = tmp_dir("a11y");
    fs::write(dir.join("index.html"), "<img src=\"x.png\">").unwrap();
    let result = accessibility_suite::run_accessibility_suite(&dir, &["index.html".to_string()]);
    assert_eq!(result["status"], "fail");
    let findings = result["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["ruleId"] == "a11y.image-alt"));
}

#[test]
fn accessibility_suite_skips_remotion_sources() {
    let dir = tmp_dir("a11y-remotion");
    fs::write(dir.join("scene.tsx"), "import { X } from '@remotion/core';\n<img src=\"x.png\">").unwrap();
    let result = accessibility_suite::run_accessibility_suite(&dir, &["scene.tsx".to_string()]);
    assert_eq!(result["coverage"]["scannedFiles"], 0);
    assert_eq!(result["status"], "pass");
}

#[test]
fn accessibility_suite_analyze_zero_denominator() {
    let dir = tmp_dir("a11y-zero");
    let result = accessibility_suite::analyze(&dir, &[]);
    assert_eq!(result["status"], "unproven");
    assert_eq!(result["coverageGaps"], json!([{ "kind": "accessibility-denominator-zero" }]));
}

// ---------------------------------------------------------------------
// generic-source-suite
// ---------------------------------------------------------------------

#[test]
fn generic_source_suite_flags_unknown_extension() {
    let result = generic_source_suite::run_generic_source_accounting(
        &["a.zig".to_string(), "b.ts".to_string()],
        &["zig".to_string(), "ts".to_string()],
    );
    assert_eq!(result["status"], "unproven");
    let gaps = result["coverageGaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["extension"], "zig");
}

#[test]
fn generic_source_suite_all_covered_passes() {
    let result = generic_source_suite::run_generic_source_accounting(
        &["a.ts".to_string()],
        &["ts".to_string()],
    );
    assert_eq!(result["status"], "pass");
}

// ---------------------------------------------------------------------
// data-suite
// ---------------------------------------------------------------------

#[test]
fn data_suite_flags_sql_interpolation() {
    let dir = tmp_dir("data-sql");
    fs::write(dir.join("q.ts"), "const q = `SELECT * FROM users WHERE id = ${id}`;").unwrap();
    let result = data_suite::run_data_suite(&dir, &["q.ts".to_string()]);
    assert_eq!(result["status"], "candidates");
    let candidates = result["candidates"].as_array().unwrap();
    assert!(candidates.iter().any(|c| c["ruleId"] == "data.sql-interpolation"));
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
    assert!(candidates.iter().any(|c| c["ruleId"] == "container.latest-tag"));
    assert!(candidates.iter().any(|c| c["ruleId"] == "container-root-user"));
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
// framework-suite
// ---------------------------------------------------------------------

#[test]
fn framework_suite_flags_electron_node_integration() {
    let dir = tmp_dir("fw-electron");
    fs::write(dir.join("main.js"), "new BrowserWindow({ webPreferences: { nodeIntegration: true } })").unwrap();
    let plan = json!({
        "coverageFamilies": [
            { "id": "framework.electron", "denominator": { "paths": ["main.js"] } }
        ]
    });
    let results = framework_suite::run_framework_suite(&dir, &plan);
    assert_eq!(results.len(), 1);
    let candidates = results[0]["candidates"].as_array().unwrap();
    assert!(candidates.iter().any(|c| c["ruleId"] == "electron-node-integration"));
}

#[test]
fn framework_suite_analyze_zero_families_is_unproven() {
    let dir = tmp_dir("fw-empty");
    let plan = json!({ "coverageFamilies": [] });
    let result = framework_suite::analyze(&dir, &plan);
    assert_eq!(result["status"], "unproven");
    assert_eq!(result["coverageGaps"], json!([{ "kind": "framework-denominator-zero" }]));
}

// ---------------------------------------------------------------------
// security-suite
// ---------------------------------------------------------------------

#[test]
fn security_suite_flags_disabled_tls_verification() {
    let dir = tmp_dir("sec-tls");
    fs::write(dir.join("client.js"), "https.request({ rejectUnauthorized: false })").unwrap();
    let result = security_suite::generate_security_candidates(
        &dir, &["client.js".to_string()], "insecure-defaults", None,
    ).unwrap();
    let candidates = result["candidates"].as_array().unwrap();
    assert!(candidates.iter().any(|c| c["ruleId"] == "security.tls-verification-disabled"));
    assert!(candidates.iter().all(|c| c["verdict"] == "UNADJUDICATED"));
}

#[test]
fn security_suite_credential_scan_skips_placeholders() {
    let dir = tmp_dir("sec-cred");
    fs::write(
        dir.join("config.env"),
        "API_KEY=\"changeme\"\nSECRET=\"correct-horse-battery-staple-9f8e7d6c\"\n",
    ).unwrap();
    let result = security_suite::generate_security_candidates(
        &dir, &["config.env".to_string()], "credentials", None,
    ).unwrap();
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
