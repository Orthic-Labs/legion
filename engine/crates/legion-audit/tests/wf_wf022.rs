//! Ported tests for chunk wf022 (`src/lib/report/sarif/index.mjs`,
//! `scripts/report-to-sarif.mjs`) against
//! `legion_audit::wf_port::wf022::render_sarif_report`.
//!
//! Source assertions ported from `tests/security-reporting.test.mjs`.

use legion_audit::wf_port::wf022::render_sarif_report;
use serde_json::json;

#[test]
fn sarif_primitive_result_references_candidate_and_variant_receipt() {
    let report = json!({
        "findings": [{
            "id": "f1", "candidateId": "c1", "ruleId": "credentials.format", "severity": "high",
            "title": "Credential", "file": "a.ts", "line": 3,
            "variantReceiptId": "sha256:receipt", "relatedAttackPathIds": ["path-1"],
        }],
    });
    let sarif = render_sarif_report(&report);
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["properties"]["candidateId"], json!("c1"));
    assert_eq!(result["properties"]["variantReceiptId"], json!("sha256:receipt"));
    assert_eq!(result["properties"]["relatedAttackPathIds"], json!(["path-1"]));
}

#[test]
fn sarif_emits_ordered_code_flow_for_proven_path() {
    let report = json!({
        "security": {
            "attackPaths": {
                "proven": [{
                    "id": "path-1", "severity": "critical", "priority": "PRIVILEGE_ESCALATION",
                    "start": {"factIds": ["f1"]}, "objective": {"id": "objective.privilege-escalation"},
                    "stepAssessments": [
                        {"candidateId": "c1", "file": "a.ts", "line": 3},
                        {"candidateId": "c2", "file": "b.ts", "line": 9},
                    ],
                    "constituentFindingIds": ["f1"], "proof": {"digest": "sha256:p"},
                }],
            },
        },
    });
    let sarif = render_sarif_report(&report);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let path_result = results
        .iter()
        .find(|r| r["ruleId"].as_str().unwrap_or_default().starts_with("security.attack-path"))
        .expect("path result present");
    assert_eq!(path_result["partialFingerprints"]["legionPath/v1"], json!("path-1"));
    let locations = path_result["codeFlows"][0]["threadFlows"][0]["locations"]
        .as_array()
        .unwrap();
    assert_eq!(locations.len(), 2);
    assert_eq!(locations[0]["order"], json!(0));
}

#[test]
fn partial_paths_are_never_emitted_as_failing_sarif_results() {
    let report = json!({
        "security": {
            "attackPaths": {
                "proven": [],
                "partiallySupported": [{"id": "p2", "severity": null}],
            },
        },
    });
    let sarif = render_sarif_report(&report);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(!results
        .iter()
        .any(|r| r["ruleId"].as_str().unwrap_or_default().starts_with("security.attack-path")));
}

#[test]
fn path_identity_is_stable_across_line_shifts() {
    let make = |line: i64| {
        render_sarif_report(&json!({
            "security": {
                "attackPaths": {
                    "proven": [{
                        "id": "path-1", "severity": "high", "priority": "PRIVILEGE_ESCALATION",
                        "objective": {"id": "objective.privilege-escalation"},
                        "stepAssessments": [{"candidateId": "c1", "file": "a.ts", "line": line}],
                        "constituentFindingIds": [],
                    }],
                },
            },
        }))
    };
    let a = make(3);
    let b = make(40);
    let find_path = |sarif: &serde_json::Value| -> serde_json::Value {
        sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["ruleId"].as_str().unwrap_or_default().starts_with("security.attack-path"))
            .cloned()
            .unwrap()
    };
    let pa = find_path(&a);
    let pb = find_path(&b);
    assert_eq!(pa["partialFingerprints"]["legionPath/v1"], pb["partialFingerprints"]["legionPath/v1"]);
}

#[test]
fn no_double_counted_vulnerability_total_paths_and_primitives_counted_separately() {
    let report = json!({
        "findings": [{"id": "f1", "ruleId": "r", "severity": "high", "title": "x"}],
        "security": {
            "attackPaths": {
                "proven": [{
                    "id": "path-1", "severity": "critical", "priority": "DIRECT_CROWN_JEWEL",
                    "objective": {"id": "objective.crown-jewel-access"},
                    "stepAssessments": [], "constituentFindingIds": ["f1"],
                }],
            },
        },
    });
    let sarif = render_sarif_report(&report);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let primitive: Vec<_> = results.iter().filter(|r| r["ruleId"] == json!("r")).collect();
    let paths: Vec<_> = results
        .iter()
        .filter(|r| r["ruleId"].as_str().unwrap_or_default().starts_with("security.attack-path"))
        .collect();
    assert_eq!(primitive.len(), 1);
    assert_eq!(paths.len(), 1);
    assert_ne!(primitive[0]["ruleId"], paths[0]["ruleId"]);
    assert_ne!(
        primitive[0]["partialFingerprints"]["legionFinding/v1"],
        paths[0]["partialFingerprints"]["legionPath/v1"]
    );
}
