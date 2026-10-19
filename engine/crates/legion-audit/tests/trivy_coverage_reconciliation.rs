//! Reconciliation protocol controls, not real-tool accuracy observations.
use std::collections::BTreeMap;

use legion_audit::{
    native_providers::security::{
        adapter::SecurityProviderExecutor,
        common::{digest, digest_json},
        container_iac,
    },
    AuditProvider, InventoryEnvelope, ProviderExecutor,
};
use serde_json::{json, Value};

fn input(paths: &[&str], targets: &[&str]) -> Value {
    let binding = json!({"repositoryRevision": "fixture-revision", "digest": digest(b"inventory")});
    let scope = json!({"digest": digest(b"selection"), "count": paths.len(),
        "computedDigest": digest(b"selection"), "computedCount": paths.len(),
        "entries": paths.iter().map(|path| json!({"path": path, "digest": digest(path.as_bytes())})).collect::<Vec<_>>()});
    let dispositions: Vec<Value> = paths.iter().map(|path| json!({
        "path": path,
        "disposition": if *path == "README.md" { "outside-supported-iac-scope" } else { "applicable-iac" },
        "state": "validated", "frozenDigest": digest(path.as_bytes()),
        "observedDigest": digest(path.as_bytes()), "postScanDigest": digest(path.as_bytes())
    })).collect();
    let raw: Vec<Value> = targets.iter().map(|target| json!({
        "Target": target, "Class": "config", "Type": "dockerfile",
        "Misconfigurations": [], "MisconfigurationSummary": {"Successes": 1, "Failures": 0, "Exceptions": 0}
    })).collect();
    let unique: BTreeMap<String, Value> = raw
        .iter()
        .map(|row| (digest_json(row), row.clone()))
        .collect();
    let observations: Vec<Value> = unique.iter().map(|(id, row)| json!({
        "target": row["Target"], "reportedTarget": row["Target"], "type": row["Type"], "rawResultDigest": id
    })).collect();
    let valid: std::collections::BTreeSet<&str> = targets
        .iter()
        .copied()
        .filter(|target| paths.contains(target))
        .collect();
    let examined_records = unique
        .values()
        .filter(|row| {
            row["Target"]
                .as_str()
                .is_some_and(|target| valid.contains(target))
        })
        .count();
    json!({
        "plan": {"binding": binding, "repositoryBinding": {"root": "/fixture"},
            "selectedDenominator": scope, "denominator": {"pathCount": paths.len()}},
        "projection": {"files": paths},
        "artifacts": {
            "renderedInfrastructure": observations,
            "iacEvidence": {
                "binding": binding, "databaseIdentityKind": "embedded-checks-version-derived",
                "databaseDigest": digest(b"trivy-builtin-checks\0Version: fixture"),
                "sourceDispositions": dispositions, "rawResults": raw,
                "examined": valid.len() + examined_records, "findings": [],
                "executionReceipt": {"binding": binding, "selectedDenominator": scope,
                    "complete": true, "state": "completed", "exitCode": 0,
                    "tool": {"name": "trivy", "version": "Version: fixture", "executableDigest": digest(b"tool")},
                    "executableDigest": digest(b"tool"), "stdoutDigest": digest(b"output"), "stdoutBytes": 1,
                    "receiptId": "unit-protocol-receipt", "policyId": "unit-protocol-policy",
                    "sandbox": {"required": true, "networkEnabled": true, "receiptId": "sandbox:unit-protocol"}
                }
            }
        }
    })
}

fn has_gap(analysis: &Value, kind: &str) -> bool {
    analysis["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["kind"] == kind)
}

#[test]
fn one_source_and_one_config_observation_reconcile_in_own_unit() {
    let analysis = container_iac::analyze(&input(&["Dockerfile", "README.md"], &["Dockerfile"]));
    assert_eq!(analysis["complete"], true);
    assert_eq!(analysis["status"], "pass");
    assert_eq!(analysis["denominator"]["expected"], 2);
    assert_eq!(analysis["denominator"]["examined"], 2);
    assert_eq!(
        analysis["sourceCoverage"]["validatedPaths"],
        json!(["Dockerfile", "README.md"])
    );
    assert_eq!(analysis["configObservationCount"], 1);
}

#[test]
fn duplicate_and_unrelated_records_cannot_cover_missing_second_source() {
    let analysis = container_iac::analyze(&input(
        &["a/Dockerfile", "b/Dockerfile"],
        &["a/Dockerfile", "a/Dockerfile", "unrelated/Dockerfile"],
    ));
    assert_eq!(analysis["complete"], false);
    assert_eq!(analysis["denominator"]["expected"], 4);
    assert_eq!(analysis["denominator"]["examined"], 2);
    assert_eq!(
        analysis["sourceCoverage"]["validatedPaths"],
        json!(["a/Dockerfile"])
    );
    assert!(has_gap(&analysis, "iac-source-result-missing"));
    assert!(has_gap(
        &analysis,
        "iac-config-result-correspondence-invalid"
    ));
}

#[test]
fn repeated_identical_config_record_does_not_inflate_resource_count() {
    let analysis = container_iac::analyze(&input(&["Dockerfile"], &["Dockerfile", "Dockerfile"]));
    assert_eq!(analysis["complete"], true);
    assert_eq!(
        analysis["denominator"],
        json!({"kind": "infrastructure-resources", "expected": 2, "examined": 2})
    );
}

#[test]
fn absent_infrastructure_is_partial_even_with_valid_source_identity() {
    let analysis = container_iac::analyze(&input(&["Dockerfile"], &[]));
    assert_eq!(analysis["complete"], false);
    assert_eq!(analysis["denominator"]["examined"], 0);
    assert!(has_gap(&analysis, "rendered-resources-absent"));
    assert!(has_gap(&analysis, "iac-source-result-missing"));
}

#[test]
fn invalid_receipt_binding_database_and_frozen_count_fail_closed() {
    for (pointer, value, kind) in [
        (
            "/artifacts/iacEvidence/executionReceipt/complete",
            json!(false),
            "iac-execution-receipt-invalid",
        ),
        (
            "/artifacts/iacEvidence/executionReceipt/binding/digest",
            json!(digest(b"wrong")),
            "iac-receipt-binding-invalid",
        ),
        (
            "/artifacts/iacEvidence/databaseDigest",
            json!(digest(b"wrong")),
            "iac-database-identity-invalid",
        ),
        (
            "/plan/selectedDenominator/count",
            json!(2),
            "iac-frozen-selection-invalid",
        ),
        (
            "/artifacts/iacEvidence/executionReceipt/sandbox/required",
            json!(false),
            "iac-execution-receipt-invalid",
        ),
        (
            "/artifacts/iacEvidence/rawResults",
            Value::Null,
            "iac-config-output-invalid",
        ),
        (
            "/artifacts/iacEvidence/rawResults/0/Class",
            json!("lang-pkgs"),
            "iac-config-output-invalid",
        ),
    ] {
        let mut artifact = input(&["Dockerfile"], &["Dockerfile"]);
        *artifact.pointer_mut(pointer).unwrap() = value;
        let analysis = container_iac::analyze(&artifact);
        assert_eq!(analysis["complete"], false, "{pointer}");
        assert!(has_gap(&analysis, kind), "{pointer}: {analysis}");
    }
}

#[test]
fn unreadable_drifted_or_unhashed_source_cannot_be_covered_by_result() {
    for kind in [
        "iac-source-unreadable",
        "iac-source-drift",
        "iac-source-digest-missing",
    ] {
        let mut artifact = input(&["Dockerfile", "README.md"], &["Dockerfile"]);
        let row = &mut artifact["artifacts"]["iacEvidence"]["sourceDispositions"][0];
        row["state"] = json!("unproven");
        row["reason"] = json!(kind);
        let analysis = container_iac::analyze(&artifact);
        assert_eq!(analysis["complete"], false);
        assert_eq!(analysis["denominator"]["examined"], 0);
        assert_eq!(
            analysis["sourceCoverage"]["validatedPaths"],
            json!(["README.md"])
        );
        assert!(has_gap(&analysis, kind));
    }
}

#[test]
fn outside_scope_readme_requires_pre_and_post_frozen_identity() {
    for kind in [
        "iac-source-unreadable",
        "iac-source-drift",
        "iac-source-digest-missing",
    ] {
        let mut artifact = input(&["Dockerfile", "README.md"], &["Dockerfile"]);
        let row = &mut artifact["artifacts"]["iacEvidence"]["sourceDispositions"][1];
        row["state"] = json!("unproven");
        row["reason"] = json!(kind);
        let analysis = container_iac::analyze(&artifact);
        assert_eq!(analysis["complete"], false);
        assert_eq!(analysis["denominator"]["expected"], 2);
        assert_eq!(analysis["denominator"]["examined"], 2);
        assert_eq!(
            analysis["sourceCoverage"]["validatedPaths"],
            json!(["Dockerfile"])
        );
        assert!(has_gap(&analysis, kind));
    }
    for (field, value) in [
        ("frozenDigest", Value::Null),
        ("observedDigest", json!(digest(b"drift before scan"))),
        ("postScanDigest", json!(digest(b"drift after scan"))),
    ] {
        let mut artifact = input(&["Dockerfile", "README.md"], &["Dockerfile"]);
        artifact["artifacts"]["iacEvidence"]["sourceDispositions"][1][field] = value;
        let analysis = container_iac::analyze(&artifact);
        assert_eq!(analysis["complete"], false, "{field}");
        assert_eq!(
            analysis["sourceCoverage"]["validatedPaths"],
            json!(["Dockerfile"])
        );
        assert!(has_gap(&analysis, "iac-source-identity-invalid"));
    }
}

#[test]
fn forged_target_correspondence_and_post_scan_drift_are_rejected() {
    let mut artifact = input(&["Dockerfile"], &["elsewhere/Dockerfile"]);
    artifact["artifacts"]["renderedInfrastructure"][0]["target"] = json!("Dockerfile");
    artifact["artifacts"]["renderedInfrastructure"][0]["targetValidated"] = json!(true);
    let analysis = container_iac::analyze(&artifact);
    assert_eq!(analysis["complete"], false);
    assert!(has_gap(
        &analysis,
        "iac-config-result-correspondence-invalid"
    ));
    let mut artifact = input(&["Dockerfile"], &["Dockerfile"]);
    artifact["artifacts"]["iacEvidence"]["sourceDispositions"][0]["postScanDigest"] =
        json!(digest(b"drift"));
    assert_eq!(container_iac::analyze(&artifact)["complete"], false);
}

#[test]
fn caller_json_cannot_enable_native_frozen_path_conversion() {
    let inventory: InventoryEnvelope = serde_json::from_value(json!({
        "schemaVersion": 1, "repositoryId": "fixture", "generation": "revision",
        "entries": [{"path": "Dockerfile", "sourceFile": false, "digest": digest(b"source")}],
        "digest": digest(b"inventory")
    }))
    .unwrap();
    let denominator = inventory
        .denominator_entries(&json!({"op": "always"}))
        .unwrap();
    let provider: AuditProvider = serde_json::from_value(json!({
        "id": "container.iac", "version": "1.0.0", "role": "security", "phase": "source",
        "lensIds": [], "dependencies": [], "kind": "typed-external-project-tool",
        "configuration": {"selector": {"op": "always"}, "denominatorDigest": denominator.digest, "denominatorCount": 1},
        "bounds": {}, "cleanClaim": "candidates-only", "benchmarkStatus": "not-required",
        "benchmarkRequiredForCleanClaim": false, "qualificationDigest": null, "required": false
    })).unwrap();
    let mut artifact = input(&["Dockerfile"], &["Dockerfile"]);
    artifact["nativeSourceCoverage"] = json!(true);
    artifact["producer"] = json!({"mode": "tool", "native": true});
    let executor =
        SecurityProviderExecutor::new(BTreeMap::from([("container.iac".into(), artifact)]));
    let result = executor.execute(&provider, &inventory).unwrap();
    // Host artifacts retain their own infrastructure unit. Only an actual
    // ArtifactProducer invocation can convert that unit to one frozen path.
    assert_eq!(result.coverage.unwrap().expected, 2);
}
