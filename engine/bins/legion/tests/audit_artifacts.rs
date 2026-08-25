use std::{collections::BTreeMap, process::Command};

use legion_audit::{InventoryEntry, InventoryEnvelope};
use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus};

#[test]
fn configured_audit_writes_reconciled_json_and_sarif() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let repository_id = root.to_string_lossy().into_owned();
    let provider_id = ProviderId::new("fixture-provider").unwrap();
    let inventory = InventoryEnvelope::new(
        &repository_id,
        "fixture-generation",
        vec![InventoryEntry {
            path: "src/lib.rs".into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            digest: None,
        }],
    )
    .unwrap();
    let result = ProviderResult {
        schema_version: 1,
        provider: provider_id.clone(),
        applicable: true,
        required: true,
        status: ProviderStatus::Complete,
        complete: true,
        coverage: Some(Coverage {
            denominator_digest: inventory.digest.clone(),
            expected: 1,
            examined: 1,
            gaps: Vec::new(),
        }),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: BTreeMap::new(),
    };
    let specification = ProviderSpec {
        schema_version: 2,
        id: provider_id.clone(),
        provider_version: "1".into(),
        family: "fixture".into(),
        lens_ids: Vec::new(),
        role: "deterministic".into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: vec!["blueprint-packet".into()],
        produces: vec!["provider-result".into()],
        selector: serde_json::json!({"op": "always"}),
        denominator_kind: "selected-scope".into(),
        runner: serde_json::json!({"kind": "built-in"}),
        host_capabilities: Vec::new(),
        execution: serde_json::json!({}),
        reasoning: serde_json::json!({}),
        benchmark: serde_json::json!({
            "status": "qualified",
            "requiredForCleanClaim": true,
            "qualificationDigest": "sha256:fixture"
        }),
        clean_claim: "finding-producing".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    };
    let packet = serde_json::json!({
        "schema": "membrane.blueprint-packet.v1",
        "status": "ready",
        "state": "ready",
        "generationId": "fixture-generation",
        "manifestDigest": format!("sha256:{}", "1".repeat(64)),
        "sourceObservation": {"kind": "fixture"},
        "files": ["src/lib.rs"],
        "fileCount": 1,
        "sourceFileCount": 1,
        "parsedExtensions": ["rs"],
        "unsupportedExtensions": [],
        "overlay": {"state": "ready", "dirtyTracked": 0, "untracked": 0}
    });
    std::fs::write(
        root.join("blueprint-packet.json"),
        serde_json::to_vec_pretty(&packet).unwrap(),
    )
    .unwrap();
    let plan_path = root.join("provider-plan.json");
    std::fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({"providers": [specification]})).unwrap(),
    )
    .unwrap();
    let result_path = root.join("provider-result.json");
    std::fs::write(
        &result_path,
        serde_json::to_vec_pretty(&serde_json::json!({"providerResult": result})).unwrap(),
    )
    .unwrap();
    let out = root.join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            &repository_id,
            "--out",
            out.to_str().unwrap(),
            "--json",
            "--blueprint-packet",
            root.join("blueprint-packet.json").to_str().unwrap(),
            "--expected-generation",
            "fixture-generation",
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
        ])
        .env("AUDIT_PLAN_SIGNING_KEY", "fixture-signing-key")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["auditStatus"], "pass");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "clean");
    assert_eq!(report["claims"]["executedProviderCount"], 1);
    let sarif: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.sarif")).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert!(out.join("execution.json").is_file());
}
