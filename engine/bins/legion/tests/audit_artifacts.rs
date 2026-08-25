use std::{collections::BTreeMap, process::Command};

use legion_audit::{InventoryEntry, InventoryEnvelope};
use legion_catalog::Catalog;
use legion_contracts::{
    AgentDefinition, AgentId, BudgetCeiling, Coverage, PolicyPack, ProviderId, ProviderResult,
    ProviderSpec, ProviderStatus, ReportId, ReportStatus, ReportV1, RoutingCeiling, ToolCeiling,
};
use legion_provider_sdk::ProviderDefinition;

#[test]
fn configured_audit_writes_reconciled_json_and_sarif() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    std::fs::create_dir_all(&root).unwrap();
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
    let definition = ProviderDefinition {
        schema_version: 1,
        id: provider_id,
        provider_version: "1".into(),
        implementation_key: "fixture".into(),
        capabilities: Vec::new(),
        depends_on: Vec::new(),
        required: true,
        permissions: Vec::new(),
        source_provenance: BTreeMap::new(),
    };
    let profile = AgentDefinition::new(
        AgentId::new("legion").unwrap(),
        "Legion",
        "native fixture",
        BudgetCeiling {
            max_active_time_ms: 30_000,
            max_cost_micros: 1,
            max_output_bytes: 1_000_000,
        },
        ToolCeiling::default(),
        RoutingCeiling::default(),
    )
    .unwrap();
    let report = ReportV1 {
        schema_version: 1,
        report_id: ReportId::new("fixture").unwrap(),
        status: ReportStatus::Incomplete,
        findings: Vec::new(),
        gaps: vec!["not-executed".into()],
        claims: BTreeMap::new(),
        targets: vec![repository_id.clone()],
        extensions: BTreeMap::new(),
    };
    let config = serde_json::json!({
        "schemaVersion": 1,
        "profile": profile,
        "policy": PolicyPack {
            schema_version: 1,
            id: "fixture".into(),
            version: 1,
            rules: Vec::new(),
            extensions: BTreeMap::new(),
        },
        "providerSpecs": [specification],
        "providers": [{"definition": definition, "result": result}],
        "blueprintPacketPath": root.join("blueprint-packet.json"),
        "blueprintExpectedGeneration": "fixture-generation",
        "catalog": Catalog::new(Vec::new()).unwrap(),
        "report": report
    });
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
    let config_path = root.join("application.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let out = root.join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            &repository_id,
            "--out",
            out.to_str().unwrap(),
            "--json",
        ])
        .env("LEGION_NATIVE_APPLICATION_CONFIG", &config_path)
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
