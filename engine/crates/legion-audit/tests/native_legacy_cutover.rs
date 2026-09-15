//! Native legacy-check cutover coverage.
//!
//! These tests exercise the exact registry route and the filesystem-owned
//! implementations.  They do not invoke Node, a shell, or a project tool.

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::{
    native_providers::legacy_checks::spec, AuditProvider, InventoryEntry, InventoryEnvelope,
    NativeProviderRegistry, ProviderExecutor, ProviderKind,
};
use serde_json::{json, Value};

/// Registry lens ids exactly as shipped in `src/registry/providers.json`.
fn registry_lens_ids(id: &str) -> Vec<String> {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .expect("packaged provider registry");
    let registry: Value = serde_json::from_str(&raw).expect("registry JSON");
    registry["providers"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["id"].as_str() == Some(id))
                .map(|item| {
                    item["lensIds"]
                        .as_array()
                        .map(|lenses| {
                            lenses
                                .iter()
                                .filter_map(|lens| lens.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                        .unwrap_or_default()
                })
        })
        .unwrap_or_default()
}

fn provider(id: &str, selector: Value) -> AuditProvider {
    let contract = spec(id).expect("legacy provider must be frozen");
    AuditProvider {
        id: id.into(),
        version: "2.0.0".into(),
        role: contract.role.into(),
        phase: contract.phase.into(),
        lens_ids: registry_lens_ids(id),
        dependencies: Vec::new(),
        kind: ProviderKind::TypedExternalProjectTool,
        configuration: BTreeMap::from([
            ("selector".into(), selector),
            (
                "runner".into(),
                json!({"kind":"legacy-check","check":contract.check}),
            ),
        ]),
        bounds: BTreeMap::new(),
        clean_claim: "evidence-only".into(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: false,
    }
}

fn root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("legion-native-legacy-cutover-{suffix}"));
    fs::create_dir_all(root.join("src-tauri")).expect("temporary repository");
    root
}

fn inventory(paths: &[&str]) -> InventoryEnvelope {
    InventoryEnvelope::new(
        "legacy-cutover-fixture",
        "legacy-cutover-generation",
        paths
            .iter()
            .map(|path| InventoryEntry {
                path: (*path).into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            })
            .collect(),
    )
    .expect("fixture inventory")
}

#[test]
fn exact_registry_route_returns_candidates_bound_to_frozen_denominator() {
    let root = root();
    fs::write(
        root.join("src-tauri/frontend.ts"),
        "invoke('missing_command');",
    )
    .expect("frontend fixture");
    let selector = json!({"op":"anyPath","patterns":["src-tauri/**"]});
    let inventory = inventory(&["src-tauri/frontend.ts"]);
    let expected = inventory
        .denominator_entries(&selector)
        .expect("frozen selector");
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.tauri.contract-mirror", selector),
            &inventory,
        )
        .expect("native exact dispatch");

    assert_eq!(result.provider.to_string(), "legacy.tauri.contract-mirror");
    assert!(result.complete);
    assert_eq!(
        result
            .coverage
            .as_ref()
            .expect("coverage")
            .denominator_digest,
        expected.digest
    );
    assert!(!result
        .details
        .get("candidates")
        .and_then(Value::as_array)
        .expect("candidate projection")
        .is_empty());
    assert_eq!(
        result.details.get("processState").and_then(Value::as_str),
        Some("completed")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn native_negative_path_has_no_synthetic_candidate() {
    let root = root();
    fs::write(root.join("src-tauri/frontend.ts"), "invoke('ping');").expect("frontend fixture");
    fs::write(
        root.join("src-tauri/backend.rs"),
        "#[tauri::command]\npub fn ping() {}",
    )
    .expect("backend fixture");
    fs::write(root.join("src-tauri/tauri.conf.json"), "{}").expect("config fixture");
    let selector = json!({"op":"anyPath","patterns":["src-tauri/**"]});
    let inventory = inventory(&[
        "src-tauri/backend.rs",
        "src-tauri/frontend.ts",
        "src-tauri/tauri.conf.json",
    ]);
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.tauri.contract-mirror", selector),
            &inventory,
        )
        .expect("native exact dispatch");

    assert!(result.complete);
    assert!(result
        .details
        .get("candidates")
        .and_then(Value::as_array)
        .expect("candidate projection")
        .is_empty());
    assert!(result.coverage.as_ref().expect("coverage").gaps.is_empty());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unreadable_frozen_entry_degrades_with_process_and_receipt_state() {
    let root = root();
    let selector = json!({"op":"anyPath","patterns":["src-tauri/**"]});
    let inventory = inventory(&["src-tauri/missing.ts"]);
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.tauri.contract-mirror", selector),
            &inventory,
        )
        .expect("typed degradation");

    assert!(!result.complete);
    assert_eq!(
        result.details.get("processState").and_then(Value::as_str),
        Some("failed")
    );
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("source-unavailable:")));
    let receipt = result
        .details
        .get("executionReceipt")
        .expect("terminal receipt");
    assert_eq!(
        receipt.get("providerId").and_then(Value::as_str),
        Some("legacy.tauri.contract-mirror")
    );
    assert_eq!(
        receipt.get("complete").and_then(Value::as_bool),
        Some(false)
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn all_frozen_contracts_have_an_exact_dispatch_entry() {
    for contract in legion_audit::native_providers::legacy_checks::specs() {
        assert_eq!(
            spec(&contract.provider_id).map(|item| item.check),
            Some(contract.check)
        );
    }
    assert_eq!(
        legion_audit::native_providers::legacy_checks::specs().len(),
        32
    );
}

#[test]
fn external_route_without_authorized_capability_cannot_claim_process_or_coverage() {
    let root = root();
    fs::write(root.join("package.json"), "{}").unwrap();
    let inventory = inventory(&["package.json"]);
    let result = NativeProviderRegistry::new(&root)
        .execute(&provider("legacy.quality.build", json!({"op":"always"})), &inventory)
        .expect("capability absence is a typed result");
    assert!(!result.complete);
    assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
    assert!(result.coverage_gaps.iter().any(|gap| gap == "external-project-tool-capability-unavailable"));
    let receipt = &result.details["executionReceipt"];
    assert_eq!(receipt["processTree"]["started"], false);
    assert_eq!(receipt["processTree"]["reaped"], false);
    assert_eq!(receipt["executable"]["version"]["qualified"], false);
    assert_eq!(receipt["parser"]["attempted"], false);
    assert!(receipt["exitCode"].is_null());
    assert!(receipt["policy"].is_null());
    assert!(receipt["stdout"]["path"].is_null());
    fs::remove_dir_all(root).unwrap();
}

fn specification(id: &str) -> legion_contracts::ProviderSpec {
    let contract = spec(id).unwrap();
    serde_json::from_value(json!({
        "schemaVersion":2, "id":id, "providerVersion":"2.0.0",
        "family":"fixture", "role":contract.role, "phase":contract.phase,
        "lensIds": registry_lens_ids(id), "dependsOn":[], "consumes":["repository-inventory"],
        "produces":["provider-result"], "selector":{"op":"always"},
        "denominatorKind":"repository-inventory",
        "runner":{"kind":"legacy-check","check":contract.check},
        "hostCapabilities":[], "execution":{}, "reasoning":{},
        "benchmark":{"status":"unproven","requiredForCleanClaim":false},
        "cleanClaim":"evidence-only", "controlIds":[], "scopes":[], "selectable":true
    })).unwrap()
}

#[test]
fn in_process_legacy_check_passes_frozen_execution_without_fabricated_process_evidence() {
    let root = root();
    fs::write(root.join("src-tauri/plain.rs"), "fn plain() {}\n").unwrap();
    let inventory = inventory(&["src-tauri/plain.rs"]);
    let plan = legion_audit::AuditPlan::compile(&inventory, &[specification("legacy.tauri.contract-mirror")])
        .unwrap().freeze(Some(b"fixture-key")).unwrap();
    assert_eq!(plan.providers()[0].kind, ProviderKind::RustAlgorithm);
    let report = legion_audit::execute(&plan, &inventory, &NativeProviderRegistry::new(&root)).unwrap();
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert!(report.results[0].result.complete);
    let receipt = &report.results[0].result.details["executionReceipt"];
    assert_eq!(receipt["kind"], "native-legacy-check-receipt");
    assert_eq!(receipt["processTree"]["started"], false);
    assert!(receipt["policy"].is_null());
    assert!(receipt["stdout"]["path"].is_null());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn external_refusal_survives_common_report_validation_with_no_examined_files() {
    let root = root();
    fs::write(root.join("package.json"), "{}").unwrap();
    let inventory = inventory(&["package.json"]);
    let plan = legion_audit::AuditPlan::compile(&inventory, &[specification("legacy.quality.build")])
        .unwrap().freeze(Some(b"fixture-key")).unwrap();
    assert_eq!(plan.providers()[0].kind, ProviderKind::TypedExternalProjectTool);
    let report = legion_audit::execute(&plan, &inventory, &NativeProviderRegistry::new(&root)).unwrap();
    assert!(!report.results[0].result.complete);
    assert!(report.gaps.iter().any(|gap| gap == "external-project-tool-capability-unavailable"), "{:?}", report.gaps);
    assert!(!report.gaps.iter().any(|gap| gap.contains("invalid-provider-result")), "{:?}", report.gaps);
    assert_eq!(report.results[0].result.coverage.as_ref().unwrap().examined, 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn changed_and_oversized_source_cannot_count_as_examined() {
    let root = root();
    let path = root.join("src-tauri/plain.rs");
    fs::write(&path, "fn changed() {}\n").unwrap();
    let mut entries = inventory(&["src-tauri/plain.rs"]).entries;
    entries[0].digest = Some(format!("sha256:{}", "0".repeat(64)));
    let frozen = InventoryEnvelope::new("fixture", "generation", entries).unwrap();
    let result = NativeProviderRegistry::new(&root).execute(&provider("legacy.tauri.contract-mirror", json!({"op":"always"})), &frozen).unwrap();
    assert!(!result.complete);
    assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
    assert!(result.coverage_gaps.iter().any(|gap| gap.starts_with("source-digest-drift:")));
    fs::write(path, vec![b'x'; 1_048_577]).unwrap();
    let result = NativeProviderRegistry::new(&root).execute(&provider("legacy.tauri.contract-mirror", json!({"op":"always"})), &inventory(&["src-tauri/plain.rs"])).unwrap();
    assert!(!result.complete);
    assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
    assert!(result.coverage_gaps.iter().any(|gap| gap.starts_with("source-file-byte-limit:")));
    fs::remove_dir_all(root).unwrap();
}
