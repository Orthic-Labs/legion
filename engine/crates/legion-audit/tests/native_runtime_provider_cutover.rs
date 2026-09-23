//! Dispatch coverage for every frozen `runtime-script` provider now routed to Rust.
use legion_audit::{AuditProvider, InventoryEntry, InventoryEnvelope, NativeProviderRegistry, ProviderExecutor, ProviderKind};
use legion_contracts::{ProviderSpec, ProviderStatus};
use serde_json::Value;
use std::{collections::{BTreeMap, BTreeSet}, fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}, time::{SystemTime, UNIX_EPOCH}};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

const TESTED_RUNTIME_IDS: [&str; 29] = [
    "architecture.core", "code.c-family", "code.dotnet", "code.go", "code.javascript", "code.jvm", "code.long-tail", "code.mobile", "code.php-ruby", "code.python", "code.rust", "compatibility.core", "container.iac", "dependency.osv", "docs.contract", "framework.backend", "framework.data", "framework.frontend", "governance.policy", "imported.sarif", "legacy.accessibility.internal-suite", "legacy.framework.major-suite", "legacy.visual.core", "requirements.traceability", "secrets.current-history", "security.opengrep", "structural.ast-grep", "supply-chain.license-sbom-provenance", "test-quality.core",
];

fn frozen_specs() -> Vec<ProviderSpec> {
    let raw = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/providers.json")).unwrap();
    let registry: Value = serde_json::from_str(&raw).unwrap();
    registry["providers"].as_array().unwrap().iter()
        .filter(|item| item["runner"]["kind"] == "runtime-script")
        .map(|item| serde_json::from_value(item.clone()).unwrap())
        .collect()
}

fn provider(spec: &ProviderSpec) -> AuditProvider {
    AuditProvider {
        id: spec.id.to_string(), version: spec.provider_version.clone(), role: spec.role.clone(),
        phase: spec.phase.clone(), lens_ids: spec.lens_ids.clone(),
        dependencies: spec.depends_on.iter().map(ToString::to_string).collect(),
        kind: ProviderKind::RustAlgorithm, configuration: BTreeMap::from([(String::from("selector"), spec.selector.clone())]),
        bounds: BTreeMap::new(), clean_claim: spec.clean_claim.clone(), benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false, qualification_digest: None, required: spec.selectable,
    }
}

fn fixture_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-runtime-cutover-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("src")).unwrap();
    for (path, body) in [
        ("src/lib.rs", "fn main() {}\n"), ("src/index.js", "export const value = 1;\n"),
        ("src/Main.java", "class Main {}\n"), ("src/main.go", "package main\n"),
        ("src/main.py", "print('ok')\n"), ("src/main.swift", "import Foundation\n"),
        ("src/main.cs", "class Main {}\n"), ("package.json", "{\"scripts\":{\"test\":\"true\"}}\n"),
        ("Cargo.lock", "# fixture\n"), ("pyproject.toml", "[project]\nname='fixture'\n"),
        ("terraform.tf", "resource \"x\" \"y\" {}\n"), ("results.sarif", "{\"runs\":[]}\n"),
    ] { fs::write(root.join(path), body).unwrap(); }
    root
}

fn inventory() -> InventoryEnvelope {
    let paths = ["src/lib.rs", "src/index.js", "src/Main.java", "src/main.go", "src/main.py", "src/main.swift", "src/main.cs", "package.json", "Cargo.lock", "pyproject.toml", "terraform.tf", "results.sarif"];
    InventoryEnvelope::new("runtime-cutover", "frozen-generation", paths.into_iter().map(|path| InventoryEntry {
        path: path.into(), symbols: Vec::new(), dependencies: Vec::new(), package_scripts: Vec::new(), source_file: true, digest: None,
    }).collect()).unwrap()
}

fn assert_authority(result: &legion_contracts::ProviderResult) {
    let evidence = result.details.get("findingEvidence").and_then(Value::as_object);
    let locations = result.details.get("findingLocations").and_then(Value::as_object);
    for finding in &result.findings {
        assert!(evidence.is_some_and(|items| items.contains_key(finding.id.as_str())), "finding lacks evidence authority");
        assert!(locations.is_some_and(|items| items.contains_key(finding.id.as_str())), "finding lacks location authority");
    }
    if let Some(candidates) = result.details.get("candidates") {
        assert!(candidates.is_array(), "candidate projection must remain an array");
    }
}

#[test]
fn every_frozen_runtime_script_id_dispatches_with_bound_denominator() {
    let specs = frozen_specs();
    let ids: Vec<_> = specs.iter().map(|spec| spec.id.to_string()).collect();
    assert_eq!(ids.len(), 29);
    assert_eq!(
        ids.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        TESTED_RUNTIME_IDS.into_iter().collect::<BTreeSet<_>>(),
        "registry runtime-script IDs must equal this table's tested IDs",
    );
    let root = fixture_root("positive");
    let inventory = inventory();
    let registry = NativeProviderRegistry::new(&root);
    for spec in &specs {
        let provider = provider(spec);
        let expected = inventory.denominator_entries(&spec.selector).unwrap();
        let result = registry.execute(&provider, &inventory).unwrap_or_else(|error| panic!("{}: {error}", spec.id));
        assert_eq!(result.provider.to_string(), spec.id.to_string());
        assert_authority(&result);
        if let Some(coverage) = result.coverage {
            assert_eq!(coverage.denominator_digest, expected.digest, "{} denominator", spec.id);
            assert!(coverage.examined <= coverage.expected, "{} over-examined frozen denominator", spec.id);
        }
        assert!(matches!(result.status, ProviderStatus::Complete | ProviderStatus::Partial | ProviderStatus::Failed));
    }
    assert_eq!(ids, frozen_specs().iter().map(|spec| spec.id.to_string()).collect::<Vec<_>>());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_runtime_inputs_degrade_truthfully_without_fabricated_findings() {
    let root = fixture_root("negative");
    let inventory = InventoryEnvelope::new("runtime-cutover", "empty-generation", vec![InventoryEntry {
        path: "missing/source.ts".into(), symbols: Vec::new(), dependencies: Vec::new(), package_scripts: Vec::new(), source_file: true, digest: None,
    }]).unwrap();
    let registry = NativeProviderRegistry::new(&root);
    for spec in frozen_specs() {
        let result = registry.execute(&provider(&spec), &inventory).unwrap_or_else(|error| panic!("{}: {error}", spec.id));
        assert_eq!(result.provider.to_string(), spec.id.to_string());
        assert_authority(&result);
        if result.coverage.as_ref().is_some_and(|coverage| coverage.expected == 0) {
            assert!(!result.complete, "{} claims complete with zero denominator", spec.id);
        }
        assert!(matches!(result.status, ProviderStatus::Complete | ProviderStatus::Partial | ProviderStatus::Failed));
    }
    fs::remove_dir_all(root).unwrap();
}
