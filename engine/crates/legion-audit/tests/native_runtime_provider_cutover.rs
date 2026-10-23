//! Dispatch coverage for every frozen `runtime-script` provider now routed to Rust.
use legion_audit::{
    AuditProvider, InventoryEntry, InventoryEnvelope, NativeProviderRegistry, ProviderExecutor,
    ProviderKind,
};
use legion_contracts::{ProviderSpec, ProviderStatus};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

const TESTED_RUNTIME_IDS: [&str; 46] = [
    "architecture.core",
    "architecture.structure",
    "code.android.lint",
    "code.apple.targets",
    "code.dotnet",
    "code.javascript",
    "code.javascript.native",
    "code.jvm",
    "code.kotlin.detekt-source",
    "code.kotlin.detekt-typed",
    "code.long-tail",
    "code.mobile",
    "code.python",
    "code.rust",
    "code.rust.targets",
    "compatibility.core",
    "container.iac",
    "dependency.osv",
    "docs.contract",
    "framework.backend",
    "framework.data",
    "framework.frontend",
    "framework.nginx",
    "governance.capability-ownership",
    "governance.policy",
    "imported.sarif",
    "legacy.accessibility.internal-suite",
    "legacy.data.internal-suite",
    "legacy.framework.major-suite",
    "legacy.infrastructure.internal-suite",
    "legacy.visual.core",
    "requirements.traceability",
    "secrets.current-history",
    "security.agent-skill-mcp",
    "security.agentic-ci",
    "security.credentials",
    "security.insecure-defaults",
    "security.misuse-resistance",
    "security.opengrep",
    "security.scanner-shellcheck",
    "security.scanner-squawk",
    "security.scanner-zizmor",
    "security.suppression-changes",
    "structural.ast-grep",
    "supply-chain.license-sbom-provenance",
    "test-quality.core",
];

fn frozen_specs() -> Vec<ProviderSpec> {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .unwrap();
    let registry: Value = serde_json::from_str(&raw).unwrap();
    registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["runner"]["kind"] == "runtime-script")
        .map(|item| serde_json::from_value(item.clone()).unwrap())
        .collect()
}

fn provider(spec: &ProviderSpec) -> AuditProvider {
    AuditProvider {
        id: spec.id.to_string(),
        version: spec.provider_version.clone(),
        role: spec.role.clone(),
        phase: spec.phase.clone(),
        lens_ids: spec.lens_ids.clone(),
        dependencies: spec.depends_on.iter().map(ToString::to_string).collect(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([(String::from("selector"), spec.selector.clone())]),
        bounds: BTreeMap::new(),
        clean_claim: spec.clean_claim.clone(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: spec.selectable,
    }
}

fn fixture_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-runtime-cutover-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    for directory in ["src", "app", "config", ".github/workflows"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    for (path, body) in [
        ("src/lib.rs", "fn main() {}\n"),
        ("src/index.js", "export const value = 1;\n"),
        ("src/Main.java", "class Main {}\n"),
        ("src/main.go", "package main\n"),
        ("src/main.py", "print('ok')\n"),
        ("src/main.swift", "import Foundation\n"),
        ("src/main.cs", "class Main {}\n"),
        ("package.json", "{\"scripts\":{\"test\":\"true\"}}\n"),
        ("Cargo.lock", "# fixture\n"),
        ("pyproject.toml", "[project]\nname='fixture'\n"),
        ("terraform.tf", "resource \"x\" \"y\" {}\n"),
        ("results.sarif", "{\"runs\":[]}\n"),
        ("migration.sql", "ALTER TABLE users DROP COLUMN name;\n"),
        ("run.sh", "#!/bin/sh\necho $value\n"),
        (
            "pod.yaml",
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: fixture\n",
        ),
        (
            ".github/workflows/ci.yml",
            "name: fixture\non: push\njobs: {}\n",
        ),
        ("app/model.rb", "class Model; end\n"),
        ("config/application.rb", "require 'rails'\n"),
        ("Gemfile", "source 'https://rubygems.org'\ngem 'rails'\n"),
        ("go.mod", "module example.com/fixture\n\ngo 1.22\n"),
    ] {
        fs::write(root.join(path), body).unwrap();
    }
    root
}

fn inventory() -> InventoryEnvelope {
    let paths = [
        "src/lib.rs",
        "src/index.js",
        "src/Main.java",
        "src/main.go",
        "src/main.py",
        "src/main.swift",
        "src/main.cs",
        "package.json",
        "Cargo.lock",
        "pyproject.toml",
        "terraform.tf",
        "results.sarif",
        "migration.sql",
        "run.sh",
        "pod.yaml",
        ".github/workflows/ci.yml",
        "app/model.rb",
        "config/application.rb",
        "Gemfile",
        "go.mod",
    ];
    InventoryEnvelope::new(
        "runtime-cutover",
        "frozen-generation",
        paths
            .into_iter()
            .map(|path| InventoryEntry {
                path: path.into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            })
            .collect(),
    )
    .unwrap()
}

fn assert_authority(result: &legion_contracts::ProviderResult) {
    let evidence = result
        .details
        .get("findingEvidence")
        .and_then(Value::as_object);
    let locations = result
        .details
        .get("findingLocations")
        .and_then(Value::as_object);
    for finding in &result.findings {
        assert!(
            evidence.is_some_and(|items| items.contains_key(finding.id.as_str())),
            "finding lacks evidence authority"
        );
        assert!(
            locations.is_some_and(|items| items.contains_key(finding.id.as_str())),
            "finding lacks location authority"
        );
    }
    if let Some(candidates) = result.details.get("candidates") {
        assert!(
            candidates.is_array(),
            "candidate projection must remain an array"
        );
    }
}

#[test]
fn every_frozen_runtime_script_id_dispatches_with_bound_denominator() {
    let specs = frozen_specs();
    let ids: Vec<_> = specs.iter().map(|spec| spec.id.to_string()).collect();
    assert_eq!(ids.len(), TESTED_RUNTIME_IDS.len());
    assert_eq!(
        ids.iter().collect::<BTreeSet<_>>().len(),
        ids.len(),
        "runtime registry IDs must be unique"
    );
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
        if provider.id.starts_with("security.scanner-") {
            assert!(
                !expected.entries.is_empty(),
                "{} scanner fixture must exercise selected input",
                spec.id
            );
        }
        let result = registry
            .execute(&provider, &inventory)
            .unwrap_or_else(|error| panic!("{}: {error}", spec.id));
        assert_eq!(result.provider.to_string(), spec.id.to_string());
        if provider.id.starts_with("security.scanner-") {
            assert!(
                result.applicable,
                "{} selected scanner cannot deselect itself",
                spec.id
            );
            assert!(
                result.coverage.is_some(),
                "{} selected scanner must report frozen coverage",
                spec.id
            );
        }
        assert_authority(&result);
        assert_status_is_settled(&spec.id.to_string(), &result);
        if let Some(coverage) = result.coverage {
            assert_eq!(
                coverage.denominator_digest, expected.digest,
                "{} denominator",
                spec.id
            );
            assert!(
                coverage.examined <= coverage.expected,
                "{} over-examined frozen denominator",
                spec.id
            );
        }
    }
    assert_eq!(
        ids,
        frozen_specs()
            .iter()
            .map(|spec| spec.id.to_string())
            .collect::<Vec<_>>()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_runtime_inputs_degrade_truthfully_without_fabricated_findings() {
    let root = fixture_root("negative");
    let inventory = InventoryEnvelope::new(
        "runtime-cutover",
        "empty-generation",
        vec![InventoryEntry {
            path: "missing/source.ts".into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: None,
        }],
    )
    .unwrap();
    let registry = NativeProviderRegistry::new(&root);
    for spec in frozen_specs() {
        let result = registry
            .execute(&provider(&spec), &inventory)
            .unwrap_or_else(|error| panic!("{}: {error}", spec.id));
        assert_eq!(result.provider.to_string(), spec.id.to_string());
        assert_authority(&result);
        if result
            .coverage
            .as_ref()
            .is_some_and(|coverage| coverage.expected == 0)
        {
            assert!(
                !result.complete,
                "{} claims complete with zero denominator",
                spec.id
            );
        }
        assert_status_is_settled(&spec.id.to_string(), &result);
    }
    fs::remove_dir_all(root).unwrap();
}

/// A provider that applies reports Complete, Partial or Failed. A provider
/// with no applicable input reports the engine's not-applicable shape:
/// `applicable: false`, `Ok`, no coverage, and no gap.
fn assert_status_is_settled(id: &str, result: &legion_contracts::ProviderResult) {
    // Some packs report `applicable: false` with their own Partial result;
    // only an `Ok` not-applicable result must carry the engine's exact shape.
    if result.applicable || result.status != ProviderStatus::Ok {
        assert!(
            matches!(
                result.status,
                ProviderStatus::Complete | ProviderStatus::Partial | ProviderStatus::Failed
            ),
            "{id} status {:?}",
            result.status
        );
    } else {
        assert_eq!(
            result.status,
            ProviderStatus::Ok,
            "{id} not-applicable status"
        );
        assert!(result.coverage.is_none(), "{id} not-applicable coverage");
        assert!(result.coverage_gaps.is_empty(), "{id} not-applicable gaps");
        assert_eq!(
            result.details["applicability"],
            Value::String("not-applicable".into()),
            "{id} not-applicable marker"
        );
    }
}
