//! The architecture-family providers self-source their input from the frozen
//! denominator when the host injects none, and keep host input authoritative.

use legion_audit::{
    native_providers::availability::unavailable_reason, AuditProvider, FilesystemInventorySource,
    InventoryEnvelope, InventorySource, NativeProviderRegistry, ProviderExecutor, ProviderKind,
};
use legion_contracts::{ProviderResult, ProviderStatus};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn fixture_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-arch-producer-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

fn write(root: &Path, path: &str, body: &str) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, body).unwrap();
}

fn provider(id: &str) -> AuditProvider {
    AuditProvider {
        id: id.into(),
        version: "2.0.0".into(),
        role: "diagnose".into(),
        phase: "static".into(),
        lens_ids: Vec::new(),
        dependencies: Vec::new(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([("selector".into(), json!({"op":"always"}))]),
        bounds: BTreeMap::new(),
        clean_claim: "evidence-only".into(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: false,
    }
}

fn inventory(root: &Path) -> InventoryEnvelope {
    FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("architecture-producer-fixture")
        .unwrap()
}

fn run(root: &Path, id: &str) -> ProviderResult {
    NativeProviderRegistry::new(root)
        .execute(&provider(id), &inventory(root))
        .unwrap()
}

/// (finding id, first located path) for every finding.
fn located(result: &ProviderResult) -> Vec<(String, String)> {
    let locations = result
        .details
        .get("findingLocations")
        .cloned()
        .unwrap_or(Value::Null);
    result
        .findings
        .iter()
        .map(|finding| {
            let id = finding.id.as_str().to_owned();
            let path = locations
                .get(&id)
                .and_then(|paths| paths.get(0))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            (id, path)
        })
        .collect()
}

const RUST_BODY: &str = "pub fn value() -> u32 {\n    let a = 1;\n    let b = 2;\n    a + b\n}\n";

fn module(uses: &str, extra: &str, tested: bool) -> String {
    let tests = if tested {
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn value_is_three() {\n        assert_eq!(super::value(), 3);\n    }\n}\n"
    } else {
        ""
    };
    format!("{uses}\n{RUST_BODY}{extra}\n{tests}")
}

fn dirty_fixture() -> PathBuf {
    let root = fixture_root("dirty");
    write(
        &root,
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    );
    write(
        &root,
        "src/lib.rs",
        "pub mod alpha;\npub mod beta;\npub mod untested;\n",
    );
    write(
        &root,
        "src/alpha.rs",
        &module(
            "use crate::beta::value as other;",
            "// REQ-1 implemented here",
            true,
        ),
    );
    write(
        &root,
        "src/beta.rs",
        &module("use crate::alpha::value as other;", "", true),
    );
    write(&root, "src/untested.rs", &module("", "", false));
    write(
        &root,
        "web/package.json",
        "{\"name\":\"web\",\"dependencies\":{}}\n",
    );
    write(
        &root,
        "web/src/a.ts",
        "import { b } from './b';\nexport function a(): number {\n  const x = 1;\n  const y = 2;\n  return b() + x + y;\n}\n",
    );
    write(
        &root,
        "web/src/b.ts",
        "import { a } from './a';\nexport function b(): number {\n  const x = 1;\n  const y = 2;\n  return a() + x + y;\n}\n",
    );
    write(
        &root,
        "web/src/a.test.ts",
        "import { a } from './a';\ntest('a', () => {\n  expect(a()).toBe(1);\n});\n",
    );
    write(
        &root,
        "web/src/b.test.ts",
        "import { b } from './b';\ntest('b', () => {\n  expect(b()).toBe(1);\n});\n",
    );
    write(
        &root,
        "README.md",
        "# Fixture\n\nSee `src/alpha.rs` and `src/ghost/missing.rs`.\n\n- REQ-1 values add up\n- REQ-2 values are persisted\n",
    );
    root
}

fn clean_fixture() -> PathBuf {
    let root = fixture_root("clean");
    write(
        &root,
        "Cargo.toml",
        "[package]\nname = \"clean\"\nversion = \"0.1.0\"\n",
    );
    write(&root, "src/lib.rs", "pub mod good;\n");
    write(&root, "src/good.rs", &module("", "", true));
    write(
        &root,
        "README.md",
        "# Clean\n\nSee `src/good.rs` for the code.\n",
    );
    root
}

#[test]
fn cyclic_imports_become_findings_with_member_paths() {
    let root = dirty_fixture();
    let result = run(&root, "architecture.core");
    assert!(unavailable_reason(&result).is_none());
    assert_eq!(result.status, ProviderStatus::Failed);
    let findings = located(&result);
    let paths: Vec<&str> = findings.iter().map(|(_, path)| path.as_str()).collect();
    assert!(paths.contains(&"src/alpha.rs"), "{paths:?}");
    assert!(paths.contains(&"web/src/a.ts"), "{paths:?}");
    assert_eq!(findings.len(), 2, "{findings:?}");
    let input = result.details.get("nativeInput").unwrap();
    assert_eq!(input["producer"]["kind"], "self-sourced");
    assert!(!input["projection"]["auditFacts"]["dependencyEdges"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn doc_citing_a_missing_path_is_located_at_the_doc() {
    let root = dirty_fixture();
    let result = run(&root, "docs.contract");
    let findings = located(&result);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].1, "README.md");
    let evidence = &result.details["findingEvidence"][&findings[0].0];
    assert_eq!(evidence["cited"], "src/ghost/missing.rs");
}

#[test]
fn source_without_a_test_is_reported_and_tested_sources_are_not() {
    let root = dirty_fixture();
    let result = run(&root, "test-quality.core");
    let findings = located(&result);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].1, "src/untested.rs");
}

#[test]
fn undelivered_requirement_is_reported() {
    let root = dirty_fixture();
    let result = run(&root, "requirements.traceability");
    let ids: Vec<String> = located(&result).into_iter().map(|(id, _)| id).collect();
    assert!(
        ids.contains(&"requirements.traceability:REQ-2".to_owned()),
        "{ids:?}"
    );
}

#[test]
fn providers_without_derivable_input_stay_unavailable_with_a_specific_reason() {
    let root = dirty_fixture();
    for (id, prefix) in [
        (
            "compatibility.core",
            "compatibility-observations-not-derivable",
        ),
        ("framework.backend", "no-backend-framework-detected"),
        ("framework.frontend", "no-frontend-framework-detected"),
        ("framework.data", "no-data-model-files-detected"),
    ] {
        let result = run(&root, id);
        let reason = unavailable_reason(&result).unwrap_or_else(|| panic!("{id} not unavailable"));
        assert!(reason.starts_with(prefix), "{id}: {reason}");
        assert!(!result.complete);
    }
}

#[test]
fn clean_fixture_produces_no_findings() {
    let root = clean_fixture();
    for id in ["architecture.core", "docs.contract", "test-quality.core"] {
        let result = run(&root, id);
        assert!(unavailable_reason(&result).is_none(), "{id}");
        assert!(result.findings.is_empty(), "{id}: {:?}", located(&result));
        assert!(result.complete, "{id}: {:?}", result.coverage_gaps);
        let coverage = result.coverage.as_ref().unwrap();
        assert_eq!(coverage.examined, coverage.expected, "{id}");
    }
    let requirements = run(&root, "requirements.traceability");
    assert_eq!(
        unavailable_reason(&requirements),
        Some("no-requirement-ids-declared-in-docs")
    );
}

#[test]
fn unreadable_denominator_files_become_coverage_gaps() {
    let root = clean_fixture();
    let inv = inventory(&root);
    // Content drift after the inventory was frozen is a gap, never a silent read.
    write(&root, "src/good.rs", "pub fn changed() {}\n");
    let result = NativeProviderRegistry::new(&root)
        .execute(&provider("docs.contract"), &inv)
        .unwrap();
    assert!(!result.complete);
    assert!(
        result
            .coverage_gaps
            .iter()
            .any(|gap| gap == "producer-skipped:src/good.rs:drift"),
        "{:?}",
        result.coverage_gaps
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert!(coverage.examined < coverage.expected);
}

#[test]
fn host_injected_input_keeps_precedence() {
    let root = dirty_fixture();
    let mut injected = provider("architecture.core");
    let input = json!({"projection":{"auditFacts":{"dependencyEdges":[{"from":"x","to":"y"}]}}});
    injected.configuration.insert("input".into(), input.clone());
    let result = NativeProviderRegistry::new(&root)
        .execute(&injected, &inventory(&root))
        .unwrap();
    assert!(unavailable_reason(&result).is_none());
    assert!(result.findings.is_empty());
    assert_eq!(result.details.get("nativeInput"), Some(&input));
}
