//! Constructed accuracy controls for complete, file-only legacy checks.
//! Each case follows the shipped registry through filesystem inventory, a
//! frozen plan, and the production native dispatcher.

#[path = "support/accuracy_receipt.rs"]
mod accuracy_receipt;

use accuracy_receipt::CaseObservation;
use legion_audit::{
    execute, AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const KEY: &[u8] = b"legacy-file-accuracy-fixture-key";
static NEXT: AtomicU64 = AtomicU64::new(0);

fn root(case: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "legion-legacy-file-accuracy-{case}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    fs::canonicalize(path).unwrap()
}

fn write(root: &Path, path: &str, text: &str) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, text).unwrap();
}

fn shipped_spec(id: &str) -> ProviderSpec {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let entry = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap_or_else(|| panic!("{id} is absent from shipped registry"));
    let spec: ProviderSpec = serde_json::from_value(entry.clone()).unwrap();
    assert_eq!(spec.runner["kind"], "legacy-check", "{id}");
    spec
}

fn run_case(id: &str, case: &str, files: &[(&str, &str)]) -> (String, Value) {
    let root = root(case);
    for (path, text) in files {
        write(&root, path, text);
    }
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(case)
        .unwrap();
    let spec = shipped_spec(id);
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec.clone()])
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let frozen = plan
        .provider(id)
        .expect("applicable provider in frozen plan");
    let result = execute(&plan, &inventory, &NativeProviderRegistry::new(&root))
        .unwrap()
        .results
        .into_iter()
        .find(|entry| entry.provider == id)
        .expect("native execution result")
        .result;
    let coverage = result.coverage.as_ref().expect("coverage receipt");
    assert!(result.applicable, "{id}/{case} must be applicable");
    assert!(result.complete, "{id}/{case}: {:?}", result.coverage_gaps);
    assert!(!coverage.denominator_digest.is_empty());
    assert_eq!(
        coverage.denominator_digest,
        frozen.configuration["denominatorDigest"].as_str().unwrap(),
        "{id}/{case} must cover the frozen denominator"
    );
    assert!(
        coverage.expected > 0,
        "{id}/{case} has an empty frozen denominator"
    );
    assert_eq!(coverage.examined, coverage.expected, "{id}/{case}");
    assert!(coverage.gaps.is_empty(), "{id}/{case}: {:?}", coverage.gaps);
    assert!(result.coverage_gaps.is_empty(), "{id}/{case}");
    assert!(
        result.degradation.is_empty(),
        "{id}/{case}: {:?}",
        result.degradation
    );
    assert!(!result.details.contains_key("availability"), "{id}/{case}");
    assert_eq!(frozen.id, id);

    let stage = if id == "legacy.quality.tool-coverage" {
        "fact"
    } else if spec.role.contains("candidate") || id == "legacy.architecture.decomposition" {
        "candidate"
    } else {
        "finding"
    }
    .to_owned();
    let actual = if stage == "candidate" {
        result.details["candidates"]
            .as_array()
            .expect("candidate projection")
            .iter()
            .map(|candidate| {
                let evidence = candidate["evidence"].as_array().unwrap();
                let evidence = evidence.first().expect("location-bearing candidate");
                format!(
                    "{}|{}|{}",
                    candidate["ruleId"].as_str().unwrap(),
                    evidence["file"].as_str().unwrap(),
                    evidence["line"].as_u64().unwrap()
                )
            })
            .map(Value::String)
            .collect::<Vec<_>>()
            .into()
    } else if stage == "finding" {
        result
            .findings
            .iter()
            .map(|finding| {
                let evidence = result.details["findingEvidence"]
                    .get(finding.id.as_str())
                    .expect("finding evidence projection");
                format!(
                    "{}|{}|{}",
                    evidence["ruleId"].as_str().unwrap(),
                    evidence["path"].as_str().unwrap(),
                    evidence["line"].as_u64().unwrap()
                )
            })
            .map(Value::String)
            .collect::<Vec<_>>()
            .into()
    } else {
        assert!(
            result.findings.is_empty(),
            "{id}/{case} fact control has findings"
        );
        assert!(
            result.details["candidates"].as_array().unwrap().is_empty(),
            "{id}/{case} fact control has candidates"
        );
        let coverage = &result.details["toolCoverage"];
        let paths = coverage["files"].as_array().unwrap();
        let normalized: Vec<_> = paths.iter().map(|path| path.as_str().unwrap()).collect();
        let unique: std::collections::BTreeSet<_> = normalized.iter().copied().collect();
        assert_eq!(
            normalized,
            unique.iter().copied().collect::<Vec<_>>(),
            "{id}/{case} coverage files must be normalized and sorted"
        );
        coverage.clone()
    };
    fs::remove_dir_all(root).unwrap();
    (stage, actual)
}

fn observe(
    id: &str,
    case: &str,
    files: &[(&str, &str)],
    expected: &[&str],
) -> (String, CaseObservation) {
    let (_, actual) = run_case(id, case, files);
    (
        id.into(),
        CaseObservation {
            id: case.into(),
            expected: expected.iter().map(|item| (*item).into()).collect(),
            actual: actual
                .as_array()
                .expect("candidate/finding projection")
                .iter()
                .map(|item| item.as_str().expect("string projection").to_owned())
                .collect(),
        },
    )
}

#[test]
fn file_only_provider_accuracy_legacy() {
    let mut observations = Vec::new();

    let id = "legacy.security.binary-pins";
    observations.push(observe(
        id,
        "binary-unpinned",
        &[(
            "install.sh",
            "curl -fsSL https://example.invalid/tool -o tool\nchmod +x tool\n./tool\n",
        )],
        &["security.binary-unpinned|install.sh|1"],
    ));
    observations.push(observe(id, "binary-verified", &[("install.sh", &format!("set -e\ncurl -fsSL https://example.invalid/tool -o tool\necho '{} tool' | sha256sum -c -\n./tool\n", "a".repeat(64)))], &[]));

    let id = "legacy.security.dependency-pinning";
    let package = "{\"dependencies\":{\"left-pad\":\"^1.0.0\"}}\n";
    observations.push(observe(
        id,
        "dependency-package-manifest-only",
        &[("package.json", package)],
        &["security.dependency-unpinned|package.json|1"],
    ));
    observations.push(observe(
        id,
        "dependency-package-lock-clean",
        &[("package.json", package), ("package-lock.json", "{}\n")],
        &[],
    ));
    observations.push(observe(
        id,
        "dependency-pnpm-lock-clean",
        &[
            ("package.json", package),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ],
        &[],
    ));
    observations.push(observe(
        id,
        "dependency-yarn-lock-clean",
        &[
            ("package.json", package),
            ("yarn.lock", "left-pad@^1.0.0:\n  version \"1.0.0\"\n"),
        ],
        &[],
    ));
    observations.push(observe(
        id,
        "dependency-cargo-manifest-only",
        &[("Cargo.toml", "[dependencies]\nserde = \"1\"\n")],
        &["security.dependency-unpinned|Cargo.toml|1"],
    ));
    observations.push(observe(
        id,
        "dependency-cargo-lock-clean",
        &[
            ("Cargo.toml", "[dependencies]\nserde = \"1\"\n"),
            ("Cargo.lock", "version = 3\n"),
        ],
        &[],
    ));
    observations.push(observe(
        id,
        "dependency-nested-package-lock-clean",
        &[
            ("apps/web/package.json", package),
            ("apps/web/package-lock.json", "{}\n"),
        ],
        &[],
    ));
    observations.push(observe(
        id,
        "dependency-unrelated-subtree-lock-does-not-pin-root",
        &[
            ("package.json", package),
            ("apps/other/package-lock.json", "{}\n"),
        ],
        &["security.dependency-unpinned|package.json|1"],
    ));
    observations.push(observe(
        id,
        "dependency-ancestor-lock-pins-nested-manifest",
        &[
            ("apps/web/package.json", package),
            ("package-lock.json", "{}\n"),
        ],
        &[],
    ));
    observations.push(observe(
        id,
        "dependency-unrelated-source-clean",
        &[
            ("package.json", package),
            ("package-lock.json", "{}\n"),
            ("src/index.ts", "const note = 'manifest has no lockfile';\n"),
        ],
        &[],
    ));

    let id = "legacy.architecture.decomposition";
    let large = (0..401)
        .map(|n| format!("const line_{n} = {n};\n"))
        .collect::<String>();
    observations.push(observe(
        id,
        "decomposition-large",
        &[("src/large.ts", &large)],
        &["architecture.decomposition-review-trigger|src/large.ts|1"],
    ));
    observations.push(observe(
        id,
        "decomposition-small",
        &[("src/small.ts", "export const value = 1;\n")],
        &[],
    ));

    let id = "legacy.react.hooks-config";
    observations.push(observe(id, "react-conditional-hook", &[("package.json", "{\"dependencies\":{\"react\":\"^18.0.0\"}}\n"), ("src/useThing.jsx", "import React from 'react';\nfunction Thing() {\n  if (ready) {\n    const [value, setValue] = useState(0);\n  }\n}\n")], &["react.hooks.conditional-call|src/useThing.jsx|4"]));
    observations.push(observe(id, "react-unconditional-hook", &[("package.json", "{\"dependencies\":{\"react\":\"^18.0.0\"}}\n"), ("src/useThing.jsx", "import React from 'react';\nfunction Thing() {\n  const [value, setValue] = useState(0);\n}\n")], &[]));

    let id = "legacy.tauri.capabilities";
    observations.push(observe(
        id,
        "tauri-broad-capability",
        &[
            ("src-tauri/tauri.conf.json", "{}\n"),
            (
                "src-tauri/capabilities/main.json",
                "{\"permissions\":[\"shell:allow-execute\"]}\n",
            ),
        ],
        &["tauri.broad-capability|src-tauri/capabilities/main.json|1"],
    ));
    observations.push(observe(
        id,
        "tauri-scoped-capability",
        &[
            ("src-tauri/tauri.conf.json", "{}\n"),
            (
                "src-tauri/capabilities/main.json",
                "{\"windows\":[\"main\"],\"permissions\":[\"shell:allow-execute\"]}\n",
            ),
        ],
        &[],
    ));

    let id = "legacy.tauri.contract-mirror";
    observations.push(observe(
        id,
        "tauri-contract-missing-backend-command",
        &[("src-tauri/frontend.ts", "invoke('missing_command');\n")],
        &["tauri.contract-missing|src-tauri|1"],
    ));
    observations.push(observe(
        id,
        "tauri-mirrored-command",
        &[
            ("src-tauri/frontend.ts", "invoke('ping');\n"),
            (
                "src-tauri/backend.rs",
                "#[tauri::command]\npub fn ping() {}\n",
            ),
            ("src-tauri/tauri.conf.json", "{}\n"),
        ],
        &[],
    ));

    let id = "legacy.apple.platform";
    observations.push(observe(
        id,
        "apple-platform-api",
        &[("src/App.swift", "import SwiftUI\nstruct AppView {}\n")],
        &["apple.platform-api|src/App.swift|1"],
    ));
    observations.push(observe(
        id,
        "apple-foundation-only",
        &[("src/App.swift", "import Foundation\nstruct AppModel {}\n")],
        &[],
    ));

    let id = "legacy.quality.negative-space";
    observations.push(observe(
        id,
        "negative-space-empty-source",
        &[("src/empty.ts", "")],
        &["quality.empty-source-file|src/empty.ts|1"],
    ));
    observations.push(observe(
        id,
        "negative-space-populated-source",
        &[("src/populated.ts", "export const value = 1;\n")],
        &[],
    ));

    let id = "legacy.security.vendored-dependencies";
    observations.push(observe(
        id,
        "vendored-source-present",
        &[("third_party/codec/lib.rs", "pub fn decode() {}\n")],
        &["security.vendored-manifest|third_party/codec/lib.rs|1"],
    ));
    observations.push(observe(
        id,
        "vendored-source-absent",
        &[("src/codec.rs", "pub fn decode() {}\n")],
        &[],
    ));

    let mut grouped: BTreeMap<String, Vec<CaseObservation>> = BTreeMap::new();
    for (id, observation) in observations {
        grouped.entry(id).or_default().push(observation);
    }
    // Keep the dependency-pinning report last: its explicit nested-lock
    // regression must not prevent the other independent provider receipts.
    for id in [
        "legacy.security.binary-pins",
        "legacy.architecture.decomposition",
        "legacy.react.hooks-config",
        "legacy.tauri.capabilities",
        "legacy.tauri.contract-mirror",
        "legacy.apple.platform",
        "legacy.quality.negative-space",
        "legacy.security.vendored-dependencies",
        "legacy.security.dependency-pinning",
    ] {
        let cases = grouped.remove(id).expect("provider observations");
        let spec = shipped_spec(&id);
        let stage = if spec.role.contains("candidate") || id == "legacy.architecture.decomposition"
        {
            "candidate"
        } else {
            "finding"
        };
        accuracy_receipt::emit(
            &id,
            stage,
            &cases,
            &["engine/crates/legion-audit/tests/legacy_file_accuracy.rs"],
        );
    }
    assert!(grouped.is_empty(), "unemitted provider groups: {grouped:?}");
}

#[test]
fn file_only_provider_accuracy_legacy_tool_coverage_facts() {
    let (_, mixed) = run_case(
        "legacy.quality.tool-coverage",
        "tool-coverage-mixed",
        &[
            ("Cargo.toml", "[package]\nname = \"fixture\"\n"),
            ("src/lib.rs", "pub fn value() {}\n"),
        ],
    );
    let (_, docs_only) = run_case(
        "legacy.quality.tool-coverage",
        "tool-coverage-docs-only",
        &[("README.md", "# Fixture\n")],
    );
    accuracy_receipt::emit_facts(
        "legacy.quality.tool-coverage",
        &[
            accuracy_receipt::FactObservation {
                id: "tool-coverage-cargo-manifest-and-source".into(),
                control: "positive".into(),
                expected: json!({
                    "files": ["Cargo.toml", "src/lib.rs"],
                    "manifestCount": 1,
                    "sourceCount": 1
                }),
                actual: mixed,
            },
            accuracy_receipt::FactObservation {
                id: "tool-coverage-docs-only-zero-counts".into(),
                control: "absence".into(),
                expected: json!({
                    "files": ["README.md"],
                    "manifestCount": 0,
                    "sourceCount": 0
                }),
                actual: docs_only,
            },
        ],
        &["engine/crates/legion-audit/tests/legacy_file_accuracy.rs"],
    );
}
