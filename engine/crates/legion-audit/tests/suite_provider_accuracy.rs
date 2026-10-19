//! Measured planted/clean file-only output for the legacy data,
//! infrastructure, and framework candidate suites, plus accessibility finding
//! output. Accessibility identities bind the intended rule, path, and line;
//! emitted IDs and locations are measured without inferring from the fixture.

#[path = "support/accuracy_receipt.rs"]
mod accuracy_receipt;

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use accuracy_receipt::CaseObservation;
use legion_audit::{
    execute, AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::{ProviderResult, ProviderSpec};
use serde_json::Value;
use sha2::{Digest, Sha256};

const KEY: &[u8] = b"suite-provider-accuracy-fixture-key";
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture(label: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-suite-provider-accuracy-{label}-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    for (path, text) in files {
        let target = root.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, text).unwrap();
    }
    fs::canonicalize(root).unwrap()
}

fn registry_spec(id: &str) -> ProviderSpec {
    let registry_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    );
    let registry: Value = serde_json::from_slice(&fs::read(registry_path).unwrap()).unwrap();
    serde_json::from_value(
        registry["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|provider| provider["id"] == id)
            .unwrap_or_else(|| panic!("{id} is absent from shipped registry"))
            .clone(),
    )
    .unwrap()
}

fn run_file_only(id: &str, root: &Path) -> ProviderResult {
    let inventory = FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("suite-accuracy")
        .unwrap();
    let plan = AuditPlan::compile_with_root(Some(root), &inventory, &[registry_spec(id)])
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    assert!(plan.provider(id).is_some(), "{id} must be in frozen plan");
    let execution = execute(&plan, &inventory, &NativeProviderRegistry::new(root)).unwrap();
    assert_eq!(execution.planned_providers, vec![id]);
    let provider_execution = execution
        .results
        .iter()
        .find(|result| result.provider == id)
        .unwrap_or_else(|| panic!("missing execution result for {id}"));
    assert!(!provider_execution.skipped, "{id} was skipped");
    let result = &provider_execution.result;
    assert!(result.applicable, "{id} must be applicable");
    assert!(
        result.complete,
        "{id} is incomplete: {:?}",
        result.coverage_gaps
    );
    assert!(
        result.coverage_gaps.is_empty(),
        "{id}: {:?}",
        result.coverage_gaps
    );
    let coverage = result.coverage.as_ref().expect("frozen coverage");
    assert!(coverage.expected > 0, "{id} requires a nonzero denominator");
    assert_eq!(
        coverage.examined, coverage.expected,
        "{id} must cover its frozen denominator"
    );
    assert!(coverage.gaps.is_empty(), "{id}: {:?}", coverage.gaps);
    result.clone()
}

fn candidate_labels(result: &ProviderResult) -> Vec<String> {
    assert!(
        result.findings.is_empty(),
        "candidate suite must not promote candidates"
    );
    let mut labels: Vec<String> = result.details["candidates"]
        .as_array()
        .expect("candidate output array")
        .iter()
        .map(|candidate| {
            format!(
                "{}|{}|{}",
                candidate["ruleId"].as_str().unwrap(),
                candidate["file"].as_str().unwrap(),
                candidate["line"].as_u64().unwrap()
            )
        })
        .collect();
    labels.sort();
    labels
}

fn finding_labels(result: &ProviderResult) -> Vec<String> {
    let locations = &result.details["findingLocations"];
    let mut labels = Vec::new();
    for finding in &result.findings {
        let id = finding.id.to_string();
        for location in locations[&id].as_array().expect("finding locations") {
            labels.push(format!("{id}|{}", location.as_str().unwrap()));
        }
    }
    labels.sort();
    labels
}

/// Accessibility finding IDs are stable hashes of rule, path, and line.
/// Build expected IDs only from the planted rule identity, never provider output.
fn expected_finding(rule: &str, path: &str, line: usize) -> String {
    let identity = format!("{rule}\0{path}\0{line}");
    let hex: String = Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let id = format!("sha256:{hex}");
    format!("{id}|{path}:{line}")
}

fn observe(
    id: &str,
    planted: &[(&str, &str)],
    clean: &[(&str, &str)],
) -> (Vec<String>, Vec<String>) {
    let planted_root = fixture("planted", planted);
    let planted_result = run_file_only(id, &planted_root);
    let planted_actual = candidate_labels(&planted_result);
    fs::remove_dir_all(planted_root).unwrap();

    let clean_root = fixture("clean", clean);
    let clean_result = run_file_only(id, &clean_root);
    let clean_actual = candidate_labels(&clean_result);
    fs::remove_dir_all(clean_root).unwrap();
    (planted_actual, clean_actual)
}

fn observe_findings(
    id: &str,
    planted: &[(&str, &str)],
    clean: &[(&str, &str)],
) -> (Vec<String>, Vec<String>) {
    let planted_root = fixture("planted", planted);
    let planted_result = run_file_only(id, &planted_root);
    let planted_actual = finding_labels(&planted_result);
    fs::remove_dir_all(planted_root).unwrap();

    let clean_root = fixture("clean", clean);
    let clean_result = run_file_only(id, &clean_root);
    let clean_actual = finding_labels(&clean_result);
    fs::remove_dir_all(clean_root).unwrap();
    (planted_actual, clean_actual)
}

#[test]
fn file_only_provider_accuracy_suites() {
    let (planted, clean) = observe(
        "legacy.data.internal-suite",
        &[(
            "db/001.sql",
            "ALTER TABLE users ADD COLUMN age INT NOT NULL;\n",
        )],
        &[(
            "db/schema.sql",
            "CREATE TABLE users (id INTEGER PRIMARY KEY);\n",
        )],
    );
    accuracy_receipt::emit(
        "legacy.data.internal-suite",
        "candidate",
        &[
            CaseObservation {
                id: "data.planted".into(),
                expected: vec!["data.not-null-migration|db/001.sql|1".into()],
                actual: planted,
            },
            CaseObservation {
                id: "data.clean".into(),
                expected: vec![],
                actual: clean,
            },
        ],
        &["engine/crates/legion-audit/tests/suite_provider_accuracy.rs"],
    );

    let (planted, clean) = observe(
        "legacy.infrastructure.internal-suite",
        &[("Dockerfile", "FROM node:latest\n")],
        &[("Dockerfile", "FROM node:22\nUSER node\n")],
    );
    accuracy_receipt::emit(
        "legacy.infrastructure.internal-suite",
        "candidate",
        &[
            CaseObservation {
                id: "infrastructure.planted".into(),
                expected: vec![
                    "container.latest-tag|Dockerfile|1".into(),
                    "container-root-user|Dockerfile|1".into(),
                ],
                actual: planted,
            },
            CaseObservation {
                id: "infrastructure.clean".into(),
                expected: vec![],
                actual: clean,
            },
        ],
        &["engine/crates/legion-audit/tests/suite_provider_accuracy.rs"],
    );

    let (planted, clean) = observe(
        "legacy.framework.major-suite",
        &[
            ("package.json", "{\"dependencies\":{\"next\":\"14.0.0\"}}\n"),
            (
                "app/page.js",
                "export default () => <div dangerouslySetInnerHTML={{ __html: input }} />;\n",
            ),
        ],
        &[
            ("package.json", "{\"dependencies\":{\"next\":\"14.0.0\"}}\n"),
            (
                "app/page.js",
                "export default () => <main>Welcome</main>;\n",
            ),
        ],
    );
    accuracy_receipt::emit(
        "legacy.framework.major-suite",
        "candidate",
        &[
            CaseObservation {
                id: "framework.planted".into(),
                expected: vec!["next-unsafe-html|app/page.js|1".into()],
                actual: planted,
            },
            CaseObservation {
                id: "framework.clean".into(),
                expected: vec![],
                actual: clean,
            },
        ],
        &["engine/crates/legion-audit/tests/suite_provider_accuracy.rs"],
    );

    let (planted, clean) = observe_findings(
        "legacy.accessibility.internal-suite",
        &[("src/page.html", "<img src=\"/logo.svg\">\n")],
        &[(
            "src/page.html",
            "<img src=\"/logo.svg\" alt=\"Company logo\">\n",
        )],
    );
    accuracy_receipt::emit(
        "legacy.accessibility.internal-suite",
        "finding",
        &[
            CaseObservation {
                id: "accessibility.planted".into(),
                expected: vec![expected_finding("a11y.image-alt", "src/page.html", 1)],
                actual: planted,
            },
            CaseObservation {
                id: "accessibility.clean".into(),
                expected: vec![],
                actual: clean,
            },
        ],
        &["engine/crates/legion-audit/tests/suite_provider_accuracy.rs"],
    );
}
