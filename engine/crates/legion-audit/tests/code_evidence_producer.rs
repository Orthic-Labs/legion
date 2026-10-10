//! The `code.*` providers source their own evidence from the frozen
//! denominator. No test here depends on any external tool being installed.
use legion_audit::{
    native_providers::code::{evidence::EvidenceLimits, ProviderExecutorAdapter},
    AuditProvider, InventoryEntry, InventoryEnvelope, ProviderExecutor, ProviderKind,
};
use legion_contracts::{ProviderResult, ProviderStatus};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn fixture(files: &[(&str, &str)]) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-code-evidence-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    for (path, body) in files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, body).unwrap();
    }
    root
}

fn entry(root: &Path, path: &str) -> InventoryEntry {
    let digest = fs::read(root.join(path))
        .ok()
        .map(|bytes| format!("sha256:{}", hex::encode(Sha256::digest(bytes))));
    InventoryEntry {
        path: path.into(),
        symbols: Vec::new(),
        dependencies: Vec::new(),
        package_scripts: Vec::new(),
        source_file: true,
        digest,
    }
}

fn inventory(root: &Path, paths: &[&str]) -> InventoryEnvelope {
    InventoryEnvelope::new(
        "code-evidence",
        "generation",
        paths.iter().map(|path| entry(root, path)).collect(),
    )
    .unwrap()
}

fn provider(id: &str) -> AuditProvider {
    AuditProvider {
        id: id.into(),
        version: "1.0.0".into(),
        role: "diagnose".into(),
        phase: "p1".into(),
        lens_ids: Vec::new(),
        dependencies: Vec::new(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([("selector".into(), json!({"op": "always"}))]),
        bounds: BTreeMap::new(),
        clean_claim: "evidence-only".into(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: false,
    }
}

/// `rule@path:line` for every finding, with the authority maps cross-checked.
fn located(result: &ProviderResult) -> BTreeSet<String> {
    let evidence = result.details["findingEvidence"].as_object().unwrap();
    let locations = result.details["findingLocations"].as_object().unwrap();
    assert_eq!(evidence.len(), result.findings.len());
    result
        .findings
        .iter()
        .map(|finding| {
            let item = &evidence[finding.id.as_str()];
            let at = locations[finding.id.as_str()][0].as_str().unwrap();
            assert_eq!(
                at,
                format!("{}:{}", item["path"].as_str().unwrap(), item["line"])
            );
            format!("{}@{at}", item["ruleId"].as_str().unwrap())
        })
        .collect()
}

const DEFECT_FILES: &[(&str, &str)] = &[
    (
        "src/lib.rs",
        "// TODO: remove the shim\nfn run() {\n    compute().ok();\n    dbg!(1);\n}\n",
    ),
    (
        "web/app.js",
        "function load() {\n  try { risky(); } catch (e) {}\n  debugger;\n}\n",
    ),
    (
        "tools/job.py",
        "def job():\n    try:\n        work()\n    except:\n        pass\n",
    ),
    ("svc/main.go", "package main\nfunc f() {\n    _ = g()\n}\n"),
    (
        "a/One.java",
        "class One {\n  int runOne() {\n    int total = computeTotal(order, rates);\n    int tax = computeTax(total, region);\n    int fee = computeFee(total, tax, plan);\n    int sum = total + tax + fee - discount;\n    audit.record(order, sum, region, plan);\n    return finalizeInvoice(order, sum, audit);\n  }\n}\n",
    ),
    (
        "a/Two.java",
        "class Two {\n  int runTwo() {\n    int total = computeTotal(order, rates);\n    int tax = computeTax(total, region);\n    int fee = computeFee(total, tax, plan);\n    int sum = total + tax + fee - discount;\n    audit.record(order, sum, region, plan);\n    return finalizeInvoice(order, sum, audit);\n  }\n}\n",
    ),
    ("README.md", "# readme\n"),
];

const DEFECT_PATHS: &[&str] = &[
    "README.md",
    "a/One.java",
    "a/Two.java",
    "src/lib.rs",
    "svc/main.go",
    "tools/job.py",
    "web/app.js",
];

fn run(root: &Path, paths: &[&str], id: &str) -> ProviderResult {
    ProviderExecutorAdapter::new()
        .with_root(root)
        .execute(&provider(id), &inventory(root, paths))
        .unwrap()
}

#[test]
fn planted_defects_are_found_with_exact_locations_and_counts() {
    let root = fixture(DEFECT_FILES);
    let cases: &[(&str, &[&str], u64)] = &[
        (
            "code.rust",
            &[
                "debt-marker@src/lib.rs:1",
                "error-swallowed@src/lib.rs:3",
                "debug-leftover@src/lib.rs:4",
            ],
            1,
        ),
        (
            "code.javascript",
            &["empty-catch@web/app.js:2", "debug-leftover@web/app.js:3"],
            1,
        ),
        (
            "code.python",
            &[
                "bare-except@tools/job.py:4",
                "swallowed-exception@tools/job.py:4",
            ],
            1,
        ),
        ("code.go", &["ignored-error@svc/main.go:3"], 1),
        ("code.jvm", &["duplicate-block@a/Two.java:3"], 2),
    ];
    for (id, expected, files) in cases {
        let result = run(&root, DEFECT_PATHS, id);
        assert_eq!(
            located(&result),
            expected
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<String>>(),
            "{id}"
        );
        let coverage = result.coverage.as_ref().unwrap();
        assert_eq!(
            (coverage.expected, coverage.examined),
            (DEFECT_PATHS.len() as u64, *files),
            "{id}: expected is the frozen denominator count"
        );
        assert_eq!(
            coverage.denominator_digest,
            inventory(&root, DEFECT_PATHS).digest
        );
        assert!(
            !result.complete,
            "{id}: no tool receipts, so never complete"
        );
        assert_eq!(result.status, ProviderStatus::Partial);
        assert_eq!(
            result.details["nativeAnalysis"]["denominator"]["examined"],
            json!(files)
        );
        result.validate().unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn clean_fixture_yields_no_findings_and_typed_tool_gaps() {
    let root = fixture(&[(
        "src/lib.rs",
        "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n",
    )]);
    let result = run(&root, &["src/lib.rs"], "code.rust");
    assert!(result.findings.is_empty());
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 1));
    assert!(!result.complete);
    for tool in ["metadata", "check", "lint", "test", "dependency"] {
        let missing = format!("unavailable:tool-missing:{tool}");
        let unrun = format!("unavailable:tool-not-run:{tool}");
        assert!(
            result.coverage_gaps.contains(&missing) || result.coverage_gaps.contains(&unrun),
            "{tool} must be a typed gap, never a pass: {:?}",
            result.coverage_gaps
        );
    }
    assert!(!result
        .coverage_gaps
        .iter()
        .any(|gap| gap.contains("file-skipped")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unread_files_are_named_gaps_and_never_counted_as_examined() {
    let root = fixture(&[
        ("src/a.rs", "pub fn a() {}\n"),
        (
            "src/big.rs",
            &"// padding line to exceed the cap\n".repeat(40),
        ),
        ("src/b.rs", "pub fn b() {}\n"),
    ]);
    let inv = inventory(
        &root,
        &["src/a.rs", "src/b.rs", "src/big.rs", "src/gone.rs"],
    );
    let adapter = ProviderExecutorAdapter::new()
        .with_root(&root)
        .with_limits(EvidenceLimits {
            max_file_bytes: 200,
            ..EvidenceLimits::default()
        });
    let result = adapter.execute(&provider("code.rust"), &inv).unwrap();
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (4, 2));
    assert!(result
        .coverage_gaps
        .contains(&"code.rust:file-skipped:file-size-cap:src/big.rs".to_string()));
    assert!(result
        .coverage_gaps
        .contains(&"code.rust:file-skipped:missing:src/gone.rs".to_string()));
    assert!(!result.complete);

    // Total cap: only the first file fits, the rest are named skips.
    let adapter = ProviderExecutorAdapter::new()
        .with_root(&root)
        .with_limits(EvidenceLimits {
            max_total_bytes: 14,
            ..EvidenceLimits::default()
        });
    let result = adapter.execute(&provider("code.rust"), &inv).unwrap();
    assert_eq!(result.coverage.as_ref().unwrap().examined, 1);
    assert!(result
        .coverage_gaps
        .contains(&"code.rust:file-skipped:total-size-cap:src/b.rs".to_string()));

    // A file that changed after inventory is not examined.
    fs::write(root.join("src/a.rs"), "pub fn a() { /* TODO */ }\n").unwrap();
    let result = adapter_for(&root)
        .execute(&provider("code.rust"), &inv)
        .unwrap();
    assert!(result
        .coverage_gaps
        .contains(&"code.rust:file-skipped:changed-since-inventory:src/a.rs".to_string()));
    assert!(result.findings.is_empty());
    fs::remove_dir_all(root).unwrap();
}

fn adapter_for(root: &Path) -> ProviderExecutorAdapter {
    ProviderExecutorAdapter::new().with_root(root)
}

#[test]
fn host_injected_input_takes_precedence_and_is_not_replaced() {
    let root = fixture(DEFECT_FILES);
    let inv = inventory(&root, DEFECT_PATHS);

    let injected = json!({"files": [{"path": "src/lib.rs"}]});
    let via_builder = ProviderExecutorAdapter::new()
        .with_root(&root)
        .with_input("code.rust", injected.clone())
        .execute(&provider("code.rust"), &inv)
        .unwrap();
    let mut configured = provider("code.rust");
    configured.configuration.insert("input".into(), injected);
    let via_configuration = adapter_for(&root).execute(&configured, &inv).unwrap();

    for result in [via_builder, via_configuration] {
        assert!(result.findings.is_empty(), "injected input is not re-read");
        assert!(!result.details.contains_key("nativeProducer"));
        assert!(result
            .coverage_gaps
            .contains(&"unavailable:tool-evidence-not-produced:code.rust".to_string()));
        assert_eq!(
            result.coverage.as_ref().unwrap().expected,
            inv.entries.len() as u64
        );
        assert!(!result.complete);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn long_tail_reads_unclaimed_source_files() {
    let root = fixture(&[
        ("lib/tool.lua", "-- helper\n-- TODO: port this\nreturn 1\n"),
        ("src/lib.rs", "pub fn a() {}\n"),
    ]);
    let result = run(&root, &["lib/tool.lua", "src/lib.rs"], "code.long-tail");
    assert_eq!(
        located(&result),
        BTreeSet::from(["debt-marker@lib/tool.lua:2".to_string()])
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (2, 1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn language_with_no_files_is_a_denominator_gap_not_a_pass() {
    let root = fixture(&[("README.md", "# readme\n")]);
    let result = run(&root, &["README.md"], "code.python");
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!((coverage.expected, coverage.examined), (1, 0));
    assert!(!result.complete);
    assert!(result.findings.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn frozen_count_differing_from_language_count_is_valid_and_not_complete() {
    let root = fixture(DEFECT_FILES);
    let inv = inventory(&root, DEFECT_PATHS);
    // The plan recorded a denominator count and digest at freeze time.
    let mut planned = provider("code.rust");
    planned
        .configuration
        .insert("denominatorCount".into(), json!(DEFECT_PATHS.len()));
    planned
        .configuration
        .insert("denominatorDigest".into(), json!(inv.digest.clone()));
    let result = adapter_for(&root).execute(&planned, &inv).unwrap();
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.expected, DEFECT_PATHS.len() as u64);
    assert_eq!(coverage.examined, 1, "only the one Rust file was read");
    assert_eq!(coverage.denominator_digest, inv.digest);
    assert!(!result.complete);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("code.rust:selection-narrower-than-denominator:1of7")));
    assert_eq!(result.findings.len(), 3, "findings are preserved");
    result.validate().unwrap();
    fs::remove_dir_all(root).unwrap();
}
