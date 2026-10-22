//! Constructed planted & clean controls for native `code.*` finding output.
//! These measure the self-sourced file heuristics; analyzer tool gaps remain
//! explicit and prevent whole-provider qualification.

#[path = "support/accuracy_receipt.rs"]
mod accuracy_receipt;

use accuracy_receipt::CaseObservation;
use legion_audit::{
    execute, AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const KEY: &[u8] = b"code-provider-accuracy-fixture-key";
const PROVIDER_IDS: [&str; 7] = [
    "code.dotnet",
    "code.javascript",
    "code.jvm",
    "code.long-tail",
    "code.mobile",
    "code.python",
    "code.rust",
];
const BINDING_FIXTURE: &str = "engine/crates/legion-audit/tests/code_provider_accuracy.rs";

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Control {
    provider: &'static str,
    positive_path: &'static str,
    positive_source: &'static str,
    // Literal rule/path/line expectations, authored from the shipped rules.
    expected: &'static [&'static str],
    clean_path: &'static str,
    clean_source: &'static str,
}

const CONTROLS: [Control; 7] = [
    Control {
        provider: "code.dotnet",
        positive_path: "src/Worker.cs",
        positive_source: "class Worker {\n    void Run() { try { Work(); } catch {} }\n}\n",
        expected: &["empty-catch@src/Worker.cs:2"],
        clean_path: "src/Worker.cs",
        clean_source: "class Worker {\n    void Run() { Work(); }\n}\n",
    },
    Control {
        provider: "code.javascript",
        positive_path: "src/worker.js",
        positive_source: "function run() {\n  debugger;\n}\n",
        expected: &["debug-leftover@src/worker.js:2"],
        clean_path: "src/worker.js",
        clean_source: "function run() {\n  return true;\n}\n",
    },
    Control {
        provider: "code.jvm",
        positive_path: "src/Worker.java",
        positive_source:
            "class Worker {\n  void run() {\n    System.out.print(\"trace\");\n  }\n}\n",
        expected: &["debug-leftover@src/Worker.java:3"],
        clean_path: "src/Worker.java",
        clean_source: "class Worker {\n  void run() {\n    work();\n  }\n}\n",
    },
    Control {
        provider: "code.long-tail",
        positive_path: "scripts/worker.sh",
        positive_source: "#!/bin/sh\n# TODO: remove compatibility shim\nexit 0\n",
        expected: &["debt-marker@scripts/worker.sh:2"],
        clean_path: "scripts/worker.sh",
        clean_source: "#!/bin/sh\n# compatibility helper\nexit 0\n",
    },
    Control {
        provider: "code.mobile",
        positive_path: "Sources/Worker.swift",
        positive_source: "import Foundation\nfunc run() {\n    NSLog(\"trace\")\n}\n",
        expected: &["debug-leftover@Sources/Worker.swift:3"],
        clean_path: "Sources/Worker.swift",
        clean_source: "import Foundation\nfunc run() {\n    work()\n}\n",
    },
    Control {
        provider: "code.python",
        positive_path: "src/worker.py",
        positive_source: "def run():\n    try:\n        work()\n    except:\n        pass\n",
        expected: &[
            "bare-except@src/worker.py:4",
            "swallowed-exception@src/worker.py:4",
        ],
        clean_path: "src/worker.py",
        clean_source: "def run():\n    return True\n",
    },
    Control {
        provider: "code.rust",
        positive_path: "src/lib.rs",
        positive_source: "// TODO: remove shim\nfn run() {\n    dbg!(1);\n}\n",
        expected: &["debt-marker@src/lib.rs:1", "debug-leftover@src/lib.rs:3"],
        clean_path: "src/lib.rs",
        clean_source: "pub fn add(left: u32, right: u32) -> u32 {\n    left + right\n}\n",
    },
];

fn registry_spec(id: &str) -> ProviderSpec {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let item = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("{id} missing from shipped registry"));
    serde_json::from_value(item.clone()).unwrap()
}

fn fixture_root(provider: &str, case: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-code-accuracy-{}-{provider}-{case}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn write(root: &Path, path: &str, source: &str) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, source).unwrap();
}

fn observe(
    control: &Control,
    case_id: &str,
    path: &str,
    source: &str,
) -> (CaseObservation, Vec<String>) {
    let root = fixture_root(control.provider, case_id);
    write(&root, path, source);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(case_id)
        .unwrap();
    let spec = registry_spec(control.provider);
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let report = execute(&plan, &inventory, &NativeProviderRegistry::new(&root)).unwrap();
    let result = &report
        .results
        .iter()
        .find(|item| item.provider == control.provider)
        .unwrap_or_else(|| panic!("{} result absent", control.provider))
        .result;

    assert!(
        result.applicable,
        "{}:{case_id} is inapplicable",
        control.provider
    );
    let coverage = result
        .coverage
        .as_ref()
        .expect("applicable result has coverage");
    assert_eq!(
        coverage.denominator_digest, inventory.digest,
        "{}:{case_id}",
        control.provider
    );
    assert_eq!(
        coverage.expected,
        inventory.entries.len() as u64,
        "{}:{case_id}",
        control.provider
    );
    assert_eq!(
        coverage.examined, coverage.expected,
        "{}:{case_id} did not read full frozen denominator",
        control.provider
    );
    assert!(
        !result.coverage_gaps.iter().any(|gap| {
            gap.contains("file-skipped:")
                || gap.contains("findings-truncated:")
                || gap.contains("duplicate-detection-truncated")
        }),
        "{}:{case_id} has a file-evidence gap: {:?}",
        control.provider,
        result.coverage_gaps
    );

    let evidence = result.details["findingEvidence"].as_object().unwrap();
    let locations = result.details["findingLocations"].as_object().unwrap();
    let actual = result
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
        .collect();
    let gaps = result
        .coverage_gaps
        .iter()
        .map(|gap| format!("{case_id}:{gap}"))
        .collect();
    fs::remove_dir_all(root).unwrap();
    (
        CaseObservation {
            id: case_id.into(),
            expected: if case_id.ends_with("positive") {
                control.expected.iter().map(|item| (*item).into()).collect()
            } else {
                Vec::new()
            },
            actual,
        },
        gaps,
    )
}

#[test]
fn file_only_provider_accuracy_code() {
    let ids = CONTROLS
        .iter()
        .map(|control| control.provider)
        .collect::<Vec<_>>();
    assert_eq!(ids.as_slice(), &PROVIDER_IDS);
    for control in &CONTROLS {
        let (positive, mut gaps) = observe(
            control,
            &format!("{}-positive", control.provider),
            control.positive_path,
            control.positive_source,
        );
        let (clean, clean_gaps) = observe(
            control,
            &format!("{}-clean", control.provider),
            control.clean_path,
            control.clean_source,
        );
        gaps.extend(clean_gaps);
        accuracy_receipt::emit_partial(
            control.provider,
            "finding",
            &[positive, clean],
            &[BINDING_FIXTURE],
            &gaps,
        );
    }
}
