//! Measured output evidence, separate from selection tests & semantic adjudication.
//! Callers must establish applicability, complete frozen coverage & production dispatch.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

pub struct CaseObservation {
    pub id: String,
    pub expected: Vec<String>,
    pub actual: Vec<String>,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

// The workspace enables serde_json/preserve_order. Sort recursively instead
// of depending on object insertion order; Python validates these same bytes.
fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort();
                let mut sorted = serde_json::Map::new();
                for key in keys {
                    sorted.insert(key.clone(), ordered(&object[key]));
                }
                Value::Object(sorted)
            }
            Value::Array(array) => Value::Array(array.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).unwrap()
}

fn bound_file(root: &Path, path: &Path) -> Value {
    let relative = path
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    json!({"path": relative, "digest": digest(&fs::read(path).unwrap())})
}

fn bind_tree(root: &Path, path: &Path, out: &mut Vec<Value>) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        assert!(
            !path.is_symlink(),
            "benchmark source binding refuses symlinks"
        );
        if path.is_dir() {
            bind_tree(root, &path, out);
        } else {
            out.push(bound_file(root, &path));
        }
    }
}

/// Emit one measured, corpus-scoped record; no registry promotion occurs here.
pub fn emit(provider_id: &str, stage: &str, cases: &[CaseObservation], fixture_paths: &[&str]) {
    emit_inner(provider_id, stage, cases, fixture_paths, &[]);
}

/// Accuracy of observed native output cannot discharge missing tool/host coverage.
pub fn emit_partial(
    provider_id: &str,
    stage: &str,
    cases: &[CaseObservation],
    fixture_paths: &[&str],
    gaps: &[String],
) {
    assert!(
        !gaps.is_empty(),
        "partial evidence must name missing coverage"
    );
    emit_inner(provider_id, stage, cases, fixture_paths, gaps);
}

fn emit_inner(
    provider_id: &str,
    stage: &str,
    cases: &[CaseObservation],
    fixture_paths: &[&str],
    gaps: &[String],
) {
    assert!(matches!(stage, "candidate" | "finding"));
    assert!(
        cases.iter().any(|case| !case.expected.is_empty()),
        "positive control required"
    );
    assert!(
        cases.iter().any(|case| case.expected.is_empty()),
        "clean control required"
    );
    let mut ids = BTreeSet::new();
    let (mut tp, mut fp, mut fn_) = (0, 0, 0);
    let records: Vec<Value> = cases
        .iter()
        .map(|case| {
            assert!(ids.insert(&case.id), "duplicate case identity");
            let expected: BTreeSet<_> = case.expected.iter().cloned().collect();
            let actual: BTreeSet<_> = case.actual.iter().cloned().collect();
            assert_eq!(expected.len(), case.expected.len(), "duplicate expectation");
            // Duplicated emissions are false positives, not silently deduplicated away.
            let matched = expected.intersection(&actual).count();
            let extra = actual.difference(&expected).count() + case.actual.len() - actual.len();
            let missed = expected.difference(&actual).count();
            tp += matched;
            fp += extra;
            fn_ += missed;
            json!({"caseId":case.id,"expected":expected,"actual":case.actual,
            "truePositives":matched,"falsePositives":extra,"falseNegatives":missed})
        })
        .collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let registry: Value =
        serde_json::from_slice(&fs::read(root.join("src/registry/providers.json")).unwrap())
            .unwrap();
    let mut spec = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == provider_id)
        .expect("shipped provider")
        .clone();
    // Qualification metadata is excluded to avoid a self-referential digest.
    spec.as_object_mut().unwrap().remove("benchmark");
    let mut implementation = Vec::new();
    // Bind the complete Audit/SDK/contracts/rules implementation, not just adapter entrypoints.
    let implementation_roots = [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "engine/crates/legion-effects/src",
        "src/registry/rules",
        "src/registry/controls",
    ];
    for tree in implementation_roots {
        bind_tree(&root, &root.join(tree), &mut implementation);
    }
    for path in [
        "engine/Cargo.lock",
        "engine/Cargo.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-audit/tests/support/accuracy_receipt.rs",
    ] {
        implementation.push(bound_file(&root, &root.join(path)));
    }
    implementation.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let mut fixtures: Vec<_> = fixture_paths
        .iter()
        .map(|path| bound_file(&root, &root.join(path)))
        .collect();
    fixtures.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let passed = fp == 0 && fn_ == 0;
    // These two providers own artifact ingestion/policy-record validation, not
    // the accuracy or certification of the upstream artifact's producer.
    let measurement_kind = match provider_id {
        "imported.sarif" | "governance.policy" => "adapter-protocol",
        _ => stage,
    };
    let mut result = json!({
        "schema":"legion-file-provider-accuracy/1", "provider":provider_id,
        "providerVersion":spec["providerVersion"], "stage":stage,
        "scope":"constructed planted & clean controls; not a population accuracy estimate",
        "executionPath":"native-sdk-frozen-plan-file-only", "modelCalls":0,
        "coverageState":if gaps.is_empty() {"complete"} else {"partial"},
        "measurementKind":measurement_kind,"measurementStatus":if passed {"pass"} else {"fail"},
        "requiredDependencies":{"productionDispatch":"exercised",
            "positiveControl":"exercised","negativeControl":"exercised",
            "scope":"named corpus; no claim about untested rules",
            "externalExecution":if gaps.is_empty() {"not-required"} else {"missing"}},
        "qualificationEligible":passed && gaps.is_empty(),"coverageGaps":gaps,
        "binding":{"providerSpecDigest":digest(&canonical_bytes(&spec)),
            "implementationDigest":digest(&canonical_bytes(&json!(implementation))),
            "implementationFileCount":implementation.len(),
            "implementationRoots":implementation_roots,"fixtures":fixtures},
        "cases":records,
        "metrics":{"truePositives":tp,"falsePositives":fp,"falseNegatives":fn_,
            "precision":if tp+fp>0 {tp as f64/(tp+fp) as f64} else {0.0},
            "recall":if tp+fn_>0 {tp as f64/(tp+fn_) as f64} else {0.0},
            "positiveCases":cases.iter().filter(|case| !case.expected.is_empty()).count(),
            "cleanCases":cases.iter().filter(|case| case.expected.is_empty()).count()},
        "status":if passed {"pass"} else {"fail"}
    });
    result["qualificationDigest"] = json!(digest(&canonical_bytes(&result)));
    if let Some(dir) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
        let dir = Path::new(&dir);
        fs::create_dir_all(dir).unwrap();
        let name = provider_id.replace('.', "_");
        fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
    }
    println!(
        "FILE_PROVIDER_ACCURACY {}",
        serde_json::to_string(&result).unwrap()
    );
    assert_eq!(
        (fp, fn_),
        (0, 0),
        "{provider_id}: measured false positives/misses"
    );
}
