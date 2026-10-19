//! Measured output evidence, separate from selection tests & semantic adjudication.
//! Callers must establish applicability, complete frozen coverage & production dispatch.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

#[derive(Debug)]
pub struct CaseObservation {
    pub id: String,
    pub expected: Vec<String>,
    pub actual: Vec<String>,
}

#[derive(Debug)]
pub struct OutcomeObservation {
    pub id: String,
    pub expected: String,
    pub actual: String,
    pub expected_gaps: Vec<String>,
    pub actual_gaps: Vec<String>,
}

#[derive(Debug)]
pub struct FactObservation {
    pub id: String,
    /// Explicit control role: `positive` or `absence`.
    pub control: String,
    pub expected: Value,
    pub actual: Value,
}

fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let hex = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
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

fn normalize_fact(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                sorted.insert(key.clone(), normalize_fact(&object[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(array) => Value::Array(array.iter().map(normalize_fact).collect()),
        _ => value.clone(),
    }
}

fn bound_file(root: &Path, path: &Path) -> Value {
    let relative = path
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    json!({"path": relative, "digest": digest(&fs::read(path).unwrap())})
}

// Generated host receipts are runtime evidence, never implementation inputs.
// Match one exact repository-relative directory & lowercase SHA-256 JSON name.
fn generated_session_provenance(relative: &str) -> bool {
    relative
        .strip_prefix("engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/")
        .and_then(|name| name.strip_suffix(".json"))
        .is_some_and(|name| {
            name.len() == 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[test]
fn source_binding_receipt_exclusion_is_exact() {
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    assert!(generated_session_provenance(&format!(
        "{prefix}{}.json",
        "0123456789abcdef".repeat(4)
    )));
    for relative in [
        "engine/crates/legion-audit/src/mod.rs".to_owned(),
        "engine/crates/legion-audit/src/nested/.audit/anything.rs".to_owned(),
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("nested/{prefix}{}.json", "a".repeat(64)),
    ] {
        assert!(
            !generated_session_provenance(&relative),
            "unexpected exclusion: {relative}"
        );
    }
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
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if !generated_session_provenance(&relative) {
                out.push(bound_file(root, &path));
            }
        }
    }
}

/// Bind the shipped provider specification, implementation, and named corpus
/// once for each receipt kind.
fn source_binding(provider_id: &str, fixture_paths: &[&str]) -> (Value, Value) {
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
        "engine/crates/legion-audit/tests",
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
    ] {
        implementation.push(bound_file(&root, &root.join(path)));
    }
    implementation.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let mut fixtures: Vec<_> = fixture_paths
        .iter()
        .map(|path| bound_file(&root, &root.join(path)))
        .collect();
    fixtures.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let binding = json!({
        "providerSpecDigest":digest(&canonical_bytes(&spec)),
        "implementationDigest":digest(&canonical_bytes(&json!(implementation))),
        "implementationFileCount":implementation.len(),
        "implementationRoots":implementation_roots,
        "fixtures":fixtures
    });
    (spec["providerVersion"].clone(), binding)
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

/// Emit measured verifier outcomes. An expected rejection is a successful
/// control when the native path returns the same outcome and gaps.
pub fn emit_outcomes(provider_id: &str, cases: &[OutcomeObservation], fixture_paths: &[&str]) {
    assert!(
        cases.iter().any(|case| case.expected == "accepted"),
        "accepted outcome control required"
    );
    assert!(
        cases
            .iter()
            .any(|case| matches!(case.expected.as_str(), "unproven" | "rejected")),
        "unproven or rejected outcome control required"
    );
    let mut ids = BTreeSet::new();
    let mut matched = 0;
    let outcome_cases: Vec<Value> = cases
        .iter()
        .map(|case| {
            assert!(ids.insert(&case.id), "duplicate outcome case identity");
            assert!(
                matches!(case.expected.as_str(), "accepted" | "unproven" | "rejected")
                    && matches!(case.actual.as_str(), "accepted" | "unproven" | "rejected"),
                "unknown verifier outcome"
            );
            for (label, gaps) in [
                ("expected", &case.expected_gaps),
                ("actual", &case.actual_gaps),
            ] {
                let unique: BTreeSet<_> = gaps.iter().collect();
                assert_eq!(unique.len(), gaps.len(), "duplicate {label} outcome gap");
            }
            let mut expected_gaps = case.expected_gaps.clone();
            expected_gaps.sort();
            let mut actual_gaps = case.actual_gaps.clone();
            actual_gaps.sort();
            let case_matched = case.expected == case.actual && expected_gaps == actual_gaps;
            if case_matched {
                matched += 1;
            }
            json!({
                "caseId":case.id,
                "expected":case.expected,
                "actual":case.actual,
                "expectedGaps":expected_gaps,
                "actualGaps":actual_gaps,
                "matched":case_matched
            })
        })
        .collect();
    let mismatched = cases.len() - matched;
    let passed = mismatched == 0;
    let (provider_version, binding) = source_binding(provider_id, fixture_paths);
    let mut result = json!({
        "schema":"legion-file-provider-accuracy/1",
        "provider":provider_id,
        "providerVersion":provider_version,
        "stage":"outcome",
        "scope":"constructed verifier acceptance & rejection controls; not a population accuracy estimate",
        "executionPath":"native-sdk-frozen-plan-file-only",
        "modelCalls":0,
        "coverageState":"complete",
        "measurementKind":"verification-outcome",
        "measurementStatus":if passed {"pass"} else {"fail"},
        "requiredDependencies":{
            "productionDispatch":"exercised",
            "acceptanceControl":"exercised",
            "rejectionControl":"exercised",
            "scope":"named verifier cases; no claim about untested outcomes",
            "externalExecution":"not-required"
        },
        "qualificationEligible":passed,
        "coverageGaps":[],
        "binding":binding,
        "outcomeCases":outcome_cases,
        "metrics":{"cases":cases.len(),"matched":matched,"mismatched":mismatched},
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
    assert_eq!(mismatched, 0, "{provider_id}: verifier outcome mismatch");
}

/// Emit exact native fact output on named positive and absence controls.
pub fn emit_facts(provider_id: &str, cases: &[FactObservation], fixture_paths: &[&str]) {
    let mut ids = BTreeSet::new();
    let mut controls = BTreeSet::new();
    let mut matched = 0;
    let fact_cases: Vec<Value> = cases
        .iter()
        .map(|case| {
            assert!(ids.insert(&case.id), "duplicate fact case identity");
            assert!(
                matches!(case.control.as_str(), "positive" | "absence"),
                "unknown fact control kind"
            );
            controls.insert(case.control.as_str());
            let expected = normalize_fact(&case.expected);
            let actual = normalize_fact(&case.actual);
            let case_matched = expected == actual;
            if case_matched {
                matched += 1;
            }
            json!({
                "caseId":case.id,
                "controlKind":case.control,
                "expected":expected,
                "actual":actual,
                "matched":case_matched
            })
        })
        .collect();
    assert!(
        controls.contains("positive"),
        "positive fact control required"
    );
    assert!(
        controls.contains("absence"),
        "zero-count/absence control required"
    );
    let positive = cases
        .iter()
        .find(|case| case.control == "positive")
        .expect("positive fact control required");
    let absence = cases
        .iter()
        .find(|case| case.control == "absence")
        .expect("absence fact control required");
    assert_ne!(
        normalize_fact(&positive.expected),
        normalize_fact(&absence.expected),
        "positive & absence fact controls must contrast"
    );
    let mismatched = cases.len() - matched;
    let passed = mismatched == 0;
    let (provider_version, binding) = source_binding(provider_id, fixture_paths);
    let mut result = json!({
        "schema":"legion-file-provider-accuracy/1",
        "provider":provider_id,
        "providerVersion":provider_version,
        "stage":"fact-output",
        "scope":"exact native fact output on named constructed controls; not a population accuracy estimate",
        "executionPath":"native-sdk-frozen-plan-file-only",
        "modelCalls":0,
        "coverageState":"complete",
        "measurementKind":"fact-output",
        "measurementStatus":if passed {"pass"} else {"fail"},
        "requiredDependencies":{
            "productionDispatch":"exercised",
            "positiveControl":"exercised",
            "absenceControl":"exercised",
            "scope":"named native facts; exact full object equality",
            "externalExecution":"not-required"
        },
        "qualificationEligible":passed,
        "coverageGaps":[],
        "binding":binding,
        "factCases":fact_cases,
        "metrics":{"cases":cases.len(),"matched":matched,"mismatched":mismatched},
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
    assert_eq!(mismatched, 0, "{provider_id}: native fact-output mismatch");
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
    let (provider_version, binding) = source_binding(provider_id, fixture_paths);
    let passed = fp == 0 && fn_ == 0;
    // These two providers own artifact ingestion/policy-record validation, not
    // the accuracy or certification of the upstream artifact's producer.
    let measurement_kind = match provider_id {
        "imported.sarif" | "governance.policy" => "adapter-protocol",
        _ => stage,
    };
    let mut result = json!({
        "schema":"legion-file-provider-accuracy/1", "provider":provider_id,
        "providerVersion":provider_version, "stage":stage,
        "scope":"constructed planted & clean controls; not a population accuracy estimate",
        "executionPath":"native-sdk-frozen-plan-file-only", "modelCalls":0,
        "coverageState":if gaps.is_empty() {"complete"} else {"partial"},
        "measurementKind":measurement_kind,"measurementStatus":if passed {"pass"} else {"fail"},
        "requiredDependencies":{"productionDispatch":"exercised",
            "positiveControl":"exercised","negativeControl":"exercised",
            "scope":"named corpus; no claim about untested rules",
            "externalExecution":if gaps.is_empty() {"not-required"} else {"missing"}},
        "qualificationEligible":passed && gaps.is_empty(),"coverageGaps":gaps,
        "binding":binding,
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
