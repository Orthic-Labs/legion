//! Packet A18 adversarial assurance-qualification corpus.
//!
//! The production validator lives in `legion-dev` (`audit_assurance.rs`,
//! root registers the command); a binary crate cannot be imported here, so
//! this test independently recomputes the corpus invariants from the raw
//! fixture JSON — canonical digests, metric counts, held-out separation,
//! raw-output bytes — and pins the expected verdicts in `expectations.json`.
//! Root runs the same corpus through the native validator and must observe
//! the same verdicts. Every record is `syntheticFixture: true`: this corpus
//! enrolls nothing and claims no production qualification.
//!
//! checks not run — root integration owns verification (authored only).

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/assurance-qualification")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn load(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn load_corpus(name: &str) -> Value {
    load(&corpus_dir().join(name))
}

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

fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

fn record_digest(record: &Value) -> String {
    let mut unsigned = record.clone();
    unsigned
        .as_object_mut()
        .expect("record is an object")
        .remove("qualificationDigest");
    digest(&canonical_bytes(&unsigned))
}

fn expectations() -> Value {
    load_corpus("expectations.json")
}

fn expected_records() -> Vec<(String, Value, Value)> {
    let expectations = expectations();
    expectations["records"]
        .as_object()
        .expect("expectations.records")
        .iter()
        .map(|(name, expected)| (name.clone(), load_corpus(name), expected.clone()))
        .collect()
}

#[test]
fn corpus_digests_bind_record_bytes_and_forgery_is_detectable() {
    let records = expected_records();
    assert_eq!(records.len(), 8, "corpus must keep all record cases");
    for (name, record, expected) in &records {
        assert_eq!(
            record["schema"], "legion-audit-assurance-qualification/1",
            "{name}"
        );
        assert_eq!(
            record["syntheticFixture"], true,
            "{name}: corpus never enrolls"
        );
        let claimed = record["qualificationDigest"].as_str().expect("digest");
        if name == "forged-digest.json" {
            assert_ne!(
                record_digest(record),
                claimed,
                "{name}: forgery must not verify"
            );
            assert_eq!(expected["verdict"], "rejected");
        } else {
            assert_eq!(
                record_digest(record),
                claimed,
                "{name}: stale/forged digest"
            );
        }
        // No record may claim an unbounded platform scope.
        for field in ["target", "platform", "variant", "toolVersion"] {
            let value = record["scope"][field].as_str().unwrap_or("");
            assert!(!value.is_empty() && value != "*", "{name}: scope.{field}");
        }
        assert!(
            record["scope"]["excludedSupport"]
                .as_array()
                .is_some_and(|v| !v.is_empty()),
            "{name}: excluded support must be named"
        );
    }
}

fn u32_field(value: &Value, key: &str) -> u32 {
    value[key]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0)
}

#[test]
fn declared_metrics_are_recomputed_from_outcome_counts() {
    for (name, record, _) in &expected_records() {
        let outcomes = record["outcomes"].as_array().expect("outcomes");
        let (mut tp, mut fp, mut fn_) = (0_u32, 0_u32, 0_u32);
        let mut ids = BTreeSet::new();
        for outcome in outcomes {
            assert!(
                ids.insert(outcome["fixtureId"].as_str().unwrap_or("")),
                "{name}"
            );
            let expected = u32_field(outcome, "expectedFindings");
            let emitted = u32_field(outcome, "emittedFindings");
            let matched = u32_field(outcome, "matchedFindings").min(expected);
            match outcome["kind"].as_str() {
                Some("positive") => {
                    tp += matched;
                    fp += emitted.saturating_sub(matched);
                    fn_ += expected.saturating_sub(matched);
                }
                Some("negative") => fp += emitted,
                Some("unsupported") => {}
                other => panic!("{name}: unknown outcome kind {other:?}"),
            }
        }
        // Basis ids must all be measured, and held-out ids stay separate.
        let authored: BTreeSet<_> = record["basis"]["fixtureIds"]
            .as_array()
            .map(|ids| ids.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let heldout: BTreeSet<_> = record["basis"]["heldoutFixtureIds"]
            .as_array()
            .map(|ids| ids.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert!(
            authored.is_disjoint(&heldout),
            "{name}: held-out split leaked"
        );
        for id in authored.iter().chain(&heldout) {
            assert!(ids.contains(id), "{name}: basis fixture {id} not measured");
        }
        if record["basis"]["kind"] == "heldout" && !outcomes.is_empty() {
            assert!(
                !heldout.is_empty(),
                "{name}: heldout basis needs held-out ids"
            );
        }
        if let Some(declared) = record.get("metrics").filter(|m| !m.is_null()) {
            assert_eq!(
                declared["sampleSize"].as_u64(),
                Some(outcomes.len() as u64),
                "{name}"
            );
            assert!(
                !declared["method"].as_str().unwrap_or("").is_empty(),
                "{name}"
            );
            let precision = (tp + fp > 0).then(|| f64::from(tp) / f64::from(tp + fp));
            let recall = (tp + fn_ > 0).then(|| f64::from(tp) / f64::from(tp + fn_));
            assert_eq!(
                declared["precision"].as_f64(),
                precision,
                "{name}: precision"
            );
            assert_eq!(declared["recall"].as_f64(), recall, "{name}: recall");
        }
    }
}

#[test]
fn false_green_zero_input_and_fixture_only_cases_stay_unqualified() {
    for (name, record, expected) in &expected_records() {
        let outcomes = record["outcomes"].as_array().expect("outcomes");
        let false_green = outcomes.iter().any(|outcome| {
            outcome["kind"] == "positive"
                && outcome["claimedClean"] == true
                && u32_field(outcome, "expectedFindings") > u32_field(outcome, "matchedFindings")
        });
        if false_green {
            assert_eq!(expected["verdict"], "rejected", "{name}: false-green");
        }
        if outcomes.is_empty() {
            assert_eq!(expected["verdict"], "rejected", "{name}: zero input");
        }
        if record["basis"]["kind"] == "authored-fixture" {
            assert_ne!(
                expected["effectiveLifecycle"], "qualified",
                "{name}: authored fixtures do not qualify behaviour"
            );
        }
        assert_ne!(expected["verdict"], "clean", "{name}");
        if expected["verdict"] == "valid" {
            assert_eq!(expected["effectiveLifecycle"], "qualified", "{name}");
            assert_eq!(record["syntheticFixture"], false, "{name}");
        }
    }
}

#[test]
fn raw_output_digests_match_retained_bytes() {
    let root = repo_root();
    for (name, record, _) in &expected_records() {
        let raw_outputs = record["provenance"]["rawOutputs"]
            .as_array()
            .expect("rawOutputs");
        if name == "missing-raw-output.json" {
            assert!(raw_outputs.is_empty());
            continue;
        }
        assert!(!raw_outputs.is_empty(), "{name}: raw output required");
        for raw in raw_outputs {
            let relative = raw["path"].as_str().expect("raw path");
            assert!(
                !relative.contains("..") && !relative.starts_with('/'),
                "{name}"
            );
            let bytes =
                fs::read(root.join(relative)).unwrap_or_else(|e| panic!("{name}: {relative}: {e}"));
            assert_eq!(digest(&bytes), raw["sha256"].as_str().unwrap(), "{name}");
        }
    }
}

#[test]
fn negative_evidence_corpus_covers_every_kind_and_never_expects_clean() {
    let cases = load_corpus("negative-evidence-cases.json");
    let cases = cases.as_array().expect("case array");
    let kinds: BTreeSet<_> = cases
        .iter()
        .filter_map(|case| case["kind"].as_str())
        .collect();
    let required: BTreeSet<_> = [
        "forged-import",
        "stale-import",
        "wrong-target-import",
        "zero-input",
        "source-drift",
        "invalid-parser-output",
        "skipped-provider",
        "missing-graph",
        "dependency-format-gap",
        "runtime-closure-mismatch",
        "incomplete-review",
    ]
    .into_iter()
    .collect();
    assert_eq!(kinds, required, "packet item 5 kinds must all be exercised");
    let mut ids = BTreeSet::new();
    for case in cases {
        assert!(
            ids.insert(case["id"].as_str().unwrap_or("")),
            "duplicate case id"
        );
        let verdict = case["expectedVerdict"].as_str().expect("expectedVerdict");
        assert!(
            matches!(verdict, "unmet" | "rejected" | "findings-retained"),
            "{}: verdict {verdict}",
            case["id"]
        );
        if case["findings"].as_u64().unwrap_or(0) > 0 {
            assert_eq!(verdict, "findings-retained", "{}", case["id"]);
        }
        if case["authenticated"] == false || case["digestMatches"] == false {
            assert_eq!(verdict, "rejected", "{}: integrity failure", case["id"]);
        }
    }
}

/// A02 consumption at the reported signature level: a fixture-scoped, stale
/// qualification scope must not apply to a production context, and a missing
/// record never applies either.
#[test]
fn a02_fixture_only_stale_qualification_is_not_applicable() {
    use legion_audit::assurance::{
        evaluate_qualification, QualificationContext, QualificationScope,
    };

    let fixture = load_corpus("a02-qualification.json");
    let now = fixture["now"].as_str().expect("now");
    let scope: QualificationScope =
        serde_json::from_value(fixture["scope"].clone()).expect("A02 scope shape");
    let context: QualificationContext =
        serde_json::from_value(fixture["context"].clone()).expect("A02 context shape");

    let verdict = serde_json::to_value(evaluate_qualification(Some(&scope), &context, now))
        .expect("verdict serializes");
    assert_eq!(
        verdict["applicable"].as_bool(),
        Some(false),
        "fixture-only/stale A02 qualification must not apply: {verdict}"
    );
    let missing = serde_json::to_value(evaluate_qualification(None, &context, now))
        .expect("verdict serializes");
    assert_eq!(missing["applicable"].as_bool(), Some(false));
    assert_eq!(fixture["expectedApplicable"], false);
}

fn scope_and_context(
    record_rule: Option<&str>,
    run_rule: Option<&str>,
    record_features: &[&str],
    run_features: &[&str],
) -> (
    legion_audit::assurance::QualificationScope,
    legion_audit::assurance::QualificationContext,
) {
    let mut scope = serde_json::json!({
        "providerId": "p", "providerVersion": "1", "host": "h",
        "toolchain": "t", "target": "x", "evidenceBasis": "production",
        "fixtureScope": "corpus",
        "digest": format!("sha256:{}", "a".repeat(64)),
        "features": record_features,
    });
    let mut context = serde_json::json!({
        "providerId": "p", "providerVersion": "1", "host": "h",
        "toolchain": "t", "target": "x",
        "features": run_features,
        "requiresProductionEvidence": true,
    });
    if let Some(r) = record_rule {
        scope["ruleVersion"] = r.into();
    }
    if let Some(r) = run_rule {
        context["ruleVersion"] = r.into();
    }
    (
        serde_json::from_value(scope).unwrap(),
        serde_json::from_value(context).unwrap(),
    )
}

#[test]
fn rule_version_and_feature_drift_are_not_qualified() {
    use legion_audit::assurance::evaluate_qualification;
    let now = "2026-10-23T00:00:00Z";
    let (s, c) = scope_and_context(Some("r1"), Some("r1"), &["a"], &["a"]);
    assert!(evaluate_qualification(Some(&s), &c, now).applicable);
    let (s, c) = scope_and_context(Some("r1"), Some("r2"), &["a"], &["a"]);
    let v = evaluate_qualification(Some(&s), &c, now);
    assert!(!v.applicable && v.mismatches.iter().any(|m| m.starts_with("ruleVersion")));
    let (s, c) = scope_and_context(Some("r1"), None, &["a"], &["a"]);
    assert!(!evaluate_qualification(Some(&s), &c, now).applicable);
    let (s, c) = scope_and_context(Some("r1"), Some("r1"), &["a"], &["a", "b"]);
    let v = evaluate_qualification(Some(&s), &c, now);
    assert!(v
        .mismatches
        .contains(&"feature-not-qualified:b".to_string()));
    let (s, c) = scope_and_context(Some("r1"), Some("r1"), &["a", "z"], &["a"]);
    let v = evaluate_qualification(Some(&s), &c, now);
    assert!(v.mismatches.contains(&"feature-not-executed:z".to_string()));
}
