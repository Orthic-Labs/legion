#![forbid(unsafe_code)]
//! Port of deleted `bench/run-provider-selection-benchmark.mjs` +
//! `bench/precision-recall.mjs`: runs the native provider selector over the
//! labeled ground-truth corpus and asserts the same zero-FP/zero-FN
//! threshold the JS bench enforced (`process.exitCode = 1` on any
//! falsePositive or falseNegative).

use legion_audit::wf_port::wf010::provider_registry::{select_providers, SelectOptions};
use serde_json::Value;
use std::fs;

const LABELS: &str = include_str!("fixtures/provider_selection_labeled_samples.json");

fn registry() -> Value {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .expect("packaged provider registry");
    serde_json::from_str(&raw).expect("registry JSON")
}

#[test]
fn provider_selection_benchmark_meets_precision_recall_thresholds() {
    let corpus: Value = serde_json::from_str(LABELS).expect("labeled samples fixture");
    let registry = registry();
    let samples = corpus["samples"].as_array().expect("samples array");

    let mut true_positive = 0u32;
    let mut false_positive = 0u32;
    let mut true_negative = 0u32;
    let mut false_negative = 0u32;

    for sample in samples {
        let expected = sample["expected"].as_bool().unwrap_or(false);
        let provider_id = sample["provider"].as_str().expect("sample.provider");
        let projection = &sample["projection"];
        let result = select_providers(&registry, projection, &SelectOptions::default())
            .unwrap_or_else(|e| panic!("select_providers failed for {}: {e:?}", sample["id"]));
        let detected = result
            .selected
            .iter()
            .any(|p| p["id"].as_str() == Some(provider_id));

        match (expected, detected) {
            (true, true) => true_positive += 1,
            (false, true) => false_positive += 1,
            (false, false) => true_negative += 1,
            (true, false) => false_negative += 1,
        }
    }

    // Same gate the JS bench enforced: any false positive or false negative
    // fails the benchmark. precision == recall == 1.0 required.
    assert_eq!(
        false_positive, 0,
        "provider selection benchmark: unexpected false positives (tp={true_positive} tn={true_negative} fn={false_negative})"
    );
    assert_eq!(
        false_negative, 0,
        "provider selection benchmark: unexpected false negatives (tp={true_positive} tn={true_negative} fp={false_positive})"
    );
    assert!(true_positive + true_negative > 0, "benchmark corpus must not be empty");
}
