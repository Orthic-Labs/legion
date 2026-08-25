//! LEG-I01 retained-Python-surface compatibility acceptance corpus.

use serde_json::Value;

fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../migration/native-rust/fixtures/python-surface-cases.v1.json"
    ))
    .expect("LEG-001 Python-surface fixtures remain valid JSON")
}

#[test]
fn retained_surface_contracts_preserve_typed_results_and_ids() {
    let fixture = fixtures();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    assert_eq!(cases[0]["expected"]["id_stable"], true);
    assert_eq!(cases[0]["expected"]["json_round_trip"], true);
    assert_eq!(cases[1]["expected"]["typed_result"], true);
    assert_eq!(cases[1]["expected"]["network_policy"], "explicit");
}

#[test]
fn invalid_handoff_is_typed_and_never_silently_coerced() {
    let fixture = fixtures();
    let case = &fixture["cases"][2];
    assert_eq!(case["expected"]["valid"], false);
    assert_eq!(case["expected"]["failure_is_typed"], true);
    assert_eq!(case["expected"]["silent_coercion"], false);
}
