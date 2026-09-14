use legion_minimize::{validate_decision, DECISION_SCHEMA};
use serde_json::json;

#[test]
fn validate_decision_requires_schema() {
    let err = validate_decision(&json!({}), &[], &[]).unwrap_err();
    assert!(err.to_string().contains(DECISION_SCHEMA));
}

#[test]
fn validate_decision_requires_ordered_prior_rungs() {
    let decision = json!({
        "schema": DECISION_SCHEMA,
        "selected_rung": "REUSE",
        "prior_rungs": [{"rung": "NOT_BUILD", "verdict": "REJECTED", "evidence": "x"}],
        "decision_id": "d1",
        "state_a": "a",
        "state_b": "b",
        "allowed_new_files": [],
        "allowed_new_dependencies": []
    });
    validate_decision(&decision, &[], &[]).expect("valid decision");
}
