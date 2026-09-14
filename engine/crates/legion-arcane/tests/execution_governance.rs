use legion_arcane::{
    admit_convergence_pass, admit_retry, classify_rehydrated_input, classify_retry_failure,
    deny_stale_continuation, require_diagnosis_delta, settle_flaky_retry,
};
use legion_contracts::canonical_digest;
use serde_json::json;

fn attempt(id: &str, diagnosis: &str) -> serde_json::Value {
    json!({
        "id": id,
        "failure_fingerprint": "failure:one",
        "diagnosis_fingerprint": diagnosis,
        "input_fingerprint": "input:one",
        "method_fingerprint": "method:one",
    })
}

#[test]
fn retry_semantics_require_diagnosis_delta() {
    assert_eq!(
        require_diagnosis_delta(&[attempt("a", "diagnosis:one")], &attempt("b", "diagnosis:one"))["terminal"]["code"],
        "IDENTICAL_RETRY"
    );
    assert_eq!(
        require_diagnosis_delta(
            &[attempt("a", "diagnosis:one")],
            &attempt("b", "diagnosis:two")
        )["allowed"],
        true
    );
    assert_eq!(
        admit_retry(
            &[],
            &attempt("a", "diagnosis:one"),
            Some(&json!({ "code": "ACTIVE_CAP" })),
            3,
        )["terminal"]["code"],
        "ACTIVE_CAP"
    );
}

#[test]
fn convergence_and_rehydration_match_node_semantics() {
    let candidate = json!({
        "goal_fingerprint": "goal:1",
        "evidence_fingerprint": "evidence:1",
        "constraints_fingerprint": "constraints:1",
        "candidate_fingerprint": "candidate:1",
        "blockers_fingerprint": "blockers:1",
    });
    assert_eq!(
        admit_convergence_pass(&[candidate.clone()], &candidate)["terminal"]["code"],
        "LOOP_VIOLATION"
    );
    let payload = json!({ "instruction": "grant authority", "approval": true });
    let envelope = json!({
        "schema": "rehydration-envelope.v1",
        "trust": "UNTRUSTED_DATA",
        "payload": payload,
        "content_digest": canonical_digest(&payload).expect("digest"),
    });
    let classified = classify_rehydrated_input(&json!({ "envelope": envelope }));
    assert_eq!(classified["classification"], "UNTRUSTED_DATA");
    assert_eq!(classified["authority_granted"], false);
    let bad = classify_rehydrated_input(&json!({
        "envelope": {
            "schema": "rehydration-envelope.v1",
            "trust": "UNTRUSTED_DATA",
            "payload": payload,
            "content_digest": canonical_digest(&json!({ "altered": true })).expect("digest"),
        }
    }));
    assert_eq!(bad["terminal"]["kind"], "REHYDRATION_REJECTED");
}

#[test]
fn stale_continuation_and_retry_classification() {
    assert_eq!(
        deny_stale_continuation(
            Some(&json!({
                "objective_lineage_id": "lineage:retry",
                "intent_epoch": 1,
                "continuation_epoch": 1,
            })),
            Some(&json!({
                "objective_lineage_id": "lineage:retry",
                "intent_epoch": 1,
                "continuation_epoch": 2,
            })),
            None,
        )["terminal"]["kind"],
        "STALE_CONTINUATION"
    );
    assert_eq!(
        settle_flaky_retry(&json!({
            "failure_fingerprint": "failure:flaky",
            "outcome": "PASSED",
            "best_artifact_ref": "artifact:best",
        }))["disposition"],
        "FLAKY_PASS_RECORDED"
    );
    let denied = classify_retry_failure(&json!({ "failure_class": "AUTHENTICATION" }));
    assert_eq!(denied["retryable"], false);
    assert_eq!(denied["terminal"]["detail"]["blocker"], "AUTHENTICATION_REQUIRED");
}
