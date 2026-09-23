//! Integration tests for wf009 (`src/lib/providers` executor surface).
//!
//! Ports assertions from `tests/provider-executor.test.mjs`'s
//! `imported-artifact provider requires its artifact` case, plus additional
//! coverage for `normalizeExecutorAction`'s `LEGION_ACTION_MALFORMED` path,
//! against `legion_audit::wf_port::wf009`.

use legion_audit::wf_port::wf009::{
    imported_artifact_receipt, ingest_imported_artifact, normalize_executor_action,
    ExecutorPortError,
};
use serde_json::json;

fn binding() -> serde_json::Value {
    json!({"repositoryRevision": "rev1", "digest": "sha256:aaaa"})
}

#[test]
fn imported_artifact_missing_from_map_is_a_binding_or_field_error() {
    // Mirrors the JS test's "missing" branch: no artifact entry at all.
    // The Rust port takes the artifact value directly rather than an
    // artifacts map keyed by id, so "missing" here means an artifact value
    // that carries no binding at all.
    let error = ingest_imported_artifact(&serde_json::Value::Null, &binding()).unwrap_err();
    assert_eq!(
        error,
        ExecutorPortError::BindingMismatch("imported artifact".into())
    );
}

#[test]
fn imported_artifact_present_with_binding_digest_and_path_passes() {
    let artifact = json!({
        "binding": binding(),
        "path": "codeql.sarif",
        "digest": "sha256:bbbb",
    });
    let receipt = imported_artifact_receipt("codeql", &artifact, &binding()).unwrap();
    assert_eq!(receipt["status"], "pass");
    assert_eq!(receipt["complete"], true);
    assert_eq!(receipt["provider"], "codeql");
    assert_eq!(receipt["artifact"]["path"], "codeql.sarif");
    assert_eq!(receipt["artifact"]["digest"], "sha256:bbbb");
    assert_eq!(receipt["artifact"]["bytes"], serde_json::Value::Null);
    assert_eq!(receipt["artifact"]["mediaType"], serde_json::Value::Null);
}

#[test]
fn imported_artifact_binding_mismatch_is_rejected_before_field_check() {
    let artifact = json!({
        "binding": {"repositoryRevision": "different", "digest": "sha256:aaaa"},
        "path": "codeql.sarif",
        "digest": "sha256:bbbb",
    });
    let error = imported_artifact_receipt("codeql", &artifact, &binding()).unwrap_err();
    assert_eq!(
        error,
        ExecutorPortError::BindingMismatch("imported artifact".into())
    );
}

#[test]
fn normalize_executor_action_round_trips_well_formed_payload() {
    let value = json!({
        "operation": "inspect",
        "effectClass": "COMMAND_EXEC",
        "target": "workspace",
        "arguments": {},
    });
    let action = normalize_executor_action(&value).expect("well-formed action");
    assert_eq!(action.operation, "inspect");
    assert_eq!(action.effect_class, "COMMAND_EXEC");
    assert_eq!(action.target, "workspace");
    assert!(action.arguments.is_empty());
}

#[test]
fn normalize_executor_action_rejects_array_payload() {
    let error = normalize_executor_action(&json!([1, 2, 3])).unwrap_err();
    match error {
        ExecutorPortError::ActionMalformed { path, .. } => assert_eq!(path, "$"),
        other => panic!("expected ActionMalformed, got {other:?}"),
    }
}

#[test]
fn normalize_executor_action_rejects_unknown_field() {
    let value = json!({
        "operation": "inspect",
        "effectClass": "COMMAND_EXEC",
        "target": "workspace",
        "unexpected": 1,
    });
    let error = normalize_executor_action(&value).unwrap_err();
    match error {
        ExecutorPortError::ActionMalformed { path, message } => {
            assert_eq!(path, "$.unexpected");
            assert!(message.contains("unknown executor action field"));
        }
        other => panic!("expected ActionMalformed, got {other:?}"),
    }
}

#[test]
fn normalize_executor_action_rejects_missing_target() {
    let value = json!({
        "operation": "inspect",
        "effectClass": "COMMAND_EXEC",
    });
    let error = normalize_executor_action(&value).unwrap_err();
    match error {
        ExecutorPortError::ActionMalformed { path, .. } => assert_eq!(path, "$.target"),
        other => panic!("expected ActionMalformed, got {other:?}"),
    }
}
