use crate::command_verifier::verify_command_result;
use crate::decision::decision;
use crate::evidence_authority::{classify_technology_requirement, resolve_latency_target, EvidenceAuthorityRegistry};
use crate::execution_governance::{
    admit_convergence_pass, admit_retry, classify_rehydrated_input, classify_retry_failure,
    deny_stale_continuation, record_attempt, settle_flaky_retry, EventStoreAccept,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const EXECUTION_CONTROL_OPERATIONS: [&str; 10] = [
    "command.verify",
    "evidence.latency.resolve",
    "evidence.technology.classify",
    "execution.convergence.admit",
    "execution.retry.classify",
    "execution.retry.admit",
    "execution.retry.settle",
    "execution.retry.record",
    "execution.continuation.check",
    "execution.rehydration.classify",
];

pub struct ExecutionControlCapability {
    pub operations: BTreeSet<String>,
    pub observed_command_result: Option<Value>,
    pub sealed_expected_command_output: Option<Value>,
    pub evidence_authority_registry: Option<EvidenceAuthorityRegistry>,
    pub convergence_passes: Vec<Value>,
    pub retry_attempts: Vec<Value>,
    pub retry_stop: Option<Value>,
    pub retry_max_identical_attempts: i64,
    pub continuation_current: Option<Value>,
    pub continuation_stop: Option<Value>,
    pub execution_snapshot: Option<ExecutionSnapshot>,
    pub execution_context: Option<Value>,
}

pub struct ExecutionSnapshot {
    pub event_store: Box<dyn EventStoreAccept>,
    pub state: Value,
}

impl ExecutionControlCapability {
    pub fn new(operations: Vec<String>) -> Result<Self, String> {
        if operations.is_empty()
            || operations
                .iter()
                .any(|operation| !EXECUTION_CONTROL_OPERATIONS.contains(&operation.as_str()))
        {
            return Err("invalid execution control capability operations".into());
        }
        Ok(Self {
            operations: operations.into_iter().collect(),
            observed_command_result: None,
            sealed_expected_command_output: None,
            evidence_authority_registry: None,
            convergence_passes: Vec::new(),
            retry_attempts: Vec::new(),
            retry_stop: None,
            retry_max_identical_attempts: 3,
            continuation_current: None,
            continuation_stop: None,
            execution_snapshot: None,
            execution_context: None,
        })
    }

    fn trusted(&self, operation: &str) -> bool {
        self.operations.contains(operation)
    }
}

fn exact_operation(value: &Value) -> bool {
    let object = value.as_object();
    if object.is_none() {
        return false;
    }
    let object = object.unwrap();
    object.len() == 2
        && object.get("operation").and_then(Value::as_str).is_some()
        && object.get("input").is_some_and(Value::is_object)
}

fn refusal(reason: &str) -> Value {
    decision(
        false,
        Some("ARC_SCHEMA_INVALID"),
        Some("execution control operation is invalid"),
        json!({ "reason": reason }),
    )
}

fn diagnostic(operation: &str, result: &Value) -> Value {
    json!({
        "allowed": false,
        "code": "ARC_DIAGNOSTIC_ONLY",
        "message": "caller-controlled execution control result is not consumable",
        "detail": {
            "operation": operation,
            "observedAllowed": result.get("allowed") == Some(&json!(true)),
        },
        "consumable": false,
        "diagnostic": result,
    })
}

fn output(operation: Option<&str>, result: Value, consumable: bool) -> Value {
    json!({
        "kind": "arcane-execution-control-decision",
        "operation": operation,
        "consumable": consumable,
        "result": result,
    })
}

pub fn dispatch_execution_control(
    operation: &Value,
    capability: Option<&ExecutionControlCapability>,
) -> Value {
    if !exact_operation(operation) {
        return output(None, refusal("INVALID_OPERATION"), false);
    }
    let operation_name = operation["operation"].as_str().unwrap_or_default();
    let input = &operation["input"];
    let trusted = capability.is_some_and(|cap| cap.trusted(operation_name));
    let consume = |result: Value| {
        if trusted {
            output(Some(operation_name), result, true)
        } else {
            output(Some(operation_name), diagnostic(operation_name, &result), false)
        }
    };

    let result = match operation_name {
        "command.verify" => {
            let observed = capability
                .and_then(|cap| cap.observed_command_result.as_ref())
                .map(|value| value.clone())
                .unwrap_or(json!({}));
            verify_command_result(
                &observed,
                capability.and_then(|cap| cap.sealed_expected_command_output.as_ref()),
            )
        }
        "evidence.latency.resolve" => {
            let registry = capability.and_then(|cap| cap.evidence_authority_registry.as_ref());
            if registry.is_none() {
                return consume(refusal("HOST_EVIDENCE_AUTHORITY_REQUIRED"));
            }
            resolve_latency_target(input, registry.unwrap())
        }
        "evidence.technology.classify" => {
            let registry = capability.and_then(|cap| cap.evidence_authority_registry.as_ref());
            if registry.is_none() {
                return consume(refusal("HOST_EVIDENCE_AUTHORITY_REQUIRED"));
            }
            classify_technology_requirement(input, registry.unwrap())
        }
        "execution.convergence.admit" => {
            let passes = capability
                .map(|cap| cap.convergence_passes.as_slice())
                .unwrap_or(&[]);
            admit_convergence_pass(passes, input.get("candidate").unwrap_or(&Value::Null))
        }
        "execution.retry.classify" => classify_retry_failure(input),
        "execution.retry.admit" => {
            let attempts = capability
                .map(|cap| cap.retry_attempts.as_slice())
                .unwrap_or(&[]);
            admit_retry(
                attempts,
                input.get("candidate").unwrap_or(&Value::Null),
                capability.and_then(|cap| cap.retry_stop.as_ref()),
                capability
                    .map(|cap| cap.retry_max_identical_attempts)
                    .unwrap_or(3),
            )
        }
        "execution.retry.settle" => settle_flaky_retry(input),
        "execution.continuation.check" => deny_stale_continuation(
            input.get("token"),
            capability.and_then(|cap| cap.continuation_current.as_ref()),
            capability.and_then(|cap| cap.continuation_stop.as_ref()),
        ),
        "execution.rehydration.classify" => classify_rehydrated_input(input),
        "execution.retry.record" => {
            let snapshot = capability.and_then(|cap| cap.execution_snapshot.as_ref());
            record_attempt(
                snapshot.map(|value| value.event_store.as_ref()),
                snapshot.map(|value| &value.state),
                capability.and_then(|cap| cap.execution_context.as_ref()),
                input.get("attempt").unwrap_or(&Value::Null),
                capability.and_then(|cap| cap.retry_stop.as_ref()),
                capability
                    .map(|cap| cap.retry_max_identical_attempts)
                    .unwrap_or(3),
            )
        }
        _ => refusal("UNKNOWN_OPERATION"),
    };
    consume(result)
}
