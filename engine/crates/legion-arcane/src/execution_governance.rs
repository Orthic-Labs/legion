use crate::continuity::rehydrate_untrusted_data;
use legion_contracts::canonical_digest;
use serde_json::{json, Map, Value};

const RETRY_BLOCKERS: [(&str, &str); 4] = [
    ("AUTHENTICATION", "AUTHENTICATION_REQUIRED"),
    ("MISSING_RESOURCE", "RESOURCE_UNAVAILABLE"),
    ("INVALID_CONTRACT", "CONTRACT_INVALID"),
    ("CONTEXT_FAILURE", "CONTEXT_INVALID"),
];

fn non_empty(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty())
}

fn terminal(kind: &str, code: &str, detail: Value) -> Value {
    json!({
        "allowed": false,
        "terminal": {
            "kind": kind,
            "code": code,
            "detail": detail,
        }
    })
}

fn allowed(detail: Value) -> Value {
    json!({
        "allowed": true,
        "terminal": Value::Null,
        "detail": detail,
    })
}

pub fn fingerprint_convergence_input(input: &Value) -> Option<String> {
    if !input.is_object() {
        return None;
    }
    let fields = [
        "goal_fingerprint",
        "evidence_fingerprint",
        "constraints_fingerprint",
        "candidate_fingerprint",
        "blockers_fingerprint",
    ];
    if fields.iter().any(|field| !non_empty(&input[*field])) {
        return None;
    }
    let object = fields
        .iter()
        .map(|field| (field.to_string(), input[*field].clone()))
        .collect::<Map<String, Value>>();
    canonical_digest(&object).ok()
}

pub fn admit_convergence_pass(passes: &[Value], candidate: &Value) -> Value {
    let fingerprint = fingerprint_convergence_input(candidate);
    if fingerprint.is_none() {
        return terminal("BUDGET_STOP", "INVALID_CONVERGENCE_INPUT", json!({}));
    }
    let fingerprint = fingerprint.unwrap();
    let prior_count = passes
        .iter()
        .filter_map(fingerprint_convergence_input)
        .filter(|value| value == &fingerprint)
        .count();
    if prior_count > 0 {
        terminal(
            "BUDGET_STOP",
            "LOOP_VIOLATION",
            json!({
                "input_fingerprint": fingerprint,
                "prior_count": prior_count,
            }),
        )
    } else {
        allowed(json!({
            "input_fingerprint": fingerprint,
            "prior_count": 0,
        }))
    }
}

pub fn classify_retry_failure(input: &Value) -> Value {
    let failure_class = input.get("failure_class").and_then(Value::as_str);
    if failure_class.is_none() || failure_class == Some("") {
        return terminal("BUDGET_STOP", "INVALID_FAILURE_CLASS", json!({}));
    }
    let failure_class = failure_class.unwrap();
    for (key, blocker) in RETRY_BLOCKERS {
        if failure_class == key {
            return json!({
                "retryable": false,
                "terminal": {
                    "kind": "BUDGET_STOP",
                    "code": "NON_RETRYABLE",
                    "detail": {
                        "failure_class": failure_class,
                        "blocker": blocker,
                    }
                }
            });
        }
    }
    json!({
        "retryable": true,
        "terminal": Value::Null,
        "detail": { "failure_class": failure_class },
    })
}

pub fn settle_flaky_retry(input: &Value) -> Value {
    let failure_fingerprint = input.get("failure_fingerprint");
    let outcome = input.get("outcome").and_then(Value::as_str);
    if !non_empty(failure_fingerprint.unwrap_or(&Value::Null))
        || !matches!(outcome, Some("PASSED") | Some("FAILED"))
    {
        return terminal("BUDGET_STOP", "INVALID_RETRY_DISPOSITION", json!({}));
    }
    let passed = outcome == Some("PASSED");
    json!({
        "allowed": true,
        "terminal": Value::Null,
        "disposition": if passed { "FLAKY_PASS_RECORDED" } else { "FAILURE_RECORDED" },
        "failure_fingerprint": failure_fingerprint,
        "pass_recorded": passed,
        "best_artifact_ref": input.get("best_artifact_ref").cloned().unwrap_or(Value::Null),
    })
}

fn normalized_attempt(attempt: &Value) -> Option<Value> {
    if !attempt.is_object() {
        return None;
    }
    let id = attempt
        .get("id")
        .or_else(|| attempt.get("attempt_id"))
        .filter(|value| non_empty(value));
    if id.is_none()
        || !non_empty(&attempt["failure_fingerprint"])
        || !non_empty(&attempt["diagnosis_fingerprint"])
    {
        return None;
    }
    Some(json!({
        "id": id,
        "failure_fingerprint": attempt["failure_fingerprint"],
        "diagnosis_fingerprint": attempt["diagnosis_fingerprint"],
        "input_fingerprint": attempt.get("input_fingerprint").cloned().unwrap_or(Value::Null),
        "method_fingerprint": attempt.get("method_fingerprint").cloned().unwrap_or(Value::Null),
        "retry_class": attempt.get("retry_class").cloned().unwrap_or(json!("changed_method")),
        "failure_class": attempt.get("failure_class").cloned().unwrap_or(Value::Null),
    }))
}

pub fn require_diagnosis_delta(attempts: &[Value], candidate: &Value) -> Value {
    let next = normalized_attempt(candidate);
    if next.is_none() {
        return terminal("BUDGET_STOP", "INVALID_RETRY_ATTEMPT", json!({}));
    }
    let next = next.unwrap();
    let prior = attempts
        .iter()
        .filter_map(normalized_attempt)
        .filter(|attempt| attempt["failure_fingerprint"] == next["failure_fingerprint"])
        .collect::<Vec<_>>();
    if prior.is_empty() {
        return allowed(json!({ "diagnosis_delta": true, "prior_count": 0 }));
    }
    let diagnosis_delta = prior
        .iter()
        .all(|attempt| attempt["diagnosis_fingerprint"] != next["diagnosis_fingerprint"]);
    if diagnosis_delta {
        allowed(json!({
            "diagnosis_delta": true,
            "prior_count": prior.len(),
        }))
    } else {
        terminal(
            "BUDGET_STOP",
            "IDENTICAL_RETRY",
            json!({
                "failure_fingerprint": next["failure_fingerprint"],
                "diagnosis_fingerprint": next["diagnosis_fingerprint"],
                "prior_count": prior.len(),
            }),
        )
    }
}

fn behavioral_loop(attempts: &[Value], candidate: &Value) -> Option<Value> {
    let next = normalized_attempt(candidate)?;
    let prior = attempts
        .iter()
        .filter_map(normalized_attempt)
        .filter(|attempt| {
            attempt["failure_fingerprint"] == next["failure_fingerprint"]
                && attempt["input_fingerprint"] == next["input_fingerprint"]
        })
        .collect::<Vec<_>>();
    let mut methods = prior
        .iter()
        .filter_map(|attempt| attempt["method_fingerprint"].as_str())
        .collect::<Vec<_>>();
    if let Some(method) = next["method_fingerprint"].as_str() {
        methods.push(method);
    }
    methods.sort();
    methods.dedup();
    if prior.is_empty()
        || prior
            .iter()
            .any(|attempt| attempt["diagnosis_fingerprint"] == next["diagnosis_fingerprint"])
        || methods.len() < 2
    {
        return None;
    }
    Some(terminal(
        "BUDGET_STOP",
        "LOOP_VIOLATION",
        json!({
            "failure_fingerprint": next["failure_fingerprint"],
            "input_fingerprint": next["input_fingerprint"],
            "method_fingerprints": methods,
            "prior_count": prior.len(),
        }),
    ))
}

pub fn admit_retry(
    attempts: &[Value],
    candidate: &Value,
    stop: Option<&Value>,
    max_identical_attempts: i64,
) -> Value {
    if let Some(stop) = stop {
        return terminal(
            "BUDGET_STOP",
            stop.get("code")
                .and_then(Value::as_str)
                .unwrap_or("STOP_PRECEDENCE"),
            json!({ "stop": stop }),
        );
    }
    if max_identical_attempts < 1 {
        return terminal("BUDGET_STOP", "INVALID_RETRY_LIMIT", json!({}));
    }
    if candidate.get("failure_class").is_some() {
        let classification = classify_retry_failure(candidate);
        if classification.get("retryable") == Some(&json!(false)) {
            return classification;
        }
    }
    let delta = require_diagnosis_delta(attempts, candidate);
    if delta.get("allowed") != Some(&json!(true)) {
        return delta;
    }
    if let Some(loop_result) = behavioral_loop(attempts, candidate) {
        return loop_result;
    }
    let next = normalized_attempt(candidate).unwrap();
    let identical = attempts
        .iter()
        .filter_map(normalized_attempt)
        .filter(|attempt| attempt["failure_fingerprint"] == next["failure_fingerprint"])
        .count();
    if identical >= max_identical_attempts as usize {
        return terminal(
            "BUDGET_STOP",
            "RETRY_LIMIT",
            json!({
                "failure_fingerprint": next["failure_fingerprint"],
                "attempts": identical,
                "max_identical_attempts": max_identical_attempts,
            }),
        );
    }
    allowed(json!({
        "retry_class": next["retry_class"],
        "diagnosis_delta": true,
        "prior_identical_failures": identical,
    }))
}

pub fn deny_stale_continuation(
    token: Option<&Value>,
    current: Option<&Value>,
    stop: Option<&Value>,
) -> Value {
    if let Some(stop) = stop {
        return terminal(
            "BUDGET_STOP",
            stop.get("code")
                .and_then(Value::as_str)
                .unwrap_or("STOP_PRECEDENCE"),
            json!({ "stop": stop }),
        );
    }
    if token.is_none() || current.is_none() {
        return terminal("STALE_CONTINUATION", "CONTINUATION_BINDING_MISSING", json!({}));
    }
    let token = token.unwrap();
    let current = current.unwrap();
    let fields = [
        "objective_lineage_id",
        "intent_epoch",
        "continuation_epoch",
    ];
    let mismatches = fields
        .iter()
        .filter(|field| token.get(*field) != current.get(*field))
        .map(|field| (*field).to_string())
        .collect::<Vec<_>>();
    if mismatches.is_empty() {
        allowed(json!({ "continuation": "CURRENT" }))
    } else {
        terminal(
            "STALE_CONTINUATION",
            "CONTINUATION_STALE",
            json!({ "mismatches": mismatches }),
        )
    }
}

pub fn classify_rehydrated_input(input: &Value) -> Value {
    let envelope = input.get("envelope");
    match envelope.and_then(|value| rehydrate_untrusted_data(value).ok()) {
        Some(rehydrated) => json!({
            "allowed": true,
            "terminal": Value::Null,
            "classification": "UNTRUSTED_DATA",
            "authority_granted": false,
            "instruction_status": "DATA_ONLY",
            "effect_downgrade_allowed": false,
            "data": rehydrated["data"],
        }),
        None => terminal("REHYDRATION_REJECTED", "INVALID_REHYDRATION_ENVELOPE", json!({})),
    }
}

pub trait EventStoreAccept {
    fn accept(&self, proposal: &Value, expected_state_fingerprint: &str) -> Value;
}

pub fn record_attempt(
    event_store: Option<&dyn EventStoreAccept>,
    state: Option<&Value>,
    context: Option<&Value>,
    attempt: &Value,
    stop: Option<&Value>,
    max_identical_attempts: i64,
) -> Value {
    let execution_id = context
        .and_then(|value| value.get("execution_id"))
        .filter(|value| non_empty(value));
    let repository_id = context
        .and_then(|value| value.get("repository_id"))
        .filter(|value| non_empty(value));
    let retry_items = state
        .and_then(|value| value.get("execution"))
        .and_then(|value| value.get("retry"))
        .and_then(|value| value.get("items"))
        .and_then(Value::as_array);
    if event_store.is_none()
        || retry_items.is_none()
        || execution_id.is_none()
        || repository_id.is_none()
    {
        return terminal("BUDGET_STOP", "RETRY_RECORDING_UNAVAILABLE", json!({}));
    }
    let candidate = normalized_attempt(attempt);
    if candidate.is_none() {
        return terminal("BUDGET_STOP", "INVALID_RETRY_ATTEMPT", json!({}));
    }
    let candidate = candidate.unwrap();
    let admission = admit_retry(
        retry_items.unwrap(),
        &candidate,
        stop,
        max_identical_attempts,
    );
    if admission.get("allowed") != Some(&json!(true)) {
        return admission;
    }
    let state = state.unwrap();
    let context = context.unwrap();
    let proposal = json!({
        "objective_lineage_id": state["task"]["objective_lineage_id"],
        "intent_epoch": state["intent"]["intent_epoch"],
        "execution_id": context["execution_id"],
        "repository_id": context["repository_id"],
        "actor_role": context.get("actor_role").cloned().unwrap_or(json!("alchemist")),
        "phase": "execute",
        "event_type": "RETRY_RECORDED",
        "payload": candidate,
        "acceptance_ids": [],
        "decision_ids": [],
        "finding_ids": [],
        "input_fingerprint": candidate["input_fingerprint"],
        "output_refs": [],
        "checkpoint_ref": Value::Null,
        "cost_delta": json!({}),
        "retry_class": candidate["retry_class"],
        "terminal_reason": Value::Null,
        "privacy_class": "metadata",
    });
    let fingerprint = state
        .get("state_fingerprint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let accepted = event_store.unwrap().accept(&proposal, fingerprint);
    if accepted.get("accepted") != Some(&json!(true)) {
        return json!({
            "allowed": false,
            "terminal": {
                "kind": "BUDGET_STOP",
                "code": accepted.get("decision").and_then(|value| value.get("code")).cloned().unwrap_or(json!("RETRY_RECORDING_UNAVAILABLE")),
                "detail": accepted.get("decision").and_then(|value| value.get("detail")).cloned().unwrap_or(json!({})),
            },
            "decision": accepted.get("decision").cloned().unwrap_or(Value::Null),
        });
    }
    json!({
        "allowed": true,
        "terminal": Value::Null,
        "attempt": candidate,
        "event": accepted.get("event").cloned().unwrap_or(Value::Null),
        "state": accepted.get("state").cloned().unwrap_or(Value::Null),
        "state_fingerprint": accepted.get("state_fingerprint").cloned().unwrap_or(Value::Null),
    })
}
