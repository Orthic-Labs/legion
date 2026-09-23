//! Ported tests for chunk wf050 (area `src/providers/runtime/web`,
//! target crate `legion-audit`):
//!   - `src/providers/runtime/web/performance/index.mjs`
//!   - `src/providers/runtime/web/protocols/index.mjs`
//!   - `src/providers/runtime/web/runner/index.mjs`
//!   - `src/providers/runtime/web/scenario/index.mjs`
//!   - `src/providers/runtime/web/shared.mjs`
//!
//! No JS `.test.mjs` file targeting these five modules directly was found
//! under `tests/` in the JS tree, so these assertions are derived from the
//! source's own documented behaviour (binding validation, redaction,
//! denominator accounting, adapter dispatch) rather than ported line-for-
//! line from an existing test file.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod
//! wf050;` inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf050::performance::{verify_web_performance, CaptureEvidence};
use legion_audit::wf_port::wf050::protocols::{execute_web_protocol, AdapterExecuteResult, ProtocolPlanRow};
use legion_audit::wf_port::wf050::runner::run_web_control;
use legion_audit::wf_port::wf050::scenario::{run_web_scenario, AdapterCallResult};
use legion_audit::wf_port::wf050::shared::{
    denominator, exact_binding, finalize, redact, same_binding, sort_by_id,
};
use serde_json::{json, Value};

fn full_binding() -> Value {
    json!({
        "targetId": "target-1",
        "environment": "staging",
        "actorId": "actor-1",
        "tenantId": "tenant-1",
        "browser": "chromium",
        "browserVersion": "120.0",
        "viewport": "1280x720",
        "locale": "en-US",
        "sourceRevision": "abc123",
        "artifactDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000",
    })
}

fn no_sanitize(artifact: &Value) -> (bool, bool, Value) {
    (true, false, artifact.clone())
}

// ---------------------------------------------------------------------
// shared.mjs
// ---------------------------------------------------------------------

#[test]
fn shared_exact_binding_flags_missing_keys_as_opaque_and_sorted() {
    let result = exact_binding(&json!({ "targetId": "t1" }));
    assert!(result.gaps.contains(&"environment".to_string()));
    // Every declared binding key ends up present in the normalized output.
    for key in ["targetId", "environment", "actorId", "tenantId", "browser", "browserVersion", "viewport", "locale", "sourceRevision", "artifactDigest"] {
        assert!(result.binding.get(key).is_some(), "missing key {key}");
    }
    assert_eq!(result.binding.get("targetId"), Some(&Value::String("t1".to_string())));
}

#[test]
fn shared_exact_binding_flags_extra_sensitive_and_undeclared_keys() {
    let result = exact_binding(&json!({ "token": "abc", "weird": "x" }));
    assert!(result.gaps.contains(&"binding-extra-sensitive".to_string()));
    assert!(result.gaps.contains(&"binding-extra-undeclared".to_string()));
}

#[test]
fn shared_same_binding_compares_only_declared_keys() {
    let a = full_binding();
    let mut b = full_binding();
    b["extra"] = json!("ignored");
    assert!(same_binding(&a, &b));
    let mut c = full_binding();
    c["targetId"] = json!("other");
    assert!(!same_binding(&a, &c));
}

#[test]
fn shared_redact_masks_sensitive_keys_and_inline_bearer_and_email() {
    let value = json!({
        "token": "abc123",
        "note": "contact admin@example.com or use Bearer xyz789",
    });
    let out = redact(&value);
    assert_eq!(out["token"], json!("[REDACTED]"));
    assert_eq!(out["note"], json!("contact [REDACTED] or use [REDACTED]"));
}

#[test]
fn shared_denominator_counts_missing_ids() {
    let expected = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let receipts = vec!["a".to_string()];
    let omitted = vec!["b".to_string()];
    let counts = denominator(&expected, &receipts, &omitted);
    assert_eq!(counts.total, 3);
    assert_eq!(counts.accounted, 2);
    assert_eq!(counts.missing, vec!["c".to_string()]);
}

#[test]
fn shared_sort_by_id_orders_lexicographically() {
    let sorted = sort_by_id(&[json!({"id": "b"}), json!({"id": "a"})]);
    assert_eq!(sorted[0]["id"], json!("a"));
    assert_eq!(sorted[1]["id"], json!("b"));
}

#[test]
fn shared_finalize_forces_error_on_invalid_binding() {
    let out = finalize("legion-web-test", json!({ "status": "pass", "terminal": true, "binding": {} }));
    assert_eq!(out["status"], json!("error"));
    assert_eq!(out["terminal"], json!(true));
    assert_eq!(out["kind"], json!("legion-web-test"));
    assert!(out.get("digest").is_some());
}

// ---------------------------------------------------------------------
// performance/index.mjs (`verifyWebPerformance`)
// ---------------------------------------------------------------------

fn passing_capture() -> CaptureEvidence {
    CaptureEvidence { coverage_gaps: Vec::new(), digest: json!("sha256:abc"), captures: json!([]) }
}

#[test]
fn performance_invalid_captures_returns_error_immediately() {
    let capture = passing_capture();
    let result = verify_web_performance(&json!({ "binding": full_binding(), "captures": "nope" }), &capture);
    assert_eq!(result["status"], json!("error"));
    assert_eq!(result["coverageGaps"], json!(["performance-captures-invalid"]));
}

#[test]
fn performance_pass_when_samples_valid_and_budget_met() {
    let capture = passing_capture();
    let input = json!({
        "binding": full_binding(),
        "captures": [
            { "repeat": 1, "performance": { "lcp": 100.0, "memory": 10.0, "longTasks": [1.0], "layoutShifts": [0.1], "paints": [1.0], "userTimings": [1.0] } },
        ],
        "budgets": { "lcp": 500.0 },
    });
    let result = verify_web_performance(&input, &capture);
    assert_eq!(result["status"], json!("pass"));
    assert_eq!(result["metrics"]["lcp"], json!(100.0));
}

#[test]
fn performance_flags_budget_exceeded_as_fail() {
    let capture = passing_capture();
    let input = json!({
        "binding": full_binding(),
        "captures": [
            { "repeat": 1, "performance": { "lcp": 900.0, "memory": 10.0, "longTasks": [], "layoutShifts": [], "paints": [], "userTimings": [] } },
        ],
        "budgets": { "lcp": 500.0 },
    });
    // longTasks/layoutShifts/paints/userTimings empty arrays are invalid
    // (numericArray requires length > 0), so this also carries those gaps,
    // but the budget-exceeded gap must still force `fail`.
    let result = verify_web_performance(&input, &capture);
    assert_eq!(result["status"], json!("fail"));
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"budget-exceeded:lcp".to_string()));
}

#[test]
fn performance_missing_budgets_is_a_gap_but_not_fail() {
    let capture = passing_capture();
    let input = json!({
        "binding": full_binding(),
        "captures": [
            { "repeat": 1, "performance": { "lcp": 100.0, "memory": 10.0, "longTasks": [1.0], "layoutShifts": [0.1], "paints": [1.0], "userTimings": [1.0] } },
        ],
    });
    let result = verify_web_performance(&input, &capture);
    assert_eq!(result["status"], json!("unproven"));
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"performance-budget-missing".to_string()));
}

// ---------------------------------------------------------------------
// protocols/index.mjs (`executeWebProtocol`)
// ---------------------------------------------------------------------

#[test]
fn protocols_blocks_in_production() {
    let mut binding = full_binding();
    binding["environment"] = json!("production");
    let input = json!({ "binding": binding, "protocol": "csrf" });
    let plan = [ProtocolPlanRow { protocol_id: "csrf", applicable: true }];
    let result = execute_web_protocol(&input, &plan, &no_sanitize, None);
    assert_eq!(result["status"], json!("blocked"));
    assert_eq!(result["coverageGaps"], json!(["production-effect-forbidden"]));
}

#[test]
fn protocols_unrecognized_protocol_is_unproven() {
    let input = json!({ "binding": full_binding(), "protocol": "unknown" });
    let plan = [ProtocolPlanRow { protocol_id: "csrf", applicable: true }];
    let result = execute_web_protocol(&input, &plan, &no_sanitize, None);
    assert_eq!(result["status"], json!("unproven"));
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"protocol-unrecognized".to_string()));
}

#[test]
fn protocols_not_applicable_is_unsupported() {
    let input = json!({ "binding": full_binding(), "protocol": "csrf" });
    let plan = [ProtocolPlanRow { protocol_id: "csrf", applicable: false }];
    let result = execute_web_protocol(&input, &plan, &no_sanitize, None);
    assert_eq!(result["status"], json!("unsupported"));
}

#[test]
fn protocols_missing_adapter_is_unproven() {
    let input = json!({ "binding": full_binding(), "protocol": "csrf" });
    let plan = [ProtocolPlanRow { protocol_id: "csrf", applicable: true }];
    let result = execute_web_protocol(&input, &plan, &no_sanitize, None);
    assert_eq!(result["status"], json!("unproven"));
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"protocol-adapter-missing".to_string()));
}

#[test]
fn protocols_adapter_success_with_full_state_passes() {
    let input = json!({ "binding": full_binding(), "protocol": "csrf" });
    let plan = [ProtocolPlanRow { protocol_id: "csrf", applicable: true }];
    let adapter = |_binding: &Value, _protocol: &str| -> AdapterExecuteResult {
        AdapterExecuteResult::Ok(json!({ "status": "pass", "observedState": { "a": 1 }, "durableState": { "a": 1 } }))
    };
    let result = execute_web_protocol(&input, &plan, &no_sanitize, Some(&adapter));
    assert_eq!(result["status"], json!("pass"));
    assert_eq!(result["observedState"], json!({"a": 1}));
}

#[test]
fn protocols_adapter_error_is_error_status() {
    let input = json!({ "binding": full_binding(), "protocol": "csrf" });
    let plan = [ProtocolPlanRow { protocol_id: "csrf", applicable: true }];
    let adapter = |_binding: &Value, _protocol: &str| -> AdapterExecuteResult {
        AdapterExecuteResult::Err { name: "Error".to_string(), message: "boom".to_string() }
    };
    let result = execute_web_protocol(&input, &plan, &no_sanitize, Some(&adapter));
    assert_eq!(result["status"], json!("error"));
    assert_eq!(result["errors"][0]["message"], json!("boom"));
}

// ---------------------------------------------------------------------
// runner/index.mjs (`runWebControl`)
// ---------------------------------------------------------------------

#[test]
fn runner_unsupported_family_is_blocked() {
    let result = run_web_control(
        &full_binding(),
        None,
        &json!({}),
        &|_| json!({}),
        &|_| json!({}),
        &|_| json!({}),
        &|_| json!({}),
    );
    assert_eq!(result["status"], json!("blocked"));
    assert_eq!(result["coverageGaps"], json!(["web-control-family-unsupported"]));
}

#[test]
fn runner_dispatches_protocol_family() {
    let result = run_web_control(
        &full_binding(),
        Some("protocol"),
        &json!({}),
        &|_| json!({ "status": "pass", "kind": "protocol" }),
        &|_| json!({}),
        &|_| json!({}),
        &|_| json!({}),
    );
    assert_eq!(result["status"], json!("pass"));
    assert_eq!(result["kind"], json!("protocol"));
}

#[test]
fn runner_api_family_relabels_provider_and_drops_envelope_fields() {
    let result = run_web_control(
        &full_binding(),
        Some("api"),
        &json!({}),
        &|_| json!({}),
        &|_| json!({}),
        &|_| json!({}),
        &|_| json!({ "digest": "x", "kind": "y", "schemaVersion": 1, "provider": "runtime.service.api", "status": "pass" }),
    );
    assert_eq!(result["provider"], json!("runtime.web"));
    assert_eq!(result["delegatedProvider"], json!("runtime.service.api"));
    assert_eq!(result["status"], json!("pass"));
    assert_eq!(result["kind"], json!("legion-web-api-provider"));
}

// ---------------------------------------------------------------------
// scenario/index.mjs (`runWebScenario`)
// ---------------------------------------------------------------------

fn one_journey() -> Value {
    json!({
        "id": "journey-1",
        "controlId": "control-1",
        "routeId": "route-1",
        "actionId": "action-1",
        "route": "/home",
        "stateId": "state-1",
        "matrixCombinationId": "combo-1",
        "directApplicable": false,
        "deepApplicable": false,
        "applicable": true,
    })
}

#[test]
fn scenario_invalid_collections_error_immediately() {
    let result = run_web_scenario(
        &full_binding(),
        &json!("nope"),
        &json!([]),
        &json!({}),
        &[one_journey()],
        &[],
        &no_sanitize,
        None,
        None,
    );
    assert_eq!(result["status"], json!("error"));
    assert_eq!(result["coverageGaps"], json!(["scenario-collections-invalid"]));
}

#[test]
fn scenario_blocks_in_production() {
    let mut binding = full_binding();
    binding["environment"] = json!("production");
    let result = run_web_scenario(
        &binding,
        &json!(["control-1"]),
        &json!([]),
        &json!({}),
        &[one_journey()],
        &[],
        &no_sanitize,
        None,
        None,
    );
    assert_eq!(result["status"], json!("blocked"));
    assert!(result["receipts"].as_array().unwrap().iter().all(|r| r["status"] == json!("blocked")));
}

#[test]
fn scenario_control_not_supplied_is_unproven_journey_not_observed() {
    let result = run_web_scenario(
        &full_binding(),
        &json!([]),
        &json!([]),
        &json!({}),
        &[one_journey()],
        &[],
        &no_sanitize,
        None,
        None,
    );
    let receipt = &result["receipts"][0];
    assert_eq!(receipt["status"], json!("unproven"));
    assert_eq!(receipt["coverageGaps"], json!(["journey-not-observed"]));
}

#[test]
fn scenario_missing_adapter_is_unproven() {
    let result = run_web_scenario(
        &full_binding(),
        &json!(["control-1"]),
        &json!([]),
        &json!({}),
        &[one_journey()],
        &[],
        &no_sanitize,
        None,
        None,
    );
    let receipt = &result["receipts"][0];
    assert_eq!(receipt["status"], json!("unproven"));
    assert_eq!(receipt["coverageGaps"], json!(["adapter-missing"]));
}

#[test]
fn scenario_full_pass_with_matching_adapter() {
    let expected_state = json!({ "a": 1 });
    let journey_invoke = |_control: &str, _journey: &Value, _binding: &Value, _expected: &Value| -> AdapterCallResult {
        AdapterCallResult::Ok(json!({
            "status": "pass",
            "terminal": true,
            "observedState": { "a": 1 },
            "durableState": { "a": 1 },
            "browserDiagnostics": {
                "denominator": ["cache", "console", "cookies", "cors", "csp", "error", "headers", "hydration", "network"],
                "facts": [
                    {"id": "cache", "status": "pass", "terminal": true, "binding": full_binding()},
                    {"id": "console", "status": "pass", "terminal": true, "binding": full_binding()},
                    {"id": "cookies", "status": "pass", "terminal": true, "binding": full_binding()},
                    {"id": "cors", "status": "pass", "terminal": true, "binding": full_binding()},
                    {"id": "csp", "status": "pass", "terminal": true, "binding": full_binding()},
                    {"id": "error", "status": "pass", "terminal": true, "binding": full_binding()},
                    {"id": "headers", "status": "pass", "terminal": true, "binding": full_binding()},
                    {"id": "hydration", "status": "pass", "terminal": true, "binding": full_binding()},
                    {"id": "network", "status": "pass", "terminal": true, "binding": full_binding()},
                ],
            },
            "serverAuthorization": {
                "kind": "server-authorization-evidence",
                "source": "server",
                "uiDerived": false,
                "actorId": "actor-1",
                "tenantId": "tenant-1",
                "controlId": "control-1",
                "status": "pass",
                "terminal": true,
                "authorizationIds": ["auth-1"],
                "binding": full_binding(),
            },
        }))
    };
    let result = run_web_scenario(
        &full_binding(),
        &json!(["control-1"]),
        &json!([]),
        &expected_state,
        &[one_journey()],
        &[],
        &no_sanitize,
        Some(&journey_invoke),
        None,
    );
    let receipt = &result["receipts"][0];
    assert_eq!(receipt["status"], json!("pass"), "receipt: {receipt}");
    assert_eq!(receipt["coverageGaps"], json!([]));
    assert_eq!(result["status"], json!("pass"), "result: {result}");
}

#[test]
fn scenario_unplanned_control_marks_preflight_invalid() {
    let result = run_web_scenario(
        &full_binding(),
        &json!(["not-a-real-control"]),
        &json!([]),
        &json!({}),
        &[one_journey()],
        &[],
        &no_sanitize,
        None,
        None,
    );
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.iter().any(|g| g.starts_with("control-unrecognized:not-a-real-control")));
}
