//! Integration tests for packet r46c1
//! (`src/lib/dispatch-validator/validate-dispatch.py::goal_route_errors`,
//! and its sibling GoalRoute artifact/receipt validator ported from
//! `src/lib/goalroute/scripts/validate-route.py`), ported from the cases
//! in `src/lib/dispatch-validator/test_validate_dispatch.py` that exercise
//! goal routes (the `## 1C. Goal Route & Critical Path` section and its
//! `CHECKOUT_RELATIVE_GOAL_ROUTE_*` fixture wiring).

use legion_runtime::wf_port::r46::goal_route_errors;
use legion_runtime::wf_port::r46::goal_route_validator::{validate_receipt, validate_route};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir() -> PathBuf {
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("legion-r46c1-{pid}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// -- goal_route_errors: label/table validation (no filesystem artifact) --

#[test]
fn allow_template_short_circuits_to_no_errors() {
    assert!(goal_route_errors("anything at all", true, None).is_empty());
}

#[test]
fn empty_document_reports_every_missing_goal_route_contract() {
    let errors = goal_route_errors("", false, None);
    // Every one of the 12 `rules` label checks, plus the State A/B
    // concreteness, proof, constraints x5, bottleneck, route mode, and
    // artifact/receipt path requirements should all fire on an empty doc.
    assert!(errors.iter().any(|e| e.contains("**State A:** lacks enforceable")));
    assert!(errors.iter().any(|e| e.contains("**State B:** lacks enforceable")));
    assert!(errors
        .iter()
        .any(|e| e.contains("Goal success proof requires executable action + evidence path")));
    assert!(errors
        .iter()
        .any(|e| e.contains("Hard route constraints missing AUTHORITY")));
    assert!(errors
        .iter()
        .any(|e| e.contains("Bottleneck requires numeric critical-path bound")));
    assert!(errors
        .iter()
        .any(|e| e.contains("Route mode must be COMPARE or SINGLE_FEASIBLE")));
    assert!(errors
        .iter()
        .any(|e| e.contains("Goal route artifact path is required")));
    assert!(errors
        .iter()
        .any(|e| e.contains("Goal route receipt path is required")));
    assert!(errors
        .iter()
        .any(|e| e.contains("goal route comparison requires exactly one SELECTED route")));
}

#[test]
fn state_a_label_present_but_not_concrete_is_flagged_separately() {
    // A one-char state value matches the `^STATE_A:\s*\S` contract regex
    // (any non-space char) but fails `is_concrete` (needs >= 8 chars).
    let text = "- **State A:** STATE_A:x\n";
    let errors = goal_route_errors(text, false, None);
    assert!(!errors.iter().any(|e| e == "**State A:** lacks enforceable goal-route contract"));
    assert!(errors
        .iter()
        .any(|e| e == "**State A:** requires concrete state, not label-only value"));
}

#[test]
fn route_mode_accepts_compare_case_insensitively() {
    let text = "- **Route mode:** `compare`\n";
    let errors = goal_route_errors(text, false, None);
    assert!(!errors.iter().any(|e| e.contains("Route mode must be")));
}

fn minimal_compare_table(status_a: &str, status_b: &str) -> String {
    format!(
        "\
## 1C. Goal Route & Critical Path

| Route | Steps | Dependencies | Constraints | Wall | Expected | Cost | Risk | Rework | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| A | STEPS:A/ONE | EDGES:A/ONE->A/ONE | PASS: ok | 100 | 100 | 1 | 1 | 1 | {status_a} | EVIDENCE:/tmp/a.log |
| B | STEPS:B/ONE | EDGES:B/ONE->B/ONE | PASS: ok | 200 | 200 | 1 | 1 | 1 | {status_b} | DOMINATED_BY:A EVIDENCE:/tmp/b.log |

## 1D. Experiment Topology & Workload Funnel
"
    )
}

#[test]
fn compare_table_row_must_contain_eleven_cells() {
    let text = "\
## 1C. Goal Route & Critical Path

| Route | Steps |
|---|---|
| A | STEPS:A/ONE |

## 1D. Experiment Topology & Workload Funnel
";
    let errors = goal_route_errors(text, false, None);
    assert!(errors
        .iter()
        .any(|e| e.contains("goal route comparison row 1 must contain 11 cells")));
}

#[test]
fn exactly_one_selected_route_is_required() {
    // Both rows SELECTED: violates "exactly one SELECTED route".
    let table = minimal_compare_table("SELECTED", "SELECTED");
    let errors = goal_route_errors(&table, false, None);
    assert!(errors
        .iter()
        .any(|e| e == "goal route comparison requires exactly one SELECTED route"));
}

#[test]
fn single_feasible_mode_rejects_multiple_candidate_rows() {
    let mut text = String::from("- **Route mode:** `single_feasible`\n\n");
    text.push_str(&minimal_compare_table("SELECTED", "REJECTED"));
    let errors = goal_route_errors(&text, false, None);
    assert!(errors
        .iter()
        .any(|e| e == "SINGLE_FEASIBLE route mode requires exactly one candidate route"));
}

// -- GoalRoute artifact validator (validate_route / validate_receipt) --

fn minimal_valid_route() -> serde_json::Value {
    json!({
        "schema": "goal-route.v2",
        "route_id": "r46c1-fixture",
        "purpose": "DELIVERY",
        "routine": true,
        "comparison_mode": "SINGLE_FEASIBLE",
        "state_a": {
            "description": "repository at baseline before the fix lands",
            "evidence": [
                {
                    "locator": "src/lib/example.py",
                    "sha256": "a".repeat(64),
                    "check": "file exists and is unmodified"
                }
            ]
        },
        "state_b": {
            "description": "repository with the fix landed and verified",
            "proof": [
                {
                    "command": "run the verification suite",
                    "expected": "all checks pass",
                    "evidence_path": "/tmp/state-b-proof.log"
                }
            ]
        },
        "constraints": {
            "authority": {"rule": "only touch owned files", "evidence_locator": "/tmp/authority.log"},
            "safety": {"rule": "no destructive operations", "evidence_locator": "/tmp/safety.log"},
            "scope": {"rule": "single packet only", "evidence_locator": "/tmp/scope.log"},
            "quality": {"rule": "tests must pass", "evidence_locator": "/tmp/quality.log"},
            "cost": {"rule": "bounded token budget", "evidence_locator": "/tmp/cost.log"}
        },
        "single_feasible_evidence": ["/tmp/only-feasible.log"],
        "candidates": [
            {
                "id": "A",
                "constraint_status": "PASS",
                "constraint_evidence": "/tmp/constraint.log",
                "steps": [
                    {
                        "id": "A/ONE",
                        "operation": "run the fix script",
                        "min_wall_ms": 100,
                        "kind": "ADVANCE_B",
                        "b_state_delta": "state moved",
                        "depends_on": []
                    }
                ],
                "nominal_critical_path_ms": 100,
                "probabilities_bps": {"retry": 0, "terminal_failure": 0},
                "retry_cost_ms": 0,
                "rework_cost_ms": 0,
                "cost_units": 1,
                "risk_units": 1,
                "rework_units": 1,
                "expected_time_to_verified_b_ms": 100,
                "status": "SELECTED",
                "evidence": ["/tmp/candidate-a.log"]
            }
        ],
        "selected_route_id": "A",
        "selected_critical_path": ["A/ONE"],
        "parallel_lanes": [],
        "bottleneck": {"step_id": "A/ONE", "bound_ms": 100, "resource": "single worker"},
        "deleted_work": [],
        "deferred_work": [],
        "invalidation": {
            "revision": 1,
            "semantic_correction": "NONE",
            "source_fingerprint_sha256": "b".repeat(64),
            "invalidates": []
        },
        "alchemist": {"required": false, "reason": "routine single-candidate fix, no comparison"}
    })
}

#[test]
fn minimal_valid_route_has_no_errors() {
    let route = minimal_valid_route();
    let errors = validate_route(&route);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn route_missing_schema_is_rejected() {
    let mut route = minimal_valid_route();
    route["schema"] = json!("wrong-schema");
    let errors = validate_route(&route);
    assert!(errors.iter().any(|e| e == "schema must equal goal-route.v2"));
}

#[test]
fn route_with_cyclic_steps_is_rejected() {
    let mut route = minimal_valid_route();
    route["candidates"][0]["steps"] = json!([
        {
            "id": "A/ONE",
            "operation": "run the fix script",
            "min_wall_ms": 100,
            "kind": "ADVANCE_B",
            "b_state_delta": "state moved",
            "depends_on": ["A/TWO"]
        },
        {
            "id": "A/TWO",
            "operation": "run the follow-up script",
            "min_wall_ms": 100,
            "kind": "ADVANCE_B",
            "b_state_delta": "state moved again",
            "depends_on": ["A/ONE"]
        }
    ]);
    let errors = validate_route(&route);
    assert!(errors
        .iter()
        .any(|e| e.contains("dependency graph contains cycle")));
}

#[test]
fn selected_candidate_must_pass_constraints() {
    let mut route = minimal_valid_route();
    route["candidates"][0]["constraint_status"] = json!("FAIL");
    let errors = validate_route(&route);
    assert!(errors
        .iter()
        .any(|e| e == "selected candidate A must pass constraints"));
}

#[test]
fn non_routine_route_without_alchemist_required_is_rejected() {
    let mut route = minimal_valid_route();
    route["routine"] = json!(false);
    let errors = validate_route(&route);
    assert!(errors.iter().any(|e| e == "non-routine route requires Alchemist"));
}

#[test]
fn alchemist_required_with_valid_uuid_binding_has_no_errors() {
    let mut route = minimal_valid_route();
    route["routine"] = json!(false);
    route["alchemist"] = json!({
        "required": true,
        "run_id": "0d4ce380-d482-41bc-b65c-1049448502b6",
        "state_ref": "alchemist://run/0d4ce380-d482-41bc-b65c-1049448502b6/state",
        "checkpoint": "GOAL_ROUTE_V2"
    });
    let errors = validate_route(&route);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn validate_receipt_reports_mismatch_against_a_wrong_route_sha() {
    let dir = temp_dir();
    let route_path = dir.join("route.json");
    let receipt_path = dir.join("route.receipt.json");
    let route_bytes = serde_json::to_vec(&minimal_valid_route()).unwrap();
    std::fs::write(&route_path, &route_bytes).unwrap();
    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&json!({
            "schema": "goal-route.receipt.v2",
            "route_path": "route.json",
            "route_sha256": "0".repeat(64),
            "validator_version": "2.1.0",
            "validator_sha256": "0".repeat(64)
        }))
        .unwrap(),
    )
    .unwrap();

    let errors = validate_receipt(&route_path, &receipt_path, &route_bytes);
    assert!(errors.iter().any(|e| e == "receipt route_sha256 mismatch"));
}

#[test]
fn validate_receipt_reports_unreadable_receipt() {
    let dir = temp_dir();
    let route_path = dir.join("route.json");
    let receipt_path = dir.join("missing-receipt.json");
    let route_bytes = serde_json::to_vec(&minimal_valid_route()).unwrap();
    std::fs::write(&route_path, &route_bytes).unwrap();

    let errors = validate_receipt(&route_path, &receipt_path, &route_bytes);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].starts_with("receipt unreadable:"));
}
