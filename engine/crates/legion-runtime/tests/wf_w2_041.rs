//! Integration tests for chunk w2_041
//! (`src/lib/core/plan-stages/{control-baseline,index,product-topology,
//! registry}.mjs` and `src/lib/core/reconcile-run.mjs`).
//!
//! These exercise the ported functions through the crate's public surface,
//! as opposed to the unit tests colocated in each `wf_port::w2_041::*`
//! module. This file requires the integrator wiring noted in this chunk's
//! report (`pub mod wf_port;` / `pub mod w2_041;` in
//! `src/wf_port/mod.rs`) to compile.

use legion_runtime::wf_port::w2_041::control_baseline::{control_baseline_stage, resolve_topology};
use legion_runtime::wf_port::w2_041::product_topology::product_topology_stage_result;
use legion_runtime::wf_port::w2_041::reconcile_run::reconcile_run;
use legion_runtime::wf_port::w2_041::registry::{run_planning_stages, PlanStage};
use serde_json::{json, Value};

#[test]
fn product_topology_stage_reports_unknown_stack_gap() {
    let artifact = json!({
        "portfolio": {"targets": [{"id": "t1", "conflicts": []}], "coverage": {"unknownDeliverables": []}, "conflicts": []},
        "components": {"coverage": {"unknownComponents": [], "expectedTargets": 1, "coveredTargets": 1}},
        "stacks": {"coverage": {"unknownStacks": ["s1"]}},
        "externalSystems": {"systems": []},
        "journeys": {"gaps": []},
        "productContext": {"gaps": []},
        "claimImpact": [],
        "scenarios": {"omitted": []},
    });
    let result = product_topology_stage_result(&artifact);
    assert_eq!(result["complete"], json!(false));
    assert_eq!(result["status"], json!("unproven"));
    assert_eq!(result["detail"], json!("unknown-stack"));
    assert_eq!(result["artifact"], artifact);
}

#[test]
fn control_baseline_stage_end_to_end_missing_then_pass() {
    // No topology at all.
    let missing = control_baseline_stage(None, 1, || json!({"controls": []}), |_| Vec::new());
    assert_eq!(missing["status"], json!("missing"));

    // Topology present, packs present, baseline with one control, no impacts.
    let artifacts = json!({"product-portfolio": {"portfolio": {}, "components": {}, "stacks": {"stacks": []}}});
    let topology = resolve_topology(Some(&artifacts), None).unwrap().clone();
    let pass = control_baseline_stage(
        Some(&topology),
        1,
        || json!({"controls": [{"id": "c1"}]}),
        |_| Vec::new(),
    );
    assert_eq!(pass["status"], json!("pass"));
    assert_eq!(pass["complete"], json!(true));
}

#[test]
fn run_planning_stages_wires_product_topology_and_control_baseline_end_to_end() {
    struct ProductTopology;
    impl PlanStage for ProductTopology {
        fn id(&self) -> &str {
            "product-portfolio"
        }
        fn run(&self, _options: &Value, _host: &Value) -> Value {
            product_topology_stage_result(&json!({
                "portfolio": {"targets": [{"id": "t1", "conflicts": []}], "coverage": {"unknownDeliverables": []}, "conflicts": []},
                "components": {"coverage": {"unknownComponents": [], "expectedTargets": 0, "coveredTargets": 0}},
                "stacks": {"coverage": {"unknownStacks": []}},
                "externalSystems": {"systems": []},
                "journeys": {"gaps": []},
                "productContext": {"gaps": []},
                "claimImpact": [],
                "scenarios": {"omitted": []},
            }))
        }
    }

    struct ControlBaseline;
    impl PlanStage for ControlBaseline {
        fn id(&self) -> &str {
            "control-baseline"
        }
        fn run(&self, options: &Value, _host: &Value) -> Value {
            let topology = options.pointer("/artifacts/product-portfolio").cloned();
            control_baseline_stage(
                topology.as_ref(),
                1,
                || json!({"controls": [{"id": "c1"}]}),
                |_| Vec::new(),
            )
        }
    }

    let product_topology = ProductTopology;
    let control_baseline = ControlBaseline;
    let stages: Vec<&dyn PlanStage> = vec![&product_topology, &control_baseline];
    let result = run_planning_stages(&stages, &json!({}), &json!({}), "inventory");
    assert_eq!(result["artifacts"]["control-baseline"]["baseline"]["controls"], json!([{"id": "c1"}]));
    // repository-binding and blueprint-packet are still required for "inventory" and unregistered.
    let gaps = result["gaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g["stage"] == json!("repository-binding")));
    assert!(gaps.iter().any(|g| g["stage"] == json!("blueprint-packet")));
    assert!(!gaps.iter().any(|g| g["stage"] == json!("product-portfolio")));
}

#[test]
fn reconcile_run_end_to_end_pass_when_every_provider_passes_cleanly() {
    let plan = json!({
        "root": "/repo",
        "binding": {"repo": "sha256:abc"},
        "providers": [
            {"id": "arch", "phase": "structure", "benchmark": "b-arch", "denominatorDigest": "d1"},
        ],
    });
    let receipts = vec![json!({
        "provider": "arch",
        "binding": {"repo": "sha256:abc"},
        "denominatorDigest": "d1",
        "exitCode": 0,
        "spawnStatus": "completed",
        "providerResult": {"status": "pass", "complete": true, "provider": "arch", "coverageGaps": []},
    })];
    let facts = reconcile_run(&plan, &receipts, None, "2026-09-23T00:00:00.000Z");
    assert_eq!(facts["incomplete"], json!(false));
    assert_eq!(facts["executionFailed"], json!(false));
    assert_eq!(facts["provider_reconciliation"]["duplicateChecks"], json!([]));
    assert_eq!(facts["provider_reconciliation"]["unplannedChecks"], json!([]));
    assert_eq!(facts["provider_reconciliation"]["bindingMismatches"], json!([]));
    assert_eq!(facts["provider_reconciliation"]["denominatorMismatches"], json!([]));
    assert_eq!(facts["checks"][0]["verdict"], json!("pass"));
}
