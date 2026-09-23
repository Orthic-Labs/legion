//! Port of `src/lib/core/plan-stages/{registry,index}.mjs`.
//!
//! The two static tables `registry.mjs` defines — `PLANNING_STAGE_IDS` and
//! the per-claim-level `REQUIRED` stage list — are **ALREADY-NATIVE-VERIFIED**:
//! they are ported byte-for-byte as
//! [`crate::p5_core::PLANNING_STAGE_IDS`] / [`crate::p5_core::required_stages_for`]
//! (`src/p5_core/core_records.rs`, `plan-stages/registry.mjs: PLANNING_STAGE_IDS,
//! requiredStagesFor`). This file does not duplicate them.
//!
//! What `registry.mjs` also defines, and what had no native port before this
//! chunk, is the `runPlanningStages(stages, options, host)` orchestration
//! loop itself. That is ported here as [`run_planning_stages`], operating on
//! a small [`PlanStage`] trait so it stays independent of any concrete
//! stage's own dependencies (which belong to other chunks). `index.mjs` is a
//! pure re-export of `registry.mjs` plus the two sibling stage modules and
//! has no behaviour to port.

use crate::p5_core::{required_stages_for, PLANNING_STAGE_IDS};
use serde_json::{json, Map, Value};

/// A single planning stage, matching the `{ id, run(options, host) }` shape
/// `registry.mjs` expects. `run` is synchronous here: every ported stage
/// decision in this chunk (`product_topology_stage_result`,
/// `control_baseline_stage`) is itself synchronous once its own out-of-chunk
/// data dependencies are supplied by the caller.
pub trait PlanStage {
    fn id(&self) -> &str;
    fn run(&self, options: &Value, host: &Value) -> Value;
}

/// Port of `runPlanningStages(stages, options = {}, host = {})`.
///
/// `claim_level` stands in for `options.claimLevel ?? 'inventory'` (the JS
/// reads it off `options`; it is taken as an explicit parameter here so
/// callers are not required to round-trip it through a JSON `options`
/// object). Returns `{ status, complete, artifacts, gaps }`.
pub fn run_planning_stages(stages: &[&dyn PlanStage], options: &Value, host: &Value, claim_level: &str) -> Value {
    let by_id: std::collections::HashMap<&str, &dyn PlanStage> =
        stages.iter().map(|s| (s.id(), *s)).collect();
    let required = required_stages_for(claim_level);

    let mut artifacts = Map::new();
    let mut gaps: Vec<Value> = Vec::new();

    for id in PLANNING_STAGE_IDS.iter() {
        match by_id.get(id) {
            None => {
                if required.contains(id) {
                    gaps.push(json!({"stage": id, "status": "missing"}));
                }
            }
            Some(stage) => {
                let mut merged_options = options.clone();
                if let Value::Object(map) = &mut merged_options {
                    map.insert("artifacts".to_string(), Value::Object(artifacts.clone()));
                } else {
                    merged_options = json!({"artifacts": artifacts.clone()});
                }
                let result = stage.run(&merged_options, host);
                if let Some(artifact) = result.get("artifact") {
                    if !artifact.is_null() {
                        artifacts.insert((*id).to_string(), artifact.clone());
                    }
                }
                let complete = result.get("complete").and_then(Value::as_bool).unwrap_or(false);
                if !complete {
                    let status = result
                        .get("status")
                        .cloned()
                        .filter(|v| !v.is_null())
                        .unwrap_or(json!("unproven"));
                    let detail = result.get("detail").cloned().unwrap_or(Value::Null);
                    gaps.push(json!({"stage": id, "status": status, "detail": detail}));
                }
            }
        }
    }

    json!({
        "status": if gaps.is_empty() { "pass" } else { "unproven" },
        "complete": gaps.is_empty(),
        "artifacts": artifacts,
        "gaps": gaps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedStage {
        id: &'static str,
        result: Value,
    }

    impl PlanStage for FixedStage {
        fn id(&self) -> &str {
            self.id
        }
        fn run(&self, _options: &Value, _host: &Value) -> Value {
            self.result.clone()
        }
    }

    #[test]
    fn unregistered_required_stage_reports_a_missing_gap() {
        let stages: Vec<&dyn PlanStage> = Vec::new();
        let result = run_planning_stages(&stages, &json!({}), &json!({}), "inventory");
        let gaps = result["gaps"].as_array().unwrap();
        // inventory requires repository-binding, blueprint-packet, product-portfolio.
        assert_eq!(gaps.len(), 3);
        assert!(gaps.iter().all(|g| g["status"] == json!("missing")));
        assert_eq!(result["status"], json!("unproven"));
        assert_eq!(result["complete"], json!(false));
    }

    #[test]
    fn unregistered_non_required_stage_for_this_claim_level_is_silently_skipped() {
        let stage = FixedStage {
            id: "repository-binding",
            result: json!({"complete": true, "artifact": {"k": "v"}}),
        };
        let stages: Vec<&dyn PlanStage> = vec![&stage];
        let result = run_planning_stages(&stages, &json!({}), &json!({}), "inventory");
        // blueprint-packet and product-portfolio are still required and missing.
        let gaps = result["gaps"].as_array().unwrap();
        assert_eq!(gaps.len(), 2);
        assert!(gaps.iter().any(|g| g["stage"] == json!("blueprint-packet")));
        assert!(gaps.iter().any(|g| g["stage"] == json!("product-portfolio")));
    }

    #[test]
    fn registered_stage_artifact_is_recorded_and_threaded_to_the_next_stage() {
        struct SeenArtifacts;
        impl PlanStage for SeenArtifacts {
            fn id(&self) -> &str {
                "blueprint-packet"
            }
            fn run(&self, options: &Value, _host: &Value) -> Value {
                let seen = options.get("artifacts").and_then(|a| a.get("repository-binding")).cloned();
                json!({"complete": true, "artifact": {"sawPrior": seen}})
            }
        }
        let first = FixedStage {
            id: "repository-binding",
            result: json!({"complete": true, "artifact": {"marker": "rb"}}),
        };
        let second = SeenArtifacts;
        let stages: Vec<&dyn PlanStage> = vec![&first, &second];
        let result = run_planning_stages(&stages, &json!({}), &json!({}), "inventory");
        assert_eq!(
            result["artifacts"]["blueprint-packet"]["sawPrior"],
            json!({"marker": "rb"})
        );
        // product-portfolio is still required and unregistered.
        assert_eq!(result["gaps"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn incomplete_stage_records_status_and_detail_gap() {
        let stage = FixedStage {
            id: "repository-binding",
            result: json!({"complete": false, "status": "unproven", "detail": "some-detail"}),
        };
        let stages: Vec<&dyn PlanStage> = vec![&stage];
        let result = run_planning_stages(&stages, &json!({}), &json!({}), "inventory");
        let gap = result["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["stage"] == json!("repository-binding"))
            .unwrap();
        assert_eq!(gap["status"], json!("unproven"));
        assert_eq!(gap["detail"], json!("some-detail"));
    }

    #[test]
    fn runtime_claim_level_requires_every_planning_stage() {
        let stages: Vec<&dyn PlanStage> = Vec::new();
        let result = run_planning_stages(&stages, &json!({}), &json!({}), "runtime");
        assert_eq!(result["gaps"].as_array().unwrap().len(), PLANNING_STAGE_IDS.len());
    }
}
