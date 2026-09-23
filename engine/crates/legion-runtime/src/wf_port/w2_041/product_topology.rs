//! Port of `src/lib/core/plan-stages/product-topology.mjs`.
//!
//! `productTopologyStage.run(options, host)` calls `inspectProduct(options,
//! host)` (from `inspect-product.mjs`, which composes `inventory/*` — a
//! large graph of dependencies owned by other chunks, not this one) and then
//! computes a completeness verdict from the resulting artifact. Only that
//! second, self-contained half — the verdict computation given an already
//! built artifact — is this chunk's file, and it is ported here in full.

use serde_json::{json, Value};

/// Port of the body of `productTopologyStage.run` starting from
/// `const artifact = await inspectProduct(options, host)`: given that
/// already-built `legion-product-inspection` artifact, returns
/// `{ complete, status, artifact, detail }`.
pub fn product_topology_stage_result(artifact: &Value) -> Value {
    let target_count = array_len(artifact, "/portfolio/targets");
    let unknown_targets = array_len(artifact, "/portfolio/coverage/unknownDeliverables");
    let unknown_components = array_len(artifact, "/components/coverage/unknownComponents");
    let expected_targets = artifact
        .pointer("/components/coverage/expectedTargets")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let covered_targets = artifact
        .pointer("/components/coverage/coveredTargets")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let uncovered_targets = expected_targets.saturating_sub(covered_targets);
    let unknown_stacks = array_len(artifact, "/stacks/coverage/unknownStacks");
    let unknown_external = artifact
        .pointer("/externalSystems/systems")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("status").and_then(Value::as_str) == Some("unknown"))
                .count()
        })
        .unwrap_or(0);
    let journey_gaps = array_len(artifact, "/journeys/gaps");
    let context_gaps = array_len(artifact, "/productContext/gaps");
    let capability_gaps = array_len(artifact, "/claimImpact");
    let scenario_gaps = artifact
        .pointer("/scenarios/omitted")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("mandatory").and_then(Value::as_bool).unwrap_or(false))
                .count()
        })
        .unwrap_or(0);
    let portfolio_conflicts = array_len(artifact, "/portfolio/conflicts");
    let target_conflicts: usize = artifact
        .pointer("/portfolio/targets")
        .and_then(Value::as_array)
        .map(|targets| {
            targets
                .iter()
                .map(|target| {
                    target
                        .get("conflicts")
                        .and_then(Value::as_array)
                        .map(|a| a.len())
                        .unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0);
    let conflicts = portfolio_conflicts + target_conflicts;

    let complete = target_count > 0
        && unknown_targets == 0
        && unknown_components == 0
        && uncovered_targets == 0
        && unknown_stacks == 0
        && unknown_external == 0
        && journey_gaps == 0
        && context_gaps == 0
        && capability_gaps == 0
        && scenario_gaps == 0
        && conflicts == 0;

    let detail: Option<&str> = if target_count == 0 {
        Some("target-denominator-zero")
    } else if unknown_targets > 0 {
        Some("unaccounted-deliverable")
    } else if unknown_components > 0 {
        Some("unknown-material-component")
    } else if uncovered_targets > 0 {
        Some("target-component-coverage-gap")
    } else if unknown_stacks > 0 {
        Some("unknown-stack")
    } else if unknown_external > 0 {
        Some("external-system-evidence-gap")
    } else if journey_gaps > 0 {
        Some("journey-coverage-gap")
    } else if context_gaps > 0 {
        Some("product-context-gap")
    } else if capability_gaps > 0 {
        Some("capability-evidence-gap")
    } else if scenario_gaps > 0 {
        Some("mandatory-scenario-gap")
    } else if conflicts > 0 {
        Some("target-conflict")
    } else {
        None
    };

    json!({
        "complete": complete,
        "status": if complete { "pass" } else { "unproven" },
        "artifact": artifact,
        "detail": detail,
    })
}

fn array_len(value: &Value, pointer: &str) -> usize {
    value.pointer(pointer).and_then(Value::as_array).map(|a| a.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_artifact() -> Value {
        json!({
            "portfolio": {"targets": [{"id": "t1", "conflicts": []}], "coverage": {"unknownDeliverables": []}, "conflicts": []},
            "components": {"coverage": {"unknownComponents": [], "expectedTargets": 1, "coveredTargets": 1}},
            "stacks": {"coverage": {"unknownStacks": []}},
            "externalSystems": {"systems": []},
            "journeys": {"gaps": []},
            "productContext": {"gaps": []},
            "claimImpact": [],
            "scenarios": {"omitted": []},
        })
    }

    #[test]
    fn complete_when_every_denominator_is_covered() {
        let result = product_topology_stage_result(&base_artifact());
        assert_eq!(result["complete"], json!(true));
        assert_eq!(result["status"], json!("pass"));
        assert!(result["detail"].is_null());
    }

    #[test]
    fn zero_targets_reports_denominator_zero_first() {
        let mut artifact = base_artifact();
        artifact["portfolio"]["targets"] = json!([]);
        let result = product_topology_stage_result(&artifact);
        assert_eq!(result["complete"], json!(false));
        assert_eq!(result["detail"], json!("target-denominator-zero"));
    }

    #[test]
    fn detail_precedence_matches_js_ternary_chain() {
        // unknownTargets and unknownComponents both non-zero: unknownTargets wins.
        let mut artifact = base_artifact();
        artifact["portfolio"]["coverage"]["unknownDeliverables"] = json!(["d1"]);
        artifact["components"]["coverage"]["unknownComponents"] = json!(["c1"]);
        let result = product_topology_stage_result(&artifact);
        assert_eq!(result["detail"], json!("unaccounted-deliverable"));
    }

    #[test]
    fn uncovered_targets_uses_saturating_subtraction() {
        let mut artifact = base_artifact();
        artifact["components"]["coverage"]["expectedTargets"] = json!(1);
        artifact["components"]["coverage"]["coveredTargets"] = json!(0);
        let result = product_topology_stage_result(&artifact);
        assert_eq!(result["detail"], json!("target-component-coverage-gap"));
    }

    #[test]
    fn mandatory_scenario_gap_ignores_non_mandatory_omissions() {
        let mut artifact = base_artifact();
        artifact["scenarios"]["omitted"] = json!([{"mandatory": false}]);
        let result = product_topology_stage_result(&artifact);
        assert_eq!(result["complete"], json!(true));
    }

    #[test]
    fn target_conflicts_are_summed_with_portfolio_conflicts() {
        let mut artifact = base_artifact();
        artifact["portfolio"]["targets"] = json!([{"id": "t1", "conflicts": ["x", "y"]}]);
        let result = product_topology_stage_result(&artifact);
        assert_eq!(result["detail"], json!("target-conflict"));
    }
}
