//! Cross-module smoke tests for the L3 inventory port
//! (`legion_runtime::l3_inventory`), exercising the composite entry points
//! that call across several source `.mjs` files at once, rather than the
//! per-function unit tests already inline in each `l3_inventory` submodule.

use legion_runtime::l3_inventory::{components, journeys, product_targets, stacks};
use serde_json::json;

#[test]
fn end_to_end_portfolio_components_and_stacks_are_consistent() {
    let projection = json!({
        "files": ["src/auth/login.ts", "Cargo.toml", "src/db/schema.sql"],
        "dependencies": {"rust": "1.0.0", "stripe": "1.0.0"},
        "entrypoints": [],
        "buildOutputs": [],
    });

    let targets = product_targets::discover_targets(&projection, &serde_json::Value::Null);
    assert!(!targets.is_empty());

    let portfolio = product_targets::build_portfolio(
        targets,
        vec![],
        vec![],
        vec![],
        vec![],
        serde_json::Value::Null,
    )
    .expect("valid target portfolio should build without error");
    assert_eq!(portfolio["kind"], "legion-product-portfolio");

    let graph = components::extract_components(&portfolio, &projection, &serde_json::Value::Null)
        .expect("component extraction should succeed for a consistent portfolio");
    assert_eq!(graph["kind"], "legion-component-graph");

    let stack_graph = stacks::build_stack_graph(&portfolio, &graph, &projection, &serde_json::Value::Null);
    assert_eq!(stack_graph["kind"], "legion-stack-graph");
    let known: Vec<_> = stack_graph["stacks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["known"] == true)
        .collect();
    assert!(!known.is_empty(), "rust/stripe dependencies should classify as known stacks");
}

#[test]
fn journeys_are_scoped_per_target() {
    let portfolio = json!({"targets": [{"id": "target:a"}, {"id": "target:b"}]});
    let contract = json!({"declared": {"criticalJourneys": ["sign-up", "checkout"]}});
    let result = journeys::build_journeys(&portfolio, &contract, &json!({}), &serde_json::Value::Null);
    assert_eq!(result["journeys"].as_array().unwrap().len(), 4);
    assert!(result["complete"].as_bool().unwrap());
}
