//! Integration test for the production entry point of packet r45's port of
//! `src/lib/core/inspect-product.mjs`:
//! `legion_runtime::wf_port::r45::inspect_product::inspect_product_from_projection`.
//! Exercises the full wiring through the real `l3_inventory` builders and
//! `w2_041::control_baseline::compile_baseline_and_impacts_json`, not just
//! the pure-assembly unit tests inline in `inspect_product.rs`.

use legion_runtime::wf_port::r45::inspect_product::{inspect_product_from_projection, InspectProductOptions};
use serde_json::json;
use std::path::Path;

#[test]
fn inspect_product_from_projection_assembles_a_full_inspection_with_zero_packs() {
    let projection = json!({
        "files": ["src/auth/login.ts", "Cargo.toml"],
        "dependencies": {"rust": "1.0.0"},
        "entrypoints": [],
        "buildOutputs": [],
    });
    let binding = serde_json::Value::Null;
    let host = json!({"capabilities": {}});

    let result = inspect_product_from_projection(InspectProductOptions {
        projection: &projection,
        declarations: vec![],
        target_relations: vec![],
        target_conflicts: vec![],
        material_deliverables: vec![],
        binding: &binding,
        release_contract: &json!({}),
        packs: Some(vec![]),
        repo_root: Path::new("."),
        host: &host,
        now_ms: Some(1_000),
    })
    .expect("inspection should assemble without error");

    assert_eq!(result["schemaVersion"], json!(1));
    assert_eq!(result["kind"], json!("legion-product-inspection"));
    assert!(result["portfolio"]["digest"].as_str().unwrap().starts_with("sha256:"));
    // Zero packs -> compileBaseline sees an empty control set -> denominator
    // is empty, mirroring `control-baseline.mjs`'s own
    // `control-denominator-missing`/`control-denominator-zero` handling for
    // the *stage* wrapper; here (direct `compile_baseline_and_impacts_json`
    // call, not the stage) an empty pack list simply yields an empty
    // baseline, not an error.
    assert_eq!(result["baseline"]["controls"], json!([]));
    assert_eq!(result["reportSkeleton"]["controlIds"], json!([]));
    assert!(result["reportSkeleton"]["targetIds"].as_array().unwrap().len() >= 1);
}

#[test]
fn inspect_product_from_projection_reuses_an_already_merged_release_contract() {
    let projection = json!({"files": [], "entrypoints": [], "buildOutputs": []});
    let binding = serde_json::Value::Null;
    let host = json!({"capabilities": {}});
    let release_contract = json!({"kind": "legion-release-contract", "environments": ["prod"], "roles": [], "supportedPlatforms": []});

    let result = inspect_product_from_projection(InspectProductOptions {
        projection: &projection,
        declarations: vec![],
        target_relations: vec![],
        target_conflicts: vec![],
        material_deliverables: vec![],
        binding: &binding,
        release_contract: &release_contract,
        packs: Some(vec![]),
        repo_root: Path::new("."),
        host: &host,
        now_ms: None,
    })
    .expect("inspection should assemble without error");

    // Passed through untouched, not re-merged (mirrors
    // `releaseContract.kind === 'legion-release-contract' ? releaseContract : mergeReleaseContract(...)`).
    assert_eq!(result["releaseContract"]["environments"], json!(["prod"]));
}
