//! Integration port of the subset of `tests/provider-sdk.test.mjs` and all of
//! `tests/provider-dag.test.mjs` covered by wf011
//! (`src/lib/providers/sdk/{artifacts,contracts,dag,index,result}.mjs`).
//!
//! `provider-sdk.test.mjs`'s `stableId`/`pathDenominator`/
//! `validateProviderRecord` tests exercise `testkit.mjs`, which is outside
//! this chunk, so they are not ported here.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf011;`
//! inside it) into `legion-audit`'s `src/lib.rs`.

use legion_audit::wf_port::wf011::{
    normalize_provider_result, topological_providers, validate_artifact_authority, validate_provider_dag,
    validate_provider_output_authority, validate_provider_v2, validate_role_output,
};
use serde_json::json;

// --- provider-sdk.test.mjs (normalizeProviderResult / topologicalProviders) ---

#[test]
fn normalize_provider_result_is_reexported_through_the_sdk() {
    let provider = json!({
        "id": "p",
        "denominator": {"pathDigest": "sha256:d"},
        "benchmark": {"requiredForCleanClaim": true},
    });
    let result = json!({"status": "pass", "complete": true, "findings": []});
    let normalized = normalize_provider_result(&provider, &result);
    assert_eq!(normalized["provider"], "p");
    assert_eq!(normalized["required"], true);
}

#[test]
fn topological_providers_is_exported_through_the_sdk() {
    let ordered = topological_providers(&[
        json!({"id": "b", "dependsOn": ["a"]}),
        json!({"id": "a", "dependsOn": []}),
    ])
    .unwrap();
    let ids: Vec<&str> = ordered.iter().map(|p| p["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["a", "b"]);
}

// --- provider-dag.test.mjs ---

fn p(id: &str, deps: Vec<&str>, produces: Vec<&str>, consumes: Vec<&str>, role: &str) -> serde_json::Value {
    json!({
        "id": id, "providerVersion": "1.0.0", "role": role, "phase": "runtime",
        "dependsOn": deps, "produces": produces, "consumes": consumes,
        "activation": {"kind": "always"}, "runner": {"kind": "runtime-script"},
        "benchmark": {"status": "unproven", "requiredForCleanClaim": true},
    })
}

#[test]
fn topological_order_respects_dependencies() {
    let ordered = topological_providers(&[
        p("c", vec!["a", "b"], vec![], vec![], "deterministic"),
        p("a", vec![], vec![], vec![], "deterministic"),
        p("b", vec!["a"], vec![], vec![], "deterministic"),
    ])
    .unwrap();
    let ids: Vec<&str> = ordered.iter().map(|p| p["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["a", "b", "c"]);
}

#[test]
fn unknown_dependency_is_rejected() {
    let err = topological_providers(&[p("a", vec!["ghost"], vec![], vec![], "deterministic")]).unwrap_err();
    assert!(err.0.contains("depends on unknown"));
}

#[test]
fn self_dependency_is_rejected() {
    let err = topological_providers(&[p("a", vec!["a"], vec![], vec![], "deterministic")]).unwrap_err();
    assert!(err.0.contains("depends on itself"));
}

#[test]
fn dependency_cycle_is_rejected() {
    let err = topological_providers(&[
        p("a", vec!["b"], vec![], vec![], "deterministic"),
        p("b", vec!["a"], vec![], vec![], "deterministic"),
    ])
    .unwrap_err();
    assert!(err.0.contains("cycle"));
}

#[test]
fn unproduced_consumed_artifact_is_rejected() {
    let err =
        validate_provider_dag(&[p("a", vec![], vec![], vec!["security-surface-model"], "deterministic")]).unwrap_err();
    assert!(err.0.contains("consumes unproduced"));
}

#[test]
fn duplicate_singleton_producer_is_rejected() {
    let err = validate_provider_dag(&[
        p("a", vec![], vec!["security-candidates"], vec![], "deterministic"),
        p("b", vec![], vec!["security-candidates"], vec![], "deterministic"),
    ])
    .unwrap_err();
    assert!(err.0.contains("produced by both"));
}

#[test]
fn role_output_authority_violations_are_rejected() {
    assert!(validate_role_output(&p("a", vec![], vec!["security-candidates"], vec![], "model-builder"))
        .unwrap_err()
        .0
        .contains("may not produce"));
    assert!(validate_role_output(&p("a", vec![], vec!["findings"], vec![], "adjudicator"))
        .unwrap_err()
        .0
        .contains("may not produce"));
    assert!(validate_role_output(&p(
        "a",
        vec![],
        vec!["attack-path-hypotheses"],
        vec![],
        "candidate-generator"
    ))
    .unwrap_err()
    .0
    .contains("may not produce"));
    assert!(validate_role_output(&p("a", vec![], vec!["findings"], vec![], "evidence-synthesizer")).is_ok());
}

#[test]
fn unknown_role_is_rejected() {
    let err = validate_role_output(&json!({"id": "x", "role": "not-a-role", "produces": []})).unwrap_err();
    assert!(err.0.contains("unknown role"));
}

#[test]
fn valid_dag_validates_cleanly() {
    let ok = validate_provider_dag(&[
        p("surface", vec![], vec!["security-surface-model"], vec![], "model-builder"),
        p(
            "packs",
            vec!["surface"],
            vec!["security-candidates"],
            vec!["security-surface-model"],
            "candidate-generator",
        ),
    ])
    .unwrap();
    assert!(ok);
}

// --- artifacts.mjs (validateArtifactAuthority) ---

#[test]
fn artifact_authority_rejects_duplicate_producer_and_unproduced_consumer() {
    let dup = validate_artifact_authority(&[
        json!({"id": "a", "produces": ["x"]}),
        json!({"id": "b", "produces": ["x"]}),
    ])
    .unwrap_err();
    assert_eq!(dup.0, "duplicate artifact producer: x");

    let unproduced = validate_artifact_authority(&[json!({"id": "a", "consumes": ["ghost"]})]).unwrap_err();
    assert_eq!(unproduced.0, "unproduced artifact: ghost");

    let owners = validate_artifact_authority(&[
        json!({"id": "a", "produces": ["x"]}),
        json!({"id": "b", "produces": [], "consumes": ["x"]}),
    ])
    .unwrap();
    assert_eq!(owners.get("x").map(String::as_str), Some("a"));
}

// --- contracts.mjs (validateProviderV2 / validateProviderOutputAuthority) ---

fn valid_v2_provider() -> serde_json::Value {
    json!({
        "schemaVersion": 2, "id": "p1", "providerVersion": "1.0.0", "family": "security",
        "lensIds": [], "role": "deterministic", "phase": "runtime", "dependsOn": [], "consumes": [],
        "produces": [], "selector": {}, "denominatorKind": "paths", "runner": {"kind": "legacy-check"},
        "hostCapabilities": [], "execution": {}, "reasoning": {}, "benchmark": {}, "cleanClaim": "none",
        "controlIds": [], "scopes": [], "selectable": false,
    })
}

#[test]
fn validate_provider_v2_accepts_the_minimum_valid_shape() {
    assert!(validate_provider_v2(&valid_v2_provider()).is_ok());
}

#[test]
fn validate_provider_v2_rejects_missing_required_field() {
    let mut provider = valid_v2_provider();
    provider.as_object_mut().unwrap().remove("selector");
    let err = validate_provider_v2(&provider).unwrap_err();
    assert!(err.0.contains("missing selector"));
}

#[test]
fn candidate_generator_output_authority_is_enforced() {
    let provider = json!({"role": "candidate-generator"});
    let result = json!({"findings": [{"id": "f1"}]});
    let err = validate_provider_output_authority(&provider, &result).unwrap_err();
    assert_eq!(err.0, "candidate-generator cannot emit findings");
}
