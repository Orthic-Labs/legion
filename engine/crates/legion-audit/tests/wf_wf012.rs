//! Integration tests for wf012 (`src/lib/providers/sdk/{schedule,selectors,testkit}.mjs`)
//! against `legion_audit::wf_port::wf012`.
//!
//! No existing JS test files were found for `schedule.mjs`, `selectors.mjs`
//! or `testkit.mjs` (no `schedule.test.mjs` / `selectors.test.mjs` /
//! `testkit.test.mjs` under `tests/` in the legion repo), so there are no
//! upstream assertions to port; these tests are original coverage derived
//! directly from the JS source semantics documented in each ported module.

use legion_audit::wf_port::wf012::{
    compile_schedule, evaluate_selector, normalize_provider_result, path_denominator, stable_id,
    validate_provider_record, validate_provider_result, DagError, Projection, ScheduleError,
    ScheduleProvider, Selector,
};
use serde_json::json;
use std::collections::BTreeMap;

fn provider(id: &str, deps: &[&str], resources: &[(&str, f64)]) -> ScheduleProvider {
    ScheduleProvider {
        id: id.to_string(),
        resources: resources
            .iter()
            .map(|(name, amount)| (name.to_string(), *amount))
            .collect(),
        dependencies: Some(deps.iter().map(|s| s.to_string()).collect()),
        depends_on: None,
    }
}

// ---- schedule.mjs: compileSchedule ----------------------------------------

#[test]
fn compile_schedule_orders_independent_providers_into_one_wave_sorted_by_id() {
    let providers = vec![
        provider("b", &[], &[]),
        provider("a", &[], &[]),
        provider("c", &[], &[]),
    ];
    let result = compile_schedule(&providers, &BTreeMap::new()).unwrap();
    assert_eq!(result.waves, vec![vec!["a", "b", "c"]]);
    assert_eq!(result.order, vec!["a", "b", "c"]);
}

#[test]
fn compile_schedule_respects_dependency_waves() {
    let providers = vec![
        provider("build", &["fetch"], &[]),
        provider("fetch", &[], &[]),
        provider("test", &["build"], &[]),
    ];
    let result = compile_schedule(&providers, &BTreeMap::new()).unwrap();
    assert_eq!(
        result.waves,
        vec![vec!["fetch"], vec!["build"], vec!["test"]]
    );
    assert_eq!(result.order, vec!["fetch", "build", "test"]);
}

#[test]
fn compile_schedule_per_provider_resource_ceiling_exceeded() {
    let providers = vec![provider("heavy", &[], &[("cpu", 8.0)])];
    let mut ceilings = BTreeMap::new();
    ceilings.insert("cpu".to_string(), 4.0);
    let error = compile_schedule(&providers, &ceilings).unwrap_err();
    assert_eq!(
        error,
        ScheduleError::ResourceCeilingExceeded("heavy".into(), "cpu".into())
    );
}

#[test]
fn compile_schedule_splits_a_wave_when_aggregate_ceiling_is_exceeded() {
    // Two independent providers each fit individually under the ceiling of
    // 3, but together (3 + 2 = 5) exceed it, so the greedy first-fit (sorted
    // by id) selects "a" into wave 1 and defers "b" to wave 2.
    let providers = vec![
        provider("a", &[], &[("cpu", 3.0)]),
        provider("b", &[], &[("cpu", 2.0)]),
    ];
    let mut ceilings = BTreeMap::new();
    ceilings.insert("cpu".to_string(), 3.0);
    let result = compile_schedule(&providers, &ceilings).unwrap();
    assert_eq!(result.waves, vec![vec!["a"], vec!["b"]]);
}

#[test]
fn compile_schedule_dependencies_field_takes_priority_over_depends_on() {
    let providers = vec![
        ScheduleProvider {
            id: "x".into(),
            resources: vec![],
            dependencies: Some(vec!["y".into()]),
            depends_on: Some(vec!["ignored-should-not-be-used".into()]),
        },
        provider("y", &[], &[]),
    ];
    let result = compile_schedule(&providers, &BTreeMap::new()).unwrap();
    assert_eq!(result.waves, vec![vec!["y"], vec!["x"]]);
}

#[test]
fn compile_schedule_unknown_dependency_errors() {
    let providers = vec![provider("a", &["missing"], &[])];
    let error = compile_schedule(&providers, &BTreeMap::new()).unwrap_err();
    assert_eq!(
        error,
        ScheduleError::Dag(DagError::UnknownDependency("a".into(), "missing".into()))
    );
}

#[test]
fn compile_schedule_self_dependency_errors() {
    let providers = vec![provider("a", &["a"], &[])];
    let error = compile_schedule(&providers, &BTreeMap::new()).unwrap_err();
    assert_eq!(error, ScheduleError::Dag(DagError::SelfDependency("a".into())));
}

#[test]
fn compile_schedule_cycle_errors() {
    let providers = vec![provider("a", &["b"], &[]), provider("b", &["a"], &[])];
    let error = compile_schedule(&providers, &BTreeMap::new()).unwrap_err();
    match error {
        ScheduleError::Dag(DagError::Cycle(payload)) => {
            assert!(payload.contains("\"id\":\"a\""));
            assert!(payload.contains("\"id\":\"b\""));
        }
        other => panic!("expected cycle error, got {other:?}"),
    }
}

// ---- selectors.mjs: evaluateSelector ---------------------------------------

#[test]
fn evaluate_selector_default_selector_matches_any_projection() {
    assert!(evaluate_selector(&Selector::default(), &Projection::default()));
}

#[test]
fn evaluate_selector_requires_all_paths_present() {
    let selector = Selector {
        paths: vec!["src/a.rs".into(), "src/b.rs".into()],
        extensions: vec![],
    };
    let projection_full = Projection {
        files: vec!["src/a.rs".into(), "src/b.rs".into(), "src/c.rs".into()],
        parsed_extensions: vec![],
    };
    assert!(evaluate_selector(&selector, &projection_full));

    let projection_partial = Projection {
        files: vec!["src/a.rs".into()],
        parsed_extensions: vec![],
    };
    assert!(!evaluate_selector(&selector, &projection_partial));
}

#[test]
fn evaluate_selector_requires_all_extensions_present() {
    let selector = Selector {
        paths: vec![],
        extensions: vec!["rs".into(), "toml".into()],
    };
    let matching = Projection {
        files: vec![],
        parsed_extensions: vec!["rs".into(), "toml".into(), "md".into()],
    };
    assert!(evaluate_selector(&selector, &matching));

    let missing = Projection {
        files: vec![],
        parsed_extensions: vec!["rs".into()],
    };
    assert!(!evaluate_selector(&selector, &missing));
}

// ---- testkit.mjs: stableId / pathDenominator / validateProviderRecord -----

#[test]
fn stable_id_is_deterministic_and_key_order_independent() {
    let a = json!({"b": 1, "a": 2});
    let b = json!({"a": 2, "b": 1});
    assert_eq!(stable_id("ns", &a), stable_id("ns", &b));
}

#[test]
fn stable_id_differs_by_namespace() {
    let value = json!({"a": 1});
    assert_ne!(stable_id("ns1", &value), stable_id("ns2", &value));
}

#[test]
fn stable_id_matches_known_vector() {
    // Cross-checked against the JS implementation's double-encoding quirk:
    // body = JSON.stringify(JSON.stringify(canonicalize(value))).
    // For namespace "path-denominator" and value [] (an empty array):
    //   canonicalize([]) -> []
    //   JSON.stringify([]) -> "[]"
    //   JSON.stringify("[]") -> "\"[]\""
    //   sha256("path-denominator\0\"[]\"")
    let digest = stable_id("path-denominator", &json!([]));
    assert!(digest.starts_with("sha256:"));
    assert_eq!(digest.len(), "sha256:".len() + 64);

    // Recompute independently to lock the exact hex digest.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"path-denominator\0\"[]\"");
    let expected = format!("sha256:{:x}", hasher.finalize());
    assert_eq!(digest, expected);
}

#[test]
fn path_denominator_dedupes_filters_and_sorts() {
    let paths = vec![
        "src/b.rs".to_string(),
        "src/a.rs".to_string(),
        "src/b.rs".to_string(),
        "node_modules/x.js".to_string(),
    ];
    let result = path_denominator(&paths, &["node_modules".to_string()]);
    assert_eq!(result.paths, vec!["src/a.rs".to_string(), "src/b.rs".to_string()]);
    assert_eq!(result.path_count, 2);
    assert_eq!(
        result.path_digest,
        stable_id(
            "path-denominator",
            &json!(["src/a.rs".to_string(), "src/b.rs".to_string()])
        )
    );
}

#[test]
fn validate_provider_record_requires_all_four_fields() {
    assert!(validate_provider_record(&json!({
        "id": "p1", "providerVersion": "1.0.0", "role": "deterministic", "phase": "audit"
    })));
    assert!(!validate_provider_record(&json!({
        "id": "p1", "providerVersion": "1.0.0", "role": "deterministic"
    })));
    // JS truthiness: empty string id is falsy.
    assert!(!validate_provider_record(&json!({
        "id": "", "providerVersion": "1.0.0", "role": "deterministic", "phase": "audit"
    })));
}

// ---- testkit.mjs re-exports: validateProviderResult / normalizeProviderResult

#[test]
fn validate_provider_result_accepts_minimal_valid_result() {
    let result = json!({
        "schemaVersion": 1,
        "provider": "x",
        "status": "pass",
        "complete": true,
    });
    assert!(validate_provider_result(&result).is_ok());
}

#[test]
fn validate_provider_result_rejects_invalid_status() {
    let result = json!({
        "schemaVersion": 1,
        "provider": "x",
        "status": "invalid-status",
        "complete": true,
    });
    let error = validate_provider_result(&result).unwrap_err();
    assert_eq!(error.field, "status");
}

#[test]
fn validate_provider_result_rejects_null_array_field() {
    let result = json!({
        "schemaVersion": 1,
        "provider": "x",
        "status": "pass",
        "complete": true,
        "findings": null,
    });
    let error = validate_provider_result(&result).unwrap_err();
    assert_eq!(error.field, "findings");
}

#[test]
fn validate_provider_result_rejects_bad_artifact_digest() {
    let result = json!({
        "schemaVersion": 1,
        "provider": "x",
        "status": "pass",
        "complete": true,
        "artifacts": [{"kind": "sarif", "path": "out.sarif", "digest": "not-a-digest"}],
    });
    let error = validate_provider_result(&result).unwrap_err();
    assert_eq!(error.field, "artifacts.digest");
}

#[test]
fn normalize_provider_result_matches_js_self_test() {
    // Mirrors the self-test block at the bottom of
    // scripts/normalize-provider-result.mjs.
    let plan_contract = json!({
        "id": "test.provider",
        "denominator": {"pathDigest": "sha256:test"},
        "benchmark": {"requiredForCleanClaim": true},
    });
    let raw_output = json!({
        "status": "pass",
        "complete": true,
        "findings": [],
    });
    let normalized =
        normalize_provider_result(Some(&plan_contract), Some(&raw_output)).unwrap();
    assert_eq!(normalized["provider"], "test.provider");
    assert_eq!(normalized["status"], "pass");
    assert_eq!(normalized["coverage"]["denominatorDigest"], "sha256:test");
    assert_eq!(normalized["required"], true);
    assert!(normalized["degradation"].is_array());
}

#[test]
fn normalize_provider_result_defaults_provider_to_unknown() {
    let normalized = normalize_provider_result(None, None).unwrap();
    assert_eq!(normalized["provider"], "unknown");
    assert_eq!(normalized["status"], "unproven");
    assert_eq!(normalized["complete"], false);
    assert_eq!(normalized["required"], false);
    assert_eq!(normalized["coverage"]["denominatorDigest"], "sha256:unbound");
}
