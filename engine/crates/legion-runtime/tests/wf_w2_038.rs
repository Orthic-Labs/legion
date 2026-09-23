//! Integration tests for the w2_038 port of `src/lib/controls/{baseline/
//! compile,packs/registry,scenarios/compile}.mjs`.
//!
//! NOTE: requires the integrator to wire `pub mod w2_038;` into
//! `legion_runtime::wf_port` (see `engine/crates/legion-runtime/src/wf_port/
//! mod.rs`) before this file will compile/run. `pub mod wf_port;` is already
//! present in `legion-runtime`'s `lib.rs`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use legion_runtime::p5_core::controls_support::Value;
use legion_runtime::wf_port::w2_038::baseline::compile_baseline;
use legion_runtime::wf_port::w2_038::registry::{load_control_packs, pack_index};
use legion_runtime::wf_port::w2_038::scenarios::compile_scenarios;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_038")
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(key),
        _ => None,
    }
}

#[test]
fn load_control_packs_reads_the_fixture_registry() {
    let packs = load_control_packs(&fixtures_dir()).expect("registry loads");
    assert_eq!(packs.len(), 1);
    assert_eq!(get(&packs[0], "id"), Some(&Value::str("pack.universal")));
}

#[test]
fn pack_index_indexes_the_loaded_pack_controls() {
    let packs = load_control_packs(&fixtures_dir()).unwrap();
    let index = pack_index(&packs).unwrap();
    assert!(index.contains_key("ctl.readme-present"));
}

/// End-to-end: registry -> baseline -> scenario matrix, mirroring how
/// `legion-topology`'s `inspect_repository` chains `compileBaseline` and
/// `compileScenarios` in the JS source (see `src/lib/topology/inspect.mjs`),
/// but with real (non-stubbed) composition logic.
#[test]
fn baseline_and_scenarios_compile_end_to_end_from_loaded_packs() {
    let packs = load_control_packs(&fixtures_dir()).unwrap();

    let portfolio = Value::object([(
        "targets",
        Value::array([Value::object([
            ("id", Value::str("target.web")),
            ("kind", Value::str("web")),
        ])]),
    )]);
    let components = Value::object([("components", Value::array([]))]);

    let baseline = compile_baseline(&packs, &portfolio, &components, &[], &Value::object([]), None)
        .expect("baseline compiles");

    let controls = get(&baseline, "controls").expect("controls field present");
    if let Value::Array(items) = controls {
        assert_eq!(items.len(), 1);
        let control = &items[0];
        assert_eq!(get(control, "id"), Some(&Value::str("ctl.readme-present")));
        assert_eq!(get(control, "unimplemented"), Some(&Value::Bool(true)));
        assert_eq!(
            get(control, "targetIds"),
            Some(&Value::array([Value::str("target.web")]))
        );
    } else {
        panic!("expected controls array");
    }
    assert_eq!(
        get(&baseline, "denominator"),
        Some(&Value::array([Value::str("ctl.readme-present")]))
    );

    let capabilities = vec![Value::object([
        ("id", Value::str("fs:readme")),
        ("available", Value::Bool(true)),
    ])];
    let mut dimensions = BTreeMap::new();
    dimensions.insert("os".to_string(), vec![Value::str("mac"), Value::str("win")]);

    let scenarios = compile_scenarios(&baseline, &[], &capabilities, None, &dimensions, &[], &[])
        .expect("scenarios compile");

    if let Value::Array(rows) = get(&scenarios, "scenarios").expect("scenarios field present") {
        // Two pairwise combinations for a single-dimension axis with two
        // values, one scenario row each (evidence is satisfied).
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(get(row, "controlId"), Some(&Value::str("ctl.readme-present")));
            assert_eq!(get(row, "mandatory"), Some(&Value::Bool(true)));
        }
    } else {
        panic!("expected scenarios array");
    }
    assert_eq!(get(&scenarios, "complete"), Some(&Value::Bool(true)));
}

#[test]
fn missing_registry_index_is_a_reported_error_not_a_silent_empty_list() {
    let empty_root = std::env::temp_dir().join(format!(
        "w2_038_missing_registry_{}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&empty_root);
    let err = load_control_packs(&empty_root).unwrap_err();
    assert!(err.contains("index.json"));
    std::fs::remove_dir_all(&empty_root).ok();
}
