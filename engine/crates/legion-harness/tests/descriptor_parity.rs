//! The harness descriptor table and the runtime host adapters describe the
//! same hosts. The runtime adapter is the source of truth; this test fails
//! when descriptors.json drifts from it.

use legion_runtime::p7_host::host_adapters::{
    claude_code_descriptor, cline_descriptor, codex_descriptor, command_code_descriptor,
    pi_descriptor,
};
use serde_json::Value;

fn harness_descriptors() -> Vec<Value> {
    serde_json::from_str(include_str!("../src/descriptors.json")).expect("descriptors.json parses")
}

#[test]
fn harness_descriptors_match_runtime_host_adapters() {
    let runtime = [
        claude_code_descriptor(),
        cline_descriptor(),
        codex_descriptor(),
        command_code_descriptor(),
        pi_descriptor(),
    ];
    let harness = harness_descriptors();
    let mut harness_ids: Vec<&str> = harness.iter().filter_map(|d| d["id"].as_str()).collect();
    let mut runtime_ids: Vec<&str> = runtime.iter().filter_map(|d| d["id"].as_str()).collect();
    harness_ids.sort_unstable();
    runtime_ids.sort_unstable();
    assert_eq!(harness_ids, runtime_ids, "same set of built-in hosts");
    for expected in &runtime {
        let id = expected["id"].as_str().unwrap();
        let actual = harness.iter().find(|d| d["id"] == *id).unwrap();
        assert_eq!(
            actual, expected,
            "descriptors.json entry for {id} disagrees with runtime host_adapters"
        );
    }
}

#[test]
fn codex_native_agents_are_not_declared_unsupported() {
    let harness = harness_descriptors();
    let codex = harness.iter().find(|d| d["id"] == "codex").unwrap();
    assert_eq!(codex["surfaces"]["agents"]["fidelity"], "strong");
    assert_ne!(codex["surfaces"]["agents"]["mechanism"]["kind"], "none");
}
