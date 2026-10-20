//! No transport, fake receipt or host identity is used by these controls.
use legion_audit::review_runtime::qualification::{self, MAX_RESERVED_TOKENS};
use serde_json::{json, Value};
use std::path::PathBuf;

fn corpus() -> (PathBuf, Value, Value) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/ci/fixtures/audit-reasoning-runtime-accuracy");
    let read = |name| serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap();
    let cases = read("cases.json");
    let plan = read("packet-plan.json");
    (root, cases, plan)
}

#[test]
fn reasoning_runtime_no_call_contract() {
    let (root, cases, plan) = corpus();
    let checked = qualification::preflight(&root, &cases, &plan).unwrap();
    assert_eq!(checked["modelCalls"], 0);
    assert_eq!(checked["qualification"], false);
    assert_eq!(checked["productionDispatchValidated"], false);
    assert_eq!(checked["reservationCeilingTokens"], MAX_RESERVED_TOKENS);
    assert_eq!(checked["proposedPackets"], 8);
    assert_eq!(checked["providers"].as_array().unwrap().len(), 17);
    println!("REASONING_RUNTIME_NO_CALL {}", checked);
}

#[test]
fn reasoning_runtime_no_call_rejects_contract_drift() {
    let (root, cases, plan) = corpus();
    let mut changed = plan.clone();
    changed["maxTokens"] = json!(50_000);
    assert!(qualification::preflight(&root, &cases, &changed).is_err());
    let mut changed = plan.clone();
    changed["packets"][1]["caseIds"][0] = plan["packets"][0]["caseIds"][0].clone();
    assert!(qualification::preflight(&root, &cases, &changed).is_err());
    let mut changed = cases.clone();
    changed["cases"][0]["expected"]["positive"][0]["text"] = json!("not original source");
    assert!(qualification::preflight(&root, &changed, &plan).is_err());
    let mut changed = cases.clone();
    changed["providers"][0] = json!("reasoning.unknown");
    assert!(qualification::preflight(&root, &changed, &plan).is_err());
    let mut changed = cases.clone();
    changed["cases"][0]["fixtureRoot"] = json!("../outside");
    assert!(qualification::preflight(&root, &changed, &plan).is_err());
}

#[test]
fn reasoning_runtime_export_refuses_source_without_native_run() {
    // No fake epoch, process, model response or signed receipt is constructed.
    assert!(qualification::export_run(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))).is_err());
}
