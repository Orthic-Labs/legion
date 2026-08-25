//! LEG-I01 contract acceptance corpus.
//!
//! These tests are intentionally side-effect free.  They consume only the
//! sealed LEG-001 fixture manifest and public native contract APIs.  The
//! integration owner must run them after workspace compilation and record
//! receipts in `migration/native-rust/acceptance-report.json`.

use legion_contracts::{
    canonical_equal, derived_id_string, AgentId, BudgetCeiling, InvocationGrant, Plan, PlanId,
    PlanNode, PlanNodeKind, ProviderId, ProviderResult, ProviderStatus,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn fixture_manifest() -> Value {
    serde_json::from_str(include_str!(
        "../../migration/native-rust/fixtures/manifest.v1.json"
    ))
    .expect("LEG-001 manifest remains valid JSON")
}

#[test]
fn leg001_manifest_is_complete_and_unique() {
    let manifest = fixture_manifest();
    assert_eq!(manifest["packetId"], "LEG-001");
    assert_eq!(manifest["case_counts"]["total"], 30);
    let files = manifest["files"].as_object().expect("fixture file hashes");
    assert_eq!(files.len(), 9);
    assert!(files
        .values()
        .all(|value| value.as_str().unwrap().starts_with("sha256:")));
}

#[test]
fn plan_and_provider_results_round_trip_canonically() {
    let provider = ProviderId::new("fixture-provider").unwrap();
    let plan = Plan::new(
        1,
        PlanId::new("fixture-plan").unwrap(),
        vec![PlanNode {
            id: "root".parse().unwrap(),
            kind: PlanNodeKind::Provider,
            provider: Some(provider.clone()),
            depends_on: Vec::new(),
            configuration: BTreeMap::new(),
        }],
        vec![provider.clone()],
    )
    .unwrap();
    let plan_json = serde_json::to_value(&plan).unwrap();
    let decoded: Plan = serde_json::from_value(plan_json.clone()).unwrap();
    assert!(canonical_equal(&plan, &decoded).unwrap());
    assert_eq!(plan.ordered_nodes().unwrap().len(), 1);

    let result = ProviderResult {
        schema_version: 1,
        provider,
        applicable: true,
        required: true,
        status: ProviderStatus::Partial,
        complete: false,
        coverage: None,
        findings: Vec::new(),
        coverage_gaps: vec!["fixture-gap".into()],
        degradation: vec!["fixture".into()],
        details: BTreeMap::new(),
    };
    result.validate().unwrap();
    let decoded: ProviderResult =
        serde_json::from_value(serde_json::to_value(&result).unwrap()).unwrap();
    assert!(canonical_equal(&result, &decoded).unwrap());
}

#[test]
fn stable_ids_and_grants_are_replayable() {
    let bytes = br#"{"case_id":"contract-fixture","value":1}"#;
    assert_eq!(derived_id_string(bytes), derived_id_string(bytes));
    let agent = AgentId::new("fixture-agent").unwrap();
    let grant = InvocationGrant::new(
        agent,
        "fixture-task".parse().unwrap(),
        BudgetCeiling {
            max_active_time_ms: 1,
            max_cost_micros: 1,
            max_output_bytes: 1,
        },
    )
    .unwrap();
    let decoded: InvocationGrant =
        serde_json::from_value(serde_json::to_value(&grant).unwrap()).unwrap();
    assert_eq!(grant, decoded);
    let _ = BTreeSet::<String>::new();
}
