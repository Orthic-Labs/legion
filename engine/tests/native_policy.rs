//! LEG-I01 policy differential and fail-closed acceptance corpus.

use legion_policy_model::{
    intersect, CapabilityCeiling, EffectClass, EnforcementLevel, PolicyPack, TrustLevel,
};
use serde_json::Value;
use std::collections::BTreeSet;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../migration/native-rust/fixtures/policy-cases.v1.json"
    ))
    .expect("LEG-001 policy fixtures remain valid JSON")
}

#[test]
fn policy_fixture_requires_fail_closed_unknown_effect() {
    let case = &fixture()["cases"][0];
    assert_eq!(case["case_id"], "policy-01-unknown-effect-deny");
    assert_eq!(case["expected"]["allowed"], false);
    assert_eq!(case["expected"]["implicit_allow"], false);
}

#[test]
fn capability_intersection_never_widens_either_ceiling() {
    let mut left_effects = BTreeSet::new();
    left_effects.insert(EffectClass::FileWrite);
    let mut right_effects = BTreeSet::new();
    right_effects.insert(EffectClass::FileWrite);
    right_effects.insert(EffectClass::FileDelete);
    let left = CapabilityCeiling {
        effects: left_effects,
        operations: ["write".into()].into_iter().collect(),
        targets: ["src/".into()].into_iter().collect(),
        max_ttl_seconds: 20,
        max_uses: 2,
        delegable: false,
        trust: TrustLevel::HostConnectionTrust,
    };
    let right = CapabilityCeiling {
        effects: right_effects,
        operations: ["write".into(), "delete".into()].into_iter().collect(),
        targets: ["src/".into(), "tests/".into()].into_iter().collect(),
        max_ttl_seconds: 10,
        max_uses: 1,
        delegable: false,
        trust: TrustLevel::CapabilitySignature,
    };
    let intersection = intersect(&left, &right);
    assert!(intersection.effects.is_subset(&left.effects));
    assert!(intersection.effects.is_subset(&right.effects));
    assert!(intersection.operations.is_subset(&left.operations));
    assert!(intersection.targets.is_subset(&left.targets));
    assert_eq!(intersection.max_ttl_seconds, 10);
    assert_eq!(intersection.max_uses, 1);
    assert_eq!(intersection.trust, TrustLevel::CapabilitySignature);
}

#[test]
fn policy_pack_rejects_invalid_schema_and_zero_ceilings() {
    let value = fixture();
    let _ = value["cases"][1]["expected"]["required_fields"]
        .as_array()
        .unwrap();
    let pack = PolicyPack {
        schema_version: 99,
        kind: "arcane-policy-pack".into(),
        policy_id: "fixture".into(),
        version: 1,
        contract_versions: Vec::new(),
        unclassified_effect: legion_policy_model::UnclassifiedEffect::Deny,
        effect_rules: Vec::new(),
        capability: Default::default(),
        leases: legion_policy_model::LeasePolicy {
            max_ttl_seconds: 0,
            max_uses: 0,
            delegable: false,
        },
        trust_minima: legion_policy_model::TrustMinima {
            mutation: TrustLevel::Unauthenticated,
            read_only: TrustLevel::Unauthenticated,
            claim_release: TrustLevel::Unauthenticated,
            legacy_import: TrustLevel::Unauthenticated,
        },
        host_enforcement: legion_policy_model::HostEnforcement {
            required_for_mutation: EnforcementLevel::ReadOnly,
            required_for_read_only: EnforcementLevel::ReadOnly,
        },
        receipt_requirements: legion_policy_model::ReceiptRequirements {
            effect_receipt: true,
            bind_policy_digest: true,
            bind_capability_id: true,
        },
    };
    assert!(pack.validate().is_err());
}
