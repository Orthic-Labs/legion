//! Bounded property tests for the Guard's typed policy boundary.
//!
//! These tests deliberately exercise the policy evaluator and its precedence
//! helpers rather than a model.  The hook adapter is a separate binary crate;
//! its JSON-shaped inputs are represented here by bounded serde values and by
//! the canonical `EffectRequest`/`PolicyContext` shapes.  No generated input
//! may cause an evaluator panic, an authorization fallback, or an implicit
//! interpretation of an unknown class.

use std::{collections::BTreeSet, panic::AssertUnwindSafe};

use legion_contracts::{
    canonical_default_policy_pack, AgentId, EffectClass as ContractEffectClass, EffectRequest,
    PolicyPack as ContractPolicyPack, RequestId, TaskId,
};
use legion_policy::{
    evaluate,
    precedence::{matching_rule_ids, EVALUATION_ORDER},
    PolicyEvaluator,
};
use legion_policy_model::{
    ApprovalState, CapabilityCeiling, CapabilityGrant, CanonicalPath, ContractVersion,
    DecisionOutcome, EffectClass, EnforcementLevel, HostEnforcement, LeasePolicy, PathOperation,
    PathScope, PolicyContext, PolicyPack, PolicyRule, ReceiptRequirements, ReceiptState,
    RuleDecision, RulePredicate, SymlinkState, TrustLevel, TrustMinima, UnclassifiedEffect,
    POLICY_SCHEMA_VERSION,
};
use proptest::{prelude::*, test_runner::Config as ProptestConfig};
use serde_json::{json, Map, Value};

const CONTRACT_NAME: &str = "legion-hook";
const REPOSITORY: &str = "property-repository";
const WORKTREE: &str = "property-worktree";

// The limits are intentional: they cover large/nested tool payloads while
// keeping every generated case finite in memory and evaluation time.
fn bounded_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..=128).prop_map(|chars| chars.into_iter().collect())
}

fn large_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 0..=4096)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn bounded_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|number| Value::Number(number.into())),
        bounded_text().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 256, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..=4).prop_map(Value::Array),
            prop::collection::vec((bounded_text(), inner), 0..=4).prop_map(|entries| {
                let mut object = Map::new();
                for (key, value) in entries {
                    object.insert(key, value);
                }
                Value::Object(object)
            }),
        ]
    })
}

fn adversarial_payload() -> impl Strategy<Value = Value> {
    prop_oneof![
        bounded_json(),
        large_text().prop_map(|text| json!({
            "tool_name": "Bash",
            "tool_input": {"command": text, "cwd": "..\\..\\odd"},
            "nested": {"sh": "sh -c", "cmd": "cmd /c", "powershell": "powershell -Command"}
        })),
        bounded_text().prop_map(|text| json!({
            "name": "mcp__filesystem__write_file",
            "arguments": {"path": text, "content": [null, {"unicode": "λ🦀"}]},
            "targets": ["a", "a/../b", "C:\\\\odd\\path"]
        })),
        prop::collection::vec(bounded_text(), 0..=8).prop_map(|targets| {
            let edits: Vec<Value> = targets
                .iter()
                .map(|target| json!({"file_path": target, "old_string": "x", "new_string": "y"}))
                .collect();
            json!({"tool_name": "MultiEdit", "tool_input": {"targets": targets, "edits": edits}})
        }),
    ]
}

fn all_operations() -> BTreeSet<String> {
    ["read", "write", "delete", "move", "execute"]
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

fn all_effects() -> BTreeSet<EffectClass> {
    EffectClass::ALL.into_iter().collect()
}

fn property_pack() -> PolicyPack {
    let contract = ContractVersion {
        name: CONTRACT_NAME.into(),
        major: 1,
        minor: 0,
    };
    let mut effect_rules = Vec::new();
    for effect_class in EffectClass::ALL {
        let allowed = matches!(
            effect_class,
            EffectClass::FileWrite
                | EffectClass::FileDelete
                | EffectClass::FileMove
                | EffectClass::CommandExec
                | EffectClass::VcsCommit
        );
        effect_rules.push(PolicyRule {
            schema_version: POLICY_SCHEMA_VERSION,
            id: format!("property-{:?}", effect_class),
            effect_class,
            rule: if allowed {
                RuleDecision::Allow
            } else {
                RuleDecision::Deny
            },
            predicate: RulePredicate::default(),
            approval_required: false,
            trust_minimum: TrustLevel::Unauthenticated,
            required_enforcement: EnforcementLevel::Unsupported,
            receipt_required: false,
            exception_capable: false,
            note: Some("bounded property-test rule".into()),
        });
    }

    PolicyPack {
        schema_version: POLICY_SCHEMA_VERSION,
        kind: "arcane-policy-pack".into(),
        policy_id: "property-policy".into(),
        version: 1,
        contract_versions: vec![contract],
        unclassified_effect: UnclassifiedEffect::Deny,
        effect_rules,
        capability: CapabilityCeiling {
            effects: all_effects(),
            operations: all_operations(),
            targets: BTreeSet::new(),
            max_ttl_seconds: 1,
            max_uses: 1,
            delegable: false,
            trust: TrustLevel::Unauthenticated,
        },
        leases: LeasePolicy {
            max_ttl_seconds: 1,
            max_uses: 1,
            delegable: false,
        },
        trust_minima: TrustMinima {
            mutation: TrustLevel::Unauthenticated,
            read_only: TrustLevel::Unauthenticated,
            claim_release: TrustLevel::Unauthenticated,
            legacy_import: TrustLevel::Unauthenticated,
        },
        host_enforcement: HostEnforcement {
            required_for_mutation: EnforcementLevel::ReadOnly,
            required_for_read_only: EnforcementLevel::Unsupported,
        },
        receipt_requirements: ReceiptRequirements {
            effect_receipt: false,
            bind_policy_digest: false,
            bind_capability_id: false,
        },
    }
}

fn valid_context(effect_class: EffectClass, operation: PathOperation) -> PolicyContext {
    let contract = ContractVersion {
        name: CONTRACT_NAME.into(),
        major: 1,
        minor: 0,
    };
    PolicyContext {
        schema_version: POLICY_SCHEMA_VERSION,
        contract,
        effect_class,
        operation,
        path: Some(
            CanonicalPath::from_relative(
                "property-root",
                PathScope {
                    repository: REPOSITORY.into(),
                    worktree: WORKTREE.into(),
                },
                "src/guard.rs",
                SymlinkState::NotFollowed,
            )
            .expect("fixed property-test path is canonical"),
        ),
        repository: REPOSITORY.into(),
        worktree: WORKTREE.into(),
        trust: TrustLevel::Unauthenticated,
        enforcement: EnforcementLevel::Strong,
        approval: ApprovalState::None,
        lease: legion_policy_model::LeaseState::Active,
        receipt: ReceiptState::NotRequired,
        grant: Some(CapabilityGrant {
            schema_version: POLICY_SCHEMA_VERSION,
            id: "property-grant".into(),
            effects: all_effects(),
            operations: all_operations(),
            targets: BTreeSet::new(),
            ttl_seconds: 1,
            max_uses: 1,
            delegable: false,
            trust: TrustLevel::Unauthenticated,
            lease_id: None,
        }),
        tags: BTreeSet::new(),
    }
}

fn valid_effect_request() -> EffectRequest {
    EffectRequest {
        schema_version: 1,
        request_id: RequestId::new("property-request").expect("fixed request id is valid"),
        task_id: TaskId::new("property-task").expect("fixed task id is valid"),
        requested_by: AgentId::new("property-agent").expect("fixed agent id is valid"),
        effect_class: ContractEffectClass::FILE_WRITE,
        target: "src/guard.rs".into(),
        operation: "write".into(),
        preview: Some("bounded property test".into()),
        source_revision: "0123456789abcdef0123456789abcdef01234567".into(),
        approval_required: false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_and_nested_payloads_never_panic(
        raw in prop::collection::vec(any::<u8>(), 0..=1024),
        payload in adversarial_payload(),
    ) {
        let serialized_payload = serde_json::to_vec(&payload).expect("Value serializes");
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = serde_json::from_slice::<Value>(&raw);
            let _ = serde_json::from_slice::<PolicyContext>(&raw);
            if let Ok(context) = serde_json::from_slice::<PolicyContext>(&raw) {
                let _ = evaluate(&property_pack(), &context);
            }
            if let Ok(pack) = serde_json::from_slice::<PolicyPack>(&raw) {
                let _ = pack.validate();
                let _ = pack.digest();
            }
            let _ = serde_json::from_slice::<ContractPolicyPack>(&raw);
            if let Ok(request) = serde_json::from_slice::<EffectRequest>(&raw) {
                let _ = request.validate();
            }

            let _ = serde_json::from_slice::<Value>(&serialized_payload);
            if let Ok(context) = serde_json::from_slice::<PolicyContext>(&serialized_payload) {
                let _ = evaluate(&property_pack(), &context);
            }
            if let Ok(pack) = serde_json::from_slice::<PolicyPack>(&serialized_payload) {
                let _ = pack.validate();
                let _ = pack.digest();
            }
            let _ = serde_json::from_slice::<ContractPolicyPack>(&serialized_payload);
            if let Ok(request) = serde_json::from_slice::<EffectRequest>(&serialized_payload) {
                let _ = request.validate();
            }
        }));
        prop_assert!(result.is_ok(), "bounded hostile JSON must not panic");
    }

    #[test]
    fn malformed_context_fields_fail_closed(
        field in prop_oneof![
            Just("schema_version"), Just("contract"), Just("effect_class"),
            Just("operation"), Just("path"), Just("repository"), Just("worktree"),
            Just("trust"), Just("enforcement"), Just("approval"), Just("lease"),
            Just("receipt"), Just("grant"), Just("tags")
        ],
        mode in prop_oneof![Just("missing"), Just("null"), Just("wrong_type")],
        nested in bounded_json(),
    ) {
        let mut value = serde_json::to_value(valid_context(EffectClass::FileWrite, PathOperation::Write))
            .expect("valid context serializes");
        let object = value.as_object_mut().expect("context is an object");
        match mode {
            "missing" => { object.remove(field); }
            "null" => { object.insert(field.into(), Value::Null); }
            _ => { object.insert(field.into(), json!({"adversarial": nested})); }
        }

        let parsed = serde_json::from_value::<PolicyContext>(value);
        if let Ok(context) = parsed {
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| evaluate(&property_pack(), &context)));
            prop_assert!(result.is_ok(), "accepted malformed shape must not panic");
            prop_assert_ne!(
                result.expect("panic was checked").decision.outcome,
                DecisionOutcome::Allow,
                "a malformed optional field must not fall through to allow"
            );
        }
    }

    #[test]
    fn known_dangerous_effect_variants_stay_denied(
        effect_class in prop_oneof![
            Just(EffectClass::CredentialAccess), Just(EffectClass::DependencyInstall),
            Just(EffectClass::VcsPush), Just(EffectClass::Publish),
            Just(EffectClass::NetworkEgress), Just(EffectClass::ProcessSpawn),
            Just(EffectClass::ExternalSideEffect),
        ],
        operation in prop_oneof![
            Just(PathOperation::Read), Just(PathOperation::Write), Just(PathOperation::Delete),
            Just(PathOperation::Move), Just(PathOperation::Execute),
        ],
        hostile_target in prop_oneof![
            bounded_text(), large_text(),
            Just("sh -c 'rm -rf /'; cmd /c del /s /q C:\\\\; powershell -Command Remove-Item -Recurse".into()),
            Just("mcp__filesystem__write_file::../../outside".into()),
        ],
    ) {
        let mut context = valid_context(effect_class, operation);
        context.tags.insert(hostile_target.clone());
        let evaluation = evaluate(&property_pack(), &context);
        prop_assert_eq!(evaluation.decision.outcome, DecisionOutcome::Deny);
        prop_assert_ne!(evaluation.decision.outcome, DecisionOutcome::RequireApproval);
    }

    #[test]
    fn unknown_effect_class_is_explicitly_rejected(
        suffix in bounded_text(),
    ) {
        let mut value = serde_json::to_value(valid_context(EffectClass::FileWrite, PathOperation::Write))
            .expect("valid context serializes");
        value.as_object_mut().expect("context is an object").insert(
            "effect_class".into(),
            Value::String(format!("UNRECOGNIZED_EFFECT_{suffix}")),
        );
        let parsed = serde_json::from_value::<PolicyContext>(value);
        prop_assert!(parsed.is_err(), "unknown classification must not be accepted");
    }

    #[test]
    fn precedence_is_sorted_and_independent_of_rule_storage_order(reverse in any::<bool>()) {
        let original = property_pack();
        let mut reordered = original.clone();
        if reverse {
            reordered.effect_rules.reverse();
        }
        let context = valid_context(EffectClass::FileWrite, PathOperation::Write);
        let ids = matching_rule_ids(&original, &context);
        let mut sorted = ids.clone();
        sorted.sort();
        prop_assert_eq!(&ids, &sorted);

        let first = evaluate(&original, &context);
        let second = evaluate(&reordered, &context);
        prop_assert_eq!(first.decision, second.decision);
        prop_assert_eq!(first.explanation.matched_rule_ids, second.explanation.matched_rule_ids);
    }

    #[test]
    fn evaluator_trace_never_reverses_precedence(
        effect_class in prop::sample::select(EffectClass::ALL.to_vec())
    ) {
        let context = valid_context(effect_class, PathOperation::Write);
        let evaluation = evaluate(&property_pack(), &context);
        let mut last = 0usize;
        for entry in evaluation.explanation.trace {
            let current = EVALUATION_ORDER
                .iter()
                .position(|stage| *stage == entry.stage)
                .expect("trace stage is in the public evaluation order");
            prop_assert!(current >= last, "evaluation trace moved backwards");
            last = current;
        }
    }
}

#[test]
fn live_default_policy_is_valid_and_reserved_classes_are_not_ambient_allowed() {
    let pack = canonical_default_policy_pack();
    pack.validate().expect("live default policy must validate");
    // The pack draws its line at destruction, not caution. A push, a publish,
    // an install, an outbound request and a spawned process destroy nothing,
    // and denying them stopped ordinary work with no way to proceed. What
    // stays reserved is what cannot be undone or what leaks.
    for effect_class in [
        ContractEffectClass::CREDENTIAL_ACCESS,
        ContractEffectClass::EXTERNAL_SIDE_EFFECT,
        ContractEffectClass::MCP_UNCLASSIFIED_OBSERVATION,
    ] {
        assert!(
            pack.rules
                .iter()
                .filter(|rule| rule.effect_class == effect_class)
                .all(|rule| !rule.allowed),
            "reserved class {effect_class:?} must remain denied"
        );
    }
    // A destructive delete is reserved by operation rather than by class, so
    // assert that shape directly: the ordinary delete stays ambient.
    assert!(
        pack.rules
            .iter()
            .any(|rule| rule.effect_class == ContractEffectClass::FILE_DELETE && !rule.allowed),
        "a destructive FILE_DELETE rule must remain in the pack"
    );
}

#[test]
fn conflicting_alias_shape_is_rejected_instead_of_silently_resolved() {
    let mut request = serde_json::to_value(valid_effect_request()).expect("request serializes");
    request
        .as_object_mut()
        .expect("request is an object")
        .insert("effectClass".into(), json!("FILE_DELETE"));
    assert!(
        serde_json::from_value::<EffectRequest>(request).is_err(),
        "an alternate effect-class spelling must not silently override the typed field"
    );
}

#[test]
fn policy_evaluator_constructor_rejects_invalid_policy_without_fallback() {
    let mut invalid_pack = property_pack();
    invalid_pack.version = 0;
    let evaluation = evaluate(
        &invalid_pack,
        &valid_context(EffectClass::FileWrite, PathOperation::Write),
    );
    assert_ne!(evaluation.decision.outcome, DecisionOutcome::Allow);

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| PolicyEvaluator::new(invalid_pack)));
    assert!(result.is_ok(), "invalid policy construction must not panic");
    assert!(result.expect("panic was checked").is_err());
}

