//! Signed plan amendments, generation chain, objective DAG and engagement.
//!
//! Requires `lib.rs` exports: `pub mod amendment;`,
//! `pub use dag::{...ObjectiveGraph, ExecutionState, ProofState as ObjectiveProofState, Observation...}`,
//! `pub use plan::{AuthorityMode, Engagement, ...}` (see packet return).

use std::collections::BTreeMap;

use legion_audit::amendment::{
    apply, apply_followup, verify_chain, AmendmentBody, AmendmentOperation, SignedAmendment,
};
use legion_audit::{
    AuditPlan, AuditProvider, AuthorityMode, Engagement, EngagementAuthority, EngagementScope,
    ExecutionState, FrozenPlan, ObjectiveProofState, Observation, ProviderKind, StopConditions,
    ENGAGEMENT_BOUND, PLAN_SCHEMA_V1, PLAN_SCHEMA_V2,
};
use serde_json::{json, Value};

const KEY: &[u8] = b"plan-amendment-fixture-key";
const NOW: u64 = 1_900_000_000;
const EXPIRY: u64 = 2_000_000_000;

fn provider(id: &str, deps: &[&str], consumes: &[&str], produces: &[&str]) -> AuditProvider {
    let mut configuration: BTreeMap<String, Value> = [
        "schemaVersion",
        "family",
        "selector",
        "denominatorKind",
        "hostCapabilities",
        "execution",
        "reasoning",
        "benchmark",
        "controlIds",
        "scopes",
        "selectable",
        "runnerClass",
        "denominatorDigest",
        "denominatorCount",
    ]
    .into_iter()
    .map(|field| (field.to_owned(), Value::Null))
    .collect();
    configuration.insert("runner".into(), json!({"kind": "built-in"}));
    configuration.insert("consumes".into(), json!(consumes));
    configuration.insert("produces".into(), json!(produces));
    AuditProvider {
        id: id.into(),
        version: "1".into(),
        role: "deterministic".into(),
        phase: "scan".into(),
        lens_ids: Vec::new(),
        dependencies: deps.iter().map(|d| d.to_string()).collect(),
        kind: ProviderKind::BuiltIn,
        configuration,
        bounds: BTreeMap::new(),
        clean_claim: "claim".into(),
        benchmark_status: "unqualified".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: true,
    }
}

fn raw_plan(schema: u32, providers: Vec<AuditProvider>) -> AuditPlan {
    AuditPlan {
        schema_version: schema,
        repository_id: "/frozen/source".into(),
        inventory_generation: "gen".into(),
        inventory_digest: "inventory".into(),
        providers,
        bounds: legion_audit::execution_policy::binding()
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        excluded_conditional_providers: Vec::new(),
    }
}

fn explicit() -> Engagement {
    Engagement {
        format: "audit-engagement/v1".into(),
        engagement_id: "eng-1".into(),
        authority: EngagementAuthority {
            mode: AuthorityMode::Explicit,
            principal: "operator".into(),
            approval_ref: Some("approval-1".into()),
            expires_at_unix: Some(EXPIRY),
            budget_ceiling_tokens: Some(1000),
        },
        scope: EngagementScope {
            include: vec!["**".into()],
            exclude: vec![".git/**".into()],
            revision: None,
        },
        strategy: vec!["security".into(), "correctness".into()],
        stop_conditions: StopConditions {
            max_tokens: Some(500),
            max_seconds: Some(600),
            stop_on_severity: Some("critical".into()),
            breaker_failures: Some(3),
        },
    }
}

fn implicit() -> Engagement {
    let mut engagement = explicit();
    engagement.authority = EngagementAuthority {
        mode: AuthorityMode::ImplicitReadOnly,
        principal: "generated".into(),
        approval_ref: None,
        expires_at_unix: None,
        budget_ceiling_tokens: None,
    };
    engagement
}

fn v2_plan(engagement: Option<&Engagement>) -> FrozenPlan {
    let mut plan = raw_plan(
        PLAN_SCHEMA_V2,
        vec![
            provider("p.a", &[], &["blueprint-packet"], &["fact"]),
            provider("p.b", &["p.a"], &["fact"], &[]),
        ],
    );
    if let Some(engagement) = engagement {
        plan = plan.with_engagement(engagement).unwrap();
    }
    plan.with_objective_graph()
        .unwrap()
        .freeze(Some(KEY))
        .unwrap()
}

fn sign(base: &FrozenPlan, ops: Vec<AmendmentOperation>) -> SignedAmendment {
    SignedAmendment::sign(AmendmentBody::new(base, "reason", NOW, ops).unwrap(), KEY).unwrap()
}

fn err(result: Result<impl std::fmt::Debug, legion_audit::AuditError>) -> String {
    result.unwrap_err().to_string()
}

#[test]
fn unsigned_or_wrong_key_amendment_is_rejected() {
    let base = v2_plan(Some(&explicit()));
    let ops = vec![AmendmentOperation::ExtendBudget { max_tokens: 800 }];
    let mut unsigned = sign(&base, ops.clone());
    unsigned.signature = String::new();
    assert!(err(apply(&base, &unsigned, KEY)).contains("unsigned"));
    let other = SignedAmendment::sign(
        AmendmentBody::new(&base, "reason", NOW, ops).unwrap(),
        b"another-key",
    )
    .unwrap();
    assert!(err(apply(&base, &other, KEY)).contains("signature verification failed"));
}

#[test]
fn forged_amendment_body_is_rejected() {
    let base = v2_plan(Some(&explicit()));
    let mut forged = sign(
        &base,
        vec![AmendmentOperation::ExtendBudget { max_tokens: 800 }],
    );
    forged.body.operations = vec![AmendmentOperation::ExtendBudget { max_tokens: 900 }];
    assert!(err(apply(&base, &forged, KEY)).contains("digest mismatch"));
    // Re-computed digest without the key still cannot produce the signature.
    forged.digest = forged.body.digest().unwrap();
    assert!(err(apply(&base, &forged, KEY)).contains("signature verification failed"));
}

#[test]
fn unsigned_base_plan_cannot_be_amended() {
    let plan = raw_plan(PLAN_SCHEMA_V2, vec![provider("p.a", &[], &[], &[])])
        .with_objective_graph()
        .unwrap();
    let diagnostic = plan.freeze_source_diagnostic().unwrap();
    let signed = sign(
        &diagnostic,
        vec![AmendmentOperation::ExtendBudget { max_tokens: 800 }],
    );
    assert!(err(apply(&diagnostic, &signed, KEY)).contains("unsigned"));
}

#[test]
fn wrong_parent_digest_or_generation_is_rejected() {
    let base = v2_plan(Some(&explicit()));
    let mut body = AmendmentBody::new(
        &base,
        "reason",
        NOW,
        vec![AmendmentOperation::ExtendBudget { max_tokens: 800 }],
    )
    .unwrap();
    body.base_plan_digest = format!("sha256:{}", "0".repeat(64));
    let signed = SignedAmendment::sign(body.clone(), KEY).unwrap();
    assert!(err(apply(&base, &signed, KEY)).contains("different parent"));
    body.base_plan_digest = base.digest().to_owned();
    body.base_generation = 7;
    let signed = SignedAmendment::sign(body, KEY).unwrap();
    assert!(err(apply(&base, &signed, KEY)).contains("generation"));
}

#[test]
fn disallowed_operations_do_not_parse_or_apply() {
    let parsed: Result<AmendmentOperation, _> =
        serde_json::from_value(json!({"op": "remove_provider", "providerId": "p.a"}));
    assert!(parsed.is_err());
    let parsed: Result<AmendmentOperation, _> =
        serde_json::from_value(json!({"op": "extend_budget", "maxTokens": 1, "extra": 1}));
    assert!(parsed.is_err());

    // Effect escalation needs the engagement approval reference.
    let base = v2_plan(Some(&explicit()));
    let mut external = provider("p.ext", &[], &[], &[]);
    external.kind = ProviderKind::TypedExternalProjectTool;
    let signed = sign(
        &base,
        vec![AmendmentOperation::AddObligation {
            provider: external.clone(),
        }],
    );
    assert!(err(apply(&base, &signed, KEY)).contains("approval"));
    let mut body = AmendmentBody::new(
        &base,
        "reason",
        NOW,
        vec![AmendmentOperation::AddObligation { provider: external }],
    )
    .unwrap();
    body.approval_refs = vec!["approval-1".into()];
    apply(&base, &SignedAmendment::sign(body, KEY).unwrap(), KEY).unwrap();

    // A duplicate provider is not an "add".
    let signed = sign(
        &base,
        vec![AmendmentOperation::AddObligation {
            provider: provider("p.a", &[], &[], &[]),
        }],
    );
    assert!(err(apply(&base, &signed, KEY)).contains("already in the plan"));
}

#[test]
fn legacy_schema_one_plan_reads_but_cannot_be_amended() {
    let plan = raw_plan(
        PLAN_SCHEMA_V1,
        vec![provider("p.a", &[], &["whatever-unproduced"], &[])],
    );
    let frozen = plan.clone().freeze(Some(KEY)).unwrap();
    assert_eq!(frozen.plan().generation().unwrap(), 1);
    assert!(frozen.plan().engagement().unwrap().is_none());
    // Legacy dependency semantics: the artifact rule is schema 2 only.
    assert!(plan.objective_graph().is_err());
    let signed = sign(
        &frozen,
        vec![AmendmentOperation::ExtendBudget { max_tokens: 800 }],
    );
    assert!(err(apply(&frozen, &signed, KEY)).contains("legacy schema 1"));
    // A schema 1 plan may not smuggle schema 2 sections.
    let mut smuggled = plan;
    smuggled.bounds.insert(ENGAGEMENT_BOUND.into(), json!({}));
    assert!(err(smuggled.freeze(Some(KEY))).contains("schema 1"));
}

#[test]
fn consumed_artifact_without_producer_or_with_cycle_is_rejected() {
    let missing = raw_plan(PLAN_SCHEMA_V2, vec![provider("p.a", &[], &["ghost"], &[])]);
    assert!(err(missing.with_objective_graph()).contains("no producer"));

    let cycle = raw_plan(
        PLAN_SCHEMA_V2,
        vec![
            provider("p.a", &[], &["y"], &["x"]),
            provider("p.b", &[], &["x"], &["y"]),
        ],
    );
    assert!(err(cycle.with_objective_graph()).contains("cycle"));

    // Declared cycle through dependsOn is also rejected.
    let declared = raw_plan(
        PLAN_SCHEMA_V2,
        vec![
            provider("p.a", &["p.b"], &[], &[]),
            provider("p.b", &["p.a"], &[], &[]),
        ],
    );
    assert!(declared.with_objective_graph().is_err());

    // A schema 2 plan without (or with a stale) graph binding does not freeze.
    let unbound = raw_plan(PLAN_SCHEMA_V2, vec![provider("p.a", &[], &[], &[])]);
    assert!(err(unbound.clone().freeze(Some(KEY))).contains("objective graph"));
    let mut stale = unbound.with_objective_graph().unwrap();
    stale.providers.push(provider("p.c", &[], &[], &[]));
    assert!(err(stale.freeze(Some(KEY))).contains("objective graph binding"));
}

#[test]
fn objective_ids_are_stable_edges_compiled_and_lifecycle_separates_proof() {
    let a = v2_plan(None);
    let b = v2_plan(None);
    let graph = a.plan().objective_graph().unwrap();
    assert_eq!(graph, b.plan().objective_graph().unwrap());
    let producer = graph.objective_for_provider("p.a").unwrap();
    let consumer = graph.objective_for_provider("p.b").unwrap();
    assert!(producer.objective_id.starts_with("obj_") && producer.objective_id.len() == 20);
    // Edge p.a -> p.b comes from produces/consumes as well as dependsOn.
    assert_eq!(consumer.dependencies, vec![producer.objective_id.clone()]);

    // Artifact-only edge (no dependsOn).
    let artifact_only = raw_plan(
        PLAN_SCHEMA_V2,
        vec![
            provider("p.a", &[], &[], &["fact"]),
            provider("p.b", &[], &["fact"], &[]),
        ],
    );
    let graph2 = artifact_only.objective_graph().unwrap();
    assert_eq!(
        graph2
            .objective_for_provider("p.b")
            .unwrap()
            .dependencies
            .len(),
        1
    );

    // Lifecycle: failure blocks dependents, proof stays independent.
    let mut observed = BTreeMap::new();
    observed.insert(producer.objective_id.clone(), Observation::Failed);
    let status = graph.derive_status(&observed).unwrap();
    assert_eq!(
        status[&producer.objective_id].execution,
        ExecutionState::Failed
    );
    assert_eq!(
        status[&consumer.objective_id].execution,
        ExecutionState::Blocked
    );
    assert_eq!(
        status[&consumer.objective_id].proof,
        ObjectiveProofState::Unproven
    );

    observed.insert(
        producer.objective_id.clone(),
        Observation::Done {
            proof: ObjectiveProofState::Unproven,
        },
    );
    let status = graph.derive_status(&observed).unwrap();
    assert_eq!(
        status[&producer.objective_id].execution,
        ExecutionState::Done
    );
    assert_eq!(
        status[&producer.objective_id].proof,
        ObjectiveProofState::Unproven
    );
    assert_eq!(graph.ready(&status).len(), 1);
    // Done before its dependency is done fails closed.
    let mut inconsistent = BTreeMap::new();
    inconsistent.insert(
        consumer.objective_id.clone(),
        Observation::Done {
            proof: ObjectiveProofState::Validated,
        },
    );
    let status = graph.derive_status(&inconsistent).unwrap();
    assert_eq!(
        status[&consumer.objective_id].execution,
        ExecutionState::Blocked
    );
    assert!(graph
        .derive_status(&BTreeMap::from([(
            "obj_unknown".to_owned(),
            Observation::Running
        )]))
        .is_err());
}

#[test]
fn engagement_is_frozen_validated_and_covered_by_the_digest() {
    let with = v2_plan(Some(&explicit()));
    let without = v2_plan(None);
    assert_ne!(with.digest(), without.digest());
    assert_eq!(with.plan().engagement().unwrap().unwrap(), explicit());
    assert!(without.plan().engagement().unwrap().is_none());

    let mut no_expiry = explicit();
    no_expiry.authority.expires_at_unix = None;
    assert!(no_expiry.validate().is_err());
    let mut over = explicit();
    over.stop_conditions.max_tokens = Some(5000);
    assert!(over.validate().is_err());
    assert!(explicit().check_unexpired(NOW).is_ok());
    assert!(explicit().check_unexpired(EXPIRY).is_err());

    // Tampering with the frozen engagement invalidates the signed plan.
    let mut tampered = with.plan().clone();
    tampered.bounds.get_mut(ENGAGEMENT_BOUND).unwrap()["authority"]["principal"] = json!("mallory");
    assert_ne!(legion_audit::plan_digest(&tampered).unwrap(), with.digest());
    assert!(legion_audit::verify(&tampered, with.digest(), with.signature(), Some(KEY)).is_err());
}

#[test]
fn exclusion_requires_explicit_authority_and_reason() {
    let exclusion = |authority_ref: &str, reason: &str| AmendmentOperation::AddExclusion {
        pattern: "vendor/**".into(),
        reason: reason.into(),
        authority_ref: authority_ref.into(),
    };
    let no_engagement = v2_plan(None);
    let signed = sign(
        &no_engagement,
        vec![exclusion("approval-1", "generated code")],
    );
    assert!(err(apply(&no_engagement, &signed, KEY)).contains("requires an engagement"));

    let implicit_plan = v2_plan(Some(&implicit()));
    let signed = sign(
        &implicit_plan,
        vec![exclusion("approval-1", "generated code")],
    );
    assert!(err(apply(&implicit_plan, &signed, KEY)).contains("explicit authority"));

    let base = v2_plan(Some(&explicit()));
    let signed = sign(&base, vec![exclusion("some-other-ref", "generated code")]);
    assert!(err(apply(&base, &signed, KEY)).contains("authority reference"));
    let signed = sign(&base, vec![exclusion("approval-1", "  ")]);
    assert!(err(apply(&base, &signed, KEY)).contains("reason"));

    // Issued after the authority expired.
    let late = SignedAmendment::sign(
        AmendmentBody::new(
            &base,
            "reason",
            EXPIRY + 1,
            vec![exclusion("approval-1", "why")],
        )
        .unwrap(),
        KEY,
    )
    .unwrap();
    assert!(err(apply(&base, &late, KEY)).contains("expired"));

    let signed = sign(&base, vec![exclusion("approval-1", "generated code")]);
    let (next, link) = apply(&base, &signed, KEY).unwrap();
    assert!(next
        .plan()
        .engagement()
        .unwrap()
        .unwrap()
        .scope
        .exclude
        .contains(&"vendor/**".to_owned()));
    assert_eq!(link.result_generation, 2);
}

#[test]
fn budget_extension_stays_within_the_authority_ceiling() {
    let base = v2_plan(Some(&explicit()));
    for (tokens, ok) in [(800u64, true), (500, false), (1001, false)] {
        let signed = sign(
            &base,
            vec![AmendmentOperation::ExtendBudget { max_tokens: tokens }],
        );
        assert_eq!(apply(&base, &signed, KEY).is_ok(), ok, "{tokens}");
    }
    let implicit_plan = v2_plan(Some(&implicit()));
    let signed = sign(
        &implicit_plan,
        vec![AmendmentOperation::ExtendBudget { max_tokens: 800 }],
    );
    assert!(apply(&implicit_plan, &signed, KEY).is_err());
}

#[test]
fn generation_chain_verifies_and_detects_tampering() {
    let genesis = v2_plan(Some(&explicit()));
    let first = sign(
        &genesis,
        vec![AmendmentOperation::AddObligation {
            provider: provider("p.c", &["p.b"], &["blueprint-packet"], &[]),
        }],
    );
    let (gen2, link1) = apply(&genesis, &first, KEY).unwrap();
    assert_eq!(gen2.plan().generation().unwrap(), 2);
    assert!(gen2.plan().providers.iter().any(|p| p.id == "p.c"));
    // Objective ids of unchanged objectives survive the new generation.
    let old_graph = genesis.plan().objective_graph().unwrap();
    let new_graph = gen2.plan().objective_graph().unwrap();
    assert_eq!(
        old_graph
            .objective_for_provider("p.a")
            .unwrap()
            .objective_id,
        new_graph
            .objective_for_provider("p.a")
            .unwrap()
            .objective_id
    );
    let second = sign(
        &gen2,
        vec![AmendmentOperation::ExtendBudget { max_tokens: 900 }],
    );
    let (gen3, link2) = apply(&gen2, &second, KEY).unwrap();
    assert_eq!(gen3.plan().generation().unwrap(), 3);

    let chain = vec![link1.clone(), link2.clone()];
    let verified = verify_chain(&genesis, &chain, KEY).unwrap();
    assert_eq!(verified.digest(), gen3.digest());

    // Skipped link, reordered links, wrong key, forged result digest.
    assert!(verify_chain(&genesis, &[link2.clone()], KEY).is_err());
    assert!(verify_chain(&genesis, &[link2.clone(), link1.clone()], KEY).is_err());
    assert!(verify_chain(&genesis, &chain, b"wrong-key").is_err());
    let mut forged = chain.clone();
    forged[1].result_plan_digest = format!("sha256:{}", "1".repeat(64));
    assert!(verify_chain(&genesis, &forged, KEY).is_err());
    // A non-genesis plan cannot start a chain.
    assert!(verify_chain(&gen2, &[link2], KEY).is_err());
    // A sibling fork of generation 1 does not chain onto generation 2.
    let fork = sign(
        &genesis,
        vec![AmendmentOperation::ExtendBudget { max_tokens: 700 }],
    );
    let (fork_plan, fork_link) = apply(&genesis, &fork, KEY).unwrap();
    assert_ne!(fork_plan.digest(), gen2.digest());
    assert!(verify_chain(&genesis, &[link1, fork_link], KEY).is_err());
}

#[test]
fn followup_adapter_requires_binding_to_the_base_digest() {
    let base = v2_plan(Some(&explicit()));
    let mut variant = provider("variant.analysis", &[], &[], &[]);
    variant.role = "variant-analysis".into();
    variant.lens_ids = vec!["security".into()];
    let bad = apply_followup(
        &base,
        variant.clone(),
        json!({"kind": "security-variant-analysis", "parentPlanDigest": "sha256:other"}),
        "variant",
        NOW,
        KEY,
    );
    assert!(err(bad).contains("base plan digest"));
    let binding = json!({"kind": "security-variant-analysis", "parentPlanDigest": base.digest()});
    let (next, link) = apply_followup(&base, variant, binding, "variant", NOW, KEY).unwrap();
    assert_eq!(link.result_generation, 2);
    assert_eq!(
        next.plan().bounds["followupRuns"][0]["providerId"],
        json!("variant.analysis")
    );
    let mut wrong_role = provider("not.variant", &[], &[], &[]);
    wrong_role.role = "deterministic".into();
    assert!(apply_followup(
        &base,
        wrong_role,
        json!({"parentPlanDigest": base.digest()}),
        "x",
        NOW,
        KEY
    )
    .is_err());
}
