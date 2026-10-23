//! Wiring of signed amendments into continuation, follow-up and variant
//! ledger paths: generation chains verify, forgeries are refused, follow-up
//! generations are signed with the parent key, and the ledger is required.

use std::collections::BTreeMap;

use legion_audit::amendment::{
    apply, apply_followup, frozen_plan_from_run_json, record_in_journal, AmendmentBody,
    AmendmentChainRecord, AmendmentOperation, SignedAmendment,
};
use legion_audit::journal::{EventKind, Journal};
use legion_audit::native_providers::reasoning::followup::{
    root_cause_signature, LedgerAssessment, VariantLedger, VARIANT_LEDGER_FILE,
    VARIANT_LEDGER_REQUIRED,
};
use legion_audit::{
    AuditPlan, AuditProvider, AuthorityMode, Engagement, EngagementAuthority, EngagementScope,
    FrozenPlan, ProviderKind, StopConditions, PLAN_SCHEMA_V2,
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

fn temp_dir(name: &str) -> std::path::PathBuf {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).unwrap();
    let dir = std::env::temp_dir().join(format!("legion-amd-wiring-{name}-{}", hex::encode(nonce)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_json(plan: &FrozenPlan) -> Value {
    json!({"nativePlan": {
        "schemaVersion": 1,
        "digest": plan.digest(),
        "signature": plan.signature(),
        "plan": serde_json::to_value(plan.plan()).unwrap(),
    }})
}

fn extend(base: &FrozenPlan, tokens: u64) -> (FrozenPlan, AmendmentChainRecord) {
    let body = AmendmentBody::new(
        base,
        "budget continuation: explicit operator resume",
        NOW,
        vec![AmendmentOperation::ExtendBudget { max_tokens: tokens }],
    )
    .unwrap();
    let signed = SignedAmendment::sign(body, KEY).unwrap();
    let (next, applied) = apply(base, &signed, KEY).unwrap();
    let record = AmendmentChainRecord::new(base, vec![applied], &next).unwrap();
    (next, record)
}

#[test]
fn budget_continuation_creates_generation_two_and_the_chain_verifies() {
    let base = v2_plan(Some(&explicit()));
    let (next, record) = extend(&base, 900);
    assert_eq!(base.plan().generation().unwrap(), 1);
    assert_eq!(next.plan().generation().unwrap(), 2);
    assert_eq!(
        next.plan()
            .engagement()
            .unwrap()
            .unwrap()
            .stop_conditions
            .max_tokens,
        Some(900)
    );
    let replayed = record.verify(&base, KEY).unwrap();
    assert_eq!(replayed.digest(), next.digest());
    // The persisted form round-trips and still verifies.
    let again: AmendmentChainRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(again, record);
    assert_eq!(again.verify(&base, KEY).unwrap().digest(), next.digest());
    // Exceeding the engagement authority ceiling is refused.
    let body = AmendmentBody::new(
        &base,
        "too much",
        NOW,
        vec![AmendmentOperation::ExtendBudget { max_tokens: 5000 }],
    )
    .unwrap();
    assert!(apply(&base, &SignedAmendment::sign(body, KEY).unwrap(), KEY).is_err());
}

#[test]
fn forged_chain_links_and_results_are_rejected() {
    let base = v2_plan(Some(&explicit()));
    let (_, record) = extend(&base, 900);

    let mut forged = record.clone();
    forged.links[0].amendment.body.operations =
        vec![AmendmentOperation::ExtendBudget { max_tokens: 1000 }];
    assert!(forged.verify(&base, KEY).is_err());

    let mut resigned = record.clone();
    resigned.links[0].amendment.body.operations =
        vec![AmendmentOperation::ExtendBudget { max_tokens: 1000 }];
    resigned.links[0].amendment.digest = resigned.links[0].amendment.body.digest().unwrap();
    assert!(resigned.verify(&base, KEY).is_err());

    let mut wrong_result = record.clone();
    wrong_result.result_plan["digest"] = json!(format!("sha256:{}", "1".repeat(64)));
    assert!(wrong_result.verify(&base, KEY).is_err());

    assert!(record.verify(&base, b"another-key").is_err());
    let other = v2_plan(Some(&implicit()));
    assert!(record.verify(&other, KEY).is_err());
}

#[test]
fn embedded_run_plan_restores_only_under_its_key() {
    let base = v2_plan(Some(&explicit()));
    let json = run_json(&base);
    let restored = frozen_plan_from_run_json(&json, KEY).unwrap();
    assert_eq!(restored.digest(), base.digest());
    assert!(frozen_plan_from_run_json(&json, b"another-key").is_err());
    assert!(frozen_plan_from_run_json(&json!({}), KEY).is_err());
}

#[test]
fn followup_generation_is_signed_with_the_parent_key() {
    let base = v2_plan(Some(&explicit()));
    let mut variant = provider("variant.analysis", &[], &[], &[]);
    variant.role = "variant-analysis".into();
    variant.lens_ids = vec!["security".into()];
    let binding = json!({"kind": "security-variant-analysis", "parentPlanDigest": base.digest()});
    let (next, link) =
        apply_followup(&base, variant, binding, "variant follow-up", NOW, KEY).unwrap();
    assert_eq!(link.result_generation, 2);
    assert_eq!(next.plan().generation().unwrap(), 2);
    let record = AmendmentChainRecord::new(&base, vec![link], &next).unwrap();
    assert!(record.verify(&base, KEY).is_ok());
    // A fresh (epoch) key cannot produce or verify the generation.
    assert!(record.verify(&base, b"fresh-epoch-key").is_err());
    assert!(apply_followup(
        &base,
        provider("not.variant", &[], &[], &[]),
        json!({"parentPlanDigest": base.digest()}),
        "x",
        NOW,
        KEY
    )
    .is_err());
}

#[test]
fn amendment_events_reach_a_live_journal_only() {
    let base = v2_plan(Some(&explicit()));
    let (_, record) = extend(&base, 900);
    let applied = &record.links[0];

    let none = temp_dir("nojournal");
    assert!(!record_in_journal(&none, base.digest(), applied, NOW).unwrap());

    let live = temp_dir("live");
    drop(Journal::create(&live, base.digest(), 1).unwrap());
    assert!(record_in_journal(&live, base.digest(), applied, NOW).unwrap());
    let reopened = Journal::open(&live, base.digest()).unwrap();
    assert_eq!(reopened.effective_plan_digest(), applied.result_plan_digest);
    drop(reopened);

    let finalized = temp_dir("finalized");
    let mut journal = Journal::create(&finalized, base.digest(), 1).unwrap();
    journal
        .append(EventKind::ReportFinalized, "report", base.digest(), 2)
        .unwrap();
    drop(journal);
    assert!(!record_in_journal(&finalized, base.digest(), applied, NOW).unwrap());
}

fn ledger(matched: u64, confirmed: u64, rejected: u64, unresolved: u64) -> VariantLedger {
    VariantLedger {
        root_cause_signature: root_cause_signature("rule", "sink", "control").unwrap(),
        denominator_count: 4,
        matched,
        examined: confirmed + rejected + unresolved,
        confirmed,
        rejected,
        unresolved,
        rejection_reasons: vec!["guarded".into(); rejected as usize],
        parent_plan_digest: format!("sha256:{}", "a".repeat(64)),
        followup_plan_digest: format!("sha256:{}", "b".repeat(64)),
        confirmed_digest: format!("sha256:{}", "c".repeat(64)),
        ledger_digest: String::new(),
    }
    .seal()
    .unwrap()
}

#[test]
fn variant_ledger_is_required_and_unresolved_keeps_the_pass_incomplete() {
    assert!(VARIANT_LEDGER_REQUIRED);
    assert_eq!(VARIANT_LEDGER_FILE, "variant-ledger.json");
    assert!(ledger(3, 2, 1, 0).is_complete());
    assert!(matches!(
        ledger(3, 1, 1, 1).assess(),
        LedgerAssessment::Incomplete(_)
    ));
    let mut tampered = ledger(3, 2, 1, 0);
    tampered.unresolved = 0;
    tampered.rejected = 0;
    assert!(tampered
        .verify_binding(
            &tampered.parent_plan_digest.clone(),
            &tampered.followup_plan_digest.clone(),
            &tampered.confirmed_digest.clone(),
            4
        )
        .is_err());
}
