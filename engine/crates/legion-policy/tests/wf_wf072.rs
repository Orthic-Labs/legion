//! Integration tests for wf072's ported modules
//! (`legion_policy::wf_port::wf072::*`).
//!
//! NOTE for the integration owner: this file will not compile until
//! `pub mod wf_port;` is added to `engine/crates/legion-policy/src/lib.rs`
//! (if not already present from another wf packet) and `pub mod wf072;` to
//! `engine/crates/legion-policy/src/wf_port/mod.rs` (see the wf072 report).
//! Until then, the equivalent coverage lives as `#[cfg(test)]` unit tests
//! inside each `wf_port::wf072::*` submodule.

use legion_policy::wf_port::wf072::evidence_envelope::{
    import_legacy_evidence, seal_evidence, unfaithful_dimensions, Dependency, LegacyEnvelope, SealEvidenceInput,
    DEPENDENCY_DIMENSION,
};
use legion_policy::wf_port::wf072::evidence_migration::migrate_legacy_evidence;
use legion_policy::wf_port::wf072::evidence_registry::{
    evidence_freshness, Artifact, FreshnessContext, Freshness,
};
use legion_policy::wf_port::wf072::gate_validity::{
    execute_validated_gate, validate_gate, ExecResult, ExecResultStatus, Fixture, GateContract, Match,
};
use legion_policy::wf_port::wf072::ingest::{
    AuthorityAssertion, Effect, EffectReceipt, EventResult, HostEvent, HostIngestor, PriorCorrelation, ResultOutcome,
};
use legion_policy::wf_port::wf072::support::{ArcCode, Json};

// ---------------------------------------------------------------------
// evidence-envelope.mjs
// ---------------------------------------------------------------------

#[test]
fn dependency_dimension_set_has_16_entries_and_9_unfaithful_projections() {
    assert_eq!(DEPENDENCY_DIMENSION.len(), 16);
    assert_eq!(unfaithful_dimensions().len(), 9);
}

#[test]
fn seal_evidence_projects_source_digest_dependency_and_seals_deterministically() {
    let input = SealEvidenceInput {
        evidence_id: "ev-int-1".into(),
        provisional: false,
        run_id: "run-int-1".into(),
        task_id: None,
        contract_id: None,
        producer_authority: "capability:audit".into(),
        capability: "audit".into(),
        observation: Json::Obj(vec![("claim".into(), Json::str("clean"))]),
        evidence_class: "internal".into(),
        source_revision: Some("git:deadbeef".into()),
        dependencies: vec![Dependency { dimension: "source-digest".into(), reference: "sha256:11".into(), digest: Some("sha256:11".into()) }],
        authentication_verification_method: Some("mac".into()),
        authentication: Json::Null,
        replay_defense: Json::Null,
        observed_at: "2026-01-01T00:00:00Z".into(),
    };
    let sealed1 = seal_evidence(input.clone()).unwrap();
    let sealed2 = seal_evidence(input).unwrap();
    assert_eq!(sealed1.envelope_digest, sealed2.envelope_digest, "sealing is deterministic");
}

#[test]
fn import_legacy_evidence_never_qualifies() {
    let legacy = LegacyEnvelope {
        kind: "legion-legacy-envelope".into(),
        legacy_kind: "manual-audit".into(),
        payload: Json::str("payload"),
        authenticated: false,
        source_revision: Some("git:1".into()),
        source: "legacy-cli".into(),
        captured_at: "2025-01-01T00:00:00Z".into(),
        provisional_mapping_ref: None,
    };
    let imported = import_legacy_evidence(&legacy, "ev-int-2".into(), None, None, None).unwrap();
    assert!(imported.never_qualifying);
    assert_eq!(imported.trust_class, "legacy-unauthenticated");
}

// ---------------------------------------------------------------------
// evidence-migration.mjs
// ---------------------------------------------------------------------

#[test]
fn migration_batch_quarantines_malformed_and_rejects_authenticated_true_separately() {
    let good = LegacyEnvelope {
        kind: "legion-legacy-envelope".into(),
        legacy_kind: "k".into(),
        payload: Json::str("p"),
        authenticated: false,
        source_revision: Some("git:1".into()),
        source: "legacy-tool".into(),
        captured_at: "2026-01-01T00:00:00Z".into(),
        provisional_mapping_ref: None,
    };
    let malformed = LegacyEnvelope {
        kind: "wrong-kind".into(),
        legacy_kind: "k".into(),
        payload: Json::Null,
        authenticated: false,
        source_revision: None,
        source: "s".into(),
        captured_at: "2026-01-01T00:00:00Z".into(),
        provisional_mapping_ref: None,
    };
    let mut auth_true = good.clone();
    auth_true.authenticated = true;

    let records = vec![good, malformed, auth_true];
    let result = migrate_legacy_evidence(
        &records,
        "2026-01-01T00:00:00Z",
        "mapping-v1",
        |i| format!("ev-{i}"),
        |_| {},
    );
    assert_eq!(result.imported.len(), 1);
    assert_eq!(result.quarantined.len(), 1);
    assert_eq!(result.rejected.len(), 1);
    assert_eq!(result.receipt.trust_granted, 0, "old records never gain trust");
    assert!(result.receipt.record_count_matches);
}

// ---------------------------------------------------------------------
// evidence-registry.mjs
// ---------------------------------------------------------------------

#[test]
fn evidence_freshness_state_mismatch_takes_precedence_over_time_checks() {
    let artifact = Artifact {
        authenticated: true,
        integrated_state: Some("state-a".into()),
        observed_at_millis: Some(1000),
        valid_until_millis: Some(2000),
        acceptance_id: "acc-1".into(),
        producer: "p".into(),
        verifier: "v".into(),
        completion_consumer: "c".into(),
    };
    let ctx = FreshnessContext { integrated_state: Some("state-b".into()), latest_material_change_millis: Some(0), now_millis: 1500 };
    assert_eq!(evidence_freshness(&artifact, &ctx), Freshness::StateMismatch);
}

// ---------------------------------------------------------------------
// gate-validity.mjs
// ---------------------------------------------------------------------

#[test]
fn gate_validity_full_lifecycle_validate_then_execute() {
    let contract = GateContract {
        id: "gate-int-1".into(),
        inspected_scope: "repo".into(),
        discovery_breadth: "full".into(),
        blocking_filter: "hard".into(),
        threshold: "zero-tolerance".into(),
        gates: true,
        authority: "audit".into(),
        failure_semantics: "block".into(),
        payload: Json::Obj(vec![("id".into(), Json::str("gate-int-1"))]),
    };
    let fixtures: Vec<(&'static str, Option<(Fixture, ExecResult)>)> = vec![
        ("knownGood", Some((Fixture { id: "kg".into(), payload: Json::str("kg") }, ExecResult { status: ExecResultStatus::Pass }))),
        ("knownBad", Some((Fixture { id: "kb".into(), payload: Json::str("kb") }, ExecResult { status: ExecResultStatus::Fail }))),
        ("empty", Some((Fixture { id: "e".into(), payload: Json::str("e") }, ExecResult { status: ExecResultStatus::Fail }))),
        ("malformed", Some((Fixture { id: "m".into(), payload: Json::str("m") }, ExecResult { status: ExecResultStatus::Fail }))),
    ];
    let validity = validate_gate(&contract, &fixtures).expect("gate self-test should pass");

    let inspected = vec![Json::str("finding-1")];
    let clean = execute_validated_gate(&contract, Some(&validity), &inspected, &[]);
    assert!(clean.allowed);

    let matched = vec![Match { rule_id: Some("rule-x".into()), reason: Some("profanity".into()) }];
    let dirty = execute_validated_gate(&contract, Some(&validity), &inspected, &matched);
    assert!(!dirty.allowed);
    assert_eq!(dirty.code, Some(ArcCode::ArcClaimPrerequisiteUnmet));
}

// ---------------------------------------------------------------------
// ingest.mjs (HostIngestor)
// ---------------------------------------------------------------------

fn sample_event() -> HostEvent {
    HostEvent {
        event_id: "evt-int-1".into(),
        event_type: "post-effect".into(),
        effect: Some(Effect { effect_class: "file-write".into(), target: "/repo/file.rs".into(), operation: "write".into() }),
        run_id: Some("run-int-1".into()),
        contract_id: Some("contract-1".into()),
        task_id: Some("task-1".into()),
        session_id: "sess-int-1".into(),
        workspace: "ws-int-1".into(),
        source_revision: Some("git:cafef00d".into()),
        prior_correlation: Some(PriorCorrelation {
            request_id: "req-int-1".into(),
            requested_effect: Some(Effect { effect_class: "file-write".into(), target: "/repo/file.rs".into(), operation: "write".into() }),
            authorized_effect: Some(Effect { effect_class: "file-write".into(), target: "/repo/file.rs".into(), operation: "write".into() }),
            capability_id: Some("cap-int-1".into()),
        }),
        result: EventResult { outcome: ResultOutcome::Success, observed_digest: Some("sha256:22".into()) },
        replay_nonce: "nonce-1".into(),
        replay_sequence: 1,
        time: "2026-01-01T00:00:00Z".into(),
        idempotency_key: Some("idem-int-1".into()),
        structurally_valid: true,
        payload_claims_authority: false,
    }
}

#[test]
fn host_ingestor_end_to_end_accepts_and_persists_an_effect_receipt() {
    let mut ingestor = HostIngestor::new();
    let authority = AuthorityAssertion {
        asserted_by: "host".into(),
        receipt: None,
        connection_trust: Some(legion_policy::wf_port::wf072::ingest::ConnectionTrust {
            issuer_identity: "host:claude-code".into(),
            verified_at: None,
        }),
    };
    let mut appended: Vec<EffectReceipt> = Vec::new();
    let mut invalidated: Vec<(String, String)> = Vec::new();

    let outcome = ingestor.ingest(
        &sample_event(),
        &authority,
        |_| "mutation-observation".to_string(),
        |_, _| Ok(()),
        |_| Ok(()),
        || "receipt-int-1".to_string(),
        |r: &EffectReceipt| appended.push(r.clone()),
        Some(|target: &str, digest: &str| invalidated.push((target.to_string(), digest.to_string()))),
    );

    assert!(outcome.accepted);
    let receipt = outcome.receipt.expect("post-effect with a bound run should mint a receipt");
    assert_eq!(receipt.receipt_id, "receipt-int-1");
    assert!(receipt.matched);
    assert_eq!(appended.len(), 1);
    assert_eq!(invalidated, vec![("/repo/file.rs".to_string(), "sha256:22".to_string())]);
}

#[test]
fn host_ingestor_refuses_a_model_self_report_end_to_end() {
    let mut ingestor = HostIngestor::new();
    let authority = AuthorityAssertion { asserted_by: "model".into(), receipt: None, connection_trust: None };
    let outcome = ingestor.ingest(
        &sample_event(),
        &authority,
        |_| "x".to_string(),
        |_, _| Ok(()),
        |_| Ok(()),
        || "should-not-mint".to_string(),
        |_: &EffectReceipt| panic!("must never persist a model self-report"),
        None::<fn(&str, &str)>,
    );
    assert!(!outcome.accepted);
    assert_eq!(outcome.decision.code, Some(ArcCode::ArcModelSelfReport));
}
