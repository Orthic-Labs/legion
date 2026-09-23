//! Integration tests for wf073
//! (`src/lib/verification/arcane/{invalidation,pending-terminal-operation-store,
//! provider-capability,review-disposition-policy}.mjs` and
//! `s11-bindings/advisory-judgment.mjs`).
//!
//! NOTE: these tests exercise `legion_policy::wf_port::wf073`, which is not
//! yet wired into `legion-policy`'s public module tree (`src/lib.rs` needs
//! `pub mod wf_port;` and `src/wf_port/mod.rs` needs `pub mod wf073;` — both
//! left to the integration owner per this chunk's scope). Until wired, this
//! file will not compile; this mirrors the existing pattern for
//! `tests/wf_wf068.rs` / `tests/wf_wf069.rs` in this same crate, which are
//! in the identical pre-wiring state.

use legion_policy::wf_port::wf073::{
    advisory_judgment_bindings, advisory_judgment_runtime_ids, evaluate_review_disposition_case,
    review_disposition_policy_ids, validate_advisory_judgment_observation, validate_review_disposition_decision,
    AdapterCapability, ArcaneError, CaseEvidence, Coverage, Dependency, DependencyLedger, EligibilityStatus,
    ExploitChainEvidence, ExploitLink, Finding, HandoffEvidence, InMemoryProviderCapabilityStore,
    PendingTerminalOperationStore, ProviderCapabilityRegistry, ReviewDispositionDecision,
    ReviewReopenEvidence, Status,
};

// ---------------------------------------------------------------------
// invalidation.mjs — DependencyLedger
// (ported from tests/arcane-package-s05-invalidation.test.mjs)
// ---------------------------------------------------------------------

fn fixed_clock() -> DependencyLedger {
    DependencyLedger::new(|| "2026-01-01T00:00:00.000Z".to_string())
}

#[test]
fn source_revision_change_cascades_exactly_once_and_leaves_unrelated_evidence_unaffected() {
    let mut ledger = fixed_clock();
    let src_digest_1 = format!("sha256:{}", "1".repeat(64));
    let src_digest_2 = format!("sha256:{}", "2".repeat(64));

    ledger.register(
        "ev_A",
        vec![Dependency { dimension: "git-revision".into(), reference: "repo:main".into(), digest: src_digest_1.clone() }],
    );
    ledger.register(
        "ev_B",
        vec![Dependency { dimension: "evidence".into(), reference: "ev_A".into(), digest: format!("sha256:{}", "a".repeat(64)) }],
    );
    ledger.register(
        "ev_D",
        vec![Dependency { dimension: "config-digest".into(), reference: "config:app".into(), digest: format!("sha256:{}", "d".repeat(64)) }],
    );
    ledger.link("ev_B", Some("AC-1"), Some("clm_1")).unwrap();

    let event = ledger.observe_change("git-revision", "repo:main", &src_digest_2);

    assert_eq!(event.staled_evidence, vec!["ev_A".to_string()]);
    assert_eq!(event.cascaded_evidence, vec!["ev_B".to_string()]);
    assert_eq!(event.affected_criteria, vec!["AC-1".to_string()]);
    assert_eq!(event.affected_claims, vec!["clm_1".to_string()]);
    assert_eq!(event.unaffected, vec!["ev_D".to_string()]);
    assert_eq!(event.changed.dimension, "git-revision");
    assert_eq!(event.changed.reference, "repo:main");
    assert_eq!(event.changed.from, Some(src_digest_1));
    assert_eq!(event.changed.to, src_digest_2);

    assert!(ledger.is_stale("ev_A").unwrap());
    assert!(ledger.is_stale("ev_B").unwrap());
    assert!(!ledger.is_stale("ev_D").unwrap());

    let eligibility = ledger.proof_eligibility("AC-1");
    assert_eq!(eligibility.status, EligibilityStatus::Unproven);
    assert_eq!(eligibility.stale_evidence, vec!["ev_B".to_string()]);
}

#[test]
fn changing_a_different_dimension_stales_exactly_the_bound_evidence() {
    let mut ledger = fixed_clock();
    ledger.register("ev_1", vec![Dependency { dimension: "config-digest".into(), reference: "config:x".into(), digest: format!("sha256:{}", "1".repeat(64)) }]);
    ledger.register("ev_2", vec![Dependency { dimension: "policy-version".into(), reference: "policy:y".into(), digest: format!("sha256:{}", "2".repeat(64)) }]);
    ledger.register("ev_3", vec![Dependency { dimension: "config-digest".into(), reference: "config:other".into(), digest: format!("sha256:{}", "3".repeat(64)) }]);

    let event = ledger.observe_change("config-digest", "config:x", &format!("sha256:{}", "f".repeat(64)));

    assert_eq!(event.staled_evidence, vec!["ev_1".to_string()]);
    assert!(event.cascaded_evidence.is_empty());
    assert!(event.unaffected.contains(&"ev_2".to_string()));
    assert!(event.unaffected.contains(&"ev_3".to_string()));
    assert!(ledger.is_stale("ev_1").unwrap());
    assert!(!ledger.is_stale("ev_2").unwrap());
    assert!(!ledger.is_stale("ev_3").unwrap());
}

#[test]
fn historical_preservation_original_digest_never_overwritten() {
    let mut ledger = fixed_clock();
    let original_digest = format!("sha256:{}", "7".repeat(64));
    ledger.register("ev_hist", vec![Dependency { dimension: "source-digest".into(), reference: "file:a.js".into(), digest: original_digest.clone() }]);

    ledger.observe_change("source-digest", "file:a.js", &format!("sha256:{}", "8".repeat(64)));

    let rec = ledger.get_evidence("ev_hist").unwrap();
    assert!(rec.stale);
    assert_eq!(rec.dependencies[0].digest, original_digest);
    assert_eq!(rec.stale_events.len(), 1);
    assert_eq!(rec.stale_events[0].from, Some(original_digest));
}

#[test]
fn untrusted_legacy_evidence_can_never_become_proven() {
    let mut ledger = fixed_clock();
    ledger.register_with_trust("ev_legacy", vec![], false);
    ledger.link("ev_legacy", Some("AC-legacy"), None).unwrap();

    let eligibility = ledger.proof_eligibility("AC-legacy");
    assert_ne!(eligibility.status, EligibilityStatus::Proven);
    assert_eq!(eligibility.status, EligibilityStatus::Insufficient);
    assert!(eligibility.reasons.iter().any(|r| r.contains("ev_legacy")));
}

#[test]
fn corrupt_ledger_entry_blocks_strong_claims_and_reports_affected_ids() {
    let mut ledger = fixed_clock();
    ledger.register("ev_ok", vec![Dependency { dimension: "config-digest".into(), reference: "config:z".into(), digest: format!("sha256:{}", "0".repeat(64)) }]);
    ledger.link("ev_ok", Some("AC-corrupt"), None).unwrap();
    assert_eq!(ledger.proof_eligibility("AC-corrupt").status, EligibilityStatus::Proven);

    ledger.mark_corrupt("ev_ok", "digest chain broken at sequence 4").unwrap();

    let eligibility = ledger.proof_eligibility("AC-corrupt");
    assert_eq!(eligibility.status, EligibilityStatus::Insufficient);
    assert!(eligibility
        .reasons
        .iter()
        .any(|r| r.contains("ev_ok") && r.contains("digest chain broken at sequence 4")));

    let quarantined = ledger.quarantined();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].evidence_id, "ev_ok");

    let rec = ledger.get_evidence("ev_ok").unwrap();
    assert!(rec.corrupt);
    assert_eq!(rec.dependencies.len(), 1);
}

#[test]
fn unknown_evidence_id_is_rejected_with_arc_dependency_unknown() {
    let mut ledger = fixed_clock();
    let link_err = ledger.link("ev_missing", Some("AC-x"), None).unwrap_err();
    assert_eq!(link_err.code, "ARC_DEPENDENCY_UNKNOWN");
    let stale_err = ledger.is_stale("ev_missing").unwrap_err();
    assert_eq!(stale_err.code, "ARC_DEPENDENCY_UNKNOWN");
}

#[test]
fn proof_eligibility_with_no_linked_evidence_is_insufficient() {
    let ledger = fixed_clock();
    assert_eq!(ledger.proof_eligibility("AC-none").status, EligibilityStatus::Insufficient);
}

#[test]
fn snapshot_exposes_state_consistently_with_individual_accessors() {
    let mut ledger = fixed_clock();
    ledger.register("ev_snap", vec![Dependency { dimension: "tool-version".into(), reference: "tool:node".into(), digest: format!("sha256:{}", "9".repeat(64)) }]);
    ledger.link("ev_snap", Some("AC-snap"), Some("clm_snap")).unwrap();

    let snap = ledger.snapshot();
    assert!(snap.evidence.iter().any(|e| e.evidence_id == "ev_snap"));
    assert!(snap
        .criteria
        .iter()
        .any(|(id, ev)| id.as_str() == "AC-snap" && ev.contains(&"ev_snap".to_string())));
    assert!(snap
        .claims
        .iter()
        .any(|(id, crit)| id.as_str() == "clm_snap" && crit.contains(&"AC-snap".to_string())));
    assert!(snap.quarantined.is_empty());
}

// ---------------------------------------------------------------------
// pending-terminal-operation-store.mjs
// ---------------------------------------------------------------------

#[test]
fn mint_rejects_caller_supplied_authentication_or_claim_id() {
    let dir = std::env::temp_dir().join(format!("wf073-ptos-{}", std::process::id()));
    let store = PendingTerminalOperationStore::new(dir, vec![1, 2, 3, 4], || "2026-01-01T00:00:00.000Z".to_string());
    let mut fields = serde_json::Map::new();
    fields.insert("claimId".into(), serde_json::json!("sha256:deadbeef"));
    let err: ArcaneError = store.mint(fields).unwrap_err();
    assert_eq!(err.code, "ARC_AUTHORITY_MODEL_CLAIMED");
}

#[test]
fn mint_append_matching_and_resolve_round_trip() {
    let dir = std::env::temp_dir().join(format!("wf073-ptos-rt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = PendingTerminalOperationStore::new(dir, vec![9, 9, 9], || "2026-01-01T00:00:00.000Z".to_string());

    let digest = format!("sha256:{}", "a".repeat(64));
    let mut fields = serde_json::Map::new();
    fields.insert("invocationProofDigest".into(), serde_json::json!(digest));
    fields.insert("producerAuthority".into(), serde_json::json!("legion"));
    fields.insert("runId".into(), serde_json::json!("run-1"));
    fields.insert("taskId".into(), serde_json::json!("task-1"));
    fields.insert("contractId".into(), serde_json::json!("contract-1"));
    fields.insert("contractVersion".into(), serde_json::json!(1));
    fields.insert("contractDigest".into(), serde_json::json!(digest));
    fields.insert("sourceRevision".into(), serde_json::json!("abcdef1"));
    fields.insert("turnCorrelationDigest".into(), serde_json::json!(digest));
    fields.insert("expectedStopOrdinal".into(), serde_json::json!(1));
    fields.insert("outcomeSummaryDigest".into(), serde_json::json!(digest));
    fields.insert("artifactStateDigest".into(), serde_json::json!(digest));

    let claim = store.mint(fields).expect("mint succeeds");
    let claim_id = claim.get("claimId").unwrap().as_str().unwrap().to_string();

    let appended = store.append(claim.clone());
    assert_eq!(appended.get("allowed").unwrap(), true);

    // Idempotent re-append of the identical claim.
    let appended_again = store.append(claim.clone());
    assert_eq!(appended_again.get("allowed").unwrap(), true);
    assert_eq!(
        appended_again.get("detail").unwrap().get("idempotent").unwrap(),
        true
    );

    let found = store.matching(claim.get("turnCorrelationDigest").unwrap().as_str().unwrap(), 1);
    assert!(found.is_some());

    let resolved = store.resolve(
        &claim_id,
        &format!("sha256:{}", "b".repeat(64)),
        claim.get("turnCorrelationDigest").unwrap().as_str().unwrap(),
        1,
        true,
    );
    assert_eq!(resolved.get("allowed").unwrap(), true);
    assert_eq!(
        resolved.get("detail").unwrap().get("certification").unwrap(),
        "genuine"
    );
}

#[test]
fn resolve_rejects_mismatched_stop_binding() {
    let dir = std::env::temp_dir().join(format!("wf073-ptos-mismatch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = PendingTerminalOperationStore::new(dir, vec![4, 4, 4], || "2026-01-01T00:00:00.000Z".to_string());
    let digest = format!("sha256:{}", "c".repeat(64));
    let mut fields = serde_json::Map::new();
    fields.insert("invocationProofDigest".into(), serde_json::json!(digest));
    fields.insert("producerAuthority".into(), serde_json::json!("legion"));
    fields.insert("runId".into(), serde_json::json!("run-2"));
    fields.insert("taskId".into(), serde_json::json!("task-2"));
    fields.insert("contractId".into(), serde_json::json!("contract-2"));
    fields.insert("contractVersion".into(), serde_json::json!(1));
    fields.insert("contractDigest".into(), serde_json::json!(digest));
    fields.insert("sourceRevision".into(), serde_json::json!("abcdef1"));
    fields.insert("turnCorrelationDigest".into(), serde_json::json!(digest));
    fields.insert("expectedStopOrdinal".into(), serde_json::json!(1));
    fields.insert("outcomeSummaryDigest".into(), serde_json::json!(digest));
    fields.insert("artifactStateDigest".into(), serde_json::json!(digest));
    let claim = store.mint(fields).unwrap();
    let claim_id = claim.get("claimId").unwrap().as_str().unwrap().to_string();
    store.append(claim.clone());

    let resolved = store.resolve(&claim_id, "sha256:zz", "sha256:wrong-turn", 1, true);
    assert_eq!(resolved.get("allowed").unwrap(), false);
    assert_eq!(resolved.get("code").unwrap(), "ARC_BINDING_MISMATCH");
}

// ---------------------------------------------------------------------
// provider-capability.mjs
// ---------------------------------------------------------------------

fn full_adapter(id: &str) -> AdapterCapability {
    AdapterCapability {
        adapter_id: id.to_string(),
        machine_readable: true,
        gateable: true,
        downloadable: true,
        trusted_retrieval: true,
        trajectory_bindable: true,
    }
}

#[test]
fn record_rejects_an_incomplete_adapter() {
    let mut registry = ProviderCapabilityRegistry::new(InMemoryProviderCapabilityStore::default());
    let mut broken = full_adapter("adapter-1");
    broken.gateable = false;
    let decision = registry.record("provider-1", &broken, "2026-01-01T00:00:00.000Z", None, "normal", None, None);
    assert!(!decision.allowed);
    assert_eq!(decision.code, Some("ARC_UNSOUND_SEAL"));
    assert_eq!(decision.admission, Some("INFORMATIONAL_ONLY"));
}

#[test]
fn record_rejects_sensitive_without_retention_or_deletion_owner() {
    let mut registry = ProviderCapabilityRegistry::new(InMemoryProviderCapabilityStore::default());
    let adapter = full_adapter("adapter-2");
    let decision = registry.record("provider-2", &adapter, "2026-01-01T00:00:00.000Z", None, "sensitive", None, None);
    assert!(!decision.allowed);
    assert_eq!(decision.admission, Some("DENIED"));
}

#[test]
fn record_then_get_round_trips_through_the_adapter() {
    let mut registry = ProviderCapabilityRegistry::new(InMemoryProviderCapabilityStore::default());
    let adapter = full_adapter("adapter-3");
    let decision = registry.record("provider-3", &adapter, "2026-01-01T00:00:00.000Z", None, "normal", None, None);
    assert!(decision.allowed);
    let stored = registry.get("provider-3").expect("stored");
    assert_eq!(stored.provider_id, "provider-3");
    assert_eq!(stored.adapter.adapter_id, "adapter-3");
}

#[test]
fn registry_without_store_always_reports_informational_only() {
    let mut registry: ProviderCapabilityRegistry<InMemoryProviderCapabilityStore> =
        ProviderCapabilityRegistry::without_store();
    let adapter = full_adapter("adapter-4");
    let decision = registry.record("provider-4", &adapter, "2026-01-01T00:00:00.000Z", None, "normal", None, None);
    assert!(!decision.allowed);
    assert_eq!(decision.admission, Some("INFORMATIONAL_ONLY"));
}

// ---------------------------------------------------------------------
// review-disposition-policy.mjs
// (ported from tests/arcane-package-review-disposition-policy.test.mjs)
// ---------------------------------------------------------------------

#[test]
fn irreversible_uncertainty_after_exhausted_review_budget_needs_a_spike() {
    let evidence = HandoffEvidence {
        irreversible: true,
        uncertainty: true,
        review_budget_exhausted: true,
        external_block: false,
        budget_stop: false,
    };
    let decision = evaluate_review_disposition_case("AE-HANDOFF-004", CaseEvidence::Handoff(&evidence)).unwrap();
    assert_eq!(decision.disposition(), Some("NEEDS_SPIKE"));
    assert!(validate_review_disposition_decision("AE-HANDOFF-004", &decision));
}

#[test]
fn unsupported_links_deny_exploit_chain_and_downgrade_coverage() {
    let evidence = ExploitChainEvidence {
        nodes: vec!["entry".to_string(), "sink".to_string()],
        links: vec![ExploitLink {
            from: "entry".to_string(),
            to: "sink".to_string(),
            demonstrated: false,
            evidence_id: String::new(),
        }],
        coverage: Some(Coverage {
            claimed_areas: vec!["entry".to_string(), "sink".to_string(), "auth".to_string()],
            inspected_areas: vec!["entry".to_string(), "sink".to_string()],
        }),
    };
    let decision =
        evaluate_review_disposition_case("AE-REVIEW-VERDICT-SECURITY-002", CaseEvidence::ExploitChain(&evidence))
            .unwrap();
    assert_eq!(decision.disposition(), Some("NO_EXPLOIT_CHAIN"));
    if let ReviewDispositionDecision::ExploitChain { coverage, .. } = &decision {
        assert_eq!(coverage.disposition, "INCOMPLETE_COVERAGE");
    } else {
        panic!("expected ExploitChain decision");
    }
    assert!(validate_review_disposition_decision(
        "AE-REVIEW-VERDICT-SECURITY-002",
        &decision
    ));
}

#[test]
fn closed_reviews_with_advisory_items_only_never_reopen() {
    let evidence = ReviewReopenEvidence {
        review_closed: true,
        findings: vec![Finding {
            id: "style-note".to_string(),
            blocking: false,
            disposition: "ADVISORY".to_string(),
        }],
    };
    let decision =
        evaluate_review_disposition_case("AE-REVIEW-VERDICT-SECURITY-005", CaseEvidence::ReviewReopen(&evidence))
            .unwrap();
    assert_eq!(decision.disposition(), Some("NO_REOPEN"));
    assert!(validate_review_disposition_decision(
        "AE-REVIEW-VERDICT-SECURITY-005",
        &decision
    ));
}

#[test]
fn policy_rejects_malformed_or_contrary_evidence_instead_of_defaulting_to_success() {
    let missing = evaluate_review_disposition_case("AE-HANDOFF-004", CaseEvidence::Missing).unwrap();
    assert_eq!(*missing.status(), Status::Deny);

    let reopen_required_evidence = ReviewReopenEvidence {
        review_closed: true,
        findings: vec![Finding {
            id: "security".to_string(),
            blocking: true,
            disposition: "BLOCKING".to_string(),
        }],
    };
    let reopen_required = evaluate_review_disposition_case(
        "AE-REVIEW-VERDICT-SECURITY-005",
        CaseEvidence::ReviewReopen(&reopen_required_evidence),
    )
    .unwrap();
    assert_eq!(reopen_required.disposition(), Some("REOPEN_REQUIRED"));

    assert_eq!(
        review_disposition_policy_ids(),
        &["AE-HANDOFF-004", "AE-REVIEW-VERDICT-SECURITY-002", "AE-REVIEW-VERDICT-SECURITY-005"]
    );
}

// ---------------------------------------------------------------------
// s11-bindings/advisory-judgment.mjs
// (ported from tests/stage11-advisory-judgment.test.mjs)
// ---------------------------------------------------------------------

#[test]
fn advisory_judgment_rows_remain_pending_without_external_sage_oracle_records() {
    let ids = advisory_judgment_runtime_ids();
    assert_eq!(ids.len(), 35);
    assert!(!ids.contains(&"AD-1"));
    assert!(!ids.contains(&"AD-2"));
    assert!(ids.contains(&"AE-ADVERSARIAL-010"));
    assert!(ids.contains(&"AE-REVIEW-VERDICT-SECURITY-002"));
    for id in ids.iter().copied() {
        let result = advisory_judgment_bindings(id, Some(id)).unwrap();
        assert!(!result.allowed, "{id}");
        assert_eq!(result.disposition, "PENDING", "{id}");
    }
}

#[test]
fn advisory_observation_validator_rejects_pending_output() {
    assert!(!validate_advisory_judgment_observation());
}
