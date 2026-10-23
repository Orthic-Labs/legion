//! Security contracts v2: one evidence-strength vocabulary, candidates from the
//! declared channel only, typed candidate fields, required negative control,
//! and the denominator-bound variant ledger.

use std::collections::BTreeMap;

use legion_audit::native_providers::reasoning::{
    followup::{root_cause_signature, LedgerAssessment, VariantLedger},
    security_adjudication::{
        candidate_generator_contract_gap, create_adjudication_packet, create_security_candidate,
        finalize_security_verdict, scanner_candidates, NegativeControl, NewSecurityCandidate,
        SecurityAdjudicationError, SecurityCandidateV2, SecurityVerdictInput, SecurityVerdictKind,
    },
};
use legion_contracts::{
    enums::{EvidenceStrength, EVIDENCE_STRENGTH},
    FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use serde_json::json;

// ---- evidence-strength vocabulary -------------------------------------------------

#[test]
fn canonical_vocabulary_matches_schema_enum() {
    for text in EVIDENCE_STRENGTH {
        let strength = EvidenceStrength::from_wire(text).expect("canonical spelling parses");
        assert_eq!(strength.as_str(), *text);
        assert!(!EvidenceStrength::is_legacy_spelling(text));
    }
}

#[test]
fn legacy_spellings_are_read_and_emitted_canonically() {
    let observed: EvidenceStrength = serde_json::from_value(json!("observed")).unwrap();
    assert_eq!(observed, EvidenceStrength::StrongInference);
    assert_eq!(
        serde_json::to_value(observed).unwrap(),
        json!("strong-inference")
    );
    let candidate: EvidenceStrength = serde_json::from_value(json!("candidate")).unwrap();
    assert_eq!(candidate, EvidenceStrength::Possible);
    assert!(serde_json::from_value::<EvidenceStrength>(json!("certain")).is_err());
    assert!(serde_json::from_value::<EvidenceStrength>(json!("VERIFIED")).is_err());
    assert!(EvidenceStrength::Possible.rank() < EvidenceStrength::StrongInference.rank());
    assert!(EvidenceStrength::StrongInference.rank() < EvidenceStrength::Verified.rank());
}

// ---- candidates only from the declared channel -------------------------------------

fn result_with(findings: &[&str], candidates: serde_json::Value) -> ProviderResult {
    ProviderResult {
        schema_version: 1,
        provider: ProviderId::new("security.misuse-resistance").unwrap(),
        applicable: true,
        required: false,
        status: ProviderStatus::Ok,
        complete: false,
        coverage: None,
        findings: findings
            .iter()
            .map(|id| FindingRef {
                id: FindingId::new(*id).unwrap(),
                severity: "high".into(),
            })
            .collect(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: BTreeMap::from([("candidates".to_owned(), candidates)]),
    }
}

#[test]
fn stray_findings_are_never_promoted_to_candidates_and_are_a_gap() {
    let root = std::env::temp_dir();
    let result = result_with(
        &["stray-1"],
        json!([{"id": "real-1", "ruleId": "r", "claim": "declared candidate", "file": "a.rs", "line": 1}]),
    );
    let candidates = scanner_candidates(&root, "security.misuse-resistance", &result);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].finding_id, "real-1");
    let gap = candidate_generator_contract_gap("security.misuse-resistance", &result)
        .expect("stray finding is a contract gap");
    assert!(gap.contains("stray-1"));
    let clean = result_with(&[], json!([]));
    assert!(candidate_generator_contract_gap("security.misuse-resistance", &clean).is_none());
    assert!(scanner_candidates(&root, "p", &result_with(&["only-finding"], json!([]))).is_empty());
}

// ---- candidate v2 -----------------------------------------------------------------

#[test]
fn v1_candidate_upgrades_with_empty_typed_fields_and_canonical_strength() {
    let v1 = json!({
        "id": "sha256:abc", "ruleId": "security.command-injection",
        "provider": "security.misuse-resistance", "claim": "input reaches exec",
        "evidenceStrength": "candidate", "verdict": "UNADJUDICATED",
        "evidence": [{"file": "src/run.ts", "line": 4}]
    });
    let candidate = SecurityCandidateV2::from_value(&v1).unwrap();
    assert_eq!(candidate.schema_version, 2);
    assert_eq!(candidate.evidence_strength, EvidenceStrength::Possible);
    assert!(candidate.sources.is_empty() && candidate.chain_roles.is_empty());
    let emitted = serde_json::to_value(&candidate).unwrap();
    assert_eq!(emitted["evidenceStrength"], "possible");
    assert!(emitted.get("sources").is_none());
}

#[test]
fn v2_candidate_carries_typed_fields_and_reports_unobserved_controls() {
    let candidate = SecurityCandidateV2::from_value(&json!({
        "id": "sha256:1", "provider": "security.authorization", "claim": "missing owner check",
        "ruleId": "authorization.object-write.missing-owner-check",
        "sources": ["source:http.route.patch-project"], "sinks": ["sink:db.update-project"],
        "effects": ["write-object:project:any-tenant"], "preconditions": ["principal supplies projectId"],
        "chainRoles": ["starter", "privilege-escalation"],
        "requiredControls": ["control:ownership", "control:csrf"],
        "observedControls": ["control:csrf"],
        "entrypointRefs": ["entry:1"], "assetRefs": ["asset:tenant-project"]
    }))
    .unwrap();
    assert_eq!(candidate.unobserved_controls(), vec!["control:ownership"]);
    assert_eq!(candidate.sinks, vec!["sink:db.update-project"]);
}

#[test]
fn candidate_cannot_self_verify_or_use_unknown_roles() {
    let base = json!({"id": "x", "provider": "p", "claim": "c"});
    let mut verified = base.clone();
    verified["evidenceStrength"] = json!("verified");
    assert!(SecurityCandidateV2::from_value(&verified).is_err());
    let mut adjudicated = base.clone();
    adjudicated["verdict"] = json!("TRUE_POSITIVE");
    assert!(SecurityCandidateV2::from_value(&adjudicated).is_err());
    let mut role = base.clone();
    role["chainRoles"] = json!(["wizard"]);
    assert!(SecurityCandidateV2::from_value(&role).is_err());
    let mut blank = base;
    blank["sinks"] = json!(["  "]);
    assert!(SecurityCandidateV2::from_value(&blank).is_err());
}

// ---- negative control -------------------------------------------------------------

fn packet(
) -> legion_audit::native_providers::reasoning::security_adjudication::SecurityAdjudicationPacket {
    let candidate = create_security_candidate(NewSecurityCandidate {
        id: "finding-1",
        provider: "reasoning.security",
        context_id: "gen-ctx",
        claim: "unsanitized input reaches a shell sink",
        alleged_root_cause: None,
        alleged_trigger: None,
        alleged_impact: None,
        evidence: vec![json!({"path": "src/exec.rs", "line": 42})],
        generated_at: Some("2026-01-01T00:00:00Z".into()),
    })
    .unwrap();
    create_adjudication_packet(candidate, "legacy.security.adjudication", "adj-ctx", None).unwrap()
}

fn input(strength: EvidenceStrength, control: Option<NegativeControl>) -> SecurityVerdictInput {
    SecurityVerdictInput {
        verdict: SecurityVerdictKind::TruePositive,
        evidence_strength: Some(strength),
        severity: Some("high".into()),
        exploitability: None,
        threat_model: Some("unauthenticated remote attacker".into()),
        attacker_control: Some("full argument control".into()),
        reachability: Some("directly reachable from the public API".into()),
        trust_boundaries: vec!["network".into()],
        sink: None,
        primary_controls: Vec::new(),
        mitigations: Vec::new(),
        proof: Some("PoC command injection reproduced locally".into()),
        impact: Some("arbitrary command execution".into()),
        rationale: None,
        devils_advocate: Some("checked for shell escaping; none present".into()),
        negative_control: control,
    }
}

fn control() -> NegativeControl {
    NegativeControl {
        hypothesis: "escaping the argument removes the injection".into(),
        method: "same call with the argument shell-escaped".into(),
        outcome: "no command separator reaches the shell".into(),
    }
}

#[test]
fn verdict_above_possible_requires_a_complete_negative_control() {
    for strength in [
        EvidenceStrength::Verified,
        EvidenceStrength::StrongInference,
    ] {
        let missing = finalize_security_verdict(&packet(), input(strength, None)).unwrap_err();
        assert!(matches!(
            missing,
            SecurityAdjudicationError::MissingNegativeControl(_)
        ));
        let mut blank = control();
        blank.outcome = "   ".into();
        let incomplete =
            finalize_security_verdict(&packet(), input(strength, Some(blank))).unwrap_err();
        assert!(matches!(
            incomplete,
            SecurityAdjudicationError::MissingNegativeControl(_)
        ));
        let verdict =
            finalize_security_verdict(&packet(), input(strength, Some(control()))).unwrap();
        assert_eq!(verdict.negative_control, Some(control()));
        assert_eq!(
            serde_json::to_value(&verdict).unwrap()["negativeControl"]["method"],
            control().method
        );
    }
}

#[test]
fn possible_strength_still_cannot_survive() {
    let error = finalize_security_verdict(
        &packet(),
        input(EvidenceStrength::Possible, Some(control())),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SecurityAdjudicationError::WeakEvidenceStrength(_)
    ));
}

// ---- variant ledger ---------------------------------------------------------------

fn ledger_entries(
    confirmed: u64,
    rejected: u64,
    unresolved: u64,
) -> Vec<legion_audit::native_providers::reasoning::followup::VariantEntry> {
    use legion_audit::native_providers::reasoning::followup::{VariantDisposition, VariantEntry};
    let mut entries = Vec::new();
    for (count, disposition) in [
        (confirmed, VariantDisposition::Confirmed),
        (rejected, VariantDisposition::Rejected),
        (unresolved, VariantDisposition::Unresolved),
    ] {
        for _ in 0..count {
            let index = entries.len();
            entries.push(VariantEntry {
                id: format!("v{index}"),
                path: format!("p{index}"),
                anchor: format!("sink.call({index})"),
                disposition,
                reason: "guarded".into(),
            });
        }
    }
    entries
}

fn ledger(matched: u64, confirmed: u64, rejected: u64, unresolved: u64) -> VariantLedger {
    VariantLedger {
        root_cause_signature: root_cause_signature("cmd-injection", "process.exec", "shell-escape")
            .unwrap(),
        denominator_count: (confirmed + rejected + unresolved).max(1),
        matched,
        examined: confirmed + rejected + unresolved,
        confirmed,
        rejected,
        unresolved,
        rejection_reasons: (0..rejected)
            .map(|i| format!("escaped at wrapper {i}"))
            .collect(),
        parent_plan_digest: "sha256:parent".into(),
        followup_plan_digest: "sha256:followup".into(),
        confirmed_digest: "sha256:confirmed".into(),
        entries: ledger_entries(confirmed, rejected, unresolved),
        analysis_paths: (0..(confirmed + rejected + unresolved).max(1))
            .map(|index| format!("p{index}"))
            .collect(),
        ledger_digest: String::new(),
    }
    .seal()
    .unwrap()
}

#[test]
fn unresolved_variants_keep_the_pass_incomplete() {
    assert_eq!(ledger(5, 2, 3, 0).assess(), LedgerAssessment::Complete);
    assert!(ledger(5, 2, 2, 1).assess() != LedgerAssessment::Complete);
    assert!(matches!(
        ledger(5, 2, 2, 1).assess(),
        LedgerAssessment::Incomplete(_)
    ));
    // Matched but never examined is also incomplete.
    assert!(matches!(
        ledger(6, 2, 3, 0).assess(),
        LedgerAssessment::Incomplete(_)
    ));
    assert!(!ledger(5, 2, 2, 1).is_complete());
}

#[test]
fn inconsistent_or_unreasoned_ledgers_are_never_complete() {
    let mut over = ledger(5, 2, 3, 0);
    over.matched = 4;
    assert!(matches!(over.assess(), LedgerAssessment::Inconsistent(_)));
    let mut unreasoned = ledger(5, 2, 3, 0);
    unreasoned.rejection_reasons.clear();
    assert!(matches!(
        unreasoned.assess(),
        LedgerAssessment::Inconsistent(_)
    ));
    let mut unsigned = ledger(5, 5, 0, 0);
    unsigned.root_cause_signature.clear();
    assert!(matches!(
        unsigned.assess(),
        LedgerAssessment::Inconsistent(_)
    ));
}

#[test]
fn ledger_binding_rejects_tampering_and_foreign_plans() {
    let sealed = ledger(5, 5, 0, 0);
    sealed
        .verify_binding("sha256:parent", "sha256:followup", "sha256:confirmed", 5)
        .unwrap();
    assert!(sealed
        .verify_binding("sha256:other", "sha256:followup", "sha256:confirmed", 5)
        .is_err());
    assert!(sealed
        .verify_binding("sha256:parent", "sha256:followup", "sha256:confirmed", 4)
        .is_err());
    let mut tampered = sealed.clone();
    tampered.unresolved = 0;
    tampered.matched = 1;
    assert!(tampered
        .verify_binding("sha256:parent", "sha256:followup", "sha256:confirmed", 5)
        .is_err());
    assert!(root_cause_signature("", "sink", "control").is_err());
}
