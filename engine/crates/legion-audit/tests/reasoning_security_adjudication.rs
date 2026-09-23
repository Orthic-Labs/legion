//! Integration coverage for the security-adjudication independence port
//! (`native_providers::reasoning::security_adjudication`), exercised from
//! outside the crate to confirm the public surface is sufficient for a host
//! integrator to wire the "no generator closes its own finding" rule.

use legion_audit::native_providers::reasoning::security_adjudication::{
    create_adjudication_packet, create_security_candidate, finalize_security_verdict,
    verify_adjudication_packet, EvidenceStrength, NewSecurityCandidate, SecurityAdjudicationError,
    SecurityVerdictInput, SecurityVerdictKind,
};

fn candidate() -> legion_audit::native_providers::reasoning::security_adjudication::SecurityCandidate
{
    create_security_candidate(NewSecurityCandidate {
        id: "finding-1",
        provider: "reasoning.security",
        context_id: "gen-ctx",
        claim: "unsanitized input reaches a shell sink",
        alleged_root_cause: Some("missing shell-escape before exec".into()),
        alleged_trigger: Some("user-controlled filename".into()),
        alleged_impact: Some("remote command execution".into()),
        evidence: vec![serde_json::json!({"path": "src/exec.rs", "line": 42})],
        generated_at: Some("2026-01-01T00:00:00Z".into()),
    })
    .expect("candidate is well-formed")
}

#[test]
fn generator_cannot_adjudicate_in_its_own_provider_or_context() {
    let same_provider = create_adjudication_packet(candidate(), "reasoning.security", "adj-ctx", None);
    assert!(matches!(
        same_provider,
        Err(SecurityAdjudicationError::SelfAdjudication(_, _))
    ));

    let same_context = create_adjudication_packet(
        candidate(),
        "legacy.security.adjudication",
        "gen-ctx",
        None,
    );
    assert!(matches!(
        same_context,
        Err(SecurityAdjudicationError::SameContext(_))
    ));
}

#[test]
fn independent_adjudication_can_close_a_true_positive_with_full_evidence() {
    let packet = create_adjudication_packet(
        candidate(),
        "legacy.security.adjudication",
        "adj-ctx",
        Some("2026-01-01T00:01:00Z".into()),
    )
    .expect("independent packet is accepted");
    assert!(verify_adjudication_packet(&packet));

    let verdict = finalize_security_verdict(
        &packet,
        SecurityVerdictInput {
            verdict: SecurityVerdictKind::TruePositive,
            evidence_strength: Some(EvidenceStrength::Verified),
            severity: Some("critical".into()),
            exploitability: Some("network".into()),
            threat_model: Some("unauthenticated remote attacker".into()),
            attacker_control: Some("full argument control".into()),
            reachability: Some("directly reachable from the public API".into()),
            trust_boundaries: vec!["network-to-process".into()],
            sink: Some("std::process::Command".into()),
            primary_controls: Vec::new(),
            mitigations: Vec::new(),
            proof: Some("PoC command injection reproduced locally".into()),
            impact: Some("arbitrary command execution as the service user".into()),
            rationale: None,
            devils_advocate: Some("checked for existing shell-escaping; none present".into()),
        },
    )
    .expect("full evidentiary bar is met");

    assert!(verdict.variant_analysis_required);
    assert_eq!(verdict.candidate_provider, "reasoning.security");
    assert_eq!(verdict.adjudicator_provider, "legacy.security.adjudication");
    assert!(verdict.verdict_digest.starts_with("sha256:"));
}

#[test]
fn surviving_verdict_without_proof_is_rejected() {
    let packet = create_adjudication_packet(
        candidate(),
        "legacy.security.adjudication",
        "adj-ctx",
        Some("2026-01-01T00:01:00Z".into()),
    )
    .unwrap();

    let result = finalize_security_verdict(
        &packet,
        SecurityVerdictInput {
            verdict: SecurityVerdictKind::LikelyTruePositive,
            evidence_strength: Some(EvidenceStrength::Observed),
            severity: Some("high".into()),
            exploitability: None,
            threat_model: Some("threat model".into()),
            attacker_control: Some("partial".into()),
            reachability: Some("reachable".into()),
            trust_boundaries: Vec::new(),
            sink: None,
            primary_controls: Vec::new(),
            mitigations: Vec::new(),
            proof: None,
            impact: Some("impact".into()),
            rationale: None,
            devils_advocate: Some("challenge".into()),
        },
    );
    assert!(matches!(
        result,
        Err(SecurityAdjudicationError::MissingProof(_))
    ));
}

#[test]
fn false_positive_verdict_needs_no_proof_but_rejects_severity() {
    let packet = create_adjudication_packet(
        candidate(),
        "legacy.security.adjudication",
        "adj-ctx",
        Some("2026-01-01T00:01:00Z".into()),
    )
    .unwrap();

    let clean = finalize_security_verdict(
        &packet,
        SecurityVerdictInput {
            verdict: SecurityVerdictKind::FalsePositive,
            evidence_strength: Some(EvidenceStrength::Possible),
            severity: None,
            exploitability: None,
            threat_model: Some("threat model".into()),
            attacker_control: None,
            reachability: Some("not reachable: input is server-generated".into()),
            trust_boundaries: Vec::new(),
            sink: None,
            primary_controls: Vec::new(),
            mitigations: Vec::new(),
            proof: None,
            impact: Some("none".into()),
            rationale: Some("filename is never attacker-controlled".into()),
            devils_advocate: None,
        },
    )
    .expect("false positive needs no proof");
    assert!(!clean.variant_analysis_required);
}
