//! Integration tests for wf069's ported modules
//! (`legion_policy::wf_port::wf069::*`).
//!
//! NOTE for the integration owner: this file will not compile until
//! `pub mod wf_port;` is added to `engine/crates/legion-policy/src/lib.rs`
//! (if not already present from another wf packet) and `pub mod wf069;` to
//! `engine/crates/legion-policy/src/wf_port/mod.rs` (see the wf069 report).
//! Until then, the equivalent coverage lives as `#[cfg(test)]` unit tests
//! inside each `wf_port::wf069::*` submodule.

use legion_policy::wf_port::wf069::errors::ArcCode;
use legion_policy::wf_port::wf069::ownership_economics::{
    admit_vendor_selection, adversarial_ownership_economics_binding_ids,
    assess_source_of_truth_ownership_detailed, AdverseCaseEconomics, OwnershipSource, VendorCandidate,
};
use legion_policy::wf_port::wf069::proportionality::{
    adversarial_proportionality_binding_ids, assess_architecture_proportionality,
    assess_mandatory_obligation_readiness, Drivers, Obligation, ObligationReadinessInput, ObligationStatus,
    ProportionalityInput,
};
use legion_policy::wf_port::wf069::reconstruction::{
    assess_ai_readiness, assess_architecture_reconstruction, execute_adversarial_ai_reconstruction_case,
    validate_ai_readiness_observation, validate_architecture_reconstruction_observation, AiReadinessInput,
    ArchitectureReconstructionInput, Evaluation, EvidenceEntry, Fallback, HumanAuthority, ProvenanceEntry,
    ReconstructionCase, AI_RECONSTRUCTION_BINDING_IDS,
};

// ---------------------------------------------------------------------
// AE-ADVERSARIAL-001 / 002 — proportionality (adversarial-proportionality.mjs)
// ---------------------------------------------------------------------

#[test]
fn ae_adversarial_001_rejects_the_default_over_engineered_fixture() {
    // Mirrors JS `DEFAULT_INPUTS['AE-ADVERSARIAL-001']`.
    let input = ProportionalityInput {
        deployment: "greenfield".into(),
        scale: "low".into(),
        proposed_complexity: "distributed".into(),
        drivers: Drivers::default(),
        obligations: vec![],
    };
    let result = assess_architecture_proportionality(&input).unwrap();
    assert_eq!(result.decision, "REJECT");
    assert_eq!(result.code, Some("ARC_PROPORTIONALITY_EXCESS"));
    assert_eq!(result.minimum_complexity, "minimal");
    assert_eq!(result.proposed_complexity, "distributed");
}

#[test]
fn ae_adversarial_002_blocks_the_default_missing_obligations_fixture() {
    // Mirrors JS `DEFAULT_INPUTS['AE-ADVERSARIAL-002']`.
    let input = ObligationReadinessInput {
        objective: "minimize".into(),
        proposed_complexity: "minimal".into(),
        obligations: vec![
            Obligation {
                id: "privacy-retention".into(),
                domain: "privacy".into(),
                mandatory: true,
                status: ObligationStatus::Missing,
            },
            Obligation {
                id: "regulated-audit".into(),
                domain: "compliance".into(),
                mandatory: true,
                status: ObligationStatus::Missing,
            },
        ],
    };
    let result = assess_mandatory_obligation_readiness(&input).unwrap();
    assert_eq!(result.decision, "BLOCK");
    assert_eq!(result.code, Some("ARC_MANDATORY_OBLIGATION_MISSING"));
    assert!(result.missing_domains.contains(&"privacy".to_string()));
    assert!(result.missing_domains.contains(&"compliance".to_string()));
}

#[test]
fn proportionality_binding_ids_are_stable() {
    assert_eq!(adversarial_proportionality_binding_ids(), ["AE-ADVERSARIAL-001", "AE-ADVERSARIAL-002"]);
}

// ---------------------------------------------------------------------
// AE-ADVERSARIAL-006 / 007 — ownership & economics (adversarial-ownership-economics.mjs)
// ---------------------------------------------------------------------

#[test]
fn ae_adversarial_006_conflicting_authority_blocks_selection() {
    // Mirrors JS `ownershipFixture()`.
    let sources = vec![
        OwnershipSource {
            source_id: "billing-cache".into(),
            owner: "platform".into(),
            authorities: vec!["account-balance".into()],
        },
        OwnershipSource {
            source_id: "ledger-db".into(),
            owner: "finance".into(),
            authorities: vec!["account-balance".into()],
        },
    ];
    let (decision, conflicts) = assess_source_of_truth_ownership_detailed(&sources).unwrap();
    assert!(!decision.allowed);
    assert_eq!(decision.code, Some(ArcCode::ArcClaimPrerequisiteUnmet));
    assert!(conflicts.iter().any(|c| c.authority == "account-balance" && c.owners.len() == 2));
}

#[test]
fn ae_adversarial_007_incomplete_adverse_economics_blocks_selection() {
    // Mirrors JS `economicsFixture()`.
    let candidates = vec![VendorCandidate {
        candidate_id: "vendor-a".into(),
        score: 100.0,
        adverse_case_economics: Some(AdverseCaseEconomics {
            outage_cost: Some(1000.0),
            overage_cost: Some(25.0),
            egress_cost: None,
            exit_cost: None,
        }),
    }];
    let outcome = admit_vendor_selection(&candidates, "vendor-a").unwrap();
    assert!(!outcome.decision.allowed);
    assert_eq!(outcome.decision.code, Some(ArcCode::ArcEvidenceInsufficient));
    assert!(outcome.missing_economic_metrics.contains(&"egressCost"));
    assert!(outcome.missing_economic_metrics.contains(&"exitCost"));
}

#[test]
fn ownership_economics_binding_ids_are_stable() {
    assert_eq!(adversarial_ownership_economics_binding_ids(), ["AE-ADVERSARIAL-006", "AE-ADVERSARIAL-007"]);
}

// ---------------------------------------------------------------------
// AE-ADVERSARIAL-009 / 010 — AI readiness & architecture reconstruction
// (adversarial-ai-reconstruction.mjs)
// ---------------------------------------------------------------------

fn full_readiness_input() -> AiReadinessInput {
    AiReadinessInput {
        system_id: Some("sys-1".into()),
        provenance: vec![ProvenanceEntry { source_ref: Some("repo@sha".into()), digest: Some("sha256:aa".into()) }],
        evaluation: Some(Evaluation {
            status: Some("PASS".into()),
            report_ref: Some("report-1".into()),
            evaluated_at: Some("2026-01-01T00:00:00Z".into()),
            has_metrics: true,
        }),
        fallback: Some(Fallback {
            mode: Some("manual".into()),
            owner: Some("ops".into()),
            tested_at: Some("2026-01-01T00:00:00Z".into()),
        }),
        human_authority: Some(HumanAuthority {
            role: Some("lead".into()),
            authority_ref: Some("charter-1".into()),
            approved_at: Some("2026-01-01T00:00:00Z".into()),
        }),
    }
}

#[test]
fn ae_adversarial_009_ready_requires_all_four_evidence_kinds() {
    let ready = assess_ai_readiness(&full_readiness_input());
    assert!(ready.readiness);
    assert_eq!(ready.disposition, "READY");

    let not_ready = assess_ai_readiness(&AiReadinessInput::default());
    assert!(!not_ready.readiness);
    assert_eq!(not_ready.disposition, "NOT_READY");
    assert_eq!(not_ready.missing, vec!["provenance", "evaluation", "fallback", "humanAuthority"]);
}

#[test]
fn ae_adversarial_009_observation_validator_recomputes() {
    let input = full_readiness_input();
    let observed = assess_ai_readiness(&input);
    assert!(validate_ai_readiness_observation(&input, &observed));

    // A forged verdict that doesn't match a recomputation from input is rejected.
    let mut tampered_input = input.clone();
    tampered_input.provenance.clear();
    assert!(!validate_ai_readiness_observation(&tampered_input, &observed));
}

#[test]
fn ae_adversarial_010_uncertainty_reported_without_as_of() {
    let input = ArchitectureReconstructionInput { as_of: None, required_scopes: vec![], evidence: vec![] };
    let result = assess_architecture_reconstruction(&input);
    assert_eq!(result.disposition, "UNCERTAINTY_REPORTED");
    assert!(!result.conclusion_allowed);
    assert!(!result.clean_allowed);
    assert_eq!(result.uncertainty_reason, Some("INVALID_AS_OF"));
}

#[test]
fn ae_adversarial_010_ready_when_all_required_scopes_are_fresh() {
    let fresh = |scope: &str| EvidenceEntry {
        scope: Some(scope.into()),
        source_ref: Some("src".into()),
        observed_at: Some("2026-05-01T00:00:00Z".into()),
        expires_at: Some("2026-12-01T00:00:00Z".into()),
    };
    let input = ArchitectureReconstructionInput {
        as_of: Some("2026-06-01T00:00:00Z".into()),
        required_scopes: vec![],
        evidence: vec![fresh("topology"), fresh("runtime"), fresh("deployment"), fresh("ownership")],
    };
    let result = assess_architecture_reconstruction(&input);
    assert_eq!(result.disposition, "RECONSTRUCTION_READY");
    assert!(result.conclusion_allowed);
    assert!(result.clean_allowed);
    assert!(result.missing_scopes.is_empty());
}

#[test]
fn ae_adversarial_010_observation_validator_recomputes() {
    let input = ArchitectureReconstructionInput {
        as_of: Some("2026-06-01T00:00:00Z".into()),
        required_scopes: vec!["topology".into()],
        evidence: vec![],
    };
    let observed = assess_architecture_reconstruction(&input);
    assert!(validate_architecture_reconstruction_observation(&input, &observed));
}

#[test]
fn execute_case_dispatches_and_reports_unknown_ids() {
    match execute_adversarial_ai_reconstruction_case("AE-ADVERSARIAL-009", Some(&full_readiness_input()), None) {
        ReconstructionCase::AiReadiness(r) => assert!(r.readiness),
        _ => panic!("expected AiReadiness case"),
    }
    match execute_adversarial_ai_reconstruction_case("AE-ADVERSARIAL-999", None, None) {
        ReconstructionCase::UnknownCase => {}
        _ => panic!("expected unknown case"),
    }
}

#[test]
fn reconstruction_binding_ids_are_stable() {
    assert_eq!(AI_RECONSTRUCTION_BINDING_IDS, ["AE-ADVERSARIAL-009", "AE-ADVERSARIAL-010"]);
}
