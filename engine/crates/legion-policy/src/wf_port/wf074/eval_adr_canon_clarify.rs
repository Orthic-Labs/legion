//! Rust port of
//! `src/lib/verification/arcane/s11-bindings/eval-adr-canon-clarify.mjs`.
//!
//! Deterministic evaluators for architecture corpus families. Inputs are
//! structured policy facts; row prose/expectations are never consulted.
//! Fully self-contained (no unported production dependency): ported as
//! ALREADY... no, NOT-STARTED-in-Rust-until-now, now PORTED in full,
//! including its fixed `CASES` table and observation validators.

use super::canonical::{digest_value, Json};

pub const IDS: &[&str] = &[
    "AE-ADR-ADMISSION-001",
    "AE-ADR-ADMISSION-002",
    "AE-CANON-DRIFT-001",
    "AE-CANON-DRIFT-002",
    "AE-CLARIFICATION-CONVERGENCE-001",
    "AE-CLARIFICATION-CONVERGENCE-002",
];

pub fn adr_canon_clarify_runtime_ids() -> &'static [&'static str] {
    IDS
}

/// Mirrors the JS object literals returned by each evaluator: a small,
/// fixed set of shapes, modeled directly rather than through a generic
/// `Json` value so field access stays typed.
#[derive(Debug, Clone, PartialEq)]
pub enum EvalOutcome {
    AdrAdmission {
        status: &'static str, // "ADMIT" | "REJECT" | "PENDING"
        artifact: Option<&'static str>,
        architecture_route: Option<bool>,
        alternatives: Option<i64>,
        missing_producer: Option<&'static str>,
    },
    CanonOwnerDrift {
        status: &'static str, // "PASS" | "FAIL" | "PENDING"
        source_owner: Option<String>,
        owner_count: Option<usize>,
        drift: Option<bool>,
        missing_producer: Option<&'static str>,
    },
    GeneratedSourceDrift {
        status: &'static str, // "PASS" | "FAIL" | "PENDING"
        source_digest: Option<String>,
        generated_digest: Option<String>,
        drift: Option<bool>,
        remediation: Option<&'static str>,
        missing_producer: Option<&'static str>,
    },
    ClarificationConvergence {
        status: &'static str, // "STOP" | "CONTINUE" | "PENDING"
        stop_questioning: Option<bool>,
        dispositions_recorded: Option<bool>,
        missing_producer: Option<&'static str>,
    },
    FogMetadata {
        status: &'static str, // "READY" | "FOG" | "PENDING"
        fog_metadata_only: Option<bool>,
        scheduled_work: Option<bool>,
        blocker: Option<bool>,
        missing_producer: Option<&'static str>,
    },
}

/// Inputs for `evaluate_adr_admission`. JS defaults every field to a typed
/// falsy value and validates the caller actually passed typed values before
/// treating the defaults as real input — a caller supplying no facts at all
/// gets PENDING, not a false ADMIT/REJECT decided on defaults. `Option`
/// fields here model "field present, is it the right type" the way the JS
/// does with a `typeof` check on values that arrive already coerced by
/// destructuring defaults; a `None` behaves like the JS default did.
#[derive(Debug, Clone, Default)]
pub struct AdrAdmissionInput {
    pub reversible: Option<bool>,
    pub boundary_accepted: Option<bool>,
    pub architecture_worth: Option<bool>,
    pub local_alternatives: Option<i64>,
}

/// Decide ADR admission from explicit, typed architecture policy facts.
pub fn evaluate_adr_admission(input: &AdrAdmissionInput) -> EvalOutcome {
    let reversible = input.reversible.unwrap_or(false);
    let boundary_accepted = input.boundary_accepted.unwrap_or(false);
    let architecture_worth = input.architecture_worth.unwrap_or(false);
    let local_alternatives = input.local_alternatives.unwrap_or(0);
    // JS: `typeof v === 'boolean'` always holds once destructuring applies
    // its default, EXCEPT when the caller explicitly passed a non-boolean
    // value; this Rust signature can't carry that ill-typed case, so the
    // only PENDING trigger left is a negative alternatives count.
    if local_alternatives < 0 {
        return EvalOutcome::AdrAdmission {
            status: "PENDING",
            artifact: None,
            architecture_route: None,
            alternatives: None,
            missing_producer: Some("typed architecture admission facts"),
        };
    }
    let admit = architecture_worth && (!reversible || !boundary_accepted);
    EvalOutcome::AdrAdmission {
        status: if admit { "ADMIT" } else { "REJECT" },
        artifact: Some(if admit { "ADR" } else { "LOCAL_DECISION_LOG" }),
        architecture_route: Some(admit),
        alternatives: Some(local_alternatives),
        missing_producer: None,
    }
}

/// Compare canonical owners without treating duplicate declarations as
/// valid.
pub fn evaluate_canon_owner_drift(owners: &[&str]) -> EvalOutcome {
    if owners.iter().any(|o| o.is_empty()) {
        return EvalOutcome::CanonOwnerDrift {
            status: "PENDING",
            source_owner: None,
            owner_count: None,
            drift: None,
            missing_producer: Some("canonical owner registry"),
        };
    }
    let mut unique: Vec<&str> = Vec::new();
    for o in owners {
        if !unique.contains(o) {
            unique.push(o);
        }
    }
    let pass = unique.len() == 1;
    EvalOutcome::CanonOwnerDrift {
        status: if pass { "PASS" } else { "FAIL" },
        source_owner: if pass {
            Some(unique[0].to_string())
        } else {
            None
        },
        owner_count: Some(unique.len()),
        drift: Some(unique.len() > 1),
        missing_producer: None,
    }
}

/// Detect generated/source drift using canonical serialization digests.
pub fn evaluate_generated_source_drift(source: &Json, generated: &Json) -> EvalOutcome {
    let source_digest = digest_value(source);
    let generated_digest = digest_value(generated);
    match (source_digest, generated_digest) {
        (Some(sd), Some(gd)) => {
            let drift = sd != gd;
            EvalOutcome::GeneratedSourceDrift {
                status: if drift { "FAIL" } else { "PASS" },
                source_digest: Some(sd),
                generated_digest: Some(gd),
                drift: Some(drift),
                remediation: if drift {
                    Some("REGENERATE_FROM_SOURCE")
                } else {
                    None
                },
                missing_producer: None,
            }
        }
        _ => EvalOutcome::GeneratedSourceDrift {
            status: "PENDING",
            source_digest: None,
            generated_digest: None,
            drift: None,
            remediation: None,
            missing_producer: Some("canonical source and generated artifacts"),
        },
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClarificationImpact {
    pub acceptance: bool,
    pub ranking: bool,
    pub authority: bool,
    pub safety: bool,
    pub increment: bool,
}

/// Stop clarification when next question cannot alter any recorded
/// disposition.
pub fn evaluate_clarification_convergence(
    impact: &ClarificationImpact,
    dispositions_recorded: bool,
) -> EvalOutcome {
    let affects = impact.acceptance
        || impact.ranking
        || impact.authority
        || impact.safety
        || impact.increment;
    let stop = !affects && dispositions_recorded;
    EvalOutcome::ClarificationConvergence {
        status: if stop { "STOP" } else { "CONTINUE" },
        stop_questioning: Some(stop),
        dispositions_recorded: Some(dispositions_recorded),
        missing_producer: None,
    }
}

/// Keep imprecise concern as FOG metadata; no work item is created.
pub fn evaluate_fog_metadata(question: &str, sharpening_observation: &str) -> EvalOutcome {
    let precise = !question.trim().is_empty() && !sharpening_observation.trim().is_empty();
    EvalOutcome::FogMetadata {
        status: if precise { "READY" } else { "FOG" },
        fog_metadata_only: Some(!precise),
        scheduled_work: Some(false),
        blocker: Some(false),
        missing_producer: None,
    }
}

/// The fixed `CASES` table from the JS module: one hard-coded input per
/// runtime id.
pub fn execute_adr_canon_clarify_case(id: &str) -> Option<EvalOutcome> {
    match id {
        "AE-ADR-ADMISSION-001" => Some(evaluate_adr_admission(&AdrAdmissionInput {
            reversible: Some(true),
            boundary_accepted: Some(true),
            architecture_worth: Some(false),
            local_alternatives: Some(1),
        })),
        "AE-ADR-ADMISSION-002" => Some(evaluate_adr_admission(&AdrAdmissionInput {
            reversible: Some(true),
            boundary_accepted: Some(true),
            architecture_worth: Some(false),
            local_alternatives: Some(2),
        })),
        "AE-CANON-DRIFT-001" => Some(evaluate_canon_owner_drift(&[
            "architecture-source",
            "overlay-generated",
        ])),
        "AE-CANON-DRIFT-002" => Some(evaluate_generated_source_drift(
            &Json::obj([("rule", Json::str("source"))]),
            &Json::obj([("rule", Json::str("drift"))]),
        )),
        "AE-CLARIFICATION-CONVERGENCE-001" => Some(evaluate_clarification_convergence(
            &ClarificationImpact::default(),
            true,
        )),
        "AE-CLARIFICATION-CONVERGENCE-002" => Some(evaluate_fog_metadata("", "")),
        _ => None,
    }
}

/// Mirrors `adrCanonClarifyBindingIds` / `executeAdrCanonClarifyBinding`
/// naming aliases in the JS module.
pub fn adr_canon_clarify_binding_ids() -> &'static [&'static str] {
    adr_canon_clarify_runtime_ids()
}
pub fn execute_adr_canon_clarify_binding(id: &str) -> Option<EvalOutcome> {
    execute_adr_canon_clarify_case(id)
}

/// Independent observation validator, ported field-for-field from
/// `validateAdrCanonClarifyObservation`.
pub fn validate_adr_canon_clarify_observation(id: &str, value: &EvalOutcome) -> bool {
    if !IDS.contains(&id) {
        return false;
    }
    match (id, value) {
        (id, EvalOutcome::AdrAdmission { status, architecture_route, .. })
            if id.starts_with("AE-ADR-") =>
        {
            matches!(*status, "ADMIT" | "REJECT" | "PENDING")
                && (*status == "PENDING" || architecture_route.is_some())
        }
        ("AE-CANON-DRIFT-001", EvalOutcome::CanonOwnerDrift { status, drift, .. }) => {
            matches!(*status, "PASS" | "FAIL" | "PENDING") && (*status == "PENDING" || drift.is_some())
        }
        ("AE-CANON-DRIFT-002", EvalOutcome::GeneratedSourceDrift { status, drift, .. }) => {
            matches!(*status, "PASS" | "FAIL" | "PENDING") && (*status == "PENDING" || drift.is_some())
        }
        (
            "AE-CLARIFICATION-CONVERGENCE-001",
            EvalOutcome::ClarificationConvergence {
                status,
                stop_questioning,
                ..
            },
        ) => {
            matches!(*status, "STOP" | "CONTINUE" | "PENDING")
                && (*status == "PENDING" || stop_questioning.is_some())
        }
        ("AE-CLARIFICATION-CONVERGENCE-002", EvalOutcome::FogMetadata { status, scheduled_work, .. }) => {
            matches!(*status, "FOG" | "READY" | "PENDING")
                && (*status == "PENDING" || *scheduled_work == Some(false))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adr_admission_001_rejects_with_reversible_and_boundary_accepted() {
        let out = execute_adr_canon_clarify_case("AE-ADR-ADMISSION-001").unwrap();
        match out {
            EvalOutcome::AdrAdmission {
                status,
                artifact,
                architecture_route,
                alternatives,
                ..
            } => {
                assert_eq!(status, "REJECT");
                assert_eq!(artifact, Some("LOCAL_DECISION_LOG"));
                assert_eq!(architecture_route, Some(false));
                assert_eq!(alternatives, Some(1));
            }
            _ => panic!("wrong outcome variant"),
        }
    }

    #[test]
    fn admit_when_architecture_worth_and_boundary_not_accepted() {
        let out = evaluate_adr_admission(&AdrAdmissionInput {
            reversible: Some(true),
            boundary_accepted: Some(false),
            architecture_worth: Some(true),
            local_alternatives: Some(0),
        });
        match out {
            EvalOutcome::AdrAdmission { status, artifact, .. } => {
                assert_eq!(status, "ADMIT");
                assert_eq!(artifact, Some("ADR"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn negative_alternatives_is_pending() {
        let out = evaluate_adr_admission(&AdrAdmissionInput {
            local_alternatives: Some(-1),
            ..Default::default()
        });
        assert!(matches!(out, EvalOutcome::AdrAdmission { status: "PENDING", .. }));
    }

    #[test]
    fn canon_drift_001_detects_two_owners() {
        let out = execute_adr_canon_clarify_case("AE-CANON-DRIFT-001").unwrap();
        match out {
            EvalOutcome::CanonOwnerDrift { status, owner_count, drift, .. } => {
                assert_eq!(status, "FAIL");
                assert_eq!(owner_count, Some(2));
                assert_eq!(drift, Some(true));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn canon_drift_single_owner_passes() {
        let out = evaluate_canon_owner_drift(&["a", "a", "a"]);
        match out {
            EvalOutcome::CanonOwnerDrift { status, source_owner, drift, .. } => {
                assert_eq!(status, "PASS");
                assert_eq!(source_owner.as_deref(), Some("a"));
                assert_eq!(drift, Some(false));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn canon_drift_002_source_and_generated_differ() {
        let out = execute_adr_canon_clarify_case("AE-CANON-DRIFT-002").unwrap();
        match out {
            EvalOutcome::GeneratedSourceDrift {
                status,
                drift,
                remediation,
                source_digest,
                generated_digest,
                ..
            } => {
                assert_eq!(status, "FAIL");
                assert_eq!(drift, Some(true));
                assert_eq!(remediation, Some("REGENERATE_FROM_SOURCE"));
                assert_ne!(source_digest, generated_digest);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn generated_source_drift_pass_when_equal() {
        let v = Json::obj([("a", Json::Num(1.0))]);
        let out = evaluate_generated_source_drift(&v.clone(), &v);
        match out {
            EvalOutcome::GeneratedSourceDrift { status, drift, remediation, .. } => {
                assert_eq!(status, "PASS");
                assert_eq!(drift, Some(false));
                assert_eq!(remediation, None);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn clarification_convergence_001_stops() {
        let out = execute_adr_canon_clarify_case("AE-CLARIFICATION-CONVERGENCE-001").unwrap();
        match out {
            EvalOutcome::ClarificationConvergence { status, stop_questioning, .. } => {
                assert_eq!(status, "STOP");
                assert_eq!(stop_questioning, Some(true));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn clarification_continues_when_any_field_affected() {
        let out = evaluate_clarification_convergence(
            &ClarificationImpact {
                safety: true,
                ..Default::default()
            },
            true,
        );
        assert!(matches!(out, EvalOutcome::ClarificationConvergence { status: "CONTINUE", .. }));
    }

    #[test]
    fn clarification_continues_when_dispositions_not_recorded() {
        let out = evaluate_clarification_convergence(&ClarificationImpact::default(), false);
        assert!(matches!(out, EvalOutcome::ClarificationConvergence { status: "CONTINUE", .. }));
    }

    #[test]
    fn fog_metadata_002_is_fog_on_blank_inputs() {
        let out = execute_adr_canon_clarify_case("AE-CLARIFICATION-CONVERGENCE-002").unwrap();
        match out {
            EvalOutcome::FogMetadata { status, fog_metadata_only, scheduled_work, blocker, .. } => {
                assert_eq!(status, "FOG");
                assert_eq!(fog_metadata_only, Some(true));
                assert_eq!(scheduled_work, Some(false));
                assert_eq!(blocker, Some(false));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn fog_metadata_ready_on_precise_inputs() {
        let out = evaluate_fog_metadata("why does X drift", "observed at commit abc");
        match out {
            EvalOutcome::FogMetadata { status, fog_metadata_only, .. } => {
                assert_eq!(status, "READY");
                assert_eq!(fog_metadata_only, Some(false));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_case_id_returns_none() {
        assert!(execute_adr_canon_clarify_case("AE-DOES-NOT-EXIST").is_none());
    }

    #[test]
    fn all_runtime_ids_execute_to_some_outcome() {
        for id in adr_canon_clarify_runtime_ids() {
            assert!(execute_adr_canon_clarify_case(id).is_some(), "{id} did not execute");
        }
    }

    #[test]
    fn validator_accepts_every_case_table_outcome() {
        for id in adr_canon_clarify_runtime_ids() {
            let out = execute_adr_canon_clarify_case(id).unwrap();
            assert!(
                validate_adr_canon_clarify_observation(id, &out),
                "{id} failed its own observation validator"
            );
        }
    }

    #[test]
    fn validator_rejects_unknown_id() {
        let out = execute_adr_canon_clarify_case("AE-CANON-DRIFT-001").unwrap();
        assert!(!validate_adr_canon_clarify_observation("AE-NOT-A-CASE", &out));
    }

    #[test]
    fn binding_alias_names_match_case_functions() {
        assert_eq!(adr_canon_clarify_binding_ids(), adr_canon_clarify_runtime_ids());
        assert_eq!(
            execute_adr_canon_clarify_binding("AE-CANON-DRIFT-001"),
            execute_adr_canon_clarify_case("AE-CANON-DRIFT-001")
        );
    }
}
