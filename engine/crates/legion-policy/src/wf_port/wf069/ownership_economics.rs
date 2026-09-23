//! Faithful port of `src/lib/verification/arcane/adversarial-ownership-economics.mjs`.
//!
//! Production admissions for two architecture hazards. Both operate only on
//! structured facts: no selection can be inferred from prose or an eval row.
//! `compareEvidenceCandidates` (from `evidence-registry.mjs`) is inlined here
//! since wf069 owns no other file it could live in.

use std::collections::{BTreeSet, HashSet};

use super::errors::{ArcCode, ArcaneError, Decision};

pub const ADVERSARIAL_OWNERSHIP_ECONOMICS_IDS: [&str; 2] = ["AE-ADVERSARIAL-006", "AE-ADVERSARIAL-007"];

pub const REQUIRED_ADVERSE_ECONOMIC_METRICS: [&str; 4] =
    ["outageCost", "overageCost", "egressCost", "exitCost"];

// ---------------------------------------------------------------------
// compareEvidenceCandidates (ported from evidence-registry.mjs, the part
// ownership/economics depends on).
// ---------------------------------------------------------------------

/// A named boolean hard gate over a candidate. Mirrors the JS `hardGates[i].evaluate`
/// callback form (the alternate `field`/`equals`/`oneOf`/`includes` declarative
/// form is not exercised by this file's callers and is intentionally not ported).
pub struct HardGate<'a, C> {
    pub id: &'a str,
    pub evaluate: Box<dyn Fn(&C) -> bool + 'a>,
}

pub struct EliminatedCandidate<'a, C> {
    pub candidate: &'a C,
    pub failures: Vec<(&'a str, &'static str)>,
}

pub struct ComparisonResult<'a, C> {
    pub eligible: Vec<&'a C>,
    pub eliminated: Vec<EliminatedCandidate<'a, C>>,
    pub ranked: Vec<(&'a C, f64)>,
}

/// Eliminate mechanically-evaluable hard-gate failures before any scoring.
pub fn compare_evidence_candidates<'a, C>(
    candidates: &'a [C],
    hard_gates: &[HardGate<'a, C>],
    score: impl Fn(&C) -> f64,
) -> ComparisonResult<'a, C> {
    let mut eliminated = Vec::new();
    let mut eligible = Vec::new();
    for candidate in candidates {
        let mut failures = Vec::new();
        for gate in hard_gates {
            if !(gate.evaluate)(candidate) {
                failures.push((gate.id, "hard-gate-failed"));
            }
        }
        if !failures.is_empty() {
            eliminated.push(EliminatedCandidate { candidate, failures });
        } else {
            eligible.push(candidate);
        }
    }
    let mut ranked: Vec<(&C, f64)> = eligible.iter().map(|c| (*c, score(c))).collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ComparisonResult { eligible, eliminated, ranked }
}

// ---------------------------------------------------------------------
// assessSourceOfTruthOwnership (AE-ADVERSARIAL-006)
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OwnershipSource {
    pub source_id: String,
    pub owner: String,
    pub authorities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipConflict {
    pub authority: String,
    pub sources: Vec<(String, String)>, // (sourceId, owner)
    pub owners: Vec<String>,
}

/// Detect incompatible ownership before an architecture selector can use its
/// inputs. A duplicated authority is a conflict only when independent owners
/// claim it; multiple records owned by one authority may be replicas.
///
/// Thin wrapper over `assess_source_of_truth_ownership_detailed` for callers
/// that only need the pass/fail `Decision` (the JS `detail.ownershipConflicts`
/// array is a nested structure the flat `Decision.detail` string-pair list
/// can't hold — use the `_detailed` variant when that list is needed).
pub fn assess_source_of_truth_ownership(sources: &[OwnershipSource]) -> Result<Decision, ArcaneError> {
    assess_source_of_truth_ownership_detailed(sources).map(|(decision, _)| decision)
}

/// Detailed variant returning the structured conflict list directly,
/// matching `detail.ownershipConflicts` in the JS result.
pub fn assess_source_of_truth_ownership_detailed(
    sources: &[OwnershipSource],
) -> Result<(Decision, Vec<OwnershipConflict>), ArcaneError> {
    if sources.is_empty() {
        return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "sources must be a non-empty array"));
    }
    // Re-run the same logic to recover the structured conflicts (the plain
    // `assess_source_of_truth_ownership` above intentionally mirrors the JS
    // function's public signature/behavior for callers who only need the
    // pass/fail decision).
    let mut claims_by_authority: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    let mut source_ids = HashSet::new();
    for source in sources {
        if source.source_id.trim().is_empty()
            || source.owner.trim().is_empty()
            || source.authorities.is_empty()
            || source.authorities.iter().any(|a| a.trim().is_empty())
        {
            return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "source is malformed"));
        }
        if !source_ids.insert(source.source_id.clone()) {
            return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "source.sourceId must be unique"));
        }
        let authorities: BTreeSet<String> = source.authorities.iter().cloned().collect();
        for authority in authorities {
            claims_by_authority
                .entry(authority)
                .or_default()
                .push((source.source_id.clone(), source.owner.clone()));
        }
    }
    let mut conflicts: Vec<OwnershipConflict> = claims_by_authority
        .into_iter()
        .filter(|(_, claims)| {
            claims.len() > 1 && claims.iter().map(|(_, owner)| owner.clone()).collect::<HashSet<_>>().len() > 1
        })
        .map(|(authority, claims)| {
            let mut owners: Vec<String> = claims.iter().map(|(_, owner)| owner.clone()).collect();
            owners.sort();
            owners.dedup();
            OwnershipConflict { authority, sources: claims, owners }
        })
        .collect();
    conflicts.sort_by(|a, b| a.authority.cmp(&b.authority));

    let decision = if !conflicts.is_empty() {
        Decision::deny(
            ArcCode::ArcClaimPrerequisiteUnmet,
            "selection blocked by conflicting authority ownership",
            vec![("disposition".to_string(), "BLOCK_SELECTION".to_string())],
        )
    } else {
        Decision::allow(
            "authority ownership is unambiguous for selection",
            vec![("disposition".to_string(), "ELIGIBLE_FOR_SELECTION".to_string())],
        )
    };
    Ok((decision, conflicts))
}

// ---------------------------------------------------------------------
// admitVendorSelection (AE-ADVERSARIAL-007)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct AdverseCaseEconomics {
    pub outage_cost: Option<f64>,
    pub overage_cost: Option<f64>,
    pub egress_cost: Option<f64>,
    pub exit_cost: Option<f64>,
}

fn metric_set(economics: &AdverseCaseEconomics) -> (bool, Vec<&'static str>) {
    let checks: [(&'static str, Option<f64>); 4] = [
        ("outageCost", economics.outage_cost),
        ("overageCost", economics.overage_cost),
        ("egressCost", economics.egress_cost),
        ("exitCost", economics.exit_cost),
    ];
    let missing: Vec<&'static str> = checks
        .iter()
        .filter(|(_, v)| !matches!(v, Some(x) if x.is_finite() && *x >= 0.0))
        .map(|(name, _)| *name)
        .collect();
    (missing.is_empty(), missing)
}

#[derive(Debug, Clone)]
pub struct VendorCandidate {
    pub candidate_id: String,
    pub score: f64,
    pub adverse_case_economics: Option<AdverseCaseEconomics>,
}

#[derive(Debug)]
pub struct VendorSelectionOutcome {
    pub decision: Decision,
    pub missing_economic_metrics: Vec<&'static str>,
}

/// Admit a vendor selection only after the selected vendor supplies a
/// complete, non-negative adverse-case economic model. Other candidate
/// scores cannot compensate for this missing hard-gate evidence.
pub fn admit_vendor_selection(
    candidates: &[VendorCandidate],
    selected_candidate_id: &str,
) -> Result<VendorSelectionOutcome, ArcaneError> {
    if candidates.is_empty() {
        return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "candidates must be a non-empty array"));
    }
    if selected_candidate_id.trim().is_empty() {
        return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "selectedCandidateId must be a non-empty string"));
    }
    let mut ids = HashSet::new();
    for c in candidates {
        if c.candidate_id.trim().is_empty() {
            return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "candidate.candidateId must be a non-empty string"));
        }
        if !ids.insert(c.candidate_id.clone()) {
            return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "candidate.candidateId must be unique"));
        }
    }
    let selected = candidates
        .iter()
        .find(|c| c.candidate_id == selected_candidate_id)
        .ok_or_else(|| {
            ArcaneError::new(ArcCode::ArcSchemaInvalid, "selectedCandidateId must identify a candidate")
        })?;

    let default_econ = AdverseCaseEconomics::default();
    let hard_gates = vec![HardGate {
        id: "adverse-case-economics-complete",
        evaluate: Box::new(|c: &VendorCandidate| {
            metric_set(c.adverse_case_economics.as_ref().unwrap_or(&default_econ)).0
        }),
    }];
    let comparison = compare_evidence_candidates(candidates, &hard_gates, |c| c.score);
    let _ = comparison; // comparison detail is informational in the JS result; not required by callers here.

    let (complete, missing) = metric_set(selected.adverse_case_economics.as_ref().unwrap_or(&default_econ));
    if !complete {
        return Ok(VendorSelectionOutcome {
            decision: Decision::deny(
                ArcCode::ArcEvidenceInsufficient,
                "selected vendor lacks adverse-case economic evidence",
                vec![
                    ("disposition".to_string(), "BLOCK_SELECTION".to_string()),
                    ("selectedCandidateId".to_string(), selected_candidate_id.to_string()),
                ],
            ),
            missing_economic_metrics: missing,
        });
    }
    Ok(VendorSelectionOutcome {
        decision: Decision::allow(
            "selected vendor has complete adverse-case economic evidence",
            vec![
                ("disposition".to_string(), "ELIGIBLE_FOR_SELECTION".to_string()),
                ("selectedCandidateId".to_string(), selected_candidate_id.to_string()),
            ],
        ),
        missing_economic_metrics: vec![],
    })
}

pub fn adversarial_ownership_economics_binding_ids() -> [&'static str; 2] {
    ADVERSARIAL_OWNERSHIP_ECONOMICS_IDS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_conflict_blocks_selection() {
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
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].authority, "account-balance");
        assert_eq!(conflicts[0].owners.len(), 2);

        // The plain (non-detailed) entry point matches the same disposition.
        let plain = assess_source_of_truth_ownership(&sources).unwrap();
        assert!(!plain.allowed);
    }

    #[test]
    fn ownership_replica_records_are_not_a_conflict() {
        let sources = vec![
            OwnershipSource {
                source_id: "replica-1".into(),
                owner: "platform".into(),
                authorities: vec!["account-balance".into()],
            },
            OwnershipSource {
                source_id: "replica-2".into(),
                owner: "platform".into(),
                authorities: vec!["account-balance".into()],
            },
        ];
        let decision = assess_source_of_truth_ownership(&sources).unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn vendor_selection_blocks_incomplete_economics() {
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
    fn vendor_selection_allows_complete_economics() {
        let candidates = vec![VendorCandidate {
            candidate_id: "vendor-a".into(),
            score: 100.0,
            adverse_case_economics: Some(AdverseCaseEconomics {
                outage_cost: Some(1000.0),
                overage_cost: Some(25.0),
                egress_cost: Some(5.0),
                exit_cost: Some(10.0),
            }),
        }];
        let outcome = admit_vendor_selection(&candidates, "vendor-a").unwrap();
        assert!(outcome.decision.allowed);
        assert!(outcome.missing_economic_metrics.is_empty());
    }

    #[test]
    fn vendor_selection_rejects_unknown_selected_id() {
        let candidates = vec![VendorCandidate { candidate_id: "vendor-a".into(), score: 1.0, adverse_case_economics: None }];
        let err = admit_vendor_selection(&candidates, "vendor-z").unwrap_err();
        assert_eq!(err.code, ArcCode::ArcSchemaInvalid);
    }

    #[test]
    fn compare_evidence_candidates_eliminates_hard_gate_failures() {
        let candidates = vec![
            VendorCandidate { candidate_id: "a".into(), score: 10.0, adverse_case_economics: None },
            VendorCandidate {
                candidate_id: "b".into(),
                score: 5.0,
                adverse_case_economics: Some(AdverseCaseEconomics {
                    outage_cost: Some(1.0),
                    overage_cost: Some(1.0),
                    egress_cost: Some(1.0),
                    exit_cost: Some(1.0),
                }),
            },
        ];
        let default_econ = AdverseCaseEconomics::default();
        let gates = vec![HardGate {
            id: "complete",
            evaluate: Box::new(|c: &VendorCandidate| {
                metric_set(c.adverse_case_economics.as_ref().unwrap_or(&default_econ)).0
            }),
        }];
        let result = compare_evidence_candidates(&candidates, &gates, |c| c.score);
        assert_eq!(result.eliminated.len(), 1);
        assert_eq!(result.eligible.len(), 1);
        assert_eq!(result.eligible[0].candidate_id, "b");
    }

    #[test]
    fn binding_ids_match_js_constant() {
        assert_eq!(
            adversarial_ownership_economics_binding_ids(),
            ["AE-ADVERSARIAL-006", "AE-ADVERSARIAL-007"]
        );
    }
}
