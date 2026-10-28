use legion_review::rounds::*;

fn clean() -> ReviewLoopInput {
    serde_json::from_str(include_str!("rounds-approved.json")).unwrap()
}
fn finding(kind: FindingKind) -> FindingUpdate {
    FindingUpdate {
        id: "F1".into(), kind, criterion: "Required behavior is preserved".into(),
        disposition: FindingDisposition::Open, resolution_digest: None, evidence_refs: vec!["source/file.rs:10".into()],
    }
}
fn delta(input: &ReviewLoopInput) -> ReviewRound {
    let prior = input.rounds.last().unwrap();
    ReviewRound {
        number: prior.number + 1, digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        base: prior.base.clone(), scope: ReviewScope::Delta, prior_digest: Some(prior.digest.clone()),
        reviewer: "oracle-agent".into(), status: RoundStatus::Complete, evidence_refs: vec!["review/next".into()], findings: vec![],
    }
}
fn has(input: &ReviewLoopInput, reason: ReviewLoopReason) {
    let result = assess_review_loop(input).unwrap();
    assert!(!result.approved, "{result:?}");
    assert!(result.reasons.contains(&reason), "{result:?}");
    assert_eq!(result.effect_authority, legion_runtime::delivery::EffectAuthority::None);
}

#[test]
fn full_zero_finding_review_and_valid_delta_approve_exact_current_revision() {
    let mut input = clean();
    assert!(assess_review_loop(&input).unwrap().approved);
    let next = delta(&input);
    input.current_digest = next.digest.clone();
    input.rounds.push(next);
    assert!(assess_review_loop(&input).unwrap().approved);
}

#[test]
fn self_review_and_stale_artifact_or_base_never_approve() {
    let mut input = clean();
    input.rounds[0].reviewer = "IMPLEMENTER-AGENT".into();
    has(&input, ReviewLoopReason::SelfReview);
    input = clean();
    input.current_digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
    has(&input, ReviewLoopReason::StaleArtifact);
    input = clean();
    input.current_base = "cccccccccccccccccccccccccccccccccccccccc".into();
    has(&input, ReviewLoopReason::StaleBase);
}

#[test]
fn delta_requires_completed_full_lineage_and_exact_prior_digest() {
    let mut input = clean();
    input.rounds[0].scope = ReviewScope::Delta;
    has(&input, ReviewLoopReason::MissingFullReview);
    input = clean();
    let mut next = delta(&input);
    next.prior_digest = Some(next.digest.clone());
    input.current_digest = next.digest.clone();
    input.rounds.push(next);
    has(&input, ReviewLoopReason::InvalidRoundLineage);
    input = clean();
    input.rounds[0].status = RoundStatus::Incomplete;
    let next = delta(&input);
    input.current_digest = next.digest.clone();
    input.rounds.push(next);
    has(&input, ReviewLoopReason::InvalidRoundLineage);
}

#[test]
fn omitted_findings_persist_and_budget_exhaustion_is_not_approval() {
    let mut input = clean();
    input.max_rounds = 2;
    input.rounds[0].findings.push(finding(FindingKind::Outcome));
    let next = delta(&input);
    input.current_digest = next.digest.clone();
    input.rounds.push(next);
    let result = assess_review_loop(&input).unwrap();
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].disposition, FindingDisposition::Open);
    assert_eq!(result.status, ReviewLoopStatus::Exhausted);
    has(&input, ReviewLoopReason::UnresolvedOutcomeOrSafety);
    has(&input, ReviewLoopReason::Exhausted);
}

#[test]
fn resolved_requires_complete_review_and_current_digest_evidence() {
    for invalid_case in 0..4 {
        let mut input = clean();
        input.rounds[0].findings.push(finding(FindingKind::Safety));
        let mut next = delta(&input);
        let mut update = finding(FindingKind::Safety);
        update.disposition = FindingDisposition::Resolved;
        update.resolution_digest = Some(next.digest.clone());
        match invalid_case {
            0 => next.status = RoundStatus::Incomplete,
            1 => update.resolution_digest = Some(input.current_digest.clone()),
            2 => update.evidence_refs.clear(),
            _ => next.evidence_refs.clear(),
        }
        next.findings.push(update);
        input.current_digest = next.digest.clone();
        input.rounds.push(next);
        has(&input, ReviewLoopReason::UnprovedResolution);
    }
    let mut input = clean();
    input.rounds[0].findings.push(finding(FindingKind::Safety));
    let mut next = delta(&input);
    let mut update = finding(FindingKind::Safety);
    update.disposition = FindingDisposition::Resolved;
    update.resolution_digest = Some(next.digest.clone());
    next.findings.push(update);
    input.current_digest = next.digest.clone();
    input.rounds.push(next);
    assert!(assess_review_loop(&input).unwrap().approved);
}

#[test]
fn advisory_does_not_block_but_blocking_findings_cannot_be_downgraded() {
    let mut input = clean();
    input.rounds[0].findings.push(finding(FindingKind::Advisory));
    assert!(assess_review_loop(&input).unwrap().approved);
    input = clean();
    input.rounds[0].findings.push(finding(FindingKind::Outcome));
    let mut next = delta(&input);
    next.findings.push(finding(FindingKind::Advisory));
    input.current_digest = next.digest.clone();
    input.rounds.push(next);
    has(&input, ReviewLoopReason::FindingDowngrade);
}

#[test]
fn disputed_and_deferred_safety_still_block_and_criterion_is_stable() {
    for disposition in [FindingDisposition::FixedPending, FindingDisposition::Disputed, FindingDisposition::DeferredOutOfScope] {
        let mut input = clean();
        let mut update = finding(FindingKind::Safety);
        update.disposition = disposition;
        input.rounds[0].findings.push(update);
        has(&input, ReviewLoopReason::UnresolvedOutcomeOrSafety);
    }
    let mut input = clean();
    input.rounds[0].findings.push(finding(FindingKind::Safety));
    let mut next = delta(&input);
    let mut update = finding(FindingKind::Safety);
    update.criterion = "different acceptance criterion".into();
    next.findings.push(update);
    input.current_digest = next.digest.clone();
    input.rounds.push(next);
    has(&input, ReviewLoopReason::FindingIdentityChanged);
}

#[test]
fn strict_schema_bounds_and_sequential_rounds() {
    let mut input = clean();
    input.max_rounds = 33;
    assert!(assess_review_loop(&input).is_err());
    input = clean();
    input.rounds[0].number = 2;
    assert!(assess_review_loop(&input).is_err());
    let mut json = serde_json::to_value(clean()).unwrap();
    json["councilAuthority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ReviewLoopInput>(json).is_err());
}
