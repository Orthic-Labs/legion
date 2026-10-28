use legion_runtime::delivery::*;

fn ready() -> DeliveryAssessmentRequest {
    serde_json::from_str(include_str!("delivery-ready.json")).unwrap()
}
fn has(request: &DeliveryAssessmentRequest, reason: DeliveryReason) {
    let result = assess_delivery(request).unwrap();
    assert!(!result.ready, "{result:?}");
    assert!(result.reasons.contains(&reason), "{result:?}");
    assert_eq!(result.effect_authority, EffectAuthority::None);
}

#[test]
fn exact_complete_snapshot_is_diagnostic_readiness_only() {
    let result = assess_delivery(&ready()).unwrap();
    assert!(result.ready);
    assert_eq!(result.status, DeliveryStatus::ReadyForHandoff);
    assert_eq!(result.effect_authority, EffectAuthority::None);
}

#[test]
fn duplicate_failure_cannot_be_hidden_by_success() {
    let mut request = ready();
    let mut failure = request.snapshot.checks[0].clone();
    failure.status = CheckStatus::Failure;
    request.snapshot.checks.push(failure);
    has(&request, DeliveryReason::RequiredCheckFailed);
    request.snapshot.checks.reverse();
    has(&request, DeliveryReason::RequiredCheckFailed);
}

#[test]
fn check_identity_and_head_are_required() {
    let mut request = ready();
    request.snapshot.checks[0].app_id = Some(999);
    has(&request, DeliveryReason::MissingRequiredCheck);
    request = ready();
    request.snapshot.checks[0].head = request.expected_base.clone();
    has(&request, DeliveryReason::MissingRequiredCheck);
}

#[test]
fn unknown_policy_or_incomplete_pages_never_ready() {
    let mut request = ready();
    request.snapshot.branch_policy.known = false;
    has(&request, DeliveryReason::UnknownBranchPolicy);
    for field in 0..4 {
        request = ready();
        match field {
            0 => request.snapshot.completeness.checks = false,
            1 => request.snapshot.completeness.reviews = false,
            2 => request.snapshot.completeness.threads = false,
            _ => request.snapshot.completeness.policy = false,
        }
        assert!(!assess_delivery(&request).unwrap().ready);
    }
}

#[test]
fn review_must_be_independent_current_and_complete() {
    let mut request = ready();
    request.independent_review.reviewer = "IMPLEMENTER-AGENT".into();
    has(&request, DeliveryReason::SelfReview);
    request = ready();
    request.independent_review.head = request.expected_base.clone();
    has(&request, DeliveryReason::IndependentReviewWrongRevision);
    request = ready();
    request.independent_review.evidence_refs.clear();
    has(&request, DeliveryReason::IndependentReviewMissingEvidence);
}

#[test]
fn changed_revision_and_clock_fail_closed() {
    let mut request = ready();
    request.snapshot.head_after = request.expected_base.clone();
    has(&request, DeliveryReason::RevisionChangedDuringCollection);
    request = ready();
    request.snapshot.observed_at_unix_seconds = 1;
    has(&request, DeliveryReason::StaleObservation);
    request = ready();
    request.snapshot.observed_at_unix_seconds = 1001;
    has(&request, DeliveryReason::FutureObservation);
}

#[test]
fn handoff_requires_human_and_stops_existing_automation() {
    let mut request = ready();
    request.snapshot.human_review = HumanReview::Pending;
    has(&request, DeliveryReason::WaitingForHumanReview);
    request = ready();
    request.snapshot.auto_merge_enabled = true;
    has(&request, DeliveryReason::AutoMergeMustBeDisabledForHandoff);
    request = ready();
    request.snapshot.in_merge_queue = true;
    has(&request, DeliveryReason::MergeQueueMustBeExitedForHandoff);
}

#[test]
fn neutral_and_skipped_require_explicit_policy() {
    for status in [CheckStatus::Neutral, CheckStatus::Skipped] {
        let mut request = ready();
        request.snapshot.checks[0].status = status;
        has(&request, DeliveryReason::RequiredCheckFailed);
        request.snapshot.branch_policy.allow_neutral = true;
        request.snapshot.branch_policy.allow_skipped = true;
        assert!(assess_delivery(&request).unwrap().ready);
    }
}

#[test]
fn merge_requested_is_not_merged_and_merged_identity_must_match() {
    let mut request = ready();
    request.terminal_goal = TerminalGoal::MergeRequested;
    assert_eq!(assess_delivery(&request).unwrap().status, DeliveryStatus::ReadyForMergeRequest);
    request.snapshot.state = PullRequestState::Merged;
    has(&request, DeliveryReason::MissingMergeCommit);
    request.snapshot.merge_commit = Some("cccccccccccccccccccccccccccccccccccccccc".into());
    assert_eq!(assess_delivery(&request).unwrap().status, DeliveryStatus::ObservedMerged);
    request.snapshot.pull_request += 1;
    assert_eq!(assess_delivery(&request).unwrap().status, DeliveryStatus::NotReady);
    request = ready();
    request.snapshot.state = PullRequestState::Merged;
    request.snapshot.merge_commit = Some("cccccccccccccccccccccccccccccccccccccccc".into());
    request.snapshot.observed_at_unix_seconds = 1;
    assert_eq!(assess_delivery(&request).unwrap().status, DeliveryStatus::NotReady);
    request.snapshot.observed_at_unix_seconds = 990;
    request.snapshot.state = PullRequestState::Closed;
    assert_eq!(assess_delivery(&request).unwrap().status, DeliveryStatus::ClosedWithoutMerge);
}

#[test]
fn strict_version_and_unknown_fields() {
    let mut request = ready();
    request.schema_version = 2;
    assert!(assess_delivery(&request).is_err());
    let mut json = serde_json::to_value(ready()).unwrap();
    json["mergeAuthorized"] = serde_json::json!(true);
    assert!(serde_json::from_value::<DeliveryAssessmentRequest>(json).is_err());
    let mut json = serde_json::to_value(ready()).unwrap();
    json["snapshot"]["branchPolicy"]["requiredChecks"][0].as_object_mut().unwrap().remove("appId");
    assert!(serde_json::from_value::<DeliveryAssessmentRequest>(json).is_err());
}
