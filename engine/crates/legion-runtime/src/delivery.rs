//! Pure delivery diagnostics. Observations and imported proofs never grant effect authority.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const DELIVERY_SCHEMA_VERSION: u32 = 1;
const MAX_ITEMS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryAssessmentRequest {
    pub schema_version: u32,
    pub repository: String,
    pub pull_request: u64,
    pub expected_head: String,
    pub expected_base: String,
    pub terminal_goal: TerminalGoal,
    pub now_unix_seconds: u64,
    pub max_age_seconds: u64,
    pub snapshot: DeliverySnapshot,
    pub verification: RevisionProof,
    pub independent_review: RevisionProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TerminalGoal {
    UserHandoff,
    MergeRequested,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliverySnapshot {
    pub repository: String,
    pub pull_request: u64,
    pub observed_at_unix_seconds: u64,
    pub head_before: String,
    pub base_before: String,
    pub head_after: String,
    pub base_after: String,
    pub state: PullRequestState,
    pub draft: bool,
    pub mergeability: Mergeability,
    pub merge_state: MergeState,
    pub completeness: ObservationCompleteness,
    pub branch_policy: BranchPolicy,
    pub checks: Vec<CheckObservation>,
    pub human_review: HumanReview,
    pub unresolved_threads: u32,
    pub auto_merge_enabled: bool,
    pub in_merge_queue: bool,
    pub merge_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationCompleteness {
    pub checks: bool,
    pub reviews: bool,
    pub threads: bool,
    pub policy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchPolicy {
    pub known: bool,
    pub required_checks: Vec<RequiredCheck>,
    pub human_review_required: bool,
    pub allow_neutral: bool,
    pub allow_skipped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequiredCheck {
    pub name: String,
    /// None explicitly means policy permits any application identity.
    #[serde(deserialize_with = "required_nullable_app_id")]
    pub app_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckObservation {
    pub name: String,
    #[serde(deserialize_with = "required_nullable_app_id")]
    pub app_id: Option<u64>,
    pub head: String,
    pub status: CheckStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Success,
    Neutral,
    Skipped,
    Pending,
    Failure,
    Cancelled,
    TimedOut,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestState {
    Open,
    Closed,
    Merged,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mergeability {
    Positive,
    Conflicting,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MergeState {
    Clear,
    Behind,
    Blocked,
    Unknown,
    Queue,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HumanReview {
    Satisfied,
    Pending,
    ChangesRequested,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionProof {
    pub completed: bool,
    pub head: String,
    pub base: String,
    pub observed_at_unix_seconds: u64,
    pub implementer: String,
    pub reviewer: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectAuthority {
    None,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    ReadyForHandoff,
    ReadyForMergeRequest,
    NotReady,
    ClosedWithoutMerge,
    ObservedMerged,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryReason {
    WrongPullRequest,
    RevisionChangedDuringCollection,
    UnexpectedRevision,
    StaleObservation,
    FutureObservation,
    IncompleteChecks,
    IncompleteReviews,
    IncompleteThreads,
    IncompletePolicy,
    UnknownBranchPolicy,
    Draft,
    MergeConflict,
    UnknownMergeability,
    BehindBase,
    BlockedMergeState,
    UnknownMergeState,
    WaitingForMergeQueue,
    MissingRequiredCheck,
    RequiredCheckFailed,
    RequiredCheckPending,
    RequiredCheckUnknown,
    WaitingForHumanReview,
    HumanChangesRequested,
    UnknownHumanReview,
    UnresolvedThreads,
    AutoMergeMustBeDisabledForHandoff,
    MergeQueueMustBeExitedForHandoff,
    VerificationIncomplete,
    VerificationWrongRevision,
    VerificationMissingEvidence,
    IndependentReviewIncomplete,
    IndependentReviewWrongRevision,
    IndependentReviewMissingEvidence,
    SelfReview,
    ProofImplementerMismatch,
    MissingMergeCommit,
    ClosedWithoutMerge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryAssessment {
    pub schema_version: u32,
    pub repository: String,
    pub pull_request: u64,
    pub head: String,
    pub base: String,
    pub terminal_goal: TerminalGoal,
    pub status: DeliveryStatus,
    pub ready: bool,
    pub reasons: Vec<DeliveryReason>,
    pub effect_authority: EffectAuthority,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid delivery assessment: {0}")]
pub struct DeliveryAssessmentError(pub String);

fn required_nullable_app_id<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(deserializer)
}

fn bounded_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 2048
}
fn revision(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Assess one bounded snapshot. This function performs no I/O, polling, or effects.
pub fn assess_delivery(
    request: &DeliveryAssessmentRequest,
) -> Result<DeliveryAssessment, DeliveryAssessmentError> {
    let s = &request.snapshot;
    let invalid = |message: &str| DeliveryAssessmentError(message.to_owned());
    if request.schema_version != DELIVERY_SCHEMA_VERSION {
        return Err(invalid("unsupported schema version"));
    }
    if !bounded_text(&request.repository)
        || !bounded_text(&s.repository)
        || request.pull_request == 0
        || s.pull_request == 0
    {
        return Err(invalid(
            "repository and positive pull request number required",
        ));
    }
    if request.max_age_seconds == 0 || request.max_age_seconds > 86_400 {
        return Err(invalid("maxAgeSeconds must be 1..=86400"));
    }
    if [
        &request.expected_head,
        &request.expected_base,
        &s.head_before,
        &s.base_before,
        &s.head_after,
        &s.base_after,
    ]
    .iter()
    .any(|v| !revision(v))
    {
        return Err(invalid("head/base must be full hexadecimal revisions"));
    }
    if s.checks.len() > MAX_ITEMS || s.branch_policy.required_checks.len() > MAX_ITEMS {
        return Err(invalid("check bound exceeded"));
    }
    if s.checks
        .iter()
        .any(|c| !bounded_text(&c.name) || !revision(&c.head))
        || s.branch_policy
            .required_checks
            .iter()
            .any(|c| !bounded_text(&c.name))
    {
        return Err(invalid("invalid check name or head"));
    }
    if let Some(commit) = &s.merge_commit {
        if !revision(commit) {
            return Err(invalid("invalid merge commit"));
        }
    }
    for p in [&request.verification, &request.independent_review] {
        if p.evidence_refs.len() > MAX_ITEMS
            || p.evidence_refs.iter().any(|e| !bounded_text(e))
            || p.implementer.len() > 2048
            || p.reviewer.len() > 2048
        {
            return Err(invalid("invalid or excessive proof metadata"));
        }
        if (!p.head.is_empty() && !revision(&p.head)) || (!p.base.is_empty() && !revision(&p.base))
        {
            return Err(invalid("invalid proof revision"));
        }
    }
    let mut reasons = BTreeSet::new();
    if request.repository != s.repository || request.pull_request != s.pull_request {
        reasons.insert(DeliveryReason::WrongPullRequest);
    }
    if s.head_before != s.head_after || s.base_before != s.base_after {
        reasons.insert(DeliveryReason::RevisionChangedDuringCollection);
    }
    if s.head_after != request.expected_head || s.base_after != request.expected_base {
        reasons.insert(DeliveryReason::UnexpectedRevision);
    }
    for time in [
        s.observed_at_unix_seconds,
        request.verification.observed_at_unix_seconds,
        request.independent_review.observed_at_unix_seconds,
    ] {
        if time > request.now_unix_seconds {
            reasons.insert(DeliveryReason::FutureObservation);
        } else if request.now_unix_seconds - time > request.max_age_seconds {
            reasons.insert(DeliveryReason::StaleObservation);
        }
    }
    if !s.completeness.checks {
        reasons.insert(DeliveryReason::IncompleteChecks);
    }
    if !s.completeness.reviews {
        reasons.insert(DeliveryReason::IncompleteReviews);
    }
    if !s.completeness.threads {
        reasons.insert(DeliveryReason::IncompleteThreads);
    }
    if !s.completeness.policy {
        reasons.insert(DeliveryReason::IncompletePolicy);
    }
    if !s.branch_policy.known {
        reasons.insert(DeliveryReason::UnknownBranchPolicy);
    }
    if s.draft {
        reasons.insert(DeliveryReason::Draft);
    }
    match s.mergeability {
        Mergeability::Positive => {}
        Mergeability::Conflicting => {
            reasons.insert(DeliveryReason::MergeConflict);
        }
        Mergeability::Unknown => {
            reasons.insert(DeliveryReason::UnknownMergeability);
        }
    }
    match s.merge_state {
        MergeState::Clear => {}
        MergeState::Behind => {
            reasons.insert(DeliveryReason::BehindBase);
        }
        MergeState::Blocked => {
            reasons.insert(DeliveryReason::BlockedMergeState);
        }
        MergeState::Unknown => {
            reasons.insert(DeliveryReason::UnknownMergeState);
        }
        MergeState::Queue => {
            reasons.insert(DeliveryReason::WaitingForMergeQueue);
        }
    }
    for required in &s.branch_policy.required_checks {
        let observations: Vec<_> = s
            .checks
            .iter()
            .filter(|c| {
                c.name == required.name
                    && c.head == request.expected_head
                    && (required.app_id.is_none() || c.app_id == required.app_id)
            })
            .collect();
        if observations.is_empty() {
            reasons.insert(DeliveryReason::MissingRequiredCheck);
        }
        for observation in observations {
            match observation.status {
                CheckStatus::Success => {}
                CheckStatus::Neutral if s.branch_policy.allow_neutral => {}
                CheckStatus::Skipped if s.branch_policy.allow_skipped => {}
                CheckStatus::Pending => {
                    reasons.insert(DeliveryReason::RequiredCheckPending);
                }
                CheckStatus::Unknown => {
                    reasons.insert(DeliveryReason::RequiredCheckUnknown);
                }
                _ => {
                    reasons.insert(DeliveryReason::RequiredCheckFailed);
                }
            }
        }
    }
    match s.human_review {
        HumanReview::ChangesRequested => {
            reasons.insert(DeliveryReason::HumanChangesRequested);
        }
        HumanReview::Unknown => {
            reasons.insert(DeliveryReason::UnknownHumanReview);
        }
        HumanReview::Pending if s.branch_policy.human_review_required => {
            reasons.insert(DeliveryReason::WaitingForHumanReview);
        }
        _ => {}
    }
    if s.unresolved_threads > 0 {
        reasons.insert(DeliveryReason::UnresolvedThreads);
    }
    if request.terminal_goal == TerminalGoal::UserHandoff {
        if s.auto_merge_enabled {
            reasons.insert(DeliveryReason::AutoMergeMustBeDisabledForHandoff);
        }
        if s.in_merge_queue {
            reasons.insert(DeliveryReason::MergeQueueMustBeExitedForHandoff);
        }
    } else if s.in_merge_queue {
        reasons.insert(DeliveryReason::WaitingForMergeQueue);
    }
    for (proof, independent) in [
        (&request.verification, false),
        (&request.independent_review, true),
    ] {
        if !proof.completed {
            reasons.insert(if independent {
                DeliveryReason::IndependentReviewIncomplete
            } else {
                DeliveryReason::VerificationIncomplete
            });
        }
        if proof.head != request.expected_head || proof.base != request.expected_base {
            reasons.insert(if independent {
                DeliveryReason::IndependentReviewWrongRevision
            } else {
                DeliveryReason::VerificationWrongRevision
            });
        }
        if proof.evidence_refs.is_empty() {
            reasons.insert(if independent {
                DeliveryReason::IndependentReviewMissingEvidence
            } else {
                DeliveryReason::VerificationMissingEvidence
            });
        }
        if independent
            && (proof.implementer.trim().is_empty()
                || proof.reviewer.trim().is_empty()
                || proof
                    .implementer
                    .trim()
                    .eq_ignore_ascii_case(proof.reviewer.trim()))
        {
            reasons.insert(DeliveryReason::SelfReview);
        }
    }
    if request.verification.implementer.trim().is_empty()
        || request.verification.implementer.trim() != request.independent_review.implementer.trim()
    {
        reasons.insert(DeliveryReason::ProofImplementerMismatch);
    }
    // An observed merge is a separate terminal fact, but it still must describe
    // this exact PR and a coherent, fresh collection of this exact revision.
    let merge_identity_valid = request.repository == s.repository
        && request.pull_request == s.pull_request
        && s.head_before == s.head_after
        && s.base_before == s.base_after
        && s.head_after == request.expected_head
        && s.base_after == request.expected_base
        && s.observed_at_unix_seconds <= request.now_unix_seconds
        && request.now_unix_seconds - s.observed_at_unix_seconds <= request.max_age_seconds;
    let status = match s.state {
        PullRequestState::Closed => {
            reasons.insert(DeliveryReason::ClosedWithoutMerge);
            if merge_identity_valid {
                DeliveryStatus::ClosedWithoutMerge
            } else {
                DeliveryStatus::NotReady
            }
        }
        PullRequestState::Merged => {
            if s.merge_commit.is_none() {
                reasons.insert(DeliveryReason::MissingMergeCommit);
                DeliveryStatus::NotReady
            } else if merge_identity_valid {
                DeliveryStatus::ObservedMerged
            } else {
                DeliveryStatus::NotReady
            }
        }
        PullRequestState::Open if reasons.is_empty() => match request.terminal_goal {
            TerminalGoal::UserHandoff => DeliveryStatus::ReadyForHandoff,
            TerminalGoal::MergeRequested => DeliveryStatus::ReadyForMergeRequest,
        },
        PullRequestState::Open => DeliveryStatus::NotReady,
    };
    let ready = matches!(
        status,
        DeliveryStatus::ReadyForHandoff | DeliveryStatus::ReadyForMergeRequest
    );
    Ok(DeliveryAssessment {
        schema_version: DELIVERY_SCHEMA_VERSION,
        repository: request.repository.clone(),
        pull_request: request.pull_request,
        head: request.expected_head.clone(),
        base: request.expected_base.clone(),
        terminal_goal: request.terminal_goal.clone(),
        status,
        ready,
        reasons: reasons.into_iter().collect(),
        effect_authority: EffectAuthority::None,
    })
}
