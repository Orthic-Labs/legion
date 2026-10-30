//! Bounded ordinary review ledger; this is neither Council nor effect authorization.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const REVIEW_LOOP_SCHEMA_VERSION: u32 = 1;
const MAX_ROUNDS: usize = 32;
const MAX_FINDINGS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewLoopInput {
    pub schema_version: u32,
    pub current_digest: String,
    pub current_base: String,
    pub implementer: String,
    pub max_rounds: u32,
    pub rounds: Vec<ReviewRound>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewRound {
    pub number: u32,
    pub digest: String,
    pub base: String,
    pub scope: ReviewScope,
    pub prior_digest: Option<String>,
    pub reviewer: String,
    pub status: RoundStatus,
    pub evidence_refs: Vec<String>,
    pub findings: Vec<FindingUpdate>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewScope {
    Full,
    Delta,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoundStatus {
    Complete,
    Incomplete,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingUpdate {
    pub id: String,
    pub kind: FindingKind,
    pub criterion: String,
    pub disposition: FindingDisposition,
    pub resolution_digest: Option<String>,
    pub evidence_refs: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Outcome,
    Safety,
    Advisory,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDisposition {
    Open,
    FixedPending,
    Resolved,
    Disputed,
    DeferredOutOfScope,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLoopReason {
    MissingFullReview,
    InvalidRoundLineage,
    SelfReview,
    IncompleteReview,
    MissingEvidence,
    StaleArtifact,
    StaleBase,
    FindingIdentityChanged,
    FindingDowngrade,
    UnprovedResolution,
    UnresolvedOutcomeOrSafety,
    Exhausted,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLoopStatus {
    Approved,
    NeedsRevision,
    Incomplete,
    Exhausted,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewLoopAssessment {
    pub schema_version: u32,
    pub digest: String,
    pub base: String,
    pub status: ReviewLoopStatus,
    pub approved: bool,
    pub rounds_used: u32,
    pub rounds_remaining: u32,
    pub reasons: Vec<ReviewLoopReason>,
    pub findings: Vec<FindingUpdate>,
    pub effect_authority: legion_runtime::delivery::EffectAuthority,
}
#[derive(Debug, thiserror::Error)]
#[error("invalid review loop: {0}")]
pub struct ReviewLoopError(pub String);

fn text_valid(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 2048
}
fn digest_valid(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn evidence_valid(values: &[String]) -> bool {
    values.len() <= MAX_FINDINGS && values.iter().all(|s| text_valid(s))
}

/// Fold explicit updates into a persistent finding ledger. Omission never closes a finding.
pub fn assess_review_loop(
    input: &ReviewLoopInput,
) -> Result<ReviewLoopAssessment, ReviewLoopError> {
    let invalid = |s: &str| ReviewLoopError(s.to_owned());
    if input.schema_version != REVIEW_LOOP_SCHEMA_VERSION {
        return Err(invalid("unsupported schema version"));
    }
    if !digest_valid(&input.current_digest)
        || !digest_valid(&input.current_base)
        || !text_valid(&input.implementer)
    {
        return Err(invalid("full digest/base and implementer required"));
    }
    if input.max_rounds == 0
        || input.max_rounds as usize > MAX_ROUNDS
        || input.rounds.len() > input.max_rounds as usize
    {
        return Err(invalid("round budget must be 1..=32 and not exceeded"));
    }
    for (index, round) in input.rounds.iter().enumerate() {
        if round.number as usize != index + 1 {
            return Err(invalid("round numbers must be sequential from one"));
        }
        if !digest_valid(&round.digest)
            || !digest_valid(&round.base)
            || !text_valid(&round.reviewer)
            || !evidence_valid(&round.evidence_refs)
            || round.findings.len() > MAX_FINDINGS
        {
            return Err(invalid("invalid round metadata or bounds"));
        }
        if round
            .prior_digest
            .as_ref()
            .is_some_and(|v| !digest_valid(v))
        {
            return Err(invalid("invalid prior digest"));
        }
        let mut ids = BTreeSet::new();
        for finding in &round.findings {
            if !text_valid(&finding.id)
                || !text_valid(&finding.criterion)
                || !evidence_valid(&finding.evidence_refs)
                || finding
                    .resolution_digest
                    .as_ref()
                    .is_some_and(|v| !digest_valid(v))
                || !ids.insert(&finding.id)
            {
                return Err(invalid("invalid finding metadata, duplicate ID, or bounds"));
            }
        }
    }
    let mut reasons = BTreeSet::new();
    let mut ledger: BTreeMap<String, FindingUpdate> = BTreeMap::new();
    for (index, round) in input.rounds.iter().enumerate() {
        let independent = !round
            .reviewer
            .trim()
            .eq_ignore_ascii_case(input.implementer.trim());
        if !independent {
            reasons.insert(ReviewLoopReason::SelfReview);
        }
        match round.scope {
            ReviewScope::Full => {
                if round.prior_digest.is_some() {
                    reasons.insert(ReviewLoopReason::InvalidRoundLineage);
                }
            }
            ReviewScope::Delta => {
                if index == 0 {
                    reasons.insert(ReviewLoopReason::MissingFullReview);
                } else {
                    let prior = &input.rounds[index - 1];
                    if round.prior_digest.as_ref() != Some(&prior.digest)
                        || round.base != prior.base
                        || prior.status != RoundStatus::Complete
                        || prior.evidence_refs.is_empty()
                    {
                        reasons.insert(ReviewLoopReason::InvalidRoundLineage);
                    }
                }
            }
        }
        for update in &round.findings {
            if let Some(prior) = ledger.get(&update.id) {
                if prior.criterion != update.criterion {
                    reasons.insert(ReviewLoopReason::FindingIdentityChanged);
                    continue;
                }
                if prior.kind != update.kind {
                    reasons.insert(if update.kind == FindingKind::Advisory {
                        ReviewLoopReason::FindingDowngrade
                    } else {
                        ReviewLoopReason::FindingIdentityChanged
                    });
                    continue;
                }
            }
            if update.disposition == FindingDisposition::Resolved
                && (!independent
                    || round.status != RoundStatus::Complete
                    || round.evidence_refs.is_empty()
                    || update.resolution_digest.as_ref() != Some(&round.digest)
                    || update.evidence_refs.is_empty())
            {
                reasons.insert(ReviewLoopReason::UnprovedResolution);
                // A rejected new resolved finding must still enter the ledger as open.
                if !ledger.contains_key(&update.id) {
                    let mut open = update.clone();
                    open.disposition = FindingDisposition::Open;
                    open.resolution_digest = None;
                    ledger.insert(open.id.clone(), open);
                }
                continue;
            }
            ledger.insert(update.id.clone(), update.clone());
        }
        if ledger.len() > MAX_FINDINGS {
            return Err(invalid("persistent finding bound exceeded"));
        }
    }
    if let Some(last) = input.rounds.last() {
        if last.digest != input.current_digest {
            reasons.insert(ReviewLoopReason::StaleArtifact);
        }
        if last.base != input.current_base {
            reasons.insert(ReviewLoopReason::StaleBase);
        }
        if last.status != RoundStatus::Complete {
            reasons.insert(ReviewLoopReason::IncompleteReview);
        }
        if last.evidence_refs.is_empty() {
            reasons.insert(ReviewLoopReason::MissingEvidence);
        }
    } else {
        reasons.insert(ReviewLoopReason::MissingFullReview);
        reasons.insert(ReviewLoopReason::IncompleteReview);
    }
    if ledger
        .values()
        .any(|f| f.kind != FindingKind::Advisory && f.disposition != FindingDisposition::Resolved)
    {
        reasons.insert(ReviewLoopReason::UnresolvedOutcomeOrSafety);
    }
    let approved = reasons.is_empty();
    let exhausted = !approved && input.rounds.len() == input.max_rounds as usize;
    if exhausted {
        reasons.insert(ReviewLoopReason::Exhausted);
    }
    let status = if approved {
        ReviewLoopStatus::Approved
    } else if exhausted {
        ReviewLoopStatus::Exhausted
    } else if reasons.contains(&ReviewLoopReason::UnresolvedOutcomeOrSafety) {
        ReviewLoopStatus::NeedsRevision
    } else {
        ReviewLoopStatus::Incomplete
    };
    Ok(ReviewLoopAssessment {
        schema_version: REVIEW_LOOP_SCHEMA_VERSION,
        digest: input.current_digest.clone(),
        base: input.current_base.clone(),
        status,
        approved,
        rounds_used: input.rounds.len() as u32,
        rounds_remaining: input.max_rounds - input.rounds.len() as u32,
        reasons: reasons.into_iter().collect(),
        findings: ledger.into_values().collect(),
        effect_authority: legion_runtime::delivery::EffectAuthority::None,
    })
}
