use std::collections::BTreeSet;

use legion_contracts::{FindingId, RequestId};
use serde::{Deserialize, Serialize};

use crate::{
    candidate::{CandidateEnvelope, CandidateEvidence},
    error::ReviewError,
    provider::{ProviderJudgment, ProviderOutcome, ReviewProviderMetadata},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicationRequest {
    pub request_id: RequestId,
    pub candidates: CandidateEnvelope,
    pub outcomes: Vec<ProviderOutcome>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicatedResult {
    pub candidate_id: FindingId,
    pub adjudicator_id: String,
    pub verdict: String,
    pub rationale: String,
    pub evidence_ids: Vec<String>,
    pub metadata: ReviewProviderMetadata,
}

impl From<&ProviderJudgment> for AdjudicatedResult {
    fn from(value: &ProviderJudgment) -> Self {
        Self {
            candidate_id: value.candidate_id.clone(),
            adjudicator_id: value.adjudicator_id.clone(),
            verdict: value.verdict.clone(),
            rationale: value.rationale.clone(),
            evidence_ids: value.evidence_ids.clone(),
            metadata: value.metadata.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adjudication {
    pub schema_version: u32,
    pub request_id: RequestId,
    pub review_id: String,
    pub candidates: Vec<CandidateEvidence>,
    pub results: Vec<AdjudicatedResult>,
    pub providers: Vec<ReviewProviderMetadata>,
    pub gaps: Vec<String>,
    pub complete: bool,
}

pub fn adjudicate(request: AdjudicationRequest) -> Result<Adjudication, ReviewError> {
    request.candidates.validate()?;
    let candidate_ids: BTreeSet<FindingId> = request
        .candidates
        .candidates
        .iter()
        .map(|item| item.candidate_id.clone())
        .collect();
    let evidence_ids = request.candidates.evidence_ids();
    let mut results = Vec::new();
    let mut providers = Vec::new();
    let mut gaps = Vec::new();
    let mut adjudicators = BTreeSet::new();
    for outcome in &request.outcomes {
        match outcome {
            ProviderOutcome::Judgment(judgment) => {
                judgment.validate()?;
                providers.push(judgment.metadata.clone());
                if !candidate_ids.contains(&judgment.candidate_id) {
                    return Err(ReviewError::UnknownCandidate(
                        judgment.candidate_id.to_string(),
                    ));
                }
                for evidence in &judgment.evidence_ids {
                    if !evidence_ids.contains(evidence) {
                        return Err(ReviewError::UnknownEvidence(evidence.clone()));
                    }
                }
                if !adjudicators.insert((
                    judgment.candidate_id.clone(),
                    judgment.adjudicator_id.clone(),
                )) {
                    return Err(ReviewError::Duplicate(judgment.adjudicator_id.clone()));
                }
                results.push(AdjudicatedResult::from(judgment));
            }
            ProviderOutcome::Failure { metadata, gap } => {
                metadata.validate()?;
                providers.push(metadata.clone());
                let gap = if gap.trim().is_empty() {
                    format!("provider {} failed", metadata.provider)
                } else {
                    gap.clone()
                };
                gaps.push(format!("{}: {gap}", metadata.provider));
            }
        }
    }
    results.sort_by(|left, right| {
        left.candidate_id
            .cmp(&right.candidate_id)
            .then(left.adjudicator_id.cmp(&right.adjudicator_id))
    });
    gaps.sort();
    gaps.dedup();
    providers.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then(left.model.cmp(&right.model))
            .then(left.route.cmp(&right.route))
    });
    providers.dedup();
    Ok(Adjudication {
        schema_version: 1,
        request_id: request.request_id,
        review_id: request.candidates.review_id,
        candidates: request.candidates.candidates,
        results,
        providers,
        complete: gaps.is_empty(),
        gaps,
    })
}
