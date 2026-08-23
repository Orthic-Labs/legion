use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    adjudication::{AdjudicatedResult, Adjudication},
    error::ReviewError,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedReview {
    pub schema_version: u32,
    pub request_id: legion_contracts::RequestId,
    pub review_id: String,
    pub candidates: Vec<crate::candidate::CandidateEvidence>,
    pub results: Vec<AdjudicatedResult>,
    pub providers: Vec<crate::provider::ReviewProviderMetadata>,
    pub gaps: Vec<String>,
    pub complete: bool,
}

pub fn normalize(mut adjudication: Adjudication) -> Result<NormalizedReview, ReviewError> {
    if adjudication.schema_version != 1 {
        return Err(ReviewError::Invalid(
            "unsupported adjudication schema".into(),
        ));
    }
    adjudication
        .candidates
        .sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    adjudication.results.sort_by(|left, right| {
        left.candidate_id
            .cmp(&right.candidate_id)
            .then(left.adjudicator_id.cmp(&right.adjudicator_id))
    });
    let mut gaps = BTreeSet::new();
    gaps.extend(adjudication.gaps);
    Ok(NormalizedReview {
        schema_version: 1,
        request_id: adjudication.request_id,
        review_id: adjudication.review_id,
        candidates: adjudication.candidates,
        results: adjudication.results,
        providers: adjudication.providers,
        complete: gaps.is_empty() && adjudication.complete,
        gaps: gaps.into_iter().collect(),
    })
}
