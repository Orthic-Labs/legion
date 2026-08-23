use std::collections::BTreeSet;

use legion_contracts::{derived_id, ReceiptId, RequestId};
use serde::{Deserialize, Serialize};

use crate::{error::ReviewError, normalize::NormalizedReview, provider::ReviewProviderMetadata};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReceipt {
    pub schema_version: u32,
    pub receipt_id: ReceiptId,
    pub request_id: RequestId,
    pub review_id: String,
    pub status: ReviewStatus,
    pub candidate_ids: Vec<String>,
    pub adjudicator_ids: Vec<String>,
    pub providers: Vec<ReviewProviderMetadata>,
    pub gaps: Vec<String>,
}

impl ReviewReceipt {
    pub fn validate(&self) -> Result<(), ReviewError> {
        if self.schema_version != 1 || self.review_id.trim().is_empty() {
            return Err(ReviewError::Receipt(
                "unsupported schema or empty review_id".into(),
            ));
        }
        if matches!(self.status, ReviewStatus::Complete) && !self.gaps.is_empty() {
            return Err(ReviewError::Receipt(
                "complete receipt cannot contain gaps".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ReviewError> {
        legion_contracts::canonical_digest(self)
            .map_err(|error| ReviewError::Receipt(error.to_string()))
    }
}

pub fn emit_receipt(
    review: &NormalizedReview,
    providers: Vec<ReviewProviderMetadata>,
) -> Result<ReviewReceipt, ReviewError> {
    let mut candidate_ids: Vec<_> = review
        .candidates
        .iter()
        .map(|candidate| candidate.candidate_id.to_string())
        .collect();
    let mut adjudicator_ids: Vec<_> = review
        .results
        .iter()
        .map(|result| result.adjudicator_id.clone())
        .collect();
    candidate_ids.sort();
    candidate_ids.dedup();
    adjudicator_ids.sort();
    adjudicator_ids.dedup();
    let mut gaps = BTreeSet::new();
    gaps.extend(review.gaps.iter().cloned());
    let mut recorded = providers;
    recorded.extend(review.providers.clone());
    recorded.extend(review.results.iter().map(|result| result.metadata.clone()));
    recorded.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then(left.model.cmp(&right.model))
            .then(left.route.cmp(&right.route))
    });
    recorded.dedup();
    for provider in &recorded {
        provider.validate()?;
    }
    let status = if review.complete {
        ReviewStatus::Complete
    } else if review.results.is_empty() {
        ReviewStatus::Failed
    } else {
        ReviewStatus::Partial
    };
    let draft = ReviewReceipt {
        schema_version: 1,
        receipt_id: ReceiptId::new("pending")?,
        request_id: review.request_id.clone(),
        review_id: review.review_id.clone(),
        status,
        candidate_ids,
        adjudicator_ids,
        providers: recorded,
        gaps: gaps.into_iter().collect(),
    };
    let bytes = legion_contracts::canonical_json_bytes(&draft)
        .map_err(|error| ReviewError::Receipt(error.to_string()))?;
    let id =
        derived_id::<ReceiptId>(&bytes).map_err(|error| ReviewError::Receipt(error.to_string()))?;
    let receipt = ReviewReceipt {
        receipt_id: id,
        ..draft
    };
    receipt.validate()?;
    Ok(receipt)
}
