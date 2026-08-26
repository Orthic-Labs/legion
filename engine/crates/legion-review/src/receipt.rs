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
    #[serde(default)]
    pub review_digest: String,
    pub status: ReviewStatus,
    pub candidate_ids: Vec<String>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    pub adjudicator_ids: Vec<String>,
    pub providers: Vec<ReviewProviderMetadata>,
    pub gaps: Vec<String>,
}

impl ReviewReceipt {
    pub fn omissions(&self) -> &[String] {
        &self.gaps
    }

    pub fn validate(&self) -> Result<(), ReviewError> {
        if self.schema_version != 1
            || self.review_id.trim().is_empty()
            || self.review_digest.trim().is_empty()
            || self.candidate_ids.iter().any(|id| id.trim().is_empty())
            || self.evidence_ids.iter().any(|id| id.trim().is_empty())
            || self.adjudicator_ids.iter().any(|id| id.trim().is_empty())
        {
            return Err(ReviewError::Receipt(
                "unsupported schema or empty receipt identity".into(),
            ));
        }
        if matches!(self.status, ReviewStatus::Complete) && !self.gaps.is_empty() {
            return Err(ReviewError::Receipt(
                "complete receipt cannot contain gaps".into(),
            ));
        }
        if matches!(self.status, ReviewStatus::Complete)
            && (self.candidate_ids.is_empty()
                || self.evidence_ids.is_empty()
                || self.adjudicator_ids.is_empty())
        {
            return Err(ReviewError::Receipt(
                "complete receipt requires candidates and independent adjudicators".into(),
            ));
        }
        if !matches!(self.status, ReviewStatus::Complete) && self.gaps.is_empty() {
            return Err(ReviewError::Receipt(
                "incomplete receipt must disclose omissions or failure gaps".into(),
            ));
        }
        for provider in &self.providers {
            provider.validate()?;
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
    let mut evidence_ids: Vec<_> = review
        .candidates
        .iter()
        .map(|candidate| candidate.evidence_id.clone())
        .collect();
    candidate_ids.sort();
    candidate_ids.dedup();
    evidence_ids.sort();
    evidence_ids.dedup();
    adjudicator_ids.sort();
    adjudicator_ids.dedup();
    let mut gaps = BTreeSet::new();
    gaps.extend(review.gaps.iter().cloned());
    let mut recorded = providers;
    recorded.extend(review.providers.clone());
    recorded.extend(review.results.iter().map(|result| result.metadata.clone()));
    recorded.sort_by_key(ReviewProviderMetadata::identity_key);
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
        review_digest: review.digest()?,
        status,
        candidate_ids,
        evidence_ids,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjudication::AdjudicatedResult;
    use crate::candidate::{CandidateClass, CandidateEvidence};
    use crate::provider::ReviewProviderMetadata;
    use legion_contracts::{BudgetCeiling, FindingId, ProviderId, RequestId};
    use std::collections::BTreeMap;

    fn provider() -> ReviewProviderMetadata {
        ReviewProviderMetadata {
            provider: ProviderId::new("provider-a").unwrap(),
            provider_version: "1".into(),
            model: "model".into(),
            model_version: None,
            evidence_pack: "pack".into(),
            route: "host".into(),
            budget: BudgetCeiling {
                max_active_time_ms: 1000,
                ..BudgetCeiling::default()
            },
        }
    }

    #[test]
    fn failed_review_always_has_terminal_gap() {
        let receipt = emit_receipt(
            &NormalizedReview {
                schema_version: 1,
                request_id: RequestId::new("request").unwrap(),
                review_id: "review".into(),
                candidates: vec![CandidateEvidence {
                    candidate_id: FindingId::new("finding").unwrap(),
                    evidence_id: "evidence".into(),
                    class: CandidateClass::Observed,
                    source_revision: "git:abc".into(),
                    title: "finding".into(),
                    severity: "low".into(),
                    message: "message".into(),
                    locations: vec!["src/lib.rs:1".into()],
                    facts: BTreeMap::new(),
                }],
                results: Vec::<AdjudicatedResult>::new(),
                providers: vec![provider()],
                gaps: vec!["provider unavailable".into()],
                complete: false,
            },
            Vec::new(),
        )
        .unwrap();
        assert_eq!(receipt.status, ReviewStatus::Failed);
        assert!(receipt.validate().is_ok());
        assert!(!receipt.gaps.is_empty());
    }
}
