use std::collections::BTreeSet;

use legion_contracts::{FindingId, RequestId};
use serde::{Deserialize, Serialize};

use crate::{
    candidate::{CandidateEnvelope, CandidateEvidence},
    error::ReviewError,
    provider::{
        normalize_verdict, ProviderJudgment, ProviderOutcome, ReviewProviderMetadata, ReviewVerdict,
    },
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

impl Adjudication {
    /// Gaps are the packet's explicit omissions; an empty list is only
    /// meaningful after every candidate has an independent judgment.
    pub fn omissions(&self) -> &[String] {
        &self.gaps
    }
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
                let mut judgment = judgment.clone();
                if judgment.rationale.trim().is_empty() {
                    judgment.metadata.validate()?;
                    if judgment.metadata.evidence_pack != request.candidates.evidence_pack {
                        return Err(ReviewError::Provenance(format!(
                            "provider {} evidence pack does not match review packet",
                            judgment.metadata.provider
                        )));
                    }
                    providers.push(judgment.metadata.clone());
                    gaps.push(format!(
                        "{}: provider judgment rationale is missing",
                        judgment.metadata.provider
                    ));
                    continue;
                }
                outcome.validate()?;
                judgment.verdict = normalize_verdict(&judgment.verdict)?;
                judgment.validate()?;
                providers.push(judgment.metadata.clone());
                if !candidate_ids.contains(&judgment.candidate_id) {
                    return Err(ReviewError::UnknownCandidate(
                        judgment.candidate_id.to_string(),
                    ));
                }
                let Some(candidate) = request.candidates.candidate(&judgment.candidate_id) else {
                    return Err(ReviewError::UnknownCandidate(
                        judgment.candidate_id.to_string(),
                    ));
                };
                if judgment.metadata.evidence_pack != request.candidates.evidence_pack {
                    return Err(ReviewError::Provenance(format!(
                        "provider {} evidence pack does not match review packet",
                        judgment.metadata.provider
                    )));
                }
                if candidate
                    .producer_provider()
                    .is_some_and(|producer| producer == judgment.metadata.provider.as_str())
                {
                    return Err(ReviewError::SelfClosure(
                        judgment.metadata.provider.to_string(),
                    ));
                }
                for evidence in &judgment.evidence_ids {
                    if !evidence_ids.contains(evidence) {
                        return Err(ReviewError::UnknownEvidence(evidence.clone()));
                    }
                }
                if !judgment
                    .evidence_ids
                    .iter()
                    .any(|evidence| evidence == &candidate.evidence_id)
                {
                    return Err(ReviewError::Provenance(format!(
                        "judgment for candidate {} does not cite candidate evidence {}",
                        candidate.candidate_id, candidate.evidence_id
                    )));
                }
                if !adjudicators.insert((
                    judgment.candidate_id.clone(),
                    judgment.adjudicator_id.clone(),
                )) {
                    return Err(ReviewError::Duplicate(judgment.adjudicator_id.clone()));
                }
                if matches!(
                    ReviewVerdict::parse(&judgment.verdict),
                    ReviewVerdict::Unknown
                ) {
                    gaps.push(format!(
                        "candidate {} returned unknown verdict",
                        judgment.candidate_id
                    ));
                }
                results.push(AdjudicatedResult::from(&judgment));
            }
            ProviderOutcome::Failure { metadata, gap } => {
                outcome.validate()?;
                if metadata.evidence_pack != request.candidates.evidence_pack {
                    return Err(ReviewError::Provenance(format!(
                        "provider {} evidence pack does not match review packet",
                        metadata.provider
                    )));
                }
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

    // An omitted outcome is an omission, never an implicit pass.  A model
    // generated candidate is also never allowed to close itself through this
    // deterministic protocol.
    for candidate in &request.candidates.candidates {
        let reviewed = results
            .iter()
            .any(|result| result.candidate_id == candidate.candidate_id);
        if !reviewed {
            gaps.push(format!(
                "candidate {} has no independent provider judgment",
                candidate.candidate_id
            ));
        }
    }
    results.sort_by(|left, right| {
        left.candidate_id
            .cmp(&right.candidate_id)
            .then(left.adjudicator_id.cmp(&right.adjudicator_id))
    });
    gaps.sort();
    gaps.dedup();
    providers.sort_by_key(ReviewProviderMetadata::identity_key);
    providers.dedup();
    gaps.sort();
    gaps.dedup();
    let complete = !results.is_empty()
        && gaps.is_empty()
        && request.candidates.candidates.iter().all(|candidate| {
            results.iter().any(|result| {
                result.candidate_id == candidate.candidate_id
                    && !matches!(
                        ReviewVerdict::parse(&result.verdict),
                        ReviewVerdict::Unknown
                    )
            })
        });
    Ok(Adjudication {
        schema_version: 1,
        request_id: request.request_id,
        review_id: request.candidates.review_id,
        candidates: request.candidates.candidates,
        results,
        providers,
        complete,
        gaps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::CandidateClass;
    use crate::provider::ReviewProviderMetadata;
    use legion_contracts::BudgetCeiling;
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn candidate(class: CandidateClass, facts: BTreeMap<String, Value>) -> CandidateEvidence {
        CandidateEvidence {
            candidate_id: FindingId::new("finding-1").unwrap(),
            evidence_id: "evidence-1".into(),
            class,
            source_revision: "git:abc".into(),
            title: "Finding".into(),
            severity: "high".into(),
            message: "Observed fact".into(),
            locations: vec!["src/lib.rs:10".into()],
            facts,
        }
    }

    fn metadata(provider: &str) -> ReviewProviderMetadata {
        ReviewProviderMetadata {
            provider: legion_contracts::ProviderId::new(provider).unwrap(),
            provider_version: "1".into(),
            model: "review-model".into(),
            model_version: Some("1".into()),
            evidence_pack: "pack-1".into(),
            route: "host".into(),
            budget: BudgetCeiling {
                max_active_time_ms: 1000,
                ..BudgetCeiling::default()
            },
        }
    }

    fn request(
        candidate: CandidateEvidence,
        outcomes: Vec<ProviderOutcome>,
    ) -> AdjudicationRequest {
        AdjudicationRequest {
            request_id: RequestId::new("request-1").unwrap(),
            candidates: CandidateEnvelope {
                schema_version: 1,
                review_id: "review-1".into(),
                evidence_pack: "pack-1".into(),
                candidates: vec![candidate],
            },
            outcomes,
        }
    }

    #[test]
    fn omitted_provider_outcome_is_incomplete() {
        let result = adjudicate(request(
            candidate(CandidateClass::Observed, BTreeMap::new()),
            vec![],
        ))
        .unwrap();
        assert!(!result.complete);
        assert!(result.gaps.iter().any(|gap| gap.contains("no independent")));
    }

    #[test]
    fn unknown_verdict_is_preserved_and_not_complete() {
        let metadata = metadata("provider-a");
        let judgment = ProviderJudgment {
            adjudicator_id: "reviewer-a".into(),
            candidate_id: FindingId::new("finding-1").unwrap(),
            evidence_ids: vec!["evidence-1".into()],
            verdict: "not-in-vocabulary".into(),
            rationale: "insufficient signal".into(),
            metadata,
            details: BTreeMap::new(),
        };
        let result = adjudicate(request(
            candidate(CandidateClass::Observed, BTreeMap::new()),
            vec![ProviderOutcome::Judgment(judgment)],
        ))
        .unwrap();
        assert_eq!(result.results[0].verdict, "unknown");
        assert!(!result.complete);
    }

    #[test]
    fn missing_rationale_is_an_incomplete_provider_gap() {
        let judgment = ProviderJudgment {
            adjudicator_id: "reviewer-a".into(),
            candidate_id: FindingId::new("finding-1").unwrap(),
            evidence_ids: vec!["evidence-1".into()],
            verdict: "confirmed".into(),
            rationale: String::new(),
            metadata: metadata("provider-a"),
            details: BTreeMap::new(),
        };
        let result = adjudicate(request(
            candidate(CandidateClass::Observed, BTreeMap::new()),
            vec![ProviderOutcome::Judgment(judgment)],
        ))
        .unwrap();
        assert!(!result.complete);
        assert!(result
            .gaps
            .iter()
            .any(|gap| gap.contains("rationale is missing")));
    }

    #[test]
    fn candidate_producer_cannot_self_close() {
        let facts = BTreeMap::from([("provider".into(), Value::String("provider-a".into()))]);
        let judgment = ProviderJudgment {
            adjudicator_id: "reviewer-a".into(),
            candidate_id: FindingId::new("finding-1").unwrap(),
            evidence_ids: vec!["evidence-1".into()],
            verdict: "confirmed".into(),
            rationale: "source supports finding".into(),
            metadata: metadata("provider-a"),
            details: BTreeMap::new(),
        };
        assert!(matches!(
            adjudicate(request(
                candidate(CandidateClass::Observed, facts),
                vec![ProviderOutcome::Judgment(judgment)]
            )),
            Err(ReviewError::SelfClosure(_))
        ));
    }

    #[test]
    fn model_candidate_closes_with_independent_provider() {
        let facts =
            BTreeMap::from([("provider".into(), Value::String("producer-provider".into()))]);
        let judgment = ProviderJudgment {
            adjudicator_id: "reviewer-provider".into(),
            candidate_id: FindingId::new("finding-1").unwrap(),
            evidence_ids: vec!["evidence-1".into()],
            verdict: "confirmed".into(),
            rationale: "independent evidence supports finding".into(),
            metadata: metadata("reviewer-provider"),
            details: BTreeMap::new(),
        };
        let result = adjudicate(request(
            candidate(CandidateClass::ModelJudgment, facts),
            vec![ProviderOutcome::Judgment(judgment)],
        ))
        .unwrap();
        assert!(result.complete);
    }
}
