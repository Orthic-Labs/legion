use std::collections::BTreeMap;

use legion_contracts::{BudgetCeiling, FindingId, ProviderId};
use legion_provider_sdk::{HostInference, InferenceClient, InferenceRequest, InferenceResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ReviewError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewProviderMetadata {
    pub provider: ProviderId,
    pub provider_version: String,
    pub model: String,
    pub model_version: Option<String>,
    pub evidence_pack: String,
    pub route: String,
    pub budget: BudgetCeiling,
}

impl ReviewProviderMetadata {
    pub fn validate(&self) -> Result<(), ReviewError> {
        for (field, value) in [
            ("provider_version", &self.provider_version),
            ("model", &self.model),
            ("evidence_pack", &self.evidence_pack),
            ("route", &self.route),
        ] {
            if value.trim().is_empty() {
                return Err(ReviewError::Invalid(format!("{field} must be non-empty")));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderJudgment {
    pub adjudicator_id: String,
    pub candidate_id: FindingId,
    pub evidence_ids: Vec<String>,
    pub verdict: String,
    pub rationale: String,
    pub metadata: ReviewProviderMetadata,
    pub details: BTreeMap<String, Value>,
}

impl ProviderJudgment {
    pub fn validate(&self) -> Result<(), ReviewError> {
        if self.adjudicator_id.trim().is_empty() || self.verdict.trim().is_empty() {
            return Err(ReviewError::Invalid(
                "adjudicator_id and verdict must be non-empty".into(),
            ));
        }
        self.metadata.validate()
    }

    pub fn from_response(
        adjudicator_id: impl Into<String>,
        candidate_id: FindingId,
        evidence_ids: Vec<String>,
        metadata: ReviewProviderMetadata,
        response: &InferenceResponse,
    ) -> Result<Self, ReviewError> {
        let parsed = serde_json::from_str::<Value>(&response.text)
            .map_err(|error| ReviewError::Provider(format!("malformed judgment JSON: {error}")))?;
        let object = parsed
            .as_object()
            .ok_or_else(|| ReviewError::Provider("judgment must be a JSON object".into()))?;
        let verdict = object
            .get("verdict")
            .and_then(Value::as_str)
            .ok_or_else(|| ReviewError::Provider("judgment verdict is missing".into()))?;
        let rationale = object
            .get("rationale")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let details = object
            .iter()
            .filter(|(key, _)| *key != "verdict" && *key != "rationale")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let judgment = Self {
            adjudicator_id: adjudicator_id.into(),
            candidate_id,
            evidence_ids,
            verdict: verdict.to_owned(),
            rationale,
            metadata,
            details,
        };
        judgment.validate()?;
        Ok(judgment)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProviderOutcome {
    Judgment(ProviderJudgment),
    Failure {
        metadata: ReviewProviderMetadata,
        gap: String,
    },
}

impl ProviderOutcome {
    pub fn failure(metadata: ReviewProviderMetadata, gap: impl Into<String>) -> Self {
        Self::Failure {
            metadata,
            gap: gap.into(),
        }
    }
}

/// Runs an injected LEG-027 inference client. No process or interpreter path
/// is available here; response parsing remains inside the review boundary.
pub async fn infer_judgment(
    client: &dyn InferenceClient,
    request: InferenceRequest,
    adjudicator_id: impl Into<String>,
    candidate_id: FindingId,
    evidence_ids: Vec<String>,
    metadata: ReviewProviderMetadata,
) -> Result<ProviderJudgment, ReviewError> {
    request
        .validate()
        .map_err(|error| ReviewError::Provider(error.to_string()))?;
    let response = client
        .infer(request)
        .await
        .map_err(|error| ReviewError::Provider(error.to_string()))?;
    ProviderJudgment::from_response(
        adjudicator_id,
        candidate_id,
        evidence_ids,
        metadata,
        &response,
    )
}

pub async fn infer_with_host(
    client: HostInference,
    request: InferenceRequest,
    adjudicator_id: impl Into<String>,
    candidate_id: FindingId,
    evidence_ids: Vec<String>,
    metadata: ReviewProviderMetadata,
) -> Result<ProviderJudgment, ReviewError> {
    infer_judgment(
        client.as_ref(),
        request,
        adjudicator_id,
        candidate_id,
        evidence_ids,
        metadata,
    )
    .await
}
