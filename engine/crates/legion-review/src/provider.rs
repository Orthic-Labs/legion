use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{BudgetCeiling, FindingId, ProviderId};
use legion_provider_sdk::{HostInference, InferenceClient, InferenceRequest, InferenceResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ReviewError;

/// Verdict vocabulary for a reviewer response.  Unknown model text is
/// normalized to `Unknown` instead of being treated as a successful verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewVerdict {
    Confirmed,
    Rejected,
    Unproven,
    NeedsHuman,
    Unknown,
}

impl ReviewVerdict {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "confirmed" | "confirm" => Self::Confirmed,
            "rejected" | "reject" => Self::Rejected,
            "unproven" | "unproved" => Self::Unproven,
            "needs-human" | "needs_human" | "needs human" => Self::NeedsHuman,
            "unknown" => Self::Unknown,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::Unproven => "unproven",
            Self::NeedsHuman => "needs-human",
            Self::Unknown => "unknown",
        }
    }
}

pub fn normalize_verdict(value: &str) -> Result<String, ReviewError> {
    if value.trim().is_empty() {
        return Err(ReviewError::Invalid("verdict must be non-empty".into()));
    }
    Ok(ReviewVerdict::parse(value).as_str().into())
}

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
        if self
            .model_version
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ReviewError::Invalid(
                "model_version must be non-empty when supplied".into(),
            ));
        }
        if self.budget.max_active_time_ms == 0 {
            return Err(ReviewError::Invalid(
                "provider review budget requires a positive active-time bound".into(),
            ));
        }
        Ok(())
    }

    pub fn identity_key(&self) -> String {
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.provider,
            self.provider_version,
            self.model,
            self.model_version.as_deref().unwrap_or_default(),
            self.evidence_pack,
            self.route,
            self.budget.max_active_time_ms,
            self.budget.max_cost_micros,
            self.budget.max_output_bytes
        )
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
        if self.adjudicator_id.trim().is_empty()
            || self.verdict.trim().is_empty()
            || self.rationale.trim().is_empty()
        {
            return Err(ReviewError::Invalid(
                "adjudicator_id, verdict, and rationale must be non-empty".into(),
            ));
        }
        self.metadata.validate()?;
        if self.evidence_ids.is_empty() {
            return Err(ReviewError::Invalid(
                "provider judgment must reference evidence".into(),
            ));
        }
        let mut evidence_ids = BTreeSet::new();
        for evidence_id in &self.evidence_ids {
            if evidence_id.trim().is_empty() {
                return Err(ReviewError::Invalid(
                    "provider judgment evidence ids must be non-empty".into(),
                ));
            }
            if !evidence_ids.insert(evidence_id) {
                return Err(ReviewError::Duplicate(evidence_id.clone()));
            }
        }
        Ok(())
    }

    pub fn from_response(
        adjudicator_id: impl Into<String>,
        candidate_id: FindingId,
        evidence_ids: Vec<String>,
        metadata: ReviewProviderMetadata,
        response: &InferenceResponse,
    ) -> Result<Self, ReviewError> {
        if !response.model.trim().is_empty() && response.model != metadata.model {
            return Err(ReviewError::Provenance(format!(
                "response model {} does not match provider metadata {}",
                response.model, metadata.model
            )));
        }
        let parsed = serde_json::from_str::<Value>(response.text.trim())
            .map_err(|error| ReviewError::Provider(format!("malformed judgment JSON: {error}")))?;
        let object = parsed
            .as_object()
            .ok_or_else(|| ReviewError::Provider("judgment must be a JSON object".into()))?;
        let raw_verdict = object
            .get("verdict")
            .and_then(Value::as_str)
            .ok_or_else(|| ReviewError::Provider("judgment verdict is missing".into()))?;
        let verdict = normalize_verdict(raw_verdict)?;
        let rationale = object
            .get("rationale")
            .and_then(Value::as_str)
            .ok_or_else(|| ReviewError::Provider("judgment rationale is missing".into()))?
            .to_owned();
        if rationale.trim().is_empty() {
            return Err(ReviewError::Provider(
                "judgment rationale is missing or empty".into(),
            ));
        }
        let details = object
            .iter()
            .filter(|(key, _)| *key != "verdict" && *key != "rationale")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let judgment = Self {
            adjudicator_id: adjudicator_id.into(),
            candidate_id,
            evidence_ids,
            verdict,
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

    pub fn validate(&self) -> Result<(), ReviewError> {
        match self {
            Self::Judgment(judgment) => judgment.validate(),
            Self::Failure { metadata, gap } => {
                metadata.validate()?;
                if gap.trim().is_empty() {
                    return Err(ReviewError::Invalid(
                        "provider failure must disclose a gap".into(),
                    ));
                }
                Ok(())
            }
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
    if request.cancellation.is_cancelled() {
        return Err(ReviewError::Cancelled);
    }
    request
        .validate()
        .map_err(|error| ReviewError::Provider(error.to_string()))?;
    let cancellation = request.cancellation.clone();
    let response = match client.infer(request).await {
        Ok(response) => response,
        Err(_error) if cancellation.is_cancelled() => return Err(ReviewError::Cancelled),
        Err(error) => return Err(ReviewError::Provider(error.to_string())),
    };
    if cancellation.is_cancelled() {
        return Err(ReviewError::Cancelled);
    }
    ProviderJudgment::from_response(
        adjudicator_id,
        candidate_id,
        evidence_ids,
        metadata,
        &response,
    )
}

/// Convert provider failure into a typed outcome so callers can always issue
/// a terminal receipt.  A host or model failure never becomes an empty pass.
pub async fn infer_outcome(
    client: &dyn InferenceClient,
    request: InferenceRequest,
    adjudicator_id: impl Into<String>,
    candidate_id: FindingId,
    evidence_ids: Vec<String>,
    metadata: ReviewProviderMetadata,
) -> ProviderOutcome {
    match infer_judgment(
        client,
        request,
        adjudicator_id,
        candidate_id,
        evidence_ids,
        metadata.clone(),
    )
    .await
    {
        Ok(judgment) => ProviderOutcome::Judgment(judgment),
        Err(error) => ProviderOutcome::failure(metadata, error.to_string()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(provider: &str) -> ReviewProviderMetadata {
        ReviewProviderMetadata {
            provider: ProviderId::new(provider).unwrap(),
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
    fn unsupported_verdict_is_honestly_unknown() {
        assert_eq!(normalize_verdict("confirmed").unwrap(), "confirmed");
        assert_eq!(
            normalize_verdict("unexpected-model-output").unwrap(),
            "unknown"
        );
    }

    #[test]
    fn missing_rationale_is_provider_failure() {
        let response = InferenceResponse {
            text: r#"{"verdict":"confirmed"}"#.into(),
            model: "model".into(),
            finish_reason: None,
            usage: legion_provider_sdk::inference::InferenceUsage::default(),
        };
        let result = ProviderJudgment::from_response(
            "reviewer",
            FindingId::new("finding-1").unwrap(),
            vec!["evidence-1".into()],
            metadata("provider-a"),
            &response,
        );
        assert!(matches!(result, Err(ReviewError::Provider(_))));
    }
}
