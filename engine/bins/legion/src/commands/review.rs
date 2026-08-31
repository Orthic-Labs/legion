use super::CommandResult;
use clap::Args;
use legion_contracts::{BudgetCeiling, ProviderId};
use legion_provider_sdk::{
    http_client::{HttpInferenceClient, HttpInferenceConfig},
    EnvironmentSecretProvider, InferenceRequest, ScopedCredentialAuthorizer,
};
use serde_json::json;
use std::fs;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const AUTHORIZED_PROVIDER_ENV: &str = "LEGION_AUTHORIZED_CREDENTIAL_PROVIDER";
const PROVIDER_BEARER_TOKEN_ENV: &str = "LEGION_PROVIDER_BEARER_TOKEN";

#[derive(Debug, Args)]
pub struct ReviewArgs {
    #[arg(long)]
    pub input: Option<String>,
    #[arg(long)]
    pub json: bool,
    /// OpenAI-compatible endpoint for an independently authorized reviewer.
    #[arg(long)]
    pub provider_endpoint: Option<String>,
    /// Provider identity required to match Guard-projected credential scope.
    #[arg(long)]
    pub provider_id: Option<String>,
    /// Model used by the authorized review provider.
    #[arg(long)]
    pub provider_model: Option<String>,
    /// Bounded active time for each provider judgment.
    #[arg(long, default_value_t = 60_000)]
    pub provider_timeout_ms: u64,
}

pub async fn run(args: ReviewArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(super::CommandError::cancelled());
    }
    let input = args
        .input
        .ok_or_else(|| super::CommandError::usage("review requires --input <request.json>"))?;
    let bytes = fs::read(&input).map_err(super::io_error)?;
    let mut request: legion_review::AdjudicationRequest = serde_json::from_slice(&bytes)
        .map_err(|error| super::CommandError::usage(format!("invalid review request: {error}")))?;
    let mut credential_receipt = None;
    if let Some(endpoint) = args.provider_endpoint {
        let provider_id = args.provider_id.ok_or_else(|| {
            super::CommandError::usage("--provider-endpoint requires --provider-id")
        })?;
        let model = args.provider_model.ok_or_else(|| {
            super::CommandError::usage("--provider-endpoint requires --provider-model")
        })?;
        if args.provider_timeout_ms == 0 {
            return Err(super::CommandError::usage(
                "--provider-timeout-ms must be greater than zero",
            ));
        }
        let authorized_provider = std::env::var(AUTHORIZED_PROVIDER_ENV).map_err(|_| {
            super::CommandError::incomplete(format!(
                "Guard credential scope is unavailable; inject {AUTHORIZED_PROVIDER_ENV} for this execution"
            ))
        })?;
        let secrets = EnvironmentSecretProvider::new(PROVIDER_BEARER_TOKEN_ENV)
            .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
        let authorizer = ScopedCredentialAuthorizer::new(authorized_provider)
            .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
        let (client, receipt) = HttpInferenceClient::authorized(
            HttpInferenceConfig::new(endpoint),
            &provider_id,
            &secrets,
            &authorizer,
        )
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
        let provider = ProviderId::new(provider_id.clone())
            .map_err(|error| super::CommandError::usage(error.to_string()))?;
        let metadata = legion_review::ReviewProviderMetadata {
            provider,
            provider_version: "http-v1".into(),
            model: model.clone(),
            model_version: None,
            evidence_pack: request.candidates.evidence_pack.clone(),
            route: "authorized-http".into(),
            budget: BudgetCeiling {
                max_active_time_ms: args.provider_timeout_ms,
                ..BudgetCeiling::default()
            },
        };
        for candidate in request.candidates.candidates.clone() {
            if cancellation.is_cancelled() {
                return Err(super::CommandError::cancelled());
            }
            let user = serde_json::to_string(&candidate)
                .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
            let mut inference = InferenceRequest::new(
                model.clone(),
                "Return one JSON object with verdict and rationale for this evidence-bound review candidate.",
                user,
                Instant::now() + Duration::from_millis(args.provider_timeout_ms),
            )
            .with_attribution(request.candidates.review_id.clone(), candidate.candidate_id.to_string());
            inference.cancellation = cancellation.clone();
            let outcome = legion_review::infer_outcome(
                &client,
                inference,
                provider_id.clone(),
                candidate.candidate_id,
                vec![candidate.evidence_id],
                metadata.clone(),
            )
            .await;
            request.outcomes.push(outcome);
        }
        credential_receipt = Some(json!({
            "providerId": receipt.provider_id,
            "effect": receipt.effect,
            "auth": {"scheme": receipt.auth.scheme, "present": receipt.auth.present}
        }));
    } else if args.provider_id.is_some() || args.provider_model.is_some() {
        return Err(super::CommandError::usage(
            "--provider-id and --provider-model require --provider-endpoint",
        ));
    }
    let (normalized, receipt) = legion_review::review(request, Vec::new())
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    if cancellation.is_cancelled() {
        return Err(super::CommandError::cancelled());
    }
    let status = if normalized.complete {
        "complete"
    } else {
        "incomplete"
    };
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-review",
        "status": status,
        "review": normalized,
        "receipt": receipt,
        "credentialReceipt": credential_receipt
    }))
}
