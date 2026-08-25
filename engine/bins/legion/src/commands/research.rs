use super::CommandResult;
use clap::Args;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct ResearchArgs {
    #[arg(long)]
    pub query: String,
    #[arg(long, value_delimiter = ',')]
    pub provider: Vec<String>,
    #[arg(long, default_value_t = 5)]
    pub max_hits: u32,
    #[arg(long = "source-record")]
    pub source_records: Vec<PathBuf>,
    #[arg(long, default_value_t = 2)]
    pub min_independent_providers: usize,
}
pub fn run(args: ResearchArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(super::CommandError::cancelled());
    }
    let mut records = BTreeMap::<String, Vec<legion_research::SourceRecord>>::new();
    for path in &args.source_records {
        let bytes = std::fs::read(path).map_err(super::io_error)?;
        let source: legion_research::SourceRecord =
            serde_json::from_slice(&bytes).map_err(|error| {
                super::CommandError::usage(format!("invalid source record: {error}"))
            })?;
        source
            .validate()
            .map_err(|error| super::CommandError::usage(error.to_string()))?;
        records
            .entry(source.provider.clone())
            .or_default()
            .push(source);
    }
    if records.is_empty() {
        return Ok(json!({
            "schemaVersion": 1,
            "kind": "legion-research",
            "status": "incomplete",
            "query": args.query,
            "failures": ["host-injected source records are required"],
            "externalRequests": 0,
        }));
    }
    let providers = if args.provider.is_empty() {
        records.keys().cloned().collect()
    } else {
        args.provider
    };
    let independent_provider_count = providers
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if independent_provider_count < args.min_independent_providers {
        return Ok(json!({
            "schemaVersion": 1,
            "kind": "legion-research",
            "status": "incomplete",
            "query": args.query,
            "independentProviders": independent_provider_count,
            "requiredIndependentProviders": args.min_independent_providers,
            "failures": ["independent source-provider requirement is unmet"],
            "externalRequests": records.values().flatten().filter(|source| source.metadata.contains_key("request_receipt")).count(),
        }));
    }
    let request = legion_research::WorkflowRequest {
        schema_version: 1,
        query: args.query,
        source_providers: providers,
        max_hits_per_provider: args.max_hits,
        max_source_bytes: 1_000_000,
    };
    request
        .validate()
        .map_err(|error| super::CommandError::usage(error.to_string()))?;
    let workflow_cancellation = legion_research::Cancellation::new();
    let mut workflow = legion_research::ResearchWorkflow::new(
        legion_research::BudgetLimits::default(),
        Instant::now() + Duration::from_secs(30),
        workflow_cancellation,
    );
    for (provider, records) in records {
        workflow
            .register(Arc::new(RecordSource { provider, records }))
            .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    }
    let outcome = workflow.run(request.clone());
    let outcome = outcome.map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    if cancellation.is_cancelled() {
        return Err(super::CommandError::cancelled());
    }
    let status = serde_json::to_value(outcome.status).map_err(super::io_error)?;
    let receipt = legion_research::ResearchReceipt::from_outcome(&outcome)
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    let external_requests = receipt.external_requests;
    let evidence = outcome.ledger.records().cloned().collect::<Vec<_>>();
    let claims = outcome.ledger.claims().cloned().collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-research",
        "status": status,
        "request": request,
        "report": outcome.report,
        "receipt": receipt,
        "externalRequests": external_requests,
        "independentProviders": independent_provider_count,
        "requiredIndependentProviders": args.min_independent_providers,
        "evidence": evidence,
        "claims": claims,
        "failures": outcome.failures,
        "budget": outcome.budget,
        "stages": outcome.stages
    }))
}

struct RecordSource {
    provider: String,
    records: Vec<legion_research::SourceRecord>,
}

impl legion_research::SourceClient for RecordSource {
    fn provider(&self) -> &str {
        &self.provider
    }

    fn estimated_bytes(&self, hit: &legion_research::SourceHit) -> u64 {
        self.records
            .iter()
            .find(|record| record.source_id == hit.source_id)
            .map(|record| record.byte_length)
            .unwrap_or(1)
    }

    fn search(
        &self,
        _: &str,
        limit: u32,
        _: Instant,
        cancellation: &legion_research::Cancellation,
    ) -> Result<Vec<legion_research::SourceHit>, legion_research::ResearchError> {
        if cancellation.is_cancelled() {
            return Err(legion_research::ResearchError::Cancelled);
        }
        Ok(self
            .records
            .iter()
            .take(limit as usize)
            .map(|record| legion_research::SourceHit {
                source_id: record.source_id.clone(),
                uri: record.uri.clone(),
                title: record.title.clone(),
                provider: record.provider.clone(),
                relevance: None,
            })
            .collect())
    }

    fn open(
        &self,
        hit: &legion_research::SourceHit,
        _: Instant,
        cancellation: &legion_research::Cancellation,
    ) -> Result<legion_research::SourceRecord, legion_research::ResearchError> {
        if cancellation.is_cancelled() {
            return Err(legion_research::ResearchError::Cancelled);
        }
        self.records
            .iter()
            .find(|record| record.source_id == hit.source_id)
            .cloned()
            .ok_or_else(|| {
                legion_research::ResearchError::InvalidSource("source hit is unavailable".into())
            })
    }
}
