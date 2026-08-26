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

#[allow(clippy::too_many_arguments)]
fn terminal_unproven(
    query: String,
    failures: Vec<legion_research::SourceFailure>,
    available_source_records: usize,
    independent_provider_count: usize,
    required_independent_providers: usize,
    external_requests: usize,
    route: &legion_research::ResearchRoute,
    authorization: &legion_research::ResearchAuthorization,
    selected_provider_denominator: usize,
) -> CommandResult {
    let report = legion_research::ResearchReport::terminal_unproven(query.clone(), failures)
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    let budget = legion_research::BudgetSnapshot {
        limits: legion_research::BudgetLimits::default(),
        usage: legion_research::BudgetUsage::default(),
    };
    let stages = vec![
        legion_research::StageRecord {
            stage: legion_research::WorkflowStage::Created,
            completed: true,
            detail: Some(format!(
                "route_frozen:{};allowed_effects:{};effect_grant:{};approval_receipts:{};selected_provider_denominator:{}",
                route.digest().map_err(|error| super::CommandError::incomplete(error.to_string()))?,
                route.allowed_effects.join(","),
                authorization.effect_grant.join(","),
                if route.human_gates.is_empty() { "not-required" } else { "missing" },
                selected_provider_denominator
            )),
        },
        legion_research::StageRecord {
            stage: legion_research::WorkflowStage::Unproven,
            completed: true,
            detail: Some("required_host_evidence_unavailable_or_provider_denominator_unmet".into()),
        },
    ];
    let receipt = legion_research::ResearchReceipt::from_terminal_bound(
        &report,
        budget,
        stages,
        available_source_records as u64,
        external_requests as u64,
        route,
        authorization,
        selected_provider_denominator as u64,
    )
    .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-research",
        "status": "unproven",
        "verdict": "UNPROVEN",
        "incomplete": true,
        "query": query,
        "route": route,
        "availableSourceRecords": available_source_records,
        "independentProviders": independent_provider_count,
        "requiredIndependentProviders": required_independent_providers,
        "failures": report.omissions.clone(),
        "externalRequests": receipt.external_requests,
        "report": report,
        "receipt": receipt,
    }))
}

fn terminal_cancelled(
    query: String,
    route: &legion_research::ResearchRoute,
    authorization: &legion_research::ResearchAuthorization,
    selected_provider_denominator: usize,
) -> CommandResult {
    let report = legion_research::ResearchReport::terminal_cancelled(query.clone())
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    let budget = legion_research::BudgetSnapshot {
        limits: legion_research::BudgetLimits::default(),
        usage: legion_research::BudgetUsage::default(),
    };
    let stages = vec![
        legion_research::StageRecord {
            stage: legion_research::WorkflowStage::Created,
            completed: true,
            detail: Some(format!(
                "route_frozen:{};allowed_effects:{};effect_grant:{};approval_receipts:not-required;selected_provider_denominator:{}",
                route.digest().map_err(|error| super::CommandError::incomplete(error.to_string()))?,
                route.allowed_effects.join(","),
                authorization.effect_grant.join(","),
                selected_provider_denominator
            )),
        },
        legion_research::StageRecord {
            stage: legion_research::WorkflowStage::Cancelled,
            completed: true,
            detail: Some("caller_cancellation_observed".into()),
        },
    ];
    let receipt = legion_research::ResearchReceipt::from_terminal_bound(
        &report,
        budget,
        stages,
        0,
        0,
        route,
        authorization,
        selected_provider_denominator as u64,
    )
    .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-research",
        "status": "cancelled",
        "incomplete": true,
        "query": query,
        "route": route,
        "verdict": "CANCELLED",
        "failures": report.omissions.clone(),
        "externalRequests": 0,
        "report": report,
        "receipt": receipt,
    }))
}

pub fn run(args: ResearchArgs, cancellation: CancellationToken) -> CommandResult {
    let route = legion_research::ResearchRoute::host_injected(&args.query);
    route
        .validate()
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    let authorization = legion_research::ResearchAuthorization::full(&route)
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    let requested_provider_denominator = args
        .provider
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        .max(1);
    if cancellation.is_cancelled() {
        return terminal_cancelled(
            args.query,
            &route,
            &authorization,
            requested_provider_denominator,
        );
    }
    let mut records = BTreeMap::<String, Vec<legion_research::SourceRecord>>::new();
    let mut failures = Vec::new();
    for path in &args.source_records {
        if cancellation.is_cancelled() {
            let selected_provider_denominator = if args.provider.is_empty() {
                records.len().max(1)
            } else {
                requested_provider_denominator
            };
            return terminal_cancelled(
                args.query.clone(),
                &route,
                &authorization,
                selected_provider_denominator,
            );
        }
        let source = match std::fs::read(path)
            .map_err(super::io_error)
            .and_then(|bytes| {
                serde_json::from_slice::<legion_research::SourceRecord>(&bytes).map_err(|error| {
                    super::CommandError::usage(format!("invalid source record: {error}"))
                })
            }) {
            Ok(source) => source,
            Err(error) => {
                failures.push(legion_research::SourceFailure {
                    provider: path.display().to_string(),
                    stage: legion_research::WorkflowStage::Discovering,
                    reason: format!("host source record unavailable: {}", error.message),
                });
                continue;
            }
        };
        if let Err(error) = source.validate() {
            failures.push(legion_research::SourceFailure {
                provider: source.provider.clone(),
                stage: legion_research::WorkflowStage::Discovering,
                reason: format!("host source record rejected: {error}"),
            });
            continue;
        }
        records
            .entry(source.provider.clone())
            .or_default()
            .push(source);
    }
    if records.is_empty() {
        failures.push(legion_research::SourceFailure {
            provider: "host-injected-sources".into(),
            stage: legion_research::WorkflowStage::Discovering,
            reason: "required host-injected source records are unavailable".into(),
        });
        return terminal_unproven(
            args.query,
            failures,
            0,
            0,
            args.min_independent_providers,
            0,
            &route,
            &authorization,
            args.provider
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                .max(1),
        );
    }

    let providers = if args.provider.is_empty() {
        records
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
    } else {
        args.provider
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    };
    let independent_provider_count = providers
        .iter()
        .filter(|provider| records.contains_key(*provider))
        .count();
    if independent_provider_count < args.min_independent_providers {
        failures.push(legion_research::SourceFailure {
            provider: "provider-denominator".into(),
            stage: legion_research::WorkflowStage::Discovering,
            reason: "independent source-provider requirement is unmet".into(),
        });
        return terminal_unproven(
            args.query,
            failures,
            records.values().flatten().count(),
            independent_provider_count,
            args.min_independent_providers,
            records
                .values()
                .flatten()
                .filter(|source| source.metadata.contains_key("request_receipt"))
                .count(),
            &route,
            &authorization,
            providers.len(),
        );
    }
    let providers = providers.into_iter().collect::<Vec<_>>();
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
    let workflow_cancellation = legion_research::Cancellation::from_probe({
        let caller = cancellation.clone();
        move || caller.is_cancelled()
    });
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
    let outcome = workflow.run_with_route(request.clone(), route.clone(), authorization.clone());
    let outcome = outcome.map_err(|error| super::CommandError::incomplete(error.to_string()))?;
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
        "incomplete": outcome.status != legion_research::WorkflowStatus::Ok,
        "request": request,
        "route": route,
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
