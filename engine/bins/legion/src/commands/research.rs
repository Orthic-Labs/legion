use super::CommandResult;
use clap::Args;
use legion_research::research_port::{citecheck, ledger, meter, retraction};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct ResearchArgs {
    /// Route query for the host-injected search. Not required with `--step`.
    #[arg(long, required_unless_present = "step")]
    pub query: Option<String>,
    /// Run one pure Research step instead of a search: `ledger-check`,
    /// `ledger-render`, `citecheck`, `meter`, or `retraction`.
    #[arg(long)]
    pub step: Option<String>,
    /// Evidence ledger rows (JSONL) for `ledger-check` and `ledger-render`,
    /// and for `citecheck`.
    #[arg(long)]
    pub evidence: Option<PathBuf>,
    /// Claim ledger rows (JSONL) for `ledger-check` and `ledger-render`.
    #[arg(long)]
    pub claims: Option<PathBuf>,
    /// Markdown draft to bind citations for `citecheck`.
    #[arg(long)]
    pub draft: Option<PathBuf>,
    /// Output path for `ledger-render`.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Brief title for `ledger-render`.
    #[arg(long, default_value = "Research brief")]
    pub title: String,
    /// DOI list (one per line) for `retraction`.
    #[arg(long)]
    pub dois: Option<PathBuf>,
    /// DOIs already disclosed as retracted in the draft, one per line.
    #[arg(long)]
    pub disclosed: Option<PathBuf>,
    /// Let unknown retraction status pass instead of blocking.
    #[arg(long = "allow-unknown")]
    pub allow_unknown: bool,
    /// JSON map of DOI to pre-fetched retraction metadata. A DOI the map does
    /// not resolve needs a network fetch, which this command does not perform.
    #[arg(long = "retraction-fixture")]
    pub retraction_fixture: Option<PathBuf>,
    /// JSON budget/usage state for `meter`. The updated state is reported, not written.
    #[arg(long = "meter-state")]
    pub meter_state: Option<PathBuf>,
    /// Metered effect for `meter`: `external_request` or `worker`.
    #[arg(long)]
    pub effect: Option<String>,
    /// Units consumed by one `meter` step.
    #[arg(long, default_value_t = 1)]
    pub units: u64,
    /// Worker lifecycle for `meter --effect worker`: `start` or `finish`.
    #[arg(long = "worker-event")]
    pub worker_event: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub provider: Vec<String>,
    #[arg(long, default_value_t = 5)]
    pub max_hits: u32,
    #[arg(long = "source-record")]
    pub source_records: Vec<PathBuf>,
    #[arg(long, default_value_t = 2)]
    pub min_independent_providers: usize,
    /// Route domain. The medical and legal gates are only reachable when the
    /// route names them; a route frozen at `general` can never reach either,
    /// so a sensitive query was silently answered as an ordinary one.
    #[arg(long, default_value = "general")]
    pub domain: String,
    /// Route sensitivity. Bound with the domain because the gates read both.
    #[arg(long, default_value = "public")]
    pub sensitivity: String,
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
    if let Some(step) = args.step.clone() {
        return run_step(&step, &args);
    }
    let query = args
        .query
        .clone()
        .ok_or_else(|| super::CommandError::usage("--query is required unless --step is given"))?;
    let route =
        legion_research::ResearchRoute::host_injected_with(&query, &args.domain, &args.sensitivity);
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
            query,
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
                query.clone(),
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
            query,
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
            query,
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
        query,
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
    // Source records rejected or unreadable before the workflow ran are failures
    // of this run too. Dropping them would let a run with missing evidence read
    // as complete, so they are reported and the status is at most partial.
    let mut failure_values = Vec::new();
    for failure in failures.iter().chain(outcome.failures.iter()) {
        failure_values.push(serde_json::to_value(failure).map_err(super::io_error)?);
    }
    let status = if outcome.status == legion_research::WorkflowStatus::Ok
        && !failure_values.is_empty()
    {
        serde_json::to_value(legion_research::WorkflowStatus::Partial).map_err(super::io_error)?
    } else {
        serde_json::to_value(outcome.status).map_err(super::io_error)?
    };
    let incomplete =
        outcome.status != legion_research::WorkflowStatus::Ok || !failure_values.is_empty();
    let receipt = legion_research::ResearchReceipt::from_outcome(&outcome)
        .map_err(|error| super::CommandError::incomplete(error.to_string()))?;
    let external_requests = receipt.external_requests;
    let evidence = outcome.ledger.records().cloned().collect::<Vec<_>>();
    let claims = outcome.ledger.claims().cloned().collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-research",
        "status": status,
        "incomplete": incomplete,
        "request": request,
        "route": route,
        "report": outcome.report,
        "receipt": receipt,
        "externalRequests": external_requests,
        "independentProviders": independent_provider_count,
        "requiredIndependentProviders": args.min_independent_providers,
        "evidence": evidence,
        "claims": claims,
        "failures": failure_values,
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

/// Dispatches one pure Research step. Every step returns JSON; a status outside
/// `ok` maps to a non-zero exit in the CLI (`failed` 2, `unavailable` 2).
fn run_step(step: &str, args: &ResearchArgs) -> CommandResult {
    match step {
        "ledger-check" => step_ledger_check(args),
        "ledger-render" => step_ledger_render(args),
        "citecheck" => step_citecheck(args),
        "meter" => step_meter(args),
        "retraction" => step_retraction(args),
        other => Err(super::CommandError::usage(format!(
            "unknown --step {other}; expected ledger-check, ledger-render, citecheck, meter, or retraction"
        ))),
    }
}

fn required_path<'a>(
    value: &'a Option<PathBuf>,
    flag: &str,
) -> Result<&'a PathBuf, super::CommandError> {
    value
        .as_ref()
        .ok_or_else(|| super::CommandError::usage(format!("{flag} is required for this --step")))
}

fn read_text(path: &PathBuf) -> Result<String, super::CommandError> {
    std::fs::read_to_string(path).map_err(|error| {
        super::CommandError::usage(format!("cannot read {}: {error}", path.display()))
    })
}

fn read_jsonl(path: &PathBuf) -> Result<Vec<Value>, super::CommandError> {
    let text = read_text(path)?;
    ledger::parse_jsonl(&path.display().to_string(), &text).map_err(super::CommandError::usage)
}

fn read_lines(path: &PathBuf) -> Result<Vec<String>, super::CommandError> {
    Ok(read_text(path)?
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

fn step_envelope(step: &str, status: &str, result: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-research-step",
        "step": step,
        "status": status,
        "incomplete": status != "ok",
        "result": result,
    })
}

fn step_ledger_check(args: &ResearchArgs) -> CommandResult {
    let evidence = read_jsonl(required_path(&args.evidence, "--evidence")?)?;
    let claims = read_jsonl(required_path(&args.claims, "--claims")?)?;
    let checked = ledger::check(&evidence, &claims).map_err(super::CommandError::usage)?;
    let status = if checked.overall_ok { "ok" } else { "failed" };
    Ok(step_envelope("ledger-check", status, checked.to_json()))
}

fn step_ledger_render(args: &ResearchArgs) -> CommandResult {
    let evidence = read_jsonl(required_path(&args.evidence, "--evidence")?)?;
    let claims = read_jsonl(required_path(&args.claims, "--claims")?)?;
    let out = required_path(&args.out, "--out")?;
    let as_of = legion_research::research_port::today();
    match ledger::render(&evidence, &claims, &args.title, &as_of) {
        Ok(text) => {
            legion_research::research_port::atomic_write_text(out, &text)
                .map_err(super::io_error)?;
            Ok(step_envelope(
                "ledger-render",
                "ok",
                json!({"out": out.display().to_string(), "bytes": text.len()}),
            ))
        }
        Err(reason) => Ok(step_envelope(
            "ledger-render",
            "failed",
            json!({"reason": reason}),
        )),
    }
}

fn step_citecheck(args: &ResearchArgs) -> CommandResult {
    let draft = read_text(required_path(&args.draft, "--draft")?)?;
    let evidence = read_jsonl(required_path(&args.evidence, "--evidence")?)?;
    let report = citecheck::check(&draft, &evidence).map_err(super::CommandError::usage)?;
    let status = if report["ok"].as_bool() == Some(true) {
        "ok"
    } else {
        "failed"
    };
    Ok(step_envelope("citecheck", status, report))
}

fn state_u64(section: &Value, key: &str) -> Result<u64, super::CommandError> {
    section.get(key).and_then(Value::as_u64).ok_or_else(|| {
        super::CommandError::usage(format!(
            "meter state field {key} must be an unsigned integer"
        ))
    })
}

fn step_meter(args: &ResearchArgs) -> CommandResult {
    let state_path = required_path(&args.meter_state, "--meter-state")?;
    let state: Value = serde_json::from_str(&read_text(state_path)?)
        .map_err(|error| super::CommandError::usage(format!("invalid meter state: {error}")))?;
    let budget_section = state
        .get("budget")
        .ok_or_else(|| super::CommandError::usage("meter state requires a budget object"))?;
    let usage_section = state
        .get("usage")
        .ok_or_else(|| super::CommandError::usage("meter state requires a usage object"))?;
    let budget = meter::MeterBudget {
        external_requests: state_u64(budget_section, "external_requests")?,
        workers: state_u64(budget_section, "workers")?,
    };
    let current = meter::MeterUsage {
        external_requests: state_u64(usage_section, "external_requests")?,
        workers_active: state_u64(usage_section, "workers_active")?,
        workers_started: state_u64(usage_section, "workers_started")?,
    };
    let effect = args
        .effect
        .as_deref()
        .ok_or_else(|| super::CommandError::usage("--effect is required for --step meter"))?;
    let worker_event = args.worker_event.as_deref();
    let outcome = meter::consume(&budget, &current, effect, args.units, worker_event)
        .map_err(super::CommandError::usage)?;
    let refused = matches!(outcome, meter::MeterOutcome::Refused { .. });
    let mut result = meter::outcome_json(&budget, &outcome, effect, args.units, worker_event);
    if let Value::Object(map) = &mut result {
        map.insert("persisted".to_string(), Value::Bool(false));
    }
    let status = if refused { "failed" } else { "ok" };
    Ok(step_envelope("meter", status, result))
}

fn step_retraction(args: &ResearchArgs) -> CommandResult {
    let dois = read_lines(required_path(&args.dois, "--dois")?)?;
    let disclosed = match &args.disclosed {
        Some(path) => read_lines(path)?,
        None => Vec::new(),
    };
    let fixture: Option<serde_json::Map<String, Value>> = match &args.retraction_fixture {
        Some(path) => {
            let value: Value = serde_json::from_str(&read_text(path)?).map_err(|error| {
                super::CommandError::usage(format!("invalid retraction fixture: {error}"))
            })?;
            match value {
                Value::Object(map) => Some(map),
                _ => {
                    return Err(super::CommandError::usage(
                        "retraction fixture must be a JSON object",
                    ))
                }
            }
        }
        None => None,
    };
    let result = retraction::sweep(
        &dois,
        &disclosed,
        !args.allow_unknown,
        fixture.as_ref(),
        &retraction::network_unavailable,
    );
    let gap = retraction::has_unavailable_gap(&result);
    let blocked = result["block_brief"].as_bool().unwrap_or(true);
    let status = if gap {
        "unavailable"
    } else if blocked {
        "failed"
    } else {
        "ok"
    };
    let mut envelope = step_envelope("retraction", status, result);
    if gap {
        if let Value::Object(map) = &mut envelope {
            map.insert(
                "reason".to_string(),
                Value::String(retraction::UNAVAILABLE_NETWORK.to_string()),
            );
        }
    }
    Ok(envelope)
}
