//! Derived run metrics (CP section 20). Computed only from a verified journal
//! plus receipts and the budget ledger. Never authoritative: nothing here
//! feeds proof, eligibility or report status, and the output says so.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::AuditError;
use crate::journal::{gap_payload_digest, verify_events, AuditEvent, EventKind};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptMetric {
    pub provider: String,
    pub output_bytes: u64,
    pub cache_hit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetEntry {
    pub provider: String,
    pub resource: String,
    pub amount: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsInput {
    pub plan_digest: String,
    pub receipts: Vec<ReceiptMetric>,
    pub budget: Vec<BudgetEntry>,
    /// Providers reused from a prior run (`ResumePlan::reused`).
    pub reused_providers: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateCounts {
    pub completed: u64,
    pub failed: u64,
    pub skipped: u64,
    pub gaps: u64,
    pub interrupted: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunMetrics {
    pub format: String,
    /// Always false: metrics never carry proof semantics.
    pub authoritative: bool,
    pub derived_from_head: Option<String>,
    pub event_count: u64,
    pub counts: StateCounts,
    pub retries: u64,
    pub breaker_trips: u64,
    pub fallbacks: u64,
    pub amendments: u64,
    pub resumes: u64,
    pub total_duration_ms: u64,
    pub provider_duration_ms: BTreeMap<String, u64>,
    /// Timestamps that went backwards; durations are clamped to zero.
    pub clock_anomalies: u64,
    pub receipts_cache_hits: u64,
    pub reused_providers: Vec<String>,
    pub output_bytes_total: u64,
    pub budget_totals: BTreeMap<String, u64>,
}

/// Derive metrics from journal events. Refuses an unverifiable journal: metrics
/// over a tampered history would be misleading.
pub fn derive(events: &[AuditEvent], input: &MetricsInput) -> Result<RunMetrics, AuditError> {
    let (defects, _, _) = verify_events(events, &input.plan_digest);
    if let Some(first) = defects.first() {
        return Err(AuditError::Invalid(format!(
            "metrics refused: journal does not verify ({first})"
        )));
    }
    let mut counts = StateCounts::default();
    let mut retries = 0;
    let mut breaker_trips = 0;
    let mut fallbacks = 0;
    let mut amendments = 0;
    let mut resumes = 0;
    let mut anomalies = 0;
    let mut durations: BTreeMap<String, u64> = BTreeMap::new();
    let mut started_at: BTreeMap<&str, u64> = BTreeMap::new();
    let mut resumed = false;
    for event in events {
        match event.kind {
            EventKind::ProviderStarted => {
                started_at.insert(event.subject.as_str(), event.at);
            }
            EventKind::ProviderFinished
            | EventKind::ProviderFailed
            | EventKind::ProviderSkipped => {
                if event.kind != EventKind::ProviderSkipped {
                    if let Some(start) = started_at.remove(event.subject.as_str()) {
                        if event.at < start {
                            anomalies += 1;
                        }
                        *durations.entry(event.subject.clone()).or_default() +=
                            event.at.saturating_sub(start);
                    }
                }
                match event.kind {
                    EventKind::ProviderFinished => counts.completed += 1,
                    EventKind::ProviderSkipped => counts.skipped += 1,
                    _ => {
                        if resumed && event.payload_digest == gap_payload_digest(&event.subject) {
                            counts.gaps += 1;
                        } else {
                            counts.failed += 1;
                        }
                    }
                }
            }
            EventKind::RetryScheduled => retries += 1,
            EventKind::BreakerTripped => breaker_trips += 1,
            EventKind::FallbackUsed => fallbacks += 1,
            EventKind::AmendmentApplied => amendments += 1,
            EventKind::RunResumed => {
                resumes += 1;
                resumed = true;
            }
            _ => {}
        }
    }
    counts.interrupted = started_at.len() as u64;
    let total = match (events.first(), events.last()) {
        (Some(first), Some(last)) => {
            if last.at < first.at {
                anomalies += 1;
            }
            last.at.saturating_sub(first.at)
        }
        _ => 0,
    };
    let mut budget_totals: BTreeMap<String, u64> = BTreeMap::new();
    for entry in &input.budget {
        let total = budget_totals.entry(entry.resource.clone()).or_default();
        *total = total.saturating_add(entry.amount);
    }
    let mut bytes = 0u64;
    let mut cache_hits = 0;
    for receipt in &input.receipts {
        bytes = bytes.saturating_add(receipt.output_bytes);
        if receipt.cache_hit {
            cache_hits += 1;
        }
    }
    Ok(RunMetrics {
        format: "run-metrics/v1".to_owned(),
        authoritative: false,
        derived_from_head: events.last().map(|e| e.digest.clone()),
        event_count: events.len() as u64,
        counts,
        retries,
        breaker_trips,
        fallbacks,
        amendments,
        resumes,
        total_duration_ms: total,
        provider_duration_ms: durations,
        clock_anomalies: anomalies,
        receipts_cache_hits: cache_hits,
        reused_providers: input.reused_providers.iter().cloned().collect(),
        output_bytes_total: bytes,
        budget_totals,
    })
}

/// Canonical JSON text for `run-metrics.json` (stable key order).
pub fn to_json(metrics: &RunMetrics) -> Result<String, AuditError> {
    let bytes = legion_contracts::canonical_json_bytes(metrics)
        .map_err(|e| AuditError::Invalid(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| AuditError::Invalid(e.to_string()))
}
