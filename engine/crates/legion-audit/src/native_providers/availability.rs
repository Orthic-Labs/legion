//! Typed provider availability.
//!
//! Several provider families are constructed and dispatched natively but have
//! no producer for the input they analyze (architecture graph, scanner
//! artifacts, tool receipts, a runtime executable). Their analyzers already
//! refuse to claim success, yet an empty input looked the same as "ran and
//! found a gap". A provider that cannot run reports `unavailable:<reason>`:
//! a coverage gap (so the verdict stays incomplete), a typed `availability`
//! detail, and a report coverage note naming the provider and the reason.

use rightkit_evidence_contracts::{ProviderResult, ProviderStatus};
use serde_json::{json, Value};

/// Detail key carrying `{"state":"unavailable","reason":...}`.
pub const AVAILABILITY_DETAIL: &str = "availability";

/// The coverage gap string for an unavailable provider.
pub fn unavailable_gap(reason: &str) -> String {
    format!("unavailable:{reason}")
}

/// The `availability` detail value for `reason`.
pub fn unavailable_detail(reason: &str) -> Value {
    json!({"state": "unavailable", "reason": reason})
}

/// Marks `result` as unable to run: never complete, never `ok`/`complete`,
/// with a typed coverage gap and `availability` detail. Idempotent.
pub fn mark_unavailable(result: &mut ProviderResult, reason: &str) {
    let gap = unavailable_gap(reason);
    result.complete = false;
    if matches!(result.status, ProviderStatus::Ok | ProviderStatus::Complete) {
        result.status = ProviderStatus::Partial;
    }
    if !result.coverage_gaps.contains(&gap) {
        result.coverage_gaps.push(gap.clone());
    }
    if let Some(coverage) = result.coverage.as_mut() {
        if !coverage.gaps.contains(&gap) {
            coverage.gaps.push(gap);
        }
    }
    result
        .details
        .insert(AVAILABILITY_DETAIL.into(), unavailable_detail(reason));
}

/// The reason a result was marked unavailable, if it was.
pub fn unavailable_reason(result: &ProviderResult) -> Option<&str> {
    let detail = result.details.get(AVAILABILITY_DETAIL)?;
    (detail.get("state").and_then(Value::as_str) == Some("unavailable"))
        .then(|| detail.get("reason").and_then(Value::as_str))
        .flatten()
}
