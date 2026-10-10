//! Typed provider availability.
//!
//! Several provider families are constructed and dispatched natively but have
//! no producer for the input they analyze (architecture graph, scanner
//! artifacts, tool receipts, a runtime executable). Their analyzers already
//! refuse to claim success, yet an empty input looked the same as "ran and
//! found a gap". A provider that cannot run reports `unavailable:<reason>`:
//! a coverage gap (so the verdict stays incomplete), a typed `availability`
//! detail, and a report coverage note naming the provider and the reason.

use legion_contracts::{ProviderResult, ProviderStatus};
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

#[cfg(test)]
mod tests {
    use super::*;
    use legion_contracts::{Coverage, ProviderId};
    use std::collections::BTreeMap;

    fn result(status: ProviderStatus, complete: bool) -> ProviderResult {
        ProviderResult {
            schema_version: 1,
            provider: ProviderId::new("architecture.core").unwrap(),
            applicable: true,
            required: false,
            status,
            complete,
            coverage: Some(Coverage {
                denominator_digest: "sha256:x".into(),
                expected: 2,
                examined: 2,
                gaps: Vec::new(),
            }),
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::new(),
        }
    }

    #[test]
    fn unavailable_results_are_never_complete_and_carry_a_typed_gap() {
        let mut marked = result(ProviderStatus::Complete, true);
        mark_unavailable(&mut marked, "input-not-produced:architecture.core");
        mark_unavailable(&mut marked, "input-not-produced:architecture.core");
        assert!(!marked.complete);
        assert_eq!(marked.status, ProviderStatus::Partial);
        assert_eq!(
            marked.coverage_gaps,
            vec!["unavailable:input-not-produced:architecture.core"]
        );
        assert_eq!(marked.coverage.as_ref().unwrap().gaps.len(), 1);
        assert!(!marked.coverage.as_ref().unwrap().complete());
        assert_eq!(
            unavailable_reason(&marked),
            Some("input-not-produced:architecture.core")
        );
        marked.validate().unwrap();
    }

    #[test]
    fn failed_status_is_preserved() {
        let mut marked = result(ProviderStatus::Failed, false);
        mark_unavailable(&mut marked, "artifact-not-produced:security.opengrep");
        assert_eq!(marked.status, ProviderStatus::Failed);
        assert_eq!(unavailable_reason(&result(ProviderStatus::Ok, false)), None);
    }
}
