//! Port of the accounting in `tools/research-core/meter.py`: external-request
//! and worker budget consumption with refusal.
//!
//! The Python persists the mutated run manifest and appends `budget.consumed`
//! or `budget.refused` events through `manifest.py`. That file-backed run state
//! is not ported. This module is the pure step: it takes the current budget and
//! usage and returns either the next usage or a refusal. The caller owns
//! persistence and event recording.

use serde_json::{json, Value};

/// `budget` block of a run manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeterBudget {
    pub external_requests: u64,
    pub workers: u64,
}

/// `usage` block of a run manifest.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MeterUsage {
    pub external_requests: u64,
    pub workers_active: u64,
    pub workers_started: u64,
}

/// Outcome of one consumption step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MeterOutcome {
    /// The step fits the budget; `usage` is the next state.
    Consumed { usage: MeterUsage },
    /// The step would exceed the budget; usage is unchanged.
    Refused { reason: String },
}

/// Applies one metered effect, mirroring `consume(...)` in `meter.py`.
///
/// `effect` is `external_request` or `worker`. A worker step needs
/// `worker_event` of `start` or `finish`; `finish` saturates at zero. Units are
/// unsigned: the Python accepts negative integers, which this port refuses.
pub fn consume(
    budget: &MeterBudget,
    usage: &MeterUsage,
    effect: &str,
    units: u64,
    worker_event: Option<&str>,
) -> Result<MeterOutcome, String> {
    match effect {
        "external_request" => {
            let proposed = usage.external_requests.saturating_add(units);
            if proposed > budget.external_requests {
                return Ok(MeterOutcome::Refused {
                    reason: format!(
                        "research budget exceeded: external_requests {proposed} > {}",
                        budget.external_requests
                    ),
                });
            }
            let mut next = usage.clone();
            next.external_requests = proposed;
            Ok(MeterOutcome::Consumed { usage: next })
        }
        "worker" => match worker_event {
            Some("start") => {
                let proposed = usage.workers_active.saturating_add(units);
                if proposed > budget.workers {
                    return Ok(MeterOutcome::Refused {
                        reason: format!(
                            "research budget exceeded: workers_active {proposed} > {}",
                            budget.workers
                        ),
                    });
                }
                let mut next = usage.clone();
                next.workers_active = proposed;
                next.workers_started = usage.workers_started.saturating_add(units);
                Ok(MeterOutcome::Consumed { usage: next })
            }
            Some("finish") => {
                let mut next = usage.clone();
                next.workers_active = usage.workers_active.saturating_sub(units);
                Ok(MeterOutcome::Consumed { usage: next })
            }
            _ => Err("worker effect requires worker_event=start|finish".to_string()),
        },
        other => Err(format!("unknown metered effect: {other}")),
    }
}

/// Result object for a step, shaped like the Python `consume` return value,
/// plus the event the Python would record. Events are reported, not persisted.
pub fn outcome_json(
    budget: &MeterBudget,
    outcome: &MeterOutcome,
    effect: &str,
    units: u64,
    worker_event: Option<&str>,
) -> Value {
    match outcome {
        MeterOutcome::Consumed { usage } => json!({
            "ok": true,
            "usage": {
                "external_requests": usage.external_requests,
                "workers_active": usage.workers_active,
                "workers_started": usage.workers_started,
            },
            "budget": {
                "external_requests": budget.external_requests,
                "workers": budget.workers,
            },
            "events": [{
                "type": "budget.consumed",
                "effect": effect,
                "units": units,
                "worker_event": worker_event,
            }],
        }),
        MeterOutcome::Refused { reason } => json!({
            "ok": false,
            "reason": reason,
            "events": [{
                "type": "budget.refused",
                "effect": effect,
                "units": units,
                "worker_event": worker_event,
                "reason": reason,
            }],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> MeterBudget {
        MeterBudget {
            external_requests: 2,
            workers: 1,
        }
    }

    #[test]
    fn external_requests_accumulate_until_the_budget_refuses() {
        let mut usage = MeterUsage::default();
        for _ in 0..2 {
            match consume(&budget(), &usage, "external_request", 1, None).unwrap() {
                MeterOutcome::Consumed { usage: next } => usage = next,
                other => panic!("expected consumption, got {other:?}"),
            }
        }
        assert_eq!(usage.external_requests, 2);
        let refused = consume(&budget(), &usage, "external_request", 1, None).unwrap();
        assert_eq!(
            refused,
            MeterOutcome::Refused {
                reason: "research budget exceeded: external_requests 3 > 2".to_string()
            }
        );
    }

    #[test]
    fn worker_start_counts_started_and_finish_releases_active_saturating() {
        let usage = MeterUsage::default();
        let started = match consume(&budget(), &usage, "worker", 1, Some("start")).unwrap() {
            MeterOutcome::Consumed { usage } => usage,
            other => panic!("expected consumption, got {other:?}"),
        };
        assert_eq!(started.workers_active, 1);
        assert_eq!(started.workers_started, 1);

        let second = consume(&budget(), &started, "worker", 1, Some("start")).unwrap();
        assert!(matches!(second, MeterOutcome::Refused { .. }));

        let finished = match consume(&budget(), &started, "worker", 5, Some("finish")).unwrap() {
            MeterOutcome::Consumed { usage } => usage,
            other => panic!("expected consumption, got {other:?}"),
        };
        assert_eq!(finished.workers_active, 0);
        assert_eq!(finished.workers_started, 1);
    }

    #[test]
    fn worker_without_event_and_unknown_effect_are_errors() {
        let usage = MeterUsage::default();
        assert!(consume(&budget(), &usage, "worker", 1, None).is_err());
        assert!(consume(&budget(), &usage, "bogus", 1, None).is_err());
    }

    #[test]
    fn outcome_json_reports_the_consumed_event_shape() {
        let usage = MeterUsage {
            external_requests: 1,
            workers_active: 0,
            workers_started: 0,
        };
        let outcome = MeterOutcome::Consumed { usage };
        let value = outcome_json(&budget(), &outcome, "external_request", 1, None);
        assert_eq!(value["ok"], true);
        assert_eq!(value["usage"]["external_requests"], 1);
        assert_eq!(value["events"][0]["type"], "budget.consumed");
    }
}
