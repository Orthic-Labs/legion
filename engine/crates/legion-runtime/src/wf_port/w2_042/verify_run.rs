//! Port of `src/lib/core/verify-run.mjs` — see the chunk-level doc comment
//! in [`super`] for the full disposition note.

use serde_json::{json, Value};

use crate::l3_inventory::binding::{digest as binding_digest, same_binding};
use crate::p5_core::verification_projection::semantic_projection;

/// One dependency-order / exclusive-lock-overlap / reasoning-context-reuse
/// gap, mirroring the ad hoc `{kind, ...}` objects `integrityGaps` pushes in
/// JS. Kept as `Value` so each kind's distinct extra fields round-trip
/// exactly.
pub type IntegrityGap = Value;

fn providers_map(plan: &Value) -> Vec<(String, Value)> {
    plan.get("providers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|provider| {
            let id = provider.get("id")?.as_str()?.to_string();
            Some((id, provider.clone()))
        })
        .collect()
}

fn receipts(snapshot: &Value) -> Vec<Value> {
    snapshot
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn provider_dependencies(provider: &Value) -> Vec<String> {
    let deps = provider
        .get("dependencies")
        .filter(|v| !v.is_null())
        .or_else(|| provider.get("dependsOn"))
        .and_then(Value::as_array);
    deps.into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Port of the private `integrityGaps(snapshot)` helper.
pub fn integrity_gaps(snapshot: &Value) -> Vec<IntegrityGap> {
    let mut gaps = Vec::new();

    // dependency-order
    let plan = snapshot.get("plan").cloned().unwrap_or(Value::Null);
    let providers = providers_map(&plan);
    let receipt_list = receipts(snapshot);
    let order: std::collections::HashMap<&str, usize> = receipt_list
        .iter()
        .enumerate()
        .filter_map(|(index, receipt)| receipt.get("provider").and_then(Value::as_str).map(|p| (p, index)))
        .collect();

    for (id, provider) in &providers {
        for dependency in provider_dependencies(provider) {
            if let Some(&id_index) = order.get(id.as_str()) {
                let dependency_ok = order
                    .get(dependency.as_str())
                    .map(|&dependency_index| dependency_index <= id_index)
                    .unwrap_or(false);
                if !dependency_ok {
                    gaps.push(json!({
                        "kind": "dependency-order",
                        "provider": id,
                        "dependency": dependency,
                    }));
                }
            }
        }
    }

    // exclusive-lock-overlap
    #[derive(Clone)]
    struct Interval {
        provider: Value,
        concurrency_key: String,
        started_at: String,
        completed_at: String,
    }
    let intervals: Vec<Interval> = receipt_list
        .iter()
        .filter_map(|receipt| {
            let concurrency_key = receipt.get("concurrencyKey")?.as_str()?.to_string();
            let started_at = receipt.get("startedAt")?.as_str()?.to_string();
            let completed_at = receipt.get("completedAt")?.as_str()?.to_string();
            Some(Interval {
                provider: receipt.get("provider").cloned().unwrap_or(Value::Null),
                concurrency_key,
                started_at,
                completed_at,
            })
        })
        .collect();
    for left in 0..intervals.len() {
        for right in (left + 1)..intervals.len() {
            let a = &intervals[left];
            let b = &intervals[right];
            // RFC 3339 zero-padded UTC timestamps sort lexicographically the
            // same as chronologically; see the chunk-level doc comment for
            // the scope of this equivalence.
            if a.concurrency_key == b.concurrency_key
                && a.started_at < b.completed_at
                && b.started_at < a.completed_at
            {
                gaps.push(json!({
                    "kind": "exclusive-lock-overlap",
                    "providers": [a.provider, b.provider],
                    "concurrencyKey": a.concurrency_key,
                }));
            }
        }
    }

    // reasoning-context-reuse
    let mut contexts: std::collections::HashSet<String> = std::collections::HashSet::new();
    for judgment in snapshot
        .get("judgments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(context_id) = judgment.get("contextId").and_then(Value::as_str) else {
            continue;
        };
        if contexts.contains(context_id) {
            gaps.push(json!({
                "kind": "reasoning-context-reuse",
                "contextId": context_id,
            }));
        }
        contexts.insert(context_id.to_string());
    }

    gaps
}

/// The `{binding, snapshot|run}` shape `verifySealedRun`'s
/// `currentRepository` parameter accepts (`currentRepository?.binding ??
/// currentRepository?.snapshot?.binding ?? currentRepository ?? null` and
/// `currentRepository?.snapshot ?? currentRepository?.run ?? null`).
#[derive(Debug, Clone, Default)]
pub struct CurrentRepository {
    pub binding: Option<Value>,
    pub snapshot: Option<Value>,
}

impl CurrentRepository {
    fn resolved_binding(&self) -> Value {
        self.binding
            .clone()
            .or_else(|| {
                self.snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.get("binding").cloned())
            })
            .unwrap_or(Value::Null)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub valid: bool,
    pub prior_digest: String,
    pub current_digest: Option<String>,
    pub binding: Value,
    pub status: String,
    pub gaps: Vec<IntegrityGap>,
    pub verified_at: String,
}

impl VerificationReceipt {
    pub fn to_value(&self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "kind": self.kind,
            "valid": self.valid,
            "priorDigest": self.prior_digest,
            "currentDigest": self.current_digest,
            "binding": self.binding,
            "status": self.status,
            "gaps": self.gaps,
            "verifiedAt": self.verified_at,
        })
    }
}

/// Port of `verifySealedRun({priorRun, currentRepository}, host)`. `prior`
/// is the already-parsed value of `priorRun` (the JS `typeof priorRun ===
/// 'string'` branch reads and `JSON.parse`s a file, which is host I/O
/// outside this chunk's scope — see the chunk-level doc comment); `now` is
/// an RFC 3339 timestamp standing in for `host.clock.now().toISOString()`.
pub fn verify_sealed_run(prior: &Value, current_repository: &CurrentRepository, now: &str) -> VerificationReceipt {
    let current_binding = current_repository.resolved_binding();
    let expected_binding = prior
        .get("binding")
        .cloned()
        .or_else(|| prior.get("plan").and_then(|plan| plan.get("binding")).cloned())
        .unwrap_or(Value::Null);

    let current = current_repository.snapshot.clone();

    let mut gaps: Vec<IntegrityGap> = Vec::new();
    let binding_drift = prior.is_null() || expected_binding.is_null() || !same_binding(&expected_binding, &current_binding);
    if binding_drift {
        gaps.push(json!({"kind": "binding-drift"}));
    }
    if current.is_none() {
        gaps.push(json!({"kind": "semantic-replay-unavailable"}));
    }

    let prior_semantic = binding_digest(&semantic_projection(prior.clone()));
    let current_semantic = current
        .as_ref()
        .map(|snapshot| binding_digest(&semantic_projection(snapshot.clone())));

    if let Some(current_semantic_value) = &current_semantic {
        if &prior_semantic != current_semantic_value {
            gaps.push(json!({
                "kind": "semantic-drift",
                "priorDigest": prior_semantic,
                "currentDigest": current_semantic_value,
            }));
        }
    }

    if let Some(snapshot) = &current {
        gaps.extend(integrity_gaps(snapshot));
    }

    let valid = gaps.is_empty();
    VerificationReceipt {
        schema_version: 1,
        kind: "legion-verification-receipt".to_string(),
        valid,
        prior_digest: prior_semantic,
        current_digest: current_semantic,
        binding: current_binding,
        status: if valid { "pass".to_string() } else { "unproven".to_string() },
        gaps,
        verified_at: now.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding(revision: &str) -> Value {
        json!({"repositoryRevision": revision})
    }

    #[test]
    fn valid_when_binding_and_semantics_match_and_no_gaps() {
        let prior = json!({
            "binding": binding("rev-1"),
            "data": 1,
        });
        let current_repository = CurrentRepository {
            binding: Some(binding("rev-1")),
            snapshot: Some(json!({"binding": binding("rev-1"), "data": 1})),
        };
        let receipt = verify_sealed_run(&prior, &current_repository, "2026-01-01T00:00:00.000Z");
        assert!(receipt.valid, "{:?}", receipt.gaps);
        assert_eq!(receipt.status, "pass");
        assert_eq!(receipt.kind, "legion-verification-receipt");
    }

    #[test]
    fn binding_drift_when_bindings_differ() {
        let prior = json!({"binding": binding("rev-1")});
        let current_repository = CurrentRepository {
            binding: Some(binding("rev-2")),
            snapshot: Some(json!({"binding": binding("rev-2")})),
        };
        let receipt = verify_sealed_run(&prior, &current_repository, "2026-01-01T00:00:00.000Z");
        assert!(!receipt.valid);
        assert!(receipt.gaps.iter().any(|g| g["kind"] == "binding-drift"));
    }

    #[test]
    fn semantic_replay_unavailable_when_no_current_snapshot() {
        let prior = json!({"binding": binding("rev-1")});
        let current_repository = CurrentRepository {
            binding: Some(binding("rev-1")),
            snapshot: None,
        };
        let receipt = verify_sealed_run(&prior, &current_repository, "2026-01-01T00:00:00.000Z");
        assert!(!receipt.valid);
        assert!(receipt.gaps.iter().any(|g| g["kind"] == "semantic-replay-unavailable"));
        assert!(receipt.current_digest.is_none());
    }

    #[test]
    fn semantic_drift_when_projected_content_differs() {
        let prior = json!({"binding": binding("rev-1"), "data": 1});
        let current_repository = CurrentRepository {
            binding: Some(binding("rev-1")),
            snapshot: Some(json!({"binding": binding("rev-1"), "data": 2})),
        };
        let receipt = verify_sealed_run(&prior, &current_repository, "2026-01-01T00:00:00.000Z");
        assert!(!receipt.valid);
        assert!(receipt.gaps.iter().any(|g| g["kind"] == "semantic-drift"));
    }

    #[test]
    fn integrity_gaps_detects_dependency_order_violation() {
        let snapshot = json!({
            "plan": {"providers": [{"id": "b", "dependencies": ["a"]}]},
            "receipts": [{"provider": "b"}, {"provider": "a"}],
        });
        let gaps = integrity_gaps(&snapshot);
        assert!(gaps.iter().any(|g| g["kind"] == "dependency-order" && g["provider"] == "b" && g["dependency"] == "a"));
    }

    #[test]
    fn integrity_gaps_allows_dependency_run_before_dependent() {
        let snapshot = json!({
            "plan": {"providers": [{"id": "b", "dependencies": ["a"]}]},
            "receipts": [{"provider": "a"}, {"provider": "b"}],
        });
        let gaps = integrity_gaps(&snapshot);
        assert!(!gaps.iter().any(|g| g["kind"] == "dependency-order"));
    }

    #[test]
    fn integrity_gaps_detects_exclusive_lock_overlap() {
        let snapshot = json!({
            "receipts": [
                {"provider": "a", "concurrencyKey": "lock-1", "startedAt": "2026-01-01T00:00:00.000Z", "completedAt": "2026-01-01T00:05:00.000Z"},
                {"provider": "b", "concurrencyKey": "lock-1", "startedAt": "2026-01-01T00:02:00.000Z", "completedAt": "2026-01-01T00:06:00.000Z"},
            ],
        });
        let gaps = integrity_gaps(&snapshot);
        assert!(gaps.iter().any(|g| g["kind"] == "exclusive-lock-overlap"));
    }

    #[test]
    fn integrity_gaps_allows_non_overlapping_exclusive_intervals() {
        let snapshot = json!({
            "receipts": [
                {"provider": "a", "concurrencyKey": "lock-1", "startedAt": "2026-01-01T00:00:00.000Z", "completedAt": "2026-01-01T00:01:00.000Z"},
                {"provider": "b", "concurrencyKey": "lock-1", "startedAt": "2026-01-01T00:02:00.000Z", "completedAt": "2026-01-01T00:03:00.000Z"},
            ],
        });
        let gaps = integrity_gaps(&snapshot);
        assert!(!gaps.iter().any(|g| g["kind"] == "exclusive-lock-overlap"));
    }

    #[test]
    fn integrity_gaps_detects_reasoning_context_reuse() {
        let snapshot = json!({
            "judgments": [
                {"contextId": "ctx-1"},
                {"contextId": "ctx-1"},
            ],
        });
        let gaps = integrity_gaps(&snapshot);
        assert!(gaps.iter().any(|g| g["kind"] == "reasoning-context-reuse" && g["contextId"] == "ctx-1"));
    }
}
