//! Faithful port of `src/lib/providers/sdk/dag.mjs`'s `topologicalProviders`
//! export, scoped to wf012 (`src/lib/providers/sdk/schedule.mjs`,
//! `selectors.mjs`, `testkit.mjs`). This is a standalone port living under
//! `wf_port::wf012` — it is not wired into the crate's existing `dag` module
//! (`legion-audit::dag::topological`, which serves `AuditProvider`/`AuditPlan`
//! and has a different provider shape and different error strings).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Minimal provider view needed for dependency-graph scheduling. Mirrors the
/// duck-typed shape `dag.mjs`/`schedule.mjs` operate on: an `id` and a
/// `dependsOn` list (already normalized by the caller in the JS source).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DagProvider {
    pub id: String,
    #[serde(default, rename = "dependsOn")]
    pub depends_on: Vec<String>,
}

/// Mirrors the `Error` thrown by `topologicalProviders` in dag.mjs. The JS
/// source throws plain `Error`, not `TypeError`, for these three cases.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DagError {
    #[error("provider {0} depends on unknown {1}")]
    UnknownDependency(String, String),
    #[error("provider {0} depends on itself")]
    SelfDependency(String),
    #[error("provider dependency cycle: {0}")]
    Cycle(String),
}

/// Port of `topologicalProviders(providers)` from dag.mjs.
///
/// JS behavior reproduced exactly:
/// - Validates every `dependsOn` entry references a known provider and is not
///   a self-dependency, checked up front for all providers before scheduling
///   begins (matches the JS `for (const [id, deps] of incoming)` pre-pass).
/// - Kahn's algorithm: providers with no remaining dependencies become
///   "ready", ties broken by ascending `id` (`ready.sort()` after each
///   insertion — the JS source keeps `ready` sorted incrementally rather than
///   sorting once at the end, but the resulting order is identical to
///   collecting-then-sorting since insertion order does not matter once
///   re-sorted).
/// - On cycle, the error payload is a JSON array of `{ id, dependsOn }` for
///   every provider that never became ready, `dependsOn` sorted ascending,
///   ordered by ascending `id`, embedded via `JSON.stringify`.
pub fn topological_providers(providers: &[DagProvider]) -> Result<Vec<DagProvider>, DagError> {
    let by_id: BTreeMap<&str, &DagProvider> =
        providers.iter().map(|p| (p.id.as_str(), p)).collect();

    let mut incoming: BTreeMap<String, BTreeSet<String>> = providers
        .iter()
        .map(|p| (p.id.clone(), p.depends_on.iter().cloned().collect()))
        .collect();

    for (id, deps) in &incoming {
        for dependency in deps {
            if !by_id.contains_key(dependency.as_str()) {
                return Err(DagError::UnknownDependency(id.clone(), dependency.clone()));
            }
            if dependency == id {
                return Err(DagError::SelfDependency(id.clone()));
            }
        }
    }

    let mut ready: Vec<String> = incoming
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .map(|(id, _)| id.clone())
        .collect();
    ready.sort();

    let mut ordered_ids: Vec<String> = Vec::with_capacity(providers.len());

    // Track membership for the `!ordered.some(...) && !ready.includes(...)`
    // guard from the JS source, using a set for the "already ordered" half
    // (a linear `Vec` scan would also work but a set matches the intent and
    // keeps this cheap for large provider sets).
    let mut ordered_set: BTreeSet<String> = BTreeSet::new();

    while let Some(id) = ready.first().cloned() {
        ready.remove(0);
        ordered_ids.push(id.clone());
        ordered_set.insert(id.clone());

        for (other_id, deps) in incoming.iter_mut() {
            if !deps.remove(&id) || !deps.is_empty() {
                continue;
            }
            if !ordered_set.contains(other_id) && !ready.contains(other_id) {
                ready.push(other_id.clone());
                ready.sort();
            }
        }
    }

    if ordered_ids.len() != providers.len() {
        let mut cyclic: Vec<(String, Vec<String>)> = incoming
            .into_iter()
            .filter(|(id, deps)| !deps.is_empty() && !ordered_set.contains(id))
            .map(|(id, deps)| {
                let mut deps: Vec<String> = deps.into_iter().collect();
                deps.sort();
                (id, deps)
            })
            .collect();
        cyclic.sort_by(|a, b| a.0.cmp(&b.0));

        let payload: Vec<serde_json::Value> = cyclic
            .into_iter()
            .map(|(id, deps_on)| {
                serde_json::json!({ "id": id, "dependsOn": deps_on })
            })
            .collect();
        let rendered =
            serde_json::to_string(&serde_json::Value::Array(payload)).unwrap_or_default();
        return Err(DagError::Cycle(rendered));
    }

    Ok(ordered_ids
        .into_iter()
        .map(|id| (*by_id.get(id.as_str()).expect("id present")).clone())
        .collect())
}
