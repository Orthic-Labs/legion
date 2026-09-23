//! Faithful port of `src/lib/providers/sdk/schedule.mjs`'s `compileSchedule`.
//!
//! JS source (reformatted for reference):
//! ```js
//! export function compileSchedule(providers, ceilings = {}) {
//!   for (const provider of providers)
//!     for (const [name, amount] of Object.entries(provider.resources ?? {}))
//!       if (ceilings[name] != null && amount > ceilings[name])
//!         throw new TypeError(`resource ceiling exceeded: ${provider.id}:${name}`);
//!   const normalized = providers.map((item) => ({
//!     ...item,
//!     dependsOn: item.dependencies ?? item.dependsOn ?? [],
//!   }));
//!   const ordered = topologicalProviders(normalized);
//!   const remaining = new Map(ordered.map((item) => [item.id, item]));
//!   const done = new Set();
//!   const waves = [];
//!   while (remaining.size) {
//!     const ready = [...remaining.values()]
//!       .filter((item) => (item.dependsOn ?? []).every((id) => done.has(id)))
//!       .sort((a, b) => a.id.localeCompare(b.id));
//!     if (!ready.length) throw new TypeError('provider dependency cycle');
//!     const used = {};
//!     const selected = [];
//!     for (const item of ready) {
//!       const fits = Object.entries(item.resources ?? {}).every(
//!         ([name, amount]) => (used[name] ?? 0) + amount <= (ceilings[name] ?? Infinity),
//!       );
//!       if (!fits) continue;
//!       selected.push(item);
//!       for (const [name, amount] of Object.entries(item.resources ?? {}))
//!         used[name] = (used[name] ?? 0) + amount;
//!     }
//!     if (!selected.length) throw new TypeError('aggregate resource ceiling prevents progress');
//!     waves.push(selected.map(({ id }) => id));
//!     for (const { id } of selected) {
//!       remaining.delete(id);
//!       done.add(id);
//!     }
//!   }
//!   return { order: waves.flat(), waves };
//! }
//! ```
//!
//! Note the pre-pass throws on the FIRST offending `(provider, resource)`
//! pair in providers/resource-entry iteration order (JS `Object.entries`
//! preserves insertion order for string keys) — this port walks providers in
//! input order and each provider's resources in insertion order (a `Vec` of
//! pairs, not a `BTreeMap`, to keep that order) to match exactly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::dag::{topological_providers, DagError, DagProvider};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScheduleProvider {
    pub id: String,
    /// Preserves JS insertion order; a resource name may appear only once
    /// per provider in realistic input, matching `Object.entries`.
    #[serde(default)]
    pub resources: Vec<(String, f64)>,
    #[serde(default)]
    pub dependencies: Option<Vec<String>>,
    #[serde(default, rename = "dependsOn")]
    pub depends_on: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ScheduleError {
    #[error("resource ceiling exceeded: {0}:{1}")]
    ResourceCeilingExceeded(String, String),
    #[error("provider dependency cycle")]
    DependencyCycle,
    #[error("aggregate resource ceiling prevents progress")]
    AggregateCeilingPreventsProgress,
    #[error(transparent)]
    Dag(#[from] DagError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScheduleResult {
    pub order: Vec<String>,
    pub waves: Vec<Vec<String>>,
}

/// `ceilings[name]` absent (JS `undefined`) means no ceiling for that
/// resource — mirrors `ceilings[name] != null` (JS `!= null` matches both
/// `undefined` and `null`) and `ceilings[name] ?? Infinity`.
pub fn compile_schedule(
    providers: &[ScheduleProvider],
    ceilings: &BTreeMap<String, f64>,
) -> Result<ScheduleResult, ScheduleError> {
    for provider in providers {
        for (name, amount) in &provider.resources {
            if let Some(&ceiling) = ceilings.get(name) {
                if *amount > ceiling {
                    return Err(ScheduleError::ResourceCeilingExceeded(
                        provider.id.clone(),
                        name.clone(),
                    ));
                }
            }
        }
    }

    let normalized: Vec<DagProvider> = providers
        .iter()
        .map(|item| DagProvider {
            id: item.id.clone(),
            depends_on: item
                .dependencies
                .clone()
                .or_else(|| item.depends_on.clone())
                .unwrap_or_default(),
        })
        .collect();

    // `topologicalProviders` here is validation only (unknown/self/cycle
    // dependencies): its output order is immediately discarded into a Map
    // keyed by id, so downstream wave selection re-derives readiness from
    // `done` and re-sorts by id regardless of this order.
    let ordered = topological_providers(&normalized)?;

    let resources_by_id: BTreeMap<&str, &[(String, f64)]> = providers
        .iter()
        .map(|p| (p.id.as_str(), p.resources.as_slice()))
        .collect();

    let mut remaining: BTreeMap<String, Vec<String>> = ordered
        .into_iter()
        .map(|item| (item.id, item.depends_on))
        .collect();
    let mut done: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut waves: Vec<Vec<String>> = Vec::new();

    while !remaining.is_empty() {
        let mut ready: Vec<(String, Vec<String>)> = remaining
            .iter()
            .filter(|(_, deps)| deps.iter().all(|id| done.contains(id)))
            .map(|(id, deps)| (id.clone(), deps.clone()))
            .collect();
        ready.sort_by(|a, b| a.0.cmp(&b.0));

        if ready.is_empty() {
            return Err(ScheduleError::DependencyCycle);
        }

        let mut used: BTreeMap<String, f64> = BTreeMap::new();
        let mut selected: Vec<String> = Vec::new();

        for (id, _deps) in &ready {
            let resources = resources_by_id.get(id.as_str()).copied().unwrap_or(&[]);
            let fits = resources.iter().all(|(name, amount)| {
                let already_used = used.get(name).copied().unwrap_or(0.0);
                let ceiling = ceilings.get(name).copied().unwrap_or(f64::INFINITY);
                already_used + amount <= ceiling
            });
            if !fits {
                continue;
            }
            selected.push(id.clone());
            for (name, amount) in resources {
                *used.entry(name.clone()).or_insert(0.0) += amount;
            }
        }

        if selected.is_empty() {
            return Err(ScheduleError::AggregateCeilingPreventsProgress);
        }

        waves.push(selected.clone());
        for id in &selected {
            remaining.remove(id);
            done.insert(id.clone());
        }
    }

    let order = waves.iter().flatten().cloned().collect();
    Ok(ScheduleResult { order, waves })
}
