//! Port of src/lib/core/scheduler.mjs (packet P5a-core).
//!
//! Faithful port of `providerDependencies` and `scheduleProviders`. The JS
//! source treats `providers` as loosely-typed objects with optional
//! `dependencies`/`dependsOn`, `resources`, and `concurrencyKey` fields; the
//! Rust port models that as an explicit `SchedulerProvider` struct built by
//! the caller (the JS "either field, must agree" duplicate-field check has
//! no equivalent since Rust has one field).

use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct SchedulerProvider {
    pub id: String,
    pub dependencies: Vec<String>,
    /// Named resource claims, e.g. {"cpu": 1.0}.
    pub resources: BTreeMap<String, f64>,
    pub concurrency_key: Option<String>,
}

impl SchedulerProvider {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            dependencies: Vec::new(),
            resources: BTreeMap::new(),
            concurrency_key: None,
        }
    }

    pub fn with_dependencies(mut self, deps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.dependencies = deps.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_resources(mut self, resources: BTreeMap<String, f64>) -> Self {
        self.resources = resources;
        self
    }

    pub fn with_concurrency_key(mut self, key: impl Into<String>) -> Self {
        self.concurrency_key = Some(key.into());
        self
    }
}

/// Deduplicated dependency IDs for a provider (order not significant; JS
/// used a Set). Mirrors `providerDependencies` minus the dual-field
/// disagreement check, which does not apply to the single-field Rust type.
pub fn provider_dependencies(provider: &SchedulerProvider) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for dep in &provider.dependencies {
        if seen.insert(dep.clone()) {
            out.push(dep.clone());
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedProvider {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScheduleResult {
    /// Waves of provider IDs scheduled to run together, in order.
    pub waves: Vec<Vec<String>>,
    /// Set when `resources` ceilings were supplied (JS's "soft" scheduling
    /// mode that returns `{admitted, ready, blocked, waves}` instead of
    /// throwing on the first unschedulable provider).
    pub resourced: Option<ResourcedSchedule>,
}

#[derive(Debug, Clone, Default)]
pub struct ResourcedSchedule {
    pub admitted: Vec<String>,
    pub ready: Vec<String>,
    pub blocked: Vec<BlockedProvider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleMode {
    Auto,
    Serial,
}

#[derive(Debug, Clone)]
pub struct ScheduleOptions {
    pub mode: ScheduleMode,
    pub concurrency: usize,
    /// `None` mirrors JS `resources == null`: any scheduling failure
    /// (unknown dependency, cycle, no-progress) is a hard error. `Some`
    /// mirrors the "soft" resource-ceiling mode.
    pub resources: Option<BTreeMap<String, f64>>,
}

impl Default for ScheduleOptions {
    fn default() -> Self {
        Self {
            mode: ScheduleMode::Auto,
            concurrency: 4,
            resources: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    DuplicateProvider(String),
    Blocked(String),
    Cycle,
    NoProgress,
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulerError::DuplicateProvider(id) => write!(f, "duplicate provider ID: {id}"),
            SchedulerError::Blocked(reason) => write!(f, "{reason}"),
            SchedulerError::Cycle => write!(f, "provider dependency cycle"),
            SchedulerError::NoProgress => write!(f, "scheduler cannot make progress"),
        }
    }
}

impl std::error::Error for SchedulerError {}

/// Port of `scheduleProviders`. Returns `Ok(ScheduleResult)` with only
/// `waves` populated when `options.resources` is `None` (hard-fail mode,
/// matching JS `resources == null`), or with `resourced` populated as well
/// when resource ceilings are supplied (soft mode).
pub fn schedule_providers(
    providers: &[SchedulerProvider],
    options: &ScheduleOptions,
) -> Result<ScheduleResult, SchedulerError> {
    let mut ids: HashSet<&str> = HashSet::new();
    for p in providers {
        if !ids.insert(p.id.as_str()) {
            return Err(SchedulerError::DuplicateProvider(p.id.clone()));
        }
    }

    let deps: HashMap<&str, Vec<String>> = providers
        .iter()
        .map(|p| (p.id.as_str(), provider_dependencies(p)))
        .collect();

    let mut blocked: BTreeMap<String, String> = BTreeMap::new();
    let block = |blocked: &mut BTreeMap<String, String>, id: &str, reason: String| {
        blocked.entry(id.to_string()).or_insert(reason);
    };

    for p in providers {
        for dep in &deps[p.id.as_str()] {
            if !ids.contains(dep.as_str()) {
                block(&mut blocked, &p.id, format!("unknown-dependency:{dep}"));
            }
        }
    }

    let propagate = |blocked: &mut BTreeMap<String, String>| loop {
        let mut changed = false;
        for p in providers {
            if blocked.contains_key(&p.id) {
                continue;
            }
            if let Some(dep) = deps[p.id.as_str()].iter().find(|d| blocked.contains_key(*d)) {
                block(blocked, &p.id, format!("dependency-blocked:{dep}"));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    };
    propagate(&mut blocked);

    if options.resources.is_none() && !blocked.is_empty() {
        let (_, reason) = blocked.iter().next().unwrap();
        return Err(SchedulerError::Blocked(reason.clone()));
    }

    let mut remaining: BTreeMap<String, &SchedulerProvider> = providers
        .iter()
        .filter(|p| !blocked.contains_key(&p.id))
        .map(|p| (p.id.clone(), p))
        .collect();

    let mut done: HashSet<String> = HashSet::new();
    let mut waves: Vec<Vec<String>> = Vec::new();

    loop {
        if remaining.is_empty() {
            break;
        }
        let mut ready: Vec<&SchedulerProvider> = remaining
            .values()
            .filter(|p| deps[p.id.as_str()].iter().all(|d| done.contains(d)))
            .copied()
            .collect();
        ready.sort_by(|a, b| a.id.cmp(&b.id));

        if ready.is_empty() {
            if options.resources.is_none() {
                return Err(SchedulerError::Cycle);
            }
            for id in remaining.keys() {
                block(&mut blocked, id, "dependency-cycle".to_string());
            }
            break;
        }

        let mut wave: Vec<String> = Vec::new();
        let mut used: BTreeMap<String, f64> = BTreeMap::new();
        let mut locks: HashSet<String> = HashSet::new();

        for provider in &ready {
            let claims: Vec<(&String, &f64)> = provider.resources.iter().collect();
            let impossible = options.resources.as_ref().is_some_and(|res| {
                claims.iter().any(|(name, amount)| {
                    **amount < 0.0 || **amount > *res.get(*name).unwrap_or(&f64::INFINITY)
                })
            });
            if impossible {
                block(&mut blocked, &provider.id, "resource-ceiling".to_string());
                continue;
            }
            if wave.len() >= options.concurrency
                || (options.mode == ScheduleMode::Serial && !wave.is_empty())
            {
                continue;
            }
            if let Some(key) = &provider.concurrency_key {
                if locks.contains(key) {
                    continue;
                }
            }
            let fits = options.resources.as_ref().is_none_or(|res| {
                claims.iter().all(|(name, amount)| {
                    used.get(*name).copied().unwrap_or(0.0) + **amount
                        <= *res.get(*name).unwrap_or(&f64::INFINITY)
                })
            });
            if !fits {
                continue;
            }
            wave.push(provider.id.clone());
            if let Some(key) = &provider.concurrency_key {
                locks.insert(key.clone());
            }
            for (name, amount) in claims {
                *used.entry(name.clone()).or_insert(0.0) += *amount;
            }
        }

        for id in blocked.keys() {
            remaining.remove(id);
        }
        propagate(&mut blocked);
        for id in blocked.keys() {
            remaining.remove(id);
        }

        if wave.is_empty() {
            if options.resources.is_none() {
                return Err(SchedulerError::NoProgress);
            }
            for p in &ready {
                block(&mut blocked, &p.id, "resource-ceiling".to_string());
            }
            propagate(&mut blocked);
            break;
        }

        waves.push(wave.clone());
        for id in &wave {
            remaining.remove(id);
            done.insert(id.clone());
        }
    }

    if options.resources.is_none() {
        return Ok(ScheduleResult {
            waves,
            resourced: None,
        });
    }

    let admitted = waves.first().cloned().unwrap_or_default();
    let ready: Vec<String> = waves.iter().skip(1).flatten().cloned().collect();
    let mut blocked_list: Vec<BlockedProvider> = blocked
        .into_iter()
        .map(|(id, reason)| BlockedProvider { id, reason })
        .collect();
    blocked_list.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(ScheduleResult {
        resourced: Some(ResourcedSchedule {
            admitted,
            ready,
            blocked: blocked_list,
        }),
        waves,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_dependencies_dedupes() {
        let p = SchedulerProvider::new("a").with_dependencies(["x", "y", "x"]);
        assert_eq!(provider_dependencies(&p), vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn schedule_orders_by_dependency_waves() {
        let providers = vec![
            SchedulerProvider::new("a"),
            SchedulerProvider::new("b").with_dependencies(["a"]),
            SchedulerProvider::new("c").with_dependencies(["a"]),
        ];
        let result = schedule_providers(&providers, &ScheduleOptions::default()).unwrap();
        assert_eq!(result.waves.len(), 2);
        assert_eq!(result.waves[0], vec!["a".to_string()]);
        let mut second = result.waves[1].clone();
        second.sort();
        assert_eq!(second, vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn schedule_rejects_duplicate_ids() {
        let providers = vec![SchedulerProvider::new("a"), SchedulerProvider::new("a")];
        let err = schedule_providers(&providers, &ScheduleOptions::default()).unwrap_err();
        assert_eq!(err, SchedulerError::DuplicateProvider("a".to_string()));
    }

    #[test]
    fn schedule_rejects_unknown_dependency_hard_mode() {
        let providers = vec![SchedulerProvider::new("a").with_dependencies(["missing"])];
        let err = schedule_providers(&providers, &ScheduleOptions::default()).unwrap_err();
        assert!(matches!(err, SchedulerError::Blocked(_)));
    }

    #[test]
    fn schedule_rejects_cycle_hard_mode() {
        let providers = vec![
            SchedulerProvider::new("a").with_dependencies(["b"]),
            SchedulerProvider::new("b").with_dependencies(["a"]),
        ];
        let err = schedule_providers(&providers, &ScheduleOptions::default()).unwrap_err();
        assert_eq!(err, SchedulerError::Cycle);
    }

    #[test]
    fn schedule_soft_mode_reports_blocked_resource_ceiling() {
        let mut resources = BTreeMap::new();
        resources.insert("cpu".to_string(), 1.0);
        let mut claim = BTreeMap::new();
        claim.insert("cpu".to_string(), 2.0);
        let providers = vec![SchedulerProvider::new("a").with_resources(claim)];
        let opts = ScheduleOptions {
            resources: Some(resources),
            ..ScheduleOptions::default()
        };
        let result = schedule_providers(&providers, &opts).unwrap();
        let resourced = result.resourced.unwrap();
        assert!(resourced.admitted.is_empty());
        assert_eq!(resourced.blocked.len(), 1);
        assert_eq!(resourced.blocked[0].id, "a");
        assert_eq!(resourced.blocked[0].reason, "resource-ceiling");
    }

    #[test]
    fn schedule_respects_concurrency_key_exclusion() {
        let providers = vec![
            SchedulerProvider::new("a").with_concurrency_key("lock"),
            SchedulerProvider::new("b").with_concurrency_key("lock"),
        ];
        let result = schedule_providers(&providers, &ScheduleOptions::default()).unwrap();
        // Both share a concurrency key, so they cannot land in the same wave.
        assert_eq!(result.waves.len(), 2);
        assert_eq!(result.waves[0].len(), 1);
        assert_eq!(result.waves[1].len(), 1);
    }
}
