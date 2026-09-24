//! Port of `src/lib/core/scheduler.mjs` (`providerDependencies`,
//! `scheduleProviders`).
//!
//! Not one of this packet's seven owned files, but ported here to close
//! `src/lib/verification/arcane/s11-bindings/eval-concurrency-convergence.mjs`'s
//! `AE-CONCURRENCY-ATTENTION-002`/`-006` gap in
//! `crate::wf_port::wf074::eval_concurrency_convergence`, which was
//! previously `BlockedOnDependency` on this exact module. `scheduleProviders`
//! is pure logic (a topological/resource scheduler, no I/O), so faking it
//! was never necessary — the only blocker was that no Rust port existed.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Provider {
    pub id: String,
    /// Raw `dependencies`/`dependsOn` input; resolved by `provider_dependencies`.
    pub dependencies: Vec<String>,
    pub depends_on: Option<Vec<String>>,
    pub resources: BTreeMap<String, f64>,
    pub concurrency_key: Option<String>,
}

impl Provider {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            dependencies: Vec::new(),
            depends_on: None,
            resources: BTreeMap::new(),
            concurrency_key: None,
        }
    }
    pub fn with_dependencies(mut self, deps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.dependencies = deps.into_iter().map(Into::into).collect();
        self
    }
    pub fn with_resources(mut self, resources: impl IntoIterator<Item = (&'static str, f64)>) -> Self {
        self.resources = resources.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        self
    }
}

#[derive(Debug)]
pub struct SchedulerError(pub String);

/// Mirrors JS `providerDependencies(provider)`. `dependencies`/`dependsOn`
/// agreement checking is folded in: both fields are `Vec<String>` here
/// already (unlike JS's untyped input), so the "must be string IDs" branch
/// is unreachable by construction and only the equality/dedup logic
/// applies.
pub fn provider_dependencies(provider: &Provider) -> Result<Vec<String>, SchedulerError> {
    if let Some(depends_on) = &provider.depends_on {
        let mut a: Vec<&str> = provider.dependencies.iter().map(String::as_str).collect();
        let mut b: Vec<&str> = depends_on.iter().map(String::as_str).collect();
        a.sort();
        b.sort();
        if !provider.dependencies.is_empty() && a != b {
            return Err(SchedulerError(format!("provider {} dependency fields disagree", provider.id)));
        }
    }
    let source = if !provider.dependencies.is_empty() {
        &provider.dependencies
    } else {
        provider.depends_on.as_ref().unwrap_or(&provider.dependencies)
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for id in source {
        if seen.insert(id.clone()) {
            out.push(id.clone());
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct ScheduleOptions {
    pub mode: Option<&'static str>, // "auto" | "serial"
    pub concurrency: usize,
    pub resources: Option<BTreeMap<String, f64>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Blocked {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScheduleResult {
    pub waves: Vec<Vec<String>>,
    /// Only populated when `resources` is `Some(..)` (mirrors the JS
    /// `result` object only existing on that branch).
    pub admitted: Vec<String>,
    pub ready: Vec<String>,
    pub blocked: Vec<Blocked>,
    pub has_resources: bool,
}

/// Mirrors JS `scheduleProviders(providers, { mode, concurrency, resources })`.
/// Returns `Err` for the JS `throw` cases that occur when `resources` is
/// `None` (unknown dependency, cycle, blocked provider, no progress); with
/// `resources: Some(..)` those become `blocked` entries instead, exactly as
/// in the JS source.
pub fn schedule_providers(providers: &[Provider], options: &ScheduleOptions) -> Result<ScheduleResult, SchedulerError> {
    let concurrency = if options.concurrency == 0 { 4 } else { options.concurrency };
    let mode = options.mode.unwrap_or("auto");
    let resources = options.resources.clone();

    let mut normalized: Vec<(String, Vec<String>, BTreeMap<String, f64>, Option<String>)> = Vec::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for p in providers {
        if !ids.insert(p.id.clone()) {
            return Err(SchedulerError(format!("duplicate provider ID: {}", p.id)));
        }
        let deps = provider_dependencies(p)?;
        normalized.push((p.id.clone(), deps, p.resources.clone(), p.concurrency_key.clone()));
    }

    let mut blocked: Vec<Blocked> = Vec::new();
    let mut blocked_ids: BTreeSet<String> = BTreeSet::new();
    let mut block = |id: &str, reason: String, blocked: &mut Vec<Blocked>, blocked_ids: &mut BTreeSet<String>| {
        if blocked_ids.insert(id.to_string()) {
            blocked.push(Blocked { id: id.to_string(), reason });
        }
    };

    for (id, deps, _, _) in &normalized {
        for dep in deps {
            if !ids.contains(dep) {
                block(id, format!("unknown-dependency:{dep}"), &mut blocked, &mut blocked_ids);
            }
        }
    }

    let propagate = |normalized: &Vec<(String, Vec<String>, BTreeMap<String, f64>, Option<String>)>,
                      blocked: &mut Vec<Blocked>,
                      blocked_ids: &mut BTreeSet<String>| {
        loop {
            let mut changed = false;
            for (id, deps, _, _) in normalized {
                if blocked_ids.contains(id) {
                    continue;
                }
                if let Some(dep) = deps.iter().find(|d| blocked_ids.contains(*d)) {
                    if blocked_ids.insert(id.clone()) {
                        blocked.push(Blocked { id: id.clone(), reason: format!("dependency-blocked:{dep}") });
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
    };
    propagate(&normalized, &mut blocked, &mut blocked_ids);

    if resources.is_none() && !blocked.is_empty() {
        return Err(SchedulerError(blocked[0].reason.clone()));
    }

    let mut remaining: BTreeMap<String, (Vec<String>, BTreeMap<String, f64>, Option<String>)> = normalized
        .iter()
        .filter(|(id, ..)| !blocked_ids.contains(id))
        .map(|(id, deps, res, ck)| (id.clone(), (deps.clone(), res.clone(), ck.clone())))
        .collect();

    let mut done: BTreeSet<String> = BTreeSet::new();
    let mut waves: Vec<Vec<String>> = Vec::new();

    while !remaining.is_empty() {
        let mut ready: Vec<(String, Vec<String>, BTreeMap<String, f64>, Option<String>)> = remaining
            .iter()
            .filter(|(_, (deps, _, _))| deps.iter().all(|d| done.contains(d)))
            .map(|(id, (deps, res, ck))| (id.clone(), deps.clone(), res.clone(), ck.clone()))
            .collect();
        ready.sort_by(|a, b| a.0.cmp(&b.0));

        if ready.is_empty() {
            if resources.is_none() {
                return Err(SchedulerError("provider dependency cycle".to_string()));
            }
            for id in remaining.keys() {
                if blocked_ids.insert(id.clone()) {
                    blocked.push(Blocked { id: id.clone(), reason: "dependency-cycle".to_string() });
                }
            }
            break;
        }

        let mut wave: Vec<String> = Vec::new();
        let mut used: BTreeMap<String, f64> = BTreeMap::new();
        let mut locks: BTreeSet<String> = BTreeSet::new();

        for (id, _, res, ck) in &ready {
            let claims: Vec<(&String, &f64)> = res.iter().collect();
            let impossible = resources.as_ref().map(|caps| {
                claims.iter().any(|(name, amount)| {
                    **amount < 0.0 || **amount > *caps.get(*name).unwrap_or(&f64::INFINITY)
                })
            }).unwrap_or(false);
            if impossible {
                if blocked_ids.insert(id.clone()) {
                    blocked.push(Blocked { id: id.clone(), reason: "resource-ceiling".to_string() });
                }
                continue;
            }
            if wave.len() >= concurrency || (mode == "serial" && !wave.is_empty()) {
                continue;
            }
            if let Some(key) = ck {
                if locks.contains(key) {
                    continue;
                }
            }
            let fits = resources.as_ref().map(|caps| {
                claims.iter().all(|(name, amount)| {
                    used.get(*name).copied().unwrap_or(0.0) + **amount <= *caps.get(*name).unwrap_or(&f64::INFINITY)
                })
            }).unwrap_or(true);
            if !fits {
                continue;
            }
            wave.push(id.clone());
            if let Some(key) = ck {
                locks.insert(key.clone());
            }
            for (name, amount) in claims {
                *used.entry(name.clone()).or_insert(0.0) += amount;
            }
        }

        for id in &blocked_ids {
            remaining.remove(id);
        }
        propagate(&normalized, &mut blocked, &mut blocked_ids);
        for id in &blocked_ids {
            remaining.remove(id);
        }

        if wave.is_empty() {
            if resources.is_none() {
                return Err(SchedulerError("scheduler cannot make progress".to_string()));
            }
            for (id, ..) in &ready {
                if blocked_ids.insert(id.clone()) {
                    blocked.push(Blocked { id: id.clone(), reason: "resource-ceiling".to_string() });
                }
            }
            propagate(&normalized, &mut blocked, &mut blocked_ids);
            break;
        }

        waves.push(wave.clone());
        for id in &wave {
            remaining.remove(id);
            done.insert(id.clone());
        }
    }

    if resources.is_none() {
        return Ok(ScheduleResult { waves, admitted: Vec::new(), ready: Vec::new(), blocked: Vec::new(), has_resources: false });
    }

    let admitted = waves.first().cloned().unwrap_or_default();
    let ready: Vec<String> = waves.iter().skip(1).flatten().cloned().collect();
    let mut blocked_sorted = blocked.clone();
    blocked_sorted.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(ScheduleResult { waves, admitted, ready, blocked: blocked_sorted, has_resources: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disjoint_providers_admit_in_one_wave_without_resources() {
        let providers = vec![
            Provider::new("author-a"),
            Provider::new("fixture-b"),
        ];
        let result = schedule_providers(&providers, &ScheduleOptions { concurrency: 2, ..Default::default() }).unwrap();
        assert_eq!(result.waves.len(), 1);
        assert_eq!(result.waves[0].len(), 2);
    }

    #[test]
    fn independent_ready_work_admitted_under_capacity() {
        let providers = vec![
            Provider::new("task-a").with_resources([("cpu", 1.0)]),
            Provider::new("task-b").with_resources([("cpu", 1.0)]),
            Provider::new("task-c").with_resources([("cpu", 1.0)]),
        ];
        let mut resources = BTreeMap::new();
        resources.insert("cpu".to_string(), 2.0);
        let result = schedule_providers(
            &providers,
            &ScheduleOptions { concurrency: 2, resources: Some(resources), ..Default::default() },
        )
        .unwrap();
        assert_eq!(result.admitted.len(), 2);
        assert_eq!(result.ready.len(), 1);
        assert!(result.blocked.is_empty());
    }

    #[test]
    fn unknown_dependency_throws_without_resources() {
        let providers = vec![Provider::new("a").with_dependencies(["missing"])];
        let err = schedule_providers(&providers, &ScheduleOptions { concurrency: 4, ..Default::default() });
        assert!(err.is_err());
    }

    #[test]
    fn cycle_blocks_with_resources_instead_of_throwing() {
        let providers = vec![
            Provider::new("a").with_dependencies(["b"]),
            Provider::new("b").with_dependencies(["a"]),
        ];
        let result = schedule_providers(
            &providers,
            &ScheduleOptions { concurrency: 4, resources: Some(BTreeMap::new()), ..Default::default() },
        )
        .unwrap();
        assert_eq!(result.blocked.len(), 2);
    }
}
