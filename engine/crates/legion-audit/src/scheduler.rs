//! Deterministic scheduling policy for frozen audit plans.
//!
//! The plan freezes each provider's `execution` declaration (schedule class,
//! resource claims, concurrency key, parallelism cap, failure policy). This
//! module parses that declaration fail-closed and builds dependency-respecting
//! waves against a host capacity. It never runs providers and never observes
//! completion order: wave membership is a pure function of the frozen plan, the
//! host configuration, and already-settled outcomes, so results recorded in
//! frozen plan order are byte-identical however the host interleaves work.
//!
//! Optional frozen keys read from `execution` (all absent in today's registry;
//! absence means the conservative default):
//! - `retry: {"maxAttempts": n}`: bounded retry for no-effect providers only
//! - `effectful: bool`: explicit effect declaration (never overrides a derived
//!   `true`)
//! - `breakerGroup: str`, `breakerThreshold: n`: shared failure breaker
//! - `fallback: {"provider": id, "equivalence": "equivalent|degraded|none"}`
//! - `contextProviders: [id]`: extra providers whose results this provider may
//!   read (besides its dependencies and a visual capture source)

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::plan::{AuditProvider, ProviderKind};

/// Hard ceiling on frozen retry attempts; a plan cannot widen it.
pub const MAX_RETRY_ATTEMPTS: u32 = 3;
/// Default number of infrastructure failures that trips a breaker group.
pub const DEFAULT_BREAKER_THRESHOLD: u32 = 2;

/// Resources whose use implies an observable effect outside the process.
const EFFECT_RESOURCES: [&str; 8] = [
    "projectExecution",
    "browser",
    "nativeSurface",
    "virtualMachine",
    "simulator",
    "physicalDevice",
    "externalSystem",
    "signer",
];

/// Host capacity and parallelism. The default is sequential, which preserves
/// the historical one-provider-at-a-time behaviour.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    pub max_parallelism: usize,
    pub capacity: BTreeMap<String, u64>,
}

impl SchedulerConfig {
    pub fn default_capacity() -> BTreeMap<String, u64> {
        [
            ("cpu", 8),
            ("memoryMb", 16_384),
            ("io", 8),
            ("projectExecution", 1),
            ("browser", 1),
            ("nativeSurface", 1),
            ("virtualMachine", 1),
            ("simulator", 1),
            ("physicalDevice", 1),
            ("externalSystem", 1),
            ("reviewer", 1),
            ("signer", 1),
        ]
        .into_iter()
        .map(|(name, units)| (name.to_owned(), units))
        .collect()
    }

    pub fn sequential() -> Self {
        Self {
            max_parallelism: 1,
            capacity: Self::default_capacity(),
        }
    }

    pub fn parallel(max_parallelism: usize) -> Self {
        Self {
            max_parallelism: max_parallelism.max(1),
            capacity: Self::default_capacity(),
        }
    }

    pub fn with_capacity(mut self, resource: &str, units: u64) -> Self {
        self.capacity.insert(resource.to_owned(), units);
        self
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self::sequential()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleClass {
    Serial,
    ParallelSafe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailurePolicy {
    BlockDependents,
    Continue,
}

/// Declared proof equivalence of a fallback relative to its primary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FallbackEquivalence {
    Equivalent,
    Degraded,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackSpec {
    pub provider: String,
    pub equivalence: FallbackEquivalence,
}

/// Parsed frozen execution policy of one provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPolicy {
    pub schedule_class: ScheduleClass,
    pub claims: BTreeMap<String, u64>,
    pub concurrency_key: Option<String>,
    pub max_parallelism: Option<usize>,
    pub order_sensitive: bool,
    pub failure_policy: FailurePolicy,
    pub effectful: bool,
    /// Attempts the plan asked for (>= 1), before the effect rule applies.
    pub retry_requested: u32,
    pub breaker_group: Option<String>,
    pub breaker_threshold: u32,
    pub fallback: Option<FallbackSpec>,
    pub context_providers: Vec<String>,
    /// Set when the frozen declaration is malformed; the provider is then not
    /// scheduled and becomes an explicit gap.
    pub invalid: Option<String>,
}

impl ProviderPolicy {
    pub fn from_provider(provider: &AuditProvider) -> Self {
        let null = Value::Null;
        let execution = provider.configuration.get("execution").unwrap_or(&null);
        let mut invalid = None;
        let mut flag = |reason: String| {
            invalid.get_or_insert(reason);
        };

        // Unknown or absent class is serial: never assume parallel safety.
        let schedule_class = match execution.get("scheduleClass").and_then(Value::as_str) {
            Some("parallel-safe") => ScheduleClass::ParallelSafe,
            _ => ScheduleClass::Serial,
        };
        let failure_policy = match execution.get("failurePolicy").and_then(Value::as_str) {
            Some("continue") => FailurePolicy::Continue,
            _ => FailurePolicy::BlockDependents,
        };

        let mut claims = BTreeMap::new();
        match execution.get("resourceClaims") {
            None | Some(Value::Null) => {}
            Some(Value::Object(map)) => {
                for (name, units) in map {
                    match units.as_u64() {
                        Some(0) => {}
                        Some(units) => {
                            claims.insert(name.clone(), units);
                        }
                        None => flag(format!("resourceClaims.{name}")),
                    }
                }
            }
            Some(_) => flag("resourceClaims".into()),
        }

        let concurrency_key = match execution.get("concurrencyKey") {
            None | Some(Value::Null) => None,
            Some(Value::String(key)) if !key.is_empty() => Some(key.clone()),
            Some(_) => {
                flag("concurrencyKey".into());
                None
            }
        };
        let max_parallelism = match execution.get("maxParallelism") {
            None | Some(Value::Null) => None,
            Some(value) => match value.as_u64().filter(|n| *n >= 1) {
                Some(n) => Some(usize::try_from(n).unwrap_or(usize::MAX)),
                None => {
                    flag("maxParallelism".into());
                    None
                }
            },
        };
        let order_sensitive = execution
            .get("orderSensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let derived_effect = matches!(
            provider.kind,
            ProviderKind::TypedExternalProjectTool
                | ProviderKind::HostService
                | ProviderKind::EffectExecutor
        ) || EFFECT_RESOURCES
            .iter()
            .any(|resource| claims.get(*resource).copied().unwrap_or(0) > 0)
            // An unknown resource claim is treated as an effect: fail closed.
            || claims
                .keys()
                .any(|name| !SchedulerConfig::default_capacity().contains_key(name));
        let effectful = derived_effect
            || execution
                .get("effectful")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        let retry_requested = match execution.get("retry").and_then(|r| r.get("maxAttempts")) {
            None | Some(Value::Null) => 1,
            Some(value) => match value.as_u64().filter(|n| *n >= 1) {
                Some(n) => u32::try_from(n).unwrap_or(u32::MAX).min(MAX_RETRY_ATTEMPTS),
                None => {
                    flag("retry.maxAttempts".into());
                    1
                }
            },
        };

        let breaker_group = match execution.get("breakerGroup") {
            None | Some(Value::Null) => None,
            Some(Value::String(group)) if !group.is_empty() => Some(group.clone()),
            Some(_) => {
                flag("breakerGroup".into());
                None
            }
        };
        let breaker_threshold = match execution.get("breakerThreshold") {
            None | Some(Value::Null) => DEFAULT_BREAKER_THRESHOLD,
            Some(value) => match value.as_u64().filter(|n| *n >= 1) {
                Some(n) => u32::try_from(n).unwrap_or(u32::MAX),
                None => {
                    flag("breakerThreshold".into());
                    DEFAULT_BREAKER_THRESHOLD
                }
            },
        };

        let fallback = match execution.get("fallback") {
            None | Some(Value::Null) => None,
            Some(value) => match value.get("provider").and_then(Value::as_str) {
                Some(id) if !id.is_empty() => Some(FallbackSpec {
                    provider: id.to_owned(),
                    // Unknown or absent equivalence claims no equivalence.
                    equivalence: match value.get("equivalence").and_then(Value::as_str) {
                        Some("equivalent") => FallbackEquivalence::Equivalent,
                        Some("degraded") => FallbackEquivalence::Degraded,
                        _ => FallbackEquivalence::None,
                    },
                }),
                _ => {
                    flag("fallback.provider".into());
                    None
                }
            },
        };

        let mut context_providers = Vec::new();
        match execution.get("contextProviders") {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in items {
                    match item.as_str() {
                        Some(id) if !id.is_empty() => context_providers.push(id.to_owned()),
                        _ => flag("contextProviders".into()),
                    }
                }
            }
            Some(_) => flag("contextProviders".into()),
        }

        Self {
            schedule_class,
            claims,
            concurrency_key,
            max_parallelism,
            order_sensitive,
            failure_policy,
            effectful,
            retry_requested,
            breaker_group,
            breaker_threshold,
            fallback,
            context_providers,
            invalid,
        }
    }

    /// Attempts actually allowed: effectful providers are never re-run.
    pub fn attempts_allowed(&self) -> u32 {
        if self.effectful {
            1
        } else {
            self.retry_requested.max(1)
        }
    }

    pub fn retry_denied_for_effect(&self) -> bool {
        self.effectful && self.retry_requested > 1
    }

    /// First claimed resource that exceeds the host capacity outright. Such a
    /// provider can never be scheduled and must become an explicit gap.
    pub fn exceeds_capacity(&self, config: &SchedulerConfig) -> Option<String> {
        self.claims
            .iter()
            .find(|(name, units)| **units > config.capacity.get(*name).copied().unwrap_or(0))
            .map(|(name, _)| name.clone())
    }

    fn serialises(&self) -> bool {
        self.schedule_class == ScheduleClass::Serial || self.order_sensitive
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Admitted,
    /// Does not fit this wave; later candidates may still be admitted.
    Deferred,
    /// Must run ahead of any later candidate; stop filling this wave.
    Barrier,
}

/// Builds one wave from candidates offered in frozen plan order.
pub struct WaveBuilder<'a> {
    config: &'a SchedulerConfig,
    members: Vec<usize>,
    used: BTreeMap<String, u64>,
    keys: BTreeSet<String>,
    cap: usize,
    serial_member: bool,
}

impl<'a> WaveBuilder<'a> {
    pub fn new(config: &'a SchedulerConfig) -> Self {
        Self {
            config,
            members: Vec::new(),
            used: BTreeMap::new(),
            keys: BTreeSet::new(),
            cap: usize::MAX,
            serial_member: false,
        }
    }

    pub fn try_admit(&mut self, index: usize, policy: &ProviderPolicy) -> Admission {
        if policy.serialises() {
            if !self.members.is_empty() {
                return Admission::Barrier;
            }
        } else {
            if self.serial_member {
                return Admission::Barrier;
            }
            let limit = self
                .config
                .max_parallelism
                .max(1)
                .min(self.cap)
                .min(policy.max_parallelism.unwrap_or(usize::MAX));
            if self.members.len() + 1 > limit {
                return Admission::Deferred;
            }
            if let Some(key) = &policy.concurrency_key {
                if self.keys.contains(key) {
                    return Admission::Deferred;
                }
            }
            let fits = policy.claims.iter().all(|(name, units)| {
                self.used.get(name).copied().unwrap_or(0) + units
                    <= self.config.capacity.get(name).copied().unwrap_or(0)
            });
            if !fits {
                return Admission::Deferred;
            }
        }
        for (name, units) in &policy.claims {
            *self.used.entry(name.clone()).or_insert(0) += units;
        }
        if let Some(key) = &policy.concurrency_key {
            self.keys.insert(key.clone());
        }
        if let Some(max) = policy.max_parallelism {
            self.cap = self.cap.min(max);
        }
        self.serial_member |= policy.serialises();
        self.members.push(index);
        Admission::Admitted
    }

    pub fn finish(self) -> Vec<usize> {
        self.members
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(class: ScheduleClass) -> ProviderPolicy {
        ProviderPolicy {
            schedule_class: class,
            claims: BTreeMap::new(),
            concurrency_key: None,
            max_parallelism: None,
            order_sensitive: false,
            failure_policy: FailurePolicy::BlockDependents,
            effectful: false,
            retry_requested: 1,
            breaker_group: None,
            breaker_threshold: DEFAULT_BREAKER_THRESHOLD,
            fallback: None,
            context_providers: Vec::new(),
            invalid: None,
        }
    }

    #[test]
    fn serial_provider_runs_alone_and_blocks_later_candidates() {
        let config = SchedulerConfig::parallel(4);
        let mut wave = WaveBuilder::new(&config);
        assert_eq!(
            wave.try_admit(0, &policy(ScheduleClass::ParallelSafe)),
            Admission::Admitted
        );
        assert_eq!(
            wave.try_admit(1, &policy(ScheduleClass::Serial)),
            Admission::Barrier
        );
        assert_eq!(wave.finish(), vec![0]);
    }

    #[test]
    fn concurrency_key_and_capacity_defer() {
        let config = SchedulerConfig::parallel(4).with_capacity("cpu", 2);
        let mut keyed = policy(ScheduleClass::ParallelSafe);
        keyed.concurrency_key = Some("tool".into());
        keyed.claims.insert("cpu".into(), 1);
        let mut heavy = policy(ScheduleClass::ParallelSafe);
        heavy.claims.insert("cpu".into(), 2);
        let mut wave = WaveBuilder::new(&config);
        assert_eq!(wave.try_admit(0, &keyed), Admission::Admitted);
        assert_eq!(wave.try_admit(1, &keyed), Admission::Deferred);
        assert_eq!(wave.try_admit(2, &heavy), Admission::Deferred);
        assert_eq!(wave.finish(), vec![0]);
    }

    #[test]
    fn effectful_claims_disable_retry() {
        let mut p = policy(ScheduleClass::ParallelSafe);
        p.retry_requested = 3;
        assert_eq!(p.attempts_allowed(), 3);
        p.effectful = true;
        assert_eq!(p.attempts_allowed(), 1);
        assert!(p.retry_denied_for_effect());
    }
}
