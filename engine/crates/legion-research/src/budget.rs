use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::{error::ResearchError, workflow::Cancellation};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    pub max_sources: u64,
    pub max_calls: u64,
    pub max_bytes: u64,
    pub max_cost_micros: u64,
}

impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            max_sources: 32,
            max_calls: 64,
            max_bytes: 16 * 1024 * 1024,
            max_cost_micros: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetUsage {
    pub sources: u64,
    pub calls: u64,
    pub bytes: u64,
    pub cost_micros: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub limits: BudgetLimits,
    pub usage: BudgetUsage,
}

impl BudgetSnapshot {
    pub fn remaining(&self) -> BudgetUsage {
        BudgetUsage {
            sources: self.limits.max_sources.saturating_sub(self.usage.sources),
            calls: self.limits.max_calls.saturating_sub(self.usage.calls),
            bytes: self.limits.max_bytes.saturating_sub(self.usage.bytes),
            cost_micros: self
                .limits
                .max_cost_micros
                .saturating_sub(self.usage.cost_micros),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BudgetAccount {
    snapshot: BudgetSnapshot,
    deadline: Instant,
}

impl BudgetAccount {
    pub fn new(limits: BudgetLimits, deadline: Instant) -> Self {
        Self {
            snapshot: BudgetSnapshot {
                limits,
                usage: BudgetUsage::default(),
            },
            deadline,
        }
    }
    pub fn from_timeout(limits: BudgetLimits, timeout: Duration) -> Self {
        Self::new(limits, Instant::now() + timeout)
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn snapshot(&self) -> BudgetSnapshot {
        self.snapshot
    }
    pub fn remaining(&self) -> BudgetUsage {
        self.snapshot.remaining()
    }

    pub fn ensure_available(&self, cancellation: &Cancellation) -> Result<(), ResearchError> {
        if cancellation.is_cancelled() {
            return Err(ResearchError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(ResearchError::DeadlineExceeded);
        }
        Ok(())
    }

    pub fn reserve_call(&mut self, cancellation: &Cancellation) -> Result<(), ResearchError> {
        self.ensure_available(cancellation)?;
        self.reserve(
            "calls",
            1,
            self.snapshot.usage.calls,
            self.snapshot.limits.max_calls,
            |usage| usage.calls += 1,
        )
    }

    pub fn reserve_source(&mut self, cancellation: &Cancellation) -> Result<(), ResearchError> {
        self.ensure_available(cancellation)?;
        self.reserve(
            "sources",
            1,
            self.snapshot.usage.sources,
            self.snapshot.limits.max_sources,
            |usage| usage.sources += 1,
        )
    }

    pub fn reserve_bytes(
        &mut self,
        bytes: u64,
        cancellation: &Cancellation,
    ) -> Result<(), ResearchError> {
        self.ensure_available(cancellation)?;
        self.reserve(
            "bytes",
            bytes,
            self.snapshot.usage.bytes,
            self.snapshot.limits.max_bytes,
            |usage| usage.bytes += bytes,
        )
    }

    pub fn reserve_cost(
        &mut self,
        cost_micros: u64,
        cancellation: &Cancellation,
    ) -> Result<(), ResearchError> {
        self.ensure_available(cancellation)?;
        self.reserve(
            "cost_micros",
            cost_micros,
            self.snapshot.usage.cost_micros,
            self.snapshot.limits.max_cost_micros,
            |usage| usage.cost_micros += cost_micros,
        )
    }

    fn reserve<F>(
        &mut self,
        dimension: &'static str,
        requested: u64,
        used: u64,
        ceiling: u64,
        charge: F,
    ) -> Result<(), ResearchError>
    where
        F: FnOnce(&mut BudgetUsage),
    {
        let remaining = ceiling.saturating_sub(used);
        if requested > remaining {
            return Err(ResearchError::BudgetExceeded {
                dimension,
                requested,
                remaining,
            });
        }
        charge(&mut self.snapshot.usage);
        Ok(())
    }
}
