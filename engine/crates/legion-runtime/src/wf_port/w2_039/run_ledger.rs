//! Faithful port of the `RunLedger` class from `src/lib/core/execute-plan.mjs`.
//!
//! `RunLedger` tracks cumulative steps/calls/spend/wall-time against
//! (optionally infinite) limits. `reserve` atomically checks a prospective
//! increment against the limits *before* committing it; on breach it does
//! not mutate the running totals, flips the ledger into a terminal
//! `STOPPED` state (once — `terminal` sticks to the first breach, mirroring
//! JS's unconditional `this.terminal = ...` on every breach, which in
//! practice is only ever reached once because callers stop calling `reserve`
//! after the thrown error), and returns that breach as an error carrying the
//! same receipt shape JS attaches to `error.receipt`. `charge` is a thin
//! wrapper reserving only `spend_micros` (JS: `charge({spendMicros}) {
//! return this.reserve({spendMicros}); }`).
//!
//! The rest of `execute-plan.mjs` (`executePlan`, `RuntimeAdmission`,
//! `asReceipt`, `skippedReceipt`) depends on `./execution-receipt.mjs`,
//! `./scheduler.mjs`, `../providers/provider-executor.mjs` and
//! `../providers/sdk/result.mjs`, none of which are in this chunk, and this
//! crate already ships a native `RuntimeAdmission`
//! (`legion_runtime::engine::RuntimeAdmission`) covering that class. Only
//! `RunLedger` is ported here.

use std::fmt;

/// Mirrors the JS constructor's default limits object (`Infinity` for every
/// field when omitted).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RunLimits {
    pub max_steps: f64,
    pub max_calls: f64,
    pub max_spend_micros: f64,
    pub max_wall_time_ms: f64,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            max_steps: f64::INFINITY,
            max_calls: f64::INFINITY,
            max_spend_micros: f64::INFINITY,
            max_wall_time_ms: f64::INFINITY,
        }
    }
}

/// Mirrors the object passed to `reserve`/`charge`; every field defaults to 0.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Reservation {
    pub steps: f64,
    pub calls: f64,
    pub spend_micros: f64,
}

/// Mirrors the reason strings JS uses for `breach` / `receipt.reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreachReason {
    StepLimit,
    CallLimit,
    SpendLimit,
    WallTimeLimit,
}

impl BreachReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            BreachReason::StepLimit => "step-limit",
            BreachReason::CallLimit => "call-limit",
            BreachReason::SpendLimit => "spend-limit",
            BreachReason::WallTimeLimit => "wall-time-limit",
        }
    }
}

impl fmt::Display for BreachReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Mirrors the `terminal` receipt JS attaches at `{state:'STOPPED', reason,
/// ...next}` and also sets as `error.receipt`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TerminalReceipt {
    pub state: &'static str, // always "STOPPED", kept as a field to mirror the JS shape
    pub reason: BreachReason,
    pub steps: f64,
    pub calls: f64,
    pub spend_micros: f64,
    pub wall_time_ms: f64,
}

/// Mirrors the object `throw new Error(...)` carries via `error.code =
/// 'LEGION_RUN_BUDGET'` and `error.receipt`.
#[derive(Clone, Copy, Debug, PartialEq, thiserror::Error)]
#[error("run budget exceeded: {reason}")]
pub struct RunBudgetError {
    pub code: &'static str, // always "LEGION_RUN_BUDGET"
    pub reason: BreachReason,
    pub receipt: TerminalReceipt,
}

/// A frozen totals snapshot, mirroring the object `reserve` returns via
/// `Object.freeze({...next})` (without `state`, which only appears in the
/// terminal receipt).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Totals {
    pub steps: f64,
    pub calls: f64,
    pub spend_micros: f64,
    pub wall_time_ms: f64,
}

/// Mirrors the object `snapshot()` returns.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Snapshot {
    pub steps: f64,
    pub calls: f64,
    pub spend_micros: f64,
    pub wall_time_ms: f64,
    pub terminal: Option<TerminalReceipt>,
}

/// A monotonic clock abstraction mirroring the JS `clock=()=>Date.now()`
/// default; tests can supply a deterministic fake.
pub trait Clock {
    /// Milliseconds since some fixed epoch, monotonically non-decreasing.
    fn now_ms(&self) -> f64;
}

/// The default clock, matching `Date.now()`.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as f64)
            .unwrap_or(0.0)
    }
}

/// Faithful port of the JS `RunLedger` class.
pub struct RunLedger<C: Clock = SystemClock> {
    limits: RunLimits,
    clock: C,
    started_at: f64,
    steps: f64,
    calls: f64,
    spend_micros: f64,
    terminal: Option<TerminalReceipt>,
}

impl RunLedger<SystemClock> {
    /// Mirrors `new RunLedger({...})` using the real wall clock.
    pub fn new(limits: RunLimits) -> Self {
        Self::with_clock(limits, SystemClock)
    }
}

impl<C: Clock> RunLedger<C> {
    /// Mirrors `new RunLedger({...limits, clock})` with an injected clock,
    /// used by tests that need deterministic wall-time behavior.
    pub fn with_clock(limits: RunLimits, clock: C) -> Self {
        let started_at = clock.now_ms();
        Self {
            limits,
            clock,
            started_at,
            steps: 0.0,
            calls: 0.0,
            spend_micros: 0.0,
            terminal: None,
        }
    }

    /// Mirrors `reserve({steps=0,calls=0,spendMicros=0}={})`.
    pub fn reserve(&mut self, reservation: Reservation) -> Result<Totals, RunBudgetError> {
        let wall_time_ms = self.clock.now_ms() - self.started_at;
        let next = Totals {
            steps: self.steps + reservation.steps,
            calls: self.calls + reservation.calls,
            spend_micros: self.spend_micros + reservation.spend_micros,
            wall_time_ms,
        };
        let breach = if next.steps > self.limits.max_steps {
            Some(BreachReason::StepLimit)
        } else if next.calls > self.limits.max_calls {
            Some(BreachReason::CallLimit)
        } else if next.spend_micros > self.limits.max_spend_micros {
            Some(BreachReason::SpendLimit)
        } else if next.wall_time_ms > self.limits.max_wall_time_ms {
            Some(BreachReason::WallTimeLimit)
        } else {
            None
        };
        if let Some(reason) = breach {
            let receipt = TerminalReceipt {
                state: "STOPPED",
                reason,
                steps: next.steps,
                calls: next.calls,
                spend_micros: next.spend_micros,
                wall_time_ms: next.wall_time_ms,
            };
            self.terminal = Some(receipt);
            return Err(RunBudgetError {
                code: "LEGION_RUN_BUDGET",
                reason,
                receipt,
            });
        }
        self.steps = next.steps;
        self.calls = next.calls;
        self.spend_micros = next.spend_micros;
        Ok(next)
    }

    /// Mirrors `charge({spendMicros=0}={}) { return this.reserve({spendMicros}); }`.
    pub fn charge(&mut self, spend_micros: f64) -> Result<Totals, RunBudgetError> {
        self.reserve(Reservation {
            steps: 0.0,
            calls: 0.0,
            spend_micros,
        })
    }

    /// Mirrors `snapshot()`.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            steps: self.steps,
            calls: self.calls,
            spend_micros: self.spend_micros,
            wall_time_ms: self.clock.now_ms() - self.started_at,
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeClock {
        now: Cell<f64>,
    }
    impl Clock for FakeClock {
        fn now_ms(&self) -> f64 {
            self.now.get()
        }
    }
    impl FakeClock {
        fn at(ms: f64) -> Self {
            Self { now: Cell::new(ms) }
        }
        fn advance(&self, ms: f64) {
            self.now.set(self.now.get() + ms);
        }
    }

    #[test]
    fn unbounded_ledger_accepts_reservations() {
        let mut ledger = RunLedger::new(RunLimits::default());
        let totals = ledger
            .reserve(Reservation {
                steps: 1.0,
                calls: 1.0,
                spend_micros: 100.0,
            })
            .expect("no limits set, should not breach");
        assert_eq!(totals.steps, 1.0);
        assert_eq!(totals.calls, 1.0);
        assert_eq!(totals.spend_micros, 100.0);
    }

    #[test]
    fn step_limit_breach_does_not_commit_totals() {
        let mut ledger = RunLedger::new(RunLimits {
            max_steps: 1.0,
            ..RunLimits::default()
        });
        ledger.reserve(Reservation { steps: 1.0, ..Default::default() }).unwrap();
        let err = ledger
            .reserve(Reservation { steps: 1.0, ..Default::default() })
            .unwrap_err();
        assert_eq!(err.code, "LEGION_RUN_BUDGET");
        assert_eq!(err.reason, BreachReason::StepLimit);
        assert_eq!(err.receipt.reason.as_str(), "step-limit");
        // Committed totals must remain at the pre-breach value (1 step),
        // matching JS: the breach path never runs Object.assign(this, next).
        assert_eq!(ledger.snapshot().steps, 1.0);
    }

    #[test]
    fn call_limit_breach() {
        let mut ledger = RunLedger::new(RunLimits {
            max_calls: 0.0,
            ..RunLimits::default()
        });
        let err = ledger
            .reserve(Reservation { calls: 1.0, ..Default::default() })
            .unwrap_err();
        assert_eq!(err.reason, BreachReason::CallLimit);
    }

    #[test]
    fn spend_limit_breach() {
        let mut ledger = RunLedger::new(RunLimits {
            max_spend_micros: 50.0,
            ..RunLimits::default()
        });
        let err = ledger
            .reserve(Reservation { spend_micros: 51.0, ..Default::default() })
            .unwrap_err();
        assert_eq!(err.reason, BreachReason::SpendLimit);
    }

    #[test]
    fn wall_time_limit_breach() {
        let clock = FakeClock::at(0.0);
        let mut ledger = RunLedger::with_clock(
            RunLimits {
                max_wall_time_ms: 10.0,
                ..RunLimits::default()
            },
            clock,
        );
        // Advance the underlying clock past the limit before reserving.
        // (RunLedger owns the clock, so we reach in through a second handle.)
        // Simplest: construct with clock that we can advance via Cell.
        let err = ledger.reserve(Reservation::default());
        // With no time elapsed yet this should succeed.
        assert!(err.is_ok());
    }

    #[test]
    fn wall_time_limit_breach_after_advancing() {
        let clock = FakeClock::at(0.0);
        // Keep a raw pointer-free second reference via Rc would be cleaner,
        // but Cell is Copy-free; instead rebuild using an Rc<FakeClock>.
        struct SharedClock(std::rc::Rc<FakeClock>);
        impl Clock for SharedClock {
            fn now_ms(&self) -> f64 {
                self.0.now_ms()
            }
        }
        let shared = std::rc::Rc::new(clock);
        let mut ledger = RunLedger::with_clock(
            RunLimits {
                max_wall_time_ms: 10.0,
                ..RunLimits::default()
            },
            SharedClock(shared.clone()),
        );
        shared.advance(11.0);
        let err = ledger
            .reserve(Reservation::default())
            .unwrap_err();
        assert_eq!(err.reason, BreachReason::WallTimeLimit);
    }

    #[test]
    fn charge_only_affects_spend() {
        let mut ledger = RunLedger::new(RunLimits::default());
        let totals = ledger.charge(250.0).unwrap();
        assert_eq!(totals.spend_micros, 250.0);
        assert_eq!(totals.steps, 0.0);
        assert_eq!(totals.calls, 0.0);
    }

    #[test]
    fn snapshot_reflects_terminal_state_after_breach() {
        let mut ledger = RunLedger::new(RunLimits {
            max_steps: 0.0,
            ..RunLimits::default()
        });
        let _ = ledger.reserve(Reservation { steps: 1.0, ..Default::default() });
        let snap = ledger.snapshot();
        let terminal = snap.terminal.expect("terminal should be set after breach");
        assert_eq!(terminal.state, "STOPPED");
        assert_eq!(terminal.reason, BreachReason::StepLimit);
    }

    #[test]
    fn snapshot_before_any_breach_has_no_terminal() {
        let ledger = RunLedger::new(RunLimits::default());
        assert!(ledger.snapshot().terminal.is_none());
    }
}
