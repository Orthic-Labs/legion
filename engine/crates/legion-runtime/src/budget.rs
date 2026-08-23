use legion_contracts::BudgetCeiling;

use crate::error::RuntimeError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetReservation {
    pub active_time_ms: u64,
    pub cost_micros: u64,
    pub output_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetAccount {
    ceiling: BudgetCeiling,
    spent: BudgetReservation,
}

impl BudgetAccount {
    pub fn new(ceiling: BudgetCeiling) -> Self {
        Self {
            ceiling,
            spent: BudgetReservation {
                active_time_ms: 0,
                cost_micros: 0,
                output_bytes: 0,
            },
        }
    }
    pub fn spent(&self) -> &BudgetReservation {
        &self.spent
    }
    pub fn remaining(&self) -> BudgetReservation {
        BudgetReservation {
            active_time_ms: self
                .ceiling
                .max_active_time_ms
                .saturating_sub(self.spent.active_time_ms),
            cost_micros: self
                .ceiling
                .max_cost_micros
                .saturating_sub(self.spent.cost_micros),
            output_bytes: self
                .ceiling
                .max_output_bytes
                .saturating_sub(self.spent.output_bytes),
        }
    }
    pub fn reserve(&mut self, reservation: &BudgetReservation) -> Result<(), RuntimeError> {
        let remaining = self.remaining();
        if reservation.active_time_ms > remaining.active_time_ms
            || reservation.cost_micros > remaining.cost_micros
            || reservation.output_bytes > remaining.output_bytes
        {
            return Err(RuntimeError::Budget(
                "declared worst-case reservation exceeds remaining budget".into(),
            ));
        }
        self.spent.active_time_ms += reservation.active_time_ms;
        self.spent.cost_micros += reservation.cost_micros;
        self.spent.output_bytes += reservation.output_bytes;
        Ok(())
    }
    pub fn charge(&mut self, actual: &BudgetReservation) -> Result<(), RuntimeError> {
        self.reserve(actual)
    }
}
