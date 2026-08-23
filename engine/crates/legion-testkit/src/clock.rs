#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeClock {
    monotonic_ms: u64,
    wall_time_ms: i64,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl FakeClock {
    pub fn new(monotonic_ms: u64, wall_time_ms: i64) -> Self {
        Self {
            monotonic_ms,
            wall_time_ms,
        }
    }

    pub fn monotonic_ms(&self) -> u64 {
        self.monotonic_ms
    }

    pub fn wall_time_ms(&self) -> i64 {
        self.wall_time_ms
    }

    pub fn advance_monotonic_ms(&mut self, amount: u64) {
        self.monotonic_ms = self.monotonic_ms.saturating_add(amount);
    }

    pub fn set_wall_time_ms(&mut self, value: i64) {
        self.wall_time_ms = value;
    }
}
