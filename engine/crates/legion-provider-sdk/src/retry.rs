//! Bounded retry classification for inference transport failures.

use std::time::{Duration, Instant};

use crate::inference::{InferenceError, InferenceErrorCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            initial_backoff: Duration::from_millis(25),
            max_backoff: Duration::from_millis(250),
        }
    }
}

impl RetryPolicy {
    pub fn disabled() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    pub fn can_retry(&self, error: &InferenceError, attempt: u32, deadline: Instant) -> bool {
        attempt < self.max_attempts
            && error.retryable
            && !error.effect_started
            && Instant::now() < deadline
    }

    pub fn delay(&self, attempt: u32, deadline: Instant) -> Duration {
        let exponent = attempt.saturating_sub(1).min(16);
        let multiplier = 1u32 << exponent;
        self.initial_backoff
            .saturating_mul(multiplier)
            .min(self.max_backoff)
            .min(
                deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_default(),
            )
    }

    pub fn exhausted(&self, last: InferenceError) -> InferenceError {
        if self.max_attempts <= 1 {
            return last;
        }
        let mut error = InferenceError::new(
            InferenceErrorCode::RetryExhausted,
            format!("inference retry budget exhausted: {}", last.message),
        );
        error.http_status = last.http_status;
        error.effect_started = last.effect_started;
        error
    }
}

/// HTTP statuses which are safe to retry before any provider effect is known.
pub fn retryable_status(status: u16) -> bool {
    matches!(status, 408 | 409 | 425 | 429 | 500 | 502 | 503 | 504)
}
