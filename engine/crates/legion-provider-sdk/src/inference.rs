//! Typed inference boundary used by providers.
//!
//! Implementations are deliberately transport-agnostic.  A host adapter may
//! inject an in-process implementation; the HTTP implementation lives in
//! [`crate::http_client`].  Neither path starts a process or serializes a
//! credential into a request receipt.

use std::{
    collections::BTreeMap,
    fmt,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures_util::Stream;
use tokio_util::sync::CancellationToken;

use crate::stream::StreamEvent;

pub type InferenceStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, InferenceError>> + Send>>;

#[derive(Clone, Debug)]
pub struct InferenceRequest {
    pub model: String,
    pub system: String,
    pub user: String,
    pub max_tokens: u32,
    pub deadline: Instant,
    pub cancellation: CancellationToken,
    pub headers: BTreeMap<String, String>,
    pub route_id: Option<String>,
    pub work_unit_id: Option<String>,
    pub estimated_cost_micros: u64,
}

impl InferenceRequest {
    pub fn new(
        model: impl Into<String>,
        system: impl Into<String>,
        user: impl Into<String>,
        deadline: Instant,
    ) -> Self {
        Self {
            model: model.into(),
            system: system.into(),
            user: user.into(),
            max_tokens: 2048,
            deadline,
            cancellation: CancellationToken::new(),
            headers: BTreeMap::new(),
            route_id: Some("direct".into()),
            work_unit_id: Some("standalone".into()),
            estimated_cost_micros: 0,
        }
    }

    pub fn with_attribution(
        mut self,
        route_id: impl Into<String>,
        work_unit_id: impl Into<String>,
    ) -> Self {
        self.route_id = Some(route_id.into());
        self.work_unit_id = Some(work_unit_id.into());
        self
    }

    pub fn remaining(&self) -> Duration {
        self.deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default()
    }

    pub fn validate(&self) -> Result<(), InferenceError> {
        if self.model.trim().is_empty() {
            return Err(InferenceError::invalid("model must be non-empty"));
        }
        if self.max_tokens == 0 {
            return Err(InferenceError::invalid(
                "max_tokens must be greater than zero",
            ));
        }
        if self.remaining().is_zero() {
            return Err(InferenceError::timeout());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InferenceCallTrace {
    pub route_id: String,
    pub work_unit_id: String,
    pub model: String,
    pub elapsed_ms: u64,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cost_micros: u64,
    pub status: String,
}

pub trait InferenceTraceSink: Send + Sync {
    fn record(&self, trace: InferenceCallTrace);
}

#[derive(Default)]
pub struct MemoryInferenceTrace {
    calls: Mutex<Vec<InferenceCallTrace>>,
}

impl MemoryInferenceTrace {
    pub fn calls(&self) -> Vec<InferenceCallTrace> {
        self.calls.lock().expect("inference trace").clone()
    }

    pub fn aggregate_by_work_unit(&self) -> BTreeMap<String, InferenceUsage> {
        let mut aggregate = BTreeMap::<String, InferenceUsage>::new();
        for call in self.calls() {
            let usage = aggregate.entry(call.work_unit_id).or_default();
            usage.prompt_tokens = sum_optional(usage.prompt_tokens, call.prompt_tokens);
            usage.completion_tokens = sum_optional(usage.completion_tokens, call.completion_tokens);
            usage.total_tokens = sum_optional(usage.total_tokens, call.total_tokens);
        }
        aggregate
    }

    pub fn aggregate_cost_by_work_unit(&self) -> BTreeMap<String, u64> {
        let mut aggregate = BTreeMap::new();
        for call in self.calls() {
            let cost = aggregate.entry(call.work_unit_id).or_insert(0u64);
            *cost = cost.saturating_add(call.cost_micros);
        }
        aggregate
    }
}

impl InferenceTraceSink for MemoryInferenceTrace {
    fn record(&self, trace: InferenceCallTrace) {
        self.calls.lock().expect("inference trace").push(trace);
    }
}

fn sum_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (None, None) => None,
        (left, right) => Some(
            left.unwrap_or_default()
                .saturating_add(right.unwrap_or_default()),
        ),
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InferenceUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InferenceResponse {
    pub text: String,
    pub model: String,
    pub finish_reason: Option<String>,
    pub usage: InferenceUsage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InferenceErrorCode {
    InvalidRequest,
    MissingCredential,
    Transport,
    HttpStatus,
    Timeout,
    Cancelled,
    MalformedResponse,
    MalformedStream,
    RequestTooLarge,
    BodyTooLarge,
    HeaderLimitExceeded,
    RetryExhausted,
    HostUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InferenceError {
    pub code: InferenceErrorCode,
    pub message: String,
    pub retryable: bool,
    pub effect_started: bool,
    pub http_status: Option<u16>,
}

impl InferenceError {
    pub fn new(code: InferenceErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
            effect_started: false,
            http_status: None,
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(InferenceErrorCode::InvalidRequest, message)
    }
    pub fn timeout() -> Self {
        Self::new(InferenceErrorCode::Timeout, "inference deadline exceeded")
    }
    pub fn cancelled() -> Self {
        Self::new(InferenceErrorCode::Cancelled, "inference cancelled")
    }
    pub fn transport(message: impl Into<String>, retryable: bool) -> Self {
        let mut e = Self::new(InferenceErrorCode::Transport, message);
        e.retryable = retryable;
        e
    }
    pub fn http(status: u16, message: impl Into<String>, retryable: bool) -> Self {
        let mut e = Self::new(InferenceErrorCode::HttpStatus, message);
        e.http_status = Some(status);
        e.retryable = retryable;
        e
    }
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::new(InferenceErrorCode::MalformedResponse, message)
    }
    pub fn with_effect_started(mut self) -> Self {
        self.effect_started = true;
        self.retryable = false;
        self
    }
}

impl fmt::Display for InferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for InferenceError {}

impl fmt::Display for InferenceErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid_request",
            Self::MissingCredential => "missing_credential",
            Self::Transport => "transport",
            Self::HttpStatus => "http_status",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::MalformedResponse => "malformed_response",
            Self::MalformedStream => "malformed_stream",
            Self::RequestTooLarge => "request_too_large",
            Self::BodyTooLarge => "body_too_large",
            Self::HeaderLimitExceeded => "header_limit_exceeded",
            Self::RetryExhausted => "retry_exhausted",
            Self::HostUnavailable => "host_unavailable",
        })
    }
}

#[async_trait]
pub trait InferenceClient: Send + Sync {
    async fn infer(&self, request: InferenceRequest) -> Result<InferenceResponse, InferenceError>;
    async fn stream(&self, request: InferenceRequest) -> Result<InferenceStream, InferenceError>;
}

/// Host-provided inference is intentionally an injected capability, not a
/// process or CLI fallback.
pub type HostInference = Arc<dyn InferenceClient>;

#[cfg(test)]
mod trace_tests {
    use super::*;

    #[test]
    fn leg_023_every_call_is_attributed_and_operator_aggregation_is_stable() {
        let trace = MemoryInferenceTrace::default();
        trace.record(InferenceCallTrace {
            route_id: "route-1".into(),
            work_unit_id: "work-1".into(),
            model: "model".into(),
            elapsed_ms: 4,
            prompt_tokens: Some(2),
            completion_tokens: Some(3),
            total_tokens: Some(5),
            cost_micros: 7,
            status: "complete".into(),
        });
        trace.record(InferenceCallTrace {
            route_id: "route-1".into(),
            work_unit_id: "work-1".into(),
            model: "model".into(),
            elapsed_ms: 5,
            prompt_tokens: Some(7),
            completion_tokens: Some(11),
            total_tokens: Some(18),
            cost_micros: 11,
            status: "complete".into(),
        });
        let aggregate = trace.aggregate_by_work_unit();
        assert_eq!(aggregate["work-1"].prompt_tokens, Some(9));
        assert_eq!(aggregate["work-1"].total_tokens, Some(23));
        assert_eq!(trace.aggregate_cost_by_work_unit()["work-1"], 18);
        let request = InferenceRequest::new(
            "model",
            "system",
            "user",
            Instant::now() + Duration::from_secs(1),
        );
        assert_eq!(request.route_id.as_deref(), Some("direct"));
        assert_eq!(request.work_unit_id.as_deref(), Some("standalone"));
    }
}
