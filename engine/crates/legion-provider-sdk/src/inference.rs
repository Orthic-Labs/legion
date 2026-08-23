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
    sync::Arc,
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
        }
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
