//! Rustls HTTP inference client for OpenAI-compatible provider endpoints.

use std::time::Instant;

use futures_util::StreamExt;
use serde_json::{json, Value};

use crate::{
    auth::{
        authorize_credential_access, AuthError, BearerAuth, CredentialAccessGrant,
        CredentialAuthorizer, CredentialReceipt, SecretProvider,
    },
    inference::{
        InferenceCallTrace, InferenceClient, InferenceError, InferenceErrorCode, InferenceRequest,
        InferenceResponse, InferenceStream, InferenceTraceSink, InferenceUsage,
    },
    retry::{retryable_status, RetryPolicy},
    stream::{SseDecoder, StreamEvent, StreamLimits},
};

const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_HEADERS: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_NAME_BYTES: usize = 256;
const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug)]
pub struct HttpInferenceConfig {
    pub endpoint: String,
    pub limits: StreamLimits,
    pub retry: RetryPolicy,
}

impl HttpInferenceConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            limits: StreamLimits::default(),
            retry: RetryPolicy::default(),
        }
    }
    fn validate(&self) -> Result<(), InferenceError> {
        if self.endpoint.trim().is_empty() {
            Err(InferenceError::invalid(
                "inference endpoint must be non-empty",
            ))
        } else {
            Ok(())
        }
    }
}

pub struct HttpInferenceClient {
    client: reqwest::Client,
    config: HttpInferenceConfig,
    auth: BearerAuth,
    _credential_scope: CredentialAccessGrant,
    trace_sink: Option<std::sync::Arc<dyn InferenceTraceSink>>,
}

impl HttpInferenceClient {
    fn new(
        config: HttpInferenceConfig,
        auth: BearerAuth,
        credential_scope: CredentialAccessGrant,
    ) -> Result<Self, InferenceError> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|error| {
                InferenceError::transport(
                    format!("HTTP client initialization failed: {error}"),
                    false,
                )
            })?;
        Ok(Self {
            client,
            config,
            auth,
            _credential_scope: credential_scope,
            trace_sink: None,
        })
    }

    fn with_client(
        client: reqwest::Client,
        config: HttpInferenceConfig,
        auth: BearerAuth,
        credential_scope: CredentialAccessGrant,
    ) -> Result<Self, InferenceError> {
        config.validate()?;
        Ok(Self {
            client,
            config,
            auth,
            _credential_scope: credential_scope,
            trace_sink: None,
        })
    }

    pub fn authorized(
        config: HttpInferenceConfig,
        provider_id: &str,
        secrets: &dyn SecretProvider,
        authorizer: &dyn CredentialAuthorizer,
    ) -> Result<(Self, CredentialReceipt), InferenceError> {
        let grant = authorize_credential_access(provider_id, authorizer)?;
        let auth = BearerAuth::from_provider(secrets, &grant)?;
        let receipt = CredentialReceipt {
            provider_id: grant.provider_id().into(),
            auth: auth.redacted(),
            effect: "CREDENTIAL_ACCESS",
        };
        Ok((Self::new(config, auth, grant)?, receipt))
    }

    pub fn with_authorized_client(
        client: reqwest::Client,
        config: HttpInferenceConfig,
        provider_id: &str,
        secrets: &dyn SecretProvider,
        authorizer: &dyn CredentialAuthorizer,
    ) -> Result<(Self, CredentialReceipt), InferenceError> {
        let grant = authorize_credential_access(provider_id, authorizer)?;
        let auth = BearerAuth::from_provider(secrets, &grant)?;
        let receipt = CredentialReceipt {
            provider_id: grant.provider_id().into(),
            auth: auth.redacted(),
            effect: "CREDENTIAL_ACCESS",
        };
        Ok((Self::with_client(client, config, auth, grant)?, receipt))
    }

    pub fn with_trace_sink(mut self, trace_sink: std::sync::Arc<dyn InferenceTraceSink>) -> Self {
        self.trace_sink = Some(trace_sink);
        self
    }

    fn trace(
        &self,
        request: &InferenceRequest,
        started: Instant,
        status: &str,
        usage: Option<&InferenceUsage>,
    ) {
        let Some(trace_sink) = &self.trace_sink else {
            return;
        };
        trace_sink.record(InferenceCallTrace {
            route_id: request
                .route_id
                .clone()
                .unwrap_or_else(|| "unattributed-route".into()),
            work_unit_id: request
                .work_unit_id
                .clone()
                .unwrap_or_else(|| "unattributed-work-unit".into()),
            model: request.model.clone(),
            elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            prompt_tokens: usage.and_then(|value| value.prompt_tokens),
            completion_tokens: usage.and_then(|value| value.completion_tokens),
            total_tokens: usage.and_then(|value| value.total_tokens),
            cost_micros: request.estimated_cost_micros,
            status: status.into(),
        });
    }

    async fn send(
        &self,
        request: &InferenceRequest,
        stream: bool,
    ) -> Result<reqwest::Response, InferenceError> {
        request.validate()?;
        if request.cancellation.is_cancelled() {
            return Err(InferenceError::cancelled());
        }
        if request.headers.len() > MAX_REQUEST_HEADERS {
            return Err(InferenceError::new(
                InferenceErrorCode::HeaderLimitExceeded,
                "request header count exceeds configured limit",
            ));
        }
        let mut header_bytes = 0usize;
        let mut builder = self
            .client
            .post(&self.config.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                if stream {
                    "text/event-stream"
                } else {
                    "application/json"
                },
            );
        for (name, value) in &request.headers {
            if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("cookie") {
                continue;
            }
            if name.len() > MAX_HEADER_NAME_BYTES || value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(InferenceError::new(
                    InferenceErrorCode::HeaderLimitExceeded,
                    "request header exceeds configured size limit",
                ));
            }
            header_bytes = header_bytes
                .saturating_add(name.len())
                .saturating_add(value.len());
            if header_bytes > MAX_HEADER_BYTES {
                return Err(InferenceError::new(
                    InferenceErrorCode::HeaderLimitExceeded,
                    "request headers exceed configured size limit",
                ));
            }
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::try_from(name),
                reqwest::header::HeaderValue::try_from(value),
            ) {
                builder = builder.header(name, value);
            }
        }
        let body = json!({ "model": request.model, "messages": [{"role": "system", "content": request.system}, {"role": "user", "content": request.user}], "max_tokens": request.max_tokens, "temperature": 0.2, "stream": stream });
        let body = serde_json::to_vec(&body)
            .map_err(|_| InferenceError::malformed("inference request could not be encoded"))?;
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(InferenceError::new(
                InferenceErrorCode::RequestTooLarge,
                "inference request exceeds configured body limit",
            ));
        }
        let builder = self.auth.apply(builder.body(body));
        let remaining = request.remaining();
        if remaining.is_zero() {
            return Err(InferenceError::timeout());
        }
        let send = builder.send();
        let response = tokio::select! {
            _ = request.cancellation.cancelled() => return Err(InferenceError::cancelled()),
            result = tokio::time::timeout(remaining, send) => result.map_err(|_| InferenceError::timeout())?.map_err(|error| InferenceError::transport(format!("HTTP transport failed: {error}"), error.is_timeout() || error.is_connect()))?,
        };
        validate_response_headers(&response)?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(InferenceError::http(
                status,
                format!("provider returned HTTP {status}"),
                retryable_status(status),
            ));
        }
        Ok(response)
    }

    async fn infer_once(
        &self,
        request: InferenceRequest,
    ) -> Result<InferenceResponse, InferenceError> {
        let response = self.send(&request, false).await?;
        let mut bytes = Vec::new();
        let mut body = response.bytes_stream();
        while let Some(chunk) = tokio::select! {
            _ = request.cancellation.cancelled() => return Err(InferenceError::cancelled()),
            result = tokio::time::timeout(request.remaining(), body.next()) => result.map_err(|_| InferenceError::timeout())?,
        } {
            let chunk = chunk.map_err(|error| {
                InferenceError::transport(format!("response body failed: {error}"), true)
            })?;
            if bytes.len().saturating_add(chunk.len()) > self.config.limits.max_body_bytes {
                return Err(InferenceError::new(
                    InferenceErrorCode::BodyTooLarge,
                    "provider response exceeds configured limit",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_response(&bytes, &request.model)
    }

    async fn stream_once(
        &self,
        request: InferenceRequest,
    ) -> Result<InferenceStream, InferenceError> {
        let response = self.send(&request, true).await?;
        let decoder = SseDecoder::new(self.config.limits);
        let cancellation = request.cancellation.clone();
        let deadline = request.deadline;
        let body = response.bytes_stream();
        let stream = futures_util::stream::unfold(
            (body, decoder, cancellation, deadline, false),
            |(mut body, mut decoder, cancellation, deadline, finished)| async move {
                if finished {
                    return None;
                }
                if cancellation.is_cancelled() {
                    return Some((
                        Ok(decoder.cancel()),
                        (body, decoder, cancellation, deadline, true),
                    ));
                }
                if std::time::Instant::now() >= deadline {
                    return Some((
                        Err(InferenceError::timeout()),
                        (body, decoder, cancellation, deadline, true),
                    ));
                }
                match tokio::select! {
                    _ = cancellation.cancelled() => return Some((Ok(decoder.cancel()), (body, decoder, cancellation, deadline, true))),
                    result = tokio::time::timeout(deadline.checked_duration_since(Instant::now()).unwrap_or_default(), body.next()) => result,
                } {
                    Ok(Some(Ok(bytes))) => {
                        let events = match decoder.push(&bytes) {
                            Ok(events) => events,
                            Err(error) => vec![decoder.failed(error.message)],
                        };
                        let terminal = events.iter().any(|event| {
                            matches!(
                                event,
                                StreamEvent::Completed { .. } | StreamEvent::Failed { .. }
                            )
                        });
                        if let Some(event) = events.into_iter().next() {
                            Some((Ok(event), (body, decoder, cancellation, deadline, terminal)))
                        } else {
                            Some((
                                Ok(StreamEvent::Started { model: None }),
                                (body, decoder, cancellation, deadline, false),
                            ))
                        }
                    }
                    Ok(Some(Err(error))) => Some((
                        Ok(decoder.failed(format!("response body failed: {error}"))),
                        (body, decoder, cancellation, deadline, true),
                    )),
                    Ok(None) => {
                        let event = match decoder.finish() {
                            Ok(event) => event,
                            Err(error) => decoder.failed(error.message),
                        };
                        Some((Ok(event), (body, decoder, cancellation, deadline, true)))
                    }
                    Err(_) => Some((
                        Ok(decoder.failed("inference stream deadline exceeded")),
                        (body, decoder, cancellation, deadline, true),
                    )),
                }
            },
        );
        Ok(Box::pin(stream))
    }
}

#[async_trait::async_trait]
impl InferenceClient for HttpInferenceClient {
    async fn infer(&self, request: InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        let mut last = None;
        for attempt in 1..=self.config.retry.max_attempts.max(1) {
            let started = Instant::now();
            match self.infer_once(request.clone()).await {
                Ok(response) => {
                    self.trace(&request, started, "complete", Some(&response.usage));
                    return Ok(response);
                }
                Err(error)
                    if self
                        .config
                        .retry
                        .can_retry(&error, attempt, request.deadline) =>
                {
                    self.trace(&request, started, "retry", None);
                    let delay = self.config.retry.delay(attempt, request.deadline);
                    tokio::select! {
                        _ = request.cancellation.cancelled() => return Err(InferenceError::cancelled()),
                        _ = tokio::time::sleep(delay) => { last = Some(error); }
                    }
                }
                Err(error) => {
                    self.trace(&request, started, "failed", None);
                    return Err(last
                        .map(|previous| self.config.retry.exhausted(previous))
                        .unwrap_or(error));
                }
            }
        }
        Err(self
            .config
            .retry
            .exhausted(last.unwrap_or_else(InferenceError::timeout)))
    }

    async fn stream(&self, request: InferenceRequest) -> Result<InferenceStream, InferenceError> {
        let started = Instant::now();
        let result = self.stream_once(request.clone()).await;
        self.trace(
            &request,
            started,
            if result.is_ok() {
                "stream-started"
            } else {
                "failed"
            },
            None,
        );
        result
    }
}

fn parse_response(
    bytes: &[u8],
    requested_model: &str,
) -> Result<InferenceResponse, InferenceError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| InferenceError::malformed("provider response is not valid JSON"))?;
    let choice = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .ok_or_else(|| InferenceError::malformed("provider response has no choices"))?;
    let text = choice
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| InferenceError::malformed("provider response has no message content"))?;
    if text.is_empty() {
        return Err(InferenceError::malformed(
            "provider response content is empty",
        ));
    }
    let usage = value
        .get("usage")
        .and_then(Value::as_object)
        .map(|object| InferenceUsage {
            prompt_tokens: object.get("prompt_tokens").and_then(Value::as_u64),
            completion_tokens: object.get("completion_tokens").and_then(Value::as_u64),
            total_tokens: object.get("total_tokens").and_then(Value::as_u64),
        })
        .unwrap_or_default();
    Ok(InferenceResponse {
        text: text.to_owned(),
        model: value
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(requested_model)
            .to_owned(),
        finish_reason: choice
            .get("finish_reason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        usage,
    })
}

fn validate_response_headers(response: &reqwest::Response) -> Result<(), InferenceError> {
    if response.headers().len() > MAX_REQUEST_HEADERS {
        return Err(InferenceError::new(
            InferenceErrorCode::HeaderLimitExceeded,
            "response header count exceeds configured limit",
        ));
    }
    let mut total = 0usize;
    for (name, value) in response.headers() {
        if name.as_str().len() > MAX_HEADER_NAME_BYTES
            || value.as_bytes().len() > MAX_HEADER_VALUE_BYTES
        {
            return Err(InferenceError::new(
                InferenceErrorCode::HeaderLimitExceeded,
                "response header exceeds configured size limit",
            ));
        }
        total = total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len());
    }
    if total > MAX_HEADER_BYTES {
        return Err(InferenceError::new(
            InferenceErrorCode::HeaderLimitExceeded,
            "response headers exceed configured size limit",
        ));
    }
    Ok(())
}

impl From<AuthError> for InferenceError {
    fn from(error: AuthError) -> Self {
        InferenceError::new(InferenceErrorCode::MissingCredential, error.message)
    }
}

#[cfg(test)]
mod credential_scope_tests {
    use super::*;
    use crate::auth::{AuthError, CredentialEffectDecision};
    use secrecy::SecretString;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Secrets(AtomicUsize);
    impl SecretProvider for Secrets {
        fn bearer_token(&self) -> Result<SecretString, AuthError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::from("never-print-this-token".to_string()))
        }
    }

    struct Authorizer(CredentialEffectDecision);
    impl CredentialAuthorizer for Authorizer {
        fn authorize_credential_access(
            &self,
            _provider_id: &str,
        ) -> Result<CredentialEffectDecision, AuthError> {
            Ok(self.0)
        }
    }

    #[test]
    fn grd_013_credentials_resolve_only_after_authorized_effect_and_receipt_is_redacted() {
        let secrets = Secrets(AtomicUsize::new(0));
        let denied = HttpInferenceClient::authorized(
            HttpInferenceConfig::new("https://provider.invalid"),
            "provider-1",
            &secrets,
            &Authorizer(CredentialEffectDecision::Denied),
        );
        assert!(denied.is_err());
        assert_eq!(secrets.0.load(Ordering::SeqCst), 0);

        let (_, receipt) = HttpInferenceClient::authorized(
            HttpInferenceConfig::new("https://provider.invalid"),
            "provider-1",
            &secrets,
            &Authorizer(CredentialEffectDecision::Allowed),
        )
        .expect("authorized transport");
        assert_eq!(secrets.0.load(Ordering::SeqCst), 1);
        assert!(receipt.auth.present);
        assert_eq!(receipt.effect, "CREDENTIAL_ACCESS");
        assert!(!format!("{receipt:?}").contains("never-print-this-token"));
    }
}
