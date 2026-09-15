//! Typed host-side seam for native reasoning providers.
//!
//! The host owns the concrete reviewer transport, credential scope, fresh
//! context, and receipt signer.  This adapter deliberately exposes only a
//! versioned data envelope to the audit composition; it never accepts a shell
//! command, executable path, or model-supplied authority claim.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const REQUEST_SCHEMA_VERSION: u32 = 1;
pub const REQUEST_KIND: &str = "legion-reasoning-invocation";
pub const RESPONSE_SCHEMA_VERSION: u32 = 1;
pub const RESPONSE_KIND: &str = "legion-reasoning-host-response";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningHostRequest {
    pub schema_version: u32,
    pub kind: String,
    pub request_id: String,
    pub provider_id: String,
    pub contract: String,
    pub plan_digest: String,
    pub plan_signature: String,
    pub repository_id: String,
    pub inventory_generation: String,
    pub inventory_digest: String,
    pub denominator_digest: String,
    pub denominator_count: u64,
    pub denominator_paths: Vec<String>,
    pub packet: Value,
}

impl ReasoningHostRequest {
    pub fn validate(&self) -> Result<(), HostReasoningError> {
        if self.schema_version != REQUEST_SCHEMA_VERSION
            || self.kind != REQUEST_KIND
            || self.request_id.trim().is_empty()
            || self.provider_id.trim().is_empty()
            || self.contract.trim().is_empty()
            || self.plan_digest.trim().is_empty()
            || self.plan_signature.trim().is_empty()
            || self.repository_id.trim().is_empty()
            || self.inventory_generation.trim().is_empty()
            || self.inventory_digest.trim().is_empty()
            || self.denominator_digest.trim().is_empty()
            || self.packet.is_null()
        {
            return Err(HostReasoningError::Invalid(
                "malformed reasoning host request".into(),
            ));
        }
        if self
            .denominator_paths
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self.denominator_count != self.denominator_paths.len() as u64
        {
            return Err(HostReasoningError::Invalid(
                "reasoning denominator is not canonical".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningHostResponse {
    pub schema_version: u32,
    pub kind: String,
    pub result: Value,
    pub receipt: Value,
}

impl ReasoningHostResponse {
    pub fn validate(&self) -> Result<(), HostReasoningError> {
        if self.schema_version != RESPONSE_SCHEMA_VERSION
            || self.kind != RESPONSE_KIND
            || !self.result.is_object()
            || !self.receipt.is_object()
        {
            return Err(HostReasoningError::Invalid(
                "malformed reasoning host response".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostReasoningError {
    Unavailable,
    Degraded(String),
    Invalid(String),
    Invocation(String),
}

impl std::fmt::Display for HostReasoningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("reasoning host unavailable"),
            Self::Degraded(reason) => write!(formatter, "reasoning host degraded: {reason}"),
            Self::Invalid(reason) => write!(formatter, "invalid reasoning host exchange: {reason}"),
            Self::Invocation(reason) => {
                write!(formatter, "reasoning host invocation failed: {reason}")
            }
        }
    }
}

impl std::error::Error for HostReasoningError {}

/// Host composition implements this trait with its existing authenticated
/// reviewer service.  The service must return the host-signed receipt; the
/// audit side verifies it against the frozen request before accepting result
/// data.
pub trait ReasoningHostService: Send + Sync {
    fn invoke(
        &self,
        request: &ReasoningHostRequest,
    ) -> Result<ReasoningHostResponse, HostReasoningError>;
}

pub struct ReasoningHostAdapter<S> {
    service: S,
}

impl<S> ReasoningHostAdapter<S> {
    pub fn new(service: S) -> Self {
        Self { service }
    }
}

impl<S: ReasoningHostService> ReasoningHostService for ReasoningHostAdapter<S> {
    fn invoke(
        &self,
        request: &ReasoningHostRequest,
    ) -> Result<ReasoningHostResponse, HostReasoningError> {
        request.validate()?;
        let response = self.service.invoke(request)?;
        response.validate()?;
        Ok(response)
    }
}
