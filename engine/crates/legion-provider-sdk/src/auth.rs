//! Credential isolation for provider transports.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthErrorCode {
    Missing,
    Rejected,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthError {
    pub code: AuthErrorCode,
    pub message: String,
}

impl AuthError {
    pub fn missing() -> Self {
        Self {
            code: AuthErrorCode::Missing,
            message: "provider credential is unavailable".into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: AuthErrorCode::Invalid,
            message: message.into(),
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "provider authentication: {}", self.message)
    }
}
impl std::error::Error for AuthError {}

/// Secret lookup is the only API that may supply a provider credential.
/// Implementations must not return values from logs, receipts, or diagnostics.
pub trait SecretProvider: Send + Sync {
    fn bearer_token(&self) -> Result<SecretString, AuthError>;
}

#[derive(Clone)]
pub struct BearerAuth {
    token: SecretString,
}

impl BearerAuth {
    pub fn new(token: SecretString) -> Result<Self, AuthError> {
        if token.expose_secret().trim().is_empty() {
            return Err(AuthError::invalid("credential must be non-empty"));
        }
        Ok(Self { token })
    }

    pub fn from_provider(provider: &dyn SecretProvider) -> Result<Self, AuthError> {
        Self::new(provider.bearer_token()?)
    }

    pub(crate) fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.bearer_auth(self.token.expose_secret())
    }
}

impl fmt::Debug for BearerAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerAuth")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Stable, non-sensitive authentication metadata suitable for receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedactedAuth {
    pub scheme: &'static str,
    pub present: bool,
}

impl BearerAuth {
    pub fn redacted(&self) -> RedactedAuth {
        RedactedAuth {
            scheme: "bearer",
            present: true,
        }
    }
}
