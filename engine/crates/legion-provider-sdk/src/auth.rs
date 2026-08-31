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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialEffectDecision {
    Allowed,
    Denied,
}

/// Guard-owned boundary. SDK receives only a decision, never policy internals.
pub trait CredentialAuthorizer: Send + Sync {
    fn authorize_credential_access(
        &self,
        provider_id: &str,
    ) -> Result<CredentialEffectDecision, AuthError>;
}

pub struct CredentialAccessGrant {
    provider_id: String,
}

impl CredentialAccessGrant {
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
}

pub fn authorize_credential_access(
    provider_id: &str,
    authorizer: &dyn CredentialAuthorizer,
) -> Result<CredentialAccessGrant, AuthError> {
    if provider_id.trim().is_empty() {
        return Err(AuthError::invalid("provider identity must be non-empty"));
    }
    match authorizer.authorize_credential_access(provider_id)? {
        CredentialEffectDecision::Allowed => Ok(CredentialAccessGrant {
            provider_id: provider_id.into(),
        }),
        CredentialEffectDecision::Denied => Err(AuthError {
            code: AuthErrorCode::Rejected,
            message: "credential access denied".into(),
        }),
    }
}

#[derive(Clone)]
pub struct BearerAuth {
    token: SecretString,
}

impl BearerAuth {
    fn new(token: SecretString) -> Result<Self, AuthError> {
        if token.expose_secret().trim().is_empty() {
            return Err(AuthError::invalid("credential must be non-empty"));
        }
        Ok(Self { token })
    }

    pub(crate) fn from_provider(
        provider: &dyn SecretProvider,
        _grant: &CredentialAccessGrant,
    ) -> Result<Self, AuthError> {
        let token = provider.bearer_token().map_err(|error| AuthError {
            code: error.code,
            message: "provider credential is unavailable".into(),
        })?;
        Self::new(token)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReceipt {
    pub provider_id: String,
    pub auth: RedactedAuth,
    pub effect: &'static str,
}

impl BearerAuth {
    pub fn redacted(&self) -> RedactedAuth {
        RedactedAuth {
            scheme: "bearer",
            present: true,
        }
    }
}
