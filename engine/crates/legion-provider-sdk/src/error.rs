use std::fmt;

use legion_contracts::ProviderId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    MissingTool,
    Timeout,
    MalformedOutput,
    Cancelled,
    DuplicateProvider,
    UnknownImplementation,
    MissingDependency,
    DependencyCycle,
    IncompatibleVersion,
    InvalidRegistry,
    InvalidResult,
    PolicyDenied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub message: String,
    pub provider: Option<ProviderId>,
}

impl ProviderError {
    pub fn new(kind: ProviderErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            provider: None,
        }
    }

    pub fn for_provider(
        kind: ProviderErrorKind,
        provider: ProviderId,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            provider: Some(provider),
        }
    }

    pub fn missing_tool(tool: impl Into<String>) -> Self {
        Self::new(
            ProviderErrorKind::MissingTool,
            format!("missing provider tool: {}", tool.into()),
        )
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, "provider deadline exceeded")
    }

    pub fn malformed(message: impl Into<String>) -> Self {
        Self::new(ProviderErrorKind::MalformedOutput, message)
    }

    pub fn cancelled() -> Self {
        Self::new(ProviderErrorKind::Cancelled, "provider cancelled")
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(provider) = &self.provider {
            write!(
                output,
                "provider {}: {}: {}",
                provider, self.kind, self.message
            )
        } else {
            write!(output, "{}: {}", self.kind, self.message)
        }
    }
}

impl std::error::Error for ProviderError {}

impl fmt::Display for ProviderErrorKind {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::MissingTool => "missing_tool",
            Self::Timeout => "timeout",
            Self::MalformedOutput => "malformed_output",
            Self::Cancelled => "cancelled",
            Self::DuplicateProvider => "duplicate_provider",
            Self::UnknownImplementation => "unknown_implementation",
            Self::MissingDependency => "missing_dependency",
            Self::DependencyCycle => "dependency_cycle",
            Self::IncompatibleVersion => "incompatible_version",
            Self::InvalidRegistry => "invalid_registry",
            Self::InvalidResult => "invalid_result",
            Self::PolicyDenied => "policy_denied",
        };
        output.write_str(name)
    }
}

impl From<ProviderError> for legion_contracts::ContractError {
    fn from(error: ProviderError) -> Self {
        legion_contracts::ContractError::InvalidContract {
            path: "provider".into(),
            reason: error.to_string(),
        }
    }
}
