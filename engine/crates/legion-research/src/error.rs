use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResearchError {
    Invalid(String),
    InvalidSource(String),
    InvalidEvidence(String),
    BudgetExceeded {
        dimension: &'static str,
        requested: u64,
        remaining: u64,
    },
    DeadlineExceeded,
    Cancelled,
    SourceFailed {
        source: String,
        message: String,
    },
    Provider(String),
    Report(String),
}

impl ResearchError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
    pub fn source(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self::SourceFailed {
            source: source.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ResearchError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(out, "invalid research contract: {message}"),
            Self::InvalidSource(message) => write!(out, "invalid source: {message}"),
            Self::InvalidEvidence(message) => write!(out, "invalid evidence: {message}"),
            Self::BudgetExceeded { dimension, requested, remaining } => write!(out, "research budget exceeded for {dimension}: requested {requested}, remaining {remaining}"),
            Self::DeadlineExceeded => out.write_str("research workflow deadline exceeded"),
            Self::Cancelled => out.write_str("research workflow cancelled"),
            Self::SourceFailed { source, message } => write!(out, "source {source} failed: {message}"),
            Self::Provider(message) => write!(out, "research provider failed: {message}"),
            Self::Report(message) => write!(out, "invalid research report: {message}"),
        }
    }
}

impl std::error::Error for ResearchError {}

impl From<legion_provider_sdk::ProviderError> for ResearchError {
    fn from(error: legion_provider_sdk::ProviderError) -> Self {
        Self::Provider(error.to_string())
    }
}
