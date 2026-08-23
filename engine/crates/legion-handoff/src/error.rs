use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceErrorCode {
    Unavailable,
    Denied,
    Invalid,
    Stale,
}

impl fmt::Display for SourceErrorCode {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Unavailable => "source_unavailable",
            Self::Denied => "source_denied",
            Self::Invalid => "source_invalid",
            Self::Stale => "source_stale",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceError {
    pub code: SourceErrorCode,
    pub source: String,
    pub detail: String,
}

impl SourceError {
    pub fn new(
        code: SourceErrorCode,
        source: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            source: source.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{} at {}: {}", self.code, self.source, self.detail)
    }
}

impl std::error::Error for SourceError {}

#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("{0}")]
    Source(#[from] SourceError),
    #[error("invalid handoff: {0}")]
    Invalid(String),
    #[error("handoff budget exceeded: {0}")]
    Budget(String),
    #[error("required handoff record unavailable: {0}")]
    RequiredUnavailable(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, HandoffError>;
