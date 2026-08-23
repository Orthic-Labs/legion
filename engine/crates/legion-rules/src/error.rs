use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid rule pack: {0}")]
    InvalidPack(String),
    #[error("duplicate rule id: {0}")]
    DuplicateRule(String),
    #[error("unsupported rule class: {0}")]
    UnsupportedClass(String),
    #[error("invalid pattern for {rule}: {source}")]
    InvalidPattern { rule: String, source: regex::Error },
    #[error("structural source unavailable: {0}")]
    SourceUnavailable(String),
    #[error("blueprint generation mismatch: expected {expected}, got {actual}")]
    GenerationMismatch { expected: String, actual: String },
}

pub type Result<T> = std::result::Result<T, RuleError>;
