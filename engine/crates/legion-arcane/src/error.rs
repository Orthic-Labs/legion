use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArcaneError {
    #[error("{code}: {message}")]
    Typed { code: &'static str, message: String },
    #[error("canonical error: {0}")]
    Canonical(#[from] legion_contracts::canonical::CanonicalError),
    #[error("io error: {0}")]
    Io(String),
}

impl ArcaneError {
    pub fn typed(code: &'static str, message: impl Into<String>) -> Self {
        Self::Typed {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Typed { code, .. } => code,
            Self::Canonical(_) => "ARC_CANONICALIZATION_FAILED",
            Self::Io(_) => "ARC_STORE_CORRUPT",
        }
    }
}
