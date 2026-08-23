use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecisionError {
    #[error("invalid decision at {path}: {reason}")]
    Invalid { path: String, reason: String },
    #[error("unsupported decision schema version {0}")]
    UnsupportedVersion(u32),
    #[error("decision JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("decision storage error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("canonical decision error: {0}")]
    Canonical(#[from] legion_contracts::canonical::CanonicalError),
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

impl DecisionError {
    pub(crate) fn invalid(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.into(),
            reason: reason.into(),
        }
    }
}
