use std::{io, path::PathBuf};

use thiserror::Error;

/// Typed failure classes shared by catalog discovery, parsing, and projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureCode {
    SourceDrift,
    SemanticBlocker,
    OwnershipCollision,
    BoundExceeded,
    UnrelatedChanges,
    InvalidCatalog,
}

impl FailureCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceDrift => "SOURCE_DRIFT",
            Self::SemanticBlocker => "SEMANTIC_BLOCKER",
            Self::OwnershipCollision => "OWNERSHIP_COLLISION",
            Self::BoundExceeded => "BOUND_EXCEEDED",
            Self::UnrelatedChanges => "UNRELATED_CHANGES",
            Self::InvalidCatalog => "INVALID_CATALOG",
        }
    }
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("SOURCE_DRIFT at {path}: {reason}")]
    SourceDrift { path: String, reason: String },
    #[error("SEMANTIC_BLOCKER: {reason}")]
    SemanticBlocker { reason: String },
    #[error("OWNERSHIP_COLLISION: {identity}")]
    OwnershipCollision { identity: String },
    #[error("BOUND_EXCEEDED: {detail}")]
    BoundExceeded { detail: String },
    #[error("UNRELATED_CHANGES at {path}: {reason}")]
    UnrelatedChanges { path: String, reason: String },
    #[error("invalid catalog at {path}: {reason}")]
    InvalidCatalog { path: String, reason: String },
    #[error("invalid frontmatter: {0}")]
    InvalidFrontmatter(String),
    #[error("unsupported catalog format `{0}`")]
    UnsupportedFormat(String),
    #[error("I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid UTF-8 in {path}")]
    Utf8 { path: String },
    #[error("YAML parse failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl CatalogError {
    pub const fn code(&self) -> FailureCode {
        match self {
            Self::SourceDrift { .. } => FailureCode::SourceDrift,
            Self::SemanticBlocker { .. } => FailureCode::SemanticBlocker,
            Self::OwnershipCollision { .. } => FailureCode::OwnershipCollision,
            Self::BoundExceeded { .. } => FailureCode::BoundExceeded,
            Self::UnrelatedChanges { .. } => FailureCode::UnrelatedChanges,
            _ => FailureCode::InvalidCatalog,
        }
    }
}
