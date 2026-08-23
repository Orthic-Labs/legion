use std::fmt::{Display, Formatter};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureCode {
    SourceDrift,
    SemanticBlocker,
    OwnershipCollision,
    BoundExceeded,
    UnrelatedChanges,
    HarnessConflict,
    InvalidDescriptor,
    Io,
}

impl FailureCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceDrift => "SOURCE_DRIFT",
            Self::SemanticBlocker => "SEMANTIC_BLOCKER",
            Self::OwnershipCollision => "OWNERSHIP_COLLISION",
            Self::BoundExceeded => "BOUND_EXCEEDED",
            Self::UnrelatedChanges => "UNRELATED_CHANGES",
            Self::HarnessConflict => "HARNESS_CONFLICT",
            Self::InvalidDescriptor => "INVALID_DESCRIPTOR",
            Self::Io => "IO_ERROR",
        }
    }
}

#[derive(Debug)]
pub enum HostError {
    SourceDrift { path: String, reason: String },
    SemanticBlocker { reason: String },
    OwnershipCollision { path: String, reason: String },
    BoundExceeded { reason: String },
    UnrelatedChanges { path: String, reason: String },
    HarnessConflict { path: String, reason: String },
    InvalidDescriptor { path: String, reason: String },
    Io { path: PathBuf, reason: String },
    Json(serde_json::Error),
    Toml(toml::de::Error),
}

impl Display for HostError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceDrift { path, reason } => {
                write!(formatter, "SOURCE_DRIFT at {path}: {reason}")
            }
            Self::SemanticBlocker { reason } => write!(formatter, "SEMANTIC_BLOCKER: {reason}"),
            Self::OwnershipCollision { path, reason } => {
                write!(formatter, "OWNERSHIP_COLLISION at {path}: {reason}")
            }
            Self::BoundExceeded { reason } => write!(formatter, "BOUND_EXCEEDED: {reason}"),
            Self::UnrelatedChanges { path, reason } => {
                write!(formatter, "UNRELATED_CHANGES at {path}: {reason}")
            }
            Self::HarnessConflict { path, reason } => {
                write!(formatter, "HARNESS_CONFLICT at {path}: {reason}")
            }
            Self::InvalidDescriptor { path, reason } => {
                write!(formatter, "invalid host descriptor at {path}: {reason}")
            }
            Self::Io { path, reason } => write!(formatter, "I/O at {}: {reason}", path.display()),
            Self::Json(error) => write!(formatter, "JSON parse failed: {error}"),
            Self::Toml(error) => write!(formatter, "TOML parse failed: {error}"),
        }
    }
}

impl std::error::Error for HostError {}
impl From<serde_json::Error> for HostError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<toml::de::Error> for HostError {
    fn from(error: toml::de::Error) -> Self {
        Self::Toml(error)
    }
}

impl HostError {
    pub const fn code(&self) -> FailureCode {
        match self {
            Self::SourceDrift { .. } => FailureCode::SourceDrift,
            Self::SemanticBlocker { .. } => FailureCode::SemanticBlocker,
            Self::OwnershipCollision { .. } => FailureCode::OwnershipCollision,
            Self::BoundExceeded { .. } => FailureCode::BoundExceeded,
            Self::UnrelatedChanges { .. } => FailureCode::UnrelatedChanges,
            Self::HarnessConflict { .. } => FailureCode::HarnessConflict,
            Self::InvalidDescriptor { .. } => FailureCode::InvalidDescriptor,
            Self::Io { .. } => FailureCode::Io,
            Self::Json(_) | Self::Toml(_) => FailureCode::InvalidDescriptor,
        }
    }
}
