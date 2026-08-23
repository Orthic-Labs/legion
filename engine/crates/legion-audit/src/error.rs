use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AuditError {
    #[error("SOURCE_DRIFT: {0}")]
    SourceDrift(String),
    #[error("SEMANTIC_BLOCKER: {0}")]
    SemanticBlocker(String),
    #[error("OWNERSHIP_COLLISION: {0}")]
    OwnershipCollision(String),
    #[error("BOUND_EXCEEDED: {0}")]
    BoundExceeded(String),
    #[error("UNRELATED_CHANGES: {0}")]
    UnrelatedChanges(String),
    #[error("invalid audit contract: {0}")]
    Invalid(String),
    #[error("provider failed: {0}")]
    Provider(String),
}

impl From<legion_contracts::ContractError> for AuditError {
    fn from(error: legion_contracts::ContractError) -> Self {
        Self::Invalid(error.to_string())
    }
}
