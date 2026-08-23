use thiserror::Error;

/// Typed failures produced while evaluating immutable policy inputs.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyEvaluationError {
    #[error("policy pack is invalid: {0}")]
    InvalidPolicy(String),
    #[error("unsupported contract")]
    UnsupportedContract,
    #[error("unknown effect")]
    UnknownEffect,
    #[error("invalid identity")]
    InvalidIdentity,
    #[error("invalid scope")]
    InvalidScope,
    #[error("definition ceiling exceeded")]
    DefinitionCeiling,
    #[error("invocation grant is invalid")]
    InvocationGrant,
    #[error("canonical target or path is invalid")]
    InvalidPath,
    #[error("explicit deny")]
    ExplicitDeny,
    #[error("approval required")]
    ApprovalRequired,
    #[error("lease is invalid")]
    LeaseInvalid,
    #[error("trust is insufficient")]
    TrustInsufficient,
    #[error("sandbox or host enforcement is insufficient")]
    EnforcementInsufficient,
    #[error("effect receipt is required")]
    ReceiptRequired,
    #[error("no matching allow rule")]
    NoMatchingRule,
    #[error("evaluator error: {0}")]
    EvaluatorError(String),
}
