use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewError {
    Invalid(String),
    Duplicate(String),
    UnknownCandidate(String),
    UnknownEvidence(String),
    Provenance(String),
    SelfClosure(String),
    Cancelled,
    Provider(String),
    Receipt(String),
}

impl fmt::Display for ReviewError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(value) => write!(out, "invalid review: {value}"),
            Self::Duplicate(value) => write!(out, "duplicate review identity: {value}"),
            Self::UnknownCandidate(value) => write!(out, "unknown candidate: {value}"),
            Self::UnknownEvidence(value) => write!(out, "unknown evidence: {value}"),
            Self::Provenance(value) => write!(out, "invalid review provenance: {value}"),
            Self::SelfClosure(value) => {
                write!(out, "provider cannot self-close candidate: {value}")
            }
            Self::Cancelled => out.write_str("review cancelled"),
            Self::Provider(value) => write!(out, "provider review failed: {value}"),
            Self::Receipt(value) => write!(out, "receipt failed: {value}"),
        }
    }
}

impl std::error::Error for ReviewError {}

impl From<legion_contracts::ContractError> for ReviewError {
    fn from(error: legion_contracts::ContractError) -> Self {
        Self::Invalid(error.to_string())
    }
}

impl From<legion_provider_sdk::ProviderError> for ReviewError {
    fn from(error: legion_provider_sdk::ProviderError) -> Self {
        Self::Provider(error.to_string())
    }
}
