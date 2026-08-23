use std::fmt;

#[derive(Debug)]
pub enum RuntimeError {
    InvalidProfile(String),
    InvalidTask(String),
    GrantExceedsCeiling(String),
    Route(String),
    Plan(String),
    Budget(String),
    Scheduler(String),
    Provider(legion_provider_sdk::ProviderError),
    Escalation(String),
    Cancelled,
    DeadlineExceeded,
    Policy(String),
    Contract(String),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(value) => write!(out, "invalid profile: {value}"),
            Self::InvalidTask(value) => write!(out, "invalid task: {value}"),
            Self::GrantExceedsCeiling(value) => {
                write!(out, "invocation grant exceeds definition ceiling: {value}")
            }
            Self::Route(value) => write!(out, "route selection failed: {value}"),
            Self::Plan(value) => write!(out, "plan compilation failed: {value}"),
            Self::Budget(value) => write!(out, "budget exhausted: {value}"),
            Self::Scheduler(value) => write!(out, "provider scheduling failed: {value}"),
            Self::Provider(value) => write!(out, "provider error: {value}"),
            Self::Escalation(value) => write!(out, "escalation denied: {value}"),
            Self::Cancelled => out.write_str("cancelled"),
            Self::DeadlineExceeded => out.write_str("deadline exceeded"),
            Self::Policy(value) => write!(out, "policy denied: {value}"),
            Self::Contract(value) => write!(out, "contract error: {value}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<legion_provider_sdk::ProviderError> for RuntimeError {
    fn from(error: legion_provider_sdk::ProviderError) -> Self {
        Self::Provider(error)
    }
}

impl From<legion_contracts::ContractError> for RuntimeError {
    fn from(error: legion_contracts::ContractError) -> Self {
        Self::Contract(error.to_string())
    }
}
