#![forbid(unsafe_code)]

use serde::{de::Error as _, Deserialize, Deserializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("invalid {kind} identifier: {reason}")]
    InvalidId {
        kind: &'static str,
        reason: &'static str,
    },
    #[error("unsupported schema major version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid contract at {path}: {reason}")]
    InvalidContract { path: String, reason: String },
    #[error("canonical JSON error: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

pub mod agent;
pub mod canonical;
pub mod host;
pub mod id;
pub mod plan;
pub mod policy;
pub mod provider;
pub mod receipt;
pub mod report;
pub mod task;

pub use agent::{AgentDefinition, BudgetCeiling, InvocationGrant, RoutingCeiling, ToolCeiling};
pub use canonical::{
    canonical_digest, canonical_digest_hex, canonical_equal, canonical_json_bytes,
};
pub use host::{HostCapability, HostDescriptor, HostSurface};
pub use id::*;
pub use plan::{Plan, PlanNode, PlanNodeKind};
pub use policy::{EffectClass, EffectRequest, PolicyPack, PolicyRule};
pub use provider::{Coverage, FindingRef, ProviderResult, ProviderSpec, ProviderStatus};
pub use receipt::{InvocationReceipt, InvocationStatus};
pub use report::{Finding, Report, ReportStatus};
pub use task::{Latitude, TaskSpec, TaskStatus};

pub type AgentProfile = AgentDefinition;
pub type CapabilityGrant = InvocationGrant;
pub type ExecutionPlan = Plan;
pub type PlanV1 = Plan;
pub type ProviderRecord = ProviderSpec;
pub type ReportV1 = Report;

pub(crate) fn require_version(version: u32, supported: u32) -> Result<(), ContractError> {
    if version == supported {
        Ok(())
    } else {
        Err(ContractError::UnsupportedVersion(version))
    }
}

pub fn deserialize_schema_version_1<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version == 1 {
        Ok(version)
    } else {
        Err(D::Error::custom(format!(
            "unsupported schema major version {version}"
        )))
    }
}

pub fn deserialize_schema_version_2<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version == 2 {
        Ok(version)
    } else {
        Err(D::Error::custom(format!(
            "unsupported schema major version {version}"
        )))
    }
}

pub(crate) fn non_empty(path: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(ContractError::InvalidContract {
            path: path.into(),
            reason: "must be non-empty".into(),
        })
    } else {
        Ok(())
    }
}
