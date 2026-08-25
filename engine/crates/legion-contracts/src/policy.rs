use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    canonical_digest,
    id::{AgentId, RequestId, TaskId},
    require_version, ContractError,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum EffectClass {
    FILE_WRITE,
    FILE_DELETE,
    FILE_MOVE,
    COMMAND_EXEC,
    NETWORK_EGRESS,
    PROCESS_SPAWN,
    CREDENTIAL_ACCESS,
    DEPENDENCY_INSTALL,
    VCS_COMMIT,
    VCS_PUSH,
    PUBLISH,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalRequirement {
    None,
    User,
    Authority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub id: String,
    pub effect_class: EffectClass,
    pub allowed: bool,
    pub approval: ApprovalRequirement,
    pub targets: Vec<String>,
    pub required_trust: Option<String>,
    pub required_enforcement: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyPack {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub id: String,
    pub version: u32,
    pub rules: Vec<PolicyRule>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl PolicyPack {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        let mut ids = std::collections::BTreeSet::new();
        if self.id.trim().is_empty() {
            return Err(ContractError::InvalidContract {
                path: "id".into(),
                reason: "must be non-empty".into(),
            });
        }
        if self.version == 0 {
            return Err(ContractError::InvalidContract {
                path: "version".into(),
                reason: "must be positive".into(),
            });
        }
        for rule in &self.rules {
            require_version(rule.schema_version, 1)?;
            if !ids.insert(&rule.id) {
                return Err(ContractError::InvalidContract {
                    path: "rules.id".into(),
                    reason: "duplicate rule id".into(),
                });
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub request_id: RequestId,
    pub task_id: TaskId,
    pub requested_by: AgentId,
    pub effect_class: EffectClass,
    pub target: String,
    pub operation: String,
    pub preview: Option<String>,
    pub source_revision: String,
    pub approval_required: bool,
}

impl EffectRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        for (path, value) in [
            ("target", &self.target),
            ("operation", &self.operation),
            ("source_revision", &self.source_revision),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::InvalidContract {
                    path: path.into(),
                    reason: "must be non-empty".into(),
                });
            }
        }
        Ok(())
    }
}
