use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{id::HostId, require_version, ContractError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCapability {
    pub id: String,
    pub available: bool,
    pub fidelity: String,
    pub degradation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSurface {
    pub id: String,
    pub kind: String,
    pub capabilities: Vec<HostCapability>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDescriptor {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub host_id: HostId,
    pub platform: String,
    pub version: String,
    pub surfaces: Vec<HostSurface>,
    pub capabilities: Vec<HostCapability>,
}

impl HostDescriptor {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)
    }
}
