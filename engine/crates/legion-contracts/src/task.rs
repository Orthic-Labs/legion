use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    id::{AgentId, RequestId, TaskId},
    non_empty, require_version, ContractError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Latitude {
    Exact,
    Bounded,
    Open,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskStatus {
    Repair,
    BlockedDecision,
    NeedsAmendment,
    OutOfScope,
    BudgetStop,
    FailedContract,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub task_id: TaskId,
    pub request_id: RequestId,
    pub title: String,
    pub description: Option<String>,
    pub own_scope: Vec<String>,
    pub read_scope: Vec<String>,
    pub depends_on: Vec<TaskId>,
    pub implements_decisions: Vec<String>,
    pub latitude: Latitude,
    pub declared_checks: Vec<String>,
    pub evidence_requirements: Vec<String>,
    pub status: TaskStatus,
    pub assigned_authority: AgentId,
}

impl TaskSpec {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        non_empty("title", &self.title)?;
        if self.own_scope.is_empty() {
            return Err(ContractError::InvalidContract {
                path: "own_scope".into(),
                reason: "must contain at least one scope item".into(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub request_id: RequestId,
    pub task_id: Option<TaskId>,
    pub payload: serde_json::Value,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl RequestEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)
    }
}
