use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    canonical_digest,
    id::{InvocationId, PlanId, ProviderId, ReceiptId, RequestId, TaskId},
    policy::EffectClass,
    require_version, ContractError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvocationStatus {
    Ok,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationReceipt {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub receipt_id: ReceiptId,
    pub invocation_id: InvocationId,
    pub request_id: RequestId,
    pub task_id: TaskId,
    pub plan_id: PlanId,
    pub provider: ProviderId,
    pub status: InvocationStatus,
    pub complete: bool,
    pub findings: Vec<String>,
    pub gaps: Vec<String>,
    pub artifacts: BTreeMap<String, String>,
}

impl InvocationReceipt {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        if self.complete && (!self.gaps.is_empty() || self.status != InvocationStatus::Ok) {
            return Err(ContractError::InvalidContract {
                path: "complete".into(),
                reason: "only successful gap-free invocation may be complete".into(),
            });
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceipt {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub receipt_id: ReceiptId,
    pub request_id: RequestId,
    pub effect_class: EffectClass,
    pub target: String,
    pub operation: String,
    pub result: String,
    pub matched: bool,
    pub actual_diff_digest: Option<String>,
    pub evidence: BTreeMap<String, serde_json::Value>,
}
