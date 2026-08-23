use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{
    capability::CapabilityGrant,
    effect::{ApprovalRequirement, ContractVersion, EffectClass, EnforcementLevel, TrustLevel},
    path::{CanonicalPath, PathOperation},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    None,
    User,
    Authority,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Absent,
    Active,
    Expired,
    Exhausted,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    NotRequired,
    Required,
    Present,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyContext {
    pub schema_version: u32,
    pub contract: ContractVersion,
    pub effect_class: EffectClass,
    pub operation: PathOperation,
    pub path: Option<CanonicalPath>,
    pub repository: String,
    pub worktree: String,
    pub trust: TrustLevel,
    pub enforcement: EnforcementLevel,
    pub approval: ApprovalState,
    pub lease: LeaseState,
    pub receipt: ReceiptState,
    pub grant: Option<CapabilityGrant>,
    pub tags: BTreeSet<String>,
}

impl PolicyContext {
    pub fn approval_satisfies(&self, requirement: ApprovalRequirement) -> bool {
        match requirement {
            ApprovalRequirement::None => true,
            ApprovalRequirement::User => matches!(
                self.approval,
                ApprovalState::User | ApprovalState::Authority
            ),
            ApprovalRequirement::Authority => self.approval == ApprovalState::Authority,
        }
    }
}
