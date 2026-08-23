use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    UnsupportedContract,
    UnknownEffect,
    InvalidIdentity,
    InvalidScope,
    DefinitionCeiling,
    InvocationGrant,
    InvalidPath,
    ExplicitDeny,
    ApprovalRequired,
    LeaseInvalid,
    TrustInsufficient,
    EnforcementInsufficient,
    ReceiptRequired,
    NoMatchingRule,
    MalformedPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub schema_version: u32,
    pub outcome: DecisionOutcome,
    pub reason: Option<DenialReason>,
    pub matched_rule_ids: Vec<String>,
    pub rejected_alternatives: Vec<String>,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_digest: String,
}

impl PolicyDecision {
    pub fn allow(
        policy_id: impl Into<String>,
        policy_version: u32,
        policy_digest: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            outcome: DecisionOutcome::Allow,
            reason: None,
            matched_rule_ids: Vec::new(),
            rejected_alternatives: Vec::new(),
            policy_id: policy_id.into(),
            policy_version,
            policy_digest: policy_digest.into(),
        }
    }
    pub fn deny(
        reason: DenialReason,
        policy_id: impl Into<String>,
        policy_version: u32,
        policy_digest: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            outcome: DecisionOutcome::Deny,
            reason: Some(reason),
            matched_rule_ids: Vec::new(),
            rejected_alternatives: Vec::new(),
            policy_id: policy_id.into(),
            policy_version,
            policy_digest: policy_digest.into(),
        }
    }
}
