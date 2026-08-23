use legion_contracts::{canonical_digest, canonical_json_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

use crate::{
    capability::CapabilityCeiling,
    effect::{ContractVersion, EnforcementLevel, TrustLevel, POLICY_SCHEMA_VERSION},
    rule::PolicyRule,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnclassifiedEffect {
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasePolicy {
    pub max_ttl_seconds: u64,
    pub max_uses: u32,
    pub delegable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustMinima {
    pub mutation: TrustLevel,
    pub read_only: TrustLevel,
    pub claim_release: TrustLevel,
    pub legacy_import: TrustLevel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEnforcement {
    pub required_for_mutation: EnforcementLevel,
    pub required_for_read_only: EnforcementLevel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRequirements {
    pub effect_receipt: bool,
    pub bind_policy_digest: bool,
    pub bind_capability_id: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPack {
    pub schema_version: u32,
    pub kind: String,
    pub policy_id: String,
    pub version: u32,
    pub contract_versions: Vec<ContractVersion>,
    pub unclassified_effect: UnclassifiedEffect,
    pub effect_rules: Vec<PolicyRule>,
    pub capability: CapabilityCeiling,
    pub leases: LeasePolicy,
    pub trust_minima: TrustMinima,
    pub host_enforcement: HostEnforcement,
    pub receipt_requirements: ReceiptRequirements,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PackError {
    #[error("unsupported policy schema version {0}")]
    UnsupportedVersion(u32),
    #[error("policy pack field {0} is invalid: {1}")]
    Invalid(String, String),
    #[error("duplicate policy rule id {0}")]
    DuplicateRuleId(String),
    #[error("canonical policy digest failed: {0}")]
    Canonical(String),
}

impl PolicyPack {
    pub fn validate(&self) -> Result<(), PackError> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            return Err(PackError::UnsupportedVersion(self.schema_version));
        }
        if self.kind != "arcane-policy-pack" {
            return Err(PackError::Invalid(
                "kind".into(),
                "must be arcane-policy-pack".into(),
            ));
        }
        if self.policy_id.trim().is_empty() {
            return Err(PackError::Invalid(
                "policy_id".into(),
                "must be non-empty".into(),
            ));
        }
        if self.version == 0 {
            return Err(PackError::Invalid(
                "version".into(),
                "must be positive".into(),
            ));
        }
        if !matches!(self.unclassified_effect, UnclassifiedEffect::Deny) {
            return Err(PackError::Invalid(
                "unclassified_effect".into(),
                "must deny".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        for contract in &self.contract_versions {
            contract
                .validate()
                .map_err(|e| PackError::Invalid("contract_versions".into(), e))?;
        }
        for rule in &self.effect_rules {
            if rule.schema_version != POLICY_SCHEMA_VERSION {
                return Err(PackError::UnsupportedVersion(rule.schema_version));
            }
            if rule.id.trim().is_empty() {
                return Err(PackError::Invalid(
                    "effect_rules.id".into(),
                    "must be non-empty".into(),
                ));
            }
            if !ids.insert(&rule.id) {
                return Err(PackError::DuplicateRuleId(rule.id.clone()));
            }
        }
        if self.capability.max_ttl_seconds == 0
            || self.capability.max_uses == 0
            || self.leases.max_ttl_seconds == 0
            || self.leases.max_uses == 0
        {
            return Err(PackError::Invalid(
                "capability".into(),
                "lease ceilings must be positive".into(),
            ));
        }
        if self.capability.max_ttl_seconds > self.leases.max_ttl_seconds
            || self.capability.max_uses > self.leases.max_uses
            || self.capability.delegable && !self.leases.delegable
        {
            return Err(PackError::Invalid(
                "capability".into(),
                "capability ceiling exceeds lease policy".into(),
            ));
        }
        Ok(())
    }

    pub fn canonicalized(&self) -> Self {
        let mut value = self.clone();
        value.contract_versions.sort();
        value
            .effect_rules
            .sort_by(|left, right| left.id.cmp(&right.id));
        value
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PackError> {
        self.validate()?;
        canonical_json_bytes(&self.canonicalized()).map_err(|e| PackError::Canonical(e.to_string()))
    }

    pub fn digest(&self) -> Result<String, PackError> {
        self.validate()?;
        canonical_digest(&self.canonicalized()).map_err(|e| PackError::Canonical(e.to_string()))
    }
}
