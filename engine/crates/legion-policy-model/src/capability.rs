use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

use crate::effect::{EffectClass, TrustLevel};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCeiling {
    pub effects: BTreeSet<EffectClass>,
    pub operations: BTreeSet<String>,
    pub targets: BTreeSet<String>,
    pub max_ttl_seconds: u64,
    pub max_uses: u32,
    pub delegable: bool,
    pub trust: TrustLevel,
}

impl Default for CapabilityCeiling {
    fn default() -> Self {
        Self {
            effects: BTreeSet::new(),
            operations: BTreeSet::new(),
            targets: BTreeSet::new(),
            max_ttl_seconds: 1,
            max_uses: 1,
            delegable: false,
            trust: TrustLevel::Unauthenticated,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    pub schema_version: u32,
    pub id: String,
    pub effects: BTreeSet<EffectClass>,
    pub operations: BTreeSet<String>,
    pub targets: BTreeSet<String>,
    pub ttl_seconds: u64,
    pub max_uses: u32,
    pub delegable: bool,
    pub trust: TrustLevel,
    pub lease_id: Option<String>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CapabilityDenial {
    #[error("grant contains effect outside definition ceiling")]
    EffectOutsideCeiling,
    #[error("grant contains operation outside definition ceiling")]
    OperationOutsideCeiling,
    #[error("grant contains target outside definition ceiling")]
    TargetOutsideCeiling,
    #[error("grant ttl exceeds definition ceiling")]
    TtlExceedsCeiling,
    #[error("grant use count exceeds definition ceiling")]
    UsesExceedCeiling,
    #[error("grant is delegable while definition ceiling is not")]
    DelegationExceedsCeiling,
    #[error("grant trust is below definition ceiling")]
    TrustBelowCeiling,
    #[error("capability identity is empty")]
    EmptyIdentity,
}

impl CapabilityGrant {
    pub fn validate(&self) -> Result<(), CapabilityDenial> {
        if self.id.trim().is_empty() {
            return Err(CapabilityDenial::EmptyIdentity);
        }
        if self.ttl_seconds == 0 || self.max_uses == 0 {
            return Err(CapabilityDenial::TtlExceedsCeiling);
        }
        Ok(())
    }

    pub fn is_subset_of(&self, ceiling: &CapabilityCeiling) -> Result<(), CapabilityDenial> {
        self.validate()?;
        if !self.effects.is_subset(&ceiling.effects) {
            return Err(CapabilityDenial::EffectOutsideCeiling);
        }
        if !self.operations.is_subset(&ceiling.operations) {
            return Err(CapabilityDenial::OperationOutsideCeiling);
        }
        if !self.targets.is_subset(&ceiling.targets) {
            return Err(CapabilityDenial::TargetOutsideCeiling);
        }
        if self.ttl_seconds > ceiling.max_ttl_seconds {
            return Err(CapabilityDenial::TtlExceedsCeiling);
        }
        if self.max_uses > ceiling.max_uses {
            return Err(CapabilityDenial::UsesExceedCeiling);
        }
        if self.delegable && !ceiling.delegable {
            return Err(CapabilityDenial::DelegationExceedsCeiling);
        }
        if !self.trust.satisfies(ceiling.trust) {
            return Err(CapabilityDenial::TrustBelowCeiling);
        }
        Ok(())
    }
}

/// Intersection is the only composition operation that can widen neither side.
pub fn intersect(left: &CapabilityCeiling, right: &CapabilityCeiling) -> CapabilityCeiling {
    CapabilityCeiling {
        effects: left.effects.intersection(&right.effects).copied().collect(),
        operations: left
            .operations
            .intersection(&right.operations)
            .cloned()
            .collect(),
        targets: left.targets.intersection(&right.targets).cloned().collect(),
        max_ttl_seconds: left.max_ttl_seconds.min(right.max_ttl_seconds),
        max_uses: left.max_uses.min(right.max_uses),
        delegable: left.delegable && right.delegable,
        trust: left.trust.max(right.trust),
    }
}
