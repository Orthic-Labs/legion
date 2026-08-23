#![forbid(unsafe_code)]

pub mod capability;
pub mod context;
pub mod decision;
pub mod effect;
pub mod pack;
pub mod path;
pub mod rule;

pub use capability::{intersect, CapabilityCeiling, CapabilityDenial, CapabilityGrant};
pub use context::{ApprovalState, LeaseState, PolicyContext, ReceiptState};
pub use decision::{DecisionOutcome, DenialReason, PolicyDecision};
pub use effect::{
    ApprovalRequirement, ContractVersion, EffectClass, EnforcementLevel, Operation, TrustLevel,
    POLICY_SCHEMA_VERSION,
};
pub use pack::{
    HostEnforcement, LeasePolicy, PackError, PolicyPack, ReceiptRequirements, TrustMinima,
    UnclassifiedEffect,
};
pub use path::{CanonicalPath, PathError, PathOperation, PathOwnership, PathScope, SymlinkState};
pub use rule::{PolicyRule, RuleDecision, RulePredicate};
