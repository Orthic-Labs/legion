#![forbid(unsafe_code)]

pub mod capability;
pub mod descriptor;
pub mod detect;
pub mod error;
pub mod install;
pub mod ownership;
pub mod projection;
pub mod uninstall;
pub mod verify;

pub use capability::{capabilities, capability, Capability, Fidelity, SURFACES};
pub use descriptor::{
    deterministic_lookup, DescriptorRegistry, DetectionRule, HostDescriptor, Mechanism,
    SurfaceDescriptor, SCHEMA_VERSION,
};
pub use detect::{detect, detect_all, HostEvidence};
pub use error::{FailureCode, HostError};
pub use install::{
    apply, digest, install, plan, FileEffects, Mutation, MutationKind, MutationPlan,
};
pub use ownership::{
    digest_bytes, marker_for, owned_block, parse_marker, verify_owned_block, OwnershipMark,
};
pub use projection::{
    project_instructions, project_mcp, project_skills, CollisionPolicy, ProjectionItem,
};
pub use uninstall::{plan_uninstall, uninstall, OwnedTarget, UninstallResult};
pub use verify::{verify, Verification};

/// Stable ownership identifier used by generated projections and mutation receipts.
pub const OWNER: &str = "legion-host";
