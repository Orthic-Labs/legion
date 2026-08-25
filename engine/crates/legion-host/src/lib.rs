#![forbid(unsafe_code)]

pub mod agent_plugins;
pub mod capability;
pub mod descriptor;
pub mod detect;
pub mod error;
pub mod install;
pub mod ownership;
pub mod projection;
pub mod setup_registry;
pub mod uninstall;
pub mod verify;

pub use agent_plugins::{
    assemble_clean_room, classify_external_qualification, validate_templates, AssembledPackage,
    ExternalQualification, ExternalQualificationInputs, ExternalQualificationStatus,
    PinnedAxEvidence, PortableTemplates, VerifiedPortableInputs, RIGHTKIT_AX_SOURCE_COMMIT,
    RIGHTKIT_AX_VERSION,
};
pub use capability::{capabilities, capability, Capability, ClientFidelity, Fidelity, SURFACES};
pub use descriptor::{
    deterministic_lookup, ClientIdentity, DescriptorRegistry, DetectionRule, HostDescriptor,
    Mechanism, SurfaceDescriptor, SCHEMA_VERSION,
};
pub use detect::{detect, detect_all, CommandResolutionEvidence, HostEvidence};
pub use error::{FailureCode, HostError};
pub use install::{
    apply, apply_transaction, capture_preimage, digest, install, install_transactional, plan,
    rollback, FileEffects, Mutation, MutationKind, MutationPlan, TransactionPreimage,
};
pub use ownership::{
    digest_bytes, marker_for, owned_block, parse_marker, validate_relative_path,
    verify_owned_block, OwnershipMark,
};
pub use projection::{
    project_instructions, project_mcp, project_skills, CollisionPolicy, ProjectionItem,
};
pub use setup_registry::{
    platform_state_root, BackupRecord, BoundRelease, ClientEvidence, ClientSelector, ClientStatus,
    ConfirmedSetup, DetectedClient, OnDiskSetupStore, PlanConfirmation, PlannedMutation,
    RecoveryReport, RollbackPlan, RuntimeLease, SetupAction, SetupError, SetupErrorCode,
    SetupExecution, SetupPreview, SetupRegistry, SetupRequest, SetupState, SetupStore, StateLock,
    SETUP_REGISTRY_SCHEMA_VERSION,
};
pub use uninstall::{
    plan_uninstall, uninstall, uninstall_transactional, OwnedTarget, UninstallResult,
};
pub use verify::{verify, verify_client_identity, Verification};

/// Stable ownership identifier used by generated projections and mutation receipts.
pub const OWNER: &str = "legion-host";
