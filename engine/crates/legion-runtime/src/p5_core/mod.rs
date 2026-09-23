//! Packet P5-runtime-core: JS→Rust port of src/lib/core, src/lib/controls,
//! src/lib/config, src/lib/contracts (excl. arcane), src/lib/errors.mjs,
//! src/lib/index.mjs, src/lib/version.mjs, src/lib/verification (excl.
//! arcane), src/lib/verification-projection.mjs, src/lib/adapters,
//! src/adapters/{ecosystem-manifests,security-adjudication,
//! security-chain-adjudication,untrusted-evidence-envelope}.mjs,
//! src/packages/kernel, src/packages/context (Membrane/Blueprint dropped).
//!
//! See /private/tmp/claude-501/-Volumes-D-claude-heardright/
//! 27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/full-P5-runtime-core.md
//! for the per-file port status table; this module currently covers only the
//! files ported so far (denominators, exit taxonomy). The remainder of the
//! packet is unstarted — see the report for the exact remaining file list.

pub mod denominators;
pub mod exit_taxonomy;

pub mod core_records;
pub mod core_scheduler;

pub mod adapters_chain_adjudication;
pub mod adapters_ecosystem_manifests;
pub mod adapters_untrusted_evidence;
pub mod contracts_enums;
pub mod contracts_families;
pub mod contracts_lenses;
pub mod verification_audit_projection;
pub mod verification_projection;

pub use denominators::{reconcile_denominator, DenominatorReconciliation};
pub use exit_taxonomy::{exit_code_for_report, Exit, ExitReport, TaxonomyError};

pub use core_records::{
    achieved_claim_level, build_judgment_packet, reconcile_claim, required_stages_for, run_layout,
    reviewer_policy, ClaimReconciliation, JudgmentPacketInput, ReviewerPolicy, ReviewerPolicyError,
    RunLayout, CLAIM_LEVELS, JUDGMENT_VERDICTS, PLANNING_STAGE_IDS, RUN_DIRECTORIES,
};
pub use core_scheduler::{
    provider_dependencies, schedule_providers, BlockedProvider, ResourcedSchedule, ScheduleMode,
    ScheduleOptions, ScheduleResult, SchedulerError, SchedulerProvider,
};

pub use adapters_chain_adjudication::{
    create_chain_adjudication_packet, finalize_chain_verdict, ChainAdjudicationError,
    ChainAdjudicationPacket, ChainVerdict, CreateChainAdjudicationPacketInput,
};
pub use adapters_ecosystem_manifests::{read_ecosystem_manifests, EcosystemManifest};
pub use adapters_untrusted_evidence::{
    bound_packet_evidence, escape_for_reasoning, untrusted_evidence_envelope, BoundEvidence,
    EvidenceInput, UntrustedEvidenceEnvelope, PACKET_LIMITS,
};
pub use contracts_enums::{
    assert_enum, assert_schema_version, assert_schema_version_default, EvidenceClass,
    JudgmentVerdict, ProviderRole, ProviderStatus, ReasoningRequirement, UnknownEnumValue,
    UnsupportedSchemaVersion,
};
pub use contracts_families::{
    assert_acyclic, validate_families, FamilyRecord, FamilyValidationError,
};
pub use contracts_lenses::{validate_lenses, LensRecord, LensValidationError};
pub use verification_audit_projection::{verification_digest, verification_projection};
pub use verification_projection::{semantic_projection, verification_receipt};

// Packet P5b-controls-config: src/lib/controls/** and src/lib/config/**.
pub mod config_core;
pub mod controls_contracts;
pub mod controls_evidence;
pub mod controls_scenarios;
pub mod controls_selectors;
pub mod controls_sources;
pub mod controls_support;

// Packet P5d: src/packages/kernel/** (src/packages/context is Membrane/
// Blueprint transport only and was dropped entirely, see report).
pub mod kernel_contracts;
pub mod kernel_errors;
pub mod kernel_ids;
pub mod kernel_journal;
pub mod kernel_lifecycle;
pub mod kernel_profiles;
pub mod kernel_registry;
pub mod kernel_scheduler;
pub mod kernel_stores;

pub use kernel_contracts::{assert_contract, bind_run_identity};
pub use kernel_errors::{exit_code_for_category, KernelError, KernelErrorOptions};
pub use kernel_ids::{
    mint_id, now_millis, prefix_for, random_entropy, validate_execution_task_id, validate_id,
};
pub use kernel_journal::JsonlJournal;
pub use kernel_lifecycle::{KernelTask, TaskLifecycle};
pub use kernel_profiles::{
    default_profile_policy, downgrade_model_profile, load_model_profile, ModelProfile, ProfileLimits,
};
pub use kernel_registry::{negotiate_capabilities, CapabilityNegotiation, OperationRegistry};
pub use kernel_scheduler::{scheduler_options_from_argv, LaneContext, LaneNode, LaneScheduler};
pub use kernel_stores::{digest_content, ArtifactStore, EventStore};
