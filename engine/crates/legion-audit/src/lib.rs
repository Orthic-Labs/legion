#![forbid(unsafe_code)]

pub mod amendment;
pub mod artifact_evidence;
pub mod assurance;
pub mod continuation;
mod dag;
pub mod debt;
pub mod dependency_inventory;
pub mod domain_contract;
mod error;
pub mod evidence_issuers;
mod execution;
pub mod execution_policy;
pub mod finding_history;
pub mod graph_context;
pub mod host_owner;
mod integrity;
mod inventory;
pub mod journal;
pub mod metrics;
pub mod native_providers;
pub mod next;
mod normalize;
pub mod owner_admission;
pub mod p12_pipeline;
mod plan;
pub mod profiles;
mod report;
pub mod resume;
pub mod review_runtime;
pub mod runtime_obligations;
pub mod scheduler;
pub mod scope;
pub mod snapshot;
pub mod source_cache;
mod trusted_git;
mod verify;
pub mod wf_port;
mod worktree;

pub use dag::topological;
pub use dag::{
    topological_with_artifacts, EdgeKind, ExecutionState, Objective, ObjectiveEdge, ObjectiveGraph,
    ObjectiveStatus, Observation, ProofState as ObjectiveProofState, FROZEN_FACT_SOURCES,
};
pub use error::AuditError;
pub use execution::{
    execute, execute_scheduled, execute_with_cancellation, execute_with_cancellation_scheduled,
    ExecutionContext, ExecutionReport, FallbackRecord, ProofState, ProviderExecution,
    ProviderExecutor, ProviderRecord, RunState,
};
pub use integrity::{
    canonical_bytes, digest, host_plan_key_dir, new_plan_key, new_run_id, plan_digest, plan_key_id,
    plan_signing_key_for_run, resolve_plan_key, sign, store_host_plan_key, verify,
    PlanKeyResolution, PlanKeySource,
};
pub use inventory::{
    FilesystemInventorySource, InventoryDenominator, InventoryEntry, InventoryEnvelope,
    InventorySnapshot, InventorySource,
};
pub use native_providers::NativeProviderRegistry;
pub use normalize::{
    normalize, normalize_all, replay_differences, replay_digest, replay_normalize,
};
pub use plan::{
    AuditPlan, AuditProvider, AuthorityMode, Engagement, EngagementAuthority, EngagementScope,
    FrozenPlan, ProviderKind, StopConditions, ENGAGEMENT_BOUND, FOLLOWUP_RUNS_BOUND, LINEAGE_BOUND,
    OBJECTIVE_GRAPH_BOUND, PLAN_SCHEMA_V1, PLAN_SCHEMA_V2,
};
pub use report::{canonical_report, canonical_report_assured, lift_report_v2, project_assurance};
pub use verify::{
    parse_effect_artifact_ref, read_effect_artifact, replay_run_value,
    validate_effect_artifact_path, verify_assurance, verify_binding, verify_execution,
    verify_source_diagnostic, DETAILS_ARTIFACT_REF_KEYS, REPLAY_RUN_FILES,
};
pub use worktree::{cleanup, create, WorktreeEffect, WorktreeReceipt};
