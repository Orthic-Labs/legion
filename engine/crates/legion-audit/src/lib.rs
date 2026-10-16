#![forbid(unsafe_code)]

pub mod continuation;
mod dag;
mod error;
mod execution;
pub mod graph_context;
mod integrity;
mod inventory;
pub mod native_providers;
pub mod next;
mod normalize;
pub mod p12_pipeline;
mod plan;
mod report;
pub mod review_runtime;
pub mod scope;
pub mod snapshot;
pub mod source_cache;
mod verify;
pub mod wf_port;
mod worktree;

pub use dag::topological;
pub use error::AuditError;
pub use execution::{
    execute, execute_with_cancellation, ExecutionContext, ExecutionReport, ProviderExecution,
    ProviderExecutor,
};
pub use integrity::{canonical_bytes, digest, plan_digest, sign, verify};
pub use inventory::{
    FilesystemInventorySource, InventoryDenominator, InventoryEntry, InventoryEnvelope,
    InventorySnapshot, InventorySource,
};
pub use native_providers::NativeProviderRegistry;
pub use normalize::{normalize, normalize_all};
pub use plan::{AuditPlan, AuditProvider, FrozenPlan, ProviderKind};
pub use report::{canonical_report, lift_report_v2};
pub use verify::{
    parse_effect_artifact_ref, read_effect_artifact, validate_effect_artifact_path, verify_binding,
    verify_execution, verify_source_diagnostic, DETAILS_ARTIFACT_REF_KEYS,
};
pub use worktree::{cleanup, create, WorktreeEffect, WorktreeReceipt};
