#![forbid(unsafe_code)]

mod dag;
mod error;
mod execution;
mod integrity;
mod inventory;
mod normalize;
mod plan;
mod report;
mod verify;
mod worktree;
pub mod native_providers;
pub mod wf_port;

pub use dag::topological;
pub use error::AuditError;
pub use execution::{execute, execute_with_cancellation, ExecutionReport, ProviderExecution, ProviderExecutor};
pub use integrity::{canonical_bytes, digest, plan_digest, sign, verify};
pub use inventory::{
    BlueprintInventorySource, BlueprintSource, FileBlueprintInventorySource,
    FilesystemInventorySource, InventoryDenominator, InventoryEntry, InventoryEnvelope,
    InventorySnapshot,
};
pub use normalize::{normalize, normalize_all};
pub use plan::{AuditPlan, AuditProvider, FrozenPlan, ProviderKind};
pub use report::canonical_report;
pub use verify::{verify_binding, verify_execution, verify_source_diagnostic};
pub use worktree::{cleanup, create, WorktreeEffect, WorktreeReceipt};
pub use native_providers::NativeProviderRegistry;
