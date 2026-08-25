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

pub use dag::topological;
pub use error::AuditError;
pub use execution::{execute, ExecutionReport, ProviderExecution, ProviderExecutor};
pub use integrity::{canonical_bytes, digest, plan_digest, sign, verify};
pub use inventory::{
    BlueprintInventorySource, BlueprintSource, InventoryEntry, InventoryEnvelope, InventorySnapshot,
};
pub use normalize::{normalize, normalize_all};
pub use plan::{AuditPlan, AuditProvider, FrozenPlan, ProviderKind};
pub use report::canonical_report;
pub use verify::{verify_binding, verify_execution};
pub use worktree::{cleanup, create, WorktreeEffect, WorktreeReceipt};
