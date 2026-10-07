#![forbid(unsafe_code)]

mod dag;
mod error;
mod execution;
mod integrity;
mod inventory;
pub mod native_providers;
mod normalize;
pub mod p12_pipeline;
mod plan;
mod report;
mod verify;
pub mod wf_port;
mod worktree;

pub use dag::topological;
pub use error::AuditError;
pub use execution::{
    execute, execute_with_cancellation, ExecutionReport, ProviderExecution, ProviderExecutor,
};
pub use integrity::{canonical_bytes, digest, plan_digest, sign, verify};
pub use inventory::{
    FilesystemInventorySource, InventoryDenominator, InventoryEntry, InventoryEnvelope,
    InventorySnapshot, InventorySource,
};
pub use native_providers::NativeProviderRegistry;
pub use normalize::{normalize, normalize_all};
pub use plan::{AuditPlan, AuditProvider, FrozenPlan, ProviderKind};
pub use report::canonical_report;
pub use verify::{verify_binding, verify_execution, verify_source_diagnostic};
pub use worktree::{cleanup, create, WorktreeEffect, WorktreeReceipt};
