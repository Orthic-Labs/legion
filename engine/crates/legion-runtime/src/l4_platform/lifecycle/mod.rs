//! Port of `src/lib/platform/lifecycle/**`.

pub mod actions;

pub use actions::{lifecycle_receipt, run_lifecycle_action, LifecycleAdapter};
