//! Port of `src/lib/platform/faults/**`.

pub mod injectors;
pub mod orchestrator;

pub use injectors::{validate_fault_injection, FaultDecision};
pub use orchestrator::{orchestrate_fault, FaultAdapter};
