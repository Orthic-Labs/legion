//! Chunk wf050: port of `src/providers/runtime/web/{performance,protocols,
//! runner,scenario}/index.mjs` and `src/providers/runtime/web/shared.mjs`.
//!
//! The integrator wires this in via `pub mod wf_port;` in
//! `legion-audit`'s `lib.rs` and `pub mod wf050;` in `wf_port/mod.rs`.

pub mod performance;
pub mod protocols;
pub mod runner;
pub mod scenario;
pub mod shared;

pub use performance::{verify_web_performance, CaptureEvidence};
pub use protocols::{execute_web_protocol, AdapterExecuteResult, ProtocolPlanRow, SanitizedArtifact};
pub use runner::run_web_control;
pub use scenario::{run_web_scenario, AdapterCallResult};
