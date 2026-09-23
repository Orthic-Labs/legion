//! wf_port chunk w2_050 — port of `src/lib/review/{__init__,_codex-diag,
//! agent_room_driver,cache,config}.py`.
//!
//! `src/lib/review/__init__.py` is a docstring-only package marker with no
//! runtime behavior; nothing to port beyond this module doc comment.

pub mod cache;
pub mod codex_diag;
pub mod config;
pub mod room_driver;

pub use cache::Cache;
pub use codex_diag::{default_codex_cmd, diag_command, run_diag, run_diag_live, DiagOutcome};
pub use config::{load_models_config, ConfigError, ModelsConfig};
pub use room_driver::{
    active_result, discover_passed_value_gate, fallback_result, now_iso, pending_link_delivery,
    readiness_complete, resolve_room_binary, room_id, run_room_advisory, safe_diagnostic,
    CommandRunner, PassedValueGate, RoomDriverError, RunsEvidence, SystemRunner,
    READINESS_TIMEOUT_SECS, ROOM_SEATS,
};
