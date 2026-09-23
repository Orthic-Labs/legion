//! wf012 — port of `src/lib/providers/sdk/{schedule,selectors,testkit}.mjs`.
//!
//! No native Rust coverage of these three modules was found (searched for
//! `topological`/`compileSchedule`/`evaluateSelector`/`stableId`/
//! `pathDenominator`/wave-scheduling in `engine/`). The closest neighbors are
//! `legion-audit::dag::topological` and `legion-provider-sdk::registry`'s
//! `topological_order`, which both implement plain Kahn's-algorithm ordering
//! for `AuditProvider`/`ProviderDefinition` — a different provider shape with
//! no `dependsOn`/`dependencies` duality, no resource-ceiling wave batching,
//! and different error messages, so they are not equivalent to
//! `dag.mjs::topologicalProviders` + `schedule.mjs::compileSchedule`. This
//! module ports the JS behavior directly instead of adapting those.
//!
//! Owned exclusively by this wf012 chunk: everything under
//! `wf_port/wf012/**` plus `tests/wf_wf012.rs`. The integrator wires
//! `pub mod wf_port;` (crate root) and `pub mod wf012;` (in `wf_port/mod.rs`).

pub mod dag;
pub mod schedule;
pub mod selectors;
pub mod testkit;

pub use dag::{topological_providers, DagError, DagProvider};
pub use schedule::{compile_schedule, ScheduleError, ScheduleProvider, ScheduleResult};
pub use selectors::{evaluate_selector, Projection, Selector};
pub use testkit::{
    normalize_provider_result, path_denominator, stable_id, validate_provider_record,
    validate_provider_result, PathDenominator, ProviderResultValidationError, PROVIDER_STATUS,
};
