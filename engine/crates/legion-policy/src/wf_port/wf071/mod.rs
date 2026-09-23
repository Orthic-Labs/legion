//! wf071 — Rust port of `src/lib/verification/arcane/{
//! calibration-convergence-policy,completion-evidence,completion-gate,
//! completion-state,current-user-risk-acceptance}.mjs`.
//!
//! Additive only: the JS remains the source of truth until CI parity is
//! proven and a later packet deletes it. See the wf071 report at
//! `/private/tmp/claude-501/-Volumes-D-claude-heardright/27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/wf/wf071.md`
//! for per-file status, what was ported faithfully, and what could not be
//! (with the reason and the dependency this module would need once other
//! wf packets land it).
//!
//! NOTE for the integration owner: not yet wired into the crate root. Add
//! `pub mod wf_port;` to `engine/crates/legion-policy/src/lib.rs` (if not
//! already present from another wf packet) and `pub mod wf071;` to
//! `engine/crates/legion-policy/src/wf_port/mod.rs` before running
//! `cargo test` against it.

pub mod calibration_convergence_policy;
pub mod completion_state;

pub use calibration_convergence_policy::{
    calibration_convergence_scenario_facts, classify_calibration_drift,
    converge_clarifications, dispose_frozen_review_finding,
    evaluate_calibration_convergence_case, validate_calibration_convergence_observation,
    CalibrationConvergenceOutcome, CalibrationDriftInput, ClarificationQuestion,
    ConvergeClarificationsInput, DisposeFrozenReviewFindingInput, FrozenDecision, ReviewFinding,
    RuntimeMeasurement, TargetPublication,
};
pub use completion_state::{
    completion_integrated_state, completion_integrated_state_for_repositories,
    path_matches, repository_relative, RepositoryScope,
};
