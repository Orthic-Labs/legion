//! Port of `src/lib/dispatch-validator/validate-dispatch.py`'s
//! `managed_rust_route_errors()` (packet r46).
//!
//! This closes one of the two remaining gaps chunk w2_044 documented as
//! not ported (`wf_port::w2_044`'s module doc originally listed
//! `managed_rust_route_errors` among the unported surface). It scans
//! Markdown dispatch-document text for direct `cargo`/`rustc`/`rustdoc`
//! invocations that bypass RightKit (`rightkit build ...`), in fenced code
//! blocks, inline code spans, Markdown table cells, `- **Label:**` value
//! lines, and (best-effort) a referenced GoalRoute JSON document's
//! `state_b.proof[].command` fields.
//!
//! Packet r46b extends this module with the Markdown dispatch-document
//! heading/label/step/table walk: `ordered_heading_errors` (`headings.rs`),
//! the label/value/dependency helpers (`labels.rs`, `dependency.rs`), the
//! `### Step N` validator (`steps.rs`), the Markdown table walk
//! (`tables.rs`), the `## 5A. Script & Runner Gate` parser
//! (`script_gate.rs`), and `status_errors` (`status.rs`).
//!
//! Packet r46c1 adds `goal_route_errors` (`goal_route.rs`), the `## 1C.
//! Goal Route & Critical Path` validator, and its sibling GoalRoute
//! artifact/receipt validator ported from
//! `src/lib/goalroute/scripts/validate-route.py` (`goal_route_validator.rs`).
//!
//! Packet r46c2 adds `execution_identity_errors` (`execution_identity.rs`),
//! `execution_control_errors` (`execution_control.rs`),
//! `decision_scope_errors` (`decision_scope.rs`),
//! `authority_correction_errors` (`authority_correction.rs`),
//! `topology_errors` (`topology.rs`), and [`cli::validate_ported_errors`], a
//! partial port of `validate()` composing every check that is fully ported
//! across r46/r46b/r46c1/r46c2.
//!
//! Packet r46d completes the CLI dispatcher: `REQUIRED_LABELS`
//! (`required_labels.rs`), `BYPASS_PATTERNS`/`SECRET_PATTERNS`
//! (`patterns.rs`), the `/script` gate YES/NO branch, the `## 10.
//! TRUE_BLOCKER Conditions` and `## 11. Dispatcher Author Gate` section
//! checks, `storage_errors` (`storage.rs`), and the full `validate()`/
//! `main()` CLI (`cli::validate_full_errors`, `cli::run`). See `cli.rs`'s
//! module doc for the one remaining named gap (the dynamic
//! `minimize_gate.py` load, replaced by the [`cli::MinimizeGate`] trait).

pub mod authority_correction;
pub mod cli;
pub mod decision_scope;
pub mod dependency;
pub mod execution_control;
pub mod execution_identity;
pub mod goal_route;
pub mod goal_route_validator;
pub mod headings;
pub mod labels;
pub mod patterns;
pub mod required_labels;
pub mod route_scan;
pub mod script_gate;
pub mod status;
pub mod steps;
pub mod storage;
pub mod tables;
pub mod topology;

pub use authority_correction::authority_correction_errors;
pub use cli::{validate_full_errors, validate_ported_errors, MinimizeGate, NoMinimizeGate, RunOptions, RunOutcome};
pub use decision_scope::decision_scope_errors;
pub use dependency::parse_dependency_contract;
pub use execution_control::execution_control_errors;
pub use execution_identity::execution_identity_errors;
pub use goal_route::goal_route_errors;
pub use headings::{ordered_heading_errors, REQUIRED_HEADINGS};
pub use labels::{authority_label_value, fenced_value_after, is_concrete};
pub use patterns::{bypass_pattern_errors, secret_pattern_errors};
pub use required_labels::{required_label_errors, REQUIRED_LABELS};
pub use route_scan::{label_value, managed_rust_route_errors};
pub use script_gate::script_gate_values;
pub use status::status_errors;
pub use steps::{step_errors, STEP_LABELS};
pub use storage::storage_errors;
pub use tables::{table_errors, table_rows, validate_table, FAILURE_CLASSES};
pub use topology::topology_errors;
