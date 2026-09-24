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
//! The other, much larger, unported surface — `ordered_heading_errors`,
//! the ~90-entry `REQUIRED_LABELS` table walk, `step_errors`,
//! `table_errors`, `goal_route_errors`, `status_errors`,
//! `execution_identity_errors`, `execution_control_errors`,
//! `decision_scope_errors`, `authority_correction_errors`,
//! `topology_errors`, and the `validate()`/`main()` CLI dispatcher (roughly
//! `validate-dispatch.py` lines 933-3475) — is **NOT-STARTED** in this
//! packet. See the packet r46 report for the precise function inventory.

pub mod route_scan;

pub use route_scan::managed_rust_route_errors;
