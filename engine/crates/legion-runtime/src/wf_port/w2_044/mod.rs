//! Port of `src/lib/dispatch-validator/{enforce_cheap_review_routing.py,
//! validate-dispatch.py (partial),validate-tasklist.py (partial)}` (chunk
//! w2_044, extended by packet r46).
//!
//! `validate-dispatch.py` is a 3475-line fail-closed structural validator
//! for zero-context agent dispatches. Its `authority_packet_errors` entry
//! point (and the path/digest helpers it depends on) is ported **in full,
//! for every `packetType`** (`direct`, `sage`, `oracle`/`seer`,
//! `alchemist`, `worker`) in [`authority_packet`] and [`paths`]/[`digest`].
//! Packet r46 closed the `direct`/`worker` gap this doc previously
//! described as unported: dispatch-wave/lane validation, worker
//! OWN/READ/FORBIDDEN scope and collision checks,
//! `executorRequirement`/escalation policy validation, the Oracle
//! pre-execution audit contract, the `worker` packet capsule/projection
//! checks, and — previously entirely un-ported and un-noted — the `sage`/
//! `oracle`/`seer`/`alchemist` branches are now all implemented in
//! [`authority_packet::direct_packet_errors`] and
//! [`authority_packet::authority_packet_errors`]'s `packet_type` match.
//! Packet r46 also separately ported `managed_rust_route_errors()` in full,
//! under `wf_port::r46`.
//!
//! `enforce_cheap_review_routing.py` is ported in full in [`routing`]: the
//! `TIERS`/`PROFILES` sets and the `routing_errors` tier/profile/
//! `CHEAP_STRICT` doctrine check, layered on top of the ported
//! `authority_packet_errors`.
//!
//! `validate-tasklist.py` is a thin compatibility CLI that shells out to
//! `validate-dispatch.py` with `--packet-type`/`--receipt-mode` flags and
//! forwards its stdout/stderr/exit code; it is **fully ported** (packet
//! r47) as [`tasklist::run_cli`], which reproduces that subprocess/argv
//! contract itself (including `--receipt-mode verify` and `--packet-type
//! worker`) rather than reimplementing `validate-dispatch.py`'s own
//! decision logic — the latter is what remains partially ported below.
//! [`tasklist::validate_and_write_receipt`] additionally ports the
//! *decision* surface for the default `--packet-type authority
//! --receipt-mode write` path (delegate structural validation to the
//! authority packet checks; on success write a `<stem>.receipt.json`
//! sidecar; on failure return a non-zero code and leave no receipt), which
//! is what `test_validate_tasklist.py`'s fixture exercises. The full
//! `validate()` CLI (line ~3098 of `validate-dispatch.py`) that the real
//! `validate-dispatch.py` subprocess runs also covers Markdown dispatch
//! documents (`storage_errors`, heading/table/goal-route/topology checks);
//! that decision logic is **not ported** — see the follow-up list below.
//!
//! `test_enforce_cheap_review_routing.py` is ported in full as
//! `tests/wf_w2_044.rs::enforce_cheap_review_routing_tests` (all three
//! assertions: CHEAP_STRICT/strict doctrine pass, CHEAP_STRICT+standard
//! failure, missing `routingRationale` failure).
//!
//! `test_validate_tasklist.py` is ported as
//! `tests/wf_w2_044.rs::tasklist_tests` for the two paths its fixture
//! exercises (pass + receipt written; missing-field failure), which land
//! entirely inside the ported `authority_packet_errors` surface.
//!
//! **Not ported** (left for follow-up work against the same source file;
//! see packet r46's report for the exact function inventory):
//!   - `validate-dispatch.py`'s Markdown dispatch-document validation
//!     surface: `storage_errors`, `ordered_heading_errors`, the
//!     ~90-entry `REQUIRED_LABELS`/`STEP_LABELS` table walk, `step_errors`,
//!     `table_errors`, `goal_route_errors`, `status_errors`,
//!     `execution_identity_errors`, `execution_control_errors`,
//!     `decision_scope_errors`, `authority_correction_errors`,
//!     `topology_errors`, and the `validate()`/`main()` CLI entry point
//!     that dispatches between packet/Markdown modes and writes/verifies
//!     receipts for the full contract (lines ~933-3475). This is roughly
//!     2,500 of the file's 3,475 lines and did not fit packet r46's pass.
//!   - `test_validate_dispatch.py` (1883 lines) and
//!     `test_direct_dispatch_waves.py`'s assertions against the above
//!     unported surface (the direct-dispatch-wave assertions that exercise
//!     `authority_packet_errors` are now covered by
//!     `authority_packet::tests::direct_packet_minimal_valid_shape_is_clean`
//!     and `direct_packet_reports_own_collision`).

pub mod authority_packet;
pub mod digest;
pub mod paths;
pub mod routing;
pub mod tasklist;
