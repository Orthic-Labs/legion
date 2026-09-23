//! Port of `src/lib/dispatch-validator/{enforce_cheap_review_routing.py,
//! validate-dispatch.py (partial),validate-tasklist.py (partial)}` (chunk
//! w2_044).
//!
//! `validate-dispatch.py` is a 3475-line fail-closed structural validator
//! for zero-context agent dispatches. Its `authority_packet_errors` entry
//! point (and the path/digest helpers it depends on) is ported in
//! [`authority_packet`] and [`paths`]/[`digest`] **for every packet shape
//! except `packetType == "direct"` and `packetType == "worker"`** — those
//! two branches are several hundred additional lines each of dispatch-wave,
//! lane, worker-allowlist and executor-requirement structural checks
//! (`validate-dispatch.py` lines ~322-860) that this chunk's budget could
//! not reach without leaving other files unported or non-compiling. They
//! are intentionally **not ported here** (calling
//! [`authority_packet::authority_packet_errors`] on a `direct` or `worker`
//! packet returns only the base/routing/digest errors, not the
//! packet-type-specific ones the Python validator also raises) and are
//! listed as follow-up work below.
//!
//! `enforce_cheap_review_routing.py` is ported in full in [`routing`]: the
//! `TIERS`/`PROFILES` sets and the `routing_errors` tier/profile/
//! `CHEAP_STRICT` doctrine check, layered on top of the ported
//! `authority_packet_errors`.
//!
//! `validate-tasklist.py` is a thin compatibility CLI that shells out to
//! `validate-dispatch.py` with `--packet-type`/`--receipt-mode` flags and
//! forwards its stdout/stderr/exit code. Its *decision* surface — "delegate
//! structural validation to the authority packet checks; on success write a
//! `<stem>.receipt.json` sidecar; on failure return a non-zero code and
//! leave no receipt" — is ported in [`tasklist`]. The full `validate()` CLI
//! (line ~3098 of `validate-dispatch.py`) that tasklist delegates to also
//! covers Markdown dispatch documents (`storage_errors`, heading/table/
//! goal-route/topology checks) and `--receipt-mode verify` semantics; those
//! are **not ported** — see the follow-up list below.
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
//! **Not ported in this chunk** (left for follow-up chunks against the same
//! source files):
//!   - `validate-dispatch.py` `packetType == "direct"` structural checks
//!     (objective/integrationOwner/authority/fileTouchPolicy/dispatches/
//!     workers/executorRequirement/oracleAudit/recovery), lines ~322-860.
//!   - `validate-dispatch.py` `packetType == "worker"` checks and
//!     `managed_rust_route_errors` (line 860+).
//!   - `validate-dispatch.py` Markdown dispatch-document validation:
//!     `storage_errors`, `step_errors`, `table_errors`, `goal_route_errors`,
//!     `status_errors`, `execution_identity_errors`,
//!     `execution_control_errors`, `decision_scope_errors`,
//!     `authority_correction_errors`, `topology_errors`, and the `validate()`
//!     CLI entry point that dispatches between packet/Markdown modes and
//!     writes/verifies receipts for the full contract (lines ~933-3475).
//!   - `test_validate_dispatch.py` (1883 lines) and
//!     `test_direct_dispatch_waves.py`, which assert the above unported
//!     surfaces.

pub mod authority_packet;
pub mod digest;
pub mod paths;
pub mod routing;
pub mod tasklist;
