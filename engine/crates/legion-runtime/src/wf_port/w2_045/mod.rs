//! Port of `src/lib/dispatch-validator/{validate-dispatch.py,validate-tasklist.py}`
//! (chunk w2_045).
//!
//! `validate-dispatch.py` is a ~3,500-line fail-closed structural validator for
//! zero-context agent dispatch Markdown documents and typed JSON authority
//! packets: heading/label/table shape checks, per-step execution contracts,
//! GoalRoute DAG binding, an `authority_packet_errors` JSON-schema validator
//! for the five packet types (`direct`, `sage`, `oracle`/`seer`, `alchemist`,
//! `worker`), a managed-Rust-route (RightKit) bypass scanner, and a receipt
//! read/write/verify CLI. `validate-tasklist.py` is a thin compatibility
//! wrapper that shells out to `validate-dispatch.py` per packet.
//!
//! This chunk ports the **pure path/scope primitives** that both scripts
//! build every structural and ownership check on top of, under
//! [`path_utils`]: `clean_path_value`, `is_absolute_path`,
//! `in_platform_temp_dir`, `normalized_path` (Python's
//! `Path(...).expanduser().resolve(strict=False)` lexical-normalization
//! semantics, reimplemented without touching the filesystem so behaviour is
//! identical whether or not the path exists), `repository_root`,
//! `canonical_locator`, `resolve_declared_path`, `direct_scope_path`,
//! `direct_file_allowlist_path`, `scope_static_prefix`, and
//! `scopes_overlap`. These are ported in full, with unit tests mirroring the
//! Python functions' own edge cases (dot-segments, glob tokens, Windows
//! drive letters, case-folding on `nt`, temp-directory detection).
//!
//! Two pieces originally listed here as NOT-STARTED are now ported
//! elsewhere: the five-way `authority_packet_errors` packet-type dispatcher
//! (digest binding, git revision resolution via `git rev-parse`,
//! dispatch-wave/worker OWN/READ/FORBIDDEN collision matrix,
//! executor-requirement escalation policy) is ported in full in
//! `wf_port::w2_044::authority_packet` (packet r46 closed its
//! `direct`/`worker` gap, reusing this module's `direct_scope_path`/
//! `direct_file_allowlist_path`/`scopes_overlap`); `managed_rust_route_errors`
//! is ported in full in `wf_port::r46`. `validate-tasklist.py`'s
//! subprocess-wrapper CLI is ported in full in
//! `wf_port::w2_044::tasklist::run_cli` (packet r47).
//!
//! The remaining ~majority of `validate-dispatch.py` — the ordered-heading
//! walk, the ~90-entry required-label table, the per-`### Step N`
//! label/route/dependency-DAG validator, the Markdown table extractors, the
//! `BYPASS_PATTERNS`/`SECRET_PATTERNS` regex banks, and the receipt
//! write/verify CLI (`storage_errors`, `step_errors`, `table_errors`,
//! `goal_route_errors`, `status_errors`, `execution_identity_errors`,
//! `execution_control_errors`, `decision_scope_errors`,
//! `authority_correction_errors`, `topology_errors`, `validate()`, `main()`
//! — validate-dispatch.py lines ~933-3475) is **NOT-STARTED**. Those pieces
//! are much larger than the primitives here and porting them faithfully
//! (including the ~90-row label table and the GoalRoute DAG cross-check)
//! did not fit packet r46's pass either. See the packet r46 report for the
//! exact function inventory and suggested follow-up split.

pub mod path_utils;
