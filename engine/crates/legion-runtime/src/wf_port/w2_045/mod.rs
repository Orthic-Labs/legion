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
//! The remaining ~90% of `validate-dispatch.py` — the ordered-heading walk,
//! the ~90-entry required-label table, the per-`### Step N` label/route/
//! dependency-DAG validator, the Markdown table extractors, the five-way
//! `authority_packet_errors` packet-type dispatcher (digest binding, git
//! revision resolution via `git rev-parse`, dispatch-wave/worker
//! OWN/READ/FORBIDDEN collision matrix, executor-requirement escalation
//! policy), the `BYPASS_PATTERNS`/`SECRET_PATTERNS` regex banks, the
//! `managed_rust_route_errors` RightKit scanner, and the receipt
//! write/verify CLI in `validate-dispatch.py`, plus the whole of
//! `validate-tasklist.py`'s subprocess-wrapper CLI — is **NOT-STARTED**.
//! Those pieces are much larger than the primitives here, several depend on
//! `git` subprocess invocation and filesystem I/O (digest binding, receipt
//! read/write) rather than pure functions, and porting them faithfully
//! (including the ~90-row label table and the GoalRoute DAG cross-check)
//! did not fit this chunk's budget. See the chunk report for the exact
//! function inventory and suggested follow-up split.

pub mod path_utils;
