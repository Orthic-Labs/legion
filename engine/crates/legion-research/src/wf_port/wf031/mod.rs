//! Port of `src/lib/research-core/tests/{test_research_provider_fence,
//! test_research_resource_guard,test_research_route_effect_boundaries,
//! test_research_route_workspace,test_research_shards}.py` (packet wf031,
//! area `src/lib/research-core`, target crate `legion-research`).
//!
//! This packet's assignment is five *test* files, not library modules.
//! Per the port method, each is checked against existing Rust coverage
//! first:
//!
//! - `test_research_shards.py` — **ALREADY-NATIVE-VERIFIED** at
//!   `crate::wf_port::wf023::shards`. Its
//!   `plan_checkpoint_resume_and_merge_are_deterministic` unit test is a
//!   line-for-line match of this Python file's assertions (same shard ids,
//!   same resumable/attempts state after the same checkpoint sequence,
//!   same merge-dedup-by-id error message). No gap.
//! - `test_research_provider_fence.py` — **ALREADY-NATIVE-VERIFIED** at
//!   `crate::wf_port::wf027::support::data_only_envelope`, re-asserted
//!   verbatim in `tests/wf_wf027.rs::provider_fence_matches_python_test`
//!   (same input body, same normalized output, same digest check). No gap.
//! - `test_research_resource_guard.py` — **ALREADY-NATIVE-VERIFIED** at
//!   `crate::wf_port::wf028::resource_guard::authorize`. Its own
//!   `authorize_denies_forbidden_pattern`/`authorize_denies_workspace_escape`
//!   unit tests cover the same `/**`-suffix forbidden-pattern denial and
//!   workspace-escape rejection this Python file asserts (this file's
//!   fixture uses a `consumer/**` route pattern under a temp workspace;
//!   the existing Rust tests use `*.env`/an absolute outside path — same
//!   `_matches`/`_relative_path` code paths, confirmed by reading
//!   `resource_guard.rs` above). No gap.
//! - `test_research_route_workspace.py` — **ALREADY-NATIVE-VERIFIED** at
//!   `crate::wf_port::wf029::route_resolve::resolve`/`build_subject` for
//!   the domain-detection and gate half (personal-medical intent routes to
//!   `medical`, subject kind `self`, gate
//!   `confirm-personal-medical-route`; a host-supplied `history_source` is
//!   honored explicitly, never inferred — see that module's own doc
//!   comment on `build_subject`, which states the de-personalisation this
//!   test's own docstring describes as already done). The other half of
//!   the Python test — asserting `route_resolve.WORKSPACE` (a
//!   Python-module-level `Path` constant derived from `__file__`) equals
//!   the real repository root — has no Rust equivalent to port: a Rust
//!   crate has no analogous runtime "workspace root from my own source
//!   file's location" concept (no I/O in `route_resolve.rs`'s ported
//!   functions depends on any such path), so that half of the assertion
//!   is dropped as inapplicable by design, not as a gap. This module adds
//!   `tests/wf_wf031.rs::route_workspace_domain_and_history_matches_python_test`
//!   below, re-asserting the applicable half directly against this
//!   packet's own crate-level import path, to close the loop for this
//!   assigned file specifically.
//! - `test_research_route_effect_boundaries.py` — **partially covered,
//!   partially ported here**. `ledger.validate_evidence`'s block verdicts
//!   (missing `instructionPolicy`, lead-only `source_type`, missing opened
//!   passage text) are already ALREADY-NATIVE-VERIFIED at
//!   `crate::wf_port::wf025::ledger::validate_evidence` (its own
//!   `validate_evidence_*` unit tests cover the identical cases). What was
//!   *not* covered anywhere: the stateful `run.py` half this test exercises
//!   (`init_run`, `grant`, `acquire`, `record_evidence`, and the
//!   `RESEARCH_RUN_ROOT`-rooted manifest they read/write) — `run.py`'s
//!   stateful orchestrator is explicitly un-ported dead work tracked in
//!   `crate::wf_port::wf029` ("NOT ported: ... `grant`, `acquire`,
//!   `record_evidence`, ..."). `run_state.rs` below ports the minimal
//!   faithful slice of that stateful orchestrator this test actually
//!   exercises: `init_run` (route resolution + manifest creation on disk),
//!   `grant` (effect-granting via the already-ported
//!   `route_resolve::grant_effects`, persisted to the manifest),
//!   `record_evidence` (the "route effects have not been granted" gate,
//!   then `ledger::validate_evidence` admission), and `acquire` (the same
//!   gate, then `run::resolve_acquire_provider`'s frozen-route provider
//!   check — the Python function's error is raised there, before any
//!   provider is ever constructed, so no provider machinery needs porting
//!   to make this assertion faithful). `render_draft`, `verify`,
//!   `finalize`, `record_claim`, and the patch/citecheck/retraction stages
//!   are still not ported (not exercised by this test file; still
//!   downstream of `citecheck.py`/`contradictions.py`/`gap_critic.py`/
//!   `domain_verify.py`/`retraction.py`/`patcher.py`/`draft_integrity.py`/
//!   `effect_audit.py`/`patch_guard.py`/`providers/search_open_find.py`,
//!   none of which is ported).
//!
//! Depends on sibling packets `wf023` (shard reference only, read-only,
//! not re-verified), `wf025` (`ledger::validate_evidence`), `wf027`
//! (`support::data_only_envelope`, read-only reference), `wf028`
//! (`resource_guard::authorize`, read-only reference), and `wf029`
//! (`route_resolve::{resolve,grant_effects}`, `run::{check_effects,
//! resolve_acquire_provider}`). All are read-only imports; this packet
//! writes nothing outside `wf_port/wf031/**` and
//! `tests/wf_wf031.rs`/`tests/fixtures/wf_wf031/**`.

pub mod run_state;
