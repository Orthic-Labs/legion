//! Port of `src/lib/research-core/{router/__init__,router/route_detect,
//! router/route_resolve,run,shards}.py` (packet wf029, area
//! `src/lib/research-core`, target crate `legion-research`).
//!
//! `router/__init__.py` is empty (a package marker) — nothing to port.
//!
//! Status per file, in full in `scratchpad/loss/wf/wf029.md`:
//! - `route_detect.py`: full faithful port (`route_detect.rs`), pure
//!   text-heuristic functions, no I/O.
//! - `route_resolve.py`: full faithful port of every non-CLI function
//!   (`route_resolve.rs`): `build_subject`, `resolve`, `pending_gates`,
//!   `gate_verdicts`, `grant_effects`, `validate_route`. The `argparse`
//!   `main` shim is not ported (see that module's doc comment).
//! - `run.py`: **partial**. The pure decision functions
//!   (`_default_search_provider`, `_resolve_acquire_provider`,
//!   `_check_effects`, the `init_run` scale-budget mapping) are ported in
//!   `run.rs`. The stateful orchestrator functions (`init_run`'s directory
//!   write, `grant`, `acquire`, `record_evidence`, `record_claim`,
//!   `render_draft`, `issue_patch_receipt`, `apply_draft_patch`, `verify`,
//!   `finalize`, and the `argparse` `main`) are NOT ported: they depend on
//!   `manifest.py`, `ledger.py`, `citecheck.py`, `contradictions.py`,
//!   `gap_critic.py`, `domain_verify.py`, `retraction.py`, `patcher.py`,
//!   `draft_integrity.py`, `effect_audit.py`, `meter.py`, `patch_guard.py`,
//!   and `providers/search_open_find.py`, none of which has a canonical
//!   port under `legion-research` yet.
//! - `shards.py`: **ALREADY-NATIVE-VERIFIED**, at
//!   `crate::wf_port::wf023::shards`. That module is a faithful,
//!   independently-tested port of this exact file (confirmed identical by
//!   direct comparison during this chunk's port); it predates this chunk
//!   and lives in wf023 because `control.py` (wf023's file) depends on it.
//!   No new file is added here for it — see the packet report for the
//!   verification detail and the note already in `wf023::shards`'s own doc
//!   comment about consolidating the duplicate if wf023 is ever revisited.

pub mod route_detect;
pub mod route_resolve;
pub mod run;
