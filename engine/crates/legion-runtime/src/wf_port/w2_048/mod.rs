//! Chunk w2_048 (`area src/lib/host`).
//!
//! ## Disposition per source file
//!
//! - `src/lib/host/arcane/session-binding.mjs` (`SessionBindingStore`) —
//!   ALREADY-NATIVE-VERIFIED at
//!   `legion-arcane::session_binding::SessionBindingStore`
//!   (`engine/crates/legion-arcane/src/session_binding.rs`). Covers
//!   `getBinding`/`ensureBinding`/`putBinding`/`compareAndSwap` including the
//!   `wx`-exclusive-create race convergence and the temp+rename atomic
//!   upgrade path. Gaps found while verifying (reported, not fixed — that
//!   file is outside this chunk's owned paths):
//!     * the JS store validates the optional `delivery` and `lifecycle`
//!       shapes on both `readBinding` and `putBinding`, and `putBinding`
//!       carries forward the previous `work`/`lifecycle` when the caller
//!       omits them; the Rust store's `put` writes whatever `Value` the
//!       caller passes with no shape validation and no carry-forward — callers
//!       must reconstruct the full record themselves.
//!     * `compareAndSwap` in JS takes an exclusive `.cas-lock` file
//!       (`open(..., 'wx')`) around the whole compare+write so a concurrent
//!       `compareAndSwap` cannot interleave with it; the Rust
//!       `compare_and_swap` does a plain read-compare-write with no lock,
//!       so two concurrent Rust callers can both pass the compare and one
//!       write is lost (the JS file's own stated purpose for the lock).
//!
//! - `src/lib/host/arcane/source-revision.mjs` (`resolveSourceRevisionFs`,
//!   the fs-only, git-parity `HEAD` SHA resolver) — ALREADY-NATIVE-VERIFIED
//!   at `resolve_source_revision` in
//!   `engine/bins/legion-hook/src/main.rs` (detached HEAD, symbolic ref via
//!   loose ref file, worktree `commondir`, and `packed-refs` fallback are
//!   all covered, with tests `source_revision_reads_git_metadata_without_spawning`,
//!   `source_revision_resolves_from_a_subdirectory`, and
//!   `source_revision_reads_packed_refs_without_spawning`). No gap found.
//!   (This is a different source file from `src/lib/qualification/source-revision.mjs`,
//!   which is a content-hash algorithm already ported separately at
//!   `legion-audit::wf_port::wf014::source_revision` — not this chunk's file.)
//!
//! - `src/lib/skill-projection.mjs` — ALREADY-NATIVE-VERIFIED at
//!   `legion-harness::skills` (`engine/crates/legion-harness/src/skills.rs`):
//!   `project_skills`/`verify_skill_projection`/`unproject_skills`/
//!   `classify_destination`/`package_matches` all present and matching the
//!   JS module's collision-safe two-phase symlink/copy-fallback behaviour,
//!   including the "foreign destination -> nothing written" invariant. No
//!   gap found.
//!
//! - `src/lib/host/arcane/stop-disposition.mjs` — **no existing Rust
//!   coverage** (only its caller, `evaluateHostStop` in
//!   `hook-adapter-core.mjs`, is referenced elsewhere, and that caller's
//!   Rust port is out of scope for this chunk). Ported fresh below as
//!   `stop_disposition`, faithfully: same disposition set, same intent
//!   classification, same certification rule.

pub mod stop_disposition;
