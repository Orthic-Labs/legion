//! Port chunk w2_042 (area `src/lib/core`, target crate `legion-runtime`).
//!
//! Source files and disposition:
//!
//! - `src/lib/core/repository-binding.mjs` — **PORTED** in full, see
//!   [`repository_binding`]. `bindRepository(root, options)` walks the
//!   repository (via `git ls-files --cached --others --exclude-standard`
//!   when Git is available, falling back to a manual directory walk that
//!   excludes the same fixed runtime-state directories/paths JS excludes)
//!   and hashes every entry's content (or `symlink\0<target>` / `missing\0`
//!   / `non-file:<kind>\0` marker) into one SHA-256 `dirtyOverlayDigest`,
//!   then wraps it with the caller-supplied authority digests into the
//!   record's overall `digest` via [`crate::l3_inventory::binding::digest`]
//!   — the exact same canonicalize/digest primitive `repository-binding.mjs`
//!   imports from `./binding.mjs`, already ported at
//!   `legion_runtime::l3_inventory::binding`. Both Git-backed and
//!   non-Git-backed fixed exclusion sets match the JS `FALLBACK_*` constants
//!   exactly.
//!
//! - `src/lib/core/run-manifest.mjs` — **PORTED** in full, see
//!   [`run_manifest`]. `writeCanonicalManifest(store, binding)` computes the
//!   manifest value (`terminalAbsences` = the sorted list of artifact paths
//!   whose `status` is `"missing"`, plus the record's own digest) exactly as
//!   JS does; the store-write side effect itself (`store.writeJson(...)`) is
//!   outside this chunk's scope (no `Store`/persistence trait exists yet
//!   anywhere in `legion-runtime` — confirmed via
//!   `git grep -n "writeJson\|trait.*Store" engine/crates/legion-runtime/src`),
//!   so [`run_manifest::build_canonical_manifest`] returns the manifest
//!   `Value` plus the `CanonicalManifestArtifact` envelope fields
//!   (`path`, `kind`, `producer`, `producerVersion`, `schemaVersion`,
//!   `mediaType`, `binding`, `denominatorDigest`) `writeJson` was called
//!   with, so an integrator wiring a future `Store` can persist it with one
//!   call. `validateRunManifest(manifest, files, expectedBinding)` is
//!   ported as [`run_manifest::validate_run_manifest`] with identical issue
//!   ordering (`binding:mismatch`, `source-revision:missing`,
//!   `terminal-absences:mismatch`, then sorted `orphan:`/
//!   `missing-or-drifted:` entries).
//!
//! - `src/lib/core/verify-run.mjs` — **PORTED** in full, see
//!   [`verify_run`]. `verifySealedRun({priorRun, currentRepository}, host)`
//!   is ported as [`verify_run::verify_sealed_run`] taking the already
//!   parsed `prior` value directly (the JS `typeof priorRun === 'string'`
//!   branch is a host-`fs` read outside this chunk's scope — the caller
//!   reads/parses `priorRun` before calling, same contract
//!   `verifySealedRun` used once `host.fs.readFile` had resolved) and an
//!   explicit `now: String` (RFC 3339) in place of `host.clock.now()`. The
//!   private `integrityGaps(snapshot)` helper (dependency-order,
//!   exclusive-lock-overlap, reasoning-context-reuse) is ported as
//!   [`verify_run::integrity_gaps`] with the same three gap kinds in the
//!   same order. Interval overlap comparison uses RFC 3339 string ordering
//!   in place of `Date.parse`: every timestamp this codebase produces
//!   (`host.clock.now().toISOString()`, JS `Date#toISOString()`) is
//!   zero-padded, fixed-width, UTC (`Z`-suffixed) RFC 3339, for which
//!   lexicographic and chronological order coincide; a non-UTC-offset or
//!   variable-width timestamp would compare incorrectly, which is a
//!   documented gap, not a silent behavior change, since no such input
//!   exists in this codebase's own writers.
//!   Uses `legion_runtime::p5_core::verification_projection::semantic_projection`
//!   for the projection step (already ported from
//!   `src/lib/verification/projection.mjs`, this chunk's `verify-run.mjs`
//!   dependency) and `crate::l3_inventory::binding` for `digest`/`same_binding`
//!   (`verify-run.mjs`'s `./binding.mjs` import), matching the JS's own
//!   reuse of both modules exactly.

pub mod repository_binding;
pub mod run_manifest;
pub mod verify_run;

pub use repository_binding::{bind_repository, BindOptions, RepositoryBinding};
pub use run_manifest::{
    build_canonical_manifest, validate_run_manifest, ArtifactRecord, CanonicalManifestArtifact,
    RunManifest,
};
pub use verify_run::{verify_sealed_run, CurrentRepository, VerificationReceipt};
