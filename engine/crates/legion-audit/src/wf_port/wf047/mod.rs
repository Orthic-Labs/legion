//! wf047 — `src/providers/runtime/{service,web}` chunk.
//!
//! Ports, all confirmed to have no prior native coverage by `git grep`
//! across `engine/` for their JS function names before writing this
//! module:
//!
//! - `src/providers/runtime/service/data/index.mjs` (`verifyServiceData`)
//!   and its dependency `src/providers/runtime/web/data/index.mjs`
//!   (`verifyDataExercise`, not itself in this chunk's file list, but
//!   ported here since `verifyServiceData`'s behaviour is entirely defined
//!   by it) — [`data`].
//! - `src/providers/runtime/service/faults/index.mjs`
//!   (`createServiceFixtureAdapter` / `createFaultAdapter`) — [`faults`].
//! - `src/providers/runtime/web/accessibility/index.mjs`
//!   (`verifyWebAccessibility`) — [`accessibility`]. Has a known gap: see
//!   that module's doc comment re: `captureWebEvidence`.
//! - `src/providers/runtime/web/actors/index.mjs` (`buildActorFixtures`,
//!   `switchActor`) — [`actors`].
//! - `src/providers/runtime/web/api/index.mjs` (`verifyApiExercise`) —
//!   [`api`]. Has a known gap: see that module's doc comment re:
//!   `sanitizeProducedArtifact`.
//!
//! All five share `src/providers/runtime/web/shared.mjs`
//! (`finalize`/`denominator`/`sameBinding`/`exactBinding`/`sortById`/
//! `redact`/`canonicalize`/`digest`), ported once at [`shared`] and reused
//! by every submodule in this chunk.

pub mod accessibility;
pub mod actors;
pub mod api;
pub mod data;
pub mod faults;
pub mod shared;
