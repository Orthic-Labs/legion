//! Port of chunk wf065 (area `tools/audit`):
//!
//! - `tools/audit/audit-verify.mjs` — out-of-band plan/facts drift
//!   verification CLI. `git grep` over `engine/` for `audit-verify`,
//!   `verifyPlanSeal`, `verifyPlanBinding`, `frozenContract`, and
//!   `ALLOWED_CHILD_KEYS` found no prior native port. The pure
//!   drift-classification/digest logic is ported in [`audit_verify`]; the
//!   CLI's plan recomputation (Blueprint-backed) and its own re-spawn of
//!   `collect-facts.mjs` are process orchestration, not pure functions, and
//!   are not ported — see that module's doc comment for the exact boundary.
//! - `tools/audit/audit_provider.py` — **dropped**. Its own module docstring
//!   names it "G4 of the Membrane unified architecture": it is a
//!   `ContextProvider`-shaped adapter that emits `ContextCandidateSet`
//!   records for Membrane's planner. Per this chunk's instructions
//!   ("Membrane/Blueprint are moving to another product: DROP anything that
//!   talks to them"), this file is not ported.
//! - `tools/audit/audit_store.py` — the typed `AuditFindingV1` JSONL store
//!   `audit_provider.py` reads from. This module is storage-only (no
//!   Membrane/planner import), so it is ported in full in [`audit_store`]
//!   and is usable independent of the dropped provider adapter.
//! - `tools/audit/collect-facts.mjs` — the deterministic scanner-runner CLI.
//!   `git grep` for `collect-facts`, `gitleaksCandidates`, `classifyFile`,
//!   and `decompositionReviewLoc` found no prior native port (the
//!   `native_providers/legacy_checks` module and
//!   `native_legacy_provider_equivalence.rs` test only *reference*
//!   `collect-facts.mjs` by name/path as the legacy JS baseline they
//!   equivalence-test against — they do not port its internals). Its pure,
//!   process-free helpers are ported in full in [`collect_facts`]; the
//!   process-spawning check runners (`tsc`, `eslint`, `clippy`, `gitleaks`,
//!   `npm audit`, `pip-audit`, ...) are external-tool orchestration, not
//!   pure functions, and are not ported — see that module's doc comment.
//! - `tools/audit/provider-benchmarks.mjs` — the precision/recall
//!   measurement harness. No prior native port found (`git grep` for
//!   `measureFixtureSet`, `qualificationFromResults`, `computeFixturesDigest`,
//!   `resultQualificationDigest` under `engine/` is empty). Ported in full in
//!   [`provider_benchmarks`], excepting the frozen-JSON-Schema validation
//!   (no schema file/validator in this chunk's owned paths — a structural
//!   equivalent is used instead) and the `measure`/`verify`/`status` CLI's
//!   dynamic `import()` of a caller-supplied runner module (this port's
//!   `measure_fixture_set` takes the runner as a Rust closure directly, same
//!   as the JS API already required of its callers).
//!
//! None of these five files import each other in the source tree (each is
//! `node`/`python`-invoked independently), so each ported module below is
//! self-contained; nothing here depends on another `wf_port` chunk.

pub mod audit_store;
pub mod audit_verify;
pub mod collect_facts;
pub mod provider_benchmarks;
