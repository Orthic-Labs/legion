//! Packet r53 — faithful port of `src/lib/providers/sdk/index.mjs`, the
//! provider SDK barrel module for `@orthic-labs/legion/provider-sdk`.
//!
//! The JS file itself is ten re-exports across four sibling modules
//! (`dag.mjs`, `testkit.mjs`, `registry/provider-contracts.mjs`,
//! `registry/provider-registry.mjs`). None of the ten symbols had an
//! existing Rust port at port time (checked with `git grep` for each
//! `snake_case` name across `engine/`) — the crate's own `registry.rs` /
//! `testkit.rs` / `result.rs` are ports of *different* JS sources and do not
//! cover this surface — so this module ports all four source files in full:
//!
//! - [`dag`] — `dag.mjs`: `topologicalProviders`, `ROLE_OUTPUT_AUTHORITY`,
//!   `validateRoleOutput`, `validateProviderDag`.
//! - [`testkit`] — `testkit.mjs`: `stableId`, `pathDenominator`,
//!   `validateProviderRecord`, plus its re-exports of
//!   `validateProviderResult`/`normalizeProviderResult`
//!   (`scripts/normalize-provider-result.mjs`, ported here as
//!   [`testkit::validate_provider_result`] /
//!   [`testkit::normalize_provider_result`] since that script has no other
//!   owner and this is its only reachable export surface).
//! - [`contracts`] — `registry/provider-contracts.mjs`: `PROVIDER_PHASES`,
//!   `PROVIDER_ROLES`, `PROVIDER_STATUS`, `assertEnum`.
//! - [`canonical`] — `registry/provider-registry.mjs`: `canonicalJson`,
//!   `canonicalize`, `sha256`. (Ported narrowly: only the three symbols
//!   `index.mjs` re-exports, not the whole registry-loading module.)

pub mod canonical;
pub mod contracts;
pub mod dag;
pub mod testkit;
