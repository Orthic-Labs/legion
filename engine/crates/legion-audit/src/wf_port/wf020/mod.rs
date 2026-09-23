//! wf020 — `src/lib/report/families/{data-privacy,docs-contract,
//! governance,requirements,shared}.mjs`.
//!
//! All five source files assigned to this chunk carry exactly one piece of
//! behaviour between them: `shared.mjs` defines `buildFamilySummary`, and
//! `data-privacy.mjs`, `docs-contract.mjs`, `governance.mjs`, and
//! `requirements.mjs` are each, verbatim, their entire file:
//!
//! ```js
//! export {buildFamilySummary} from './shared.mjs';
//! ```
//!
//! There is no family-specific logic anywhere in this chunk — no branch in
//! `shared.mjs` reads a family name to change behaviour, and none of the
//! four re-export files adds so much as a comment.
//!
//! **This exact function was already ported and unit-tested** as
//! `wf_port::wf019::family_summary::build_family_summary`
//! (`engine/crates/legion-audit/src/wf_port/wf019/family_summary.rs`).
//! wf019 was assigned the `architecture.mjs` / `code.mjs` /
//! `compatibility.mjs` / `data-integrity.mjs` re-exports of the very same
//! `shared.mjs` function — a different set of four call sites for one
//! shared implementation. wf019's own module doc says as much: it names
//! this chunk's files as "out of scope there" and "identical callers of
//! the same underlying summary logic."
//!
//! Disposition for every file in this chunk: **ALREADY-NATIVE-VERIFIED**
//! via `wf_port::wf019::family_summary`. This module does not re-implement
//! `buildFamilySummary` (that would create the second-entry-point problem
//! called out in `docs/agent-rules.md`'s HeardRight sibling rule about one
//! canonical entry point — the same principle applies here: one Rust
//! implementation of `buildFamilySummary`, not two). Instead it re-exports
//! the wf019 port under `wf_port::wf020` so this chunk's families are
//! reachable through their own module path, and
//! `tests/wf_wf020.rs` exercises it directly against this chunk's family
//! names (`data-privacy`, `docs-contract`, `governance`, `requirements`)
//! as an independent regression check owned by this chunk.
//!
//! No JS test file exists for any of these five source files (there is no
//! `families/shared.test.mjs`, `data-privacy.test.mjs`, etc. anywhere in
//! the JS tree as of this port), so there is no JS assertion set to port
//! test-for-test; `tests/wf_wf020.rs` instead re-derives coverage from the
//! `buildFamilySummary` source in `shared.mjs` directly, scoped to this
//! chunk's family names.

pub use crate::wf_port::wf019::family_summary::{
    build_family_summary, Denominator, FamilyResult, FamilySummary, ProviderSummary, SummaryGap,
};
