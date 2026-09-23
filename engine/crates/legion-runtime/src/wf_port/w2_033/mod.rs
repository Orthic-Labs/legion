//! Chunk w2_033 (area `skills/seo/scripts`): Rust ports of `rank_tracker.py`, `search_ops.py`,
//! `seo_closure.py`, and `seo_project.py`.
//!
//! `render_gap.mjs` — the fifth file in this chunk — is already natively covered by
//! `crate::p9_skills::render_gap` (`diff_signals`/`SeoSignals`), which ports the same pure
//! `diff()`/summary core verbatim; see that module's doc comment for what is and is not
//! ported from `render_gap.mjs`. No gap found against the current `render_gap.mjs` source.
//!
//! Every script here is CLI-plus-filesystem-state tooling (JSON/CSV snapshot files, an
//! interventions store, a repo-structure closure gate). Consistent with the existing
//! `wf_port`/`p9_skills` convention (see `render_gap.rs`), each submodule ports the pure,
//! deterministic logic — parsing/normalization, state transitions, diffing, hashing,
//! arithmetic, validation — and leaves file IO, `argparse` CLI wiring, and `os.environ`
//! reads to a host wrapper that supplies already-loaded data to these functions.

pub mod rank_tracker;
pub mod search_ops;
pub mod seo_closure;
pub mod seo_project;
