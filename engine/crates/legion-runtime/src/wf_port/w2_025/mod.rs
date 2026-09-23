//! Port of chunk `w2_025` (area `skills/seo/extensions/banana/scripts`,
//! files `batch.py`, `cost_tracker.py`, `edit.py`, `generate.py`,
//! `presets.py`).
//!
//! ## Scope
//!
//! `cost_tracker.py`, `presets.py`, and `batch.py` are fully pure,
//! deterministic, filesystem-adjacent logic and are ported faithfully in
//! [`cost_tracker`], [`presets`], and [`batch`] respectively (the
//! filesystem reads/writes those Python CLIs perform against
//! `~/.banana/...` are left to the caller; each module documents the exact
//! on-disk shape/filename Python used so a caller's I/O layer matches it).
//!
//! `generate.py` and `edit.py` are stdlib-only Gemini REST API clients:
//! every deterministic piece (input validation, request-body construction,
//! response-shape extraction, output filename construction) is ported in
//! [`generate`] and [`edit`]. The actual `urllib.request` HTTP call is not
//! reproduced — this crate's `Cargo.toml` has no HTTP client dependency and
//! this module may not add one; see each module's doc comment and the
//! chunk's integration report for the exact dependency patch needed.

pub mod batch;
pub mod cost_tracker;
pub mod edit;
pub mod generate;
pub mod presets;
