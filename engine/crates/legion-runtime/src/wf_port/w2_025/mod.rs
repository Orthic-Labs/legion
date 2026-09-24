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
//! `generate.py` and `edit.py` are stdlib-only Gemini REST API clients.
//! `generate.py` (packet r33) is now fully ported end-to-end in
//! [`generate`], including the live HTTP round trip
//! ([`generate::ReqwestImageTransport`], behind the [`generate::ImageTransport`]
//! trait) and the image write ([`generate::StdFs`]); `edit.py` is
//! unchanged from the prior chunk — every deterministic piece is ported in
//! [`edit`], with its HTTP call left as a documented gap for whichever
//! packet closes it next.

pub mod batch;
pub mod cost_tracker;
pub mod edit;
pub mod generate;
pub mod presets;
