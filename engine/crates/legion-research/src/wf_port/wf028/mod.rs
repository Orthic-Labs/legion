//! wf028: faithful Rust port of `src/lib/research-core`'s scholarly
//! provider, provider-neutral search/open/find dispatcher, run-finalization
//! receipt, resource-authorization guard, and DOI retraction sweep.
//!
//! Ported files:
//! - `providers/scholarly.py` -> [`scholarly`]
//! - `providers/search_open_find.py` -> [`search_open_find`]
//! - `receipt.py` (a thin `from manifest import finalize` re-export) -> [`receipt`]
//! - `resource_guard.py` -> [`resource_guard`]
//! - `retraction.py` -> [`retraction`]
//!
//! [`support`] is a self-contained reimplementation of the pieces of the
//! sibling `common.py` and `manifest.py` this packet's own files actually
//! exercise (`utc_now`, `today`, `sha256_text`, JSON read/atomic-write,
//! JSONL append, and the cross-platform file lock); those two files are not
//! owned by this packet, so this mirrors the boundary choice `wf026`'s
//! `meter.rs` documents for the same reason.
//!
//! Network transport for `scholarly.py` (Crossref) and `retraction.py`
//! (OpenAlex, Crossref) is injected via `ScholarlyTransport` /
//! `RetractionTransport` rather than performed directly: no HTTP client
//! crate (`reqwest`, `ureq`, ...) is a workspace dependency of
//! `legion-research`, and this packet is read-only on `Cargo.toml`. The
//! dependency patch a real transport needs is in `wf028.md`.

pub mod receipt;
pub mod resource_guard;
pub mod retraction;
pub mod scholarly;
pub mod search_open_find;
pub mod support;

pub use receipt::finalize as receipt_finalize;
pub use resource_guard::{authorize as resource_authorize, read_resource};
pub use retraction::{check_doi, sweep as retraction_sweep};
pub use scholarly::{find as scholarly_find, open as scholarly_open, search as scholarly_search};
pub use search_open_find::provider as search_open_find_provider;
