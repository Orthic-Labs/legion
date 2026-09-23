//! wf025: faithful Rust port of the `src/lib/research-core` Python run
//! bookkeeping and evidence-quality scripts (`events.py`, `gap_critic.py`,
//! `independence.py`, `ledger.py`, `manifest.py`). Like its sibling wf024,
//! this operates on loose JSON (`serde_json::Value`) matching the Python
//! scripts' own schemas, not the strict `EvidenceRecord`/`Claim` types
//! elsewhere in this crate, so field names, check names, and ordering
//! match the originals exactly. `manifest.rs` is the one module here with
//! real side effects (disk-persisted run state), matching `manifest.py`.

pub mod gap_critic;
pub mod independence;
pub mod iso_date;
pub mod ledger;
pub mod manifest;

// `events.py` is a one-function re-export of `manifest.record_event`;
// mirrored here the same way.
pub use manifest::record_event;

pub use gap_critic::{review as gap_critic_review, review_to_json as gap_critic_review_to_json};
pub use independence::cluster as independence_cluster;
pub use ledger::{check as ledger_check, render as ledger_render, validate_evidence as ledger_validate_evidence};
