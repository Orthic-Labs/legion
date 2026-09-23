//! wf024: faithful Rust port of the `src/lib/research-core` Python assurance
//! scripts (domain verification, draft-integrity, and effect-audit
//! reconciliation). These operate on loose JSON (the scripts' own schema,
//! not the strict `EvidenceRecord`/`Claim`/`BudgetUsage` types elsewhere in
//! this crate) so the port keeps the exact field names, check names, and
//! ordering the Python originals produced.

pub mod domain_verify;
pub mod draft_integrity;
pub mod effect_audit;

pub use domain_verify::verify as domain_verify;
pub use draft_integrity::check as draft_integrity_check;
pub use effect_audit::audit as effect_audit;
