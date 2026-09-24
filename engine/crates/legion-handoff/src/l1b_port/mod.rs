//! L1b literal port of `src/lib/handoff/validate_handoff.py`.
//!
//! Ports the pure validation core: heading order, label presence and
//! concreteness, resume-step structure, table shape, enum/readiness
//! coherence, author-gate checklist, banned phrases, and secret scanning.
//! The `argparse` CLI (`main`) and receipt file I/O are not ported — this
//! is a library surface; a caller wires its own file reads/writes around
//! `validate` and `storage_errors`.

pub mod cli;
pub mod validate;

pub use cli::run;
pub use validate::{
    clean_path_value, concrete, fenced_after, is_absolute_path, label_value, normalized_path,
    ordered_errors, resume_errors, storage_errors, table_errors, table_rows, validate as validate_handoff,
    FORBIDDEN_STORAGE_PARTS, HEADINGS, LABELS, STEP_LABELS,
};
