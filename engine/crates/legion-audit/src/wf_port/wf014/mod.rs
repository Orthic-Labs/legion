//! wf014 — port of `src/lib/qualification/*.mjs`.
//!
//! Four small, pure(ish) modules used to build and validate
//! `legion-book-qualification` receipts:
//!
//! - [`schema_validator`]: a dependency-free JSON-Schema subset evaluator.
//! - [`source_revision`]: content-hashes the tracked (+dirty) source tree.
//! - [`source_slice`]: builds a v1 "source slice" receipt from task/source
//!   records.
//! - [`book_receipt`]: validates a v1 or v2 receipt against filesystem
//!   evidence, the v2 JSON schema, and (v2) the current source revision.

pub mod book_receipt;
pub mod schema_validator;
pub mod source_revision;
pub mod source_slice;

pub use book_receipt::{load_book_receipt, validate_book_receipt, BookReceiptOptions};
pub use schema_validator::validate_schema;
pub use source_revision::{committed_source_revision, current_source_revision};
pub use source_slice::source_slice_qualification;
