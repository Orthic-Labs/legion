#![forbid(unsafe_code)]

mod assets;
mod decision;
mod error;
mod git;
mod json_util;
mod review;

pub use assets::resolve_minimize_paths;
pub use decision::{
    decision_receipt, validate_decision, verify_decision, DECISION_RECEIPT_SCHEMA, DECISION_SCHEMA,
};
pub use error::MinimizeError;
pub use git::{canonical_locator, GitContext};
pub use json_util::{file_exists, read_json, write_json};
pub use review::{
    build_receipt, build_review, reuse_findings, staged_new_dependencies, validate_review,
    verify_receipt, MinimizePaths, RECEIPT_SCHEMA, REVIEW_SCHEMA, RUNGS,
};
