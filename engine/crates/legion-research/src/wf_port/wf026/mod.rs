//! wf026: faithful Rust port of `src/lib/research-core` budget metering and
//! patch-stage receipt/apply scripts.
//!
//! Ported files:
//! - `meter.py` -> `meter`
//! - `patch_guard.py` -> `patch_guard`
//! - `patcher.py` -> `patcher`
//!
//! `methods/__init__.py` and `providers/__init__.py` are empty Python package
//! markers with no logic to port.

pub mod meter;
pub mod patch_guard;
pub mod patcher;

pub use meter::consume as meter_consume;
pub use patch_guard::issue_receipt as patch_guard_issue_receipt;
pub use patcher::{apply_patch, validate_correction_receipt};
