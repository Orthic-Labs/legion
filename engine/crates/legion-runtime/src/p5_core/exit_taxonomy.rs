//! Ported from src/lib/errors.mjs (packet P5-runtime-core).
//!
//! Canonical CLI exit taxonomy. Completion, policy, incompleteness, internal
//! failure, usage, and integrity are distinct — an incomplete run must never
//! return PASS even when it found zero issues.
//!
//! `LegionError`/`UsageError`/etc. from the JS source are represented here as
//! a single `TaxonomyError` carrying the same `code` string and `exit_code`,
//! since Rust error handling does not need a parallel subclass hierarchy to
//! get the same dispatch: match on `.code()` or `.exit_code()`.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum Exit {
    Pass = 0,
    PolicyFail = 1,
    Incomplete = 2,
    InternalError = 3,
    Usage = 4,
    Integrity = 5,
}

impl Exit {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonomyError {
    pub message: String,
    pub code: &'static str,
    pub exit_code: Exit,
}

impl TaxonomyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: "LEGION_ERROR",
            exit_code: Exit::InternalError,
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: "USAGE",
            exit_code: Exit::Usage,
        }
    }

    pub fn integrity(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: "INTEGRITY",
            exit_code: Exit::Integrity,
        }
    }

    pub fn incomplete(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: "INCOMPLETE",
            exit_code: Exit::Incomplete,
        }
    }

    pub fn policy(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: "POLICY_FAIL",
            exit_code: Exit::PolicyFail,
        }
    }
}

impl fmt::Display for TaxonomyError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{}", self.message)
    }
}

impl std::error::Error for TaxonomyError {}

/// Minimal projection of the report shape `exitCodeForReport` inspects.
/// Mirrors the optional-chaining reads in the JS source; every field is
/// optional exactly as `report?.foo` treats a missing key as absent.
#[derive(Debug, Clone, Default)]
pub struct ExitReport {
    pub integrity_valid: Option<bool>,
    pub gates_plan_binding: Option<String>,
    pub incomplete: Option<bool>,
    pub audit_status: Option<String>,
    pub quality_gate: Option<String>,
}

/// Port of `exitCodeForReport(report)`.
pub fn exit_code_for_report(report: &ExitReport) -> Exit {
    if report.integrity_valid == Some(false) || report.gates_plan_binding.as_deref() == Some("fail")
    {
        return Exit::Integrity;
    }
    if report.incomplete == Some(true) || report.audit_status.as_deref() == Some("incomplete") {
        return Exit::Incomplete;
    }
    if report.audit_status.as_deref() == Some("fail")
        || report.quality_gate.as_deref() == Some("fail")
    {
        return Exit::PolicyFail;
    }
    if report.audit_status.as_deref() == Some("pass") {
        return Exit::Pass;
    }
    Exit::InternalError
}
