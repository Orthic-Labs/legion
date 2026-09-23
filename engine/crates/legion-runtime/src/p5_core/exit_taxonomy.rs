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
        Self { message: message.into(), code: "LEGION_ERROR", exit_code: Exit::InternalError }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: "USAGE", exit_code: Exit::Usage }
    }

    pub fn integrity(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: "INTEGRITY", exit_code: Exit::Integrity }
    }

    pub fn incomplete(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: "INCOMPLETE", exit_code: Exit::Incomplete }
    }

    pub fn policy(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: "POLICY_FAIL", exit_code: Exit::PolicyFail }
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
    if report.integrity_valid == Some(false)
        || report.gates_plan_binding.as_deref() == Some("fail")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_takes_priority_over_everything() {
        let report = ExitReport {
            integrity_valid: Some(false),
            audit_status: Some("pass".into()),
            ..Default::default()
        };
        assert_eq!(exit_code_for_report(&report), Exit::Integrity);
    }

    #[test]
    fn plan_binding_fail_is_integrity() {
        let report = ExitReport {
            gates_plan_binding: Some("fail".into()),
            audit_status: Some("pass".into()),
            ..Default::default()
        };
        assert_eq!(exit_code_for_report(&report), Exit::Integrity);
    }

    #[test]
    fn incomplete_flag_or_status_maps_to_incomplete() {
        let by_flag = ExitReport { incomplete: Some(true), ..Default::default() };
        let by_status =
            ExitReport { audit_status: Some("incomplete".into()), ..Default::default() };
        assert_eq!(exit_code_for_report(&by_flag), Exit::Incomplete);
        assert_eq!(exit_code_for_report(&by_status), Exit::Incomplete);
    }

    #[test]
    fn fail_status_or_quality_gate_maps_to_policy_fail() {
        let by_status = ExitReport { audit_status: Some("fail".into()), ..Default::default() };
        let by_gate = ExitReport { quality_gate: Some("fail".into()), ..Default::default() };
        assert_eq!(exit_code_for_report(&by_status), Exit::PolicyFail);
        assert_eq!(exit_code_for_report(&by_gate), Exit::PolicyFail);
    }

    #[test]
    fn pass_status_maps_to_pass() {
        let report = ExitReport { audit_status: Some("pass".into()), ..Default::default() };
        assert_eq!(exit_code_for_report(&report), Exit::Pass);
    }

    #[test]
    fn unrecognized_shape_defaults_to_internal_error() {
        let report = ExitReport::default();
        assert_eq!(exit_code_for_report(&report), Exit::InternalError);
    }

    #[test]
    fn exit_codes_match_js_numeric_taxonomy() {
        assert_eq!(Exit::Pass.code(), 0);
        assert_eq!(Exit::PolicyFail.code(), 1);
        assert_eq!(Exit::Incomplete.code(), 2);
        assert_eq!(Exit::InternalError.code(), 3);
        assert_eq!(Exit::Usage.code(), 4);
        assert_eq!(Exit::Integrity.code(), 5);
    }
}
