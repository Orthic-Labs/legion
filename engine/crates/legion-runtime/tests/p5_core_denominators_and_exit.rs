//! Integration tests for packet P5-runtime-core's first ported slice.
//! Requires the lib.rs patch in the packet report (`pub mod p5_core;`) to be
//! applied before this compiles — see
//! scratchpad/loss/full-P5-runtime-core.md.

use legion_runtime::p5_core::{exit_code_for_report, reconcile_denominator, Exit, ExitReport};

#[test]
fn reconcile_denominator_reports_missing_ids() {
    let result = reconcile_denominator(vec!["alpha", "beta", "gamma"], vec!["beta"]);
    assert_eq!(result.missing, vec!["alpha", "gamma"]);
}

#[test]
fn exit_code_for_report_prioritizes_integrity_over_pass() {
    let report = ExitReport {
        integrity_valid: Some(false),
        audit_status: Some("pass".to_string()),
        ..Default::default()
    };
    assert_eq!(exit_code_for_report(&report), Exit::Integrity);
}
