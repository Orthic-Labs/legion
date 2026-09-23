//! Integration tests for the wf_port w2_003 chunk: port of
//! `skills/covenant/engine/packet-validator.py`.
//!
//! NOTE: these tests reference `legion_runtime::wf_port::w2_003`, which
//! requires the integrator wiring described in the w2_003 report
//! (`pub mod wf_port;` in lib.rs already exists; `pub mod w2_003;` needs
//! adding to `engine/crates/legion-runtime/src/wf_port/mod.rs`).

use legion_runtime::wf_port::w2_003::{run, validate, CANONICAL_MODE, HEADINGS, LABELS};
use std::path::{Path, PathBuf};

fn fixture_template() -> String {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_003/template.md");
    std::fs::read_to_string(fixture).expect("template fixture present")
}

// Ported from skills/covenant/scripts/test_validate_external_review_packet.py
#[test]
fn canonical_template_self_checks_clean() {
    let template = fixture_template();
    let errors = validate(&template, Path::new("template.md"), false, true);
    assert_eq!(errors, Vec::<String>::new());
}

// Ported from skills/covenant/scripts/test_validate_external_review_packet.py
#[test]
fn non_canonical_mode_is_rejected() {
    let template = fixture_template();
    let mutated = template.replacen(CANONICAL_MODE, "RUN_COVENANT", 1);
    let errors = validate(&mutated, Path::new("template.md"), false, true);
    assert!(errors.iter().any(|e| e.contains("Mode must be")));
}

#[test]
fn run_reports_pass_message_for_clean_template_self_check() {
    let template = fixture_template();
    let outcome = run(&template, Path::new("template.md"), false, true);
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.message.starts_with("PASS:"));
}

#[test]
fn run_reports_fail_message_with_defect_count() {
    let outcome = run("", Path::new("x.md"), false, true);
    assert_eq!(outcome.exit_code, 1);
    assert!(outcome.message.starts_with(&format!(
        "FAIL: {} packet defect(s)",
        HEADINGS.len() + LABELS.len()
    )));
}

#[test]
fn empty_packet_reports_every_missing_heading_and_label() {
    let errors = validate("", Path::new("x.md"), false, true);
    assert_eq!(errors.len(), HEADINGS.len() + LABELS.len());
}
