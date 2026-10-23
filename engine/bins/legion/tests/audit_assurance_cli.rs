use std::process::Command;

fn legion(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(arguments)
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .output()
        .expect("native Legion CLI must execute")
}

#[test]
fn audit_help_lists_assurance_flags_and_gate() {
    let output = legion(&["audit", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "--runtime-policy",
        "--product-contract",
        "--artifact-manifest",
        "gate",
        "pre-pr",
    ] {
        assert!(text.contains(needle), "audit --help must mention {needle}");
    }
}

#[test]
fn gate_help_names_its_verdicts_and_requires_a_run() {
    let output = legion(&["audit", "gate", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("--run"));
    assert!(text.contains("blocked-findings"));
    let output = legion(&["audit", "gate"]);
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn gate_on_a_missing_run_is_incomplete_never_success() {
    let output = legion(&["audit", "gate", "--run", "/nonexistent-legion-gate-run"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn gate_rejects_an_unknown_required_profile() {
    let output = legion(&["audit", "gate", "--run", ".", "--profile", "standard"]);
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn assurance_flags_require_a_new_profile() {
    let output = legion(&[
        "audit",
        ".",
        "--plan-only",
        "--runtime-policy",
        "no-node-python",
    ]);
    assert_eq!(output.status.code(), Some(4));
    let output = legion(&[
        "audit",
        ".",
        "--runtime-policy",
        "unrestricted",
        "--profile",
        "release",
    ]);
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn report_help_still_accepts_new_projection_kinds_as_text() {
    let output = legion(&[
        "report",
        "/nonexistent-report.json",
        "--report",
        "assurance",
    ]);
    assert_ne!(output.status.code(), Some(0));
}
