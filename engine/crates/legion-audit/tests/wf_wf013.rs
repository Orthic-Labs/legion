//! Integration-level assertions for the wf013 port (`src/lib/qa-engine/{qa,qa-shot,qa-functional}.mjs`).
//!
//! The bulk of behavior-level assertions live as unit tests inside
//! `src/wf_port/wf013/mod.rs` (co-located with the pure functions they exercise, per this
//! crate's existing wf_port convention). This file adds fixture-driven checks that read the
//! action-file shape qa.mjs accepts, confirming the ported argument/viewport/throttle logic
//! agrees with a realistic `actions.json` and CLI invocation captured from the legacy tool.
//!
//! NOTE: `legion_audit::wf_port::wf013` is expected to be wired by the integrator via
//! `pub mod wf_port;` / `pub mod wf013;` in the crate's module tree (see chunk instructions).
//! This file is written against that path and will start compiling once that wiring lands.

use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf013")
}

#[test]
fn sample_actions_file_is_well_formed_json_array() {
    let path = fixtures_dir().join("sample_actions.json");
    let raw = fs::read_to_string(&path).expect("fixture should exist");
    let value: serde_json::Value =
        serde_json::from_str(&raw).expect("sample_actions.json must be valid JSON");
    assert!(value.is_array(), "qa.mjs requires --actions file to be a JSON array");
    let arr = value.as_array().unwrap();
    assert!(!arr.is_empty());
    for action in arr {
        assert!(
            action.get("type").and_then(|t| t.as_str()).is_some(),
            "every action needs a string `type`, as runAction() dispatches on it"
        );
    }
}

#[test]
fn cli_invocation_fixture_parses_to_expected_args() {
    let path = fixtures_dir().join("sample_cli_invocation.txt");
    let raw = fs::read_to_string(&path).expect("fixture should exist");
    let argv: Vec<String> = raw.split_whitespace().map(|s| s.to_string()).collect();

    let args = legion_audit::wf_port::wf013::parse_args(&argv)
        .expect("fixture invocation should parse cleanly");

    assert!(args.actions.is_some(), "fixture invocation uses --actions");
    assert_eq!(args.route, "/?qa=1");
    // fixture requests --viewport mobile
    assert_eq!(args.width, 390.0);
    assert_eq!(args.height, 844.0);
    assert!(args.mobile);
    assert_eq!(args.throttle.as_deref(), Some("slow-3g"));
}

#[test]
fn qa_functional_wrapper_matches_fixture_invocation_passthrough() {
    let path = fixtures_dir().join("sample_cli_invocation.txt");
    let raw = fs::read_to_string(&path).expect("fixture should exist");
    let argv: Vec<String> = raw.split_whitespace().map(|s| s.to_string()).collect();

    // qa-functional.mjs passes argv through unchanged because it contains --actions.
    let rewritten = legion_audit::wf_port::wf013::qa_functional_final_args(&argv);
    assert_eq!(rewritten, argv);
}

#[test]
fn qa_functional_wrapper_degrades_to_help_for_shot_only_invocation() {
    let path = fixtures_dir().join("sample_shot_invocation.txt");
    let raw = fs::read_to_string(&path).expect("fixture should exist");
    let argv: Vec<String> = raw.split_whitespace().map(|s| s.to_string()).collect();

    let rewritten = legion_audit::wf_port::wf013::qa_functional_final_args(&argv);
    assert_eq!(rewritten, vec!["--help".to_string()]);

    // qa-shot.mjs, by contrast, always prepends --shot to the same argv.
    let shot_rewritten = legion_audit::wf_port::wf013::qa_shot_final_args(&argv);
    assert_eq!(shot_rewritten[0], "--shot");
    assert_eq!(&shot_rewritten[1..], argv.as_slice());
}
