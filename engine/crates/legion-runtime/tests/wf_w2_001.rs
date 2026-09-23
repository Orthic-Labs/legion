//! Integration tests for chunk w2_001
//! (`skills/alchemist/scripts/{parse_events.py,run-worker.sh,run-worker.ps1,
//! start-stack.vbs,tray.ps1}`), exercising the port through the crate's
//! public `wf_port::w2_001` module against a fixture event log.

use legion_runtime::wf_port::w2_001::parse_events::{run_summary, ParsedLine};
use legion_runtime::wf_port::w2_001::stack_status;
use legion_runtime::wf_port::w2_001::worker_launch;

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wf_w2_001")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

#[test]
fn run_summary_on_fixture_log_matches_python_report_shape() {
    let log = fixture("sample_run.jsonl");
    let report = run_summary(&log);

    assert!(report.contains("=== alchemist run summary ==="));
    assert!(report.contains("events: 6"));
    assert!(report.contains("commands run by worker: 1"));
    assert!(report.contains("$ cargo test --lib"));
    assert!(report.contains("patch/apply events: 1"));
    assert!(report.contains("ERRORS (1):"));
    assert!(report.contains("! gateway timeout"));
    assert!(report.contains("--- final worker message (tail) ---"));
    assert!(report.contains("Done: patched x and ran cargo test."));
    assert!(report.contains(
        "NOTE: this summarizes what the worker CLAIMS. The host must still read"
    ));
}

#[test]
fn fixture_log_has_no_non_json_lines() {
    let log = fixture("sample_run.jsonl");
    let parsed = legion_runtime::wf_port::w2_001::parse_events::iter_events(&log);
    assert_eq!(parsed.len(), 6);
    for line in parsed {
        assert!(matches!(line, ParsedLine::Event(_)));
    }
}

#[test]
fn worker_launch_profile_round_trip() {
    let toml = "profile_name = \"fast\"\nmodel = \"omniroute/qwen3.6-27b\"\n";
    let model = worker_launch::extract_model(toml).expect("model line present");
    assert_eq!(model, "omniroute/qwen3.6-27b");

    assert_eq!(
        worker_launch::profile_file_path("/home/u/.codex", "fast"),
        "/home/u/.codex/fast.config.toml"
    );

    assert_eq!(
        worker_launch::classify_healthz(Some(200)),
        worker_launch::GatewayHealth::Reachable
    );
    assert_eq!(
        worker_launch::classify_healthz(Some(503)),
        worker_launch::GatewayHealth::Unreachable
    );

    assert!(worker_launch::validate_brief("  \n").is_err());
    assert!(worker_launch::validate_brief("fix the bug").is_ok());
}

#[test]
fn stack_status_idempotency_and_text() {
    assert!(stack_status::should_start(false));
    assert!(!stack_status::should_start(true));
    assert_eq!(
        stack_status::status_menu_text(true, false),
        "OmniRoute: up   Citadel: down"
    );
    assert_eq!(
        stack_status::tray_tooltip_text(false, false),
        "Alchemist - OmniRoute down, Citadel down"
    );
}
