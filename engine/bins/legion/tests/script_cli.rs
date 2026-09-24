use std::process::Command;

/// `legion script --list` enumerates every `<skill>/<stem>` Rust port wired
/// into the static dispatch table, so it must include the ports called out
/// in the porting docs as flagship examples (seo/pagespeed_check, the
/// designer detector-adjacent live tooling, etc).
#[test]
fn native_script_list_includes_known_ports() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "--list"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let scripts: Vec<&str> = value["scripts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        scripts.contains(&"seo/pagespeed_check"),
        "expected seo/pagespeed_check in {scripts:?}"
    );
    assert!(
        scripts.contains(&"designer/live-poll"),
        "expected designer/live-poll in {scripts:?}"
    );
    for name in [
        "designer/live",
        "designer/live-complete",
        "designer/live-resume",
        "designer/live-status",
        "designer/live-wrap",
        "designer/live-target",
        "designer/live-accept",
        "designer/live-inject",
        "designer/live-insert",
        "designer/live-server",
        "designer/live-commit-manual-edits",
        "designer/hook-admin",
    ] {
        assert!(scripts.contains(&name), "expected {name} in {scripts:?}");
    }
    assert!(
        scripts.contains(&"seo/indexnow"),
        "expected seo/indexnow in {scripts:?}"
    );
    assert!(
        scripts.contains(&"seo/indexing_notify"),
        "expected seo/indexing_notify in {scripts:?}"
    );
    assert!(
        scripts.contains(&"seo/keyword_planner"),
        "expected seo/keyword_planner in {scripts:?}"
    );
    assert!(
        scripts.contains(&"seo/rank_tracker"),
        "expected seo/rank_tracker in {scripts:?}"
    );
    assert!(
        scripts.contains(&"seo/search_ops"),
        "expected seo/search_ops in {scripts:?}"
    );
    for name in [
        "designer/context",
        "designer/context-signals",
        "designer/critique-storage",
        "designer/detect",
        "designer/detect-csp",
        "designer/palette",
    ] {
        assert!(scripts.contains(&name), "expected {name} in {scripts:?}");
    }
    // Huashu deck/video scripts (skills/designer/engine/huashu/scripts/*),
    // wired to the wf_port r00/w2_007/r02/r03 ports.
    for name in [
        "designer/export-deck-pptx",
        "designer/export-deck-stage-pdf",
        "designer/gen-deck-thumbs",
        "designer/fetch-images",
        "designer/render-video",
        "designer/render-video-seek",
        "designer/narrate-pipeline",
        "designer/tts-doubao",
        "designer/verify",
    ] {
        assert!(scripts.contains(&name), "expected {name} in {scripts:?}");
    }
    // Every table entry has a "<skill>/<stem>" shape.
    for name in &scripts {
        assert!(name.contains('/'), "malformed script name: {name}");
    }
}

/// An unknown script name is a usage error (exit code 4), not a panic.
#[test]
fn native_script_unknown_name_is_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "nope/not-a-real-script"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "{output:?}");
}

/// `legion script seo/seo_closure --help`-shaped smoke: the dispatcher
/// reaches the real port and returns its exit code (not a Legion CLI error),
/// proving the table wiring itself (not just `--list`) works end to end.
#[test]
fn native_script_dispatches_to_the_ported_entry_point() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "seo/seo_closure", "--help"])
        .output()
        .unwrap();
    // Exit code is whatever seo_closure::run's own argv handling returns for
    // `--help` (i.e. it ran the port, not Legion's own usage path at exit 4
    // with the "unknown script" message).
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unknown script"),
        "dispatcher fell through to the unknown-script path: {stderr}"
    );
}

/// `designer/palette` is pure/offline (no cwd, network, or browser
/// dependency), so it's a clean end-to-end smoke: pick a known seed id and
/// check the report names it.
#[test]
fn native_script_designer_palette_picks_known_seed() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "designer/palette", "--id", "seed-200"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("seed-200"),
        "expected seed-200 in output: {stdout}"
    );
}

/// An unknown `--id` exits 2 with a stderr message, matching the source
/// `palette.mjs`'s `process.exit(2)` on an unrecognized seed id.
#[test]
fn native_script_designer_palette_unknown_id_exits_2() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "designer/palette", "--id", "not-a-real-seed"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

/// `designer/detect-csp` and `designer/context-signals` are offline and
/// cwd-only: both should run to completion and print JSON.
#[test]
fn native_script_designer_detect_csp_runs_and_prints_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "designer/detect-csp"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("detect-csp output should be JSON");
}

#[test]
fn native_script_designer_context_signals_runs_and_prints_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "designer/context-signals"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("context-signals output should be JSON");
}

/// Huashu deck-export ports validate required argv before touching a
/// browser, so a missing-flag invocation is a clean offline smoke: it must
/// return the CLI's own usage-error exit code, not launch headless Chrome.
#[test]
fn native_script_designer_export_deck_pptx_missing_args_exits_1() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "designer/export-deck-pptx"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[test]
fn native_script_designer_export_deck_stage_pdf_missing_args_exits_1() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "designer/export-deck-stage-pdf"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[test]
fn native_script_designer_fetch_images_missing_args_exits_1() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "designer/fetch-images"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

/// `designer/critique-storage`'s `slug` subcommand is pure string logic —
/// no filesystem writes — and a clean way to prove the CLI dispatch works.
#[test]
fn native_script_designer_critique_storage_slug() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "designer/critique-storage", "slug", "src/App.tsx"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim().contains("app"), "unexpected slug: {stdout}");
}

#[test]
fn native_script_list_includes_dispatch_and_seo_ports() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "--list"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let scripts: Vec<&str> = value["scripts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for name in [
        "dispatch/validate-dispatch",
        "tasklist/validate-tasklist",
        "seo/google_report",
    ] {
        assert!(scripts.contains(&name), "expected {name} in {scripts:?}");
    }
}

/// Missing positional `dispatch` argument is an argparse-style usage error
/// (exit code 2), mirroring `validate-dispatch.py`'s own `argparse` failure.
#[test]
fn native_script_dispatch_validate_dispatch_missing_args_exits_2() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "dispatch/validate-dispatch"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

/// A dispatch file that does not exist on disk fails the `is_file()`
/// pre-check with exit code 2 and the same `FAIL: dispatch file not found`
/// message the Python `main()` prints.
#[test]
fn native_script_dispatch_validate_dispatch_missing_file_exits_2() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "script",
            "dispatch/validate-dispatch",
            "/nonexistent/does-not-exist.md",
            "--template-self-check",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("FAIL: dispatch file not found"), "{stderr}");
}

/// Missing positional `packets` argument is an argparse-style usage error
/// (exit code 2), mirroring `validate-tasklist.py`'s own `argparse` failure.
#[test]
fn native_script_tasklist_validate_tasklist_missing_args_exits_2() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "tasklist/validate-tasklist"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

/// A packet file that does not exist fails the per-packet pre-check with
/// exit code 2, run entirely in-process (no Python subprocess spawned).
#[test]
fn native_script_tasklist_validate_tasklist_missing_packet_exits_2() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["script", "tasklist/validate-tasklist", "/nonexistent/packet.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("FAIL: packet file not found"), "{stderr}");
}

/// `seo/google_report` with a `--data` file that does not exist fails with
/// the same "Error reading data file" message `google_report.py` prints.
#[test]
fn native_script_seo_google_report_missing_data_file_exits_1() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "script",
            "seo/google_report",
            "--type",
            "cwv-audit",
            "--domain",
            "example.com",
            "--format",
            "html",
            "--data",
            "/nonexistent/report-data.json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error reading data file"), "{stderr}");
}
