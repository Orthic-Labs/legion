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
