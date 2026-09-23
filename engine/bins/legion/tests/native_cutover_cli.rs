//! Executable regression tests for the observable Node-to-native CLI contract.
//! Every invocation uses its own temporary working directory and user-state roots.
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "legion-cutover-cli-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("home")).unwrap();
        // The child process resolves its working directory via getcwd(2)
        // after chdir, which returns the real path (symlinks resolved, e.g.
        // macOS's /var -> /private/var). Canonicalize here so paths this
        // fixture computes match what the product actually reports.
        // Unix only: on Windows canonicalize adds a `\\?\` prefix the CLI never prints.
        #[cfg(unix)]
        let root = std::fs::canonicalize(&root).unwrap();
        Self(root)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_legion"))
            .args(args)
            .current_dir(&self.0)
            .env("HOME", self.0.join("home"))
            .env("USERPROFILE", self.0.join("home"))
            .env("LOCALAPPDATA", self.0.join("home/local"))
            .env("APPDATA", self.0.join("home/roaming"))
            .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
            .env_remove("LEGION_M1_CONFIG")
            .env_remove("ARCANE_KEY_DIR")
            .output()
            .expect("native CLI executes")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn audit_help_preserves_node_usage_error_contract() {
    let fixture = Fixture::new();
    let output = fixture.run(&["audit", "--help"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Unknown option '--help'. To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- \"--help\"\n"
    );
}

#[test]
fn no_command_keeps_stdout_usage_and_usage_exit() {
    let fixture = Fixture::new();
    for args in [vec![], vec!["--json"]] {
        let output = fixture.run(&args);
        assert_eq!(output.status.code(), Some(4));
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: legion"));
    }
}

#[test]
fn version_and_unknown_command_keep_their_channels() {
    let fixture = Fixture::new();
    for args in [vec!["--version"], vec!["--json", "--version"]] {
        let output = fixture.run(&args);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            env!("CARGO_PKG_VERSION")
        );
        assert!(output.stderr.is_empty());
    }
    let output = fixture.run(&["frobnicate"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "unknown command: frobnicate\n"
    );
}

#[test]
fn state_snapshot_deduplicates_file_count_and_accepts_equals_options() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.0.join("surface")).unwrap();
    std::fs::write(fixture.0.join("surface/one.txt"), "one\n").unwrap();
    let snapshot = fixture.run(&[
        "state",
        "snapshot",
        "--path=surface",
        "--path",
        "./surface",
        "--out=before.json",
    ]);
    assert_eq!(
        snapshot.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&snapshot.stderr)
    );
    assert_eq!(json(&snapshot)["files"], 1);
    assert_eq!(json(&snapshot)["surfaces"], 2);
    let stored: Value =
        serde_json::from_slice(&std::fs::read(fixture.0.join("before.json")).unwrap()).unwrap();
    assert_eq!(stored["surfaces"].as_object().unwrap().len(), 1);
    let verify = fixture.run(&["state", "verify", "--snapshot=before.json"]);
    assert_eq!(verify.status.code(), Some(0));
    assert!(verify.stderr.is_empty());
    assert_eq!(json(&verify)["verdict"], "clean");
}

#[test]
fn state_breach_has_json_deltas_and_stderr_diagnostics() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.0.join("surface")).unwrap();
    std::fs::write(fixture.0.join("surface/modified.txt"), "before").unwrap();
    std::fs::write(fixture.0.join("surface/deleted.txt"), "before").unwrap();
    let snapshot = fixture.run(&[
        "state",
        "snapshot",
        "--path",
        "surface",
        "--out",
        "before.json",
    ]);
    assert_eq!(snapshot.status.code(), Some(0));
    std::fs::write(fixture.0.join("surface/modified.txt"), "after").unwrap();
    std::fs::remove_file(fixture.0.join("surface/deleted.txt")).unwrap();
    std::fs::write(fixture.0.join("surface/created.txt"), "after").unwrap();
    let output = fixture.run(&["state", "verify", "--snapshot", "before.json"]);
    assert_eq!(output.status.code(), Some(1));
    let result = json(&output);
    assert_eq!(result["verdict"], "breach");
    assert_eq!(result["deltas"].as_array().unwrap().len(), 3);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr
        .starts_with("STATE BOUNDARY BREACH: 3 delta(s) under snapshotted production state\n"));
    for (path, change) in [
        ("modified.txt", "modified"),
        ("deleted.txt", "deleted"),
        ("created.txt", "created"),
    ] {
        assert!(result["deltas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|delta| delta["path"] == path && delta["change"] == change));
        assert!(stderr.contains(&format!(" :: {path}\n")));
    }
}

#[test]
fn absent_surface_appearing_later_is_a_breach() {
    let fixture = Fixture::new();
    assert!(!fixture.0.join("absent").exists());
    let snapshot = fixture.run(&[
        "state",
        "snapshot",
        "--path",
        "absent",
        "--out",
        "before.json",
    ]);
    assert_eq!(snapshot.status.code(), Some(0));
    assert_eq!(json(&snapshot)["files"], 0);
    std::fs::write(fixture.0.join("absent"), "new state").unwrap();
    let output = fixture.run(&["state", "verify", "--snapshot", "before.json"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(json(&output)["deltas"][0]["change"], "created");
}

#[test]
fn invalid_snapshot_fails_without_mutating_the_input() {
    let fixture = Fixture::new();
    let path = fixture.0.join("invalid.json");
    std::fs::write(&path, r#"{"schema":"wrong","surfaces":{}}"#).unwrap();
    let before = std::fs::read(&path).unwrap();
    let output = fixture.run(&["state", "verify", "--snapshot=invalid.json"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("snapshot schema must be"));
    assert_eq!(std::fs::read(Path::new(&path)).unwrap(), before);
}

#[test]
fn empty_or_missing_snapshot_output_cannot_create_an_option_named_file() {
    let fixture = Fixture::new();
    for args in [
        vec!["state", "snapshot", "--path=absent", "--out="],
        vec![
            "state",
            "snapshot",
            "--path=absent",
            "--out",
            "--unexpected",
        ],
    ] {
        let output = fixture.run(&args);
        assert_eq!(
            output.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }
    assert!(!fixture.0.join("--unexpected").exists());
}

#[test]
fn rules_compile_preserves_policy_json_order_and_emits_compact_receipt() {
    let fixture = Fixture::new();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/lib/guard/compat/rules/arcane-policy-v1.rules");
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/lib/guard/compat/policy/arcane-policy-v1.json");
    let output_path = fixture.0.join("nested").join("compiled.json");

    let preview = fixture.run(&[
        "rules",
        "compile",
        source.to_str().unwrap(),
        "--base",
        base.to_str().unwrap(),
    ]);
    assert_eq!(
        preview.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview_text = String::from_utf8_lossy(&preview.stdout);
    assert!(preview_text
        .starts_with("{\n  \"schemaVersion\": 1,\n  \"kind\": \"arcane-policy-bundle\""));
    assert!(preview_text.ends_with("\n"));
    assert_eq!(
        serde_json::from_slice::<Value>(&preview.stdout).unwrap()["effectRules"]
            .as_array()
            .unwrap()
            .len(),
        12
    );

    let written = fixture.run(&[
        "rules",
        "compile",
        source.to_str().unwrap(),
        "--base",
        base.to_str().unwrap(),
        "--out",
        "nested/compiled.json",
    ]);
    assert_eq!(
        written.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&written.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&written.stdout),
        format!(
            "{{\"output\":\"{}\"}}\n",
            output_path.display().to_string().replace('\\', "\\\\")
        )
    );
    assert_eq!(std::fs::read(&output_path).unwrap(), preview.stdout);
    assert!(!fixture.0.join("nested/compiled.json.tmp").exists());
}

#[test]
fn rules_compile_rejects_noncanonical_grammar_with_usage_exit() {
    let fixture = Fixture::new();
    let source = fixture.0.join("bad.rules");
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/lib/guard/compat/policy/arcane-policy-v1.json");
    std::fs::write(
        &source,
        "allow FILE_WRITE approval=none trust=other enforcement=strong\n",
    )
    .unwrap();
    let output = fixture.run(&[
        "rules",
        "compile",
        "bad.rules",
        "--base",
        base.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "line 1: invalid rule\n"
    );
}
