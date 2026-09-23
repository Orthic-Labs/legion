//! Executable coverage for product CLI behavior that does not require an
//! installed composition or packaged assets.
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "legion-product-parity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("home")).unwrap();
        Self(root)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_legion"));
        command
            .args(args)
            .current_dir(&self.0)
            .env("HOME", self.0.join("home"))
            .env("USERPROFILE", self.0.join("home"))
            .env("LOCALAPPDATA", self.0.join("home/local"))
            .env("APPDATA", self.0.join("home/roaming"))
            .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
            .env_remove("LEGION_M1_CONFIG")
            .env_remove("ARCANE_KEY_DIR")
            .env_remove("AUDIT_NETWORK_GUARD")
            .env_remove("AUDIT_PLAN_SIGNING_KEY");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("native CLI executes")
    }

    fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = self.command(args);
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("native CLI executes")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn output_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn root_help_matches_node_usage_surface() {
    let fixture = Fixture::new();
    let output = fixture.run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("legion <command>"));
    assert!(stdout.contains("Commands:"));
    assert!(output.stderr.is_empty());
}

#[test]
fn report_json_and_markdown_render_without_installed_assets() {
    let fixture = Fixture::new();
    let report = json!({
        "schema_version": 1,
        "report_id": "report-product-parity",
        "status": "clean",
        "findings": [],
        "gaps": [],
        "claims": {},
        "targets": []
    });
    std::fs::write(
        fixture.0.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();

    let json_output = fixture.run(&["report", "report.json", "--format", "json"]);
    assert_eq!(json_output.status.code(), Some(0));
    let rendered = output_json(&json_output);
    assert_eq!(rendered["report_id"], "report-product-parity");
    assert_eq!(rendered["status"], "clean");

    let markdown_output = fixture.run(&[
        "report",
        "report.json",
        "--format",
        "markdown",
        "--out",
        "rendered.md",
    ]);
    assert_eq!(markdown_output.status.code(), Some(0));
    assert!(markdown_output.stdout.is_empty());
    let markdown = std::fs::read_to_string(fixture.0.join("rendered.md")).unwrap();
    assert!(markdown.starts_with("# Legion Report\n"));
    assert!(markdown.contains("report-product-parity"));
}

#[test]
fn report_invalid_input_is_a_usage_error_without_output() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("report.json"), b"{invalid\n").unwrap();
    let output = fixture.run(&["report", "report.json", "--format", "json"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid report"));
}

#[test]
fn bind_does_not_auto_select_claude_code_and_explicit_request_is_retired() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.0.join(".claude")).unwrap();

    let checked = fixture.run(&["bind", "--check", "."]);
    assert_eq!(checked.status.code(), Some(0));
    let checked_json = output_json(&checked);
    assert_eq!(checked_json["kind"], "legion-bind-preview");
    assert_eq!(checked_json["dryRun"], true);
    assert!(!checked_json["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .any(|harness| harness["name"] == "claude-code"));

    let retired = fixture.run(&["bind", "--harness", "claude-code", "."]);
    assert_eq!(retired.status.code(), Some(0));
    let claude = output_json(&retired)["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|harness| harness["name"] == "claude-code")
        .cloned()
        .expect("explicit Claude Code harness");
    assert_eq!(claude["retired"], true);
    assert!(claude["wouldWrite"].as_array().unwrap().is_empty());
    assert!(!fixture.0.join(".legion").exists());
}

#[test]
fn doctor_json_preserves_machine_shape_and_host_capability_flags() {
    let fixture = Fixture::new();
    let output = fixture.run_with_env(
        &["doctor", ".", "--json"],
        &[("AUDIT_NETWORK_GUARD", "active"), ("AUDIT_PLAN_SIGNING_KEY", "fixture-key")],
    );
    assert_eq!(output.status.code(), Some(0));
    let report = output_json(&output);
    assert_eq!(report["kind"], "legion-doctor");
    assert_eq!(report["cleanClaimPossible"], false);
    assert_eq!(report["hostCapabilities"]["networkSandbox"], true);
    assert_eq!(report["hostCapabilities"]["signing"], true);
    assert!(report.get("text").is_none());
    assert!(report.get("json").is_none());
}

#[test]
fn doctor_reports_missing_binding_and_legacy_mcp_migrations() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.0.join(".mcp.json"),
        serde_json::to_vec(&json!({
            "mcpServers": {"seer": {"command": "python3", "args": ["-m", "legion_kernel.adapters.mcp_server"]}}
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::create_dir(fixture.0.join(".codex")).unwrap();
    std::fs::write(
        fixture.0.join(".codex/config.toml"),
        b"[mcp_servers.seer]\ncommand = \"python3\"\nargs = [\"-m\", \"legion_kernel.adapters.mcp_server\"]\n",
    )
    .unwrap();

    let root = fixture.0.to_string_lossy().into_owned();
    let output = fixture.run(&["doctor", &root, "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let report = output_json(&output);
    assert_eq!(report["binding"]["receiptPresent"], false);
    assert_eq!(report["naming"]["bindings"]["claudeCode"]["status"], "legacy-present");
    assert_eq!(report["naming"]["bindings"]["codex"]["status"], "legacy-present");
    assert!(report["gaps"].as_array().unwrap().iter().any(|gap| {
        gap["kind"] == "naming-migration-pending"
    }));
}
