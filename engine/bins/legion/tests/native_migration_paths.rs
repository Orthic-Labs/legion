//! Focused executable coverage for Node CLI cases being migrated to native Rust.
use serde_json::Value;
use std::{path::PathBuf, process::{Command, Output}, time::{SystemTime, UNIX_EPOCH}};

/// Parallel tests must never share a scratch root.
static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "legion-migration-paths-{}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("home")).unwrap();
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
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!("{error}; stderr={}", String::from_utf8_lossy(&output.stderr))
    })
}

#[test]
fn init_write_creates_config_and_ignore_entries_idempotently() {
    let fixture = Fixture::new();
    let first = fixture.run(&["init", ".", "--write"]);
    assert_eq!(first.status.code(), Some(0), "{}", String::from_utf8_lossy(&first.stderr));
    assert_eq!(json(&first)["kind"], "legion-init-preview");
    let config = fixture.0.join("legion.config.json");
    let ignore = fixture.0.join(".gitignore");
    assert!(config.is_file());
    assert!(std::fs::read_to_string(&ignore).unwrap().contains(".legion/"));
    let config_before = std::fs::read(&config).unwrap();
    let ignore_before = std::fs::read(&ignore).unwrap();
    let second = fixture.run(&["init", ".", "--write"]);
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(std::fs::read(config).unwrap(), config_before);
    assert_eq!(std::fs::read(ignore).unwrap(), ignore_before);
}

#[test]
fn bind_write_projects_codex_harness_and_is_idempotent() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.0.join(".codex")).unwrap();
    std::fs::write(fixture.0.join(".codex/config.toml"), "[user]\nkeep = true\n\n# >>> legion:managed-block v1 >>>\n[mcp_servers.legion]\ncommand = \"legion\"\n# <<< legion:managed-block v1 <<<\n").unwrap();
    let output = fixture.run(&["bind", "--write", "."]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let result = json(&output);
    assert_eq!(result["kind"], "legion-bind-result");
    assert_eq!(result["dryRun"], false);
    assert!(fixture.0.join(".codex/agents/sage.toml").is_file());
    assert!(fixture.0.join(".codex/config.toml").is_file());
    assert!(fixture.0.join(".legion/binding.json").is_file());
    let config = std::fs::read_to_string(fixture.0.join(".codex/config.toml")).unwrap();
    assert!(config.contains("[user]"));
    assert!(config.contains("keep = true"));
    assert!(!config.contains("[mcp_servers.legion]"));
    let binding = std::fs::read(&fixture.0.join(".legion/binding.json")).unwrap();
    let second = fixture.run(&["bind", "--write", "--harness", "codex", "."]);
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(std::fs::read(&fixture.0.join(".legion/binding.json")).unwrap(), binding);
}

#[test]
fn verify_invalid_facts_is_usage_error_without_rewriting_artifact() {
    let fixture = Fixture::new();
    let path = fixture.0.join("facts.json");
    std::fs::write(&path, b"{invalid\n").unwrap();
    let before = std::fs::read(&path).unwrap();
    let output = fixture.run(&["verify", "facts.json"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid verify facts artifact"));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn verify_reports_content_integrity_mismatch_as_failed_result() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("facts.json"), br#"{"kind":"wrong-facts"}
"#).unwrap();
    std::fs::write(fixture.0.join("plan.json"), br#"{"kind":"wrong-plan","schemaVersion":99}
"#).unwrap();
    let output = fixture.run(&["verify", "."]);
    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let result = json(&output);
    assert_eq!(result["kind"], "legion-verify");
    assert_eq!(result["valid"], false);
    assert!(result["contentErrors"].as_array().unwrap().len() >= 2);
}

#[test]
fn completion_without_authenticated_key_material_is_incomplete() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("outcome.json"), b"{}\n").unwrap();
    let output = fixture.run(&["completion", "claim", "--file", "outcome.json", "--session", "migration-session"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ARC_AUTH_KEY_UNAVAILABLE"),
        "{stderr}"
    );
}

#[test]
fn state_verification_recovers_after_reverting_mutation() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.0.join("surface")).unwrap();
    let path = fixture.0.join("surface/value.txt");
    std::fs::write(&path, b"stable\n").unwrap();
    let snapshot = fixture.run(&["state", "snapshot", "--path", "surface", "--out", "before.json"]);
    assert_eq!(snapshot.status.code(), Some(0));
    std::fs::write(&path, b"changed\n").unwrap();
    let breached = fixture.run(&["state", "verify", "--snapshot", "before.json"]);
    assert_eq!(breached.status.code(), Some(1));
    assert_eq!(json(&breached)["verdict"], "breach");
    std::fs::write(&path, b"stable\n").unwrap();
    let recovered = fixture.run(&["state", "verify", "--snapshot", "before.json"]);
    assert_eq!(recovered.status.code(), Some(0));
    assert_eq!(json(&recovered)["verdict"], "clean");
}
