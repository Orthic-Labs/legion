//! Rust port of `scripts/release/windows/qualify-installed.mjs`: runs a
//! finalized Windows installer through its qualification stages
//! (install, version, same-version-upgrade, legacy junction migration, plugin-root transport,
//! staged-validation-failure, mirror-sync-failure, forced-refresh-failure,
//! stalled-child, repair, status, doctor, uninstall) in an isolated
//! `LOCALAPPDATA`/`USERPROFILE`, and writes either `qualification.json` or,
//! on failure, `qualification-failure.json` with captured evidence — Phase A
//! item 9: a failed run must leave a readable receipt instead of silently
//! deleting its workspace. Ported 1:1, including the full per-stage
//! `commandEvidence` trail and the `setupPayload` structural validation of
//! repair/status JSON responses. Native Claude/Codex CLI installation is
//! reported separately because the isolated profile does not provision them.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::paths::{
    is_revision_hex, is_stable_semver, sha256_file, CommandOptions, CommandRunner, ReleaseResult,
};
use crate::process_boundary::{command_diagnostic, command_evidence};

fn fail(message: impl Into<String>) -> String {
    format!("windows-installed-qualification: {}", message.into())
}

/// Mirrors `windowsEnvironment`: replaces keys of `base` with `overrides`,
/// matching case-insensitively (Windows env vars are case-insensitive; a
/// stray `Path`/`LocalAppData` in the real environment must not survive
/// alongside an isolated `PATH`/`LOCALAPPDATA`).
pub fn windows_environment(
    base: &HashMap<String, String>,
    overrides: &HashMap<String, String>,
) -> HashMap<String, String> {
    let replaced: std::collections::HashSet<String> =
        overrides.keys().map(|k| k.to_lowercase()).collect();
    let mut out: HashMap<String, String> = base
        .iter()
        .filter(|(k, _)| !replaced.contains(&k.to_lowercase()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, v) in overrides {
        out.insert(k.clone(), v.clone());
    }
    out
}

fn text_tail(path: &Path, max_bytes: usize) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let value = fs::read_to_string(path).ok()?;
    if value.len() <= max_bytes {
        Some(value)
    } else {
        let mut start = value.len() - max_bytes;
        while !value.is_char_boundary(start) {
            start += 1;
        }
        Some(value[start..].to_string())
    }
}

fn qualification_failure_diagnostics(install_log: &Path, activation_events: &Path) -> String {
    let mut sections = Vec::new();
    for (label, path) in [
        ("Inno setup log", install_log),
        ("Legion activation events", activation_events),
    ] {
        if let Some(contents) = text_tail(path, 12 * 1024) {
            if !contents.trim().is_empty() {
                sections.push(format!(
                    "--- {label} (last 12 KiB) ---\n{}",
                    contents.trim()
                ));
            }
        }
    }
    if sections.is_empty() {
        String::new()
    } else {
        format!("\nProduct installer diagnostics:\n{}", sections.join("\n"))
    }
}

fn finalization(path: &Path, version: &str, source_revision: &str) -> ReleaseResult<Value> {
    let text = fs::read_to_string(path).map_err(|e| {
        fail(format!(
            "Windows finalization manifest could not be read: {e}"
        ))
    })?;
    let value: Value = serde_json::from_str(&text).map_err(|e| {
        fail(format!(
            "Windows finalization manifest is invalid JSON: {e}"
        ))
    })?;
    let ok = value.get("schemaVersion").and_then(Value::as_i64) == Some(1)
        && value.get("kind").and_then(Value::as_str) == Some("legion-installer-finalization")
        && value.get("product").and_then(Value::as_str) == Some("legion")
        && value.get("platform").and_then(Value::as_str) == Some("windows")
        && value.get("version").and_then(Value::as_str) == Some(version)
        && value
            .get("sourceRevision")
            .and_then(Value::as_str)
            .map(|s| s.to_lowercase())
            == Some(source_revision.to_string())
        && value.get("assets").and_then(Value::as_array).is_some();
    if !ok {
        return Err(fail("Windows finalization manifest identity is invalid"));
    }
    let installers = value
        .get("assets")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter(|a| a.get("role").and_then(Value::as_str) == Some("installer"))
        .count();
    if installers != 1 {
        return Err(fail(
            "Windows finalization must contain exactly one installer",
        ));
    }
    Ok(value)
}

#[derive(Default)]
pub struct QualifyInstalledWindowsInput {
    pub setup: Option<PathBuf>,
    pub output_root: Option<PathBuf>,
    pub finalization_path: Option<PathBuf>,
    pub source_revision: String,
    pub version: String,
    pub platform_is_windows: bool,
}

pub fn qualify_installed_windows(
    runner: CommandRunner,
    input: QualifyInstalledWindowsInput,
) -> ReleaseResult<Value> {
    if !input.platform_is_windows {
        return Err(fail("qualification requires Windows"));
    }
    if !is_stable_semver(&input.version) {
        return Err(fail("stable version is required"));
    }
    if !is_revision_hex(&input.source_revision) {
        return Err(fail("source revision is invalid"));
    }
    let revision = input.source_revision.to_lowercase();
    let installer = input
        .setup
        .clone()
        .ok_or_else(|| fail("--setup is required"))?;
    if !installer.is_file() {
        return Err(fail(format!(
            "setup EXE is missing or unsafe: {}",
            installer.display()
        )));
    }
    if !installer.to_string_lossy().to_lowercase().ends_with(".exe") {
        return Err(fail("setup must be an EXE"));
    }
    let output = input
        .output_root
        .clone()
        .ok_or_else(|| fail("--output-root is required"))?;
    fs::create_dir_all(&output).map_err(|e| fail(e.to_string()))?;
    if output.join("qualification.json").exists() {
        return Err(fail("qualification evidence already exists"));
    }
    let finalization_file = input
        .finalization_path
        .clone()
        .ok_or_else(|| fail("--finalization is required"))?;
    let manifest = finalization(&finalization_file, &input.version, &revision)?;
    let development_install = manifest.get("profile").and_then(Value::as_str)
        == Some("internal-unsigned")
        && manifest
            .get("signing")
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            == Some("unsigned");
    let finalization_sha256 = sha256_file(&finalization_file)?;

    let workspace = std::env::temp_dir().join(format!(
        "legion-installed-qualification-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    fs::create_dir_all(&workspace).map_err(|e| fail(e.to_string()))?;
    let workspace = canonical_qualification_workspace(&workspace)?;
    let result = qualify_inner(
        runner,
        &installer,
        &output,
        &input.version,
        &revision,
        &finalization_sha256,
        &workspace,
        development_install,
    );
    let _ = fs::remove_dir_all(&workspace);
    result
}

fn canonical_qualification_workspace(path: &Path) -> ReleaseResult<PathBuf> {
    // Windows temp_dir() can contain an 8.3 alias (RUNNER~1), while Inno's
    // PowerShell activation records the long spelling (runneradmin). Resolve
    // our existing workspace before deriving paths so strict receipt & runtime
    // assertions retain one spelling; do not relax them to accept other roots.
    fs::canonicalize(path)
        .map(crate::windows_release_support::strip_verbatim)
        .map_err(|e| {
            fail(format!(
                "qualification workspace could not be resolved: {e}"
            ))
        })
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

struct StepOutcome {
    stdout: String,
    #[allow(dead_code)]
    stderr: String,
    evidence: Value,
}

fn execute(
    runner: CommandRunner,
    executable: &Path,
    args: &[String],
    options: &CommandOptions,
    label: &str,
) -> ReleaseResult<StepOutcome> {
    let result = runner(&executable.to_string_lossy(), args, options);
    if result.error_message.is_some() || result.status != Some(0) {
        return Err(fail(format!(
            "{label} failed: {}",
            command_diagnostic(&result)
        )));
    }
    let evidence = serde_json::to_value(command_evidence(&result)).unwrap();
    Ok(StepOutcome {
        stdout: result.stdout.unwrap_or_default().trim().to_string(),
        stderr: result.stderr.unwrap_or_default().trim().to_string(),
        evidence,
    })
}

fn execute_expected_failure(
    runner: CommandRunner,
    executable: &Path,
    args: &[String],
    options: &CommandOptions,
    label: &str,
) -> ReleaseResult<StepOutcome> {
    let result = runner(&executable.to_string_lossy(), args, options);
    if result.error_message.is_some() {
        return Err(fail(format!(
            "{label} did not return control: {}",
            command_diagnostic(&result)
        )));
    }
    if result.status == Some(0) {
        return Err(fail(format!("{label} falsely reported success")));
    }
    let evidence = serde_json::to_value(command_evidence(&result)).unwrap();
    Ok(StepOutcome {
        stdout: result.stdout.unwrap_or_default().trim().to_string(),
        stderr: result.stderr.unwrap_or_default().trim().to_string(),
        evidence,
    })
}

/// Sends the canonical probe set through the installed executable's actual
/// plugin-root transport.  Installer qualification must catch strict package
/// validation failures that `--version` and setup repair cannot observe.
fn probe_plugin_root_transport(
    executable: &Path,
    plugin_root: &Path,
    options: &CommandOptions,
) -> ReleaseResult<StepOutcome> {
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"legion_apple","arguments":{"operation":"catalog"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"legion_apple","arguments":{"operation":"app-store","arguments":{"action":"apps","execute":false}}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"legion_apple","arguments":{"operation":"simulator.list","arguments":{"execute":false}}}}),
    ];
    let input = requests
        .iter()
        .map(|request| format!("{request}\n"))
        .collect::<String>();
    let mut command = Command::new(executable);
    command.args(["serve", "--stdio", "--plugin-root"]);
    command.arg(plugin_root);
    if let Some(cwd) = &options.cwd {
        command.current_dir(cwd);
    }
    if let Some(env) = &options.env {
        command.env_clear();
        command.envs(env);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| fail(format!("plugin-root MCP spawn failed: {e}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| fail("plugin-root MCP stdin missing"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail("plugin-root MCP stdout missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| fail("plugin-root MCP stderr missing"))?;
    let out_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let err_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let write_error = stdin.write_all(input.as_bytes()).err();
    drop(stdin);
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if started.elapsed() < Duration::from_secs(30) => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Ok(None) => {
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|e| fail(format!("plugin-root MCP wait failed: {e}")))?;
                break (status, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail(format!("plugin-root MCP poll failed: {error}")));
            }
        }
    };
    let stdout = out_reader
        .join()
        .map_err(|_| fail("plugin-root MCP stdout reader failed"))?
        .map_err(|e| fail(format!("plugin-root MCP stdout read failed: {e}")))?;
    let stderr = err_reader
        .join()
        .map_err(|_| fail("plugin-root MCP stderr reader failed"))?
        .map_err(|e| fail(format!("plugin-root MCP stderr read failed: {e}")))?;
    let stdout_text = String::from_utf8_lossy(&stdout).to_string();
    let stderr_text = String::from_utf8_lossy(&stderr).to_string();
    if timed_out
        || !status.success()
        || write_error.is_some()
        || stdout.len() > 2 * 1024 * 1024
        || stderr.len() > 2 * 1024 * 1024
    {
        return Err(fail(format!("plugin-root MCP failed: status={status}; timeout={timed_out}; write={write_error:?}; stderr={}", stderr_text.trim())));
    }
    let responses: Vec<Value> = stdout_text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|e| fail(format!("plugin-root MCP response JSON is invalid: {e}")))?;
    if responses.len() != requests.len()
        || responses.iter().enumerate().any(|(index, response)| {
            response.get("id").and_then(Value::as_u64) != Some(index as u64 + 1)
                || response.get("error").is_some()
                || response.get("result").is_none()
                || response.pointer("/result/isError").and_then(Value::as_bool) == Some(true)
        })
    {
        return Err(fail(format!(
            "plugin-root MCP returned incomplete/error responses: {responses:?}"
        )));
    }
    let names: std::collections::BTreeSet<_> = responses[1]
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("plugin-root MCP tools/list missing tools"))?
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect();
    let expected: std::collections::BTreeSet<_> =
        ["legion_m1_status", "legion_m1_invoke", "legion_apple"]
            .into_iter()
            .collect();
    if names != expected {
        return Err(fail(format!(
            "plugin-root MCP canonical tool list mismatch: {names:?}"
        )));
    }
    let summary = json!({"mode":"plugin-root", "responses":responses.len(), "tools":names.into_iter().collect::<Vec<_>>()});
    Ok(StepOutcome {
        stdout: summary.to_string(),
        stderr: stderr_text.trim().to_string(),
        evidence: json!({"status":0, "stdout":summary, "stderr":stderr_text.trim()}),
    })
}

/// Mirrors `setupPayload`: parses a repair/status JSON response, asserts
/// complete installed activation bound to the stable-current executable,
/// structural client activation for `requiredClients`, and current-state
/// projections for `requiredProjections`; returns the same trimmed summary
/// shape the JS returns for embedding into the final evidence bundle.
fn setup_payload(
    run: &StepOutcome,
    kind: &str,
    executable: &Path,
    label: &str,
    required_clients: &[&str],
    required_projections: &[&str],
) -> ReleaseResult<Value> {
    let value: Value = serde_json::from_str(&run.stdout)
        .map_err(|e| fail(format!("{label} did not return JSON: {e}")))?;
    if value.get("kind").and_then(Value::as_str) != Some(kind)
        || value.get("status").and_then(Value::as_str) != Some("complete")
        || value.get("origin").and_then(Value::as_str) != Some("installed")
    {
        return Err(fail(format!(
            "{label} did not report complete installed activation"
        )));
    }
    let value_executable = value
        .get("executable")
        .and_then(Value::as_str)
        .unwrap_or("");
    let executable_matches = Path::new(value_executable) == executable
        || PathBuf::from(value_executable).file_name() == executable.file_name();
    if !executable_matches || value.get("stableCurrent") != Some(&Value::Bool(true)) {
        return Err(fail(format!(
            "{label} did not bind stable current executable"
        )));
    }
    let clients = if kind == "legion-setup-execution" {
        value.get("execution").and_then(|e| e.get("clients"))
    } else {
        value.get("clients")
    };
    let clients_array = clients
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for client_id in required_clients {
        let client = clients_array.iter().find(|item| {
            let id = item
                .get("clientId")
                .and_then(Value::as_str)
                .or_else(|| item.get("client_id").and_then(Value::as_str));
            id == Some(*client_id)
        });
        let ok = client
            .map(|c| {
                c.get("installed") == Some(&Value::Bool(true))
                    && c.get("fidelity").and_then(Value::as_str) == Some("Full")
            })
            .unwrap_or(false);
        if !ok {
            return Err(fail(format!(
                "{label} did not structurally activate {client_id}"
            )));
        }
    }
    let projections = value
        .get("liveIdentity")
        .and_then(|l| l.get("projections"))
        .cloned()
        .unwrap_or(json!({}));
    for projection in required_projections {
        if projections
            .get(projection)
            .and_then(|p| p.get("state"))
            .and_then(Value::as_str)
            != Some("current")
        {
            return Err(fail(format!("{label} did not verify current {projection}")));
        }
    }
    let clients_out: Vec<Value> = clients_array
        .iter()
        .map(|c| {
            let id = c.get("clientId").and_then(Value::as_str).or_else(|| c.get("client_id").and_then(Value::as_str));
            json!({ "clientId": id, "installed": c.get("installed"), "fidelity": c.get("fidelity") })
        })
        .collect();
    let projections_out: Value = projections
        .as_object()
        .map(|obj| {
            Value::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.get("state").cloned().unwrap_or(Value::Null)))
                    .collect(),
            )
        })
        .unwrap_or(json!({}));
    let native_marketplaces = json!({
        "claude": projections.get("claudeMarketplace").and_then(|p| p.get("state")),
        "codex": projections.get("codexMarketplace").and_then(|p| p.get("state")),
    });
    Ok(json!({
        "kind": value.get("kind"),
        "status": value.get("status"),
        "origin": value.get("origin"),
        "executable": value.get("executable"),
        "stableCurrent": value.get("stableCurrent"),
        "clients": clients_out,
        "projections": projections_out,
        "nativeMarketplaces": native_marketplaces,
        "authenticatedLiveQualification": value.get("authenticatedLiveQualification").and_then(|a| a.get("status")).cloned().unwrap_or(Value::Null),
    }))
}

fn validate_installed_native_marketplaces(install_root: &Path) -> ReleaseResult<Value> {
    let release_path = install_root.join("share/legion/release.json");
    let text = fs::read_to_string(&release_path)
        .map_err(|error| fail(format!("installed release metadata unavailable: {error}")))?;
    let metadata: Value = serde_json::from_str(&text).map_err(|error| {
        fail(format!(
            "installed release metadata is invalid JSON: {error}"
        ))
    })?;
    super::windows_finalize_installer::validate_native_marketplace_assets(install_root, &metadata)
        .map_err(fail)
}

fn native_clients_unobserved(
    profile: &Path,
    repair: &Value,
    status: &Value,
) -> ReleaseResult<Value> {
    let claude_profile = profile.join(".claude").is_dir();
    let codex_profile = profile.join(".codex").is_dir();
    if claude_profile || codex_profile {
        return Err(fail(
            "isolated qualification unexpectedly contains a native client profile",
        ));
    }
    let empty_states = json!({});
    let repair_states = repair.get("nativeMarketplaces").unwrap_or(&empty_states);
    let status_states = status.get("nativeMarketplaces").unwrap_or(&empty_states);
    let mut clients = serde_json::Map::new();
    for client in ["claude", "codex"] {
        let repair_state = repair_states.get(client).and_then(Value::as_str);
        let status_state = status_states.get(client).and_then(Value::as_str);
        for (operation, state) in [("repair", repair_state), ("status", status_state)] {
            if !matches!(state, Some("not_selected" | "client_unavailable")) {
                return Err(fail(format!(
                    "isolated {client} marketplace {operation} did not report an unobserved client state"
                )));
            }
        }
        clients.insert(
            client.into(),
            json!({ "repair": repair_state, "status": status_state }),
        );
    }
    Ok(json!({ "status": "not-provisioned", "clients": clients }))
}

/// Mirrors `disappears`: polls until `path` no longer exists or `timeout` elapses.
fn disappears(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    !path.exists()
}

/// Installed-tree inventory captured before cleanup. Stable-pointer defects
/// are invisible without link types and resolved targets, and the workspace
/// that holds them is deleted right after this qualification run.
fn inventory(root: &Path, depth: u32) -> Value {
    if !root.exists() || depth > 3 {
        return Value::Array(vec![]);
    }
    let Ok(entries) = fs::read_dir(root) else {
        return Value::Array(vec![]);
    };
    let mut out = vec![];
    for entry in entries.flatten() {
        let path = entry.path();
        let mut link_type = Value::Null;
        let mut target = Value::Null;
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.is_symlink() {
                link_type = Value::String("link".to_string());
                target = fs::read_link(&path)
                    .map(|p| Value::String(p.to_string_lossy().to_string()))
                    .unwrap_or(Value::Null);
            }
        }
        let is_dir = path.is_dir();
        let mut record = json!({
            "name": entry.file_name().to_string_lossy().to_string(),
            "kind": if is_dir { "directory" } else { "file" },
            "linkType": link_type,
            "target": target,
        });
        if is_dir {
            record["children"] = inventory(&path, depth + 1);
        }
        out.push(record);
    }
    Value::Array(out)
}

#[cfg(test)]
mod native_client_qualification_tests {
    use super::native_clients_unobserved;
    use serde_json::json;
    use std::fs;

    fn isolated_profile() -> std::path::PathBuf {
        let profile = std::env::temp_dir().join(format!(
            "legion-native-client-qualification-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&profile).unwrap();
        profile
    }

    #[test]
    fn native_clients_are_separate_from_product_qualification() {
        let profile = isolated_profile();
        let repair = json!({
            "nativeMarketplaces": {
                "claude": "not_selected",
                "codex": "client_unavailable"
            }
        });
        let status = json!({
            "nativeMarketplaces": {
                "claude": "not_selected",
                "codex": "client_unavailable"
            }
        });
        let observed = native_clients_unobserved(&profile, &repair, &status).unwrap();
        assert_eq!(observed["status"], "not-provisioned");
        assert_eq!(observed["clients"]["claude"]["repair"], "not_selected");
        assert_eq!(observed["clients"]["codex"]["repair"], "client_unavailable");
        fs::remove_dir_all(profile).unwrap();
    }

    #[test]
    fn native_client_state_cannot_claim_absence_when_marketplace_is_current() {
        let profile = isolated_profile();
        let marketplaces = json!({
            "claude": "current",
            "codex": "not_selected"
        });
        let repair = json!({"nativeMarketplaces": marketplaces});
        let status = repair.clone();
        let result = native_clients_unobserved(&profile, &repair, &status);
        assert!(result.is_err());
        fs::remove_dir_all(profile).unwrap();
    }
}

fn assert_real_install_directory(path: &Path) -> ReleaseResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| fail(format!("installed directory {}: {e}", path.display())))?;
    #[cfg(windows)]
    let is_reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let is_reparse = metadata.file_type().is_symlink();
    if !metadata.is_dir() || is_reparse {
        return Err(fail(format!(
            "installed payload must be a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn payload_file_sha256(current: &Path, relative: &Path) -> ReleaseResult<String> {
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(fail("payload identity path must stay below current"));
    }
    assert_real_install_directory(current)?;
    let mut path = current.to_path_buf();
    for component in &components[..components.len() - 1] {
        path.push(component.as_os_str());
        assert_real_install_directory(&path)?;
    }
    path.push(components.last().unwrap().as_os_str());
    let metadata = fs::symlink_metadata(&path)
        .map_err(|e| fail(format!("payload identity file {}: {e}", path.display())))?;
    #[cfg(windows)]
    let is_reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let is_reparse = metadata.file_type().is_symlink();
    if !metadata.is_file() || is_reparse {
        return Err(fail(format!(
            "payload identity requires a real regular file: {}",
            path.display()
        )));
    }
    let canonical_current = fs::canonicalize(current).map_err(|e| fail(e.to_string()))?;
    let canonical_file = fs::canonicalize(&path).map_err(|e| fail(e.to_string()))?;
    if !canonical_file.starts_with(&canonical_current) || canonical_file == canonical_current {
        return Err(fail(format!(
            "payload identity file escapes current: {}",
            path.display()
        )));
    }
    sha256_file(&canonical_file)
}

/// Capture independent readback expectations from qualification's final isolated
/// payload. Reject junctions at every level, including parents of fixed current.
fn installed_payload_identity(workspace: &Path, current: &Path) -> ReleaseResult<Value> {
    let relative = current
        .strip_prefix(workspace)
        .map_err(|_| fail("payload identity current escapes qualification workspace"))?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(fail(
            "payload identity current must stay below qualification workspace",
        ));
    }
    assert_real_install_directory(workspace)?;
    let mut directory = workspace.to_path_buf();
    for component in relative.components() {
        directory.push(component.as_os_str());
        assert_real_install_directory(&directory)?;
    }
    let canonical_workspace = fs::canonicalize(workspace).map_err(|e| fail(e.to_string()))?;
    let canonical_current = fs::canonicalize(current).map_err(|e| fail(e.to_string()))?;
    if !canonical_current.starts_with(&canonical_workspace)
        || canonical_current == canonical_workspace
    {
        return Err(fail(
            "payload identity current escapes qualification workspace",
        ));
    }
    let digest = |relative: &str| payload_file_sha256(&canonical_current, Path::new(relative));
    Ok(json!({
        "runtimeSha256": {
            "legion": digest("bin/legion.exe")?,
            "legion-hook": digest("bin/legion-hook.exe")?,
            "legion-mcp": digest("bin/legion-mcp.exe")?,
        },
        "releaseManifestSha256": digest("share/legion/release.json")?,
        "capabilityBodySha256": {
            "debugger": digest("share/legion/assets/skills/debugger/SKILL.md")?,
            "architect": digest("share/legion/assets/skills/architect/SKILL.md")?,
        },
    }))
}

fn assert_fixed_payload_layout(root: &Path) -> ReleaseResult<()> {
    assert_real_install_directory(&root.join("current"))?;
    let release_text = fs::read_to_string(root.join("current/share/legion/release.json"))
        .map_err(|e| fail(e.to_string()))?;
    let release: Value = serde_json::from_str(release_text.trim_start_matches('\u{feff}'))
        .map_err(|e| fail(e.to_string()))?;
    let release_version = release
        .get("releaseVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("current payload lacks release version"))?;
    if root
        .join(format!(".next-version-{release_version}"))
        .exists()
    {
        return Err(fail("fixed installation retained its staged payload"));
    }
    for entry in fs::read_dir(root).map_err(|e| fail(e.to_string()))? {
        let entry = entry.map_err(|e| fail(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "current.previous" | ".next-previous" | "versions" | ".rollback-codex"
        ) {
            return Err(fail(format!(
                "fixed installation retained its transaction storage: {name}"
            )));
        }
    }
    Ok(())
}

fn assert_fixed_activation_receipt(root: &Path) -> ReleaseResult<()> {
    let text = fs::read_to_string(root.join("activation.json"))
        .map_err(|e| fail(format!("activation receipt could not be read: {e}")))?;
    let receipt: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| fail(format!("activation receipt is invalid: {e}")))?;
    let matches = |field: &str, expected: &Path| {
        receipt.get(field).and_then(Value::as_str).map(|value| {
            value.replace('/', "\\").to_ascii_lowercase()
                == expected
                    .to_string_lossy()
                    .replace('/', "\\")
                    .to_ascii_lowercase()
        }) == Some(true)
    };
    if receipt.get("state").and_then(Value::as_str) != Some("activated")
        || !matches("current", &root.join("current"))
        || !matches("target", &root.join("current"))
        || !receipt.get("previous").map(Value::is_null).unwrap_or(true)
    {
        return Err(fail(
            "activation receipt does not bind fixed current without retained previous payload",
        ));
    }
    Ok(())
}

const PRIOR_PAYLOAD_MARKER: &str = "qualification-prior-payload-marker.txt";

fn assert_no_prior_payload_copies(root: &Path) -> ReleaseResult<()> {
    for entry in fs::read_dir(root).map_err(|e| fail(e.to_string()))? {
        let entry = entry.map_err(|e| fail(e.to_string()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|e| fail(e.to_string()))?;
        if entry.file_name() == PRIOR_PAYLOAD_MARKER {
            return Err(fail(format!(
                "development activation saved prior payload: {}",
                path.display()
            )));
        }
        // Never follow qualification's foreign junction/link fixtures.
        #[cfg(windows)]
        let is_link = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let is_link = metadata.file_type().is_symlink();
        if metadata.is_dir() && !is_link {
            assert_no_prior_payload_copies(&path)?;
        }
    }
    Ok(())
}

fn assert_failed_development_activation(
    root: &Path,
    mirror_root: &Path,
    workspace: &Path,
    runtime_sha256: &str,
    events_path: &Path,
    prior_events: &str,
) -> ReleaseResult<()> {
    for product_root in [root, mirror_root] {
        assert_fixed_payload_layout(product_root)?;
        if sha256_file(&product_root.join("current/bin/legion.exe"))? != runtime_sha256 {
            return Err(fail("development failure changed candidate runtime bytes"));
        }
    }
    assert_no_prior_payload_copies(workspace)?;
    let text = fs::read_to_string(root.join("activation.json")).map_err(|e| fail(e.to_string()))?;
    let receipt: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| fail(e.to_string()))?;
    let current = root.join("current");
    if receipt["state"] != "failed"
        || receipt["recovery"] != "reinstall"
        || receipt["current"].as_str() != current.to_str()
        || receipt["target"].as_str() != current.to_str()
        || !receipt["previous"].is_null()
    {
        return Err(fail(
            "development failure retained stale success receipt or lost reinstall state",
        ));
    }
    let events = fs::read_to_string(events_path).map_err(|e| fail(e.to_string()))?;
    let added = events
        .strip_prefix(prior_events)
        .ok_or_else(|| fail("development failure rewrote activation events"))?;
    let mut failed = false;
    let mut reinstall = false;
    for line in added.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line.trim_start_matches('\u{feff}'))
            .map_err(|e| fail(e.to_string()))?;
        failed |= event["stage"] == "activation" && event["status"] == "failed";
        reinstall |= event["stage"] == "recovery" && event["status"] == "required";
        if event["stage"]
            .as_str()
            .unwrap_or("")
            .starts_with("rollback")
        {
            return Err(fail(
                "development failure attempted rollback or old-runtime repair",
            ));
        }
    }
    if !failed || !reinstall {
        return Err(fail(
            "development failure omitted failed activation or reinstall event",
        ));
    }
    Ok(())
}

fn assert_stable_runtime_events(events_path: &Path, executable: &Path) -> ReleaseResult<()> {
    let text = fs::read_to_string(events_path)
        .map_err(|e| fail(format!("activation events could not be read: {e}")))?;
    let mut observed_runtime = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line.trim_start_matches('\u{feff}'))
            .map_err(|e| fail(format!("activation event is invalid: {e}")))?;
        if event.get("status").and_then(Value::as_str) != Some("started") {
            continue;
        }
        let detail = event.get("detail").and_then(Value::as_str).unwrap_or("");
        if let Some(path) = detail.strip_prefix("executable=") {
            let path = path.split("; timeout=").next().unwrap_or(path);
            if Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.eq_ignore_ascii_case("legion.exe"))
                == Some(true)
            {
                observed_runtime = true;
                if !path.eq_ignore_ascii_case(&executable.to_string_lossy()) {
                    return Err(fail(format!(
                        "activation executed Legion outside fixed current: {path}"
                    )));
                }
            }
        }
    }
    if !observed_runtime {
        return Err(fail(
            "activation did not record fixed-current runtime execution",
        ));
    }
    Ok(())
}

fn assert_no_new_runtime_events(events_path: &Path, before: &str) -> ReleaseResult<()> {
    let after = fs::read_to_string(events_path).map_err(|e| fail(e.to_string()))?;
    let added = after
        .strip_prefix(before)
        .ok_or_else(|| fail("activation rejection replaced prior event evidence"))?;
    for line in added.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line.trim_start_matches('\u{feff}'))
            .map_err(|e| fail(e.to_string()))?;
        if event.get("status").and_then(Value::as_str) == Some("started")
            && event
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .starts_with("executable=")
        {
            return Err(fail("rejected prior state triggered runtime execution"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn qualify_inner(
    runner: CommandRunner,
    installer: &Path,
    output: &Path,
    version: &str,
    revision: &str,
    finalization_sha256: &str,
    workspace: &Path,
    development_install: bool,
) -> ReleaseResult<Value> {
    let local_app_data = workspace.join("local-app-data");
    let install_root = local_app_data.join("Orthic Labs").join("Legion");
    let mirror_current = local_app_data
        .join("Packages")
        .join("Legion-Qualification")
        .join("LocalCache")
        .join("Local")
        .join("Orthic Labs")
        .join("Legion")
        .join("current");
    fs::create_dir_all(mirror_current.parent().unwrap()).map_err(|e| {
        fail(format!(
            "could not create isolated LocalCache mirror fixture: {e}"
        ))
    })?;
    let profile = workspace.join("profile");
    // Do not create client profile directories here: that would make setup
    // treat a missing native CLI as an installed host and turn product
    // qualification into a fake marketplace-install pass.
    let executable = install_root.join("current").join("bin").join("legion.exe");
    let install_log = output.join("setup-install.log");
    let activation_events = output.join("activation-events.jsonl");
    let staged_validation_failure_log = output.join("setup-staged-validation-failure.log");
    let mirror_sync_failure_log = output.join("setup-mirror-sync-failure.log");
    let forced_refresh_failure_log = output.join("setup-forced-refresh-failure.log");
    let stalled_child_log = output.join("setup-stalled-child.log");
    let setup_logs: Vec<(&str, &PathBuf)> = vec![
        ("install", &install_log),
        ("activationEvents", &activation_events),
        ("stagedValidationFailure", &staged_validation_failure_log),
        ("mirrorSyncFailure", &mirror_sync_failure_log),
        ("forcedRefreshFailure", &forced_refresh_failure_log),
        ("stalledChild", &stalled_child_log),
    ];

    let base_env: HashMap<String, String> = std::env::vars().collect();
    let mut overrides = HashMap::new();
    // Inno transaction storage must be observable by no-prior-copy assertions.
    let installer_temp = workspace.join("installer-temp");
    fs::create_dir_all(&installer_temp).map_err(|e| fail(e.to_string()))?;
    for key in ["TEMP", "TMP"] {
        overrides.insert(
            key.to_string(),
            installer_temp.to_string_lossy().to_string(),
        );
    }
    overrides.insert(
        "LOCALAPPDATA".to_string(),
        local_app_data.to_string_lossy().to_string(),
    );
    overrides.insert(
        "USERPROFILE".to_string(),
        profile.to_string_lossy().to_string(),
    );
    // Native clients inherit these locations from the host process. Keep their
    // config/cache roots in the qualification profile so installed setup cannot
    // touch the operator's real marketplaces when CLIs happen to be on PATH.
    overrides.insert("HOME".to_string(), profile.to_string_lossy().to_string());
    overrides.insert(
        "CLAUDE_CONFIG_DIR".to_string(),
        profile.join(".claude").to_string_lossy().to_string(),
    );
    overrides.insert(
        "CODEX_HOME".to_string(),
        profile.join(".codex").to_string_lossy().to_string(),
    );
    overrides.insert(
        "LEGION_STATE_ROOT".to_string(),
        local_app_data.join("Legion").to_string_lossy().to_string(),
    );
    overrides.insert(
        "LEGION_INSTALL_EVENT_LOG".to_string(),
        activation_events.to_string_lossy().to_string(),
    );
    overrides.insert(
        "LEGION_INSTALL_PACKAGES_ROOT".to_string(),
        local_app_data
            .join("Packages")
            .to_string_lossy()
            .to_string(),
    );
    let path_sep = if cfg!(windows) { ";" } else { ":" };
    overrides.insert(
        "PATH".to_string(),
        format!(
            "{}{path_sep}{}",
            install_root.join("current").join("bin").display(),
            base_env.get("PATH").cloned().unwrap_or_default()
        ),
    );
    let environment = windows_environment(&base_env, &overrides);
    let workspace_opts = CommandOptions {
        cwd: Some(workspace.to_path_buf()),
        env: Some(environment.clone()),
    };
    let install_root_opts = CommandOptions {
        cwd: Some(install_root.clone()),
        env: Some(environment.clone()),
    };

    let stages: std::cell::RefCell<Vec<Value>> = std::cell::RefCell::new(vec![]);
    let current_stage = std::cell::RefCell::new("setup".to_string());
    let step = |stage: &str,
                run: &mut dyn FnMut() -> ReleaseResult<StepOutcome>|
     -> ReleaseResult<StepOutcome> {
        *current_stage.borrow_mut() = stage.to_string();
        let result = run()?;
        let mut entry = json!({ "stage": stage });
        if let (Some(obj), Some(ev_obj)) = (entry.as_object_mut(), result.evidence.as_object()) {
            for (k, v) in ev_obj {
                obj.insert(k.clone(), v.clone());
            }
        }
        stages.borrow_mut().push(entry);
        Ok(result)
    };

    let run_result = (|| -> ReleaseResult<Value> {
        let reinstall = |stage: &str| -> ReleaseResult<()> {
            step(stage, &mut || {
                execute(
                    runner,
                    installer,
                    &[
                        "/VERYSILENT".into(),
                        "/SUPPRESSMSGBOXES".into(),
                        "/NORESTART".into(),
                        format!("/DIR={}", install_root.display()),
                        format!("/LOG={}", install_log.display()),
                    ],
                    &workspace_opts,
                    "reinstall after development activation failure",
                )
            })?;
            assert_fixed_payload_layout(&install_root)?;
            assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
            assert_fixed_activation_receipt(&install_root)
        };
        let seed_prior_markers = || -> ReleaseResult<()> {
            for current in [install_root.join("current"), mirror_current.clone()] {
                fs::write(
                    current.join(PRIOR_PAYLOAD_MARKER),
                    "prior installed payload",
                )
                .map_err(|e| fail(e.to_string()))?;
            }
            Ok(())
        };
        let install_run = step("install", &mut || {
            execute(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                    format!("/LOG={}", install_log.display()),
                ],
                &workspace_opts,
                "silent setup",
            )
        })?;
        let _ = install_run;
        if !executable.is_file() {
            return Err(fail(format!(
                "installed legion.exe is missing or unsafe: {}",
                executable.display()
            )));
        }

        let installed_version = step("version", &mut || {
            execute(
                runner,
                &executable,
                &["--version".into()],
                &install_root_opts,
                "installed legion --version",
            )
        })?;
        if installed_version.stdout != version {
            return Err(fail("installed current reported an unexpected version"));
        }
        let mirror_executable = mirror_current.join("bin").join("legion.exe");
        if !mirror_executable.is_file() {
            return Err(fail(format!(
                "isolated LocalCache mirror executable is missing: {}",
                mirror_executable.display()
            )));
        }

        assert_fixed_payload_layout(&install_root)?;
        assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
        assert_fixed_activation_receipt(&install_root)?;
        if install_root.join("versions").exists()
            || mirror_current.parent().unwrap().join("versions").exists()
        {
            return Err(fail("fresh installation created generation storage"));
        }

        // Hold the real Inno mutex in another process while invoking setup.
        // A rejected installer must leave payload, receipt & staging untouched.
        let installed_sha256 = sha256_file(&executable)?;
        let installed_receipt =
            fs::read(install_root.join("activation.json")).map_err(|e| fail(e.to_string()))?;
        let lock_probe = workspace.join("probe-installer-lock.ps1");
        fs::write(
            &lock_probe,
            r#"param([string]$Installer, [string]$InstallRoot)
$ErrorActionPreference = 'Stop'
$mutex = [Threading.Mutex]::new($false, 'Local\OrthicLabs.Legion.Setup')
$lockAcquired = $false
$installerProcess = $null
try {
  $lockAcquired = $mutex.WaitOne(0)
  if (-not $lockAcquired) { throw 'Could not acquire installer qualification mutex' }
  # A standalone GUI invocation can return before Setup checks its mutex.
  # Keep it held through the complete process tree & read this process's exit.
  $installerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR="' + $InstallRoot + '"'
  $installerProcess = Start-Process -FilePath $Installer -ArgumentList $installerArguments -WindowStyle Hidden -Wait -PassThru
  if (-not $installerProcess.HasExited) { throw 'Concurrent installer did not exit' }
  $installerExitCode = $installerProcess.ExitCode
  if ($null -eq $installerExitCode) { throw 'Concurrent installer exit code is unavailable' }
  if ($installerExitCode -eq 0) { throw 'Concurrent installer falsely succeeded' }
  Write-Output ('blockedInstallerExit=' + $installerExitCode)
} finally {
  if ($null -ne $installerProcess) { $installerProcess.Dispose() }
  if ($lockAcquired) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
}
"#,
        )
        .map_err(|e| fail(e.to_string()))?;
        let events_before_lock =
            fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
        step("concurrent-installer-rejection", &mut || {
            execute(
                runner,
                Path::new("powershell.exe"),
                &[
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-File".into(),
                    lock_probe.to_string_lossy().to_string(),
                    "-Installer".into(),
                    installer.to_string_lossy().to_string(),
                    "-InstallRoot".into(),
                    install_root.to_string_lossy().to_string(),
                ],
                &workspace_opts,
                "concurrent installer rejection",
            )
        })?;
        assert_no_new_runtime_events(&activation_events, &events_before_lock)
            .map_err(|error| format!("{error}; stage=concurrent-installer-rejection"))?;
        if sha256_file(&executable)? != installed_sha256
            || fs::read(install_root.join("activation.json")).map_err(|e| fail(e.to_string()))?
                != installed_receipt
            || install_root
                .join(format!(".next-version-{version}"))
                .exists()
        {
            return Err(fail("concurrent installer changed prior installation"));
        }

        for (stage, name) in [
            (
                "unowned-stage-rejection",
                format!(".next-version-{version}"),
            ),
            ("unowned-snapshot-rejection", ".rollback-codex".to_string()),
        ] {
            let foreign_root = install_root.join(name);
            fs::create_dir_all(&foreign_root).map_err(|e| fail(e.to_string()))?;
            fs::write(foreign_root.join("foreign.txt"), "preserve unowned state")
                .map_err(|e| fail(e.to_string()))?;
            let prior_events =
                fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
            step(stage, &mut || {
                execute_expected_failure(
                    runner,
                    installer,
                    &[
                        "/VERYSILENT".into(),
                        "/SUPPRESSMSGBOXES".into(),
                        "/NORESTART".into(),
                        format!("/DIR={}", install_root.display()),
                    ],
                    &workspace_opts,
                    stage,
                )
            })?;
            assert_no_new_runtime_events(&activation_events, &prior_events)
                .map_err(|error| format!("{error}; stage={stage}"))?;
            if fs::read_to_string(foreign_root.join("foreign.txt"))
                .map_err(|e| fail(e.to_string()))?
                != "preserve unowned state"
                || sha256_file(&executable)? != installed_sha256
                || fs::read(install_root.join("activation.json"))
                    .map_err(|e| fail(e.to_string()))?
                    != installed_receipt
            {
                return Err(fail(format!("{stage} changed foreign or installed state")));
            }
            fs::remove_dir_all(foreign_root).map_err(|e| fail(e.to_string()))?;
        }

        let foreign_current = workspace.join("foreign-current-target");
        fs::rename(install_root.join("current"), &foreign_current)
            .map_err(|e| fail(e.to_string()))?;
        step("foreign-junction-fixture", &mut || {
            execute(
                runner,
                Path::new("cmd.exe"),
                &[
                    "/D".into(),
                    "/C".into(),
                    "mklink".into(),
                    "/J".into(),
                    install_root.join("current").to_string_lossy().to_string(),
                    foreign_current.to_string_lossy().to_string(),
                ],
                &workspace_opts,
                "foreign current junction fixture",
            )
        })?;
        let foreign_events =
            fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
        step("foreign-junction-rejection", &mut || {
            execute_expected_failure(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                ],
                &workspace_opts,
                "foreign current junction rejection",
            )
        })?;
        assert_no_new_runtime_events(&activation_events, &foreign_events)
            .map_err(|error| format!("{error}; stage=foreign-junction-rejection"))?;
        if sha256_file(&foreign_current.join("bin/legion.exe"))? != installed_sha256
            || fs::read(install_root.join("activation.json")).map_err(|e| fail(e.to_string()))?
                != installed_receipt
        {
            return Err(fail(
                "foreign junction rejection changed foreign payload or receipt",
            ));
        }
        fs::remove_dir(install_root.join("current")).map_err(|e| fail(e.to_string()))?;
        fs::rename(&foreign_current, install_root.join("current"))
            .map_err(|e| fail(e.to_string()))?;
        assert_fixed_payload_layout(&install_root)?;

        // Mirror ownership must reject before canonical current is replaced.
        let foreign_mirror = workspace.join("foreign-mirror-current");
        fs::rename(&mirror_current, &foreign_mirror).map_err(|e| fail(e.to_string()))?;
        step("foreign-mirror-junction-fixture", &mut || {
            execute(
                runner,
                Path::new("cmd.exe"),
                &[
                    "/D".into(),
                    "/C".into(),
                    "mklink".into(),
                    "/J".into(),
                    mirror_current.to_string_lossy().to_string(),
                    foreign_mirror.to_string_lossy().to_string(),
                ],
                &workspace_opts,
                "foreign mirror junction fixture",
            )
        })?;
        let mirror_rejection_events =
            fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
        step("foreign-mirror-junction-rejection", &mut || {
            execute_expected_failure(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                ],
                &workspace_opts,
                "foreign mirror junction rejection",
            )
        })?;
        assert_no_new_runtime_events(&activation_events, &mirror_rejection_events)?;
        if sha256_file(&executable)? != installed_sha256
            || fs::read(install_root.join("activation.json")).map_err(|e| fail(e.to_string()))?
                != installed_receipt
            || sha256_file(&foreign_mirror.join("bin/legion.exe"))? != installed_sha256
        {
            return Err(fail(
                "foreign mirror rejection changed canonical or foreign installed state",
            ));
        }
        fs::remove_dir(&mirror_current).map_err(|e| fail(e.to_string()))?;
        fs::rename(&foreign_mirror, &mirror_current).map_err(|e| fail(e.to_string()))?;

        // Same-version reinstall replaces current completely & removes prior payloads.
        let stale_dir = install_root
            .join("current")
            .join("plugin")
            .join("skills")
            .join("alchemist")
            .join("scripts");
        let stale_file = stale_dir.join("obsolete-upgrade-marker.txt");
        let pre_upgrade_current_sha256 = sha256_file(&executable)?;
        let pre_upgrade_mirror_sha256 = sha256_file(&mirror_executable)?;
        fs::create_dir_all(&stale_dir)
            .map_err(|e| fail(format!("could not seed stale upgrade entry: {e}")))?;
        fs::write(&stale_file, "stale same-version payload")
            .map_err(|e| fail(format!("could not seed stale upgrade marker: {e}")))?;
        let mut staged_failure_env = environment.clone();
        staged_failure_env.insert(
            "LEGION_INSTALL_TEST_MODE".to_string(),
            "staged-validation-failure".to_string(),
        );
        let staged_failure_opts = CommandOptions {
            cwd: Some(workspace.to_path_buf()),
            env: Some(staged_failure_env),
        };
        step("staged-validation-failure", &mut || {
            execute_expected_failure(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                    format!("/LOG={}", staged_validation_failure_log.display()),
                ],
                &staged_failure_opts,
                "staged payload validation failure",
            )
        })?;
        if sha256_file(&executable)? != pre_upgrade_current_sha256
            || sha256_file(&mirror_executable)? != pre_upgrade_mirror_sha256
        {
            return Err(fail(
                "staged payload validation failure changed prior runtime or mirror",
            ));
        }
        if !stale_dir.exists() || !stale_file.exists() {
            return Err(fail(
                "staged payload validation failure did not preserve prior current tree",
            ));
        }
        assert_fixed_payload_layout(&install_root)?;
        assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
        assert_fixed_activation_receipt(&install_root)?;
        seed_prior_markers()?;
        let mut mirror_failure_env = environment.clone();
        mirror_failure_env.insert(
            "LEGION_INSTALL_TEST_MODE".to_string(),
            "mirror-sync-failure".to_string(),
        );
        let mirror_failure_opts = CommandOptions {
            cwd: Some(workspace.to_path_buf()),
            env: Some(mirror_failure_env),
        };
        let mirror_failure_events =
            fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
        step("mirror-sync-failure", &mut || {
            execute_expected_failure(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                    format!("/LOG={}", mirror_sync_failure_log.display()),
                ],
                &mirror_failure_opts,
                "packaged LocalCache mirror failure",
            )
        })?;
        if development_install {
            assert_failed_development_activation(
                &install_root,
                mirror_current.parent().unwrap(),
                workspace,
                &pre_upgrade_current_sha256,
                &activation_events,
                &mirror_failure_events,
            )?;
            if stale_file.exists() {
                return Err(fail(
                    "development mirror failure retained obsolete prior current entries",
                ));
            }
        } else {
            if sha256_file(&executable)? != pre_upgrade_current_sha256
                || sha256_file(&mirror_executable)? != pre_upgrade_mirror_sha256
            {
                return Err(fail(
                    "packaged LocalCache mirror failure changed prior runtime or mirror",
                ));
            }
            if !stale_dir.exists() || !stale_file.exists() {
                return Err(fail(
                    "packaged LocalCache mirror failure did not preserve prior current tree",
                ));
            }
            assert_fixed_payload_layout(&install_root)?;
            assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
            assert_fixed_activation_receipt(&install_root)?;
        }
        let upgrade_run = step("same-version-upgrade", &mut || {
            execute(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                    format!("/LOG={}", install_log.display()),
                ],
                &workspace_opts,
                "same-version upgrade",
            )
        })?;
        let _ = upgrade_run;
        if stale_dir.exists() || stale_file.exists() {
            return Err(fail(
                "same-version upgrade retained obsolete payload entries",
            ));
        }
        assert_fixed_payload_layout(&install_root)?;
        assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
        assert_fixed_activation_receipt(&install_root)?;

        if development_install {
            seed_prior_markers()?;
            let mut interrupted_env = environment.clone();
            interrupted_env.insert(
                "LEGION_INSTALL_TEST_MODE".into(),
                "partial-current-removal-failure".into(),
            );
            let interrupted_opts = CommandOptions {
                cwd: Some(workspace.to_path_buf()),
                env: Some(interrupted_env),
            };
            step("interrupted-development-replacement", &mut || {
                execute_expected_failure(
                    runner,
                    installer,
                    &[
                        "/VERYSILENT".into(),
                        "/SUPPRESSMSGBOXES".into(),
                        "/NORESTART".into(),
                        format!("/DIR={}", install_root.display()),
                    ],
                    &interrupted_opts,
                    "interrupted development current removal",
                )
            })?;
            let retained_stage = install_root.join(format!(".next-version-{version}"));
            let prior_identity = install_root.join("current/share/legion/release.json");
            let receipt_path = install_root.join("activation.json");
            let interrupted_receipt = fs::read(&receipt_path).map_err(|e| fail(e.to_string()))?;
            let interrupted: Value =
                serde_json::from_slice(&interrupted_receipt).map_err(|e| fail(e.to_string()))?;
            if prior_identity.exists()
                || !install_root
                    .join("current")
                    .join(PRIOR_PAYLOAD_MARKER)
                    .is_file()
                || interrupted["state"] != "failed"
                || interrupted["recovery"] != "reinstall"
                || interrupted["developmentRecovery"]["installerSha256"]
                    .as_str()
                    .map(str::to_ascii_lowercase)
                    != Some(sha256_file(installer)?)
                || sha256_file(&retained_stage.join("bin/legion.exe"))?
                    != pre_upgrade_current_sha256
            {
                return Err(fail("interrupted replacement lost candidate stage, partial current, or exact-installer context"));
            }
            let reject_retry = |stage: &str, expected_receipt: &[u8]| -> ReleaseResult<()> {
                let prior_events =
                    fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
                step(stage, &mut || {
                    execute_expected_failure(
                        runner,
                        installer,
                        &[
                            "/VERYSILENT".into(),
                            "/SUPPRESSMSGBOXES".into(),
                            "/NORESTART".into(),
                            format!("/DIR={}", install_root.display()),
                        ],
                        &workspace_opts,
                        stage,
                    )
                })?;
                assert_no_new_runtime_events(&activation_events, &prior_events)?;
                if prior_identity.exists()
                    || !install_root
                        .join("current")
                        .join(PRIOR_PAYLOAD_MARKER)
                        .is_file()
                    || fs::read(&receipt_path).map_err(|e| fail(e.to_string()))? != expected_receipt
                    || sha256_file(&retained_stage.join("bin/legion.exe"))?
                        != pre_upgrade_current_sha256
                {
                    return Err(fail(format!(
                        "{stage} changed interrupted or foreign state"
                    )));
                }
                Ok(())
            };
            let mut wrong_installer = interrupted.clone();
            wrong_installer["developmentRecovery"]["installerSha256"] = json!("0".repeat(64));
            let wrong_installer_bytes = serde_json::to_vec(&wrong_installer).unwrap();
            fs::write(&receipt_path, &wrong_installer_bytes).map_err(|e| fail(e.to_string()))?;
            reject_retry(
                "development-retry-installer-mismatch",
                &wrong_installer_bytes,
            )?;
            let mut missing_context = interrupted;
            missing_context
                .as_object_mut()
                .unwrap()
                .remove("developmentRecovery");
            let missing_context_bytes = serde_json::to_vec(&missing_context).unwrap();
            fs::write(&receipt_path, &missing_context_bytes).map_err(|e| fail(e.to_string()))?;
            reject_retry("development-retry-missing-context", &missing_context_bytes)?;
            fs::write(&receipt_path, &interrupted_receipt).map_err(|e| fail(e.to_string()))?;
            let foreign_marker = install_root.join("current/foreign-retry-marker.txt");
            fs::write(&foreign_marker, "preserve foreign retry bytes")
                .map_err(|e| fail(e.to_string()))?;
            reject_retry("development-retry-foreign-current", &interrupted_receipt)?;
            if fs::read_to_string(&foreign_marker).map_err(|e| fail(e.to_string()))?
                != "preserve foreign retry bytes"
            {
                return Err(fail("development retry changed foreign current bytes"));
            }
            fs::remove_file(foreign_marker).map_err(|e| fail(e.to_string()))?;
            reinstall("interrupted-development-reinstall")?;
            assert_no_prior_payload_copies(workspace)?;

            // Different bytes at the same owned path expose retry-of-retry
            // failures that identical same-version payloads cannot detect.
            let plugin_identity = install_root.join("current/plugin/.claude-plugin/plugin.json");
            let candidate_plugin_bytes =
                fs::read(&plugin_identity).map_err(|e| fail(e.to_string()))?;
            let mut distinct_prior: Value =
                serde_json::from_slice(&candidate_plugin_bytes).map_err(|e| fail(e.to_string()))?;
            distinct_prior["qualificationPriorContent"] = json!("different original payload bytes");
            let distinct_prior_bytes = serde_json::to_vec(&distinct_prior).unwrap();
            if distinct_prior_bytes == candidate_plugin_bytes {
                return Err(fail(
                    "retry fixture did not create distinct prior payload bytes",
                ));
            }
            fs::write(&plugin_identity, &distinct_prior_bytes).map_err(|e| fail(e.to_string()))?;
            seed_prior_markers()?;
            let mut candidate_failure_env = environment.clone();
            candidate_failure_env
                .insert("LEGION_INSTALL_TEST_MODE".into(), "refresh-failure".into());
            let candidate_failure_opts = CommandOptions {
                cwd: Some(workspace.to_path_buf()),
                env: Some(candidate_failure_env),
            };
            step("different-candidate-refresh-failure", &mut || {
                execute_expected_failure(
                    runner,
                    installer,
                    &[
                        "/VERYSILENT".into(),
                        "/SUPPRESSMSGBOXES".into(),
                        "/NORESTART".into(),
                        format!("/DIR={}", install_root.display()),
                    ],
                    &candidate_failure_opts,
                    "different candidate post-move refresh failure",
                )
            })?;
            if fs::read(&plugin_identity).map_err(|e| fail(e.to_string()))?
                != candidate_plugin_bytes
            {
                return Err(fail(
                    "post-move failure did not preserve distinct candidate bytes",
                ));
            }
            assert_no_prior_payload_copies(workspace)?;
            step("interrupted-candidate-retry", &mut || {
                execute_expected_failure(
                    runner,
                    installer,
                    &[
                        "/VERYSILENT".into(),
                        "/SUPPRESSMSGBOXES".into(),
                        "/NORESTART".into(),
                        format!("/DIR={}", install_root.display()),
                    ],
                    &interrupted_opts,
                    "interrupted deletion of already activated candidate",
                )
            })?;
            let candidate_retry_receipt =
                fs::read(&receipt_path).map_err(|e| fail(e.to_string()))?;
            let candidate_retry: Value = serde_json::from_slice(&candidate_retry_receipt)
                .map_err(|e| fail(e.to_string()))?;
            if prior_identity.exists()
                || candidate_retry["state"] != "failed"
                || fs::read(&plugin_identity).map_err(|e| fail(e.to_string()))?
                    != candidate_plugin_bytes
                || sha256_file(&retained_stage.join("bin/legion.exe"))?
                    != pre_upgrade_current_sha256
                || candidate_retry["developmentRecovery"]["priorCurrent"]["digests"]
                    ["plugin\\.claude-plugin\\plugin.json"]
                    == candidate_retry["developmentRecovery"]["candidateDigests"]
                        ["plugin\\.claude-plugin\\plugin.json"]
            {
                return Err(fail("retry-of-retry fixture lost distinct original/candidate identities or partial candidate"));
            }
            // One prior-only file plus candidate-only bytes must not pass as
            // an allowed union of individually recorded files.
            let mixed_marker = install_root.join("current").join(PRIOR_PAYLOAD_MARKER);
            fs::write(&mixed_marker, "prior installed payload").map_err(|e| fail(e.to_string()))?;
            reject_retry("development-retry-mixed-payloads", &candidate_retry_receipt)?;
            fs::remove_file(mixed_marker).map_err(|e| fail(e.to_string()))?;
            reinstall("interrupted-candidate-retry-reinstall")?;
            if fs::read(&plugin_identity).map_err(|e| fail(e.to_string()))?
                != candidate_plugin_bytes
            {
                return Err(fail(
                    "retry-of-retry did not activate exact candidate bytes",
                ));
            }
            assert_no_prior_payload_copies(workspace)?;
        }

        // Reproduce the historical junction layout using the same installed
        // bytes. Its target must be retired only after real current succeeds.
        let legacy_target = install_root.join("versions").join(version);
        fs::create_dir_all(legacy_target.parent().unwrap())
            .map_err(|e| fail(format!("could not create legacy generation fixture: {e}")))?;
        fs::rename(install_root.join("current"), &legacy_target)
            .map_err(|e| fail(format!("could not seed legacy generation fixture: {e}")))?;
        let legacy_marker = "legacy-current-marker.txt";
        fs::write(legacy_target.join(legacy_marker), "prior junction payload")
            .map_err(|e| fail(format!("could not seed legacy payload marker: {e}")))?;
        step("legacy-junction-fixture", &mut || {
            execute(
                runner,
                Path::new("cmd.exe"),
                &[
                    "/D".into(),
                    "/C".into(),
                    "mklink".into(),
                    "/J".into(),
                    install_root.join("current").to_string_lossy().to_string(),
                    legacy_target.to_string_lossy().to_string(),
                ],
                &workspace_opts,
                "legacy current junction fixture",
            )
        })?;
        let obsolete_backup = install_root.join(".previous-current-legacy-fixture");
        fs::create_dir_all(&obsolete_backup).map_err(|e| fail(e.to_string()))?;
        fs::write(obsolete_backup.join("marker.txt"), "obsolete backup")
            .map_err(|e| fail(e.to_string()))?;
        let foreign_history = install_root.join("versions").join("foreign-history");
        fs::create_dir_all(&foreign_history).map_err(|e| fail(e.to_string()))?;
        fs::write(
            foreign_history.join("marker.txt"),
            "retired version history",
        )
        .map_err(|e| fail(e.to_string()))?;
        let history_link_target = workspace.join("retired-history-external-target");
        fs::create_dir_all(&history_link_target).map_err(|e| fail(e.to_string()))?;
        fs::write(
            history_link_target.join("preserve.txt"),
            "outside retired history",
        )
        .map_err(|e| fail(e.to_string()))?;
        step("legacy-history-link-fixture", &mut || {
            execute(
                runner,
                Path::new("cmd.exe"),
                &[
                    "/D".into(),
                    "/C".into(),
                    "mklink".into(),
                    "/J".into(),
                    foreign_history
                        .join("external-link")
                        .to_string_lossy()
                        .to_string(),
                    history_link_target.to_string_lossy().to_string(),
                ],
                &workspace_opts,
                "retired history junction fixture",
            )
        })?;
        let mirror_foreign_history = mirror_current
            .parent()
            .unwrap()
            .join(".previous-current-foreign-history");
        fs::create_dir_all(&mirror_foreign_history).map_err(|e| fail(e.to_string()))?;
        fs::write(
            mirror_foreign_history.join("marker.txt"),
            "preserve mirror history",
        )
        .map_err(|e| fail(e.to_string()))?;
        // Fixed historical roots are retired even when they contain unknown old entries.
        for root in [&install_root, mirror_current.parent().unwrap()] {
            for history in ["current.previous", ".next-previous"] {
                fs::create_dir_all(root.join(history)).map_err(|e| fail(e.to_string()))?;
                fs::write(root.join(history).join("retired.txt"), "retired payload")
                    .map_err(|e| fail(e.to_string()))?;
            }
        }
        step("legacy-layout-upgrade", &mut || {
            execute(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                    format!("/LOG={}", install_log.display()),
                ],
                &workspace_opts,
                "legacy junction migration",
            )
        })?;
        assert_fixed_payload_layout(&install_root)?;
        assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
        assert_fixed_activation_receipt(&install_root)?;
        if legacy_target.exists()
            || foreign_history.exists()
            || !obsolete_backup.join("marker.txt").is_file()
            || !mirror_foreign_history.join("marker.txt").is_file()
            || install_root.join("current").join(legacy_marker).exists()
            || fs::read_to_string(history_link_target.join("preserve.txt"))
                .map_err(|e| fail(e.to_string()))?
                != "outside retired history"
        {
            return Err(fail(
                "legacy migration retained history or changed unrelated directories",
            ));
        }
        // Release restores prior bytes; dev preserves candidate & requires reinstall.
        let rollback_marker = install_root.join("current").join(PRIOR_PAYLOAD_MARKER);
        seed_prior_markers()?;
        let plugin_root_transport = step("plugin-root-transport", &mut || {
            probe_plugin_root_transport(
                &executable,
                &install_root.join("current").join("plugin"),
                &install_root_opts,
            )
        })?;
        let native_marketplace_payload =
            validate_installed_native_marketplaces(&install_root.join("current"))?;
        let activated_sha256 = sha256_file(&executable)?;
        let prior_receipt =
            fs::read(install_root.join("activation.json")).map_err(|e| fail(e.to_string()))?;

        let mut forced_env = environment.clone();
        forced_env.insert(
            "LEGION_INSTALL_TEST_MODE".to_string(),
            "refresh-failure".to_string(),
        );
        let forced_opts = CommandOptions {
            cwd: Some(workspace.to_path_buf()),
            env: Some(forced_env),
        };
        let refresh_failure_events =
            fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
        step("forced-refresh-failure", &mut || {
            execute_expected_failure(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                    format!("/LOG={}", forced_refresh_failure_log.display()),
                ],
                &forced_opts,
                "forced client refresh failure",
            )
        })?;
        if development_install {
            assert_failed_development_activation(
                &install_root,
                mirror_current.parent().unwrap(),
                workspace,
                &activated_sha256,
                &activation_events,
                &refresh_failure_events,
            )?;
            reinstall("reinstall-after-refresh-failure")?;
            seed_prior_markers()?;
        } else {
            if sha256_file(&executable)? != activated_sha256
                || fs::read_to_string(&rollback_marker).map_err(|e| fail(e.to_string()))?
                    != "prior installed payload"
                || fs::read(install_root.join("activation.json"))
                    .map_err(|e| fail(e.to_string()))?
                    != prior_receipt
            {
                return Err(fail(
                    "forced client refresh failure did not restore current payload & receipt",
                ));
            }
            assert_fixed_payload_layout(&install_root)?;
            assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
            assert_fixed_activation_receipt(&install_root)?;
        }

        let mirror_before_receipt_failure = sha256_file(&mirror_executable)?;
        // Fault injection stays in qualification. Dot-source the exact activation
        // source compiled with this xtask; no QA switch ships in the installer.
        let receipt_activation_source = workspace.join("receipt-activation.ps1");
        fs::write(
            &receipt_activation_source,
            include_str!("../../../../scripts/release/windows/activate.ps1"),
        )
        .map_err(|e| fail(e.to_string()))?;
        let receipt_activation_source_sha256 = sha256_file(&receipt_activation_source)?;
        let receipt_fault_wrapper = workspace.join("probe-partial-receipt-write.ps1");
        let receipt_fault_proof = workspace.join("partial-receipt-write-observed.txt");
        fs::write(&receipt_fault_wrapper, r#"param([string]$ActivationScript, [string]$InstallRoot, [string]$Version, [string]$ProofPath, [string]$InstallerPath, [switch]$DevelopmentInstall)
$ErrorActionPreference = 'Stop'
$receiptToFail = [IO.Path]::GetFullPath((Join-Path $InstallRoot 'activation.json'))
$stage = Join-Path $InstallRoot ('.next-version-' + $Version)
if (Test-Path -LiteralPath $stage) { throw 'Receipt probe stage already exists' }
Copy-Item -LiteralPath (Join-Path $InstallRoot 'current') -Destination $stage -Recurse
if ($DevelopmentInstall) {
  Remove-Item -LiteralPath (Join-Path $stage 'qualification-prior-payload-marker.txt')
}
function Set-Content {
  [CmdletBinding()]
  param([Parameter(ValueFromPipeline=$true)]$Value, [string]$LiteralPath, [string]$Encoding)
  process {
    if ([IO.Path]::GetFullPath($LiteralPath) -ieq $receiptToFail) {
      [IO.File]::WriteAllText($LiteralPath, '{')
      if ([IO.File]::ReadAllText($LiteralPath) -cne '{') { throw 'Partial receipt write was not observed' }
      [IO.File]::WriteAllText($ProofPath, 'partial activation receipt observed')
      throw 'Injected Set-Content failure after partial activation receipt write'
    }
    Microsoft.PowerShell.Management\Set-Content @PSBoundParameters
  }
}
$mode = @{}
if ($DevelopmentInstall) { $mode.DevelopmentInstall = $true; $mode.InstallerPath = $InstallerPath }
. $ActivationScript -InstallRoot $InstallRoot -Version $Version @mode
throw 'Receipt fault did not interrupt activation'
"#).map_err(|e| fail(e.to_string()))?;
        let receipt_failure_events =
            fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
        step("receipt-write-failure", &mut || {
            execute_expected_failure(
                runner,
                Path::new("powershell.exe"),
                &[
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-File".into(),
                    receipt_fault_wrapper.to_string_lossy().to_string(),
                    "-ActivationScript".into(),
                    receipt_activation_source.to_string_lossy().to_string(),
                    "-InstallRoot".into(),
                    install_root.to_string_lossy().to_string(),
                    "-Version".into(),
                    version.to_string(),
                    "-ProofPath".into(),
                    receipt_fault_proof.to_string_lossy().to_string(),
                    "-InstallerPath".into(),
                    installer.to_string_lossy().to_string(),
                ]
                .into_iter()
                .chain(if development_install {
                    vec!["-DevelopmentInstall".into()]
                } else {
                    vec![]
                })
                .collect::<Vec<String>>(),
                &workspace_opts,
                "partial activation receipt write failure",
            )
        })?;
        let partial_write_observed = fs::read_to_string(&receipt_fault_proof)
            .map(|proof| proof == "partial activation receipt observed")
            .unwrap_or(false);
        if development_install {
            if !partial_write_observed {
                return Err(fail(
                    "development receipt failure lost candidate or partial-write proof",
                ));
            }
            assert_failed_development_activation(
                &install_root,
                mirror_current.parent().unwrap(),
                workspace,
                &activated_sha256,
                &activation_events,
                &receipt_failure_events,
            )?;
            reinstall("reinstall-after-receipt-failure")?;
            seed_prior_markers()?;
        } else {
            if !partial_write_observed
                || sha256_file(&executable)? != activated_sha256
                || sha256_file(&mirror_executable)? != mirror_before_receipt_failure
                || fs::read_to_string(&rollback_marker).map_err(|e| fail(e.to_string()))?
                    != "prior installed payload"
                || fs::read(install_root.join("activation.json"))
                    .map_err(|e| fail(e.to_string()))?
                    != prior_receipt
            {
                return Err(fail(
                    "partial receipt write failure did not restore exact prior receipt & payloads",
                ));
            }
            assert_fixed_payload_layout(&install_root)?;
            assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
            assert_fixed_activation_receipt(&install_root)?;
        }

        let mut stalled_env = environment.clone();
        stalled_env.insert(
            "LEGION_INSTALL_TEST_MODE".to_string(),
            "stalled-child".to_string(),
        );
        stalled_env.insert(
            "LEGION_INSTALL_CHILD_TIMEOUT_SECONDS".to_string(),
            "1".to_string(),
        );
        let stalled_opts = CommandOptions {
            cwd: Some(workspace.to_path_buf()),
            env: Some(stalled_env),
        };
        let timeout_failure_events =
            fs::read_to_string(&activation_events).map_err(|e| fail(e.to_string()))?;
        step("stalled-child", &mut || {
            execute_expected_failure(
                runner,
                installer,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                    format!("/DIR={}", install_root.display()),
                    format!("/LOG={}", stalled_child_log.display()),
                ],
                &stalled_opts,
                "stalled installer child",
            )
        })?;
        if development_install {
            assert_failed_development_activation(
                &install_root,
                mirror_current.parent().unwrap(),
                workspace,
                &activated_sha256,
                &activation_events,
                &timeout_failure_events,
            )?;
            reinstall("reinstall-after-timeout-failure")?;
        } else {
            if sha256_file(&executable)? != activated_sha256
                || fs::read_to_string(&rollback_marker).map_err(|e| fail(e.to_string()))?
                    != "prior installed payload"
                || fs::read(install_root.join("activation.json"))
                    .map_err(|e| fail(e.to_string()))?
                    != prior_receipt
            {
                return Err(fail(
                    "stalled installer child did not restore current payload & receipt",
                ));
            }
            assert_fixed_payload_layout(&install_root)?;
            assert_fixed_payload_layout(mirror_current.parent().unwrap())?;
            assert_fixed_activation_receipt(&install_root)?;
        }
        assert_stable_runtime_events(&activation_events, &executable)?;

        let repair_run = step("repair", &mut || {
            execute(
                runner,
                &executable,
                &[
                    "--json".into(),
                    "setup".into(),
                    "repair".into(),
                    "--confirm".into(),
                ],
                &install_root_opts,
                "installed legion setup repair",
            )
        })?;
        let repair = setup_payload(
            &repair_run,
            "legion-setup-execution",
            &executable,
            "installed legion setup repair",
            &[],
            &[],
        )?;

        let status_run = step("status", &mut || {
            execute(
                runner,
                &executable,
                &["--json".into(), "setup".into(), "status".into()],
                &install_root_opts,
                "installed legion setup status",
            )
        })?;
        let status = setup_payload(
            &status_run,
            "legion-setup-status",
            &executable,
            "installed legion setup status",
            &[],
            &[],
        )?;

        step("doctor", &mut || {
            execute(
                runner,
                &executable,
                &["doctor".into()],
                &install_root_opts,
                "installed legion doctor",
            )
        })?;

        *current_stage.borrow_mut() = "payload-identity".to_string();
        let payload_identity =
            installed_payload_identity(workspace, &install_root.join("current"))?;

        let uninstaller = install_root.join("unins000.exe");
        if !uninstaller.is_file() {
            return Err(fail(format!(
                "installed uninstaller is missing or unsafe: {}",
                uninstaller.display()
            )));
        }
        step("uninstall", &mut || {
            execute(
                runner,
                &uninstaller,
                &[
                    "/VERYSILENT".into(),
                    "/SUPPRESSMSGBOXES".into(),
                    "/NORESTART".into(),
                ],
                &workspace_opts,
                "silent uninstall",
            )
        })?;
        if !disappears(&install_root, Duration::from_millis(3000)) {
            return Err(fail("silent uninstall left installed product behind"));
        }

        let evidence_path = output.join("qualification.json");
        let commands_stage = |name: &str| -> Value {
            stages
                .borrow()
                .iter()
                .find(|s| s.get("stage").and_then(Value::as_str) == Some(name))
                .cloned()
                .unwrap_or(Value::Null)
        };
        let native_marketplace_states = json!({
            "repair": repair.get("nativeMarketplaces"),
            "status": status.get("nativeMarketplaces"),
        });
        let native_clients = native_clients_unobserved(&profile, &repair, &status)?;
        let evidence = json!({
            "schemaVersion": 1, "kind": "legion-windows-installed-installer-qualification", "status": "qualified",
            "product": "legion", "version": version, "sourceRevision": revision,
            "windowsFinalizationSha256": finalization_sha256,
            "payloadIdentity": payload_identity,
            "setup": {
                "name": installer.file_name().map(|n| n.to_string_lossy().to_string()),
                "sha256": sha256_file(installer)?,
                "size": fs::metadata(installer).map_err(|e| fail(e.to_string()))?.len(),
            },
            "commands": {
                "install": commands_stage("install"),
                "version": commands_stage("version"),
                "concurrentInstallerRejection": commands_stage("concurrent-installer-rejection"),
                "unownedStageRejection": commands_stage("unowned-stage-rejection"),
                "unownedSnapshotRejection": commands_stage("unowned-snapshot-rejection"),
                "foreignJunctionRejection": commands_stage("foreign-junction-rejection"),
                "foreignMirrorJunctionRejection": commands_stage("foreign-mirror-junction-rejection"),
                "stagedValidationFailure": commands_stage("staged-validation-failure"),
                "mirrorSyncFailure": commands_stage("mirror-sync-failure"),
                "sameVersionUpgrade": commands_stage("same-version-upgrade"),
                "interruptedDevelopmentReplacement": commands_stage("interrupted-development-replacement"),
                "interruptedDevelopmentReinstall": commands_stage("interrupted-development-reinstall"),
                "developmentRetryInstallerMismatch": commands_stage("development-retry-installer-mismatch"),
                "developmentRetryMissingContext": commands_stage("development-retry-missing-context"),
                "developmentRetryForeignCurrent": commands_stage("development-retry-foreign-current"),
                "differentCandidateRefreshFailure": commands_stage("different-candidate-refresh-failure"),
                "interruptedCandidateRetry": commands_stage("interrupted-candidate-retry"),
                "developmentRetryMixedPayloads": commands_stage("development-retry-mixed-payloads"),
                "interruptedCandidateRetryReinstall": commands_stage("interrupted-candidate-retry-reinstall"),
                "legacyJunctionFixture": commands_stage("legacy-junction-fixture"),
                "legacyHistoryLinkFixture": commands_stage("legacy-history-link-fixture"),
                "legacyLayoutUpgrade": commands_stage("legacy-layout-upgrade"),
                "pluginRootTransport": commands_stage("plugin-root-transport"),
                "forcedRefreshFailure": commands_stage("forced-refresh-failure"),
                "receiptWriteFailure": commands_stage("receipt-write-failure"),
                "stalledChild": commands_stage("stalled-child"),
                "repair": commands_stage("repair"),
                "status": commands_stage("status"),
                "doctor": commands_stage("doctor"),
                "uninstall": commands_stage("uninstall"),
            },
            "activation": {
                "repair": repair,
                "status": status,
                "nativeClients": native_clients,
                "marketplaceStates": native_marketplace_states,
                "stagedValidationPriorCurrentPreserved": true,
                "stagedValidationRollbackVerified": !development_install,
                "mirrorSyncRollbackVerified": !development_install,
                "developmentCandidatePreservationVerified": development_install,
                "developmentNoPriorCopiesVerified": development_install,
                "developmentReinstallRecoveryVerified": development_install,
                "interruptedDevelopmentReinstallVerified": development_install,
                "differentCandidateRetryOfRetryVerified": development_install,
                "sameVersionUpgradeClean": true,
                "fixedCurrentLayoutVerified": true,
                "concurrentInstallerRejected": true,
                "foreignStatePreserved": true,
                "foreignJunctionRejectedBeforeExecution": true,
                "noPriorPayloadRetentionVerified": true,
                "legacyJunctionMigrationVerified": true,
                "retiredHistoryLinkTargetsPreserved": true,
                "stableRuntimeExecutionVerified": true,
                "nativeMarketplacePayload": native_marketplace_payload,
                "pluginRootTransport": plugin_root_transport.stdout,
                "rollbackVerified": !development_install,
                "partialReceiptWriteRollbackVerified": !development_install,
                "partialReceiptWriteActivationSourceSha256": receipt_activation_source_sha256,
                "stalledChildBounded": true,
            },
        });
        fs::write(
            &evidence_path,
            format!("{}\n", serde_json::to_string_pretty(&evidence).unwrap()),
        )
        .map_err(|e| fail(e.to_string()))?;
        let mut result = evidence.clone();
        result["evidence"] = json!({ "path": evidence_path, "role": "qualification", "size": fs::metadata(&evidence_path).map(|m| m.len()).unwrap_or(0), "sha256": sha256_file(&evidence_path)? });
        Ok(result)
    })();

    match run_result {
        Ok(v) => Ok(v),
        Err(err) => {
            let failure_path = output.join("qualification-failure.json");
            let setup_summary = fs::metadata(installer).ok().map(|m| {
                json!({
                    "name": installer.file_name().map(|n| n.to_string_lossy().to_string()),
                    "sha256": sha256_file(installer).unwrap_or_default(),
                    "size": m.len(),
                })
            });
            let mut logs = serde_json::Map::new();
            for (name, path) in &setup_logs {
                logs.insert(
                    (*name).to_string(),
                    text_tail(path, 32768)
                        .map(Value::String)
                        .unwrap_or(Value::Null),
                );
            }
            let failure = json!({
                "schemaVersion": 1, "kind": "legion-windows-installed-installer-qualification-failure", "status": "failed",
                "product": "legion", "version": version, "sourceRevision": revision,
                "failedStage": current_stage.borrow().clone(), "error": err,
                "setup": setup_summary,
                "completedStages": stages.borrow().clone(),
                "installRoot": install_root,
                "installTree": inventory(&install_root, 0),
                "activationEvents": text_tail(&activation_events, 32768),
                "setupLogs": Value::Object(logs),
                "recordedAt": now_iso8601(),
            });
            let _ = fs::write(
                &failure_path,
                format!("{}\n", serde_json::to_string_pretty(&failure).unwrap()),
            );
            // CI surfaces the xtask error before operators can inspect the
            // qualification receipt. Include only bounded logs emitted by
            // this product installer so activation failures retain their
            // PowerShell cause instead of collapsing to Inno's exit code.
            let diagnostics = qualification_failure_diagnostics(&install_log, &activation_events);
            if diagnostics.is_empty() {
                Err(err)
            } else {
                Err(format!("{err}{diagnostics}"))
            }
        }
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
}

#[cfg(test)]
mod windows_qualification_tests {
    use super::*;

    const IDENTITY_FILES: [(&str, &str); 6] = [
        ("bin/legion.exe", "/runtimeSha256/legion"),
        ("bin/legion-hook.exe", "/runtimeSha256/legion-hook"),
        ("bin/legion-mcp.exe", "/runtimeSha256/legion-mcp"),
        ("share/legion/release.json", "/releaseManifestSha256"),
        (
            "share/legion/assets/skills/debugger/SKILL.md",
            "/capabilityBodySha256/debugger",
        ),
        (
            "share/legion/assets/skills/architect/SKILL.md",
            "/capabilityBodySha256/architect",
        ),
    ];

    fn payload_identity_fixture() -> (PathBuf, PathBuf) {
        let workspace = std::env::temp_dir().join(format!(
            "legion-payload-identity-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let current = workspace.join("installed/current");
        for (relative, _) in IDENTITY_FILES {
            let path = current.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"abc").unwrap();
        }
        (workspace, current)
    }

    #[test]
    fn payload_identity_hashes_each_final_payload_file_and_changes_with_bytes() {
        let (workspace, current) = payload_identity_fixture();
        let original = installed_payload_identity(&workspace, &current).unwrap();
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let abcd = "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589";
        assert_eq!(
            original,
            json!({
                "runtimeSha256": {"legion": abc, "legion-hook": abc, "legion-mcp": abc},
                "releaseManifestSha256": abc,
                "capabilityBodySha256": {"debugger": abc, "architect": abc},
            })
        );
        for (relative, field) in IDENTITY_FILES {
            let path = current.join(relative);
            fs::write(&path, b"abcd").unwrap();
            let changed = installed_payload_identity(&workspace, &current).unwrap();
            let mut expected = original.clone();
            *expected.pointer_mut(field).unwrap() = json!(abcd);
            assert_eq!(changed, expected, "changed payload file: {relative}");
            fs::write(path, b"abc").unwrap();
        }
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn payload_identity_rejects_missing_and_nonregular_inputs() {
        let (workspace, current) = payload_identity_fixture();
        for (relative, _) in IDENTITY_FILES {
            let path = current.join(relative);
            fs::remove_file(&path).unwrap();
            assert!(installed_payload_identity(&workspace, &current).is_err());
            fs::create_dir(&path).unwrap();
            assert!(installed_payload_identity(&workspace, &current).is_err());
            fs::remove_dir(&path).unwrap();
            fs::write(path, b"abc").unwrap();
        }
        assert!(payload_file_sha256(&current, Path::new("../outside.exe")).is_err());
        assert!(payload_file_sha256(&current, &current.join("bin/legion.exe")).is_err());
        assert!(installed_payload_identity(&current, &workspace).is_err());
        fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn payload_identity_rejects_file_symlinks_even_to_matching_bytes() {
        let (workspace, current) = payload_identity_fixture();
        let outside = workspace.join("outside.exe");
        fs::write(&outside, b"abc").unwrap();
        let runtime = current.join("bin/legion.exe");
        fs::remove_file(&runtime).unwrap();
        std::os::unix::fs::symlink(&outside, &runtime).unwrap();
        assert!(installed_payload_identity(&workspace, &current).is_err());
        fs::remove_file(runtime).unwrap();
        fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(any(unix, windows))]
    fn link_identity_directory(target: &Path, link: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        {
            // Junctions require no developer-mode/admin symlink privilege &
            // exercise FILE_ATTRIBUTE_REPARSE_POINT rather than only symlinks.
            let result = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "junction fixture failed: {result:?}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    fn remove_identity_directory_link(link: &Path) {
        #[cfg(unix)]
        fs::remove_file(link).unwrap();
        #[cfg(windows)]
        fs::remove_dir(link).unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn payload_identity_rejects_current_parent_and_nested_directory_links() {
        let (workspace, current) = payload_identity_fixture();
        for relative in [
            "installed/current/bin",
            "installed/current/share/legion/assets/skills/debugger",
            "installed/current",
            "installed",
        ] {
            let original = workspace.join(relative);
            let outside = workspace.join("foreign-payload");
            fs::rename(&original, &outside).unwrap();
            link_identity_directory(&outside, &original);
            assert!(installed_payload_identity(&workspace, &current).is_err());
            remove_identity_directory_link(&original);
            fs::rename(&outside, &original).unwrap();
        }
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn development_failure_requires_failed_receipt_events_and_no_prior_copies() {
        let workspace = std::env::temp_dir().join(format!(
            "legion-development-failure-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let root = workspace.join("installed");
        let mirror = workspace.join("mirror");
        for product in [&root, &mirror] {
            fs::create_dir_all(product.join("current/bin")).unwrap();
            fs::create_dir_all(product.join("current/share/legion")).unwrap();
            fs::write(product.join("current/bin/legion.exe"), "candidate runtime").unwrap();
            fs::write(
                product.join("current/share/legion/release.json"),
                r#"{"releaseVersion":"1.2.3"}"#,
            )
            .unwrap();
        }
        let receipt = root.join("activation.json");
        let failed_receipt = json!({
            "state": "failed", "recovery": "reinstall", "current": root.join("current"),
            "target": root.join("current"), "previous": null,
        });
        fs::write(&receipt, failed_receipt.to_string()).unwrap();
        let events = workspace.join("events.jsonl");
        fs::write(&events, "{\"stage\":\"activation\",\"status\":\"failed\"}\n{\"stage\":\"recovery\",\"status\":\"required\"}\n").unwrap();
        let digest = sha256_file(&root.join("current/bin/legion.exe")).unwrap();
        assert!(assert_failed_development_activation(
            &root, &mirror, &workspace, &digest, &events, ""
        )
        .is_ok());
        let saved = workspace.join("installer-temp/prior");
        fs::create_dir_all(&saved).unwrap();
        fs::write(saved.join(PRIOR_PAYLOAD_MARKER), "old payload").unwrap();
        assert!(assert_failed_development_activation(
            &root, &mirror, &workspace, &digest, &events, ""
        )
        .is_err());
        fs::remove_dir_all(saved).unwrap();
        let mut stale_receipt = failed_receipt;
        stale_receipt["state"] = json!("activated");
        fs::write(&receipt, stale_receipt.to_string()).unwrap();
        assert!(assert_failed_development_activation(
            &root, &mirror, &workspace, &digest, &events, ""
        )
        .is_err());
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn resolved_workspace_preserves_strict_receipt_and_runtime_bindings() {
        let fixture = std::env::temp_dir().join(format!(
            "legion-qualification-paths-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        fs::create_dir_all(fixture.join("alias-parent")).unwrap();
        fs::create_dir_all(fixture.join("workspace/current/bin")).unwrap();
        fs::create_dir_all(fixture.join("workspace/current.previous/bin")).unwrap();
        // Exercise alternate spelling even when this host has no 8.3 aliases.
        let input = fixture.join("alias-parent/../workspace");
        let workspace = canonical_qualification_workspace(&input).unwrap();
        let current = workspace.join("current");
        let previous = workspace.join("current.previous");
        let receipt = workspace.join("activation.json");
        fs::write(
            &receipt,
            json!({
                "state": "activated", "current": current, "target": current, "previous": null,
            })
            .to_string(),
        )
        .unwrap();
        assert!(assert_fixed_activation_receipt(&workspace).is_ok());
        assert!(assert_fixed_activation_receipt(&input).is_err());
        fs::write(
            &receipt,
            json!({
                "state": "activated", "current": current, "target": current, "previous": previous,
            })
            .to_string(),
        )
        .unwrap();
        assert!(assert_fixed_activation_receipt(&workspace).is_err());
        assert!(assert_fixed_activation_receipt(&input).is_err());
        fs::write(
            &receipt,
            json!({
                "state": "activated", "current": previous, "target": current, "previous": previous,
            })
            .to_string(),
        )
        .unwrap();
        assert!(assert_fixed_activation_receipt(&workspace).is_err());
        fs::write(
            &receipt,
            json!({
                "state": "activated", "current": current, "target": previous, "previous": previous,
            })
            .to_string(),
        )
        .unwrap();
        assert!(assert_fixed_activation_receipt(&workspace).is_err());
        let events = workspace.join("events.jsonl");
        let executable = current.join("bin/legion.exe");
        fs::write(&events, json!({
            "status": "started", "detail": format!("executable={}; timeout=600s", executable.display()),
        }).to_string()).unwrap();
        assert!(assert_stable_runtime_events(&events, &executable).is_ok());
        fs::write(&events, json!({
            "status": "started", "detail": format!("executable={}; timeout=600s", previous.join("bin/legion.exe").display()),
        }).to_string()).unwrap();
        assert!(assert_stable_runtime_events(&events, &executable).is_err());
        assert!(canonical_qualification_workspace(&workspace.join("missing")).is_err());
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn windows_environment_replaces_case_insensitively() {
        let base = HashMap::from([
            ("LocalAppData".to_string(), "real".to_string()),
            ("USERPROFILE".to_string(), "real-profile".to_string()),
            ("Path".to_string(), "real-path".to_string()),
            ("KEEP".to_string(), "yes".to_string()),
        ]);
        let overrides = HashMap::from([
            ("LOCALAPPDATA".to_string(), "isolated".to_string()),
            ("USERPROFILE".to_string(), "isolated-profile".to_string()),
            ("PATH".to_string(), "isolated-path".to_string()),
        ]);
        let env = windows_environment(&base, &overrides);
        assert_eq!(env.get("KEEP"), Some(&"yes".to_string()));
        assert_eq!(env.get("LOCALAPPDATA"), Some(&"isolated".to_string()));
        assert_eq!(
            env.get("USERPROFILE"),
            Some(&"isolated-profile".to_string())
        );
        assert_eq!(env.get("PATH"), Some(&"isolated-path".to_string()));
        assert_eq!(env.len(), 4);
    }

    #[test]
    fn a_failed_qualification_writes_failure_evidence_before_cleanup() {
        let root = std::env::temp_dir().join(format!(
            "legion-qualify-evidence-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        fs::create_dir_all(&root).unwrap();
        let setup = root.join("Legion-setup.exe");
        fs::write(&setup, "not a real installer").unwrap();
        let finalization_path = root.join("finalization.json");
        fs::write(
            &finalization_path,
            serde_json::to_string(&json!({
                "schemaVersion": 1, "kind": "legion-installer-finalization", "product": "legion", "platform": "windows",
                "version": "0.3.12", "sourceRevision": "a".repeat(40),
                "assets": [{ "role": "installer", "name": "Legion-setup.exe" }],
            })).unwrap(),
        ).unwrap();
        let output_root = root.join("out");

        let runner = |_cmd: &str, _args: &[String], _opts: &CommandOptions| {
            crate::process_boundary::CommandResult {
                error_message: None,
                status: Some(1),
                signal: None,
                stdout: Some(String::new()),
                stderr: Some("installer exited 2".to_string()),
            }
        };

        let result = qualify_installed_windows(
            &runner,
            QualifyInstalledWindowsInput {
                setup: Some(setup),
                output_root: Some(output_root.clone()),
                finalization_path: Some(finalization_path),
                source_revision: "a".repeat(40),
                version: "0.3.12".to_string(),
                platform_is_windows: true,
            },
        );
        assert!(result.is_err());
        assert!(
            output_root.join("qualification-failure.json").exists(),
            "qualification-failure.json must exist after a failed run"
        );
    }
}
