//! Rust port of `scripts/release/windows/qualify-installed.mjs`: runs a
//! finalized Windows installer through all nine qualification stages
//! (install, version, forced-refresh-failure, stalled-child, repair, status,
//! codex-plugin-opt-in, doctor, uninstall) in an isolated
//! `LOCALAPPDATA`/`USERPROFILE`, and writes either `qualification.json` or,
//! on failure, `qualification-failure.json` with captured evidence — Phase A
//! item 9: a failed run must leave a readable receipt instead of silently
//! deleting its workspace. Ported 1:1, including the full per-stage
//! `commandEvidence` trail and the `setupPayload` structural validation of
//! repair/status/codex-plugin-repair JSON responses.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::paths::{is_revision_hex, is_stable_semver, sha256_file, CommandOptions, CommandRunner, ReleaseResult};
use crate::process_boundary::{command_diagnostic, command_evidence};

fn fail(message: impl Into<String>) -> String {
    format!("windows-installed-qualification: {}", message.into())
}

/// Mirrors `windowsEnvironment`: replaces keys of `base` with `overrides`,
/// matching case-insensitively (Windows env vars are case-insensitive; a
/// stray `Path`/`LocalAppData` in the real environment must not survive
/// alongside an isolated `PATH`/`LOCALAPPDATA`).
pub fn windows_environment(base: &HashMap<String, String>, overrides: &HashMap<String, String>) -> HashMap<String, String> {
    let replaced: std::collections::HashSet<String> = overrides.keys().map(|k| k.to_lowercase()).collect();
    let mut out: HashMap<String, String> = base.iter().filter(|(k, _)| !replaced.contains(&k.to_lowercase())).map(|(k, v)| (k.clone(), v.clone())).collect();
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
        Some(value[value.len() - max_bytes..].to_string())
    }
}

fn finalization(path: &Path, version: &str, source_revision: &str) -> ReleaseResult<Value> {
    let text = fs::read_to_string(path).map_err(|e| fail(format!("Windows finalization manifest could not be read: {e}")))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| fail(format!("Windows finalization manifest is invalid JSON: {e}")))?;
    let ok = value.get("schemaVersion").and_then(Value::as_i64) == Some(1)
        && value.get("kind").and_then(Value::as_str) == Some("legion-installer-finalization")
        && value.get("product").and_then(Value::as_str) == Some("legion")
        && value.get("platform").and_then(Value::as_str) == Some("windows")
        && value.get("version").and_then(Value::as_str) == Some(version)
        && value.get("sourceRevision").and_then(Value::as_str).map(|s| s.to_lowercase()) == Some(source_revision.to_string())
        && value.get("assets").and_then(Value::as_array).is_some();
    if !ok {
        return Err(fail("Windows finalization manifest identity is invalid"));
    }
    let installers = value.get("assets").and_then(Value::as_array).unwrap().iter().filter(|a| a.get("role").and_then(Value::as_str) == Some("installer")).count();
    if installers != 1 {
        return Err(fail("Windows finalization must contain exactly one installer"));
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

pub fn qualify_installed_windows(runner: CommandRunner, input: QualifyInstalledWindowsInput) -> ReleaseResult<Value> {
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
    let installer = input.setup.clone().ok_or_else(|| fail("--setup is required"))?;
    if !installer.is_file() {
        return Err(fail(format!("setup EXE is missing or unsafe: {}", installer.display())));
    }
    if !installer.to_string_lossy().to_lowercase().ends_with(".exe") {
        return Err(fail("setup must be an EXE"));
    }
    let output = input.output_root.clone().ok_or_else(|| fail("--output-root is required"))?;
    fs::create_dir_all(&output).map_err(|e| fail(e.to_string()))?;
    if output.join("qualification.json").exists() {
        return Err(fail("qualification evidence already exists"));
    }
    let finalization_file = input.finalization_path.clone().ok_or_else(|| fail("--finalization is required"))?;
    finalization(&finalization_file, &input.version, &revision)?;
    let finalization_sha256 = sha256_file(&finalization_file)?;

    let workspace = std::env::temp_dir().join(format!("legion-installed-qualification-{}-{}", std::process::id(), rand_suffix()));
    fs::create_dir_all(&workspace).map_err(|e| fail(e.to_string()))?;
    let result = qualify_inner(runner, &installer, &output, &input.version, &revision, &finalization_sha256, &workspace);
    let _ = fs::remove_dir_all(&workspace);
    result
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

fn execute(runner: CommandRunner, executable: &Path, args: &[String], options: &CommandOptions, label: &str) -> ReleaseResult<StepOutcome> {
    let result = runner(&executable.to_string_lossy(), args, options);
    if result.error_message.is_some() || result.status != Some(0) {
        return Err(fail(format!("{label} failed: {}", command_diagnostic(&result))));
    }
    let evidence = serde_json::to_value(command_evidence(&result)).unwrap();
    Ok(StepOutcome { stdout: result.stdout.unwrap_or_default().trim().to_string(), stderr: result.stderr.unwrap_or_default().trim().to_string(), evidence })
}

fn execute_expected_failure(runner: CommandRunner, executable: &Path, args: &[String], options: &CommandOptions, label: &str) -> ReleaseResult<StepOutcome> {
    let result = runner(&executable.to_string_lossy(), args, options);
    if result.error_message.is_some() {
        return Err(fail(format!("{label} did not return control: {}", command_diagnostic(&result))));
    }
    if result.status == Some(0) {
        return Err(fail(format!("{label} falsely reported success")));
    }
    let evidence = serde_json::to_value(command_evidence(&result)).unwrap();
    Ok(StepOutcome { stdout: result.stdout.unwrap_or_default().trim().to_string(), stderr: result.stderr.unwrap_or_default().trim().to_string(), evidence })
}

/// Mirrors `setupPayload`: parses a repair/status JSON response, asserts
/// complete installed activation bound to the stable-current executable,
/// structural client activation for `requiredClients`, and current-state
/// projections for `requiredProjections`; returns the same trimmed summary
/// shape the JS returns for embedding into the final evidence bundle.
fn setup_payload(run: &StepOutcome, kind: &str, executable: &Path, label: &str, required_clients: &[&str], required_projections: &[&str]) -> ReleaseResult<Value> {
    let value: Value = serde_json::from_str(&run.stdout).map_err(|e| fail(format!("{label} did not return JSON: {e}")))?;
    if value.get("kind").and_then(Value::as_str) != Some(kind) || value.get("status").and_then(Value::as_str) != Some("complete") || value.get("origin").and_then(Value::as_str) != Some("installed") {
        return Err(fail(format!("{label} did not report complete installed activation")));
    }
    let value_executable = value.get("executable").and_then(Value::as_str).unwrap_or("");
    let executable_matches = Path::new(value_executable) == executable || PathBuf::from(value_executable).file_name() == executable.file_name();
    if !executable_matches || value.get("stableCurrent") != Some(&Value::Bool(true)) {
        return Err(fail(format!("{label} did not bind stable current executable")));
    }
    let clients = if kind == "legion-setup-execution" { value.get("execution").and_then(|e| e.get("clients")) } else { value.get("clients") };
    let clients_array = clients.and_then(Value::as_array).cloned().unwrap_or_default();
    for client_id in required_clients {
        let client = clients_array.iter().find(|item| {
            let id = item.get("clientId").and_then(Value::as_str).or_else(|| item.get("client_id").and_then(Value::as_str));
            id == Some(*client_id)
        });
        let ok = client.map(|c| c.get("installed") == Some(&Value::Bool(true)) && c.get("fidelity").and_then(Value::as_str) == Some("Full")).unwrap_or(false);
        if !ok {
            return Err(fail(format!("{label} did not structurally activate {client_id}")));
        }
    }
    let projections = value.get("liveIdentity").and_then(|l| l.get("projections")).cloned().unwrap_or(json!({}));
    for projection in required_projections {
        if projections.get(projection).and_then(|p| p.get("state")).and_then(Value::as_str) != Some("current") {
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
        .map(|obj| Value::Object(obj.iter().map(|(k, v)| (k.clone(), v.get("state").cloned().unwrap_or(Value::Null))).collect()))
        .unwrap_or(json!({}));
    Ok(json!({
        "kind": value.get("kind"),
        "status": value.get("status"),
        "origin": value.get("origin"),
        "executable": value.get("executable"),
        "stableCurrent": value.get("stableCurrent"),
        "clients": clients_out,
        "projections": projections_out,
        "authenticatedLiveQualification": value.get("authenticatedLiveQualification").and_then(|a| a.get("status")).cloned().unwrap_or(Value::Null),
    }))
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
    let Ok(entries) = fs::read_dir(root) else { return Value::Array(vec![]) };
    let mut out = vec![];
    for entry in entries.flatten() {
        let path = entry.path();
        let mut link_type = Value::Null;
        let mut target = Value::Null;
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.is_symlink() {
                link_type = Value::String("link".to_string());
                target = fs::read_link(&path).map(|p| Value::String(p.to_string_lossy().to_string())).unwrap_or(Value::Null);
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

#[allow(clippy::too_many_arguments)]
fn qualify_inner(runner: CommandRunner, installer: &Path, output: &Path, version: &str, revision: &str, finalization_sha256: &str, workspace: &Path) -> ReleaseResult<Value> {
    let local_app_data = workspace.join("local-app-data");
    let install_root = local_app_data.join("Orthic Labs").join("Legion");
    let profile = workspace.join("profile");
    for client_root in [".claude", ".codex"] {
        fs::create_dir_all(profile.join(client_root)).map_err(|e| fail(e.to_string()))?;
    }
    let executable = install_root.join("current").join("bin").join("legion.exe");
    let install_log = output.join("setup-install.log");
    let activation_events = output.join("activation-events.jsonl");
    let forced_refresh_failure_log = output.join("setup-forced-refresh-failure.log");
    let stalled_child_log = output.join("setup-stalled-child.log");
    let setup_logs: Vec<(&str, &PathBuf)> = vec![
        ("install", &install_log),
        ("activationEvents", &activation_events),
        ("forcedRefreshFailure", &forced_refresh_failure_log),
        ("stalledChild", &stalled_child_log),
    ];

    let base_env: HashMap<String, String> = std::env::vars().collect();
    let mut overrides = HashMap::new();
    overrides.insert("LOCALAPPDATA".to_string(), local_app_data.to_string_lossy().to_string());
    overrides.insert("USERPROFILE".to_string(), profile.to_string_lossy().to_string());
    overrides.insert("LEGION_STATE_ROOT".to_string(), local_app_data.join("Legion").to_string_lossy().to_string());
    overrides.insert("LEGION_INSTALL_EVENT_LOG".to_string(), activation_events.to_string_lossy().to_string());
    let path_sep = if cfg!(windows) { ";" } else { ":" };
    overrides.insert("PATH".to_string(), format!("{}{path_sep}{}", install_root.join("current").join("bin").display(), base_env.get("PATH").cloned().unwrap_or_default()));
    let environment = windows_environment(&base_env, &overrides);
    let workspace_opts = CommandOptions { cwd: Some(workspace.to_path_buf()), env: Some(environment.clone()) };
    let install_root_opts = CommandOptions { cwd: Some(install_root.clone()), env: Some(environment.clone()) };

    let stages: std::cell::RefCell<Vec<Value>> = std::cell::RefCell::new(vec![]);
    let current_stage = std::cell::RefCell::new("setup".to_string());
    let step = |stage: &str, run: &mut dyn FnMut() -> ReleaseResult<StepOutcome>| -> ReleaseResult<StepOutcome> {
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
        let install_run = step("install", &mut || {
            execute(
                runner,
                installer,
                &["/VERYSILENT".into(), "/SUPPRESSMSGBOXES".into(), "/NORESTART".into(), format!("/DIR={}", install_root.display()), format!("/LOG={}", install_log.display())],
                &workspace_opts,
                "silent setup",
            )
        })?;
        let _ = install_run;
        if !executable.is_file() {
            return Err(fail(format!("installed legion.exe is missing or unsafe: {}", executable.display())));
        }

        step("version", &mut || execute(runner, &executable, &["--version".into()], &install_root_opts, "installed legion --version"))?;
        let activated_sha256 = sha256_file(&executable)?;

        let mut forced_env = environment.clone();
        forced_env.insert("LEGION_INSTALL_TEST_MODE".to_string(), "refresh-failure".to_string());
        let forced_opts = CommandOptions { cwd: Some(workspace.to_path_buf()), env: Some(forced_env) };
        step("forced-refresh-failure", &mut || {
            execute_expected_failure(
                runner,
                installer,
                &["/VERYSILENT".into(), "/SUPPRESSMSGBOXES".into(), "/NORESTART".into(), format!("/DIR={}", install_root.display()), format!("/LOG={}", forced_refresh_failure_log.display())],
                &forced_opts,
                "forced client refresh failure",
            )
        })?;
        if sha256_file(&executable)? != activated_sha256 {
            return Err(fail("forced client refresh failure did not restore previous activation"));
        }

        let mut stalled_env = environment.clone();
        stalled_env.insert("LEGION_INSTALL_TEST_MODE".to_string(), "stalled-child".to_string());
        stalled_env.insert("LEGION_INSTALL_CHILD_TIMEOUT_SECONDS".to_string(), "1".to_string());
        let stalled_opts = CommandOptions { cwd: Some(workspace.to_path_buf()), env: Some(stalled_env) };
        step("stalled-child", &mut || {
            execute_expected_failure(
                runner,
                installer,
                &["/VERYSILENT".into(), "/SUPPRESSMSGBOXES".into(), "/NORESTART".into(), format!("/DIR={}", install_root.display()), format!("/LOG={}", stalled_child_log.display())],
                &stalled_opts,
                "stalled installer child",
            )
        })?;
        if sha256_file(&executable)? != activated_sha256 {
            return Err(fail("stalled installer child did not restore previous activation"));
        }

        let repair_run = step("repair", &mut || execute(runner, &executable, &["--json".into(), "setup".into(), "repair".into(), "--confirm".into()], &install_root_opts, "installed legion setup repair"))?;
        let repair = setup_payload(&repair_run, "legion-setup-execution", &executable, "installed legion setup repair", &["claude-code", "codex"], &["claudePlugin"])?;

        let status_run = step("status", &mut || execute(runner, &executable, &["--json".into(), "setup".into(), "status".into()], &install_root_opts, "installed legion setup status"))?;
        let status = setup_payload(&status_run, "legion-setup-status", &executable, "installed legion setup status", &["claude-code", "codex"], &["claudePlugin"])?;

        fs::create_dir_all(profile.join(".codex").join("plugins").join("legion")).map_err(|e| fail(e.to_string()))?;
        let codex_plugin_repair_run = step("codex-plugin-opt-in", &mut || {
            execute(runner, &executable, &["--json".into(), "setup".into(), "repair".into(), "--confirm".into(), "--client".into(), "codex".into()], &install_root_opts, "installed legion setup repair for codex plugin")
        })?;
        let codex_plugin_repair = setup_payload(&codex_plugin_repair_run, "legion-setup-execution", &executable, "installed legion setup repair for codex plugin", &["codex"], &["codexPlugin"])?;

        step("doctor", &mut || execute(runner, &executable, &["doctor".into()], &install_root_opts, "installed legion doctor"))?;

        let uninstaller = install_root.join("unins000.exe");
        if !uninstaller.is_file() {
            return Err(fail(format!("installed uninstaller is missing or unsafe: {}", uninstaller.display())));
        }
        step("uninstall", &mut || execute(runner, &uninstaller, &["/VERYSILENT".into(), "/SUPPRESSMSGBOXES".into(), "/NORESTART".into()], &workspace_opts, "silent uninstall"))?;
        if !disappears(&install_root, Duration::from_millis(3000)) {
            return Err(fail("silent uninstall left installed product behind"));
        }

        let evidence_path = output.join("qualification.json");
        let commands_stage = |name: &str| -> Value { stages.borrow().iter().find(|s| s.get("stage").and_then(Value::as_str) == Some(name)).cloned().unwrap_or(Value::Null) };
        let evidence = json!({
            "schemaVersion": 1, "kind": "legion-windows-installed-installer-qualification", "status": "qualified",
            "product": "legion", "version": version, "sourceRevision": revision,
            "windowsFinalizationSha256": finalization_sha256,
            "setup": {
                "name": installer.file_name().map(|n| n.to_string_lossy().to_string()),
                "sha256": sha256_file(installer)?,
                "size": fs::metadata(installer).map_err(|e| fail(e.to_string()))?.len(),
            },
            "commands": {
                "install": commands_stage("install"),
                "version": commands_stage("version"),
                "forcedRefreshFailure": commands_stage("forced-refresh-failure"),
                "stalledChild": commands_stage("stalled-child"),
                "repair": commands_stage("repair"),
                "status": commands_stage("status"),
                "codexPluginOptIn": commands_stage("codex-plugin-opt-in"),
                "doctor": commands_stage("doctor"),
                "uninstall": commands_stage("uninstall"),
            },
            "activation": { "repair": repair, "status": status, "codexPluginRepair": codex_plugin_repair, "rollbackVerified": true, "stalledChildBounded": true },
        });
        fs::write(&evidence_path, format!("{}\n", serde_json::to_string_pretty(&evidence).unwrap())).map_err(|e| fail(e.to_string()))?;
        let mut result = evidence.clone();
        result["evidence"] = json!({ "path": evidence_path, "role": "qualification", "size": fs::metadata(&evidence_path).map(|m| m.len()).unwrap_or(0), "sha256": sha256_file(&evidence_path)? });
        Ok(result)
    })();

    match run_result {
        Ok(v) => Ok(v),
        Err(err) => {
            let failure_path = output.join("qualification-failure.json");
            let setup_summary = fs::metadata(installer).ok().map(|m| json!({
                "name": installer.file_name().map(|n| n.to_string_lossy().to_string()),
                "sha256": sha256_file(installer).unwrap_or_default(),
                "size": m.len(),
            }));
            let mut logs = serde_json::Map::new();
            for (name, path) in &setup_logs {
                logs.insert((*name).to_string(), text_tail(path, 32768).map(Value::String).unwrap_or(Value::Null));
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
            let _ = fs::write(&failure_path, format!("{}\n", serde_json::to_string_pretty(&failure).unwrap()));
            Err(err)
        }
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(env.get("USERPROFILE"), Some(&"isolated-profile".to_string()));
        assert_eq!(env.get("PATH"), Some(&"isolated-path".to_string()));
        assert_eq!(env.len(), 4);
    }

    #[test]
    fn a_failed_qualification_writes_failure_evidence_before_cleanup() {
        let root = std::env::temp_dir().join(format!("legion-qualify-evidence-{}-{}", std::process::id(), rand_suffix()));
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

        let runner = |_cmd: &str, _args: &[String], _opts: &CommandOptions| crate::process_boundary::CommandResult {
            error_message: None,
            status: Some(1),
            signal: None,
            stdout: Some(String::new()),
            stderr: Some("installer exited 2".to_string()),
        };

        let result = qualify_installed_windows(&runner, QualifyInstalledWindowsInput {
            setup: Some(setup),
            output_root: Some(output_root.clone()),
            finalization_path: Some(finalization_path),
            source_revision: "a".repeat(40),
            version: "0.3.12".to_string(),
            platform_is_windows: true,
        });
        assert!(result.is_err());
        assert!(output_root.join("qualification-failure.json").exists(), "qualification-failure.json must exist after a failed run");
    }
}
