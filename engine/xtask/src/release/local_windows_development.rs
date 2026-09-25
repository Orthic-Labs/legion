//! Rust port of `scripts/release/local-windows-development.mjs`: the
//! Windows-only inner-loop path from a dirty source tree to an installed,
//! stable-current Legion, run entirely unsigned for local iteration.
//!
//! Native binary assembly now shells out to the built `xtask` binary's own
//! `assemble-native-release` subcommand (self-exec via `current_exe()`)
//! instead of `node scripts/assemble-native-release.mjs`, per the
//! now-ported `assemble_native_release.rs`. The Inno Setup build and
//! installed-qualification steps call `windows_finalize_installer` and
//! `windows_qualify_installed` in-process rather than spawning `node`
//! workers, matching the rest of this crate's release modules.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{json, Value};

use super::paths::{is_revision_hex, is_stable_semver, sha256_file, CommandOptions, CommandRunner, ReleaseResult};
use super::windows_finalize_installer::{finalize_windows_installer, FinalizeWindowsInstallerInput};
use super::windows_qualify_installed::{qualify_installed_windows, QualifyInstalledWindowsInput};
use crate::process_boundary::command_diagnostic;

const ARCHITECTURE: &str = "x86_64";
const TARGET: &str = "x86_64-pc-windows-msvc";

fn fail(message: impl Into<String>) -> String {
    format!("local-windows-development: {}", message.into())
}

fn assert_below(root: &Path, path: &Path, label: &str) -> ReleaseResult<PathBuf> {
    if !path.starts_with(root) {
        return Err(fail(format!("{label} escapes {}", root.display())));
    }
    Ok(path.to_path_buf())
}

fn assert_file(path: &Path, label: &str) -> ReleaseResult<PathBuf> {
    let meta = fs::symlink_metadata(path).map_err(|_| fail(format!("{label} is missing or unsafe: {}", path.display())))?;
    if meta.is_symlink() || !meta.is_file() {
        return Err(fail(format!("{label} is missing or unsafe: {}", path.display())));
    }
    Ok(path.to_path_buf())
}

/// Mirrors `resolveInnoCompiler`: probes well-known Inno Setup 6 install
/// locations before falling back to `where.exe iscc.exe`.
pub fn resolve_inno_compiler(env: &HashMap<String, String>, where_exe: impl Fn() -> Option<String>) -> ReleaseResult<PathBuf> {
    let mut candidates: Vec<PathBuf> = vec![];
    if let Some(v) = env.get("INNO_SETUP_PATH") {
        candidates.push(PathBuf::from(v));
    }
    if let Some(v) = env.get("ChocolateyInstall") {
        candidates.push(Path::new(v).join("bin").join("iscc.exe"));
    }
    if let Some(v) = env.get("LOCALAPPDATA") {
        candidates.push(Path::new(v).join("Programs").join("Inno").join("ISCC.exe"));
        candidates.push(Path::new(v).join("Programs").join("Inno Setup 6").join("ISCC.exe"));
    }
    if let Some(v) = env.get("ProgramFiles") {
        candidates.push(Path::new(v).join("Inno Setup 6").join("ISCC.exe"));
    }
    if let Some(v) = env.get("ProgramFiles(x86)") {
        candidates.push(Path::new(v).join("Inno Setup 6").join("ISCC.exe"));
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Some(discovered) = where_exe() {
        let discovered = discovered.trim();
        if !discovered.is_empty() && Path::new(discovered).exists() {
            return Ok(PathBuf::from(discovered));
        }
    }
    Err(fail("Inno Setup 6 compiler is missing; install workspace Windows installer prerequisite or set INNO_SETUP_PATH"))
}

fn record(path: &Path, role: &'static str) -> ReleaseResult<Value> {
    Ok(json!({ "path": path, "role": role, "size": fs::metadata(path).map_err(|e| fail(e.to_string()))?.len(), "sha256": sha256_file(path)? }))
}

/// Mirrors `localFinalization`: the unsigned finalization manifest shape for
/// the internal-unsigned local development route (no signing evidence).
pub fn local_finalization(installer: &Path, release_version: &str, source_revision: &str) -> ReleaseResult<Value> {
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-installer-finalization",
        "status": "local-unsigned",
        "profile": "internal-unsigned",
        "product": "legion",
        "platform": "windows",
        "version": release_version,
        "sourceRevision": source_revision,
        "architecture": ARCHITECTURE,
        "signing": { "status": "unsigned", "reason": "internal_local_unsigned_route" },
        "assets": [record(installer, "installer")?],
        "evidence": [],
    }))
}

fn assert_local_authorization(root: &Path) -> ReleaseResult<()> {
    let path = root.join(".rightkit-local-development.json");
    let file = assert_file(&path, "local development declaration")?;
    let text = fs::read_to_string(&file).map_err(|e| fail(e.to_string()))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| fail(format!("invalid local development declaration: {e}")))?;
    let ok = value.get("schemaVersion").and_then(Value::as_i64) == Some(1)
        && value.get("repository").and_then(Value::as_str) == Some("Orthic-Labs/legion")
        && value.get("platform").and_then(Value::as_str) == Some("win32")
        && value.get("purpose").and_then(Value::as_str) == Some("unsigned-installer");
    if !ok {
        return Err(fail("local development declaration does not authorize Legion Windows unsigned installer work"));
    }
    Ok(())
}

fn version(root: &Path) -> ReleaseResult<String> {
    let path = root.join("release").join("version.json");
    let text = fs::read_to_string(&path).map_err(|e| fail(format!("release/version.json could not be read: {e}")))?;
    let value: Value = serde_json::from_str(&text).map_err(|_| fail("release/version.json is invalid"))?;
    let ok = value.get("schemaVersion").and_then(Value::as_i64) == Some(1) && value.get("kind").and_then(Value::as_str) == Some("legion-release-version");
    let v = value.get("version").and_then(Value::as_str).unwrap_or("");
    if !ok || !is_stable_semver(v) {
        return Err(fail("release/version.json is invalid"));
    }
    Ok(v.to_string())
}

pub struct SourceState {
    pub revision: String,
    pub dirty: bool,
}

fn source_state(runner: CommandRunner, root: &Path) -> ReleaseResult<SourceState> {
    let options = CommandOptions { cwd: Some(root.to_path_buf()), env: None };
    let rev_result = runner("git", &["rev-parse".to_string(), "HEAD".to_string()], &options);
    if rev_result.error_message.is_some() || rev_result.status != Some(0) {
        return Err(fail(format!("source revision failed: {}", command_diagnostic(&rev_result))));
    }
    let revision = rev_result.stdout.unwrap_or_default().trim().to_lowercase();
    if !is_revision_hex(&revision) {
        return Err(fail("source revision is invalid"));
    }
    let status_result = runner("git", &["status".to_string(), "--porcelain".to_string(), "--untracked-files=normal".to_string()], &options);
    if status_result.error_message.is_some() || status_result.status != Some(0) {
        return Err(fail(format!("source status failed: {}", command_diagnostic(&status_result))));
    }
    let dirty = !status_result.stdout.unwrap_or_default().trim().is_empty();
    Ok(SourceState { revision, dirty })
}

fn run_labeled(runner: CommandRunner, command: &str, args: &[String], options: &CommandOptions, label: &str) -> ReleaseResult<crate::process_boundary::CommandResult> {
    let result = runner(command, args, options);
    if result.error_message.is_some() || result.status != Some(0) {
        return Err(fail(format!("{label} failed: {}", command_diagnostic(&result))));
    }
    Ok(result)
}

fn run_json_labeled(runner: CommandRunner, command: &str, args: &[String], options: &CommandOptions, label: &str) -> ReleaseResult<Value> {
    let result = run_labeled(runner, command, args, options, label)?;
    let stdout = result.stdout.unwrap_or_default();
    serde_json::from_str(stdout.trim()).map_err(|_| fail(format!("{label} did not emit JSON: {}", stdout.trim())))
}

/// Emits the same `{"schema":"legion.local-windows-phase.v1", "phase", "elapsedMs"}`
/// line to stdout the JS `phase()` wrapper wrote, after running `action`.
fn phase<T>(name: &str, action: impl FnOnce() -> ReleaseResult<T>) -> ReleaseResult<T> {
    let started = Instant::now();
    let result = action();
    let elapsed_ms = started.elapsed().as_millis();
    println!("{}", json!({ "schema": "legion.local-windows-phase.v1", "phase": name, "elapsedMs": elapsed_ms }));
    result
}

pub struct RunLocalWindowsDevelopmentOptions<'a> {
    pub build_only: bool,
    pub is_windows_host: bool,
    pub runner: CommandRunner<'a>,
    pub env: &'a HashMap<String, String>,
    pub repository_root: &'a Path,
    pub xtask_binary: &'a Path,
    pub inno_template: &'a str,
    pub activation_script: &'a Path,
    pub where_exe: &'a dyn Fn() -> Option<String>,
}

/// Full port of `runLocalWindowsDevelopment`.
pub fn run_local_windows_development(options: RunLocalWindowsDevelopmentOptions) -> ReleaseResult<Value> {
    if !options.is_windows_host {
        return Err(fail("Windows host is required"));
    }
    let local_app_data = options.env.get("LOCALAPPDATA").cloned().unwrap_or_default();
    if local_app_data.is_empty() {
        return Err(fail("LOCALAPPDATA is required"));
    }
    let root = options.repository_root;
    assert_local_authorization(root)?;
    let started = Instant::now();
    let release_version = version(root)?;
    let source = source_state(options.runner, root)?;

    let output_root = root.join("dist").join("local-windows");
    let assembly_root = root.join("dist").join("native").join(format!("windows-{ARCHITECTURE}")).join(format!("legion-{release_version}"));
    let installer_root = assert_below(&output_root, &output_root.join("installer"), "installer output")?;
    let qualification_root = assert_below(&output_root, &output_root.join("qualification"), "qualification output")?;
    for path in [&installer_root, &qualification_root] {
        let _ = fs::remove_dir_all(path);
    }
    fs::create_dir_all(&installer_root).map_err(|e| fail(e.to_string()))?;

    // Managed native release build via the workspace's `rightkit.cmd` wrapper.
    phase("native-release-build", || {
        let comspec = options.env.get("ComSpec").cloned().unwrap_or_else(|| "cmd.exe".to_string());
        let build_options = CommandOptions { cwd: Some(root.to_path_buf()), env: Some(options.env.clone()) };
        run_labeled(
            options.runner,
            &comspec,
            &["/d".into(), "/s".into(), "/c".into(), "rightkit.cmd".into(), "cargo".into(), "build".into(), "--manifest-path".into(), "engine/Cargo.toml".into(), "--locked".into(), "--release".into(), "--bins".into(), "--target".into(), TARGET.into()],
            &build_options,
            "managed native release build",
        )?;
        Ok(())
    })?;

    // Native assembly, now via the built xtask binary's own subcommand.
    phase("native-assembly", || {
        let assembly_options = CommandOptions { cwd: Some(root.to_path_buf()), env: Some(options.env.clone()) };
        run_labeled(
            options.runner,
            &options.xtask_binary.to_string_lossy(),
            &[
                "assemble-native-release".into(),
                "--profile".into(), "release".into(),
                "--platform".into(), "windows".into(),
                "--architecture".into(), ARCHITECTURE.into(),
                "--target".into(), TARGET.into(),
                "--out".into(), assembly_root.to_string_lossy().to_string(),
                "--force".into(),
            ],
            &assembly_options,
            "native assembly",
        )?;
        Ok(())
    })?;

    let inno = resolve_inno_compiler(options.env, options.where_exe)?;
    let installer = phase("unsigned-installer", || {
        let result = finalize_windows_installer(
            options.runner,
            root,
            options.inno_template,
            options.activation_script,
            FinalizeWindowsInstallerInput {
                input_root: Some(assembly_root.clone()),
                output_root: Some(installer_root.clone()),
                version: release_version.clone(),
                architecture: ARCHITECTURE.to_string(),
                receipt_path: None,
                rendered_script_path: None,
                unsigned: true,
                inno_setup_path: Some(inno.to_string_lossy().to_string()),
            },
        )?;
        Ok(result)
    })?;
    if installer.status != "unsigned" {
        return Err(fail("installer worker did not report unsigned output"));
    }
    assert_file(&installer.installer, "unsigned installer")?;
    if installer.sha256 != sha256_file(&installer.installer)? {
        return Err(fail("unsigned installer digest mismatch"));
    }
    let payload_executable = assert_file(&assembly_root.join("bin").join("legion.exe"), "assembled Legion executable")?;
    let payload_executable_sha256 = sha256_file(&payload_executable)?;
    let finalization_path = installer_root.join("installer-finalization.json");
    let finalization_value = local_finalization(&installer.installer, &release_version, &source.revision)?;
    fs::write(&finalization_path, format!("{}\n", serde_json::to_string_pretty(&finalization_value).unwrap())).map_err(|e| fail(e.to_string()))?;

    if options.build_only {
        return Ok(json!({
            "status": "built",
            "profile": "internal-unsigned",
            "installer": installer.installer,
            "installerSha256": installer.sha256,
            "finalization": finalization_path,
            "sourceRevision": source.revision,
            "dirty": source.dirty,
            "elapsedMs": started.elapsed().as_millis(),
        }));
    }

    fs::create_dir_all(&qualification_root).map_err(|e| fail(e.to_string()))?;
    let qualification = phase("installed-qualification", || {
        qualify_installed_windows(
            options.runner,
            QualifyInstalledWindowsInput {
                setup: Some(installer.installer.clone()),
                output_root: Some(qualification_root.clone()),
                finalization_path: Some(finalization_path.clone()),
                source_revision: source.revision.clone(),
                version: release_version.clone(),
                platform_is_windows: true,
            },
        )
    })?;
    if qualification.get("status").and_then(Value::as_str) != Some("qualified") {
        return Err(fail("installed qualification did not pass"));
    }

    let install_root = PathBuf::from(&local_app_data).join("Orthic Labs").join("Legion");
    let install_log = output_root.join("install.log");
    phase("stable-install", || {
        let install_options = CommandOptions { cwd: Some(root.to_path_buf()), env: Some(options.env.clone()) };
        run_labeled(
            options.runner,
            &installer.installer.to_string_lossy(),
            &["/VERYSILENT".into(), "/SUPPRESSMSGBOXES".into(), "/NORESTART".into(), format!("/DIR={}", install_root.display()), format!("/LOG={}", install_log.display())],
            &install_options,
            "stable installer",
        )?;
        Ok(())
    })?;
    let executable = assert_file(&install_root.join("current").join("bin").join("legion.exe"), "stable Legion executable")?;
    let installed_executable_sha256 = sha256_file(&executable)?;
    if installed_executable_sha256 != payload_executable_sha256 {
        return Err(fail(format!("installed executable digest mismatch: {installed_executable_sha256} != {payload_executable_sha256}")));
    }
    let version_options = CommandOptions { cwd: Some(install_root.clone()), env: Some(options.env.clone()) };
    let installed_version = run_labeled(options.runner, &executable.to_string_lossy(), &["--version".to_string()], &version_options, "installed version")?.stdout.unwrap_or_default().trim().to_string();
    if installed_version != release_version {
        return Err(fail(format!("installed version mismatch: {installed_version}")));
    }
    let status = run_json_labeled(options.runner, &executable.to_string_lossy(), &["--json".into(), "setup".into(), "status".into()], &version_options, "installed setup status")?;
    let status_ok = status.get("kind").and_then(Value::as_str) == Some("legion-setup-status")
        && status.get("status").and_then(Value::as_str) == Some("complete")
        && status.get("origin").and_then(Value::as_str) == Some("installed")
        && status.get("stableCurrent") == Some(&Value::Bool(true));
    if !status_ok {
        return Err(fail("installed setup status is not complete at stable current"));
    }
    if status.get("liveIdentity").and_then(|l| l.get("projections")).and_then(|p| p.get("claudePlugin")).and_then(|c| c.get("state")).and_then(Value::as_str) != Some("current") {
        return Err(fail("Claude projection is not current"));
    }
    let user_profile = options.env.get("USERPROFILE").cloned().unwrap_or_default();
    let codex_opt_in = Path::new(&user_profile).join(".codex").join("plugins").join("legion").exists();
    if codex_opt_in && status.get("liveIdentity").and_then(|l| l.get("projections")).and_then(|p| p.get("codexPlugin")).and_then(|c| c.get("state")).and_then(Value::as_str) != Some("current") {
        return Err(fail("Codex opt-in projection is not current"));
    }

    let result = json!({
        "status": "pass",
        "origin": "installed",
        "profile": "internal-unsigned",
        "installer": installer.installer,
        "installerSha256": installer.sha256,
        "finalization": finalization_path,
        "qualification": qualification.get("evidence").and_then(|e| e.get("path")).cloned().unwrap_or_else(|| json!(qualification_root.join("qualification.json"))),
        "installedRoot": install_root,
        "installedExecutable": executable,
        "executableSha256": installed_executable_sha256,
        "payloadExecutableSha256": payload_executable_sha256,
        "installedVersion": installed_version,
        "sourceRevision": source.revision,
        "dirty": source.dirty,
        "codexOptIn": codex_opt_in,
        "elapsedMs": started.elapsed().as_millis(),
    });
    fs::write(output_root.join("local-verification.json"), format!("{}\n", serde_json::to_string_pretty(&result).unwrap())).map_err(|e| fail(e.to_string()))?;
    Ok(result)
}
