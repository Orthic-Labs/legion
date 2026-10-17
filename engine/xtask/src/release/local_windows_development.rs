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

use super::paths::{
    is_revision_hex, is_stable_semver, sha256_file, CommandOptions, CommandRunner, ReleaseResult,
};
use super::windows_finalize_installer::{
    finalize_windows_installer, FinalizeWindowsInstallerInput,
};
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
    let meta = fs::symlink_metadata(path)
        .map_err(|_| fail(format!("{label} is missing or unsafe: {}", path.display())))?;
    if meta.is_symlink() || !meta.is_file() {
        return Err(fail(format!(
            "{label} is missing or unsafe: {}",
            path.display()
        )));
    }
    Ok(path.to_path_buf())
}

/// Mirrors `resolveInnoCompiler`: probes well-known Inno Setup 6 install
/// locations before falling back to `where.exe iscc.exe`.
pub fn resolve_inno_compiler(
    env: &HashMap<String, String>,
    where_exe: impl Fn() -> Option<String>,
) -> ReleaseResult<PathBuf> {
    let mut candidates: Vec<PathBuf> = vec![];
    if let Some(v) = env.get("INNO_SETUP_PATH") {
        candidates.push(PathBuf::from(v));
    }
    if let Some(v) = env.get("ChocolateyInstall") {
        candidates.push(Path::new(v).join("bin").join("iscc.exe"));
    }
    if let Some(v) = env.get("LOCALAPPDATA") {
        candidates.push(Path::new(v).join("Programs").join("Inno").join("ISCC.exe"));
        candidates.push(
            Path::new(v)
                .join("Programs")
                .join("Inno Setup 6")
                .join("ISCC.exe"),
        );
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
    Ok(
        json!({ "path": path, "role": role, "size": fs::metadata(path).map_err(|e| fail(e.to_string()))?.len(), "sha256": sha256_file(path)? }),
    )
}

/// Mirrors `localFinalization`: the unsigned finalization manifest shape for
/// the internal-unsigned local development route (no signing evidence).
pub fn local_finalization(
    installer: &Path,
    release_version: &str,
    source_revision: &str,
) -> ReleaseResult<Value> {
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
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| fail(format!("invalid local development declaration: {e}")))?;
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
    let text = fs::read_to_string(&path)
        .map_err(|e| fail(format!("release/version.json could not be read: {e}")))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|_| fail("release/version.json is invalid"))?;
    let ok = value.get("schemaVersion").and_then(Value::as_i64) == Some(1)
        && value.get("kind").and_then(Value::as_str) == Some("legion-release-version");
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
    let options = CommandOptions {
        cwd: Some(root.to_path_buf()),
        env: None,
    };
    let rev_result = runner(
        "git",
        &["rev-parse".to_string(), "HEAD".to_string()],
        &options,
    );
    if rev_result.error_message.is_some() || rev_result.status != Some(0) {
        return Err(fail(format!(
            "source revision failed: {}",
            command_diagnostic(&rev_result)
        )));
    }
    let revision = rev_result.stdout.unwrap_or_default().trim().to_lowercase();
    if !is_revision_hex(&revision) {
        return Err(fail("source revision is invalid"));
    }
    let status_result = runner(
        "git",
        &[
            "status".to_string(),
            "--porcelain".to_string(),
            "--untracked-files=normal".to_string(),
        ],
        &options,
    );
    if status_result.error_message.is_some() || status_result.status != Some(0) {
        return Err(fail(format!(
            "source status failed: {}",
            command_diagnostic(&status_result)
        )));
    }
    let dirty = !status_result.stdout.unwrap_or_default().trim().is_empty();
    Ok(SourceState { revision, dirty })
}

fn preassembled_input(
    input: &Path,
    build_only: bool,
    env: &HashMap<String, String>,
    source: &SourceState,
    xtask_binary: &Path,
) -> ReleaseResult<PathBuf> {
    if !build_only || env.get("GITHUB_ACTIONS").map(String::as_str) != Some("true") {
        return Err(fail(
            "preassembled input requires hosted CI build-only packaging",
        ));
    }
    if source.dirty || env.get("GITHUB_SHA").map(String::as_str) != Some(source.revision.as_str()) {
        return Err(fail(
            "preassembled input requires a clean checkout at GITHUB_SHA",
        ));
    }
    let runner_temp = env
        .get("RUNNER_TEMP")
        .ok_or_else(|| fail("RUNNER_TEMP is required"))?;
    let expected = Path::new(runner_temp)
        .join("legion-install")
        .canonicalize()
        .map_err(|e| fail(format!("CI payload is unavailable: {e}")))?;
    let metadata = fs::symlink_metadata(input).map_err(|e| fail(e.to_string()))?;
    if metadata.is_symlink() || !metadata.is_dir() {
        return Err(fail("preassembled root must be a real directory"));
    }
    let input = input.canonicalize().map_err(|e| fail(e.to_string()))?;
    if input != expected {
        return Err(fail("preassembled root must be RUNNER_TEMP/legion-install"));
    }
    assert_file(xtask_binary, "CI xtask executable")?;
    let binary_root = xtask_binary
        .parent()
        .ok_or_else(|| fail("CI xtask has no parent"))?;
    if binary_root.file_name().and_then(|name| name.to_str()) != Some("debug") {
        return Err(fail("CI xtask must be the already-built dev executable"));
    }
    for name in ["legion.exe", "legion-hook.exe", "legion-mcp.exe"] {
        let assembled = assert_file(&input.join("bin").join(name), "CI payload binary")?;
        let built = assert_file(&binary_root.join(name), "CI dev binary")?;
        if sha256_file(&assembled)? != sha256_file(&built)? {
            return Err(fail(format!(
                "preassembled {name} differs from the CI dev build"
            )));
        }
    }
    let manifest_path = assert_file(
        &input.join("share/legion/release.json"),
        "CI release metadata",
    )?;
    let manifest: Value =
        serde_json::from_slice(&fs::read(manifest_path).map_err(|e| fail(e.to_string()))?)
            .map_err(|e| fail(e.to_string()))?;
    let runtime_sha = sha256_file(&input.join("bin/legion.exe"))?;
    let provenance = format!("local-build://windows-{ARCHITECTURE}/{runtime_sha}");
    if manifest
        .pointer("/runtime/provenance")
        .and_then(Value::as_str)
        != Some(provenance.as_str())
    {
        return Err(fail(
            "preassembled input lacks matching local Windows build provenance",
        ));
    }
    // Existing finalization also checks Windows identity, runtime & marketplace
    // digests, required files & the complete payload's safe tree before ISCC.
    Ok(crate::windows_release_support::strip_verbatim(input))
}

fn run_labeled(
    runner: CommandRunner,
    command: &str,
    args: &[String],
    options: &CommandOptions,
    label: &str,
) -> ReleaseResult<crate::process_boundary::CommandResult> {
    let result = runner(command, args, options);
    if result.error_message.is_some() || result.status != Some(0) {
        return Err(fail(format!(
            "{label} failed: {}",
            command_diagnostic(&result)
        )));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_boundary::CommandResult;

    struct CiFixture {
        root: PathBuf,
        input: PathBuf,
        xtask: PathBuf,
        env: HashMap<String, String>,
        source: SourceState,
    }

    impl CiFixture {
        fn new() -> Self {
            let scratch = std::env::var_os("RUNNER_TEMP")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(if cfg!(windows) {
                        r"D:\scratch"
                    } else {
                        "/Volumes/D/scratch"
                    })
                });
            let root = scratch.join(format!(
                "legion-preassembled-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let input = root.join("runner/legion-install");
            let binary_root = root.join("debug");
            for path in [
                input.join("bin"),
                input.join("share/legion"),
                binary_root.clone(),
                root.join("release"),
            ] {
                fs::create_dir_all(path).unwrap();
            }
            let xtask = binary_root.join("xtask.exe");
            fs::write(&xtask, b"xtask").unwrap();
            for name in ["legion.exe", "legion-hook.exe", "legion-mcp.exe"] {
                fs::write(binary_root.join(name), name).unwrap();
                fs::write(input.join("bin").join(name), name).unwrap();
            }
            let digest = sha256_file(&input.join("bin/legion.exe")).unwrap();
            fs::write(
                input.join("share/legion/release.json"),
                json!({
                    "releaseVersion": "1.2.3",
                    "runtime": { "platform": "windows", "architecture": "x86_64", "sha256": digest,
                        "provenance": format!("local-build://windows-x86_64/{digest}") }
                })
                .to_string(),
            )
            .unwrap();
            fs::write(
                root.join("release/version.json"),
                r#"{"schemaVersion":1,"kind":"legion-release-version","version":"1.2.3"}"#,
            )
            .unwrap();
            fs::write(root.join(".rightkit-local-development.json"), r#"{"schemaVersion":1,"repository":"Orthic-Labs/legion","platform":"win32","purpose":"unsigned-installer"}"#).unwrap();
            let source = SourceState {
                revision: "a".repeat(40),
                dirty: false,
            };
            let env = HashMap::from([
                ("GITHUB_ACTIONS".into(), "true".into()),
                ("GITHUB_SHA".into(), source.revision.clone()),
                (
                    "RUNNER_TEMP".into(),
                    root.join("runner").to_string_lossy().into_owned(),
                ),
                (
                    "LOCALAPPDATA".into(),
                    root.join("local").to_string_lossy().into_owned(),
                ),
            ]);
            Self {
                root,
                input,
                xtask,
                env,
                source,
            }
        }
    }

    impl Drop for CiFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn preassembled_packaging_never_invokes_build_or_assembly() {
        let fixture = CiFixture::new();
        let runner = |command: &str, args: &[String], _: &CommandOptions| {
            assert_eq!(command, "git", "preassembled packaging invoked {command}");
            CommandResult {
                status: Some(0),
                stdout: Some(if args[0] == "rev-parse" {
                    fixture.source.revision.clone()
                } else {
                    String::new()
                }),
                ..Default::default()
            }
        };
        let error = run_local_windows_development(RunLocalWindowsDevelopmentOptions {
            build_only: true,
            preassembled_root: Some(&fixture.input),
            is_windows_host: true,
            runner: &runner,
            env: &fixture.env,
            repository_root: &fixture.root,
            xtask_binary: &fixture.xtask,
            inno_template: "",
            activation_script: &fixture.root.join("activate.ps1"),
            where_exe: &|| None,
        })
        .unwrap_err();
        assert!(
            error.contains("Inno Setup 6 compiler is missing"),
            "{error}"
        );
        assert!(fixture.input.join("bin/legion.exe").is_file());
    }

    #[test]
    fn preassembled_input_rejects_source_path_provenance_and_binary_mismatch() {
        let mut fixture = CiFixture::new();
        let validate = |fixture: &CiFixture, input: &Path, build_only| {
            preassembled_input(
                input,
                build_only,
                &fixture.env,
                &fixture.source,
                &fixture.xtask,
            )
        };
        assert!(validate(&fixture, &fixture.input, true).is_ok());
        assert!(validate(&fixture, &fixture.input, false).is_err());
        fixture.env.insert("GITHUB_ACTIONS".into(), "false".into());
        assert!(validate(&fixture, &fixture.input, true).is_err());
        fixture.env.insert("GITHUB_ACTIONS".into(), "true".into());
        fixture.source.dirty = true;
        assert!(validate(&fixture, &fixture.input, true).is_err());
        fixture.source.dirty = false;
        fixture.env.insert("GITHUB_SHA".into(), "b".repeat(40));
        assert!(validate(&fixture, &fixture.input, true).is_err());
        fixture
            .env
            .insert("GITHUB_SHA".into(), fixture.source.revision.clone());
        assert!(validate(&fixture, &fixture.root, true).is_err());
        let manifest = fixture.input.join("share/legion/release.json");
        let original = fs::read(&manifest).unwrap();
        fs::write(
            &manifest,
            r#"{"runtime":{"provenance":"local-build://macos-x86_64/wrong"}}"#,
        )
        .unwrap();
        assert!(validate(&fixture, &fixture.input, true).is_err());
        fs::write(manifest, original).unwrap();
        for name in ["legion.exe", "legion-hook.exe", "legion-mcp.exe"] {
            fs::write(fixture.input.join("bin").join(name), "tampered").unwrap();
            assert!(
                validate(&fixture, &fixture.input, true).is_err(),
                "accepted altered {name}"
            );
            fs::write(fixture.input.join("bin").join(name), name).unwrap();
        }
    }
}

fn run_json_labeled(
    runner: CommandRunner,
    command: &str,
    args: &[String],
    options: &CommandOptions,
    label: &str,
) -> ReleaseResult<Value> {
    let result = run_labeled(runner, command, args, options, label)?;
    let stdout = result.stdout.unwrap_or_default();
    serde_json::from_str(stdout.trim())
        .map_err(|_| fail(format!("{label} did not emit JSON: {}", stdout.trim())))
}

/// Emits the same `{"schema":"legion.local-windows-phase.v1", "phase", "elapsedMs"}`
/// line to stdout the JS `phase()` wrapper wrote, after running `action`.
fn phase<T>(name: &str, action: impl FnOnce() -> ReleaseResult<T>) -> ReleaseResult<T> {
    let started = Instant::now();
    let result = action();
    let elapsed_ms = started.elapsed().as_millis();
    println!(
        "{}",
        json!({ "schema": "legion.local-windows-phase.v1", "phase": name, "elapsedMs": elapsed_ms })
    );
    result
}

pub struct RunLocalWindowsDevelopmentOptions<'a> {
    pub build_only: bool,
    pub preassembled_root: Option<&'a Path>,
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
pub fn run_local_windows_development(
    options: RunLocalWindowsDevelopmentOptions,
) -> ReleaseResult<Value> {
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
    let local_assembly_root = root
        .join("dist")
        .join("native")
        .join(format!("windows-{ARCHITECTURE}"))
        .join(format!("legion-{release_version}"));
    let assembly_root = match options.preassembled_root {
        Some(input) => preassembled_input(
            input,
            options.build_only,
            options.env,
            &source,
            options.xtask_binary,
        )?,
        None => local_assembly_root,
    };
    let installer_root = assert_below(
        &output_root,
        &output_root.join("installer"),
        "installer output",
    )?;
    let qualification_root = assert_below(
        &output_root,
        &output_root.join("qualification"),
        "qualification output",
    )?;
    for path in [&installer_root, &qualification_root] {
        let _ = fs::remove_dir_all(path);
    }
    fs::create_dir_all(&installer_root).map_err(|e| fail(e.to_string()))?;

    if options.preassembled_root.is_none() {
        // Managed native dev build via the workspace's `rightkit.cmd` wrapper.
        phase("native-dev-build", || {
            let comspec = options
                .env
                .get("ComSpec")
                .cloned()
                .unwrap_or_else(|| "cmd.exe".to_string());
            let mut build_env = options.env.clone();
            build_env.insert("RIGHTKIT_BUILD_MODE".into(), "dev".into());
            build_env.insert("RIGHTKIT_CARGO_PROFILE".into(), "dev".into());
            build_env.insert("CARGO_INCREMENTAL".into(), "1".into());
            let build_options = CommandOptions {
                cwd: Some(root.to_path_buf()),
                env: Some(build_env),
            };
            let hosted_ci = options.env.get("GITHUB_ACTIONS").map(String::as_str) == Some("true");
            let command = if hosted_ci { "cargo" } else { &comspec };
            let mut arguments: Vec<String> = if hosted_ci {
                vec![]
            } else {
                vec![
                    "/d".into(),
                    "/s".into(),
                    "/c".into(),
                    "rightkit.cmd".into(),
                    "cargo".into(),
                ]
            };
            arguments.extend(
                [
                    "build",
                    "--manifest-path",
                    "engine/Cargo.toml",
                    "--locked",
                    "--profile",
                    "dev",
                    "-p",
                    "legion",
                    "-p",
                    "legion-hook",
                    "-p",
                    "legion-mcp",
                    "--target",
                    TARGET,
                ]
                .map(String::from),
            );
            run_labeled(
                options.runner,
                command,
                &arguments,
                &build_options,
                "managed native dev build",
            )?;
            Ok(())
        })?;

        // Native assembly, now via the built xtask binary's own subcommand.
        phase("native-assembly", || {
            let assembly_options = CommandOptions {
                cwd: Some(root.to_path_buf()),
                env: Some(options.env.clone()),
            };
            run_labeled(
                options.runner,
                &options.xtask_binary.to_string_lossy(),
                &[
                    "assemble-native-release".into(),
                    "--profile".into(),
                    "debug".into(),
                    "--platform".into(),
                    "windows".into(),
                    "--architecture".into(),
                    ARCHITECTURE.into(),
                    "--target".into(),
                    TARGET.into(),
                    "--out".into(),
                    assembly_root.to_string_lossy().to_string(),
                    "--force".into(),
                ],
                &assembly_options,
                "native assembly",
            )?;
            Ok(())
        })?;
    }

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
    let payload_executable = assert_file(
        &assembly_root.join("bin").join("legion.exe"),
        "assembled Legion executable",
    )?;
    let payload_executable_sha256 = sha256_file(&payload_executable)?;
    let finalization_path = installer_root.join("installer-finalization.json");
    let finalization_value =
        local_finalization(&installer.installer, &release_version, &source.revision)?;
    fs::write(
        &finalization_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&finalization_value).unwrap()
        ),
    )
    .map_err(|e| fail(e.to_string()))?;

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

    let install_root = PathBuf::from(&local_app_data)
        .join("Orthic Labs")
        .join("Legion");
    let install_log = output_root.join("install.log");
    phase("stable-install", || {
        let install_options = CommandOptions {
            cwd: Some(root.to_path_buf()),
            env: Some(options.env.clone()),
        };
        run_labeled(
            options.runner,
            &installer.installer.to_string_lossy(),
            &[
                "/VERYSILENT".into(),
                "/SUPPRESSMSGBOXES".into(),
                "/NORESTART".into(),
                format!("/DIR={}", install_root.display()),
                format!("/LOG={}", install_log.display()),
            ],
            &install_options,
            "stable installer",
        )?;
        Ok(())
    })?;
    let executable = assert_file(
        &install_root.join("current").join("bin").join("legion.exe"),
        "stable Legion executable",
    )?;
    let installed_executable_sha256 = sha256_file(&executable)?;
    if installed_executable_sha256 != payload_executable_sha256 {
        return Err(fail(format!("installed executable digest mismatch: {installed_executable_sha256} != {payload_executable_sha256}")));
    }
    let version_options = CommandOptions {
        cwd: Some(install_root.clone()),
        env: Some(options.env.clone()),
    };
    let installed_version = run_labeled(
        options.runner,
        &executable.to_string_lossy(),
        &["--version".to_string()],
        &version_options,
        "installed version",
    )?
    .stdout
    .unwrap_or_default()
    .trim()
    .to_string();
    if installed_version != release_version {
        return Err(fail(format!(
            "installed version mismatch: {installed_version}"
        )));
    }
    let status = run_json_labeled(
        options.runner,
        &executable.to_string_lossy(),
        &["--json".into(), "setup".into(), "status".into()],
        &version_options,
        "installed setup status",
    )?;
    let status_ok = status.get("kind").and_then(Value::as_str) == Some("legion-setup-status")
        && status.get("status").and_then(Value::as_str) == Some("complete")
        && status.get("origin").and_then(Value::as_str) == Some("installed")
        && status.get("stableCurrent") == Some(&Value::Bool(true));
    if !status_ok {
        return Err(fail(
            "installed setup status is not complete at stable current",
        ));
    }
    if status
        .get("liveIdentity")
        .and_then(|l| l.get("projections"))
        .and_then(|p| p.get("claudePlugin"))
        .and_then(|c| c.get("state"))
        .and_then(Value::as_str)
        != Some("current")
    {
        return Err(fail("Claude projection is not current"));
    }
    let user_profile = options.env.get("USERPROFILE").cloned().unwrap_or_default();
    let codex_opt_in = Path::new(&user_profile)
        .join(".codex")
        .join("plugins")
        .join("legion")
        .exists();
    if codex_opt_in
        && status
            .get("liveIdentity")
            .and_then(|l| l.get("projections"))
            .and_then(|p| p.get("codexPlugin"))
            .and_then(|c| c.get("state"))
            .and_then(Value::as_str)
            != Some("current")
    {
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
    fs::write(
        output_root.join("local-verification.json"),
        format!("{}\n", serde_json::to_string_pretty(&result).unwrap()),
    )
    .map_err(|e| fail(e.to_string()))?;
    Ok(result)
}
