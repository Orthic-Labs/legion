//! Core lifecycle port of `qualifyWindowsRelease` from
//! `qualify-windows-release.mjs`: extracts current/prior portable archives,
//! installs the current one into an isolated user-local "current" root,
//! proves install/command-resolution/client-integration/update/rollback/
//! uninstall, and writes the qualification receipt plus integration journal.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

use crate::windows_release_config::WindowsInstallContract;
use crate::windows_release_support::{
    assert_regular_file, assert_source_revision, assert_version, bare_digest, digest_matches, has_forbidden_binding_segment,
    read_json, release_generation, sha256_file, sha256_prefixed, version_root_matches,
};
// The JS qualifier's pathsEqual resolved both sides (realpath), unlike the packager's.
use crate::windows_release_support::canonical_paths_equal as paths_equal;

use super::journal::{integration_journal_record, write_integration_journal, write_pointer, write_receipt, IntegrationJournalInput};
use super::proofs::{command_environment, resolve_codex_executable, setup_health, CurrentRelease};
use super::tree::{
    assert_directory, assert_extracted_tree, assert_inside, atomic_replace_product, copy_tree, extract_with_native_windows_tar,
    is_same_or_inside, native_tool, next_run_sequence, remove_exact, tree_digest, CommandOptions, CommandOutcome,
};

pub const REQUIRED_BINARIES: [&str; 3] = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"];
pub const REQUIRED_GATES: [&str; 6] = ["installed-product", "command-resolution", "client-integration", "update", "rollback", "uninstall"];

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn native_architecture_for(normalized: &str) -> Option<&'static str> {
    match normalized {
        "x86_64" => Some("x64"),
        "arm64" => Some("arm64"),
        _ => None,
    }
}

/// Mirrors `normalizeArchitecture` (the qualify script's own alias table).
pub fn normalize_architecture(value: &str) -> Result<String, String> {
    let normalized = match value.trim().to_lowercase().as_str() {
        "x64" | "amd64" | "x86_64" | "windows-x86_64" => "x86_64",
        "arm64" | "aarch64" | "windows-arm64" => "arm64",
        _ => return Err(format!("unsupported Windows architecture: {value}; expected x86_64 or arm64")),
    };
    Ok(normalized.to_string())
}

pub fn target_identity(architecture: &str) -> Result<Value, String> {
    let normalized = normalize_architecture(architecture)?;
    let configured = crate::windows_release_config::windows_architecture(&normalized).ok_or_else(|| format!("unsupported Windows architecture: {architecture}"))?;
    Ok(json!({
        "platform": configured.platform,
        "architecture": configured.architecture,
        "nativeArchitecture": configured.native_architecture,
        "targetTriple": configured.target_triple,
        "executable": "legion.exe",
        "artifactId": configured.artifact_id,
    }))
}

fn compare_versions(left: &str, right: &str) -> i64 {
    let lp: Vec<i64> = left.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    let rp: Vec<i64> = right.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    for i in 0..3 {
        let l = lp.get(i).copied().unwrap_or(0);
        let r = rp.get(i).copied().unwrap_or(0);
        if l != r {
            return l - r;
        }
    }
    0
}

struct StablePaths {
    root: PathBuf,
    current: PathBuf,
    previous: PathBuf,
    next: PathBuf,
    versions: PathBuf,
    journal: PathBuf,
    executable: PathBuf,
}

fn stable_install_paths(install_root: &Path) -> StablePaths {
    let root = install_root.to_path_buf();
    StablePaths {
        current: root.join(WindowsInstallContract::STABLE_CURRENT_NAME),
        previous: root.join(WindowsInstallContract::PREVIOUS_CURRENT_NAME),
        next: root.join(WindowsInstallContract::NEXT_CURRENT_NAME),
        versions: root.join("versions"),
        journal: root.join(WindowsInstallContract::INTEGRATION_JOURNAL_NAME),
        executable: root.join(WindowsInstallContract::STABLE_CURRENT_NAME).join("bin").join("legion.exe"),
        root,
    }
}

fn assert_stable_install_paths(paths: StablePaths) -> Result<StablePaths, String> {
    if has_forbidden_binding_segment(&paths.root.to_string_lossy())
        || has_forbidden_binding_segment(&paths.current.to_string_lossy())
        || has_forbidden_binding_segment(&paths.executable.to_string_lossy())
    {
        return Err(format!("stable installed binding escapes user-local current: {}", paths.executable.display()));
    }
    Ok(paths)
}

pub struct ReleaseInfo {
    pub metadata: Value,
    pub release_version: String,
    pub runtime_sha256: String,
    #[allow(dead_code)]
    pub release_path: PathBuf,
    pub generation: String,
}

/// Mirrors `releaseMetadata`.
fn release_metadata(root: &Path, architecture: &str, label: &str) -> Result<ReleaseInfo, String> {
    let release_path = root.join("share").join("legion").join("release.json");
    let metadata = read_json(&release_path, &format!("{label} release identity"))?;
    let release_version = assert_version(metadata.get("releaseVersion").and_then(|v| v.as_str()), &format!("{label} release version"))?;
    let runtime = metadata.get("runtime").filter(|v| v.is_object());
    let runtime = runtime.ok_or_else(|| format!("{label} release identity has no runtime object: {}", release_path.display()))?;
    let runtime_platform = runtime.get("platform").and_then(|v| v.as_str()).unwrap_or_default().to_lowercase();
    if runtime_platform != "windows" {
        return Err(format!("{label} release identity platform is not Windows: {}", runtime.get("platform").and_then(|v| v.as_str()).unwrap_or_default()));
    }
    if runtime.get("architecture").and_then(|v| v.as_str()) != Some(architecture) {
        return Err(format!(
            "{label} release architecture mismatch: expected {architecture}, got {}",
            runtime.get("architecture").and_then(|v| v.as_str()).unwrap_or_default()
        ));
    }
    let runtime_path = root.join("bin").join("legion.exe");
    assert_regular_file(&runtime_path, &format!("{label} runtime binary"))?;
    let runtime_sha256 = sha256_file(&runtime_path)?;
    if !digest_matches(runtime.get("sha256").and_then(|v| v.as_str()), Some(&runtime_sha256)) {
        return Err(format!(
            "{label} runtime digest mismatch: {} != {runtime_sha256}",
            runtime.get("sha256").and_then(|v| v.as_str()).unwrap_or_default()
        ));
    }
    let generation = release_generation(&metadata, &release_version, &runtime_sha256);
    Ok(ReleaseInfo { metadata, release_version, runtime_sha256, release_path, generation })
}

/// Mirrors `validateProductRoot`.
fn validate_product_root(root: &Path, architecture: &str, label: &str) -> Result<ReleaseInfo, String> {
    assert_extracted_tree(root, label)?;
    for binary in REQUIRED_BINARIES {
        assert_regular_file(&root.join("bin").join(binary), &format!("{label} binary {binary}"))?;
    }
    release_metadata(root, architecture, label)
}

/// Mirrors `retainedVersionMatches`.
fn retained_version_matches(root: Option<&Path>, expected: Option<&ReleaseInfo>, architecture: &str, label: &str) -> bool {
    match (root, expected) {
        (Some(root), Some(expected)) => match validate_product_root(root, architecture, label) {
            Ok(observed) => observed.release_version == expected.release_version && digest_matches(Some(&observed.runtime_sha256), Some(&expected.runtime_sha256)),
            Err(_) => false,
        },
        _ => false,
    }
}

/// Mirrors `resolvePathCommand`.
fn resolve_path_command(product_root: &Path, executable: &str, platform: &str, path_value: &str) -> Option<PathBuf> {
    let expected = product_root.join("bin").join(executable);
    if !expected.exists() || has_forbidden_binding_segment(&expected.to_string_lossy()) {
        return None;
    }
    let separator = if platform == "win32" { ';' } else { ':' };
    for entry in path_value.split(separator).filter(|e| !e.is_empty()) {
        let candidate = Path::new(entry).join(executable);
        if candidate.to_string_lossy().to_lowercase() == expected.to_string_lossy().to_lowercase() {
            return Some(expected);
        }
    }
    None
}

fn gate(name: &str, status: &str, details: Value) -> Value {
    let mut value = json!({ "name": name, "status": status });
    if let Value::Object(map) = details {
        if let Value::Object(base) = &mut value {
            for (k, v) in map {
                base.insert(k, v);
            }
        }
    }
    value
}

fn unproven_gate(name: &str, reason: &str) -> Value {
    gate(name, "unproven", json!({ "reason": reason }))
}

fn failed_gate(name: &str, reason: &str, details: Value) -> Value {
    let mut merged = details;
    if let Value::Object(map) = &mut merged {
        map.insert("reason".to_string(), json!(reason));
    }
    gate(name, "fail", merged)
}

fn all_gates_pass(gates: &Value) -> bool {
    REQUIRED_GATES.iter().all(|name| gates.get(name).and_then(|g| g.get("status")).and_then(|v| v.as_str()) == Some("pass"))
}

/// Mirrors `versionOutputMatches` (word-boundary-ish match of the version
/// string in stdout via a hand-escaped regex in JS; Rust does a plain
/// substring check bounded by non-alphanumeric/start/end, which is
/// equivalent for the `x.y.z` version strings this receives).
fn version_output_matches(invocation: &Value, version: &str) -> bool {
    let stdout = invocation.get("stdout").and_then(|v| v.as_str()).unwrap_or_default();
    let stderr = invocation.get("stderr").and_then(|v| v.as_str()).unwrap_or_default();
    if !super::proofs::command_succeeded(invocation) || stdout.trim().is_empty() || !stderr.trim().is_empty() {
        return false;
    }
    let bytes: Vec<char> = stdout.chars().collect();
    let version_chars: Vec<char> = version.chars().collect();
    if version_chars.is_empty() {
        return false;
    }
    'outer: for start in 0..bytes.len() {
        if start + version_chars.len() > bytes.len() {
            break;
        }
        for (offset, ch) in version_chars.iter().enumerate() {
            if bytes[start + offset] != *ch {
                continue 'outer;
            }
        }
        let before_ok = start == 0 || bytes[start - 1].is_whitespace();
        let end = start + version_chars.len();
        let after_ok = end == bytes.len() || bytes[end].is_whitespace();
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

#[derive(Default)]
pub struct QualifyWindowsOptions {
    pub current_zip: Option<PathBuf>,
    pub prior_zip: Option<PathBuf>,
    pub architecture: Option<String>,
    pub source_revision: Option<String>,
    pub output: Option<PathBuf>,
    pub work_root: Option<PathBuf>,
    pub platform: Option<String>,
    pub runner_architecture: Option<String>,
    pub archive_extractor: Option<Box<dyn Fn(&Path, &Path) -> Result<(), String>>>,
    pub command_runner: Option<Box<dyn Fn(&str, &[String], &CommandOptions) -> CommandOutcome>>,
    pub codex_executable: Option<PathBuf>,
    pub allow_downgrade: bool,
}

/// Mirrors `qualifyWindowsRelease`. Returns the receipt JSON with
/// `receiptPath` merged in, exactly as the JS function's return value.
pub fn qualify_windows_release(options: QualifyWindowsOptions) -> Result<Value, String> {
    // Recorded before the defaults are applied: any override means a simulated run.
    let platform_overridden = options.platform.is_some() || options.runner_architecture.is_some();
    // Node's `process.platform` / `process.arch` spellings, which the JS compared against.
    let platform = options.platform.unwrap_or_else(|| {
        match std::env::consts::OS { "windows" => "win32", "macos" => "darwin", other => other }.to_string()
    });
    let platform = if platform == "macos" { "darwin".to_string() } else { platform };
    let runner_architecture = options.runner_architecture.unwrap_or_else(|| {
        match std::env::consts::ARCH { "x86_64" => "x64", "aarch64" => "arm64", other => other }.to_string()
    });
    let allow_downgrade = options.allow_downgrade;
    let host_path = std::env::var("PATH").unwrap_or_default();

    let codex_executable_input = options.codex_executable.clone();
    let codex_executable = match &codex_executable_input {
        Some(supplied) => Some(fs::canonicalize(supplied).unwrap_or_else(|_| supplied.clone())),
        None => resolve_codex_executable(&host_path, &platform),
    };
    if let Some(codex) = &codex_executable {
        if has_forbidden_binding_segment(&codex.to_string_lossy()) {
            return Err(format!("Codex executable escapes allowed qualification roots: {}", codex.display()));
        }
    }

    let simulated = options.archive_extractor.is_some()
        || options.command_runner.is_some()
        || codex_executable_input.is_some()
        || platform_overridden;

    if platform != "win32" {
        return Err(format!("Windows qualification requires a Windows host; observed {platform}"));
    }
    let normalized_architecture = normalize_architecture(options.architecture.as_deref().unwrap_or_default())?;
    let native_architecture = native_architecture_for(&normalized_architecture).unwrap_or_default();
    if runner_architecture != native_architecture {
        return Err(format!(
            "Windows qualification architecture mismatch: {normalized_architecture} requires process.arch {native_architecture}, observed {runner_architecture}"
        ));
    }
    let current_zip = options.current_zip.ok_or_else(|| "current Windows portable ZIP is required".to_string())?;
    let output = options.output.ok_or_else(|| "qualification output receipt is required".to_string())?;
    let work_root = options.work_root.ok_or_else(|| "isolated work root is required".to_string())?;
    let revision = assert_source_revision(options.source_revision.as_deref())?;
    let identity = target_identity(&normalized_architecture)?;

    let current_archive = fs::canonicalize(&current_zip).unwrap_or(current_zip.clone());
    let prior_archive = options.prior_zip.as_ref().map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.clone()));
    assert_regular_file(&current_archive, "current Windows portable ZIP")?;
    if let Some(prior) = &prior_archive {
        assert_regular_file(prior, "prior Windows portable ZIP")?;
    }
    if !current_archive.to_string_lossy().to_lowercase().ends_with(".zip") {
        return Err(format!("current archive must be a ZIP: {}", current_archive.display()));
    }
    if let Some(prior) = &prior_archive {
        if !prior.to_string_lossy().to_lowercase().ends_with(".zip") {
            return Err(format!("prior archive must be a ZIP: {}", prior.display()));
        }
    }
    let isolated_root = work_root.clone();
    assert_directory(&isolated_root, "isolated work root", true)?;
    let run_root = isolated_root.join(format!(
        "qualification-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0),
        RUN_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    assert_inside(&isolated_root, &run_root, "qualification run root", &platform)?;
    fs::create_dir_all(&run_root).map_err(|e| e.to_string())?;
    let current_root = run_root.join("current-stage");
    let prior_root = run_root.join("prior-stage");
    let foreign_marker = run_root.join("foreign-marker.txt");
    let archive_sha256 = sha256_prefixed(&fs::read(&current_archive).map_err(|e| e.to_string())?);
    let prior_archive_sha256 = match &prior_archive {
        Some(p) => Some(sha256_prefixed(&fs::read(p).map_err(|e| e.to_string())?)),
        None => None,
    };

    let default_extractor = |archive: &Path, destination: &Path| extract_with_native_windows_tar(archive, destination);
    let extraction = |archive_path: &Path, destination: &Path, label: &str| -> Result<(), String> {
        assert_inside(&run_root, destination, &format!("{label} extraction root"), &platform)?;
        fs::create_dir_all(destination).map_err(|e| e.to_string())?;
        if fs::read_dir(destination).map_err(|e| e.to_string())?.next().is_some() {
            return Err(format!("{label} extraction root is not empty: {}", destination.display()));
        }
        match &options.archive_extractor {
            Some(extractor) => extractor(archive_path, destination)?,
            None => default_extractor(archive_path, destination)?,
        }
        assert_extracted_tree(destination, &format!("{label} extracted archive"))
    };
    extraction(&current_archive, &current_root, "current")?;
    let current = validate_product_root(&current_root, &normalized_architecture, "current")?;
    let prior = if let Some(prior_archive_path) = &prior_archive {
        extraction(prior_archive_path, &prior_root, "prior")?;
        Some(validate_product_root(&prior_root, &normalized_architecture, "prior")?)
    } else {
        None
    };

    let env = command_environment(&run_root, codex_executable.as_deref(), &host_path)?;
    let local_appdata = env.environment.get("LOCALAPPDATA").cloned().unwrap_or_default();
    let install_root = WindowsInstallContract::LOCAL_APP_DATA_SUBDIR.iter().fold(PathBuf::from(local_appdata), |acc, part| acc.join(part));
    let stable_paths = assert_stable_install_paths(stable_install_paths(&install_root))?;
    let versions_root = stable_paths.versions.clone();
    let product_root = stable_paths.current.clone();
    let previous_pointer = stable_paths.previous.clone();
    let integration_journal_path = stable_paths.journal.clone();
    for path in [&stable_paths.root, &versions_root] {
        assert_inside(&run_root, path, "stable user-local install path", &platform)?;
        assert_directory(path, "stable user-local install directory", true)?;
    }
    let current_version_root = versions_root.join(format!("{}-{}", current.release_version, &bare_digest(&archive_sha256)[..12]));
    let prior_version_root = match (&prior, &prior_archive_sha256) {
        (Some(prior_info), Some(prior_digest)) => Some(versions_root.join(format!("{}-{}", prior_info.release_version, &bare_digest(prior_digest)[..12]))),
        _ => None,
    };
    copy_tree(&current_root, &current_version_root, &run_root)?;
    if let (Some(_), Some(prior_root_target)) = (&prior, &prior_version_root) {
        copy_tree(&prior_root, prior_root_target, &run_root)?;
    }

    let mut environment = env.environment.clone();
    let path_value = [Some(product_root.join("bin").to_string_lossy().to_string()), codex_executable.as_ref().and_then(|c| c.parent()).map(|p| p.to_string_lossy().to_string())]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(";");
    environment.insert("PATH".to_string(), path_value);

    let run_command_raw = |command: &str, args: &[String], override_options: Option<&CommandOptions>| -> CommandOutcome {
        let opts = match override_options {
            Some(o) => o.clone(),
            None => CommandOptions { cwd: product_root.clone(), env: environment.clone() },
        };
        match &options.command_runner {
            Some(runner) => runner(command, args, &opts),
            None => native_tool(command, args, &opts),
        }
    };
    let run_command = |command: &str, args: &[String], override_options: Option<&CommandOptions>| -> Value {
        let outcome = run_command_raw(command, args, override_options);
        super::proofs::invocation_record(command, args, outcome)
    };

    let install_current = atomic_replace_product(&current_root, &product_root, &run_root, None)?;
    let installed_launcher = stable_paths.executable.clone();
    if has_forbidden_binding_segment(&installed_launcher.to_string_lossy())
        || !paths_equal(Some(&installed_launcher.to_string_lossy()), Some(&product_root.join("bin").join("legion.exe").to_string_lossy()))
    {
        return Err(format!("installed activation path is outside stable current: {}", installed_launcher.display()));
    }
    let version_invocation = run_command(&installed_launcher.to_string_lossy(), &["--version".to_string()], None);
    let version_matches = version_output_matches(&version_invocation, &current.release_version);
    let current_release = CurrentRelease { release_version: &current.release_version, runtime_sha256: &current.runtime_sha256 };
    let current_health = setup_health(
        &run_command,
        &env.state,
        &installed_launcher,
        codex_executable.as_deref(),
        &current_release,
        &current.generation,
        &normalized_architecture,
        Some(&current_version_root),
    );
    let setup_complete = current_health.get("complete").and_then(|v| v.as_bool()).unwrap_or(false);
    let repair_invocation = current_health.get("repairInvocation").cloned().unwrap_or(Value::Null);
    let status_invocation = current_health.get("statusInvocation").cloned().unwrap_or(Value::Null);
    let qualification_proofs = current_health.get("qualificationProofs").cloned().unwrap_or(Value::Null);

    let mut integration_journal = write_integration_journal(
        &integration_journal_path,
        integration_journal_record(IntegrationJournalInput {
            state_root: &env.state,
            current_path: &product_root,
            previous_path: &previous_pointer,
            active_version_root: &current_version_root,
            prior_version_root: prior_version_root.as_deref(),
            target_version: &current.release_version,
            prior_version: prior.as_ref().map(|p| p.release_version.as_str()),
            state_name: "installed",
            prior_health: None,
            current_health: Some(&current_health),
        }),
    )?;

    let installed_pass = install_current.success && super::proofs::command_succeeded(&version_invocation) && version_matches && setup_complete;
    let mut gates = serde_json::Map::new();
    gates.insert(
        "installed-product".to_string(),
        if installed_pass {
            gate(
                "installed-product",
                "pass",
                json!({
                    "productRoot": product_root,
                    "activationPath": installed_launcher,
                    "origin": WindowsInstallContract::ORIGIN,
                    "installRoot": install_root,
                    "generation": current.generation,
                    "resolvedVersionRoot": current_version_root,
                    "releaseVersion": current.release_version,
                    "runtimeSha256": current.runtime_sha256,
                    "install": { "success": install_current.success, "atomicReplacement": install_current.committed },
                    "commands": [version_invocation, repair_invocation, status_invocation],
                    "codexExecutable": codex_executable,
                    "qualificationProofs": {
                        "commandPath": qualification_proofs.get("commandPath"),
                        "qualificationPath": qualification_proofs.get("qualificationPath"),
                    },
                }),
            )
        } else {
            failed_gate(
                "installed-product",
                "installed binary lifecycle command failed or returned an unexpected release",
                json!({
                    "productRoot": product_root,
                    "commands": [version_invocation, repair_invocation, status_invocation],
                    "codexExecutable": codex_executable,
                    "setupComplete": setup_complete,
                    "qualificationProofs": {
                        "valid": qualification_proofs.get("valid"),
                        "reason": qualification_proofs.get("reason"),
                    },
                }),
            )
        },
    );

    {
        let resolved = resolve_path_command(&product_root, "legion.exe", &platform, environment.get("PATH").map(String::as_str).unwrap_or_default());
        let mut env_for_call = environment.clone();
        env_for_call.insert("PATH".to_string(), format!("{};{}", product_root.join("bin").display(), environment.get("PATH").cloned().unwrap_or_default()));
        let invocation = run_command("legion.exe", &["--version".to_string()], Some(&CommandOptions { cwd: product_root.clone(), env: env_for_call }));
        let pass = resolved.is_some() && version_output_matches(&invocation, &current.release_version);
        gates.insert(
            "command-resolution".to_string(),
            if pass {
                gate("command-resolution", "pass", json!({ "resolvedPath": resolved, "command": invocation }))
            } else {
                failed_gate(
                    "command-resolution",
                    "installed legion.exe was not resolved and executed from isolated PATH",
                    json!({ "resolvedPath": resolved, "command": invocation }),
                )
            },
        );
    }

    {
        let pass = setup_complete;
        gates.insert(
            "client-integration".to_string(),
            if pass {
                gate(
                    "client-integration",
                    "pass",
                    json!({
                        "client": "codex",
                        "repair": repair_invocation,
                        "setupStatus": status_invocation,
                        "codexExecutable": codex_executable,
                        "qualificationProofs": {
                            "commandPath": qualification_proofs.get("commandPath"),
                            "qualificationPath": qualification_proofs.get("qualificationPath"),
                        },
                    }),
                )
            } else {
                failed_gate(
                    "client-integration",
                    "isolated Codex repair, status, projection, or live M1 evidence did not complete",
                    json!({
                        "client": "codex",
                        "repair": repair_invocation,
                        "setupStatus": status_invocation,
                        "codexExecutable": codex_executable,
                        "qualificationProofs": {
                            "valid": qualification_proofs.get("valid"),
                            "reason": qualification_proofs.get("reason"),
                        },
                    }),
                )
            },
        );
    }

    let mut prior_tree_sha256: Option<String> = None;
    let mut prior_health: Option<Value> = None;
    let mut rollback_health: Option<Value> = None;
    let mut final_health: Option<Value> = None;

    match &prior {
        None => {
            gates.insert("update".to_string(), unproven_gate("update", "prior archive was not supplied; update cannot be proven"));
            gates.insert("rollback".to_string(), unproven_gate("rollback", "prior archive was not supplied; rollback cannot be proven"));
        }
        Some(prior_info) => {
            let prior_root_path = prior_version_root.clone().unwrap();
            prior_tree_sha256 = Some(tree_digest(&prior_root)?);
            let archives_differ = !digest_matches(prior_archive_sha256.as_deref(), Some(&archive_sha256));
            let runtimes_differ = !digest_matches(Some(&prior_info.runtime_sha256), Some(&current.runtime_sha256));
            let downgrade = compare_versions(&current.release_version, &prior_info.release_version) < 0;
            if downgrade && !allow_downgrade {
                gates.insert(
                    "update".to_string(),
                    failed_gate(
                        "update",
                        "downgrade requires explicit allowDowngrade",
                        json!({ "from": prior_info.release_version, "to": current.release_version, "allowDowngrade": allow_downgrade }),
                    ),
                );
                gates.insert("rollback".to_string(), unproven_gate("rollback", "rollback is unproven when downgrade was not explicitly allowed"));
            } else {
                let seed_prior = atomic_replace_product(&prior_root, &product_root, &run_root, None)?;
                let pointer_written = seed_prior.success && write_pointer(&previous_pointer, &prior_root_path)?;
                let seeded_prior_release = CurrentRelease { release_version: &prior_info.release_version, runtime_sha256: &prior_info.runtime_sha256 };
                let computed_prior_health = if seed_prior.success {
                    Some(setup_health(
                        &run_command,
                        &env.state,
                        &installed_launcher,
                        codex_executable.as_deref(),
                        &seeded_prior_release,
                        &prior_info.generation,
                        &normalized_architecture,
                        Some(&prior_root_path),
                    ))
                } else {
                    None
                };
                prior_health = computed_prior_health.clone();
                integration_journal = write_integration_journal(
                    &integration_journal_path,
                    integration_journal_record(IntegrationJournalInput {
                        state_root: &env.state,
                        current_path: &product_root,
                        previous_path: &previous_pointer,
                        active_version_root: &prior_root_path,
                        prior_version_root: Some(&prior_root_path),
                        target_version: &current.release_version,
                        prior_version: Some(&prior_info.release_version),
                        state_name: "update-pending",
                        prior_health: prior_health.as_ref(),
                        current_health: prior_health.as_ref(),
                    }),
                )?;
                let update_attempt = atomic_replace_product(&current_root, &product_root, &run_root, None)?;
                let updated_identity = if update_attempt.success { release_metadata(&product_root, &normalized_architecture, "updated product").ok() } else { None };
                let update_health = if update_attempt.success {
                    Some(setup_health(
                        &run_command,
                        &env.state,
                        &installed_launcher,
                        codex_executable.as_deref(),
                        &current_release,
                        &current.generation,
                        &normalized_architecture,
                        Some(&current_version_root),
                    ))
                } else {
                    None
                };
                let retained_versions = retained_version_matches(Some(&current_version_root), Some(&current), &normalized_architecture, "retained current version")
                    && retained_version_matches(prior_version_root.as_deref(), Some(prior_info), &normalized_architecture, "retained prior version");
                let update_pass = seed_prior.success
                    && pointer_written
                    && prior_health.as_ref().and_then(|h| h.get("complete")).and_then(|v| v.as_bool()).unwrap_or(false)
                    && update_attempt.success
                    && update_health.as_ref().and_then(|h| h.get("complete")).and_then(|v| v.as_bool()).unwrap_or(false)
                    && updated_identity.as_ref().map(|i| i.release_version == current.release_version).unwrap_or(false)
                    && updated_identity.as_ref().map(|i| digest_matches(Some(&i.runtime_sha256), Some(&current.runtime_sha256))).unwrap_or(false)
                    && updated_identity.as_ref().map(|i| i.generation == current.generation).unwrap_or(false)
                    && update_attempt.backup_moved
                    && archives_differ
                    && runtimes_differ
                    && retained_versions;
                integration_journal = write_integration_journal(
                    &integration_journal_path,
                    integration_journal_record(IntegrationJournalInput {
                        state_root: &env.state,
                        current_path: &product_root,
                        previous_path: &previous_pointer,
                        active_version_root: &current_version_root,
                        prior_version_root: Some(&prior_root_path),
                        target_version: &current.release_version,
                        prior_version: Some(&prior_info.release_version),
                        state_name: if update_pass { "updated" } else { "update-failed" },
                        prior_health: prior_health.as_ref(),
                        current_health: update_health.as_ref(),
                    }),
                )?;
                gates.insert(
                    "update".to_string(),
                    if update_pass {
                        gate(
                            "update",
                            "pass",
                            json!({
                                "from": prior_info.release_version,
                                "to": current.release_version,
                                "backupAndAtomicReplacement": true,
                                "stableCurrentPath": product_root,
                                "activationPath": installed_launcher,
                                "origin": WindowsInstallContract::ORIGIN,
                                "installRoot": install_root,
                                "generation": current.generation,
                                "resolvedVersionRoot": current_version_root,
                                "retainedPriorVersionRoot": prior_root_path,
                                "integrationJournal": integration_journal_path,
                                "priorHealthSha256": prior_health.as_ref().and_then(|h| h.get("fingerprint")),
                                "currentHealthSha256": update_health.as_ref().and_then(|h| h.get("fingerprint")),
                                "archivesDiffer": archives_differ,
                                "runtimesDiffer": runtimes_differ,
                                "productRoot": product_root,
                            }),
                        )
                    } else {
                        failed_gate(
                            "update",
                            "update must retain prior version, restore integrations, and pass exact setup health",
                            json!({
                                "seedPrior": seed_prior.success,
                                "updateAttempt": update_attempt.success,
                                "priorHealth": prior_health,
                                "updateHealth": update_health,
                                "retainedVersions": retained_versions,
                                "archivesDiffer": archives_differ,
                                "runtimesDiffer": runtimes_differ,
                                "priorArchiveSha256": prior_archive_sha256,
                                "archiveSha256": archive_sha256,
                                "priorRuntimeSha256": prior_info.runtime_sha256,
                                "runtimeSha256": current.runtime_sha256,
                                "productRoot": product_root,
                            }),
                        )
                    },
                );

                let seed_prior_for_rollback = atomic_replace_product(&prior_root, &product_root, &run_root, None)?;
                let injected = std::cell::Cell::new(false);
                let inject_failure = |phase_after_backup: bool| -> Result<(), String> {
                    if phase_after_backup {
                        return Err("injected qualification failure after backup rename".to_string());
                    }
                    Ok(())
                };
                let _ = &injected;
                let rollback_inject: Box<dyn Fn() -> Result<(), String>> = Box::new(move || inject_failure(true));
                let rollback_attempt = atomic_replace_product(&current_root, &product_root, &run_root, Some(rollback_inject.as_ref()))?;
                let restored_prior = if product_root.exists() { Some(tree_digest(&product_root)?) } else { None };
                if rollback_attempt.rolled_back {
                    rollback_health = Some(setup_health(
                        &run_command,
                        &env.state,
                        &installed_launcher,
                        codex_executable.as_deref(),
                        &seeded_prior_release,
                        &prior_info.generation,
                        &normalized_architecture,
                        Some(&prior_root_path),
                    ));
                }
                let restored_prior_health = prior_health.as_ref().and_then(|h| h.get("complete")).and_then(|v| v.as_bool()).unwrap_or(false)
                    && rollback_health.as_ref().and_then(|h| h.get("complete")).and_then(|v| v.as_bool()).unwrap_or(false)
                    && prior_health.as_ref().and_then(|h| h.get("fingerprint")) == rollback_health.as_ref().and_then(|h| h.get("fingerprint"));
                let rollback_pointer_restored = previous_pointer.exists()
                    && fs::read_to_string(&previous_pointer).map(|s| s.trim() == prior_root_path.to_string_lossy()).unwrap_or(false);
                let rollback_pass = seed_prior_for_rollback.success
                    && !rollback_attempt.success
                    && rollback_attempt.rolled_back
                    && restored_prior.as_deref() == prior_tree_sha256.as_deref()
                    && restored_prior_health
                    && rollback_pointer_restored
                    && archives_differ
                    && runtimes_differ;
                integration_journal = write_integration_journal(
                    &integration_journal_path,
                    integration_journal_record(IntegrationJournalInput {
                        state_root: &env.state,
                        current_path: &product_root,
                        previous_path: &previous_pointer,
                        active_version_root: &prior_root_path,
                        prior_version_root: Some(&prior_root_path),
                        target_version: &current.release_version,
                        prior_version: Some(&prior_info.release_version),
                        state_name: if rollback_pass { "rollback-restored" } else { "rollback-failed" },
                        prior_health: prior_health.as_ref(),
                        current_health: rollback_health.as_ref(),
                    }),
                )?;
                gates.insert(
                    "rollback".to_string(),
                    if rollback_pass {
                        gate(
                            "rollback",
                            "pass",
                            json!({
                                "injectedFailure": true,
                                "stableCurrentPath": product_root,
                                "activationPath": installed_launcher,
                                "origin": WindowsInstallContract::ORIGIN,
                                "installRoot": install_root,
                                "generation": prior_info.generation,
                                "resolvedVersionRoot": prior_root_path,
                                "previousPointer": previous_pointer,
                                "retainedPriorVersionRoot": prior_root_path,
                                "integrationsRestored": true,
                                "priorHealthRestored": true,
                                "priorHealthSha256": rollback_health.as_ref().and_then(|h| h.get("fingerprint")),
                                "integrationJournal": integration_journal_path,
                                "restoredPriorSha256": restored_prior,
                                "archivesDiffer": archives_differ,
                                "runtimesDiffer": runtimes_differ,
                                "productRoot": product_root,
                            }),
                        )
                    } else {
                        failed_gate(
                            "rollback",
                            "failed update must restore pointer, integrations, prior version, and exact prior health",
                            json!({
                                "seedPriorForRollback": seed_prior_for_rollback.success,
                                "rollbackAttempt": rollback_attempt.success,
                                "restoredPrior": restored_prior,
                                "expectedPrior": prior_tree_sha256,
                                "priorHealth": prior_health,
                                "rollbackHealth": rollback_health,
                                "rollbackPointerRestored": rollback_pointer_restored,
                                "archivesDiffer": archives_differ,
                                "runtimesDiffer": runtimes_differ,
                                "productRoot": product_root,
                            }),
                        )
                    },
                );

                let restored_current = atomic_replace_product(&current_root, &product_root, &run_root, None)?;
                if restored_current.success {
                    final_health = Some(setup_health(
                        &run_command,
                        &env.state,
                        &installed_launcher,
                        codex_executable.as_deref(),
                        &current_release,
                        &current.generation,
                        &normalized_architecture,
                        Some(&current_version_root),
                    ));
                }
            }
        }
    }

    if final_health.is_some() {
        integration_journal = write_integration_journal(
            &integration_journal_path,
            integration_journal_record(IntegrationJournalInput {
                state_root: &env.state,
                current_path: &product_root,
                previous_path: &previous_pointer,
                active_version_root: &current_version_root,
                prior_version_root: prior_version_root.as_deref(),
                target_version: &current.release_version,
                prior_version: prior.as_ref().map(|p| p.release_version.as_str()),
                state_name: "ready-for-uninstall",
                prior_health: prior_health.as_ref(),
                current_health: final_health.as_ref(),
            }),
        )?;
    }

    let marker_bytes = b"foreign marker\n";
    if !foreign_marker.exists() {
        fs::write(&foreign_marker, marker_bytes).map_err(|e| e.to_string())?;
    } else {
        assert_regular_file(&foreign_marker, "foreign marker")?;
    }
    let marker_before = fs::read(&foreign_marker).map_err(|e| e.to_string())?;
    remove_exact(&product_root, &run_root, "product root for uninstall")?;
    let marker_after = fs::read(&foreign_marker).map_err(|e| e.to_string())?;
    let durable_state_retained = retained_version_matches(Some(&current_version_root), Some(&current), &normalized_architecture, "retained current version")
        && (prior.is_none() || retained_version_matches(prior_version_root.as_deref(), prior.as_ref(), &normalized_architecture, "retained prior version"))
        && integration_journal_path.exists()
        && integration_journal.get("kind").and_then(|v| v.as_str()) == Some("legion-integration-journal");
    let uninstall_pass = !product_root.exists() && marker_before == marker_after && durable_state_retained;
    gates.insert(
        "uninstall".to_string(),
        if uninstall_pass {
            gate(
                "uninstall",
                "pass",
                json!({
                    "productRootRemoved": true,
                    "foreignMarkerPreserved": true,
                    "foreignMarker": foreign_marker,
                    "durableStateRetained": durable_state_retained,
                    "retainedCurrentVersionRoot": current_version_root,
                    "retainedPriorVersionRoot": prior_version_root,
                    "integrationJournal": integration_journal_path,
                }),
            )
        } else {
            failed_gate(
                "uninstall",
                "product root was not removed, durable state was not retained, or foreign marker changed",
                json!({
                    "productRoot": product_root,
                    "foreignMarker": foreign_marker,
                    "durableStateRetained": durable_state_retained,
                    "integrationJournal": integration_journal_path,
                }),
            )
        },
    );

    let gates_value = Value::Object(gates);
    let lifecycle_pass = all_gates_pass(&gates_value);
    let status = if lifecycle_pass && !simulated { "qualified" } else { "blocked" };

    let mut receipt = json!({
        "schemaVersion": 1,
        "kind": "legion-windows-installed-product-qualification",
        "status": status,
        "nativeExecution": !simulated,
        "executionMode": if simulated { "simulated" } else { "native" },
        "targetIdentity": identity,
        "releaseVersion": current.release_version,
        "sourceRevision": revision,
        "archiveSha256": archive_sha256,
        "runtimeSha256": current.runtime_sha256,
        "runner": { "os": platform, "architecture": runner_architecture, "simulated": simulated },
        "origin": WindowsInstallContract::ORIGIN,
        "installRoot": install_root,
        "executable": installed_launcher,
        "generation": current.generation,
        "binding": {
            "origin": WindowsInstallContract::ORIGIN,
            "installRoot": install_root,
            "currentPath": product_root,
            "executable": installed_launcher,
            "generation": current.generation,
            "resolvedVersionRoot": current_version_root,
        },
        "install": {
            "root": install_root,
            "origin": WindowsInstallContract::ORIGIN,
            "currentPath": product_root,
            "executable": installed_launcher,
            "generation": current.generation,
            "previousPath": previous_pointer,
            "nextPath": stable_paths.next,
            "versionsRoot": versions_root,
            "currentVersionRoot": current_version_root,
            "priorVersionRoot": prior_version_root,
            "integrationJournal": integration_journal_path,
            "allowDowngrade": allow_downgrade,
        },
        "integrationJournal": integration_journal,
        "health": {
            "current": current_health.get("fingerprint"),
            "currentVersionRoot": current_version_root,
            "prior": prior_health.as_ref().and_then(|h| h.get("fingerprint")),
            "priorVersionRoot": prior_version_root,
            "rollback": rollback_health.as_ref().and_then(|h| h.get("fingerprint")),
            "final": final_health.as_ref().and_then(|h| h.get("fingerprint")),
        },
        "gates": gates_value,
        "archive": {
            "current": { "path": current_archive, "sha256": archive_sha256 },
        },
        "isolatedWorkRoot": run_root,
    });

    if let (Some(receipt_obj), Some(prior_archive_path)) = (receipt.as_object_mut(), &prior_archive) {
        if let Some(archive_obj) = receipt_obj.get_mut("archive").and_then(|v| v.as_object_mut()) {
            archive_obj.insert("prior".to_string(), json!({ "path": prior_archive_path, "sha256": prior_archive_sha256 }));
        }
        if let Some(prior_info) = &prior {
            receipt_obj.insert("priorReleaseVersion".to_string(), json!(prior_info.release_version));
            receipt_obj.insert("priorArchiveSha256".to_string(), json!(prior_archive_sha256));
            receipt_obj.insert("priorRuntimeSha256".to_string(), json!(prior_info.runtime_sha256));
        }
    }
    if status != "qualified" {
        let reason = if simulated {
            "injected archive, command, platform, architecture, or executable seams are simulated and cannot qualify a native Windows release"
        } else {
            "all six lifecycle gates must pass; unproven gates cannot qualify"
        };
        if let Some(obj) = receipt.as_object_mut() {
            obj.insert("reason".to_string(), json!(reason));
        }
    }

    let receipt_path = write_receipt(&output, &receipt)?;
    if let Some(obj) = receipt.as_object_mut() {
        obj.insert("receiptPath".to_string(), json!(receipt_path));
    }
    Ok(receipt)
}

#[allow(dead_code)]
fn unused_env_map() -> BTreeMap<String, String> {
    BTreeMap::new()
}
