//! Codex live-client proof validation and `setup status`/`repair` health
//! checks, ported from `qualify-windows-release.mjs`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::windows_release_config::WindowsInstallContract;
use crate::windows_release_support::{digest_matches, has_forbidden_binding_segment, is_nonempty_digest, sha256_prefixed};
// The JS qualifier's pathsEqual resolved both sides (realpath), unlike the packager's.
use crate::windows_release_support::canonical_paths_equal as paths_equal;

use super::tree::{CommandOptions, CommandOutcome};

pub const QUALIFICATION_SCHEMA_VERSION: i64 = 2;
pub const QUALIFICATION_MECHANISM: &str = "agent-plugins-bare-command";
pub const QUALIFICATION_SERVER: &str = "legion";
pub const QUALIFICATION_TOOL: &str = "legion_m1_status";
pub fn qualification_mcp_args() -> Vec<&'static str> {
    vec!["serve", "--stdio"]
}

/// Mirrors `resolveCodexExecutable`.
pub fn resolve_codex_executable(path_value: &str, platform: &str) -> Option<PathBuf> {
    let separator = if platform == "win32" { ';' } else { ':' };
    let names: Vec<&str> = if platform == "win32" {
        vec!["codex.exe", "codex.cmd", "codex.bat", "codex"]
    } else {
        vec!["codex"]
    };
    for entry in path_value.split(separator).filter(|e| !e.is_empty()) {
        for name in &names {
            let candidate = Path::new(entry).join(name);
            if has_forbidden_binding_segment(&candidate.to_string_lossy()) {
                continue;
            }
            if let Ok(actual) = fs::canonicalize(&candidate) {
                if let Ok(metadata) = fs::symlink_metadata(&actual) {
                    if !has_forbidden_binding_segment(&actual.to_string_lossy()) && metadata.is_file() && !metadata.file_type().is_symlink() {
                        return Some(actual);
                    }
                }
            }
        }
    }
    None
}

pub struct EnvResult {
    pub home: PathBuf,
    pub codex_root: PathBuf,
    pub state: PathBuf,
    pub environment: BTreeMap<String, String>,
}

/// Mirrors `commandEnvironment`: builds an isolated HOME/USERPROFILE tree and
/// scrubs `LEGION_M1_CONFIG`/`LEGION_NATIVE_APPLICATION_CONFIG`/`PATH` from
/// the inherited environment.
pub fn command_environment(work_root: &Path, codex_executable: Option<&Path>, host_path: &str) -> Result<EnvResult, String> {
    let home = work_root.join("home");
    let codex_root = home.join(".codex");
    let local = home.join("local");
    let roaming = home.join("roaming");
    let data = home.join("data");
    let state = home.join("state").join("Legion");
    let temp = home.join("temp");
    for directory in [&home, &codex_root, &local, &roaming, &data, &state, &temp] {
        super::tree::assert_directory(directory, "isolated environment directory", true)?;
    }
    if let Some(codex) = codex_executable {
        crate::windows_release_support::assert_regular_file(codex, "Codex executable")?;
    }
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    environment.remove("LEGION_M1_CONFIG");
    environment.remove("LEGION_NATIVE_APPLICATION_CONFIG");
    environment.remove("PATH");
    environment.remove("Path");
    environment.remove("path");
    let codex_path = codex_executable.and_then(|c| c.parent()).map(|p| p.to_string_lossy().to_string());
    let path_value = [codex_path.as_deref(), Some(host_path)]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(";");
    environment.insert("HOME".to_string(), home.to_string_lossy().to_string());
    environment.insert("USERPROFILE".to_string(), home.to_string_lossy().to_string());
    environment.insert("CODEX_HOME".to_string(), codex_root.to_string_lossy().to_string());
    environment.insert("LOCALAPPDATA".to_string(), local.to_string_lossy().to_string());
    environment.insert("APPDATA".to_string(), roaming.to_string_lossy().to_string());
    environment.insert("XDG_DATA_HOME".to_string(), data.to_string_lossy().to_string());
    environment.insert("LEGION_STATE_ROOT".to_string(), state.to_string_lossy().to_string());
    environment.insert("TEMP".to_string(), temp.to_string_lossy().to_string());
    environment.insert("TMP".to_string(), temp.to_string_lossy().to_string());
    environment.insert("PATH".to_string(), path_value);
    Ok(EnvResult { home, codex_root, state, environment })
}

/// Mirrors `proofReleaseMatches`.
fn proof_release_matches(proof: &Value, release_version: &str, runtime_sha256: &str) -> bool {
    match proof.get("release") {
        Some(release) if release.is_object() => {
            release.get("releaseVersion").and_then(|v| v.as_str()) == Some(release_version)
                && digest_matches(release.get("runtimeDigest").and_then(|v| v.as_str()), Some(runtime_sha256))
        }
        _ => false,
    }
}

/// Mirrors `proofClientRecord`.
pub fn proof_client_record(payload: Option<&Value>, execution: bool) -> Option<Value> {
    let payload = payload?;
    let clients = if execution {
        payload.pointer("/execution/clients")
    } else {
        payload.get("clients")
    };
    let clients = clients?.as_array()?;
    let matches: Vec<&Value> = clients.iter().filter(|c| c.get("clientId").and_then(|v| v.as_str()) == Some("codex")).collect();
    if matches.len() == 1 {
        Some(matches[0].clone())
    } else {
        None
    }
}

/// Mirrors `proofRecordComplete`.
pub fn proof_record_complete(record: Option<&Value>) -> bool {
    match record {
        Some(record) => {
            record.get("clientId").and_then(|v| v.as_str()) == Some("codex")
                && record.get("installed").and_then(|v| v.as_bool()) == Some(true)
                && record.get("fidelity").and_then(|v| v.as_str()) == Some("Full")
        }
        None => false,
    }
}

/// Mirrors `codexProjectionCurrent`.
pub fn codex_projection_current(payload: &Value) -> bool {
    payload.pointer("/liveIdentity/projections/codexSkills/state").and_then(|v| v.as_str()) == Some("current")
}

/// Mirrors `liveExecutableMatches`.
#[allow(clippy::too_many_arguments)]
pub fn live_executable_matches(
    payload: &Value,
    installed_launcher: &Path,
    release_version: &str,
    runtime_sha256: &str,
    generation_expected: &str,
    architecture: &str,
    install_root: &Path,
    active_version_root: Option<&Path>,
) -> bool {
    let executable = match payload.pointer("/liveIdentity/executable") {
        Some(v) if v.is_object() => v,
        _ => return false,
    };
    let binding = payload.pointer("/liveIdentity/binding");
    let executable_binding = executable.get("binding");
    let origin = executable
        .get("origin")
        .and_then(|v| v.as_str())
        .or_else(|| executable_binding.and_then(|b| b.get("origin")).and_then(|v| v.as_str()))
        .or_else(|| binding.and_then(|b| b.get("origin")).and_then(|v| v.as_str()))
        .or_else(|| payload.pointer("/liveIdentity/origin").and_then(|v| v.as_str()));
    let observed_install_root = executable
        .get("installRoot")
        .and_then(|v| v.as_str())
        .or_else(|| executable_binding.and_then(|b| b.get("installRoot")).and_then(|v| v.as_str()))
        .or_else(|| binding.and_then(|b| b.get("installRoot")).and_then(|v| v.as_str()))
        .or_else(|| payload.pointer("/liveIdentity/installRoot").and_then(|v| v.as_str()));
    let generation = executable
        .get("generation")
        .and_then(|v| v.as_str())
        .or_else(|| executable_binding.and_then(|b| b.get("generation")).and_then(|v| v.as_str()))
        .or_else(|| binding.and_then(|b| b.get("generation")).and_then(|v| v.as_str()))
        .or_else(|| payload.pointer("/liveIdentity/generation").and_then(|v| v.as_str()));
    let runtime_platform = executable.get("runtimePlatform").and_then(|v| v.as_str()).unwrap_or_default().to_lowercase();
    let stable_manifest_path = installed_launcher
        .parent() // bin
        .and_then(|p| p.parent()) // current
        .map(|p| p.join("share").join("legion").join("release.json"));
    let resolved_manifest_path = active_version_root.map(|root| root.join("share").join("legion").join("release.json"));
    let manifest_path = executable.get("manifestPath").and_then(|v| v.as_str());

    executable.get("state").and_then(|v| v.as_str()) == Some("current")
        && origin == Some(WindowsInstallContract::ORIGIN)
        && lexical_paths_equal(observed_install_root, Some(&install_root.to_string_lossy()))
        && generation == Some(generation_expected)
        && !has_forbidden_binding_segment(executable.get("path").and_then(|v| v.as_str()).unwrap_or_default())
        && !has_forbidden_binding_segment(observed_install_root.unwrap_or_default())
        && !has_forbidden_binding_segment(manifest_path.unwrap_or_default())
        && lexical_paths_equal(executable.get("path").and_then(|v| v.as_str()), Some(&installed_launcher.to_string_lossy()))
        && (paths_equal(manifest_path, stable_manifest_path.as_ref().map(|p| p.to_string_lossy()).as_deref())
            || (resolved_manifest_path.is_some()
                && paths_equal(manifest_path, resolved_manifest_path.as_ref().map(|p| p.to_string_lossy()).as_deref())))
        && executable.get("releaseVersion").and_then(|v| v.as_str()) == Some(release_version)
        && executable.get("expectedReleaseVersion").and_then(|v| v.as_str()) == Some(release_version)
        && digest_matches(executable.get("runtimeDigest").and_then(|v| v.as_str()), Some(runtime_sha256))
        && ["windows", "win32", "win"].contains(&runtime_platform.as_str())
        && executable.get("runtimeArchitecture").and_then(|v| v.as_str()) == Some(architecture)
}

/// Mirrors `lexicalPathsEqual`.
fn lexical_paths_equal(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(l), Some(r)) => {
            let nl = Path::new(l).to_string_lossy().replace('\\', "/").to_lowercase();
            let nr = Path::new(r).to_string_lossy().replace('\\', "/").to_lowercase();
            !l.is_empty() && !r.is_empty() && nl == nr
        }
        _ => false,
    }
}

/// Mirrors `proofRefsMatch`.
pub fn proof_refs_match(record: Option<&Value>, command_path: &Path, qualification_path: &Path) -> bool {
    let record = match record {
        Some(r) => r,
        None => return false,
    };
    let command_ref = record.get("commandProofRef").and_then(|v| v.as_str());
    let qualification_ref = record.get("qualificationEvidenceRef").and_then(|v| v.as_str());
    !has_forbidden_binding_segment(command_ref.unwrap_or_default())
        && !has_forbidden_binding_segment(qualification_ref.unwrap_or_default())
        && paths_equal(command_ref, Some(&command_path.to_string_lossy()))
        && paths_equal(qualification_ref, Some(&qualification_path.to_string_lossy()))
}

pub struct CurrentRelease<'a> {
    pub release_version: &'a str,
    pub runtime_sha256: &'a str,
}

/// Mirrors `validateLiveCodexProofs`.
pub fn validate_live_codex_proofs(
    state: &Path,
    installed_launcher: &Path,
    codex_executable: &Path,
    current: &CurrentRelease,
) -> Value {
    let qualification_root = state.join("qualification");
    let command_path = qualification_root.join("codex-command.json");
    let qualification_path = qualification_root.join("codex-qualification.json");
    let command = crate::windows_release_support::read_json(&command_path, "Codex command proof");
    let qualification = crate::windows_release_support::read_json(&qualification_path, "Codex qualification proof");
    let (command, qualification) = match (command, qualification) {
        (Ok(c), Ok(q)) => (c, q),
        (Err(e), _) | (_, Err(e)) => {
            return json!({
                "valid": false,
                "commandPath": command_path,
                "qualificationPath": qualification_path,
                "reason": e,
            });
        }
    };
    let installed_bytes = fs::read(installed_launcher).unwrap_or_default();
    let codex_bytes = fs::read(codex_executable).unwrap_or_default();
    let installed_digest = crate::windows_release_support::sha256_hex(&installed_bytes);
    let codex_digest = sha256_prefixed(&codex_bytes);

    let command_valid = command.get("schemaVersion").and_then(|v| v.as_i64()) == Some(QUALIFICATION_SCHEMA_VERSION)
        && command.get("kind").and_then(|v| v.as_str()) == Some("legion-command-resolution-proof")
        && command.get("clientId").and_then(|v| v.as_str()) == Some("codex")
        && command.get("mechanism").and_then(|v| v.as_str()) == Some(QUALIFICATION_MECHANISM)
        && proof_release_matches(&command, current.release_version, current.runtime_sha256)
        && paths_equal(command.get("launcherPath").and_then(|v| v.as_str()), Some(&codex_executable.to_string_lossy()))
        && digest_matches(command.get("launcherSha256").and_then(|v| v.as_str()), Some(&codex_digest))
        && command.get("resolved").and_then(|v| v.as_bool()) == Some(true)
        && command.get("exitCode").and_then(|v| v.as_i64()) == Some(0)
        && is_nonempty_digest(command.get("outputSha256").and_then(|v| v.as_str()))
        && command.get("legionCommand").and_then(|v| v.as_str()) == Some("legion --version")
        && command.get("legionResolved").and_then(|v| v.as_bool()) == Some(true)
        && command.get("legionExitCode").and_then(|v| v.as_i64()) == Some(0)
        && paths_equal(command.get("legionLauncherPath").and_then(|v| v.as_str()), Some(&installed_launcher.to_string_lossy()))
        && digest_matches(command.get("legionLauncherSha256").and_then(|v| v.as_str()), Some(&installed_digest))
        && is_nonempty_digest(command.get("legionOutputSha256").and_then(|v| v.as_str()))
        && command.get("mcpCommand").and_then(|v| v.as_str()) == Some(QUALIFICATION_SERVER)
        && command.get("mcpArgs") == Some(&json!(qualification_mcp_args()));

    let qualification_valid = qualification.get("schemaVersion").and_then(|v| v.as_i64()) == Some(QUALIFICATION_SCHEMA_VERSION)
        && qualification.get("kind").and_then(|v| v.as_str()) == Some("legion-real-client-qualification")
        && qualification.get("clientId").and_then(|v| v.as_str()) == Some("codex")
        && qualification.get("mechanism").and_then(|v| v.as_str()) == Some(QUALIFICATION_MECHANISM)
        && proof_release_matches(&qualification, current.release_version, current.runtime_sha256)
        && paths_equal(qualification.get("launcherPath").and_then(|v| v.as_str()), Some(&codex_executable.to_string_lossy()))
        && qualification.get("mcpServer").and_then(|v| v.as_str()) == Some(QUALIFICATION_SERVER)
        && qualification.get("mcpTool").and_then(|v| v.as_str()) == Some(QUALIFICATION_TOOL)
        && qualification.get("invocationStatus").and_then(|v| v.as_str()) == Some("complete")
        && qualification.get("observedReleaseVersion").and_then(|v| v.as_str()) == Some(current.release_version)
        && qualification.get("capabilityCount").and_then(|v| v.as_i64()).map(|n| n > 0).unwrap_or(false)
        && qualification.get("hostRequirements").and_then(|v| v.as_array()).is_some()
        && qualification.get("capabilities").and_then(|v| v.as_array()).is_some()
        && qualification.get("capabilities").and_then(|v| v.as_array()).map(|a| a.len()) == qualification.get("capabilityCount").and_then(|v| v.as_i64()).map(|n| n as usize)
        && qualification.get("hostRequirements").and_then(|v| v.as_array()).map(|a| a.iter().all(|v| v.is_object())).unwrap_or(false)
        && qualification.get("capabilities").and_then(|v| v.as_array()).map(|a| a.iter().all(|v| v.is_object())).unwrap_or(false)
        && qualification.get("degradedCount").and_then(|v| v.as_i64()).map(|n| n >= 0).unwrap_or(false)
        && qualification.get("degradedCount").and_then(|v| v.as_i64()) <= qualification.get("capabilityCount").and_then(|v| v.as_i64())
        && qualification.get("completed").and_then(|v| v.as_bool()) == Some(true)
        && is_nonempty_digest(qualification.get("outputSha256").and_then(|v| v.as_str()))
        && paths_equal(qualification.get("legionLauncherPath").and_then(|v| v.as_str()), Some(&installed_launcher.to_string_lossy()))
        && digest_matches(qualification.get("legionLauncherSha256").and_then(|v| v.as_str()), Some(&installed_digest))
        && qualification.get("mcpCommand").and_then(|v| v.as_str()) == Some(QUALIFICATION_SERVER)
        && qualification.get("mcpArgs") == Some(&json!(qualification_mcp_args()));

    let valid = command_valid && qualification_valid;
    json!({
        "valid": valid,
        "commandPath": command_path,
        "qualificationPath": qualification_path,
        "command": command,
        "qualification": qualification,
        "reason": if valid { Value::Null } else { Value::String("Codex command or completed M1 qualification proof is invalid".to_string()) },
    })
}

/// Mirrors `invocationRecord`.
pub fn invocation_record(command: &str, args: &[String], result: CommandOutcome) -> Value {
    let stdout_sha = sha256_prefixed(result.stdout.as_bytes());
    let stderr_sha = sha256_prefixed(result.stderr.as_bytes());
    let combined = format!("{}{}", result.stdout, result.stderr);
    let output_sha = sha256_prefixed(combined.as_bytes());
    let mut value = json!({
        "command": command,
        "args": args,
        "exitCode": result.exit_code,
        "stdoutSha256": stdout_sha,
        "stderrSha256": stderr_sha,
        "outputSha256": output_sha,
        "stdout": result.stdout,
        "stderr": result.stderr,
    });
    if let Some(error) = result.error {
        value["error"] = json!(error);
    }
    if let Some(signal) = result.signal {
        value["signal"] = json!(signal);
    }
    value
}

pub fn command_succeeded(invocation: &Value) -> bool {
    invocation.get("exitCode").and_then(|v| v.as_i64()) == Some(0)
        && invocation.get("error").is_none()
        && invocation.get("signal").is_none()
}

pub fn parse_json_output(invocation: &Value) -> Option<Value> {
    let stdout = invocation.get("stdout").and_then(|v| v.as_str())?;
    if stdout.trim().is_empty() {
        return None;
    }
    serde_json::from_str(stdout).ok()
}

/// Mirrors `exactCompleteJson`.
pub fn exact_complete_json(invocation: &Value, kind: &str) -> Option<Value> {
    let stdout = invocation.get("stdout").and_then(|v| v.as_str()).unwrap_or_default();
    let stderr = invocation.get("stderr").and_then(|v| v.as_str()).unwrap_or_default();
    if !command_succeeded(invocation) || stdout.trim().is_empty() || !stderr.trim().is_empty() {
        return None;
    }
    let payload = parse_json_output(invocation)?;
    if payload.is_object()
        && payload.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1)
        && payload.get("kind").and_then(|v| v.as_str()) == Some(kind)
        && payload.get("status").and_then(|v| v.as_str()) == Some("complete")
    {
        Some(payload)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
pub fn setup_health(
    run_command: &dyn Fn(&str, &[String], Option<&CommandOptions>) -> Value,
    state: &Path,
    installed_launcher: &Path,
    codex_executable: Option<&Path>,
    current: &CurrentRelease,
    current_generation: &str,
    architecture: &str,
    active_version_root: Option<&Path>,
) -> Value {
    let install_root = installed_launcher
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .unwrap_or(Path::new("."));
    let repair_args = vec!["--json".to_string(), "setup".to_string(), "repair".to_string(), "--confirm".to_string()];
    let repair_invocation = run_command(&installed_launcher.to_string_lossy(), &repair_args, None);
    let repair_payload = exact_complete_json(&repair_invocation, "legion-setup-execution");
    let status_args = vec!["--json".to_string(), "setup".to_string(), "status".to_string()];
    let status_invocation = run_command(&installed_launcher.to_string_lossy(), &status_args, None);
    let status_payload = exact_complete_json(&status_invocation, "legion-setup-status");

    let qualification_proofs = match codex_executable {
        Some(codex) => validate_live_codex_proofs(state, installed_launcher, codex, current),
        None => json!({
            "valid": false,
            "commandPath": state.join("qualification").join("codex-command.json"),
            "qualificationPath": state.join("qualification").join("codex-qualification.json"),
            "reason": "a real Codex executable was not resolved from the host PATH",
        }),
    };

    let repair_client = proof_client_record(repair_payload.as_ref(), true);
    let status_client = proof_client_record(status_payload.as_ref(), false);
    let qualification_valid = qualification_proofs.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
    let complete = repair_payload.is_some()
        && status_payload.is_some()
        && proof_record_complete(repair_client.as_ref())
        && proof_record_complete(status_client.as_ref())
        && repair_payload
            .as_ref()
            .map(|p| live_executable_matches(p, installed_launcher, current.release_version, current.runtime_sha256, current_generation, architecture, install_root, active_version_root))
            .unwrap_or(false)
        && status_payload
            .as_ref()
            .map(|p| live_executable_matches(p, installed_launcher, current.release_version, current.runtime_sha256, current_generation, architecture, install_root, active_version_root))
            .unwrap_or(false)
        && repair_payload.as_ref().map(codex_projection_current).unwrap_or(false)
        && status_payload.as_ref().map(codex_projection_current).unwrap_or(false)
        && qualification_valid
        && {
            let command_path = qualification_proofs.get("commandPath").and_then(|v| v.as_str()).map(PathBuf::from).unwrap_or_default();
            let qualification_path = qualification_proofs.get("qualificationPath").and_then(|v| v.as_str()).map(PathBuf::from).unwrap_or_default();
            proof_refs_match(repair_client.as_ref(), &command_path, &qualification_path)
                || proof_refs_match(status_client.as_ref(), &command_path, &qualification_path)
        };

    let fingerprint_source = json!({
        "repair": repair_payload,
        "status": status_payload,
        "commandProof": qualification_proofs.get("command"),
        "qualificationProof": qualification_proofs.get("qualification"),
    });
    let fingerprint = sha256_prefixed(serde_json::to_string(&fingerprint_source).unwrap_or_default().as_bytes());

    json!({
        "complete": complete,
        "origin": WindowsInstallContract::ORIGIN,
        "installRoot": install_root,
        "executable": installed_launcher,
        "generation": current_generation,
        "resolvedVersionRoot": active_version_root,
        "repairArgs": repair_args,
        "repairInvocation": repair_invocation,
        "repairPayload": repair_payload,
        "statusArgs": status_args,
        "statusInvocation": status_invocation,
        "statusPayload": status_payload,
        "qualificationProofs": qualification_proofs,
        "repairClient": repair_client,
        "statusClient": status_client,
        "fingerprint": fingerprint,
    })
}
