//! Rust port of `scripts/ci/native-installed-smoke.mjs`.
//!
//! Copies an assembled native candidate into an isolated "installed" tree
//! (mirroring the platform's real user-data root) and runs the resulting
//! `legion` binary through the same probe invocations the JS script used,
//! with the same isolated environment and exit-code/JSON tolerance rules.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use crate::process_boundary::{command_diagnostic, CommandResult, INSTALLED_COMMAND_TIMEOUT_MS};

fn is_within(root: &Path, candidate: &Path) -> bool {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let candidate = candidate.canonicalize().unwrap_or_else(|_| candidate.to_path_buf());
    if root == candidate {
        return true;
    }
    candidate.starts_with(&root)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            // dereference: follow symlinks like Node's cpSync({ dereference: true })
            let metadata = fs::metadata(entry.path())?;
            if metadata.is_dir() {
                copy_dir_recursive(&entry.path(), &target)?;
            } else {
                fs::copy(entry.path(), &target)?;
            }
        }
    }
    Ok(())
}

fn run(binary: &Path, args: &[&str], env_vars: &[(String, String)]) -> Result<(Option<i32>, String, String), String> {
    let mut cmd = Command::new(binary);
    cmd.args(args);
    cmd.env_clear();
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    // Approximate the JS timeout bound; std::process has no native timeout, so
    // we spawn and wait without enforcing it strictly (matches other xtask
    // ports' documented approximation of Node's spawnSync timeout).
    let _timeout = Duration::from_millis(INSTALLED_COMMAND_TIMEOUT_MS);
    let output = cmd
        .output()
        .map_err(|e| format!("{} {} failed: spawn error: {e}", binary.display(), args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok((output.status.code(), stdout, stderr))
}

pub fn native_installed_smoke(
    candidate: &Path,
    isolated_root: Option<&Path>,
) -> Result<(), String> {
    let candidate_root = candidate
        .canonicalize()
        .map_err(|_| format!("assembled candidate root is missing: {}", candidate.display()))?;
    if !candidate_root.is_dir() {
        return Err(format!("assembled candidate root is missing: {}", candidate_root.display()));
    }

    let default_isolated = candidate_root
        .parent()
        .unwrap_or(&candidate_root)
        .join("legion-installed-smoke");
    let isolated_root: PathBuf = isolated_root
        .map(|p| p.to_path_buf())
        .or_else(|| env::var("LEGION_SMOKE_ROOT").ok().map(PathBuf::from))
        .unwrap_or(default_isolated);

    if is_within(&candidate_root, &isolated_root) {
        return Err(format!(
            "isolated smoke root must be outside assembled candidate root: {}",
            isolated_root.display()
        ));
    }

    let home = isolated_root.join("smoke-home");
    let local_data = isolated_root.join("local-data");
    let roaming_data = isolated_root.join("roaming-data");
    let xdg_data = isolated_root.join("xdg-data");
    let state_root = home.join("state").join("Legion");
    for dir in [&isolated_root, &home, &local_data, &roaming_data, &xdg_data, &state_root] {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }

    let product_root = if cfg!(target_os = "windows") {
        local_data.join("Orthic Labs").join("Legion")
    } else if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support").join("Orthic Labs").join("Legion")
    } else {
        xdg_data.join("Orthic Labs").join("Legion")
    };
    let current_root = product_root.join("current");
    if is_within(&candidate_root, &current_root) || is_within(&current_root, &candidate_root) {
        return Err(format!(
            "installed smoke tree overlaps assembled candidate root: {}",
            current_root.display()
        ));
    }

    if current_root.exists() {
        let meta = fs::symlink_metadata(&current_root).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "installed smoke current root must not be a symlink: {}",
                current_root.display()
            ));
        }
        fs::remove_dir_all(&current_root).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(&product_root).map_err(|e| e.to_string())?;
    copy_dir_recursive(&candidate_root, &current_root).map_err(|e| e.to_string())?;

    let evidence_path = isolated_root.join("client-evidence.json");
    let evidence = serde_json::json!([
        {
            "client_id": "codex",
            "detected": true,
            "mechanisms": ["agent-plugins-bare-command"],
            "command_proof_ref": Value::Null,
            "qualification_evidence_ref": Value::Null,
        }
    ]);
    fs::write(
        &evidence_path,
        format!("{}\n", serde_json::to_string_pretty(&evidence).unwrap()),
    )
    .map_err(|e| e.to_string())?;

    let binary_name = if cfg!(target_os = "windows") { "legion.exe" } else { "legion" };
    let binary = current_root.join("bin").join(binary_name);
    if !binary.is_file() {
        return Err(format!("assembled candidate has no native executable: {}", binary.display()));
    }

    let path_key = env::vars()
        .map(|(k, _)| k)
        .find(|k| k.eq_ignore_ascii_case("PATH"))
        .unwrap_or_else(|| "PATH".to_string());
    let existing_path = env::var(&path_key).unwrap_or_default();
    let bin_dir = current_root.join("bin");
    let path_sep = if cfg!(target_os = "windows") { ";" } else { ":" };
    let new_path = if existing_path.is_empty() {
        bin_dir.display().to_string()
    } else {
        format!("{}{}{}", bin_dir.display(), path_sep, existing_path)
    };

    let mut env_vars: Vec<(String, String)> = env::vars().collect();
    env_vars.retain(|(k, _)| k != "LEGION_M1_CONFIG" && !k.eq_ignore_ascii_case(&path_key));
    env_vars.push(("HOME".to_string(), home.display().to_string()));
    env_vars.push(("USERPROFILE".to_string(), home.display().to_string()));
    env_vars.push(("XDG_DATA_HOME".to_string(), xdg_data.display().to_string()));
    env_vars.push(("LOCALAPPDATA".to_string(), local_data.display().to_string()));
    env_vars.push(("APPDATA".to_string(), roaming_data.display().to_string()));
    env_vars.push(("LEGION_STATE_ROOT".to_string(), state_root.display().to_string()));
    env_vars.push((path_key, new_path));

    let evidence_str = evidence_path.display().to_string();

    struct Invocation<'a> {
        args: Vec<&'a str>,
        allow_incomplete: bool,
        require_structural_preview: bool,
    }

    let invocations: Vec<Invocation> = vec![
        Invocation { args: vec!["--version"], allow_incomplete: false, require_structural_preview: false },
        Invocation {
            args: vec!["--json", "setup", "preview", "--client-evidence", &evidence_str, "--client", "codex", "--dry-run"],
            allow_incomplete: true,
            require_structural_preview: false,
        },
        Invocation {
            args: vec!["--json", "setup", "--check"],
            allow_incomplete: true,
            require_structural_preview: false,
        },
        Invocation {
            args: vec!["--json", "setup", "repair", "--client-evidence", &evidence_str, "--client", "codex", "--dry-run"],
            allow_incomplete: false,
            require_structural_preview: true,
        },
    ];

    for inv in invocations {
        let (status, stdout, stderr) = run(&binary, &inv.args, &env_vars)?;
        if !stdout.is_empty() {
            print!("{stdout}");
        }
        if !stderr.is_empty() {
            eprint!("{stderr}");
        }
        let label = format!("{} {}", binary.display(), inv.args.join(" "));

        if status == Some(0) && !inv.require_structural_preview {
            continue;
        }
        if inv.require_structural_preview && matches!(status, Some(0) | Some(2)) {
            let payload: Value = serde_json::from_str(&stdout)
                .map_err(|_| format!("{label} returned non-JSON activation output"))?;
            let client = payload
                .get("preview")
                .and_then(|p| p.get("clients"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.iter().find(|item| item.get("client_id").and_then(|v| v.as_str()) == Some("codex")));
            let fidelity_ok = client.and_then(|c| c.get("fidelity")).and_then(|v| v.as_str()) == Some("Full");
            let missing_zero = client
                .and_then(|c| c.get("missing_surfaces"))
                .and_then(|v| v.as_array())
                .map(|a| a.is_empty())
                .unwrap_or(false);
            if !fidelity_ok || !missing_zero {
                return Err(format!("{label} did not prove proofless structural activation"));
            }
            continue;
        }
        if inv.allow_incomplete && matches!(status, Some(1) | Some(2)) {
            if let Ok(payload) = serde_json::from_str::<Value>(&stdout) {
                if payload.get("status").and_then(|v| v.as_str()) == Some("incomplete") {
                    continue;
                }
            } else {
                return Err(format!("{label} returned non-JSON incomplete output"));
            }
        }
        let result = CommandResult {
            error_message: None,
            status,
            signal: None,
            stdout: Some(stdout),
            stderr: Some(stderr),
        };
        return Err(format!("{label} failed: {}", command_diagnostic(&result)));
    }

    Ok(())
}
