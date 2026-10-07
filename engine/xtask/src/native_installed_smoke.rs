//! Rust port of `scripts/ci/native-installed-smoke.mjs`.
//!
//! Copies an assembled native candidate into an isolated "installed" tree
//! (mirroring the platform's real user-data root) and runs the resulting
//! `legion` binary through the same probe invocations the JS script used,
//! with the same isolated environment and exit-code/JSON tolerance rules.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::process_boundary::{command_diagnostic, CommandResult, INSTALLED_COMMAND_TIMEOUT_MS};

fn is_within(root: &Path, candidate: &Path) -> bool {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let candidate = candidate
        .canonicalize()
        .unwrap_or_else(|_| candidate.to_path_buf());
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

fn run(
    binary: &Path,
    args: &[&str],
    env_vars: &[(String, String)],
) -> Result<(Option<i32>, String, String), String> {
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
    let output = cmd.output().map_err(|e| {
        format!(
            "{} {} failed: spawn error: {e}",
            binary.display(),
            args.join(" ")
        )
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok((output.status.code(), stdout, stderr))
}

/// Drop the Windows verbatim prefix canonicalize() adds: the installed
/// product receives these paths as arguments and cannot open `\\?\` forms
/// through every API (observed: "Incorrect function").
fn plain_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path
    }
}

/// Probe both client transports against actual assembled descriptors, without
/// executing Apple tools or contacting account services.
fn smoke_mcp_transport(
    binary: &Path,
    plugin_root: Option<&Path>,
    env_vars: &[(String, String)],
) -> Result<(), String> {
    let mut command = Command::new(binary);
    command.args(["serve", "--stdio"]);
    if let Some(root) = plugin_root {
        command.arg("--plugin-root").arg(root);
    }
    command
        .env_clear()
        .envs(env_vars.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("MCP smoke spawn failed: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("MCP smoke stdin missing")?;
    let stdout = child.stdout.take().ok_or("MCP smoke stdout missing")?;
    let stderr = child.stderr.take().ok_or("MCP smoke stderr missing")?;
    const CAPTURE: u64 = 2 * 1024 * 1024;
    let read = |pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(CAPTURE + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
    };
    let out_reader = read(Box::new(stdout));
    let err_reader = read(Box::new(stderr));
    let requests = [
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"legion_apple","arguments":{"operation":"catalog"}}}),
        serde_json::json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"legion_apple","arguments":{"operation":"app-store","arguments":{"action":"apps","execute":false}}}}),
        serde_json::json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"legion_apple","arguments":{"operation":"simulator.list","arguments":{"execute":false}}}}),
    ];
    let input = requests
        .iter()
        .map(|request| format!("{request}\n"))
        .collect::<String>();
    let write_error = stdin.write_all(input.as_bytes()).err();
    drop(stdin);
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if started.elapsed() < Duration::from_secs(30) => {
                std::thread::sleep(Duration::from_millis(25))
            }
            result => {
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|e| format!("MCP smoke wait failed: {e}"))?;
                if let Err(error) = result {
                    return Err(format!("MCP smoke poll failed: {error}"));
                }
                break (status, true);
            }
        }
    };
    let stdout = out_reader
        .join()
        .map_err(|_| "MCP smoke stdout reader failed")?
        .map_err(|e| e.to_string())?;
    let stderr = err_reader
        .join()
        .map_err(|_| "MCP smoke stderr reader failed")?
        .map_err(|e| e.to_string())?;
    if timed_out
        || !status.success()
        || write_error.is_some()
        || stdout.len() as u64 > CAPTURE
        || stderr.len() as u64 > CAPTURE
    {
        return Err(format!("MCP smoke failed (plugin-root={}, status={status}, timeout={timed_out}, write={write_error:?}): {}",
            plugin_root.is_some(), String::from_utf8_lossy(&stderr)));
    }
    let responses: Vec<Value> = String::from_utf8_lossy(&stdout)
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("MCP smoke response JSON: {e}"))?;
    if responses.len() != requests.len()
        || responses.iter().enumerate().any(|(index, response)| {
            response.get("id").and_then(Value::as_u64) != Some(index as u64 + 1)
                || response.get("error").is_some()
                || response.get("result").is_none()
                || response.pointer("/result/isError").and_then(Value::as_bool) == Some(true)
        })
    {
        return Err(format!(
            "MCP smoke returned incomplete/error responses: {responses:?}"
        ));
    }
    let names: std::collections::BTreeSet<_> = responses[1]
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("MCP smoke tools/list missing tools")?
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect();
    let expected: std::collections::BTreeSet<_> =
        ["legion_m1_status", "legion_m1_invoke", "legion_apple"]
            .into_iter()
            .collect();
    if names != expected {
        return Err(format!("MCP smoke canonical tool list mismatch: {names:?}"));
    }
    println!(
        "installed MCP smoke PASS: plugin-root={}, 3 canonical tools, catalog/apps/simulator plans",
        plugin_root.is_some()
    );
    Ok(())
}

pub fn native_installed_smoke(
    candidate: &Path,
    isolated_root: Option<&Path>,
) -> Result<(), String> {
    let candidate_root = candidate.canonicalize().map(plain_path).map_err(|_| {
        format!(
            "assembled candidate root is missing: {}",
            candidate.display()
        )
    })?;
    if !candidate_root.is_dir() {
        return Err(format!(
            "assembled candidate root is missing: {}",
            candidate_root.display()
        ));
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
    for dir in [
        &isolated_root,
        &home,
        &local_data,
        &roaming_data,
        &xdg_data,
        &state_root,
    ] {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }

    let product_root = if cfg!(target_os = "windows") {
        local_data.join("Orthic Labs").join("Legion")
    } else if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Application Support")
            .join("Orthic Labs")
            .join("Legion")
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

    let binary_name = if cfg!(target_os = "windows") {
        "legion.exe"
    } else {
        "legion"
    };
    let binary = current_root.join("bin").join(binary_name);
    if !binary.is_file() {
        return Err(format!(
            "assembled candidate has no native executable: {}",
            binary.display()
        ));
    }

    let path_key = env::vars()
        .map(|(k, _)| k)
        .find(|k| k.eq_ignore_ascii_case("PATH"))
        .unwrap_or_else(|| "PATH".to_string());
    let existing_path = env::var(&path_key).unwrap_or_default();
    let bin_dir = current_root.join("bin");
    let path_sep = if cfg!(target_os = "windows") {
        ";"
    } else {
        ":"
    };
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
    env_vars.push((
        "LEGION_STATE_ROOT".to_string(),
        state_root.display().to_string(),
    ));
    env_vars.push((path_key, new_path));

    let evidence_str = evidence_path.display().to_string();

    struct Invocation<'a> {
        args: Vec<&'a str>,
        allow_incomplete: bool,
        require_structural_preview: bool,
    }

    let invocations: Vec<Invocation> = vec![
        Invocation {
            args: vec!["--version"],
            allow_incomplete: false,
            require_structural_preview: false,
        },
        Invocation {
            args: vec![
                "--json",
                "setup",
                "preview",
                "--client-evidence",
                &evidence_str,
                "--client",
                "codex",
                "--dry-run",
            ],
            allow_incomplete: true,
            require_structural_preview: false,
        },
        Invocation {
            args: vec!["--json", "setup", "--check"],
            allow_incomplete: true,
            require_structural_preview: false,
        },
        Invocation {
            args: vec![
                "--json",
                "setup",
                "repair",
                "--client-evidence",
                &evidence_str,
                "--client",
                "codex",
                "--dry-run",
            ],
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
                .and_then(|arr| {
                    arr.iter().find(|item| {
                        item.get("client_id").and_then(|v| v.as_str()) == Some("codex")
                    })
                });
            let fidelity_ok = client
                .and_then(|c| c.get("fidelity"))
                .and_then(|v| v.as_str())
                == Some("Full");
            let missing_zero = client
                .and_then(|c| c.get("missing_surfaces"))
                .and_then(|v| v.as_array())
                .map(|a| a.is_empty())
                .unwrap_or(false);
            if !fidelity_ok || !missing_zero {
                return Err(format!(
                    "{label} did not prove proofless structural activation"
                ));
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

    // Exercise the installed native Minimize path, including its shipped policy.
    // A source-checkout fallback must not hide an incomplete installer payload.
    let policy = current_root.join("share/legion/assets/lib/minimize/POLICY.md");
    let policy_bytes =
        fs::read(&policy).map_err(|e| format!("installed Minimize policy is missing: {e}"))?;
    let decision = isolated_root.join("minimize-decision.json");
    let receipt = isolated_root.join("minimize-receipt.json");
    fs::write(
        &decision,
        serde_json::json!({
            "schema": "minimize-decision.v1",
            "decision_id": "installed-native-smoke",
            "state_a": "missing receipt", "state_b": "verified native receipt",
            "selected_rung": "REUSE",
            "prior_rungs": [{"rung": "NOT_BUILD", "verdict": "REJECTED",
                "evidence": "installed native receipt validation is requested"}],
            "allowed_new_files": [], "allowed_new_dependencies": []
        })
        .to_string(),
    )
    .map_err(|e| e.to_string())?;
    let decision_str = decision.display().to_string();
    let receipt_str = receipt.display().to_string();
    for args in [
        vec!["minimize", "decision", "validate", &decision_str],
        vec![
            "minimize",
            "decision",
            "receipt",
            &decision_str,
            &receipt_str,
        ],
        vec![
            "minimize",
            "decision",
            "verify",
            &decision_str,
            &receipt_str,
        ],
    ] {
        let (status, stdout, stderr) = run(&binary, &args, &env_vars)?;
        if status != Some(0) || stdout.trim() != "MINIMIZE PASS" {
            return Err(format!(
                "installed native Minimize {} failed: {stdout} {stderr}",
                args.join(" ")
            ));
        }
    }
    fs::remove_file(&policy).map_err(|e| e.to_string())?;
    let missing = run(
        &binary,
        &[
            "minimize",
            "decision",
            "verify",
            &decision_str,
            &receipt_str,
        ],
        &env_vars,
    );
    fs::write(&policy, policy_bytes).map_err(|e| e.to_string())?;
    let (status, _, stderr) = missing?;
    if status == Some(0) || !stderr.contains("minimize policy asset") {
        return Err(format!(
            "installed Minimize accepted a missing policy: {stderr}"
        ));
    }

    smoke_mcp_transport(&binary, None, &env_vars)?;
    smoke_mcp_transport(&binary, Some(&current_root.join("plugin")), &env_vars)?;
    Ok(())
}
