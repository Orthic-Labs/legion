//! Port of `src/lib/providers/executor/tool-identity.mjs` (`qualifyTool`).
//!
//! Spawns `executable` with `version_args` (default `["--version"]`) and
//! reports one of four statuses, exactly mirroring the JS state machine:
//! - `missing-executable`: `spawn` itself threw synchronously (JS `catch`
//!   around `spawn(...)`), or the child emitted an `ENOENT` `error` event.
//! - `probe-error`: the child emitted a non-ENOENT `error` event, or closed
//!   with a non-zero exit code.
//! - `timeout`: the probe was killed after `timeout_ms` (default 5000).
//! - `available`: the child closed with exit code 0.
//!
//! `version` is the first line of combined stdout+stderr, trimmed, only when
//! `available`. `executable_digest` is `sha256:<hex>` of the executable's
//! bytes only when `executable` is an absolute path that exists on disk,
//! matching JS `isAbsolute(executable) && existsSync(executable)`.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Mirrors the JS `probe` object: `{command, outputDigest, exitCode?, signal?}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Probe {
    pub command: Vec<String>,
    pub output_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ToolStatus {
    MissingExecutable,
    ProbeError,
    Timeout,
    Available,
}

/// Mirrors the JS resolved value of `qualifyTool`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolQualification {
    pub status: ToolStatus,
    pub name: String,
    pub version: Option<String>,
    pub probe: Probe,
    pub executable_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Faithful port of `qualifyTool({executable, versionArgs, cwd, env, timeoutMs})`.
///
/// `env` replaces (not merges into) the child's environment, matching Node's
/// `spawn(..., {env})` semantics when `env` is given explicitly.
pub async fn qualify_tool(
    executable: &str,
    version_args: &[String],
    cwd: Option<&Path>,
    env: &[(String, String)],
    timeout_ms: u64,
) -> ToolQualification {
    let command_line: Vec<String> = std::iter::once(executable.to_string())
        .chain(version_args.iter().cloned())
        .collect();

    let mut command = Command::new(executable);
    command
        .args(version_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    for (key, value) in env {
        command.env(key, value);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            // Mirrors the JS synchronous `catch` around `spawn(...)`: no
            // process was ever created, so the probe digest is over empty
            // output and the executable is reported missing.
            return ToolQualification {
                status: ToolStatus::MissingExecutable,
                name: executable.to_string(),
                version: None,
                probe: Probe {
                    command: command_line,
                    output_digest: sha256_digest(&[]),
                    exit_code: None,
                    signal: None,
                },
                executable_digest: None,
                error: Some(error.kind().to_string()),
            };
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_end(&mut stdout).await;
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_end(&mut stderr).await;
    }

    let wait_result = timeout(Duration::from_millis(timeout_ms), child.wait()).await;

    let timed_out = wait_result.is_err();
    if timed_out {
        let _ = child.kill().await;
    }

    let mut output = stdout;
    output.extend_from_slice(&stderr);
    let output_digest = sha256_digest(&output);

    let exit_status = match wait_result {
        Ok(Ok(status)) => Some(status),
        _ => None,
    };

    let status = if timed_out {
        ToolStatus::Timeout
    } else {
        match &exit_status {
            Some(status) if status.success() => ToolStatus::Available,
            _ => ToolStatus::ProbeError,
        }
    };

    let version = if matches!(status, ToolStatus::Available) {
        let text = String::from_utf8_lossy(&output);
        text.trim()
            .split(['\n', '\r'])
            .next()
            .map(|line| line.to_string())
    } else {
        None
    };

    #[cfg(unix)]
    let exit_code = exit_status.and_then(|status| {
        use std::os::unix::process::ExitStatusExt;
        status.code().or_else(|| status.signal().map(|_| -1))
    });
    #[cfg(not(unix))]
    let exit_code = exit_status.and_then(|status| status.code());

    let executable_digest = if Path::new(executable).is_absolute() && Path::new(executable).exists() {
        std::fs::read(executable).ok().map(|bytes| sha256_digest(&bytes))
    } else {
        None
    };

    ToolQualification {
        status,
        name: executable.to_string(),
        version,
        probe: Probe {
            command: command_line,
            output_digest,
            exit_code,
            signal: None,
        },
        executable_digest,
        error: None,
    }
}
