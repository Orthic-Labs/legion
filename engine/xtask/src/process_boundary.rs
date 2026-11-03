//! Rust port of `scripts/release/process-boundary.mjs`.
//!
//! Ported 1:1: constants, diagnostic clipping/summarization, and command
//! evidence hashing. `releaseSpawnOptions` has no Rust analogue (Node
//! `spawnSync` options); callers should apply the same `RELEASE_COMMAND_TIMEOUT_MS`
//! / `RELEASE_CAPTURE_MAX_BYTES` bounds to `std::process::Command`.

use std::time::Duration;

use rightkit_child_process::{run_command, OwnedCommand, RunOptions};
use sha2::{Digest, Sha256};

pub const RELEASE_CAPTURE_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const RELEASE_COMMAND_TIMEOUT_MS: u64 = 30 * 60 * 1000;
pub const INSTALLED_COMMAND_TIMEOUT_MS: u64 = 5 * 60 * 1000;

const DIAGNOSTIC_LIMIT: usize = 4096;

fn text(value: Option<&str>) -> String {
    value.unwrap_or("").trim().to_string()
}

fn clipped(value: Option<&str>) -> String {
    let normalized = text(value);
    if normalized.chars().count() <= DIAGNOSTIC_LIMIT {
        return normalized;
    }
    let truncated: String = normalized.chars().take(DIAGNOSTIC_LIMIT).collect();
    let omitted = normalized.chars().count() - DIAGNOSTIC_LIMIT;
    format!("{truncated}… [truncated {omitted} chars]")
}

/// Mirrors `diagnosticOutput`: for long stdout that parses as a JSON object,
/// keep only `kind`/`status`/`remediation`; otherwise clip as plain text.
fn diagnostic_output(value: Option<&str>) -> String {
    let normalized = text(value);
    if normalized.chars().count() <= DIAGNOSTIC_LIMIT {
        return normalized;
    }
    if let Ok(serde_json::Value::Object(payload)) = serde_json::from_str(&normalized) {
        let summary = serde_json::json!({
            "kind": payload.get("kind").cloned().unwrap_or(serde_json::Value::Null),
            "status": payload.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "remediation": payload.get("remediation").cloned().unwrap_or(serde_json::Value::Array(vec![])),
        });
        return summary.to_string();
    }
    clipped(Some(&normalized))
}

/// Input shape mirroring the fields `commandDiagnostic`/`commandEvidence`
/// read off a Node `spawnSync` result.
#[derive(Debug, Default, Clone)]
pub struct CommandResult {
    pub error_message: Option<String>,
    pub status: Option<i32>,
    pub signal: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

pub fn command_diagnostic(result: &CommandResult) -> String {
    let mut parts = Vec::new();
    let error = clipped(result.error_message.as_deref());
    if !error.is_empty() {
        parts.push(format!("error={error}"));
    }
    if let Some(status) = result.status {
        parts.push(format!("exit={status}"));
    }
    if let Some(signal) = &result.signal {
        if !signal.is_empty() {
            parts.push(format!("signal={signal}"));
        }
    }
    let stderr = clipped(result.stderr.as_deref());
    let stdout = diagnostic_output(result.stdout.as_deref());
    if !stderr.is_empty() {
        parts.push(format!("stderr={stderr}"));
    }
    if !stdout.is_empty() {
        parts.push(format!("stdout={stdout}"));
    }
    if parts.is_empty() {
        "command returned no diagnostic output".to_string()
    } else {
        parts.join("; ")
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamEvidence {
    pub bytes: usize,
    pub sha256: String,
}

fn stream_evidence(value: Option<&str>) -> StreamEvidence {
    let output = value.unwrap_or("");
    let bytes = output.len();
    let mut hasher = Sha256::new();
    hasher.update(output.as_bytes());
    StreamEvidence {
        bytes,
        sha256: hex::encode(hasher.finalize()),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CommandEvidence {
    #[serde(rename = "exitCode")]
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub stdout: StreamEvidence,
    pub stderr: StreamEvidence,
}

pub fn command_evidence(result: &CommandResult) -> CommandEvidence {
    CommandEvidence {
        exit_code: result.status,
        signal: result.signal.clone(),
        stdout: stream_evidence(result.stdout.as_deref()),
        stderr: stream_evidence(result.stderr.as_deref()),
    }
}

#[cfg(unix)]
fn exit_signal(status: std::process::ExitStatus) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|signal| signal.to_string())
}
#[cfg(not(unix))]
fn exit_signal(_: std::process::ExitStatus) -> Option<String> {
    None
}

/// Runs a configured command under a deadline and a per-stream capture cap.
///
/// On deadline expiry the whole process tree is terminated and reaped, and the
/// result carries a `timed out after <ms>ms` diagnostic in `error_message`. A
/// stream that exceeds `max_bytes` is kept to its first `max_bytes` and the
/// result carries an `output exceeded` diagnostic (Node's `ENOBUFS` analogue),
/// so callers fail closed instead of trusting clipped output. A spawn or
/// capture failure yields `error_message` with no status.
pub fn run_bounded(command: OwnedCommand, timeout: Duration, max_bytes: usize) -> CommandResult {
    let options = RunOptions::new(timeout)
        .stdout_cap(max_bytes)
        .stderr_cap(max_bytes);
    match run_command(command, None, &options) {
        Ok(output) => {
            let mut notes = Vec::new();
            if output.timed_out {
                notes.push(format!(
                    "timed out after {}ms; process tree terminated",
                    timeout.as_millis()
                ));
            }
            if output.stdout.truncated || output.stderr.truncated {
                notes.push(format!("output exceeded {max_bytes} bytes per stream"));
            }
            CommandResult {
                error_message: (!notes.is_empty()).then(|| notes.join("; ")),
                status: output.status.code(),
                signal: exit_signal(output.status),
                stdout: Some(String::from_utf8_lossy(&output.stdout.bytes).into_owned()),
                stderr: Some(String::from_utf8_lossy(&output.stderr.bytes).into_owned()),
            }
        }
        Err(error) => CommandResult {
            error_message: Some(error.to_string()),
            ..Default::default()
        },
    }
}
