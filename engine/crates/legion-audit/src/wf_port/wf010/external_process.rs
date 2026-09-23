//! Port of `src/lib/providers/executor/external-process.mjs`, re-exported by
//! `src/lib/providers/external-process.mjs` (this chunk's assigned file,
//! which is itself a pure re-export: `export { blocked, pickEnvironment,
//! runExternal } from './executor/external-process.mjs'`).
//!
//! Covers `pickEnvironment`, `blocked`, and `runExternal`'s allowlist /
//! shell-forbidden / digest-pinning guard clauses and its terminal status
//! machine. The full `runExternal` also threads an `artifactStore`,
//! `processTree` and `networkSandbox` capability host that this crate has no
//! native equivalent for yet (see module gap note on [`RunExternalHost`]),
//! so completeness there is `false` unless a caller supplies those receipts.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::tool_identity::{qualify_tool, ToolQualification, ToolStatus};

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Faithful port of `pickEnvironment(env, keys)`: keeps only the keys present
/// in `env`, preserving `keys`' relative order (JS `Object.fromEntries` over
/// a filtered/mapped array keeps insertion order of `keys`).
pub fn pick_environment(env: &BTreeMap<String, String>, keys: &[String]) -> Vec<(String, String)> {
    keys.iter()
        .filter_map(|key| env.get(key).map(|value| (key.clone(), value.clone())))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandSpec {
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawArtifact {
    pub path: String,
    pub digest: String,
    pub bytes: usize,
    pub immutable: bool,
}

fn raw_artifact(provider: &str, stream: &str, bytes: &[u8], immutable: bool) -> RawArtifact {
    RawArtifact {
        path: format!("raw/{provider}.{stream}"),
        digest: sha256_digest(bytes),
        bytes: bytes.len(),
        immutable,
    }
}

/// Mirrors the JS `providerResult(provider, status, complete, coverageGaps)`
/// helper's shape closely enough for the execution-result envelope below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderResultEnvelope {
    pub schema_version: u32,
    pub provider: String,
    pub status: String,
    pub complete: bool,
    pub coverage_gaps: Vec<CoverageGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageGap {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn provider_result(provider: &str, status: &str, complete: bool, coverage_gaps: Vec<CoverageGap>) -> ProviderResultEnvelope {
    ProviderResultEnvelope {
        schema_version: 1,
        provider: provider.to_string(),
        status: status.to_string(),
        complete,
        coverage_gaps,
    }
}

/// Mirrors the JS `legion-execution-result` envelope returned by `blocked`
/// and `runExternal`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionResult {
    pub schema_version: u32,
    pub kind: String,
    pub provider: Option<String>,
    pub complete: bool,
    pub command: CommandSpec,
    pub started_at: i64,
    pub completed_at: i64,
    pub duration_ms: i64,
    pub spawn_status: String,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub timed_out: bool,
    pub stdout_artifact: RawArtifact,
    pub stderr_artifact: RawArtifact,
    pub environment_keys: Vec<String>,
    pub tool: Option<ToolQualification>,
    pub provider_result: ProviderResultEnvelope,
}

/// Faithful port of `blocked(spec, reason, state='blocked')`.
pub fn blocked(spec: &RunExternalSpec, reason: &str, state: &str) -> ExecutionResult {
    let provider = spec.provider.clone().unwrap_or_else(|| "process".to_string());
    let empty = raw_artifact(&provider, "stdout", &[], false);
    let empty_err = raw_artifact(&provider, "stderr", &[], false);
    ExecutionResult {
        schema_version: 1,
        kind: "legion-execution-result".to_string(),
        provider: spec.provider.clone(),
        complete: false,
        command: CommandSpec {
            executable: spec.executable.clone(),
            args: spec.args.clone(),
            cwd: spec.cwd.clone(),
        },
        started_at: 0,
        completed_at: 0,
        duration_ms: 0,
        spawn_status: state.to_string(),
        exit_code: None,
        signal: None,
        timed_out: state == "timeout",
        stdout_artifact: empty,
        stderr_artifact: empty_err,
        environment_keys: spec.environment_keys.clone(),
        tool: None,
        provider_result: provider_result(
            &provider,
            if state == "blocked" { "blocked" } else { "unproven" },
            false,
            vec![CoverageGap { kind: state.to_string(), reason: Some(reason.to_string()) }],
        ),
    }
}

const DEFAULT_ALLOWED: &[&str] = &[
    "node", "git", "tsc", "eslint", "python3", "python", "ruff", "cargo", "go", "dotnet",
    "opengrep", "ast-grep", "sg", "osv-scanner", "gitleaks", "syft", "trivy", "swift", "clang",
    "gcc", "cmake", "mvn", "gradle", "php", "composer", "ruby", "bundle",
];

fn bounded_probe_timeout(value: Option<u64>) -> u64 {
    value.map(|timeout| timeout.clamp(1, 5000)).unwrap_or(5000)
}

/// Host capabilities `runExternal` threads through. Unset fields degrade the
/// receipt the same way an absent JS host object property does (`gaps`
/// accumulate `immutable-raw-output-unavailable` /
/// `process-tree-hard-kill-unavailable`, `complete` stays `false`), rather
/// than being treated as an error.
///
/// GAP: the JS `host.artifactStore.writeBytes` and `host.processTree`
/// capabilities are asynchronous, caller-supplied receipt producers with no
/// existing native equivalent in this crate; only their *absence* behaviour
/// (unsealed output/process-tree gaps) is ported here.
#[derive(Debug, Clone, Default)]
pub struct RunExternalHost {
    pub allowed_executables: Option<Vec<String>>,
    pub env: BTreeMap<String, String>,
    pub network_sandbox_active: bool,
    pub network_sandbox_receipt: bool,
    pub outputs_sealed: bool,
    pub process_tree_sealed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RunExternalSpec {
    pub provider: Option<String>,
    pub executable: String,
    pub executable_digest: Option<String>,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub timeout_ms: Option<u64>,
    pub max_output_bytes: Option<usize>,
    pub environment_keys: Vec<String>,
    pub project_execution: bool,
    pub shell: bool,
    pub version_args: Option<Vec<String>>,
    pub version_timeout_ms: Option<u64>,
}

/// Faithful port of `runExternal(spec, host)`'s guard clauses and terminal
/// status machine. See the [`RunExternalHost`] gap note for the boundary
/// this stops at.
pub async fn run_external(spec: &RunExternalSpec, host: &RunExternalHost) -> ExecutionResult {
    if spec.shell {
        // JS throws synchronously here rather than returning a receipt;
        // callers must treat this the same way (panic mirrors `throw`).
        panic!("shell execution is forbidden");
    }
    if spec.project_execution && !(host.network_sandbox_active && host.network_sandbox_receipt) {
        return blocked(spec, "network-sandbox-receipt-missing", "blocked");
    }
    let allowed: Vec<String> = host
        .allowed_executables
        .clone()
        .unwrap_or_else(|| DEFAULT_ALLOWED.iter().map(|s| s.to_string()).collect());
    if !allowed.iter().any(|item| item == &spec.executable) {
        return blocked(spec, "executable-not-allowlisted", "blocked");
    }
    if !Path::new(&spec.executable).is_absolute() {
        return blocked(spec, "executable-bytes-not-sealed", "unsealed-executable");
    }

    let environment = pick_environment(&host.env, &spec.environment_keys);
    let version_args = spec
        .version_args
        .clone()
        .unwrap_or_else(|| vec!["--version".to_string()]);
    let tool = qualify_tool(
        &spec.executable,
        &version_args,
        spec.cwd.as_ref().map(Path::new),
        &environment,
        bounded_probe_timeout(spec.version_timeout_ms),
    )
    .await;

    if tool.status == ToolStatus::MissingExecutable {
        let mut result = blocked(spec, "missing-executable", "missing-executable");
        result.tool = Some(tool);
        return result;
    }
    if tool.status != ToolStatus::Available || tool.executable_digest.is_none() {
        let (reason, state) = if tool.status == ToolStatus::Available {
            ("executable-digest-missing", "unsealed-executable")
        } else {
            let reason = match tool.status {
                ToolStatus::ProbeError => "probe-error",
                ToolStatus::Timeout => "timeout",
                _ => "probe-error",
            };
            (reason, reason)
        };
        let mut result = blocked(spec, reason, state);
        result.tool = Some(tool);
        return result;
    }
    if let (Some(expected), Some(actual)) = (&spec.executable_digest, &tool.executable_digest) {
        if expected != actual {
            let mut result = blocked(spec, "executable-digest-mismatch", "unsealed-executable");
            result.tool = Some(tool);
            return result;
        }
    }

    let provider = spec.provider.clone().unwrap_or_else(|| "process".to_string());
    let started = Instant::now();
    let started_at = 0i64;

    let mut command = tokio::process::Command::new(&spec.executable);
    command
        .args(&spec.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_clear();
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in &environment {
        command.env(key, value);
    }

    let max_output_bytes = spec.max_output_bytes.unwrap_or(8_388_608);
    let timeout_ms = spec.timeout_ms.unwrap_or(120_000);

    let spawn_result = command.spawn();
    let mut child = match spawn_result {
        Ok(child) => child,
        Err(error) => {
            let state = if error.kind() == std::io::ErrorKind::NotFound {
                "missing-executable"
            } else {
                "spawn-error"
            };
            let mut result = blocked(spec, &error.kind().to_string(), state);
            result.tool = Some(tool);
            return result;
        }
    };

    use tokio::io::AsyncReadExt;
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut output_limited = false;
    let mut timed_out = false;

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let deadline = tokio::time::sleep(Duration::from_millis(timeout_ms));
    tokio::pin!(deadline);

    let exit_status = loop {
        let mut out_chunk = [0u8; 8192];
        let mut err_chunk = [0u8; 8192];
        tokio::select! {
            biased;
            _ = &mut deadline => {
                timed_out = true;
                let _ = child.kill().await;
                break None;
            }
            result = async {
                match &mut stdout_pipe {
                    Some(out) => out.read(&mut out_chunk).await,
                    None => std::future::pending().await,
                }
            }, if stdout_pipe.is_some() => {
                match result {
                    Ok(0) | Err(_) => { stdout_pipe = None; }
                    Ok(n) => {
                        stdout_buf.extend_from_slice(&out_chunk[..n]);
                        if stdout_buf.len() + stderr_buf.len() >= max_output_bytes {
                            output_limited = true;
                            let _ = child.kill().await;
                            break None;
                        }
                    }
                }
            }
            result = async {
                match &mut stderr_pipe {
                    Some(err) => err.read(&mut err_chunk).await,
                    None => std::future::pending().await,
                }
            }, if stderr_pipe.is_some() => {
                match result {
                    Ok(0) | Err(_) => { stderr_pipe = None; }
                    Ok(n) => {
                        stderr_buf.extend_from_slice(&err_chunk[..n]);
                        if stdout_buf.len() + stderr_buf.len() >= max_output_bytes {
                            output_limited = true;
                            let _ = child.kill().await;
                            break None;
                        }
                    }
                }
            }
            status = child.wait(), if stdout_pipe.is_none() && stderr_pipe.is_none() => {
                break status.ok();
            }
        }
    };

    stdout_buf.truncate(max_output_bytes);
    if stderr_buf.len() + stdout_buf.len() > max_output_bytes {
        let remaining = max_output_bytes.saturating_sub(stdout_buf.len());
        stderr_buf.truncate(remaining);
    }

    let exit_code = exit_status.as_ref().and_then(|status| status.code());
    let completed_at = started_at + started.elapsed().as_millis() as i64;

    let spawn_status = if output_limited {
        "output-limit"
    } else if timed_out {
        "timeout"
    } else if exit_code.is_none() {
        "signal"
    } else if exit_code == Some(0) {
        "completed"
    } else {
        "failed-exit"
    };

    let process_complete = spawn_status == "completed";
    let mut gaps = Vec::new();
    if !process_complete {
        gaps.push(CoverageGap { kind: spawn_status.to_string(), reason: None });
    }
    let sealed_outputs = host.outputs_sealed;
    let sealed_tree = host.process_tree_sealed;
    if !sealed_outputs {
        gaps.push(CoverageGap { kind: "immutable-raw-output-unavailable".to_string(), reason: None });
    }
    if !sealed_tree {
        gaps.push(CoverageGap { kind: "process-tree-hard-kill-unavailable".to_string(), reason: None });
    }
    let complete = process_complete && sealed_outputs && sealed_tree;

    ExecutionResult {
        schema_version: 1,
        kind: "legion-execution-result".to_string(),
        provider: spec.provider.clone(),
        complete,
        command: CommandSpec { executable: spec.executable.clone(), args: spec.args.clone(), cwd: spec.cwd.clone() },
        started_at,
        completed_at,
        duration_ms: completed_at - started_at,
        spawn_status: spawn_status.to_string(),
        exit_code,
        signal: None,
        timed_out,
        stdout_artifact: raw_artifact(&provider, "stdout", &stdout_buf, sealed_outputs),
        stderr_artifact: raw_artifact(&provider, "stderr", &stderr_buf, sealed_outputs),
        environment_keys: spec.environment_keys.clone(),
        tool: Some(tool),
        provider_result: provider_result(
            &provider,
            if complete { "pass" } else if spawn_status == "output-limit" { "partial" } else { "unproven" },
            complete,
            gaps,
        ),
    }
}
