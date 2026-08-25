//! Unix process execution for the governed effects boundary.
//!
//! Every child is placed in its own process group before `exec`.  Cleanup is
//! consequently group-scoped, so a target cannot leave descendants behind.

use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::error::EffectError;
use crate::platform::{PlatformProcess, ProcessFuture, ProcessLaunch, ProcessOutput};
use crate::receipt::ProcessTreeEvidence;

/// Unix process-group backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixProcess;

impl UnixProcess {
    pub const fn new() -> Self {
        Self
    }
}

impl PlatformProcess for UnixProcess {
    fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a> {
        Box::pin(run_process(launch))
    }
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    limited: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopReason {
    Timeout,
    Cancelled,
    OutputLimited,
}

async fn run_process(launch: ProcessLaunch) -> Result<ProcessOutput, EffectError> {
    let started_at_ms = now_ms();
    let mut command = Command::new(&launch.executable);
    command
        .args(&launch.args)
        .current_dir(&launch.cwd)
        .env_clear()
        .envs(&launch.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // This hook runs in the child between fork and exec.  It must not capture
    // Rust state or perform allocation: only the async-safe setpgid syscall.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }

    let mut child = command
        .spawn()
        .map_err(|error| EffectError::SpawnFailed(error.to_string()))?;
    let pid = child
        .id()
        .ok_or_else(|| EffectError::SpawnFailed("child pid unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| EffectError::SpawnFailed("stdout pipe unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| EffectError::SpawnFailed("stderr pipe unavailable".into()))?;

    let reader_stop = CancellationToken::new();
    let output_limited = CancellationToken::new();
    let stdout_task = tokio::spawn(read_capped(
        stdout,
        launch.stdout_limit,
        reader_stop.clone(),
        output_limited.clone(),
    ));
    let stderr_task = tokio::spawn(read_capped(
        stderr,
        launch.stderr_limit,
        reader_stop.clone(),
        output_limited.clone(),
    ));

    let mut status = None;
    let mut stop_reason = None;
    let timeout = tokio::time::sleep(Duration::from_millis(launch.timeout_ms));
    tokio::pin!(timeout);

    tokio::select! {
        result = child.wait() => {
            status = Some(result.map_err(|error| EffectError::SpawnFailed(error.to_string()))?);
        }
        _ = &mut timeout => stop_reason = Some(StopReason::Timeout),
        _ = launch.cancellation.cancelled() => stop_reason = Some(StopReason::Cancelled),
        _ = output_limited.cancelled() => stop_reason = Some(StopReason::OutputLimited),
    }

    if let Some(reason) = stop_reason {
        let cleanup = cleanup_group(pid, launch.termination_grace_ms).await;
        if status.is_none() {
            status = Some(
                child
                    .wait()
                    .await
                    .map_err(|error| EffectError::SpawnFailed(error.to_string()))?,
            );
        }

        // A reader can otherwise remain blocked by a surviving pipe holder.
        // Group cleanup above is authoritative; cancellation only releases
        // local readers after the process has been reaped.
        reader_stop.cancel();

        let stdout_capture = stdout_task
            .await
            .map_err(|error| EffectError::Internal(error.to_string()))??;
        let stderr_capture = stderr_task
            .await
            .map_err(|error| EffectError::Internal(error.to_string()))??;
        let output_limited_seen = stdout_capture.limited || stderr_capture.limited;
        let completed_at_ms = now_ms();
        return Ok(ProcessOutput {
            stdout: stdout_capture.bytes,
            stderr: stderr_capture.bytes,
            exit_code: status.as_ref().and_then(|value| value.code()),
            signal: status.as_ref().and_then(ExitStatusExt::signal),
            timed_out: reason == StopReason::Timeout,
            cancelled: reason == StopReason::Cancelled,
            output_limited: reason == StopReason::OutputLimited || output_limited_seen,
            kill_succeeded: cleanup.kill_succeeded,
            process_tree: ProcessTreeEvidence {
                started: true,
                terminated: cleanup.terminated,
                hard_killed: cleanup.hard_killed,
                reaped: status.is_some(),
                detail: Some(stop_detail(reason)),
            },
            started_at_ms,
            completed_at_ms,
        });
    }

    let status = status.ok_or_else(|| EffectError::Internal("child status unavailable".into()))?;
    // A direct child may exit while descendants still retain its pipes.  Run
    // the same group cleanup before awaiting readers, so no descendant can
    // escape or leave this future blocked on inherited stdout/stderr.
    let cleanup = cleanup_group(pid, launch.termination_grace_ms).await;
    let stdout_capture = stdout_task
        .await
        .map_err(|error| EffectError::Internal(error.to_string()))??;
    let stderr_capture = stderr_task
        .await
        .map_err(|error| EffectError::Internal(error.to_string()))??;
    let output_limited_seen = stdout_capture.limited || stderr_capture.limited;
    let completed_at_ms = now_ms();
    Ok(ProcessOutput {
        stdout: stdout_capture.bytes,
        stderr: stderr_capture.bytes,
        exit_code: status.code(),
        signal: status.signal(),
        timed_out: false,
        cancelled: false,
        output_limited: output_limited_seen,
        kill_succeeded: cleanup.kill_succeeded,
        process_tree: ProcessTreeEvidence {
            started: true,
            terminated: cleanup.terminated,
            hard_killed: cleanup.hard_killed,
            reaped: true,
            detail: Some("normal exit: process-group cleanup completed".into()),
        },
        started_at_ms,
        completed_at_ms,
    })
}

#[derive(Clone, Copy, Debug)]
struct CleanupResult {
    terminated: bool,
    hard_killed: bool,
    kill_succeeded: bool,
}

async fn cleanup_group(pid: u32, grace_ms: u64) -> CleanupResult {
    let term = signal_group(pid, libc::SIGTERM);
    if term.absent {
        return CleanupResult {
            terminated: true,
            hard_killed: false,
            kill_succeeded: true,
        };
    }

    // Keep the injected grace exact even when the direct child exits early:
    // descendants can retain process-group pipes after the leader is gone.
    tokio::time::sleep(Duration::from_millis(grace_ms)).await;
    let hard = signal_group(pid, libc::SIGKILL);
    CleanupResult {
        terminated: term.succeeded,
        hard_killed: true,
        kill_succeeded: term.succeeded && hard.succeeded,
    }
}

async fn read_capped<R>(
    mut reader: R,
    limit: usize,
    stop: CancellationToken,
    output_limited: CancellationToken,
) -> Result<CapturedOutput, EffectError>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    loop {
        let remaining = limit.saturating_sub(bytes.len());
        let read_len = remaining.saturating_add(1).min(buffer.len());
        let read = tokio::select! {
            _ = stop.cancelled() => return Ok(CapturedOutput { bytes, limited: false }),
            result = reader.read(&mut buffer[..read_len]) => result
                .map_err(|error| EffectError::Internal(error.to_string()))?,
        };
        if read == 0 {
            return Ok(CapturedOutput {
                bytes,
                limited: false,
            });
        }
        if read > remaining {
            bytes.extend_from_slice(&buffer[..remaining]);
            output_limited.cancel();
            return Ok(CapturedOutput {
                bytes,
                limited: true,
            });
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

#[derive(Clone, Copy, Debug)]
struct GroupSignal {
    succeeded: bool,
    absent: bool,
}

fn signal_group(pid: u32, signal: i32) -> GroupSignal {
    if pid == 0 || pid > i32::MAX as u32 {
        return GroupSignal {
            succeeded: false,
            absent: false,
        };
    }
    let result = unsafe { libc::kill(-(pid as i32), signal) };
    if result == 0 {
        return GroupSignal {
            succeeded: true,
            absent: false,
        };
    }
    // ESRCH means group members already exited, which is a successful
    // idempotent cleanup outcome.
    let absent = std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    GroupSignal {
        succeeded: absent,
        absent,
    }
}

fn stop_detail(reason: StopReason) -> String {
    match reason {
        StopReason::Timeout => "timeout: cooperative termination then bounded hard cleanup".into(),
        StopReason::Cancelled => {
            "cancelled: cooperative termination then bounded hard cleanup".into()
        }
        StopReason::OutputLimited => {
            "output limit: cooperative termination then bounded hard cleanup".into()
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
