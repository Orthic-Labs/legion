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

/// Upper bound (exclusive) of descriptor numbers to mark close-on-exec.
fn descriptor_limit() -> libc::c_int {
    const CEILING: libc::rlim_t = 1 << 20;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let soft = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
        limit.rlim_cur
    } else {
        CEILING
    };
    let ceiling = soft.min(CEILING) as libc::c_int;
    // Sweeping the whole rlimit costs ~126 ms per spawn at a 1M soft limit.
    // Bound the sweep by the highest descriptor actually open, read before
    // fork (allocation is fine here). Residual race: a descriptor another
    // thread opens without close-on-exec (raw libc calls, or an explicit
    // clear) between this scan and fork, numbered above the scanned maximum,
    // is inherited. Linux close_range marks every descriptor regardless.
    highest_open_descriptor()
        .map(|highest| (highest + 1).min(ceiling))
        .unwrap_or(ceiling)
}

fn highest_open_descriptor() -> Option<libc::c_int> {
    let directory = if cfg!(any(target_os = "linux", target_os = "android")) {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(directory)
        .ok()?
        .filter_map(|entry| {
            entry
                .ok()?
                .file_name()
                .to_str()?
                .parse::<libc::c_int>()
                .ok()
        })
        .max()
}

/// Marks every descriptor in `3..limit` close-on-exec.  Async-signal-safe:
/// only `syscall` and `fcntl`, no allocation, no locks.  The std exec-error
/// pipe is already close-on-exec, so re-marking it is harmless.
unsafe fn mark_descriptors_cloexec(limit: libc::c_int) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        const SYS_CLOSE_RANGE: libc::c_long = 436;
        const CLOSE_RANGE_CLOEXEC: libc::c_long = 1 << 2;
        let done = libc::syscall(
            SYS_CLOSE_RANGE,
            3 as libc::c_long,
            libc::c_int::MAX as libc::c_long,
            CLOSE_RANGE_CLOEXEC,
        );
        if done == 0 {
            return;
        }
    }
    let mut fd: libc::c_int = 3;
    while fd < limit {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
        fd += 1;
    }
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

    // Temporary Legion-side fix for rightkit#835: the child must not inherit
    // any descriptor above stdio (an inherited connected socket would defeat
    // the sandbox).  Mark each one close-on-exec so exec drops it and the
    // child sees EBADF.  The bound is read here, before fork.
    let fd_limit = descriptor_limit();

    // This hook runs in the child between fork and exec.  It must not capture
    // Rust state or perform allocation: only the async-signal-safe setpgid,
    // fcntl and syscall calls, with a plain integer bound computed above.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            mark_descriptors_cloexec(fd_limit);
            Ok(())
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
        let mut cleanup = cleanup_group(pid, launch.termination_grace_ms).await;
        if status.is_none() {
            status = Some(
                child
                    .wait()
                    .await
                    .map_err(|error| EffectError::SpawnFailed(error.to_string()))?,
            );
        }
        // Darwin may reject group signalling while its exited leader is
        // still a zombie. Only a fresh ESRCH after wait/reap establishes
        // that no group member remains; permissions/unknown stay failed.
        cleanup.confirm_after_reap(|| signal_group(pid, 0));

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
                detail: Some(format!("{}; {}", stop_detail(reason), cleanup.detail())),
            },
            started_at_ms,
            completed_at_ms,
        });
    }

    let status = status.ok_or_else(|| EffectError::Internal("child status unavailable".into()))?;
    // A direct child may exit while descendants still retain its pipes.  Run
    // the same group cleanup before awaiting readers, so no descendant can
    // escape or leave this future blocked on inherited stdout/stderr.
    let mut cleanup = cleanup_group(pid, launch.termination_grace_ms).await;
    // The leader is already reaped here; Darwin can still refuse the group
    // signal (EPERM) while a member is a zombie. Only a fresh ESRCH proves the
    // group is gone, exactly as on the stop path above.
    cleanup.confirm_after_reap(|| signal_group(pid, 0));
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
            detail: Some(format!(
                "normal exit: process-group cleanup; {}",
                cleanup.detail()
            )),
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
    term: GroupSignal,
    hard: Option<GroupSignal>,
    after_reap: Option<GroupSignal>,
}

impl CleanupResult {
    fn confirm_after_reap(&mut self, probe: impl FnOnce() -> GroupSignal) {
        if self.kill_succeeded {
            return;
        }
        let observed = probe();
        self.after_reap = Some(observed);
        if observed.absent {
            self.terminated = true;
            self.kill_succeeded = true;
        }
    }

    fn detail(&self) -> String {
        format!(
            "term_errno={:?}, kill_errno={:?}, post_reap_probe_errno={:?}, post_reap_group_absent={:?}",
            self.term.errno,
            self.hard.and_then(|signal| signal.errno),
            self.after_reap.and_then(|signal| signal.errno),
            self.after_reap.map(|signal| signal.absent),
        )
    }
}

async fn cleanup_group(pid: u32, grace_ms: u64) -> CleanupResult {
    let term = signal_group(pid, libc::SIGTERM);
    if term.absent {
        return CleanupResult {
            terminated: true,
            hard_killed: false,
            kill_succeeded: true,
            term,
            hard: None,
            after_reap: None,
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
        term,
        hard: Some(hard),
        after_reap: None,
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
    errno: Option<i32>,
}

fn signal_group(pid: u32, signal: i32) -> GroupSignal {
    if pid == 0 || pid > i32::MAX as u32 {
        return GroupSignal {
            succeeded: false,
            absent: false,
            errno: Some(libc::EINVAL),
        };
    }
    let result = unsafe { libc::kill(-(pid as i32), signal) };
    if result == 0 {
        return GroupSignal {
            succeeded: true,
            absent: false,
            errno: None,
        };
    }
    // ESRCH means group members already exited, which is a successful
    // idempotent cleanup outcome.
    let errno = std::io::Error::last_os_error().raw_os_error();
    let absent = errno == Some(libc::ESRCH);
    GroupSignal {
        succeeded: absent,
        absent,
        errno,
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

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn post_reap_absence_reconciles_failed_escalation_after_successful_term() {
        let mut cleanup = CleanupResult {
            terminated: true,
            hard_killed: true,
            kill_succeeded: false,
            term: GroupSignal {
                succeeded: true,
                absent: false,
                errno: None,
            },
            hard: Some(GroupSignal {
                succeeded: false,
                absent: false,
                errno: Some(libc::EPERM),
            }),
            after_reap: None,
        };
        // Neither permission denial nor a still-existing group proves cleanup.
        for observed in [
            GroupSignal {
                succeeded: false,
                absent: false,
                errno: Some(libc::EPERM),
            },
            GroupSignal {
                succeeded: true,
                absent: false,
                errno: None,
            },
            GroupSignal {
                succeeded: false,
                absent: false,
                errno: None,
            },
        ] {
            cleanup.confirm_after_reap(|| observed);
            assert!(!cleanup.kill_succeeded);
        }
        cleanup.confirm_after_reap(|| GroupSignal {
            succeeded: true,
            absent: true,
            errno: Some(libc::ESRCH),
        });
        assert!(cleanup.kill_succeeded && cleanup.terminated && cleanup.hard_killed);
        let detail = cleanup.detail();
        assert!(detail.contains(&format!("kill_errno=Some({})", libc::EPERM)));
        assert!(detail.contains("post_reap_group_absent=Some(true)"));
        cleanup.confirm_after_reap(|| panic!("successful cleanup needs no additional signal"));
    }
}
