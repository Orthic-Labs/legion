//! CI-only deadline adapter; lifecycle & containment stay with RightKit.
use rightkit_child_process::{sweep, AdoptedIdentity, OwnedCommand, ReapOutcome};
use serde_json::json;
use std::{
    ffi::OsString,
    process::{ExitStatus, Stdio},
    time::{Duration, Instant},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
// Every managed qualification command gets the default deadline. The per-selector
// matrix deadlines belonged to test selectors that no longer exist.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

#[cfg(unix)]
fn signal(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}
#[cfg(not(unix))]
fn signal(_: ExitStatus) -> Option<i32> {
    None
}

fn shell_status(status: ExitStatus) -> u8 {
    status.code().map_or_else(
        || (128 + signal(status).unwrap_or(0)) as u8,
        |code| code as u8,
    )
}

/// How long one second look at the descendants the sweep could not signal may wait for
/// them to finish exiting. It matches the bound `rightkit-child-process` 0.5.6 applies to
/// the same case inside `sweep`.
const FAILED_RECHECK_TIMEOUT: Duration = Duration::from_secs(2);
const FAILED_RECHECK_POLL: Duration = Duration::from_millis(20);

/// What a second look at one remembered descendant found (Orthic-Labs/legion#116).
///
/// The sweep lists a pid as `failed` when its signal errored. On Windows that includes a
/// process that is already exiting: `TerminateProcess` fails with `ERROR_ACCESS_DENIED`
/// while the exit finishes. Such a descendant is gone, not failed, and counting it failed
/// turned passing lanes into exit 125.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Recheck {
    /// The remembered process no longer runs: its pid names nothing, names a different
    /// process, or is an exited process awaiting reap.
    Gone,
    /// The remembered process still runs although the sweep could not stop it.
    Running,
    /// The process could not be observed, which proves nothing about whether it exited.
    Unobserved,
}

/// Maps `AdoptedIdentity::confirmed_gone` to a verdict. An observation error is never
/// read as an exit: a descendant that cannot be proven gone stays failed.
fn recheck_observation(observed: &std::io::Result<bool>) -> Recheck {
    match observed {
        Ok(true) => Recheck::Gone,
        Ok(false) => Recheck::Running,
        Err(_) => Recheck::Unobserved,
    }
}

/// Combines the verdicts for every identity remembered under one pid. The pid is gone only
/// when each remembered process is; no identity at all proves nothing.
fn combine_rechecks(rechecks: impl IntoIterator<Item = Recheck>) -> Recheck {
    let mut any = false;
    let mut unobserved = false;
    for recheck in rechecks {
        any = true;
        match recheck {
            Recheck::Running => return Recheck::Running,
            Recheck::Unobserved => unobserved = true,
            Recheck::Gone => {}
        }
    }
    if any && !unobserved {
        Recheck::Gone
    } else {
        Recheck::Unobserved
    }
}

/// The pids a sweep listed as `failed`, split by a second look.
#[derive(Debug, Default, Eq, PartialEq)]
struct FailedSweep {
    /// The signal failed but the process is gone: it was exiting, so it is not a failure.
    exited: Vec<u32>,
    /// Still running, or not provably gone: a real failure.
    failed: Vec<u32>,
}

fn split_failed(failed: &[u32], mut recheck: impl FnMut(u32) -> Recheck) -> FailedSweep {
    let mut split = FailedSweep::default();
    for &pid in failed {
        if recheck(pid) == Recheck::Gone {
            split.exited.push(pid);
        } else {
            split.failed.push(pid);
        }
    }
    split
}

/// Whether the sweep leaves the lane failed: a real failure or any survivor. A survivor was
/// force-signalled and still present at the end of the sweep, so it is never rechecked away.
fn sweep_failed(split: &FailedSweep, survivors: &[u32]) -> bool {
    !split.failed.is_empty() || !survivors.is_empty()
}

/// Whether a sweep that errored before it finished still fails the lane. It does unless
/// every remembered descendant is proven gone, which is the state the sweep was after.
fn sweep_error_fails(rechecks: impl IntoIterator<Item = Recheck>) -> bool {
    combine_rechecks(rechecks) != Recheck::Gone
}

/// Looks again at one remembered process until it is confirmed gone or `deadline` passes,
/// always observing at least once. An observation error is retried: a process that is
/// still exiting can refuse to be opened for a moment.
fn recheck_identity(identity: &AdoptedIdentity, deadline: Instant) -> Recheck {
    loop {
        let verdict = recheck_observation(&identity.confirmed_gone());
        if verdict == Recheck::Gone || Instant::now() >= deadline {
            return verdict;
        }
        std::thread::sleep(FAILED_RECHECK_POLL);
    }
}

fn recheck_pid(descendants: &[AdoptedIdentity], pid: u32, deadline: Instant) -> Recheck {
    combine_rechecks(
        descendants
            .iter()
            .filter(|identity| identity.pid() == pid)
            .map(|identity| recheck_identity(identity, deadline)),
    )
}

pub fn run(sequence: u64, argv: &[OsString]) -> u8 {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || !matches!(
            std::env::var("RUNNER_OS").as_deref(),
            Ok("macOS" | "Windows")
        )
        || sequence == 0
        || argv.is_empty()
    {
        eprintln!("CI qualification child requires managed native CI & original span");
        return 125;
    }
    let timeout = COMMAND_TIMEOUT;
    let recorded_argv: Vec<_> = argv.iter().map(|value| value.to_string_lossy()).collect();
    let started = Instant::now();
    let mut command = OwnedCommand::new(&argv[0]);
    command.partial_spawn_cleanup_timeout(CLEANUP_TIMEOUT);
    command
        .command_mut()
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!(
                "AUDIT_QUALIFICATION_NATIVE_END {}",
                json!({
                "sequence":sequence,"argv":recorded_argv,"timedOut":false,
                "spawnError":error.to_string(),"wrapperExitCode":125})
            );
            return 125;
        }
    };
    child.set_drop_reap_timeout(Duration::ZERO);
    let pid = child.id();
    // Remember owner-proven descendants while parent links remain available,
    // including native children that create their own Unix process groups.
    let mut descendants: Vec<AdoptedIdentity> = Vec::new();
    let observed = (|| -> std::io::Result<bool> {
        let handle = child.process_handle()?;
        loop {
            for identity in child.descendant_identities()? {
                if !descendants.iter().any(|prior| {
                    prior.pid() == identity.pid() && prior.start_token() == identity.start_token()
                }) {
                    descendants.push(identity);
                }
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            // Observe without reaping: leader identity still pins its group
            // until bounded tree teardown kills stragglers & collects status.
            if handle.wait_exited_timeout(remaining.min(Duration::from_secs(1)))? {
                return Ok(true);
            }
            if started.elapsed() >= timeout {
                return Ok(false);
            }
        }
    })();
    let timed_out = matches!(&observed, Ok(false));
    let wait_error = observed.err().map(|error| error.to_string());
    let cleanup = child.terminate_tree_bounded(CLEANUP_TIMEOUT);
    let (native_status, cleanup_error) = match cleanup {
        Ok(ReapOutcome::Exited(status)) => (Some(status), None),
        Ok(ReapOutcome::TimedOut) => (
            None,
            Some("owned tree reap exceeded cleanup bound".to_owned()),
        ),
        Err(error) => (None, Some(error.to_string())),
    };
    descendants.reverse();
    // Owner checks pid+start identity before every signal. Its force wait is
    // fixed500ms; no unrelated process is killed after PID reuse.
    let swept = sweep(&descendants, Duration::ZERO);
    // A descendant whose signal errored may simply be exiting (Windows reports
    // ERROR_ACCESS_DENIED then). Look again at each before it can fail the lane; a live
    // survivor or an unobservable pid still does.
    let recheck_deadline = Instant::now() + FAILED_RECHECK_TIMEOUT;
    let (sweep_receipt, lane_sweep_failed) = match swept {
        Ok(report) => {
            let split = split_failed(&report.failed, |pid| {
                recheck_pid(&descendants, pid, recheck_deadline)
            });
            let failed = sweep_failed(&split, &report.survivors);
            (
                json!({"gone":report.gone,"terminated":report.terminated,
                "refused":report.refused,"survivors":report.survivors,
                "failed":split.failed,"failedButGone":split.exited}),
                failed,
            )
        }
        Err(error) => {
            let failed = sweep_error_fails(
                descendants
                    .iter()
                    .map(|identity| recheck_identity(identity, recheck_deadline)),
            );
            let gone_after_error = !failed;
            (
                json!({"error":error.to_string(),"descendantsGoneAfterError":gone_after_error}),
                failed,
            )
        }
    };
    let status = if cleanup_error.is_some() || wait_error.is_some() || lane_sweep_failed {
        125
    } else if timed_out {
        124
    } else {
        native_status.map_or(125, shell_status)
    };
    eprintln!(
        "{} {}",
        if timed_out {
            "AUDIT_QUALIFICATION_COMMAND_TIMEOUT"
        } else {
            "AUDIT_QUALIFICATION_NATIVE_END"
        },
        json!({
            "sequence":sequence,"argv":recorded_argv,"pid":pid,"timeoutSeconds":timeout.as_secs(),
            "elapsedMillis":started.elapsed().as_millis(),"timedOut":timed_out,
            "nativeExitCode":native_status.and_then(|value| value.code()),
            "nativeSignal":native_status.and_then(signal),"wrapperExitCode":status,
            "waitError":wait_error,"cleanup":{"reaped":native_status.is_some(),
                "error":cleanup_error,"descendants":sweep_receipt}
        })
    );
    // Final owner Drop can send a kill but adds zero reap wait.
    drop(child);
    status
}
