//! CI-only deadline adapter; lifecycle & containment stay with RightKit.
use rightkit_child_process::{sweep, AdoptedIdentity, IdentityCheck, OwnedCommand, ReapOutcome};
use serde_json::json;
use std::{
    ffi::OsString,
    io,
    path::Path,
    process::{ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a descendant the sweep could not signal may keep reading as present before the
/// wrapper counts it a survivor. A process that is already exiting refuses `TerminateProcess`
/// (Windows: `ERROR_ACCESS_DENIED`) a moment before its handle signals; RightKit 0.5.6 waits
/// the same 2 s on that handle, so this matches it until Legion moves to 0.5.6.
const FAILED_RECHECK_WINDOW: Duration = Duration::from_secs(2);
const FAILED_RECHECK_POLL: Duration = Duration::from_millis(20);

fn command_timeout(argv: &[OsString]) -> Duration {
    // Run39394355495 macOS seq44 completed in816.08s (snapshot SHA56fb2...).
    // Only complete source-owned selectors get matrix deadlines; native calls stay120s.
    let mobile = [
        "test",
        "--locked",
        "-p",
        "legion-audit",
        "--lib",
        "native_providers::code::tools::mobile_sdk::tests::native::native_mobile_sdk_controls",
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ];
    let javascript = [
        "test",
        "--locked",
        "-p",
        "legion-audit",
        "--test",
        "real_javascript_sdk_accuracy",
        "real_javascript_sdk_accuracy",
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ];
    let rust = [
        "test",
        "--locked",
        "-p",
        "legion-audit",
        "--test",
        "real_rust_code_accuracy",
        "real_rust_code_accuracy",
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ];
    // Run39520170497 macOS seq57: the .NET harness (three language SDK builds)
    // exceeded the 300s default (exit124); run 39550845440 took 1297s of 1500s.
    let dotnet = [
        "test",
        "--locked",
        "-p",
        "legion-audit",
        "--lib",
        "native_providers::code::tools::dotnet_sdk_accuracy::original_dotnet_sdk_contract_has_real_language_task_and_boundary_controls",
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ];
    // The .NET span runs cargo through its recording child
    // (`python3 run-dotnet-sdk-qualification-child.py --output-root DIR -- cargo ...`);
    // the deadline belongs to the cargo command after the separator.
    let child_wrapped = argv.len() > 4
        && Path::new(&argv[0])
            .file_name()
            .is_some_and(|name| name == "python3" || name == "python3.exe" || name == "python")
        && Path::new(&argv[1])
            .file_name()
            .is_some_and(|name| name == "run-dotnet-sdk-qualification-child.py")
        && argv[2] == "--output-root"
        && argv[4] == "--";
    let argv: &[OsString] = if child_wrapped { &argv[5..] } else { argv };
    // Run39526093982 macOS seq92: the Rust SDK validator (python) reads and
    // re-derives the whole retained record and timed out at the 300s default.
    let python_validator = argv.len() >= 2
        && Path::new(&argv[0])
            .file_name()
            .is_some_and(|name| name == "python3" || name == "python3.exe" || name == "python")
        && Path::new(&argv[1])
            .file_name()
            .is_some_and(|name| name == "audit-rust-code-sdk-accuracy.py");
    if python_validator {
        return Duration::from_secs(1500);
    }
    let cargo = argv
        .first()
        .and_then(|value| Path::new(value).file_name())
        .is_some_and(|name| name == "cargo" || name == "cargo.exe");
    if cargo {
        for (selector, seconds) in [
            (mobile.as_slice(), 1200),
            (javascript.as_slice(), 1800),
            (rust.as_slice(), 2400),
            (dotnet.as_slice(), 2400),
        ] {
            if argv.len() == selector.len() + 1
                && argv[1..]
                    .iter()
                    .zip(selector)
                    .all(|(value, expected)| value == *expected)
            {
                return Duration::from_secs(seconds);
            }
        }
    }
    Duration::from_secs(300)
}

/// What re-reading the identity of one pid the sweep listed as `failed` says now.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Recheck {
    /// No process has the pid: the descendant is gone.
    Gone,
    /// The pid names a different process: the remembered descendant is gone.
    Replaced,
    /// The remembered process is still present.
    Live,
    /// The identity could not be read, or the pid was never remembered. Nothing proves the
    /// descendant is gone.
    Unresolved(String),
}

/// The pids the sweep listed as `failed`, sorted by what re-reading their identity found.
#[derive(Debug, Default, Eq, PartialEq)]
struct FailedRecheck {
    gone: Vec<u32>,
    replaced: Vec<u32>,
    live: Vec<u32>,
    unresolved: Vec<(u32, String)>,
}

impl FailedRecheck {
    /// Only a descendant that is still present or whose state is unknown fails the lane.
    fn blocks(&self) -> bool {
        !self.live.is_empty() || !self.unresolved.is_empty()
    }

    fn receipt(&self) -> serde_json::Value {
        json!({
            "gone": self.gone,
            "replaced": self.replaced,
            "live": self.live,
            "unresolved": self.unresolved.iter()
                .map(|(pid, error)| json!({"pid": pid, "error": error}))
                .collect::<Vec<_>>(),
        })
    }
}

/// Combines the identity checks of every remembered identity that carries one pid (a pid
/// reused during the span is remembered once per start time; the sweep reports pids only).
/// Present beats unreadable beats gone: only proof that every identity is gone clears a pid.
fn combine_identity_checks(checks: impl IntoIterator<Item = io::Result<IdentityCheck>>) -> Recheck {
    let (mut replaced, mut error, mut seen) = (false, None, false);
    for check in checks {
        seen = true;
        match check {
            Ok(IdentityCheck::Same) => return Recheck::Live,
            Ok(IdentityCheck::Replaced) => replaced = true,
            Ok(IdentityCheck::Gone) => {}
            Err(failure) => error = error.or_else(|| Some(failure.to_string())),
        }
    }
    match (seen, error) {
        (false, _) => Recheck::Unresolved("pid is not a remembered descendant".to_owned()),
        (true, Some(error)) => Recheck::Unresolved(error),
        (true, None) if replaced => Recheck::Replaced,
        (true, None) => Recheck::Gone,
    }
}

/// Re-reads, by pid and start identity (the proof the sweep itself uses), each pid the sweep
/// could not signal. `probe` reads one pid; `keep_waiting` pauses and says whether the window
/// is still open. A pid that reads as present is probed again until the window closes, since
/// a process that is mid-exit still reads as present for a moment; only one that never stops
/// being present is live. Gone, replaced and unreadable pids are settled at once.
fn recheck_failed(
    failed: &[u32],
    mut probe: impl FnMut(u32) -> Recheck,
    mut keep_waiting: impl FnMut() -> bool,
) -> FailedRecheck {
    let mut report = FailedRecheck::default();
    let mut pending: Vec<u32> = Vec::new();
    for &pid in failed {
        if !pending.contains(&pid) {
            pending.push(pid);
        }
    }
    while !pending.is_empty() {
        let mut present = Vec::new();
        for pid in pending {
            match probe(pid) {
                Recheck::Gone => report.gone.push(pid),
                Recheck::Replaced => report.replaced.push(pid),
                Recheck::Live => present.push(pid),
                Recheck::Unresolved(error) => report.unresolved.push((pid, error)),
            }
        }
        pending = present;
        if !pending.is_empty() && !keep_waiting() {
            report.live.append(&mut pending);
        }
    }
    report
}

/// [`recheck_failed`] against the identities remembered while the tree was observable, for at
/// most `window`.
fn recheck_failed_descendants(
    descendants: &[AdoptedIdentity],
    failed: &[u32],
    window: Duration,
) -> FailedRecheck {
    let deadline = Instant::now() + window;
    recheck_failed(
        failed,
        |pid| {
            combine_identity_checks(
                descendants
                    .iter()
                    .filter(|identity| identity.pid() == pid)
                    .map(AdoptedIdentity::verify),
            )
        },
        || {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(FAILED_RECHECK_POLL);
            true
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{combine_identity_checks, command_timeout, recheck_failed, FailedRecheck, Recheck};
    use rightkit_child_process::IdentityCheck;
    use serde_json::json;
    use std::{cell::Cell, ffi::OsString, io, time::Duration};

    fn matrix_commands() -> Vec<(Vec<OsString>, u64)> {
        [
            (
                "--lib",
                "native_providers::code::tools::mobile_sdk::tests::native::native_mobile_sdk_controls",
                1200,
            ),
            ("--test", "real_javascript_sdk_accuracy", 1800),
            ("--test", "real_rust_code_accuracy", 2400),
            (
                "--lib",
                "native_providers::code::tools::dotnet_sdk_accuracy::original_dotnet_sdk_contract_has_real_language_task_and_boundary_controls",
                2400,
            ),
        ]
        .into_iter()
        .map(|(kind, target, seconds)| {
            let mut argv = vec!["cargo", "test", "--locked", "-p", "legion-audit", kind, target];
            if kind == "--test" {
                argv.push(target);
            }
            argv.extend(["--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]);
            (argv.into_iter().map(OsString::from).collect(), seconds)
        })
        .collect()
    }

    #[test]
    fn exact_matrix_commands_get_only_their_declared_deadlines() {
        for (mut argv, seconds) in matrix_commands() {
            for executable in [
                "cargo",
                "cargo.exe",
                "/toolchain/bin/cargo",
                "/toolchain/bin/cargo.exe",
            ] {
                argv[0] = executable.into();
                assert_eq!(
                    command_timeout(&argv),
                    Duration::from_secs(seconds),
                    "{argv:?}"
                );
            }
        }
    }

    #[test]
    fn dotnet_child_wrapped_command_gets_the_dotnet_deadline() {
        let (cargo_argv, seconds) = matrix_commands().pop().unwrap();
        let mut argv: Vec<OsString> = [
            "/usr/bin/python3",
            "/work/scripts/ci/run-dotnet-sdk-qualification-child.py",
            "--output-root",
            "/tmp/dotnet",
            "--",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        argv.extend(cargo_argv);
        assert_eq!(command_timeout(&argv), Duration::from_secs(seconds));
    }

    #[test]
    fn rust_validator_gets_its_own_deadline() {
        let argv: Vec<OsString> = [
            "/usr/bin/python3",
            "scripts/ci/audit-rust-code-sdk-accuracy.py",
            "--root",
            "/w",
            "--receipts",
            "/r",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(command_timeout(&argv), Duration::from_secs(1500));
        let other: Vec<OsString> = [
            "/usr/bin/python3",
            "scripts/ci/audit-semgrep-provider-accuracy.py",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(command_timeout(&other), Duration::from_secs(300));
    }

    #[test]
    fn matrix_command_near_misses_keep_default_deadline() {
        let default = Duration::from_secs(300);
        assert_eq!(command_timeout(&[]), default);
        for (argv, _) in matrix_commands() {
            // Every token matters, including executable, target, & inner controls.
            for index in 0..argv.len() {
                let mut changed = argv.clone();
                changed[index].push("-near-miss");
                assert_eq!(command_timeout(&changed), default, "{changed:?}");
                let mut missing = argv.clone();
                missing.remove(index);
                assert_eq!(command_timeout(&missing), default, "{missing:?}");
            }
            let mut extended = argv;
            extended.push("--extra".into());
            assert_eq!(command_timeout(&extended), default, "{extended:?}");
        }
    }

    fn ok(check: IdentityCheck) -> io::Result<IdentityCheck> {
        Ok(check)
    }

    fn unreadable() -> io::Result<IdentityCheck> {
        Err(io::Error::other("identity unreadable"))
    }

    #[test]
    fn identity_checks_clear_a_pid_only_when_every_identity_is_gone() {
        use IdentityCheck::{Gone, Replaced, Same};
        assert_eq!(combine_identity_checks([ok(Gone)]), Recheck::Gone);
        assert_eq!(combine_identity_checks([ok(Gone), ok(Gone)]), Recheck::Gone);
        assert_eq!(combine_identity_checks([ok(Replaced)]), Recheck::Replaced);
        assert_eq!(
            combine_identity_checks([ok(Gone), ok(Replaced)]),
            Recheck::Replaced
        );
        // Present beats everything, wherever it sits among the identities of one pid.
        assert_eq!(combine_identity_checks([ok(Same)]), Recheck::Live);
        assert_eq!(
            combine_identity_checks([ok(Gone), unreadable(), ok(Same)]),
            Recheck::Live
        );
        // Unreadable beats gone: nothing proves the descendant left.
        assert_eq!(
            combine_identity_checks([ok(Gone), unreadable()]),
            Recheck::Unresolved("identity unreadable".to_owned())
        );
        // A pid the wrapper never remembered cannot be proven gone.
        assert!(matches!(
            combine_identity_checks([]),
            Recheck::Unresolved(_)
        ));
    }

    #[test]
    fn descendant_that_was_already_exiting_no_longer_fails_the_lane() {
        // Windows: TerminateProcess is refused on a process that is exiting, so the sweep
        // lists it as failed; its handle signals within the window and it reads as gone.
        let mut reads = 0;
        let mut waits = 0;
        let report = recheck_failed(
            &[4242],
            |_| {
                reads += 1;
                if reads < 3 {
                    Recheck::Live
                } else {
                    Recheck::Gone
                }
            },
            || {
                waits += 1;
                true
            },
        );
        assert_eq!(report.gone, vec![4242]);
        assert!(!report.blocks());
        assert_eq!((reads, waits), (3, 2));
    }

    #[test]
    fn descendant_replaced_by_an_unrelated_process_no_longer_fails_the_lane() {
        let report = recheck_failed(&[7], |_| Recheck::Replaced, || unreachable!());
        assert_eq!(report.replaced, vec![7]);
        assert!(!report.blocks());
    }

    #[test]
    fn live_survivor_keeps_the_lane_failed_once_the_window_closes() {
        let mut waits = 0;
        let report = recheck_failed(
            &[11],
            |_| Recheck::Live,
            || {
                waits += 1;
                waits <= 4
            },
        );
        assert_eq!(report.live, vec![11]);
        assert!(report.gone.is_empty());
        assert!(report.blocks());
        assert_eq!(waits, 5);
    }

    #[test]
    fn unresolvable_failure_keeps_the_lane_failed_without_waiting() {
        let report = recheck_failed(
            &[13],
            |_| Recheck::Unresolved("denied".to_owned()),
            || unreachable!(),
        );
        assert_eq!(report.unresolved, vec![(13, "denied".to_owned())]);
        assert!(report.blocks());
    }

    #[test]
    fn mixed_failures_clear_only_the_gone_ones() {
        let live_reads = Cell::new(0);
        let report = recheck_failed(
            &[1, 2, 3, 4, 2],
            |pid| match pid {
                1 => Recheck::Gone,
                2 => {
                    live_reads.set(live_reads.get() + 1);
                    Recheck::Live
                }
                3 => Recheck::Replaced,
                _ => Recheck::Unresolved("denied".to_owned()),
            },
            || live_reads.get() < 2,
        );
        assert_eq!(
            report,
            FailedRecheck {
                gone: vec![1],
                replaced: vec![3],
                live: vec![2],
                unresolved: vec![(4, "denied".to_owned())],
            }
        );
        // The duplicate pid is probed once per round, not once per listing.
        assert_eq!(live_reads.get(), 2);
        assert!(report.blocks());
    }

    #[test]
    fn no_failures_never_blocks() {
        let report = recheck_failed(&[], |_| unreachable!(), || unreachable!());
        assert_eq!(report, FailedRecheck::default());
        assert!(!report.blocks());
    }

    #[test]
    fn recheck_receipt_names_every_entry_with_its_outcome() {
        let report = FailedRecheck {
            gone: vec![1],
            replaced: vec![3],
            live: vec![2],
            unresolved: vec![(4, "denied".to_owned())],
        };
        assert_eq!(
            report.receipt(),
            json!({"gone":[1],"replaced":[3],"live":[2],
                "unresolved":[{"pid":4,"error":"denied"}]})
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_descendant_is_live_until_it_is_gone_and_a_recycled_pid_is_replaced() {
        use super::recheck_failed_descendants;
        use rightkit_child_process::{AdoptedIdentity, StartToken};
        use std::{num::NonZeroU32, process::Command};

        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id();
        let identity = AdoptedIdentity::capture(NonZeroU32::new(pid).unwrap())
            .unwrap()
            .expect("a running child has an identity");
        let window = Duration::from_millis(100);

        let live = recheck_failed_descendants(std::slice::from_ref(&identity), &[pid], window);
        assert_eq!(live.live, vec![pid]);
        assert!(live.blocks());

        child.kill().unwrap();
        child.wait().unwrap();
        let gone = recheck_failed_descendants(std::slice::from_ref(&identity), &[pid], window);
        assert_eq!(gone.gone, vec![pid]);
        assert!(!gone.blocks());

        // The same pid with another start time names a different process now.
        let own = std::process::id();
        let recycled = AdoptedIdentity::from_recorded(
            NonZeroU32::new(own).unwrap(),
            StartToken { major: 0, minor: 0 },
            None,
        );
        let replaced = recheck_failed_descendants(&[recycled], &[own], window);
        assert_eq!(replaced.replaced, vec![own]);
        assert!(!replaced.blocks());
    }
}

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
    let timeout = command_timeout(argv);
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
    let (sweep_receipt, sweep_failed) = match swept {
        Ok(report) => {
            // The sweep lists a descendant it could not signal as `failed` even when that
            // descendant was already exiting (Windows refuses TerminateProcess on it). Only
            // one that is still present, or whose state cannot be read, fails the lane.
            let recheck =
                recheck_failed_descendants(&descendants, &report.failed, FAILED_RECHECK_WINDOW);
            let failed = recheck.blocks() || !report.survivors.is_empty();
            (
                json!({"gone":report.gone,"terminated":report.terminated,
                "refused":report.refused,"survivors":report.survivors,"failed":report.failed,
                "failedRecheck":recheck.receipt()}),
                failed,
            )
        }
        Err(error) => (json!({"error":error.to_string()}), true),
    };
    let status = if cleanup_error.is_some() || wait_error.is_some() || sweep_failed {
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
