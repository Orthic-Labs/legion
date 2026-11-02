//! CI-only deadline adapter; lifecycle & containment stay with RightKit.
use rightkit_child_process::{sweep, AdoptedIdentity, OwnedCommand, ReapOutcome};
use serde_json::json;
use std::{
    ffi::OsString,
    path::Path,
    process::{ExitStatus, Stdio},
    time::{Duration, Instant},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);

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
    // Run40060030080 macOS seq31 (and run39839571253 seq31): the JVM harness
    // (15 sequential child controls, each re-driving Gradle/Kotlin/Scala builds
    // cold) hit the 300s default (exit124) after finishing only its first
    // control; that `positive` child alone took 206.55s (retained
    // child.stdout.log). 15 x 206.55s = 3098s bounds the span if every control
    // were as slow as the slowest one seen, so the deadline is 3600s. The
    // receipt's elapsedMillis from the next full run replaces this bound.
    let jvm = [
        "test",
        "--locked",
        "-p",
        "legion-audit",
        "--test",
        "real_jvm_sdk_accuracy",
        "real_jvm_sdk_accuracy",
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
            (jvm.as_slice(), 3600),
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

#[cfg(test)]
mod tests {
    use super::{
        combine_rechecks, command_timeout, recheck_identity, recheck_observation, recheck_pid,
        split_failed, sweep_error_fails, sweep_failed, FailedSweep, Recheck,
    };
    use rightkit_child_process::{AdoptedIdentity, StartToken};
    use std::{
        ffi::OsString,
        io,
        num::NonZeroU32,
        time::{Duration, Instant},
    };

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
            ("--test", "real_jvm_sdk_accuracy", 3600),
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
        let (cargo_argv, seconds) = matrix_commands()
            .into_iter()
            .find(|(argv, _)| {
                argv.iter()
                    .any(|value| value.to_string_lossy().contains("dotnet_sdk"))
            })
            .unwrap();
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

    // Orthic-Labs/legion#116: a descendant the sweep failed to signal because it was
    // already exiting must not turn a passing lane into exit 125.

    fn split_with(failed: &[u32], verdicts: &[(u32, Recheck)]) -> FailedSweep {
        split_failed(failed, |pid| {
            verdicts
                .iter()
                .find(|(candidate, _)| *candidate == pid)
                .map_or(Recheck::Unobserved, |(_, verdict)| *verdict)
        })
    }

    #[test]
    fn exiting_descendant_is_not_a_failed_sweep() {
        let split = split_with(&[41], &[(41, Recheck::Gone)]);
        assert_eq!(
            split,
            FailedSweep {
                exited: vec![41],
                failed: vec![]
            }
        );
        assert!(!sweep_failed(&split, &[]));
    }

    #[test]
    fn running_or_unobserved_descendant_stays_failed() {
        for verdict in [Recheck::Running, Recheck::Unobserved] {
            let split = split_with(&[41], &[(41, verdict)]);
            assert_eq!(
                split,
                FailedSweep {
                    exited: vec![],
                    failed: vec![41]
                },
                "{verdict:?}"
            );
            assert!(sweep_failed(&split, &[]), "{verdict:?}");
        }
    }

    #[test]
    fn mixed_failures_keep_only_the_real_ones_in_order() {
        let split = split_with(
            &[1, 2, 3, 4],
            &[
                (1, Recheck::Gone),
                (2, Recheck::Running),
                (3, Recheck::Gone),
                (4, Recheck::Unobserved),
            ],
        );
        assert_eq!(split.exited, vec![1, 3]);
        assert_eq!(split.failed, vec![2, 4]);
        assert!(sweep_failed(&split, &[]));
    }

    #[test]
    fn every_failed_pid_is_rechecked_exactly_once() {
        let mut seen = Vec::new();
        let split = split_failed(&[7, 8, 9], |pid| {
            seen.push(pid);
            Recheck::Gone
        });
        assert_eq!(seen, vec![7, 8, 9]);
        assert_eq!(split.exited, vec![7, 8, 9]);
    }

    #[test]
    fn survivors_fail_the_sweep_even_when_every_failed_pid_exited() {
        let split = split_with(&[41], &[(41, Recheck::Gone)]);
        assert!(sweep_failed(&split, &[52]));
    }

    #[test]
    fn clean_sweep_report_passes() {
        let split = split_with(&[], &[]);
        assert_eq!(split, FailedSweep::default());
        assert!(!sweep_failed(&split, &[]));
    }

    #[test]
    fn observation_error_is_never_read_as_an_exit() {
        assert_eq!(recheck_observation(&Ok(true)), Recheck::Gone);
        assert_eq!(recheck_observation(&Ok(false)), Recheck::Running);
        for error in [
            io::Error::from(io::ErrorKind::PermissionDenied),
            io::Error::from_raw_os_error(5),
            io::Error::other("unreadable"),
        ] {
            assert_eq!(recheck_observation(&Err(error)), Recheck::Unobserved);
        }
    }

    #[test]
    fn one_pid_is_gone_only_when_every_remembered_identity_is() {
        use Recheck::{Gone, Running, Unobserved};
        assert_eq!(combine_rechecks(Vec::<Recheck>::new()), Unobserved);
        assert_eq!(combine_rechecks([Gone]), Gone);
        assert_eq!(combine_rechecks([Gone, Gone]), Gone);
        assert_eq!(combine_rechecks([Gone, Unobserved]), Unobserved);
        assert_eq!(combine_rechecks([Gone, Running]), Running);
        assert_eq!(combine_rechecks([Unobserved, Running, Gone]), Running);
    }

    #[test]
    fn errored_sweep_fails_unless_every_descendant_is_gone() {
        use Recheck::{Gone, Running, Unobserved};
        assert!(sweep_error_fails(Vec::<Recheck>::new()));
        assert!(!sweep_error_fails([Gone, Gone]));
        assert!(sweep_error_fails([Gone, Running]));
        assert!(sweep_error_fails([Gone, Unobserved]));
    }

    #[test]
    fn recheck_tells_a_recycled_pid_from_a_running_process() {
        let pid = NonZeroU32::new(std::process::id()).expect("process id is nonzero");
        let live = AdoptedIdentity::capture(pid)
            .expect("own identity is readable")
            .expect("own process exists");
        // Same pid, other start time: the pid changed hands, so the remembered process is gone.
        let recycled = AdoptedIdentity::from_recorded(pid, StartToken { major: 0, minor: 0 }, None);
        // A deadline that has already passed still observes once.
        let now = Instant::now();
        assert_eq!(recheck_identity(&live, now), Recheck::Running);
        assert_eq!(recheck_identity(&recycled, now), Recheck::Gone);
        assert_eq!(
            recheck_pid(std::slice::from_ref(&recycled), pid.get(), now),
            Recheck::Gone
        );
        assert_eq!(
            recheck_pid(&[recycled, live.clone()], pid.get(), now),
            Recheck::Running
        );
        assert_eq!(recheck_pid(&[], pid.get(), now), Recheck::Unobserved);
        assert_eq!(
            recheck_pid(&[live], pid.get().wrapping_add(1), now),
            Recheck::Unobserved
        );
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
