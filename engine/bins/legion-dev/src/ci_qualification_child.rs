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
    use super::command_timeout;
    use std::{ffi::OsString, time::Duration};

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
            let failed = !report.failed.is_empty() || !report.survivors.is_empty();
            (
                json!({"gone":report.gone,"terminated":report.terminated,
                "refused":report.refused,"survivors":report.survivors,"failed":report.failed}),
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
