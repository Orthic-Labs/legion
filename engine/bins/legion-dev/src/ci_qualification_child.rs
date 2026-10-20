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
    // Only this complete source-owned selector gets1200s; native calls stay120s.
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
    let cargo = argv
        .first()
        .and_then(|value| Path::new(value).file_name())
        .is_some_and(|name| name == "cargo" || name == "cargo.exe");
    if cargo
        && argv.len() == mobile.len() + 1
        && argv[1..]
            .iter()
            .zip(mobile)
            .all(|(value, expected)| value == expected)
    {
        Duration::from_secs(1200)
    } else {
        Duration::from_secs(300)
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
