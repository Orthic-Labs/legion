#![cfg(windows)]

use std::{collections::BTreeMap, time::Duration};

use legion_effects::{platform::windows::WindowsProcess, PlatformProcess, ProcessLaunch};
use tokio_util::sync::CancellationToken;

fn launch(mode: &str, timeout_ms: u64, stdout_limit: usize) -> ProcessLaunch {
    let mut environment = BTreeMap::new();
    environment.insert("LEGION_WINDOWS_FIXTURE".into(), mode.into());
    ProcessLaunch {
        executable: std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        args: vec![
            "--exact".into(),
            "fixture_child".into(),
            "--nocapture".into(),
        ],
        cwd: std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        environment,
        stdout_limit,
        stderr_limit: 4096,
        timeout_ms,
        termination_grace_ms: 5,
        cancellation: CancellationToken::new(),
    }
}

#[tokio::test]
async fn timeout_reports_bounded_job_cleanup() {
    let output = WindowsProcess.run(launch("sleep", 25, 4096)).await.unwrap();
    assert!(output.timed_out);
    assert!(output.process_tree.reaped);
    assert!(output.process_tree.terminated);
}

#[tokio::test]
async fn cancellation_reports_bounded_job_cleanup() {
    let process = WindowsProcess;
    let launch = launch("sleep", 5_000, 4096);
    let cancellation = launch.cancellation.clone();
    cancellation.cancel();
    let output = process
        .run(ProcessLaunch {
            cancellation,
            ..launch
        })
        .await
        .unwrap();
    assert!(output.cancelled);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn output_cap_terminates_job() {
    let output = WindowsProcess
        .run(launch("burst", 5_000, 64))
        .await
        .unwrap();
    assert!(output.output_limited);
    assert!(output.process_tree.reaped);
    assert!(output.stdout.len() <= 64);
}

#[test]
fn fixture_child() {
    match std::env::var("LEGION_WINDOWS_FIXTURE").as_deref() {
        Ok("sleep") => std::thread::sleep(Duration::from_millis(500)),
        Ok("burst") => print!("{}", "x".repeat(16 * 1024)),
        _ => {}
    }
}
