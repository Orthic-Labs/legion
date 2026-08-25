#![cfg(unix)]

use std::collections::BTreeMap;

use legion_effects::{platform::unix::UnixProcess, PlatformProcess, ProcessLaunch};
use tokio_util::sync::CancellationToken;

fn launch(executable: &str, args: &[&str]) -> ProcessLaunch {
    ProcessLaunch {
        executable: executable.into(),
        args: args.iter().map(|value| (*value).into()).collect(),
        cwd: "/tmp".into(),
        environment: BTreeMap::new(),
        stdout_limit: 1024,
        stderr_limit: 1024,
        timeout_ms: 1000,
        termination_grace_ms: 2,
        cancellation: CancellationToken::new(),
    }
}

#[tokio::test]
async fn captures_direct_output_and_reaps_child() {
    let output = UnixProcess::new()
        .run(launch("/usr/bin/printf", &["hello"]))
        .await
        .expect("direct process should spawn");

    assert_eq!(output.stdout, b"hello");
    assert!(output.stderr.is_empty());
    assert_eq!(output.exit_code, Some(0));
    assert!(output.process_tree.started);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn output_cap_terminates_process() {
    let mut request = launch("/usr/bin/printf", &["123456789"]);
    request.stdout_limit = 3;
    let output = UnixProcess::new()
        .run(request)
        .await
        .expect("direct process should spawn");

    assert_eq!(output.stdout, b"123");
    assert!(output.output_limited);
    assert!(output.process_tree.terminated);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn cancellation_uses_process_group_cleanup() {
    let request = launch("/bin/sleep", &["30"]);
    request.cancellation.cancel();
    let output = UnixProcess::new()
        .run(request)
        .await
        .expect("direct process should spawn");

    assert!(output.cancelled);
    assert!(output.process_tree.terminated);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn timeout_reaps_direct_child_after_grace() {
    let mut request = launch("/bin/sleep", &["30"]);
    request.timeout_ms = 1;
    let output = UnixProcess::new()
        .run(request)
        .await
        .expect("direct process should spawn");

    assert!(output.timed_out);
    assert!(output.process_tree.terminated);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn timeout_hard_kills_process_group_with_grandchild() {
    let mut request = launch("/bin/sh", &["-c", "sleep 30 & wait"]);
    request.timeout_ms = 1;
    let output = UnixProcess::new()
        .run(request)
        .await
        .expect("direct process should spawn");

    assert!(output.timed_out);
    assert!(output.process_tree.hard_killed);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn normal_exit_cleans_grandchild_process_group() {
    let output = UnixProcess::new()
        .run(launch("/bin/sh", &["-c", "sleep 30 & exit 0"]))
        .await
        .expect("direct process should spawn");

    assert_eq!(output.exit_code, Some(0));
    assert!(output.process_tree.reaped);
    assert!(output.process_tree.detail.is_some());
}
