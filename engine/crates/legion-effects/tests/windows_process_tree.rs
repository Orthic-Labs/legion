#![cfg(windows)]

use std::{
    collections::BTreeMap,
    fs,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use legion_effects::{platform::windows::WindowsProcess, PlatformProcess, ProcessLaunch};
use tokio_util::sync::CancellationToken;
use windows_sys::{
    core::BOOL,
    Win32::System::Console::{SetConsoleCtrlHandler, CTRL_BREAK_EVENT, PHANDLER_ROUTINE},
};

static CTRL_BREAK_SEEN: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn consume_ctrl_break(ctrl_type: u32) -> BOOL {
    if ctrl_type == CTRL_BREAK_EVENT {
        1
    } else {
        0
    }
}

unsafe extern "system" fn stop_on_ctrl_break(ctrl_type: u32) -> BOOL {
    if ctrl_type == CTRL_BREAK_EVENT {
        CTRL_BREAK_SEEN.store(true, Ordering::Release);
        1
    } else {
        0
    }
}

fn install_ctrl_handler(handler: PHANDLER_ROUTINE) {
    assert_ne!(unsafe { SetConsoleCtrlHandler(handler, 1) }, 0);
}

#[allow(clippy::zombie_processes)]
fn spawn_live_descendant() {
    // Deliberately do not wait: this child inherits the tested KILL_ON_CLOSE
    // job, so leader exit must leave it live for process-tree cleanup.
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "fixture_child", "--nocapture"])
        .env("LEGION_WINDOWS_FIXTURE", "grandchild-sleep")
        .spawn()
        .unwrap();
}

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
        termination_grace_ms: 250,
        cancellation: CancellationToken::new(),
    }
}

#[tokio::test]
async fn normal_exit_reports_natural_completion_and_cleanup_truth() {
    let output = WindowsProcess
        .run(launch("normal", 5_000, 4096))
        .await
        .unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert!(!output.timed_out);
    assert!(!output.cancelled);
    assert!(!output.output_limited);
    assert!(output.kill_succeeded);
    assert!(output.process_tree.started);
    assert!(output.process_tree.terminated);
    assert!(!output.process_tree.hard_killed);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn command_shim_runs_through_cmd_with_arguments_preserved() {
    let root = std::env::temp_dir().join(format!(
        "legion-command-shim-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::create_dir_all(&root).unwrap();
    let shim = root.join("client.cmd");
    fs::write(&shim, "@echo off\r\necho %~1^|%~2\r\n").unwrap();
    let output = WindowsProcess
        .run(ProcessLaunch {
            executable: shim.to_string_lossy().into_owned(),
            args: vec!["first value".into(), "second value".into()],
            cwd: root.to_string_lossy().into_owned(),
            environment: std::env::vars().collect(),
            stdout_limit: 4096,
            stderr_limit: 4096,
            timeout_ms: 5_000,
            termination_grace_ms: 250,
            cancellation: CancellationToken::new(),
        })
        .await
        .unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "first value|second value"
    );
}

#[tokio::test]
async fn normal_leader_exit_hard_cleans_live_descendant() {
    let output = WindowsProcess
        .run(launch("leader-exits-with-descendant", 5_000, 4096))
        .await
        .unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert!(!output.timed_out);
    assert!(!output.cancelled);
    assert!(!output.output_limited);
    assert!(output.kill_succeeded);
    assert!(output.process_tree.started);
    assert!(output.process_tree.terminated);
    assert!(output.process_tree.hard_killed);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn timeout_reports_cooperative_cleanup_without_hard_kill() {
    let output = WindowsProcess
        .run(launch("cooperative-sleep", 1_000, 4096))
        .await
        .unwrap();
    assert!(output.timed_out);
    assert!(!output.cancelled);
    assert!(!output.output_limited);
    assert!(output.kill_succeeded);
    assert!(output.process_tree.reaped);
    assert!(output.process_tree.terminated);
    assert!(!output.process_tree.hard_killed);
}

#[tokio::test]
async fn timeout_reports_required_hard_cleanup_truth() {
    let output = WindowsProcess
        .run(launch("non-cooperative-sleep", 250, 4096))
        .await
        .unwrap();
    assert!(output.timed_out);
    assert!(!output.cancelled);
    assert!(!output.output_limited);
    assert!(output.kill_succeeded);
    assert!(output.process_tree.reaped);
    assert!(output.process_tree.terminated);
    assert!(output.process_tree.hard_killed);
}

#[tokio::test]
async fn cancellation_reports_cooperative_cleanup_without_hard_kill() {
    let process = WindowsProcess;
    let launch = launch("cooperative-sleep", 5_000, 4096);
    let cancellation = launch.cancellation.clone();
    let mut run = Box::pin(process.run(ProcessLaunch {
        cancellation: cancellation.clone(),
        ..launch
    }));
    let output = tokio::select! {
        result = &mut run => result.unwrap(),
        _ = tokio::time::sleep(Duration::from_millis(250)) => {
            cancellation.cancel();
            run.await.unwrap()
        }
    };
    assert!(output.cancelled);
    assert!(!output.timed_out);
    assert!(!output.output_limited);
    assert!(output.kill_succeeded);
    assert!(output.process_tree.started);
    assert!(output.process_tree.terminated);
    assert!(!output.process_tree.hard_killed);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn cancellation_reports_required_hard_cleanup_truth() {
    let process = WindowsProcess;
    let launch = launch("non-cooperative-sleep", 5_000, 4096);
    let cancellation = launch.cancellation.clone();
    let mut run = Box::pin(process.run(ProcessLaunch {
        cancellation: cancellation.clone(),
        ..launch
    }));
    let output = tokio::select! {
        result = &mut run => result.unwrap(),
        _ = tokio::time::sleep(Duration::from_millis(250)) => {
            cancellation.cancel();
            run.await.unwrap()
        }
    };
    assert!(output.cancelled);
    assert!(!output.timed_out);
    assert!(!output.output_limited);
    assert!(output.kill_succeeded);
    assert!(output.process_tree.started);
    assert!(output.process_tree.terminated);
    assert!(output.process_tree.hard_killed);
    assert!(output.process_tree.reaped);
}

#[tokio::test]
async fn output_cap_reports_required_hard_cleanup_truth() {
    let output = WindowsProcess
        .run(launch("burst", 5_000, 64))
        .await
        .unwrap();
    assert!(output.output_limited);
    assert!(!output.timed_out);
    assert!(!output.cancelled);
    assert!(output.kill_succeeded);
    assert!(output.process_tree.started);
    assert!(output.process_tree.terminated);
    assert!(output.process_tree.reaped);
    assert!(output.stdout.len() <= 64);
}

#[test]
fn fixture_child() {
    match std::env::var("LEGION_WINDOWS_FIXTURE").as_deref() {
        Ok("sleep") => std::thread::sleep(Duration::from_millis(500)),
        Ok("cooperative-sleep") => {
            CTRL_BREAK_SEEN.store(false, Ordering::Release);
            install_ctrl_handler(Some(stop_on_ctrl_break));
            while !CTRL_BREAK_SEEN.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok("non-cooperative-sleep") => {
            install_ctrl_handler(Some(consume_ctrl_break));
            std::thread::sleep(Duration::from_secs(2));
        }
        Ok("burst") => print!("{}", "x".repeat(16 * 1024)),
        Ok("leader-exits-with-descendant") => spawn_live_descendant(),
        Ok("grandchild-sleep") => std::thread::sleep(Duration::from_millis(500)),
        _ => {}
    }
}
