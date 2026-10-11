#![cfg(windows)]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use legion_runtime::wf_port::r24::read_live_server_info;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const PIPE_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "legion-live-server-background-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("temporary project root");
    root
}

fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> Receiver<std::io::Result<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = tx.send(pipe.read_to_end(&mut bytes).map(|_| bytes));
    });
    rx
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if start.elapsed() >= timeout => return Ok(None),
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(format!("launcher try_wait failed: {error}")),
        }
    }
}

fn stop_fixture(root: &Path) -> Result<Option<ExitStatus>, String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_legion"));
    command
        .args(["script", "designer/live-server", "stop"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    let mut child = command
        .spawn()
        .map_err(|error| format!("stop spawn failed: {error}"))?;
    let status = wait_for_exit(&mut child, STOP_TIMEOUT)?;
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(status)
}

fn kill_fixture_pid(pid: u32) -> Result<Option<ExitStatus>, String> {
    let mut command = Command::new("taskkill");
    command
        .args(["/PID", &pid.to_string(), "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    let mut child = command
        .spawn()
        .map_err(|error| format!("fixture taskkill spawn failed: {error}"))?;
    let status = wait_for_exit(&mut child, STOP_TIMEOUT)?;
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(status)
}

fn record_removed(root: &Path) -> bool {
    let start = Instant::now();
    while start.elapsed() < STOP_TIMEOUT {
        if read_live_server_info(root).is_none() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

fn health(port: u16) -> Result<String, String> {
    let address = ("127.0.0.1", port)
        .to_socket_addrs()
        .map_err(|error| format!("resolve health address: {error}"))?
        .next()
        .ok_or_else(|| "missing health address".to_string())?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|error| format!("connect health: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set health timeout: {error}"))?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|error| format!("write health request: {error}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("read health response: {error}"))?;
    Ok(response)
}

#[test]
fn background_launcher_closes_pipes_before_server_stops() {
    let root = temp_root();
    let mut command = Command::new(env!("CARGO_BIN_EXE_legion"));
    command
        .args(["script", "designer/live-server", "--background"])
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    let mut launcher = command.spawn().expect("background launcher spawn");
    let stdout_rx = spawn_reader(launcher.stdout.take().expect("launcher stdout"));
    let stderr_rx = spawn_reader(launcher.stderr.take().expect("launcher stderr"));

    let mut failures = Vec::new();
    let launcher_status = match wait_for_exit(&mut launcher, LAUNCH_TIMEOUT) {
        Ok(Some(status)) => {
            if !status.success() {
                failures.push(format!("background launcher exited {status}"));
            }
            Some(status)
        }
        Ok(None) => {
            failures.push("background launcher did not exit before timeout".to_string());
            None
        }
        Err(error) => {
            failures.push(error);
            None
        }
    };
    // This freshly-created root can only contain this test's connection
    // record. Retain its PID before cleanup so a failing stop can terminate
    // only that detached fixture.
    let fixture_record = read_live_server_info(&root).map(|(record, _)| record);
    let fixture_pid = fixture_record.as_ref().map(|record| record.pid);

    let mut stdout = None;
    let mut stderr = None;
    if launcher_status.is_some_and(|status| status.success()) {
        match stdout_rx.recv_timeout(PIPE_TIMEOUT) {
            Ok(Ok(bytes)) => stdout = Some(bytes),
            Ok(Err(error)) => failures.push(format!("stdout reader failed: {error}")),
            Err(error) => failures.push(format!("stdout did not reach EOF: {error}")),
        }
        match stderr_rx.recv_timeout(PIPE_TIMEOUT) {
            Ok(Ok(bytes)) => stderr = Some(bytes),
            Ok(Err(error)) => failures.push(format!("stderr reader failed: {error}")),
            Err(error) => failures.push(format!("stderr did not reach EOF: {error}")),
        }
    }

    if let (Some(stdout), Some(_stderr)) = (&stdout, &stderr) {
        match serde_json::from_slice::<serde_json::Value>(stdout) {
            Ok(value) => match fixture_record.as_ref() {
                Some(record) => {
                    if value.get("pid").and_then(serde_json::Value::as_u64)
                        != Some(record.pid.into())
                        || value.get("port").and_then(serde_json::Value::as_u64)
                            != Some(record.port.into())
                        || value.get("token").and_then(serde_json::Value::as_str)
                            != Some(record.token.as_str())
                    {
                        failures.push(format!(
                            "background JSON does not match server record: {value} vs {record:?}"
                        ));
                    }
                    match health(record.port) {
                        Ok(response) if response.contains("200 OK") => {}
                        Ok(response) => {
                            failures.push(format!("unexpected health response: {response}"))
                        }
                        Err(error) => failures.push(error),
                    }
                }
                None => failures.push("background launcher left no server record".to_string()),
            },
            Err(error) => failures.push(format!("background stdout was not JSON: {error}")),
        }
    }

    // A timed-out launcher reproduces the old inherited-handle failure. Stop
    // its detached fixture before waiting on either reader so this test stays
    // bounded even while exercising that failure path.
    let stop_status = stop_fixture(&root);
    if launcher_status.is_none() {
        let _ = launcher.kill();
        let _ = launcher.wait();
    }
    let stop_succeeded = matches!(&stop_status, Ok(Some(status)) if status.success());
    if launcher_status.is_some_and(|status| status.success()) {
        match &stop_status {
            Ok(Some(status)) if status.success() => {}
            Ok(Some(status)) => failures.push(format!("positional stop exited {status}")),
            Ok(None) => failures.push("positional stop timed out".to_string()),
            Err(error) => failures.push(error.clone()),
        }
    }
    let record_was_removed = fixture_pid.is_some_and(|_| record_removed(&root));
    if launcher_status.is_some_and(|status| status.success()) && !record_was_removed {
        failures.push("positional stop did not remove server record".to_string());
    }
    if let Some(pid) = fixture_pid.filter(|_| !stop_succeeded || !record_was_removed) {
        match kill_fixture_pid(pid) {
            Ok(Some(status)) if status.success() => {}
            Ok(Some(status)) => failures.push(format!("fixture taskkill exited {status}")),
            Ok(None) => failures.push("fixture taskkill timed out".to_string()),
            Err(error) => failures.push(error),
        }
    }

    if stdout.is_none() {
        match stdout_rx.recv_timeout(PIPE_TIMEOUT) {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => failures.push(format!("stdout cleanup reader failed: {error}")),
            Err(error) => failures.push(format!("stdout cleanup reader timed out: {error}")),
        }
    }
    if stderr.is_none() {
        match stderr_rx.recv_timeout(PIPE_TIMEOUT) {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => failures.push(format!("stderr cleanup reader failed: {error}")),
            Err(error) => failures.push(format!("stderr cleanup reader timed out: {error}")),
        }
    }
    let _ = fs::remove_dir_all(&root);

    assert!(failures.is_empty(), "{}", failures.join("; "));
}
