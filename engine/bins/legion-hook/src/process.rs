//! Bounded child processes for the hook. A hook has seconds, not minutes, and a
//! stuck child must never hold the host's tool call or turn end open.

use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Win32 `CREATE_NO_WINDOW`: a console program started without a console
/// window. Without it a hook that runs from a GUI host flashes a visible
/// console for every child it starts.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Process-creation flags every bounded child is started with: no visible
/// console on Windows, none elsewhere.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const fn background_creation_flags() -> u32 {
    #[cfg(windows)]
    {
        CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Output kept per stream. More than this is cut, not buffered.
const MAX_STREAM_BYTES: u64 = 256 * 1024;

pub(crate) struct Finished {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Unfinished {
    /// The program could not be started (not installed, not executable).
    NotStarted,
    /// It ran past the limit and was killed.
    TimedOut,
}

/// Run `command` to completion within `limit`.
pub(crate) fn bounded_output(
    mut command: Command,
    limit: Duration,
) -> Result<Finished, Unfinished> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(background_creation_flags());
    let mut child = command.spawn().map_err(|_| Unfinished::NotStarted)?;
    let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Unfinished::NotStarted);
    };
    let out = thread::spawn(move || read_capped(&mut stdout));
    let err = thread::spawn(move || read_capped(&mut stderr));
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    status
        .map(|status| Finished {
            code: status.code(),
            stdout,
            stderr,
        })
        .ok_or(Unfinished::TimedOut)
}

fn read_capped(reader: &mut impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.take(MAX_STREAM_BYTES).read_to_end(&mut bytes);
    // Drain the rest so the child is never blocked writing to a full pipe.
    let _ = std::io::copy(reader, &mut std::io::sink());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_children_start_without_a_console_window_on_windows() {
        let expected = if cfg!(windows) { 0x0800_0000 } else { 0 };
        assert_eq!(background_creation_flags(), expected);
    }

    /// `Command` cannot report the flags it was given, and a Windows console
    /// window cannot be observed from a test on another host, so the contract
    /// is pinned in the source: the Windows branch of `bounded_output` sets
    /// the flags before it spawns.
    #[test]
    fn bounded_output_sets_the_creation_flags_before_it_spawns() {
        let source = include_str!("process.rs");
        let body = source
            .split("pub(crate) fn bounded_output(")
            .nth(1)
            .and_then(|rest| rest.split("fn read_capped").next())
            .expect("bounded_output is in this file");
        let call = "command.creation_flags(background_creation_flags());";
        let at = body.find(call).expect("the flags are set");
        assert!(body[..at].trim_end().ends_with("#[cfg(windows)]"));
        assert!(at < body.find("command.spawn()").expect("the child is spawned"));
    }

    fn shell(script: &str) -> Command {
        if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/C", script]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            command
        }
    }

    #[test]
    fn a_finished_child_returns_its_status_and_output() {
        let finished = bounded_output(shell("echo out && echo err 1>&2"), Duration::from_secs(10))
            .expect("the child runs");
        assert_eq!(finished.code, Some(0));
        assert!(String::from_utf8_lossy(&finished.stdout).contains("out"));
        assert!(String::from_utf8_lossy(&finished.stderr).contains("err"));
    }

    #[test]
    fn a_missing_program_is_not_started() {
        let result = bounded_output(
            Command::new("legion-hook-no-such-program"),
            Duration::from_secs(1),
        );
        assert!(matches!(result, Err(Unfinished::NotStarted)));
    }
}
