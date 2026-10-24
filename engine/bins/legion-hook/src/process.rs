//! Bounded child processes for the hook. A hook has seconds, not minutes, and a
//! stuck child must never hold the host's tool call or turn end open.

use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

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
