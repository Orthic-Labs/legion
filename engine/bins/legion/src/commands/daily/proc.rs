//! Child processes for `legion daily` (`gh`, `git`, `ssh`, `scp`, `df`). Every
//! child is started with no stdin and, on Windows, no visible console. Output
//! is captured; a spawn failure is an `Err`, a nonzero exit is `ok == false`.
use std::process::{Command, Stdio};

pub struct Ran {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// A command with the daily job's process defaults applied.
pub fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: background automation never opens a console.
        command.creation_flags(0x0800_0000);
    }
    command
}

/// Run to completion and capture stdout and stderr as lossy UTF-8.
pub fn run(mut command: Command) -> Result<Ran, String> {
    let output = command.output().map_err(|error| error.to_string())?;
    Ok(Ran {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// The `Err` text for a failed run: stderr, else stdout, clipped.
pub fn failure_text(ran: &Ran) -> String {
    let source = if ran.stderr.trim().is_empty() {
        &ran.stdout
    } else {
        &ran.stderr
    };
    super::text::clip(source, 300)
}
