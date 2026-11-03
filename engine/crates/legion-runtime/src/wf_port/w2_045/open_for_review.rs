//! Entry point for `legion script designer/open-for-review`.
//!
//! Port of `skills/designer/scripts/open-for-review.mjs`, whose implementation
//! is the historical `src/lib/open-for-review.mjs` (recovered from Legion history
//! at `ebb349ae^`). The decision logic (filter to existing paths, one path opens
//! itself, several open their common parent) is the existing
//! `crate::p7_host::open_for_review::open_for_review`, reused unchanged. This
//! module adds the missing argv entry point, the launch behind a trait, and the
//! `--print` dry run.
//!
//! Usage: `legion script designer/open-for-review [--print] <path> [<path> ...]`.
//! Relative paths resolve against the current directory before launch.
//! Exit codes: 0 opened (or printed under `--print`), 1 no path exists or the
//! launch failed (with the reason on stderr), 2 no paths given.
//!
//! Launch commands match the script's platform switch: `open` on macOS,
//! `xdg-open` elsewhere, and `cmd /C start "" <path>` on Windows. Every launch
//! is an argv `Command`, never a shell string. On Windows, paths containing
//! characters that cmd.exe would interpret are refused rather than passed on.
//!
//! Deviations from the script: the script exited 0 even when nothing opened;
//! this port exits 1. The script had no `--print`; this port adds it.

use super::path_utils;
use crate::p7_host::open_for_review::{open_for_review, OpenForReviewOutcome};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const USAGE: &str = "usage: legion script designer/open-for-review [--print] <path> [<path> ...]\n  --print  print the resolved target without launching the OS viewer\nexit: 0 opened or printed, 1 no path exists or launch failed, 2 no paths given";

/// Launches the OS viewer for one resolved target.
pub trait Launcher {
    fn open(&self, target: &Path) -> Result<(), String>;
}

/// Real launcher: argv-based spawn, waits for the opener to exit, and reports a
/// non-zero status or a spawn failure as the reason.
pub struct OsLauncher;

impl Launcher for OsLauncher {
    fn open(&self, target: &Path) -> Result<(), String> {
        let (program, args) = opener_command(target)?;
        let status = Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("failed to start {}: {}", program, e))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{} exited with {}", program, status))
        }
    }
}

/// Platform opener and its argv for `target`.
pub fn opener_command(target: &Path) -> Result<(&'static str, Vec<OsString>), String> {
    let target_arg = target.as_os_str().to_os_string();
    if cfg!(windows) {
        check_windows_target(&target.to_string_lossy())?;
        Ok((
            "cmd",
            vec![
                OsString::from("/C"),
                OsString::from("start"),
                OsString::from(""),
                target_arg,
            ],
        ))
    } else if cfg!(target_os = "macos") {
        Ok(("open", vec![target_arg]))
    } else {
        Ok(("xdg-open", vec![target_arg]))
    }
}

/// cmd.exe interprets these characters even inside `start` arguments, so a
/// path containing one cannot be passed through it safely.
pub fn check_windows_target(target: &str) -> Result<(), String> {
    match target
        .chars()
        .find(|c| matches!(*c, '&' | '|' | '<' | '>' | '^' | '%' | '"'))
    {
        Some(bad) => Err(format!(
            "refusing to launch a path containing '{}' through cmd.exe",
            bad
        )),
        None => Ok(()),
    }
}

fn absolutize(raw: &str, cwd: &Path) -> PathBuf {
    path_utils::resolve(&cwd.join(raw).to_string_lossy())
}

/// Process entry for `designer/open-for-review`. Returns the exit code.
pub fn run_cli(
    argv: &[String],
    cwd: &Path,
    launcher: &dyn Launcher,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let mut print_only = false;
    let mut raw_paths: Vec<String> = Vec::new();
    for arg in argv {
        match arg.as_str() {
            "--help" | "-h" => {
                let _ = writeln!(out, "{}", USAGE);
                return 0;
            }
            "--print" => print_only = true,
            other => raw_paths.push(other.to_string()),
        }
    }
    if raw_paths.is_empty() {
        let _ = writeln!(err, "{}", USAGE);
        return 2;
    }

    let candidates: Vec<PathBuf> = raw_paths.iter().map(|p| absolutize(p, cwd)).collect();
    let exists = |p: &Path| p.exists();
    let mut failure: Option<String> = None;
    let outcome: OpenForReviewOutcome = {
        let mut launch = |target: &Path| -> bool {
            if print_only {
                return true;
            }
            match launcher.open(target) {
                Ok(()) => true,
                Err(reason) => {
                    failure = Some(reason);
                    false
                }
            }
        };
        open_for_review(&candidates, &exists, &mut launch)
    };

    let ok = outcome.ok;
    match outcome.opened {
        Some(target) if ok => {
            if print_only {
                let _ = writeln!(out, "{}", target.display());
            } else {
                let _ = writeln!(out, "[open-for-review] opened: {}", target.display());
            }
            0
        }
        Some(target) => {
            let reason = failure.unwrap_or_else(|| "launch failed".to_string());
            let _ = writeln!(
                err,
                "[open-for-review] could not open: {}: {}",
                target.display(),
                reason
            );
            1
        }
        None => {
            let _ = writeln!(
                err,
                "[open-for-review] none of the paths exist: {}",
                raw_paths.join(", ")
            );
            1
        }
    }
}
