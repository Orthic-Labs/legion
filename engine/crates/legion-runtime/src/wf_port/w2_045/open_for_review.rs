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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeLauncher {
        calls: RefCell<Vec<PathBuf>>,
        result: Result<(), String>,
    }

    impl FakeLauncher {
        fn new(result: Result<(), String>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                result,
            }
        }
    }

    impl Launcher for FakeLauncher {
        fn open(&self, target: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push(target.to_path_buf());
            self.result.clone()
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "legion-w2_045-open-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn run(argv: &[&str], launcher: &FakeLauncher) -> (i32, String, String) {
        let args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let code = run_cli(&args, Path::new("/"), launcher, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn no_paths_is_a_usage_error_and_launches_nothing() {
        let launcher = FakeLauncher::new(Ok(()));
        let (code, _, err) = run(&[], &launcher);
        assert_eq!(code, 2);
        assert!(err.contains("usage:"));
        assert!(launcher.calls.borrow().is_empty());
    }

    #[test]
    fn print_mode_prints_the_resolved_target_without_launching() {
        let dir = temp_dir("print");
        let file = dir.join("report.md");
        std::fs::write(&file, "x").unwrap();
        let launcher = FakeLauncher::new(Ok(()));
        let arg = file.to_string_lossy().into_owned();
        let (code, out, _) = run(&["--print", arg.as_str()], &launcher);
        assert_eq!(code, 0);
        let expected = path_utils::resolve(&arg).to_string_lossy().into_owned();
        assert!(out.contains(expected.as_str()));
        assert!(launcher.calls.borrow().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn single_existing_path_is_launched_itself() {
        let dir = temp_dir("single");
        let file = dir.join("page.html");
        std::fs::write(&file, "x").unwrap();
        let launcher = FakeLauncher::new(Ok(()));
        let arg = file.to_string_lossy().into_owned();
        let (code, out, _) = run(&[arg.as_str(), "/definitely/missing.md"], &launcher);
        assert_eq!(code, 0);
        assert!(out.contains("opened:"));
        let calls = launcher.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], path_utils::resolve(&file.to_string_lossy()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn several_existing_paths_open_their_common_parent() {
        let dir = temp_dir("multi");
        let a = dir.join("a.md");
        let b = dir.join("b.md");
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "x").unwrap();
        let launcher = FakeLauncher::new(Ok(()));
        let arg_a = a.to_string_lossy().into_owned();
        let arg_b = b.to_string_lossy().into_owned();
        let (code, _, _) = run(&[arg_a.as_str(), arg_b.as_str()], &launcher);
        assert_eq!(code, 0);
        let calls = launcher.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], path_utils::resolve(&dir.to_string_lossy()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn launch_failure_is_nonzero_and_reports_the_reason() {
        let dir = temp_dir("fail");
        let file = dir.join("doc.md");
        std::fs::write(&file, "x").unwrap();
        let launcher = FakeLauncher::new(Err("opener missing".to_string()));
        let arg = file.to_string_lossy().into_owned();
        let (code, _, err) = run(&[arg.as_str()], &launcher);
        assert_eq!(code, 1);
        assert!(err.contains("could not open"));
        assert!(err.contains("opener missing"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_paths_fail_without_launching() {
        let launcher = FakeLauncher::new(Ok(()));
        let (code, _, err) = run(&["/definitely/missing/one.md"], &launcher);
        assert_eq!(code, 1);
        assert!(err.contains("none of the paths exist"));
        assert!(launcher.calls.borrow().is_empty());
    }

    #[test]
    fn windows_targets_with_cmd_metacharacters_are_refused() {
        assert!(check_windows_target("C:\\docs\\a.md").is_ok());
        assert!(check_windows_target("C:\\a&calc\\b.md").is_err());
        assert!(check_windows_target("C:\\100%\\b.md").is_err());
        assert!(check_windows_target("C:\\x\"y.md").is_err());
    }

    #[test]
    fn opener_program_matches_the_platform_switch() {
        let (program, args) = opener_command(Path::new("/tmp/x.md")).unwrap();
        if cfg!(windows) {
            assert_eq!(program, "cmd");
            assert_eq!(args.len(), 4);
        } else if cfg!(target_os = "macos") {
            assert_eq!(program, "open");
            assert_eq!(args.len(), 1);
        } else {
            assert_eq!(program, "xdg-open");
            assert_eq!(args.len(), 1);
        }
    }
}
