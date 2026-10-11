//! Integration tests for wf_port packet r03's verify.py port
//! (`legion_runtime::wf_port::r03::verify`). See that module's doc comment
//! for the full mapping back to the legacy script.
//!
//! This file depends on `legion_runtime::wf_port::r03`, which is not yet
//! wired into `legion-runtime`'s public module tree (see the r03 module
//! doc comment in `wf_port/r03/mod.rs` for the wiring note). Until that
//! lands, this file will not compile as part of the crate's test target.
//!
//! No test here launches a real browser: [`FakeDriver`] stands in for
//! [`BrowserDriver`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use legion_runtime::wf_port::r03::verify::{
    default_output_dir, parse_cli_args, parse_viewports, run, single_shot_filenames,
    slide_filename, verify_html, ArgsError, BrowserDriver, FileSystem, VerifyError, VerifyReport,
    Viewport,
};

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn parse_cli_args_matches_legacy_argparse_defaults() {
    let a = parse_cli_args(&args(&["design.html"])).unwrap();
    assert_eq!(a.viewports, "1440x900");
    assert_eq!(a.slides, 0);
    assert_eq!(a.wait, 2000);
    assert!(!a.show);
}

#[test]
fn parse_cli_args_requires_positional() {
    assert_eq!(parse_cli_args(&[]), Err(ArgsError::MissingHtmlPath));
}

#[test]
fn viewport_and_path_helpers() {
    let vs = parse_viewports("1920x1080,375x667").unwrap();
    assert_eq!(vs.len(), 2);
    assert_eq!(
        default_output_dir(Path::new("/a/b/x.html")),
        PathBuf::from("/a/b/screenshots")
    );
    assert_eq!(slide_filename("deck", 3), "deck-slide-03.png");
    let vp = Viewport {
        width: 1440,
        height: 900,
    };
    assert_eq!(
        single_shot_filenames("d", vp, 1),
        ("d.png".to_string(), "d-full.png".to_string())
    );
}

struct FakeFs {
    existing: Vec<PathBuf>,
    writes: RefCell<HashMap<PathBuf, Vec<u8>>>,
}
impl FileSystem for FakeFs {
    fn exists(&self, path: &Path) -> bool {
        self.existing.iter().any(|p| p == path)
    }
    fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.writes
            .borrow_mut()
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }
}

struct FakeDriver {
    console: Vec<String>,
    page_errors: Vec<String>,
}
impl BrowserDriver for FakeDriver {
    fn open(&mut self, _file_url: &str, _viewport: Viewport) -> Result<(), String> {
        Ok(())
    }
    fn wait_ms(&mut self, _ms: u64) {}
    fn screenshot(&mut self, _full_page: bool) -> Result<Vec<u8>, String> {
        Ok(vec![1, 2, 3])
    }
    fn press_arrow_right(&mut self) {}
    fn take_console_messages(&mut self) -> Vec<String> {
        std::mem::take(&mut self.console)
    }
    fn take_page_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.page_errors)
    }
    fn close(&mut self) {}
}

#[test]
fn verify_html_missing_file_returns_error() {
    let fs = FakeFs {
        existing: vec![],
        writes: RefCell::new(HashMap::new()),
    };
    let mut driver = FakeDriver {
        console: vec![],
        page_errors: vec![],
    };
    let mut stdout = Vec::new();
    let err = verify_html(
        Path::new("/no/such.html"),
        &[Viewport {
            width: 1440,
            height: 900,
        }],
        0,
        None,
        0,
        &fs,
        &mut driver,
        &mut stdout,
    )
    .unwrap_err();
    assert_eq!(err, VerifyError::FileNotFound("/no/such.html".to_string()));
}

#[test]
fn verify_html_success_exit_code_zero_and_screenshots_written() {
    let html = PathBuf::from("/x/design.html");
    let fs = FakeFs {
        existing: vec![html.clone()],
        writes: RefCell::new(HashMap::new()),
    };
    let mut driver = FakeDriver {
        console: vec![],
        page_errors: vec![],
    };
    let mut stdout = Vec::new();
    let report = verify_html(
        &html,
        &[Viewport {
            width: 1440,
            height: 900,
        }],
        0,
        None,
        0,
        &fs,
        &mut driver,
        &mut stdout,
    )
    .unwrap();
    assert_eq!(report.exit_code, 0);
    assert!(fs
        .writes
        .borrow()
        .contains_key(&report.output_dir.join("design.png")));
}

/// Driver whose `open` and/or `screenshot` fail on demand.
struct ScriptedDriver {
    open_error: Option<String>,
    screenshot_error: Option<String>,
}
impl BrowserDriver for ScriptedDriver {
    fn open(&mut self, _file_url: &str, _viewport: Viewport) -> Result<(), String> {
        match &self.open_error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
    fn wait_ms(&mut self, _ms: u64) {}
    fn screenshot(&mut self, _full_page: bool) -> Result<Vec<u8>, String> {
        match &self.screenshot_error {
            Some(e) => Err(e.clone()),
            None => Ok(vec![1, 2, 3]),
        }
    }
    fn press_arrow_right(&mut self) {}
    fn take_console_messages(&mut self) -> Vec<String> {
        Vec::new()
    }
    fn take_page_errors(&mut self) -> Vec<String> {
        Vec::new()
    }
    fn close(&mut self) {}
}

/// Filesystem where every write fails; the input file exists.
struct WriteFailFs;
impl FileSystem for WriteFailFs {
    fn exists(&self, _path: &Path) -> bool {
        true
    }
    fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn write(&self, _path: &Path, _bytes: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "read-only output",
        ))
    }
}

fn run_one_viewport(
    driver: &mut ScriptedDriver,
    fs: &dyn FileSystem,
    slides: i64,
) -> (VerifyReport, String) {
    let mut stdout = Vec::new();
    let report = verify_html(
        Path::new("/x/design.html"),
        &[Viewport {
            width: 1440,
            height: 900,
        }],
        slides,
        None,
        0,
        fs,
        driver,
        &mut stdout,
    )
    .unwrap();
    (report, String::from_utf8(stdout).unwrap())
}

#[test]
fn open_failure_is_recorded_skips_captures_and_fails_the_run() {
    let fs = FakeFs {
        existing: vec![PathBuf::from("/x/design.html")],
        writes: RefCell::new(HashMap::new()),
    };
    let mut driver = ScriptedDriver {
        open_error: Some("net::ERR_FILE_NOT_FOUND".to_string()),
        screenshot_error: None,
    };
    let (report, out) = run_one_viewport(&mut driver, &fs, 0);
    assert_eq!(report.exit_code, 1);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].step, "open");
    assert_eq!(report.failures[0].target, "1440x900");
    assert!(report.failures[0].reason.contains("ERR_FILE_NOT_FOUND"));
    assert!(!out.contains("✓"), "no success tick for a failed open");
    assert!(out.contains("Capture Failures (1)"));
    assert!(fs.writes.borrow().is_empty(), "no stale screenshot written");
}

#[test]
fn screenshot_failure_prints_no_tick_and_fails_the_run() {
    let fs = FakeFs {
        existing: vec![PathBuf::from("/x/design.html")],
        writes: RefCell::new(HashMap::new()),
    };
    let mut driver = ScriptedDriver {
        open_error: None,
        screenshot_error: Some("capture timed out".to_string()),
    };
    let (report, out) = run_one_viewport(&mut driver, &fs, 0);
    assert_eq!(report.exit_code, 1);
    let steps: Vec<&str> = report.failures.iter().map(|f| f.step).collect();
    assert_eq!(steps, vec!["screenshot", "screenshot"]);
    assert_eq!(report.failures[0].target, "1440x900");
    assert_eq!(report.failures[1].target, "1440x900 full-page");
    assert!(report.failures[0].reason.contains("capture timed out"));
    assert!(!out.contains("✓"), "no success tick for a failed capture");
    assert!(fs.writes.borrow().is_empty());
}

#[test]
fn slide_screenshot_failure_names_the_slide() {
    let fs = FakeFs {
        existing: vec![PathBuf::from("/x/design.html")],
        writes: RefCell::new(HashMap::new()),
    };
    let mut driver = ScriptedDriver {
        open_error: None,
        screenshot_error: Some("boom".to_string()),
    };
    let (report, out) = run_one_viewport(&mut driver, &fs, 2);
    assert_eq!(report.exit_code, 1);
    let targets: Vec<&str> = report.failures.iter().map(|f| f.target.as_str()).collect();
    assert_eq!(targets, vec!["1440x900 slide 1", "1440x900 slide 2"]);
    assert!(!out.contains("✓ slide"));
}

#[test]
fn write_failure_is_recorded_without_success_tick() {
    let mut driver = ScriptedDriver {
        open_error: None,
        screenshot_error: None,
    };
    let (report, out) = run_one_viewport(&mut driver, &WriteFailFs, 0);
    assert_eq!(report.exit_code, 1);
    assert_eq!(report.failures.len(), 2);
    assert!(report.failures.iter().all(|f| f.step == "write"));
    assert!(report.failures[0].reason.contains("read-only output"));
    assert!(!out.contains("✓"), "no success tick for a failed write");
}

#[test]
fn run_exit_code_is_nonzero_when_a_write_fails() {
    let mut driver = ScriptedDriver {
        open_error: None,
        screenshot_error: None,
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(
        &args(&["design.html"]),
        &WriteFailFs,
        &mut driver,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, 1);
}

#[test]
fn run_wires_cli_parsing_through_to_verify_html() {
    let html = PathBuf::from("ok.html");
    let fs = FakeFs {
        existing: vec![html],
        writes: RefCell::new(HashMap::new()),
    };
    let mut driver = FakeDriver {
        console: vec![],
        page_errors: vec!["boom".to_string()],
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(
        &args(&["ok.html"]),
        &fs,
        &mut driver,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, 1, "page errors should yield exit code 1");
}
