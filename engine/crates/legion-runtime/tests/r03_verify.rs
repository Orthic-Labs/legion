//! Integration tests for wf_port packet r03's verify.py port
//! (`legion_runtime::wf_port::r03::verify`). See that module's doc comment
//! for the full mapping back to the legacy script.
//!
//! This file depends on `legion_runtime::wf_port::r03`, which is not yet
//! wired into `legion-runtime`'s public module tree (see
//! `r03_tts_doubao.rs`'s header for the exact wiring step). Until that
//! lands, this file will not compile as part of the crate's test target.
//!
//! No test here launches a real browser: [`FakeDriver`] stands in for
//! [`BrowserDriver`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use legion_runtime::wf_port::r03::verify::{
    default_output_dir, parse_cli_args, parse_viewports, run, single_shot_filenames,
    slide_filename, verify_html, ArgsError, BrowserDriver, FileSystem, VerifyError, Viewport,
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
    assert_eq!(default_output_dir(Path::new("/a/b/x.html")), PathBuf::from("/a/b/screenshots"));
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
        self.writes.borrow_mut().insert(path.to_path_buf(), bytes.to_vec());
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
    assert!(fs.writes.borrow().contains_key(&report.output_dir.join("design.png")));
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
    let code = run(&args(&["ok.html"]), &fs, &mut driver, &mut stdout, &mut stderr);
    assert_eq!(code, 1, "page errors should yield exit code 1");
}
