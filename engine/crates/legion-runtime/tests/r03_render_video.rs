//! Integration tests for wf_port packet r03's render-video.js port
//! (`legion_runtime::wf_port::r03::render_video`). See that module's doc
//! comment for the full mapping back to the legacy script and the one
//! documented mechanism difference (frame-sequence capture vs. Playwright's
//! continuous WebM recording).
//!
//! This file depends on `legion_runtime::wf_port::r03`, which is not yet
//! wired into `legion-runtime`'s public module tree (see the r00/r03
//! module doc comments and `r03_tts_doubao.rs`'s header for the exact
//! wiring step). Until that lands, this file will not compile as part of
//! the crate's test target.
//!
//! No test here launches a real browser or spawns `ffmpeg`: [`FakeRecorder`]
//! and [`FakeFfmpeg`] stand in for [`Recorder`]/[`FfmpegRunner`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use legion_runtime::wf_port::r03::render_video::{
    arg, derive_paths, frame_filename, has_flag, hide_chrome_js, parse_args, resolve_trim, run,
    FfmpegRunner, FileSystem, ParseArgsError, RecordCapture, Recorder, HIDE_CHROME_CSS,
};

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn arg_and_has_flag_match_legacy_helpers() {
    let argv = args(&["file.html", "--width=800", "--keep-chrome"]);
    assert_eq!(arg(&argv, "width", Some("1920")), Some("800"));
    assert_eq!(arg(&argv, "height", Some("1080")), Some("1080"));
    assert!(has_flag(&argv, "keep-chrome"));
    assert!(!has_flag(&argv, "trim"));
}

#[test]
fn parse_args_usage_error_without_positional() {
    assert_eq!(parse_args(&[]), Err(ParseArgsError::MissingHtmlFile));
}

#[test]
fn parse_args_and_derive_paths() {
    let a = parse_args(&args(&["sub/anim.html", "--duration=5", "--width=640", "--height=360"])).unwrap();
    assert_eq!(a.duration, 5.0);
    let paths = derive_paths(&a.html_file, Path::new("/root"));
    assert_eq!(paths.mp4_out, PathBuf::from("/root/sub/anim.mp4"));
}

#[test]
fn hide_chrome_css_and_js_are_consistent() {
    assert!(HIDE_CHROME_CSS.contains(".no-record,"));
    let js = hide_chrome_js();
    assert!(js.contains(".no-record,"));
    assert!(js.contains("MutationObserver"));
}

#[test]
fn resolve_trim_matches_legacy_decision() {
    assert_eq!(resolve_trim(Some(1.0), 9.0, true), 1.0);
    assert!((resolve_trim(None, 1.8, true) - 1.85).abs() < 1e-9);
    assert!((resolve_trim(None, 1.5, false) - 2.0).abs() < 1e-9);
}

#[test]
fn frame_filename_is_zero_padded() {
    assert_eq!(frame_filename(0), "frame000000.png");
}

struct FakeRecorder {
    has_ready: bool,
    frames: usize,
}
impl Recorder for FakeRecorder {
    fn warmup(&mut self, _url: &str, _w: u32, _h: u32, _fw: f64) -> Result<(), String> {
        Ok(())
    }
    fn record(
        &mut self,
        _url: &str,
        _w: u32,
        _h: u32,
        _hide: bool,
        _rt: f64,
        _dur: f64,
        _fps: u32,
    ) -> Result<RecordCapture, String> {
        Ok(RecordCapture {
            has_ready: self.has_ready,
            animation_start_sec_millis: 900,
            frames: (0..self.frames).map(|i| vec![i as u8]).collect(),
        })
    }
}

struct FakeFfmpeg;
impl FfmpegRunner for FakeFfmpeg {
    fn encode_png_sequence(&self, _dir: &Path, _fps: u32, _out: &Path) -> Result<(), String> {
        Ok(())
    }
}

struct FakeFs {
    writes: RefCell<HashMap<PathBuf, Vec<u8>>>,
    sizes: HashMap<PathBuf, u64>,
}
impl FileSystem for FakeFs {
    fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.writes.borrow_mut().insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }
    fn remove_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn file_len(&self, path: &Path) -> std::io::Result<u64> {
        self.sizes
            .get(path)
            .copied()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
    }
}

#[test]
fn run_produces_mp4_from_captured_frames() {
    let mut recorder = FakeRecorder {
        has_ready: true,
        frames: 4,
    };
    let ffmpeg = FakeFfmpeg;
    let mut sizes = HashMap::new();
    sizes.insert(PathBuf::from("/root/anim.mp4"), 3 * 1024 * 1024);
    let fs = FakeFs {
        writes: RefCell::new(HashMap::new()),
        sizes,
    };
    let mut stdout = Vec::new();
    let out = run(
        &args(&["anim.html"]),
        Path::new("/root"),
        "abc123",
        &mut recorder,
        &ffmpeg,
        &fs,
        &mut stdout,
    )
    .unwrap();
    assert_eq!(out, PathBuf::from("/root/anim.mp4"));
    assert_eq!(fs.writes.borrow().len(), 4);
    assert!(String::from_utf8(stdout).unwrap().contains("✓ Done:"));
}
