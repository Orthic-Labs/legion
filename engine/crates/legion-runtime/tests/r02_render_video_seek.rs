//! Integration tests for wf_port packet R02
//! (`skills/designer/engine/huashu/scripts/render-video-seek.js`).
//!
//! Exercises the public API of `legion_runtime::wf_port::r02::render_video_seek`
//! from outside the crate with fake `BrowserDriver`/`FfmpegEncoder`
//! implementations, so this file never launches a real browser or shells
//! out to `ffmpeg`.
//!
//! NOTE: same wiring caveat as `r02_narrate_pipeline.rs` — `pub mod r02;`
//! is not yet added to `src/wf_port/mod.rs` by this port.

use std::path::Path;
use std::sync::Arc;

use legion_runtime::wf_port::r02::render_video_seek::{
    parse_args, round_robin_buckets, total_frames, run, BrowserDriver, DriverError, FfmpegEncoder,
    PageHandle, SeekArgs, HIDE_CHROME_CSS,
};

struct FakeDriver;

impl BrowserDriver for FakeDriver {
    fn open_page(&self, _url: &str, _keep_chrome: bool, _ready_timeout: f64) -> Result<PageHandle, DriverError> {
        Ok(PageHandle(Arc::new(())))
    }

    fn capture_frame(
        &self,
        _page: &PageHandle,
        _t: f64,
        _settle: u64,
        _width: u32,
        _height: u32,
        out_path: &Path,
    ) -> Result<(), DriverError> {
        std::fs::write(out_path, b"png").map_err(|e| DriverError::Other(e.to_string()))
    }

    fn close_page(&self, _page: PageHandle) {}
}

struct FakeEncoder;

impl FfmpegEncoder for FakeEncoder {
    fn encode(&self, _frame_dir: &Path, _fps: f64, out_path: &Path) -> Result<(), String> {
        std::fs::write(out_path, b"mp4").map_err(|e| e.to_string())
    }
}

#[test]
fn hide_chrome_css_is_exported_and_nonempty() {
    assert!(!HIDE_CHROME_CSS.trim().is_empty());
}

#[test]
fn frame_math_matches_source() {
    assert_eq!(total_frames(60.0, 2.0), 120);
    let buckets = round_robin_buckets(6, 2);
    assert_eq!(buckets[0], vec![0, 2, 4]);
    assert_eq!(buckets[1], vec![1, 3, 5]);
}

#[test]
fn parse_args_from_process_argv_shape() {
    let argv: Vec<String> = ["node", "render-video-seek.js", "anim.html", "--fps=30", "--duration=2"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let args = parse_args(&argv).unwrap();
    assert_eq!(args.html_file, "anim.html");
    assert_eq!(args.fps, 30.0);
    assert_eq!(args.duration, 2.0);
}

#[test]
fn full_orchestration_runs_against_fakes() {
    let tmp = std::env::temp_dir().join(format!(
        "r02-seek-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let html = tmp.join("anim.html");
    std::fs::write(&html, "<html></html>").unwrap();

    let args = SeekArgs {
        html_file: html.to_string_lossy().to_string(),
        duration: 1.0,
        fps: 2.0,
        width: 320,
        height: 240,
        concurrency: 2,
        settle: 1,
        ready_timeout: 1.0,
        keep_chrome: false,
    };

    let frames_dir = tmp.join(".seek-tmp");
    let outcome = run(&args, &FakeDriver, &FakeEncoder, &frames_dir).unwrap();
    assert_eq!(outcome.total_frames, 2);
    assert_eq!(outcome.frames_captured, 2);
    assert!(outcome.mp4_path.exists());
    assert!(!frames_dir.exists());

    std::fs::remove_dir_all(&tmp).ok();
}

