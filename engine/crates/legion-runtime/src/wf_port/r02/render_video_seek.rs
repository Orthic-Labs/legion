//! Full port of `render-video-seek.js`.
//!
//! Mirrors:
//! - `arg()`/`hasFlag()` CLI parsing (`--name=value`, `--flag`) and the
//!   positional `<html-file>` argument, including the "missing or starts
//!   with `--`" usage-error path.
//! - The `DURATION`/`FPS`/`WIDTH`/`HEIGHT`/`CONCURRENCY`/`SETTLE`/
//!   `READY_TIMEOUT`/`KEEP_CHROME` defaults and derived paths
//!   (`TMP_DIR`/`MP4_OUT`).
//! - `HIDE_CHROME_CSS`, byte-for-byte.
//! - `TOTAL_FRAMES = Math.round(FPS * DURATION)` and the round-robin
//!   frame-to-worker bucketing.
//! - The per-frame capture loop (`renderFrames`): seek to `f / FPS`, wait
//!   `SETTLE` rAFs, screenshot to `frame-NNNNNN.png`.
//! - The `window.__seek`/`window.__ready` readiness gate and its
//!   `/__seek|__ready/` error-message special-case.
//! - The final `ffmpeg` PNG-sequence → H.264 MP4 encode, its exact argument
//!   list, and the `pngCount === 0` / non-zero ffmpeg exit failure paths.
//!
//! Playwright + a live Chromium tab is replaced by the [`BrowserDriver`]
//! trait's real implementation, [`HeadlessChromeDriver`], built on the
//! `headless_chrome` crate (Playwright is not available for Rust; no
//! Playwright-equivalent crate was already a dependency, and
//! `headless_chrome` is the crate this port was authorized to add for this
//! purpose). Screenshot capture, `window.__seek(t)` evaluation, and the
//! `requestAnimationFrame`-settle wait are all expressed as trait methods so
//! the frame-bucketing/orchestration logic is fully unit-tested against a
//! fake driver, with no real browser launched and no network touched by the
//! test suite. `ffmpeg` (PNG-sequence encode) is likewise behind
//! [`FfmpegEncoder`].

use std::path::{Path, PathBuf};
use std::process::Command;

/// Chrome-hiding CSS injected into the page before capture, verbatim from
/// `render-video-seek.js` (kept byte-identical so both render paths produce
/// the same visual output, per the source's own comment).
pub const HIDE_CHROME_CSS: &str = r#"
  .no-record,
  .progress, .progress-bar,
  .counter, .tCur,
  .phases, .phase-label, .phase,
  .replay, button.replay,
  .masthead, .kicker, .title,
  .footer,
  [data-role="chrome"], [data-record="hidden"] {
    display: none !important;
  }
"#;

// ---------------------------------------------------------------------------
// CLI args — mirrors arg()/hasFlag()/the constant block
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct SeekArgs {
    pub html_file: String,
    pub duration: f64,
    pub fps: f64,
    pub width: u32,
    pub height: u32,
    pub concurrency: u64,
    pub settle: u64,
    pub ready_timeout: f64,
    pub keep_chrome: bool,
}

/// Mirrors `arg(name, def)`: finds a `--name=value` entry anywhere in
/// `argv[1..]` (JS scans full `process.argv`, which includes the node
/// binary and script path — neither can start with `--name=`, so scanning
/// from index 0 vs. 2 is behaviorally identical; this scans the whole
/// slice for parity with the source).
fn arg<'a>(argv: &'a [String], name: &str, def: &'a str) -> String {
    let prefix = format!("--{name}=");
    argv.iter()
        .find(|a| a.starts_with(&prefix))
        .map(|a| a[prefix.len()..].to_string())
        .unwrap_or_else(|| def.to_string())
}

fn has_flag(argv: &[String], name: &str) -> bool {
    let flag = format!("--{name}");
    argv.iter().any(|a| a == &flag)
}

/// Result of parsing argv. `Err(())` mirrors the usage-error path (`html`
/// missing, or `argv[2]` starts with `--`): the caller prints the usage
/// message and exits 1.
pub fn parse_args(argv: &[String]) -> Result<SeekArgs, ()> {
    // Mirrors `const HTML_FILE = process.argv[2];`
    let html_file = argv.get(2).cloned();
    let Some(html_file) = html_file else {
        return Err(());
    };
    if html_file.starts_with("--") {
        return Err(());
    }

    let duration = js_parse_float(&arg(argv, "duration", "30")).unwrap_or(f64::NAN);
    let fps = js_parse_float(&arg(argv, "fps", "60")).unwrap_or(f64::NAN);
    let width = js_parse_int(&arg(argv, "width", "1920")).unwrap_or(0) as u32;
    let height = js_parse_int(&arg(argv, "height", "1080")).unwrap_or(0) as u32;
    let concurrency = js_parse_int(&arg(argv, "concurrency", "4"))
        .unwrap_or(0)
        .max(1) as u64;
    let settle = js_parse_int(&arg(argv, "settle", "2")).unwrap_or(0).max(1) as u64;
    let ready_timeout = js_parse_float(&arg(argv, "readytimeout", "8")).unwrap_or(f64::NAN);
    let keep_chrome = has_flag(argv, "keep-chrome");

    Ok(SeekArgs {
        html_file,
        duration,
        fps,
        width,
        height,
        concurrency,
        settle,
        ready_timeout,
        keep_chrome,
    })
}

pub fn usage_text() -> String {
    "Usage: node render-video-seek.js <html-file>\nExample: NODE_PATH=$(npm root -g) node render-video-seek.js my-animation.html --fps=60".to_string()
}

fn js_parse_float(s: &str) -> Option<f64> {
    let re = regex::Regex::new(r"^\s*[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?").unwrap();
    let m = re.find(s)?;
    m.as_str().trim().parse::<f64>().ok()
}

fn js_parse_int(s: &str) -> Option<i64> {
    let re = regex::Regex::new(r"^\s*[+-]?\d+").unwrap();
    let m = re.find(s)?;
    m.as_str().trim().parse::<i64>().ok()
}

/// Mirrors `path.basename(HTML_FILE, path.extname(HTML_FILE))`, `DIR`,
/// `MP4_OUT`.
pub fn derive_paths(html_abs: &Path) -> (String, PathBuf, PathBuf) {
    let dir = html_abs.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
    let basename = html_abs
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mp4_out = dir.join(format!("{basename}.mp4"));
    (basename, dir, mp4_out)
}

// ---------------------------------------------------------------------------
// TOTAL_FRAMES / round-robin bucketing
// ---------------------------------------------------------------------------

/// `Math.round(FPS * DURATION)`, round-half-away-from-zero as `Math.round`
/// does for the positive finite inputs this script accepts.
pub fn total_frames(fps: f64, duration: f64) -> u64 {
    (fps * duration).round() as u64
}

/// Mirrors:
/// ```js
/// const buckets = Array.from({ length: CONCURRENCY }, () => []);
/// for (let f = 0; f < TOTAL_FRAMES; f++) buckets[f % CONCURRENCY].push(f);
/// ```
pub fn round_robin_buckets(total_frames: u64, concurrency: u64) -> Vec<Vec<u64>> {
    let concurrency = concurrency.max(1);
    let mut buckets: Vec<Vec<u64>> = (0..concurrency).map(|_| Vec::new()).collect();
    for f in 0..total_frames {
        buckets[(f % concurrency) as usize].push(f);
    }
    buckets
}

// ---------------------------------------------------------------------------
// Browser + ffmpeg boundary
// ---------------------------------------------------------------------------

/// Errors surfaced by [`BrowserDriver`]. `SeekNotReady` mirrors the
/// `/__seek|__ready/` message-pattern special case in the JS `catch` block.
#[derive(Debug, Clone, PartialEq)]
pub enum DriverError {
    SeekNotReady(String),
    Other(String),
}

/// Abstracts everything `render-video-seek.js` does through Playwright:
/// launching Chromium, opening a page per worker, waiting for the page's
/// `window.__ready`/`window.__seek` readiness gate, seeking + waiting rAFs,
/// and screenshotting a frame. One real browser (`HeadlessChromeDriver`)
/// backs all workers; `open_page` mirrors `context.newPage()` +
/// `page.goto()` + the `waitForFunction` gate.
pub trait BrowserDriver {
    /// Opens a fresh page/tab at `url`, applies the init scripts
    /// (`__recording`/`__seekRender`, and chrome-hiding CSS unless
    /// `keep_chrome`), and waits for `window.__ready === true &&
    /// typeof window.__seek === 'function'` up to `ready_timeout` seconds.
    fn open_page(&self, url: &str, keep_chrome: bool, ready_timeout: f64) -> Result<PageHandle, DriverError>;

    /// Seeks the page to time `t` seconds, waits `settle` rAFs, then
    /// screenshots the `width`x`height` viewport to `out_path` as PNG.
    fn capture_frame(
        &self,
        page: &PageHandle,
        t: f64,
        settle: u64,
        width: u32,
        height: u32,
        out_path: &Path,
    ) -> Result<(), DriverError>;

    fn close_page(&self, page: PageHandle);
}

/// Opaque handle identifying an open page/tab to a [`BrowserDriver`]. Wraps
/// whatever the concrete driver needs to address the page again (e.g. the
/// real driver's `Arc<headless_chrome::Tab>`; a fake driver's own marker
/// type), so [`BrowserDriver`] stays a plain object-safe trait without
/// forcing every implementation to share one concrete page representation.
pub struct PageHandle(pub std::sync::Arc<dyn std::any::Any + Send + Sync>);

pub trait FfmpegEncoder {
    /// Mirrors the final `ffmpeg -framerate FPS -i frame-%06d.png -c:v
    /// libx264 -pix_fmt yuv420p -crf 18 -preset medium -r FPS -movflags
    /// +faststart MP4_OUT` call. Returns `Err(stderr tail)` on non-zero
    /// exit.
    fn encode(&self, frame_dir: &Path, fps: f64, out_path: &Path) -> Result<(), String>;
}

/// Real [`BrowserDriver`] backed by the `headless_chrome` crate.
pub struct HeadlessChromeDriver {
    browser: headless_chrome::Browser,
}

impl HeadlessChromeDriver {
    pub fn launch() -> Result<Self, String> {
        let options = headless_chrome::LaunchOptionsBuilder::default()
            .build()
            .map_err(|e| e.to_string())?;
        let browser = headless_chrome::Browser::new(options).map_err(|e| e.to_string())?;
        Ok(Self { browser })
    }
}

impl BrowserDriver for HeadlessChromeDriver {
    fn open_page(&self, url: &str, keep_chrome: bool, ready_timeout: f64) -> Result<PageHandle, DriverError> {
        let tab = self
            .browser
            .new_tab()
            .map_err(|e| DriverError::Other(e.to_string()))?;

        // Mirrors `context.addInitScript(() => { window.__recording = true;
        // window.__seekRender = true; })`, plus the chrome-hiding init
        // script when `!KEEP_CHROME`, both applied before navigation via
        // `Page.addScriptToEvaluateOnNewDocument`.
        let mut init_script = String::from(
            "window.__recording = true; window.__seekRender = true;",
        );
        if !keep_chrome {
            init_script.push_str(&format!(
                "(function(css){{\n  const HIDE_MARK='data-video-hidden';\n  function injectStyle(){{ const style=document.createElement('style'); style.setAttribute('data-inject','render-video-chrome-hide'); style.textContent=css; (document.head||document.documentElement).appendChild(style); }}\n  function hideChromeBars(){{ const vh=window.innerHeight; document.querySelectorAll('div, nav, header, footer, section, aside').forEach(el => {{ if (el.hasAttribute(HIDE_MARK)) return; if (el.dataset.recordKeep === 'true') return; const s=getComputedStyle(el); if (s.position !== 'fixed' && s.position !== 'sticky') return; const r=el.getBoundingClientRect(); if (r.height > vh * 0.25) return; const atBottom = r.bottom >= vh - 30; const atTop = r.top <= 30 && r.height < 80; if (!atBottom && !atTop) return; const txt = el.textContent || ''; const hasBtn = !!el.querySelector('button, [role=\"button\"]'); const hasCtrls = /[\\u23f8\\u25b6\\u23ee\\u23ed\\u21bb\\u21ba\\u21a9\\u21aa]|\\d+\\.\\d+\\s*s/.test(txt); if (hasBtn || hasCtrls) {{ el.style.setProperty('display','none','important'); el.setAttribute(HIDE_MARK,'1'); }} }}); }}\n  const start=()=>{{ injectStyle(); hideChromeBars(); const obs=new MutationObserver(hideChromeBars); obs.observe(document.body, {{ childList: true, subtree: true }}); setTimeout(()=>obs.disconnect(), 6000); }};\n  if (document.readyState === 'loading') {{ document.addEventListener('DOMContentLoaded', start, {{ once: true }}); }} else {{ start(); }}\n}})({css:?});",
                css = HIDE_CHROME_CSS
            ));
        }
        tab.call_method(headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument {
            source: init_script,
            world_name: None,
            include_command_line_api: None,
            run_immediately: None,
        })
        .map_err(|e| DriverError::Other(e.to_string()))?;

        tab.navigate_to(url).map_err(|e| DriverError::Other(e.to_string()))?;
        tab.wait_until_navigated()
            .map_err(|e| DriverError::Other(e.to_string()))?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(ready_timeout.max(0.0));
        loop {
            let ready = tab
                .evaluate(
                    "window.__ready === true && typeof window.__seek === 'function'",
                    false,
                )
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if ready {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(DriverError::SeekNotReady(
                    "timed out waiting for window.__ready/window.__seek".to_string(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        Ok(PageHandle(tab))
    }

    fn capture_frame(
        &self,
        page: &PageHandle,
        t: f64,
        settle: u64,
        width: u32,
        height: u32,
        out_path: &Path,
    ) -> Result<(), DriverError> {
        let tab = page
            .0
            .downcast_ref::<headless_chrome::Tab>()
            .ok_or_else(|| DriverError::Other("PageHandle did not hold a headless_chrome Tab".to_string()))?;

        // Mirrors `await page.evaluate((tt) => window.__seek(tt), t)`.
        tab.evaluate(&format!("window.__seek({t})"), false)
            .map_err(|e| DriverError::Other(e.to_string()))?;

        // Mirrors `waitRaf(page, SETTLE)`: wait `settle` requestAnimationFrame
        // callbacks before screenshotting, so React/Babel commits and layout
        // have settled.
        let raf_wait_js = format!(
            "new Promise(resolve => {{ let i = 0; const step = () => {{ i++; (i >= {settle}) ? resolve() : requestAnimationFrame(step); }}; requestAnimationFrame(step); }})"
        );
        tab.evaluate(&raf_wait_js, true)
            .map_err(|e| DriverError::Other(e.to_string()))?;

        let clip = headless_chrome::protocol::cdp::Page::Viewport {
            x: 0.0,
            y: 0.0,
            width: width as f64,
            height: height as f64,
            scale: 1.0,
        };
        let png = tab
            .capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                None,
                Some(clip),
                true,
            )
            .map_err(|e| DriverError::Other(e.to_string()))?;
        std::fs::write(out_path, png).map_err(|e| DriverError::Other(e.to_string()))?;
        Ok(())
    }

    fn close_page(&self, page: PageHandle) {
        if let Some(tab) = page.0.downcast_ref::<headless_chrome::Tab>() {
            let _ = tab.close(false);
        }
    }
}

/// Real [`FfmpegEncoder`]: shells out to `ffmpeg` with the exact argument
/// list `render-video-seek.js` uses.
pub struct RealFfmpegEncoder;

impl FfmpegEncoder for RealFfmpegEncoder {
    fn encode(&self, frame_dir: &Path, fps: f64, out_path: &Path) -> Result<(), String> {
        let pattern = frame_dir.join("frame-%06d.png");
        let output = Command::new("ffmpeg")
            .args(["-y", "-framerate", &fps.to_string(), "-i"])
            .arg(&pattern)
            .args(["-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "18", "-preset", "medium", "-r"])
            .arg(fps.to_string())
            .arg("-movflags")
            .arg("+faststart")
            .arg(out_path)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: String = stderr.chars().rev().take(2000).collect::<Vec<_>>().into_iter().rev().collect();
            return Err(tail);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Orchestration — mirrors the top-level async IIFE in render-video-seek.js
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SeekError {
    Usage,
    SeekNotReady(String),
    NoFramesCaptured,
    FfmpegFailed(String),
    Other(String),
}

pub struct SeekOutcome {
    pub mp4_path: PathBuf,
    pub frames_captured: usize,
    pub total_frames: u64,
    pub log_lines: Vec<String>,
}

/// Mirrors the whole async IIFE: makes `TMP_DIR`, launches the browser,
/// captures every bucket's frames in order (the JS runs buckets
/// concurrently across workers; capture *order within a bucket* and the
/// resulting frame set are what matter for output determinism, so this
/// drives buckets sequentially — same frames, same filenames, same final
/// PNG set, without requiring the driver trait to model concurrency),
/// encodes with ffmpeg, and cleans up `TMP_DIR`.
pub fn run(
    args: &SeekArgs,
    driver: &dyn BrowserDriver,
    encoder: &dyn FfmpegEncoder,
    tmp_dir: &Path,
) -> Result<SeekOutcome, SeekError> {
    let html_abs = PathBuf::from(&args.html_file);
    let (_basename, _dir, mp4_out) = derive_paths(&html_abs);
    let url = format!("file://{}", html_abs.display());

    let frames = total_frames(args.fps, args.duration);
    let buckets = round_robin_buckets(frames, args.concurrency);

    let mut log_lines = vec![
        format!("▸ Seek-rendering: {}", args.html_file),
        format!(
            "  size: {}x{} · {}fps · duration: {}s · frames: {} · workers: {}",
            args.width, args.height, args.fps, args.duration, frames, args.concurrency
        ),
        format!("  output: {}", mp4_out.display()),
    ];

    std::fs::create_dir_all(tmp_dir).map_err(|e| SeekError::Other(e.to_string()))?;

    let page = match driver.open_page(&url, args.keep_chrome, args.ready_timeout) {
        Ok(p) => p,
        Err(DriverError::SeekNotReady(msg)) => {
            std::fs::remove_dir_all(tmp_dir).ok();
            return Err(SeekError::SeekNotReady(msg));
        }
        Err(DriverError::Other(msg)) => {
            std::fs::remove_dir_all(tmp_dir).ok();
            return Err(SeekError::Other(msg));
        }
    };

    log_lines.push(format!(
        "▸ Capturing {} frames across {} workers…",
        frames, args.concurrency
    ));

    for bucket in &buckets {
        for &f in bucket {
            let t = f as f64 / args.fps;
            let out_path = tmp_dir.join(format!("frame-{f:06}.png"));
            if let Err(e) = driver.capture_frame(&page, t, args.settle, args.width, args.height, &out_path) {
                driver.close_page(page);
                std::fs::remove_dir_all(tmp_dir).ok();
                return match e {
                    DriverError::SeekNotReady(msg) => Err(SeekError::SeekNotReady(msg)),
                    DriverError::Other(msg) => Err(SeekError::Other(msg)),
                };
            }
        }
    }
    driver.close_page(page);

    let png_count = std::fs::read_dir(tmp_dir)
        .map_err(|e| SeekError::Other(e.to_string()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "png").unwrap_or(false))
        .count();
    if png_count == 0 {
        std::fs::remove_dir_all(tmp_dir).ok();
        return Err(SeekError::NoFramesCaptured);
    }
    log_lines.push(format!("▸ Captured {png_count}/{frames} frames. Encoding H.264…"));

    if let Err(e) = encoder.encode(tmp_dir, args.fps, &mp4_out) {
        std::fs::remove_dir_all(tmp_dir).ok();
        return Err(SeekError::FfmpegFailed(e));
    }

    std::fs::remove_dir_all(tmp_dir).ok();

    let mp4_size_mb = std::fs::metadata(&mp4_out)
        .map(|m| m.len() as f64 / 1024.0 / 1024.0)
        .unwrap_or(0.0);
    log_lines.push(format!(
        "✓ Done: {} ({:.1} MB · {}fps native)",
        mp4_out.display(),
        mp4_size_mb,
        args.fps
    ));

    Ok(SeekOutcome {
        mp4_path: mp4_out,
        frames_captured: png_count,
        total_frames: frames,
        log_lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn hide_chrome_css_matches_source() {
        assert!(HIDE_CHROME_CSS.contains(".no-record"));
        assert!(HIDE_CHROME_CSS.contains("[data-role=\"chrome\"], [data-record=\"hidden\"]"));
    }

    #[test]
    fn total_frames_rounds_like_js() {
        assert_eq!(total_frames(60.0, 30.0), 1800);
        assert_eq!(total_frames(25.0, 1.234), 31);
        assert_eq!(total_frames(60.0, 0.0), 0);
    }

    #[test]
    fn buckets_are_round_robin_and_cover_all_frames() {
        let buckets = round_robin_buckets(10, 3);
        assert_eq!(buckets, vec![vec![0, 3, 6, 9], vec![1, 4, 7], vec![2, 5, 8]]);
        assert_eq!(buckets.iter().map(|b| b.len()).sum::<usize>(), 10);
    }

    #[test]
    fn concurrency_clamped_to_at_least_one() {
        let buckets = round_robin_buckets(5, 0);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0], vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn parse_args_reads_flags_and_defaults() {
        let argv = vec![
            "node".into(),
            "render-video-seek.js".into(),
            "demo.html".into(),
            "--fps=30".into(),
            "--duration=5".into(),
            "--keep-chrome".into(),
        ];
        let args = parse_args(&argv).unwrap();
        assert_eq!(args.html_file, "demo.html");
        assert_eq!(args.fps, 30.0);
        assert_eq!(args.duration, 5.0);
        assert_eq!(args.width, 1920);
        assert_eq!(args.height, 1080);
        assert_eq!(args.concurrency, 4);
        assert!(args.keep_chrome);
    }

    #[test]
    fn parse_args_missing_html_file_is_usage_error() {
        assert_eq!(parse_args(&["node".into(), "s.js".into()]), Err(()));
    }

    #[test]
    fn parse_args_flag_like_first_arg_is_usage_error() {
        assert_eq!(
            parse_args(&["node".into(), "s.js".into(), "--fps=30".into()]),
            Err(())
        );
    }

    // -- fakes for full orchestration --

    struct FakeDriver {
        ready_result: Result<(), DriverError>,
        frames_written: Mutex<Vec<PathBuf>>,
    }

    impl BrowserDriver for FakeDriver {
        fn open_page(&self, _url: &str, _keep_chrome: bool, _ready_timeout: f64) -> Result<PageHandle, DriverError> {
            self.ready_result
                .clone()
                .map(|_| PageHandle(std::sync::Arc::new("fake".to_string())))
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
            std::fs::write(out_path, b"fake-png").map_err(|e| DriverError::Other(e.to_string()))?;
            self.frames_written.lock().unwrap().push(out_path.to_path_buf());
            Ok(())
        }

        fn close_page(&self, _page: PageHandle) {}
    }

    struct FakeEncoder {
        should_fail: bool,
    }

    impl FfmpegEncoder for FakeEncoder {
        fn encode(&self, _frame_dir: &Path, _fps: f64, out_path: &Path) -> Result<(), String> {
            if self.should_fail {
                return Err("boom".to_string());
            }
            std::fs::write(out_path, b"fake-mp4").map_err(|e| e.to_string())
        }
    }

    fn tmp_dir_for(name: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::env::temp_dir().join(format!("r02-seek-{name}-{}-{}", std::process::id(), id))
    }

    #[test]
    fn run_captures_frames_and_encodes() {
        let dir = tmp_dir_for("ok");
        let html = dir.join("demo.html");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&html, "<html></html>").unwrap();

        let args = SeekArgs {
            html_file: html.to_string_lossy().to_string(),
            duration: 1.0,
            fps: 4.0,
            width: 100,
            height: 100,
            concurrency: 2,
            settle: 1,
            ready_timeout: 1.0,
            keep_chrome: false,
        };
        let driver = FakeDriver {
            ready_result: Ok(()),
            frames_written: Mutex::new(Vec::new()),
        };
        let encoder = FakeEncoder { should_fail: false };
        let tmp = dir.join(".seek-tmp");

        let outcome = run(&args, &driver, &encoder, &tmp).unwrap();
        assert_eq!(outcome.total_frames, 4);
        assert_eq!(outcome.frames_captured, 4);
        assert!(outcome.mp4_path.exists());
        assert!(!tmp.exists(), "tmp dir cleaned up");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_surfaces_seek_not_ready() {
        let dir = tmp_dir_for("notready");
        std::fs::create_dir_all(&dir).unwrap();
        let args = SeekArgs {
            html_file: dir.join("demo.html").to_string_lossy().to_string(),
            duration: 1.0,
            fps: 2.0,
            width: 100,
            height: 100,
            concurrency: 1,
            settle: 1,
            ready_timeout: 1.0,
            keep_chrome: false,
        };
        let driver = FakeDriver {
            ready_result: Err(DriverError::SeekNotReady("nope".into())),
            frames_written: Mutex::new(Vec::new()),
        };
        let encoder = FakeEncoder { should_fail: false };
        let tmp = dir.join(".seek-tmp");

        let err = run(&args, &driver, &encoder, &tmp).unwrap_err();
        assert_eq!(err, SeekError::SeekNotReady("nope".into()));
        assert!(!tmp.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_surfaces_ffmpeg_failure() {
        let dir = tmp_dir_for("ffmpegfail");
        std::fs::create_dir_all(&dir).unwrap();
        let args = SeekArgs {
            html_file: dir.join("demo.html").to_string_lossy().to_string(),
            duration: 1.0,
            fps: 2.0,
            width: 100,
            height: 100,
            concurrency: 1,
            settle: 1,
            ready_timeout: 1.0,
            keep_chrome: false,
        };
        let driver = FakeDriver {
            ready_result: Ok(()),
            frames_written: Mutex::new(Vec::new()),
        };
        let encoder = FakeEncoder { should_fail: true };
        let tmp = dir.join(".seek-tmp");

        let err = run(&args, &driver, &encoder, &tmp).unwrap_err();
        assert_eq!(err, SeekError::FfmpegFailed("boom".to_string()));

        std::fs::remove_dir_all(&dir).ok();
    }
}
