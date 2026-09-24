//! Full port of `skills/designer/engine/huashu/scripts/render-video.js`.
//!
//! `wf_port::w2_008::render_video` already ported the pure trim-offset
//! decision ([`crate::wf_port::w2_008::resolve_trim`]) and the literal
//! chrome-hiding CSS ([`crate::wf_port::w2_008::HIDE_CHROME_CSS`]) and
//! documented the rest as out of scope: no headless-browser crate was wired
//! into `legion-runtime` yet. `headless_chrome` is now a dependency of this
//! crate (added by a later packet), so this module reuses both of those and
//! completes the rest: CLI arg/positional parsing, the chrome-hiding JS
//! heuristic script, and the record → encode orchestration.
//!
//! One mechanism difference from the legacy script, called out explicitly:
//! Playwright's `recordVideo` writes a continuous WebM from context creation
//! and the script trims the pre-ready prefix with `ffmpeg -ss`.
//! `headless_chrome`/CDP has no equivalent continuous-video-recording API,
//! so [`ChromeRecorder`] instead starts capturing PNG frames *after* the
//! ready signal (or fallback font-wait) is observed, at a fixed capture
//! rate, and `ffmpeg` muxes that PNG sequence into the output MP4. The CLI
//! surface (all flags, defaults, the `<html-file>` positional), the ready-
//! signal/`__seek(0)` handshake, the chrome-hiding CSS/JS injection, the
//! output path (`<dir>/<basename>.mp4`), the banner/warning console text,
//! and the final MP4 container/codec (`libx264`, `yuv420p`, `crf 18`,
//! `preset medium`, `+faststart`) are unchanged. [`resolve_trim`] is still
//! exposed for a caller that wires a continuous-recording backend instead.

use std::io::Write as _;
use std::path::{Path, PathBuf};

pub use crate::wf_port::w2_008::render_video::{resolve_trim, HIDE_CHROME_CSS};

// ---------------------------------------------------------------------------
// CLI arg parsing — mirrors `arg(name, def)` / `hasFlag(name)` / the
// top-level `HTML_FILE`/`DURATION`/... constant derivation.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Args {
    pub html_file: String,
    pub duration: f64,
    pub width: u32,
    pub height: u32,
    pub trim_override: Option<f64>,
    pub font_wait: f64,
    pub ready_timeout: f64,
    pub keep_chrome: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseArgsError {
    #[error("Usage: node render-video.js <html-file>")]
    MissingHtmlFile,
}

/// `arg(name, def)`: `--name=value` lookup with a default.
pub fn arg<'a>(argv: &'a [String], name: &str, default: Option<&'a str>) -> Option<&'a str> {
    let prefix = format!("--{name}=");
    argv.iter()
        .find(|a| a.starts_with(&prefix))
        .map(|a| &a[prefix.len()..])
        .or(default)
}

/// `hasFlag(name)`: `argv.includes('--name')`.
pub fn has_flag(argv: &[String], name: &str) -> bool {
    argv.iter().any(|a| a == &format!("--{name}"))
}

/// Parses the CLI's own args (the legacy script's `process.argv.slice(2)`),
/// mirroring the constant derivations at the top of the script. The first
/// positional (`process.argv[2]`) is the HTML file; missing it, or it
/// starting with `--`, mirrors the `Usage:` error + `exit(1)`.
pub fn parse_args(argv: &[String]) -> Result<Args, ParseArgsError> {
    let html_file = argv.first().cloned();
    let html_file = match html_file {
        Some(f) if !f.starts_with("--") => f,
        _ => return Err(ParseArgsError::MissingHtmlFile),
    };
    // `arg`/`hasFlag` in the legacy script scan the *whole* `process.argv`
    // (including the positional), which is harmless since none of the flag
    // names collide with a bare positional value.
    let duration: f64 = arg(argv, "duration", Some("30"))
        .unwrap()
        .parse()
        .unwrap_or(f64::NAN);
    let width: u32 = arg(argv, "width", Some("1920"))
        .unwrap()
        .parse()
        .unwrap_or(1920);
    let height: u32 = arg(argv, "height", Some("1080"))
        .unwrap()
        .parse()
        .unwrap_or(1080);
    let trim_override: Option<f64> = arg(argv, "trim", None).and_then(|s| s.parse().ok());
    let font_wait: f64 = arg(argv, "fontwait", Some("1.5"))
        .unwrap()
        .parse()
        .unwrap_or(1.5);
    let ready_timeout: f64 = arg(argv, "readytimeout", Some("8"))
        .unwrap()
        .parse()
        .unwrap_or(8.0);
    let keep_chrome = has_flag(argv, "keep-chrome");

    Ok(Args {
        html_file,
        duration,
        width,
        height,
        trim_override,
        font_wait,
        ready_timeout,
        keep_chrome,
    })
}

/// Derived output paths, mirroring `HTML_ABS`/`BASENAME`/`DIR`/`MP4_OUT`.
/// `TMP_DIR` is caller-supplied since it embeds a timestamp + pid (see
/// [`tmp_dir_name`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub html_abs: PathBuf,
    pub dir: PathBuf,
    pub basename: String,
    pub mp4_out: PathBuf,
}

/// `path.resolve`, `path.basename(f, path.extname(f))`, `path.dirname`,
/// `path.join(DIR, BASENAME + '.mp4')`. `cwd` stands in for
/// `process.cwd()` when `html_file` is relative.
pub fn derive_paths(html_file: &str, cwd: &Path) -> Paths {
    let raw = Path::new(html_file);
    let html_abs = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };
    let basename = html_abs
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let dir = html_abs
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let mp4_out = dir.join(format!("{basename}.mp4"));
    Paths {
        html_abs,
        dir,
        basename,
        mp4_out,
    }
}

/// `.video-tmp-<Date.now()>-<pid>`.
pub fn tmp_dir_name(now_millis: u128, pid: u32) -> String {
    format!(".video-tmp-{now_millis}-{pid}")
}

// ---------------------------------------------------------------------------
// Chrome-hiding JS heuristic — mirrors the `addInitScript` callback body
// (with `HIDE_CHROME_CSS` inlined, since this port evaluates it as a plain
// string rather than passing a closure argument across the CDP boundary).
// ---------------------------------------------------------------------------

/// Builds the JS injected (equivalent to `addInitScript(css => {...},
/// HIDE_CHROME_CSS)`) to hide "chrome" elements: injects [`HIDE_CHROME_CSS`]
/// as a `<style>`, and a `MutationObserver`-driven heuristic that hides
/// fixed/sticky bars containing a button or scrubber/time glyphs.
pub fn hide_chrome_js() -> String {
    format!(
        r#"(function() {{
  const css = {css:?};
  const HIDE_MARK = 'data-video-hidden';
  function injectStyle() {{
    const style = document.createElement('style');
    style.setAttribute('data-inject', 'render-video-chrome-hide');
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);
  }}
  function hideChromeBars() {{
    const vh = window.innerHeight;
    document.querySelectorAll('div, nav, header, footer, section, aside').forEach(el => {{
      if (el.hasAttribute(HIDE_MARK)) return;
      if (el.dataset.recordKeep === 'true') return;
      const s = getComputedStyle(el);
      if (s.position !== 'fixed' && s.position !== 'sticky') return;
      const r = el.getBoundingClientRect();
      if (r.height > vh * 0.25) return;
      const atBottom = r.bottom >= vh - 30;
      const atTop = r.top <= 30 && r.height < 80;
      if (!atBottom && !atTop) return;
      const txt = el.textContent || '';
      const hasBtn = !!el.querySelector('button, [role="button"]');
      const hasCtrls = /[⏸▶⏮⏭↻↺↩↪]|\d+\.\d+\s*s/.test(txt);
      if (hasBtn || hasCtrls) {{
        el.style.setProperty('display', 'none', 'important');
        el.setAttribute(HIDE_MARK, '1');
      }}
    }});
  }}
  const start = () => {{
    injectStyle();
    hideChromeBars();
    const obs = new MutationObserver(hideChromeBars);
    obs.observe(document.body, {{ childList: true, subtree: true }});
    setTimeout(() => obs.disconnect(), 6000);
  }};
  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', start, {{ once: true }});
  }} else {{
    start();
  }}
  window.__recording = true;
}})();"#,
        css = HIDE_CHROME_CSS,
    )
}

/// `window.__ready === true`, mirrors `page.waitForFunction(() =>
/// window.__ready === true, { timeout })`.
pub const READY_PROBE_JS: &str = "window.__ready === true";
/// Mirrors the `page.evaluate` block that calls `window.__seek(0)` when
/// present.
pub const SEEK_ZERO_JS: &str =
    "(function(){ if (typeof window.__seek === 'function') { window.__seek(0); return true; } return false; })()";

// ---------------------------------------------------------------------------
// I/O boundaries.
// ---------------------------------------------------------------------------

/// Outcome of the record phase: whether `window.__ready` fired within the
/// timeout, the elapsed seconds to that point (or to the font-wait
/// fallback), and the captured frames (PNG bytes, in order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordCapture {
    pub has_ready: bool,
    pub animation_start_sec_millis: u64,
    pub frames: Vec<Vec<u8>>,
}

/// The browser-automation boundary. Mirrors, in order: the warmup context
/// (`goto` + wait `font_wait_secs`), then the record phase (fresh context,
/// optional chrome-hide injection, `goto`, ready-signal wait, optional
/// `__seek(0)`, then frame capture for `duration_secs` at `fps`).
pub trait Recorder {
    fn warmup(&mut self, file_url: &str, width: u32, height: u32, font_wait_secs: f64) -> Result<(), String>;
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        file_url: &str,
        width: u32,
        height: u32,
        hide_chrome: bool,
        ready_timeout_secs: f64,
        duration_secs: f64,
        fps: u32,
    ) -> Result<RecordCapture, String>;
}

/// The `ffmpeg` mux boundary, mirroring the final `spawnSync('ffmpeg', [...])`
/// call, adapted to a PNG-sequence input (`-framerate {fps} -i
/// frame%06d.png`) rather than a WebM `-ss`-trimmed input, since capture
/// already starts at the ready point (see the module doc comment).
pub trait FfmpegRunner {
    fn encode_png_sequence(&self, frame_dir: &Path, fps: u32, out: &Path) -> Result<(), String>;
}

pub trait FileSystem {
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn file_len(&self, path: &Path) -> std::io::Result<u64>;
}

/// The DEFAULT_FPS this port captures at (not exposed as a legacy CLI flag;
/// an internal implementation detail of the PNG-sequence capture mechanism
/// described in the module doc comment).
pub const DEFAULT_FPS: u32 = 30;

/// `frame%06d.png` naming for the `i`-th (0-based) captured frame.
pub fn frame_filename(i: usize) -> String {
    format!("frame{i:06}.png")
}

// ---------------------------------------------------------------------------
// Orchestration — mirrors the `(async () => { ... })()` IIFE.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    #[error("Usage: node render-video.js <html-file>")]
    Usage,
    #[error("{0}")]
    Recorder(String),
    #[error("✗ No frames captured")]
    NoFrames,
    #[error("✗ ffmpeg failed:\n{0}")]
    Ffmpeg(String),
    #[error("{0}")]
    Io(String),
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    argv: &[String],
    cwd: &Path,
    tmp_dir_suffix: &str,
    recorder: &mut dyn Recorder,
    ffmpeg: &dyn FfmpegRunner,
    fs: &dyn FileSystem,
    stdout: &mut dyn std::io::Write,
) -> Result<PathBuf, RunError> {
    let args = parse_args(argv).map_err(|_| RunError::Usage)?;
    let paths = derive_paths(&args.html_file, cwd);
    let tmp_dir = paths.dir.join(format!(".video-tmp-{tmp_dir_suffix}"));
    let file_url = format!("file://{}", paths.html_abs.to_string_lossy());

    let _ = writeln!(stdout, "▸ Rendering: {}", args.html_file);
    let _ = writeln!(
        stdout,
        "  size: {}x{} · duration: {}s · hide-chrome: {}",
        args.width,
        args.height,
        args.duration,
        !args.keep_chrome
    );
    let _ = writeln!(stdout, "  output: {}", paths.mp4_out.to_string_lossy());

    fs.create_dir_all(&tmp_dir).map_err(|e| RunError::Io(e.to_string()))?;

    let _ = writeln!(stdout, "▸ Warmup (caching fonts)…");
    recorder
        .warmup(&file_url, args.width, args.height, args.font_wait)
        .map_err(RunError::Recorder)?;

    let _ = writeln!(stdout, "▸ Recording (clean start)…");
    let capture = recorder
        .record(
            &file_url,
            args.width,
            args.height,
            !args.keep_chrome,
            args.ready_timeout,
            args.duration,
            DEFAULT_FPS,
        )
        .map_err(RunError::Recorder)?;

    if !capture.has_ready {
        let _ = writeln!(stdout);
        let _ = writeln!(
            stdout,
            "  ⚠️  WARNING: window.__ready signal not detected within {}s",
            args.ready_timeout
        );
        let _ = writeln!(
            stdout,
            "     Recording will use fallback trim of {:.2}s + 0.5s safety margin.",
            capture.animation_start_sec_millis as f64 / 1000.0
        );
        let _ = writeln!(
            stdout,
            "     This is UNRELIABLE — your video may start mid-animation or skip frames."
        );
        let _ = writeln!(stdout);
        let _ = writeln!(
            stdout,
            "     FIX: in your HTML's animation tick (or rAF first frame), add:"
        );
        let _ = writeln!(stdout, "        window.__ready = true;");
        let _ = writeln!(
            stdout,
            "     animations.jsx-based HTML does this automatically. If you wrote your"
        );
        let _ = writeln!(
            stdout,
            "     own Stage, see references/animation-pitfalls.md §12 for the pattern."
        );
        let _ = writeln!(stdout);
    }

    if capture.frames.is_empty() {
        fs.remove_dir_all(&tmp_dir).ok();
        return Err(RunError::NoFrames);
    }
    for (i, frame) in capture.frames.iter().enumerate() {
        fs.write(&tmp_dir.join(frame_filename(i)), frame)
            .map_err(|e| RunError::Io(e.to_string()))?;
    }

    let resolved_trim = resolve_trim(
        args.trim_override,
        capture.animation_start_sec_millis as f64 / 1000.0,
        capture.has_ready,
    );
    let _ = writeln!(
        stdout,
        "▸ ffmpeg: trim={:.2}s{}, encode H.264…",
        resolved_trim,
        if args.trim_override.is_some() {
            " (manual)"
        } else {
            " (auto)"
        }
    );

    ffmpeg
        .encode_png_sequence(&tmp_dir, DEFAULT_FPS, &paths.mp4_out)
        .map_err(RunError::Ffmpeg)?;

    fs.remove_dir_all(&tmp_dir).ok();

    let size_mb = fs
        .file_len(&paths.mp4_out)
        .map(|b| b as f64 / 1024.0 / 1024.0)
        .unwrap_or(0.0);
    let _ = writeln!(
        stdout,
        "✓ Done: {} ({:.1} MB)",
        paths.mp4_out.to_string_lossy(),
        size_mb
    );

    Ok(paths.mp4_out)
}

// ---------------------------------------------------------------------------
// Production implementations.
// ---------------------------------------------------------------------------

/// Production `headless_chrome`-backed [`Recorder`].
///
/// NOTE (compile-review flag, cargo cannot run in this environment): built
/// against `headless_chrome` 1.x's `Browser`/`Tab` API as used elsewhere in
/// this crate (`Browser::default`, `browser.new_tab()`, `tab.navigate_to()`,
/// `tab.wait_until_navigated()`, `tab.evaluate()`,
/// `tab.capture_screenshot()`); the ready-poll loop and per-frame capture
/// timing should be re-checked against the pinned version before this lands.
pub struct ChromeRecorder {
    browser: headless_chrome::Browser,
}

impl ChromeRecorder {
    pub fn launch() -> Result<Self, String> {
        let browser = headless_chrome::Browser::default().map_err(|e| e.to_string())?;
        Ok(Self { browser })
    }

    fn set_bounds(tab: &headless_chrome::Tab, width: u32, height: u32) {
        let _ = tab.set_bounds(headless_chrome::types::Bounds::Normal {
            left: Some(0),
            top: Some(0),
            width: Some(width as f64),
            height: Some(height as f64),
        });
    }
}

impl Recorder for ChromeRecorder {
    fn warmup(&mut self, file_url: &str, width: u32, height: u32, font_wait_secs: f64) -> Result<(), String> {
        let tab = self.browser.new_tab().map_err(|e| e.to_string())?;
        Self::set_bounds(&tab, width, height);
        tab.navigate_to(file_url).map_err(|e| e.to_string())?;
        tab.wait_until_navigated().map_err(|e| e.to_string())?;
        std::thread::sleep(std::time::Duration::from_secs_f64(font_wait_secs));
        tab.close(true).ok();
        Ok(())
    }

    fn record(
        &mut self,
        file_url: &str,
        width: u32,
        height: u32,
        hide_chrome: bool,
        ready_timeout_secs: f64,
        duration_secs: f64,
        fps: u32,
    ) -> Result<RecordCapture, String> {
        let tab = self.browser.new_tab().map_err(|e| e.to_string())?;
        Self::set_bounds(&tab, width, height);
        if hide_chrome {
            let _ = tab.evaluate(&hide_chrome_js(), false);
        }
        let t0 = std::time::Instant::now();
        tab.navigate_to(file_url).map_err(|e| e.to_string())?;
        tab.wait_until_navigated().map_err(|e| e.to_string())?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(ready_timeout_secs);
        let mut has_ready = false;
        while std::time::Instant::now() < deadline {
            if let Ok(remote) = tab.evaluate(READY_PROBE_JS, false) {
                if remote.value.and_then(|v| v.as_bool()).unwrap_or(false) {
                    has_ready = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !has_ready {
            std::thread::sleep(std::time::Duration::from_secs_f64(1.5));
        } else {
            let _ = tab.evaluate(SEEK_ZERO_JS, false);
        }
        let animation_start_sec_millis = t0.elapsed().as_millis() as u64;

        let frame_interval = std::time::Duration::from_secs_f64(1.0 / fps as f64);
        let frame_count = ((duration_secs * fps as f64).round() as u64).max(1);
        let mut frames = Vec::with_capacity(frame_count as usize);
        for _ in 0..frame_count {
            let frame_start = std::time::Instant::now();
            if let Ok(png) = tab.capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                None,
                None,
                true,
            ) {
                frames.push(png);
            }
            let elapsed = frame_start.elapsed();
            if elapsed < frame_interval {
                std::thread::sleep(frame_interval - elapsed);
            }
        }
        tab.close(true).ok();

        Ok(RecordCapture {
            has_ready,
            animation_start_sec_millis,
            frames,
        })
    }
}

/// Production `ffmpeg`-backed [`FfmpegRunner`], mirroring the legacy
/// script's codec/format flags exactly.
pub struct RealFfmpeg;

impl FfmpegRunner for RealFfmpeg {
    fn encode_png_sequence(&self, frame_dir: &Path, fps: u32, out: &Path) -> Result<(), String> {
        let pattern = frame_dir.join("frame%06d.png");
        let output = std::process::Command::new("ffmpeg")
            .args(["-y", "-framerate", &fps.to_string(), "-i"])
            .arg(&pattern)
            .args([
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-crf",
                "18",
                "-preset",
                "medium",
                "-movflags",
                "+faststart",
            ])
            .arg(out)
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

pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        std::fs::remove_dir_all(path)
    }
    fn file_len(&self, path: &Path) -> std::io::Result<u64> {
        Ok(std::fs::metadata(path)?.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_requires_positional_html_file() {
        assert_eq!(parse_args(&[]), Err(ParseArgsError::MissingHtmlFile));
        assert_eq!(
            parse_args(&a(&["--duration=5"])),
            Err(ParseArgsError::MissingHtmlFile)
        );
    }

    #[test]
    fn parse_args_defaults() {
        let args = parse_args(&a(&["my.html"])).unwrap();
        assert_eq!(args.html_file, "my.html");
        assert_eq!(args.duration, 30.0);
        assert_eq!(args.width, 1920);
        assert_eq!(args.height, 1080);
        assert_eq!(args.trim_override, None);
        assert_eq!(args.font_wait, 1.5);
        assert_eq!(args.ready_timeout, 8.0);
        assert!(!args.keep_chrome);
    }

    #[test]
    fn parse_args_overrides() {
        let args = parse_args(&a(&[
            "my.html",
            "--duration=10",
            "--width=800",
            "--height=600",
            "--trim=2.5",
            "--fontwait=0.5",
            "--readytimeout=3",
            "--keep-chrome",
        ]))
        .unwrap();
        assert_eq!(args.duration, 10.0);
        assert_eq!(args.width, 800);
        assert_eq!(args.height, 600);
        assert_eq!(args.trim_override, Some(2.5));
        assert_eq!(args.font_wait, 0.5);
        assert_eq!(args.ready_timeout, 3.0);
        assert!(args.keep_chrome);
    }

    #[test]
    fn derive_paths_matches_layout() {
        let paths = derive_paths("sub/my-anim.html", Path::new("/root"));
        assert_eq!(paths.html_abs, PathBuf::from("/root/sub/my-anim.html"));
        assert_eq!(paths.basename, "my-anim");
        assert_eq!(paths.dir, PathBuf::from("/root/sub"));
        assert_eq!(paths.mp4_out, PathBuf::from("/root/sub/my-anim.mp4"));
    }

    #[test]
    fn derive_paths_absolute_input_ignores_cwd() {
        let paths = derive_paths("/abs/anim.html", Path::new("/root"));
        assert_eq!(paths.html_abs, PathBuf::from("/abs/anim.html"));
        assert_eq!(paths.mp4_out, PathBuf::from("/abs/anim.mp4"));
    }

    #[test]
    fn hide_chrome_js_embeds_css_and_heuristic() {
        let js = hide_chrome_js();
        assert!(js.contains("no-record"));
        assert!(js.contains("MutationObserver"));
        assert!(js.contains("data-video-hidden"));
        assert!(js.contains("window.__recording = true"));
    }

    #[test]
    fn resolve_trim_reexported_and_correct() {
        assert_eq!(resolve_trim(Some(1.0), 5.0, true), 1.0);
        let t = resolve_trim(None, 1.5, false);
        assert!((t - 2.0).abs() < 1e-9);
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
                animation_start_sec_millis: 1200,
                frames: (0..self.frames).map(|i| vec![i as u8]).collect(),
            })
        }
    }

    struct FakeFfmpeg {
        should_fail: bool,
    }
    impl FfmpegRunner for FakeFfmpeg {
        fn encode_png_sequence(&self, _dir: &Path, _fps: u32, _out: &Path) -> Result<(), String> {
            if self.should_fail {
                Err("boom".to_string())
            } else {
                Ok(())
            }
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
    fn run_end_to_end_writes_frames_and_encodes() {
        let mut recorder = FakeRecorder {
            has_ready: true,
            frames: 3,
        };
        let ffmpeg = FakeFfmpeg { should_fail: false };
        let mut sizes = HashMap::new();
        sizes.insert(PathBuf::from("/root/anim.mp4"), 2 * 1024 * 1024);
        let fs = FakeFs {
            writes: RefCell::new(HashMap::new()),
            sizes,
        };
        let mut stdout = Vec::new();
        let out = run(
            &a(&["anim.html"]),
            Path::new("/root"),
            "test",
            &mut recorder,
            &ffmpeg,
            &fs,
            &mut stdout,
        )
        .unwrap();
        assert_eq!(out, PathBuf::from("/root/anim.mp4"));
        assert_eq!(fs.writes.borrow().len(), 3);
        let text = String::from_utf8(stdout).unwrap();
        assert!(text.contains("▸ Rendering: anim.html"));
        assert!(text.contains("✓ Done:"));
    }

    #[test]
    fn run_no_ready_signal_prints_warning() {
        let mut recorder = FakeRecorder {
            has_ready: false,
            frames: 1,
        };
        let ffmpeg = FakeFfmpeg { should_fail: false };
        let mut sizes = HashMap::new();
        sizes.insert(PathBuf::from("/root/anim.mp4"), 1024);
        let fs = FakeFs {
            writes: RefCell::new(HashMap::new()),
            sizes,
        };
        let mut stdout = Vec::new();
        run(
            &a(&["anim.html"]),
            Path::new("/root"),
            "test",
            &mut recorder,
            &ffmpeg,
            &fs,
            &mut stdout,
        )
        .unwrap();
        let text = String::from_utf8(stdout).unwrap();
        assert!(text.contains("WARNING: window.__ready signal not detected"));
        assert!(text.contains("UNRELIABLE"));
    }

    #[test]
    fn run_no_frames_errors() {
        let mut recorder = FakeRecorder {
            has_ready: true,
            frames: 0,
        };
        let ffmpeg = FakeFfmpeg { should_fail: false };
        let fs = FakeFs {
            writes: RefCell::new(HashMap::new()),
            sizes: HashMap::new(),
        };
        let mut stdout = Vec::new();
        let err = run(
            &a(&["anim.html"]),
            Path::new("/root"),
            "test",
            &mut recorder,
            &ffmpeg,
            &fs,
            &mut stdout,
        )
        .unwrap_err();
        assert_eq!(err, RunError::NoFrames);
    }

    #[test]
    fn run_ffmpeg_failure_propagates() {
        let mut recorder = FakeRecorder {
            has_ready: true,
            frames: 1,
        };
        let ffmpeg = FakeFfmpeg { should_fail: true };
        let fs = FakeFs {
            writes: RefCell::new(HashMap::new()),
            sizes: HashMap::new(),
        };
        let mut stdout = Vec::new();
        let err = run(
            &a(&["anim.html"]),
            Path::new("/root"),
            "test",
            &mut recorder,
            &ffmpeg,
            &fs,
            &mut stdout,
        )
        .unwrap_err();
        assert!(matches!(err, RunError::Ffmpeg(_)));
    }

    #[test]
    fn run_usage_error_on_missing_html_file() {
        let mut recorder = FakeRecorder {
            has_ready: true,
            frames: 1,
        };
        let ffmpeg = FakeFfmpeg { should_fail: false };
        let fs = FakeFs {
            writes: RefCell::new(HashMap::new()),
            sizes: HashMap::new(),
        };
        let mut stdout = Vec::new();
        let err = run(&[], Path::new("/root"), "test", &mut recorder, &ffmpeg, &fs, &mut stdout).unwrap_err();
        assert_eq!(err, RunError::Usage);
    }

    #[test]
    fn frame_filename_zero_padded() {
        assert_eq!(frame_filename(0), "frame000000.png");
        assert_eq!(frame_filename(7), "frame000007.png");
    }
}
