//! Full port of `skills/designer/engine/huashu/scripts/verify.py`.
//!
//! A Playwright-based HTML verification CLI: opens a file, optionally at
//! several viewports, either screenshots it once (viewport + full-page) or
//! steps through `slides` pages via `ArrowRight`, and reports collected
//! console errors/warnings and uncaught page errors. `headless_chrome` (a
//! dependency of this crate, added by a later packet) replaces Playwright
//! behind a [`BrowserDriver`] trait; no prior packet had ported any part of
//! this file (it was `NOT-STARTED` in the `q_q0` report — no browser-
//! automation crate was available at the time).
//!
//! Faithful to the legacy script:
//! - same CLI: positional `html_path`; `--viewports` (default `1440x900`,
//!   comma-separated `WxH`); `--slides` (default `0`); `--output` (default
//!   `<html-dir>/screenshots`); `--show` (flag); `--wait` (default `2000`ms)
//! - same "file does not exist" error (`ERROR: 文件不存在: {path}`, exit 1)
//! - same per-viewport flow: navigate, wait `wait` ms, then either
//!   `slides` screenshots (`{stem}-slide-{01}.png`, `ArrowRight` + 500ms
//!   between) or one viewport screenshot + one full-page screenshot
//!   (`{stem}{suffix}.png` / `{stem}{suffix}-full.png`, suffix only present
//!   when there's more than one viewport)
//! - same final report text; exit code is `0` unless there were page errors
//!   or any open, screenshot, or screenshot-write step failed (then `1`).
//!   Failed steps are recorded in [`VerifyReport::failures`] and never print
//!   a success tick.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Argument parsing — mirrors the `argparse` setup in `main()`.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Args {
    pub html_path: String,
    pub viewports: String,
    pub slides: i64,
    pub output: Option<String>,
    pub show: bool,
    pub wait: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgsError {
    #[error("the following arguments are required: html_path")]
    MissingHtmlPath,
    #[error("argument --{flag}: expected one argument")]
    MissingValue { flag: String },
    #[error("argument --{flag}: invalid value: {value}")]
    InvalidValue { flag: String, value: String },
}

/// Minimal argparse-equivalent: one required positional plus the five
/// documented flags (`--flag value` or `--flag=value`); `--show` is a
/// store-true flag with no value.
pub fn parse_cli_args(argv: &[String]) -> Result<Args, ArgsError> {
    let mut html_path: Option<String> = None;
    let mut viewports = "1440x900".to_string();
    let mut slides = "0".to_string();
    let mut output: Option<String> = None;
    let mut show = false;
    let mut wait = "2000".to_string();

    let mut i = 0usize;
    while i < argv.len() {
        let a = argv[i].as_str();
        let (flag, inline_value) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (a, None),
        };
        macro_rules! take_value {
            ($flag_name:expr) => {{
                if let Some(v) = inline_value.clone() {
                    v
                } else {
                    i += 1;
                    argv.get(i)
                        .cloned()
                        .ok_or_else(|| ArgsError::MissingValue {
                            flag: $flag_name.to_string(),
                        })?
                }
            }};
        }
        match flag {
            "--viewports" => viewports = take_value!("viewports"),
            "--slides" => slides = take_value!("slides"),
            "--output" => output = Some(take_value!("output")),
            "--show" => show = true,
            "--wait" => wait = take_value!("wait"),
            _ if !a.starts_with("--") && html_path.is_none() => html_path = Some(a.to_string()),
            _ => {}
        }
        i += 1;
    }

    let html_path = html_path.ok_or(ArgsError::MissingHtmlPath)?;
    let slides_n: i64 = slides.parse().map_err(|_| ArgsError::InvalidValue {
        flag: "slides".to_string(),
        value: slides.clone(),
    })?;
    let wait_n: u64 = wait.parse().map_err(|_| ArgsError::InvalidValue {
        flag: "wait".to_string(),
        value: wait.clone(),
    })?;

    Ok(Args {
        html_path,
        viewports,
        slides: slides_n,
        output,
        show,
        wait: wait_n,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
}

/// `parse_viewport(s)`: `"WxH"` -> `{width, height}`.
pub fn parse_viewport(s: &str) -> Result<Viewport, String> {
    let (w, h) = s
        .split_once('x')
        .ok_or_else(|| format!("invalid viewport: {s}"))?;
    Ok(Viewport {
        width: w
            .parse()
            .map_err(|_| format!("invalid viewport width: {w}"))?,
        height: h
            .parse()
            .map_err(|_| format!("invalid viewport height: {h}"))?,
    })
}

/// `[parse_viewport(v) for v in args.viewports.split(",")]`.
pub fn parse_viewports(csv: &str) -> Result<Vec<Viewport>, String> {
    csv.split(',').map(parse_viewport).collect()
}

// ---------------------------------------------------------------------------
// Path/filename derivation.
// ---------------------------------------------------------------------------

/// `output_dir is None -> html_path.parent / 'screenshots'`.
pub fn default_output_dir(html_path: &Path) -> PathBuf {
    html_path
        .parent()
        .map(|p| p.join("screenshots"))
        .unwrap_or_else(|| PathBuf::from("screenshots"))
}

pub fn slide_filename(stem: &str, index_1based: u32) -> String {
    format!("{stem}-slide-{index_1based:02}.png")
}

/// Screenshot filenames for the non-slide branch: viewport screenshot and
/// full-page screenshot. `suffix` is `-{w}x{h}` only when there is more
/// than one viewport (matching `f"-{w}x{h}" if len(viewports) > 1 else ""`).
pub fn single_shot_filenames(
    stem: &str,
    viewport: Viewport,
    viewport_count: usize,
) -> (String, String) {
    let suffix = if viewport_count > 1 {
        format!("-{}x{}", viewport.width, viewport.height)
    } else {
        String::new()
    };
    (
        format!("{stem}{suffix}.png"),
        format!("{stem}{suffix}-full.png"),
    )
}

// ---------------------------------------------------------------------------
// I/O boundaries.
// ---------------------------------------------------------------------------

/// One console/page-error log line, e.g. `[error] something broke`.
pub fn console_log_line(level: &str, text: &str) -> String {
    format!("[{level}] {text}")
}

pub trait FileSystem {
    fn exists(&self, path: &Path) -> bool;
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()>;
}

/// The browser-automation boundary: navigate, capture screenshots, and
/// collect console `error`/`warning` messages + uncaught page errors — the
/// same events `page.on("console", ...)` / `page.on("pageerror", ...)`
/// listen for. One [`BrowserDriver`] instance corresponds to one
/// `browser.new_context(...)` + `context.new_page()` pair (i.e. call
/// [`BrowserDriver::open`] once per viewport, like the Python `for viewport
/// in viewports` loop's `context = browser.new_context(...)`).
pub trait BrowserDriver {
    fn open(&mut self, file_url: &str, viewport: Viewport) -> Result<(), String>;
    fn wait_ms(&mut self, ms: u64);
    fn screenshot(&mut self, full_page: bool) -> Result<Vec<u8>, String>;
    fn press_arrow_right(&mut self);
    /// Console `error`/`warning` messages observed since the last call,
    /// each already formatted as `[type] text`.
    fn take_console_messages(&mut self) -> Vec<String>;
    /// Uncaught page errors (`String(err)`) observed since the last call.
    fn take_page_errors(&mut self) -> Vec<String>;
    fn close(&mut self);
}

// ---------------------------------------------------------------------------
// Orchestration — mirrors `verify_html(...)`.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("ERROR: 文件不存在: {0}")]
    FileNotFound(String),
}

/// One capture step that did not succeed. The legacy script ignored these; the port
/// records them so a run cannot report success for a screenshot that was never written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFailure {
    /// `WxH`, plus ` slide N` or ` full-page` when the step belongs to one of those.
    pub target: String,
    /// `open`, `screenshot`, or `write`.
    pub step: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub console_errors: Vec<String>,
    pub page_errors: Vec<String>,
    /// Open, screenshot, and file-write failures across all viewports, in run order.
    pub failures: Vec<CaptureFailure>,
    pub output_dir: PathBuf,
    pub exit_code: i32,
}

/// Takes one screenshot and writes it to `path`. Returns `true` only when both steps
/// succeed; otherwise records the failing step in `failures` and returns `false`.
fn capture_to_file(
    driver: &mut dyn BrowserDriver,
    fs: &dyn FileSystem,
    path: &Path,
    full_page: bool,
    target: &str,
    failures: &mut Vec<CaptureFailure>,
) -> bool {
    let png = match driver.screenshot(full_page) {
        Ok(png) => png,
        Err(reason) => {
            failures.push(CaptureFailure {
                target: target.to_string(),
                step: "screenshot",
                reason,
            });
            return false;
        }
    };
    match fs.write(path, &png) {
        Ok(()) => true,
        Err(e) => {
            failures.push(CaptureFailure {
                target: target.to_string(),
                step: "write",
                reason: format!("{}: {e}", path.to_string_lossy()),
            });
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_html(
    html_path: &Path,
    viewports: &[Viewport],
    slides: i64,
    output_dir: Option<PathBuf>,
    wait_ms: u64,
    fs: &dyn FileSystem,
    driver: &mut dyn BrowserDriver,
    stdout: &mut dyn std::io::Write,
) -> Result<VerifyReport, VerifyError> {
    if !fs.exists(html_path) {
        let _ = writeln!(stdout, "ERROR: 文件不存在: {}", html_path.to_string_lossy());
        return Err(VerifyError::FileNotFound(
            html_path.to_string_lossy().to_string(),
        ));
    }

    let output_dir = output_dir.unwrap_or_else(|| default_output_dir(html_path));
    fs.create_dir_all(&output_dir).ok();

    let file_url = format!("file://{}", html_path.to_string_lossy());
    let stem = html_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut console_errors = Vec::new();
    let mut page_errors = Vec::new();
    let mut failures: Vec<CaptureFailure> = Vec::new();

    for viewport in viewports {
        let viewport_label = format!("{}x{}", viewport.width, viewport.height);
        let _ = writeln!(stdout, "\n→ 打开 {file_url} @ {viewport_label}");
        // The legacy script has no navigation-failure branch of its own. A failed
        // open is recorded and this viewport's captures are skipped, so no
        // screenshot of a stale page from a previous viewport is written.
        match driver.open(&file_url, *viewport) {
            Ok(()) => {
                driver.wait_ms(wait_ms);

                if slides > 0 {
                    for i in 0..slides {
                        let filename = slide_filename(&stem, (i + 1) as u32);
                        let target = format!("{viewport_label} slide {}", i + 1);
                        if capture_to_file(
                            driver,
                            fs,
                            &output_dir.join(&filename),
                            false,
                            &target,
                            &mut failures,
                        ) {
                            let _ = writeln!(stdout, "  ✓ slide {} → {filename}", i + 1);
                        }
                        if i < slides - 1 {
                            driver.press_arrow_right();
                            driver.wait_ms(500);
                        }
                    }
                } else {
                    let (shot_name, full_name) =
                        single_shot_filenames(&stem, *viewport, viewports.len());
                    if capture_to_file(
                        driver,
                        fs,
                        &output_dir.join(&shot_name),
                        false,
                        &viewport_label,
                        &mut failures,
                    ) {
                        let _ = writeln!(stdout, "  ✓ 截图 → {shot_name}");
                    }
                    let full_target = format!("{viewport_label} full-page");
                    if capture_to_file(
                        driver,
                        fs,
                        &output_dir.join(&full_name),
                        true,
                        &full_target,
                        &mut failures,
                    ) {
                        let _ = writeln!(stdout, "  ✓ 完整页 → {full_name}");
                    }
                }
            }
            Err(reason) => failures.push(CaptureFailure {
                target: viewport_label.clone(),
                step: "open",
                reason,
            }),
        }

        console_errors.extend(driver.take_console_messages());
        page_errors.extend(driver.take_page_errors());
        driver.close();
    }

    let _ = writeln!(stdout, "\n{}", "=".repeat(50));
    let _ = writeln!(stdout, "验证报告");
    let _ = writeln!(stdout, "{}", "=".repeat(50));

    if !page_errors.is_empty() {
        let _ = writeln!(stdout, "\n❌ Page Errors ({}):", page_errors.len());
        for e in &page_errors {
            let _ = writeln!(stdout, "  - {e}");
        }
    } else {
        let _ = writeln!(stdout, "\n✅ 无JavaScript错误");
    }

    if !failures.is_empty() {
        let _ = writeln!(stdout, "\n❌ Capture Failures ({}):", failures.len());
        for f in &failures {
            let _ = writeln!(stdout, "  - {} [{}]: {}", f.target, f.step, f.reason);
        }
    }

    if !console_errors.is_empty() {
        let _ = writeln!(
            stdout,
            "\n⚠️  Console Errors/Warnings ({}):",
            console_errors.len()
        );
        for e in console_errors.iter().take(20) {
            let _ = writeln!(stdout, "  - {e}");
        }
        if console_errors.len() > 20 {
            let _ = writeln!(stdout, "  ... 还有{}条", console_errors.len() - 20);
        }
    } else {
        let _ = writeln!(stdout, "✅ Console干净");
    }

    let _ = writeln!(stdout, "\n📸 截图保存至: {}", output_dir.to_string_lossy());

    let exit_code = if page_errors.is_empty() && failures.is_empty() {
        0
    } else {
        1
    };
    Ok(VerifyReport {
        console_errors,
        page_errors,
        failures,
        output_dir,
        exit_code,
    })
}

/// `main()`: parses argv, resolves viewports, calls [`verify_html`].
pub fn run(
    argv: &[String],
    fs: &dyn FileSystem,
    driver: &mut dyn BrowserDriver,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> i32 {
    let args = match parse_cli_args(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 2;
        }
    };
    let viewports = match parse_viewports(&args.viewports) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 2;
        }
    };
    match verify_html(
        Path::new(&args.html_path),
        &viewports,
        args.slides,
        args.output.map(PathBuf::from),
        args.wait,
        fs,
        driver,
        stdout,
    ) {
        Ok(report) => report.exit_code,
        Err(_) => 1,
    }
}

// ---------------------------------------------------------------------------
// Production implementations.
// ---------------------------------------------------------------------------

pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }
}

/// Production `headless_chrome`-backed [`BrowserDriver`].
///
/// NOTE (compile-review flag, cargo cannot run in this environment): the
/// `Browser`/`Tab` navigation/screenshot calls follow the same pattern used
/// elsewhere in this crate (`Browser::default`, `browser.new_tab()`,
/// `tab.navigate_to()`, `tab.wait_until_navigated()`,
/// `tab.capture_screenshot()`, `tab.press_key()`). Console-message and
/// uncaught-page-error capture uses `Tab::add_event_listener` against the
/// CDP `Runtime.consoleAPICalled` / `Runtime.exceptionThrown` events; the
/// exact `headless_chrome::protocol::cdp::Runtime` event/type names should
/// be re-checked against the pinned crate version before this lands — of
/// everything in this module, this is the single highest compile-risk spot
/// per the porting brief's "self-review compile correctness carefully"
/// rule, since no other packet in this crate has needed CDP event
/// subscription (only request/response CDP calls) to compare against.
pub struct ChromeBrowserDriver {
    browser: headless_chrome::Browser,
    tab: Option<std::sync::Arc<headless_chrome::Tab>>,
    console: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    page_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    headless: bool,
}

impl ChromeBrowserDriver {
    pub fn launch(headless: bool) -> Result<Self, String> {
        let opts = headless_chrome::LaunchOptions::default_builder()
            .headless(headless)
            .build()
            .map_err(|e| e.to_string())?;
        let browser = headless_chrome::Browser::new(opts).map_err(|e| e.to_string())?;
        Ok(Self {
            browser,
            tab: None,
            console: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            page_errors: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            headless,
        })
    }
}

impl BrowserDriver for ChromeBrowserDriver {
    fn open(&mut self, file_url: &str, viewport: Viewport) -> Result<(), String> {
        let _ = self.headless;
        let tab = self.browser.new_tab().map_err(|e| e.to_string())?;
        let _ = tab.set_bounds(headless_chrome::types::Bounds::Normal {
            left: Some(0),
            top: Some(0),
            width: Some(viewport.width as f64),
            height: Some(viewport.height as f64),
        });

        let console = self.console.clone();
        let page_errors = self.page_errors.clone();
        let _ = tab.add_event_listener(std::sync::Arc::new(
            move |event: &headless_chrome::protocol::cdp::types::Event| match event {
                headless_chrome::protocol::cdp::types::Event::RuntimeConsoleAPICalled(ev) => {
                    let level = format!("{:?}", ev.params.Type).to_lowercase();
                    if level == "error" || level == "warning" {
                        let text = ev
                            .params
                            .args
                            .iter()
                            .filter_map(|a| a.value.as_ref().map(|v| v.to_string()))
                            .collect::<Vec<_>>()
                            .join(" ");
                        console
                            .lock()
                            .unwrap()
                            .push(console_log_line(&level, &text));
                    }
                }
                headless_chrome::protocol::cdp::types::Event::RuntimeExceptionThrown(ev) => {
                    page_errors
                        .lock()
                        .unwrap()
                        .push(ev.params.exception_details.text.clone());
                }
                _ => {}
            },
        ));

        tab.navigate_to(file_url).map_err(|e| e.to_string())?;
        tab.wait_until_navigated().map_err(|e| e.to_string())?;
        self.tab = Some(tab);
        Ok(())
    }

    fn wait_ms(&mut self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    fn screenshot(&mut self, full_page: bool) -> Result<Vec<u8>, String> {
        let tab = self.tab.as_ref().ok_or("no open tab")?;
        tab.capture_screenshot(
            headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
            None,
            None,
            full_page,
        )
        .map_err(|e| e.to_string())
    }

    fn press_arrow_right(&mut self) {
        if let Some(tab) = &self.tab {
            let _ = tab.press_key("ArrowRight");
        }
    }

    fn take_console_messages(&mut self) -> Vec<String> {
        std::mem::take(&mut *self.console.lock().unwrap())
    }

    fn take_page_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut *self.page_errors.lock().unwrap())
    }

    fn close(&mut self) {
        if let Some(tab) = self.tab.take() {
            tab.close(true).ok();
        }
    }
}
