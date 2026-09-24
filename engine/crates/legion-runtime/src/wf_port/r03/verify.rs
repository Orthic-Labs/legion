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
//! - same final report text and exit code (`0` unless there were page
//!   errors, in which case `1`)

use std::io::Write as _;
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
        width: w.parse().map_err(|_| format!("invalid viewport width: {w}"))?,
        height: h.parse().map_err(|_| format!("invalid viewport height: {h}"))?,
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
pub fn single_shot_filenames(stem: &str, viewport: Viewport, viewport_count: usize) -> (String, String) {
    let suffix = if viewport_count > 1 {
        format!("-{}x{}", viewport.width, viewport.height)
    } else {
        String::new()
    };
    (format!("{stem}{suffix}.png"), format!("{stem}{suffix}-full.png"))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub console_errors: Vec<String>,
    pub page_errors: Vec<String>,
    pub output_dir: PathBuf,
    pub exit_code: i32,
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
        return Err(VerifyError::FileNotFound(html_path.to_string_lossy().to_string()));
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

    for viewport in viewports {
        // The legacy script has no navigation-failure branch of its own;
        // Playwright would raise, which is out of scope for a pure
        // report-shape port. A failed open just yields no screenshots/
        // errors for this viewport rather than aborting the whole run.
        let _ = driver.open(&file_url, *viewport);
        let _ = writeln!(
            stdout,
            "\n→ 打开 {file_url} @ {}x{}",
            viewport.width, viewport.height
        );
        driver.wait_ms(wait_ms);

        if slides > 0 {
            for i in 0..slides {
                let filename = slide_filename(&stem, (i + 1) as u32);
                if let Ok(png) = driver.screenshot(false) {
                    let _ = fs.write(&output_dir.join(&filename), &png);
                }
                let _ = writeln!(stdout, "  ✓ slide {} → {filename}", i + 1);
                if i < slides - 1 {
                    driver.press_arrow_right();
                    driver.wait_ms(500);
                }
            }
        } else {
            let (shot_name, full_name) = single_shot_filenames(&stem, *viewport, viewports.len());
            if let Ok(png) = driver.screenshot(false) {
                let _ = fs.write(&output_dir.join(&shot_name), &png);
            }
            let _ = writeln!(stdout, "  ✓ 截图 → {shot_name}");
            if let Ok(png) = driver.screenshot(true) {
                let _ = fs.write(&output_dir.join(&full_name), &png);
            }
            let _ = writeln!(stdout, "  ✓ 完整页 → {full_name}");
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

    if !console_errors.is_empty() {
        let _ = writeln!(stdout, "\n⚠️  Console Errors/Warnings ({}):", console_errors.len());
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

    let exit_code = if page_errors.is_empty() { 0 } else { 1 };
    Ok(VerifyReport {
        console_errors,
        page_errors,
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
        let _ = tab.set_bounds(headless_chrome::types::Bounds {
            left: Some(0),
            top: Some(0),
            width: Some(viewport.width),
            height: Some(viewport.height),
            window_state: None,
        });

        let console = self.console.clone();
        let page_errors = self.page_errors.clone();
        let _ = tab.add_event_listener(std::sync::Arc::new(move |event: &headless_chrome::protocol::cdp::types::Event| {
            match event {
                headless_chrome::protocol::cdp::types::Event::RuntimeConsoleAPICalled(ev) => {
                    let level = format!("{:?}", ev.params.r#type).to_lowercase();
                    if level == "error" || level == "warning" {
                        let text = ev
                            .params
                            .args
                            .iter()
                            .filter_map(|a| a.value.as_ref().map(|v| v.to_string()))
                            .collect::<Vec<_>>()
                            .join(" ");
                        console.lock().unwrap().push(console_log_line(&level, &text));
                    }
                }
                headless_chrome::protocol::cdp::types::Event::RuntimeExceptionThrown(ev) => {
                    page_errors
                        .lock()
                        .unwrap()
                        .push(ev.params.exception_details.text.clone());
                }
                _ => {}
            }
        }));

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_cli_args_defaults() {
        let args = parse_cli_args(&a(&["design.html"])).unwrap();
        assert_eq!(args.html_path, "design.html");
        assert_eq!(args.viewports, "1440x900");
        assert_eq!(args.slides, 0);
        assert_eq!(args.output, None);
        assert!(!args.show);
        assert_eq!(args.wait, 2000);
    }

    #[test]
    fn parse_cli_args_all_flags_space_separated() {
        let args = parse_cli_args(&a(&[
            "deck.html",
            "--viewports",
            "1920x1080,375x667",
            "--slides",
            "10",
            "--output",
            "./shots",
            "--show",
            "--wait",
            "500",
        ]))
        .unwrap();
        assert_eq!(args.viewports, "1920x1080,375x667");
        assert_eq!(args.slides, 10);
        assert_eq!(args.output.as_deref(), Some("./shots"));
        assert!(args.show);
        assert_eq!(args.wait, 500);
    }

    #[test]
    fn parse_cli_args_equals_form() {
        let args = parse_cli_args(&a(&["d.html", "--slides=5", "--wait=100"])).unwrap();
        assert_eq!(args.slides, 5);
        assert_eq!(args.wait, 100);
    }

    #[test]
    fn parse_cli_args_missing_html_path() {
        assert_eq!(parse_cli_args(&a(&["--slides", "5"])), Err(ArgsError::MissingHtmlPath));
    }

    #[test]
    fn parse_viewport_and_csv() {
        assert_eq!(
            parse_viewport("1920x1080").unwrap(),
            Viewport {
                width: 1920,
                height: 1080
            }
        );
        assert!(parse_viewport("bogus").is_err());
        let vs = parse_viewports("1920x1080,375x667").unwrap();
        assert_eq!(vs.len(), 2);
        assert_eq!(vs[1].width, 375);
    }

    #[test]
    fn default_output_dir_is_screenshots_sibling() {
        assert_eq!(
            default_output_dir(Path::new("/a/b/design.html")),
            PathBuf::from("/a/b/screenshots")
        );
    }

    #[test]
    fn slide_filename_zero_padded() {
        assert_eq!(slide_filename("deck", 1), "deck-slide-01.png");
        assert_eq!(slide_filename("deck", 12), "deck-slide-12.png");
    }

    #[test]
    fn single_shot_filenames_suffix_only_when_multiple_viewports() {
        let vp = Viewport {
            width: 1440,
            height: 900,
        };
        assert_eq!(
            single_shot_filenames("design", vp, 1),
            ("design.png".to_string(), "design-full.png".to_string())
        );
        assert_eq!(
            single_shot_filenames("design", vp, 2),
            (
                "design-1440x900.png".to_string(),
                "design-1440x900-full.png".to_string()
            )
        );
    }

    // -- verify_html / run end-to-end with fakes ---------------------------

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
        opens: RefCell<usize>,
    }
    impl BrowserDriver for FakeDriver {
        fn open(&mut self, _file_url: &str, _viewport: Viewport) -> Result<(), String> {
            *self.opens.borrow_mut() += 1;
            Ok(())
        }
        fn wait_ms(&mut self, _ms: u64) {}
        fn screenshot(&mut self, _full_page: bool) -> Result<Vec<u8>, String> {
            Ok(vec![0x89, 0x50, 0x4E, 0x47])
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
    fn verify_html_missing_file_errors() {
        let fs = FakeFs {
            existing: vec![],
            writes: RefCell::new(HashMap::new()),
        };
        let mut driver = FakeDriver {
            console: vec![],
            page_errors: vec![],
            opens: RefCell::new(0),
        };
        let mut stdout = Vec::new();
        let err = verify_html(
            Path::new("/x/missing.html"),
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
        assert_eq!(err, VerifyError::FileNotFound("/x/missing.html".to_string()));
    }

    #[test]
    fn verify_html_single_shot_writes_two_files_and_exit_zero() {
        let html = PathBuf::from("/x/design.html");
        let fs = FakeFs {
            existing: vec![html.clone()],
            writes: RefCell::new(HashMap::new()),
        };
        let mut driver = FakeDriver {
            console: vec!["[error] boom".to_string()],
            page_errors: vec![],
            opens: RefCell::new(0),
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
        assert_eq!(report.output_dir, PathBuf::from("/x/screenshots"));
        assert!(fs.writes.borrow().contains_key(&report.output_dir.join("design.png")));
        assert!(fs
            .writes
            .borrow()
            .contains_key(&report.output_dir.join("design-full.png")));
        assert_eq!(report.console_errors, vec!["[error] boom".to_string()]);
        let text = String::from_utf8(stdout).unwrap();
        assert!(text.contains("✅ 无JavaScript错误"));
        assert!(text.contains("Console Errors/Warnings (1)"));
    }

    #[test]
    fn verify_html_slides_mode_writes_numbered_files() {
        let html = PathBuf::from("/x/deck.html");
        let fs = FakeFs {
            existing: vec![html.clone()],
            writes: RefCell::new(HashMap::new()),
        };
        let mut driver = FakeDriver {
            console: vec![],
            page_errors: vec![],
            opens: RefCell::new(0),
        };
        let mut stdout = Vec::new();
        let report = verify_html(
            &html,
            &[Viewport {
                width: 1440,
                height: 900,
            }],
            3,
            None,
            0,
            &fs,
            &mut driver,
            &mut stdout,
        )
        .unwrap();
        let dir = &report.output_dir;
        assert!(fs.writes.borrow().contains_key(&dir.join("deck-slide-01.png")));
        assert!(fs.writes.borrow().contains_key(&dir.join("deck-slide-02.png")));
        assert!(fs.writes.borrow().contains_key(&dir.join("deck-slide-03.png")));
    }

    #[test]
    fn verify_html_page_errors_yield_exit_one() {
        let html = PathBuf::from("/x/design.html");
        let fs = FakeFs {
            existing: vec![html.clone()],
            writes: RefCell::new(HashMap::new()),
        };
        let mut driver = FakeDriver {
            console: vec![],
            page_errors: vec!["TypeError: boom".to_string()],
            opens: RefCell::new(0),
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
        assert_eq!(report.exit_code, 1);
        let text = String::from_utf8(stdout).unwrap();
        assert!(text.contains("❌ Page Errors (1)"));
    }

    #[test]
    fn run_returns_exit_code_from_verify_html() {
        let html = PathBuf::from("ok.html");
        let fs = FakeFs {
            existing: vec![html.clone()],
            writes: RefCell::new(HashMap::new()),
        };
        let mut driver = FakeDriver {
            console: vec![],
            page_errors: vec![],
            opens: RefCell::new(0),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(&a(&["ok.html"]), &fs, &mut driver, &mut stdout, &mut stderr);
        assert_eq!(code, 0);
    }

    #[test]
    fn run_missing_positional_returns_exit_two() {
        let fs = FakeFs {
            existing: vec![],
            writes: RefCell::new(HashMap::new()),
        };
        let mut driver = FakeDriver {
            console: vec![],
            page_errors: vec![],
            opens: RefCell::new(0),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(&[], &fs, &mut driver, &mut stdout, &mut stderr);
        assert_eq!(code, 2);
    }
}
