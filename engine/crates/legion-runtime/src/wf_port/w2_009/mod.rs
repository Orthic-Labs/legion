//! Port of `skills/designer/engine/huashu/scripts/verify.py` (chunk w2_009).
//!
//! `verify.py` is a Playwright-driven CLI that opens a local HTML file in a
//! headless Chromium browser, captures screenshots at one or more
//! viewports (optionally paging through "slides" with `ArrowRight`),
//! collects `console` and `pageerror` events, and prints a verification
//! report, exiting `1` iff any page (JavaScript) errors were observed.
//!
//! Actually driving a browser (`playwright.sync_api`, `page.goto`,
//! `page.screenshot`, keyboard input, `context.close`) is inherently a
//! host/process side effect with no in-process return-value contract to
//! assert against in a unit test, so it is not ported here. What *is*
//! pure, deterministic logic in the script — and is ported below with unit
//! tests mirroring the Python behaviour — is:
//!
//! - `parse_viewport`: `"WxH"` viewport-string parsing (`--viewports`).
//! - the default viewport (`1440x900`) used when `--viewports` is absent.
//! - the screenshot filename scheme: `--slides` mode
//!   (`{stem}-slide-{NN}.png`, one-based, zero-padded to 2 digits),
//!   otherwise `{stem}{suffix}.png` / `{stem}{suffix}-full.png`, where
//!   `suffix` is `-{width}x{height}` iff more than one viewport was
//!   requested and empty otherwise.
//! - the console-event filter: only `console` messages of type `error` or
//!   `warning` are recorded (`log`/`info`/`debug`/etc. are dropped).
//! - the final report text and exit code: `0` unless any `pageerror`
//!   events were observed (`page_errors`), regardless of `console_errors`;
//!   the console-errors section is truncated to the first 20 entries with
//!   a "... and N more" trailer when there are more.
//!
//! CLI argument defaulting (`argparse`'s `default=` values for
//! `--viewports`, `--slides`, `--output`, `--wait`) is ported as
//! [`Args::default`] plus [`parse_viewports_arg`].

use std::path::{Path, PathBuf};

/// One `WxH` viewport request, e.g. `1440x900` (parsed by [`parse_viewport`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
}

/// Error returned by [`parse_viewport`] / [`parse_viewports_arg`] for a
/// malformed `WxH` token, mirroring the Python script's uncaught
/// `ValueError` from `w, h = s.split('x')` / `int(w)` / `int(h)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewportParseError(pub String);

impl std::fmt::Display for ViewportParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid viewport string: {:?}", self.0)
    }
}

impl std::error::Error for ViewportParseError {}

/// Port of `parse_viewport(s)`: splits `"WxH"` on a single literal `x` and
/// parses both halves as `u32` (mirrors Python `int()`, which rejects
/// non-integer or negative-with-leading-minus-as-separate-token strings the
/// same way `str.split('x')` + `int()` would).
///
/// The Python code uses `s.split('x')` with no maxsplit, so it also fails
/// (via a tuple-unpack `ValueError`) on strings with zero or more than one
/// `x`; this is mirrored by requiring exactly two parts.
pub fn parse_viewport(s: &str) -> Result<Viewport, ViewportParseError> {
    let parts: Vec<&str> = s.split('x').collect();
    if parts.len() != 2 {
        return Err(ViewportParseError(s.to_string()));
    }
    let width = parts[0]
        .parse::<u32>()
        .map_err(|_| ViewportParseError(s.to_string()))?;
    let height = parts[1]
        .parse::<u32>()
        .map_err(|_| ViewportParseError(s.to_string()))?;
    Ok(Viewport { width, height })
}

/// Port of `args.viewports.split(",")` mapped through `parse_viewport`,
/// i.e. the `--viewports` CLI argument (default `"1440x900"`).
pub fn parse_viewports_arg(s: &str) -> Result<Vec<Viewport>, ViewportParseError> {
    s.split(',').map(parse_viewport).collect()
}

/// The `--viewports` default (`"1440x900"`), matching `argparse`'s
/// `default="1440x900"`.
pub const DEFAULT_VIEWPORTS_ARG: &str = "1440x900";

/// The `verify_html` default used when `viewports=None` is passed
/// programmatically (`[{'width': 1440, 'height': 900}]`), distinct from
/// the CLI default only in that it bypasses `parse_viewport` entirely.
pub const DEFAULT_VIEWPORT: Viewport = Viewport {
    width: 1440,
    height: 900,
};

/// Port of `argparse`'s remaining `verify.py` CLI defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub html_path: String,
    pub viewports: String,
    pub slides: i64,
    pub output: Option<String>,
    pub show: bool,
    pub wait_ms: u64,
}

impl Args {
    /// `Args` for a bare `verify.py <html_path>` invocation, i.e. every
    /// flag left at its `argparse` default.
    pub fn defaults_for(html_path: impl Into<String>) -> Self {
        Args {
            html_path: html_path.into(),
            viewports: DEFAULT_VIEWPORTS_ARG.to_string(),
            slides: 0,
            output: None,
            show: false,
            wait_ms: 2000,
        }
    }
}

/// Port of `output_dir = html_path.parent / 'screenshots'`, applied when
/// `--output` is not given.
pub fn default_output_dir(html_path: &Path) -> PathBuf {
    html_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(""))
        .join("screenshots")
}

/// Kind of console message observed, restricted to the two kinds the
/// script actually records (`console_errors.append(...) if msg.type in
/// ("error", "warning") else None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleKind {
    Error,
    Warning,
}

impl ConsoleKind {
    fn as_str(self) -> &'static str {
        match self {
            ConsoleKind::Error => "error",
            ConsoleKind::Warning => "warning",
        }
    }
}

/// Port of the `page.on("console", ...)` filter/formatter: returns
/// `Some(f"[{msg.type}] {msg.text}")`-equivalent text iff `msg_type` is
/// `"error"` or `"warning"`, `None` otherwise (any other console message
/// type, e.g. `"log"`/`"info"`/`"debug"`, is dropped).
pub fn format_console_event(msg_type: &str, text: &str) -> Option<String> {
    let kind = match msg_type {
        "error" => ConsoleKind::Error,
        "warning" => ConsoleKind::Warning,
        _ => return None,
    };
    Some(format!("[{}] {}", kind.as_str(), text))
}

/// Port of the `--slides` screenshot filename: `{stem}-slide-{NN}.png`,
/// where `index` is one-based and zero-padded to 2 digits
/// (`str(i + 1).zfill(2)`).
pub fn slide_screenshot_filename(stem: &str, index_one_based: u32) -> String {
    format!("{stem}-slide-{index_one_based:02}.png")
}

/// Port of the non-slides viewport-suffix rule:
/// `f"-{viewport['width']}x{viewport['height']}"` iff more than one
/// viewport was requested, `""` otherwise (`len(viewports) > 1`).
pub fn viewport_suffix(viewport: Viewport, viewport_count: usize) -> String {
    if viewport_count > 1 {
        format!("-{}x{}", viewport.width, viewport.height)
    } else {
        String::new()
    }
}

/// Port of the non-slides screenshot filenames:
/// `f"{stem}{suffix}.png"` (viewport-clipped) and
/// `f"{stem}{suffix}-full.png"` (full page).
pub fn viewport_screenshot_filenames(stem: &str, suffix: &str) -> (String, String) {
    (format!("{stem}{suffix}.png"), format!("{stem}{suffix}-full.png"))
}

/// Result of a `verify_html` run: the pieces of the printed report plus
/// the exit code, decoupled from actually driving a browser.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifyReport {
    pub page_errors: Vec<String>,
    pub console_errors: Vec<String>,
    pub output_dir: PathBuf,
}

impl VerifyReport {
    /// Port of `return 0 if not page_errors else 1`, i.e. `main()`'s exit
    /// code / `verify_html`'s return value.
    pub fn exit_code(&self) -> i32 {
        if self.page_errors.is_empty() {
            0
        } else {
            1
        }
    }

    /// Port of the "验证报告" (verification report) text block printed at
    /// the end of `verify_html`, truncating the console-errors list to its
    /// first 20 entries with a `"... 还有{n}条"` trailer, matching the
    /// Python script's `console_errors[:20]` / `len(console_errors) - 20`.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push('\n');
        out.push_str(&"=".repeat(50));
        out.push('\n');
        out.push_str("验证报告\n");
        out.push_str(&"=".repeat(50));
        out.push('\n');

        if self.page_errors.is_empty() {
            out.push_str("\n✅ 无JavaScript错误\n");
        } else {
            out.push_str(&format!("\n❌ Page Errors ({}):\n", self.page_errors.len()));
            for e in &self.page_errors {
                out.push_str(&format!("  - {e}\n"));
            }
        }

        if self.console_errors.is_empty() {
            out.push_str("✅ Console干净\n");
        } else {
            out.push_str(&format!(
                "\n⚠️  Console Errors/Warnings ({}):\n",
                self.console_errors.len()
            ));
            for e in self.console_errors.iter().take(20) {
                out.push_str(&format!("  - {e}\n"));
            }
            if self.console_errors.len() > 20 {
                out.push_str(&format!(
                    "  ... 还有{}条\n",
                    self.console_errors.len() - 20
                ));
            }
        }

        out.push_str(&format!("\n📸 截图保存至: {}\n", self.output_dir.display()));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_viewport_splits_on_x() {
        assert_eq!(
            parse_viewport("1920x1080").unwrap(),
            Viewport {
                width: 1920,
                height: 1080
            }
        );
    }

    #[test]
    fn parse_viewport_rejects_missing_x() {
        assert!(parse_viewport("1920").is_err());
    }

    #[test]
    fn parse_viewport_rejects_extra_x() {
        assert!(parse_viewport("1920x1080x2").is_err());
    }

    #[test]
    fn parse_viewport_rejects_non_integer() {
        assert!(parse_viewport("1920xtall").is_err());
    }

    #[test]
    fn parse_viewports_arg_splits_on_comma() {
        let vs = parse_viewports_arg("1920x1080,375x667").unwrap();
        assert_eq!(
            vs,
            vec![
                Viewport {
                    width: 1920,
                    height: 1080
                },
                Viewport {
                    width: 375,
                    height: 667
                },
            ]
        );
    }

    #[test]
    fn default_viewports_arg_is_1440x900() {
        assert_eq!(
            parse_viewports_arg(DEFAULT_VIEWPORTS_ARG).unwrap(),
            vec![DEFAULT_VIEWPORT]
        );
    }

    #[test]
    fn default_output_dir_is_screenshots_sibling() {
        let p = Path::new("/a/b/design.html");
        assert_eq!(default_output_dir(p), PathBuf::from("/a/b/screenshots"));
    }

    #[test]
    fn default_output_dir_handles_bare_filename() {
        let p = Path::new("design.html");
        assert_eq!(default_output_dir(p), PathBuf::from("screenshots"));
    }

    #[test]
    fn format_console_event_keeps_error_and_warning() {
        assert_eq!(
            format_console_event("error", "boom").as_deref(),
            Some("[error] boom")
        );
        assert_eq!(
            format_console_event("warning", "careful").as_deref(),
            Some("[warning] careful")
        );
    }

    #[test]
    fn format_console_event_drops_other_kinds() {
        assert_eq!(format_console_event("log", "hi"), None);
        assert_eq!(format_console_event("info", "hi"), None);
        assert_eq!(format_console_event("debug", "hi"), None);
    }

    #[test]
    fn slide_filename_zero_pads_to_two_digits() {
        assert_eq!(slide_screenshot_filename("deck", 1), "deck-slide-01.png");
        assert_eq!(slide_screenshot_filename("deck", 10), "deck-slide-10.png");
        assert_eq!(slide_screenshot_filename("deck", 100), "deck-slide-100.png");
    }

    #[test]
    fn viewport_suffix_empty_for_single_viewport() {
        assert_eq!(viewport_suffix(DEFAULT_VIEWPORT, 1), "");
    }

    #[test]
    fn viewport_suffix_present_for_multiple_viewports() {
        assert_eq!(viewport_suffix(DEFAULT_VIEWPORT, 2), "-1440x900");
    }

    #[test]
    fn viewport_screenshot_filenames_pair() {
        let (clipped, full) = viewport_screenshot_filenames("design", "-1920x1080");
        assert_eq!(clipped, "design-1920x1080.png");
        assert_eq!(full, "design-1920x1080-full.png");
    }

    #[test]
    fn viewport_screenshot_filenames_no_suffix() {
        let (clipped, full) = viewport_screenshot_filenames("design", "");
        assert_eq!(clipped, "design.png");
        assert_eq!(full, "design-full.png");
    }

    #[test]
    fn args_defaults_for_matches_argparse_defaults() {
        let a = Args::defaults_for("design.html");
        assert_eq!(a.viewports, "1440x900");
        assert_eq!(a.slides, 0);
        assert_eq!(a.output, None);
        assert!(!a.show);
        assert_eq!(a.wait_ms, 2000);
    }

    #[test]
    fn report_exit_code_zero_without_page_errors() {
        let r = VerifyReport::default();
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn report_exit_code_one_with_page_errors() {
        let r = VerifyReport {
            page_errors: vec!["TypeError: x is not a function".to_string()],
            ..Default::default()
        };
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn report_render_clean_run() {
        let r = VerifyReport {
            output_dir: PathBuf::from("/tmp/screenshots"),
            ..Default::default()
        };
        let text = r.render();
        assert!(text.contains("✅ 无JavaScript错误"));
        assert!(text.contains("✅ Console干净"));
        assert!(text.contains("📸 截图保存至: /tmp/screenshots"));
    }

    #[test]
    fn report_render_truncates_console_errors_at_20() {
        let console_errors: Vec<String> = (0..25).map(|i| format!("[error] e{i}")).collect();
        let r = VerifyReport {
            console_errors,
            output_dir: PathBuf::from("out"),
            ..Default::default()
        };
        let text = r.render();
        assert!(text.contains("Console Errors/Warnings (25)"));
        assert!(text.contains("... 还有5条"));
        assert!(!text.contains("e24"));
        assert!(text.contains("e19"));
    }

    #[test]
    fn report_render_lists_page_errors() {
        let r = VerifyReport {
            page_errors: vec!["ReferenceError: foo is not defined".to_string()],
            output_dir: PathBuf::from("out"),
            ..Default::default()
        };
        let text = r.render();
        assert!(text.contains("Page Errors (1)"));
        assert!(text.contains("ReferenceError: foo is not defined"));
    }
}
