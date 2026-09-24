//! Port of `skills/seo/scripts/capture_screenshot.py` and
//! `skills/seo/scripts/analyze_visual.py` (packet r33 closes the
//! previously-open browser-automation gap).
//!
//! Both scripts are thin CLIs around Playwright (launch headless Chromium,
//! navigate, screenshot/query the DOM). URL scheme normalization/validation
//! (`normalize_url`), the viewport preset table, the SSRF guard that
//! rejects a hostname resolving to a private, loopback, or reserved IP,
//! and `capture_screenshot.py`'s output-path traversal guard were already
//! ported as pure functions. The live page work now runs behind the
//! [`PageBrowser`] trait ([`ChromePageBrowser`] is the production impl,
//! using this crate's existing `headless_chrome` dependency, the same way
//! `r00::gen_deck_thumbs`/`r07::real` drive it): [`run_capture_screenshot`]
//! reproduces `capture_screenshot.py`'s `capture_screenshot()` +
//! `main()`, and [`run_analyze_visual`] reproduces `analyze_visual.py`'s
//! `analyze_visual()`. No test launches a real browser — both are
//! exercised against a fake [`PageBrowser`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};

/// Mirrors `VIEWPORTS` in `capture_screenshot.py` (used identically for the
/// desktop/mobile splits in `analyze_visual.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Viewport {
    pub name: &'static str,
    pub width: u32,
    pub height: u32,
}

pub const VIEWPORTS: &[Viewport] = &[
    Viewport { name: "desktop", width: 1920, height: 1080 },
    Viewport { name: "laptop", width: 1366, height: 768 },
    Viewport { name: "tablet", width: 768, height: 1024 },
    Viewport { name: "mobile", width: 375, height: 812 },
];

pub fn viewport_by_name(name: &str) -> Option<Viewport> {
    VIEWPORTS.iter().copied().find(|v| v.name == name)
}

/// The pieces of `urlparse` this port needs: scheme and hostname (userinfo
/// and port are stripped from the host the way `parsed.hostname` does in
/// Python).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub scheme: String,
    pub hostname: Option<String>,
}

fn parse_url_minimal(url: &str) -> ParsedUrl {
    match url.find("://") {
        Some(idx) => {
            let scheme = url[..idx].to_string();
            let rest = &url[idx + 3..];
            let authority_end = rest
                .find(['/', '?', '#'])
                .unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            // Drop userinfo (before the last '@' in the authority).
            let host_port = match authority.rfind('@') {
                Some(at) => &authority[at + 1..],
                None => authority,
            };
            // IPv6 literal in brackets: hostname is inside the brackets.
            let hostname = if host_port.starts_with('[') {
                host_port
                    .find(']')
                    .map(|end| host_port[1..end].to_string())
            } else {
                let host = match host_port.rfind(':') {
                    Some(colon) => &host_port[..colon],
                    None => host_port,
                };
                if host.is_empty() { None } else { Some(host.to_string()) }
            };
            ParsedUrl { scheme, hostname }
        }
        None => ParsedUrl {
            scheme: String::new(),
            hostname: None,
        },
    }
}

/// Mirrors `normalize_url`: prefix `https://` when there is no scheme,
/// then validate scheme is `http`/`https` and a hostname is present.
/// Returns `(normalized_url, parsed)` on success, or the same error message
/// Python's `ValueError` carried on failure.
pub fn normalize_url(url: &str) -> Result<(String, ParsedUrl), String> {
    let mut parsed = parse_url_minimal(url);
    let mut effective_url = url.to_string();
    if parsed.scheme.is_empty() {
        effective_url = format!("https://{url}");
        parsed = parse_url_minimal(&effective_url);
    }
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return Err(format!("Invalid URL scheme: {}", parsed.scheme));
    }
    if parsed.hostname.is_none() {
        return Err("Invalid URL: missing hostname".to_string());
    }
    Ok((effective_url, parsed))
}

/// Mirrors the SSRF guard: resolve `hostname` and reject a private,
/// loopback, or reserved address. Python swallows `socket.gaierror`
/// (unresolvable host) and lets the request proceed to fail later; this
/// port does the same, returning `Ok(None)` when resolution fails.
///
/// Returns `Ok(Some(ip))` when resolution succeeded and the IP is safe,
/// `Err(message)` matching Python's `Blocked: URL resolves to
/// private/internal IP (<ip>)` when it is not, and `Ok(None)` when the
/// hostname could not be resolved at all.
pub fn check_ssrf(hostname: &str) -> Result<Option<IpAddr>, String> {
    let resolved = (hostname, 0u16).to_socket_addrs();
    let ip = match resolved {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip(),
            None => return Ok(None),
        },
        Err(_) => return Ok(None),
    };
    if is_blocked_ip(ip) {
        return Err(format!(
            "Blocked: URL resolves to private/internal IP ({ip})"
        ));
    }
    Ok(Some(ip))
}

/// Mirrors `ip.is_private or ip.is_loopback or ip.is_reserved` from
/// Python's `ipaddress` module.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4) || v4.is_loopback() || is_reserved_v4(v4),
        IpAddr::V6(v6) => is_loopback_or_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    // Matches Python ipaddress.IPv4Address.is_private for the common RFC
    // 1918 + link-local + CGNAT ranges (mirrors Ipv4Addr::is_private plus
    // link-local, matching Python's broader definition).
    ip.is_private() || ip.is_link_local()
}

fn is_reserved_v4(ip: Ipv4Addr) -> bool {
    // Python's is_reserved covers 240.0.0.0/4 (class E) among others; this
    // is the practically relevant subset for an SSRF guard.
    let o = ip.octets();
    o[0] >= 240 || ip.is_broadcast() || ip.is_unspecified()
}

fn is_loopback_or_private_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Mirrors `capture_screenshot.py`'s output-path traversal guard: the
/// resolved output directory must start with either the current directory
/// or the home directory.
pub fn output_dir_allowed(resolved_output_dir: &str, cwd: &str, home: &str) -> bool {
    resolved_output_dir.starts_with(cwd) || resolved_output_dir.starts_with(home)
}

/// Mirrors the filename Python builds from the parsed URL's netloc:
/// `{netloc.replace('.', '_')}_{viewport}.png`. `netloc` here is taken as
/// `hostname` (the scripts never pass a URL with userinfo/port through this
/// path), matching the common case.
pub fn screenshot_filename(hostname: &str, viewport: &str) -> String {
    format!("{}_{}.png", hostname.replace('.', "_"), viewport)
}

/// A DOM element's bounding box, as far as either script inspects it
/// (`bounding_box()["y"]` is the only field either script reads).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BoundingBox {
    pub y: f64,
}

/// Live-page boundary both scripts need: navigate, then query the DOM /
/// capture pixels. Mirrors the small slice of Playwright's `Page` API each
/// script actually calls (`goto`, `query_selector`+`bounding_box`,
/// `get_attribute`, `evaluate`, `screenshot`), generalized so both
/// `capture_screenshot.py` and `analyze_visual.py` share one trait.
pub trait PageBrowser {
    /// `browser.new_context(viewport=...)` + `page = ctx.new_page()`:
    /// (re)configures the viewport a subsequent `goto` renders at.
    fn set_viewport(&mut self, width: u32, height: u32, device_scale_factor: f64) -> Result<(), String>;
    /// `page.goto(url, wait_until="networkidle", timeout=timeout)`.
    /// Returns `Err(BrowserError::Timeout)` on a Playwright timeout
    /// (mirrors `PlaywrightTimeout`), `Err(BrowserError::Other(..))` for
    /// any other navigation failure.
    fn goto(&mut self, url: &str, timeout_ms: u64) -> Result<(), BrowserError>;
    /// `page.wait_for_timeout(ms)`.
    fn wait_ms(&mut self, ms: u64);
    /// `page.query_selector(selector).bounding_box()`: `None` if the
    /// selector matches nothing, or matches an element with no box.
    fn bounding_box(&mut self, selector: &str) -> Option<BoundingBox>;
    /// `page.query_selector(selector).get_attribute(attr)`.
    fn attribute(&mut self, selector: &str, attr: &str) -> Option<String>;
    /// `page.query_selector('meta[name="viewport"]') is not None`.
    fn exists(&mut self, selector: &str) -> bool;
    /// `page.evaluate(js)` for a numeric result (`scrollWidth`,
    /// `innerWidth`, computed `fontSize`).
    fn eval_number(&mut self, js: &str) -> Option<f64>;
    /// `page.screenshot(path=..., full_page=full_page)`, returning the PNG
    /// bytes for the caller to write.
    fn screenshot_png(&mut self, full_page: bool) -> Result<Vec<u8>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserError {
    Timeout,
    Other(String),
}

/// CTA selectors, in the order `capture_visual`'s loop tries them.
pub const CTA_SELECTORS: &[&str] = &[
    "a[href*='signup']",
    "a[href*='contact']",
    "a[href*='demo']",
    "button:has-text('Get Started')",
    "button:has-text('Sign Up')",
    "button:has-text('Contact')",
    ".cta",
    "[class*='cta']",
];

/// Hero-image selectors, in the order `analyze_visual`'s loop tries them.
pub const HERO_SELECTORS: &[&str] = &[
    ".hero img",
    "[class*='hero'] img",
    "header img",
    "main img:first-of-type",
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AboveFold {
    pub h1_visible: bool,
    pub cta_visible: bool,
    pub hero_image: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MobileResult {
    pub viewport_meta: bool,
    pub horizontal_scroll: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FontsResult {
    pub base_size: Option<f64>,
    pub readable: bool,
}

/// `analyze_visual()`'s full result dict.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AnalyzeResult {
    pub url: String,
    pub above_fold: AboveFold,
    pub mobile: MobileResult,
    pub fonts: FontsResult,
    pub error: Option<String>,
}

/// `analyze_visual(url, timeout)`: normalize, SSRF-check, then run the
/// desktop pass (H1/CTA/hero above the fold) and the mobile pass (viewport
/// meta, horizontal scroll, base font size) against `browser`. Mirrors the
/// Python function's early-return `error` paths exactly (bad URL, blocked
/// IP, timeout, any other exception message).
pub fn run_analyze_visual(browser: &mut dyn PageBrowser, url: &str, timeout_ms: u64) -> AnalyzeResult {
    let mut result = AnalyzeResult {
        url: url.to_string(),
        fonts: FontsResult { base_size: None, readable: true },
        ..Default::default()
    };

    let (normalized, parsed) = match normalize_url(url) {
        Ok(pair) => pair,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };
    result.url = normalized.clone();

    if let Some(hostname) = &parsed.hostname {
        if let Err(e) = check_ssrf(hostname) {
            result.error = Some(e);
            return result;
        }
    }

    // Desktop pass.
    if let Err(e) = browser.set_viewport(1920, 1080, 1.0) {
        result.error = Some(e);
        return result;
    }
    if let Err(e) = browser.goto(&normalized, timeout_ms) {
        result.error = Some(browser_error_message(e, timeout_ms));
        return result;
    }

    if let Some(bbox) = browser.bounding_box("h1") {
        if bbox.y < 1080.0 {
            result.above_fold.h1_visible = true;
        }
    }
    for selector in CTA_SELECTORS {
        if let Some(bbox) = browser.bounding_box(selector) {
            if bbox.y < 1080.0 {
                result.above_fold.cta_visible = true;
                break;
            }
        }
    }
    for selector in HERO_SELECTORS {
        if let Some(src) = browser.attribute(selector, "src") {
            result.above_fold.hero_image = Some(src);
            break;
        }
    }

    // Mobile pass.
    if let Err(e) = browser.set_viewport(375, 812, 1.0) {
        result.error = Some(e);
        return result;
    }
    if let Err(e) = browser.goto(&normalized, timeout_ms) {
        result.error = Some(browser_error_message(e, timeout_ms));
        return result;
    }

    result.mobile.viewport_meta = browser.exists("meta[name=\"viewport\"]");
    let scroll_width = browser.eval_number("document.documentElement.scrollWidth");
    let viewport_width = browser.eval_number("window.innerWidth");
    result.mobile.horizontal_scroll = match (scroll_width, viewport_width) {
        (Some(s), Some(v)) => s > v,
        _ => false,
    };
    let base_font_size = browser.eval_number(
        "(() => { const s = window.getComputedStyle(document.body); return parseFloat(s.fontSize); })()",
    );
    result.fonts.base_size = base_font_size;
    result.fonts.readable = base_font_size.map(|v| v >= 16.0).unwrap_or(true);

    result
}

fn browser_error_message(e: BrowserError, timeout_ms: u64) -> String {
    match e {
        BrowserError::Timeout => format!("Page load timed out after {timeout_ms}ms"),
        BrowserError::Other(msg) => msg,
    }
}

/// `capture_screenshot()`'s result dict.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaptureResult {
    pub url: String,
    pub output: String,
    pub viewport: String,
    pub success: bool,
    pub error: Option<String>,
}

/// `capture_screenshot(url, output_path, viewport, full_page, timeout)`:
/// validate viewport name, normalize URL, SSRF-check, then navigate,
/// settle 1000ms, and screenshot. The PNG bytes are handed to `write` for
/// the caller to persist (mirrors `page.screenshot(path=output_path,
/// ...)`, kept as an injected callback so this function itself touches no
/// filesystem).
pub fn run_capture_screenshot(
    browser: &mut dyn PageBrowser,
    url: &str,
    output_path: &str,
    viewport: &str,
    full_page: bool,
    timeout_ms: u64,
    write: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> CaptureResult {
    let mut result = CaptureResult {
        url: url.to_string(),
        output: output_path.to_string(),
        viewport: viewport.to_string(),
        success: false,
        error: None,
    };

    let Some(vp) = viewport_by_name(viewport) else {
        let names: Vec<&str> = VIEWPORTS.iter().map(|v| v.name).collect();
        result.error = Some(format!("Invalid viewport: {viewport}. Choose from: {names:?}"));
        return result;
    };

    let (normalized, parsed) = match normalize_url(url) {
        Ok(pair) => pair,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };
    result.url = normalized.clone();

    if let Some(hostname) = &parsed.hostname {
        if let Err(e) = check_ssrf(hostname) {
            result.error = Some(e);
            return result;
        }
    }

    let device_scale_factor = if viewport == "mobile" { 2.0 } else { 1.0 };
    if let Err(e) = browser.set_viewport(vp.width, vp.height, device_scale_factor) {
        result.error = Some(e);
        return result;
    }
    if let Err(e) = browser.goto(&normalized, timeout_ms) {
        result.error = Some(browser_error_message(e, timeout_ms));
        return result;
    }
    browser.wait_ms(1000);

    match browser.screenshot_png(full_page) {
        Ok(bytes) => match write(&bytes) {
            Ok(()) => {
                result.success = true;
            }
            Err(e) => {
                result.error = Some(e.to_string());
            }
        },
        Err(e) => {
            result.error = Some(e);
        }
    }

    result
}

/// `main()`'s output-path sanitization: `os.path.realpath(output)` must
/// start with `cwd` or `home` (matches [`output_dir_allowed`], kept
/// separate so the realpath resolution stays with the caller — this crate
/// has no canonicalization dependency requirement beyond `std::fs`).
pub fn resolve_and_check_output_dir(output: &Path, cwd: &Path, home: &Path) -> Result<PathBuf, String> {
    let resolved = std::fs::canonicalize(output).unwrap_or_else(|_| {
        // realpath() on a not-yet-created dir still resolves symlinks in
        // the existing prefix; std::fs::canonicalize requires the path to
        // exist, so fall back to the (already-absolute-ized) raw path the
        // same way Python's os.path.realpath does for a missing leaf.
        if output.is_absolute() {
            output.to_path_buf()
        } else {
            cwd.join(output)
        }
    });
    let resolved_str = resolved.to_string_lossy().to_string();
    if output_dir_allowed(&resolved_str, &cwd.to_string_lossy(), &home.to_string_lossy()) {
        Ok(resolved)
    } else {
        Err("Output path must be within current directory or home directory".to_string())
    }
}

/// Production [`PageBrowser`]: a real Chromium tab via `headless_chrome`,
/// same pattern as `r00::gen_deck_thumbs::ChromeThumbBrowser` and
/// `r07::real::RealChromeDriver`. Not exercised by this crate's tests (no
/// real browser launched in tests, per the packet's rule); only
/// [`run_analyze_visual`]/[`run_capture_screenshot`] are tested, against a
/// fake [`PageBrowser`].
pub struct ChromePageBrowser {
    _browser: headless_chrome::Browser,
    tab: std::sync::Arc<headless_chrome::Tab>,
}

impl ChromePageBrowser {
    pub fn launch() -> Result<Self, String> {
        let browser = headless_chrome::Browser::default().map_err(|e| e.to_string())?;
        let tab = browser.new_tab().map_err(|e| e.to_string())?;
        Ok(Self { _browser: browser, tab })
    }
}

impl PageBrowser for ChromePageBrowser {
    fn set_viewport(&mut self, width: u32, height: u32, device_scale_factor: f64) -> Result<(), String> {
        self.tab
            .call_method(headless_chrome::protocol::cdp::Emulation::SetDeviceMetricsOverride {
                width,
                height,
                device_scale_factor,
                mobile: device_scale_factor > 1.0,
                scale: None,
                screen_width: None,
                screen_height: None,
                position_x: None,
                position_y: None,
                dont_set_visible_size: None,
                screen_orientation: None,
                viewport: None,
                display_feature: None,
                device_posture: None,
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn goto(&mut self, url: &str, _timeout_ms: u64) -> Result<(), BrowserError> {
        self.tab
            .navigate_to(url)
            .map_err(|e| BrowserError::Other(e.to_string()))?;
        self.tab
            .wait_until_navigated()
            .map(|_| ())
            .map_err(|_| BrowserError::Timeout)
    }

    fn wait_ms(&mut self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    fn bounding_box(&mut self, selector: &str) -> Option<BoundingBox> {
        let el = self.tab.find_element(selector).ok()?;
        let box_model = el.get_box_model().ok()?;
        Some(BoundingBox { y: box_model.content.most_top() })
    }

    fn attribute(&mut self, selector: &str, attr: &str) -> Option<String> {
        let el = self.tab.find_element(selector).ok()?;
        el.get_attribute_value(attr).ok().flatten()
    }

    fn exists(&mut self, selector: &str) -> bool {
        self.tab.find_element(selector).is_ok()
    }

    fn eval_number(&mut self, js: &str) -> Option<f64> {
        let remote = self.tab.evaluate(js, false).ok()?;
        remote.value.as_ref().and_then(serde_json::Value::as_f64)
    }

    fn screenshot_png(&mut self, full_page: bool) -> Result<Vec<u8>, String> {
        self.tab
            .capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                None,
                None,
                full_page,
            )
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakePage {
        viewport: Option<(u32, u32, f64)>,
        goto_result: Option<Result<(), BrowserError>>,
        boxes: HashMap<&'static str, BoundingBox>,
        attrs: HashMap<(&'static str, &'static str), String>,
        exists: HashMap<&'static str, bool>,
        evals: HashMap<&'static str, f64>,
        screenshot: Option<Result<Vec<u8>, String>>,
    }

    impl PageBrowser for FakePage {
        fn set_viewport(&mut self, w: u32, h: u32, dsf: f64) -> Result<(), String> {
            self.viewport = Some((w, h, dsf));
            Ok(())
        }
        fn goto(&mut self, _url: &str, _timeout_ms: u64) -> Result<(), BrowserError> {
            self.goto_result.clone().unwrap_or(Ok(()))
        }
        fn wait_ms(&mut self, _ms: u64) {}
        fn bounding_box(&mut self, selector: &str) -> Option<BoundingBox> {
            self.boxes.get(selector).copied()
        }
        fn attribute(&mut self, selector: &str, attr: &str) -> Option<String> {
            self.attrs
                .iter()
                .find(|((s, a), _)| *s == selector && *a == attr)
                .map(|(_, v)| v.clone())
        }
        fn exists(&mut self, selector: &str) -> bool {
            *self.exists.get(selector).unwrap_or(&false)
        }
        fn eval_number(&mut self, js: &str) -> Option<f64> {
            self.evals.get(js).copied()
        }
        fn screenshot_png(&mut self, _full_page: bool) -> Result<Vec<u8>, String> {
            self.screenshot.clone().unwrap_or_else(|| Ok(vec![0x89, b'P', b'N', b'G']))
        }
    }

    #[test]
    fn analyze_visual_detects_h1_and_cta_above_fold() {
        let mut page = FakePage::default();
        page.boxes.insert("h1", BoundingBox { y: 100.0 });
        page.boxes.insert("a[href*='signup']", BoundingBox { y: 200.0 });
        page.attrs.insert((".hero img", "src"), "hero.png".to_string());
        page.exists.insert("meta[name=\"viewport\"]", true);
        page.evals.insert("document.documentElement.scrollWidth", 375.0);
        page.evals.insert("window.innerWidth", 375.0);
        page.evals.insert(
            "(() => { const s = window.getComputedStyle(document.body); return parseFloat(s.fontSize); })()",
            18.0,
        );

        let result = run_analyze_visual(&mut page, "example.com", 30_000);
        assert_eq!(result.url, "https://example.com");
        assert!(result.above_fold.h1_visible);
        assert!(result.above_fold.cta_visible);
        assert_eq!(result.above_fold.hero_image, Some("hero.png".to_string()));
        assert!(result.mobile.viewport_meta);
        assert!(!result.mobile.horizontal_scroll);
        assert_eq!(result.fonts.base_size, Some(18.0));
        assert!(result.fonts.readable);
        assert!(result.error.is_none());
    }

    #[test]
    fn analyze_visual_rejects_invalid_scheme() {
        let mut page = FakePage::default();
        let result = run_analyze_visual(&mut page, "ftp://example.com", 30_000);
        assert_eq!(result.error, Some("Invalid URL scheme: ftp".to_string()));
    }

    #[test]
    fn analyze_visual_blocks_private_ip_hostname() {
        let mut page = FakePage::default();
        let result = run_analyze_visual(&mut page, "http://127.0.0.1", 30_000);
        assert!(result.error.unwrap().starts_with("Blocked: URL resolves to private/internal IP"));
    }

    #[test]
    fn analyze_visual_surfaces_timeout_message() {
        let mut page = FakePage {
            goto_result: Some(Err(BrowserError::Timeout)),
            ..Default::default()
        };
        let result = run_analyze_visual(&mut page, "example.com", 5_000);
        assert_eq!(result.error, Some("Page load timed out after 5000ms".to_string()));
    }

    #[test]
    fn analyze_visual_flags_narrow_font_and_horizontal_scroll() {
        let mut page = FakePage::default();
        page.evals.insert("document.documentElement.scrollWidth", 500.0);
        page.evals.insert("window.innerWidth", 375.0);
        page.evals.insert(
            "(() => { const s = window.getComputedStyle(document.body); return parseFloat(s.fontSize); })()",
            12.0,
        );
        let result = run_analyze_visual(&mut page, "example.com", 30_000);
        assert!(result.mobile.horizontal_scroll);
        assert!(!result.fonts.readable);
    }

    #[test]
    fn capture_screenshot_rejects_unknown_viewport() {
        let mut page = FakePage::default();
        let mut writes = Vec::new();
        let result = run_capture_screenshot(&mut page, "example.com", "out.png", "ultrawide", false, 30_000, &mut |b| {
            writes.extend_from_slice(b);
            Ok(())
        });
        assert!(!result.success);
        assert!(result.error.unwrap().starts_with("Invalid viewport"));
        assert!(writes.is_empty());
    }

    #[test]
    fn capture_screenshot_writes_bytes_on_success() {
        let mut page = FakePage {
            screenshot: Some(Ok(vec![1, 2, 3])),
            ..Default::default()
        };
        let mut writes = Vec::new();
        let result = run_capture_screenshot(&mut page, "example.com", "out.png", "mobile", true, 30_000, &mut |b| {
            writes.extend_from_slice(b);
            Ok(())
        });
        assert!(result.success);
        assert_eq!(writes, vec![1, 2, 3]);
        assert_eq!(page.viewport, Some((375, 812, 2.0)));
    }

    #[test]
    fn capture_screenshot_surfaces_ssrf_block() {
        let mut page = FakePage::default();
        let mut writes = Vec::new();
        let result = run_capture_screenshot(&mut page, "http://localhost", "out.png", "desktop", false, 30_000, &mut |b| {
            writes.extend_from_slice(b);
            Ok(())
        });
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn resolve_and_check_output_dir_allows_cwd_prefix() {
        let cwd = Path::new("/home/user/project");
        let home = Path::new("/home/user");
        let out = cwd.join("screenshots");
        // Falls back to the raw joined path since the dir need not exist.
        let resolved = resolve_and_check_output_dir(&out, cwd, home);
        assert!(resolved.is_ok());
    }

    #[test]
    fn resolve_and_check_output_dir_rejects_traversal_outside_home() {
        let cwd = Path::new("/home/user/project");
        let home = Path::new("/home/user");
        let out = Path::new("/etc/passwd_dir");
        let resolved = resolve_and_check_output_dir(out, cwd, home);
        assert!(resolved.is_err());
    }
}
