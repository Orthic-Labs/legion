//! `headless_chrome`-backed [`ChromeDriver`]: the real transport that
//! replaces `detect-url-cdp.mjs`'s hand-rolled `launchHeadless` +
//! `findPageTarget` + `cdpConnect` + `runtimeEval`. See the module doc on
//! [`super`] for why this crate is the allowed replacement for that raw
//! WebSocket client rather than a re-implementation of it.
//!
//! Not exercised by this crate's tests (per the packet's "no real browser in
//! tests" rule) — only [`super::detect_url`]'s pure logic, against a fake
//! driver, is tested here.

use headless_chrome::{Browser, LaunchOptions};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use super::browser::ChromeDriver;

/// Owns a headless browser + single tab, navigated fresh for each
/// [`RealChromeDriver::new`] call — mirrors `detectUrlCdp` launching one
/// short-lived browser per scan.
pub struct RealChromeDriver {
    _browser: Browser,
    tab: std::sync::Arc<headless_chrome::Tab>,
}

impl RealChromeDriver {
    /// Launches headless Chrome/Edge at `executable` sized to `viewport`,
    /// mirroring `launchHeadless`'s `--headless=new --window-size=W,H
    /// --no-first-run --no-default-browser-check --disable-extensions
    /// --disable-background-networking` flags (a fresh, isolated profile dir
    /// is `headless_chrome`'s default behaviour, matching JS's per-launch
    /// `--user-data-dir`).
    pub fn new(
        executable: PathBuf,
        viewport: super::detect_url::Viewport,
    ) -> Result<Self, String> {
        let args: Vec<&OsStr> = vec![
            OsStr::new("--no-first-run"),
            OsStr::new("--no-default-browser-check"),
            OsStr::new("--disable-extensions"),
            OsStr::new("--disable-background-networking"),
        ];
        let launch_options = LaunchOptions::default_builder()
            .path(Some(executable))
            .headless(true)
            .window_size(Some((viewport.width, viewport.height)))
            .idle_browser_timeout(Duration::from_secs(30))
            .args(args)
            .build()
            .map_err(|e| e.to_string())?;
        let browser = Browser::new(launch_options).map_err(|e| e.to_string())?;
        let tab = browser.new_tab().map_err(|e| e.to_string())?;
        Ok(RealChromeDriver {
            _browser: browser,
            tab,
        })
    }
}

impl ChromeDriver for RealChromeDriver {
    fn navigate(&mut self, url: &str) -> Result<(), String> {
        // Mirrors `Page.navigate` + the `document.readyState === 'complete'`
        // poll loop's 30s timeout in `detectUrlCdp`.
        self.tab
            .navigate_to(url)
            .map_err(|e| e.to_string())?;
        self.tab
            .wait_until_navigated()
            .map_err(|e| format!("Timed out loading {url}: {e}"))?;
        Ok(())
    }

    fn evaluate(&mut self, expression: &str) -> Result<serde_json::Value, String> {
        // Mirrors `runtimeEval`: `Runtime.evaluate` with `awaitPromise: true,
        // returnByValue: true`, surfacing an exception as `Err`.
        let remote_object = self
            .tab
            .evaluate(expression, true)
            .map_err(|e| e.to_string())?;
        Ok(remote_object.value.unwrap_or(serde_json::Value::Null))
    }
}
