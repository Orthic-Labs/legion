//! Port of `findBrowserExecutable` from `detect-url-cdp.mjs`, plus the
//! [`ChromeDriver`] trait standing in for the rest of that file's job
//! (`launchHeadless` + `cdpConnect` + `runtimeEval`): given a URL, drive a
//! real page load and evaluate JS in it, without this crate's tests ever
//! needing a real browser or network access.

use std::path::PathBuf;

/// Mirrors the `process.platform === 'win32'` branch in
/// `findBrowserExecutable`. JS reads this from the live process; the port
/// takes it as a parameter so both branches are unit-testable on any host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Other,
}

/// Stands in for `process.env` reads (`CHROME_PATH`, `QA_BROWSER`, `HOME`,
/// `USERPROFILE`, `ProgramFiles`, `ProgramFiles(x86)`), so tests can supply a
/// fixed environment instead of the real process environment.
pub trait EnvLookup {
    fn get(&self, key: &str) -> Option<String>;
}

/// Real process-environment-backed [`EnvLookup`], used by production callers.
pub struct ProcessEnv;

impl EnvLookup for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Stands in for `fs.existsSync` in the candidate-path probe.
pub trait FsLookup {
    fn exists(&self, path: &str) -> bool;
}

/// Real filesystem-backed [`FsLookup`].
pub struct RealFs;

impl FsLookup for RealFs {
    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
}

/// Port of `findBrowserExecutable()`. Same override/candidate-list/error
/// behaviour as the JS: `CHROME_PATH`/`QA_BROWSER` win outright (and a
/// missing override path is a hard error, exactly like JS's
/// `if (!fs.existsSync(override)) throw ...`), otherwise the first existing
/// candidate from the platform-specific list wins, otherwise
/// `Err("URL scanning needs puppeteer or an installed Chrome/Edge. Neither was found.")`
/// (JS's message, kept verbatim even though this Rust port has no Puppeteer
/// lane — see the packet's module doc for why).
pub fn find_browser_executable(
    platform: Platform,
    env: &impl EnvLookup,
    fs: &impl FsLookup,
) -> Result<PathBuf, String> {
    if let Some(override_path) = env.get("CHROME_PATH").or_else(|| env.get("QA_BROWSER")) {
        if !fs.exists(&override_path) {
            return Err(format!(
                "CHROME_PATH/QA_BROWSER set but not found: {override_path}"
            ));
        }
        return Ok(PathBuf::from(override_path));
    }

    let home = env
        .get("HOME")
        .or_else(|| env.get("USERPROFILE"))
        .unwrap_or_default();

    let candidates: Vec<String> = if platform == Platform::Windows {
        let program_files = env
            .get("ProgramFiles")
            .unwrap_or_else(|| "C:\\Program Files".to_string());
        let program_files_x86 = env
            .get("ProgramFiles(x86)")
            .unwrap_or_else(|| "C:\\Program Files (x86)".to_string());
        vec![
            join_windows(&program_files, "Google\\Chrome\\Application\\chrome.exe"),
            join_windows(
                &program_files_x86,
                "Google\\Chrome\\Application\\chrome.exe",
            ),
            join_windows(&program_files, "Microsoft\\Edge\\Application\\msedge.exe"),
            join_windows(
                &program_files_x86,
                "Microsoft\\Edge\\Application\\msedge.exe",
            ),
        ]
    } else {
        vec![
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string(),
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".to_string(),
            "/Applications/Chromium.app/Contents/MacOS/Chromium".to_string(),
            join(
                &home,
                ".local/chrome-for-testing/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            ),
            join(
                &home,
                ".local/chrome-for-testing/chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            ),
            "/usr/bin/google-chrome".to_string(),
            "/usr/bin/chromium".to_string(),
            "/usr/bin/chromium-browser".to_string(),
            "/usr/bin/microsoft-edge".to_string(),
        ]
    };

    match candidates.into_iter().find(|p| fs.exists(p)) {
        Some(found) => Ok(PathBuf::from(found)),
        None => {
            Err("URL scanning needs puppeteer or an installed Chrome/Edge. Neither was found.".to_string())
        }
    }
}

fn join(base: &str, rest: &str) -> String {
    // Mirrors `path.join(home, ...)`: a trailing separator on `base` is
    // collapsed, matching Node's `path.join` normalization.
    let trimmed = base.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        rest.to_string()
    } else {
        format!("{trimmed}/{rest}")
    }
}

/// Windows variant of [`join`]: on the real Windows host, Node's default
/// `path` module is `path.win32`, which joins with `\` — unlike the POSIX
/// join used for the non-Windows candidate list above.
fn join_windows(base: &str, rest: &str) -> String {
    let trimmed = base.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        rest.to_string()
    } else {
        format!("{trimmed}\\{rest}")
    }
}

/// Stands in for `launchHeadless` + `findPageTarget` + `cdpConnect` +
/// `runtimeEval` from `detect-url-cdp.mjs`: launch/attach to a page, drive it
/// to `url`, and evaluate JS in page context. The real implementation
/// ([`super::real::RealChromeDriver`]) is backed by the `headless_chrome`
/// crate, which owns the WebSocket/CDP transport `cdpConnect` hand-rolled in
/// JS. Tests in this crate use a fake implementation instead.
pub trait ChromeDriver {
    /// Navigate to `url` and block until the page has finished loading
    /// (mirrors the `Page.navigate` + `document.readyState === 'complete'`
    /// poll loop, timing out like JS's 30s `Timed out loading {url}`).
    fn navigate(&mut self, url: &str) -> Result<(), String>;

    /// Evaluate `expression` in page context and return its JSON-serializable
    /// result (mirrors `runtimeEval`'s `Runtime.evaluate` call with
    /// `returnByValue: true`, surfacing `exceptionDetails` as an `Err`).
    fn evaluate(&mut self, expression: &str) -> Result<serde_json::Value, String>;
}
