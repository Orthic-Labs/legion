//! Port of `render-video.js`'s pure constants and trim-offset resolution
//! logic.
//!
//! Mirrors [`HIDE_CHROME_CSS`] (the literal CSS injected to hide recording
//! "chrome") and the trim-offset decision at the end of the script:
//! ```js
//! const resolvedTrim = TRIM_OVERRIDE !== null
//!   ? parseFloat(TRIM_OVERRIDE)
//!   : animationStartSec + (hasReady ? 0.05 : 0.5);
//! ```
//!
//! Not ported: launching Playwright/Chromium, the warmup/record context
//! phases, `window.__ready`/`window.__seek` polling, and the final `ffmpeg`
//! trim+encode `spawnSync` call. Those require a headless-browser
//! automation crate (e.g. `chromiumoxide` or `headless_chrome`); neither is
//! present in `engine/Cargo.lock` for this crate, so driving Chromium itself
//! is out of scope for this port (see the port report for the dependency
//! this would need). [`resolve_trim`] gives a Rust caller the same decision
//! `main()` makes once it has measured `animation_start_sec` and `has_ready`
//! by whatever browser-automation means it uses.

/// The literal CSS the script injects via `addInitScript` to hide chrome
/// elements (progress bars, replay buttons, masthead, footer, etc.) during
/// recording, byte-for-byte identical to `render-video.js`'s
/// `HIDE_CHROME_CSS` (and `render-video-seek.js`'s, which duplicates it).
pub const HIDE_CHROME_CSS: &str = "
  .no-record,
  .progress, .progress-bar,
  .counter, .tCur,
  .phases, .phase-label, .phase,
  .replay, button.replay,
  .masthead, .kicker, .title,
  .footer,
  [data-role=\"chrome\"], [data-record=\"hidden\"] {
    display: none !important;
  }
";

/// Resolve the ffmpeg trim offset. Mirrors:
/// ```js
/// const resolvedTrim = TRIM_OVERRIDE !== null
///   ? parseFloat(TRIM_OVERRIDE)
///   : animationStartSec + (hasReady ? 0.05 : 0.5);
/// ```
/// `trim_override` is `--trim=<seconds>` when explicitly passed;
/// `animation_start_sec` is the elapsed wall-clock seconds from context
/// creation to the animation-ready signal (or to the `FONT_WAIT` fallback
/// timeout); `has_ready` is whether `window.__ready` was observed within
/// `READY_TIMEOUT` (vs. falling back to the fixed font-wait).
pub fn resolve_trim(trim_override: Option<f64>, animation_start_sec: f64, has_ready: bool) -> f64 {
    match trim_override {
        Some(t) => t,
        None => animation_start_sec + if has_ready { 0.05 } else { 0.5 },
    }
}
