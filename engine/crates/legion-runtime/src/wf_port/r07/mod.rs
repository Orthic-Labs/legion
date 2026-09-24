//! Rust port of
//! `skills/designer/engine/scripts/detector/engines/browser/detect-url-cdp.mjs`
//! and `.../detect-url.mjs` (packet r07).
//!
//! Both JS files exist to answer one question — "run the Impeccable
//! detector's browser-side script against a real, rendered page at `url`,
//! and return the findings" — through two lanes:
//!
//! * `detect-url.mjs` drives Puppeteer when it's installed (`import('puppeteer')`
//!   succeeds), and otherwise lazily imports `detect-url-cdp.mjs`.
//! * `detect-url-cdp.mjs` is the fallback: it finds an installed Chrome/Edge,
//!   launches it headless, and speaks Chrome DevTools Protocol over a
//!   **hand-rolled raw WebSocket client** (`makeFrame`/`readFrames`/`cdpConnect`)
//!   with no external CDP library.
//!
//! Rust has no Puppeteer equivalent, so the two-lane split collapses to one:
//! this port always drives the browser the way `detect-url-cdp.mjs` does,
//! through the [`ChromeDriver`] trait. The *transport* (raw hand-rolled
//! WebSocket/CDP framing) is replaced by the `headless_chrome` crate — an
//! allowed new dependency for this packet — which owns the same
//! launch/connect/`Runtime.evaluate` responsibilities `cdpConnect` hand-rolled
//! in JS. Everything downstream of the transport (browser-executable
//! discovery, launch args, page-load polling, script injection, design-system
//! serialization, result collection/filtering) is ported faithfully.
//!
//! Module layout:
//! - [`browser`]: `findBrowserExecutable` (browser-executable discovery) and
//!   [`ChromeDriver`] (the trait standing in for `cdpConnect`/`Runtime.evaluate`,
//!   so the scan logic is testable with a fake — no network or real browser
//!   launch in this crate's tests), plus [`real::RealChromeDriver`], the
//!   `headless_chrome`-backed implementation.
//! - [`detect_url`]: `detectUrl`/`detectUrlCdp`/`createBrowserDetector` —
//!   options, design-system serialization for the injected page, the
//!   load/inject/evaluate/collect sequence, and provider filtering.
//! - [`findings`]: `finding()` and `filterByProviders()` from
//!   `detector/findings.mjs` and `detector/registry/antipatterns.mjs`, with
//!   the antipattern registry itself abstracted behind [`findings::AntipatternLookup`]
//!   (the full `ANTIPATTERNS` table is a separate, unported registry file —
//!   out of scope for this packet).
//!
//! **Not ported** (see the r07 report for the exact gap per file):
//! - The hand-rolled WebSocket frame encode/decode (`makeFrame`/`readFrames`)
//!   and raw `cdpConnect` handshake in `detect-url-cdp.mjs`: superseded by
//!   `headless_chrome`, which performs the equivalent job.
//! - The visual-contrast screenshot fallback lane in `detect-url.mjs`
//!   (`runVisualContrastFallback`, `captureVisualContrastCandidate`): it
//!   depends on browser-side globals (`impeccableAnalyzeVisualContrast`,
//!   `impeccableCollectVisualContrastCandidates`) injected by
//!   `detect-antipatterns-browser.js` and on `screenshot-contrast.mjs`,
//!   neither of which is ported in this packet. [`detect_url::detect_url`]
//!   takes a `visual_contrast_findings` hook that defaults to returning no
//!   findings, matching upstream's `options.visualContrast === false` short
//!   circuit exactly; a future packet porting the browser script and
//!   screenshot capture can supply a real hook.
//! - `serializeDesignSystemForBrowser`'s input type, `designSystem`, comes
//!   from `design-system.mjs`, which is itself unported (see the Q0 report).
//!   [`detect_url::DesignSystemInput`] mirrors its JS shape directly so this
//!   packet doesn't block on that one.

pub mod browser;
pub mod detect_url;
pub mod findings;
pub mod real;
pub mod registry;

pub use browser::{find_browser_executable, ChromeDriver, EnvLookup, FsLookup, Platform};
pub use detect_url::{
    detect_url, detect_url_cdp, serialize_design_system_for_browser, DesignSystemInput,
    DetectUrlOptions, Viewport,
};
pub use findings::{finding, filter_by_providers, AntipatternLookup, AntipatternRule, Finding};
pub use real::RealChromeDriver;
pub use registry::RegistryLookup;
