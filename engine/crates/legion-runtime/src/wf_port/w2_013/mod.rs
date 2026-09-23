//! Port of chunk `w2_013` (area `skills/designer/engine/scripts`, files
//! `detector/engines/static-html/detect-html.mjs`,
//! `detector/engines/visual/screenshot-contrast.mjs`,
//! `detector/findings.mjs`, `detector/node/file-system.mjs`,
//! `detector/profile/profiler.mjs`).
//!
//! ## Scope
//!
//! `findings.mjs`, `node/file-system.mjs`, and `profile/profiler.mjs` are
//! fully pure, deterministic, DOM-free logic and are ported faithfully in
//! [`findings`], [`file_system`], and [`profiler`] respectively.
//!
//! `engines/visual/screenshot-contrast.mjs` and
//! `engines/static-html/detect-html.mjs` are, for the most part, driven by
//! a live browser page (Playwright/Puppeteer `page.screenshot`/
//! `page.evaluate`/canvas pixel readback) or by a parsed-HTML-plus-CSS-
//! cascade "static browser" this chunk does not own — see the module-level
//! doc comments on [`screenshot_contrast`] and [`detect_html`] for exactly
//! what was and wasn't portable, and why (same reasoning `wf_port::w2_011`
//! used for its DOM-injection scripts).

pub mod detect_html;
pub mod file_system;
pub mod findings;
pub mod profiler;
pub mod screenshot_contrast;
