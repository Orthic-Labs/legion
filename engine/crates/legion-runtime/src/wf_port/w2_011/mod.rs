//! Port of chunk `w2_011` (area `skills/designer/engine/scripts/detector`,
//! files `browser/injected/index.mjs`, `cli/main.mjs`, `design-system.mjs`,
//! `detect-antipatterns-browser.js`, `detect-antipatterns.mjs`).
//!
//! ## Scope
//!
//! `detect-antipatterns.mjs` is a pure re-export facade (it imports and
//! re-exports symbols from `registry/`, `shared/`, `rules/`, `profile/`,
//! `engines/`, `node/`, none of which are owned by this chunk) plus a
//! `require.main`-style `if (isMainModule) detectCli();` guard. It contains
//! no logic of its own to port.
//!
//! `browser/injected/index.mjs` and `detect-antipatterns-browser.js` are
//! **browser-injected** scripts: they execute inside a live page's DOM
//! (`window`, `document`, `getComputedStyle`, `MutationObserver`, CSS
//! injection for hover/spotlight overlays, `postMessage`). They are not
//! server-side logic — running them requires an actual browser JS runtime
//! with a live DOM, which a Rust binary does not have. `detect-antipatterns-browser.js`
//! is confirmed (by its own header comment) to be a hand-maintained bundle
//! of `browser/injected/index.mjs` plus the detector's shared rule/check
//! modules for `<script>`-tag injection into a scanned page. There is no
//! faithful "port" of a DOM-injection script to a non-DOM binary; this
//! functionality stays JS-only by nature and is not attempted here. (A
//! future native browser-automation host, if legion drives an actual
//! browser via CDP, could re-inject this same JS payload rather than a
//! Rust reimplementation — porting to Rust would not remove the DOM
//! dependency, only relocate it.)
//!
//! What *is* pure, deterministic, DOM-free logic in this chunk, and is
//! ported below with unit tests mirroring the JS behaviour:
//!
//! - from `cli/main.mjs`: [`format_finding_summary`], [`format_findings`]
//!   (text/JSON finding formatting), and [`usage_text`] (`--help` output).
//! - from `design-system.mjs`: the `DESIGN.md` frontmatter YAML-subset
//!   parser ([`parse_frontmatter`]), design-system normalization
//!   ([`normalize_design_system`]), font/color/radius allow-list checks
//!   ([`is_allowed_font`], [`is_allowed_color_raw`], [`is_allowed_radius_raw`]),
//!   the regex-based *source* scan ([`check_source_design_system`]), and the
//!   finding merge/dedupe helpers ([`merge_design_system_findings`],
//!   [`dedupe_design_findings`]).
//!
//! Not ported (DOM-dependent, same reasoning as above):
//! `collectStaticDesignSystemFindings` — it walks a live `document` via
//! `document.querySelectorAll('*')` and reads computed styles via
//! `window.getComputedStyle(el)`; there is no parsed-HTML-plus-computed-style
//! engine owned by this chunk to drive it against. `loadDesignSystemForCwd`'s
//! *filesystem-independent* piece ([`normalize_design_system`]) is ported;
//! its `fs`/`path` wrapper (`resolveDesignMdPath` / `resolveDesignSidecarPath`
//! / `safeReadJson`) is trivial glue left for the integrator to wire against
//! whatever file-reading primitives `legion-runtime` uses elsewhere — read
//! `DESIGN.md`, call [`parse_frontmatter`], then [`normalize_design_system`].

pub mod cli_output;
pub mod design_system;

pub use cli_output::{format_finding_summary, format_findings, usage_text, Finding};
pub use design_system::{
    check_source_design_system, dedupe_design_findings, is_allowed_color_raw, is_allowed_font,
    is_allowed_radius_raw, merge_design_system_findings, normalize_design_system,
    parse_frontmatter, DesignFinding, DesignSystem, FrontmatterValue,
};
