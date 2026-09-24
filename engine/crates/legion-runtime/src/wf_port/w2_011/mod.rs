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
//! (packet r06 closed the remaining two gaps in `design-system.mjs`:)
//!
//! - `resolveDesignMdPath` / `resolveDesignSidecarPath` / `safeReadJson` /
//!   `loadDesignSystemForCwd` — the `fs`/`path` wrapper around
//!   [`normalize_design_system`] — ported in [`design_system_fs`], with
//!   filesystem access behind [`design_system_fs::DesignFs`] so it is
//!   unit-tested with a fake in-memory filesystem.
//! - `collectStaticDesignSystemFindings` (plus `shouldSkipStaticDesignElement`
//!   / `hasDirectText` / `sampleText`) — ported in [`design_system_dom`].
//!   The DOM walk + `getComputedStyle` read (real CSS-cascade work no
//!   engine in this crate reproduces) runs behind
//!   [`design_system_dom::DesignDomEvaluator`], with a real Chromium
//!   backend ([`design_system_dom::ChromeDesignDomEvaluator`], via
//!   `headless_chrome`, same pattern as this crate's other browser-backed
//!   ports) and unit tests driven by a fake evaluator (no real browser
//!   launched in tests). The allow-list decisions and finding
//!   construction/dedup on top of the observed styles are plain Rust,
//!   reusing [`is_allowed_font`] / [`is_allowed_color_raw`] /
//!   [`is_allowed_radius_raw`] from [`design_system`].

pub mod cli_output;
pub mod design_system;
pub mod design_system_dom;
pub mod design_system_fs;

pub use cli_output::{format_finding_summary, format_findings, usage_text, Finding};
pub use design_system::{
    check_source_design_system, dedupe_design_findings, is_allowed_color_raw, is_allowed_font,
    is_allowed_radius_raw, merge_design_system_findings, normalize_design_system,
    parse_frontmatter, DesignFinding, DesignSystem, FrontmatterValue,
};
pub use design_system_dom::{
    collect_static_design_system_findings, ChromeDesignDomEvaluator, DesignDomEvaluator,
    ElementStyleObservation,
};
pub use design_system_fs::{
    load_design_system_for_cwd, resolve_design_md_path, resolve_design_sidecar_path, DesignFs,
    RealDesignFs, ResolvedDesignMd,
};
