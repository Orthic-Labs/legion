//! Port of `skills/designer/engine/scripts/detector/engines/{browser,regex,
//! site,static-html}/*` (chunk w2_012).
//!
//! Each source file mixes pure decision/parsing logic with process,
//! network, and headless-browser side effects (Puppeteer, raw CDP over a
//! spawned Chrome, `fetch`, jsdom). Per this chunk's scope, only the pure,
//! testable logic is ported here:
//!
//! - `browser_url`: `detect-url.mjs`'s `serializeDesignSystemForBrowser`
//!   (design-system-for-page-injection shaping) and `detect-url-cdp.mjs`'s
//!   raw WebSocket frame encode/decode (`makeFrame`/`readFrames`) plus the
//!   Chrome/Edge executable candidate-path list. `detectUrl`/`detectUrlCdp`
//!   themselves launch a browser, open a network/CDP connection, and inject
//!   a script into a live page — no return-value contract to port without a
//!   headless-browser harness, so they are left to the integrator.
//! - `sweep`: `sweep.mjs`'s `extractLinks` (link scraping regex) and the
//!   required-page-profile matching decision (`REQUIRED_PAGES` + the "is
//!   this required page linked" test). `checkStatus`/`sweepSite` perform
//!   live `fetch`s and are not ported.
//! - `css_cascade`: `css-cascade.mjs`'s pure string/CSS-value parsing
//!   helpers (list/token splitting, specificity, shorthand expansion,
//!   priority comparison, `@layer` unwrapping, inline `style=""` parsing).
//!   The jsdom-backed and `csstree`-backed pieces (`buildBorderOverrideMap`,
//!   `StaticElement`/`StaticDocument`, `collectStaticCssRules`,
//!   `buildStaticStyleMap`, `collectStaticCssText`, `normalizeStaticCssValue`
//!   which needs `resolveVarRefs`/`resolveLengthPx` from the shared
//!   `rules/checks.mjs` cascade) depend on a full DOM + CSS-AST parser this
//!   crate does not have, so they stay unported.
//! - `detect_text`: `detect-text.mjs`'s file-extension/full-page gating
//!   (`extFromFilePath`, `shouldRunPageAnalyzers`), the "safe element"/
//!   "rounded"/"border-radius" line predicates, the neutral-border-color
//!   check, `stripHtmlToText`, and the eight page-level text-content
//!   analyzers (`single-font`, `flat-type-hierarchy`, `monotonous-spacing`,
//!   `em-dash-overuse`, `marketing-buzzword`, `numbered-section-markers`,
//!   `aphoristic-cadence`, `dark-glow`). The large `REGEX_MATCHERS` table
//!   (side-tab/border-accent/overused-font/gradient-text/gray-on-color/
//!   ai-color-palette/bounce-easing/layout-transition/broken-image — 15
//!   line-scoped regex+test+format triples) and the Vue/Svelte `<style>` and
//!   CSS-in-JS template-literal block extractors are not ported in this
//!   chunk for lack of remaining budget; they are pure and portable the
//!   same way, and are listed as the remaining gap in this chunk's report.

pub mod browser_url;
pub mod css_cascade;
pub mod detect_text;
pub mod sweep;
