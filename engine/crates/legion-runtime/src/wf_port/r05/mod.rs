//! wf_port packet r05 (area `skills/designer/engine/scripts/detector/cli/
//! main.mjs`, target crate `legion-runtime`).
//!
//! Ports the `impeccable detect` CLI's own orchestration: argv parsing,
//! usage text, the file/dir/URL dispatch loop, output formatting
//! (`formatFindingSummary`/`formatFindings`), the stdin-hook JSON path
//! (`handleStdin`), the framework-dev-server hint, the >50-file confirm
//! prompt, and exit codes (0 clean, 2 findings, 1 usage error).
//!
//! The seven engines `main.mjs` imports (`design-system.mjs`,
//! `detect-url.mjs`, `detect-html.mjs`, `detect-text.mjs`,
//! `impeccable-config.mjs`, `node/file-system.mjs`, `site/sweep.mjs`) each
//! have their own wf_port packets (`w2_011`, `r07`, `w2_013`/`w2_012`,
//! `r08`, `w2_016`) already in this tree; this packet composes their public
//! functions rather than re-porting them. Process/network/filesystem I/O
//! (stdin, TTY detection, the interactive confirm prompt, and the concrete
//! `ChromeDriver`/`PageFetcher`/`AntipatternLookup` implementations used for
//! URL scans) sit behind the [`cli::Io`] and [`cli::Detectors`] traits so
//! `run` is unit-tested without a real terminal, browser, or network call,
//! per this port's testing rule.
//!
//! ## Known gap
//!
//! `detectHtml`'s full per-element rule engine (`rules/checks.mjs`, ~2700
//! lines: border/color/glow/motion/icon-tile/italic-serif/hero-eyebrow/
//! quality/oversized-h1/clipped-overflow/gpt-border-shadow checks driven by
//! a static CSS cascade + computed-style resolver) and the detector
//! antipattern registry (`registry/antipatterns.mjs`, the `name`/
//! `description`/`severity`/`gated` metadata table `finding()` looks ids up
//! in) are not ported anywhere in this tree yet. [`cli::Detectors`] takes
//! HTML/URL scanning as injected callbacks for exactly this reason: this
//! packet wires the CLI faithfully around whatever detector implementation
//! is supplied, without depending on those two still-unported pieces to
//! compile or to have a concrete production implementation today.
//! `detect_text`'s eight page-level content analyzers (`single-font`,
//! `flat-type-hierarchy`, `monotonous-spacing`, `em-dash-overuse`,
//! `marketing-buzzword`, `numbered-section-markers`, `aphoristic-cadence`,
//! `dark-glow`) *are* ported, in `wf_port::w2_012::detect_text`, and are
//! wired into both `real_detectors::detect_text` and `detect_html`'s
//! text-content lane below.

pub mod cli;
pub mod design_system_loader;
pub mod output;
pub mod real_detectors;
