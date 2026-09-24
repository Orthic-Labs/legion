//! wf_port packet r08 (target crate `legion-runtime`).
//!
//! Completes the two gaps left open by `wf_port::w2_012`'s module doc:
//!
//! - [`detect_text_matchers`]: the remainder of
//!   `skills/designer/engine/scripts/detector/engines/regex/detect-text.mjs`
//!   — the 15-entry `REGEX_MATCHERS` table, `extractStyleBlocks`,
//!   `extractCSSinJS`, and `runRegexMatchers`.
//! - [`sweep_live`]: the remainder of
//!   `skills/designer/engine/scripts/detector/engines/site/sweep.mjs` —
//!   `checkStatus` and `sweepSite`'s live-network orchestration, behind a
//!   `PageFetcher` trait so it is unit-tested without real network I/O.

pub mod detect_text_matchers;
pub mod sweep_live;
