//! Port of `skills/designer/engine/huashu/scripts/render-video-seek.js`
//! (packet R02).
//!
//! `render-video-seek.js` is the deterministic frame-by-frame HTML-animation
//! renderer: it drives a headless Chromium tab (via Playwright in the
//! original) through a fixed set of timestamps using a page-exposed
//! `window.__seek(t)` hook, screenshots each frame, then muxes the PNG
//! sequence into an MP4 with `ffmpeg`.
//!
//! The script is orchestration around external processes (`ffmpeg`) or a
//! browser. To keep the pure decision logic (arg parsing, frame bucketing)
//! unit-testable without launching a real browser, every external interaction
//! is expressed as a trait (`BrowserDriver` + `FfmpegEncoder` in
//! [`render_video_seek`]) with a real implementation that drives Chromium or
//! shells out, and a fake implementation used by the test suite.

pub mod render_video_seek;
