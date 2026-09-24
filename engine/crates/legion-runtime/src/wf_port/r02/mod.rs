//! Port of `skills/designer/engine/huashu/scripts/{narrate-pipeline.mjs,
//! render-video-seek.js}` (packet R02).
//!
//! `narrate-pipeline.mjs` is the L2 long-narration orchestrator: it parses a
//! `## scene-id` markdown script, calls `tts-doubao.mjs` per cue-delimited
//! text chunk, concatenates the resulting per-scene / whole-track MP3s with
//! `ffmpeg`, and writes `voiceover.mp3` + `timeline.json`.
//!
//! `render-video-seek.js` is the deterministic frame-by-frame HTML-animation
//! renderer: it drives a headless Chromium tab (via Playwright in the
//! original) through a fixed set of timestamps using a page-exposed
//! `window.__seek(t)` hook, screenshots each frame, then muxes the PNG
//! sequence into an MP4 with `ffmpeg`.
//!
//! Both scripts are, at their core, orchestration around external processes
//! (`node`/`ffmpeg`/`ffprobe`) or a browser. To keep the pure decision logic
//! (arg parsing, markdown/cue parsing, timeline assembly, frame bucketing)
//! unit-testable without touching the network or launching a real browser,
//! every external interaction is expressed as a trait (`ProcessRunner` in
//! [`narrate_pipeline`], `BrowserDriver` + `FfmpegEncoder` in
//! [`render_video_seek`]) with a real implementation that shells out /
//! drives Chromium, and a fake implementation used by the test suite.

pub mod narrate_pipeline;
pub mod render_video_seek;
