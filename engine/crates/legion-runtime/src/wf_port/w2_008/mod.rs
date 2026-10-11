//! Rust port of `skills/designer/engine/huashu/scripts/{render-video-seek.js,
//! render-video.js}`.
//!
//! Both scripts are silent HTML-animation capture steps. Each drives a headless
//! Chromium through Playwright and muxes the captured frames with `ffmpeg`, so
//! the browser-capture and `ffmpeg` calls are process orchestration that this
//! crate does not reproduce here.
//!
//! What *is* ported here, faithfully and with unit tests, is the pure decision
//! logic in those scripts: render-video.js's trim-offset resolution and literal
//! chrome-hiding CSS, and render-video-seek.js's frame/worker bucketing.
//!
//! Each submodule's doc comment states exactly which script function it mirrors
//! and what remains unported (the actual `ffmpeg`/Playwright calls).

pub mod render_video;
pub mod render_video_seek;

pub use render_video::{resolve_trim, HIDE_CHROME_CSS};
pub use render_video_seek::{round_robin_buckets, total_frames};
