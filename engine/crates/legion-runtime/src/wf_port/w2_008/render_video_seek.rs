//! Port of `render-video-seek.js`'s pure frame/worker bucketing math.
//!
//! Mirrors:
//! ```js
//! const TOTAL_FRAMES = Math.round(FPS * DURATION);
//! // ...
//! const buckets = Array.from({ length: CONCURRENCY }, () => []);
//! for (let f = 0; f < TOTAL_FRAMES; f++) buckets[f % CONCURRENCY].push(f);
//! ```
//!
//! Not ported: launching Playwright/Chromium, `window.__seek(t)` polling per
//! frame, `page.screenshot`, and the final `ffmpeg` PNG-sequence-to-MP4
//! `spawnSync` call — same out-of-scope reasoning as
//! [`super::render_video`] (no headless-browser crate in
//! `engine/Cargo.lock`). [`total_frames`] and [`round_robin_buckets`] give a
//! Rust caller the same frame count and per-worker frame assignment the
//! script computes before it starts capturing.

/// `Math.round(FPS * DURATION)`, using round-half-away-from-zero as
/// JavaScript's `Math.round` does (Rust's `f64::round` matches this for the
/// positive, finite fps/duration values this script accepts).
pub fn total_frames(fps: f64, duration: f64) -> u64 {
    (fps * duration).round() as u64
}

/// Round-robin frame assignment across `concurrency` workers. Mirrors:
/// ```js
/// const buckets = Array.from({ length: CONCURRENCY }, () => []);
/// for (let f = 0; f < TOTAL_FRAMES; f++) buckets[f % CONCURRENCY].push(f);
/// ```
/// `concurrency` is clamped to at least 1, matching
/// `Math.max(1, parseInt(arg('concurrency', '4')))`.
pub fn round_robin_buckets(total_frames: u64, concurrency: u64) -> Vec<Vec<u64>> {
    let concurrency = concurrency.max(1);
    let mut buckets: Vec<Vec<u64>> = (0..concurrency).map(|_| Vec::new()).collect();
    for f in 0..total_frames {
        buckets[(f % concurrency) as usize].push(f);
    }
    buckets
}
