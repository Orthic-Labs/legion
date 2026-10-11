//! Tests for wf_port chunk w2_008 (`skills/designer/engine/huashu/scripts/
//! {render-video-seek.js, render-video.js}`), covering the pure logic ported in
//! `legion_runtime::wf_port::w2_008`. See that module's doc comment for what
//! remains unported (Playwright/Chromium capture, ffmpeg process calls) and why.

use legion_runtime::wf_port::w2_008::{
    resolve_trim, round_robin_buckets, total_frames, HIDE_CHROME_CSS,
};

// ---------------------------------------------------------------------------
// render-video.js / render-video-seek.js · trim resolution, frame bucketing
// ---------------------------------------------------------------------------

#[test]
fn render_video_resolve_trim_all_three_branches() {
    assert_eq!(resolve_trim(Some(2.5), 9.0, true), 2.5);
    assert!((resolve_trim(None, 1.0, true) - 1.05).abs() < 1e-9);
    assert!((resolve_trim(None, 1.0, false) - 1.5).abs() < 1e-9);
}

#[test]
fn render_video_hide_chrome_css_is_shared_literal() {
    assert!(HIDE_CHROME_CSS.contains(".masthead, .kicker, .title,"));
}

#[test]
fn render_video_seek_total_frames_and_buckets_cover_a_real_render() {
    let frames = total_frames(60.0, 31.0);
    assert_eq!(frames, 1860);
    let buckets = round_robin_buckets(frames, 4);
    assert_eq!(buckets.len(), 4);
    let total: u64 = buckets.iter().map(|b| b.len() as u64).sum();
    assert_eq!(total, frames);
    // Round-robin: bucket 0 gets frame 0, 4, 8, ...
    assert_eq!(buckets[0][1], 4);
}
