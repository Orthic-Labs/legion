//! Rust port of `skills/designer/engine/huashu/scripts/{narrate-pipeline.mjs,
//! render-narration.sh, render-video-seek.js, render-video.js, tts-doubao.mjs}`.
//!
//! These five scripts are the Huashu ("画术") long-narration video pipeline:
//! markdown narration script → TTS voiceover + timeline → HTML animation capture
//! (via Playwright/Chromium) → muxed narrated MP4. Four of the five are, at their
//! core, **process orchestration**: they shell out to `ffmpeg`/`ffprobe`, drive a
//! headless Chromium through Playwright, or POST to the Doubao (Volcano Engine)
//! TTS HTTP API. None of `chromiumoxide`, `headless_chrome`, or a Playwright
//! equivalent is present in `engine/Cargo.lock`, so faithfully reproducing the
//! actual browser-capture step is out of scope for this port without a new
//! dependency (see the report for the dependency this would need).
//!
//! What *is* ported here, faithfully and with unit tests, is every piece of pure
//! decision logic in the five scripts — the parts that are deterministic
//! functions of their inputs and don't require ffmpeg/Chromium/network to
//! exercise: narration-script parsing, cue splitting, timeline JSON shape,
//! render-narration.sh's argument parsing and path derivation, render-video.js's
//! trim-offset resolution, render-video-seek.js's frame/worker bucketing, and
//! tts-doubao.mjs's `.env` parsing plus TTS request/response (de)serialization.
//!
//! Each submodule's doc comment states exactly which script function it mirrors
//! and what remains unported (the actual `ffmpeg`/Playwright/HTTP calls), so a
//! caller wiring this into a real Rust CLI knows precisely what glue is still
//! required around these pure functions.

pub mod narrate;
pub mod render_narration;
pub mod render_video;
pub mod render_video_seek;
pub mod tts_doubao;

pub use narrate::{
    parse_script, split_by_cues, Chunk, Cue, ParsedScript, Scene, Timeline, TimelineScene,
    TimelineSceneChunk,
};
pub use render_narration::{parse_args as parse_render_narration_args, RenderNarrationArgs};
pub use render_video::{resolve_trim, HIDE_CHROME_CSS};
pub use render_video_seek::{round_robin_buckets, total_frames};
pub use tts_doubao::{build_tts_request, parse_env, parse_tts_response, TtsRequestParams};
