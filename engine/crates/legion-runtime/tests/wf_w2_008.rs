//! Tests for wf_port chunk w2_008 (`skills/designer/engine/huashu/scripts/
//! {narrate-pipeline.mjs, render-narration.sh, render-video-seek.js,
//! render-video.js, tts-doubao.mjs}`), covering the pure logic ported in
//! `legion_runtime::wf_port::w2_008`. See that module's doc comment for what
//! remains unported (Playwright/Chromium capture, ffmpeg/ffprobe process
//! calls, the live Doubao HTTP call) and why.
//!
//! This test file depends on `legion_runtime::wf_port::w2_008`, which is not
//! yet wired into `legion-runtime`'s public module tree (the integrator adds
//! `pub mod w2_008;` in `src/wf_port/mod.rs` per the w2_008 chunk
//! assignment; `pub mod wf_port;` is already present in `src/lib.rs`). Until
//! that wiring lands, this file will not compile as part of the crate's test
//! target.

use std::path::{Path, PathBuf};

use legion_runtime::wf_port::w2_008::{
    build_tts_request, parse_env, parse_render_narration_args, parse_script, parse_tts_response,
    resolve_trim, round_robin_buckets, split_by_cues, total_frames, Chunk, RenderNarrationArgs,
    TtsRequestParams, HIDE_CHROME_CSS,
};

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// narrate-pipeline.mjs · parseScript / splitByCues
// ---------------------------------------------------------------------------

#[test]
fn narrate_parses_demo_style_script() {
    let md = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_008/demo.md"),
    )
    .unwrap();
    let parsed = parse_script(&md);
    assert_eq!(parsed.meta.get("title").unwrap(), "什么是 LLM");
    assert_eq!(parsed.meta.get("voice").unwrap(), "S_JSdgdWk22");
    assert_eq!(parsed.meta.get("speed").unwrap(), "1.0");
    assert_eq!(parsed.meta.get("gap").unwrap(), "0.3");

    assert_eq!(parsed.scenes.len(), 2);
    assert_eq!(parsed.scenes[0].id, "intro");
    assert_eq!(
        parsed.scenes[0].raw,
        "大家好，我是花叔。今天我们 5 分钟讲清楚 LLM 是什么。"
    );
    assert_eq!(parsed.scenes[1].id, "what-is");
    assert!(parsed.scenes[1].raw.contains("[[cue:bigmodel]]"));
}

#[test]
fn narrate_splits_cues_from_parsed_scene() {
    let chunks = split_by_cues(
        "LLM 全称 Large Language Model，[[cue:bigmodel]]它是一个有几千亿参数的神经网络。\n本质是一个文字接龙的预测器。",
    );
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].cue_after.as_deref(), Some("bigmodel"));
    assert!(chunks[0].text.starts_with("LLM 全称"));
    assert!(chunks[1].cue_after.is_none());
    assert!(chunks[1].text.contains("文字接龙"));
}

#[test]
fn narrate_no_scene_headings_errors_like_cli_guard() {
    // Mirrors main()'s `if (scenes.length === 0) { ...; process.exit(1); }`
    // guard: the pure parser itself just returns an empty scenes vec, and
    // the caller enforces the "at least one scene" invariant.
    let parsed = parse_script("no scenes here, just prose");
    assert!(parsed.scenes.is_empty());
}

#[test]
fn narrate_adjacent_cues_drop_empty_tail_chunk() {
    let chunks = split_by_cues("intro[[cue:a]][[cue:b]]");
    assert_eq!(
        chunks,
        vec![
            Chunk {
                text: "intro".into(),
                cue_after: Some("a".into())
            },
            Chunk {
                text: "".into(),
                cue_after: Some("b".into())
            },
        ]
    );
}

// ---------------------------------------------------------------------------
// render-narration.sh · argument parsing / path & duration derivation
// ---------------------------------------------------------------------------

#[test]
fn render_narration_parses_seek_pipeline_invocation() {
    let parsed = parse_render_narration_args(&args(&[
        "demo.html",
        "--timeline=_narration/timeline.json",
        "--bgm-mood=educational",
        "--seek",
        "--seek-fps=30",
    ]))
    .unwrap();
    assert_eq!(
        parsed,
        RenderNarrationArgs {
            html: Some("demo.html".into()),
            timeline: Some("_narration/timeline.json".into()),
            bgm_mood: Some("educational".into()),
            bgm: None,
            bgm_volume: "0.18".into(),
            no_ducking: false,
            keep_silent: false,
            use_seek: true,
            seek_fps: "30".into(),
            out: None,
            width: "1920".into(),
            height: "1080".into(),
        }
    );
}

#[test]
fn render_narration_rejects_unknown_flag() {
    assert_eq!(
        parse_render_narration_args(&args(&["demo.html", "--nope"])).unwrap_err(),
        "未知参数：--nope"
    );
}

#[test]
fn render_narration_derives_default_output_paths() {
    let derived =
        legion_runtime::wf_port::w2_008::render_narration::derive_paths(&PathBuf::from(
            "/proj/demo.html",
        ));
    assert_eq!(derived.silent_mp4, PathBuf::from("/proj/demo.mp4"));
    assert_eq!(derived.default_out, PathBuf::from("/proj/demo-narrated.mp4"));
}

#[test]
fn render_narration_record_duration_matches_script_formula() {
    assert_eq!(
        legion_runtime::wf_port::w2_008::render_narration::record_duration(59.4),
        61
    );
}

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

// ---------------------------------------------------------------------------
// tts-doubao.mjs · .env parsing, request body, response parsing
// ---------------------------------------------------------------------------

#[test]
fn tts_doubao_env_and_request_round_trip() {
    let env_text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_008/sample.env"),
    )
    .unwrap();
    let env = parse_env(&env_text);
    let voice_id = env.get("DOUBAO_TTS_VOICE_ID").unwrap();
    let cluster = env.get("DOUBAO_TTS_CLUSTER").unwrap();

    let body = build_tts_request(&TtsRequestParams {
        text: "大家好",
        voice_id,
        cluster,
        speed: 1.0,
        encoding: "mp3",
        reqid: "test-reqid",
        uid: "huashu-design",
    });
    assert_eq!(body["audio"]["voice_type"], "S_JSdgdWk22");
    assert_eq!(body["app"]["cluster"], "volcano_icl");
}

#[test]
fn tts_doubao_parses_successful_response() {
    // base64 of b"mp3-bytes" -> "bXAzLWJ5dGVz"
    let body = r#"{"code":3000,"message":"success","data":"bXAzLWJ5dGVz"}"#;
    let audio = parse_tts_response(body).unwrap();
    assert_eq!(audio, b"mp3-bytes");
}

#[test]
fn tts_doubao_error_code_surfaces_message() {
    let body = r#"{"code":4003,"message":"quota exceeded"}"#;
    let err = parse_tts_response(body).unwrap_err();
    assert!(err.contains("4003"));
    assert!(err.contains("quota exceeded"));
}
