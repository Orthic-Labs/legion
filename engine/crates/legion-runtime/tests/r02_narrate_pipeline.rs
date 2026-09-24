//! Integration tests for wf_port packet R02
//! (`skills/designer/engine/huashu/scripts/narrate-pipeline.mjs`).
//!
//! Exercises the public API of `legion_runtime::wf_port::r02::narrate_pipeline`
//! from outside the crate, using a fixture markdown script and the module's
//! own fake `ProcessRunner`-style pattern reproduced here (a local fake, so
//! this file never shells out or touches the network).
//!
//! NOTE: as with the existing w2_008 packet, `pub mod r02;` has not been
//! added to `legion-runtime`'s `src/wf_port/mod.rs` by this port (the port
//! brief for this packet explicitly says not to edit that file) — wiring it
//! in is a follow-up integration step, after which this file compiles as
//! part of the crate's test target.

use std::path::{Path, PathBuf};

use legion_runtime::wf_port::r02::narrate_pipeline::{
    parse_args, parse_script, run, split_by_cues, Chunk, ProcessRunner, TtsCallResult,
};

struct FixtureRunner;

impl ProcessRunner for FixtureRunner {
    fn call_tts(
        &self,
        text: &str,
        out_path: &Path,
        _voice: Option<&str>,
        _speed: f64,
    ) -> Result<TtsCallResult, String> {
        std::fs::write(out_path, b"audio").map_err(|e| e.to_string())?;
        Ok(TtsCallResult {
            path: out_path.to_path_buf(),
            bytes: 5,
            duration: 1.0,
            text_chars: text.chars().count(),
        })
    }

    fn get_duration(&self, _file_path: &Path) -> Result<f64, String> {
        Ok(1.0)
    }

    fn ffmpeg_concat(&self, _inputs: &[PathBuf], output: &Path) -> Result<(), String> {
        std::fs::write(output, b"concat").map_err(|e| e.to_string())
    }

    fn make_silence(&self, _duration: f64, out_path: &Path) -> Result<(), String> {
        std::fs::write(out_path, b"silence").map_err(|e| e.to_string())
    }
}

#[test]
fn parses_demo_fixture_script() {
    let md = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_r02/demo.md"),
    )
    .unwrap();
    let parsed = parse_script(&md);
    assert_eq!(parsed.meta.get("title").unwrap(), "什么是 LLM");
    assert_eq!(parsed.scenes.len(), 2);
    assert_eq!(parsed.scenes[0].id, "intro");
    assert_eq!(parsed.scenes[1].id, "what-is");
}

#[test]
fn splits_cues_from_fixture_scene() {
    let md = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_r02/demo.md"),
    )
    .unwrap();
    let parsed = parse_script(&md);
    let chunks = split_by_cues(&parsed.scenes[1].raw);
    assert!(chunks
        .iter()
        .any(|c: &Chunk| c.cue_after.as_deref() == Some("bigmodel")));
}

#[test]
fn full_pipeline_runs_against_fixture_with_fake_process_runner() {
    let tmp = std::env::temp_dir().join(format!(
        "r02-narrate-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let script_path = tmp.join("demo.md");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_r02/demo.md"),
        &script_path,
    )
    .unwrap();
    let out_dir = tmp.join("out");

    let outcome = run(&script_path, &out_dir, &FixtureRunner).unwrap();
    assert_eq!(outcome.timeline.scenes.len(), 2);
    assert!(outcome.voiceover_path.exists());
    assert!(outcome.timeline_path.exists());

    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn parse_args_matches_narrate_pipeline_flags() {
    let argv: Vec<String> = ["node", "narrate-pipeline.mjs", "--script", "demo.md", "--out-dir", "_out"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let parsed = parse_args(&argv);
    assert_eq!(parsed.script.as_deref(), Some("demo.md"));
    assert_eq!(parsed.out_dir.as_deref(), Some("_out"));
}
