//! Full port of `narrate-pipeline.mjs`.
//!
//! Mirrors, exactly:
//! - `parseArgs`/`usage` (`--script`, `--out-dir`, `--help`/`-h`).
//! - `parseScript` (frontmatter `key: value` lines + `## scene-id` blocks).
//! - `splitByCues` (`[[cue:id]]` marker splitting, trimming, empty-chunk
//!   filtering).
//! - `callTTS`/`getDuration`/`ffmpegConcat`/`makeSilence` — these shell out
//!   to `node tts-doubao.mjs`, `ffprobe`, and `ffmpeg`. They are expressed
//!   here as the [`ProcessRunner`] trait so the orchestration logic
//!   (`run`) can be exercised in tests with a fake, and the real
//!   [`RealProcessRunner`] shells out exactly as the JS did.
//! - `main()`'s orchestration: scene/chunk loop, cursor accumulation,
//!   `timeline.json` assembly, `voiceover.mp3` concatenation, tmp-dir
//!   cleanup, and the same stderr progress lines / exit code 1 on error or
//!   on a script with zero `## scene` blocks.
//!
//! One unavoidable deviation from the original: `TTS_SCRIPT` is resolved in
//! the JS via `path.join(__dirname, 'tts-doubao.mjs')` — the *directory this
//! script itself lives in*. A compiled Rust binary has no equivalent of
//! `import.meta.url` pointing at the `scripts/` directory, so
//! [`RealProcessRunner::new`] takes the `tts-doubao.mjs` path explicitly
//! instead of inferring it. Behavior once that path is supplied is
//! otherwise identical (same `node <script> --text --out [--voice]
//! [--speed]` invocation, same stdout-JSON contract).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CLI args — mirrors parseArgs()/usage()
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliArgs {
    pub script: Option<String>,
    pub out_dir: Option<String>,
    pub help: bool,
}

/// Mirrors `parseArgs(argv)`. `argv` is the full `process.argv`-shaped
/// slice (`argv[0]` = program, `argv[1]` = script path); the loop starts at
/// index 2, exactly as the JS does.
pub fn parse_args(argv: &[String]) -> CliArgs {
    let mut args = CliArgs::default();
    let mut i = 2usize;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--script" {
            i += 1;
            args.script = argv.get(i).cloned();
        } else if a == "--out-dir" {
            i += 1;
            args.out_dir = argv.get(i).cloned();
        } else if a == "--help" || a == "-h" {
            args.help = true;
        }
        i += 1;
    }
    args
}

/// Mirrors `usage()`'s message text (stderr banner). The caller is
/// responsible for the JS's `process.exit(1)` side effect.
pub fn usage_text() -> String {
    "\
narrate-pipeline.mjs · L2 长解说总指挥

  --script <path>     解说稿 .md 文件（必填）
  --out-dir <path>    输出目录（必填）

输出：<out-dir>/voiceover.mp3 + <out-dir>/timeline.json"
        .to_string()
}

// ---------------------------------------------------------------------------
// parseScript / splitByCues
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedScript {
    pub meta: BTreeMap<String, String>,
    pub scenes: Vec<Scene>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scene {
    pub id: String,
    pub raw: String,
}

/// Mirrors `parseScript(md)`: an optional leading `---\n...\n---\n`
/// frontmatter block of `key: value` lines (first `:` splits, both sides
/// trimmed, lines without `:` skipped), followed by `## id` scene blocks
/// (`id` matches `[\w-]+`) running to the next heading or end of string,
/// body trimmed.
pub fn parse_script(md: &str) -> ParsedScript {
    let mut meta = BTreeMap::new();
    let mut body = md;

    if let Some(fm) = extract_frontmatter(md) {
        for line in fm.split('\n') {
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_string();
                let val = line[idx + 1..].trim().to_string();
                meta.insert(key, val);
            }
        }
        body = &md[frontmatter_block_len(md)..];
    }

    ParsedScript {
        meta,
        scenes: parse_scenes(body),
    }
}

fn extract_frontmatter(md: &str) -> Option<&str> {
    let rest = md.strip_prefix("---\n")?;
    let end = rest.find("\n---\n")?;
    Some(&rest[..end])
}

fn frontmatter_block_len(md: &str) -> usize {
    match extract_frontmatter(md) {
        Some(inner) => "---\n".len() + inner.len() + "\n---\n".len(),
        None => 0,
    }
}

fn parse_scenes(body: &str) -> Vec<Scene> {
    // Mirrors: /^##\s+([\w-]+)\s*\n([\s\S]*?)(?=^##\s+[\w-]+\s*\n|$(?![\r\n]))/gm
    let mut ids = Vec::new();
    let mut heading_starts = Vec::new();
    let mut content_starts = Vec::new();

    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        let trimmed_line = line.trim_end_matches('\n');
        if let Some(rest) = trimmed_line.strip_prefix("##") {
            // `\s+` requires at least one whitespace char between `##` and id.
            let after_hashes = rest;
            let ws_len = after_hashes.len() - after_hashes.trim_start().len();
            if ws_len > 0 {
                let id_part = after_hashes.trim_start();
                let id: String = id_part
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                    .collect();
                let after_id = &id_part[id.len()..];
                if !id.is_empty() && after_id.trim().is_empty() {
                    ids.push(id);
                    heading_starts.push(offset);
                    content_starts.push(offset + line.len());
                }
            }
        }
        offset += line.len();
    }

    let mut scenes = Vec::with_capacity(ids.len());
    for i in 0..ids.len() {
        let content_end = heading_starts.get(i + 1).copied().unwrap_or(body.len());
        let raw = body[content_starts[i]..content_end].trim().to_string();
        scenes.push(Scene {
            id: ids[i].clone(),
            raw,
        });
    }
    scenes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub text: String,
    pub cue_after: Option<String>,
}

/// Mirrors `splitByCues(text)`.
pub fn split_by_cues(text: &str) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut last_idx = 0usize;
    let mut idx = 0usize;
    loop {
        if idx >= text.len() {
            break;
        }
        let Some(rel) = text[idx..].find("[[cue:") else {
            break;
        };
        let start = idx + rel;
        let Some(close_rel) = text[start..].find("]]") else {
            break;
        };
        let close = start + close_rel;
        let id = &text[start + "[[cue:".len()..close];
        let before = text[last_idx..start].trim().to_string();
        chunks.push(Chunk {
            text: before,
            cue_after: Some(id.to_string()),
        });
        last_idx = close + "]]".len();
        idx = last_idx;
    }
    let tail = text[last_idx..].trim().to_string();
    chunks.push(Chunk {
        text: tail,
        cue_after: None,
    });
    chunks
        .into_iter()
        .filter(|c| !c.text.is_empty() || c.cue_after.is_some())
        .collect()
}

/// Mirrors JS `parseFloat`: leading whitespace skipped, then the longest
/// valid decimal-with-optional-exponent prefix is parsed; `None` if no such
/// prefix exists (matching `NaN`).
pub fn js_parse_float(s: &str) -> Option<f64> {
    let re = Regex::new(r"^\s*[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?").unwrap();
    let m = re.find(s)?;
    m.as_str().trim().parse::<f64>().ok()
}

// ---------------------------------------------------------------------------
// timeline.json shape
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cue {
    pub id: String,
    pub offset: f64,
    #[serde(rename = "absoluteTime")]
    pub absolute_time: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineSceneChunk {
    pub text: String,
    pub start: f64,
    pub end: f64,
    #[serde(rename = "absoluteStart")]
    pub absolute_start: f64,
    #[serde(rename = "absoluteEnd")]
    pub absolute_end: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineScene {
    pub id: String,
    pub start: f64,
    pub end: f64,
    pub duration: f64,
    pub audio: String,
    pub text: String,
    pub chunks: Vec<TimelineSceneChunk>,
    pub cues: Vec<Cue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Timeline {
    pub title: String,
    pub voice: Option<String>,
    pub speed: f64,
    pub gap: f64,
    #[serde(rename = "totalDuration")]
    pub total_duration: f64,
    pub scenes: Vec<TimelineScene>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voiceover: Option<String>,
}

// ---------------------------------------------------------------------------
// External process boundary — mirrors callTTS/getDuration/ffmpegConcat/makeSilence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct TtsCallResult {
    pub path: PathBuf,
    pub bytes: u64,
    pub duration: f64,
    pub text_chars: usize,
}

pub trait ProcessRunner {
    /// Mirrors `callTTS(text, outPath, opts)`.
    fn call_tts(
        &self,
        text: &str,
        out_path: &Path,
        voice: Option<&str>,
        speed: f64,
    ) -> Result<TtsCallResult, String>;

    /// Mirrors `getDuration(filePath)` (`ffprobe` format-duration query).
    fn get_duration(&self, file_path: &Path) -> Result<f64, String>;

    /// Mirrors `ffmpegConcat(inputs, output)`.
    fn ffmpeg_concat(&self, inputs: &[PathBuf], output: &Path) -> Result<(), String>;

    /// Mirrors `makeSilence(duration, outPath)`.
    fn make_silence(&self, duration: f64, out_path: &Path) -> Result<(), String>;
}

/// Real `ProcessRunner`: shells out to `node <tts_script>`, `ffprobe`, and
/// `ffmpeg` exactly as `narrate-pipeline.mjs` does.
pub struct RealProcessRunner {
    /// Path to `tts-doubao.mjs`. See the module doc comment for why this is
    /// explicit rather than inferred from the binary's own location.
    pub tts_script: PathBuf,
}

impl RealProcessRunner {
    pub fn new(tts_script: PathBuf) -> Self {
        Self { tts_script }
    }
}

impl ProcessRunner for RealProcessRunner {
    fn call_tts(
        &self,
        text: &str,
        out_path: &Path,
        voice: Option<&str>,
        speed: f64,
    ) -> Result<TtsCallResult, String> {
        // Mirrors:
        //   const args = ['--text', text, '--out', outPath];
        //   if (opts.voice) args.push('--voice', opts.voice);
        //   if (opts.speed) args.push('--speed', String(opts.speed));
        // JS truthiness: an empty-string voice, or a zero/NaN speed, is
        // falsy and is *not* passed through, even though both are valid
        // JS values reaching this function.
        let mut cmd = Command::new("node");
        cmd.arg(&self.tts_script)
            .arg("--text")
            .arg(text)
            .arg("--out")
            .arg(out_path);
        if let Some(v) = voice {
            if !v.is_empty() {
                cmd.arg("--voice").arg(v);
            }
        }
        if speed != 0.0 && !speed.is_nan() {
            cmd.arg("--speed").arg(speed.to_string());
        }
        let output = cmd.output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).map_err(|e| e.to_string())?;
        Ok(TtsCallResult {
            path: json
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .into(),
            bytes: json.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0),
            duration: json.get("duration").and_then(|v| v.as_f64()).unwrap_or(0.0),
            text_chars: json
                .get("text_chars")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
        })
    }

    fn get_duration(&self, file_path: &Path) -> Result<f64, String> {
        let output = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
            ])
            .arg(file_path)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        js_parse_float(text.trim()).ok_or_else(|| "ffprobe returned non-numeric duration".into())
    }

    fn ffmpeg_concat(&self, inputs: &[PathBuf], output: &Path) -> Result<(), String> {
        let list_file = list_file_path(output);
        let list_contents = inputs
            .iter()
            .map(|p| format!("file '{}'", p.display().to_string().replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&list_file, list_contents).map_err(|e| e.to_string())?;
        let result = Command::new("ffmpeg")
            .args(["-y", "-f", "concat", "-safe", "0", "-i"])
            .arg(&list_file)
            .args(["-c", "copy"])
            .arg(output)
            .output()
            .map_err(|e| e.to_string());
        let _ = std::fs::remove_file(&list_file);
        let output_res = result?;
        if !output_res.status.success() {
            return Err(String::from_utf8_lossy(&output_res.stderr).to_string());
        }
        Ok(())
    }

    fn make_silence(&self, duration: f64, out_path: &Path) -> Result<(), String> {
        let result = Command::new("ffmpeg")
            .args(["-y", "-f", "lavfi", "-i", "anullsrc=r=24000:cl=mono", "-t"])
            .arg(duration.to_string())
            .args(["-q:a", "9", "-acodec", "libmp3lame"])
            .arg(out_path)
            .output()
            .map_err(|e| e.to_string())?;
        if !result.status.success() {
            return Err(String::from_utf8_lossy(&result.stderr).to_string());
        }
        Ok(())
    }
}

fn list_file_path(output: &Path) -> PathBuf {
    let mut s = output.as_os_str().to_os_string();
    s.push(".list");
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// main() orchestration
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum PipelineError {
    /// `--script`/`--out-dir` missing or `--help` passed: mirrors `usage()`
    /// (prints the usage banner, exit code 1).
    Usage,
    /// Mirrors `错：解说稿没有 ## scene 段，至少一段。` (exit code 1).
    NoScenes,
    /// Mirrors the `main().catch` handler: `narrate-pipeline 失败：<msg>`
    /// (exit code 1).
    Failed(String),
}

#[derive(Debug)]
pub struct PipelineOutcome {
    pub timeline: Timeline,
    pub voiceover_path: PathBuf,
    pub timeline_path: PathBuf,
    /// Progress/summary lines written to stderr by the original script, in
    /// order, for callers that want to reproduce them verbatim.
    pub log_lines: Vec<String>,
}

/// Mirrors `main()`'s orchestration, given already-parsed, validated
/// `--script`/`--out-dir` paths and a [`ProcessRunner`].
pub fn run(script_path: &Path, out_dir: &Path, runner: &dyn ProcessRunner) -> Result<PipelineOutcome, PipelineError> {
    let audio_dir = out_dir.join("audio");
    let tmp_dir = out_dir.join(".tmp");
    std::fs::create_dir_all(&audio_dir).map_err(|e| PipelineError::Failed(e.to_string()))?;
    std::fs::create_dir_all(&tmp_dir).map_err(|e| PipelineError::Failed(e.to_string()))?;

    let md = std::fs::read_to_string(script_path).map_err(|e| PipelineError::Failed(e.to_string()))?;
    let ParsedScript { meta, scenes } = parse_script(&md);
    if scenes.is_empty() {
        return Err(PipelineError::NoScenes);
    }

    // Mirrors `meta.voice || undefined` / falsy-string check.
    let voice = meta.get("voice").filter(|v| !v.is_empty()).cloned();
    let speed = meta
        .get("speed")
        .filter(|v| !v.is_empty())
        .and_then(|v| js_parse_float(v))
        .unwrap_or(1.0);
    let gap = meta
        .get("gap")
        .filter(|v| !v.is_empty())
        .and_then(|v| js_parse_float(v))
        .unwrap_or(0.3);

    let script_basename = script_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut log_lines = vec![format!(
        "[narrate] script={} scenes={} voice={} speed={} gap={}s",
        script_basename,
        scenes.len(),
        voice.clone().unwrap_or_else(|| "(env)".to_string()),
        speed,
        gap
    )];

    let gap_file = tmp_dir.join("gap.mp3");
    if gap > 0.0 {
        runner
            .make_silence(gap, &gap_file)
            .map_err(PipelineError::Failed)?;
    }

    let title = meta.get("title").cloned().unwrap_or_else(|| {
        script_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    });

    let mut timeline = Timeline {
        title,
        voice: voice.clone(),
        speed,
        gap,
        total_duration: 0.0,
        scenes: Vec::new(),
        voiceover: None,
    };

    let mut cursor = 0.0f64;
    let mut scene_audio_files: Vec<PathBuf> = Vec::new();

    for (i, scene) in scenes.iter().enumerate() {
        log_lines.push(format!(
            "[narrate] ({}/{}) scene=\"{}\"",
            i + 1,
            scenes.len(),
            scene.id
        ));

        let chunks = split_by_cues(&scene.raw);
        let mut chunk_files: Vec<PathBuf> = Vec::new();
        let mut cue_records: Vec<(String, f64)> = Vec::new();
        let mut chunk_records: Vec<TimelineSceneChunk> = Vec::new();
        let mut scene_internal_cursor = 0.0f64;

        for (j, chunk) in chunks.iter().enumerate() {
            if chunk.text.is_empty() {
                if let Some(cue) = &chunk.cue_after {
                    cue_records.push((cue.clone(), scene_internal_cursor));
                }
                continue;
            }
            let chunk_path = tmp_dir.join(format!("{}-{}.mp3", scene.id, j));
            let result = runner
                .call_tts(&chunk.text, &chunk_path, voice.as_deref(), speed)
                .map_err(PipelineError::Failed)?;
            let chunk_start = scene_internal_cursor;
            chunk_files.push(chunk_path);
            scene_internal_cursor += result.duration;
            chunk_records.push(TimelineSceneChunk {
                text: chunk.text.clone(),
                start: chunk_start,
                end: scene_internal_cursor,
                absolute_start: cursor + chunk_start,
                absolute_end: cursor + scene_internal_cursor,
            });
            let preview: String = chunk.text.chars().take(30).collect();
            let ellipsis = if chunk.text.chars().count() > 30 { "…" } else { "" };
            log_lines.push(format!(
                "  chunk {}: {:.2}s · {} 字 · {}{}",
                j,
                result.duration,
                chunk.text.chars().count(),
                preview,
                ellipsis
            ));
            if let Some(cue) = &chunk.cue_after {
                cue_records.push((cue.clone(), scene_internal_cursor));
            }
        }

        let scene_audio = audio_dir.join(format!("{}.mp3", scene.id));
        if chunk_files.len() == 1 {
            std::fs::copy(&chunk_files[0], &scene_audio).map_err(|e| PipelineError::Failed(e.to_string()))?;
        } else {
            runner
                .ffmpeg_concat(&chunk_files, &scene_audio)
                .map_err(PipelineError::Failed)?;
        }
        let scene_duration = runner
            .get_duration(&scene_audio)
            .map_err(PipelineError::Failed)?;

        if i > 0 && gap > 0.0 {
            scene_audio_files.push(gap_file.clone());
            cursor += gap;
        }
        scene_audio_files.push(scene_audio.clone());

        timeline.scenes.push(TimelineScene {
            id: scene.id.clone(),
            start: cursor,
            end: cursor + scene_duration,
            duration: scene_duration,
            audio: scene_audio
                .strip_prefix(out_dir)
                .unwrap_or(&scene_audio)
                .to_string_lossy()
                .to_string(),
            text: strip_cue_markers(&scene.raw),
            chunks: chunk_records,
            cues: cue_records
                .iter()
                .map(|(id, offset)| Cue {
                    id: id.clone(),
                    offset: *offset,
                    absolute_time: cursor + offset,
                })
                .collect(),
        });

        cursor += scene_duration;
    }

    let voiceover_path = out_dir.join("voiceover.mp3");
    runner
        .ffmpeg_concat(&scene_audio_files, &voiceover_path)
        .map_err(PipelineError::Failed)?;
    timeline.total_duration = runner
        .get_duration(&voiceover_path)
        .map_err(PipelineError::Failed)?;
    timeline.voiceover = Some("voiceover.mp3".to_string());

    let timeline_path = out_dir.join("timeline.json");
    let timeline_json =
        serde_json::to_string_pretty(&timeline).map_err(|e| PipelineError::Failed(e.to_string()))?;
    std::fs::write(&timeline_path, timeline_json).map_err(|e| PipelineError::Failed(e.to_string()))?;

    std::fs::remove_dir_all(&tmp_dir).ok();

    log_lines.push(String::new());
    log_lines.push("[narrate] 完成。".to_string());
    log_lines.push(format!("  voiceover: {}", voiceover_path.display()));
    log_lines.push(format!("  timeline:  {}", timeline_path.display()));
    log_lines.push(format!(
        "  总时长:    {:.2}s ({:.2} min)",
        timeline.total_duration,
        timeline.total_duration / 60.0
    ));
    log_lines.push(format!("  段数:      {}", timeline.scenes.len()));
    let total_cues: usize = timeline.scenes.iter().map(|s| s.cues.len()).sum();
    log_lines.push(format!("  cue 数:    {}", total_cues));

    Ok(PipelineOutcome {
        timeline,
        voiceover_path,
        timeline_path,
        log_lines,
    })
}

/// `std::fs::canonicalize` on Windows prefixes results with `\\?\`
/// (the verbatim-path prefix); strip it so downstream `display()`/path
/// comparisons behave like the JS `path.resolve()` output they mirror.
fn strip_verbatim_prefix(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(stripped) => PathBuf::from(stripped),
        None => p,
    }
}

fn strip_cue_markers(text: &str) -> String {
    let re = Regex::new(r"\[\[cue:[\w-]+\]\]").unwrap();
    re.replace_all(text, "").to_string()
}

/// Top-level CLI entry point, mirroring `main().catch(...)`'s exit-code
/// behavior. Returns the process exit code; the caller decides how to
/// surface `usage_text()` / error messages (e.g. `eprintln!` + this exit
/// code), keeping this function free of direct process-exit side effects
/// for testability.
pub fn run_cli(argv: &[String], runner: &dyn ProcessRunner) -> (i32, Vec<String>) {
    let args = parse_args(argv);
    if args.help || args.script.is_none() || args.out_dir.is_none() {
        return (1, vec![usage_text()]);
    }
    let script_path = PathBuf::from(args.script.unwrap());
    let out_dir = PathBuf::from(args.out_dir.unwrap());
    let script_path = std::fs::canonicalize(&script_path)
        .map(strip_verbatim_prefix)
        .unwrap_or(script_path);
    let out_dir_resolved = if out_dir.is_absolute() {
        out_dir
    } else {
        std::env::current_dir().unwrap_or_default().join(out_dir)
    };

    match run(&script_path, &out_dir_resolved, runner) {
        Ok(outcome) => (0, outcome.log_lines),
        Err(PipelineError::Usage) => (1, vec![usage_text()]),
        Err(PipelineError::NoScenes) => (
            1,
            vec!["错：解说稿没有 ## scene 段，至少一段。".to_string()],
        ),
        Err(PipelineError::Failed(msg)) => (1, vec![format!("narrate-pipeline 失败：{msg}")]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[test]
    fn parse_args_reads_script_and_out_dir() {
        let argv = vec![
            "node".into(),
            "narrate-pipeline.mjs".into(),
            "--script".into(),
            "demo.md".into(),
            "--out-dir".into(),
            "_out".into(),
        ];
        let args = parse_args(&argv);
        assert_eq!(args.script.as_deref(), Some("demo.md"));
        assert_eq!(args.out_dir.as_deref(), Some("_out"));
        assert!(!args.help);
    }

    #[test]
    fn parse_args_help_flags() {
        assert!(parse_args(&["n".into(), "s".into(), "--help".into()]).help);
        assert!(parse_args(&["n".into(), "s".into(), "-h".into()]).help);
    }

    #[test]
    fn parses_frontmatter_and_scenes() {
        let md = "---\ntitle: 什么是 LLM\nvoice: S_JSdgdWk22\nspeed: 1.0\ngap: 0.3\n---\n\n## intro\n大家好。\n\n## what-is\nLLM 全称，[[cue:bigmodel]]它是一个网络。\n";
        let parsed = parse_script(md);
        assert_eq!(parsed.meta.get("title").unwrap(), "什么是 LLM");
        assert_eq!(parsed.scenes.len(), 2);
        assert_eq!(parsed.scenes[0].id, "intro");
        assert_eq!(parsed.scenes[0].raw, "大家好。");
        assert_eq!(parsed.scenes[1].raw, "LLM 全称，[[cue:bigmodel]]它是一个网络。");
    }

    #[test]
    fn no_scenes_yields_empty_vec() {
        assert!(parse_script("just text, no headings").scenes.is_empty());
    }

    #[test]
    fn split_by_cues_basic() {
        let chunks = split_by_cues("A[[cue:x]]B[[cue:y]]C");
        assert_eq!(
            chunks,
            vec![
                Chunk { text: "A".into(), cue_after: Some("x".into()) },
                Chunk { text: "B".into(), cue_after: Some("y".into()) },
                Chunk { text: "C".into(), cue_after: None },
            ]
        );
    }

    #[test]
    fn split_by_cues_adjacent_cues_drop_empty_tail() {
        let chunks = split_by_cues("[[cue:x]][[cue:y]]");
        assert_eq!(
            chunks,
            vec![
                Chunk { text: "".into(), cue_after: Some("x".into()) },
                Chunk { text: "".into(), cue_after: Some("y".into()) },
            ]
        );
    }

    #[test]
    fn js_parse_float_matches_leading_numeric_prefix() {
        assert_eq!(js_parse_float("1.0"), Some(1.0));
        assert_eq!(js_parse_float("  0.3s"), Some(0.3));
        assert_eq!(js_parse_float("abc"), None);
        assert_eq!(js_parse_float("0"), Some(0.0));
    }

    #[test]
    fn strip_cue_markers_removes_all_markers() {
        assert_eq!(strip_cue_markers("A[[cue:x]]B[[cue:y]]C"), "ABC");
    }

    // -- fake ProcessRunner for full-pipeline orchestration tests --

    struct FakeRunner {
        tts_calls: RefCell<Vec<(String, PathBuf, Option<String>, f64)>>,
        durations: RefCell<HashMap<PathBuf, f64>>,
    }

    impl FakeRunner {
        fn new() -> Self {
            Self {
                tts_calls: RefCell::new(Vec::new()),
                durations: RefCell::new(HashMap::new()),
            }
        }
    }

    impl ProcessRunner for FakeRunner {
        fn call_tts(
            &self,
            text: &str,
            out_path: &Path,
            voice: Option<&str>,
            speed: f64,
        ) -> Result<TtsCallResult, String> {
            self.tts_calls.borrow_mut().push((
                text.to_string(),
                out_path.to_path_buf(),
                voice.map(|s| s.to_string()),
                speed,
            ));
            std::fs::write(out_path, b"fake-mp3").map_err(|e| e.to_string())?;
            let duration = 1.5;
            self.durations.borrow_mut().insert(out_path.to_path_buf(), duration);
            Ok(TtsCallResult {
                path: out_path.to_path_buf(),
                bytes: 8,
                duration,
                text_chars: text.chars().count(),
            })
        }

        fn get_duration(&self, file_path: &Path) -> Result<f64, String> {
            Ok(self
                .durations
                .borrow()
                .get(file_path)
                .copied()
                .unwrap_or(2.0))
        }

        fn ffmpeg_concat(&self, inputs: &[PathBuf], output: &Path) -> Result<(), String> {
            let total: f64 = inputs
                .iter()
                .map(|p| self.durations.borrow().get(p).copied().unwrap_or(0.3))
                .sum();
            std::fs::write(output, b"concat").map_err(|e| e.to_string())?;
            self.durations.borrow_mut().insert(output.to_path_buf(), total);
            Ok(())
        }

        fn make_silence(&self, duration: f64, out_path: &Path) -> Result<(), String> {
            std::fs::write(out_path, b"silence").map_err(|e| e.to_string())?;
            self.durations.borrow_mut().insert(out_path.to_path_buf(), duration);
            Ok(())
        }
    }

    #[test]
    fn run_produces_timeline_and_voiceover_for_two_scenes() {
        let tmp = std::env::temp_dir().join(format!(
            "r02-narrate-{}-{}",
            std::process::id(),
            next_test_id()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let script_path = tmp.join("demo.md");
        std::fs::write(
            &script_path,
            "---\ntitle: demo\ngap: 0.3\n---\n\n## intro\nhello[[cue:x]]world\n\n## outro\nbye\n",
        )
        .unwrap();
        let out_dir = tmp.join("out");

        let runner = FakeRunner::new();
        let outcome = run(&script_path, &out_dir, &runner).expect("pipeline should succeed");

        assert_eq!(outcome.timeline.scenes.len(), 2);
        assert_eq!(outcome.timeline.scenes[0].id, "intro");
        assert_eq!(outcome.timeline.scenes[0].cues.len(), 1);
        assert_eq!(outcome.timeline.scenes[0].cues[0].id, "x");
        assert!(outcome.timeline.scenes[1].start > outcome.timeline.scenes[0].end);
        assert_eq!(outcome.timeline.voiceover.as_deref(), Some("voiceover.mp3"));
        assert!(outcome.voiceover_path.exists());
        assert!(outcome.timeline_path.exists());
        assert!(!out_dir.join(".tmp").exists(), "tmp dir should be cleaned up");

        let saved: Timeline =
            serde_json::from_str(&std::fs::read_to_string(&outcome.timeline_path).unwrap()).unwrap();
        assert_eq!(saved, outcome.timeline);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn run_rejects_scriptless_markdown() {
        let tmp = std::env::temp_dir().join(format!(
            "r02-narrate-noscenes-{}-{}",
            std::process::id(),
            next_test_id()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let script_path = tmp.join("empty.md");
        std::fs::write(&script_path, "no scenes here").unwrap();
        let out_dir = tmp.join("out");

        let runner = FakeRunner::new();
        let err = run(&script_path, &out_dir, &runner).unwrap_err();
        assert!(matches!(err, PipelineError::NoScenes));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn run_cli_reports_usage_when_args_missing() {
        let runner = FakeRunner::new();
        let (code, lines) = run_cli(&["node".into(), "narrate-pipeline.mjs".into()], &runner);
        assert_eq!(code, 1);
        assert!(lines[0].contains("--script"));
    }

    static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn next_test_id() -> u64 {
        TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
}
