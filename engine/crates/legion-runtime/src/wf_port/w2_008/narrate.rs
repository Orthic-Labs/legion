//! Port of `narrate-pipeline.mjs`'s pure parsing/assembly logic.
//!
//! Mirrors `parseScript` (frontmatter + `## scene-id` block parsing) and
//! `splitByCues` (`[[cue:id]]` marker splitting) exactly, including the
//! source's behavior of trimming chunk text and dropping empty non-cue chunks
//! (`chunks.filter((c) => c.text.length > 0 || c.cueAfter)`).
//!
//! Not ported: `callTTS` (shells out to `tts-doubao.mjs`), `getDuration`
//! (shells out to `ffprobe`), `ffmpegConcat`/`makeSilence` (shell out to
//! `ffmpeg`), and `main()`'s file I/O and cursor-accumulation orchestration
//! loop. Those are process-boundary glue around the pure functions below;
//! [`Timeline`] and [`TimelineScene`]/[`TimelineSceneChunk`]/[`Cue`] give a
//! Rust caller the same `timeline.json` shape `main()` produces, for a
//! caller that performs that orchestration itself (e.g. via
//! `std::process::Command` for `ffmpeg`/`ffprobe`/the TTS call).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Frontmatter + parsed `## scene-id` blocks. Mirrors `parseScript`'s
/// `{ meta, scenes }` return shape. `meta` keeps raw string values exactly as
/// found (the JS reads `meta.voice`, `meta.speed`, `meta.gap`, `meta.title` as
/// strings and parses `speed`/`gap` with `parseFloat` at the call site).
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

/// Parse frontmatter + `## scene-id` blocks from the narration markdown.
///
/// Mirrors `parseScript(md)`:
/// - Frontmatter is an optional leading `---\n...\n---\n` block; each
///   `key: value` line (first `:` splits key/value, both trimmed) becomes a
///   `meta` entry. Lines without a `:` are skipped.
/// - Scenes are `^## id\n<body>` blocks up to the next `## id` heading or end
///   of string; `id` matches `[\w-]+`; the body is trimmed.
pub fn parse_script(md: &str) -> ParsedScript {
    let mut meta = BTreeMap::new();
    let mut body = md;

    if let Some(fm) = extract_frontmatter(md) {
        for line in fm.trim_end_matches('\n').split('\n') {
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_string();
                let val = line[idx + 1..].trim().to_string();
                meta.insert(key, val);
            }
        }
        // Advance body past the whole `---\n...\n---\n` block, matching
        // `body = md.slice(fmMatch[0].length)`.
        let fm_len = frontmatter_block_len(md);
        body = &md[fm_len..];
    }

    let scenes = parse_scenes(body);
    ParsedScript { meta, scenes }
}

/// Returns the inner text of a leading `---\n...\n---\n` frontmatter block, if
/// present, mirroring the JS regex `/^---\n([\s\S]*?)\n---\n/`.
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
    //
    // Single pass: for each `## id` heading line, record its id and the byte
    // offset where its content starts (right after the heading line). A
    // scene's content ends at the *next* heading's content-start offset
    // (i.e. the next heading's own line-start), or at end-of-body for the
    // last scene.
    let mut ids = Vec::new();
    let mut heading_line_starts = Vec::new();
    let mut content_starts = Vec::new();

    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        let trimmed_line = line.trim_end_matches('\n');
        if let Some(rest) = trimmed_line.strip_prefix("## ") {
            let id_part = rest.trim_start();
            let id: String = id_part
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            let after_id = &id_part[id.len()..];
            // JS requires `\s*` (whitespace only) after the id before the
            // newline for the heading to match.
            if !id.is_empty() && after_id.trim().is_empty() {
                ids.push(id);
                heading_line_starts.push(offset);
                content_starts.push(offset + line.len());
            }
        }
        offset += line.len();
    }

    let mut scenes = Vec::with_capacity(ids.len());
    for i in 0..ids.len() {
        let content_end = heading_line_starts.get(i + 1).copied().unwrap_or(body.len());
        let raw = body[content_starts[i]..content_end].trim().to_string();
        scenes.push(Scene {
            id: ids[i].clone(),
            raw,
        });
    }
    scenes
}

/// A cue-delimited chunk of scene text. Mirrors `splitByCues`'s
/// `{ text, cueAfter? }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub text: String,
    pub cue_after: Option<String>,
}

/// Split a scene's text by `[[cue:id]]` markers into chunks.
///
/// Mirrors `splitByCues(text)`: each `[[cue:id]]` marker ends the preceding
/// (trimmed) chunk and records `cue_after = id`; a final tail chunk (no cue)
/// is always appended. Chunks are then filtered to keep only those with
/// non-empty text *or* a `cue_after` (matching
/// `chunks.filter((c) => c.text.length > 0 || c.cueAfter)`), so an
/// empty-text tail with no cue is dropped.
pub fn split_by_cues(text: &str) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut last_idx = 0usize;
    let mut idx = 0usize;
    let bytes = text.as_bytes();
    while idx < bytes.len() {
        if let Some(rel) = text[idx..].find("[[cue:") {
            let start = idx + rel;
            if let Some(close_rel) = text[start..].find("]]") {
                let close = start + close_rel;
                let id = &text[start + "[[cue:".len()..close];
                let before = text[last_idx..start].trim().to_string();
                chunks.push(Chunk {
                    text: before,
                    cue_after: Some(id.to_string()),
                });
                last_idx = close + "]]".len();
                idx = last_idx;
                continue;
            }
        }
        break;
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

/// Mirrors a `timeline.json` cue record: `{ id, offset, absoluteTime }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cue {
    pub id: String,
    pub offset: f64,
    #[serde(rename = "absoluteTime")]
    pub absolute_time: f64,
}

/// Mirrors a `timeline.json` scene's `chunks[]` record.
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

/// Mirrors a `timeline.json` `scenes[]` entry.
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

/// Mirrors the top-level `timeline.json` shape written by `main()`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frontmatter_and_scenes() {
        let md = "---\ntitle: 什么是 LLM\nvoice: S_JSdgdWk22\nspeed: 1.0\ngap: 0.3\n---\n\n## intro\n大家好。\n\n## what-is\nLLM 全称，[[cue:bigmodel]]它是一个网络。\n";
        let parsed = parse_script(md);
        assert_eq!(parsed.meta.get("title").unwrap(), "什么是 LLM");
        assert_eq!(parsed.meta.get("voice").unwrap(), "S_JSdgdWk22");
        assert_eq!(parsed.meta.get("speed").unwrap(), "1.0");
        assert_eq!(parsed.meta.get("gap").unwrap(), "0.3");
        assert_eq!(parsed.scenes.len(), 2);
        assert_eq!(parsed.scenes[0].id, "intro");
        assert_eq!(parsed.scenes[0].raw, "大家好。");
        assert_eq!(parsed.scenes[1].id, "what-is");
        assert_eq!(parsed.scenes[1].raw, "LLM 全称，[[cue:bigmodel]]它是一个网络。");
    }

    #[test]
    fn parses_scenes_without_frontmatter() {
        let md = "## a\ntext a\n\n## b\ntext b\n";
        let parsed = parse_script(md);
        assert!(parsed.meta.is_empty());
        assert_eq!(parsed.scenes.len(), 2);
        assert_eq!(parsed.scenes[0].id, "a");
        assert_eq!(parsed.scenes[0].raw, "text a");
        assert_eq!(parsed.scenes[1].id, "b");
        assert_eq!(parsed.scenes[1].raw, "text b");
    }

    #[test]
    fn no_scenes_yields_empty_vec() {
        let parsed = parse_script("just some text, no headings");
        assert!(parsed.scenes.is_empty());
    }

    #[test]
    fn split_by_cues_basic() {
        let chunks = split_by_cues("A[[cue:x]]B[[cue:y]]C");
        assert_eq!(
            chunks,
            vec![
                Chunk {
                    text: "A".into(),
                    cue_after: Some("x".into())
                },
                Chunk {
                    text: "B".into(),
                    cue_after: Some("y".into())
                },
                Chunk {
                    text: "C".into(),
                    cue_after: None
                },
            ]
        );
    }

    #[test]
    fn split_by_cues_adjacent_cues_drop_empty_non_cue_tail() {
        // "[[cue:x]][[cue:y]]" -> before "" cueAfter x; before "" cueAfter y;
        // tail "" no cue -> filtered out (empty text, no cue).
        let chunks = split_by_cues("[[cue:x]][[cue:y]]");
        assert_eq!(
            chunks,
            vec![
                Chunk {
                    text: "".into(),
                    cue_after: Some("x".into())
                },
                Chunk {
                    text: "".into(),
                    cue_after: Some("y".into())
                },
            ]
        );
    }

    #[test]
    fn split_by_cues_no_cues_single_chunk() {
        let chunks = split_by_cues("  just text  ");
        assert_eq!(
            chunks,
            vec![Chunk {
                text: "just text".into(),
                cue_after: None
            }]
        );
    }

    #[test]
    fn split_by_cues_all_empty_drops_everything() {
        let chunks = split_by_cues("   ");
        assert!(chunks.is_empty());
    }

    #[test]
    fn timeline_round_trips_through_json_with_expected_field_names() {
        let timeline = Timeline {
            title: "demo".into(),
            voice: Some("S_JSdgdWk22".into()),
            speed: 1.0,
            gap: 0.3,
            total_duration: 12.5,
            scenes: vec![TimelineScene {
                id: "intro".into(),
                start: 0.0,
                end: 5.0,
                duration: 5.0,
                audio: "audio/intro.mp3".into(),
                text: "大家好".into(),
                chunks: vec![TimelineSceneChunk {
                    text: "大家好".into(),
                    start: 0.0,
                    end: 5.0,
                    absolute_start: 0.0,
                    absolute_end: 5.0,
                }],
                cues: vec![Cue {
                    id: "bigmodel".into(),
                    offset: 2.0,
                    absolute_time: 2.0,
                }],
            }],
            voiceover: Some("voiceover.mp3".into()),
        };
        let json = serde_json::to_string(&timeline).unwrap();
        assert!(json.contains("\"totalDuration\":12.5"));
        assert!(json.contains("\"absoluteStart\":0.0"));
        assert!(json.contains("\"absoluteTime\":2.0"));
        let back: Timeline = serde_json::from_str(&json).unwrap();
        assert_eq!(back, timeline);
    }
}
