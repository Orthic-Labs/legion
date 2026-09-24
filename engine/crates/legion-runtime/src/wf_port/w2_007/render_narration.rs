//! Port of `skills/designer/engine/huashu/scripts/render-narration.sh`:
//! the two-step pipeline that (1) renders an HTML narration animation to a
//! silent MP4 (`render-video.js` or, with `--seek`, `render-video-seek.js`)
//! and (2) mixes in `voiceover.mp3` (and optional BGM) via `mix-voiceover.sh`.
//!
//! This module ports every deterministic piece: argument parsing, the
//! `timeline.json` field reads that used to go through `node -e`, the
//! record-duration computation (`totalDuration + 1s` safety buffer,
//! ceiling), path derivation, and the status/summary lines. The actual
//! Chrome recording and `ffmpeg` execution are driven by the caller (see
//! `legion script designer/render-narration` in `script.rs`), which already
//! owns real implementations of both for `designer/render-video[-seek]` and
//! can reuse them here instead of a third copy.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Options {
    pub html: Option<String>,
    pub timeline: Option<String>,
    pub bgm_mood: Option<String>,
    pub bgm: Option<String>,
    pub bgm_volume: String,
    pub ducking: bool,
    pub keep_silent: bool,
    pub use_seek: bool,
    pub seek_fps: String,
    pub out: Option<String>,
    pub width: String,
    pub height: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            html: None,
            timeline: None,
            bgm_mood: None,
            bgm: None,
            bgm_volume: "0.18".to_string(),
            ducking: true,
            keep_silent: false,
            use_seek: false,
            seek_fps: "60".to_string(),
            out: None,
            width: "1920".to_string(),
            height: "1080".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownFlag(pub String);

/// Port of the `for arg in "$@"; do case "$arg" in ... esac` loop.
pub fn parse_args<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<Options, UnknownFlag> {
    let mut opts = Options::default();
    for arg in args {
        if let Some(v) = arg.strip_prefix("--timeline=") {
            opts.timeline = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--bgm-mood=") {
            opts.bgm_mood = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--bgm=") {
            opts.bgm = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--bgm-volume=") {
            opts.bgm_volume = v.to_string();
        } else if arg == "--no-ducking" {
            opts.ducking = false;
        } else if arg == "--keep-silent" {
            opts.keep_silent = true;
        } else if arg == "--seek" {
            opts.use_seek = true;
        } else if let Some(v) = arg.strip_prefix("--seek-fps=") {
            opts.seek_fps = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--out=") {
            opts.out = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--width=") {
            opts.width = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--height=") {
            opts.height = v.to_string();
        } else if arg.starts_with('-') {
            return Err(UnknownFlag(arg.to_string()));
        } else {
            opts.html = Some(arg.to_string());
        }
    }
    Ok(opts)
}

pub const USAGE_LINE: &str = "Usage: bash render-narration.sh <html> --timeline=<path> [options]";
pub const MISSING_TIMELINE_LINE: &str = "\u{2717} \u{7f3a} --timeline=<path>（timeline.json \u{7531} narrate-pipeline.mjs \u{751f}\u{6210}）";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    MissingOrNoSuchHtml,
    MissingOrNoSuchTimeline,
}

pub fn validate(
    opts: &Options,
    html_exists: impl Fn(&str) -> bool,
    timeline_exists: impl Fn(&str) -> bool,
) -> Result<(), ValidationError> {
    match &opts.html {
        Some(h) if html_exists(h) => {}
        _ => return Err(ValidationError::MissingOrNoSuchHtml),
    }
    match &opts.timeline {
        Some(t) if timeline_exists(t) => {}
        _ => return Err(ValidationError::MissingOrNoSuchTimeline),
    }
    Ok(())
}

/// Fields read from `timeline.json`, mirroring the two `node -e` calls:
/// `.totalDuration` and `.voiceover || 'voiceover.mp3'`.
#[derive(Debug, Clone, PartialEq)]
pub struct Timeline {
    pub total_duration: f64,
    pub voiceover_rel: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineParseError(pub String);

/// Port of:
/// ```text
/// node -e "console.log(JSON.parse(require('fs').readFileSync('$TIMELINE','utf8')).totalDuration)"
/// node -e "console.log(JSON.parse(require('fs').readFileSync('$TIMELINE','utf8')).voiceover || 'voiceover.mp3')"
/// ```
pub fn parse_timeline(json_text: &str) -> Result<Timeline, TimelineParseError> {
    let value: serde_json::Value =
        serde_json::from_str(json_text).map_err(|e| TimelineParseError(e.to_string()))?;
    let total_duration = value
        .get("totalDuration")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| TimelineParseError("timeline.json missing totalDuration".to_string()))?;
    let voiceover_rel = value
        .get("voiceover")
        .and_then(|v| v.as_str())
        .unwrap_or("voiceover.mp3")
        .to_string();
    Ok(Timeline {
        total_duration,
        voiceover_rel,
    })
}

/// Port of `RECORD_DURATION=$(node -e "console.log(Math.ceil($TOTAL_DURATION + 1))")`.
pub fn record_duration(total_duration: f64) -> u64 {
    (total_duration + 1.0).ceil() as u64
}

/// Paths derived from the HTML input, mirroring the shell's
/// `HTML_ABS`/`HTML_DIR`/`HTML_BASE`/`SILENT_MP4` and the `--out` default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub html_abs: PathBuf,
    pub silent_mp4: PathBuf,
    pub out: PathBuf,
}

pub fn derive_paths(html_abs: &Path, out_override: Option<&str>) -> Paths {
    let dir = html_abs.parent().map(Path::to_path_buf).unwrap_or_default();
    let base = html_abs
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let silent_mp4 = dir.join(format!("{base}.mp4"));
    let out = match out_override {
        Some(o) => PathBuf::from(o),
        None => dir.join(format!("{base}-narrated.mp4")),
    };
    Paths {
        html_abs: html_abs.to_path_buf(),
        silent_mp4,
        out,
    }
}

/// Port of the `═══ render-narration ═══` status block.
pub fn status_block(
    opts: &Options,
    paths: &Paths,
    timeline_path: &str,
    voiceover: &Path,
    total_duration: f64,
    record_duration: u64,
) -> String {
    let mut lines = vec![
        "\u{2550}\u{2550}\u{2550} render-narration \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}"
            .to_string(),
        format!("  HTML:        {}", paths.html_abs.display()),
        format!("  Timeline:    {timeline_path}"),
        format!("  Voiceover:   {}", voiceover.display()),
        format!("  Total dur:   {total_duration}s (\u{5f55} {record_duration}s)"),
        format!("  \u{5c3a}\u{5bf8}:        {}\u{d7}{}", opts.width, opts.height),
    ];
    if let Some(mood) = &opts.bgm_mood {
        lines.push(format!("  BGM mood:    {mood}"));
    }
    if let Some(bgm) = &opts.bgm {
        lines.push(format!("  BGM:         {bgm}"));
    }
    lines.push(format!("  \u{6700}\u{7ec8}\u{8f93}\u{51fa}:    {}", paths.out.display()));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flags_matching_shell_case() {
        let opts = parse_args([
            "demo.html",
            "--timeline=_narration/timeline.json",
            "--bgm-mood=educational",
            "--seek",
            "--seek-fps=30",
            "--keep-silent",
            "--width=1280",
            "--height=720",
        ])
        .unwrap();
        assert_eq!(opts.html.as_deref(), Some("demo.html"));
        assert_eq!(opts.timeline.as_deref(), Some("_narration/timeline.json"));
        assert_eq!(opts.bgm_mood.as_deref(), Some("educational"));
        assert!(opts.use_seek);
        assert_eq!(opts.seek_fps, "30");
        assert!(opts.keep_silent);
        assert_eq!(opts.width, "1280");
        assert_eq!(opts.height, "720");
        assert!(opts.ducking);
    }

    #[test]
    fn unknown_flag_errors() {
        assert_eq!(parse_args(["--bogus"]).unwrap_err(), UnknownFlag("--bogus".to_string()));
    }

    #[test]
    fn validates_missing_html_before_timeline() {
        let opts = parse_args(["--timeline=t.json"]).unwrap();
        assert_eq!(
            validate(&opts, |_| false, |_| true).unwrap_err(),
            ValidationError::MissingOrNoSuchHtml
        );
    }

    #[test]
    fn validates_missing_timeline() {
        let opts = parse_args(["demo.html"]).unwrap();
        assert_eq!(
            validate(&opts, |_| true, |_| false).unwrap_err(),
            ValidationError::MissingOrNoSuchTimeline
        );
    }

    #[test]
    fn parses_timeline_json_with_defaults() {
        let tl = parse_timeline(r#"{"totalDuration": 12.4}"#).unwrap();
        assert_eq!(tl.total_duration, 12.4);
        assert_eq!(tl.voiceover_rel, "voiceover.mp3");
    }

    #[test]
    fn parses_timeline_json_explicit_voiceover() {
        let tl = parse_timeline(r#"{"totalDuration": 3, "voiceover": "vo.mp3"}"#).unwrap();
        assert_eq!(tl.voiceover_rel, "vo.mp3");
    }

    #[test]
    fn timeline_missing_total_duration_errors() {
        assert!(parse_timeline(r#"{"voiceover": "v.mp3"}"#).is_err());
    }

    #[test]
    fn record_duration_ceils_plus_one_second() {
        assert_eq!(record_duration(12.4), 14);
        assert_eq!(record_duration(9.0), 10);
    }

    #[test]
    fn derive_paths_defaults_to_narrated_suffix() {
        let paths = derive_paths(Path::new("/tmp/demo/anim.html"), None);
        assert_eq!(paths.silent_mp4, Path::new("/tmp/demo/anim.mp4"));
        assert_eq!(paths.out, Path::new("/tmp/demo/anim-narrated.mp4"));
    }

    #[test]
    fn derive_paths_honors_out_override() {
        let paths = derive_paths(Path::new("/tmp/demo/anim.html"), Some("/tmp/out.mp4"));
        assert_eq!(paths.out, Path::new("/tmp/out.mp4"));
    }
}
