//! Port of `render-narration.sh`'s pure argument-parsing and path-derivation
//! logic.
//!
//! Mirrors the script's `for arg in "$@"` case statement (flag parsing with
//! defaults) and the path/duration derivations that follow it: `SILENT_MP4`,
//! the default `OUT`, and `RECORD_DURATION = ceil(total_duration + 1)`.
//!
//! Not ported: reading `timeline.json` via `node -e` (that's `narrate`'s
//! [`super::narrate::Timeline`] struct — a caller parses the timeline with
//! `serde_json` directly instead of shelling out to Node), invoking
//! `render-video.js`/`render-video-seek.js`/`mix-voiceover.sh`, and the
//! final `rm -f` cleanup. Those are process-boundary orchestration this
//! script's `main` body performs after argument parsing.

use std::path::{Path, PathBuf};

/// Mirrors the script's parsed flags plus the positional `<html>` argument.
/// Field defaults match the script's variable initializers exactly.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderNarrationArgs {
    pub html: Option<String>,
    pub timeline: Option<String>,
    pub bgm_mood: Option<String>,
    pub bgm: Option<String>,
    pub bgm_volume: String,
    pub no_ducking: bool,
    pub keep_silent: bool,
    pub use_seek: bool,
    pub seek_fps: String,
    pub out: Option<String>,
    pub width: String,
    pub height: String,
}

impl Default for RenderNarrationArgs {
    fn default() -> Self {
        Self {
            html: None,
            timeline: None,
            bgm_mood: None,
            bgm: None,
            bgm_volume: "0.18".to_string(),
            no_ducking: false,
            keep_silent: false,
            use_seek: false,
            seek_fps: "60".to_string(),
            out: None,
            width: "1920".to_string(),
            height: "1080".to_string(),
        }
    }
}

/// Parse the script's argv (excluding argv[0]) into [`RenderNarrationArgs`].
///
/// Mirrors the bash `case "$arg" in ... esac` loop: recognized `--flag=value`
/// / `--flag` forms are consumed; any other leading-`-` argument is an
/// unrecognized-flag error (`未知参数：$arg`); anything else is the
/// positional `HTML` (last one wins, matching bash's unconditional
/// `*) HTML="$arg" ;;` reassignment).
pub fn parse_args(argv: &[String]) -> Result<RenderNarrationArgs, String> {
    let mut out = RenderNarrationArgs::default();
    for arg in argv {
        if let Some(v) = arg.strip_prefix("--timeline=") {
            out.timeline = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--bgm-mood=") {
            out.bgm_mood = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--bgm=") {
            out.bgm = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--bgm-volume=") {
            out.bgm_volume = v.to_string();
        } else if arg == "--no-ducking" {
            out.no_ducking = true;
        } else if arg == "--keep-silent" {
            out.keep_silent = true;
        } else if arg == "--seek" {
            out.use_seek = true;
        } else if let Some(v) = arg.strip_prefix("--seek-fps=") {
            out.seek_fps = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--out=") {
            out.out = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--width=") {
            out.width = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--height=") {
            out.height = v.to_string();
        } else if arg.starts_with('-') {
            return Err(format!("未知参数：{arg}"));
        } else {
            out.html = Some(arg.clone());
        }
    }
    Ok(out)
}

/// `RECORD_DURATION=$(node -e "console.log(Math.ceil($TOTAL_DURATION + 1))")`.
pub fn record_duration(total_duration: f64) -> i64 {
    (total_duration + 1.0).ceil() as i64
}

/// Derived paths mirroring the script's `HTML_ABS`/`HTML_DIR`/`HTML_BASE`/
/// `SILENT_MP4` and default `OUT` (when `--out` wasn't given).
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedPaths {
    pub html_dir: PathBuf,
    pub html_base: String,
    pub silent_mp4: PathBuf,
    pub default_out: PathBuf,
}

/// Mirrors:
/// ```bash
/// HTML_DIR="$(dirname "$HTML_ABS")"
/// HTML_BASE="$(basename "$HTML" .html)"
/// SILENT_MP4="$HTML_DIR/$HTML_BASE.mp4"
/// OUT="$HTML_DIR/$HTML_BASE-narrated.mp4"   # when --out unset
/// ```
/// `html_abs` should already be the resolved absolute path (the script
/// derives it via `cd "$(dirname "$HTML")" && pwd` composed with the
/// basename, which is a filesystem-touching operation out of scope for a
/// pure function; callers resolve that themselves, e.g. with
/// `std::fs::canonicalize`, and pass the result here).
pub fn derive_paths(html_abs: &Path) -> DerivedPaths {
    let html_dir = html_abs
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let html_base = html_abs
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let silent_mp4 = html_dir.join(format!("{html_base}.mp4"));
    let default_out = html_dir.join(format!("{html_base}-narrated.mp4"));
    DerivedPaths {
        html_dir,
        html_base,
        silent_mp4,
        default_out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults_match_script_initializers() {
        let parsed = parse_args(&args(&["demo.html", "--timeline=_narration/timeline.json"])).unwrap();
        assert_eq!(parsed.html.as_deref(), Some("demo.html"));
        assert_eq!(parsed.timeline.as_deref(), Some("_narration/timeline.json"));
        assert_eq!(parsed.bgm_volume, "0.18");
        assert_eq!(parsed.seek_fps, "60");
        assert_eq!(parsed.width, "1920");
        assert_eq!(parsed.height, "1080");
        assert!(!parsed.no_ducking);
        assert!(!parsed.keep_silent);
        assert!(!parsed.use_seek);
        assert!(parsed.out.is_none());
        assert!(parsed.bgm_mood.is_none());
        assert!(parsed.bgm.is_none());
    }

    #[test]
    fn parses_all_flags() {
        let parsed = parse_args(&args(&[
            "demo.html",
            "--timeline=t.json",
            "--bgm-mood=educational",
            "--bgm=custom.mp3",
            "--bgm-volume=0.5",
            "--no-ducking",
            "--keep-silent",
            "--seek",
            "--seek-fps=30",
            "--out=out.mp4",
            "--width=1280",
            "--height=720",
        ]))
        .unwrap();
        assert_eq!(parsed.bgm_mood.as_deref(), Some("educational"));
        assert_eq!(parsed.bgm.as_deref(), Some("custom.mp3"));
        assert_eq!(parsed.bgm_volume, "0.5");
        assert!(parsed.no_ducking);
        assert!(parsed.keep_silent);
        assert!(parsed.use_seek);
        assert_eq!(parsed.seek_fps, "30");
        assert_eq!(parsed.out.as_deref(), Some("out.mp4"));
        assert_eq!(parsed.width, "1280");
        assert_eq!(parsed.height, "720");
    }

    #[test]
    fn unknown_flag_errors() {
        let err = parse_args(&args(&["demo.html", "--bogus"])).unwrap_err();
        assert_eq!(err, "未知参数：--bogus");
    }

    #[test]
    fn last_positional_wins() {
        let parsed = parse_args(&args(&["first.html", "second.html"])).unwrap();
        assert_eq!(parsed.html.as_deref(), Some("second.html"));
    }

    #[test]
    fn record_duration_ceils_plus_one() {
        assert_eq!(record_duration(29.2), 31);
        assert_eq!(record_duration(30.0), 31);
        assert_eq!(record_duration(0.0), 1);
    }

    #[test]
    fn derive_paths_matches_script() {
        let derived = derive_paths(Path::new("/proj/out/demo.html"));
        assert_eq!(derived.html_dir, PathBuf::from("/proj/out"));
        assert_eq!(derived.html_base, "demo");
        assert_eq!(derived.silent_mp4, PathBuf::from("/proj/out/demo.mp4"));
        assert_eq!(
            derived.default_out,
            PathBuf::from("/proj/out/demo-narrated.mp4")
        );
    }
}
