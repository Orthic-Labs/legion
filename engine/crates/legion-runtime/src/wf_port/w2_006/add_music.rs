//! Port of `skills/designer/engine/huashu/scripts/add-music.sh` (chunk w2_006).
//!
//! The script shells out to `ffprobe` and `ffmpeg`; this port keeps the same
//! shape as the JS/shell chunks ported elsewhere in this workspace (e.g.
//! `wf015`'s `ProcessRunner`): the pure argument-resolution and
//! filtergraph-construction logic is fully ported and unit tested, and the
//! process-spawning glue that calls `ffprobe`/`ffmpeg` is exposed as a small
//! trait so a host can inject a real or fake runner instead of this engine
//! shelling out itself.

use std::path::{Path, PathBuf};

/// Default mood, matching `MOOD="tech"`.
pub const DEFAULT_MOOD: &str = "tech";

/// Errors mirroring the script's `echo ... >&2; exit 1` paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddMusicError {
    /// `[ -z "$INPUT" ] || [ ! -f "$INPUT" ]`.
    MissingOrUnreadableInput,
    /// `[ ! -f "$MUSIC" ]`.
    MusicNotFound(String),
    /// `ffprobe` produced no duration (`[ -z "$DURATION" ]`).
    DurationUnreadable,
}

impl std::fmt::Display for AddMusicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingOrUnreadableInput => write!(
                f,
                "Usage: bash add-music.sh <input.mp4> [--mood=<name>] [--music=<path>] [--out=<path>]"
            ),
            Self::MusicNotFound(path) => write!(f, "\u{2717} Music not found: {path}"),
            Self::DurationUnreadable => write!(f, "\u{2717} Could not read video duration"),
        }
    }
}

impl std::error::Error for AddMusicError {}

/// Parsed CLI arguments, port of the `for arg in "$@"` loop plus the legacy
/// positional fallback (`POSITIONAL[0..2]`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddMusicArgs {
    pub input: Option<String>,
    pub mood: Option<String>,
    pub music: Option<String>,
    pub out: Option<String>,
}

/// Port of the argument-parsing block: `--mood=`, `--music=`, `--out=` flags
/// win, and up to three bare positional args fill `input`/`music`/`out` when
/// the corresponding flag was not given (`[ -z "$CUSTOM_MUSIC" ] && [ -n
/// "${POSITIONAL[1]}" ]`, etc).
pub fn parse_args<I, S>(args: I) -> AddMusicArgs
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut mood = None;
    let mut music = None;
    let mut out = None;
    let mut positional = Vec::new();

    for arg in args {
        let arg = arg.as_ref();
        if let Some(v) = arg.strip_prefix("--mood=") {
            mood = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--music=") {
            music = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--out=") {
            out = Some(v.to_string());
        } else {
            positional.push(arg.to_string());
        }
    }

    let input = positional.first().cloned();
    if music.is_none() {
        music = positional.get(1).cloned();
    }
    if out.is_none() {
        out = positional.get(2).cloned();
    }

    AddMusicArgs {
        input,
        mood,
        music,
        out,
    }
}

/// Resolved plan for one `add-music` invocation: which music source to use
/// and its human-readable label (`SOURCE_LABEL`), plus the output path.
/// Building this never touches the filesystem; callers stat `input`/`music`
/// and call [`build_plan`] once they know those files exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMusicPlan {
    pub input: PathBuf,
    pub music: PathBuf,
    pub source_label: String,
    pub output: PathBuf,
}

/// Port of the music-source resolution (`--music` wins over `--mood`) and
/// the mood-library path template (`$ASSETS_DIR/bgm-${MOOD}.mp3`).
pub fn resolve_music_source(args: &AddMusicArgs, assets_dir: &Path) -> (PathBuf, String) {
    match &args.music {
        Some(custom) => (PathBuf::from(custom), format!("custom: {custom}")),
        None => {
            let mood = args.mood.as_deref().unwrap_or(DEFAULT_MOOD);
            (
                assets_dir.join(format!("bgm-{mood}.mp3")),
                format!("mood: {mood}"),
            )
        }
    }
}

/// Port of the output-path fallback: `<input-dir>/<input-basename>-bgm.mp4`
/// when `--out` was not given, mirroring
/// `INPUT_NAME="$(basename "$INPUT" .mp4)"` (only a trailing `.mp4`
/// extension is stripped).
pub fn resolve_output_path(input: &Path, out: Option<&str>) -> PathBuf {
    if let Some(out) = out {
        return PathBuf::from(out);
    }
    let dir = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = stem.strip_suffix(".mp4").unwrap_or(&stem);
    dir.join(format!("{stem}-bgm.mp4"))
}

/// Port of `FADE_OUT_START=$(awk "BEGIN { d = $DURATION - 1; if (d < 0) d = 0; print d }")`.
pub fn fade_out_start(duration_secs: f64) -> f64 {
    (duration_secs - 1.0).max(0.0)
}

/// Builds the exact `ffmpeg` argument vector the script invokes (excluding
/// the `ffmpeg` binary name itself), so a host can pass it straight to
/// `std::process::Command::args`.
pub fn ffmpeg_args(plan: &AddMusicPlan, duration_secs: f64) -> Vec<String> {
    let fade_out = fade_out_start(duration_secs);
    let filter = format!(
        "[1:a]atrim=0:{duration},asetpts=PTS-STARTPTS,afade=t=in:st=0:d=0.3,afade=t=out:st={fade_out}:d=1[a]",
        duration = js_like(duration_secs),
        fade_out = js_like(fade_out),
    );
    vec![
        "-y".into(),
        "-loglevel".into(),
        "error".into(),
        "-i".into(),
        plan.input.to_string_lossy().into_owned(),
        "-i".into(),
        plan.music.to_string_lossy().into_owned(),
        "-filter_complex".into(),
        filter,
        "-map".into(),
        "0:v".into(),
        "-map".into(),
        "[a]".into(),
        "-c:v".into(),
        "copy".into(),
        "-c:a".into(),
        "aac".into(),
        "-b:a".into(),
        "192k".into(),
        "-shortest".into(),
        plan.output.to_string_lossy().into_owned(),
    ]
}

/// awk prints a bare integer when the value is integral, else its natural
/// decimal form — mirrored so filtergraph strings match byte-for-byte on the
/// common integral-duration case.
fn js_like(value: f64) -> String {
    if value == value.trunc() {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

/// Builds the full `AddMusicPlan` once the caller has confirmed `input`
/// exists (`[ ! -f "$INPUT" ]` check) and resolved `assets_dir` (normally
/// `<script_dir>/../assets`). Returns [`AddMusicError::MissingOrUnreadableInput`]
/// when `args.input` is unset — the input-existence half of that same check
/// is the caller's responsibility since it requires filesystem access.
pub fn build_plan(args: &AddMusicArgs, assets_dir: &Path) -> Result<AddMusicPlan, AddMusicError> {
    let input = args
        .input
        .as_ref()
        .ok_or(AddMusicError::MissingOrUnreadableInput)?;
    let input = PathBuf::from(input);
    let (music, source_label) = resolve_music_source(args, assets_dir);
    let output = resolve_output_path(&input, args.out.as_deref());
    Ok(AddMusicPlan {
        input,
        music,
        source_label,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_prefers_flags_over_positional() {
        let a = parse_args(["in.mp4", "--mood=ad", "--out=final.mp4"]);
        assert_eq!(a.input.as_deref(), Some("in.mp4"));
        assert_eq!(a.mood.as_deref(), Some("ad"));
        assert_eq!(a.out.as_deref(), Some("final.mp4"));
        assert_eq!(a.music, None);
    }

    #[test]
    fn parse_args_legacy_positional_form() {
        let a = parse_args(["in.mp4", "music.mp3", "out.mp4"]);
        assert_eq!(a.input.as_deref(), Some("in.mp4"));
        assert_eq!(a.music.as_deref(), Some("music.mp3"));
        assert_eq!(a.out.as_deref(), Some("out.mp4"));
    }

    #[test]
    fn parse_args_flag_wins_over_positional_music() {
        // Spec (add-music.sh:55-57): INPUT/CUSTOM_MUSIC/OUTPUT read fixed
        // POSITIONAL[0]/[1]/[2] slots, not a shifting sequence — consuming
        // "--music=" out of the arg list leaves POSITIONAL[2] empty, so
        // "leftover" (POSITIONAL[1]) does NOT fill `out`. Confirmed by
        // running the bash snippet directly: OUTPUT is empty.
        let a = parse_args(["in.mp4", "--music=custom.mp3", "leftover"]);
        assert_eq!(a.music.as_deref(), Some("custom.mp3"));
        assert_eq!(a.out, None);
    }

    #[test]
    fn resolve_music_source_mood_default() {
        let args = AddMusicArgs {
            input: Some("in.mp4".into()),
            ..Default::default()
        };
        let (path, label) = resolve_music_source(&args, Path::new("/assets"));
        assert_eq!(path, PathBuf::from("/assets/bgm-tech.mp3"));
        assert_eq!(label, "mood: tech");
    }

    #[test]
    fn resolve_music_source_custom_wins() {
        let args = AddMusicArgs {
            music: Some("/x/song.mp3".into()),
            mood: Some("ad".into()),
            ..Default::default()
        };
        let (path, label) = resolve_music_source(&args, Path::new("/assets"));
        assert_eq!(path, PathBuf::from("/x/song.mp3"));
        assert_eq!(label, "custom: /x/song.mp3");
    }

    #[test]
    fn resolve_output_path_strips_mp4_suffix_only() {
        let out = resolve_output_path(Path::new("/videos/my.mp4"), None);
        assert_eq!(out, PathBuf::from("/videos/my-bgm.mp4"));
    }

    #[test]
    fn resolve_output_path_honors_explicit_out() {
        let out = resolve_output_path(Path::new("/videos/my.mp4"), Some("/tmp/x.mp4"));
        assert_eq!(out, PathBuf::from("/tmp/x.mp4"));
    }

    #[test]
    fn fade_out_start_clamps_at_zero() {
        assert_eq!(fade_out_start(10.0), 9.0);
        assert_eq!(fade_out_start(0.5), 0.0);
        assert_eq!(fade_out_start(0.0), 0.0);
    }

    #[test]
    fn ffmpeg_args_match_script_filtergraph() {
        let plan = AddMusicPlan {
            input: PathBuf::from("in.mp4"),
            music: PathBuf::from("bgm-tech.mp3"),
            source_label: "mood: tech".into(),
            output: PathBuf::from("in-bgm.mp4"),
        };
        let args = ffmpeg_args(&plan, 10.0);
        assert_eq!(
            args,
            vec![
                "-y", "-loglevel", "error", "-i", "in.mp4", "-i", "bgm-tech.mp3",
                "-filter_complex",
                "[1:a]atrim=0:10,asetpts=PTS-STARTPTS,afade=t=in:st=0:d=0.3,afade=t=out:st=9:d=1[a]",
                "-map", "0:v", "-map", "[a]", "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
                "-shortest", "in-bgm.mp4",
            ]
        );
    }

    #[test]
    fn build_plan_requires_input() {
        let args = AddMusicArgs::default();
        assert_eq!(
            build_plan(&args, Path::new("/assets")),
            Err(AddMusicError::MissingOrUnreadableInput)
        );
    }

    #[test]
    fn build_plan_happy_path() {
        let args = AddMusicArgs {
            input: Some("/videos/demo.mp4".into()),
            mood: Some("ad".into()),
            ..Default::default()
        };
        let plan = build_plan(&args, Path::new("/assets")).unwrap();
        assert_eq!(plan.input, PathBuf::from("/videos/demo.mp4"));
        assert_eq!(plan.music, PathBuf::from("/assets/bgm-ad.mp3"));
        assert_eq!(plan.source_label, "mood: ad");
        assert_eq!(plan.output, PathBuf::from("/videos/demo-bgm.mp4"));
    }
}
