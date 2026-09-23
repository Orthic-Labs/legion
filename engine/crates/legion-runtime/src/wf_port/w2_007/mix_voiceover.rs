//! Port of `skills/designer/engine/huashu/scripts/mix-voiceover.sh` (chunk
//! w2_007): mixes a voiceover track (and optional BGM, with sidechain
//! ducking) onto a video's audio via `ffmpeg`.
//!
//! Every piece of the shell script is deterministic argument handling and
//! `ffmpeg` filter-graph string construction — no browser, no external API —
//! so it is ported in full: flag parsing, the `--bgm-mood` → asset-path
//! resolution, the default output path (`<input>-voiced.mp4`), and the
//! three `ffmpeg` invocations (voice-only, voice+BGM+ducking,
//! voice+BGM static mix) built as an argument vector a caller passes to
//! `std::process::Command`. This module does not itself spawn `ffmpeg` —
//! it only builds the command, mirroring the shell script's `set -e` +
//! single `ffmpeg ...` line as data the integrator's process-execution
//! layer runs.

use std::path::{Path, PathBuf};

/// Port of the flag defaults: `BGM_VOLUME="0.18"`, `VOICE_VOLUME="1.0"`,
/// `DUCKING="1"`.
pub const DEFAULT_BGM_VOLUME: &str = "0.18";
pub const DEFAULT_VOICE_VOLUME: &str = "1.0";

/// Parsed form of the script's `for arg in "$@"; do case "$arg" in ... esac`
/// loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub input: Option<String>,
    pub voiceover: Option<String>,
    pub bgm: Option<String>,
    pub bgm_mood: Option<String>,
    pub bgm_volume: String,
    pub voice_volume: String,
    pub ducking: bool,
    pub out: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: None,
            voiceover: None,
            bgm: None,
            bgm_mood: None,
            bgm_volume: DEFAULT_BGM_VOLUME.to_string(),
            voice_volume: DEFAULT_VOICE_VOLUME.to_string(),
            ducking: true,
            out: None,
        }
    }
}

/// Error mirroring an unrecognized `-*` flag: `未知参数：$arg` + `exit 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownFlag(pub String);

/// Port of the `for arg in "$@"; do case "$arg" in ... esac; done` loop.
/// A bare (non `-`-prefixed) argument sets `INPUT`, matching the shell's
/// `*) INPUT="$arg" ;;` fallthrough — the last such argument wins, same as
/// repeated assignment in the shell loop.
pub fn parse_args<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<Options, UnknownFlag> {
    let mut opts = Options::default();
    for arg in args {
        if let Some(v) = arg.strip_prefix("--voiceover=") {
            opts.voiceover = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--bgm-mood=") {
            opts.bgm_mood = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--bgm-volume=") {
            opts.bgm_volume = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--voice-volume=") {
            opts.voice_volume = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--bgm=") {
            opts.bgm = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--out=") {
            opts.out = Some(v.to_string());
        } else if arg == "--no-ducking" {
            opts.ducking = false;
        } else if arg.starts_with('-') {
            return Err(UnknownFlag(arg.to_string()));
        } else {
            opts.input = Some(arg.to_string());
        }
    }
    Ok(opts)
}

/// Validation error variants mirroring the script's three early-exit
/// checks (`[ -z "$INPUT" ] || [ ! -f "$INPUT" ]`, `[ -z "$VOICEOVER" ]
/// || [ ! -f "$VOICEOVER" ]`, and the resolved-BGM-file-missing check).
/// `exists` predicates are injected by the caller (a `Fn(&str) -> bool`)
/// since this crate does no filesystem I/O of its own for the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// `Usage: bash mix-voiceover.sh <video.mp4> --voiceover=<v.mp3> [...]`
    MissingOrNoSuchInput,
    /// `✗ 缺 --voiceover=<path>`
    MissingOrNoSuchVoiceover,
    /// `✗ BGM 文件不存在: <path>` plus the available-moods hint.
    MissingBgmFile { path: String },
}

pub const USAGE_LINE: &str =
    "Usage: bash mix-voiceover.sh <video.mp4> --voiceover=<v.mp3> [--bgm=<b.mp3> | --bgm-mood=<name>]";
pub const MISSING_VOICEOVER_LINE: &str = "✗ 缺 --voiceover=<path>";

/// Port of `ASSETS_DIR="$SCRIPT_DIR/../assets"` and the `--bgm-mood`
/// resolution `BGM="$ASSETS_DIR/bgm-${BGM_MOOD}.mp3"` when `--bgm` was not
/// given directly.
pub fn resolve_bgm_path(script_dir: &Path, opts: &Options) -> Option<PathBuf> {
    if let Some(bgm) = &opts.bgm {
        return Some(PathBuf::from(bgm));
    }
    opts.bgm_mood
        .as_ref()
        .map(|mood| script_dir.join("..").join("assets").join(format!("bgm-{mood}.mp3")))
}

/// Port of the default-output-path fallback: `base="${INPUT%.*}"`,
/// `OUTPUT="${base}-voiced.mp4"`.
pub fn default_output_path(input: &str) -> String {
    let base = match input.rfind('.') {
        Some(idx) => &input[..idx],
        None => input,
    };
    format!("{base}-voiced.mp4")
}

/// Runs the three checks in order and returns the first that fails,
/// mirroring the script's sequential `exit 1` guards. `input_exists` /
/// `voiceover_exists` / `bgm_exists` stand in for the shell's `[ -f ... ]`
/// tests so this module stays filesystem-free.
pub fn validate(
    opts: &Options,
    input_exists: impl Fn(&str) -> bool,
    voiceover_exists: impl Fn(&str) -> bool,
    bgm_exists: impl Fn(&Path) -> bool,
    script_dir: &Path,
) -> Result<Option<PathBuf>, ValidationError> {
    match &opts.input {
        Some(input) if input_exists(input) => {}
        _ => return Err(ValidationError::MissingOrNoSuchInput),
    }
    match &opts.voiceover {
        Some(v) if voiceover_exists(v) => {}
        _ => return Err(ValidationError::MissingOrNoSuchVoiceover),
    }
    let bgm = resolve_bgm_path(script_dir, opts);
    if let Some(bgm_path) = &bgm {
        if !bgm_exists(bgm_path) {
            return Err(ValidationError::MissingBgmFile {
                path: bgm_path.display().to_string(),
            });
        }
    }
    Ok(bgm)
}

/// Port of the `available mood` hint appended to the missing-BGM error:
/// `ls "$ASSETS_DIR" | grep -E '^bgm-.*\.mp3$' | sed 's/^bgm-//;s/\.mp3$//'`.
/// `asset_filenames` stands in for the `ls` output.
pub fn available_moods(asset_filenames: &[String]) -> Vec<String> {
    asset_filenames
        .iter()
        .filter_map(|f| f.strip_prefix("bgm-").and_then(|s| s.strip_suffix(".mp3")))
        .map(|s| s.to_string())
        .collect()
}

/// Which `ffmpeg` filter-graph branch `build_ffmpeg_command` takes,
/// mirroring the script's `if [ -z "$BGM" ]; elif [ "$DUCKING" = "1" ];
/// else` chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixMode {
    VoiceOnly,
    VoiceBgmDucked,
    VoiceBgmStatic,
}

pub fn mix_mode(has_bgm: bool, ducking: bool) -> MixMode {
    if !has_bgm {
        MixMode::VoiceOnly
    } else if ducking {
        MixMode::VoiceBgmDucked
    } else {
        MixMode::VoiceBgmStatic
    }
}

/// Port of the three `ffmpeg -y -i ... -filter_complex "..." -map ... -c:v
/// copy -c:a aac -b:a 192k -shortest "$OUTPUT"` invocations, as the exact
/// argument vector a caller passes to `std::process::Command::new("ffmpeg").args(...)`.
pub fn build_ffmpeg_args(
    input: &str,
    voiceover: &str,
    bgm: Option<&str>,
    voice_volume: &str,
    bgm_volume: &str,
    ducking: bool,
    output: &str,
) -> Vec<String> {
    let mode = mix_mode(bgm.is_some(), ducking);
    let mut args: Vec<String> = vec!["-y".into(), "-i".into(), input.into(), "-i".into(), voiceover.into()];

    let filter_complex = match mode {
        MixMode::VoiceOnly => format!("[1:a]volume={voice_volume}[a]"),
        MixMode::VoiceBgmDucked => {
            args.push("-i".into());
            args.push(bgm.unwrap().into());
            format!(
                "\n      [1:a]volume={voice_volume}[voice];\n      [2:a]volume={bgm_volume},aloop=loop=-1:size=2e9[bgm_lo];\n      [bgm_lo][voice]sidechaincompress=threshold=0.04:ratio=8:attack=5:release=300:makeup=1[bgm_ducked];\n      [voice][bgm_ducked]amix=inputs=2:duration=first:dropout_transition=0,afade=t=out:st=0:d=0.5:curve=tri[a]\n    "
            )
        }
        MixMode::VoiceBgmStatic => {
            args.push("-i".into());
            args.push(bgm.unwrap().into());
            format!(
                "\n      [1:a]volume={voice_volume}[voice];\n      [2:a]volume={bgm_volume},aloop=loop=-1:size=2e9[bgm];\n      [voice][bgm]amix=inputs=2:duration=first:dropout_transition=0[a]\n    "
            )
        }
    };

    args.push("-filter_complex".into());
    args.push(filter_complex);
    args.push("-map".into());
    args.push("0:v".into());
    args.push("-map".into());
    args.push("[a]".into());
    args.push("-c:v".into());
    args.push("copy".into());
    args.push("-c:a".into());
    args.push("aac".into());
    args.push("-b:a".into());
    args.push("192k".into());
    args.push("-shortest".into());
    args.push(output.into());
    args
}

/// Port of the `─ mix-voiceover ──...` status block printed before running
/// `ffmpeg`.
pub fn status_block(opts: &Options, bgm: Option<&Path>, output: &str) -> String {
    let mut lines = vec![
        "─ mix-voiceover ──────────────".to_string(),
        format!("  视频:     {}", opts.input.as_deref().unwrap_or_default()),
        format!(
            "  人声:     {} (vol={})",
            opts.voiceover.as_deref().unwrap_or_default(),
            opts.voice_volume
        ),
    ];
    match bgm {
        Some(path) => lines.push(format!(
            "  BGM:      {} (vol={}, ducking={})",
            path.display(),
            opts.bgm_volume,
            if opts.ducking { 1 } else { 0 }
        )),
        None => lines.push("  BGM:      （无）".to_string()),
    }
    lines.push(format!("  输出:     {output}"));
    lines.push("──────────────────────────────".to_string());
    lines.join("\n")
}

/// Port of the final `✓ 完成：$OUTPUT` line.
pub fn done_line(output: &str) -> String {
    format!("✓ 完成：{output}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_reads_all_flags() {
        let opts = parse_args([
            "video.mp4",
            "--voiceover=v.mp3",
            "--bgm-mood=tech",
            "--bgm-volume=0.2",
            "--voice-volume=1.5",
            "--no-ducking",
        ])
        .unwrap();
        assert_eq!(opts.input.as_deref(), Some("video.mp4"));
        assert_eq!(opts.voiceover.as_deref(), Some("v.mp3"));
        assert_eq!(opts.bgm_mood.as_deref(), Some("tech"));
        assert_eq!(opts.bgm_volume, "0.2");
        assert_eq!(opts.voice_volume, "1.5");
        assert!(!opts.ducking);
    }

    #[test]
    fn parse_args_defaults_ducking_on() {
        let opts = parse_args(["v.mp4", "--voiceover=v.mp3"]).unwrap();
        assert!(opts.ducking);
        assert_eq!(opts.bgm_volume, DEFAULT_BGM_VOLUME);
        assert_eq!(opts.voice_volume, DEFAULT_VOICE_VOLUME);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        assert_eq!(
            parse_args(["v.mp4", "--bogus=1"]),
            Err(UnknownFlag("--bogus=1".to_string()))
        );
    }

    #[test]
    fn parse_args_last_bare_arg_wins() {
        let opts = parse_args(["a.mp4", "b.mp4", "--voiceover=v.mp3"]).unwrap();
        assert_eq!(opts.input.as_deref(), Some("b.mp4"));
    }

    #[test]
    fn resolve_bgm_path_prefers_explicit_bgm() {
        let mut opts = Options::default();
        opts.bgm = Some("/x/song.mp3".into());
        opts.bgm_mood = Some("tech".into());
        let script_dir = Path::new("/scripts");
        assert_eq!(
            resolve_bgm_path(script_dir, &opts),
            Some(PathBuf::from("/x/song.mp3"))
        );
    }

    #[test]
    fn resolve_bgm_path_derives_from_mood() {
        let mut opts = Options::default();
        opts.bgm_mood = Some("educational".into());
        let script_dir = Path::new("/scripts");
        assert_eq!(
            resolve_bgm_path(script_dir, &opts),
            Some(PathBuf::from("/scripts/../assets/bgm-educational.mp3"))
        );
    }

    #[test]
    fn resolve_bgm_path_none_when_neither_given() {
        let opts = Options::default();
        assert_eq!(resolve_bgm_path(Path::new("/scripts"), &opts), None);
    }

    #[test]
    fn default_output_path_strips_last_extension() {
        assert_eq!(default_output_path("anim.mp4"), "anim-voiced.mp4");
        assert_eq!(default_output_path("/a/b/anim.mp4"), "/a/b/anim-voiced.mp4");
        assert_eq!(default_output_path("noext"), "noext-voiced.mp4");
    }

    #[test]
    fn validate_reports_missing_input_first() {
        let opts = Options::default();
        let result = validate(&opts, |_| false, |_| false, |_| false, Path::new("/s"));
        assert_eq!(result, Err(ValidationError::MissingOrNoSuchInput));
    }

    #[test]
    fn validate_reports_missing_voiceover_second() {
        let mut opts = Options::default();
        opts.input = Some("v.mp4".into());
        let result = validate(&opts, |_| true, |_| false, |_| false, Path::new("/s"));
        assert_eq!(result, Err(ValidationError::MissingOrNoSuchVoiceover));
    }

    #[test]
    fn validate_reports_missing_bgm_file() {
        let mut opts = Options::default();
        opts.input = Some("v.mp4".into());
        opts.voiceover = Some("vo.mp3".into());
        opts.bgm_mood = Some("tech".into());
        let result = validate(&opts, |_| true, |_| true, |_| false, Path::new("/s"));
        assert!(matches!(result, Err(ValidationError::MissingBgmFile { .. })));
    }

    #[test]
    fn validate_ok_with_no_bgm() {
        let mut opts = Options::default();
        opts.input = Some("v.mp4".into());
        opts.voiceover = Some("vo.mp3".into());
        let result = validate(&opts, |_| true, |_| true, |_| false, Path::new("/s"));
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn available_moods_strips_prefix_and_suffix() {
        let files = vec![
            "bgm-tech.mp3".to_string(),
            "bgm-educational.mp3".to_string(),
            "readme.txt".to_string(),
        ];
        let moods = available_moods(&files);
        assert_eq!(moods, vec!["tech".to_string(), "educational".to_string()]);
    }

    #[test]
    fn mix_mode_matches_bash_branches() {
        assert_eq!(mix_mode(false, true), MixMode::VoiceOnly);
        assert_eq!(mix_mode(true, true), MixMode::VoiceBgmDucked);
        assert_eq!(mix_mode(true, false), MixMode::VoiceBgmStatic);
    }

    #[test]
    fn build_ffmpeg_args_voice_only() {
        let args = build_ffmpeg_args("in.mp4", "v.mp3", None, "1.0", "0.18", true, "out.mp4");
        assert_eq!(
            args,
            vec![
                "-y", "-i", "in.mp4", "-i", "v.mp3",
                "-filter_complex", "[1:a]volume=1.0[a]",
                "-map", "0:v", "-map", "[a]",
                "-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-shortest", "out.mp4",
            ]
        );
    }

    #[test]
    fn build_ffmpeg_args_voice_bgm_ducked_includes_third_input_and_sidechain() {
        let args = build_ffmpeg_args("in.mp4", "v.mp3", Some("b.mp3"), "1.0", "0.18", true, "out.mp4");
        assert!(args.contains(&"b.mp3".to_string()));
        let fc = args.iter().find(|a| a.contains("sidechaincompress")).unwrap();
        assert!(fc.contains("sidechaincompress=threshold=0.04:ratio=8:attack=5:release=300:makeup=1"));
    }

    #[test]
    fn build_ffmpeg_args_voice_bgm_static_has_no_sidechain() {
        let args = build_ffmpeg_args("in.mp4", "v.mp3", Some("b.mp3"), "1.0", "0.18", false, "out.mp4");
        assert!(!args.iter().any(|a| a.contains("sidechaincompress")));
        assert!(args.iter().any(|a| a.contains("amix=inputs=2")));
    }

    #[test]
    fn status_block_reports_no_bgm() {
        let mut opts = Options::default();
        opts.input = Some("in.mp4".into());
        opts.voiceover = Some("v.mp3".into());
        let block = status_block(&opts, None, "out.mp4");
        assert!(block.contains("BGM:      （无）"));
        assert!(block.contains("输出:     out.mp4"));
    }

    #[test]
    fn done_line_matches_script() {
        assert_eq!(done_line("out.mp4"), "✓ 完成：out.mp4");
    }
}
