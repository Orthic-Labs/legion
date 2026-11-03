//! Port of `skills/designer/engine/huashu/scripts/convert-formats.sh`
//! (chunk w2_006): converts an MP4 animation into a 60fps MP4 and a
//! palette-optimized GIF via `ffmpeg`.
//!
//! As with the other ports in this chunk, the pure argument-resolution and
//! `ffmpeg` argument-vector construction is fully ported and tested; the
//! actual process spawning is left to the host/caller.

use std::path::{Path, PathBuf};

/// Default GIF width, matching `GIF_WIDTH="960"`.
pub const DEFAULT_GIF_WIDTH: &str = "960";

/// Port of the `for arg in "$@"` case statement, including its
/// `echo "Unknown flag: $arg" >&2; exit 1` path for any other `--*` flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    UnknownFlag(String),
    MissingInput,
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFlag(flag) => write!(f, "Unknown flag: {flag}"),
            Self::MissingInput => write!(f, "Usage: $0 input.mp4 [gif_width] [--minterpolate]"),
        }
    }
}

impl std::error::Error for ArgError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertFormatsArgs {
    pub input: String,
    pub gif_width: String,
    pub use_minterpolate: bool,
}

/// Port of the argument-parsing loop: `--minterpolate` sets the flag, any
/// other `--*` token is a fatal unknown-flag error, and the first two bare
/// positionals fill `input` then `gif_width` (`if [ -z "$INPUT" ]; then
/// INPUT="$arg"; else GIF_WIDTH="$arg"; fi`) — a third bare positional
/// simply overwrites `gif_width` again, matching the shell's unconditional
/// `else` branch.
pub fn parse_args<I, S>(args: I) -> Result<ConvertFormatsArgs, ArgError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut input: Option<String> = None;
    let mut gif_width = DEFAULT_GIF_WIDTH.to_string();
    let mut use_minterpolate = false;

    for arg in args {
        let arg = arg.as_ref();
        if arg == "--minterpolate" {
            use_minterpolate = true;
        } else if let Some(rest) = arg.strip_prefix("--") {
            return Err(ArgError::UnknownFlag(format!("--{rest}")));
        } else if input.is_none() {
            input = Some(arg.to_string());
        } else {
            gif_width = arg.to_string();
        }
    }

    let input = input.ok_or(ArgError::MissingInput)?;
    Ok(ConvertFormatsArgs {
        input,
        gif_width,
        use_minterpolate,
    })
}

/// Derived output paths, port of `DIR`/`BASE`/`OUT60`/`OUTGIF`/`PAL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertFormatsPaths {
    pub out_60fps: PathBuf,
    pub out_gif: PathBuf,
    pub palette: PathBuf,
}

/// Port of `BASE=$(basename "$INPUT" .mp4)` (strips only a trailing
/// `.mp4`) and the three output-path templates.
pub fn resolve_paths(input: &Path) -> ConvertFormatsPaths {
    let dir = input.parent().unwrap_or_else(|| Path::new("."));
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = name.strip_suffix(".mp4").unwrap_or(&name).to_string();
    ConvertFormatsPaths {
        out_60fps: dir.join(format!("{base}-60fps.mp4")),
        out_gif: dir.join(format!("{base}.gif")),
        palette: dir.join(format!(".palette-{base}.png")),
    }
}

/// Port of the `VFILTER` selection between `minterpolate=...` and plain
/// `fps=60`.
pub fn video_filter(use_minterpolate: bool) -> &'static str {
    if use_minterpolate {
        "minterpolate=fps=60:mi_mode=mci:mc_mode=aobmc:me_mode=bidir:vsbmc=1"
    } else {
        "fps=60"
    }
}

/// Port of the first `ffmpeg` invocation (60fps re-encode), excluding the
/// `ffmpeg` binary name.
pub fn ffmpeg_60fps_args(input: &Path, out_60fps: &Path, use_minterpolate: bool) -> Vec<String> {
    vec![
        "-y".into(),
        "-loglevel".into(),
        "error".into(),
        "-i".into(),
        input.to_string_lossy().into_owned(),
        "-vf".into(),
        video_filter(use_minterpolate).into(),
        "-c:v".into(),
        "libx264".into(),
        "-pix_fmt".into(),
        "yuv420p".into(),
        "-profile:v".into(),
        "high".into(),
        "-level".into(),
        "4.0".into(),
        "-crf".into(),
        "18".into(),
        "-preset".into(),
        "medium".into(),
        "-movflags".into(),
        "+faststart".into(),
        out_60fps.to_string_lossy().into_owned(),
    ]
}

/// Port of the palettegen pass (pass 1 of the two-pass GIF pipeline).
pub fn ffmpeg_palettegen_args(input: &Path, gif_width: &str, palette: &Path) -> Vec<String> {
    vec![
        "-y".into(),
        "-loglevel".into(),
        "error".into(),
        "-i".into(),
        input.to_string_lossy().into_owned(),
        "-vf".into(),
        format!("fps=15,scale={gif_width}:-1:flags=lanczos,palettegen=stats_mode=diff"),
        palette.to_string_lossy().into_owned(),
    ]
}

/// Port of the paletteuse pass (pass 2), which reads back the palette
/// written by [`ffmpeg_palettegen_args`].
pub fn ffmpeg_paletteuse_args(
    input: &Path,
    gif_width: &str,
    palette: &Path,
    out_gif: &Path,
) -> Vec<String> {
    vec![
        "-y".into(),
        "-loglevel".into(),
        "error".into(),
        "-i".into(),
        input.to_string_lossy().into_owned(),
        "-i".into(),
        palette.to_string_lossy().into_owned(),
        "-lavfi".into(),
        format!(
            "fps=15,scale={gif_width}:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle"
        ),
        out_gif.to_string_lossy().into_owned(),
    ]
}
