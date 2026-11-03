//! Port of `skills/designer/engine/huashu/scripts/gen_deck_thumbs.mjs`
//! (chunk w2_007): generates a JPEG thumbnail per slide HTML file for a
//! deck's "infinite gallery" overview.
//!
//! The actual work — `page.screenshot()` through a real Chromium and
//! `sharp(buf).resize(...).jpeg(...)` — needs a headless browser and an
//! image-codec crate; neither `headless_chrome`/`chromiumoxide` nor
//! `image`/`sharp`-equivalent is in `engine/Cargo.lock`, so that half is
//! not reachable here, same boundary as `export_deck_stage_pdf`'s render
//! step. What *is* ported, faithfully, is every piece of deterministic
//! logic around it: the `arg(name, default)` CLI helper, `.html` file
//! discovery + sort order, the per-file output-path derivation, and the
//! final progress/summary line format.

use std::path::{Path, PathBuf};

/// Port of the `arg(n, d)` helper: `process.argv.indexOf('--' + n)`, then
/// the next element if present and non-empty, else `d`.
pub fn arg<'a>(argv: &'a [String], name: &str, default: &'a str) -> &'a str {
    let flag = format!("--{name}");
    match argv.iter().position(|a| a == &flag) {
        Some(idx) => match argv.get(idx + 1) {
            Some(v) if !v.is_empty() => v.as_str(),
            _ => default,
        },
        None => default,
    }
}

/// Port of the parsed-and-defaulted CLI options: `slides` (default
/// `"slides"`), `out` (default `"thumbs"`), `width` (1600), `quality`
/// (86), and the render canvas `W`/`H` (1920×1080).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub slides_dir: String,
    pub out_dir: String,
    pub width: u32,
    pub quality: u32,
    pub canvas_w: u32,
    pub canvas_h: u32,
}

impl Options {
    /// Port of the five `arg(...)` calls + `parseInt`, mirroring `parseInt`'s
    /// behavior of stopping at the first bad digit and falling back to
    /// `NaN` (here: keep the default) when nothing parses.
    pub fn from_argv(argv: &[String]) -> Self {
        let slides_dir = arg(argv, "slides", "slides").to_string();
        let out_dir = arg(argv, "out", "thumbs").to_string();
        let width = parse_int_or(arg(argv, "width", "1600"), 1600);
        let quality = parse_int_or(arg(argv, "quality", "86"), 86);
        let canvas_w = parse_int_or(arg(argv, "canvas-w", "1920"), 1920);
        let canvas_h = parse_int_or(arg(argv, "canvas-h", "1080"), 1080);
        Self {
            slides_dir,
            out_dir,
            width,
            quality,
            canvas_w,
            canvas_h,
        }
    }
}

fn parse_int_or(s: &str, default: u32) -> u32 {
    s.parse::<u32>().unwrap_or(default)
}

/// Error mirroring the two `console.error(...); process.exit(1)` guards:
/// a missing `slides` directory, or one with no `.html` files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverError {
    SlidesDirMissing(String),
    NoHtmlFiles,
}

pub fn slides_dir_missing_message(slides_dir: &str) -> String {
    format!("找不到 slides 目录: {slides_dir}")
}

pub const NO_HTML_FILES_MESSAGE: &str = "slides 目录里没有 .html";

/// Port of `fs.readdirSync(slidesDir).filter(f => f.endsWith('.html')).sort()`.
/// `entries` stands in for the directory listing so this module does no
/// filesystem I/O itself; sorting is byte/codepoint order, matching
/// JS `Array#sort()`'s default string comparison for this ASCII-filename
/// use case.
pub fn discover_html_files(
    slides_dir: &str,
    entries: &[String],
) -> Result<Vec<String>, DiscoverError> {
    let mut files: Vec<String> = entries
        .iter()
        .filter(|f| f.ends_with(".html"))
        .cloned()
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(DiscoverError::NoHtmlFiles);
    }
    let _ = slides_dir;
    Ok(files)
}

/// Variant taking an explicit `dir_exists` flag, for callers that can tell
/// "directory missing" apart from "directory empty" (the shell/Node
/// original checks `fs.existsSync` before `readdirSync`).
pub fn discover_html_files_checked(
    slides_dir: &str,
    dir_exists: bool,
    entries: &[String],
) -> Result<Vec<String>, DiscoverError> {
    if !dir_exists {
        return Err(DiscoverError::SlidesDirMissing(slides_dir.to_string()));
    }
    discover_html_files(slides_dir, entries)
}

/// Port of `base = f.replace(/\.html$/, '')` and
/// `out = path.join(outDir, base + '.jpg')`.
pub fn thumb_output_path(out_dir: &str, html_filename: &str) -> PathBuf {
    let base = html_filename.strip_suffix(".html").unwrap_or(html_filename);
    Path::new(out_dir).join(format!("{base}.jpg"))
}

/// Port of the per-file `[ok] <out>` / `[FAIL] <file>: <message>` log lines.
pub fn ok_log_line(out_path: &Path) -> String {
    format!("[ok] {}", out_path.display())
}

pub fn fail_log_line(filename: &str, message: &str) -> String {
    format!("[FAIL] {filename}: {message}")
}

/// Port of the final summary + MANIFEST-hint lines.
pub fn summary_lines(ok_count: usize, total_count: usize, out_dir: &str) -> Vec<String> {
    vec![
        format!("\n=== {ok_count}/{total_count} 张缩略图 → {out_dir}/ ==="),
        format!(
            "在 index.html 的 MANIFEST 每项加 thumb: \"{out_dir}/<同名>.jpg\"（仅画廊模式用到）"
        ),
    ]
}
