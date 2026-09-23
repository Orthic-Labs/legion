//! Port of `skills/designer/engine/huashu/scripts/export_deck_pdf.mjs`
//! (chunk w2_006): renders a directory of numbered slide `.html` files to a
//! single merged vector PDF via a headless Chromium (Playwright) and
//! `pdf-lib`.
//!
//! The actual browser rendering and PDF merge are host effects (spawning a
//! browser process, reading files, writing bytes) this pure engine crate
//! does not perform itself. What is ported and tested here is every
//! deterministic decision the script makes before and around those calls:
//! CLI argument parsing (`parseArgs`), the slide-file discovery/sort/filter
//! (`.filter(f => f.endsWith('.html')).sort()`), the per-page PDF options
//! object, and the progress/summary message formats — so a host that wires
//! in its own renderer and PDF writer reproduces the script's behavior
//! exactly instead of re-deriving it.

use std::path::PathBuf;

/// Port of `parseArgs`'s default `{ width: 1920, height: 1080 }` plus the
/// generic `--key value` pair loop (`for (let i = 0; i < a.length; i += 2)`).
#[derive(Debug, Clone, PartialEq)]
pub struct DeckPdfArgs {
    pub slides: Option<String>,
    pub out: Option<String>,
    pub width: i64,
    pub height: i64,
}

impl Default for DeckPdfArgs {
    fn default() -> Self {
        Self {
            slides: None,
            out: None,
            width: 1920,
            height: 1080,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// `if (!args.slides || !args.out)`.
    MissingSlidesOrOut,
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSlidesOrOut => f.write_str(
                "用法: node export_deck_pdf.mjs --slides <dir> --out <file.pdf> [--width 1920] [--height 1080]",
            ),
        }
    }
}

impl std::error::Error for ArgError {}

/// Port of `parseArgs`. `args` is the raw argv tail (`process.argv.slice(2)`),
/// consumed two at a time as `--key value` pairs exactly like the JS loop —
/// including its quirk that an odd-length list drops the trailing dangling
/// key (JS `a[i+1]` is `undefined`, which `parseInt` maps to `NaN`; here a
/// missing pair value is simply skipped since there is nothing meaningful to
/// assign).
pub fn parse_args<I, S>(args: I) -> Result<DeckPdfArgs, ArgError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let items: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut result = DeckPdfArgs::default();

    let mut i = 0;
    while i < items.len() {
        let key = items[i].strip_prefix("--").unwrap_or(&items[i]).to_string();
        let value = items.get(i + 1).cloned();
        match (key.as_str(), value) {
            ("slides", Some(v)) => result.slides = Some(v),
            ("out", Some(v)) => result.out = Some(v),
            ("width", Some(v)) => {
                if let Ok(n) = v.parse::<i64>() {
                    result.width = n;
                }
            }
            ("height", Some(v)) => {
                if let Ok(n) = v.parse::<i64>() {
                    result.height = n;
                }
            }
            _ => {}
        }
        i += 2;
    }

    if result.slides.is_none() || result.out.is_none() {
        return Err(ArgError::MissingSlidesOrOut);
    }
    Ok(result)
}

/// Port of the slide-file discovery in `main`:
/// `(await fs.readdir(slidesDir)).filter(f => f.endsWith('.html')).sort()`.
/// Takes the already-listed directory entries (host performs the actual
/// `readdir`) and returns them filtered and lexicographically sorted, which
/// is how `01-xxx.html` sorts before `02-xxx.html`.
pub fn select_and_sort_slides(entries: &[String]) -> Vec<String> {
    let mut files: Vec<String> = entries
        .iter()
        .filter(|f| f.ends_with(".html"))
        .cloned()
        .collect();
    files.sort();
    files
}

/// Port of the `if (!files.length)` fatal-error message.
pub fn no_slides_error(slides_dir: &str) -> String {
    format!("No .html files found in {slides_dir}")
}

/// Port of the `page.pdf({...})` options object passed for every slide.
#[derive(Debug, Clone, PartialEq)]
pub struct PagePdfOptions {
    pub width_px: i64,
    pub height_px: i64,
    pub print_background: bool,
    pub margin_top: i64,
    pub margin_right: i64,
    pub margin_bottom: i64,
    pub margin_left: i64,
    pub prefer_css_page_size: bool,
}

/// Port of the literal options passed to `page.pdf`, including the
/// `${width}px`/`${height}px` string formatting.
pub fn page_pdf_options(width: i64, height: i64) -> PagePdfOptions {
    PagePdfOptions {
        width_px: width,
        height_px: height,
        print_background: true,
        margin_top: 0,
        margin_right: 0,
        margin_bottom: 0,
        margin_left: 0,
        prefer_css_page_size: false,
    }
}

impl PagePdfOptions {
    /// The `${width}px` / `${height}px` strings Playwright receives.
    pub fn width_css(&self) -> String {
        format!("{}px", self.width_px)
    }
    pub fn height_css(&self) -> String {
        format!("{}px", self.height_px)
    }
}

/// Port of the `file://` URL construction: `'file://' + path.join(slidesDir, f)`.
pub fn slide_file_url(slides_dir: &str, file: &str) -> String {
    let joined = PathBuf::from(slides_dir).join(file);
    format!("file://{}", joined.to_string_lossy())
}

/// Port of the per-slide progress line: `` `  [${n}/${total}] ${f}` ``.
pub fn progress_line(rendered_count: usize, total: usize, file: &str) -> String {
    format!("  [{rendered_count}/{total}] {file}")
}

/// Port of `console.log(\`Found ${files.length} slides in ${slidesDir}\`)`.
pub fn found_slides_line(count: usize, slides_dir: &str) -> String {
    format!("Found {count} slides in {slides_dir}")
}

/// Port of the final summary line:
/// `` `\n✓ Wrote ${outFile}  (${kb} KB, ${files.length} pages, vector)` ``,
/// where `kb` is `(bytes.byteLength / 1024).toFixed(0)`.
pub fn wrote_summary_line(out_file: &str, byte_length: u64, page_count: usize) -> String {
    let kb = ((byte_length as f64 / 1024.0).round()) as i64;
    format!("\n\u{2713} Wrote {out_file}  ({kb} KB, {page_count} pages, vector)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_requires_slides_and_out() {
        assert_eq!(
            parse_args(["--slides", "./s"]),
            Err(ArgError::MissingSlidesOrOut)
        );
        assert_eq!(
            parse_args::<_, &str>([]),
            Err(ArgError::MissingSlidesOrOut)
        );
    }

    #[test]
    fn parse_args_defaults_and_overrides() {
        let a = parse_args(["--slides", "./s", "--out", "deck.pdf"]).unwrap();
        assert_eq!(a.slides.as_deref(), Some("./s"));
        assert_eq!(a.out.as_deref(), Some("deck.pdf"));
        assert_eq!(a.width, 1920);
        assert_eq!(a.height, 1080);

        let b = parse_args([
            "--slides", "./s", "--out", "deck.pdf", "--width", "800", "--height", "600",
        ])
        .unwrap();
        assert_eq!(b.width, 800);
        assert_eq!(b.height, 600);
    }

    #[test]
    fn select_and_sort_slides_filters_and_orders() {
        let entries = vec![
            "02-body.html".to_string(),
            "notes.txt".to_string(),
            "01-title.html".to_string(),
            "assets".to_string(),
        ];
        assert_eq!(
            select_and_sort_slides(&entries),
            vec!["01-title.html".to_string(), "02-body.html".to_string()]
        );
    }

    #[test]
    fn no_slides_error_message() {
        assert_eq!(
            no_slides_error("/decks/q3"),
            "No .html files found in /decks/q3"
        );
    }

    #[test]
    fn page_pdf_options_matches_script_literal() {
        let opts = page_pdf_options(1920, 1080);
        assert!(opts.print_background);
        assert!(!opts.prefer_css_page_size);
        assert_eq!(opts.width_css(), "1920px");
        assert_eq!(opts.height_css(), "1080px");
        assert_eq!(opts.margin_top, 0);
    }

    #[test]
    fn slide_file_url_joins_and_prefixes() {
        assert_eq!(
            slide_file_url("/decks/q3", "01-title.html"),
            "file:///decks/q3/01-title.html"
        );
    }

    #[test]
    fn progress_and_summary_lines() {
        assert_eq!(progress_line(1, 3, "01-title.html"), "  [1/3] 01-title.html");
        assert_eq!(found_slides_line(3, "/decks/q3"), "Found 3 slides in /decks/q3");
        assert_eq!(
            wrote_summary_line("/out/deck.pdf", 204_800, 3),
            "\n\u{2713} Wrote /out/deck.pdf  (200 KB, 3 pages, vector)"
        );
    }
}
