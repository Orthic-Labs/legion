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
///
/// The JS source always produces forward-slash paths for the URL regardless
/// of host OS. `PathBuf::join` would use `\` as the separator on Windows, so
/// the join is done on path components directly and re-assembled with `/`.
pub fn slide_file_url(slides_dir: &str, file: &str) -> String {
    let trimmed = slides_dir.trim_end_matches(['/', '\\']);
    format!("file://{trimmed}/{file}")
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

/// Directory listing + write boundary used by [`run_production`], matching
/// `fs.readdir(slidesDir)` and the final `fs.writeFile(outFile, merged)`.
pub trait DeckPdfFs {
    fn read_dir_names(&self, path: &std::path::Path) -> std::io::Result<Vec<String>>;
    fn write(&self, path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()>;
}

/// Per-slide print boundary: navigate a headless browser tab to the slide's
/// `file://` URL and return that single page's rendered PDF bytes, matching
/// Playwright's `page.goto(url)` + `page.pdf(opts)` per slide.
pub trait SlidePrinter {
    fn print_slide(&mut self, file_url: &str, opts: &PagePdfOptions) -> Result<Vec<u8>, String>;
}

#[derive(Debug)]
pub enum RunError {
    Args(ArgError),
    Io(std::path::PathBuf, String),
    NoSlides(String),
    Print(String, String),
    Merge(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Args(e) => write!(f, "{e}"),
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
            Self::NoSlides(dir) => write!(f, "{}", no_slides_error(dir)),
            Self::Print(file, e) => write!(f, "failed to render {file}: {e}"),
            Self::Merge(e) => write!(f, "failed to merge slide PDFs: {e}"),
        }
    }
}

pub struct RunOutcome {
    pub log_lines: Vec<String>,
    pub summary_line: String,
}

/// Port of `main()`'s full body: discover/sort slides, render each to a
/// single-page PDF via `printer`, merge the pages page-per-slide into one
/// vector PDF, and write it via `fs`. Deterministic decision logic (arg
/// parsing, slide selection, options, message formats) is delegated to the
/// pure functions above; only the browser render and the byte-level merge
/// happen here.
pub fn run_production(
    fs: &dyn DeckPdfFs,
    printer: &mut dyn SlidePrinter,
    args: &DeckPdfArgs,
) -> Result<RunOutcome, RunError> {
    let slides_dir = args.slides.clone().ok_or(RunError::Args(ArgError::MissingSlidesOrOut))?;
    let out = args.out.clone().ok_or(RunError::Args(ArgError::MissingSlidesOrOut))?;
    let slides_path = std::path::Path::new(&slides_dir);

    let entries = fs
        .read_dir_names(slides_path)
        .map_err(|e| RunError::Io(slides_path.to_path_buf(), e.to_string()))?;
    let files = select_and_sort_slides(&entries);
    if files.is_empty() {
        return Err(RunError::NoSlides(slides_dir.clone()));
    }

    let mut log_lines = vec![found_slides_line(files.len(), &slides_dir)];
    let opts = page_pdf_options(args.width, args.height);

    let mut page_pdfs: Vec<Vec<u8>> = Vec::with_capacity(files.len());
    for (idx, file) in files.iter().enumerate() {
        let url = slide_file_url(&slides_dir, file);
        let bytes = printer
            .print_slide(&url, &opts)
            .map_err(|e| RunError::Print(file.clone(), e))?;
        page_pdfs.push(bytes);
        log_lines.push(progress_line(idx + 1, files.len(), file));
    }

    let merged = merge_page_pdfs(&page_pdfs).map_err(RunError::Merge)?;
    let out_path = std::path::Path::new(&out);
    fs.write(out_path, &merged)
        .map_err(|e| RunError::Io(out_path.to_path_buf(), e.to_string()))?;

    Ok(RunOutcome {
        summary_line: wrote_summary_line(&out, merged.len() as u64, files.len()),
        log_lines,
    })
}

/// Merges N single-page PDFs (as produced by Chrome's `Page.printToPDF` for
/// each slide) into one multi-page vector PDF, page order preserved,
/// matching `pdf-lib`'s `PDFDocument.copyPages` + `addPage` loop the `.mjs`
/// used. Backed by `lopdf`: parse each page PDF, copy its page object (and
/// the objects it transitively references) into a fresh accumulator
/// document, and renumber.
pub fn merge_page_pdfs(pages: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if pages.is_empty() {
        return Err("no pages to merge".to_string());
    }
    let mut documents: Vec<lopdf::Document> = Vec::with_capacity(pages.len());
    for (i, bytes) in pages.iter().enumerate() {
        let doc = lopdf::Document::load_mem(bytes)
            .map_err(|e| format!("failed to parse page {} PDF: {e}", i + 1))?;
        documents.push(doc);
    }

    // lopdf's documented merge recipe: renumber each document's object IDs
    // into a disjoint range, then splice their objects and page trees
    // together into one accumulator document.
    let mut max_id: u32 = 1;
    let mut documents_pages: Vec<lopdf::ObjectId> = Vec::new();
    let mut documents_objects = std::collections::BTreeMap::new();
    for mut doc in documents {
        doc.renumber_objects_with(max_id);
        max_id = doc.max_id + 1;
        documents_pages.extend(doc.get_pages().into_values());
        documents_objects.extend(doc.objects.clone());
    }

    let mut merged = lopdf::Document::with_version("1.5");
    merged.objects = documents_objects.into_iter().collect();

    let pages_id = merged.new_object_id();
    let kids: Vec<lopdf::Object> = documents_pages
        .iter()
        .map(|id| lopdf::Object::Reference(*id))
        .collect();
    let page_count = kids.len() as i64;
    let mut pages_dict = lopdf::Dictionary::new();
    pages_dict.set("Type", lopdf::Object::Name(b"Pages".to_vec()));
    pages_dict.set("Kids", lopdf::Object::Array(kids.clone()));
    pages_dict.set("Count", lopdf::Object::Integer(page_count));
    merged.objects.insert(pages_id, lopdf::Object::Dictionary(pages_dict));

    for kid in &kids {
        if let lopdf::Object::Reference(id) = kid {
            if let Ok(lopdf::Object::Dictionary(dict)) = merged.get_object_mut(*id) {
                dict.set("Parent", lopdf::Object::Reference(pages_id));
            }
        }
    }

    let mut catalog = lopdf::Dictionary::new();
    catalog.set("Type", lopdf::Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", lopdf::Object::Reference(pages_id));
    let catalog_id = merged.add_object(lopdf::Object::Dictionary(catalog));
    merged.trailer.set("Root", catalog_id);
    merged.max_id = merged.objects.keys().map(|id| id.0).max().unwrap_or(1);
    merged.renumber_objects();
    merged.compress();

    let mut out = Vec::new();
    merged
        .save_to(&mut out)
        .map_err(|e| format!("failed to write merged PDF: {e}"))?;
    Ok(out)
}

/// Production `headless_chrome`-backed [`SlidePrinter`]: one browser, one
/// tab reused per slide (`navigate_to` + `print_to_pdf` per call), mirroring
/// the `.mjs`'s single shared Playwright page across the slide loop.
pub struct ChromeSlidePrinter {
    tab: std::sync::Arc<headless_chrome::Tab>,
    _browser: headless_chrome::Browser,
}

impl ChromeSlidePrinter {
    pub fn launch(width: u32, height: u32) -> Result<Self, String> {
        let launch_options = headless_chrome::LaunchOptions::default_builder()
            .headless(true)
            .window_size(Some((width, height)))
            .build()
            .map_err(|e| e.to_string())?;
        let browser = headless_chrome::Browser::new(launch_options).map_err(|e| e.to_string())?;
        let tab = browser.new_tab().map_err(|e| e.to_string())?;
        Ok(Self { tab, _browser: browser })
    }
}

impl SlidePrinter for ChromeSlidePrinter {
    fn print_slide(&mut self, file_url: &str, _opts: &PagePdfOptions) -> Result<Vec<u8>, String> {
        self.tab.navigate_to(file_url).map_err(|e| e.to_string())?;
        self.tab.wait_until_navigated().map_err(|e| e.to_string())?;
        self.tab.print_to_pdf(None).map_err(|e| e.to_string())
    }
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
