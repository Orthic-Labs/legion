//! Port of `skills/designer/engine/huashu/scripts/gen_deck_thumbs.mjs`.
//!
//! Screenshots every `*.html` slide in a directory and writes a resized
//! JPEG thumbnail per slide (used by `deck_index.html`'s "infinite gallery"
//! view). Faithful to the original:
//! - same flag names/defaults (`--slides slides`, `--out thumbs`,
//!   `--width 1600`, `--quality 86`, `--canvas-w 1920`, `--canvas-h 1080`)
//! - same "slides dir missing" / "no .html files" pre-checks (both exit 1)
//! - same per-file flow: navigate, settle 2800ms for webfonts/paint,
//!   screenshot clipped to the canvas size, resize to `width` + JPEG-encode
//!   at `quality`, one `.jpg` per `.html` (same basename)
//! - same `[ok]` / `[FAIL]` per-file log lines and final summary line
//!
//! The screenshot capture sits behind [`ThumbBrowser`] (production impl
//! drives `headless_chrome`, per this packet's allowed-crates list); the
//! resize+encode step uses the `image` crate directly (a pure function over
//! bytes, not worth mocking). No test launches a real browser.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub slides: PathBuf,
    pub out: PathBuf,
    pub width: u32,
    pub quality: u8,
    pub canvas_w: u32,
    pub canvas_h: u32,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            slides: PathBuf::from("slides"),
            out: PathBuf::from("thumbs"),
            width: 1600,
            quality: 86,
            canvas_w: 1920,
            canvas_h: 1080,
        }
    }
}

/// `arg(n, d)`: flat `--key value` pairs, falling back to [`Args::default`].
pub fn parse_args(argv: &[String]) -> Args {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    while i < argv.len() {
        if let Some(key) = argv[i].strip_prefix("--") {
            if let Some(val) = argv.get(i + 1) {
                map.insert(key.to_string(), val.clone());
            }
        }
        i += 2;
    }
    let d = Args::default();
    Args {
        slides: map.get("slides").map(PathBuf::from).unwrap_or(d.slides),
        out: map.get("out").map(PathBuf::from).unwrap_or(d.out),
        width: map
            .get("width")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.width),
        quality: map
            .get("quality")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.quality),
        canvas_w: map
            .get("canvas-w")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.canvas_w),
        canvas_h: map
            .get("canvas-h")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.canvas_h),
    }
}

/// Lists `*.html` files in `dir`, sorted, matching
/// `readdirSync(slidesDir).filter(f => f.endsWith('.html')).sort()`.
pub fn html_files(entries: &[String]) -> Vec<String> {
    let mut v: Vec<String> = entries
        .iter()
        .filter(|f| f.ends_with(".html"))
        .cloned()
        .collect();
    v.sort();
    v
}

/// `f.replace(/\.html$/, '')` then `+ '.jpg'`.
pub fn thumb_filename(html_filename: &str) -> String {
    let base = html_filename.strip_suffix(".html").unwrap_or(html_filename);
    format!("{base}.jpg")
}

pub trait FileSystem {
    fn dir_exists(&self, path: &Path) -> bool;
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn read_dir_names(&self, path: &Path) -> std::io::Result<Vec<String>>;
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()>;
}

/// Screenshot capture boundary: navigate + settle + clipped PNG capture,
/// matching `page.goto(..., {waitUntil:'load'})`, `waitForTimeout(2800)`,
/// `page.screenshot({type:'png', clip:{x:0,y:0,width:W,height:H}})`.
pub trait ThumbBrowser {
    fn screenshot_png(&mut self, file_url: &str, canvas_w: u32, canvas_h: u32) -> Result<Vec<u8>, String>;
}

/// `sharp(buf).resize(width).jpeg({ quality }).toFile(out)`: decode PNG,
/// resize to `width` (preserving aspect ratio, matching sharp's single-
/// dimension `resize(width)`), re-encode as JPEG at `quality`.
pub fn resize_to_jpeg(png_bytes: &[u8], width: u32, quality: u8) -> Result<Vec<u8>, String> {
    let img = image::load_from_memory_with_format(png_bytes, image::ImageFormat::Png)
        .map_err(|e| e.to_string())?;
    let ratio = width as f64 / img.width() as f64;
    let target_h = (img.height() as f64 * ratio).round() as u32;
    let resized = img.resize_exact(width, target_h.max(1), image::imageops::FilterType::Lanczos3);
    let mut buf = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut buf);
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, quality);
    resized
        .write_with_encoder(encoder)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenError {
    SlidesDirMissing(PathBuf),
    NoHtmlFiles(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThumbLogLine {
    Ok(String),
    Fail { file: String, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub ok_count: usize,
    pub total: usize,
    pub log: Vec<ThumbLogLine>,
}

/// `main()`: dir checks, mkdir -p out, then per-file screenshot+resize+write.
pub fn run(
    fs: &dyn FileSystem,
    browser: &mut dyn ThumbBrowser,
    args: &Args,
) -> Result<RunOutcome, GenError> {
    if !fs.dir_exists(&args.slides) {
        return Err(GenError::SlidesDirMissing(args.slides.clone()));
    }
    fs.create_dir_all(&args.out).ok();

    let entries = fs.read_dir_names(&args.slides).unwrap_or_default();
    let files = html_files(&entries);
    if files.is_empty() {
        return Err(GenError::NoHtmlFiles(args.slides.clone()));
    }

    let mut log = Vec::new();
    let mut ok_count = 0;
    for f in &files {
        let src = args.slides.join(f);
        let file_url = format!("file://{}", src.to_string_lossy());
        let result = browser
            .screenshot_png(&file_url, args.canvas_w, args.canvas_h)
            .and_then(|png| resize_to_jpeg(&png, args.width, args.quality));
        match result {
            Ok(jpeg) => {
                let out_path = args.out.join(thumb_filename(f));
                match fs.write(&out_path, &jpeg) {
                    Ok(()) => {
                        ok_count += 1;
                        log.push(ThumbLogLine::Ok(out_path.to_string_lossy().to_string()));
                    }
                    Err(e) => log.push(ThumbLogLine::Fail {
                        file: f.clone(),
                        error: e.to_string(),
                    }),
                }
            }
            Err(e) => log.push(ThumbLogLine::Fail {
                file: f.clone(),
                error: e,
            }),
        }
    }

    Ok(RunOutcome {
        ok_count,
        total: files.len(),
        log,
    })
}

/// Production `headless_chrome`-backed implementation. Same compile-review
/// caveat as `export_deck_stage_pdf::ChromeDeckStageBrowser`: field/method
/// names follow the documented 1.x API and should be re-checked once cargo
/// can run against the pinned version.
pub struct ChromeThumbBrowser {
    tab: std::sync::Arc<headless_chrome::Tab>,
    _browser: headless_chrome::Browser,
}

impl ChromeThumbBrowser {
    /// Launches headless Chrome sized to the canvas, mirroring
    /// `browser.newPage({ viewport: { width: W, height: H } })`. Window size
    /// is a launch-time option here (see `r07::real::RealChromeDriver::new`).
    pub fn launch(canvas_w: u32, canvas_h: u32) -> Result<Self, String> {
        let launch_options = headless_chrome::LaunchOptions::default_builder()
            .headless(true)
            .window_size(Some((canvas_w, canvas_h)))
            .build()
            .map_err(|e| e.to_string())?;
        let browser = headless_chrome::Browser::new(launch_options).map_err(|e| e.to_string())?;
        let tab = browser.new_tab().map_err(|e| e.to_string())?;
        Ok(Self {
            tab,
            _browser: browser,
        })
    }
}

impl ThumbBrowser for ChromeThumbBrowser {
    fn screenshot_png(&mut self, file_url: &str, _canvas_w: u32, _canvas_h: u32) -> Result<Vec<u8>, String> {
        self.tab.navigate_to(file_url).map_err(|e| e.to_string())?;
        self.tab.wait_until_navigated().map_err(|e| e.to_string())?;
        std::thread::sleep(std::time::Duration::from_millis(2800));
        self.tab
            .capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                None,
                None,
                true,
            )
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[test]
    fn parse_args_applies_defaults() {
        let args = parse_args(&[]);
        assert_eq!(args, Args::default());
    }

    #[test]
    fn parse_args_overrides() {
        let argv: Vec<String> = ["--slides", "s", "--out", "o", "--width", "800", "--quality", "70"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let args = parse_args(&argv);
        assert_eq!(args.slides, PathBuf::from("s"));
        assert_eq!(args.width, 800);
        assert_eq!(args.quality, 70);
    }

    #[test]
    fn html_files_filters_and_sorts() {
        let entries = vec!["b.html".to_string(), "a.html".to_string(), "notes.txt".to_string()];
        assert_eq!(html_files(&entries), vec!["a.html", "b.html"]);
    }

    #[test]
    fn thumb_filename_swaps_extension() {
        assert_eq!(thumb_filename("01-cover.html"), "01-cover.jpg");
    }

    struct FakeFs {
        dirs: Vec<PathBuf>,
        entries: HashMap<PathBuf, Vec<String>>,
        writes: RefCell<HashMap<PathBuf, Vec<u8>>>,
    }
    impl FileSystem for FakeFs {
        fn dir_exists(&self, path: &Path) -> bool {
            self.dirs.iter().any(|p| p == path)
        }
        fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn read_dir_names(&self, path: &Path) -> std::io::Result<Vec<String>> {
            Ok(self.entries.get(path).cloned().unwrap_or_default())
        }
        fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
            self.writes.borrow_mut().insert(path.to_path_buf(), bytes.to_vec());
            Ok(())
        }
    }

    struct FakeBrowser;
    impl ThumbBrowser for FakeBrowser {
        fn screenshot_png(&mut self, _url: &str, _w: u32, _h: u32) -> Result<Vec<u8>, String> {
            // 1x1 red PNG
            Ok(vec![
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
                0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
                0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
                0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
                0xB0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
            ])
        }
    }

    #[test]
    fn run_errors_when_slides_dir_missing() {
        let fs = FakeFs {
            dirs: vec![],
            entries: HashMap::new(),
            writes: RefCell::new(HashMap::new()),
        };
        let mut browser = FakeBrowser;
        let args = Args::default();
        assert_eq!(
            run(&fs, &mut browser, &args),
            Err(GenError::SlidesDirMissing(args.slides.clone()))
        );
    }

    #[test]
    fn run_errors_when_no_html_files() {
        let slides = PathBuf::from("slides");
        let fs = FakeFs {
            dirs: vec![slides.clone()],
            entries: HashMap::from([(slides.clone(), vec!["readme.txt".to_string()])]),
            writes: RefCell::new(HashMap::new()),
        };
        let mut browser = FakeBrowser;
        let args = Args::default();
        assert_eq!(run(&fs, &mut browser, &args), Err(GenError::NoHtmlFiles(slides)));
    }

    #[test]
    fn run_writes_one_jpeg_per_slide() {
        let slides = PathBuf::from("slides");
        let out = PathBuf::from("thumbs");
        let fs = FakeFs {
            dirs: vec![slides.clone()],
            entries: HashMap::from([(
                slides.clone(),
                vec!["01-cover.html".to_string(), "02-body.html".to_string()],
            )]),
            writes: RefCell::new(HashMap::new()),
        };
        let mut browser = FakeBrowser;
        let mut args = Args::default();
        args.slides = slides;
        args.out = out.clone();
        args.width = 4;
        let outcome = run(&fs, &mut browser, &args).unwrap();
        assert_eq!(outcome.ok_count, 2);
        assert_eq!(outcome.total, 2);
        assert!(fs.writes.borrow().contains_key(&out.join("01-cover.jpg")));
        assert!(fs.writes.borrow().contains_key(&out.join("02-body.jpg")));
    }
}
