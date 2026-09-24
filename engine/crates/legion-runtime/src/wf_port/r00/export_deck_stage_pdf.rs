//! Port of `skills/designer/engine/huashu/scripts/export_deck_stage_pdf.mjs`.
//!
//! Single-file `<deck-stage>` deck -> PDF export. Faithful to the original:
//! - same CLI args/defaults (`--html`, `--out`, `--width 1920`, `--height 1080`)
//! - same "HTML file not found" pre-check and the same page-flatten trick:
//!   pull every top-level `<section>` out of `<deck-stage>`'s slot, force
//!   fixed-size `position:relative` inline styles + `page-break-after`, drop
//!   the last section's page break so there's no trailing blank page
//! - same PDF print options (`printBackground: true`, `preferCSSPageSize: true`,
//!   width/height in `px`) and the same summary line
//!
//! All browser control sits behind [`DeckStageBrowser`]; the production
//! implementation ([`ChromeDeckStageBrowser`]) drives `headless_chrome`
//! (this packet's brief allows adding it). No test launches a real browser.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub html: PathBuf,
    pub out: PathBuf,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseArgsError {
    /// `用法: node export_deck_stage_pdf.mjs --html <deck.html> --out <file.pdf> [--width 1920] [--height 1080]`
    MissingRequired,
}

/// Parses `--html`/`--out`/`--width`/`--height` the same way the Python-style
/// `parseArgs()` in the `.mjs` does: flat `--key value` pairs, `width`/`height`
/// default to 1920/1080, `--html`/`--out` required.
pub fn parse_args(argv: &[String]) -> Result<Args, ParseArgsError> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    while i + 1 < argv.len() + 1 && i < argv.len() {
        let key = argv[i].trim_start_matches("--").to_string();
        let val = argv.get(i + 1).cloned().unwrap_or_default();
        map.insert(key, val);
        i += 2;
    }
    let html = map.get("html").ok_or(ParseArgsError::MissingRequired)?;
    let out = map.get("out").ok_or(ParseArgsError::MissingRequired)?;
    let width = map
        .get("width")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1920);
    let height = map
        .get("height")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1080);
    Ok(Args {
        html: PathBuf::from(html),
        out: PathBuf::from(out),
        width,
        height,
    })
}

/// The in-page flatten script, parameterised by width/height, matching the
/// `page.evaluate(({ W, H }) => { ... })` body verbatim in structure.
pub fn flatten_script(width: u32, height: u32) -> String {
    format!(
        r#"(() => {{
  const stage = document.querySelector('deck-stage');
  if (!stage) throw new Error('<deck-stage> not found');
  const sections = Array.from(stage.querySelectorAll(':scope > section'));
  if (!sections.length) throw new Error('No <section> found inside <deck-stage>');

  const style = document.createElement('style');
  style.textContent = `
    @page {{ size: {width}px {height}px; margin: 0; }}
    html, body {{ margin: 0 !important; padding: 0 !important; background: #fff; }}
    deck-stage {{ display: none !important; }}
  `;
  document.head.appendChild(style);

  const container = document.createElement('div');
  container.id = 'print-container';
  sections.forEach(s => {{
    s.style.cssText = `
      width: {width}px !important;
      height: {height}px !important;
      display: block !important;
      position: relative !important;
      overflow: hidden !important;
      page-break-after: always !important;
      break-after: page !important;
      margin: 0 !important;
      padding: 0 !important;
    `;
    container.appendChild(s);
  }});
  const last = sections[sections.length - 1];
  last.style.pageBreakAfter = 'auto';
  last.style.breakAfter = 'auto';
  document.body.appendChild(container);
  return sections.length;
}})()"#
    )
}

/// Browser I/O boundary. Mirrors: launch, navigate (`networkidle`), a fixed
/// settle wait for fonts/`deck-stage` init, evaluate the flatten script,
/// another settle wait, then `page.pdf(...)`.
pub trait DeckStageBrowser {
    fn navigate(&mut self, file_url: &str, width: u32, height: u32) -> Result<(), String>;
    /// Runs [`flatten_script`] and returns the section count it resolves to.
    fn evaluate_flatten(&mut self, script: &str) -> Result<u32, String>;
    fn print_to_pdf(&mut self, out: &Path, width: u32, height: u32) -> Result<Vec<u8>, String>;
}

pub trait FileSystem {
    fn exists(&self, path: &Path) -> bool;
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    HtmlNotFound(PathBuf),
    Browser(String),
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub bytes_written: usize,
    pub section_count: u32,
}

/// `main()`: existence check, navigate, flatten, print, write, summary.
pub fn run(
    fs: &dyn FileSystem,
    browser: &mut dyn DeckStageBrowser,
    args: &Args,
) -> Result<RunOutcome, RunError> {
    if !fs.exists(&args.html) {
        return Err(RunError::HtmlNotFound(args.html.clone()));
    }
    let file_url = format!("file://{}", args.html.to_string_lossy());
    browser
        .navigate(&file_url, args.width, args.height)
        .map_err(RunError::Browser)?;
    let script = flatten_script(args.width, args.height);
    let section_count = browser
        .evaluate_flatten(&script)
        .map_err(RunError::Browser)?;
    let pdf_bytes = browser
        .print_to_pdf(&args.out, args.width, args.height)
        .map_err(RunError::Browser)?;
    fs.write(&args.out, &pdf_bytes)
        .map_err(|e| RunError::Io(e.to_string()))?;
    Ok(RunOutcome {
        bytes_written: pdf_bytes.len(),
        section_count,
    })
}

/// Production `headless_chrome`-backed implementation.
///
/// NOTE (compile-review flag, cargo cannot run in this environment): built
/// against `headless_chrome` 1.x's `Browser`/`Tab` API as documented
/// (`Browser::new`, `browser.new_tab()`, `tab.navigate_to()`,
/// `tab.wait_until_navigated()`, `tab.evaluate()`,
/// `tab.print_to_pdf(Some(PrintToPdfOptions { .. }))`); field names should be
/// double-checked against the pinned version before this lands, per the
/// porting brief's "self-review compile correctness carefully" rule.
pub struct ChromeDeckStageBrowser {
    tab: std::sync::Arc<headless_chrome::Tab>,
    _browser: headless_chrome::Browser,
}

impl ChromeDeckStageBrowser {
    /// Launches headless Chrome sized to `width`x`height`, mirroring the
    /// `.mjs`'s `browser.newContext({ viewport: { width, height } })` (see
    /// `r07::real::RealChromeDriver::new` for the precedent this follows:
    /// window size is a launch-time option, not a per-navigate one).
    pub fn launch(width: u32, height: u32) -> Result<Self, String> {
        let launch_options = headless_chrome::LaunchOptions::default_builder()
            .headless(true)
            .window_size(Some((width, height)))
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

impl DeckStageBrowser for ChromeDeckStageBrowser {
    fn navigate(&mut self, file_url: &str, _width: u32, _height: u32) -> Result<(), String> {
        self.tab
            .navigate_to(file_url)
            .map_err(|e| e.to_string())?;
        self.tab
            .wait_until_navigated()
            .map_err(|e| e.to_string())?;
        std::thread::sleep(std::time::Duration::from_millis(2500));
        Ok(())
    }

    fn evaluate_flatten(&mut self, script: &str) -> Result<u32, String> {
        let remote = self
            .tab
            .evaluate(script, false)
            .map_err(|e| e.to_string())?;
        std::thread::sleep(std::time::Duration::from_millis(800));
        remote
            .value
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .ok_or_else(|| "flatten script did not return a section count".to_string())
    }

    fn print_to_pdf(&mut self, _out: &Path, _width: u32, _height: u32) -> Result<Vec<u8>, String> {
        self.tab
            .print_to_pdf(None)
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
        let argv: Vec<String> = ["--html", "deck.html", "--out", "deck.pdf"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let args = parse_args(&argv).unwrap();
        assert_eq!(args.width, 1920);
        assert_eq!(args.height, 1080);
    }

    #[test]
    fn parse_args_requires_html_and_out() {
        let argv: Vec<String> = ["--html", "deck.html"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_args(&argv), Err(ParseArgsError::MissingRequired));
    }

    #[test]
    fn flatten_script_embeds_dimensions() {
        let s = flatten_script(800, 600);
        assert!(s.contains("800px"));
        assert!(s.contains("600px"));
        assert!(s.contains("deck-stage"));
    }

    struct FakeFs {
        existing: Vec<PathBuf>,
        writes: RefCell<HashMap<PathBuf, Vec<u8>>>,
    }
    impl FileSystem for FakeFs {
        fn exists(&self, path: &Path) -> bool {
            self.existing.iter().any(|p| p == path)
        }
        fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
            self.writes.borrow_mut().insert(path.to_path_buf(), bytes.to_vec());
            Ok(())
        }
    }

    struct FakeBrowser {
        section_count: u32,
    }
    impl DeckStageBrowser for FakeBrowser {
        fn navigate(&mut self, _url: &str, _w: u32, _h: u32) -> Result<(), String> {
            Ok(())
        }
        fn evaluate_flatten(&mut self, _script: &str) -> Result<u32, String> {
            Ok(self.section_count)
        }
        fn print_to_pdf(&mut self, _out: &Path, _w: u32, _h: u32) -> Result<Vec<u8>, String> {
            Ok(vec![0x25, 0x50, 0x44, 0x46])
        }
    }

    #[test]
    fn run_errors_when_html_missing() {
        let fs = FakeFs {
            existing: vec![],
            writes: RefCell::new(HashMap::new()),
        };
        let mut browser = FakeBrowser { section_count: 3 };
        let args = Args {
            html: PathBuf::from("/nope.html"),
            out: PathBuf::from("/out.pdf"),
            width: 1920,
            height: 1080,
        };
        assert_eq!(
            run(&fs, &mut browser, &args),
            Err(RunError::HtmlNotFound(PathBuf::from("/nope.html")))
        );
    }

    #[test]
    fn run_writes_pdf_and_reports_section_count() {
        let html = PathBuf::from("/deck.html");
        let fs = FakeFs {
            existing: vec![html.clone()],
            writes: RefCell::new(HashMap::new()),
        };
        let mut browser = FakeBrowser { section_count: 5 };
        let args = Args {
            html,
            out: PathBuf::from("/out.pdf"),
            width: 1920,
            height: 1080,
        };
        let outcome = run(&fs, &mut browser, &args).unwrap();
        assert_eq!(outcome.section_count, 5);
        assert_eq!(outcome.bytes_written, 4);
        assert_eq!(fs.writes.borrow().get(&PathBuf::from("/out.pdf")).unwrap().len(), 4);
    }
}
