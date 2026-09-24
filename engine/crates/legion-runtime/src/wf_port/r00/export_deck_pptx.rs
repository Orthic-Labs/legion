//! Port of `skills/designer/engine/huashu/scripts/export_deck_pptx.mjs`.
//!
//! **PORTED.** This module ports the orchestration layer — arg parsing,
//! slide-file discovery/sort, per-file conversion loop with its
//! `[i/n] file ✓/✗` log lines, error aggregation, and the "all slides
//! failed -> don't write, exit 1" rule — behind a [`SlideConverter`] trait,
//! and wires it to a real production converter: [`RealSlideConverter`]
//! drives `wf_port::w2_007::html2pptx::{run_html2pptx, HeadlessChromeDriver}`
//! per slide (the Rust replacement for the original's `html2pptx.js` /
//! Playwright element translator) and [`write_deck`] hands the accumulated
//! `Vec<RawSlideData>` to `wf_port::w2_007::html2pptx::write_pptx_from_slides`
//! (the `zip`-crate `pptxgenjs` replacement) to produce the final `.pptx`,
//! mirroring `pres.writeFile()`. Slide size is `LAYOUT_WIDE`
//! (13.333in x 7.5in / 960pt x 540pt), matching the `.mjs`'s
//! `pres.layout = 'LAYOUT_WIDE'`.

use std::path::{Path, PathBuf};

use crate::wf_port::w2_007::html2pptx::{
    run_html2pptx, FsImageSource, HeadlessChromeDriver, RawSlideData, write_pptx_from_slides,
};

/// `LAYOUT_WIDE`: 13.333in x 7.5in, matching the `.mjs`'s `pres.layout`.
pub const LAYOUT_WIDE_WIDTH_IN: f64 = 13.333;
pub const LAYOUT_WIDE_HEIGHT_IN: f64 = 7.5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub slides: PathBuf,
    pub out: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseArgsError {
    /// `用法: node export_deck_pptx.mjs --slides <dir> --out <file.pptx>`
    MissingRequired,
}

pub fn parse_args(argv: &[String]) -> Result<Args, ParseArgsError> {
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
    let slides = map.get("slides").ok_or(ParseArgsError::MissingRequired)?;
    let out = map.get("out").ok_or(ParseArgsError::MissingRequired)?;
    Ok(Args {
        slides: PathBuf::from(slides),
        out: PathBuf::from(out),
    })
}

/// `(await fs.readdir(slidesDir)).filter(f => f.endsWith('.html')).sort()`.
pub fn html_files(entries: &[String]) -> Vec<String> {
    let mut v: Vec<String> = entries
        .iter()
        .filter(|f| f.ends_with(".html"))
        .cloned()
        .collect();
    v.sort();
    v
}

pub trait FileSystem {
    fn read_dir_names(&self, path: &Path) -> std::io::Result<Vec<String>>;
}

/// Per-slide conversion boundary standing in for `html2pptx(fullPath, pres)`.
/// `pres` in the original is a single shared `pptxgenjs` presentation that
/// every call mutates in place; here that's `P`, an opaque accumulator type
/// the caller owns.
pub trait SlideConverter<P> {
    fn convert(&mut self, slide_path: &Path, pres: &mut P) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileError {
    pub file: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    NoHtmlFiles(PathBuf),
    AllSlidesFailed { errors: Vec<FileError> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvertLogLine {
    Ok { index: usize, total: usize, file: String },
    Fail { index: usize, total: usize, file: String, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub converted: usize,
    pub total: usize,
    pub log: Vec<ConvertLogLine>,
    pub errors: Vec<FileError>,
}

/// `main()`: discover `.html` slides, convert each into `pres`, and decide
/// whether to write. The caller is responsible for actually writing `pres`
/// to `args.out` when this returns `Ok` (mirrors `pres.writeFile(...)`
/// happening in `main()` itself, but keeps the writer swappable/testable
/// too, since no pptx-writing crate exists in this workspace yet).
pub fn run<P>(
    fs: &dyn FileSystem,
    converter: &mut dyn SlideConverter<P>,
    pres: &mut P,
    args: &Args,
) -> Result<RunOutcome, RunError> {
    let entries = fs.read_dir_names(&args.slides).unwrap_or_default();
    let files = html_files(&entries);
    if files.is_empty() {
        return Err(RunError::NoHtmlFiles(args.slides.clone()));
    }

    let mut log = Vec::new();
    let mut errors = Vec::new();
    let total = files.len();
    for (i, f) in files.iter().enumerate() {
        let full_path = args.slides.join(f);
        match converter.convert(&full_path, pres) {
            Ok(()) => log.push(ConvertLogLine::Ok {
                index: i + 1,
                total,
                file: f.clone(),
            }),
            Err(e) => {
                log.push(ConvertLogLine::Fail {
                    index: i + 1,
                    total,
                    file: f.clone(),
                    error: e.clone(),
                });
                errors.push(FileError {
                    file: f.clone(),
                    error: e,
                });
            }
        }
    }

    if errors.len() == files.len() {
        return Err(RunError::AllSlidesFailed { errors });
    }

    Ok(RunOutcome {
        converted: total - errors.len(),
        total,
        log,
        errors,
    })
}

// ---------------------------------------------------------------------------
// Production wiring — real filesystem, real browser-backed converter, real
// pptx writer. Standing in for the `.mjs`'s `main()` body once
// `parseArgs()`/`readdir` have run.
// ---------------------------------------------------------------------------

/// Real [`FileSystem`]: `std::fs::read_dir`, the Rust equivalent of
/// `fs.readdir(slidesDir)`.
pub struct StdFileSystem;

impl FileSystem for StdFileSystem {
    fn read_dir_names(&self, path: &Path) -> std::io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }
}

/// Real [`SlideConverter`]: runs `run_html2pptx` (DOM walk + validation,
/// against a real `HeadlessChromeDriver` tab) for each slide file and
/// appends its `RawSlideData` to the shared `pres` accumulator — the Rust
/// equivalent of `await html2pptx(fullPath, pres)` mutating the shared
/// `pptxgenjs` presentation in place.
pub struct RealSlideConverter<'a> {
    driver: &'a mut HeadlessChromeDriver,
    cwd: PathBuf,
}

impl<'a> RealSlideConverter<'a> {
    pub fn new(driver: &'a mut HeadlessChromeDriver, cwd: PathBuf) -> Self {
        Self { driver, cwd }
    }
}

impl<'a> SlideConverter<Vec<RawSlideData>> for RealSlideConverter<'a> {
    fn convert(&mut self, slide_path: &Path, pres: &mut Vec<RawSlideData>) -> Result<(), String> {
        let html_file = slide_path.to_string_lossy().to_string();
        let outcome = run_html2pptx(
            self.driver,
            &html_file,
            &self.cwd,
            Some(LAYOUT_WIDE_WIDTH_IN),
            Some(LAYOUT_WIDE_HEIGHT_IN),
        )?;
        pres.push(outcome.slide_data);
        Ok(())
    }
}

/// Writes the accumulated per-slide `RawSlideData` to `out` as one
/// multi-slide `.pptx`, the Rust equivalent of `pres.writeFile({ fileName
/// })` at the end of `main()`.
pub fn write_deck(out: &Path, slides: &[RawSlideData]) -> Result<(), String> {
    let mut images = FsImageSource;
    write_pptx_from_slides(out, LAYOUT_WIDE_WIDTH_IN, LAYOUT_WIDE_HEIGHT_IN, slides, &mut images)
}

/// Full production entry point: launches a real headless Chrome tab,
/// discovers and converts every slide, and (when at least one slide
/// converted) writes the final `.pptx` to `args.out`. Mirrors `main()`
/// end to end, including its log lines via [`RunOutcome`]/[`RunError`].
pub fn run_production(args: &Args) -> Result<RunOutcome, RunError> {
    let fs = StdFileSystem;
    let mut driver = HeadlessChromeDriver::launch()
        .map_err(|e| RunError::AllSlidesFailed {
            errors: vec![FileError {
                file: String::new(),
                error: format!("failed to launch headless chrome: {e}"),
            }],
        })?;
    // `slides` is resolved relative to the current directory the same way
    // `path.resolve(slides)` is in the `.mjs`; `run_html2pptx`'s own
    // `resolve_html_file` re-resolves each per-file `full_path` against
    // this same `cwd`.
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut converter = RealSlideConverter::new(&mut driver, cwd);
    let mut pres: Vec<RawSlideData> = Vec::new();
    let outcome = run(&fs, &mut converter, &mut pres, args)?;
    write_deck(&args.out, &pres).map_err(|e| RunError::AllSlidesFailed {
        errors: vec![FileError {
            file: args.out.to_string_lossy().to_string(),
            error: e,
        }],
    })?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_requires_slides_and_out() {
        let argv: Vec<String> = ["--slides", "s"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_args(&argv), Err(ParseArgsError::MissingRequired));
    }

    #[test]
    fn parse_args_ok() {
        let argv: Vec<String> = ["--slides", "s", "--out", "o.pptx"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            parse_args(&argv).unwrap(),
            Args {
                slides: PathBuf::from("s"),
                out: PathBuf::from("o.pptx"),
            }
        );
    }

    #[test]
    fn html_files_filters_and_sorts() {
        let entries = vec!["02-b.html".to_string(), "01-a.html".to_string(), "x.css".to_string()];
        assert_eq!(html_files(&entries), vec!["01-a.html", "02-b.html"]);
    }

    struct FakeFs {
        names: Vec<String>,
    }
    impl FileSystem for FakeFs {
        fn read_dir_names(&self, _path: &Path) -> std::io::Result<Vec<String>> {
            Ok(self.names.clone())
        }
    }

    struct FailingOn(Vec<String>);
    impl SlideConverter<Vec<String>> for FailingOn {
        fn convert(&mut self, slide_path: &Path, pres: &mut Vec<String>) -> Result<(), String> {
            let name = slide_path.file_name().unwrap().to_string_lossy().to_string();
            if self.0.contains(&name) {
                Err(format!("bad slide {name}"))
            } else {
                pres.push(name);
                Ok(())
            }
        }
    }

    #[test]
    fn run_errors_on_empty_slide_dir() {
        let fs = FakeFs { names: vec![] };
        let mut conv = FailingOn(vec![]);
        let mut pres: Vec<String> = vec![];
        let args = Args {
            slides: PathBuf::from("slides"),
            out: PathBuf::from("o.pptx"),
        };
        assert_eq!(
            run(&fs, &mut conv, &mut pres, &args),
            Err(RunError::NoHtmlFiles(PathBuf::from("slides")))
        );
    }

    #[test]
    fn run_succeeds_with_partial_failures() {
        let fs = FakeFs {
            names: vec!["01-a.html".to_string(), "02-b.html".to_string()],
        };
        let mut conv = FailingOn(vec!["02-b.html".to_string()]);
        let mut pres: Vec<String> = vec![];
        let args = Args {
            slides: PathBuf::from("slides"),
            out: PathBuf::from("o.pptx"),
        };
        let outcome = run(&fs, &mut conv, &mut pres, &args).unwrap();
        assert_eq!(outcome.converted, 1);
        assert_eq!(outcome.total, 2);
        assert_eq!(outcome.errors.len(), 1);
        assert_eq!(pres, vec!["01-a.html".to_string()]);
    }

    #[test]
    fn run_errors_when_all_slides_fail() {
        let fs = FakeFs {
            names: vec!["01-a.html".to_string()],
        };
        let mut conv = FailingOn(vec!["01-a.html".to_string()]);
        let mut pres: Vec<String> = vec![];
        let args = Args {
            slides: PathBuf::from("slides"),
            out: PathBuf::from("o.pptx"),
        };
        match run(&fs, &mut conv, &mut pres, &args) {
            Err(RunError::AllSlidesFailed { errors }) => assert_eq!(errors.len(), 1),
            other => panic!("expected AllSlidesFailed, got {other:?}"),
        }
    }
}
