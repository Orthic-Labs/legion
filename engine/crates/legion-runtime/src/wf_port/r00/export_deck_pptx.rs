//! Port of `skills/designer/engine/huashu/scripts/export_deck_pptx.mjs`.
//!
//! **PORTED-PARTIAL.** This module faithfully ports the orchestration layer
//! — arg parsing, slide-file discovery/sort, per-file conversion loop with
//! its `[i/n] file ✓/✗` log lines, error aggregation, the "all slides
//! failed -> don't write, exit 1" rule, and the final summary line — behind
//! a [`SlideConverter`] trait. It does **not** port the conversion itself:
//! the original delegates every slide to `html2pptx.js` (a ~1178-line
//! HTML-DOM -> `pptxgenjs` element translator, per the prior `q_q0` full
//! audit), and this packet's brief does not add a pptx-writing crate — only
//! `reqwest`, `scraper`, `headless_chrome`, `image`. Without either
//! `html2pptx.js`'s own port or a pptx-writing crate, there is no faithful
//! Rust production [`SlideConverter`] to provide here; only a fake exists,
//! used in this module's tests.

use std::path::{Path, PathBuf};

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
