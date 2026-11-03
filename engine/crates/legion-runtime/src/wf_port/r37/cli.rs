//! Port of `google_report.py`'s CLI (`main()` and its `argparse` setup).
//!
//! Same flags (`--type`/`-t`, `--data`/`-d`, `--domain`, `--output-dir`/`-o`,
//! `--format`/`-f`, `--json`/`-j`), same choices, same defaults
//! (`--output-dir` defaults to `"."`, `--format` defaults to `"pdf"`), same
//! stdin-fallback-when-no-`--data`-and-stdin-is-piped behavior, same exit
//! codes (`1` on a bad/missing data source, `0` otherwise -- the Python never
//! explicitly exits nonzero for a `generate_report` error, it just prints to
//! stderr and continues to the summary print, which this port matches).

use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::report::{
    generate_report, ChromePdfRenderer, OutputFormat, PdfRenderer, ReportResult, ReportType,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Args {
    pub report_type: ReportType,
    pub data_path: Option<PathBuf>,
    pub domain: String,
    pub output_dir: PathBuf,
    pub format: OutputFormat,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseArgsError {
    MissingType,
    InvalidType(String),
    MissingDomain,
    InvalidFormat(String),
}

/// Port of the `argparse.ArgumentParser` setup. Accepts both the long
/// (`--type`) and short (`-t`) forms exactly like `argparse` does.
pub fn parse_args(argv: &[String]) -> Result<Args, ParseArgsError> {
    let mut report_type: Option<String> = None;
    let mut data_path: Option<PathBuf> = None;
    let mut domain: Option<String> = None;
    let mut output_dir = PathBuf::from(".");
    let mut format: Option<String> = None;
    let mut json = false;

    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        let take_value = |i: &mut usize| -> Option<String> {
            *i += 1;
            argv.get(*i).cloned()
        };
        match arg {
            "--type" | "-t" => report_type = take_value(&mut i),
            "--data" | "-d" => data_path = take_value(&mut i).map(PathBuf::from),
            "--domain" => domain = take_value(&mut i),
            "--output-dir" | "-o" => {
                if let Some(v) = take_value(&mut i) {
                    output_dir = PathBuf::from(v);
                }
            }
            "--format" | "-f" => format = take_value(&mut i),
            "--json" | "-j" => json = true,
            _ => {}
        }
        i += 1;
    }

    let report_type = report_type.ok_or(ParseArgsError::MissingType)?;
    let report_type = ReportType::parse(&report_type)
        .ok_or_else(|| ParseArgsError::InvalidType(report_type.clone()))?;
    let domain = domain.ok_or(ParseArgsError::MissingDomain)?;
    let format = match format {
        Some(f) => OutputFormat::parse(&f).ok_or(ParseArgsError::InvalidFormat(f))?,
        None => OutputFormat::Pdf,
    };

    Ok(Args {
        report_type,
        data_path,
        domain,
        output_dir,
        format,
        json,
    })
}

/// Boundary for reading the input JSON (a file, or stdin when `--data` is
/// omitted). Kept behind a trait per this packet's brief so tests don't touch
/// real stdin/disk.
pub trait DataSource {
    fn read_file(&self, path: &Path) -> Result<String, String>;
    /// `None` mirrors Python's `sys.stdin.isatty()` guard: no piped input available.
    fn read_stdin(&self) -> Option<Result<String, String>>;
}

pub struct RealDataSource;

impl DataSource for RealDataSource {
    fn read_file(&self, path: &Path) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    }

    fn read_stdin(&self) -> Option<Result<String, String>> {
        use std::io::IsTerminal as _;
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return None;
        }
        let mut buf = String::new();
        Some(
            std::io::stdin()
                .lock()
                .read_to_string(&mut buf)
                .map(|_| buf)
                .map_err(|e| e.to_string()),
        )
    }
}

/// Port of the "Load data" block of `main()`.
pub fn load_data(args: &Args, source: &dyn DataSource) -> Result<Value, String> {
    let raw = if let Some(path) = &args.data_path {
        source
            .read_file(path)
            .map_err(|e| format!("Error reading data file: {e}"))?
    } else if let Some(stdin_result) = source.read_stdin() {
        stdin_result.map_err(|e| format!("Error parsing stdin JSON: {e}"))?
    } else {
        return Err("Error: Provide --data file or pipe JSON via stdin.".to_string());
    };
    serde_json::from_str(&raw).map_err(|e| format!("Error parsing JSON: {e}"))
}

/// Port of `main()`'s body from "Load data" onward, given already-parsed
/// `Args` and already-loaded `data`. Returns the same lines `main()` prints
/// (stdout lines, then optionally a JSON blob) plus the process exit code.
pub fn run_with_data(
    args: &Args,
    data: &Value,
    timestamp: &str,
    renderer: Option<&mut dyn PdfRenderer>,
) -> (ReportResult, Vec<String>) {
    let result = generate_report(
        args.report_type,
        data,
        &args.domain,
        &args.output_dir,
        args.format,
        timestamp,
        renderer,
    );

    let mut stdout_lines = Vec::new();
    if args.json {
        stdout_lines.push(serde_json::to_string_pretty(&result).unwrap_or_default());
    } else {
        for f in &result.files {
            stdout_lines.push(format!("Generated: {f}"));
        }
    }
    (result, stdout_lines)
}

/// Full `main()` port: parses argv, loads data (file or stdin), renders (via
/// a real `ChromePdfRenderer` only when the requested format needs a PDF),
/// prints to stdout/stderr, and returns the process exit code.
pub fn run(argv: &[String], timestamp: &str) -> i32 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {e:?}");
            return 1;
        }
    };

    let data = match load_data(&args, &RealDataSource) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };

    let wants_pdf = matches!(
        args.format,
        OutputFormat::Pdf | OutputFormat::Both | OutputFormat::All
    );
    let mut chrome_renderer: Option<ChromePdfRenderer> = if wants_pdf {
        match ChromePdfRenderer::launch() {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("Error: PDF generation failed: {e}");
                None
            }
        }
    } else {
        None
    };
    let renderer: Option<&mut dyn PdfRenderer> =
        chrome_renderer.as_mut().map(|r| r as &mut dyn PdfRenderer);

    let (result, lines) = run_with_data(&args, &data, timestamp, renderer);
    if let Some(err) = &result.error {
        eprintln!("Error: {err}");
    }
    for line in lines {
        println!("{line}");
    }
    0
}
