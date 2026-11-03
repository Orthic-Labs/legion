//! Port of `skills/designer/engine/huashu/scripts/export_deck_pptx.mjs`
//! (chunk w2_006): converts a directory of numbered slide `.html` files into
//! an editable `.pptx` by delegating each file to `html2pptx.js`.
//!
//! `html2pptx.js` itself is a large DOM-to-PowerPoint translator that is not
//! part of this chunk's file list, so it is not ported here. What is ported
//! is everything around it: CLI argument parsing, slide discovery/sort,
//! per-slide progress/error reporting, and the run-level pass/fail policy
//! (`if errors.length === files.length` → hard fail and do not write the
//! PPTX). The per-slide conversion itself is expressed as an injected
//! closure — the same shape `html2pptx(fullPath, pres)` has in the JS,
//! generalized so a host can plug in either the real HTML→PPTX translator or
//! a test double.

/// Port of `parseArgs`'s `{ slides, out }` shape (no defaults besides
/// presence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeckPptxArgs {
    pub slides: String,
    pub out: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    MissingSlidesOrOut,
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSlidesOrOut => f.write_str(
                "用法: legion script designer/export-deck-pptx --slides <dir> --out <file.pptx>\n\n\u{26a0}\u{fe0f} HTML 必须符合 4 条硬约束（见 references/editable-pptx.md）。\n   视觉自由度优先的场景请改用 legion script designer/export-deck-pdf 导出 PDF。",
            ),
        }
    }
}

impl std::error::Error for ArgError {}

/// Port of `parseArgs`'s generic `--key value` pair loop, requiring both
/// `slides` and `out` to be present afterward.
pub fn parse_args<I, S>(args: I) -> Result<DeckPptxArgs, ArgError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let items: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut slides = None;
    let mut out = None;

    let mut i = 0;
    while i < items.len() {
        let key = items[i].strip_prefix("--").unwrap_or(&items[i]).to_string();
        let value = items.get(i + 1).cloned();
        match (key.as_str(), value) {
            ("slides", Some(v)) => slides = Some(v),
            ("out", Some(v)) => out = Some(v),
            _ => {}
        }
        i += 2;
    }

    match (slides, out) {
        (Some(slides), Some(out)) => Ok(DeckPptxArgs { slides, out }),
        _ => Err(ArgError::MissingSlidesOrOut),
    }
}

/// Same discovery/sort rule as `export_deck_pdf.mjs`:
/// `.filter(f => f.endsWith('.html')).sort()`.
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

/// Port of `console.log(\`Converting ${n} slides via html2pptx...\`)`.
pub fn converting_line(count: usize) -> String {
    format!("Converting {count} slides via html2pptx...")
}

/// One slide's outcome, port of the `errors.push({ file, error })` entries
/// plus the success case's `` `  [${i+1}/${files.length}] ${f} ✓` `` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlideOutcome {
    Ok {
        line: String,
    },
    Err {
        file: String,
        error: String,
        line: String,
    },
}

/// Port of the per-slide try/catch inside the `for` loop over `files`,
/// generalized over an injected converter (the role `html2pptx(fullPath,
/// pres)` plays in the original). `convert` returns `Ok(())` on success or
/// `Err(message)` mirroring `e.message` from a thrown JS error.
pub fn convert_slide<F>(index: usize, total: usize, file: &str, convert: F) -> SlideOutcome
where
    F: FnOnce(&str) -> Result<(), String>,
{
    let n = index + 1;
    match convert(file) {
        Ok(()) => SlideOutcome::Ok {
            line: format!("  [{n}/{total}] {file} \u{2713}"),
        },
        Err(error) => SlideOutcome::Err {
            file: file.to_string(),
            line: format!("  [{n}/{total}] {file} \u{2717}  {error}"),
            error,
        },
    }
}

/// Result of running the whole deck: whether the PPTX should be written at
/// all, port of the `if (errors.length === files.length) { ...; exit(1) }`
/// hard-fail branch versus the partial-success path that still writes the
/// file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeckOutcome {
    /// All slides converted; some may have failed but not all.
    Write {
        succeeded: usize,
        total: usize,
        warning: Option<String>,
    },
    /// Every slide failed — port of `console.error('✗ 全部失败，不生成 PPTX。'); process.exit(1)`.
    AllFailed,
}

/// Port of the post-loop error-summary logic: the `⚠️ N 张 slide 转换失败`
/// warning when `errors.len() > 0`, and the `AllFailed` branch when every
/// slide errored.
pub fn summarize(outcomes: &[SlideOutcome]) -> DeckOutcome {
    let total = outcomes.len();
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o, SlideOutcome::Err { .. }))
        .count();

    if total > 0 && failed == total {
        return DeckOutcome::AllFailed;
    }

    let warning = if failed > 0 {
        Some(format!(
            "\n\u{26a0}\u{fe0f} {failed} 张 slide 转换失败。常见原因：HTML 不符合 4 条硬约束。\n  详见 references/editable-pptx.md 的「常见错误速查」。"
        ))
    } else {
        None
    };

    DeckOutcome::Write {
        succeeded: total - failed,
        total,
        warning,
    }
}

/// Port of the final summary line:
/// `` `\n✓ Wrote ${outFile}  (${succeeded}/${total} slides, 可编辑 PPTX)` ``.
pub fn wrote_summary_line(out_file: &str, succeeded: usize, total: usize) -> String {
    format!("\n\u{2713} Wrote {out_file}  ({succeeded}/{total} slides, 可编辑 PPTX)")
}

/// Port of the `all failed` fatal line.
pub fn all_failed_line() -> &'static str {
    "\u{2717} 全部失败，不生成 PPTX。"
}
