//! Port of `skills/designer/engine/huashu/scripts/export_deck_stage_pdf.mjs`
//! (chunk w2_007).
//!
//! `export_deck_stage_pdf.mjs` drives a real Chromium via Playwright to
//! render a single-file `<deck-stage>` HTML deck, flatten its shadow-DOM
//! slides into a plain `<div>`, and print that to a paginated, vector PDF.
//! The actual page-render / `page.evaluate` DOM surgery / `page.pdf()` call
//! needs a live browser engine; there is no headless-Chromium or CDP crate
//! in `engine/Cargo.lock`, so that half is not reachable from this
//! headless-engine crate (same boundary `w2_006::deck_stage` documents for
//! `deck_stage.js`'s browser globals). See the w2_007 report for the
//! `headless_chrome` dependency patch a future chunk would need to finish
//! that half.
//!
//! What *is* ported, faithfully, is every piece of deterministic logic the
//! script computes before/around the browser call: CLI arg parsing
//! (`parseArgs`, including its usage message and non-zero exit on missing
//! `--html`/`--out`), path resolution, the injected `<style>`/inline-style
//! text the page-flattening step writes (kept as data so a future
//! browser-backed executor can reuse it verbatim), and the final
//! human-readable summary line (`✓ Wrote ... (NN KB, N pages, vector)`).

use std::path::{Path, PathBuf};

/// Parsed form of `parseArgs()`. `width`/`height` default to `1920`/`1080`
/// exactly as `{ width: 1920, height: 1080 }` does before the `--key value`
/// loop overwrites them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub html: String,
    pub out: String,
    pub width: u32,
    pub height: u32,
}

/// The usage message `parseArgs` prints to stderr before `process.exit(1)`
/// when `--html`/`--out` are missing.
pub const USAGE: &str =
    "用法: legion script designer/export-deck-stage-pdf --html <deck.html> --out <file.pdf> [--width 1920] [--height 1080]";

/// Error mirroring the `console.error(...); process.exit(1)` path — the
/// caller decides how to surface `USAGE` and pick the process exit code
/// (`1`, matching the JS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingRequiredArgs;

/// Port of `parseArgs()`. The JS reads `process.argv.slice(2)` two at a
/// time (`--key value`); an odd-length tail with no paired value is simply
/// dropped by the `a[i + 1]` `undefined` read landing on a key whose value
/// is `undefined` — mirrored here by skipping a trailing unpaired flag.
/// `--width`/`--height` go through `parseInt`, which is mirrored by
/// `str::parse::<u32>` falling back to the default on failure (JS's
/// `parseInt` failure produces `NaN`, which every downstream numeric use
/// here would need finite input for anyway — this port treats a bad number
/// the same way a host wrapping this parser should: keep the default
/// rather than propagate `NaN`).
pub fn parse_args(argv: &[String]) -> Result<Args, MissingRequiredArgs> {
    let mut html: Option<String> = None;
    let mut out: Option<String> = None;
    let mut width: u32 = 1920;
    let mut height: u32 = 1080;

    let mut i = 0;
    while i < argv.len() {
        let raw_key = &argv[i];
        let key = raw_key.strip_prefix("--").unwrap_or(raw_key);
        let value = argv.get(i + 1);
        match (key, value) {
            ("html", Some(v)) => html = Some(v.clone()),
            ("out", Some(v)) => out = Some(v.clone()),
            ("width", Some(v)) => {
                if let Ok(n) = v.parse::<u32>() {
                    width = n;
                }
            }
            ("height", Some(v)) => {
                if let Ok(n) = v.parse::<u32>() {
                    height = n;
                }
            }
            _ => {}
        }
        i += 2;
    }

    match (html, out) {
        (Some(html), Some(out)) => Ok(Args {
            html,
            out,
            width,
            height,
        }),
        _ => Err(MissingRequiredArgs),
    }
}

/// Port of `path.resolve(html)` / `path.resolve(out)` against a given
/// current-working directory (Node resolves relative to `process.cwd()`;
/// the caller supplies that explicitly here rather than this crate reading
/// process-global state).
pub fn resolve_paths(args: &Args, cwd: &Path) -> (PathBuf, PathBuf) {
    let html_abs = resolve_one(cwd, &args.html);
    let out_abs = resolve_one(cwd, &args.out);
    (html_abs, out_abs)
}

fn resolve_one(cwd: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// Port of the `<style>` text block `page.evaluate` injects into
/// `document.head`, verbatim (the `${W}`/`${H}` template substitution).
pub fn print_style(width: u32, height: u32) -> String {
    format!(
        "@page {{ size: {w}px {h}px; margin: 0; }}\n      html, body {{ margin: 0 !important; padding: 0 !important; background: #fff; }}\n      deck-stage {{ display: none !important; }}\n    ",
        w = width,
        h = height
    )
}

/// Port of the inline `cssText` each flattened `<section>` gets, before the
/// last section's `pageBreakAfter`/`breakAfter` are reset to `auto`.
pub fn section_css_text(width: u32, height: u32) -> String {
    format!(
        "width: {w}px !important;\n        height: {h}px !important;\n        display: block !important;\n        position: relative !important;\n        overflow: hidden !important;\n        page-break-after: always !important;\n        break-after: page !important;\n        margin: 0 !important;\n        padding: 0 !important;\n      ",
        w = width,
        h = height
    )
}

/// Port of the final `console.log` summary line, given the written PDF's
/// byte size and the flattened section count. `(stat.size / 1024).toFixed(0)`
/// rounds half-away-from-zero the way `toFixed` does for positive inputs.
pub fn summary_line(out_file: &Path, byte_size: u64, section_count: usize) -> String {
    let kb = ((byte_size as f64) / 1024.0).round() as u64;
    format!(
        "\n\u{2713} Wrote {}  ({} KB, {} pages, vector)",
        out_file.display(),
        kb,
        section_count
    )
}

/// Port of the verification hint line printed after the summary.
pub fn verify_hint(out_file: &Path) -> String {
    format!(
        "  验证页数：mdimport \"{p}\" && pdfinfo \"{p}\" | grep Pages",
        p = out_file.display()
    )
}
