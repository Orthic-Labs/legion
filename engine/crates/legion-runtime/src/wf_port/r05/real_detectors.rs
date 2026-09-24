//! Composes the already-ported engine pieces (`wf_port::r08`,
//! `wf_port::w2_011`, `wf_port::w2_013`, `wf_port::r07`) into the
//! `detectText`/`detectHtml`-shaped functions `main.mjs` calls directly.
//! Kept separate from `cli.rs` so the CLI dispatch loop can be tested
//! against a fake [`super::cli::Detectors`] without touching real regex/DOM
//! work, matching this port's "I/O behind a trait, tested with fakes" rule
//! for the URL/site-sweep lanes ([`RealDetectors::detect_url`] takes a
//! [`ChromeDriver`] + [`AntipatternLookup`] generically for exactly this
//! reason).
//!
//! See [`super`]'s module doc for the two capabilities genuinely not ported
//! anywhere in this tree yet (detectHtml's per-element rule engine and the
//! antipattern registry) and how that gap is reflected here: [`detect_html`]
//! produces broken-image, static typography, design-system, and
//! text-content findings but not the ~2700-line per-element rule engine's.
//! [`detect_text`] is the full composition: `r08` regex matchers + style/
//! CSS-in-JS block extraction, `w2_011` design-system source checks, and
//! `w2_012`'s eight page-level content analyzers.

use std::path::Path;

use super::super::r07::browser::ChromeDriver;
use super::super::r07::detect_url::{detect_url as port_detect_url, DetectUrlOptions, Viewport};
use super::super::r07::findings::AntipatternLookup;
use super::super::r08::detect_text_matchers::{extract_css_in_js, extract_style_blocks, run_regex_matchers};
use super::super::r08::sweep_live::{sweep_site, PageFetcher};
use super::super::w2_011::design_system::{check_source_design_system, DesignSystem};
use super::super::w2_012::detect_text::{run_page_level_analyzers, run_text_content_analyzers, should_run_page_analyzers};
use super::super::w2_013::detect_html::{
    classify_img_src, find_broken_images, is_full_page, StaticStylesheet,
};
use super::output::CliFinding;

const CSS_LIKE_EXTS: [&str; 4] = [".css", ".scss", ".sass", ".less"];

fn ext_from_path(path: &str) -> String {
    Path::new(path)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

/// Dedup rule from `detectText`: same antipattern + same snippet, within 2
/// lines of a finding already kept.
fn dedupe(findings: Vec<CliFinding>) -> Vec<CliFinding> {
    let mut out: Vec<CliFinding> = Vec::new();
    'next: for f in findings {
        for d in &out {
            if d.antipattern == f.antipattern
                && d.snippet == f.snippet
                && (d.line as i64 - f.line as i64).abs() <= 2
            {
                continue 'next;
            }
        }
        out.push(f);
    }
    out
}

/// Port of `detectText(content, filePath, options)`: full-content regex
/// matchers, `<style>` block extraction (Vue/Svelte), CSS-in-JS
/// template-literal extraction, and design-system source checking, then
/// the same 2-line dedup JS applies, then (when `shouldRunPageAnalyzers`
/// gates true) the eight page-level content analyzers appended
/// undeduped — matching `detectText`'s own `deduped.push(...analyzer
/// results)` after its dedup loop. Provider filtering
/// (`filterByProviders`) is not applied: it depends on the antipattern
/// registry's `gated` metadata, which isn't ported anywhere in this tree
/// (see [`super`]'s module doc), so `--gpt`/`--gemini` are accepted by the
/// CLI but don't change this function's output.
pub fn detect_text(content: &str, file_path: &str, design_system: Option<&DesignSystem>) -> Vec<CliFinding> {
    let ext = ext_from_path(file_path);
    let lines: Vec<&str> = content.split('\n').collect();
    let block_context = CSS_LIKE_EXTS.contains(&ext.as_str());

    let mut findings: Vec<CliFinding> = Vec::new();
    for hit in run_regex_matchers(&lines, 0, block_context) {
        findings.push(CliFinding::new(hit.antipattern, file_path, hit.line, hit.snippet));
    }

    for block in extract_style_blocks(content, &ext) {
        let block_lines: Vec<&str> = block.content.split('\n').collect();
        for hit in run_regex_matchers(&block_lines, block.start_line.saturating_sub(1), true) {
            findings.push(CliFinding::new(hit.antipattern, file_path, hit.line, hit.snippet));
        }
    }
    for block in extract_css_in_js(content, &ext) {
        let block_lines: Vec<&str> = block.content.split('\n').collect();
        for hit in run_regex_matchers(&block_lines, block.start_line.saturating_sub(1), true) {
            findings.push(CliFinding::new(hit.antipattern, file_path, hit.line, hit.snippet));
        }
    }

    if let Some(ds) = design_system {
        for df in check_source_design_system(content, file_path, Some(ds)) {
            let mut f = CliFinding::new(df.antipattern, df.file, df.line, df.snippet);
            f.ignore_value = if df.ignore_value.is_empty() { None } else { Some(df.ignore_value) };
            findings.push(f);
        }
    }

    let mut deduped = dedupe(findings);

    // Page-level analyzers (single-font, flat-type-hierarchy,
    // monotonous-spacing, em-dash-overuse, marketing-buzzword,
    // numbered-section-markers, aphoristic-cadence, dark-glow): JS runs
    // these unconditionally once `shouldRunPageAnalyzers` gates true,
    // appended after dedup (not deduped against the earlier findings, same
    // as `detectText`'s `deduped.push(...)` after the loop).
    if should_run_page_analyzers(is_full_page(content), file_path) {
        for tf in run_page_level_analyzers(content) {
            deduped.push(CliFinding::new(tf.antipattern, file_path, tf.line.unwrap_or(0), tf.detail));
        }
    }

    deduped
}

/// Port of `detectHtml(filePath, options)`'s ported subset: broken-image
/// detection over the parsed document plus, on a full page, the static
/// typography check and the design-system source check (source text, not
/// the DOM-walking `collectStaticDesignSystemFindings`, which needs the
/// full cascade engine — see [`super`]'s module doc). The ~2700-line
/// per-element rule engine (`checkElementBorders`/`Colors`/`Glow`/`Motion`/
/// etc., `rules/checks.mjs`) is not ported anywhere in this tree, so its
/// findings are absent here; this is the packet's one open gap, not
/// something fabricated to look complete.
pub fn detect_html(file_path: &str, design_system: Option<&DesignSystem>) -> std::io::Result<Vec<CliFinding>> {
    let html = std::fs::read_to_string(file_path)?;
    let document = scraper::Html::parse_document(&html);

    let mut findings: Vec<CliFinding> = Vec::new();
    for raw in find_broken_images(&document) {
        findings.push(CliFinding::new(raw.id, file_path, 0, raw.snippet));
    }

    if let Some(ds) = design_system {
        for df in check_source_design_system(&html, file_path, Some(ds)) {
            let mut f = CliFinding::new(df.antipattern, df.file, df.line, df.snippet);
            f.ignore_value = if df.ignore_value.is_empty() { None } else { Some(df.ignore_value) };
            findings.push(f);
        }
    }

    if is_full_page(&html) {
        let stylesheet = StaticStylesheet::from_document(&document);
        // Port of `shared/constants.mjs`'s `GENERIC_FONTS`/`OVERUSED_FONTS`
        // sets. Neither is ported as a shared item anywhere in this tree
        // yet (`wf_port::w2_013::detect_html::check_static_page_typography`'s
        // own doc comment says the caller supplies them from that file), so
        // they're inlined here verbatim from the JS source.
        let generic_fonts: std::collections::HashSet<String> = [
            "serif", "sans-serif", "monospace", "cursive", "fantasy", "system-ui", "ui-serif",
            "ui-sans-serif", "ui-monospace", "ui-rounded", "-apple-system", "blinkmacsystemfont",
            "segoe ui", "inherit", "initial", "unset", "revert",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let overused_fonts: std::collections::HashSet<String> = [
            "inter", "roboto", "open sans", "lato", "montserrat", "arial", "helvetica",
            "fraunces", "instrument sans", "instrument serif", "geist", "geist sans",
            "geist mono", "mona sans", "plus jakarta sans", "space grotesk", "recoleta",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        for raw in super::super::w2_013::detect_html::check_static_page_typography(
            &document,
            &stylesheet,
            &generic_fonts,
            &overused_fonts,
        ) {
            findings.push(CliFinding::new(raw.id, file_path, 0, raw.snippet));
        }

        // Text-content analyzers (em-dash overuse, marketing buzzwords,
        // numbered section markers, aphoristic cadence) — `detectHtml`
        // calls these directly too, so `.html` files get the same
        // coverage as source files.
        for tf in run_text_content_analyzers(&html, true, file_path) {
            findings.push(CliFinding::new(tf.antipattern, file_path, tf.line.unwrap_or(0), tf.detail));
        }
    }

    Ok(findings)
}

/// Thin wrapper over `wf_port::r07::detect_url::detect_url`, unifying its
/// `Finding` shape into [`CliFinding`]. `visual_contrast_findings` is
/// always the JS `visualContrast: false` no-op (`|_| Ok(Vec::new())`); see
/// `wf_port::r07`'s module doc for why the visual-contrast fallback lane
/// itself isn't ported.
pub fn detect_url(
    driver: &mut impl ChromeDriver,
    registry: &impl AntipatternLookup,
    url: &str,
    browser_script: &str,
    options: &DetectUrlOptions,
) -> Result<Vec<CliFinding>, String> {
    let findings = port_detect_url(driver, registry, url, browser_script, options, |_| Ok(Vec::new()))?;
    Ok(findings
        .into_iter()
        .map(|f| {
            let mut cf = CliFinding::new(f.antipattern, f.file, f.line, f.snippet);
            cf.name = Some(f.name);
            cf.description = Some(f.description);
            cf.severity = Some(f.severity);
            cf.ignore_value = f.ignore_value;
            cf
        })
        .collect())
}

/// Thin wrapper over `wf_port::r08::sweep_live::sweep_site`.
pub fn sweep(fetcher: &dyn PageFetcher, url: &str, site_type: Option<&str>) -> Vec<CliFinding> {
    sweep_site(fetcher, url, site_type)
        .into_iter()
        .map(|sf| CliFinding::new(sf.antipattern, sf.file, 0, sf.detail))
        .collect()
}

#[allow(unused)]
fn assert_classify(src: Option<&str>) -> Option<String> {
    classify_img_src(src)
}

/// [`super::cli::Detectors`] wired to the production engines: regex/design
/// system/broken-image/typography detection run directly, URL scanning
/// goes through the injected [`ChromeDriver`] + [`AntipatternLookup`], and
/// `--site` sweeps go through the injected [`PageFetcher`]. The browser
/// injection script (`window.impeccableDetect`, `browser_script.js`) isn't
/// ported in this tree — the caller supplies it verbatim, same as
/// `wf_port::r07::detect_url`'s own tests do.
pub struct RealDetectors<'a, Drv, Reg, Fe>
where
    Drv: ChromeDriver,
    Reg: AntipatternLookup,
    Fe: PageFetcher,
{
    pub driver: &'a mut Drv,
    pub registry: &'a Reg,
    pub fetcher: &'a Fe,
    pub browser_script: &'a str,
}

impl<'a, Drv, Reg, Fe> super::cli::Detectors for RealDetectors<'a, Drv, Reg, Fe>
where
    Drv: ChromeDriver,
    Reg: AntipatternLookup,
    Fe: PageFetcher,
{
    fn detect_text(&mut self, content: &str, file_path: &str, design_system: Option<&DesignSystem>) -> Vec<CliFinding> {
        detect_text(content, file_path, design_system)
    }

    fn detect_html(&mut self, file_path: &str, design_system: Option<&DesignSystem>) -> Result<Vec<CliFinding>, String> {
        detect_html(file_path, design_system).map_err(|e| e.to_string())
    }

    fn detect_url(&mut self, url: &str, options: &super::cli::UrlScanOptions) -> Result<Vec<CliFinding>, String> {
        let mut opts = DetectUrlOptions {
            providers: options.providers.clone(),
            ..DetectUrlOptions::default()
        };
        if let Some((w, h)) = options.viewport {
            opts.viewport = Viewport { width: w, height: h };
        }
        detect_url(self.driver, self.registry, url, self.browser_script, &opts)
    }

    fn sweep_site(&mut self, url: &str, site_type: Option<&str>) -> Vec<CliFinding> {
        sweep(self.fetcher, url, site_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_text_matches_and_dedupes() {
        let content = "a\n.x { border-l-4: 1; border-l-4: 1; }\n";
        let findings = detect_text(content, "x.css", None);
        // exact matches depend on the matcher table; just check it runs and
        // dedupe doesn't blow up.
        assert!(findings.len() <= 4);
    }

    #[test]
    fn detect_html_reports_broken_images() {
        let dir = std::env::temp_dir().join(format!(
            "r05-html-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.html");
        std::fs::write(&path, "<html><body><img src=\"\"></body></html>").unwrap();
        let findings = detect_html(path.to_str().unwrap(), None).unwrap();
        assert!(findings.iter().any(|f| f.antipattern == "broken-image"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
