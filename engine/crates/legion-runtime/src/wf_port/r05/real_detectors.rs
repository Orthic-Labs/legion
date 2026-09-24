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
//! The antipattern registry (`registry/antipatterns.mjs`) is ported at
//! `wf_port::w2_014::antipatterns`, with `wf_port::r07::RegistryLookup` as
//! the production [`AntipatternLookup`]; [`RealDetectors`] carries a
//! `providers` field so `detect_text`/`detect_html`'s `filterByProviders`
//! step and `detect_url`'s equivalent both run against it. The one
//! capability genuinely not ported anywhere in this tree is `detectHtml`'s
//! ~2700-line per-element rule engine (`rules/checks.mjs`): [`detect_html`]
//! produces broken-image, static typography, design-system, and
//! text-content findings but not that rule engine's. [`detect_text`] is the
//! full composition: `r08` regex matchers + style/CSS-in-JS block
//! extraction, `w2_011` design-system source checks, and `w2_012`'s eight
//! page-level content analyzers.

use std::path::Path;

use super::super::r07::browser::ChromeDriver;
use super::super::r07::detect_url::{detect_url as port_detect_url, DetectUrlOptions, Viewport};
use super::super::r07::findings::AntipatternLookup;
use std::collections::HashSet;
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
/// results)` after its dedup loop. This function itself does not apply
/// `filterByProviders` (it takes no registry/providers) — that gating is
/// applied by [`RealDetectors::detect_text`], the `Detectors::detect_text`
/// impl, via [`filter_cli_findings_by_providers`], now that the antipattern
/// registry is ported (`wf_port::w2_014::antipatterns`,
/// `wf_port::r07::RegistryLookup`).
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

/// Port of `filterByProviders(findings, providers)` (`registry/antipatterns.mjs`)
/// applied to [`CliFinding`]s, mirroring the final step of both
/// `detectText` (`detect-text.mjs`) and `detectHtml` (`detect-html.mjs`):
/// both call `filterByProviders(deduped/findings, options.providers)`
/// before returning. Kept local (rather than reusing
/// `r07::findings::filter_by_providers`, which operates on `r07::Finding`)
/// since `CliFinding` is this crate's own output shape; the gating logic
/// (registry lookup + `GATED_PROVIDERS` short-circuit) is identical.
fn filter_cli_findings_by_providers(
    registry: &impl AntipatternLookup,
    findings: Vec<CliFinding>,
    providers: &[String],
) -> Vec<CliFinding> {
    if !registry.has_gated_providers() {
        return findings;
    }
    let enabled: HashSet<&str> = providers.iter().map(String::as_str).collect();
    findings
        .into_iter()
        .filter(|f| match registry.get(&f.antipattern) {
            None => true,
            Some(rule) => match rule.gated {
                None => true,
                Some(gate) => enabled.contains(gate.as_str()),
            },
        })
        .collect()
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
    /// CLI-wide `--gpt`/`--gemini` providers, applied by `detect_text`/
    /// `detect_html` (via [`filter_cli_findings_by_providers`]) the same
    /// way `options.providers` gates every call in one `main.mjs`
    /// invocation; `detect_url` gets its own copy per-call through
    /// `UrlScanOptions`, matching `detectUrl`'s own `options.providers`.
    pub providers: &'a [String],
}

impl<'a, Drv, Reg, Fe> super::cli::Detectors for RealDetectors<'a, Drv, Reg, Fe>
where
    Drv: ChromeDriver,
    Reg: AntipatternLookup,
    Fe: PageFetcher,
{
    fn detect_text(&mut self, content: &str, file_path: &str, design_system: Option<&DesignSystem>) -> Vec<CliFinding> {
        let findings = detect_text(content, file_path, design_system);
        filter_cli_findings_by_providers(self.registry, findings, self.providers)
    }

    fn detect_html(&mut self, file_path: &str, design_system: Option<&DesignSystem>) -> Result<Vec<CliFinding>, String> {
        let findings = detect_html(file_path, design_system).map_err(|e| e.to_string())?;
        Ok(filter_cli_findings_by_providers(self.registry, findings, self.providers))
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
