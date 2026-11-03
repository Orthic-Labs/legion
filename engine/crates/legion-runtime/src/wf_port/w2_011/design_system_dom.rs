//! Port of `collectStaticDesignSystemFindings` (plus its
//! `shouldSkipStaticDesignElement` / `hasDirectText` / `sampleText`
//! helpers) from `design-system.mjs` (packet r06).
//!
//! The JS walks a live `document` via `document.querySelectorAll('*')` and
//! reads *computed* styles via `window.getComputedStyle(el)` — resolved
//! after CSS cascade, inheritance, and the UA stylesheet. There is no CSS
//! engine in this crate to reproduce that, so the DOM walk + visibility
//! check + `getComputedStyle` read stay exactly what they are: real
//! browser work, run behind [`DesignDomEvaluator`] via a real Chromium
//! (`headless_chrome`) in [`ChromeDesignDomEvaluator`]. Everything that
//! *is* portable logic — the allow-list decisions (`isAllowedFont` /
//! `isAllowedColorRaw` / `isAllowedRadiusRaw`, already ported in
//! `design_system.rs`), the dedup-by-(font|color|radius)-per-element
//! bookkeeping, and the finding text/shape — runs in Rust in
//! [`collect_static_design_system_findings`], against the raw per-element
//! style observations the evaluator returns. This mirrors the JS 1:1
//! while keeping the browser dependency isolated behind a trait, so the
//! decision logic is unit-tested with a fake evaluator (no real browser
//! launched in tests).

use serde::Deserialize;

use super::design_system::{
    css_color_label, extract_radius_tokens, is_allowed_color_raw, is_allowed_font,
    is_allowed_radius_raw, primary_font, DesignFinding, DesignSystem,
};

const STATIC_DESIGN_SKIP_TAGS: [&str; 9] = [
    "head", "title", "meta", "link", "style", "script", "noscript", "template", "source",
];

/// One scanned element's tag/text context plus the subset of computed
/// style values `collectStaticDesignSystemFindings` reads. `None` fields
/// mirror JS conditions that never read that property at all (e.g. a
/// border side with zero width never reads `borderXColor`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElementStyleObservation {
    pub tag: String,
    pub sample_text: String,
    pub has_direct_text: bool,
    pub skip: bool,
    pub font_family: Option<String>,
    pub color: Option<String>,
    pub background_color: Option<String>,
    /// `(side, color)` pairs, one per border side with width > 0.
    #[serde(default)]
    pub border_colors: Vec<(String, String)>,
    pub outline_color: Option<String>,
    pub border_radius: Option<String>,
}

/// Behind-a-trait boundary for the real-browser DOM walk +
/// `getComputedStyle` read. Mirrors `document.querySelectorAll('*')` plus
/// `shouldSkipStaticDesignElement` / `hasDirectText` filtering: only
/// non-skipped elements are returned, `skip` is always `false` on returned
/// rows (kept on the struct for evaluators that choose to report skipped
/// rows for diagnostics; [`collect_static_design_system_findings`] treats
/// any `skip: true` row as filtered).
pub trait DesignDomEvaluator {
    /// Parses `html` as a document and returns one [`ElementStyleObservation`]
    /// per element, in document (`querySelectorAll('*')`) order.
    fn observe(&self, html: &str) -> Result<Vec<ElementStyleObservation>, String>;
}

/// The JS walk, inlined verbatim (tags/attrs/logic mirror
/// `shouldSkipStaticDesignElement` / `hasDirectText` / `sampleText` and the
/// style reads in `collectStaticDesignSystemFindings`) for
/// [`ChromeDesignDomEvaluator`] to run inside a real page via CDP
/// `Runtime.evaluate`. Kept as a plain JS string (not a template) so a
/// reviewer can diff it against `design-system.mjs` directly.
pub const OBSERVE_JS: &str = r#"
(() => {
  const SKIP_TAGS = new Set(['head','title','meta','link','style','script','noscript','template','source']);
  function hasDirectText(el) {
    return Array.from(el.childNodes || []).some(n => n.nodeType === 3 && n.textContent.trim().length > 0);
  }
  function sampleText(el) {
    const text = String(el.textContent || '').replace(/\s+/g, ' ').trim();
    return text ? text.slice(0, 40) : '';
  }
  function shouldSkip(el) {
    const tag = el.tagName ? el.tagName.toLowerCase() : '';
    if (SKIP_TAGS.has(tag)) return true;
    let cur = el;
    while (cur) {
      if (cur.getAttribute && (cur.getAttribute('hidden') !== null || cur.getAttribute('aria-hidden') === 'true')) return true;
      const style = window.getComputedStyle(cur);
      const display = String(style.display || '').toLowerCase();
      const visibility = String(style.visibility || '').toLowerCase();
      if (display === 'none' || visibility === 'hidden' || visibility === 'collapse') return true;
      cur = cur.parentElement;
    }
    return false;
  }
  const out = [];
  for (const el of document.querySelectorAll('*')) {
    if (shouldSkip(el)) continue;
    const tag = el.tagName ? el.tagName.toLowerCase() : 'unknown';
    const style = window.getComputedStyle(el);
    const directText = hasDirectText(el);
    const borderColors = [];
    for (const side of ['Top', 'Right', 'Bottom', 'Left']) {
      if ((parseFloat(style[`border${side}Width`]) || 0) > 0) {
        borderColors.push([side.toLowerCase(), style[`border${side}Color`]]);
      }
    }
    out.push({
      tag,
      sampleText: sampleText(el),
      hasDirectText: directText,
      skip: false,
      fontFamily: style.fontFamily || null,
      color: directText ? style.color : null,
      backgroundColor: style.backgroundColor || null,
      borderColors,
      outlineColor: (parseFloat(style.outlineWidth) || 0) > 0 ? style.outlineColor : null,
      borderRadius: style.borderRadius || null,
    });
  }
  return JSON.stringify(out);
})()
"#;

fn is_transparent_css(value: &str) -> bool {
    let text = value.trim().to_lowercase();
    if text.is_empty() || text == "transparent" {
        return true;
    }
    match super::design_system::parse_design_color(&text) {
        Some(c) => c.a <= 0.05,
        None => false,
    }
}

fn snippet(tag: &str, sample: &str) -> String {
    if sample.is_empty() {
        tag.to_string()
    } else {
        format!("{tag} \"{sample}\"")
    }
}

/// Port of `collectStaticDesignSystemFindings(document, window, filePath, designSystem)`,
/// driven off already-collected [`ElementStyleObservation`]s (see the
/// module doc for why the DOM walk itself is behind [`DesignDomEvaluator`]).
pub fn collect_static_design_system_findings(
    evaluator: &dyn DesignDomEvaluator,
    html: &str,
    file_path: &str,
    design_system: Option<&DesignSystem>,
) -> Result<Vec<DesignFinding>, String> {
    let Some(ds) = design_system.filter(|d| d.present) else {
        return Ok(Vec::new());
    };

    let elements = evaluator.observe(html)?;
    let mut findings = Vec::new();
    let mut seen_fonts = std::collections::HashSet::new();
    let mut seen_colors = std::collections::HashSet::new();
    let mut seen_radii = std::collections::HashSet::new();

    for el in elements {
        if el.skip || STATIC_DESIGN_SKIP_TAGS.contains(&el.tag.as_str()) {
            continue;
        }
        let ctx = snippet(&el.tag, &el.sample_text);

        if ds.has_fonts && el.has_direct_text {
            if let Some(stack) = el.font_family.as_deref() {
                let font = primary_font(stack);
                if !font.is_empty()
                    && !seen_fonts.contains(&font)
                    && !is_allowed_font(&font, Some(ds))
                {
                    seen_fonts.insert(font.clone());
                    findings.push(DesignFinding {
                        antipattern: "design-system-font".to_string(),
                        file: file_path.to_string(),
                        snippet: format!("{ctx} uses {font}; not declared in DESIGN.md typography"),
                        line: 0,
                        ignore_value: font,
                    });
                }
            }
        }

        if ds.has_colors {
            let mut checks: Vec<(String, String)> = Vec::new();
            if el.has_direct_text {
                if let Some(c) = el.color.as_deref() {
                    checks.push(("text color".to_string(), c.to_string()));
                }
            }
            if let Some(bg) = el.background_color.as_deref() {
                if !is_transparent_css(bg) {
                    checks.push(("background".to_string(), bg.to_string()));
                }
            }
            for (side, color) in &el.border_colors {
                checks.push((format!("border-{side}"), color.clone()));
            }
            if let Some(outline) = el.outline_color.as_deref() {
                checks.push(("outline".to_string(), outline.to_string()));
            }

            for (kind, raw) in checks {
                let label = css_color_label(&raw);
                if is_allowed_color_raw(&label, Some(ds)) {
                    continue;
                }
                let key = format!("{kind}:{label}");
                if seen_colors.contains(&key) {
                    continue;
                }
                seen_colors.insert(key);
                findings.push(DesignFinding {
                    antipattern: "design-system-color".to_string(),
                    file: file_path.to_string(),
                    snippet: format!("{kind} {label} on {ctx} is outside DESIGN.md colors"),
                    line: 0,
                    ignore_value: label,
                });
            }
        }

        if ds.has_radii {
            if let Some(raw_radius) = el.border_radius.as_deref() {
                let raw_radius = raw_radius.trim();
                if !raw_radius.is_empty() {
                    for token in extract_radius_tokens(raw_radius) {
                        if is_allowed_radius_raw(&token, Some(ds)) {
                            continue;
                        }
                        if seen_radii.contains(&token) {
                            continue;
                        }
                        seen_radii.insert(token.clone());
                        findings.push(DesignFinding {
                            antipattern: "design-system-radius".to_string(),
                            file: file_path.to_string(),
                            snippet: format!(
                                "border-radius {token} on {ctx} is outside the DESIGN.md rounded scale"
                            ),
                            line: 0,
                            ignore_value: token,
                        });
                    }
                }
            }
        }
    }

    Ok(findings)
}

/// Real [`DesignDomEvaluator`]: loads `html` into a headless Chromium tab
/// (via `headless_chrome`, same launch pattern as
/// [`crate::wf_port::r07::real::RealChromeDriver`] and the `r00` deck
/// export/thumbnail evaluators elsewhere in this crate) and runs
/// [`OBSERVE_JS`] against it, matching what a real browser's
/// `getComputedStyle` produces.
pub struct ChromeDesignDomEvaluator {
    executable: std::path::PathBuf,
}

impl ChromeDesignDomEvaluator {
    /// `executable` is the Chrome/Chromium binary path, mirroring the
    /// explicit-path launch the sibling `headless_chrome` integrations in
    /// this crate use rather than relying on autodetection.
    pub fn new(executable: std::path::PathBuf) -> Self {
        Self { executable }
    }
}

impl DesignDomEvaluator for ChromeDesignDomEvaluator {
    fn observe(&self, html: &str) -> Result<Vec<ElementStyleObservation>, String> {
        use headless_chrome::{Browser, LaunchOptions};

        let launch_options = LaunchOptions::default_builder()
            .path(Some(self.executable.clone()))
            .headless(true)
            .build()
            .map_err(|e| e.to_string())?;
        let browser = Browser::new(launch_options).map_err(|e| e.to_string())?;
        let tab = browser.new_tab().map_err(|e| e.to_string())?;

        // `Page.setDocumentContent`-style load without a filesystem temp
        // file: navigate to `about:blank` then inject the markup via
        // `document.write`, matching what a static-file scan would render.
        tab.navigate_to("about:blank").map_err(|e| e.to_string())?;
        let write_js = format!(
            "document.open(); document.write({}); document.close();",
            serde_json::to_string(html).map_err(|e| e.to_string())?
        );
        tab.evaluate(&write_js, false).map_err(|e| e.to_string())?;

        let remote_object = tab.evaluate(OBSERVE_JS, false).map_err(|e| e.to_string())?;
        let json = remote_object
            .value
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| "design DOM evaluator returned no JSON".to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }
}
