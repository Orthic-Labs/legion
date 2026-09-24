//! Port of `skills/designer/engine/scripts/detector/engines/static-html/detect-html.mjs`
//! (packet `r10` extends this file with a real HTML parser, closing the
//! DOM-dependent gap this module used to defer).
//!
//! `detectHtml`'s full pipeline drives `htmlparser2` + `css-select` +
//! `css-tree` + `domutils` through `detector/engines/static-html/
//! css-cascade.mjs`'s hand-rolled `StaticDocument`/`buildStaticStyleMap`/
//! `buildStaticWindow` "static browser", then runs every entry of
//! `STATIC_ELEMENT_RULES` — each of which calls into
//! `detector/rules/checks.mjs` (2,671 lines: `checkElementBorders`,
//! `checkElementColors`, `checkElementGlow`, `checkElementMotion`,
//! `checkElementIconTile`, `checkElementItalicSerif`,
//! `checkElementHeroEyebrow`, `checkElementQuality`,
//! `checkElementOversizedH1`, `checkElementClippedOverflow`,
//! `checkElementGptBorderShadow`, plus the page-level `checkPageLayout`/
//! `checkCreamPalette`/`checkPageQualityFromDoc`/
//! `checkRepeatedSectionKickersFromDoc`/`checkHtmlPatterns`) for every CSS
//! property those checks read (color, border, shadow, filter, transform,
//! overflow, box metrics, ...). Porting those twelve rule functions and
//! their general-purpose (all-properties) computed-style cascade is a
//! separate, multi-thousand-line undertaking belonging to whichever packet
//! ports `rules/checks.mjs` and `css-cascade.mjs` themselves (neither is
//! owned by `w2_013`, and neither has a Rust port anywhere in this tree);
//! that remains the one genuinely out-of-reach piece of this file and is
//! called out precisely, function by function, in this packet's report.
//!
//! Everything else in `detect-html.mjs` **is** ported here for real, now
//! using `scraper` (an actual HTML5 parser + CSS selector engine) in place
//! of the JS `htmlparser2`/`css-select` stack:
//! - [`is_full_page`] — port of `shared/page.mjs`'s `isFullPage`.
//! - [`classify_img_src`] — `checkElementBrokenImage`'s `src`-attribute
//!   classification, now driven over a real parsed document by
//!   [`find_broken_images`], which walks every `<img>` the same way the JS
//!   `STATIC_ELEMENT_RULES` entry for `broken-image` does
//!   (`document.querySelectorAll('img')`).
//! - [`StaticStylesheet`]/[`resolve_typography_style`] — a real (not
//!   hand-waved) CSS cascade limited to the two properties
//!   `checkStaticPageTypography` reads (`font-family`, `font-size`):
//!   `<style>` block parsing, selector specificity via
//!   `w2_012::css_cascade::static_specificity`, inline `style=""` via
//!   `w2_012::css_cascade::parse_static_style_attribute`, and priority via
//!   `w2_012::css_cascade::compare_static_priority` — the same building
//!   blocks `css-cascade.mjs`'s full engine uses, just not generalized to
//!   every CSS property. `em`/`rem`/`%`-relative font sizes are left
//!   unresolved (no inherited-value chain here) and are treated as
//!   "unknown declared value", matching how the JS engine's
//!   `getComputedStyle` would need real layout for those units too far
//!   beyond what a static string cascade can give; only literal `px`/`pt`
//!   values resolve, same limitation `w2_012::css_cascade`'s doc comment
//!   already notes for `resolveLengthPx`.
//! - [`check_static_page_typography`] — full port of
//!   `checkStaticPageTypography`, driven by the two pieces above over a
//!   real `scraper::Html` document.

/// The single finding id this file's ported logic can produce, matching
/// `STATIC_ELEMENT_RULES`'s `{ id: 'broken-image', ... }` entry.
pub const BROKEN_IMAGE_ANTIPATTERN_ID: &str = "broken-image";

/// Port of `checkElementBrokenImage(el)`'s classification logic, given the
/// already-resolved `src` attribute value (`None` when the attribute is
/// absent, matching JS's `src === undefined || src === null`).
///
/// Returns `Some(snippet)` when the element should be flagged as
/// `broken-image`, `None` otherwise — mirroring the JS function's return
/// of `[{ id: 'broken-image', snippet }]` vs `[]`.
pub fn classify_img_src(src: Option<&str>) -> Option<String> {
    match src {
        None => Some("<img> with no src attribute".to_string()),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed == "#" {
                Some(format!(r#"<img src="{raw}">"#))
            } else {
                None
            }
        }
    }
}

/// Port of `shared/page.mjs`'s `isFullPage(content)`: strips HTML comments,
/// then tests for a leading `<!doctype`, `<html>`, or `<head>` tag.
pub fn is_full_page(content: &str) -> bool {
    static COMMENT_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static TAG_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let comment_re = COMMENT_RE.get_or_init(|| regex::Regex::new(r"(?s)<!--.*?-->").unwrap());
    let tag_re =
        TAG_RE.get_or_init(|| regex::Regex::new(r"(?i)<!doctype\s|<html[\s>]|<head[\s>]").unwrap());
    let stripped = comment_re.replace_all(content, "");
    tag_re.is_match(&stripped)
}

/// A single `{ id, snippet }` finding, matching the un-wrapped shape
/// `STATIC_ELEMENT_RULES` entries and `checkStaticPageTypography` return
/// before `detectHtml` pipes them through `finding()`
/// ([`super::findings::build_finding`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFinding {
    pub id: &'static str,
    pub snippet: String,
}

/// Port of the `broken-image` `STATIC_ELEMENT_RULES` entry
/// (`document.querySelectorAll('img')` + `checkElementBrokenImage`), now
/// driven over a real parsed document.
pub fn find_broken_images(document: &scraper::Html) -> Vec<RawFinding> {
    let selector = scraper::Selector::parse("img").expect("static selector");
    document
        .select(&selector)
        .filter_map(|el| {
            let src = el.value().attr("src");
            classify_img_src(src).map(|snippet| RawFinding {
                id: BROKEN_IMAGE_ANTIPATTERN_ID,
                snippet,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Typography cascade: the two properties `checkStaticPageTypography` reads
// (`font-family`, `font-size`), resolved with a real (if narrow) cascade.
// ---------------------------------------------------------------------------

use crate::wf_port::w2_012::css_cascade::{
    compare_static_priority, parse_static_style_attribute, static_specificity, DeclMeta,
};

/// One parsed CSS rule from a `<style>` block: a selector's specificity and
/// its declared `font-family`/`font-size`, with source order preserved.
struct StaticRule {
    selector: scraper::Selector,
    specificity: [u32; 3],
    order: u32,
    font_family: Option<(String, bool)>, // (value, important)
    font_size: Option<(String, bool)>,
}

/// A tiny, real CSS parser limited to top-level (non-`@`-rule) blocks and
/// the two declarations this module cares about. Mirrors
/// `collectStaticCssRules`'s selector/specificity/declaration extraction,
/// scoped down from "every property" to `font-family`/`font-size`.
pub struct StaticStylesheet {
    rules: Vec<StaticRule>,
}

impl StaticStylesheet {
    /// Parses every `<style>` element's text content in document order.
    /// `@`-rules (e.g. `@media`, `@font-face`) are skipped wholesale — this
    /// mirrors treating unconditional rules only, which is a safe subset
    /// (it never manufactures a font declaration that isn't unconditionally
    /// present in the source, so it can under-detect but not over-detect).
    pub fn from_document(document: &scraper::Html) -> Self {
        let style_selector = scraper::Selector::parse("style").expect("static selector");
        let mut css = String::new();
        for style_el in document.select(&style_selector) {
            css.push_str(&style_el.text().collect::<String>());
            css.push('\n');
        }
        Self::from_css_text(&css)
    }

    /// Parses raw CSS text directly (used by tests and by
    /// [`Self::from_document`]).
    pub fn from_css_text(css: &str) -> Self {
        let mut rules = Vec::new();
        let mut order: u32 = 0;
        let bytes = css.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            // Skip whitespace.
            while i < bytes.len() && (bytes[i] as char).is_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }
            if bytes[i] == b'@' {
                // Skip a whole at-rule: either `...;` (no block) or a
                // brace-balanced `{ ... }` block (which may itself
                // contain nested rules, e.g. `@media`).
                let mut depth = 0i32;
                let mut seen_brace = false;
                while i < bytes.len() {
                    match bytes[i] {
                        b'{' => {
                            depth += 1;
                            seen_brace = true;
                        }
                        b'}' => {
                            depth -= 1;
                            i += 1;
                            if depth <= 0 {
                                break;
                            }
                            continue;
                        }
                        b';' if !seen_brace => {
                            i += 1;
                            break;
                        }
                        _ => {}
                    }
                    i += 1;
                }
                continue;
            }
            // Selector text up to the next `{`.
            let Some(rel_brace) = css[i..].find('{') else {
                break;
            };
            let selector_text = css[i..i + rel_brace].trim().to_string();
            let after_selector = i + rel_brace + 1;
            let Some(rel_close) = css[after_selector..].find('}') else {
                break;
            };
            let body = &css[after_selector..after_selector + rel_close];
            i = after_selector + rel_close + 1;

            if selector_text.is_empty() {
                continue;
            }

            let mut font_family = None;
            let mut font_size = None;
            for decl in body.split(';') {
                let Some(colon) = decl.find(':') else { continue };
                let prop = decl[..colon].trim().to_ascii_lowercase();
                let mut value = decl[colon + 1..].trim().to_string();
                let important = value.to_ascii_lowercase().ends_with("!important");
                if important {
                    value = value[..value.len() - "!important".len()].trim_end().to_string();
                }
                match prop.as_str() {
                    "font-family" => font_family = Some((value, important)),
                    "font-size" => font_size = Some((value, important)),
                    _ => {}
                }
            }
            if font_family.is_none() && font_size.is_none() {
                continue;
            }

            for single_selector in selector_text.split(',') {
                let single_selector = single_selector.trim();
                if single_selector.is_empty() {
                    continue;
                }
                let Ok(parsed) = scraper::Selector::parse(single_selector) else {
                    continue;
                };
                rules.push(StaticRule {
                    specificity: static_specificity(single_selector),
                    selector: parsed,
                    order,
                    font_family: font_family.clone(),
                    font_size: font_size.clone(),
                });
                order += 1;
            }
        }
        Self { rules }
    }

    /// Resolves the winning `font-family`/`font-size` declared values for
    /// `el`, applying author-rule cascade (specificity + source order)
    /// then inline `style=""` (which outranks non-`!important` author
    /// rules, same as [`compare_static_priority`]'s `inline` tier).
    /// Returns the raw declared CSS text, not a resolved px number —
    /// callers resolve `font-size` further with [`resolve_px_literal`].
    pub fn resolve(&self, el: &scraper::ElementRef) -> (Option<String>, Option<String>) {
        let mut best_family: Option<(DeclMeta, String)> = None;
        let mut best_size: Option<(DeclMeta, String)> = None;

        for rule in &self.rules {
            if !rule.selector.matches(el) {
                continue;
            }
            if let Some((value, important)) = &rule.font_family {
                let meta = DeclMeta {
                    important: *important,
                    inline: false,
                    specificity: rule.specificity,
                    order: rule.order,
                };
                if compare_static_priority(best_family.as_ref().map(|(m, _)| m), &meta) {
                    best_family = Some((meta, value.clone()));
                }
            }
            if let Some((value, important)) = &rule.font_size {
                let meta = DeclMeta {
                    important: *important,
                    inline: false,
                    specificity: rule.specificity,
                    order: rule.order,
                };
                if compare_static_priority(best_size.as_ref().map(|(m, _)| m), &meta) {
                    best_size = Some((meta, value.clone()));
                }
            }
        }

        if let Some(style_attr) = el.value().attr("style") {
            for decl in parse_static_style_attribute(style_attr, 1_000_000) {
                let meta = DeclMeta {
                    important: decl.important,
                    inline: true,
                    specificity: [0, 0, 0],
                    order: decl.order,
                };
                match decl.prop.to_ascii_lowercase().as_str() {
                    "font-family" => {
                        if compare_static_priority(best_family.as_ref().map(|(m, _)| m), &meta) {
                            best_family = Some((meta, decl.value.clone()));
                        }
                    }
                    "font-size" => {
                        if compare_static_priority(best_size.as_ref().map(|(m, _)| m), &meta) {
                            best_size = Some((meta, decl.value.clone()));
                        }
                    }
                    _ => {}
                }
            }
        }

        (
            best_family.map(|(_, v)| v),
            best_size.map(|(_, v)| v),
        )
    }
}

/// Resolves a `font-size` declared value to CSS pixels when it is a literal
/// `px` or `pt` length (`1pt` = `96/72 px`, matching CSS's fixed
/// px-per-inch definition). Relative units (`em`, `rem`, `%`, unitless,
/// `vw`/`vh`, ...) need an inherited-value chain this narrow cascade does
/// not build, so they resolve to `None` — the same conservative "skip, do
/// not guess" behaviour `w2_012::css_cascade` documents for its own
/// length parsing.
pub fn resolve_px_literal(value: &str) -> Option<f64> {
    let trimmed = value.trim();
    if let Some(num) = trimmed.strip_suffix("px") {
        return num.trim().parse::<f64>().ok().filter(|n| n.is_finite());
    }
    if let Some(num) = trimmed.strip_suffix("pt") {
        return num
            .trim()
            .parse::<f64>()
            .ok()
            .map(|n| n * 96.0 / 72.0)
            .filter(|n| n.is_finite());
    }
    None
}

/// Port of `checkStaticPageTypography(document, window)`: walks every
/// text-bearing element in the selector list, resolves its primary
/// (non-generic) font, and flags overused/single/flat-hierarchy fonts.
/// `GENERIC_FONTS`/`OVERUSED_FONTS` are passed in (they live in
/// `shared/constants.mjs`, not yet ported anywhere in this tree — the
/// caller supplies the same string sets from that file).
pub fn check_static_page_typography(
    document: &scraper::Html,
    stylesheet: &StaticStylesheet,
    generic_fonts: &std::collections::HashSet<String>,
    overused_fonts: &std::collections::HashSet<String>,
) -> Vec<RawFinding> {
    let mut findings = Vec::new();

    let text_selector = scraper::Selector::parse(
        "p, h1, h2, h3, h4, h5, h6, li, td, th, dd, blockquote, figcaption, a, button, label, span, div",
    )
    .expect("static selector");
    let mut fonts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut overused_found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for el in document.select(&text_selector) {
        let has_text = el
            .children()
            .filter_map(|node| node.value().as_text())
            .any(|t| !t.trim().is_empty());
        if !has_text {
            continue;
        }
        let (family, _) = stylesheet.resolve(&el);
        let Some(family) = family else { continue };
        let stack: Vec<String> = family
            .split(',')
            .map(|f| f.trim().trim_matches(|c| c == '\'' || c == '"').to_ascii_lowercase())
            .collect();
        let Some(primary) = stack.iter().find(|f| !f.is_empty() && !generic_fonts.contains(f.as_str())) else {
            continue;
        };
        fonts.insert(primary.clone());
        if overused_fonts.contains(primary.as_str()) {
            overused_found.insert(primary.clone());
        }
    }

    for font in &overused_found {
        findings.push(RawFinding {
            id: "overused-font",
            snippet: format!("Primary font: {font}"),
        });
    }

    let all_selector = scraper::Selector::parse("*").expect("static selector");
    let all_count = document.select(&all_selector).count();
    if fonts.len() == 1 && all_count >= 20 {
        findings.push(RawFinding {
            id: "single-font",
            snippet: format!("only font used is {}", fonts.iter().next().unwrap()),
        });
    }

    let size_selector = scraper::Selector::parse(
        "h1, h2, h3, h4, h5, h6, p, span, a, li, td, th, label, button, div",
    )
    .expect("static selector");
    let mut sizes: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new(); // stored as (px*10).round()
    for el in document.select(&size_selector) {
        let (_, size) = stylesheet.resolve(&el);
        let Some(size) = size else { continue };
        let Some(px) = resolve_px_literal(&size) else { continue };
        if px >= 8.0 && px < 200.0 {
            sizes.insert((px * 10.0).round() as u64);
        }
    }
    if sizes.len() >= 3 {
        let sorted: Vec<f64> = sizes.iter().map(|s| *s as f64 / 10.0).collect();
        let ratio = sorted[sorted.len() - 1] / sorted[0];
        if ratio < 2.0 {
            let sizes_label = sorted
                .iter()
                .map(|s| format!("{s}px"))
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(RawFinding {
                id: "flat-type-hierarchy",
                snippet: format!("Sizes: {sizes_label} (ratio {ratio:.1}:1)"),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_src_attribute_is_flagged() {
        assert_eq!(
            classify_img_src(None),
            Some("<img> with no src attribute".to_string())
        );
    }

    #[test]
    fn empty_src_is_flagged() {
        assert_eq!(classify_img_src(Some("")), Some(r#"<img src="">"#.to_string()));
    }

    #[test]
    fn whitespace_only_src_is_flagged() {
        assert_eq!(classify_img_src(Some("   ")), Some(r#"<img src="   ">"#.to_string()));
    }

    #[test]
    fn hash_placeholder_src_is_flagged() {
        assert_eq!(classify_img_src(Some("#")), Some(r##"<img src="#">"##.to_string()));
    }

    #[test]
    fn real_src_is_not_flagged() {
        assert_eq!(classify_img_src(Some("/logo.png")), None);
    }

    #[test]
    fn is_full_page_detects_doctype_html_head() {
        assert!(is_full_page("<!doctype html><html><head></head></html>"));
        assert!(is_full_page("<HTML><body>hi</body></html>"));
        assert!(is_full_page("<head><title>x</title></head>"));
    }

    #[test]
    fn is_full_page_rejects_fragment() {
        assert!(!is_full_page("<div class=\"card\"><p>hi</p></div>"));
    }

    #[test]
    fn is_full_page_ignores_tags_inside_comments() {
        assert!(!is_full_page("<!-- <html><head></head></html> --><div>x</div>"));
    }

    #[test]
    fn find_broken_images_walks_real_dom() {
        let html = r#"<div><img src="/ok.png"><img src=""><img></div>"#;
        let document = scraper::Html::parse_fragment(html);
        let findings = find_broken_images(&document);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.id == "broken-image"));
        assert_eq!(findings[0].snippet, r#"<img src="">"#);
        assert_eq!(findings[1].snippet, "<img> with no src attribute");
    }

    #[test]
    fn stylesheet_resolves_tag_selector_font() {
        let css = "p { font-family: Georgia, serif; font-size: 18px; }";
        let sheet = StaticStylesheet::from_css_text(css);
        let html = "<html><body><p id=\"x\">hi</p></body></html>";
        let document = scraper::Html::parse_document(html);
        let sel = scraper::Selector::parse("#x").unwrap();
        let el = document.select(&sel).next().unwrap();
        let (family, size) = sheet.resolve(&el);
        assert_eq!(family.as_deref(), Some("Georgia, serif"));
        assert_eq!(size.as_deref(), Some("18px"));
    }

    #[test]
    fn stylesheet_class_selector_beats_tag_selector_by_specificity() {
        let css = "p { font-family: Arial; } .special { font-family: Georgia; }";
        let sheet = StaticStylesheet::from_css_text(css);
        let html = "<p class=\"special\">hi</p>";
        let document = scraper::Html::parse_fragment(html);
        let sel = scraper::Selector::parse("p").unwrap();
        let el = document.select(&sel).next().unwrap();
        let (family, _) = sheet.resolve(&el);
        assert_eq!(family.as_deref(), Some("Georgia"));
    }

    #[test]
    fn stylesheet_inline_style_beats_non_important_author_rule() {
        let css = ".special { font-family: Georgia !important; } p { font-family: Arial; }";
        let sheet = StaticStylesheet::from_css_text(css);
        let html = r#"<p class="special" style="font-family: Times">hi</p>"#;
        let document = scraper::Html::parse_fragment(html);
        let sel = scraper::Selector::parse("p").unwrap();
        let el = document.select(&sel).next().unwrap();
        let (family, _) = sheet.resolve(&el);
        // !important author rule beats inline style, matching
        // compare_static_priority's precedence.
        assert_eq!(family.as_deref(), Some("Georgia"));
    }

    #[test]
    fn stylesheet_skips_at_rule_blocks() {
        let css = "@media (min-width: 900px) { p { font-family: Georgia; } } p { font-family: Arial; }";
        let sheet = StaticStylesheet::from_css_text(css);
        let html = "<p>hi</p>";
        let document = scraper::Html::parse_fragment(html);
        let sel = scraper::Selector::parse("p").unwrap();
        let el = document.select(&sel).next().unwrap();
        let (family, _) = sheet.resolve(&el);
        assert_eq!(family.as_deref(), Some("Arial"));
    }

    #[test]
    fn resolve_px_literal_handles_px_and_pt() {
        assert_eq!(resolve_px_literal("16px"), Some(16.0));
        assert_eq!(resolve_px_literal("12pt"), Some(16.0));
        assert_eq!(resolve_px_literal("1.5em"), None);
        assert_eq!(resolve_px_literal("100%"), None);
    }

    fn font_set(values: &[&str]) -> std::collections::HashSet<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn typography_flags_overused_font() {
        let html = r#"<html><body>
            <style>p { font-family: Arial, sans-serif; font-size: 16px; }</style>
            <p>one</p><p>two</p>
        </body></html>"#;
        let document = scraper::Html::parse_document(html);
        let sheet = StaticStylesheet::from_document(&document);
        let generic = font_set(&["serif", "sans-serif"]);
        let overused = font_set(&["arial"]);
        let findings = check_static_page_typography(&document, &sheet, &generic, &overused);
        assert!(findings.iter().any(|f| f.id == "overused-font" && f.snippet.contains("arial")));
    }

    #[test]
    fn typography_flags_single_font_when_at_least_20_elements() {
        let mut body = String::new();
        for i in 0..25 {
            body.push_str(&format!("<span>t{i}</span>"));
        }
        let html = format!(
            "<html><body><style>span {{ font-family: 'Brand Sans'; }}</style>{body}</body></html>"
        );
        let document = scraper::Html::parse_document(&html);
        let sheet = StaticStylesheet::from_document(&document);
        let generic = font_set(&["serif", "sans-serif"]);
        let overused = font_set(&[]);
        let findings = check_static_page_typography(&document, &sheet, &generic, &overused);
        assert!(findings.iter().any(|f| f.id == "single-font" && f.snippet.contains("brand sans")));
    }

    #[test]
    fn typography_flags_flat_type_hierarchy() {
        let html = r#"<html><body>
            <style>
              h1 { font-family: Georgia; font-size: 20px; }
              p { font-family: Georgia; font-size: 16px; }
              span { font-family: Georgia; font-size: 15px; }
            </style>
            <h1>Title</h1><p>Body text</p><span>Label</span>
        </body></html>"#;
        let document = scraper::Html::parse_document(html);
        let sheet = StaticStylesheet::from_document(&document);
        let generic = font_set(&["serif", "sans-serif"]);
        let overused = font_set(&[]);
        let findings = check_static_page_typography(&document, &sheet, &generic, &overused);
        assert!(findings.iter().any(|f| f.id == "flat-type-hierarchy"));
    }

    #[test]
    fn typography_no_findings_without_text_content() {
        let html = "<html><body><style>div{font-family:Arial;}</style><div></div></body></html>";
        let document = scraper::Html::parse_document(html);
        let sheet = StaticStylesheet::from_document(&document);
        let generic = font_set(&["serif", "sans-serif"]);
        let overused = font_set(&["arial"]);
        let findings = check_static_page_typography(&document, &sheet, &generic, &overused);
        assert!(findings.is_empty());
    }
}
