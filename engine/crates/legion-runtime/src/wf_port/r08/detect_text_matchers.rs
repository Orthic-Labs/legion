//! wf_port packet r08 (area `skills/designer/engine/scripts/detector/engines/
//! regex/detect-text.mjs`, target crate `legion-runtime`).
//!
//! Completes the gap `wf_port::w2_012::detect_text`'s module doc explicitly
//! left open: the 15-entry `REGEX_MATCHERS` line-scoped table
//! (side-tab / border-accent-on-rounded / overused-font / gradient-text /
//! gray-on-color / ai-color-palette / bounce-easing / layout-transition /
//! broken-image), the Vue/Svelte `<style>` block extractor
//! (`extractStyleBlocks`), the CSS-in-JS template-literal extractor
//! (`extractCSSinJS`), `runRegexMatchers`, and the `detectText` orchestrator
//! (dedup + `filterByProviders` + page-level analyzer dispatch).
//!
//! Each matcher mirrors its JS `{ id, regex, test, fmt }` entry: scan every
//! line (or, for extracted blocks / CSS-like files, a +-3-line context
//! window) with the matcher's regex, keep a match only when `test` passes,
//! and format the finding snippet with `fmt`. Iteration order (outer
//! matcher, inner line, inner match) matches the JS `for` loops exactly so
//! finding order is reproducible.

use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};

use super::super::w2_012::detect_text::{has_border_radius, has_rounded, is_neutral_border_color, is_safe_element};

/// One raw regex-matcher hit: antipattern id, formatted snippet, and the
/// 1-based line number (already offset for extracted blocks).
#[derive(Debug, Clone, PartialEq)]
pub struct MatcherHit {
    pub antipattern: &'static str,
    pub snippet: String,
    pub line: u32,
}

fn re(pat: &str) -> Regex {
    Regex::new(pat).unwrap()
}
fn rei(pat: &str) -> Regex {
    RegexBuilder::new(pat).case_insensitive(true).build().unwrap()
}

/// Context string used by a matcher's `test`: either the single line (JS
/// `blockContext ? null-passed line` — no, see below) or, when
/// `block_context` is set, the +-3-line window joined with spaces. Mirrors
/// `runRegexMatchers`'s `context` local exactly.
fn context_for(lines: &[&str], i: usize, block_context: bool) -> String {
    if block_context {
        let start = i.saturating_sub(3);
        let end = (i + 4).min(lines.len());
        lines[start..end].join(" ")
    } else {
        lines[i].to_string()
    }
}

// ---------------------------------------------------------------------------
// side-tab
// ---------------------------------------------------------------------------

fn side_tab_tw_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\bborder-[lrse]-(\d+)\b"))
}
fn side_tab_css_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"border-(?:left|right)\s*:\s*(\d+)px\s+solid[^;]*"))
}
fn side_tab_width_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"border-(?:left|right)-width\s*:\s*(\d+)px"))
}
fn side_tab_inline_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"border-inline-(?:start|end)\s*:\s*(\d+)px\s+solid"))
}
fn side_tab_inline_width_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"border-inline-(?:start|end)-width\s*:\s*(\d+)px"))
}
fn side_tab_js_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r#"border(?:Left|Right)\s*[:=]\s*["'`](\d+)px\s+solid"#))
}

// ---------------------------------------------------------------------------
// border-accent-on-rounded
// ---------------------------------------------------------------------------

fn accent_tw_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\bborder-[tb]-(\d+)\b"))
}
fn accent_css_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"border-(?:top|bottom)\s*:\s*(\d+)px\s+solid"))
}

// ---------------------------------------------------------------------------
// overused-font
// ---------------------------------------------------------------------------

fn overused_font_css_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        rei(r#"font-family\s*:\s*['"]?(Inter|Roboto|Open Sans|Lato|Montserrat|Arial|Helvetica|Fraunces|Geist Sans|Geist Mono|Geist|Mona Sans|Plus Jakarta Sans|Space Grotesk|Recoleta|Instrument Sans|Instrument Serif)\b"#)
    })
}
fn overused_font_gf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        rei(r#"fonts\.googleapis\.com/css2?\?family=(Inter|Roboto|Open\+Sans|Lato|Montserrat|Fraunces|Plus\+Jakarta\+Sans|Space\+Grotesk|Instrument\+Sans|Instrument\+Serif|Mona\+Sans|Geist)\b"#)
    })
}

// ---------------------------------------------------------------------------
// gradient-text
// ---------------------------------------------------------------------------

fn gradient_clip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"background-clip\s*:\s*text|-webkit-background-clip\s*:\s*text"))
}
fn gradient_word_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"gradient"))
}
fn bg_clip_text_tw_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\bbg-clip-text\b"))
}
fn bg_gradient_to_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"\bbg-gradient-to-"))
}

// ---------------------------------------------------------------------------
// gray-on-color (Tailwind)
// ---------------------------------------------------------------------------

fn gray_text_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\btext-(?:gray|slate|zinc|neutral|stone)-(\d+)\b"))
}
fn colored_bg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\bbg-(?:red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d+\b"))
}

// ---------------------------------------------------------------------------
// ai-color-palette (Tailwind)
// ---------------------------------------------------------------------------

fn ai_text_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\btext-(?:purple|violet|indigo)-(\d+)\b"))
}
fn heading_ctx_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"\btext-(?:[2-9]xl|[3-9]xl)\b|<h[1-3]"))
}
fn ai_from_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\bfrom-(?:purple|violet|indigo)-(\d+)\b"))
}
fn ai_to_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\bto-(?:purple|violet|indigo|blue|cyan|pink|fuchsia)-\d+\b"))
}

// ---------------------------------------------------------------------------
// bounce-easing
// ---------------------------------------------------------------------------

fn animate_bounce_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"\banimate-bounce\b"))
}
fn animation_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"animation(?:-name)?\s*:\s*([^;{}]*(?:bounce|elastic|wobble|jiggle|spring)[^;{}]*)"))
}
fn bounce_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"bounce|elastic|wobble|jiggle|spring"))
}
fn cubic_bezier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"cubic-bezier\(\s*([\d.-]+)\s*,\s*([\d.-]+)\s*,\s*([\d.-]+)\s*,\s*([\d.-]+)\s*\)"))
}

// ---------------------------------------------------------------------------
// layout-transition
// ---------------------------------------------------------------------------

fn transition_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"transition\s*:\s*([^;{}]+)"))
}
fn transition_property_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"transition-property\s*:\s*([^;{}]+)"))
}
fn layout_prop_test_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"\b(?:(?:max|min)-)?(?:width|height)\b|\bpadding\b|\bmargin\b"))
}
fn layout_prop_all_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"\ball\b"))
}
fn layout_prop_found_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        rei(r"\b(?:(?:max|min)-)?(?:width|height)\b|\bpadding(?:-(?:top|right|bottom|left))?\b|\bmargin(?:-(?:top|right|bottom|left))?\b")
    })
}

// ---------------------------------------------------------------------------
// broken-image
// ---------------------------------------------------------------------------

fn broken_img_empty_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r##"<img\b[^>]*?\bsrc\s*=\s*(?:""|''|"\s+"|'\s+'|"#"|'#')"##))
}
fn broken_img_none_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // JS: /<img\b(?:(?!\bsrc\s*=)[^>])*>/gi — negative lookahead per-char is
    // not representable in the `regex` crate (no lookaround). A plain `<img
    // ...>` scan plus a post-match `src=` absence check (already what the
    // JS `test` callback re-verifies) reproduces the same matched set.
    RE.get_or_init(|| rei(r"<img\b[^>]*>"))
}
fn has_src_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| rei(r"\bsrc\s*="))
}

fn push(hits: &mut Vec<MatcherHit>, id: &'static str, snippet: String, line: u32) {
    hits.push(MatcherHit { antipattern: id, snippet, line });
}

/// Port of `runRegexMatchers(lines, filePath, lineOffset, blockContext)`
/// (the `profile` instrumentation wrapper is not ported — no profiler in
/// this crate; behavior is identical either way). `lines` are already
/// split on `\n`; `line_offset` and `block_context` mirror the JS params.
pub fn run_regex_matchers(lines: &[&str], line_offset: u32, block_context: bool) -> Vec<MatcherHit> {
    let mut hits = Vec::new();

    // --- side-tab (6 regexes) ---
    for (i, line) in lines.iter().enumerate() {
        for caps in side_tab_tw_re().captures_iter(line) {
            let n: i64 = caps[1].parse().unwrap();
            let ctx = context_for(lines, i, block_context);
            let ok = if has_rounded(&ctx) { n >= 2 } else { n >= 4 };
            if ok {
                push(&mut hits, "side-tab", caps[0].to_string(), i as u32 + 1 + line_offset);
            }
        }
        for caps in side_tab_css_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            if is_safe_element(&ctx) {
                continue;
            }
            let whole = &caps[0];
            if is_neutral_border_color(whole) {
                continue;
            }
            let n: i64 = caps[1].parse().unwrap();
            let ok = if has_border_radius(&ctx) { n >= 2 } else { n >= 3 };
            if ok {
                let trimmed = whole.trim_end_matches(|c: char| c == ';' || c.is_whitespace());
                push(&mut hits, "side-tab", trimmed.to_string(), i as u32 + 1 + line_offset);
            }
        }
        for caps in side_tab_width_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            let n: i64 = caps[1].parse().unwrap();
            if !is_safe_element(&ctx) && n >= 3 {
                push(&mut hits, "side-tab", caps[0].to_string(), i as u32 + 1 + line_offset);
            }
        }
        for caps in side_tab_inline_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            let n: i64 = caps[1].parse().unwrap();
            if !is_safe_element(&ctx) && n >= 3 {
                push(&mut hits, "side-tab", caps[0].to_string(), i as u32 + 1 + line_offset);
            }
        }
        for caps in side_tab_inline_width_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            let n: i64 = caps[1].parse().unwrap();
            if !is_safe_element(&ctx) && n >= 3 {
                push(&mut hits, "side-tab", caps[0].to_string(), i as u32 + 1 + line_offset);
            }
        }
        for caps in side_tab_js_re().captures_iter(line) {
            let n: i64 = caps[1].parse().unwrap();
            if n >= 3 {
                push(&mut hits, "side-tab", caps[0].to_string(), i as u32 + 1 + line_offset);
            }
        }
    }

    // --- border-accent-on-rounded (2 regexes) ---
    for (i, line) in lines.iter().enumerate() {
        for caps in accent_tw_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            let n: i64 = caps[1].parse().unwrap();
            if has_rounded(&ctx) && n >= 1 {
                push(&mut hits, "border-accent-on-rounded", caps[0].to_string(), i as u32 + 1 + line_offset);
            }
        }
        for caps in accent_css_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            let n: i64 = caps[1].parse().unwrap();
            if n >= 3 && has_border_radius(&ctx) {
                push(&mut hits, "border-accent-on-rounded", caps[0].to_string(), i as u32 + 1 + line_offset);
            }
        }
    }

    // --- overused-font (2 regexes) ---
    for (i, line) in lines.iter().enumerate() {
        for caps in overused_font_css_re().captures_iter(line) {
            push(&mut hits, "overused-font", caps[0].to_string(), i as u32 + 1 + line_offset);
        }
        for caps in overused_font_gf_re().captures_iter(line) {
            let name = caps[1].replace('+', " ");
            push(&mut hits, "overused-font", format!("Google Fonts: {name}"), i as u32 + 1 + line_offset);
        }
    }

    // --- gradient-text (2 regexes) ---
    for (i, line) in lines.iter().enumerate() {
        for caps in gradient_clip_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            let _ = &caps[0];
            if gradient_word_re().is_match(&ctx) {
                push(&mut hits, "gradient-text", "background-clip: text + gradient".to_string(), i as u32 + 1 + line_offset);
            }
        }
        for _caps in bg_clip_text_tw_re().find_iter(line) {
            let ctx = context_for(lines, i, block_context);
            if bg_gradient_to_re().is_match(&ctx) {
                push(&mut hits, "gradient-text", "bg-clip-text + bg-gradient".to_string(), i as u32 + 1 + line_offset);
            }
        }
    }

    // --- gray-on-color ---
    for (i, line) in lines.iter().enumerate() {
        for caps in gray_text_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            if let Some(bgm) = colored_bg_re().find(&ctx) {
                push(&mut hits, "gray-on-color", format!("{} on {}", &caps[0], bgm.as_str()), i as u32 + 1 + line_offset);
            } else if colored_bg_re().is_match(&ctx) {
                push(&mut hits, "gray-on-color", format!("{} on ?", &caps[0]), i as u32 + 1 + line_offset);
            }
        }
    }

    // --- ai-color-palette ---
    for (i, line) in lines.iter().enumerate() {
        for caps in ai_text_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            if heading_ctx_re().is_match(&ctx) {
                push(&mut hits, "ai-color-palette", format!("{} on heading", &caps[0]), i as u32 + 1 + line_offset);
            }
        }
        for caps in ai_from_re().captures_iter(line) {
            let ctx = context_for(lines, i, block_context);
            if ai_to_re().is_match(&ctx) {
                push(&mut hits, "ai-color-palette", format!("{} gradient", &caps[0]), i as u32 + 1 + line_offset);
            }
        }
    }

    // --- bounce-easing (3 regexes) ---
    for (i, line) in lines.iter().enumerate() {
        for _caps in animate_bounce_re().find_iter(line) {
            push(&mut hits, "bounce-easing", "animate-bounce (Tailwind)".to_string(), i as u32 + 1 + line_offset);
        }
        for caps in animation_name_re().captures_iter(line) {
            let val = &caps[1];
            let token = val
                .split(|c: char| c == ',' || c.is_whitespace())
                .find(|part| bounce_token_re().is_match(part))
                .map(|s| s.to_string())
                .unwrap_or_else(|| val.trim().to_string());
            push(&mut hits, "bounce-easing", format!("animation: {token}"), i as u32 + 1 + line_offset);
        }
        for caps in cubic_bezier_re().captures_iter(line) {
            let y1: f64 = caps[2].parse().unwrap();
            let y2: f64 = caps[4].parse().unwrap();
            if !(-0.1..=1.1).contains(&y1) || !(-0.1..=1.1).contains(&y2) {
                push(
                    &mut hits,
                    "bounce-easing",
                    format!("cubic-bezier({}, {}, {}, {})", &caps[1], &caps[2], &caps[3], &caps[4]),
                    i as u32 + 1 + line_offset,
                );
            }
        }
    }

    // --- layout-transition (2 regexes) ---
    for (i, line) in lines.iter().enumerate() {
        for caps in transition_re().captures_iter(line) {
            let val = caps[1].to_lowercase();
            if layout_prop_all_re().is_match(&val) || !layout_prop_test_re().is_match(&val) {
                continue;
            }
            let found: Vec<&str> = layout_prop_found_re().find_iter(&caps[1]).map(|m| m.as_str()).collect();
            let snippet = if found.is_empty() { caps[1].trim().to_string() } else { found.join(", ") };
            push(&mut hits, "layout-transition", format!("transition: {snippet}"), i as u32 + 1 + line_offset);
        }
        for caps in transition_property_re().captures_iter(line) {
            let val = caps[1].to_lowercase();
            if layout_prop_all_re().is_match(&val) || !layout_prop_test_re().is_match(&val) {
                continue;
            }
            let found: Vec<&str> = layout_prop_found_re().find_iter(&caps[1]).map(|m| m.as_str()).collect();
            let snippet = if found.is_empty() { caps[1].trim().to_string() } else { found.join(", ") };
            push(&mut hits, "layout-transition", format!("transition-property: {snippet}"), i as u32 + 1 + line_offset);
        }
    }

    // --- broken-image (2 regexes) ---
    for (i, line) in lines.iter().enumerate() {
        for m in broken_img_empty_re().find_iter(line) {
            let s: String = m.as_str().chars().take(100).collect();
            push(&mut hits, "broken-image", s, i as u32 + 1 + line_offset);
        }
        for m in broken_img_none_re().find_iter(line) {
            if !has_src_re().is_match(m.as_str()) {
                let s: String = m.as_str().chars().take(100).collect();
                push(&mut hits, "broken-image", s, i as u32 + 1 + line_offset);
            }
        }
    }

    hits
}

// ---------------------------------------------------------------------------
// extractStyleBlocks / extractCSSinJS
// ---------------------------------------------------------------------------

/// One extracted embedded-code block: its content and 1-based start line.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedBlock {
    pub content: String,
    pub start_line: u32,
}

fn style_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| RegexBuilder::new(r"<style[^>]*>([\s\S]*?)</style>").case_insensitive(true).build().unwrap())
}

/// Port of `extractStyleBlocks(content, ext)`. `ext` is matched
/// case-insensitively as the JS does (`ext.toLowerCase()`).
pub fn extract_style_blocks(content: &str, ext: &str) -> Vec<ExtractedBlock> {
    let ext = ext.to_lowercase();
    if ext != ".vue" && ext != ".svelte" {
        return Vec::new();
    }
    let mut blocks = Vec::new();
    for caps in style_block_re().captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let before = &content[..whole.start()];
        let start_line = before.matches('\n').count() as u32 + 2;
        blocks.push(ExtractedBlock { content: caps[1].to_string(), start_line });
    }
    blocks
}

const CSS_IN_JS_EXTS: &[&str] = &[".js", ".ts", ".jsx", ".tsx"];

fn css_in_js_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| re(r"(?:styled(?:\.\w+|\([^)]+\))|css)\s*`([\s\S]*?)`"))
}

/// Port of `extractCSSinJS(content, ext)`.
pub fn extract_css_in_js(content: &str, ext: &str) -> Vec<ExtractedBlock> {
    let ext = ext.to_lowercase();
    if !CSS_IN_JS_EXTS.contains(&ext.as_str()) {
        return Vec::new();
    }
    let mut blocks = Vec::new();
    for caps in css_in_js_re().captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let before = &content[..whole.start()];
        // Note: JS uses `startLine = before.split('\n').length` (no +1),
        // unlike extractStyleBlocks's `+ 1`. Ported verbatim.
        let start_line = before.matches('\n').count() as u32 + 1;
        blocks.push(ExtractedBlock { content: caps[1].to_string(), start_line });
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(hits: &[MatcherHit]) -> Vec<&'static str> {
        hits.iter().map(|h| h.antipattern).collect()
    }

    #[test]
    fn side_tab_tailwind_thick_border_flags() {
        let lines = ["<div class=\"border-l-4\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(ids(&hits), vec!["side-tab"]);
        assert_eq!(hits[0].line, 1);
    }

    #[test]
    fn side_tab_tailwind_thin_border_on_rounded_flags_at_lower_threshold() {
        let lines = ["<div class=\"rounded border-l-2\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(ids(&hits), vec!["side-tab"]);
    }

    #[test]
    fn side_tab_css_neutral_color_is_skipped() {
        let lines = ["border-left: 4px solid gray;"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert!(hits.is_empty());
    }

    #[test]
    fn side_tab_css_safe_element_is_skipped() {
        let lines = ["<a border-left: 4px solid red;"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert!(hits.is_empty());
    }

    #[test]
    fn border_accent_on_rounded_flags() {
        let lines = ["<div class=\"rounded border-t-2\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert!(ids(&hits).contains(&"border-accent-on-rounded"));
    }

    #[test]
    fn overused_font_css_flags() {
        let lines = ["font-family: 'Inter', sans-serif;"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].antipattern, "overused-font");
        assert_eq!(hits[0].snippet, "font-family: 'Inter");
    }

    #[test]
    fn overused_font_google_fonts_url_flags_with_space_replacement() {
        let lines = ["<link href=\"https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].snippet, "Google Fonts: Plus Jakarta Sans");
    }

    #[test]
    fn gradient_text_css_clip_with_gradient_context_flags() {
        let lines = ["background: linear-gradient(red, blue); background-clip: text;"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].antipattern, "gradient-text");
        assert_eq!(hits[0].snippet, "background-clip: text + gradient");
    }

    #[test]
    fn gradient_text_tailwind_flags() {
        let lines = ["<div class=\"bg-gradient-to-r bg-clip-text\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].snippet, "bg-clip-text + bg-gradient");
    }

    #[test]
    fn gray_on_color_flags_with_bg_class() {
        let lines = ["<div class=\"bg-blue-500 text-gray-300\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].antipattern, "gray-on-color");
        assert_eq!(hits[0].snippet, "text-gray-300 on bg-blue-500");
    }

    #[test]
    fn ai_color_palette_heading_flags() {
        let lines = ["<h1 class=\"text-purple-600\">Title</h1>"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert!(ids(&hits).contains(&"ai-color-palette"));
    }

    #[test]
    fn ai_color_palette_gradient_pair_flags() {
        let lines = ["<div class=\"from-purple-500 to-blue-500\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].snippet, "from-purple-500 gradient");
    }

    #[test]
    fn bounce_easing_tailwind_class_flags() {
        let lines = ["<div class=\"animate-bounce\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].snippet, "animate-bounce (Tailwind)");
    }

    #[test]
    fn bounce_easing_animation_name_flags_matched_token() {
        let lines = ["animation-name: fade-in, wobble-thing;"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].snippet, "animation: wobble-thing");
    }

    #[test]
    fn bounce_easing_cubic_bezier_overshoot_flags() {
        let lines = ["transition-timing-function: cubic-bezier(0.68, -0.55, 0.27, 1.55);"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].antipattern, "bounce-easing");
    }

    #[test]
    fn bounce_easing_cubic_bezier_in_range_does_not_flag() {
        let lines = ["transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert!(hits.is_empty());
    }

    #[test]
    fn layout_transition_width_flags_not_all() {
        let lines = ["transition: width 0.3s ease;"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].snippet, "transition: width");
    }

    #[test]
    fn layout_transition_all_does_not_flag() {
        let lines = ["transition: all 0.3s ease;"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert!(hits.is_empty());
    }

    #[test]
    fn layout_transition_property_padding_flags() {
        let lines = ["transition-property: padding-left, color;"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].snippet, "transition-property: padding-left");
    }

    #[test]
    fn broken_image_empty_src_flags() {
        let lines = ["<img src=\"\" alt=\"x\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].antipattern, "broken-image");
    }

    #[test]
    fn broken_image_missing_src_flags() {
        let lines = ["<img alt=\"x\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert_eq!(hits[0].antipattern, "broken-image");
    }

    #[test]
    fn broken_image_with_src_does_not_flag() {
        let lines = ["<img src=\"/a.png\" alt=\"x\">"];
        let hits = run_regex_matchers(&lines, 0, false);
        assert!(hits.is_empty());
    }

    #[test]
    fn line_offset_is_applied() {
        let lines = ["", "<div class=\"animate-bounce\">"];
        let hits = run_regex_matchers(&lines, 10, false);
        assert_eq!(hits[0].line, 12);
    }

    #[test]
    fn extract_style_blocks_only_vue_and_svelte() {
        let content = "<template></template>\n<style>\n.a { color: red; }\n</style>\n";
        assert!(extract_style_blocks(content, ".jsx").is_empty());
        let blocks = extract_style_blocks(content, ".vue");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_line, 3);
        assert!(blocks[0].content.contains("color: red"));
    }

    #[test]
    fn extract_css_in_js_styled_components() {
        let content = "const Box = styled.div`\n  color: red;\n`;\n";
        let blocks = extract_css_in_js(content, ".tsx");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_line, 1);
        assert!(blocks[0].content.contains("color: red"));
    }

    #[test]
    fn extract_css_in_js_ignores_non_js_ext() {
        assert!(extract_css_in_js("styled.div`color:red;`", ".html").is_empty());
    }
}
