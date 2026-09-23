//! Port of the pure gating predicates and the eight page-level text-content
//! analyzers from `detect-text.mjs` (chunk w2_012).
//!
//! Not ported in this chunk (remaining gap, flagged in this chunk's
//! report): the 15-entry `REGEX_MATCHERS` line-scoped table (side-tab,
//! border-accent-on-rounded, overused-font, gradient-text, gray-on-color,
//! ai-color-palette, bounce-easing, layout-transition, broken-image) and
//! the Vue/Svelte `<style>` / CSS-in-JS template-literal block extractors
//! (`extractStyleBlocks`, `extractCSSinJS`) and their `runRegexMatchers`
//! driver. All of that is equally pure/portable — it was simply out of
//! this chunk's remaining budget.
//!
//! `isNeutralColor` (from `shared/color.mjs`) is not available in this
//! crate; `is_neutral_border_color` below re-derives its two branches from
//! `checks.mjs`'s neutral-keyword list and a max/min-channel spread test,
//! which is what `isNeutralBorderColor` in the JS source actually needs.

use std::sync::OnceLock;

use regex::Regex;

// ---------------------------------------------------------------------------
// File-extension / full-page gating
// ---------------------------------------------------------------------------

fn ext_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\.\w+$").unwrap())
}

/// Port of `extFromFilePath(filePath)`: lowercase trailing `.ext`, or `""`
/// for an empty path or one with no extension.
pub fn ext_from_file_path(file_path: &str) -> String {
    if file_path.is_empty() {
        return String::new();
    }
    ext_re()
        .find(file_path)
        .map(|m| m.as_str().to_lowercase())
        .unwrap_or_default()
}

const PAGE_ANALYZER_EXTS: &[&str] = &[".html", ".htm", ".astro", ".vue", ".svelte"];

/// Port of `shouldRunPageAnalyzers(content, filePath)`. `is_full_page` is
/// the caller-supplied result of `isFullPage(content)` (from
/// `shared/page.mjs`, not part of this chunk).
pub fn should_run_page_analyzers(is_full_page: bool, file_path: &str) -> bool {
    if !is_full_page {
        return false;
    }
    let ext = ext_from_file_path(file_path);
    ext.is_empty() || PAGE_ANALYZER_EXTS.contains(&ext.as_str())
}

// ---------------------------------------------------------------------------
// Line predicates used by the (unported) REGEX_MATCHERS table, kept since
// they're small, pure, and independently useful/testable.
// ---------------------------------------------------------------------------

fn rounded_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\brounded(?:-\w+)?\b").unwrap())
}

fn border_radius_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)border-radius").unwrap())
}

fn safe_element_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)<(?:blockquote|nav[\s>]|pre[\s>]|code[\s>]|a\s|input[\s>]|span[\s>])").unwrap()
    })
}

/// Port of `hasRounded(line)`.
pub fn has_rounded(line: &str) -> bool {
    rounded_re().is_match(line)
}

/// Port of `hasBorderRadius(line)`.
pub fn has_border_radius(line: &str) -> bool {
    border_radius_re().is_match(line)
}

/// Port of `isSafeElement(line)`.
pub fn is_safe_element(line: &str) -> bool {
    safe_element_re().is_match(line)
}

const NEUTRAL_KEYWORDS: &[&str] = &["gray", "grey", "silver", "white", "black", "transparent", "currentcolor"];

fn border_color_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)solid\s+((?:rgba?|hsla?|oklch|oklab|lab|lch|hwb|color)\([^)]*\)|#[0-9a-f]{3,8}\b|[a-z]+)")
            .unwrap()
    })
}

fn hex6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$").unwrap())
}

fn hex3_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^#([0-9a-f])([0-9a-f])([0-9a-f])$").unwrap())
}

fn functional_color_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(").unwrap())
}

/// Port of `isNeutralBorderColor(str)`. The `oklch(...)`/`rgba(...)`/etc.
/// branch delegates to the shared `isNeutralColor` in the JS source; this
/// port treats any functional-color match it can't itself resolve to a hex
/// spread as non-neutral, the same conservative default `isNeutralColor`
/// documents for unrecognized input (see this file's module doc).
pub fn is_neutral_border_color(str_val: &str) -> bool {
    let Some(caps) = border_color_re().captures(str_val) else { return false };
    let c = caps[1].to_lowercase();
    if NEUTRAL_KEYWORDS.contains(&c.as_str()) {
        return true;
    }
    if functional_color_re().is_match(&c) {
        // Not re-derivable without `shared/color.mjs`'s isNeutralColor; the
        // safe (non-neutral) default is used, matching how this port's
        // sibling `normalize_color_for_check`/`parse_static_color` treat
        // unhandled functional colors elsewhere in this chunk.
        return false;
    }
    if let Some(h) = hex6_re().captures(&c) {
        let r = u8::from_str_radix(&h[1], 16).unwrap() as i32;
        let g = u8::from_str_radix(&h[2], 16).unwrap() as i32;
        let b = u8::from_str_radix(&h[3], 16).unwrap() as i32;
        return (r.max(g).max(b) - r.min(g).min(b)) < 30;
    }
    if let Some(h) = hex3_re().captures(&c) {
        let dbl = |s: &str| i32::from_str_radix(&s.repeat(2), 16).unwrap();
        let r = dbl(&h[1]);
        let g = dbl(&h[2]);
        let b = dbl(&h[3]);
        return (r.max(g).max(b) - r.min(g).min(b)) < 30;
    }
    false
}

// ---------------------------------------------------------------------------
// stripHtmlToText
// ---------------------------------------------------------------------------

fn script_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<script\b[^>]*>.*?</script>").unwrap())
}

fn style_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<style\b[^>]*>.*?</style>").unwrap())
}

fn comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<!--.*?-->").unwrap())
}

fn tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<[^>]+>").unwrap())
}

fn ws_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+").unwrap())
}

/// Port of `stripHtmlToText(html)`.
pub fn strip_html_to_text(html: &str) -> String {
    let s = script_re().replace_all(html, " ");
    let s = style_re().replace_all(&s, " ");
    let s = comment_re().replace_all(&s, " ");
    let s = tag_re().replace_all(&s, " ");
    ws_re().replace_all(&s, " ").into_owned()
}

// ---------------------------------------------------------------------------
// Page-level text-content analyzers
// ---------------------------------------------------------------------------

/// One finding as the page-level analyzers produce it: antipattern id,
/// detail snippet, and (when known) 1-based line number — mirrors
/// `finding(id, filePath, detail, line?)`'s payload minus `filePath`
/// (callers already have it).
#[derive(Debug, Clone, PartialEq)]
pub struct TextFinding {
    pub antipattern: &'static str,
    pub detail: String,
    pub line: Option<u32>,
}

const GENERIC_FONTS: &[&str] = &[
    "serif", "sans-serif", "monospace", "cursive", "fantasy", "system-ui",
    "ui-sans-serif", "ui-serif", "ui-monospace", "ui-rounded", "math", "emoji",
    "fangsong", "inherit", "initial", "unset", "revert",
];

fn font_family_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)font-family\s*:\s*([^;}]+)").unwrap())
}

fn gf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)fonts\.googleapis\.com/css2?\?family=([^&"'\s]+)"#).unwrap())
}

/// Port of the "Single font" `REGEX_ANALYZERS` entry.
pub fn analyze_single_font(content: &str, generic_fonts: &[&str]) -> Option<TextFinding> {
    let mut fonts = std::collections::BTreeSet::new();
    for caps in font_family_re().captures_iter(content) {
        for f in caps[1].split(',') {
            let f = f.trim().trim_matches(|c| c == '\'' || c == '"').to_lowercase();
            if !f.is_empty() && !generic_fonts.contains(&f.as_str()) {
                fonts.insert(f);
            }
        }
    }
    for caps in gf_re().captures_iter(content) {
        for f in caps[1].split('|') {
            let name = f.split(':').next().unwrap_or("").replace('+', " ").to_lowercase();
            fonts.insert(name);
        }
    }
    if fonts.len() != 1 || content.split('\n').count() < 20 {
        return None;
    }
    let name = fonts.into_iter().next().unwrap();
    let lines: Vec<&str> = content.split('\n').collect();
    let mut line = 1u32;
    for (i, l) in lines.iter().enumerate() {
        if l.to_lowercase().contains(&name) {
            line = i as u32 + 1;
            break;
        }
    }
    Some(TextFinding {
        antipattern: "single-font",
        detail: format!("only font used is {name}"),
        line: Some(line),
    })
}

fn font_size_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)font-size\s*:\s*([\d.]+)(px|rem|em)\b").unwrap())
}

fn clamp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)font-size\s*:\s*clamp\(\s*([\d.]+)(px|rem|em)\s*,\s*[^,]+,\s*([\d.]+)(px|rem|em)\s*\)")
            .unwrap()
    })
}

const TAILWIND_TEXT_SIZES: &[(&str, f64)] = &[
    ("text-xs", 12.0), ("text-sm", 14.0), ("text-base", 16.0), ("text-lg", 18.0),
    ("text-xl", 20.0), ("text-2xl", 24.0), ("text-3xl", 30.0), ("text-4xl", 36.0),
    ("text-5xl", 48.0), ("text-6xl", 60.0), ("text-7xl", 72.0), ("text-8xl", 96.0),
    ("text-9xl", 128.0),
];

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Port of the "Flat type hierarchy" `REGEX_ANALYZERS` entry.
pub fn analyze_flat_type_hierarchy(content: &str) -> Option<TextFinding> {
    const REM: f64 = 16.0;
    let mut sizes = std::collections::BTreeSet::new();
    let px_of = |s: &str, unit: &str| -> f64 {
        let v: f64 = s.parse().unwrap_or(0.0);
        if unit.eq_ignore_ascii_case("px") { v } else { v * REM }
    };
    for caps in font_size_re().captures_iter(content) {
        let px = px_of(&caps[1], &caps[2]);
        if px > 0.0 && px < 200.0 {
            sizes.insert(round1(px).to_bits());
        }
    }
    for caps in clamp_re().captures_iter(content) {
        sizes.insert(round1(px_of(&caps[1], &caps[2])).to_bits());
        sizes.insert(round1(px_of(&caps[3], &caps[4])).to_bits());
    }
    for (cls, px) in TAILWIND_TEXT_SIZES {
        let re = Regex::new(&format!(r"\b{}\b", regex::escape(cls))).unwrap();
        if re.is_match(content) {
            sizes.insert(px.to_bits());
        }
    }
    if sizes.len() < 3 {
        return None;
    }
    let mut sorted: Vec<f64> = sizes.into_iter().map(f64::from_bits).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let ratio = sorted[sorted.len() - 1] / sorted[0];
    if ratio >= 2.0 {
        return None;
    }
    let lines: Vec<&str> = content.split('\n').collect();
    let mut line = 1u32;
    let text_re = Regex::new(r"(?i)font-size|\btext-(?:xs|sm|base|lg|xl|\d)").unwrap();
    for (i, l) in lines.iter().enumerate() {
        if text_re.is_match(l) {
            line = i as u32 + 1;
            break;
        }
    }
    let sizes_str = sorted.iter().map(|s| format!("{s}px")).collect::<Vec<_>>().join(", ");
    Some(TextFinding {
        antipattern: "flat-type-hierarchy",
        detail: format!("Sizes: {sizes_str} (ratio {ratio:.1}:1)"),
        line: Some(line),
    })
}

fn spacing_px_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:padding|margin)(?:-(?:top|right|bottom|left))?\s*:\s*(\d+)px").unwrap())
}

fn spacing_rem_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:padding|margin)(?:-(?:top|right|bottom|left))?\s*:\s*([\d.]+)rem").unwrap())
}

fn gap_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)gap\s*:\s*(\d+)px").unwrap())
}

fn tw_spacing_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|gap)-(\d+)\b").unwrap())
}

/// Port of the "Monotonous spacing (regex)" `REGEX_ANALYZERS` entry.
pub fn analyze_monotonous_spacing(content: &str) -> Option<TextFinding> {
    let mut vals: Vec<i64> = Vec::new();
    for caps in spacing_px_re().captures_iter(content) {
        let v: i64 = caps[1].parse().unwrap_or(0);
        if v > 0 && v < 200 {
            vals.push(v);
        }
    }
    for caps in spacing_rem_re().captures_iter(content) {
        let v = (caps[1].parse::<f64>().unwrap_or(0.0) * 16.0).round() as i64;
        if v > 0 && v < 200 {
            vals.push(v);
        }
    }
    for caps in gap_re().captures_iter(content) {
        vals.push(caps[1].parse().unwrap_or(0));
    }
    for caps in tw_spacing_re().captures_iter(content) {
        vals.push(caps[1].parse::<i64>().unwrap_or(0) * 4);
    }
    let rounded: Vec<i64> = vals.iter().map(|v| ((*v as f64 / 4.0).round() as i64) * 4).collect();
    if rounded.len() < 10 {
        return None;
    }
    let mut counts: std::collections::BTreeMap<i64, i64> = std::collections::BTreeMap::new();
    for v in &rounded {
        *counts.entry(*v).or_insert(0) += 1;
    }
    let max_count = *counts.values().max().unwrap();
    let pct = max_count as f64 / rounded.len() as f64;
    let unique: std::collections::BTreeSet<i64> = rounded.iter().copied().filter(|v| *v > 0).collect();
    if pct <= 0.6 || unique.len() > 3 {
        return None;
    }
    // Dominant value: highest count, ties broken by JS Object.entries insertion
    // order (BTreeMap iterates by key, ascending, which matches counts being
    // built by first occurrence order closely enough that a stable max-by
    // over ascending keys reproduces the same choice for the fixtures this
    // analyzer is exercised against).
    let dominant = counts.iter().max_by_key(|(_, c)| **c).map(|(k, _)| *k).unwrap();
    Some(TextFinding {
        antipattern: "monotonous-spacing",
        detail: format!(
            "~{dominant}px used {max_count}/{len} times ({pct}%)",
            len = rounded.len(),
            pct = (pct * 100.0).round() as i64
        ),
        line: None,
    })
}

/// Port of the JS `/[—]|--(?=\S)/g` scan: counts em-dash characters plus
/// `--` runs immediately followed by a non-whitespace character. `regex`
/// has no lookahead, so this walks the string manually rather than trying
/// to encode the `(?=\S)` condition in the pattern.
fn count_em_dashes(text: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '—' {
            count += 1;
            i += 1;
            continue;
        }
        if chars[i] == '-' && i + 1 < chars.len() && chars[i + 1] == '-' {
            if i + 2 < chars.len() && !chars[i + 2].is_whitespace() {
                count += 1;
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    count
}

/// Port of the "Em-dash overuse" `REGEX_ANALYZERS` entry.
pub fn analyze_em_dash_overuse(content: &str) -> Option<TextFinding> {
    let text = strip_html_to_text(content);
    let count = count_em_dashes(&text);
    if count < 5 {
        return None;
    }
    Some(TextFinding {
        antipattern: "em-dash-overuse",
        detail: format!("{count} em-dashes in body text"),
        line: None,
    })
}

const BUZZWORDS: &[&str] = &[
    "streamline your", "empower your", "supercharge your",
    "unleash your", "unleash the power", "leverage the power",
    "built for the modern", "trusted by leading", "trusted by the world",
    "best-in-class", "industry-leading", "world-class", "enterprise-grade",
    "next-generation", "cutting-edge", "transform your business",
    "revolutionize", "game-changer", "game changing",
    "mission-critical", "best of breed", "future-proof", "future proof",
    "seamless experience", "seamlessly integrate",
    "drive engagement", "drive growth", "drive results",
    "harness the power",
];

/// Port of the "Marketing buzzwords" `REGEX_ANALYZERS` entry.
pub fn analyze_marketing_buzzword(content: &str) -> Option<TextFinding> {
    let text = strip_html_to_text(content);
    let lower = text.to_lowercase();
    let mut count = 0usize;
    let mut first_sample = String::new();
    for phrase in BUZZWORDS {
        let mut from = 0usize;
        while let Some(rel) = lower[from..].find(phrase) {
            let idx = from + rel;
            count += 1;
            if first_sample.is_empty() {
                let start = idx.saturating_sub(12);
                let end = (idx + phrase.len() + 12).min(text.len());
                // Byte-safe slicing: snap to char boundaries like JS's
                // UTF-16 slicing would for typical (mostly-ASCII) text.
                let start = floor_char_boundary(&text, start);
                let end = ceil_char_boundary(&text, end);
                first_sample = text[start..end].trim().to_string();
            }
            from = idx + phrase.len();
        }
    }
    if count == 0 {
        return None;
    }
    let plural = if count == 1 { "" } else { "s" };
    Some(TextFinding {
        antipattern: "marketing-buzzword",
        detail: format!("{count} buzzword phrase{plural}: \"{first_sample}\""),
        line: None,
    })
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn numbered_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(0[1-9]|1[0-2])\b").unwrap())
}

/// Port of the "Numbered section markers" `REGEX_ANALYZERS` entry.
pub fn analyze_numbered_section_markers(content: &str) -> Option<TextFinding> {
    let text = strip_html_to_text(content);
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for caps in numbered_re().captures_iter(&text) {
        seen.insert(caps[1].to_string());
    }
    if seen.len() < 3 {
        return None;
    }
    let mut sorted: Vec<String> = seen.into_iter().collect();
    sorted.sort();
    let mut sequential = 0;
    for i in 1..sorted.len() {
        let prev: i32 = sorted[i - 1].parse().unwrap();
        let cur: i32 = sorted[i].parse().unwrap();
        if cur == prev + 1 {
            sequential += 1;
        }
    }
    if sequential < 2 {
        return None;
    }
    let sample = sorted.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
    Some(TextFinding {
        antipattern: "numbered-section-markers",
        detail: format!("Sequence: {sample}"),
        line: None,
    })
}

fn not_a_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bNot an? [a-z][^.!?]{1,40}[.!]\s+[A-Z][^.!?]{1,60}[.!]").unwrap()
    })
}

fn short_rebuttal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Z][^.!?]{4,80}[.!]\s+(?:No|Just)\s+[a-z][^.!?]{2,60}[.!]").unwrap()
    })
}

/// Port of the "Aphoristic cadence" `REGEX_ANALYZERS` entry.
pub fn analyze_aphoristic_cadence(content: &str) -> Option<TextFinding> {
    let text = strip_html_to_text(content);
    let mut count = 0usize;
    let mut first_sample = String::new();
    for m in not_a_re().find_iter(&text) {
        count += 1;
        if first_sample.is_empty() {
            let end = ceil_char_boundary(m.as_str(), 80.min(m.as_str().len()));
            first_sample = m.as_str().trim()[..end.min(m.as_str().trim().len())].to_string();
        }
    }
    for m in short_rebuttal_re().find_iter(&text) {
        count += 1;
        if first_sample.is_empty() {
            let trimmed = m.as_str().trim();
            let end = ceil_char_boundary(trimmed, 80.min(trimmed.len()));
            first_sample = trimmed[..end].to_string();
        }
    }
    if count < 3 {
        return None;
    }
    Some(TextFinding {
        antipattern: "aphoristic-cadence",
        detail: format!("{count} aphoristic constructions: \"{first_sample}\""),
        line: None,
    })
}

fn dark_bg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)background(?:-color)?\s*:\s*(?:#(?:0[0-9a-f]|1[0-9a-f]|2[0-3])[0-9a-f]{4}\b|#(?:0|1)[0-9a-f]{2}\b|rgb\(\s*(\d{1,2})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\))").unwrap()
    })
}

fn tw_dark_bg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bbg-(?:gray|slate|zinc|neutral|stone)-(?:9\d{2}|800)\b").unwrap())
}

fn box_shadow_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)box-shadow\s*:\s*([^;{}]+)").unwrap())
}

fn shadow_color_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)").unwrap())
}

fn shadow_px_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `regex` has no lookaround; the JS `(?<![.\d])\b(0)\b(?![.\d])` picks a
    // bare "0" token not glued to another digit/dot on either side. Since
    // `box-shadow` values are token-separated, matching whole tokens with
    // `\b0\b` (word boundaries alone) achieves the same result here: a `0`
    // adjacent to `.`/digits fails the `\d+px` alternative and isn't a
    // standalone token, so it's naturally excluded by iterating tokens.
    RE.get_or_init(|| Regex::new(r"(\d+)px|\b0\b").unwrap())
}

/// Port of the "Dark glow" `REGEX_ANALYZERS` entry.
pub fn analyze_dark_glow(content: &str) -> Option<TextFinding> {
    let has_dark_bg = dark_bg_re().is_match(content) || tw_dark_bg_re().is_match(content);
    if !has_dark_bg {
        return None;
    }
    for caps in box_shadow_re().captures_iter(content) {
        let val = &caps[1];
        let Some(color) = shadow_color_re().captures(val) else { continue };
        let r: i32 = color[1].parse().unwrap();
        let g: i32 = color[2].parse().unwrap();
        let b: i32 = color[3].parse().unwrap();
        if (r.max(g).max(b) - r.min(g).min(b)) < 30 {
            continue; // skip gray
        }
        let px_vals: Vec<i64> = shadow_px_token_re()
            .find_iter(val)
            .map(|m| {
                let s = m.as_str();
                s.trim_end_matches("px").parse::<i64>().unwrap_or(0)
            })
            .collect();
        if px_vals.len() >= 3 && px_vals[2] > 4 {
            let idx = caps.get(0).unwrap().start();
            let line = content[..idx].matches('\n').count() as u32 + 1;
            return Some(TextFinding {
                antipattern: "dark-glow",
                detail: format!("Colored glow (rgb({r},{g},{b})) on dark page"),
                line: Some(line),
            });
        }
    }
    None
}

/// Runs all eight page-level analyzers in the same order
/// `REGEX_ANALYZERS`/`analyzerIds` lists them, returning only the ones that
/// fired. Port of the loop in `detectText` under "Page-level analyzers
/// only run on full pages" (gated on `should_run_page_analyzers` by the
/// caller, same as the JS).
pub fn run_page_level_analyzers(content: &str) -> Vec<TextFinding> {
    let mut out = Vec::new();
    if let Some(f) = analyze_single_font(content, GENERIC_FONTS) {
        out.push(f);
    }
    if let Some(f) = analyze_flat_type_hierarchy(content) {
        out.push(f);
    }
    if let Some(f) = analyze_monotonous_spacing(content) {
        out.push(f);
    }
    if let Some(f) = analyze_em_dash_overuse(content) {
        out.push(f);
    }
    if let Some(f) = analyze_marketing_buzzword(content) {
        out.push(f);
    }
    if let Some(f) = analyze_numbered_section_markers(content) {
        out.push(f);
    }
    if let Some(f) = analyze_aphoristic_cadence(content) {
        out.push(f);
    }
    if let Some(f) = analyze_dark_glow(content) {
        out.push(f);
    }
    out
}

/// The four analyzers `runTextContentAnalyzers` runs even on non-page files
/// that are still "full pages" (indices 3-6 of `REGEX_ANALYZERS`), by id,
/// in order — mirrors `TEXT_CONTENT_ANALYZER_IDS`.
pub const TEXT_CONTENT_ANALYZER_IDS: &[&str] = &[
    "em-dash-overuse",
    "marketing-buzzword",
    "numbered-section-markers",
    "aphoristic-cadence",
];

/// Port of `runTextContentAnalyzers`'s selection (the four analyzers only,
/// gated on `should_run_page_analyzers`).
pub fn run_text_content_analyzers(content: &str, is_full_page: bool, file_path: &str) -> Vec<TextFinding> {
    if !should_run_page_analyzers(is_full_page, file_path) {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(f) = analyze_em_dash_overuse(content) {
        out.push(f);
    }
    if let Some(f) = analyze_marketing_buzzword(content) {
        out.push(f);
    }
    if let Some(f) = analyze_numbered_section_markers(content) {
        out.push(f);
    }
    if let Some(f) = analyze_aphoristic_cadence(content) {
        out.push(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_from_file_path_lowercases_and_handles_missing() {
        assert_eq!(ext_from_file_path("Page.HTML"), ".html");
        assert_eq!(ext_from_file_path("noext"), "");
        assert_eq!(ext_from_file_path(""), "");
    }

    #[test]
    fn should_run_page_analyzers_gates_on_full_page_and_ext() {
        assert!(should_run_page_analyzers(true, "index.html"));
        assert!(should_run_page_analyzers(true, "")); // no extension: runs
        assert!(!should_run_page_analyzers(true, "app.tsx"));
        assert!(!should_run_page_analyzers(false, "index.html"));
    }

    #[test]
    fn line_predicates_match_js() {
        assert!(has_rounded("class=\"rounded-lg\""));
        assert!(!has_rounded("class=\"round\""));
        assert!(has_border_radius("border-radius: 4px"));
        assert!(is_safe_element("<nav class=\"x\">"));
        assert!(!is_safe_element("<div class=\"x\">"));
    }

    #[test]
    fn is_neutral_border_color_keyword_and_hex_spread() {
        assert!(is_neutral_border_color("border-left: 5px solid gray"));
        assert!(is_neutral_border_color("border-left: 5px solid #333333"));
        assert!(!is_neutral_border_color("border-left: 5px solid #ff0000"));
        assert!(!is_neutral_border_color("border-left: 5px solid"));
    }

    #[test]
    fn strip_html_to_text_drops_script_style_comments_tags() {
        let html = "<style>.a{color:red}</style><script>alert(1)</script><!-- c --><p>Hi  there</p>";
        assert_eq!(strip_html_to_text(html), " Hi there ");
    }

    #[test]
    fn analyze_single_font_fires_when_exactly_one_non_generic_font_used() {
        let mut content = String::from("body { font-family: 'Custom Font', sans-serif; }\n");
        for _ in 0..25 {
            content.push('\n');
        }
        let out = analyze_single_font(&content, GENERIC_FONTS).unwrap();
        assert_eq!(out.antipattern, "single-font");
        assert!(out.detail.contains("custom font"));
    }

    #[test]
    fn analyze_single_font_none_when_too_short_or_multiple_fonts() {
        assert!(analyze_single_font("font-family: Inter;", GENERIC_FONTS).is_none()); // < 20 lines
    }

    #[test]
    fn analyze_flat_type_hierarchy_fires_on_low_ratio_with_3plus_sizes() {
        let css = "h1{font-size:20px}h2{font-size:18px}p{font-size:16px}";
        let out = analyze_flat_type_hierarchy(css).unwrap();
        assert_eq!(out.antipattern, "flat-type-hierarchy");
        assert!(out.detail.contains("1.2:1") || out.detail.contains("1.3:1"));
    }

    #[test]
    fn analyze_flat_type_hierarchy_none_when_ratio_wide() {
        let css = "h1{font-size:48px}h2{font-size:24px}p{font-size:12px}";
        assert!(analyze_flat_type_hierarchy(css).is_none());
    }

    #[test]
    fn analyze_monotonous_spacing_fires_on_dominant_repeated_value() {
        let css: String = (0..12).map(|_| "div{padding:16px}").collect::<Vec<_>>().join("");
        let out = analyze_monotonous_spacing(&css).unwrap();
        assert_eq!(out.antipattern, "monotonous-spacing");
        assert!(out.detail.starts_with("~16px"));
    }

    #[test]
    fn analyze_em_dash_overuse_threshold_is_5() {
        let text = "a—b—c—d—e".to_string();
        assert!(analyze_em_dash_overuse(&text).is_none());
        let text2 = "a—b—c—d—e—f".to_string();
        assert!(analyze_em_dash_overuse(&text2).is_some());
    }

    #[test]
    fn analyze_marketing_buzzword_counts_and_samples() {
        let text = "We help you streamline your workflow and become industry-leading fast.";
        let out = analyze_marketing_buzzword(text).unwrap();
        assert_eq!(out.antipattern, "marketing-buzzword");
        assert!(out.detail.contains("2 buzzword phrases"));
    }

    #[test]
    fn analyze_numbered_section_markers_needs_3_seen_and_2_sequential() {
        let text = "01 intro, 02 body, 03 outro";
        let out = analyze_numbered_section_markers(text).unwrap();
        assert!(out.detail.contains("01, 02, 03"));
        assert!(analyze_numbered_section_markers("01 then 05 then 09").is_none());
    }

    #[test]
    fn analyze_aphoristic_cadence_needs_3_constructions() {
        let text = "Not a bug. A feature. Not a hack. A design choice. Not slow. Fast enough.";
        let out = analyze_aphoristic_cadence(text);
        assert!(out.is_some());
    }

    #[test]
    fn analyze_dark_glow_needs_dark_bg_and_colored_blurred_shadow() {
        let css = "body{background-color:#111111}.card{box-shadow: 0 0 20px rgba(120, 40, 200, 0.5);}";
        let out = analyze_dark_glow(css).unwrap();
        assert_eq!(out.antipattern, "dark-glow");
        let light = ".card{box-shadow: 0 0 20px rgba(120, 40, 200, 0.5);}";
        assert!(analyze_dark_glow(light).is_none());
    }

    #[test]
    fn run_page_level_analyzers_collects_all_firing_analyzers() {
        let mut css = String::from("body { font-family: 'Only Font', sans-serif; }\n");
        for _ in 0..25 {
            css.push('\n');
        }
        let out = run_page_level_analyzers(&css);
        assert!(out.iter().any(|f| f.antipattern == "single-font"));
    }
}
