//! Pure (non-DOM) antipattern checks ported 1:1 from
//! `skills/designer/engine/scripts/detector/rules/checks.mjs`.
//!
//! Each function documents its JS source line range at port time. Findings
//! use the same `{ id, snippet }` shape as the JS detector.

use std::sync::OnceLock;

use regex::Regex;

use crate::l6_designer_checks::css_color::{
    css_color_alpha, is_accent_color_impl, parse_any_color, shadow_max_blur_px,
};
use crate::p8_designer::constants::{GENERIC_FONTS, KNOWN_SERIF_FONTS};

/// A single detector finding: `{ id, snippet }` (checks.mjs finding shape).
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub id: &'static str,
    pub snippet: String,
}

// ─── isEmojiOnlyText (checks.mjs ~54-64) ────────────────────────────────────

fn emoji_char_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"[\u{1F1E6}-\u{1F1FF}\u{1F300}-\u{1F9FF}\u{1FA00}-\u{1FAFF}\u{2600}-\u{27BF}\u{2300}-\u{23FF}\u{FE0F}\u{200D}\u{1F3FB}-\u{1F3FF}]",
        )
        .unwrap()
    })
}

/// Port of `isEmojiOnlyText(text)` (checks.mjs ~59-64).
pub fn is_emoji_only_text(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    if !emoji_char_re().is_match(text) {
        return false;
    }
    emoji_char_re().replace_all(text, "").trim().is_empty()
}

// ─── isCardLikeFromProps (checks.mjs ~160-163) ──────────────────────────────

/// Port of `isCardLikeFromProps(hasShadow, hasBorder, hasRadius, hasBg)`.
pub fn is_card_like_from_props(has_shadow: bool, has_border: bool, has_radius: bool, has_bg: bool) -> bool {
    if !has_shadow && !has_border {
        return false;
    }
    has_radius || has_bg
}

// ─── resolveSerif (checks.mjs ~229-237) ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedSerif {
    pub primary: Option<String>,
    pub is_serif: bool,
}

/// Port of `resolveSerif(fontFamily)`.
pub fn resolve_serif(font_family: Option<&str>) -> ResolvedSerif {
    let Some(font_family) = font_family.filter(|s| !s.is_empty()) else {
        return ResolvedSerif { primary: None, is_serif: false };
    };
    let tokens: Vec<String> = font_family
        .split(',')
        .map(|f| f.trim().trim_matches(|c| c == '\'' || c == '"').to_ascii_lowercase())
        .collect();
    let primary = tokens.iter().find(|f| !f.is_empty() && !GENERIC_FONTS.contains(f.as_str())).cloned();
    let Some(primary) = primary else {
        return ResolvedSerif { primary: None, is_serif: false };
    };
    if KNOWN_SERIF_FONTS.contains(primary.as_str()) {
        return ResolvedSerif { primary: Some(primary), is_serif: true };
    }
    if tokens.iter().any(|t| t == "serif") {
        return ResolvedSerif { primary: Some(primary), is_serif: true };
    }
    ResolvedSerif { primary: Some(primary), is_serif: false }
}

// ─── checkItalicSerif (checks.mjs ~239-256) ─────────────────────────────────

pub struct ItalicSerifInput<'a> {
    pub tag: &'a str,
    pub font_style: &'a str,
    pub font_family: Option<&'a str>,
    pub font_size: f64,
    pub heading_text: &'a str,
}

/// Port of `checkItalicSerif(opts)`.
pub fn check_italic_serif(opts: ItalicSerifInput) -> Vec<Finding> {
    if opts.font_style != "italic" {
        return vec![];
    }
    if opts.tag != "h1" && !(opts.tag == "h2" && opts.font_size >= 48.0) {
        return vec![];
    }
    if opts.font_size < 48.0 {
        return vec![];
    }
    let resolved = resolve_serif(opts.font_family);
    if !resolved.is_serif {
        return vec![];
    }
    let text: String = opts.heading_text.trim().chars().take(60).collect();
    vec![Finding {
        id: "italic-serif-display",
        snippet: format!(
            "italic serif {} ({}) at {}px \"{}\"",
            opts.tag,
            resolved.primary.as_deref().unwrap_or("serif"),
            opts.font_size.round(),
            text,
        ),
    }]
}

// ─── isAccentColor (checks.mjs ~261-297) ────────────────────────────────────

/// Port of `isAccentColor(cssColor)`.
pub fn is_accent_color(css_color: Option<&str>) -> bool {
    is_accent_color_impl(css_color)
}

// ─── parseRadiusToPx (checks.mjs ~731-740) ──────────────────────────────────

fn leading_float_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?").unwrap())
}

/// Parses a leading float the way JS `parseFloat` does: reads as much of a
/// numeric prefix as matches and ignores any trailing non-numeric text
/// (`"12px"` -> `12.0`), returning `None` where `parseFloat` would yield `NaN`.
fn js_parse_float(s: &str) -> Option<f64> {
    let m = leading_float_re().find(s)?;
    m.as_str().parse::<f64>().ok()
}

/// Port of `parseRadiusToPx(value, widthPx)`.
pub fn parse_radius_to_px(value: Option<&str>, width_px: Option<f64>) -> Option<f64> {
    let value = value?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first = trimmed.split_whitespace().next()?;
    let num = js_parse_float(first)?;
    let is_percent = first.ends_with('%');
    if is_percent {
        if let Some(w) = width_px.filter(|w| *w > 0.0) {
            return Some((num / 100.0) * w);
        }
        return Some(num);
    }
    Some(num)
}

// ─── isCreamColor / creamFromClassList (checks.mjs ~2162-2195) ─────────────

/// Port of `isCreamColor(rgb)`. Takes 0-255 channels.
pub fn is_cream_color(r: f64, g: f64, b: f64) -> bool {
    if r.min(g).min(b) < 209.0 {
        return false;
    }
    if !(r >= g && g >= b) {
        return false;
    }
    let warmth = r - b;
    (6.0..=48.0).contains(&warmth)
}

fn tailwind_bg_hex() -> &'static [(&'static str, &'static str)] {
    &[
        ("bg-amber-50", "#fffbeb"),
        ("bg-amber-100", "#fef3c7"),
        ("bg-orange-50", "#fff7ed"),
        ("bg-orange-100", "#ffedd5"),
        ("bg-yellow-50", "#fefce8"),
        ("bg-stone-50", "#fafaf9"),
        ("bg-stone-100", "#f5f5f4"),
        ("bg-stone-200", "#e7e5e4"),
    ]
}

fn arbitrary_bg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bbg-\[([^\]]+)\]").unwrap())
}

/// Port of `creamFromClassList(cls)`.
pub fn cream_from_class_list(cls: Option<&str>) -> Option<String> {
    let cls = cls?;
    if let Some(m) = arbitrary_bg_re().captures(cls) {
        let raw = m.get(1)?.as_str();
        let spaced = raw.replace('_', " ");
        if let Some(rgb) = parse_any_color(&spaced) {
            if is_cream_color(rgb.r, rgb.g, rgb.b) {
                return Some(format!("bg-[{}]", raw));
            }
        }
    }
    for (tok, hex) in tailwind_bg_hex() {
        let word_re = Regex::new(&format!(r"(^|\s){}($|\s)", regex::escape(tok))).ok()?;
        if word_re.is_match(cls) {
            if let Some(rgb) = parse_any_color(hex) {
                if is_cream_color(rgb.r, rgb.g, rgb.b) {
                    return Some((*tok).to_string());
                }
            }
        }
    }
    None
}

// ─── checkOversizedH1 (checks.mjs ~2235-2252) ───────────────────────────────

const OVERSIZED_H1_FONT_PX: f64 = 72.0;
const OVERSIZED_H1_MIN_CHARS: usize = 40;
const OVERSIZED_H1_MIN_VIEWPORT_HEIGHT_RATIO: f64 = 0.28;
const OVERSIZED_H1_MIN_VIEWPORT_AREA_RATIO: f64 = 0.25;

pub struct OversizedH1Input<'a> {
    pub tag: &'a str,
    pub font_size: f64,
    pub heading_text: &'a str,
    /// (width, height) of the element's bounding rect, if known.
    pub rect: Option<(f64, f64)>,
    pub viewport_width: f64,
    pub viewport_height: f64,
}

/// Port of `checkOversizedH1(opts)`.
pub fn check_oversized_h1(opts: OversizedH1Input) -> Vec<Finding> {
    if opts.tag != "h1" {
        return vec![];
    }
    let text_len = opts.heading_text.chars().count();
    if opts.font_size >= OVERSIZED_H1_FONT_PX && text_len >= OVERSIZED_H1_MIN_CHARS {
        let mut viewport_detail = String::new();
        if let Some((w, h)) = opts.rect {
            if opts.viewport_width > 0.0 && opts.viewport_height > 0.0 {
                let height_ratio = h / opts.viewport_height;
                let area_ratio = (w * h) / (opts.viewport_width * opts.viewport_height);
                let dominates = height_ratio >= OVERSIZED_H1_MIN_VIEWPORT_HEIGHT_RATIO
                    || area_ratio >= OVERSIZED_H1_MIN_VIEWPORT_AREA_RATIO;
                if !dominates {
                    return vec![];
                }
                viewport_detail = format!(", {}vh", (height_ratio * 100.0).round());
            }
        }
        let snippet_text: String = opts.heading_text.chars().take(60).collect();
        return vec![Finding {
            id: "oversized-h1",
            snippet: format!(
                "{}px h1, {} chars{} \"{}\"",
                opts.font_size.round(),
                text_len,
                viewport_detail,
                snippet_text,
            ),
        }];
    }
    vec![]
}

// ─── checkGptThinBorderWideShadow + style adapters (checks.mjs ~2307-2336) ──

/// Port of `borderWidthsFromStyle(style)`. `style` here is the four
/// pre-parsed border widths (top/right/bottom/left) in caller order — the
/// caller does the `parseFloat(style.borderXWidth) || 0` equivalent, since a
/// live computed-style object has no Rust representation here yet.
pub fn border_widths_from_style(top: Option<f64>, right: Option<f64>, bottom: Option<f64>, left: Option<f64>) -> [f64; 4] {
    [top.unwrap_or(0.0), right.unwrap_or(0.0), bottom.unwrap_or(0.0), left.unwrap_or(0.0)]
}

/// Port of `borderColorsFromStyle(style)`.
pub fn border_colors_from_style<'a>(
    top: Option<&'a str>,
    right: Option<&'a str>,
    bottom: Option<&'a str>,
    left: Option<&'a str>,
) -> [&'a str; 4] {
    [top.unwrap_or(""), right.unwrap_or(""), bottom.unwrap_or(""), left.unwrap_or("")]
}

/// Port of `checkGptThinBorderWideShadow({ borderWidths, borderColors, boxShadow })`.
pub fn check_gpt_thin_border_wide_shadow(border_widths: &[f64], border_colors: &[&str], box_shadow: &str) -> Vec<Finding> {
    let visible_thin_borders: Vec<f64> = border_widths
        .iter()
        .zip(border_colors.iter().chain(std::iter::repeat(&"")))
        .filter_map(|(&width, &color)| {
            let alpha = css_color_alpha(color);
            if width > 0.0 && width <= 1.5 && alpha >= 0.28 {
                Some(width)
            } else {
                None
            }
        })
        .collect();
    let max_border = visible_thin_borders.iter().cloned().fold(0.0f64, f64::max);
    let blur = shadow_max_blur_px(box_shadow, 0.12);
    if visible_thin_borders.len() >= 2 && blur >= 16.0 {
        return vec![Finding {
            id: "gpt-thin-border-wide-shadow",
            snippet: format!("{}px border + {}px shadow blur", max_border, blur.round()),
        }];
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_only_text() {
        assert!(is_emoji_only_text("🔥🔥"));
        assert!(is_emoji_only_text("  🔥  "));
        assert!(!is_emoji_only_text("hi 🔥"));
        assert!(!is_emoji_only_text(""));
        assert!(!is_emoji_only_text("no emoji"));
    }

    #[test]
    fn card_like_from_props() {
        assert!(!is_card_like_from_props(false, false, true, true));
        assert!(!is_card_like_from_props(true, false, false, false));
        assert!(is_card_like_from_props(true, false, true, false));
        assert!(is_card_like_from_props(false, true, false, true));
    }

    #[test]
    fn resolve_serif_known_and_generic() {
        let r = resolve_serif(Some("Georgia, serif"));
        assert_eq!(r.primary.as_deref(), Some("georgia"));
        assert!(r.is_serif);

        let r = resolve_serif(Some("MyCustomFont, serif"));
        assert_eq!(r.primary.as_deref(), Some("mycustomfont"));
        assert!(r.is_serif);

        let r = resolve_serif(Some("Arial, sans-serif"));
        assert!(!r.is_serif);

        let r = resolve_serif(None);
        assert_eq!(r, ResolvedSerif { primary: None, is_serif: false });
    }

    #[test]
    fn italic_serif_gate_on_tag_and_size() {
        let f = check_italic_serif(ItalicSerifInput {
            tag: "h1",
            font_style: "italic",
            font_family: Some("Georgia, serif"),
            font_size: 60.0,
            heading_text: "Hello world",
        });
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "italic-serif-display");

        let none = check_italic_serif(ItalicSerifInput {
            tag: "h3",
            font_style: "italic",
            font_family: Some("Georgia, serif"),
            font_size: 60.0,
            heading_text: "Hello world",
        });
        assert!(none.is_empty());

        let none = check_italic_serif(ItalicSerifInput {
            tag: "h2",
            font_style: "italic",
            font_family: Some("Georgia, serif"),
            font_size: 30.0,
            heading_text: "Hello world",
        });
        assert!(none.is_empty());
    }

    #[test]
    fn parse_radius_to_px_percent_and_plain() {
        assert_eq!(parse_radius_to_px(Some("50%"), Some(200.0)), Some(100.0));
        assert_eq!(parse_radius_to_px(Some("50%"), None), Some(50.0));
        assert_eq!(parse_radius_to_px(Some("12px"), None), Some(12.0));
        assert_eq!(parse_radius_to_px(Some(""), None), None);
        assert_eq!(parse_radius_to_px(None, None), None);
    }

    #[test]
    fn cream_color_detection() {
        assert!(is_cream_color(250.0, 240.0, 220.0));
        assert!(!is_cream_color(255.0, 255.0, 255.0)); // white: warmth 0
        assert!(!is_cream_color(100.0, 90.0, 80.0)); // too dark
        assert!(!is_cream_color(200.0, 210.0, 190.0)); // not warm-ordered (g > r)
    }

    #[test]
    fn cream_from_class_list_tailwind_token() {
        assert_eq!(cream_from_class_list(Some("p-4 bg-amber-50 text-sm")), Some("bg-amber-50".to_string()));
        assert_eq!(cream_from_class_list(Some("p-4")), None);
        assert_eq!(cream_from_class_list(None), None);
    }

    #[test]
    fn oversized_h1_requires_length_and_size() {
        let f = check_oversized_h1(OversizedH1Input {
            tag: "h1",
            font_size: 80.0,
            heading_text: &"x".repeat(45),
            rect: None,
            viewport_width: 0.0,
            viewport_height: 0.0,
        });
        assert_eq!(f.len(), 1);

        let none = check_oversized_h1(OversizedH1Input {
            tag: "h1",
            font_size: 80.0,
            heading_text: "short",
            rect: None,
            viewport_width: 0.0,
            viewport_height: 0.0,
        });
        assert!(none.is_empty());

        let none = check_oversized_h1(OversizedH1Input {
            tag: "h2",
            font_size: 80.0,
            heading_text: &"x".repeat(45),
            rect: None,
            viewport_width: 0.0,
            viewport_height: 0.0,
        });
        assert!(none.is_empty());
    }

    #[test]
    fn oversized_h1_viewport_gate() {
        // Large font/long text but small on-screen rect relative to viewport: no finding.
        let none = check_oversized_h1(OversizedH1Input {
            tag: "h1",
            font_size: 80.0,
            heading_text: &"x".repeat(45),
            rect: Some((100.0, 20.0)),
            viewport_width: 1440.0,
            viewport_height: 900.0,
        });
        assert!(none.is_empty());
    }

    #[test]
    fn gpt_thin_border_wide_shadow_requires_two_borders_and_blur() {
        let widths = border_widths_from_style(Some(1.0), Some(1.0), Some(0.0), Some(0.0));
        let colors = border_colors_from_style(
            Some("rgba(0,0,0,0.5)"),
            Some("rgba(0,0,0,0.5)"),
            None,
            None,
        );
        let f = check_gpt_thin_border_wide_shadow(&widths, &colors, "0 4px 24px rgba(0,0,0,0.2)");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "gpt-thin-border-wide-shadow");

        // Only one visible thin border: no finding.
        let widths = border_widths_from_style(Some(1.0), Some(0.0), Some(0.0), Some(0.0));
        let f = check_gpt_thin_border_wide_shadow(&widths, &colors, "0 4px 24px rgba(0,0,0,0.2)");
        assert!(f.is_empty());
    }
}
