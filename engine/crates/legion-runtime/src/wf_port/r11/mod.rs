//! Packet r11: continues the port of
//! `skills/designer/engine/scripts/detector/rules/checks.mjs` (Section 3:
//! Pure Detection) that `l6_designer_checks` (an earlier packet) left
//! deferred, and that `wf_port::w2_014::color` (the `shared/color.mjs` port)
//! explicitly unblocked: `checkBorders`, `checkColors`, `checkIconTile`,
//! `checkHeroEyebrow`, `checkRepeatedSectionKickers`, `checkMotion`,
//! `checkGlow` (checks.mjs lines ~26-51, ~65-158, ~179-219, ~308-363,
//! ~372-440).
//!
//! Packet r10r11 closes the rest of `checks.mjs` in two sibling submodules,
//! now that `wf_port::r09` supplies a real static DOM + CSS cascade
//! (`scraper`-backed) to drive it over: [`html_patterns`] ports
//! `checkHtmlPatterns` (pure regex/string, no DOM needed), and
//! [`static_adapters`] ports the `checkElement*`/`checkPage*`/
//! `check*FromDoc` glue (`resolveBackground`/`resolveGradientStops`,
//! `checkElementBorders`/`Colors`/`IconTile`/`ItalicSerif`/`HeroEyebrow`/
//! `Motion`/`Glow`/`OversizedH1`/`ClippedOverflow`/`GptBorderShadow`,
//! `checkQuality` with `rect: null` — the exact static-engine call shape —
//! `checkPageLayout`, `checkCreamPalette`, `checkPageQualityFromDoc`,
//! `checkRepeatedSectionKickersFromDoc`) that `detect-html.mjs`'s
//! `STATIC_ELEMENT_RULES` and page-check block actually call.
//!
//! Still not ported, named precisely in [`static_adapters`]'s own doc
//! comment: the live-browser-globals `checkTypography()`/`checkLayout()`
//! (not the same functions as the ported `checkPageLayout(doc, win)` —
//! these read the ambient `document`/`getComputedStyle`, never called by
//! `detectHtml`) and every `checkElement*DOM` sibling (real
//! `getBoundingClientRect`), which belong to the separate live/visual
//! detector engine, not the static-HTML one this packet's two target files
//! are part of.
//!
//! Findings reuse `l6_designer_checks::pure_checks::Finding` (same
//! `{ id, snippet }` shape as the JS detector) so callers get one finding
//! type across both packets.

use std::sync::OnceLock;

use regex::Regex;

use crate::l6_designer_checks::pure_checks::Finding;
use crate::p8_designer::constants::{BORDER_SAFE_TAGS, SAFE_TAGS, WCAG_LARGE_BOLD_TEXT_PX, WCAG_LARGE_TEXT_PX};
use crate::wf_port::w2_014::color::{
    color_to_hex, contrast_ratio, get_hue, has_chroma, is_neutral_color, parse_rgb,
    relative_luminance, Rgba,
};

// ─── checkBorders (checks.mjs ~26-51) ───────────────────────────────────────

/// Border widths/colors for the four sides, in `[top, right, bottom, left]`
/// order (mirrors the JS `widths`/`colors` maps keyed by `Top|Right|Bottom|Left`).
pub struct BorderSides<'a> {
    pub widths: [f64; 4],
    pub colors: [Option<&'a str>; 4],
}

const SIDE_NAMES: [&str; 4] = ["Top", "Right", "Bottom", "Left"];

/// Port of `checkBorders(tag, widths, colors, radius)`.
pub fn check_borders(tag: &str, sides: &BorderSides, radius: f64) -> Vec<Finding> {
    if BORDER_SAFE_TAGS.contains(tag) {
        return vec![];
    }
    let mut findings = vec![];

    for i in 0..4 {
        let w = sides.widths[i];
        if w < 1.0 || is_neutral_color(sides.colors[i]) {
            continue;
        }

        let max_other = (0..4)
            .filter(|&j| j != i)
            .map(|j| sides.widths[j])
            .fold(f64::MIN, f64::max);
        if !(w >= 2.0 && (max_other <= 1.0 || w >= max_other * 2.0)) {
            continue;
        }

        let side = SIDE_NAMES[i];
        let sn = side.to_ascii_lowercase();
        let is_side = side == "Left" || side == "Right";

        if is_side {
            if radius > 0.0 {
                findings.push(Finding {
                    id: "side-tab",
                    snippet: format!("border-{}: {}px + border-radius: {}px", sn, w, radius),
                });
            } else if w >= 3.0 {
                findings.push(Finding {
                    id: "side-tab",
                    snippet: format!("border-{}: {}px", sn, w),
                });
            }
        } else if radius > 0.0 && w >= 2.0 {
            findings.push(Finding {
                id: "border-accent-on-rounded",
                snippet: format!("border-{}: {}px + border-radius: {}px", sn, w, radius),
            });
        }
    }

    findings
}

// ─── checkColors (checks.mjs ~65-158) ───────────────────────────────────────

pub struct ColorsInput<'a> {
    pub tag: &'a str,
    pub text_color: Option<Rgba>,
    pub bg_color: Option<Rgba>,
    pub effective_bg: Option<Rgba>,
    pub effective_bg_stops: &'a [Rgba],
    pub font_size: f64,
    pub font_weight: f64,
    pub has_direct_text: bool,
    pub is_emoji_only: bool,
    pub bg_clip: Option<&'a str>,
    pub bg_image: Option<&'a str>,
    pub class_list: Option<&'a str>,
    /// Mirrors the JS `DETECTOR_IS_BROWSER` module constant: `true` when
    /// running against a real browser DOM, `false` in the Node/jsdom path.
    /// Callers that have no browser distinction should pass `true` (this
    /// port's tests exercise both).
    pub is_browser: bool,
}

fn tw_gray_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\btext-(?:gray|slate|zinc|neutral|stone)-\d+\b").unwrap())
}
fn tw_color_bg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bbg-(?:red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d+\b").unwrap()
    })
}
fn tw_bg_clip_text_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bbg-clip-text\b").unwrap())
}
fn tw_bg_gradient_to_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bbg-gradient-to-").unwrap())
}
fn tw_purple_text_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\btext-(?:purple|violet|indigo)-\d+\b").unwrap())
}
fn tw_text_xl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\btext-(?:[2-9]xl)\b").unwrap())
}
fn tw_from_purple_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bfrom-(?:purple|violet|indigo)-\d+\b").unwrap())
}
fn tw_to_purple_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bto-(?:purple|violet|indigo|blue|cyan|pink|fuchsia)-\d+\b").unwrap())
}

/// Port of `checkColors(opts)`.
pub fn check_colors(opts: &ColorsInput) -> Vec<Finding> {
    if SAFE_TAGS.contains(opts.tag) {
        let is_styled_button = (opts.tag == "a" || opts.tag == "button")
            && opts.has_direct_text
            && opts.bg_color.map(|c| c.a > 0.5).unwrap_or(false);
        if !is_styled_button {
            return vec![];
        }
    }
    let mut findings = vec![];

    if opts.has_direct_text && !opts.is_emoji_only {
        if let Some(text_color) = opts.text_color {
            let bgs: Option<Vec<Rgba>> = if let Some(bg) = opts.effective_bg {
                Some(vec![bg])
            } else if !opts.effective_bg_stops.is_empty() {
                Some(opts.effective_bg_stops.to_vec())
            } else {
                None
            };

            if let Some(bgs) = &bgs {
                let text_lum = relative_luminance(text_color);
                let is_gray = !has_chroma(Some(text_color), 20.0) && text_lum > 0.05 && text_lum < 0.85;
                if is_gray && bgs.iter().all(|b| has_chroma(Some(*b), 40.0)) {
                    let bg_label = if opts.effective_bg.is_some() {
                        color_to_hex(Some(bgs[0]))
                    } else {
                        format!(
                            "gradient({})",
                            bgs.iter().map(|b| color_to_hex(Some(*b))).collect::<Vec<_>>().join(", ")
                        )
                    };
                    findings.push(Finding {
                        id: "gray-on-color",
                        snippet: format!("text {} on bg {}", color_to_hex(Some(text_color)), bg_label),
                    });
                }

                let ratios: Vec<f64> = bgs.iter().map(|b| contrast_ratio(text_color, *b)).collect();
                let mut worst_idx = 0usize;
                for i in 1..ratios.len() {
                    if ratios[i] < ratios[worst_idx] {
                        worst_idx = i;
                    }
                }
                let ratio = ratios[worst_idx];
                let is_large_text = opts.font_size >= WCAG_LARGE_TEXT_PX
                    || (opts.font_size >= WCAG_LARGE_BOLD_TEXT_PX && opts.font_weight >= 700.0);
                let threshold = if is_large_text { 3.0 } else { 4.5 };
                if ratio < threshold {
                    let is_alpha_fallback_fp =
                        !opts.is_browser && opts.effective_bg.is_none() && text_color.a < 1.0;
                    if !is_alpha_fallback_fp {
                        findings.push(Finding {
                            id: "low-contrast",
                            snippet: format!(
                                "{:.1}:1 (need {}:1) — text {} on {}",
                                ratio,
                                threshold,
                                color_to_hex(Some(text_color)),
                                color_to_hex(Some(bgs[worst_idx])),
                            ),
                        });
                    }
                }
            }

            if has_chroma(Some(text_color), 50.0) {
                let hue = get_hue(Some(text_color));
                if (260.0..=310.0).contains(&hue)
                    && (matches!(opts.tag, "h1" | "h2" | "h3") || opts.font_size >= 20.0)
                {
                    findings.push(Finding {
                        id: "ai-color-palette",
                        snippet: format!("Purple/violet text ({}) on heading", color_to_hex(Some(text_color))),
                    });
                }
            }
        }
    }

    if opts.bg_clip == Some("text") && opts.bg_image.map(|s| s.contains("gradient")).unwrap_or(false) {
        findings.push(Finding {
            id: "gradient-text",
            snippet: "background-clip: text + gradient".to_string(),
        });
    }

    if let Some(class_str) = opts.class_list {
        let gray_match = tw_gray_re().find(class_str);
        let color_bg_match = tw_color_bg_re().find(class_str);
        if let (Some(g), Some(c)) = (gray_match, color_bg_match) {
            findings.push(Finding {
                id: "gray-on-color",
                snippet: format!("{} on {}", g.as_str(), c.as_str()),
            });
        }

        if tw_bg_clip_text_re().is_match(class_str) && tw_bg_gradient_to_re().is_match(class_str) {
            findings.push(Finding {
                id: "gradient-text",
                snippet: "bg-clip-text + bg-gradient (Tailwind)".to_string(),
            });
        }

        if let Some(purple_text) = tw_purple_text_re().find(class_str) {
            if matches!(opts.tag, "h1" | "h2" | "h3") || tw_text_xl_re().is_match(class_str) {
                findings.push(Finding {
                    id: "ai-color-palette",
                    snippet: format!("{} on heading", purple_text.as_str()),
                });
            }
        }

        if tw_from_purple_re().is_match(class_str) && tw_to_purple_re().is_match(class_str) {
            findings.push(Finding {
                id: "ai-color-palette",
                snippet: "Purple/violet gradient (Tailwind)".to_string(),
            });
        }
    }

    findings
}

// ─── checkIconTile (checks.mjs ~179-219) ────────────────────────────────────

fn is_heading_tag(tag: &str) -> bool {
    matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
}

pub struct IconTileInput<'a> {
    pub heading_tag: &'a str,
    pub heading_text: &'a str,
    /// `0.0` mirrors the JS falsy `headingTop` (jsdom layout case: skip the
    /// vertical-stacking gate).
    pub heading_top: f64,
    pub sibling_tag: Option<&'a str>,
    pub sibling_width: f64,
    pub sibling_height: f64,
    pub sibling_bottom: f64,
    pub sibling_bg_color: Option<Rgba>,
    pub sibling_bg_image: Option<&'a str>,
    pub sibling_border_width: f64,
    pub sibling_border_radius: f64,
    pub has_icon_child: bool,
    pub icon_child_width: Option<f64>,
}

/// Port of `checkIconTile(opts)`.
pub fn check_icon_tile(opts: &IconTileInput) -> Vec<Finding> {
    if !is_heading_tag(opts.heading_tag) {
        return vec![];
    }
    let Some(sibling_tag) = opts.sibling_tag else {
        return vec![];
    };
    if is_heading_tag(sibling_tag) {
        return vec![];
    }

    if !(opts.sibling_width >= 32.0 && opts.sibling_width <= 128.0) {
        return vec![];
    }
    if !(opts.sibling_height >= 32.0 && opts.sibling_height <= 128.0) {
        return vec![];
    }

    let ratio = opts.sibling_width / opts.sibling_height;
    if ratio < 0.7 || ratio > 1.4 {
        return vec![];
    }

    let bg_visible = opts.sibling_bg_color.map(|c| c.a > 0.1).unwrap_or(false)
        || opts.sibling_bg_image.map(|s| s != "none" && !s.is_empty()).unwrap_or(false);
    let border_visible = opts.sibling_border_width > 0.0;
    if !bg_visible && !border_visible {
        return vec![];
    }

    if opts.sibling_border_radius >= opts.sibling_width / 2.0 {
        return vec![];
    }

    if !opts.has_icon_child {
        return vec![];
    }
    if let Some(w) = opts.icon_child_width {
        if w >= opts.sibling_width * 0.95 {
            return vec![];
        }
    }

    if opts.heading_top != 0.0 && opts.sibling_bottom != 0.0 && opts.sibling_bottom > opts.heading_top + 4.0 {
        return vec![];
    }

    let text: String = opts.heading_text.trim().chars().take(60).collect();
    vec![Finding {
        id: "icon-tile-stack",
        snippet: format!(
            "{}x{}px icon tile above {} \"{}\"",
            opts.sibling_width.round(),
            opts.sibling_height.round(),
            opts.heading_tag,
            text,
        ),
    }]
}

// ─── checkHeroEyebrow (checks.mjs ~308-363) ─────────────────────────────────

fn ascii_upper_no_lower_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Z]").unwrap())
}
fn ascii_lower_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[a-z]").unwrap())
}

pub struct HeroEyebrowInput<'a> {
    pub heading_tag: &'a str,
    pub heading_text: &'a str,
    pub sibling_tag: Option<&'a str>,
    pub sibling_text: &'a str,
    pub sibling_text_transform: Option<&'a str>,
    pub sibling_font_size: f64,
    pub sibling_letter_spacing: f64,
    pub sibling_font_weight: f64,
    pub sibling_color: Option<&'a str>,
}

/// Port of `checkHeroEyebrow(opts)`. `isAccentColor` is
/// `l6_designer_checks::is_accent_color` — the same local parser the JS
/// `checks.mjs` module uses for this check (not `shared/color.mjs`).
pub fn check_hero_eyebrow(opts: &HeroEyebrowInput) -> Vec<Finding> {
    if opts.heading_tag != "h1" {
        return vec![];
    }
    let Some(sibling_tag) = opts.sibling_tag else {
        return vec![];
    };
    if is_heading_tag(sibling_tag) {
        return vec![];
    }

    let text = opts.sibling_text.trim();
    let len = text.chars().count();
    if len < 2 || len > 60 {
        return vec![];
    }
    if !(opts.sibling_font_size > 0.0 && opts.sibling_font_size <= 14.0) {
        return vec![];
    }

    let is_uppercased = opts.sibling_text_transform == Some("uppercase")
        || (ascii_upper_no_lower_re().is_match(text) && !ascii_lower_re().is_match(text));
    let is_classic_tracked = is_uppercased && opts.sibling_letter_spacing >= 1.6;

    let weight = if opts.sibling_font_weight > 0.0 { opts.sibling_font_weight } else { 400.0 };
    let is_accent_bold =
        weight >= 700.0 && crate::l6_designer_checks::pure_checks::is_accent_color(opts.sibling_color);

    if !is_classic_tracked && !is_accent_bold {
        return vec![];
    }

    let heading_text_snippet: String = opts.heading_text.trim().chars().take(60).collect();
    let eyebrow_snippet: String = text.chars().take(40).collect();
    let style = if is_classic_tracked { "tracked-caps" } else { "accent-bold" };
    vec![Finding {
        id: "hero-eyebrow-chip",
        snippet: format!(
            "eyebrow chip ({}) \"{}\" above {} \"{}\"",
            style, eyebrow_snippet, opts.heading_tag, heading_text_snippet,
        ),
    }]
}

// ─── checkRepeatedSectionKickers (checks.mjs ~356-363) ──────────────────────

pub struct KickerCandidate {
    pub kicker_text: String,
    pub heading_tag: String,
    pub heading_text: String,
}

/// Port of `checkRepeatedSectionKickers(opts)`.
pub fn check_repeated_section_kickers(candidates: &[KickerCandidate], min_count: usize) -> Vec<Finding> {
    let min_count = if min_count == 0 { 3 } else { min_count };
    if candidates.len() < min_count {
        return vec![];
    }
    candidates
        .iter()
        .map(|c| Finding {
            id: "repeated-section-kickers",
            snippet: format!(
                "repeated section kicker \"{}\" before {} \"{}\" ({} on page)",
                c.kicker_text,
                c.heading_tag,
                c.heading_text,
                candidates.len(),
            ),
        })
        .collect()
}

// ─── checkMotion (checks.mjs ~365-408) ──────────────────────────────────────

fn layout_transition_props() -> &'static [&'static str] {
    &[
        "width", "height", "padding", "margin", "max-height", "max-width", "min-height",
        "min-width", "padding-top", "padding-right", "padding-bottom", "padding-left",
        "margin-top", "margin-right", "margin-bottom", "margin-left",
    ]
}

fn bounce_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)bounce|elastic|wobble|jiggle|spring").unwrap())
}
fn animate_bounce_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\banimate-bounce\b").unwrap())
}
fn cubic_bezier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"cubic-bezier\(\s*([\d.-]+)\s*,\s*([\d.-]+)\s*,\s*([\d.-]+)\s*,\s*([\d.-]+)\s*\)").unwrap()
    })
}

pub struct MotionInput<'a> {
    pub tag: &'a str,
    pub transition_property: Option<&'a str>,
    pub animation_name: Option<&'a str>,
    pub timing_functions: Option<&'a str>,
    pub class_list: Option<&'a str>,
}

/// Port of `checkMotion(opts)`.
pub fn check_motion(opts: &MotionInput) -> Vec<Finding> {
    if SAFE_TAGS.contains(opts.tag) {
        return vec![];
    }
    let mut findings = vec![];

    if let Some(name) = opts.animation_name {
        if name != "none" && bounce_name_re().is_match(name) {
            findings.push(Finding {
                id: "bounce-easing",
                snippet: format!("animation: {}", name),
            });
        }
    }
    if let Some(cls) = opts.class_list {
        if animate_bounce_re().is_match(cls) {
            findings.push(Finding {
                id: "bounce-easing",
                snippet: "animate-bounce (Tailwind)".to_string(),
            });
        }
    }

    if let Some(timing) = opts.timing_functions {
        for caps in cubic_bezier_re().captures_iter(timing) {
            let y1: f64 = caps[2].parse().unwrap_or(f64::NAN);
            let y2: f64 = caps[4].parse().unwrap_or(f64::NAN);
            if y1 < -0.1 || y1 > 1.1 || y2 < -0.1 || y2 > 1.1 {
                findings.push(Finding {
                    id: "bounce-easing",
                    snippet: format!("cubic-bezier({}, {}, {}, {})", &caps[1], &caps[2], &caps[3], &caps[4]),
                });
                break;
            }
        }
    }

    if let Some(tp) = opts.transition_property {
        if tp != "all" && tp != "none" {
            let props: Vec<String> = tp.split(',').map(|p| p.trim().to_ascii_lowercase()).collect();
            let layout_found: Vec<&str> = props
                .iter()
                .filter(|p| layout_transition_props().contains(&p.as_str()))
                .map(|p| p.as_str())
                .collect();
            if !layout_found.is_empty() {
                findings.push(Finding {
                    id: "layout-transition",
                    snippet: format!("transition: {}", layout_found.join(", ")),
                });
            }
        }
    }

    findings
}

// ─── checkGlow (checks.mjs ~410-440) ────────────────────────────────────────

fn comma_outside_parens_re() -> &'static Regex {
    // JS: /,(?![^(]*\))/ — split on commas not inside parens. The regex
    // crate has no lookahead, so this is a hand-written scan instead of a
    // regex translation (see port-brief pitfall note on backreferences).
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"rgba?\([^)]+\)").unwrap())
}
fn px_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"([\d.]+)px").unwrap())
}

fn split_shadow_layers(box_shadow: &str) -> Vec<String> {
    let mut parts = vec![];
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in box_shadow.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Port of `checkGlow(opts)`.
pub fn check_glow(box_shadow: Option<&str>, effective_bg: Option<Rgba>) -> Vec<Finding> {
    let Some(box_shadow) = box_shadow else { return vec![] };
    if box_shadow == "none" {
        return vec![];
    }
    let Some(effective_bg) = effective_bg else { return vec![] };

    let bg_lum = relative_luminance(effective_bg);
    if bg_lum >= 0.1 {
        return vec![];
    }

    for shadow in split_shadow_layers(box_shadow) {
        let Some(color_match) = comma_outside_parens_re().find(&shadow) else { continue };
        let color_str = color_match.as_str();
        let Some(color) = parse_rgb(Some(color_str)) else { continue };
        if !has_chroma(Some(color), 30.0) {
            continue;
        }

        let before_color = &shadow[..color_match.start()];
        let after_color = &shadow[color_match.end()..];
        let px_vals: Vec<f64> = px_re()
            .captures_iter(before_color)
            .chain(px_re().captures_iter(after_color))
            .filter_map(|c| c[1].parse::<f64>().ok())
            .collect();

        if px_vals.len() >= 3 && px_vals[2] > 4.0 {
            return vec![Finding {
                id: "dark-glow",
                snippet: format!("Colored glow ({}) on dark background", color_to_hex(Some(color))),
            }];
        }
    }

    vec![]
}

// Packet r10r11: closes the gap this module's own doc comment named
// ("everything DOM-shaped" / `checkHtmlPatterns`) by adding the remaining
// pieces of `checks.mjs` as sibling submodules driven over
// `wf_port::r09`'s static DOM + cascade.
pub mod html_patterns;
pub mod static_adapters;

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb(r: f64, g: f64, b: f64) -> Rgba {
        Rgba { r, g, b, a: 1.0 }
    }
    fn rgba(r: f64, g: f64, b: f64, a: f64) -> Rgba {
        Rgba { r, g, b, a }
    }

    #[test]
    fn check_borders_side_tab_and_accent_on_rounded() {
        // Strong left border, opaque red, no radius, width 3 -> side-tab.
        let sides = BorderSides {
            widths: [0.0, 0.0, 0.0, 3.0],
            colors: [None, None, None, Some("rgb(200,0,0)")],
        };
        let f = check_borders("div", &sides, 0.0);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "side-tab");

        // Top accent border with radius -> border-accent-on-rounded.
        let sides = BorderSides {
            widths: [3.0, 0.0, 0.0, 0.0],
            colors: [Some("rgb(200,0,0)"), None, None, None],
        };
        let f = check_borders("div", &sides, 8.0);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "border-accent-on-rounded");

        // BORDER_SAFE_TAGS (e.g. nav) never flags.
        let sides = BorderSides {
            widths: [3.0, 0.0, 0.0, 0.0],
            colors: [Some("rgb(200,0,0)"), None, None, None],
        };
        assert!(check_borders("nav", &sides, 8.0).is_empty());

        // Neutral color never flags.
        let sides = BorderSides {
            widths: [3.0, 0.0, 0.0, 0.0],
            colors: [Some("rgb(120,120,120)"), None, None, None],
        };
        assert!(check_borders("div", &sides, 8.0).is_empty());
    }

    #[test]
    fn check_colors_low_contrast_and_gray_on_color() {
        let text = rgb(150.0, 150.0, 150.0); // gray
        let bg = rgb(200.0, 0.0, 0.0); // chromatic red
        let opts = ColorsInput {
            tag: "p",
            text_color: Some(text),
            bg_color: None,
            effective_bg: Some(bg),
            effective_bg_stops: &[],
            font_size: 16.0,
            font_weight: 400.0,
            has_direct_text: true,
            is_emoji_only: false,
            bg_clip: None,
            bg_image: None,
            class_list: None,
            is_browser: true,
        };
        let f = check_colors(&opts);
        assert!(f.iter().any(|x| x.id == "gray-on-color"));
    }

    #[test]
    fn check_colors_safe_tag_suppressed_unless_styled_button() {
        let opts = ColorsInput {
            tag: "a",
            text_color: Some(rgb(255.0, 255.0, 255.0)),
            bg_color: None,
            effective_bg: Some(rgb(255.0, 255.0, 255.0)),
            effective_bg_stops: &[],
            font_size: 16.0,
            font_weight: 400.0,
            has_direct_text: true,
            is_emoji_only: false,
            bg_clip: None,
            bg_image: None,
            class_list: None,
            is_browser: true,
        };
        assert!(check_colors(&opts).is_empty());

        let opts2 = ColorsInput {
            bg_color: Some(rgba(0.0, 0.0, 0.0, 1.0)),
            text_color: Some(rgb(100.0, 100.0, 100.0)),
            effective_bg: Some(rgb(0.0, 0.0, 0.0)),
            ..opts
        };
        let f = check_colors(&opts2);
        assert!(!f.is_empty(), "styled <a> with opaque bg should be evaluated");
    }

    #[test]
    fn check_icon_tile_matches_shape() {
        let opts = IconTileInput {
            heading_tag: "h2",
            heading_text: "Fast delivery",
            heading_top: 0.0,
            sibling_tag: Some("div"),
            sibling_width: 64.0,
            sibling_height: 64.0,
            sibling_bottom: 0.0,
            sibling_bg_color: Some(rgb(240.0, 240.0, 240.0)),
            sibling_bg_image: None,
            sibling_border_width: 0.0,
            sibling_border_radius: 8.0,
            has_icon_child: true,
            icon_child_width: Some(24.0),
        };
        let f = check_icon_tile(&opts);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "icon-tile-stack");

        let none = check_icon_tile(&IconTileInput { has_icon_child: false, ..opts });
        assert!(none.is_empty());
    }

    #[test]
    fn check_hero_eyebrow_classic_tracked() {
        let opts = HeroEyebrowInput {
            heading_tag: "h1",
            heading_text: "Build faster",
            sibling_tag: Some("span"),
            sibling_text: "NEW RELEASE",
            sibling_text_transform: Some("uppercase"),
            sibling_font_size: 12.0,
            sibling_letter_spacing: 2.0,
            sibling_font_weight: 400.0,
            sibling_color: None,
        };
        let f = check_hero_eyebrow(&opts);
        assert_eq!(f.len(), 1);
        assert!(f[0].snippet.contains("tracked-caps"));
    }

    #[test]
    fn check_hero_eyebrow_accent_bold() {
        let opts = HeroEyebrowInput {
            heading_tag: "h1",
            heading_text: "Build faster",
            sibling_tag: Some("span"),
            sibling_text: "New release",
            sibling_text_transform: None,
            sibling_font_size: 12.0,
            sibling_letter_spacing: 0.0,
            sibling_font_weight: 700.0,
            sibling_color: Some("rgb(200, 30, 30)"),
        };
        let f = check_hero_eyebrow(&opts);
        assert_eq!(f.len(), 1);
        assert!(f[0].snippet.contains("accent-bold"));
    }

    #[test]
    fn check_repeated_section_kickers_min_count() {
        let mk = |t: &str| KickerCandidate {
            kicker_text: "WHY US".into(),
            heading_tag: "h2".into(),
            heading_text: t.into(),
        };
        let candidates = vec![mk("One"), mk("Two"), mk("Three")];
        let f = check_repeated_section_kickers(&candidates, 3);
        assert_eq!(f.len(), 3);

        let two = vec![mk("One"), mk("Two")];
        assert!(check_repeated_section_kickers(&two, 3).is_empty());
    }

    #[test]
    fn check_motion_bounce_and_layout_transition() {
        let opts = MotionInput {
            tag: "div",
            transition_property: None,
            animation_name: Some("bounceIn"),
            timing_functions: None,
            class_list: None,
        };
        let f = check_motion(&opts);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "bounce-easing");

        let opts = MotionInput {
            tag: "div",
            transition_property: Some("width, opacity"),
            animation_name: None,
            timing_functions: None,
            class_list: None,
        };
        let f = check_motion(&opts);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "layout-transition");

        // SAFE_TAGS is always suppressed.
        let opts = MotionInput {
            tag: "nav",
            transition_property: Some("width"),
            animation_name: Some("bounceIn"),
            timing_functions: None,
            class_list: None,
        };
        assert!(check_motion(&opts).is_empty());
    }

    #[test]
    fn check_glow_dark_bg_colored_blur() {
        let f = check_glow(Some("0px 0px 20px rgba(120, 0, 200, 0.6)"), Some(rgb(10.0, 10.0, 10.0)));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "dark-glow");

        // Light background: never flags.
        assert!(check_glow(Some("0px 0px 20px rgba(120, 0, 200, 0.6)"), Some(rgb(250.0, 250.0, 250.0))).is_empty());

        // No box-shadow: never flags.
        assert!(check_glow(None, Some(rgb(10.0, 10.0, 10.0))).is_empty());
        assert!(check_glow(Some("none"), Some(rgb(10.0, 10.0, 10.0))).is_empty());
    }
}
