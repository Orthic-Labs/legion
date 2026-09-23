//! Local CSS color/shadow parsing, ported 1:1 from
//! `skills/designer/engine/scripts/detector/rules/checks.mjs` lines
//! ~925-1031 and ~2264-2306 (`oklchToRgb`, `parseAnyColor`,
//! `cssColorIsTransparent`, `colorsNearlyMatch`, `shadowLayerAlpha`,
//! `shadowMaxBlurPx`, `cssColorAlpha`).
//!
//! This is intentionally a *separate* parser from
//! `shared/color.mjs`/the future `p8_designer` color foundation: `checks.mjs`
//! defines its own local `parseAnyColor` rather than importing one, and this
//! port preserves that (it is the production entry point these detector
//! rules assert against, per this repo's detokenization-entry-point
//! discipline for "one canonical parser per behavior").

use std::sync::OnceLock;

use regex::Regex;

/// Parsed CSS color: 0-255 channels, alpha in `[0, 1]`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rgba {
    pub r: f64,
    pub g: f64,
    pub b: f64,
    pub a: f64,
}

fn rgba_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"rgba?\(\s*(\d+(?:\.\d+)?)\s*,?\s*(\d+(?:\.\d+)?)\s*,?\s*(\d+(?:\.\d+)?)(?:\s*[,/]\s*([\d.]+))?\s*\)",
        )
        .unwrap()
    })
}

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^#([0-9a-fA-F]{3,8})$").unwrap())
}

fn oklch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)oklch\(\s*([\d.]+)(%?)\s*[\s,]*\s*([\d.]+)\s*[\s,]+\s*([-\d.]+)(?:deg)?(?:\s*/\s*([\d.]+)(%)?)?\s*\)",
        )
        .unwrap()
    })
}

/// Port of `oklchToRgb(L, C, H)` (checks.mjs ~925-944).
pub fn oklch_to_rgb(l: f64, c: f64, h: f64) -> Rgba {
    let h_rad = h * std::f64::consts::PI / 180.0;
    let a = c * h_rad.cos();
    let b = c * h_rad.sin();
    let l_ = l + 0.3963377774 * a + 0.2158037573 * b;
    let m_ = l - 0.1055613458 * a - 0.0638541728 * b;
    let s_ = l - 0.0894841775 * a - 1.2914855480 * b;
    let (lc, mc, sc) = (l_ * l_ * l_, m_ * m_ * m_, s_ * s_ * s_);
    let r_lin = 4.0767416621 * lc - 3.3077115913 * mc + 0.2309699292 * sc;
    let g_lin = -1.2684380046 * lc + 2.6097574011 * mc - 0.3413193965 * sc;
    let b_lin = -0.0041960863 * lc - 0.7034186147 * mc + 1.7076147010 * sc;
    let enc = |x: f64| {
        let c = x.max(0.0).min(1.0);
        if c <= 0.0031308 {
            12.92 * c
        } else {
            1.055 * c.powf(1.0 / 2.4) - 0.055
        }
    };
    Rgba {
        r: (enc(r_lin) * 255.0).round(),
        g: (enc(g_lin) * 255.0).round(),
        b: (enc(b_lin) * 255.0).round(),
        a: 1.0,
    }
}

fn hex_pair(s: &str, i: usize) -> Option<f64> {
    i64::from_str_radix(s.get(i..i + 2)?, 16).ok().map(|v| v as f64)
}

fn hex_single(c: char) -> Option<f64> {
    let s: String = [c, c].iter().collect();
    i64::from_str_radix(&s, 16).ok().map(|v| v as f64)
}

/// Port of `parseAnyColor(s)` (checks.mjs ~951-981). Returns `None` on no
/// match, exactly mirroring the JS `null` return (including for
/// `transparent`/`currentcolor`/`inherit`, which are treated as "no color"
/// here, not as a parsed value).
pub fn parse_any_color(s: &str) -> Option<Rgba> {
    let str_ = s.trim();
    if str_.is_empty() {
        return None;
    }
    let lower = str_.to_ascii_lowercase();
    if lower == "transparent" || lower == "currentcolor" || lower == "inherit" {
        return None;
    }

    if let Some(m) = rgba_re().captures(str_) {
        let r = m[1].parse::<f64>().ok()?.round();
        let g = m[2].parse::<f64>().ok()?.round();
        let b = m[3].parse::<f64>().ok()?.round();
        let a = m.get(4).and_then(|g| g.as_str().parse::<f64>().ok()).unwrap_or(1.0);
        return Some(Rgba { r, g, b, a });
    }

    if let Some(m) = hex_re().captures(str_) {
        let h = &m[1];
        let chars: Vec<char> = h.chars().collect();
        if chars.len() == 3 || chars.len() == 4 {
            let r = hex_single(chars[0])?;
            let g = hex_single(chars[1])?;
            let b = hex_single(chars[2])?;
            let a = if chars.len() == 4 { hex_single(chars[3])? / 255.0 } else { 1.0 };
            return Some(Rgba { r, g, b, a });
        }
        if chars.len() == 6 || chars.len() == 8 {
            let r = hex_pair(h, 0)?;
            let g = hex_pair(h, 2)?;
            let b = hex_pair(h, 4)?;
            let a = if chars.len() == 8 { hex_pair(h, 6)? / 255.0 } else { 1.0 };
            return Some(Rgba { r, g, b, a });
        }
        return None;
    }

    if let Some(m) = oklch_re().captures(str_) {
        let l_num: f64 = m[1].parse().ok()?;
        let l = if m.get(2).map(|g| g.as_str()) == Some("%") { l_num / 100.0 } else { l_num };
        let c: f64 = m[3].parse().ok()?;
        let h: f64 = m[4].parse().ok()?;
        let mut rgb = oklch_to_rgb(l, c, h);
        if let Some(alpha_m) = m.get(5) {
            let alpha: f64 = alpha_m.as_str().parse().ok()?;
            rgb.a = if m.get(6).map(|g| g.as_str()) == Some("%") { alpha / 100.0 } else { alpha };
        }
        return Some(rgb);
    }

    None
}

/// Port of `cssColorIsTransparent(value)` (checks.mjs ~1264-1272).
pub fn css_color_is_transparent(value: &str) -> bool {
    let str_ = value.trim().to_ascii_lowercase();
    if str_.is_empty() || str_ == "transparent" || str_ == "rgba(0, 0, 0, 0)" {
        return true;
    }
    if let Some(parsed) = parse_any_color(&str_) {
        return parsed.a <= 0.05;
    }
    fallback_zero_alpha_rgba_re().is_match(&str_)
}

fn fallback_zero_alpha_rgba_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0(?:\.0+)?\s*\)$").unwrap()
    })
}

/// Port of `colorsNearlyMatch(a, b)` (checks.mjs ~1273-1283).
pub fn colors_nearly_match(a: &str, b: &str) -> bool {
    let (Some(ca), Some(cb)) = (parse_any_color(a), parse_any_color(b)) else {
        return false;
    };
    let alpha_delta = (ca.a - cb.a).abs();
    let channel_delta = (ca.r - cb.r).abs().max((ca.g - cb.g).abs()).max((ca.b - cb.b).abs());
    alpha_delta <= 0.03 && channel_delta <= 3.0
}

/// Port of `cssColorAlpha(value)` (checks.mjs ~2301-2305).
pub fn css_color_alpha(value: &str) -> f64 {
    if css_color_is_transparent(value) {
        return 0.0;
    }
    parse_any_color(value).map(|c| c.a).unwrap_or(1.0)
}

fn css_color_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:rgba?|hsla?|oklch|oklab|lab|lch|color)\([^)]*\)|#[0-9a-fA-F]{3,8}\b|\b(?:black|white|transparent|currentcolor)\b",
        )
        .unwrap()
    })
}

/// Port of `shadowLayerAlpha(layer)` (checks.mjs ~2278-2283).
pub fn shadow_layer_alpha(layer: &str) -> f64 {
    let Some(m) = css_color_token_re().find(layer) else {
        return 1.0;
    };
    if m.as_str().eq_ignore_ascii_case("transparent") {
        return 0.0;
    }
    parse_any_color(m.as_str()).map(|c| c.a).unwrap_or(1.0)
}

fn word_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b[a-z]+\b").unwrap())
}

fn number_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-?\d*\.?\d+").unwrap())
}

/// Splits `box-shadow` layers on commas not inside parentheses, matching the
/// JS `boxShadow.split(/,(?![^()]*\))/)`.
fn split_shadow_layers(box_shadow: &str) -> Vec<&str> {
    let mut layers = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, ch) in box_shadow.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth <= 0 => {
                layers.push(&box_shadow[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    layers.push(&box_shadow[start..]);
    layers
}

/// Port of `shadowMaxBlurPx(boxShadow, { minAlpha })` (checks.mjs ~2284-2300).
pub fn shadow_max_blur_px(box_shadow: &str, min_alpha: f64) -> f64 {
    if box_shadow.is_empty() || box_shadow == "none" {
        return 0.0;
    }
    let mut max_blur = 0.0f64;
    for layer in split_shadow_layers(box_shadow) {
        if shadow_layer_alpha(layer) < min_alpha {
            continue;
        }
        let cleaned = css_color_token_re().replace_all(layer, " ");
        let cleaned = word_re().replace_all(&cleaned, " ");
        let nums: Vec<f64> = number_re()
            .find_iter(&cleaned)
            .filter_map(|m| m.as_str().parse::<f64>().ok())
            .collect();
        if nums.len() >= 3 {
            max_blur = max_blur.max(nums[2]);
        }
    }
    max_blur
}

fn accent_rgb_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)").unwrap())
}

fn accent_hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^#([0-9a-f]{3,8})\b").unwrap())
}

fn accent_oklch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^oklch\(").unwrap())
}

fn accent_num_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d*\.\d+|\d+").unwrap())
}

fn accent_hsl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)hsla?\(\s*[\d.]+\s*,\s*([\d.]+)%").unwrap())
}

/// Port of `isAccentColor(cssColor)` (checks.mjs ~261-297).
pub fn is_accent_color_impl(css_color: Option<&str>) -> bool {
    let Some(s) = css_color.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };

    if let Some(m) = accent_rgb_re().captures(s) {
        let r: f64 = m[1].parse().unwrap_or(0.0);
        let g: f64 = m[2].parse().unwrap_or(0.0);
        let b: f64 = m[3].parse().unwrap_or(0.0);
        return (r.max(g).max(b) - r.min(g).min(b)) >= 40.0;
    }

    if let Some(m) = accent_hex_re().captures(s) {
        let mut h = m[1].to_string();
        h = if h.len() == 3 || h.len() == 4 {
            h.chars().flat_map(|c| [c, c]).take(6).collect()
        } else {
            h.chars().take(6).collect()
        };
        if h.len() == 6 {
            let r = i64::from_str_radix(&h[0..2], 16).unwrap_or(0) as f64;
            let g = i64::from_str_radix(&h[2..4], 16).unwrap_or(0) as f64;
            let b = i64::from_str_radix(&h[4..6], 16).unwrap_or(0) as f64;
            return (r.max(g).max(b) - r.min(g).min(b)) >= 40.0;
        }
    }

    if accent_oklch_re().is_match(s) {
        let nums: Vec<f64> = accent_num_re().find_iter(s).filter_map(|m| m.as_str().parse().ok()).collect();
        if nums.len() >= 2 {
            return nums[1] >= 0.05;
        }
        return false;
    }

    if let Some(m) = accent_hsl_re().captures(s) {
        if let Ok(sat) = m[1].parse::<f64>() {
            return sat >= 20.0;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rgb_and_rgba() {
        let c = parse_any_color("rgb(255, 0, 0)").unwrap();
        assert_eq!((c.r, c.g, c.b, c.a), (255.0, 0.0, 0.0, 1.0));
        let c = parse_any_color("rgba(10, 20, 30, 0.5)").unwrap();
        assert_eq!((c.r, c.g, c.b, c.a), (10.0, 20.0, 30.0, 0.5));
    }

    #[test]
    fn parses_hex_short_and_long_with_alpha() {
        let c = parse_any_color("#f00").unwrap();
        assert_eq!((c.r, c.g, c.b, c.a), (255.0, 0.0, 0.0, 1.0));
        let c = parse_any_color("#ff000080").unwrap();
        assert_eq!((c.r, c.g, c.b), (255.0, 0.0, 0.0));
        assert!((c.a - (128.0 / 255.0)).abs() < 1e-6);
    }

    #[test]
    fn parses_oklch_with_percent_lightness_and_alpha() {
        let c = parse_any_color("oklch(70% 0.15 150)").unwrap();
        assert!(c.a == 1.0);
        let c = parse_any_color("oklch(70% 0.15 150 / 50%)").unwrap();
        assert!((c.a - 0.5).abs() < 1e-9);
    }

    #[test]
    fn transparent_currentcolor_inherit_are_none() {
        assert!(parse_any_color("transparent").is_none());
        assert!(parse_any_color("currentcolor").is_none());
        assert!(parse_any_color("inherit").is_none());
        assert!(parse_any_color("").is_none());
        assert!(parse_any_color("not-a-color").is_none());
    }

    #[test]
    fn css_color_is_transparent_matches_js_cases() {
        assert!(css_color_is_transparent(""));
        assert!(css_color_is_transparent("transparent"));
        assert!(css_color_is_transparent("rgba(0, 0, 0, 0)"));
        assert!(css_color_is_transparent("rgba(1, 2, 3, 0.01)"));
        assert!(!css_color_is_transparent("rgb(1, 2, 3)"));
        assert!(!css_color_is_transparent("#ff0000"));
    }

    #[test]
    fn colors_nearly_match_within_tolerance() {
        assert!(colors_nearly_match("rgb(10, 10, 10)", "rgb(12, 9, 11)"));
        assert!(!colors_nearly_match("rgb(10, 10, 10)", "rgb(20, 10, 10)"));
        assert!(!colors_nearly_match("not-a-color", "rgb(10, 10, 10)"));
    }

    #[test]
    fn css_color_alpha_matches_js() {
        assert_eq!(css_color_alpha("transparent"), 0.0);
        assert_eq!(css_color_alpha("rgb(1, 2, 3)"), 1.0);
        assert_eq!(css_color_alpha("rgba(1, 2, 3, 0.4)"), 0.4);
    }

    #[test]
    fn shadow_max_blur_px_picks_third_number_across_layers() {
        // "0px 4px 24px rgba(0,0,0,0.2), inset 0 0 0 1px #fff"
        let blur = shadow_max_blur_px(
            "0px 4px 24px rgba(0,0,0,0.2), inset 0 0 0 1px #fff",
            0.0,
        );
        assert_eq!(blur, 24.0);
    }

    #[test]
    fn shadow_max_blur_px_respects_min_alpha_gate() {
        let blur = shadow_max_blur_px("0 0 40px rgba(0,0,0,0.05)", 0.12);
        assert_eq!(blur, 0.0);
    }

    #[test]
    fn shadow_max_blur_px_none_and_empty() {
        assert_eq!(shadow_max_blur_px("none", 0.0), 0.0);
        assert_eq!(shadow_max_blur_px("", 0.0), 0.0);
    }

    #[test]
    fn is_accent_color_rgb_hex_oklch_hsl() {
        assert!(is_accent_color_impl(Some("rgb(200, 50, 30)")));
        assert!(!is_accent_color_impl(Some("rgb(120, 120, 125)")));
        assert!(is_accent_color_impl(Some("#ff0000")));
        assert!(!is_accent_color_impl(Some("#808080")));
        assert!(is_accent_color_impl(Some("oklch(60% 0.15 30)")));
        assert!(!is_accent_color_impl(Some("oklch(60% 0.01 30)")));
        assert!(is_accent_color_impl(Some("hsl(200, 40%, 50%)")));
        assert!(!is_accent_color_impl(Some("hsl(200, 5%, 50%)")));
        assert!(!is_accent_color_impl(None));
    }
}
