//! Port of `skills/designer/engine/scripts/detector/shared/color.mjs`
//! (chunk w2_014).
//!
//! Faithful, full port of every exported function: `isNeutralColor`,
//! `parseRgb`, `relativeLuminance`, `contrastRatio`, `parseGradientColors`,
//! `hasChroma`, `getHue`, `colorToHex`. All regex-based parsing in the JS
//! source is reproduced with equivalent hand-written scanning so the same
//! inputs classify identically (including the "unknown/unrecognized format
//! defaults to non-neutral" behaviour the JS comments call out explicitly).

/// Mirrors the JS `{r,g,b,a}` color record. `a` defaults to `1.0` when the
/// source color string carries no alpha channel (matches `parseRgb`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rgba {
    pub r: f64,
    pub g: f64,
    pub b: f64,
    pub a: f64,
}

/// Mirrors `isNeutralColor(color)`.
pub fn is_neutral_color(color: Option<&str>) -> bool {
    let color = match color {
        None => return true,
        Some(c) if c == "transparent" => return true,
        Some(c) => c,
    };

    if let Some((r, g, b)) = match_rgb_channels(color) {
        let max = r.max(g).max(b);
        let min = r.min(g).min(b);
        return (max - min) < 30.0;
    }

    if let Some(chroma) = match_prefixed_single(color, "oklch(") {
        return chroma < 0.02;
    }
    if let Some(chroma) = match_prefixed_single(color, "lch(") {
        return chroma < 3.0;
    }

    if let Some((a, b)) = match_prefixed_pair(color, "oklab(") {
        return a.hypot(b) < 0.02;
    }
    if let Some((a, b)) = match_prefixed_pair(color, "lab(") {
        return a.hypot(b) < 3.0;
    }

    if let Some(sat) = match_hsl_saturation(color) {
        return sat < 10.0;
    }

    if let Some((w, b)) = match_hwb(color) {
        return (1.0 - (100.0f64).min(w + b) / 100.0) < 0.1;
    }

    // Unknown / unrecognized format: err on the side of detecting.
    false
}

/// `rgba?\((\d+),\s*(\d+),\s*(\d+)`
fn match_rgb_channels(color: &str) -> Option<(f64, f64, f64)> {
    let rest = strip_rgb_prefix(color)?;
    let mut nums = split_leading_uints(rest, 3)?;
    let b = nums.pop().unwrap();
    let g = nums.pop().unwrap();
    let r = nums.pop().unwrap();
    Some((r as f64, g as f64, b as f64))
}

fn strip_rgb_prefix(color: &str) -> Option<&str> {
    if let Some(rest) = color.strip_prefix("rgba(") {
        return Some(rest);
    }
    color.strip_prefix("rgb(")
}

/// Parses up to `count` unsigned integers separated by `,` and optional
/// whitespace, from the start of `s`. Returns `None` if fewer than `count`
/// are found before a non-digit, non-separator character (mirrors the JS
/// regex's greedy-but-anchored-at-start matching).
fn split_leading_uints(s: &str, count: usize) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(count);
    let mut chars = s.char_indices().peekable();
    let bytes = s.as_bytes();
    let mut pos = 0usize;
    for i in 0..count {
        // skip whitespace/comma separators except before the first number
        if i > 0 {
            while pos < bytes.len() && (bytes[pos] == b',' || bytes[pos] == b' ') {
                pos += 1;
            }
        }
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == start {
            return None;
        }
        out.push(s[start..pos].parse::<u32>().ok()?);
    }
    let _ = chars.peek();
    Some(out)
}

/// Matches `prefix\s*[\d.]+%?\s*([\d.-]+)` and returns the captured number.
fn match_prefixed_single(color: &str, prefix: &str) -> Option<f64> {
    let idx = find_ci(color, prefix)?;
    let rest = &color[idx + prefix.len()..];
    let rest = skip_ws(rest);
    // first numeric token (lightness, possibly with trailing %)
    let (_, after_first) = take_number_token(rest)?;
    let after_first = skip_optional_percent(after_first);
    let after_first = skip_ws(after_first);
    let (num, _) = take_signed_number_token(after_first)?;
    Some(num)
}

/// Matches `prefix\s*[\d.]+%?\s*([\d.-]+)\s+([\d.-]+)` and returns the two
/// captured signed numbers (oklab/lab a and b channels).
fn match_prefixed_pair(color: &str, prefix: &str) -> Option<(f64, f64)> {
    let idx = find_ci(color, prefix)?;
    let rest = &color[idx + prefix.len()..];
    let rest = skip_ws(rest);
    let (_, after_first) = take_number_token(rest)?;
    let after_first = skip_optional_percent(after_first);
    let after_first = skip_ws(after_first);
    let (a, after_a) = take_signed_number_token(after_first)?;
    let after_a = skip_ws(after_a);
    let (b, _) = take_signed_number_token(after_a)?;
    Some((a, b))
}

/// `hsla?\(\s*[\d.-]+\s*,?\s*([\d.]+)%`
fn match_hsl_saturation(color: &str) -> Option<f64> {
    let idx = find_ci(color, "hsl(").or_else(|| find_ci(color, "hsla("))?;
    let prefix_len = if color[idx..].to_ascii_lowercase().starts_with("hsla(") {
        5
    } else {
        4
    };
    let rest = &color[idx + prefix_len..];
    let rest = skip_ws(rest);
    let (_, after_hue) = take_signed_number_token(rest)?;
    let mut after_hue = skip_ws(after_hue);
    if let Some(r) = after_hue.strip_prefix(',') {
        after_hue = skip_ws(r);
    }
    let (sat, after_sat) = take_number_token(after_hue)?;
    if after_sat.starts_with('%') {
        Some(sat)
    } else {
        None
    }
}

/// `hwb\(\s*[\d.-]+\s+([\d.]+)%\s+([\d.]+)%`
fn match_hwb(color: &str) -> Option<(f64, f64)> {
    let idx = find_ci(color, "hwb(")?;
    let rest = &color[idx + 4..];
    let rest = skip_ws(rest);
    let (_, after_hue) = take_signed_number_token(rest)?;
    if !after_hue.starts_with(char::is_whitespace) {
        return None;
    }
    let after_hue = skip_ws(after_hue);
    let (w, after_w) = take_number_token(after_hue)?;
    let after_w = after_w.strip_prefix('%')?;
    if !after_w.starts_with(char::is_whitespace) {
        return None;
    }
    let after_w = skip_ws(after_w);
    let (b, after_b) = take_number_token(after_w)?;
    after_b.strip_prefix('%')?;
    Some((w, b))
}

fn find_ci(haystack: &str, needle_lower: &str) -> Option<usize> {
    let hay_lower = haystack.to_ascii_lowercase();
    hay_lower.find(needle_lower)
}

fn skip_ws(s: &str) -> &str {
    s.trim_start_matches(char::is_whitespace)
}

fn skip_optional_percent(s: &str) -> &str {
    s.strip_prefix('%').unwrap_or(s)
}

/// Takes a `[\d.]+` token (unsigned float) from the start of `s`.
fn take_number_token(s: &str) -> Option<(f64, &str)> {
    let end = s
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit() || *c == '.')
        .last()
        .map(|(i, c)| i + c.len_utf8())?;
    if end == 0 {
        return None;
    }
    let num = s[..end].parse::<f64>().ok()?;
    Some((num, &s[end..]))
}

/// Takes a `[\d.-]+` token (signed float, JS-regex-style char class — any
/// mix of digits, `.`, `-`) from the start of `s`.
fn take_signed_number_token(s: &str) -> Option<(f64, &str)> {
    let end = s
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit() || *c == '.' || *c == '-')
        .last()
        .map(|(i, c)| i + c.len_utf8())?;
    if end == 0 {
        return None;
    }
    let num = s[..end].parse::<f64>().ok()?;
    Some((num, &s[end..]))
}

/// Mirrors `parseRgb(color)`.
pub fn parse_rgb(color: Option<&str>) -> Option<Rgba> {
    let color = match color {
        None => return None,
        Some(c) if c == "transparent" => return None,
        Some(c) => c,
    };
    let idx = find_ci(color, "rgb(").or_else(|| find_ci(color, "rgba("))?;
    let prefix_len = if color[idx..].to_ascii_lowercase().starts_with("rgba(") {
        5
    } else {
        4
    };
    let rest = &color[idx + prefix_len..];
    let nums = split_leading_uints(rest, 3)?;
    // optional alpha: `(?:,\s*([\d.]+))?`
    let mut pos = 0usize;
    let bytes = rest.as_bytes();
    let mut digit_groups = 0;
    while digit_groups < 3 && pos < bytes.len() {
        if digit_groups > 0 {
            while pos < bytes.len() && (bytes[pos] == b',' || bytes[pos] == b' ') {
                pos += 1;
            }
        }
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        digit_groups += 1;
    }
    let after_rgb = &rest[pos..];
    let after_rgb = after_rgb.trim_start();
    let a = if let Some(r) = after_rgb.strip_prefix(',') {
        let r = r.trim_start();
        take_number_token(r).map(|(n, _)| n).unwrap_or(1.0)
    } else {
        1.0
    };
    Some(Rgba {
        r: nums[0] as f64,
        g: nums[1] as f64,
        b: nums[2] as f64,
        a,
    })
}

/// Mirrors `relativeLuminance({r,g,b})`.
pub fn relative_luminance(c: Rgba) -> f64 {
    let f = |v: f64| {
        let s = v / 255.0;
        if s <= 0.03928 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b)
}

/// Mirrors `contrastRatio(c1, c2)`.
pub fn contrast_ratio(c1: Rgba, c2: Rgba) -> f64 {
    let l1 = relative_luminance(c1);
    let l2 = relative_luminance(c2);
    (l1.max(l2) + 0.05) / (l1.min(l2) + 0.05)
}

/// Mirrors `parseGradientColors(bgImage)`.
pub fn parse_gradient_colors(bg_image: Option<&str>) -> Vec<Rgba> {
    let Some(bg_image) = bg_image else {
        return Vec::new();
    };
    if !bg_image.contains("gradient") {
        return Vec::new();
    }
    let mut colors = Vec::new();

    // rgba?\([^)]+\)
    let bytes = bg_image.as_bytes();
    let lower = bg_image.to_ascii_lowercase();
    let mut i = 0usize;
    while let Some(rel) = lower[i..].find("rgb") {
        let start = i + rel;
        // must be followed by optional 'a' then '('
        let mut j = start + 3;
        if lower.as_bytes().get(j) == Some(&b'a') {
            j += 1;
        }
        if lower.as_bytes().get(j) == Some(&b'(') {
            if let Some(close_rel) = bg_image[j..].find(')') {
                let close = j + close_rel;
                let segment = &bg_image[start..=close];
                if let Some(c) = parse_rgb(Some(segment)) {
                    colors.push(c);
                }
                i = close + 1;
                continue;
            } else {
                break;
            }
        }
        i = start + 3;
    }
    let _ = bytes;

    // #([0-9a-f]{6}|[0-9a-f]{3})\b  (case-insensitive)
    let chars: Vec<char> = bg_image.chars().collect();
    let mut k = 0usize;
    while k < chars.len() {
        if chars[k] == '#' {
            let hex_start = k + 1;
            let mut hex_end = hex_start;
            while hex_end < chars.len() && chars[hex_end].is_ascii_hexdigit() {
                hex_end += 1;
            }
            let len = hex_end - hex_start;
            if len >= 6 {
                let h: String = chars[hex_start..hex_start + 6].iter().collect();
                if let (Ok(r), Ok(g), Ok(b)) = (
                    u32::from_str_radix(&h[0..2], 16),
                    u32::from_str_radix(&h[2..4], 16),
                    u32::from_str_radix(&h[4..6], 16),
                ) {
                    colors.push(Rgba {
                        r: r as f64,
                        g: g as f64,
                        b: b as f64,
                        a: 1.0,
                    });
                }
                k = hex_start + 6;
                continue;
            } else if len == 3 {
                let h: String = chars[hex_start..hex_start + 3].iter().collect();
                let hc: Vec<char> = h.chars().collect();
                let double = |c: char| -> Option<u32> {
                    let s: String = [c, c].iter().collect();
                    u32::from_str_radix(&s, 16).ok()
                };
                if let (Some(r), Some(g), Some(b)) = (double(hc[0]), double(hc[1]), double(hc[2]))
                {
                    colors.push(Rgba {
                        r: r as f64,
                        g: g as f64,
                        b: b as f64,
                        a: 1.0,
                    });
                }
                k = hex_start + 3;
                continue;
            }
        }
        k += 1;
    }

    colors
}

/// Mirrors `hasChroma(c, threshold = 30)`.
pub fn has_chroma(c: Option<Rgba>, threshold: f64) -> bool {
    match c {
        None => false,
        Some(c) => (c.r.max(c.g).max(c.b) - c.r.min(c.g).min(c.b)) >= threshold,
    }
}

/// Mirrors `getHue(c)`.
pub fn get_hue(c: Option<Rgba>) -> f64 {
    let Some(c) = c else { return 0.0 };
    let r = c.r / 255.0;
    let g = c.g / 255.0;
    let b = c.b / 255.0;
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    if max == min {
        return 0.0;
    }
    let d = max - min;
    let h = if max == r {
        ((g - b) / d + if g < b { 6.0 } else { 0.0 }) / 6.0
    } else if max == g {
        ((b - r) / d + 2.0) / 6.0
    } else {
        ((r - g) / d + 4.0) / 6.0
    };
    (h * 360.0).round()
}

/// Mirrors `colorToHex(c)`.
pub fn color_to_hex(c: Option<Rgba>) -> String {
    let Some(c) = c else { return "?".to_string() };
    format!(
        "#{:02x}{:02x}{:02x}",
        c.r.round() as i64 as u8,
        c.g.round() as i64 as u8,
        c.b.round() as i64 as u8
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_and_transparent_are_neutral() {
        assert!(is_neutral_color(None));
        assert!(is_neutral_color(Some("transparent")));
    }

    #[test]
    fn rgb_spread_threshold() {
        assert!(is_neutral_color(Some("rgb(100, 100, 100)")));
        assert!(is_neutral_color(Some("rgb(100, 110, 120)"))); // spread 20 < 30
        assert!(!is_neutral_color(Some("rgb(100, 100, 200)"))); // spread 100
    }

    #[test]
    fn rgba_with_alpha_parses() {
        let c = parse_rgb(Some("rgba(10, 20, 30, 0.5)")).unwrap();
        assert_eq!(c, Rgba { r: 10.0, g: 20.0, b: 30.0, a: 0.5 });
    }

    #[test]
    fn rgb_without_alpha_defaults_to_one() {
        let c = parse_rgb(Some("rgb(1, 2, 3)")).unwrap();
        assert_eq!(c.a, 1.0);
    }

    #[test]
    fn parse_rgb_transparent_is_none() {
        assert!(parse_rgb(Some("transparent")).is_none());
        assert!(parse_rgb(None).is_none());
    }

    #[test]
    fn oklch_chroma_threshold() {
        assert!(is_neutral_color(Some("oklch(50% 0.01 200)")));
        assert!(!is_neutral_color(Some("oklch(50% 0.05 200)")));
    }

    #[test]
    fn lch_chroma_threshold() {
        assert!(is_neutral_color(Some("lch(50% 2 200)")));
        assert!(!is_neutral_color(Some("lch(50% 10 200)")));
    }

    #[test]
    fn oklab_hypot_threshold() {
        assert!(is_neutral_color(Some("oklab(50% 0.01 0.01)")));
        assert!(!is_neutral_color(Some("oklab(50% 0.1 0.1)")));
    }

    #[test]
    fn lab_hypot_threshold() {
        assert!(is_neutral_color(Some("lab(50% 1 1)")));
        assert!(!is_neutral_color(Some("lab(50% 20 20)")));
    }

    #[test]
    fn hsl_saturation_threshold() {
        assert!(is_neutral_color(Some("hsl(200, 5%, 50%)")));
        assert!(!is_neutral_color(Some("hsl(200, 50%, 50%)")));
        assert!(is_neutral_color(Some("hsla(200 5% 50% / 0.5)")));
    }

    #[test]
    fn hwb_threshold() {
        assert!(is_neutral_color(Some("hwb(200 45% 55%)"))); // w+b=100 -> 0 chroma
        assert!(!is_neutral_color(Some("hwb(200 10% 10%)"))); // chroma 0.8
    }

    #[test]
    fn unrecognized_format_is_not_neutral() {
        assert!(!is_neutral_color(Some("currentColor")));
        assert!(!is_neutral_color(Some("var(--accent)")));
    }

    #[test]
    fn relative_luminance_black_and_white() {
        let black = Rgba { r: 0.0, g: 0.0, b: 0.0, a: 1.0 };
        let white = Rgba { r: 255.0, g: 255.0, b: 255.0, a: 1.0 };
        assert!((relative_luminance(black) - 0.0).abs() < 1e-9);
        assert!((relative_luminance(white) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn contrast_ratio_black_white_is_21() {
        let black = Rgba { r: 0.0, g: 0.0, b: 0.0, a: 1.0 };
        let white = Rgba { r: 255.0, g: 255.0, b: 255.0, a: 1.0 };
        assert!((contrast_ratio(black, white) - 21.0).abs() < 1e-6);
        assert_eq!(contrast_ratio(black, white), contrast_ratio(white, black));
    }

    #[test]
    fn gradient_colors_extracts_rgb_and_hex() {
        let bg = "linear-gradient(to right, rgb(255, 0, 0), #00ff00, #03f)";
        let colors = parse_gradient_colors(Some(bg));
        assert_eq!(colors.len(), 3);
        assert_eq!(colors[0], Rgba { r: 255.0, g: 0.0, b: 0.0, a: 1.0 });
        assert_eq!(colors[1], Rgba { r: 0.0, g: 255.0, b: 0.0, a: 1.0 });
        assert_eq!(colors[2], Rgba { r: 0.0, g: 51.0, b: 255.0, a: 1.0 });
    }

    #[test]
    fn gradient_colors_no_gradient_keyword_is_empty() {
        assert!(parse_gradient_colors(Some("rgb(255,0,0)")).is_empty());
        assert!(parse_gradient_colors(None).is_empty());
    }

    #[test]
    fn has_chroma_default_threshold() {
        let gray = Rgba { r: 100.0, g: 100.0, b: 100.0, a: 1.0 };
        let tinted = Rgba { r: 100.0, g: 100.0, b: 200.0, a: 1.0 };
        assert!(!has_chroma(Some(gray), 30.0));
        assert!(has_chroma(Some(tinted), 30.0));
        assert!(!has_chroma(None, 30.0));
    }

    #[test]
    fn get_hue_primary_colors() {
        let red = Rgba { r: 255.0, g: 0.0, b: 0.0, a: 1.0 };
        let green = Rgba { r: 0.0, g: 255.0, b: 0.0, a: 1.0 };
        let blue = Rgba { r: 0.0, g: 0.0, b: 255.0, a: 1.0 };
        let gray = Rgba { r: 50.0, g: 50.0, b: 50.0, a: 1.0 };
        assert_eq!(get_hue(Some(red)), 0.0);
        assert_eq!(get_hue(Some(green)), 120.0);
        assert_eq!(get_hue(Some(blue)), 240.0);
        assert_eq!(get_hue(Some(gray)), 0.0);
        assert_eq!(get_hue(None), 0.0);
    }

    #[test]
    fn color_to_hex_round_trips() {
        let c = Rgba { r: 255.0, g: 0.0, b: 51.0, a: 1.0 };
        assert_eq!(color_to_hex(Some(c)), "#ff0033");
        assert_eq!(color_to_hex(None), "?");
    }
}
