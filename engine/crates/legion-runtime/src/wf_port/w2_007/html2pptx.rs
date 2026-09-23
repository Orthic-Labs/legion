//! Port of `skills/designer/engine/huashu/scripts/html2pptx.js` (chunk
//! w2_007): converts an HTML slide into positioned PptxGenJS elements.
//!
//! `html2pptx` opens the HTML in a real Chromium (`playwright`), walks its
//! live DOM (`document.querySelectorAll('*')`, `getComputedStyle`,
//! `getBoundingClientRect`) inside `page.evaluate`, and hands the resulting
//! element list to `pptxgenjs`. The DOM walk and layout measurement need
//! an actual browser engine and a `pptxgenjs`-equivalent writer; neither
//! is reachable from this headless-engine crate (same boundary documented
//! in `export_deck_stage_pdf` and `w2_006::deck_stage`).
//!
//! What *is* ported, faithfully, is every pure computation the browser-side
//! code performs once it already has a CSS value in hand — the unit
//! conversions (`pxToInch`, `pxToPoints`), `rgbToHex`/`extractAlpha` color
//! parsing, `applyTextTransform`, the `getRotation` CSS-transform/matrix
//! parser, `parseBoxShadow`, the border-radius→`rectRadius` conversion, and
//! the three validation passes (`getBodyDimensions` overflow, layout-size
//! mismatch, text-box-too-close-to-bottom-edge). A host that already has
//! computed-style values from its own DOM source (a real browser via a
//! future CDP-backed executor, or a static HTML/CSS analyzer) can run this
//! module's functions directly on those values without reimplementing the
//! arithmetic or regexes.

/// `PT_PER_PX` / `PX_PER_IN` / `EMU_PER_IN` constants, verbatim.
pub const PT_PER_PX: f64 = 0.75;
pub const PX_PER_IN: f64 = 96.0;
pub const EMU_PER_IN: f64 = 914_400.0;

/// Port of `pxToInch`.
pub fn px_to_inch(px: f64) -> f64 {
    px / PX_PER_IN
}

/// Port of `pxToPoints`: `parseFloat(pxStr) * PT_PER_PX`. The caller
/// supplies the already-parsed pixel value (this port takes `f64` rather
/// than re-parsing a CSS string, since Rust callers hold typed values).
pub fn px_to_points(px: f64) -> f64 {
    px * PT_PER_PX
}

/// Port of `rgbToHex`. Handles the `rgba(0, 0, 0, 0)` / `"transparent"`
/// special case (defaults to white) and falls back to `"FFFFFF"` for any
/// string that doesn't match `rgba?\((\d+),\s*(\d+),\s*(\d+)`.
pub fn rgb_to_hex(rgb: &str) -> String {
    if rgb == "rgba(0, 0, 0, 0)" || rgb == "transparent" {
        return "FFFFFF".to_string();
    }
    match parse_rgb_components(rgb) {
        Some((r, g, b, _)) => format!("{r:02X}{g:02X}{b:02X}"),
        None => "FFFFFF".to_string(),
    }
}

/// Port of `extractAlpha`: only matches the 4-component `rgba(...)` form
/// (a plain `rgb(...)` has no alpha group, matching the JS regex requiring
/// a fourth captured group). Returns `Some(round((1 - alpha) * 100))`
/// (PptxGenJS "transparency" percent) or `None` when there is no alpha.
pub fn extract_alpha(rgb: &str) -> Option<i64> {
    let (_, _, _, alpha) = parse_rgb_components(rgb)?;
    let alpha = alpha?;
    Some(((1.0 - alpha) * 100.0).round() as i64)
}

/// Shared `rgba?\((\d+),\s*(\d+),\s*(\d+)(,\s*([\d.]+))?\)` parse used by
/// both `rgb_to_hex` and `extract_alpha`.
fn parse_rgb_components(rgb: &str) -> Option<(u8, u8, u8, Option<f64>)> {
    let inner = rgb.trim();
    let inner = inner
        .strip_prefix("rgba(")
        .or_else(|| inner.strip_prefix("rgb("))?;
    let inner = inner.strip_suffix(')')?;
    let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
    if parts.len() < 3 {
        return None;
    }
    let r: u8 = parts[0].parse().ok()?;
    let g: u8 = parts[1].parse().ok()?;
    let b: u8 = parts[2].parse().ok()?;
    let alpha = if parts.len() >= 4 {
        parts[3].parse::<f64>().ok()
    } else {
        None
    };
    Some((r, g, b, alpha))
}

/// Port of `applyTextTransform`.
pub fn apply_text_transform(text: &str, transform: &str) -> String {
    match transform {
        "uppercase" => text.to_uppercase(),
        "lowercase" => text.to_lowercase(),
        "capitalize" => capitalize_words(text),
        _ => text.to_string(),
    }
}

/// Port of `text.replace(/\b\w/g, c => c.toUpperCase())`: uppercase the
/// first word character following a word boundary (i.e. the first
/// alphanumeric/underscore char of each run of such chars).
fn capitalize_words(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_is_word = false;
    for c in text.chars() {
        let is_word = c.is_alphanumeric() || c == '_';
        if is_word && !prev_is_word {
            out.extend(c.to_uppercase());
        } else {
            out.push(c);
        }
        prev_is_word = is_word;
    }
    out
}

/// Port of `getRotation`'s writing-mode base angle.
pub fn writing_mode_angle(writing_mode: &str) -> f64 {
    match writing_mode {
        "vertical-rl" => 90.0,
        "vertical-lr" => 270.0,
        _ => 0.0,
    }
}

/// Port of `getRotation`'s `transform` contribution: a `rotate(Ndeg)`
/// match, else a `matrix(a, b, c, d, e, f)` match reduced via
/// `atan2(b, a)`, else `0`.
pub fn transform_rotation_delta(transform: &str) -> f64 {
    if transform.is_empty() || transform == "none" {
        return 0.0;
    }
    if let Some(deg) = extract_rotate_deg(transform) {
        return deg;
    }
    if let Some((a, b)) = extract_matrix_ab(transform) {
        return (b.atan2(a) * 180.0 / std::f64::consts::PI).round();
    }
    0.0
}

fn extract_rotate_deg(transform: &str) -> Option<f64> {
    let start = transform.find("rotate(")? + "rotate(".len();
    let rest = &transform[start..];
    let end = rest.find("deg)")?;
    rest[..end].trim().parse::<f64>().ok()
}

fn extract_matrix_ab(transform: &str) -> Option<(f64, f64)> {
    let start = transform.find("matrix(")? + "matrix(".len();
    let rest = &transform[start..];
    let end = rest.find(')')?;
    let values: Vec<f64> = rest[..end]
        .split(',')
        .map(|s| s.trim().parse::<f64>())
        .collect::<Result<_, _>>()
        .ok()?;
    if values.len() < 2 {
        return None;
    }
    Some((values[0], values[1]))
}

/// Port of `getRotation` end-to-end: writing-mode base + transform delta,
/// normalized into `[0, 360)`, with `0` mapped to `None` (the JS returns
/// `null` for "no rotation").
pub fn get_rotation(transform: &str, writing_mode: &str) -> Option<f64> {
    let mut angle = writing_mode_angle(writing_mode) + transform_rotation_delta(transform);
    angle %= 360.0;
    if angle < 0.0 {
        angle += 360.0;
    }
    if angle == 0.0 {
        None
    } else {
        Some(angle)
    }
}

/// Parsed `box-shadow` in PptxGenJS `shadow` shape, port of
/// `parseBoxShadow`. `blur` is already `* 0.75` (points); `offset` is the
/// hypotenuse distance in points; `opacity` defaults to `0.5` when the
/// color has no parseable alpha, exactly as the JS default does.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowSpec {
    pub angle: i64,
    pub blur: f64,
    pub color: String,
    pub offset: f64,
    pub opacity: f64,
}

/// Port of `parseBoxShadow`. Returns `None` for `"none"`/empty, for an
/// `inset` shadow (PptxGenJS doesn't support it — same early return as the
/// JS), or when fewer than two numeric px/pt values are found.
pub fn parse_box_shadow(box_shadow: &str) -> Option<ShadowSpec> {
    if box_shadow.is_empty() || box_shadow == "none" {
        return None;
    }
    if box_shadow.contains("inset") {
        return None;
    }

    let color_match = find_rgba_substring(box_shadow);
    let parts = find_length_values(box_shadow);
    if parts.len() < 2 {
        return None;
    }

    let offset_x = parts[0];
    let offset_y = parts[1];
    let blur = if parts.len() > 2 { parts[2] } else { 0.0 };

    let mut angle = 0.0;
    if offset_x != 0.0 || offset_y != 0.0 {
        angle = offset_y.atan2(offset_x) * 180.0 / std::f64::consts::PI;
        if angle < 0.0 {
            angle += 360.0;
        }
    }

    let offset = (offset_x * offset_x + offset_y * offset_y).sqrt() * PT_PER_PX;

    let mut opacity = 0.5;
    if let Some(color_str) = &color_match {
        if let Some(a) = trailing_alpha(color_str) {
            opacity = a;
        }
    }

    Some(ShadowSpec {
        angle: angle.round() as i64,
        blur: blur * 0.75,
        color: color_match.map(|c| rgb_to_hex(&c)).unwrap_or_else(|| "000000".to_string()),
        offset,
        opacity,
    })
}

/// Port of `boxShadow.match(/rgba?\([^)]+\)/)`: the first `rgb(...)` or
/// `rgba(...)` substring.
fn find_rgba_substring(s: &str) -> Option<String> {
    let start_rgba = s.find("rgba(");
    let start_rgb = s.find("rgb(");
    let start = match (start_rgba, start_rgb) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    let rest = &s[start..];
    let end = rest.find(')')?;
    Some(rest[..=end].to_string())
}

/// Port of `/[\d.]+\)$/` applied to the matched color string, i.e. the
/// alpha component of an `rgba(r, g, b, a)` string.
fn trailing_alpha(rgba: &str) -> Option<f64> {
    let (_, _, _, alpha) = parse_rgb_components(rgba)?;
    alpha
}

/// Port of `boxShadow.match(/([-\d.]+)(px|pt)/g)`: every `<number>(px|pt)`
/// token, in order, converted to a plain `f64` (unit is not distinguished,
/// matching the JS which parses both with `parseFloat` and never adjusts
/// for `pt` vs `px` here).
fn find_length_values(s: &str) -> Vec<f64> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let mut j = i;
        if bytes[j] == b'-' {
            j += 1;
        }
        let mut saw_digit = false;
        while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
            if bytes[j].is_ascii_digit() {
                saw_digit = true;
            }
            j += 1;
        }
        if saw_digit && (s[j..].starts_with("px") || s[j..].starts_with("pt")) {
            if let Ok(v) = s[start..j].parse::<f64>() {
                out.push(v);
            }
            i = j + 2;
            continue;
        }
        i = start + 1;
    }
    out
}

/// Port of the `rectRadius` IIFE shared by the DIV-shape and
/// `data-pptx-merge` branches: `%` → fraction of the min box dimension
/// (or `1` for a full circle at `>=50%`), `pt` → `/72`, else px → `/96`.
pub fn border_radius_to_rect_radius(radius_css: &str, box_w_px: f64, box_h_px: f64) -> f64 {
    let value = leading_number(radius_css);
    if value == 0.0 {
        return 0.0;
    }
    if radius_css.contains('%') {
        if value >= 50.0 {
            return 1.0;
        }
        let min_dim = box_w_px.min(box_h_px);
        return (value / 100.0) * px_to_inch(min_dim);
    }
    if radius_css.contains("pt") {
        return value / 72.0;
    }
    value / PX_PER_IN
}

fn leading_number(s: &str) -> f64 {
    let trimmed = s.trim();
    let end = trimmed
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_digit() || *c == '.' || *c == '-'))
        .map(|(i, _)| i)
        .unwrap_or(trimmed.len());
    trimmed[..end].parse().unwrap_or(0.0)
}

/// Body-dimension overflow check, port of `getBodyDimensions`'s error
/// computation (the DOM read itself is out of scope — the caller supplies
/// the four measured values).
pub fn body_overflow_errors(
    width: f64,
    height: f64,
    scroll_width: f64,
    scroll_height: f64,
) -> Vec<String> {
    let width_overflow_px = (scroll_width - width - 1.0).max(0.0);
    let height_overflow_px = (scroll_height - height - 1.0).max(0.0);
    let width_overflow_pt = width_overflow_px * PT_PER_PX;
    let height_overflow_pt = height_overflow_px * PT_PER_PX;

    let mut errors = Vec::new();
    if width_overflow_pt > 0.0 || height_overflow_pt > 0.0 {
        let mut directions = Vec::new();
        if width_overflow_pt > 0.0 {
            directions.push(format!("{width_overflow_pt:.1}pt horizontally"));
        }
        if height_overflow_pt > 0.0 {
            directions.push(format!("{height_overflow_pt:.1}pt vertically"));
        }
        let reminder = if height_overflow_pt > 0.0 {
            " (Remember: leave 0.5\" margin at bottom of slide)"
        } else {
            ""
        };
        errors.push(format!(
            "HTML content overflows body by {}{reminder}",
            directions.join(" and ")
        ));
    }
    errors
}

/// Port of `validateDimensions`: body px dimensions vs. a PptxGenJS
/// `presLayout` given in EMU, tolerating a 0.1" difference either way.
pub fn validate_dimensions(
    body_width_px: f64,
    body_height_px: f64,
    layout_width_emu: Option<f64>,
    layout_height_emu: Option<f64>,
) -> Vec<String> {
    let width_inches = px_to_inch(body_width_px);
    let height_inches = px_to_inch(body_height_px);
    let mut errors = Vec::new();

    if let (Some(lw_emu), Some(lh_emu)) = (layout_width_emu, layout_height_emu) {
        let layout_width = lw_emu / EMU_PER_IN;
        let layout_height = lh_emu / EMU_PER_IN;
        if (layout_width - width_inches).abs() > 0.1 || (layout_height - height_inches).abs() > 0.1 {
            errors.push(format!(
                "HTML dimensions ({width_inches:.1}\" \u{d7} {height_inches:.1}\") don't match presentation layout ({layout_width:.1}\" \u{d7} {layout_height:.1}\")"
            ));
        }
    }
    errors
}

/// One text element's fields relevant to `validateTextBoxPosition`: type
/// tag, font size (pt), and bottom edge (`y + h`, inches).
pub struct TextBoxCheck<'a> {
    pub type_tag: &'a str,
    pub font_size_pt: f64,
    pub bottom_edge_in: f64,
    pub text_prefix: &'a str,
}

/// Port of `validateTextBoxPosition`. Only checks elements whose type is
/// one of the text-bearing kinds; `min_bottom_margin` is `0.5`in as in the
/// JS constant.
pub const MIN_BOTTOM_MARGIN_IN: f64 = 0.5;

pub const TEXT_TYPE_TAGS: &[&str] = &["p", "h1", "h2", "h3", "h4", "h5", "h6", "list", "merged-text"];

pub fn validate_text_box_position(slide_height_in: f64, elements: &[TextBoxCheck]) -> Vec<String> {
    let mut errors = Vec::new();
    for el in elements {
        if !TEXT_TYPE_TAGS.contains(&el.type_tag) {
            continue;
        }
        let distance_from_bottom = slide_height_in - el.bottom_edge_in;
        if el.font_size_pt > 12.0 && distance_from_bottom < MIN_BOTTOM_MARGIN_IN {
            let prefix: String = el.text_prefix.chars().take(50).collect();
            let suffix = if el.text_prefix.chars().count() > 50 { "..." } else { "" };
            errors.push(format!(
                "Text box \"{prefix}{suffix}\" ends too close to bottom edge ({distance_from_bottom:.2}\" from bottom, minimum {MIN_BOTTOM_MARGIN_IN}\" required)"
            ));
        }
    }
    errors
}

/// Port of the manual-bullet-symbol validation regex
/// `/^[•\-\*▪▸○●◆◇■□]\s/` applied to `text.trimStart()`.
pub fn starts_with_manual_bullet(text: &str) -> bool {
    const BULLETS: &[char] = &['\u{2022}', '-', '*', '\u{25aa}', '\u{25b8}', '\u{25cb}', '\u{25cf}', '\u{25c6}', '\u{25c7}', '\u{25a0}', '\u{25a1}'];
    let trimmed = text.trim_start();
    let mut chars = trimmed.chars();
    match chars.next() {
        Some(c) if BULLETS.contains(&c) => matches!(chars.next(), Some(w) if w.is_whitespace()),
        _ => false,
    }
}

/// Port of `_safe`-adjacent path resolution helper in `html2pptx()`:
/// `path.isAbsolute(htmlFile) ? htmlFile : path.join(process.cwd(), htmlFile)`.
pub fn resolve_html_file(html_file: &str, cwd: &std::path::Path) -> std::path::PathBuf {
    let p = std::path::Path::new(html_file);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// Port of the combined-error message formatting at the end of
/// `html2pptx()`: a single error's message verbatim, or a numbered list
/// under `"Multiple validation errors found:"`.
pub fn combined_error_message(errors: &[String]) -> Option<String> {
    match errors.len() {
        0 => None,
        1 => Some(errors[0].clone()),
        _ => {
            let body = errors
                .iter()
                .enumerate()
                .map(|(i, e)| format!("  {}. {e}", i + 1))
                .collect::<Vec<_>>()
                .join("\n");
            Some(format!("Multiple validation errors found:\n{body}"))
        }
    }
}

/// Port of the top-level `catch (error)` prefixing:
/// `!error.message.startsWith(htmlFile) ? \`${htmlFile}: ${error.message}\` : error.message`.
pub fn prefix_error_with_file(html_file: &str, message: &str) -> String {
    if message.starts_with(html_file) {
        message.to_string()
    } else {
        format!("{html_file}: {message}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn px_conversions_match_constants() {
        assert_eq!(px_to_inch(96.0), 1.0);
        assert_eq!(px_to_points(1.0), 0.75);
    }

    #[test]
    fn rgb_to_hex_handles_transparent_and_named_cases() {
        assert_eq!(rgb_to_hex("rgba(0, 0, 0, 0)"), "FFFFFF");
        assert_eq!(rgb_to_hex("transparent"), "FFFFFF");
        assert_eq!(rgb_to_hex("rgb(255, 0, 128)"), "FF0080");
        assert_eq!(rgb_to_hex("rgba(255, 0, 128, 0.5)"), "FF0080");
        assert_eq!(rgb_to_hex("not-a-color"), "FFFFFF");
    }

    #[test]
    fn extract_alpha_only_for_rgba_with_alpha() {
        assert_eq!(extract_alpha("rgba(0, 0, 0, 0.25)"), Some(75));
        assert_eq!(extract_alpha("rgb(0, 0, 0)"), None);
        assert_eq!(extract_alpha("rgba(0, 0, 0, 1)"), Some(0));
    }

    #[test]
    fn apply_text_transform_matches_css_keywords() {
        assert_eq!(apply_text_transform("Hello World", "uppercase"), "HELLO WORLD");
        assert_eq!(apply_text_transform("Hello World", "lowercase"), "hello world");
        assert_eq!(apply_text_transform("hello world", "capitalize"), "Hello World");
        assert_eq!(apply_text_transform("Hello", "none"), "Hello");
    }

    #[test]
    fn get_rotation_combines_writing_mode_and_transform() {
        assert_eq!(get_rotation("none", "vertical-rl"), Some(90.0));
        assert_eq!(get_rotation("none", "vertical-lr"), Some(270.0));
        assert_eq!(get_rotation("rotate(45deg)", "horizontal-tb"), Some(45.0));
        assert_eq!(get_rotation("none", "horizontal-tb"), None);
    }

    #[test]
    fn get_rotation_parses_matrix_form() {
        // matrix for a 90deg rotation: a=cos90=0, b=sin90=1
        let r = get_rotation("matrix(0, 1, -1, 0, 0, 0)", "horizontal-tb").unwrap();
        assert!((r - 90.0).abs() < 1e-6);
    }

    #[test]
    fn get_rotation_normalizes_negative_and_over_360() {
        assert_eq!(get_rotation("rotate(-10deg)", "horizontal-tb"), Some(350.0));
        assert_eq!(get_rotation("rotate(370deg)", "horizontal-tb"), Some(10.0));
    }

    #[test]
    fn parse_box_shadow_rejects_none_and_inset() {
        assert_eq!(parse_box_shadow("none"), None);
        assert_eq!(parse_box_shadow(""), None);
        assert_eq!(
            parse_box_shadow("inset rgba(0,0,0,0.3) 2px 2px 8px 0px"),
            None
        );
    }

    #[test]
    fn parse_box_shadow_computes_angle_blur_offset() {
        let s = parse_box_shadow("rgba(0, 0, 0, 0.3) 2px 2px 8px 0px").unwrap();
        assert_eq!(s.angle, 45);
        assert!((s.blur - 6.0).abs() < 1e-6);
        assert_eq!(s.color, "000000");
        assert!((s.opacity - 0.3).abs() < 1e-6);
        let expected_offset = (2f64 * 2f64 + 2f64 * 2f64).sqrt() * PT_PER_PX;
        assert!((s.offset - expected_offset).abs() < 1e-6);
    }

    #[test]
    fn parse_box_shadow_defaults_opacity_without_alpha() {
        let s = parse_box_shadow("rgb(10, 20, 30) 1px 1px 2px").unwrap();
        assert!((s.opacity - 0.5).abs() < 1e-9);
    }

    #[test]
    fn border_radius_to_rect_radius_percent_and_units() {
        assert_eq!(border_radius_to_rect_radius("0px", 100.0, 100.0), 0.0);
        assert_eq!(border_radius_to_rect_radius("50%", 100.0, 100.0), 1.0);
        assert!((border_radius_to_rect_radius("25%", 200.0, 100.0) - 0.25 * px_to_inch(100.0)).abs() < 1e-9);
        assert_eq!(border_radius_to_rect_radius("36pt", 100.0, 100.0), 0.5);
        assert_eq!(border_radius_to_rect_radius("48px", 100.0, 100.0), 0.5);
    }

    #[test]
    fn body_overflow_errors_reports_both_directions() {
        let errors = body_overflow_errors(1920.0, 1080.0, 1925.0, 1100.0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("horizontally"));
        assert!(errors[0].contains("vertically"));
        assert!(errors[0].contains("0.5\" margin"));
    }

    #[test]
    fn body_overflow_errors_empty_when_no_overflow() {
        assert!(body_overflow_errors(1920.0, 1080.0, 1920.0, 1080.0).is_empty());
    }

    #[test]
    fn validate_dimensions_flags_mismatch_beyond_tolerance() {
        // 1920x1080 px @ 96dpi = 20in x 11.25in; layout EMU for 13.33x7.5in.
        let errors = validate_dimensions(1920.0, 1080.0, Some(13.33 * EMU_PER_IN), Some(7.5 * EMU_PER_IN));
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("don't match presentation layout"));
    }

    #[test]
    fn validate_dimensions_ok_within_tolerance() {
        let errors = validate_dimensions(1920.0, 1080.0, Some(20.0 * EMU_PER_IN), Some(11.25 * EMU_PER_IN));
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_text_box_position_flags_close_large_text() {
        let elements = vec![TextBoxCheck {
            type_tag: "p",
            font_size_pt: 18.0,
            bottom_edge_in: 10.9,
            text_prefix: "Some text here",
        }];
        let errors = validate_text_box_position(11.25, &elements);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Some text here"));
    }

    #[test]
    fn validate_text_box_position_ignores_small_font_or_non_text_type() {
        let elements = vec![
            TextBoxCheck { type_tag: "p", font_size_pt: 10.0, bottom_edge_in: 10.9, text_prefix: "x" },
            TextBoxCheck { type_tag: "image", font_size_pt: 18.0, bottom_edge_in: 10.9, text_prefix: "x" },
        ];
        assert!(validate_text_box_position(11.25, &elements).is_empty());
    }

    #[test]
    fn starts_with_manual_bullet_detects_and_rejects() {
        assert!(starts_with_manual_bullet("\u{2022} item one"));
        assert!(starts_with_manual_bullet("- dash item"));
        // Spec regex `/^[•\-\*▪▸○●◆◇■□]\s/` (html2pptx.js:1008) only checks
        // for the bullet char followed by whitespace; a hyphen followed by a
        // space matches regardless of what follows, so this string (which
        // does have a space after the leading `-`) also matches. Confirmed
        // against the JS regex directly.
        assert!(starts_with_manual_bullet("- not-a-bullet(no space)"));
        assert!(!starts_with_manual_bullet("not-a-bullet(no-space)"));
        assert!(!starts_with_manual_bullet("Regular text"));
    }

    #[test]
    fn combined_error_message_formats_single_and_multiple() {
        assert_eq!(combined_error_message(&[]), None);
        assert_eq!(
            combined_error_message(&["one error".to_string()]),
            Some("one error".to_string())
        );
        let multi = combined_error_message(&["a".to_string(), "b".to_string()]).unwrap();
        assert!(multi.starts_with("Multiple validation errors found:\n  1. a\n  2. b"));
    }

    #[test]
    fn prefix_error_with_file_avoids_double_prefix() {
        assert_eq!(
            prefix_error_with_file("slide.html", "boom"),
            "slide.html: boom"
        );
        assert_eq!(
            prefix_error_with_file("slide.html", "slide.html: already prefixed"),
            "slide.html: already prefixed"
        );
    }

    #[test]
    fn resolve_html_file_keeps_absolute_and_joins_relative() {
        let cwd = std::path::Path::new("/work");
        assert_eq!(
            resolve_html_file("slide.html", cwd),
            std::path::PathBuf::from("/work/slide.html")
        );
        assert_eq!(
            resolve_html_file("/abs/slide.html", cwd),
            std::path::PathBuf::from("/abs/slide.html")
        );
    }
}
