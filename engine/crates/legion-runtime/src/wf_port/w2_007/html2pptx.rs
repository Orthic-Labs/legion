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

// ---------------------------------------------------------------------------
// Live-DOM layout walk (packet r01: closes the `page.evaluate` gap noted
// in the module doc above) + PPTX (OOXML zip) output.
// ---------------------------------------------------------------------------

/// I/O boundary for the browser this module drives. `extractSlideData` and
/// `getBodyDimensions` in the JS are `page.evaluate(...)` calls that run
/// literal JS in a live Chromium tab; this trait is that same boundary in
/// Rust. Tests implement it with a fake that returns canned JSON, so no
/// test launches a real browser or touches the network, matching the
/// packet r01 rule.
pub trait PageDriver {
    /// Port of `page.goto(\`file://${filePath}\`)`.
    fn navigate_file(&mut self, path: &std::path::Path) -> Result<(), String>;
    /// Port of `page.setViewportSize({ width, height })`.
    fn set_viewport(&mut self, width: u32, height: u32) -> Result<(), String>;
    /// Port of `page.evaluate(fn)`: runs `script` (an IIFE that returns a
    /// JSON-serializable value, exactly like the JS closures this module
    /// mirrors) and returns its result already parsed as JSON.
    fn evaluate_json(&mut self, script: &str) -> Result<serde_json::Value, String>;
}

/// The `getBodyDimensions` `page.evaluate` closure, transcribed verbatim
/// (only wrapped in an IIFE so it can be sent as one `evaluate` call).
const BODY_DIMENSIONS_JS: &str = r#"(() => {
  const body = document.body;
  const style = window.getComputedStyle(body);
  return {
    width: parseFloat(style.width),
    height: parseFloat(style.height),
    scrollWidth: body.scrollWidth,
    scrollHeight: body.scrollHeight
  };
})()"#;

/// The `extractSlideData` `page.evaluate` closure, transcribed verbatim
/// from `html2pptx.js` (same variable names, same regexes, same DOM walk)
/// so that running it inside a real Chromium tab produces exactly the
/// `{ background, elements, placeholders, errors }` shape the JS produces.
/// This is the live-DOM layout walk: it needs a real CSS box model and
/// `getComputedStyle`, which only a real browser engine has, so it is run
/// through `PageDriver::evaluate_json` (a `HeadlessChromeDriver` in
/// production) rather than reimplemented as a Rust CSS engine.
pub const EXTRACT_SLIDE_DATA_JS: &str = include_str!("html2pptx_extract.js");

/// Body dimensions, port of `getBodyDimensions`'s DOM-derived fields
/// (the overflow-error computation itself lives in [`body_overflow_errors`]).
#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub struct BodyDimensions {
    pub width: f64,
    pub height: f64,
    #[serde(rename = "scrollWidth")]
    pub scroll_width: f64,
    #[serde(rename = "scrollHeight")]
    pub scroll_height: f64,
}

/// Port of the `{ background, elements, placeholders, errors }` object
/// `extractSlideData` returns. `elements` and `background` are kept as
/// `serde_json::Value` (typed just enough to route each element by its
/// `type` tag) because the JS itself is dynamically shaped per element
/// type — mirroring that shape in Rust is more faithful than forcing it
/// into one Rust enum the JS never had.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawSlideData {
    pub background: serde_json::Value,
    pub elements: Vec<serde_json::Value>,
    pub placeholders: Vec<RawPlaceholder>,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Port of one `placeholders` entry (`{ id, x, y, w, h }`, already in
/// inches).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RawPlaceholder {
    pub id: String,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

/// Port of `html2pptx()`'s outcome: the validated `slideData` plus the
/// `placeholders` array it returns to the caller (`{ slide, placeholders }`
/// in the JS — `slide` there is a live `pptxgenjs` object; here it is the
/// `.pptx` file this module writes instead, so the caller gets the
/// placeholders and the output path).
pub struct Html2PptxOutcome {
    pub slide_data: RawSlideData,
    pub placeholders: Vec<RawPlaceholder>,
}

/// Port of `html2pptx(htmlFile, pres, options)`'s browser-driving half:
/// navigate, measure the body, set the viewport to match, walk the DOM,
/// and run every validation pass in the same order as the JS
/// (`getBodyDimensions` overflow -> `validateDimensions` ->
/// `validateTextBoxPosition` -> `slideData.errors`), combining and
/// prefixing errors exactly like the JS `try`/`catch` does. `layout`
/// mirrors `pres.presLayout` (`None` when the caller passed no layout,
/// matching `pres.presLayout` being unset).
pub fn run_html2pptx<D: PageDriver>(
    driver: &mut D,
    html_file: &str,
    cwd: &std::path::Path,
    layout_width_in: Option<f64>,
    layout_height_in: Option<f64>,
) -> Result<Html2PptxOutcome, String> {
    let run = || -> Result<Html2PptxOutcome, String> {
        let file_path = resolve_html_file(html_file, cwd);
        driver.navigate_file(&file_path)?;

        let body_json = driver.evaluate_json(BODY_DIMENSIONS_JS)?;
        let body: BodyDimensions =
            serde_json::from_value(body_json).map_err(|e| format!("body dimensions: {e}"))?;

        driver.set_viewport(body.width.round() as u32, body.height.round() as u32)?;

        let slide_json = driver.evaluate_json(EXTRACT_SLIDE_DATA_JS)?;
        let slide_data: RawSlideData =
            serde_json::from_value(slide_json).map_err(|e| format!("slide data: {e}"))?;

        let mut validation_errors = body_overflow_errors(
            body.width,
            body.height,
            body.scroll_width,
            body.scroll_height,
        );

        let layout_w_emu = layout_width_in.map(|w| w * EMU_PER_IN);
        let layout_h_emu = layout_height_in.map(|h| h * EMU_PER_IN);
        validation_errors.extend(validate_dimensions(
            body.width,
            body.height,
            layout_w_emu,
            layout_h_emu,
        ));

        let slide_height_in = px_to_inch(body.height);
        let text_checks = text_box_checks_from_elements(&slide_data.elements);
        validation_errors.extend(validate_text_box_position(slide_height_in, &text_checks));

        validation_errors.extend(slide_data.errors.iter().cloned());

        if let Some(message) = combined_error_message(&validation_errors) {
            return Err(message);
        }

        let placeholders = slide_data.placeholders.clone();
        Ok(Html2PptxOutcome { slide_data, placeholders })
    };

    run().map_err(|message| prefix_error_with_file(html_file, &message))
}

/// Builds the [`TextBoxCheck`] list `validate_text_box_position` needs
/// from the raw JSON `elements`, mirroring the JS's inline `getText()`
/// closure (string `text`, array-of-runs `text`, or array `items`, first
/// non-empty entry).
fn text_box_checks_from_elements(elements: &[serde_json::Value]) -> Vec<TextBoxCheck<'_>> {
    let mut out = Vec::new();
    for el in elements {
        let type_tag = el.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if !TEXT_TYPE_TAGS.contains(&type_tag) {
            continue;
        }
        let font_size_pt = el
            .get("style")
            .and_then(|s| s.get("fontSize"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let position = el.get("position");
        let y = position.and_then(|p| p.get("y")).and_then(|v| v.as_f64()).unwrap_or(0.0);
        let h = position.and_then(|p| p.get("h")).and_then(|v| v.as_f64()).unwrap_or(0.0);
        out.push(OwnedTextBoxCheck {
            type_tag: type_tag.to_string(),
            font_size_pt,
            bottom_edge_in: y + h,
            text_prefix: extract_text_prefix(el),
        });
    }
    // `validate_text_box_position` borrows `&str`s; leak the small owned
    // strings into the vec's lifetime via a second pass so callers keep a
    // simple `&[TextBoxCheck]` signature identical to the pure-function API.
    out.into_iter()
        .map(|o| {
            let type_tag: &'static str = Box::leak(o.type_tag.into_boxed_str());
            let text_prefix: &'static str = Box::leak(o.text_prefix.into_boxed_str());
            TextBoxCheck { type_tag, font_size_pt: o.font_size_pt, bottom_edge_in: o.bottom_edge_in, text_prefix }
        })
        .collect()
}

struct OwnedTextBoxCheck {
    type_tag: String,
    font_size_pt: f64,
    bottom_edge_in: f64,
    text_prefix: String,
}

/// Port of the JS `getText()` closure inside `validateTextBoxPosition`:
/// string `text`, else first array-`text` run with non-empty `.text`,
/// else first `items` entry with non-empty `.text`, else `""`.
fn extract_text_prefix(el: &serde_json::Value) -> String {
    if let Some(s) = el.get("text").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(arr) = el.get("text").and_then(|v| v.as_array()) {
        if let Some(found) = arr.iter().find_map(|r| r.get("text").and_then(|t| t.as_str())) {
            return found.to_string();
        }
    }
    if let Some(arr) = el.get("items").and_then(|v| v.as_array()) {
        if let Some(found) = arr.iter().find_map(|r| r.get("text").and_then(|t| t.as_str())) {
            return found.to_string();
        }
    }
    String::new()
}

/// Production [`PageDriver`]: a real Chromium tab via the `headless_chrome`
/// crate (CDP), standing in for Playwright's `chromium.launch()` +
/// `browser.newPage()` in the JS. Kept out of unit tests entirely (tests
/// use a fake `PageDriver`), matching the packet r01 no-network/no-browser
/// test rule.
pub struct HeadlessChromeDriver {
    _browser: headless_chrome::Browser,
    tab: std::sync::Arc<headless_chrome::Tab>,
}

impl HeadlessChromeDriver {
    /// Port of `chromium.launch({ env: { TMPDIR }, channel: 'chrome' on
    /// darwin })`: launches a headless Chromium and opens one tab, the
    /// Rust equivalent of `browser.newPage()`.
    pub fn launch() -> Result<Self, String> {
        let browser = headless_chrome::Browser::default().map_err(|e| e.to_string())?;
        let tab = browser.new_tab().map_err(|e| e.to_string())?;
        Ok(Self { _browser: browser, tab })
    }
}

impl PageDriver for HeadlessChromeDriver {
    fn navigate_file(&mut self, path: &std::path::Path) -> Result<(), String> {
        let url = format!("file://{}", path.display());
        self.tab.navigate_to(&url).map_err(|e| e.to_string())?;
        self.tab.wait_until_navigated().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn set_viewport(&mut self, width: u32, height: u32) -> Result<(), String> {
        // Port of `page.setViewportSize`: pin the CDP device-metrics
        // override to the measured body size, exactly as Playwright's
        // viewport resize does before the DOM is walked.
        self.tab
            .call_method(headless_chrome::protocol::cdp::Emulation::SetDeviceMetricsOverride {
                width: width as u64,
                height: height as u64,
                device_scale_factor: 1.0,
                mobile: false,
                scale: None,
                screen_width: None,
                screen_height: None,
                position_x: None,
                position_y: None,
                dont_set_visible_size: None,
                screen_orientation: None,
                viewport: None,
                display_feature: None,
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn evaluate_json(&mut self, script: &str) -> Result<serde_json::Value, String> {
        let remote_object = self.tab.evaluate(script, true).map_err(|e| e.to_string())?;
        match remote_object.value {
            Some(v) => Ok(v),
            None => Ok(serde_json::Value::Null),
        }
    }
}

// ---------------------------------------------------------------------------
// PPTX (OOXML zip) output — Rust replacement for `pptxgenjs`.
// ---------------------------------------------------------------------------

/// Resolves an image reference (already stripped of a `file://` prefix,
/// same as the JS's `el.src.startsWith('file://') ? ... : ...`) to bytes
/// and a lowercase extension. Kept as a trait (rather than calling
/// `std::fs::read` directly from the writer) so unit tests can supply
/// fake image bytes without touching disk.
pub trait ImageSource {
    fn read(&mut self, path: &str) -> Result<(Vec<u8>, String), String>;
}

/// Production [`ImageSource`]: reads the file straight off disk, the Rust
/// equivalent of PptxGenJS's `addImage({ path })` resolving a local path.
pub struct FsImageSource;

impl ImageSource for FsImageSource {
    fn read(&mut self, path: &str) -> Result<(Vec<u8>, String), String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("png")
            .to_lowercase();
        Ok((bytes, ext))
    }
}

/// Strips a `file://` prefix, port of the repeated
/// `x.startsWith('file://') ? x.replace('file://', '') : x` idiom used for
/// both `background.path` and `el.src`.
fn strip_file_prefix(s: &str) -> &str {
    s.strip_prefix("file://").unwrap_or(s)
}

fn emu(inches: f64) -> i64 {
    (inches * EMU_PER_IN).round() as i64
}

fn pt_to_hundredths(pt: f64) -> i64 {
    (pt * 100.0).round() as i64
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// One resolved text run, flattened from either a plain string `text`
/// (single run, no options) or an array of `{ text, options }` runs —
/// the same two shapes `addElements`/`addText` accept in the JS.
#[derive(Debug, Clone, Default)]
struct Run {
    text: String,
    bold: bool,
    italic: bool,
    underline: bool,
    color: Option<String>,
    font_size_pt: Option<f64>,
    transparency: Option<i64>,
    break_line: bool,
}

fn runs_from_value(v: &serde_json::Value) -> Vec<Run> {
    if let Some(s) = v.as_str() {
        return vec![Run { text: s.to_string(), ..Default::default() }];
    }
    let mut out = Vec::new();
    if let Some(arr) = v.as_array() {
        for item in arr {
            let text = item.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let opts = item.get("options");
            let bold = opts.and_then(|o| o.get("bold")).and_then(|b| b.as_bool()).unwrap_or(false);
            let italic = opts.and_then(|o| o.get("italic")).and_then(|b| b.as_bool()).unwrap_or(false);
            let underline = opts.and_then(|o| o.get("underline")).and_then(|b| b.as_bool()).unwrap_or(false);
            let color = opts.and_then(|o| o.get("color")).and_then(|c| c.as_str()).map(String::from);
            let font_size_pt = opts.and_then(|o| o.get("fontSize")).and_then(|f| f.as_f64());
            let transparency = opts.and_then(|o| o.get("transparency")).and_then(|t| t.as_i64());
            let break_line = opts.and_then(|o| o.get("breakLine")).and_then(|b| b.as_bool()).unwrap_or(false);
            out.push(Run { text, bold, italic, underline, color, font_size_pt, transparency, break_line });
        }
    }
    out
}

/// Splits a flat run list into paragraphs, port of PptxGenJS's own
/// behaviour for an array of text runs: a run with `breakLine: true` ends
/// its paragraph (the next run starts a new one), and a literal `"\n"`
/// inside a run's text (from a `<br>`) also starts a new paragraph.
fn runs_to_paragraphs(runs: &[Run]) -> Vec<Vec<Run>> {
    let mut paragraphs: Vec<Vec<Run>> = vec![Vec::new()];
    for run in runs {
        let mut lines = run.text.split('\n').peekable();
        while let Some(line) = lines.next() {
            let mut r = run.clone();
            r.text = line.to_string();
            paragraphs.last_mut().unwrap().push(r);
            if lines.peek().is_some() {
                paragraphs.push(Vec::new());
            }
        }
        if run.break_line {
            paragraphs.push(Vec::new());
        }
    }
    if paragraphs.last().map(|p| p.is_empty()).unwrap_or(false) && paragraphs.len() > 1 {
        paragraphs.pop();
    }
    paragraphs
}

fn run_to_xml(run: &Run, base_font_pt: Option<f64>, base_color: Option<&str>) -> String {
    let sz = run.font_size_pt.or(base_font_pt).map(pt_to_hundredths);
    let color = run.color.as_deref().or(base_color);

    let mut r_pr = String::from("<a:rPr lang=\"en-US\" dirty=\"0\"");
    if let Some(sz) = sz {
        r_pr.push_str(&format!(" sz=\"{sz}\""));
    }
    if run.bold {
        r_pr.push_str(" b=\"1\"");
    }
    if run.italic {
        r_pr.push_str(" i=\"1\"");
    }
    if run.underline {
        r_pr.push_str(" u=\"sng\"");
    }

    let fill = color.map(|color| {
        let alpha = run
            .transparency
            .map(|t| format!("<a:alpha val=\"{}\"/>", ((100 - t).max(0)) * 1000))
            .unwrap_or_default();
        format!(
            "<a:solidFill><a:srgbClr val=\"{}\">{alpha}</a:srgbClr></a:solidFill>",
            color.trim_start_matches('#')
        )
    });

    match fill {
        Some(fill) => format!("<a:r>{r_pr}>{fill}</a:rPr><a:t>{}</a:t></a:r>", xml_escape(&run.text)),
        None => format!("<a:r>{r_pr}/><a:t>{}</a:t></a:r>", xml_escape(&run.text)),
    }
}

fn align_attr(align: Option<&str>) -> &'static str {
    match align {
        Some("center") => "ctr",
        Some("right") => "r",
        Some("justify") => "just",
        _ => "l",
    }
}

/// Builds the `<p:txBody>` for a text/shape/list/merged-text element from
/// its resolved paragraphs, port of the paragraph/run construction
/// `pptxgenjs`'s `addText` performs internally.
fn text_body_xml(paragraphs: &[Vec<Run>], align: Option<&str>, base_font_pt: Option<f64>, base_color: Option<&str>, inset0: bool) -> String {
    let body_pr = if inset0 {
        "<a:bodyPr wrap=\"square\" lIns=\"0\" tIns=\"0\" rIns=\"0\" bIns=\"0\" anchor=\"t\"><a:noAutofit/></a:bodyPr>"
    } else {
        "<a:bodyPr wrap=\"square\" anchor=\"t\"><a:noAutofit/></a:bodyPr>"
    };
    let mut xml = format!("<p:txBody>{body_pr}<a:lstStyle/>");
    if paragraphs.is_empty() {
        xml.push_str(&format!("<a:p><a:pPr algn=\"{}\"/></a:p>", align_attr(align)));
    }
    for para in paragraphs {
        xml.push_str(&format!("<a:p><a:pPr algn=\"{}\"/>", align_attr(align)));
        for run in para {
            xml.push_str(&run_to_xml(run, base_font_pt, base_color));
        }
        xml.push_str("</a:p>");
    }
    xml.push_str("</p:txBody>");
    xml
}

struct SlideBuilder<'a> {
    shapes_xml: String,
    next_id: u32,
    media: Vec<(String, Vec<u8>)>,
    image_rels: Vec<(String, String)>,
    image_source: &'a mut dyn ImageSource,
}

impl<'a> SlideBuilder<'a> {
    fn next_shape_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    fn add_image(&mut self, src: &str, x: f64, y: f64, w: f64, h: f64) -> Result<(), String> {
        let path = strip_file_prefix(src);
        let (bytes, ext) = self.image_source.read(path)?;
        let idx = self.media.len() + 1;
        let filename = format!("image{idx}.{ext}");
        self.media.push((filename.clone(), bytes));
        let id = self.next_shape_id();
        let rid = format!("rId{}", 1000 + idx); // offset clear of any layout/master rels
        self.shapes_xml.push_str(&format!(
            "<p:pic><p:nvPicPr><p:cNvPr id=\"{id}\" name=\"Picture {id}\"/><p:cNvPicPr/><p:nvPr/></p:nvPicPr>\
             <p:blipFill><a:blip r:embed=\"{rid}\"/><a:stretch><a:fillRect/></a:stretch></p:blipFill>\
             <p:spPr><a:xfrm><a:off x=\"{}\" y=\"{}\"/><a:ext cx=\"{}\" cy=\"{}\"/></a:xfrm>\
             <a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></p:spPr></p:pic>",
            emu(x), emu(y), emu(w), emu(h)
        ));
        self.image_rels.push((rid, filename));
        Ok(())
    }

    /// Port of the `line` branch in `addElements`: a straight connector.
    fn add_line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, color: Option<&str>, width_pt: f64) {
        let id = self.next_shape_id();
        let (x, y, cx, cy) = (x1.min(x2), y1.min(y2), (x2 - x1).abs().max(0.0001), (y2 - y1).abs().max(0.0001));
        let flip = if (x2 < x1) != (y2 < y1) { " flipV=\"1\"" } else { "" };
        let line_fill = color
            .map(|c| format!("<a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill>", c.trim_start_matches('#')))
            .unwrap_or_default();
        self.shapes_xml.push_str(&format!(
            "<p:cxnSp><p:nvCxnSpPr><p:cNvPr id=\"{id}\" name=\"Line {id}\"/><p:cNvCxnSpPr/><p:nvPr/></p:nvCxnSpPr>\
             <p:spPr><a:xfrm{flip}><a:off x=\"{}\" y=\"{}\"/><a:ext cx=\"{}\" cy=\"{}\"/></a:xfrm>\
             <a:prstGeom prst=\"line\"><a:avLst/></a:prstGeom><a:ln w=\"{}\">{line_fill}</a:ln></p:spPr>\
             <p:style/></p:cxnSp>",
            emu(x), emu(y), emu(cx), emu(cy), pt_to_emu_line_width(width_pt)
        ));
    }

    /// Port of the `shape` branch in `addElements`: a rect/roundRect with
    /// optional fill, line, rectRadius and shadow.
    #[allow(clippy::too_many_arguments)]
    fn add_shape(
        &mut self,
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        fill: Option<&str>,
        fill_transparency: Option<i64>,
        line_color: Option<&str>,
        line_width_pt: Option<f64>,
        rect_radius_in: f64,
        shadow: Option<&ShadowSpec>,
        text_paragraphs: &[Vec<Run>],
    ) {
        let id = self.next_shape_id();
        let prst = if rect_radius_in > 0.0 { "roundRect" } else { "rect" };
        let av_lst = if rect_radius_in > 0.0 {
            let adj = ((rect_radius_in / w.min(h).max(0.0001)) * 100_000.0).round() as i64;
            format!("<a:avLst><a:gd name=\"adj\" fmla=\"val {}\"/></a:avLst>", adj.clamp(0, 50_000))
        } else {
            "<a:avLst/>".to_string()
        };
        let mut sp_pr = format!(
            "<a:xfrm><a:off x=\"{}\" y=\"{}\"/><a:ext cx=\"{}\" cy=\"{}\"/></a:xfrm><a:prstGeom prst=\"{prst}\">{av_lst}</a:prstGeom>",
            emu(x), emu(y), emu(w), emu(h)
        );
        if let Some(fill) = fill {
            let alpha = fill_transparency
                .map(|t| format!("<a:alpha val=\"{}\"/>", ((100 - t).max(0)) * 1000))
                .unwrap_or_default();
            sp_pr.push_str(&format!(
                "<a:solidFill><a:srgbClr val=\"{}\">{alpha}</a:srgbClr></a:solidFill>",
                fill.trim_start_matches('#')
            ));
        } else {
            sp_pr.push_str("<a:noFill/>");
        }
        if let (Some(color), Some(width_pt)) = (line_color, line_width_pt) {
            sp_pr.push_str(&format!(
                "<a:ln w=\"{}\"><a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill></a:ln>",
                pt_to_emu_line_width(width_pt),
                color.trim_start_matches('#')
            ));
        } else {
            sp_pr.push_str("<a:ln><a:noFill/></a:ln>");
        }
        if let Some(shadow) = shadow {
            sp_pr.push_str(&format!(
                "<a:effectLst><a:outerShdw blurRad=\"{}\" dist=\"{}\" dir=\"{}\" rotWithShape=\"0\">\
                 <a:srgbClr val=\"{}\"><a:alpha val=\"{}\"/></a:srgbClr></a:outerShdw></a:effectLst>",
                pt_to_emu_line_width(shadow.blur),
                pt_to_emu_line_width(shadow.offset),
                (shadow.angle.clamp(0, 359) as i64) * 60_000,
                shadow.color.trim_start_matches('#'),
                (shadow.opacity.clamp(0.0, 1.0) * 100_000.0).round() as i64
            ));
        }
        let body = text_body_xml(text_paragraphs, None, None, None, false);
        self.shapes_xml.push_str(&format!(
            "<p:sp><p:nvSpPr><p:cNvPr id=\"{id}\" name=\"Shape {id}\"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>\
             <p:spPr>{sp_pr}</p:spPr><p:style/>{body}</p:sp>"
        ));
    }

    /// Port of the plain-text / list / merged-text branches of
    /// `addElements`: a text-only `<p:sp>` with no visible outline/fill.
    fn add_text_box(
        &mut self,
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        paragraphs: &[Vec<Run>],
        align: Option<&str>,
        base_font_pt: Option<f64>,
        base_color: Option<&str>,
        rotate_deg: Option<f64>,
        inset0: bool,
    ) {
        let id = self.next_shape_id();
        let rot = rotate_deg
            .map(|d| format!(" rot=\"{}\"", ((d * 60_000.0).round() as i64).rem_euclid(21_600_000)))
            .unwrap_or_default();
        let body = text_body_xml(paragraphs, align, base_font_pt, base_color, inset0);
        self.shapes_xml.push_str(&format!(
            "<p:sp><p:nvSpPr><p:cNvPr id=\"{id}\" name=\"TextBox {id}\"/><p:cNvSpPr txBox=\"1\"/><p:nvPr/></p:nvSpPr>\
             <p:spPr><a:xfrm{rot}><a:off x=\"{}\" y=\"{}\"/><a:ext cx=\"{}\" cy=\"{}\"/></a:xfrm>\
             <a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom><a:noFill/><a:ln><a:noFill/></a:ln></p:spPr>\
             <p:style/>{body}</p:sp>",
            emu(x), emu(y), emu(w), emu(h)
        ));
    }
}

fn pt_to_emu_line_width(pt: f64) -> i64 {
    // EMU per point = EMU_PER_IN / 72.
    (pt * (EMU_PER_IN / 72.0)).round() as i64
}

fn get_f64(v: &serde_json::Value, key: &str) -> Option<f64> {
    v.get(key).and_then(|x| x.as_f64())
}

fn get_str<'v>(v: &'v serde_json::Value, key: &str) -> Option<&'v str> {
    v.get(key).and_then(|x| x.as_str())
}

/// Port of the `position` sub-object shared by every element type.
fn get_position(el: &serde_json::Value) -> (f64, f64, f64, f64) {
    let p = el.get("position");
    (
        p.and_then(|p| get_f64(p, "x")).unwrap_or(0.0),
        p.and_then(|p| get_f64(p, "y")).unwrap_or(0.0),
        p.and_then(|p| get_f64(p, "w")).unwrap_or(0.0),
        p.and_then(|p| get_f64(p, "h")).unwrap_or(0.0),
    )
}

fn parse_shadow_from_json(v: &serde_json::Value) -> Option<ShadowSpec> {
    Some(ShadowSpec {
        angle: v.get("angle").and_then(|a| a.as_i64())?,
        blur: get_f64(v, "blur")?,
        color: get_str(v, "color")?.to_string(),
        offset: get_f64(v, "offset")?,
        opacity: get_f64(v, "opacity")?,
    })
}

/// Port of `addElements`: dispatches each raw JSON element to the matching
/// `SlideBuilder` call, one arm per `el.type` exactly like the JS
/// `if/else if` chain.
fn add_element(builder: &mut SlideBuilder<'_>, el: &serde_json::Value) -> Result<(), String> {
    let kind = get_str(el, "type").unwrap_or("");
    match kind {
        "image" => {
            let (x, y, w, h) = get_position(el);
            let src = get_str(el, "src").unwrap_or_default();
            builder.add_image(src, x, y, w, h)?;
        }
        "line" => {
            let x1 = get_f64(el, "x1").unwrap_or(0.0);
            let y1 = get_f64(el, "y1").unwrap_or(0.0);
            let x2 = get_f64(el, "x2").unwrap_or(0.0);
            let y2 = get_f64(el, "y2").unwrap_or(0.0);
            let color = get_str(el, "color");
            let width_pt = get_f64(el, "width").unwrap_or(1.0);
            builder.add_line(x1, y1, x2, y2, color, width_pt);
        }
        "shape" => {
            let (x, y, w, h) = get_position(el);
            let shape = el.get("shape");
            let fill = shape.and_then(|s| get_str(s, "fill"));
            let fill_transparency = shape.and_then(|s| s.get("transparency")).and_then(|t| t.as_i64());
            let line = shape.and_then(|s| s.get("line"));
            let line_color = line.and_then(|l| get_str(l, "color"));
            let line_width = line.and_then(|l| get_f64(l, "width"));
            let rect_radius = shape.and_then(|s| get_f64(s, "rectRadius")).unwrap_or(0.0);
            let shadow = shape.and_then(|s| s.get("shadow")).and_then(parse_shadow_from_json);
            let text = el.get("text").map(runs_from_value).unwrap_or_default();
            let paragraphs = runs_to_paragraphs(&text);
            builder.add_shape(x, y, w, h, fill, fill_transparency, line_color, line_width, rect_radius, shadow.as_ref(), &paragraphs);
        }
        "list" | "merged-text" => {
            let (x, y, w, h) = get_position(el);
            let style = el.get("style");
            let align = style.and_then(|s| get_str(s, "align"));
            let font_pt = style.and_then(|s| get_f64(s, "fontSize"));
            let color = style.and_then(|s| get_str(s, "color"));
            let items = el.get("items").map(runs_from_value).unwrap_or_default();
            let paragraphs = runs_to_paragraphs(&items);
            builder.add_text_box(x, y, w, h, &paragraphs, align, font_pt, color, None, kind == "merged-text");
        }
        "" => {}
        _ => {
            // Plain text element (p/h1..h6/etc — the JS uses the lowercase
            // tag name as `el.type`).
            let (x, y, w, h) = get_position(el);
            let style = el.get("style");
            let align = style.and_then(|s| get_str(s, "align"));
            let font_pt = style.and_then(|s| get_f64(s, "fontSize"));
            let color = style.and_then(|s| get_str(s, "color"));
            let rotate = style.and_then(|s| get_f64(s, "rotate"));
            let text = el.get("text").map(runs_from_value).unwrap_or_default();
            let paragraphs = runs_to_paragraphs(&text);
            builder.add_text_box(x, y, w, h, &paragraphs, align, font_pt, color, rotate, true);
        }
    }
    Ok(())
}

/// Port of `addBackground`: sets the slide's background fill or picture.
fn background_xml(background: &serde_json::Value, image_source: &mut dyn ImageSource, media: &mut Vec<(String, Vec<u8>)>) -> Result<String, String> {
    let kind = get_str(background, "type").unwrap_or("color");
    if kind == "image" {
        if let Some(path) = get_str(background, "path") {
            let (bytes, ext) = image_source.read(strip_file_prefix(path))?;
            let filename = format!("background.{ext}");
            media.push((filename.clone(), bytes));
            return Ok(String::from(
                "<p:bg><p:bgPr><a:blipFill><a:blip r:embed=\"rIdBg\"/><a:stretch><a:fillRect/></a:stretch></a:blipFill><a:effectLst/></p:bgPr></p:bg>",
            ));
        }
    }
    let color = get_str(background, "value").unwrap_or("FFFFFF");
    Ok(format!(
        "<p:bg><p:bgPr><a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill><a:effectLst/></p:bgPr></p:bg>",
        color.trim_start_matches('#')
    ))
}

/// Port of `html2pptx()`'s output half: `addBackground` + `addElements`
/// followed by `pres.writeFile()`. Where the JS hands a live `pptxgenjs`
/// slide object to those two helpers, this writes one complete, minimal
/// but valid single-slide `.pptx` (a zip of OOXML parts) directly, using
/// the `zip` crate — the Rust replacement for `pptxgenjs`'s own internal
/// zip writer.
pub fn write_pptx_from_slide_data(
    out_path: &std::path::Path,
    layout_width_in: f64,
    layout_height_in: f64,
    slide_data: &RawSlideData,
    image_source: &mut dyn ImageSource,
) -> Result<(), String> {
    let mut builder = SlideBuilder {
        shapes_xml: String::new(),
        next_id: 1,
        media: Vec::new(),
        image_rels: Vec::new(),
        image_source,
    };

    let mut bg_media: Vec<(String, Vec<u8>)> = Vec::new();
    let bg_xml = background_xml(&slide_data.background, builder.image_source, &mut bg_media)?;

    for el in &slide_data.elements {
        add_element(&mut builder, el)?;
    }

    let cx = emu(layout_width_in);
    let cy = emu(layout_height_in);

    let slide_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <p:sld xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
         xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
         xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
         <p:cSld>{bg_xml}<p:spTree><p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>\
         <p:grpSpPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/><a:chOff x=\"0\" y=\"0\"/><a:chExt cx=\"0\" cy=\"0\"/></a:xfrm></p:grpSpPr>\
         {}</p:spTree></p:cSld><p:clrMapOvr><a:overrideClrMapping bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" accent1=\"accent1\" accent2=\"accent2\" accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" hlink=\"hlink\" folHlink=\"folHlink\"/></p:clrMapOvr>\
         </p:sld>",
        builder.shapes_xml
    );

    let mut slide_rels = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/>",
    );
    if !bg_media.is_empty() {
        slide_rels.push_str(&format!(
            "<Relationship Id=\"rIdBg\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"../media/{}\"/>",
            bg_media[0].0
        ));
    }
    for (rid, filename) in &builder.image_rels {
        slide_rels.push_str(&format!(
            "<Relationship Id=\"{rid}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"../media/{filename}\"/>"
        ));
    }
    slide_rels.push_str("</Relationships>");

    let file = std::fs::File::create(out_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut write_part = |zip: &mut zip::ZipWriter<std::fs::File>, name: &str, content: &[u8]| -> Result<(), String> {
        zip.start_file(name, options).map_err(|e| e.to_string())?;
        std::io::Write::write_all(zip, content).map_err(|e| e.to_string())
    };

    write_part(&mut zip, "[Content_Types].xml", CONTENT_TYPES_XML.as_bytes())?;
    write_part(&mut zip, "_rels/.rels", PACKAGE_RELS_XML.as_bytes())?;
    write_part(&mut zip, "docProps/core.xml", CORE_PROPS_XML.as_bytes())?;
    write_part(&mut zip, "docProps/app.xml", APP_PROPS_XML.as_bytes())?;
    write_part(
        &mut zip,
        "ppt/presentation.xml",
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
             <p:presentation xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
             xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
             xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
             <p:sldMasterIdLst><p:sldMasterId id=\"2147483648\" r:id=\"rId1\"/></p:sldMasterIdLst>\
             <p:sldIdLst><p:sldId id=\"256\" r:id=\"rId2\"/></p:sldIdLst>\
             <p:sldSz cx=\"{cx}\" cy=\"{cy}\"/><p:notesSz cx=\"6858000\" cy=\"9144000\"/></p:presentation>"
        )
        .as_bytes(),
    )?;
    write_part(&mut zip, "ppt/_rels/presentation.xml.rels", PRESENTATION_RELS_XML.as_bytes())?;
    write_part(&mut zip, "ppt/theme/theme1.xml", THEME_XML.as_bytes())?;
    write_part(&mut zip, "ppt/slideMasters/slideMaster1.xml", SLIDE_MASTER_XML.as_bytes())?;
    write_part(&mut zip, "ppt/slideMasters/_rels/slideMaster1.xml.rels", SLIDE_MASTER_RELS_XML.as_bytes())?;
    write_part(&mut zip, "ppt/slideLayouts/slideLayout1.xml", SLIDE_LAYOUT_XML.as_bytes())?;
    write_part(&mut zip, "ppt/slideLayouts/_rels/slideLayout1.xml.rels", SLIDE_LAYOUT_RELS_XML.as_bytes())?;
    write_part(&mut zip, "ppt/slides/slide1.xml", slide_xml.as_bytes())?;
    write_part(&mut zip, "ppt/slides/_rels/slide1.xml.rels", slide_rels.as_bytes())?;

    for (filename, bytes) in bg_media.into_iter().chain(builder.media.into_iter()) {
        write_part(&mut zip, &format!("ppt/media/{filename}"), &bytes)?;
    }

    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

const CONTENT_TYPES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Default Extension="jpg" ContentType="image/jpeg"/>
<Default Extension="jpeg" ContentType="image/jpeg"/>
<Default Extension="gif" ContentType="image/gif"/>
<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"#;

const PACKAGE_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"#;

const CORE_PROPS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>html2pptx</dc:title>
<dc:creator>legion html2pptx (Rust port)</dc:creator>
</cp:coreProperties>"#;

const APP_PROPS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
<Application>legion-runtime html2pptx</Application>
<Slides>1</Slides>
</Properties>"#;

const PRESENTATION_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>
</Relationships>"#;

const THEME_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="html2pptx">
<a:themeElements>
<a:clrScheme name="html2pptx">
<a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>
<a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>
<a:dk2><a:srgbClr val="44546A"/></a:dk2>
<a:lt2><a:srgbClr val="E7E6E6"/></a:lt2>
<a:accent1><a:srgbClr val="4472C4"/></a:accent1>
<a:accent2><a:srgbClr val="ED7D31"/></a:accent2>
<a:accent3><a:srgbClr val="A5A5A5"/></a:accent3>
<a:accent4><a:srgbClr val="FFC000"/></a:accent4>
<a:accent5><a:srgbClr val="5B9BD5"/></a:accent5>
<a:accent6><a:srgbClr val="70AD47"/></a:accent6>
<a:hlink><a:srgbClr val="0563C1"/></a:hlink>
<a:folHlink><a:srgbClr val="954F72"/></a:folHlink>
</a:clrScheme>
<a:fontScheme name="html2pptx">
<a:majorFont><a:latin typeface="Calibri Light"/></a:majorFont>
<a:minorFont><a:latin typeface="Calibri"/></a:minorFont>
</a:fontScheme>
<a:fmtScheme name="html2pptx">
<a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>
<a:lnStyleLst><a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln w="12700"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>
<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>
<a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>
</a:fmtScheme>
</a:themeElements>
</a:theme>"#;

const SLIDE_MASTER_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill><a:effectLst/></p:bgPr></p:bg>
<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
</p:spTree></p:cSld>
<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
</p:sldMaster>"#;

const SLIDE_MASTER_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>"#;

const SLIDE_LAYOUT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank" preserve="1">
<p:cSld name="Blank">
<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
</p:spTree></p:cSld>
<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sldLayout>"#;

const SLIDE_LAYOUT_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>"#;

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

    // ---- packet r01: PageDriver orchestration + PPTX writer --------------

    struct FakeDriver {
        body: serde_json::Value,
        slide: serde_json::Value,
        navigated: Vec<std::path::PathBuf>,
        viewport: Option<(u32, u32)>,
    }

    impl PageDriver for FakeDriver {
        fn navigate_file(&mut self, path: &std::path::Path) -> Result<(), String> {
            self.navigated.push(path.to_path_buf());
            Ok(())
        }
        fn set_viewport(&mut self, width: u32, height: u32) -> Result<(), String> {
            self.viewport = Some((width, height));
            Ok(())
        }
        fn evaluate_json(&mut self, script: &str) -> Result<serde_json::Value, String> {
            if script == BODY_DIMENSIONS_JS {
                Ok(self.body.clone())
            } else {
                Ok(self.slide.clone())
            }
        }
    }

    fn ok_slide_json() -> serde_json::Value {
        serde_json::json!({
            "background": { "type": "color", "value": "112233" },
            "elements": [{
                "type": "p",
                "text": "Hello",
                "position": { "x": 1.0, "y": 1.0, "w": 3.0, "h": 0.5 },
                "style": { "fontSize": 18.0, "color": "000000", "align": "left" }
            }],
            "placeholders": [{ "id": "chart-1", "x": 0.5, "y": 0.5, "w": 2.0, "h": 2.0 }],
            "errors": []
        })
    }

    #[test]
    fn run_html2pptx_navigates_sets_viewport_and_returns_placeholders() {
        let mut driver = FakeDriver {
            body: serde_json::json!({ "width": 1280.0, "height": 720.0, "scrollWidth": 1280.0, "scrollHeight": 720.0 }),
            slide: ok_slide_json(),
            navigated: Vec::new(),
            viewport: None,
        };
        let outcome = run_html2pptx(&mut driver, "slide.html", std::path::Path::new("/decks"), None, None)
            .expect("no validation errors");
        assert_eq!(driver.navigated, vec![std::path::PathBuf::from("/decks/slide.html")]);
        assert_eq!(driver.viewport, Some((1280, 720)));
        assert_eq!(outcome.placeholders.len(), 1);
        assert_eq!(outcome.placeholders[0].id, "chart-1");
        assert_eq!(outcome.slide_data.elements.len(), 1);
    }

    #[test]
    fn run_html2pptx_combines_and_prefixes_validation_errors() {
        let mut driver = FakeDriver {
            // scrollWidth/scrollHeight overflow the body -> one error;
            // layout mismatch below -> a second error.
            body: serde_json::json!({ "width": 1280.0, "height": 720.0, "scrollWidth": 1300.0, "scrollHeight": 720.0 }),
            slide: ok_slide_json(),
            navigated: Vec::new(),
            viewport: None,
        };
        let err = run_html2pptx(&mut driver, "slide.html", std::path::Path::new("/decks"), Some(20.0), Some(11.25))
            .unwrap_err();
        assert!(err.starts_with("slide.html: "));
        assert!(err.contains("Multiple validation errors found") || err.contains("overflows body"));
    }

    #[test]
    fn run_html2pptx_flags_text_box_too_close_to_bottom() {
        let mut driver = FakeDriver {
            body: serde_json::json!({ "width": 960.0, "height": 540.0, "scrollWidth": 960.0, "scrollHeight": 540.0 }),
            slide: serde_json::json!({
                "background": { "type": "color", "value": "FFFFFF" },
                "elements": [{
                    "type": "p",
                    "text": "near the bottom edge",
                    "position": { "x": 0.5, "y": 5.4, "w": 3.0, "h": 0.3 },
                    "style": { "fontSize": 18.0, "color": "000000" }
                }],
                "placeholders": [],
                "errors": []
            }),
            navigated: Vec::new(),
            viewport: None,
        };
        let err = run_html2pptx(&mut driver, "slide.html", std::path::Path::new("/decks"), None, None).unwrap_err();
        assert!(err.contains("too close to bottom edge"));
    }

    struct FakeImages(std::collections::HashMap<&'static str, (Vec<u8>, &'static str)>);

    impl ImageSource for FakeImages {
        fn read(&mut self, path: &str) -> Result<(Vec<u8>, String), String> {
            self.0
                .get(path)
                .map(|(bytes, ext)| (bytes.clone(), ext.to_string()))
                .ok_or_else(|| format!("no fake image for {path}"))
        }
    }

    #[test]
    fn write_pptx_from_slide_data_produces_a_valid_zip_with_expected_parts() {
        let slide_data = RawSlideData {
            background: serde_json::json!({ "type": "color", "value": "112233" }),
            elements: vec![
                serde_json::json!({
                    "type": "p",
                    "text": "Hello world",
                    "position": { "x": 1.0, "y": 1.0, "w": 3.0, "h": 0.5 },
                    "style": { "fontSize": 18.0, "color": "000000", "align": "center" }
                }),
                serde_json::json!({
                    "type": "shape",
                    "text": "",
                    "position": { "x": 0.2, "y": 0.2, "w": 2.0, "h": 1.0 },
                    "shape": { "fill": "FF0000", "transparency": 10, "line": null, "rectRadius": 0.1, "shadow": null }
                }),
                serde_json::json!({
                    "type": "image",
                    "src": "file:///tmp/pic.png",
                    "position": { "x": 4.0, "y": 1.0, "w": 1.0, "h": 1.0 }
                }),
            ],
            placeholders: vec![RawPlaceholder { id: "ph1".into(), x: 0.0, y: 0.0, w: 1.0, h: 1.0 }],
            errors: vec![],
        };

        let mut images = FakeImages(std::collections::HashMap::from([(
            "/tmp/pic.png",
            (vec![0x89u8, 0x50, 0x4e, 0x47], "png"),
        )]));

        let dir = std::env::temp_dir().join(format!(
            "legion-w2007-r01-{}-{}",
            std::process::id(),
            {
                static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("slide.pptx");

        write_pptx_from_slide_data(&out, 13.333, 7.5, &slide_data, &mut images).expect("writes pptx");

        let file = std::fs::File::open(&out).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..zip.len()).map(|i| zip.by_index(i).unwrap().name().to_string()).collect();

        for expected in [
            "[Content_Types].xml",
            "_rels/.rels",
            "ppt/presentation.xml",
            "ppt/slides/slide1.xml",
            "ppt/slides/_rels/slide1.xml.rels",
            "ppt/slideMasters/slideMaster1.xml",
            "ppt/slideLayouts/slideLayout1.xml",
            "ppt/theme/theme1.xml",
            "ppt/media/image1.png",
        ] {
            assert!(names.contains(&expected.to_string()), "missing {expected}, got {names:?}");
        }

        let mut slide_xml = String::new();
        std::io::Read::read_to_string(&mut zip.by_name("ppt/slides/slide1.xml").unwrap(), &mut slide_xml).unwrap();
        assert!(slide_xml.contains("Hello world"));
        assert!(slide_xml.contains("srgbClr val=\"FF0000\""));
        assert!(slide_xml.contains("p:pic"));
        assert!(slide_xml.contains("roundRect"));

        let mut presentation_xml = String::new();
        std::io::Read::read_to_string(&mut zip.by_name("ppt/presentation.xml").unwrap(), &mut presentation_xml).unwrap();
        assert!(presentation_xml.contains(&format!("cx=\"{}\"", emu(13.333))));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn runs_to_paragraphs_splits_on_break_line_and_embedded_newline() {
        let runs = vec![
            Run { text: "line one".into(), break_line: true, ..Default::default() },
            Run { text: "line\ntwo".into(), ..Default::default() },
        ];
        let paragraphs = runs_to_paragraphs(&runs);
        assert_eq!(paragraphs.len(), 3);
        assert_eq!(paragraphs[0][0].text, "line one");
        assert_eq!(paragraphs[1][0].text, "line");
        assert_eq!(paragraphs[2][0].text, "two");
    }
}
