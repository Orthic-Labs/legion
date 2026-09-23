//! Port of `skills/designer/engine/scripts/detector/design-system.mjs`.
//!
//! Ported (pure, DOM-free):
//! - `parseFrontmatter` / the private `parseYamlSubset` YAML-subset parser
//!   → [`parse_frontmatter`] / [`FrontmatterValue`].
//! - `normalizeDesignSystem` → [`normalize_design_system`].
//! - `isAllowedFont` / `isAllowedColorRaw` / `isAllowedRadiusRaw` →
//!   [`is_allowed_font`] / [`is_allowed_color_raw`] / [`is_allowed_radius_raw`].
//! - `checkSourceDesignSystem` (the regex-driven scan over raw source text)
//!   → [`check_source_design_system`].
//! - `mergeDesignSystemFindings` / `dedupeDesignFindings` →
//!   [`merge_design_system_findings`] / [`dedupe_design_findings`].
//!
//! Reimplemented locally (not owned by this chunk, but needed as inputs):
//! `GENERIC_FONTS` (from `shared/constants.mjs`), `parseAnyColor` /
//! `resolveLengthPx` / `oklchToRgb` (from `rules/checks.mjs`), and
//! `finding()`'s field shape (from `findings.mjs`, minus the
//! `getAntipattern(id)` registry lookup this chunk does not own — see
//! [`DesignFinding`]'s doc comment).
//!
//! Not ported: `resolveDesignMdPath` / `resolveDesignSidecarPath` /
//! `safeReadJson` / `loadDesignSystemForCwd` (thin `fs`/`path` wrappers —
//! trivial to wire against whichever filesystem primitives the integrator
//! uses; [`normalize_design_system`] is the pure core they feed) and
//! `collectStaticDesignSystemFindings` / `shouldSkipStaticDesignElement` /
//! `hasDirectText` / `sampleText` (require a live DOM with computed styles;
//! see the module-level doc comment in `wf_port::w2_011`).

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

// ---------------------------------------------------------------------
// GENERIC_FONTS (shared/constants.mjs)
// ---------------------------------------------------------------------

fn generic_fonts() -> &'static [&'static str] {
    &[
        "serif",
        "sans-serif",
        "monospace",
        "cursive",
        "fantasy",
        "system-ui",
        "ui-serif",
        "ui-sans-serif",
        "ui-monospace",
        "ui-rounded",
        "-apple-system",
        "blinkmacsystemfont",
        "segoe ui",
        "inherit",
        "initial",
        "unset",
        "revert",
    ]
}

fn is_generic_font(font: &str) -> bool {
    generic_fonts().contains(&font)
}

// ---------------------------------------------------------------------
// YAML-subset frontmatter parser (parseFrontmatter / parseYamlSubset)
// ---------------------------------------------------------------------

/// A parsed frontmatter scalar/nesting value. Mirrors what `parseScalar` /
/// `parseYamlSubset` can produce: nested objects (`{}` when `rest === ''`
/// opens a new indented block), strings, booleans, `null`, and numbers
/// (integers and simple decimals only — the JS regexes `/^-?\d+$/` and
/// `/^-?\d*\.\d+$/` do not match scientific notation or `+`-prefixed
/// numbers, so those fall through to the `String` arm exactly as they do
/// in JS).
#[derive(Debug, Clone, PartialEq)]
pub enum FrontmatterValue {
    Object(HashMap<String, FrontmatterValue>),
    String(String),
    Bool(bool),
    Null,
    Number(f64),
}

impl FrontmatterValue {
    pub fn as_object(&self) -> Option<&HashMap<String, FrontmatterValue>> {
        match self {
            FrontmatterValue::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            FrontmatterValue::String(s) => Some(s),
            _ => None,
        }
    }
}

/// Port of `parseFrontmatter(md)`: requires the document to start with a
/// `---` line, find the closing `---` line, and parse the block between
/// them as the YAML subset. Returns `None` on a missing/unterminated
/// fence or a parse failure (JS: `try { ... } catch { return null; }`
/// around `parseYamlSubset`, which in this port cannot itself fail, so the
/// only `None` cases are the missing/unterminated fence).
pub fn parse_frontmatter(md: &str) -> Option<HashMap<String, FrontmatterValue>> {
    let lines: Vec<&str> = md.split(['\n']).collect();
    // JS splits on /\r?\n/; strip a trailing \r per line to match.
    let lines: Vec<&str> = lines.iter().map(|l| l.trim_end_matches('\r')).collect();
    if lines.first().map(|l| l.trim()) != Some("---") {
        return None;
    }
    let mut end: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.trim() == "---" {
            end = Some(i);
            break;
        }
    }
    let end = end?;
    let block = lines[1..end].join("\n");
    Some(parse_yaml_subset(&block))
}

/// Port of the private `parseYamlSubset(yaml)`.
fn parse_yaml_subset(yaml: &str) -> HashMap<String, FrontmatterValue> {
    struct Frame {
        indent: i64,
        // Path of keys from the root to this frame's object, used to
        // mutate the right nested map since Rust cannot hold aliasing
        // `&mut` references the way the JS closures do.
        path: Vec<String>,
    }

    let root: HashMap<String, FrontmatterValue> = HashMap::new();
    let mut stack: Vec<Frame> = vec![Frame {
        indent: -1,
        path: Vec::new(),
    }];
    let mut root = root;

    for raw in yaml.split(['\n']) {
        let raw = raw.trim_end_matches('\r');
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let content = &raw[indent..];
        let colon_idx = match find_top_level_colon(content) {
            Some(i) => i,
            None => continue,
        };

        while stack.len() > 1 && stack[stack.len() - 1].indent >= indent as i64 {
            stack.pop();
        }

        let key = unquote_yaml_key(content[..colon_idx].trim());
        let rest = strip_inline_yaml_comment(content[colon_idx + 1..].trim());
        let parent_path = stack[stack.len() - 1].path.clone();

        if rest.is_empty() {
            set_nested(&mut root, &parent_path, key.clone(), FrontmatterValue::Object(HashMap::new()));
            let mut child_path = parent_path;
            child_path.push(key);
            stack.push(Frame {
                indent: indent as i64,
                path: child_path,
            });
        } else {
            set_nested(&mut root, &parent_path, key, parse_scalar(rest));
        }
    }

    root
}

fn set_nested(
    root: &mut HashMap<String, FrontmatterValue>,
    path: &[String],
    key: String,
    value: FrontmatterValue,
) {
    let mut current = root;
    for segment in path {
        let entry = current
            .entry(segment.clone())
            .or_insert_with(|| FrontmatterValue::Object(HashMap::new()));
        match entry {
            FrontmatterValue::Object(m) => current = m,
            _ => {
                *entry = FrontmatterValue::Object(HashMap::new());
                match entry {
                    FrontmatterValue::Object(m) => current = m,
                    _ => unreachable!(),
                }
            }
        }
    }
    current.insert(key, value);
}

fn find_top_level_colon(s: &str) -> Option<usize> {
    let mut in_quote: Option<char> = None;
    let bytes: Vec<char> = s.chars().collect();
    for i in 0..bytes.len() {
        let ch = bytes[i];
        if let Some(q) = in_quote {
            if ch == q && (i == 0 || bytes[i - 1] != '\\') {
                in_quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        } else if ch == ':' {
            // byte index for &str slicing below; safe since we only slice
            // at char boundaries via `find_top_level_colon`'s callers that
            // re-derive from `.chars()` positions. Recompute as byte index.
            return Some(char_index_to_byte(s, i));
        }
    }
    None
}

fn char_index_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

fn unquote_yaml_key(key: &str) -> String {
    if (key.starts_with('"') && key.ends_with('"') && key.len() >= 2)
        || (key.starts_with('\'') && key.ends_with('\'') && key.len() >= 2)
    {
        key[1..key.len() - 1].to_string()
    } else {
        key.to_string()
    }
}

fn strip_inline_yaml_comment(s: &str) -> String {
    let mut in_quote: Option<char> = None;
    let chars: Vec<char> = s.chars().collect();
    for i in 0..chars.len() {
        let ch = chars[i];
        if let Some(q) = in_quote {
            if ch == q && (i == 0 || chars[i - 1] != '\\') {
                in_quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        } else if ch == '#' && i > 0 && chars[i - 1].is_whitespace() {
            let byte_i = char_index_to_byte(s, i);
            return s[..byte_i].trim_end().to_string();
        }
    }
    s.to_string()
}

fn parse_scalar(raw: &str) -> FrontmatterValue {
    let s = raw.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        return FrontmatterValue::String(s[1..s.len() - 1].to_string());
    }
    if s == "true" {
        return FrontmatterValue::Bool(true);
    }
    if s == "false" {
        return FrontmatterValue::Bool(false);
    }
    if s == "null" || s == "~" {
        return FrontmatterValue::Null;
    }
    if int_re().is_match(s) {
        if let Ok(n) = s.parse::<f64>() {
            return FrontmatterValue::Number(n);
        }
    }
    if decimal_re().is_match(s) {
        if let Ok(n) = s.parse::<f64>() {
            return FrontmatterValue::Number(n);
        }
    }
    FrontmatterValue::String(s.to_string())
}

fn int_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^-?\d+$").unwrap())
}
fn decimal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^-?\d*\.\d+$").unwrap())
}

// ---------------------------------------------------------------------
// Color parsing (subset of rules/checks.mjs needed here)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rgba {
    pub r: i32,
    pub g: i32,
    pub b: i32,
    pub a: f64,
}

fn oklch_to_rgb(l: f64, c: f64, h: f64) -> Rgba {
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
        let c = x.clamp(0.0, 1.0);
        if c <= 0.0031308 {
            12.92 * c
        } else {
            1.055 * c.powf(1.0 / 2.4) - 0.055
        }
    };
    Rgba {
        r: (enc(r_lin) * 255.0).round() as i32,
        g: (enc(g_lin) * 255.0).round() as i32,
        b: (enc(b_lin) * 255.0).round() as i32,
        a: 1.0,
    }
}

fn rgba_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)rgba?\(\s*(\d+(?:\.\d+)?)\s*,?\s*(\d+(?:\.\d+)?)\s*,?\s*(\d+(?:\.\d+)?)(?:\s*[,/]\s*([\d.]+))?\s*\)",
        )
        .unwrap()
    })
}
fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^#([0-9a-f]{3,8})$").unwrap())
}
fn oklch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)oklch\(\s*([\d.]+)(%?)\s*[\s,]*\s*([\d.]+)\s*[\s,]+\s*(-?[\d.]+)(?:deg)?(?:\s*/\s*([\d.]+)(%)?)?\s*\)",
        )
        .unwrap()
    })
}
fn hsl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)hsla?\(\s*(-?[\d.]+)(?:deg)?\s*,?\s*([\d.]+)%\s*,?\s*([\d.]+)%(?:\s*[,/]\s*([\d.]+))?\s*\)",
        )
        .unwrap()
    })
}

/// Port of `parseAnyColor(s)` (rgb/rgba/hex/oklch subset actually used by
/// this chunk).
fn parse_any_color(s: &str) -> Option<Rgba> {
    let str_ = s.trim();
    if str_ == "transparent" || str_.eq_ignore_ascii_case("currentcolor") || str_ == "inherit" {
        return None;
    }
    if let Some(m) = rgba_re().captures(str_) {
        return Some(Rgba {
            r: m[1].parse::<f64>().unwrap().round() as i32,
            g: m[2].parse::<f64>().unwrap().round() as i32,
            b: m[3].parse::<f64>().unwrap().round() as i32,
            a: m.get(4).map(|m| m.as_str().parse().unwrap()).unwrap_or(1.0),
        });
    }
    if let Some(m) = hex_re().captures(str_) {
        let h = &m[1];
        if h.len() == 3 || h.len() == 4 {
            let ch = |i: usize| i32::from_str_radix(&h[i..=i].repeat(2), 16).unwrap();
            return Some(Rgba {
                r: ch(0),
                g: ch(1),
                b: ch(2),
                a: if h.len() == 4 {
                    i32::from_str_radix(&h[3..4].repeat(2), 16).unwrap() as f64 / 255.0
                } else {
                    1.0
                },
            });
        }
        if h.len() == 6 || h.len() == 8 {
            let byte = |i: usize| i32::from_str_radix(&h[i..i + 2], 16).unwrap();
            return Some(Rgba {
                r: byte(0),
                g: byte(2),
                b: byte(4),
                a: if h.len() == 8 {
                    byte(6) as f64 / 255.0
                } else {
                    1.0
                },
            });
        }
    }
    if let Some(m) = oklch_re().captures(str_) {
        let l_num: f64 = m[1].parse().unwrap();
        let l = if m.get(2).map(|m| m.as_str()) == Some("%") {
            l_num / 100.0
        } else {
            l_num
        };
        let c: f64 = m[3].parse().unwrap();
        let h: f64 = m[4].parse().unwrap();
        let mut rgb = oklch_to_rgb(l, c, h);
        if let Some(alpha_m) = m.get(5) {
            let alpha: f64 = alpha_m.as_str().parse().unwrap();
            rgb.a = if m.get(6).is_some() { alpha / 100.0 } else { alpha };
        }
        return Some(rgb);
    }
    None
}

fn hsl_to_rgb(h: f64, s: f64, l: f64, alpha: f64) -> Rgba {
    let h = (((h % 360.0) + 360.0) % 360.0) / 360.0;
    let s = s.clamp(0.0, 1.0);
    let l = l.clamp(0.0, 1.0);
    let hue2rgb = |p: f64, q: f64, t: f64| {
        let mut t = t;
        if t < 0.0 {
            t += 1.0;
        }
        if t > 1.0 {
            t -= 1.0;
        }
        if t < 1.0 / 6.0 {
            return p + (q - p) * 6.0 * t;
        }
        if t < 0.5 {
            return q;
        }
        if t < 2.0 / 3.0 {
            return p + (q - p) * (2.0 / 3.0 - t) * 6.0;
        }
        p
    };
    let q = if l < 0.5 { l * (1.0 + s) } else { l + s - l * s };
    let p = 2.0 * l - q;
    Rgba {
        r: (hue2rgb(p, q, h + 1.0 / 3.0) * 255.0).round() as i32,
        g: (hue2rgb(p, q, h) * 255.0).round() as i32,
        b: (hue2rgb(p, q, h - 1.0 / 3.0) * 255.0).round() as i32,
        a: alpha,
    }
}

/// Port of `parseDesignColor(value)`.
fn parse_design_color(value: &str) -> Option<Rgba> {
    let text = value.trim();
    if let Some(c) = parse_any_color(text) {
        return Some(c);
    }
    if let Some(m) = hsl_re().captures(text) {
        return Some(hsl_to_rgb(
            m[1].parse().unwrap(),
            m[2].parse::<f64>().unwrap() / 100.0,
            m[3].parse::<f64>().unwrap() / 100.0,
            m.get(4).map(|a| a.as_str().parse().unwrap()).unwrap_or(1.0),
        ));
    }
    None
}

/// Port of `resolveLengthPx(value, fontSizePx)`.
fn resolve_length_px(value: &str, font_size_px: f64) -> Option<f64> {
    if value.is_empty() || value == "normal" || value == "auto" || value == "inherit" {
        return None;
    }
    let num = leading_number(value)?;
    if value.ends_with("px") {
        return Some(num);
    }
    if value.ends_with("rem") {
        return Some(num * 16.0);
    }
    if value.ends_with("em") {
        return Some(num * font_size_px);
    }
    if value.ends_with('%') {
        return Some((num / 100.0) * font_size_px);
    }
    Some(num * font_size_px)
}

/// Mirrors JS `parseFloat(value)`: parses a leading numeric prefix (with
/// optional sign/decimal), ignoring trailing non-numeric characters (e.g.
/// unit suffixes), and returns `None` where `parseFloat` would return `NaN`.
fn leading_number(value: &str) -> Option<f64> {
    let trimmed = value.trim_start();
    let mut end = 0usize;
    let bytes = trimmed.as_bytes();
    let mut i = 0usize;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        i += 1;
    }
    let mut seen_digit = false;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
        seen_digit = true;
        end = i;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        let dot = i;
        i += 1;
        let mut seen_frac_digit = false;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
            seen_frac_digit = true;
        }
        if seen_frac_digit {
            end = i;
        } else if !seen_digit {
            let _ = dot;
        }
    }
    if !seen_digit && end == 0 {
        return None;
    }
    trimmed[..end].parse::<f64>().ok()
}

// ---------------------------------------------------------------------
// DesignSystem (normalizeDesignSystem)
// ---------------------------------------------------------------------

const COLOR_CHANNEL_TOLERANCE: i32 = 6;
const RADIUS_TOLERANCE_PX: f64 = 0.5;

#[derive(Debug, Clone)]
pub struct RadiusEntry {
    pub name: String,
    pub value: String,
    pub px: f64,
}

#[derive(Debug, Clone)]
pub struct ColorEntry {
    pub color: Rgba,
    pub labels: Vec<String>,
}

/// Port of the object `normalizeDesignSystem` returns.
#[derive(Debug, Clone, Default)]
pub struct DesignSystem {
    pub present: bool,
    pub source_path: Option<String>,
    pub sidecar_path: Option<String>,
    pub md_newer_than_json: bool,
    pub allowed_fonts: std::collections::HashSet<String>,
    /// Keyed by `"r,g,b"` (mirrors JS `colorKey`).
    pub allowed_color_keys: HashMap<String, ColorEntry>,
    pub allowed_radii: Vec<RadiusEntry>,
    pub has_pill_radius: bool,
    pub has_fonts: bool,
    pub has_colors: bool,
    pub has_radii: bool,
}

fn color_key(c: &Rgba) -> String {
    format!("{},{},{}", c.r, c.g, c.b)
}

fn colors_close(a: &Rgba, b: &Rgba) -> bool {
    (a.r - b.r).abs().max((a.g - b.g).abs()).max((a.b - b.b).abs()) <= COLOR_CHANNEL_TOLERANCE
}

fn css_color_label(raw: &str) -> String {
    let mut out = String::new();
    let mut last_was_space = false;
    for ch in raw.trim().chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(ch);
            last_was_space = false;
        }
    }
    out
}

fn normalize_font_name(value: &str) -> String {
    let s = value.trim();
    let s = important_suffix_re().replace(s, "");
    let s = s.trim();
    let s = s.trim_matches(|c| c == '"' || c == '\'');
    let s = s.replace('+', " ");
    let s = whitespace_re().replace_all(&s, " ");
    s.trim().to_lowercase()
}

fn important_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\s*!important\s*$").unwrap())
}
fn whitespace_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+").unwrap())
}

fn split_font_stack(stack: &str) -> Vec<String> {
    let s = important_suffix_re().replace(stack, "");
    s.split(',')
        .map(|p| normalize_font_name(p))
        .filter(|s| !s.is_empty())
        .collect()
}

fn is_literal_font_stack(stack: &str) -> bool {
    !literal_font_stack_bad_re().is_match(stack)
}
fn literal_font_stack_bad_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[$`{}]|\s\+\s|\|\|").unwrap())
}

fn primary_font(stack: &str) -> String {
    if stack.is_empty() || stack.to_lowercase().contains("var(") || !is_literal_font_stack(stack) {
        return String::new();
    }
    split_font_stack(stack)
        .into_iter()
        .find(|f| !is_generic_font(f))
        .unwrap_or_default()
}

fn add_design_color(out: &mut DesignSystem, value: &str, label: &str) {
    let parsed = match parse_design_color(value) {
        Some(p) => p,
        None => return,
    };
    let key = color_key(&parsed);
    let entry = out
        .allowed_color_keys
        .entry(key)
        .or_insert_with(|| ColorEntry { color: parsed, labels: Vec::new() });
    let label = if label.is_empty() {
        css_color_label(value)
    } else {
        label.to_string()
    };
    entry.labels.push(label);
}

fn add_typography_fonts(out: &mut DesignSystem, typography: Option<&FrontmatterValue>) {
    let typography = match typography.and_then(FrontmatterValue::as_object) {
        Some(t) => t,
        None => return,
    };
    for role in typography.values() {
        let role = match role.as_object() {
            Some(r) => r,
            None => continue,
        };
        let font_family = match role.get("fontFamily").and_then(FrontmatterValue::as_str) {
            Some(f) => f,
            None => continue,
        };
        for font in split_font_stack(font_family) {
            if !is_generic_font(&font) {
                out.allowed_fonts.insert(font);
            }
        }
    }
}

fn add_color_object(out: &mut DesignSystem, colors: Option<&FrontmatterValue>, prefix: &str) {
    let colors = match colors.and_then(FrontmatterValue::as_object) {
        Some(c) => c,
        None => return,
    };
    for (name, value) in colors {
        if let Some(s) = value.as_str() {
            add_design_color(out, s, &format!("{prefix}.{name}"));
        }
    }
}

fn add_rounded_token(out: &mut DesignSystem, name: &str, value: &str) {
    let raw = value.trim();
    if raw.is_empty() || raw.to_lowercase().contains("var(") || raw.contains('%') {
        return;
    }
    let px = match resolve_length_px(raw, 16.0) {
        Some(p) if p.is_finite() => p,
        _ => return,
    };
    out.allowed_radii.push(RadiusEntry {
        name: name.to_string(),
        value: raw.to_string(),
        px,
    });
    if pill_name_re().is_match(&name.to_lowercase()) {
        out.has_pill_radius = true;
    }
}

fn pill_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(^|\.)(full|pill|round|rounded-full)$").unwrap())
}

fn add_rounded_token_num(out: &mut DesignSystem, name: &str, value: f64) {
    add_rounded_token(out, name, &format!("{value}"));
}

fn add_rounded_scale(out: &mut DesignSystem, rounded: Option<&FrontmatterValue>) {
    let rounded = match rounded.and_then(FrontmatterValue::as_object) {
        Some(r) => r,
        None => return,
    };
    for (raw_name, value) in rounded {
        let name = unquote_yaml_key(raw_name).to_lowercase();
        match value {
            FrontmatterValue::String(s) => add_rounded_token(out, &name, s),
            FrontmatterValue::Number(n) => add_rounded_token_num(out, &name, *n),
            _ => {}
        }
    }
}

/// Port of `normalizeDesignSystem(input)`.
///
/// `frontmatter` is `input.frontmatter || {}`; `sidecar_color_meta` /
/// `sidecar_rounded_meta` model `input.sidecar?.extensions?.colorMeta` and
/// `...roundedMeta` respectively (the JSON `DESIGN.json` sidecar's shape),
/// left as caller-supplied maps since JSON parsing is not owned by this
/// chunk.
pub fn normalize_design_system(
    frontmatter: &HashMap<String, FrontmatterValue>,
    source_path: Option<String>,
    sidecar_path: Option<String>,
    md_newer_than_json: bool,
) -> DesignSystem {
    let mut out = DesignSystem {
        present: true,
        source_path,
        sidecar_path,
        md_newer_than_json,
        ..Default::default()
    };

    add_typography_fonts(&mut out, frontmatter.get("typography"));
    add_color_object(&mut out, frontmatter.get("colors"), "colors");
    add_rounded_scale(&mut out, frontmatter.get("rounded"));

    out.has_fonts = !out.allowed_fonts.is_empty();
    out.has_colors = !out.allowed_color_keys.is_empty();
    out.has_radii = !out.allowed_radii.is_empty();
    out
}

/// Port of `isAllowedFont(font, designSystem)`.
pub fn is_allowed_font(font: &str, ds: Option<&DesignSystem>) -> bool {
    if font.is_empty() || is_generic_font(font) {
        return true;
    }
    match ds {
        Some(ds) if ds.has_fonts => ds.allowed_fonts.contains(font),
        _ => true,
    }
}

/// Port of `isAllowedColorRaw(raw, designSystem)`.
pub fn is_allowed_color_raw(raw: &str, ds: Option<&DesignSystem>) -> bool {
    let ds = match ds {
        Some(ds) if ds.has_colors => ds,
        _ => return true,
    };
    let text = raw.trim().to_lowercase();
    if text.is_empty()
        || text == "transparent"
        || text == "currentcolor"
        || text == "inherit"
        || text == "initial"
    {
        return true;
    }
    if text.contains("var(") {
        return true;
    }
    let parsed = match parse_design_color(&text) {
        Some(p) => p,
        None => return true,
    };
    if parsed.a <= 0.05 {
        return true;
    }
    ds.allowed_color_keys
        .values()
        .any(|entry| colors_close(&parsed, &entry.color))
}

/// Port of `isAllowedRadiusRaw(raw, designSystem)`.
pub fn is_allowed_radius_raw(raw: &str, ds: Option<&DesignSystem>) -> bool {
    let ds = match ds {
        Some(ds) if ds.has_radii => ds,
        _ => return true,
    };
    let text = raw.trim().to_lowercase();
    if text.is_empty() || text == "0" || text == "none" || text == "initial" || text == "inherit" {
        return true;
    }
    if text.contains("var(") || text.contains('%') {
        return true;
    }
    let px = match resolve_length_px(&text, 16.0) {
        Some(p) if p.is_finite() => p,
        _ => return true,
    };
    if px <= RADIUS_TOLERANCE_PX {
        return true;
    }
    if ds.has_pill_radius && px >= 99.0 {
        return true;
    }
    ds.allowed_radii
        .iter()
        .any(|entry| (entry.px - px).abs() <= RADIUS_TOLERANCE_PX)
}

// ---------------------------------------------------------------------
// Source scan (checkSourceDesignSystem)
// ---------------------------------------------------------------------

/// Minimal finding shape needed by this chunk's callers. Mirrors
/// `finding(id, filePath, snippet, line)`'s fields *except* `name` /
/// `description` / `severity`, which in JS come from `getAntipattern(id)`
/// — the antipattern registry, which is not owned by this chunk (see
/// `registry/antipatterns.mjs`, chunk-owned elsewhere). Callers that need
/// the full `name`/`description`/`severity` triad should look them up for
/// `antipattern` from that registry's Rust port and merge them in; this
/// struct carries everything `checkSourceDesignSystem` computes itself.
#[derive(Debug, Clone, PartialEq)]
pub struct DesignFinding {
    pub antipattern: String,
    pub file: String,
    pub snippet: String,
    pub line: u32,
    pub ignore_value: String,
}

fn font_decl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)font-family\s*:\s*([^;}\n]+)").unwrap())
}
fn font_js_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"fontFamily\s*[:=]\s*["'`]([^"'`]+)["'`]"#).unwrap())
}
fn google_font_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)fonts\.googleapis\.com/css2?\?[^"'\s)<>]*"#).unwrap()
    })
}
fn family_param_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[?&]family=([^&]+)").unwrap())
}
fn border_radius_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)border-radius\s*:\s*([^;}\n]+)").unwrap())
}
fn border_radius_js_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"borderRadius\s*[:=]\s*["'`]([^"'`]+)["'`]"#).unwrap())
}
fn css_color_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)#[0-9a-f]{3,8}\b|rgba?\([^)]+\)|oklch\([^)]+\)|hsla?\([^)]+\)").unwrap()
    })
}

fn line_looks_commented(line: &str) -> bool {
    let t = line.trim();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.starts_with("<!--")
}

fn decode_google_family(value: &str) -> String {
    let family = value.split(':').next().unwrap_or("").replace('+', " ");
    percent_decode(&family)
}

/// Minimal `decodeURIComponent`-equivalent for the `%XX` escapes Google
/// Fonts family params use; falls back to the input (mirrors the JS
/// `try { decodeURIComponent } catch { return family }`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

fn is_inside_css_attribute_selector(line: &str, index: usize) -> bool {
    if index == 0 && line.is_empty() {
        return false;
    }
    let before = &line[..index];
    let last_open = before.rfind('[');
    let last_open = match last_open {
        Some(v) => v,
        None => return false,
    };
    let last_close = before.rfind(']');
    if let Some(lc) = last_close {
        if lc > last_open {
            return false;
        }
    }
    let after = &line[index..];
    let close = after.find(']');
    let block = after.find('{');
    match (close, block) {
        (Some(c), Some(b)) => c < b,
        (Some(_), None) => true,
        _ => false,
    }
}

fn style_context_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:^|[{\s;"'`(,])(?:color|background(?:-color|-image)?|border(?:-(?:top|right|bottom|left))?(?:-color)?|outline(?:-color)?|box-shadow|text-shadow|fill|stroke)\s*:\s*[^;{}"'`]*"#).unwrap()
    })
}
fn css_function_context_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:linear-gradient|radial-gradient|conic-gradient|color-mix)\([^)]*$").unwrap())
}
fn js_color_key_context_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:^|[,{]\s*)(?:color|background|backgroundColor|borderColor|outlineColor|fill|stroke|boxShadow|textShadow)\s*[:=]\s*["'`]?[^"'`,}]*"#).unwrap()
    })
}

fn is_probably_color_literal(line: &str, raw: &str, index: usize) -> bool {
    if is_inside_css_attribute_selector(line, index) {
        return false;
    }
    let before = &line[..index];
    let after = &line[index + raw.len()..];

    if raw.starts_with('#') {
        if before.ends_with('&') {
            return false;
        }
        let prev_non_space = before.trim_end().chars().last();
        let next_non_space = after.trim_start().chars().next();
        if prev_non_space == Some('>') && next_non_space == Some('<') {
            return false;
        }
    }

    style_context_re().is_match(before)
        || css_function_context_re().is_match(before)
        || js_color_key_context_re().is_match(before)
}

fn extract_radius_tokens(value: &str) -> Vec<String> {
    value
        .replace(" / ", " ")
        .replace('/', " ")
        .split_whitespace()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn check_font_stack(
    stack: &str,
    file: &str,
    line: u32,
    ds: &DesignSystem,
    context: &str,
) -> Vec<DesignFinding> {
    let primary = primary_font(stack);
    if primary.is_empty() || is_allowed_font(&primary, Some(ds)) {
        return Vec::new();
    }
    let display = titlecase_first_letters(&primary);
    vec![DesignFinding {
        antipattern: "design-system-font".to_string(),
        file: file.to_string(),
        snippet: format!("{context}: {display} is not declared in DESIGN.md typography"),
        line,
        ignore_value: display,
    }]
}

fn titlecase_first_letters(s: &str) -> String {
    // Port of `primary.replace(/\b\w/g, ch => ch.toUpperCase())`.
    let mut out = String::with_capacity(s.len());
    let mut prev_is_word = false;
    for ch in s.chars() {
        let is_word = ch.is_alphanumeric() || ch == '_';
        if is_word && !prev_is_word {
            out.extend(ch.to_uppercase());
        } else {
            out.push(ch);
        }
        prev_is_word = is_word;
    }
    out
}

fn check_radius_value(
    value: &str,
    file: &str,
    line: u32,
    ds: &DesignSystem,
    context: &str,
) -> Vec<DesignFinding> {
    let mut findings = Vec::new();
    for token in extract_radius_tokens(value) {
        if is_allowed_radius_raw(&token, Some(ds)) {
            continue;
        }
        findings.push(DesignFinding {
            antipattern: "design-system-radius".to_string(),
            file: file.to_string(),
            snippet: format!("{context}: {token} is outside the DESIGN.md rounded scale"),
            line,
            ignore_value: token,
        });
    }
    findings
}

/// Port of `checkSourceDesignSystem(content, filePath, options)`.
/// `options.designSystem` maps to `ds`; `None` or `ds.present == false`
/// returns `[]` immediately, matching `if (!designSystem?.present) return [];`.
pub fn check_source_design_system(
    content: &str,
    file: &str,
    ds: Option<&DesignSystem>,
) -> Vec<DesignFinding> {
    let ds = match ds {
        Some(ds) if ds.present => ds,
        _ => return Vec::new(),
    };

    let mut findings = Vec::new();
    for (i, line) in content.split('\n').enumerate() {
        let line_num = (i + 1) as u32;
        if line_looks_commented(line) {
            continue;
        }

        if ds.has_fonts {
            for m in font_decl_re().captures_iter(line) {
                findings.extend(check_font_stack(&m[1], file, line_num, ds, "font-family"));
            }
            for m in font_js_re().captures_iter(line) {
                findings.extend(check_font_stack(&m[1], file, line_num, ds, "fontFamily"));
            }
            for m in google_font_re().find_iter(line) {
                let url = m.as_str();
                for fm in family_param_re().captures_iter(url) {
                    let font = normalize_font_name(&decode_google_family(&fm[1]));
                    if font.is_empty() || is_allowed_font(&font, Some(ds)) {
                        continue;
                    }
                    let display = decode_google_family(&fm[1]);
                    findings.push(DesignFinding {
                        antipattern: "design-system-font".to_string(),
                        file: file.to_string(),
                        snippet: format!(
                            "Google Fonts: {display} is not declared in DESIGN.md typography"
                        ),
                        line: line_num,
                        ignore_value: display,
                    });
                }
            }
        }

        if ds.has_colors {
            for m in css_color_re().find_iter(line) {
                if !is_probably_color_literal(line, m.as_str(), m.start()) {
                    continue;
                }
                let raw = css_color_label(m.as_str());
                if is_allowed_color_raw(&raw, Some(ds)) {
                    continue;
                }
                findings.push(DesignFinding {
                    antipattern: "design-system-color".to_string(),
                    file: file.to_string(),
                    snippet: format!("Undocumented color {raw} is outside DESIGN.md colors"),
                    line: line_num,
                    ignore_value: raw,
                });
            }
        }

        if ds.has_radii {
            for m in border_radius_re().captures_iter(line) {
                findings.extend(check_radius_value(&m[1], file, line_num, ds, "border-radius"));
            }
            for m in border_radius_js_re().captures_iter(line) {
                findings.extend(check_radius_value(&m[1], file, line_num, ds, "borderRadius"));
            }
        }
    }

    dedupe_design_findings(findings)
}

// ---------------------------------------------------------------------
// Merge / dedupe
// ---------------------------------------------------------------------

fn canonical_design_finding_key(item: &DesignFinding) -> Option<String> {
    if !item.antipattern.starts_with("design-system-") {
        return None;
    }
    let value = &item.ignore_value;
    if item.antipattern == "design-system-font" {
        let context = if item.snippet.to_lowercase().contains("google fonts") {
            "google-font"
        } else {
            "font"
        };
        let font = normalize_font_name(value);
        return if font.is_empty() {
            None
        } else {
            Some(format!("{}:{}:{}", item.antipattern, context, font))
        };
    }
    if item.antipattern == "design-system-color" {
        if let Some(parsed) = parse_design_color(value) {
            return Some(format!("{}:color:{}", item.antipattern, color_key(&parsed)));
        }
        let label = css_color_label(value).to_lowercase();
        return if label.is_empty() {
            None
        } else {
            Some(format!("{}:color:{}", item.antipattern, label))
        };
    }
    if item.antipattern == "design-system-radius" {
        if let Some(px) = resolve_length_px(value.trim(), 16.0) {
            if px.is_finite() {
                return Some(format!(
                    "{}:radius:{}",
                    item.antipattern,
                    (px * 100.0).round() / 100.0
                ));
            }
        }
        let label = value.trim().to_lowercase();
        return if label.is_empty() {
            None
        } else {
            Some(format!("{}:radius:{}", item.antipattern, label))
        };
    }
    None
}

/// Port of `mergeDesignSystemFindings(...groups)`.
pub fn merge_design_system_findings(groups: Vec<Vec<DesignFinding>>) -> Vec<DesignFinding> {
    let mut out: Vec<DesignFinding> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for group in groups {
        for item in group {
            if let Some(key) = canonical_design_finding_key(&item) {
                if let Some(&idx) = seen.get(&key) {
                    if out[idx].line == 0 && item.line != 0 {
                        out[idx].line = item.line;
                    }
                    continue;
                }
                seen.insert(key, out.len());
            }
            out.push(item);
        }
    }
    out
}

/// Port of `dedupeDesignFindings(findings)`.
pub fn dedupe_design_findings(findings: Vec<DesignFinding>) -> Vec<DesignFinding> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in findings {
        let ignore_or_snippet = if !item.ignore_value.is_empty() {
            &item.ignore_value
        } else {
            &item.snippet
        };
        let key = format!(
            "{}\0{}\0{}",
            item.antipattern,
            item.line,
            normalize_font_name(ignore_or_snippet)
        );
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        out.push(item);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fm(md: &str) -> HashMap<String, FrontmatterValue> {
        parse_frontmatter(md).expect("frontmatter should parse")
    }

    #[test]
    fn parse_frontmatter_requires_opening_and_closing_fence() {
        assert!(parse_frontmatter("no fence here").is_none());
        assert!(parse_frontmatter("---\nkey: value\n").is_none()); // unterminated
    }

    #[test]
    fn parse_frontmatter_parses_nested_scalars() {
        let m = fm("---\ncolors:\n  brand: \"#ff0000\"\n  accent: '#00ff00'\nrounded:\n  full: 999px\ntypography:\n  body:\n    fontFamily: \"Inter, sans-serif\"\nflag: true\nnothing: null\ncount: 3\nratio: 1.5\n---\nbody text\n");
        let colors = m["colors"].as_object().unwrap();
        assert_eq!(colors["brand"].as_str(), Some("#ff0000"));
        assert_eq!(colors["accent"].as_str(), Some("#00ff00"));
        assert_eq!(m["flag"], FrontmatterValue::Bool(true));
        assert_eq!(m["nothing"], FrontmatterValue::Null);
        assert_eq!(m["count"], FrontmatterValue::Number(3.0));
        assert_eq!(m["ratio"], FrontmatterValue::Number(1.5));
    }

    #[test]
    fn parse_frontmatter_strips_inline_comments_and_quoted_keys() {
        let m = fm("---\n\"quoted key\": value # a comment\nplain: raw # trailing\n---\n");
        assert_eq!(m["quoted key"].as_str(), Some("value"));
        assert_eq!(m["plain"].as_str(), Some("raw"));
    }

    #[test]
    fn normalize_design_system_collects_fonts_colors_radii() {
        let m = fm(
            "---\ntypography:\n  body:\n    fontFamily: \"Inter, sans-serif\"\ncolors:\n  brand: \"#336699\"\nrounded:\n  full: 999px\n  sm: 4px\n---\n",
        );
        let ds = normalize_design_system(&m, Some("DESIGN.md".to_string()), None, false);
        assert!(ds.has_fonts);
        assert!(ds.allowed_fonts.contains("inter"));
        assert!(ds.has_colors);
        assert!(ds.has_radii);
        assert!(ds.has_pill_radius); // "full" token
        assert!(is_allowed_font("inter", Some(&ds)));
        assert!(!is_allowed_font("comic sans ms", Some(&ds)));
        assert!(is_allowed_font("sans-serif", Some(&ds))); // generic always allowed
        assert!(is_allowed_color_raw("#336699", Some(&ds)));
        assert!(is_allowed_color_raw("#33669a", Some(&ds))); // within tolerance
        assert!(!is_allowed_color_raw("#ff00ff", Some(&ds)));
        assert!(is_allowed_radius_raw("4px", Some(&ds)));
        assert!(is_allowed_radius_raw("999px", Some(&ds))); // pill radius >= 99px
        assert!(!is_allowed_radius_raw("13px", Some(&ds)));
    }

    #[test]
    fn is_allowed_checks_pass_through_when_design_system_absent() {
        assert!(is_allowed_font("comic sans ms", None));
        assert!(is_allowed_color_raw("#ff00ff", None));
        assert!(is_allowed_radius_raw("13px", None));
    }

    #[test]
    fn check_source_design_system_flags_undeclared_font_and_color() {
        let m = fm("---\ntypography:\n  body:\n    fontFamily: \"Inter, sans-serif\"\ncolors:\n  brand: \"#336699\"\n---\n");
        let ds = normalize_design_system(&m, None, None, false);
        let css = "body { font-family: 'Comic Sans MS', sans-serif; color: #ff00ff; }\n";
        let findings = check_source_design_system(css, "styles.css", Some(&ds));
        assert!(findings.iter().any(|f| f.antipattern == "design-system-font"
            && f.ignore_value.eq_ignore_ascii_case("Comic Sans Ms")));
        assert!(findings
            .iter()
            .any(|f| f.antipattern == "design-system-color" && f.ignore_value == "#ff00ff"));
    }

    #[test]
    fn check_source_design_system_skips_commented_lines() {
        let m = fm("---\ncolors:\n  brand: \"#336699\"\n---\n");
        let ds = normalize_design_system(&m, None, None, false);
        let css = "// color: #ff00ff;\n";
        let findings = check_source_design_system(css, "a.js", Some(&ds));
        assert!(findings.is_empty());
    }

    #[test]
    fn check_source_design_system_empty_without_design_system() {
        let findings = check_source_design_system("color: #ff00ff;", "a.css", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn dedupe_removes_same_antipattern_line_and_value() {
        let a = DesignFinding {
            antipattern: "design-system-color".to_string(),
            file: "a.css".to_string(),
            snippet: "s".to_string(),
            line: 1,
            ignore_value: "#ff00ff".to_string(),
        };
        let b = a.clone();
        let out = dedupe_design_findings(vec![a, b]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn merge_prefers_first_seen_and_backfills_missing_line() {
        let first = DesignFinding {
            antipattern: "design-system-color".to_string(),
            file: "a.css".to_string(),
            snippet: "s".to_string(),
            line: 0,
            ignore_value: "#ff00ff".to_string(),
        };
        let second = DesignFinding {
            line: 5,
            ..first.clone()
        };
        let out = merge_design_system_findings(vec![vec![first], vec![second]]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].line, 5);
    }
}
