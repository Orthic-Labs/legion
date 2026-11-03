//! Port of the pure string/CSS-value parsing helpers in
//! `css-cascade.mjs` (chunk w2_012). The DOM/`csstree`-backed pieces
//! (`buildBorderOverrideMap`, `StaticElement`/`StaticDocument`,
//! `collectStaticCssRules`, `buildStaticStyleMap`, `collectStaticCssText`,
//! `normalizeStaticCssValue`/`computeNode` which need
//! `resolveVarRefs`/`resolveLengthPx` from the shared cascade module) are
//! not ported: they need a full HTML DOM and CSS-AST parser (`htmlparser2`
//! + `css-select` + `csstree` equivalents) this crate does not have, and
//!   have no return-value contract without one.
//!
//! Color parsing reuses this crate's existing
//! [`crate::l6_designer_checks::css_color::parse_any_color`] (the same
//! "one canonical parser" this repo already ported from
//! `rules/checks.mjs`) rather than re-deriving a second one, per this
//! chunk's method note that `parseAnyColor` here is imported from
//! `rules/checks.mjs` in the JS source.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::l6_designer_checks::css_color::parse_any_color;

// ---------------------------------------------------------------------------
// @layer unwrapping
// ---------------------------------------------------------------------------

fn at_layer_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"@layer\b[^{;]*\{").unwrap())
}

/// Port of `unwrapCssAtLayer(source)`: strips `@layer NAME { … }` wrappers,
/// leaving the inner rules as flat CSS, by balancing braces from each
/// opener. Returns `source` unchanged if it has no `@layer` or if any
/// opener's braces don't balance (matches the JS "bail and return source
/// unchanged" fallback).
pub fn unwrap_css_at_layer(source: &str) -> String {
    if source.is_empty() || !source.contains("@layer") {
        return source.to_string();
    }
    let bytes = source.as_bytes();
    let mut out = String::new();
    let mut last_idx = 0usize;
    let mut search_from = 0usize;
    while let Some(m) = at_layer_open_re().find_at(source, search_from) {
        let open_start = m.start();
        let open_end = m.end(); // position right after `{`
        let mut depth = 1i32;
        let mut i = open_end;
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            // Unbalanced — bail and return source unchanged.
            return source.to_string();
        }
        out.push_str(&source[last_idx..open_start]);
        out.push_str(&source[open_end..i - 1]);
        last_idx = i;
        search_from = i;
    }
    out.push_str(&source[last_idx..]);
    out
}

// ---------------------------------------------------------------------------
// Named-color normalization (buildBorderOverrideMap's local NAMED_COLORS)
// ---------------------------------------------------------------------------

pub const NAMED_COLORS: &[(&str, (u8, u8, u8))] = &[
    ("white", (255, 255, 255)),
    ("black", (0, 0, 0)),
    ("gray", (128, 128, 128)),
    ("grey", (128, 128, 128)),
    ("silver", (192, 192, 192)),
    ("red", (255, 0, 0)),
    ("green", (0, 128, 0)),
    ("blue", (0, 0, 255)),
    ("yellow", (255, 255, 0)),
];

fn hex6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$").unwrap())
}

fn hex3_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^#([0-9a-f])([0-9a-f])([0-9a-f])$").unwrap())
}

/// Port of `normalizeColorForCheck(value)`: hex/named colors become
/// `rgb(r, g, b)`; anything else (already-functional colors, `var()`,
/// unrecognized keywords) passes through unchanged.
pub fn normalize_color_for_check(value: &str) -> String {
    let v = value.trim();
    if v.is_empty() {
        return value.to_string();
    }
    if let Some(caps) = hex6_re().captures(v) {
        let r = u8::from_str_radix(&caps[1], 16).unwrap();
        let g = u8::from_str_radix(&caps[2], 16).unwrap();
        let b = u8::from_str_radix(&caps[3], 16).unwrap();
        return format!("rgb({r}, {g}, {b})");
    }
    if let Some(caps) = hex3_re().captures(v) {
        let dbl = |c: &str| u8::from_str_radix(&c.repeat(2), 16).unwrap();
        let r = dbl(&caps[1]);
        let g = dbl(&caps[2]);
        let b = dbl(&caps[3]);
        return format!("rgb({r}, {g}, {b})");
    }
    if let Some((_, (r, g, b))) = NAMED_COLORS
        .iter()
        .find(|(name, _)| *name == v.to_lowercase())
    {
        return format!("rgb({r}, {g}, {b})");
    }
    v.to_string()
}

// ---------------------------------------------------------------------------
// splitCssList / splitCssTokens
// ---------------------------------------------------------------------------

/// Port of `splitCssList(value)`: splits on top-level commas, respecting
/// quotes and `()`/`[]` nesting depth.
pub fn split_css_list(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    for i in 0..chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == q && (i == 0 || chars[i - 1] != '\\') {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' => depth += 1,
            ')' | ']' => depth = (depth - 1).max(0),
            ',' if depth == 0 => {
                parts.push(
                    chars[start..i]
                        .iter()
                        .collect::<String>()
                        .trim()
                        .to_string(),
                );
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail: String = chars[start..].iter().collect::<String>().trim().to_string();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

/// Port of `splitCssTokens(value)`: whitespace-separated tokens, respecting
/// quotes and `()` nesting depth (so `rgba(0, 0, 0, .5)` stays one token).
pub fn split_css_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut current = String::new();
    let chars: Vec<char> = value.chars().collect();
    for i in 0..chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            current.push(ch);
            if ch == q && (i == 0 || chars[i - 1] != '\\') {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                quote = Some(ch);
                current.push(ch);
            }
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth = (depth - 1).max(0);
                current.push(ch);
            }
            c if c.is_whitespace() && depth == 0 => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

// ---------------------------------------------------------------------------
// Prop-name mapping / color-to-css / box-value expansion
// ---------------------------------------------------------------------------

fn static_prop_map() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            ("background-color", "backgroundColor"),
            ("background-image", "backgroundImage"),
            ("background-clip", "backgroundClip"),
            ("-webkit-background-clip", "webkitBackgroundClip"),
            ("border-radius", "borderRadius"),
            ("border-top-width", "borderTopWidth"),
            ("border-right-width", "borderRightWidth"),
            ("border-bottom-width", "borderBottomWidth"),
            ("border-left-width", "borderLeftWidth"),
            ("border-top-color", "borderTopColor"),
            ("border-right-color", "borderRightColor"),
            ("border-bottom-color", "borderBottomColor"),
            ("border-left-color", "borderLeftColor"),
            ("outline-width", "outlineWidth"),
            ("outline-color", "outlineColor"),
            ("outline-style", "outlineStyle"),
            ("box-shadow", "boxShadow"),
            ("font-family", "fontFamily"),
            ("font-size", "fontSize"),
            ("font-style", "fontStyle"),
            ("font-weight", "fontWeight"),
            ("line-height", "lineHeight"),
            ("letter-spacing", "letterSpacing"),
            ("text-transform", "textTransform"),
            ("text-align", "textAlign"),
            ("hyphens", "hyphens"),
            ("-webkit-hyphens", "webkitHyphens"),
            ("transition-property", "transitionProperty"),
            ("transition-timing-function", "transitionTimingFunction"),
            ("animation-name", "animationName"),
            ("animation-timing-function", "animationTimingFunction"),
            ("width", "width"),
            ("height", "height"),
            ("padding-top", "paddingTop"),
            ("padding-right", "paddingRight"),
            ("padding-bottom", "paddingBottom"),
            ("padding-left", "paddingLeft"),
            ("margin-top", "marginTop"),
            ("margin-right", "marginRight"),
            ("margin-bottom", "marginBottom"),
            ("margin-left", "marginLeft"),
            ("position", "position"),
            ("visibility", "visibility"),
            ("top", "top"),
            ("right", "right"),
            ("bottom", "bottom"),
            ("left", "left"),
            ("inset", "inset"),
            ("display", "display"),
            ("overflow", "overflow"),
            ("overflow-x", "overflowX"),
            ("overflow-y", "overflowY"),
        ])
    })
}

/// Port of `cssPropToCamel(prop)`: the explicit `STATIC_PROP_MAP` lookup,
/// falling back to generic kebab→camel conversion.
pub fn css_prop_to_camel(prop: &str) -> String {
    if prop.is_empty() {
        return prop.to_string();
    }
    if let Some(mapped) = static_prop_map().get(prop) {
        return mapped.to_string();
    }
    let mut out = String::new();
    let mut chars = prop.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '-' {
            if let Some(&next) = chars.peek() {
                if next.is_ascii_lowercase() {
                    out.push(next.to_ascii_uppercase());
                    chars.next();
                    continue;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Port of `staticColorToCss(c)`, given `c` as `(r, g, b, a)` with `a` in
/// `[0, 1]`. Renders `rgba(...)` (alpha rounded to 3 decimals, matching
/// `Number(c.a.toFixed(3))` dropping trailing zeros) when `a < 1`, else
/// `rgb(...)`.
pub fn static_color_to_css(r: f64, g: f64, b: f64, a: f64) -> String {
    if a < 1.0 {
        // `Number(x.toFixed(3))` drops trailing zeros the same way Rust's
        // default float Display does after trimming, so format then trim.
        let a3 = format!("{a:.3}");
        let trimmed = a3.trim_end_matches('0').trim_end_matches('.');
        format!(
            "rgba({}, {}, {}, {})",
            r as i64, g as i64, b as i64, trimmed
        )
    } else {
        format!("rgb({}, {}, {})", r as i64, g as i64, b as i64)
    }
}

type StaticNamedRgba = (f64, f64, f64, f64);

const STATIC_NAMED_COLORS: &[(&str, StaticNamedRgba)] = &[
    ("black", (0.0, 0.0, 0.0, 1.0)),
    ("white", (255.0, 255.0, 255.0, 1.0)),
    ("transparent", (0.0, 0.0, 0.0, 0.0)),
    ("gray", (128.0, 128.0, 128.0, 1.0)),
    ("grey", (128.0, 128.0, 128.0, 1.0)),
    ("silver", (192.0, 192.0, 192.0, 1.0)),
    ("red", (255.0, 0.0, 0.0, 1.0)),
    ("green", (0.0, 128.0, 0.0, 1.0)),
    ("blue", (0.0, 0.0, 255.0, 1.0)),
];

/// Port of `parseStaticColor(value)`: tries the shared `parseAnyColor`
/// first, then the local `STATIC_NAMED_COLORS` keyword table.
pub fn parse_static_color(value: &str) -> Option<(f64, f64, f64, f64)> {
    if let Some(rgba) = parse_any_color(value) {
        return Some((rgba.r, rgba.g, rgba.b, rgba.a));
    }
    STATIC_NAMED_COLORS
        .iter()
        .find(|(name, _)| *name == value.trim().to_lowercase())
        .map(|(_, c)| *c)
}

fn color_like_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:rgba?\([^)]+\)|oklch\([^)]+\)|oklab\([^)]+\)|lch\([^)]+\)|lab\([^)]+\)|hsla?\([^)]+\)|hwb\([^)]+\)|#[0-9a-f]{3,8}\b|\b(?:black|white|gray|grey|silver|red|green|blue|transparent)\b)").unwrap()
    })
}

/// Port of `extractStaticColor(value)`: returns `value` unchanged (well,
/// the whole trimmed raw string) if it starts with `var(`, else the first
/// color-like substring found, else `""`.
pub fn extract_static_color(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let raw = value.trim();
    if raw.to_lowercase().starts_with("var(") {
        return raw.to_string();
    }
    color_like_re()
        .find(raw)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

/// Port of `expandStaticBoxValues(tokens)`: CSS box shorthand
/// (top/right/bottom/left) expansion from 0-4 tokens, defaulting to
/// `"0px"` for all four sides when `tokens` is empty (mirrors the JS
/// default for an empty `padding:`/`margin:` value, which would not
/// normally occur but is preserved for parity).
pub fn expand_static_box_values(tokens: &[String]) -> [String; 4] {
    match tokens.len() {
        0 => ["0px".into(), "0px".into(), "0px".into(), "0px".into()],
        1 => [
            tokens[0].clone(),
            tokens[0].clone(),
            tokens[0].clone(),
            tokens[0].clone(),
        ],
        2 => [
            tokens[0].clone(),
            tokens[1].clone(),
            tokens[0].clone(),
            tokens[1].clone(),
        ],
        3 => [
            tokens[0].clone(),
            tokens[1].clone(),
            tokens[2].clone(),
            tokens[1].clone(),
        ],
        _ => [
            tokens[0].clone(),
            tokens[1].clone(),
            tokens[2].clone(),
            tokens[3].clone(),
        ],
    }
}

fn width_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^-?[\d.]+(?:px|rem|em|%)$").unwrap())
}

/// A parsed border shorthand's width/color pieces, empty string for
/// whichever half wasn't found — matches `parseStaticBorder`'s `{ width,
/// color }` (both default `""`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StaticBorder {
    pub width: String,
    pub color: String,
}

/// Port of `parseStaticBorder(value)`.
pub fn parse_static_border(value: &str) -> StaticBorder {
    let tokens = split_css_tokens(value);
    let mut width = String::new();
    let mut color = String::new();
    for token in &tokens {
        if width.is_empty() && width_token_re().is_match(token) {
            width = token.clone();
        }
        if color.is_empty() {
            color = extract_static_color(token);
        }
    }
    StaticBorder { width, color }
}

fn font_slash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)([\d.]+(?:px|rem|em|%))(?:/([^\s]+))?").unwrap())
}

fn font_weight_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b([1-9]00|bold|normal|lighter|bolder)\b").unwrap())
}

fn font_italic_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bitalic\b").unwrap())
}

/// Port of `parseStaticFont(value)`: ordered `(prop, value)` pairs from
/// the `font` shorthand, same order the JS pushes them in
/// (`fontStyle`, `fontWeight`, `fontSize`, `lineHeight`, `fontFamily`).
pub fn parse_static_font(value: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if font_italic_re().is_match(value) {
        out.push(("fontStyle", "italic".to_string()));
    }
    if let Some(caps) = font_weight_re().captures(value) {
        out.push(("fontWeight", caps[1].to_string()));
    }
    if let Some(caps) = font_slash_re().captures(value) {
        let whole = caps.get(0).unwrap().as_str();
        out.push(("fontSize", caps[1].to_string()));
        if let Some(lh) = caps.get(2) {
            out.push(("lineHeight", lh.as_str().to_string()));
        }
        let family_start = value.find(whole).unwrap() + whole.len();
        let family = value[family_start..].trim();
        if !family.is_empty() {
            out.push(("fontFamily", family.to_string()));
        }
    }
    out
}

fn timing_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(?:ease|linear|step-|cubic-bezier\()").unwrap())
}

fn transition_prop_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^[a-z-]+$").unwrap())
}

fn transition_prop_exclude_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:ease|linear|infinite|alternate|forwards|backwards|both|normal|none)$")
            .unwrap()
    })
}

fn ends_with_s_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"s$").unwrap())
}

/// A `transition`/`animation` shorthand's extracted `property`/`name` and
/// `timing` lists, already comma-joined the way the JS `.join(', ')` does.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TransitionParts {
    pub property: String,
    pub timing: String,
}

/// Port of `parseStaticTransition(value)`.
pub fn parse_static_transition(value: &str) -> TransitionParts {
    let mut props = Vec::new();
    let mut timings = Vec::new();
    for item in split_css_list(value) {
        let tokens = split_css_tokens(&item);
        if let Some(t) = tokens.iter().find(|t| timing_re().is_match(t)) {
            timings.push(t.clone());
        }
        if let Some(p) = tokens.iter().find(|t| {
            transition_prop_token_re().is_match(t)
                && !transition_prop_exclude_re().is_match(t)
                && !ends_with_s_re().is_match(t)
        }) {
            props.push(p.clone());
        }
    }
    TransitionParts {
        property: props.join(", "),
        timing: timings.join(", "),
    }
}

fn animation_name_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^[a-z_-][\w-]*$").unwrap())
}

fn animation_name_exclude_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:ease|linear|infinite|alternate|forwards|backwards|both|normal|none|running|paused)$")
            .unwrap()
    })
}

/// Port of `parseStaticAnimation(value)`.
pub fn parse_static_animation(value: &str) -> TransitionParts {
    let mut names = Vec::new();
    let mut timings = Vec::new();
    for item in split_css_list(value) {
        let tokens = split_css_tokens(&item);
        if let Some(t) = tokens.iter().find(|t| timing_re().is_match(t)) {
            timings.push(t.clone());
        }
        if let Some(n) = tokens.iter().find(|t| {
            animation_name_token_re().is_match(t) && !animation_name_exclude_re().is_match(t)
        }) {
            names.push(n.clone());
        }
    }
    TransitionParts {
        property: names.join(", "),
        timing: timings.join(", "),
    }
}

// ---------------------------------------------------------------------------
// Cascade priority / specificity
// ---------------------------------------------------------------------------

/// A declaration's cascade metadata, mirroring the `meta` object
/// `applyStaticDeclaration`/`compareStaticPriority` compare
/// (`important`, `inline`, `specificity` as `[ids, classes, types]`,
/// source `order`).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DeclMeta {
    pub important: bool,
    pub inline: bool,
    pub specificity: [u32; 3],
    pub order: u32,
}

/// Port of `compareStaticPriority(a, b)`: returns `true` when `b` should
/// win over `a` (or `a` is absent). `!important` beats everything, then
/// inline style, then specificity (ids, classes, types), then later
/// source order wins ties (`>=`, matching the JS `b.order >= a.order`).
pub fn compare_static_priority(a: Option<&DeclMeta>, b: &DeclMeta) -> bool {
    let Some(a) = a else { return true };
    if b.important != a.important {
        return b.important;
    }
    if b.inline != a.inline {
        return b.inline;
    }
    for i in 0..3 {
        if b.specificity[i] != a.specificity[i] {
            return b.specificity[i] > a.specificity[i];
        }
    }
    b.order >= a.order
}

fn where_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r":where\([^)]*\)").unwrap())
}

fn id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"#[\w-]+").unwrap())
}

// The JS source uses `:(?!:)[\w-]+(?:\([^)]*\))?` (negative lookahead) to
// count single-colon pseudo-classes while excluding `::` pseudo-elements.
// The `regex` crate has no lookaround, so this matches both `:` and `::`
// forms and the caller filters out anything starting with `::`.
fn class_attr_pseudo_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\.[\w-]+|\[[^\]]+\]|:{1,2}[\w-]+(?:\([^)]*\))?").unwrap())
}

fn class_attr_pseudo_strip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r":{1,2}[\w-]+(?:\([^)]*\))?|\.[\w-]+|\[[^\]]+\]").unwrap())
}

fn combinator_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[*>+~(),]").unwrap())
}

fn type_selector_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[a-zA-Z][\w-]*\b").unwrap())
}

/// Port of `staticSpecificity(selector)`: `[ids, classes-or-attrs-or-
/// pseudo-classes, type-selectors]`, with `:where(...)` contents stripped
/// first (zero-specificity in real CSS).
pub fn static_specificity(selector: &str) -> [u32; 3] {
    let no_where = where_re().replace_all(selector, "");
    let ids = id_re().find_iter(&no_where).count() as u32;
    let classes = class_attr_pseudo_re()
        .find_iter(&no_where)
        .filter(|m| !m.as_str().starts_with("::"))
        .count() as u32;
    let stripped = id_re().replace_all(&no_where, " ");
    let stripped = class_attr_pseudo_strip_re().replace_all(&stripped, " ");
    let stripped = combinator_re().replace_all(&stripped, " ");
    let types = type_selector_re().find_iter(&stripped).count() as u32;
    [ids, classes, types]
}

// ---------------------------------------------------------------------------
// Inline style="" attribute parsing
// ---------------------------------------------------------------------------

/// One declaration parsed out of an inline `style=""` attribute, mirroring
/// `parseStaticStyleAttribute`'s `{ prop, value, important, order }`.
#[derive(Debug, Clone, PartialEq)]
pub struct InlineDecl {
    pub prop: String,
    pub value: String,
    pub important: bool,
    pub order: u32,
}

fn important_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)!important\s*$").unwrap())
}

/// Port of `parseStaticStyleAttribute(styleText, orderBase)`.
pub fn parse_static_style_attribute(style_text: &str, order_base: u32) -> Vec<InlineDecl> {
    let mut decls = Vec::new();
    for part in style_text.split(';') {
        let Some(idx) = part.find(':') else { continue };
        if idx == 0 {
            continue;
        }
        let prop = part[..idx].trim().to_string();
        let mut value = part[idx + 1..].trim().to_string();
        let important = important_re().is_match(&value);
        if important {
            value = important_re().replace(&value, "").trim().to_string();
        }
        let order = order_base + decls.len() as u32;
        decls.push(InlineDecl {
            prop,
            value,
            important,
            order,
        });
    }
    decls
}
