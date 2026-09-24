//! Full port of `skills/designer/engine/scripts/detector/engines/
//! static-html/css-cascade.mjs` (packet r09).
//!
//! This module re-exports the pure string/CSS-value parsing helpers
//! already ported at [`crate::wf_port::w2_012::css_cascade`] (chunk
//! w2_012's earlier, partial pass over this same source file) and adds
//! the remaining pure-logic pieces that chunk left out:
//! `BORDER_SHORTHAND_RE`, `STATIC_INHERITED_PROPS`, `STATIC_DEFAULT_STYLE`,
//! `STATIC_PROP_MAP` (as public data), and the shorthand-expansion /
//! cascade-application pair `expandStaticDeclaration` /
//! `applyStaticDeclaration`.
//!
//! The remaining pieces (previously left unported) are implemented below:
//! `resolveVarRefs`/`resolveLengthPx` (`resolve_var_refs` here;
//! `resolveLengthPx` is reused directly from
//! [`crate::wf_port::w2_011::design_system::resolve_length_px`], which is
//! the same `checks.mjs` function already ported for that packet — one
//! canonical port, not a second copy), `normalizeStaticCssValue`,
//! `collectStaticCssRules` (a small hand-written recursive-descent CSS
//! block parser — `cssparser` is not in `engine/Cargo.lock`), `StaticElement`
//! / `StaticDocument` / `makeStaticStyle` / `buildStaticWindow`,
//! `collectStaticCssText`, `buildStaticStyleMap`, and `buildBorderOverrideMap`.
//!
//! Two adaptations from the JS source, both forced by there being no
//! jsdom/live-browser CSSOM available in Rust:
//!
//! * `StaticElement`/`StaticDocument` existed in JS to hand-roll a DOM
//!   over `htmlparser2` + `css-select`. This crate already has a real
//!   HTML5 tree + CSS selector engine (`scraper`, used the same way
//!   elsewhere under `wf_port`, e.g. `w2_013::detect_html`), so
//!   `StaticElement`'s query/traversal methods are provided natively by
//!   `scraper::ElementRef`/`scraper::Html`/`scraper::Selector` instead of
//!   being re-implemented by hand. `StaticDocument`/`buildStaticWindow`
//!   are ported as the computed-style-map wrapper around that DOM
//!   ([`StaticDocument`], [`StaticWindow`], [`build_static_window`]),
//!   which is the part of those two classes that isn't just DOM plumbing.
//! * `buildBorderOverrideMap` in JS reads `:root`-level custom properties
//!   from a *live* jsdom `window.getComputedStyle(document.documentElement)`
//!   and per-side border values from the CSSOM's already-parsed
//!   `rule.style.borderLeft` etc. accessors. With no live browser, this
//!   port reads `:root`/`html` custom properties directly out of our own
//!   [`collect_static_css_rules`] AST, and reads the raw authored
//!   `border`/`border-<side>`/`border-<side>-color` declaratins from that
//!   same AST instead of a CSSOM accessor. Functionally the same
//!   :root-only, var()-in-border fallback the JS comment describes.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

pub use crate::wf_port::w2_012::css_cascade::{
    compare_static_priority, css_prop_to_camel, expand_static_box_values, extract_static_color,
    normalize_color_for_check, parse_static_animation, parse_static_border, parse_static_color,
    parse_static_font, parse_static_style_attribute, parse_static_transition, split_css_list,
    split_css_tokens, static_color_to_css, static_specificity, unwrap_css_at_layer, DeclMeta,
    InlineDecl, StaticBorder, TransitionParts, NAMED_COLORS,
};

/// Port of `resolveLengthPx`, reused verbatim from the packet that already
/// ported it out of the same `checks.mjs` source (`pub(crate)` there, so
/// re-exported at the same visibility here).
pub(crate) use crate::wf_port::w2_011::design_system::resolve_length_px;

/// Port of `BORDER_SHORTHAND_RE`.
pub fn border_shorthand_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(\d+(?:\.\d+)?)px\s+(solid|dashed|dotted|double|groove|ridge|inset|outset)\s+(.+)$")
            .unwrap()
    })
}

/// Port of `STATIC_INHERITED_PROPS`.
pub fn static_inherited_props() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        HashSet::from([
            "color",
            "fontFamily",
            "fontSize",
            "fontStyle",
            "fontWeight",
            "lineHeight",
            "letterSpacing",
            "textTransform",
            "textAlign",
            "hyphens",
            "webkitHyphens",
        ])
    })
}

/// Port of `STATIC_DEFAULT_STYLE`.
pub fn static_default_style() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            ("color", "rgb(0, 0, 0)"),
            ("backgroundColor", "rgba(0, 0, 0, 0)"),
            ("backgroundImage", "none"),
            ("borderTopWidth", "0px"),
            ("borderRightWidth", "0px"),
            ("borderBottomWidth", "0px"),
            ("borderLeftWidth", "0px"),
            ("borderTopColor", "rgb(0, 0, 0)"),
            ("borderRightColor", "rgb(0, 0, 0)"),
            ("borderBottomColor", "rgb(0, 0, 0)"),
            ("borderLeftColor", "rgb(0, 0, 0)"),
            ("borderRadius", "0px"),
            ("outlineWidth", "0px"),
            ("outlineColor", "rgb(0, 0, 0)"),
            ("outlineStyle", "none"),
            ("boxShadow", "none"),
            ("fontFamily", ""),
            ("fontSize", "16px"),
            ("fontStyle", "normal"),
            ("fontWeight", "400"),
            ("lineHeight", "normal"),
            ("letterSpacing", "normal"),
            ("textTransform", "none"),
            ("textAlign", "start"),
            ("hyphens", "manual"),
            ("webkitHyphens", "manual"),
            ("transitionProperty", ""),
            ("transitionTimingFunction", ""),
            ("animationName", ""),
            ("animationTimingFunction", ""),
            ("webkitBackgroundClip", ""),
            ("backgroundClip", ""),
            ("width", ""),
            ("height", ""),
            ("paddingTop", "0px"),
            ("paddingRight", "0px"),
            ("paddingBottom", "0px"),
            ("paddingLeft", "0px"),
            ("marginTop", "0px"),
            ("marginRight", "0px"),
            ("marginBottom", "0px"),
            ("marginLeft", "0px"),
            ("position", "static"),
            ("visibility", "visible"),
            ("top", "auto"),
            ("right", "auto"),
            ("bottom", "auto"),
            ("left", "auto"),
            ("inset", ""),
            ("display", ""),
            ("overflow", "visible"),
            ("overflowX", "visible"),
            ("overflowY", "visible"),
        ])
    })
}

/// Port of `STATIC_PROP_MAP` (kebab-case CSS property name -> camelCase
/// computed-style key). Identical table to the private one already used
/// internally by [`css_prop_to_camel`] in `w2_012::css_cascade`, exposed
/// here as public data because the JS source exports it directly.
pub fn static_prop_map() -> &'static HashMap<&'static str, &'static str> {
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

/// STATIC_NAMED_COLORS: `{r, g, b, a}` keyword table (this file's local
/// copy, distinct from `buildBorderOverrideMap`'s smaller `NAMED_COLORS`).
/// Kept as a fresh symbol here because the JS module exports both tables.
pub fn static_named_colors() -> &'static HashMap<&'static str, (u8, u8, u8, f64)> {
    static MAP: OnceLock<HashMap<&'static str, (u8, u8, u8, f64)>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            ("black", (0, 0, 0, 1.0)),
            ("white", (255, 255, 255, 1.0)),
            ("transparent", (0, 0, 0, 0.0)),
            ("gray", (128, 128, 128, 1.0)),
            ("grey", (128, 128, 128, 1.0)),
            ("silver", (192, 192, 192, 1.0)),
            ("red", (255, 0, 0, 1.0)),
            ("green", (0, 128, 0, 1.0)),
            ("blue", (0, 0, 255, 1.0)),
        ])
    })
}

fn zero_len_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^0(?:px|rem|em|%)?$").unwrap())
}

fn style_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(none|hidden|solid|dashed|dotted|double|groove|ridge|inset|outset)$").unwrap())
}

fn gradient_or_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)gradient|url\(").unwrap())
}

fn gradient_split_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:repeating-)?(?:linear|radial|conic)-gradient\(|url\(").unwrap())
}

fn border_side_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^border-(top|right|bottom|left)$").unwrap())
}

/// One expanded `(camelCase-prop, value)` pair, as produced by
/// `expandStaticDeclaration`.
pub type ExpandedDecl = (String, String);

/// Port of `expandStaticDeclaration(prop, value)`: expands CSS shorthands
/// (`background`, `border[-side]`, `border-width`, `border-color`,
/// `outline`, `padding`, `margin`, `font`, `transition`, `animation`) into
/// their longhand computed-style keys, and passes through custom
/// properties (`--x`) and any longhand already known to
/// [`static_default_style`] / [`static_inherited_props`] unchanged. Returns
/// an empty list for an empty value or an unrecognized, unmapped property
/// (matching the JS `return []` fallthrough).
pub fn expand_static_declaration(prop: &str, value: &str) -> Vec<ExpandedDecl> {
    let p = prop.to_lowercase();
    let v = value.trim();
    if v.is_empty() {
        return Vec::new();
    }
    if p.starts_with("--") {
        return vec![(p, v.to_string())];
    }
    if p == "background" {
        let mut out = Vec::new();
        let has_image = gradient_or_url_re().is_match(v);
        if has_image {
            out.push(("backgroundImage".to_string(), v.to_string()));
        }
        let before_image = if has_image {
            gradient_split_re().splitn(v, 2).next().unwrap_or(v)
        } else {
            v
        };
        let color = extract_static_color(if has_image { before_image } else { v });
        if !color.is_empty() {
            out.push(("backgroundColor".to_string(), color));
        }
        return out;
    }
    if p == "border" {
        let parsed = parse_static_border(v);
        let mut out = Vec::new();
        for side in ["Top", "Right", "Bottom", "Left"] {
            if !parsed.width.is_empty() {
                out.push((format!("border{side}Width"), parsed.width.clone()));
            }
            if !parsed.color.is_empty() {
                out.push((format!("border{side}Color"), parsed.color.clone()));
            }
        }
        return out;
    }
    if p == "outline" {
        let tokens = split_css_tokens(v);
        let parsed = parse_static_border(v);
        let style_token = tokens.iter().find(|t| style_token_re().is_match(t));
        let mut out = Vec::new();
        if !parsed.width.is_empty() {
            out.push(("outlineWidth".to_string(), parsed.width.clone()));
        }
        if !parsed.color.is_empty() {
            out.push(("outlineColor".to_string(), parsed.color.clone()));
        }
        if let Some(st) = style_token {
            out.push(("outlineStyle".to_string(), st.to_lowercase()));
        }
        if parsed.width.is_empty() && zero_len_re().is_match(v.trim()) {
            out.push(("outlineWidth".to_string(), "0px".to_string()));
        }
        return out;
    }
    if let Some(caps) = border_side_re().captures(&p) {
        let parsed = parse_static_border(v);
        let side_raw = &caps[1];
        let mut chars = side_raw.chars();
        let side = match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            None => String::new(),
        };
        let mut out = Vec::new();
        if !parsed.width.is_empty() {
            out.push((format!("border{side}Width"), parsed.width.clone()));
        }
        if !parsed.color.is_empty() {
            out.push((format!("border{side}Color"), parsed.color.clone()));
        }
        return out;
    }
    if p == "border-width" {
        let vals = expand_static_box_values(&split_css_tokens(v));
        return vec![
            ("borderTopWidth".to_string(), vals[0].clone()),
            ("borderRightWidth".to_string(), vals[1].clone()),
            ("borderBottomWidth".to_string(), vals[2].clone()),
            ("borderLeftWidth".to_string(), vals[3].clone()),
        ];
    }
    if p == "border-color" {
        let vals = expand_static_box_values(&split_css_tokens(v));
        return vec![
            ("borderTopColor".to_string(), vals[0].clone()),
            ("borderRightColor".to_string(), vals[1].clone()),
            ("borderBottomColor".to_string(), vals[2].clone()),
            ("borderLeftColor".to_string(), vals[3].clone()),
        ];
    }
    if p == "padding" {
        let vals = expand_static_box_values(&split_css_tokens(v));
        return vec![
            ("paddingTop".to_string(), vals[0].clone()),
            ("paddingRight".to_string(), vals[1].clone()),
            ("paddingBottom".to_string(), vals[2].clone()),
            ("paddingLeft".to_string(), vals[3].clone()),
        ];
    }
    if p == "margin" {
        let vals = expand_static_box_values(&split_css_tokens(v));
        return vec![
            ("marginTop".to_string(), vals[0].clone()),
            ("marginRight".to_string(), vals[1].clone()),
            ("marginBottom".to_string(), vals[2].clone()),
            ("marginLeft".to_string(), vals[3].clone()),
        ];
    }
    if p == "font" {
        return parse_static_font(v)
            .into_iter()
            .map(|(k, val)| (k.to_string(), val))
            .collect();
    }
    if p == "transition" {
        let parsed = parse_static_transition(v);
        let mut out = Vec::new();
        if !parsed.property.is_empty() {
            out.push(("transitionProperty".to_string(), parsed.property));
        }
        if !parsed.timing.is_empty() {
            out.push(("transitionTimingFunction".to_string(), parsed.timing));
        }
        return out;
    }
    if p == "animation" {
        let parsed = parse_static_animation(v);
        let mut out = Vec::new();
        if !parsed.property.is_empty() {
            out.push(("animationName".to_string(), parsed.property));
        }
        if !parsed.timing.is_empty() {
            out.push(("animationTimingFunction".to_string(), parsed.timing));
        }
        return out;
    }
    let mapped = css_prop_to_camel(&p);
    if static_default_style().contains_key(mapped.as_str()) || static_inherited_props().contains(mapped.as_str()) {
        return vec![(mapped, v.to_string())];
    }
    Vec::new()
}

/// A specified-value entry as stored per `(node, expandedProp)` by
/// `applyStaticDeclaration`, mirroring the JS `{ ...meta, prop, value }`
/// shape (`meta` = [`DeclMeta`]).
#[derive(Debug, Clone, PartialEq)]
pub struct SpecifiedDecl {
    pub meta: DeclMeta,
    pub prop: String,
    pub value: String,
}

/// Port of `applyStaticDeclaration(specified, node, prop, value, meta)`,
/// generalized over any hashable/equatable node-key type `N` in place of
/// a live DOM node reference (the JS version keys a `Map` by the actual
/// DOM node object). `specified` mirrors the JS `Map<node, Map<prop,
/// decl>>` two-level structure. Each `(prop, value)` pair is first run
/// through [`expand_static_declaration`]; for each expanded longhand,
/// [`compare_static_priority`] decides whether the new declaration wins
/// over the property's existing entry for that node.
pub fn apply_static_declaration<N: std::hash::Hash + Eq + Clone>(
    specified: &mut HashMap<N, HashMap<String, SpecifiedDecl>>,
    node: &N,
    prop: &str,
    value: &str,
    meta: DeclMeta,
) {
    let map = specified.entry(node.clone()).or_default();
    for (expanded_prop, expanded_value) in expand_static_declaration(prop, value) {
        let existing = map.get(&expanded_prop);
        let next_meta = meta;
        if compare_static_priority(existing.map(|d| &d.meta), &next_meta) {
            map.insert(
                expanded_prop.clone(),
                SpecifiedDecl { meta: next_meta, prop: expanded_prop, value: expanded_value },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// resolveVarRefs
// ---------------------------------------------------------------------------

fn var_ref_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"var\(\s*(--[a-zA-Z0-9_-]+)\s*(?:,\s*([^)]+))?\)").unwrap())
}

/// Port of `resolveVarRefs(raw, customPropMap, depth)`.
pub fn resolve_var_refs(raw: &str, custom_props: &HashMap<String, String>, depth: u32) -> String {
    if !raw.contains("var(") || depth > 8 {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut last = 0usize;
    for caps in var_ref_re().captures_iter(raw) {
        let m = caps.get(0).unwrap();
        out.push_str(&raw[last..m.start()]);
        let name = &caps[1];
        let replacement = if let Some(v) = custom_props.get(name) {
            resolve_var_refs(v, custom_props, depth + 1)
        } else if let Some(fallback) = caps.get(2) {
            resolve_var_refs(fallback.as_str().trim(), custom_props, depth + 1)
        } else {
            m.as_str().to_string()
        };
        out.push_str(&replacement);
        last = m.end();
    }
    out.push_str(&raw[last..]);
    out
}

fn parse_float_prefix(value: &str) -> Option<f64> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^\s*-?\d+(?:\.\d+)?").unwrap());
    re.find(value).and_then(|m| m.as_str().trim().parse::<f64>().ok())
}

fn modern_border_color_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^border[A-Z][a-z]+Color$").unwrap())
}

fn modern_color_fn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(?:oklch|oklab|lch|lab|hsl|hwb)\(").unwrap())
}

/// Port of `normalizeStaticCssValue(prop, value, customProps, parentStyle,
/// currentStyle)`.
pub fn normalize_static_css_value(
    prop: &str,
    value: &str,
    custom_props: &HashMap<String, String>,
    parent_style: Option<&ComputedStyle>,
    current_style: Option<&ComputedStyle>,
) -> String {
    let mut resolved = resolve_var_refs(value.trim(), custom_props, 0);
    if resolved == "inherit" {
        return parent_style
            .and_then(|p| p.0.get(prop))
            .cloned()
            .or_else(|| static_default_style().get(prop).map(|s| s.to_string()))
            .unwrap_or_default();
    }
    let is_modern_border_color =
        modern_border_color_re().is_match(prop) && modern_color_fn_re().is_match(&resolved);
    let lower = prop.to_lowercase();
    if !is_modern_border_color && (lower.ends_with("color") || prop == "color" || prop == "backgroundColor")
    {
        if let Some((r, g, b, a)) = parse_static_color(&resolved) {
            resolved = static_color_to_css(r, g, b, a);
        }
    }
    if prop == "fontSize" {
        let base = parent_style
            .and_then(|p| p.0.get("fontSize"))
            .and_then(|s| parse_float_prefix(s))
            .unwrap_or(16.0);
        if let Some(px) = resolve_length_px(&resolved, base) {
            resolved = format!("{px}px");
        }
    }
    if prop == "letterSpacing" {
        let base = current_style
            .and_then(|p| p.0.get("fontSize"))
            .or_else(|| parent_style.and_then(|p| p.0.get("fontSize")))
            .and_then(|s| parse_float_prefix(s))
            .unwrap_or(16.0);
        if let Some(px) = resolve_length_px(&resolved, base) {
            resolved = format!("{px}px");
        }
    }
    if prop == "lineHeight" && resolved != "normal" {
        let base = current_style
            .and_then(|p| p.0.get("fontSize"))
            .or_else(|| parent_style.and_then(|p| p.0.get("fontSize")))
            .and_then(|s| parse_float_prefix(s))
            .unwrap_or(16.0);
        if let Some(px) = resolve_length_px(&resolved, base) {
            resolved = format!("{px}px");
        }
    }
    resolved
}

// ---------------------------------------------------------------------------
// collectStaticCssRules: a small hand-written CSS block parser.
//
// `cssparser` is not present in `engine/Cargo.lock`; this parser only needs
// to recover (selector-list, declaration-list) pairs with `@media`/
// `@supports`/`@layer` unwrapped and `@keyframes` skipped, which is exactly
// what the JS `collectStaticCssRules` does with `csstree`.
// ---------------------------------------------------------------------------

/// One CSS rule as recovered by [`collect_static_css_rules`]: a single
/// selector (already split out of a comma-separated selector list) plus its
/// `(prop, value, important)` declarations, specificity, and source order.
#[derive(Debug, Clone, PartialEq)]
pub struct CssRule {
    pub selector: String,
    pub declarations: Vec<(String, String, bool)>,
    pub specificity: [u32; 3],
    pub order: u32,
}

fn comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").unwrap())
}

fn important_decl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)!\s*important\s*$").unwrap())
}

fn skip_string(chars: &[char], start: usize) -> usize {
    let quote = chars[start];
    let mut i = start + 1;
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == quote {
            return i + 1;
        }
        i += 1;
    }
    chars.len()
}

/// Splits `css` into top-level `(prelude, body)` pairs at each balanced
/// `{ ... }` block, skipping braces inside quoted strings.
fn parse_css_blocks(css: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = css.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut last = 0usize;
    while i < n {
        match chars[i] {
            '"' | '\'' => {
                i = skip_string(&chars, i);
                continue;
            }
            '{' => {
                let prelude: String = chars[last..i].iter().collect();
                let body_start = i + 1;
                let mut depth = 1i32;
                let mut j = body_start;
                while j < n && depth > 0 {
                    match chars[j] {
                        '"' | '\'' => {
                            j = skip_string(&chars, j);
                            continue;
                        }
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                let body_end = if j > body_start { j - 1 } else { body_start };
                let body: String = chars[body_start..body_end.min(n)].iter().collect();
                out.push((prelude, body));
                last = j;
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Splits a declaration block on top-level `;` (respecting quotes/parens),
/// mirroring the semicolon-splitting `csstree` does for us in JS.
fn split_css_declarations(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == q && (i == 0 || chars[i - 1] != '\\') {
                quote = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' => depth += 1,
            ')' | ']' => depth = (depth - 1).max(0),
            ';' if depth == 0 => {
                parts.push(chars[start..i].iter().collect::<String>());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail: String = chars[start..].iter().collect();
    if !tail.trim().is_empty() {
        parts.push(tail);
    }
    parts
}

fn parse_declarations(body: &str) -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    for part in split_css_declarations(body) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some(idx) = part.find(':') else { continue };
        if idx == 0 {
            continue;
        }
        let prop = part[..idx].trim().to_string();
        let mut value = part[idx + 1..].trim().to_string();
        let important = important_decl_re().is_match(&value);
        if important {
            value = important_decl_re().replace(&value, "").trim().to_string();
        }
        out.push((prop, value, important));
    }
    out
}

fn at_rule_name(prelude: &str) -> String {
    let rest = prelude.trim_start().trim_start_matches('@');
    rest.split(|c: char| c.is_whitespace() || c == '(')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn collect_blocks(css: &str, order: &mut u32, out: &mut Vec<CssRule>) {
    for (prelude, body) in parse_css_blocks(css) {
        let prelude_trim = prelude.trim();
        if prelude_trim.starts_with('@') {
            let name = at_rule_name(prelude_trim);
            if name.ends_with("keyframes") {
                continue;
            }
            if name == "media" || name == "supports" || name == "layer" {
                collect_blocks(&body, order, out);
            }
            continue;
        }
        if prelude_trim.is_empty() {
            continue;
        }
        let declarations = parse_declarations(&body);
        for selector in split_css_list(prelude_trim) {
            let selector = selector.trim().to_string();
            if selector.is_empty() {
                continue;
            }
            out.push(CssRule {
                specificity: static_specificity(&selector),
                selector,
                declarations: declarations.clone(),
                order: *order,
            });
            *order += 1;
        }
    }
}

/// Port of `collectStaticCssRules(cssText, csstree)`, using the
/// hand-written block parser above in place of `csstree`.
pub fn collect_static_css_rules(css_text: &str) -> Vec<CssRule> {
    let cleaned = comment_re().replace_all(css_text, "");
    let mut rules = Vec::new();
    let mut order = 0u32;
    collect_blocks(&cleaned, &mut order, &mut rules);
    rules
}

// ---------------------------------------------------------------------------
// StaticDocument / StaticWindow / makeStaticStyle
// ---------------------------------------------------------------------------

/// A computed style, ported from the plain-object shape `makeStaticStyle`
/// builds (defaults merged with computed longhands, plus a
/// `getPropertyValue` accessor — [`ComputedStyle::get_property_value`]
/// here).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ComputedStyle(pub HashMap<String, String>);

impl ComputedStyle {
    /// Port of the `getPropertyValue` closure `makeStaticStyle` attaches.
    pub fn get_property_value(&self, prop: &str) -> String {
        let key = css_prop_to_camel(prop);
        self.0
            .get(key.as_str())
            .or_else(|| self.0.get(prop))
            .cloned()
            .unwrap_or_default()
    }
}

/// Port of `makeStaticStyle(values)`: `STATIC_DEFAULT_STYLE` merged with
/// `values`.
pub fn make_static_style(values: HashMap<String, String>) -> ComputedStyle {
    let mut merged: HashMap<String, String> = static_default_style()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    merged.extend(values);
    ComputedStyle(merged)
}

/// Port of `StaticDocument`'s computed-style-map responsibility (see the
/// module-level doc comment for why its DOM/selector methods are delegated
/// to `scraper` instead of being re-implemented).
pub struct StaticDocument<'a> {
    pub html: &'a scraper::Html,
    elements: Vec<scraper::ElementRef<'a>>,
    styles: Vec<ComputedStyle>,
}

impl<'a> StaticDocument<'a> {
    /// Port of `StaticDocument.getStyle(el)`.
    pub fn get_style(&self, el: &scraper::ElementRef<'a>) -> ComputedStyle {
        self.elements
            .iter()
            .position(|e| e.id() == el.id())
            .map(|i| self.styles[i].clone())
            .unwrap_or_else(|| make_static_style(HashMap::new()))
    }
}

/// Port of `buildStaticWindow(staticDoc)`: `{ document, getComputedStyle }`.
pub struct StaticWindow<'a, 'b> {
    pub document: &'b StaticDocument<'a>,
}

impl<'a, 'b> StaticWindow<'a, 'b> {
    /// Port of the `getComputedStyle` closure `buildStaticWindow` returns.
    pub fn get_computed_style(&self, el: &scraper::ElementRef<'a>) -> ComputedStyle {
        self.document.get_style(el)
    }
}

/// Port of `buildStaticWindow(staticDoc)`.
pub fn build_static_window<'a, 'b>(document: &'b StaticDocument<'a>) -> StaticWindow<'a, 'b> {
    StaticWindow { document }
}

// ---------------------------------------------------------------------------
// collectStaticCssText
// ---------------------------------------------------------------------------

fn stylesheet_rel_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bstylesheet\b").unwrap())
}

fn protocol_relative_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(https?:)?//").unwrap())
}

/// Port of `collectStaticCssText(root, fileDir, profile, filePath,
/// modules)`. Profiling hooks (`profileStep`/`recordProfileEvent`) are
/// omitted — this repo's `wf_port` chunks don't port the JS profiler
/// scaffolding, only the behavior it wraps; unreadable linked stylesheets
/// are silently skipped, matching the JS `catch { /* skip unreadable */ }`.
pub fn collect_static_css_text(html: &scraper::Html, file_dir: &Path) -> String {
    let mut parts = Vec::new();
    if let Ok(style_sel) = scraper::Selector::parse("style") {
        for el in html.select(&style_sel) {
            parts.push(el.text().collect::<Vec<_>>().join(""));
        }
    }
    if let Ok(link_sel) = scraper::Selector::parse("link") {
        for el in html.select(&link_sel) {
            let rel = el.value().attr("rel").unwrap_or("");
            let href = el.value().attr("href").unwrap_or("");
            if !stylesheet_rel_re().is_match(rel) || href.is_empty() || protocol_relative_re().is_match(href) {
                continue;
            }
            let css_path = file_dir.join(href);
            if let Ok(css) = std::fs::read_to_string(&css_path) {
                parts.push(css);
            }
        }
    }
    parts.join("\n")
}

// ---------------------------------------------------------------------------
// buildStaticStyleMap
// ---------------------------------------------------------------------------

/// Port of `buildStaticStyleMap(root, staticDoc, cssText, modules, profile,
/// filePath)`: matches every collected CSS rule plus every inline
/// `style=""` attribute against the document (via `scraper::Selector`,
/// scraper's builtin css-select-equivalent), applies the cascade with
/// [`apply_static_declaration`], then walks the tree top-down computing
/// each element's style with inheritance + custom-property resolution,
/// exactly as `computeNode` does in JS.
pub fn build_static_style_map<'a>(html: &'a scraper::Html, css_text: &str) -> StaticDocument<'a> {
    let rules = collect_static_css_rules(css_text);

    let all_selector = scraper::Selector::parse("*").expect("static selector");
    let elements: Vec<scraper::ElementRef<'a>> = html.select(&all_selector).collect();
    let mut index_of: HashMap<_, usize> = HashMap::new();
    for (i, el) in elements.iter().enumerate() {
        index_of.insert(el.id(), i);
    }

    let mut specified: HashMap<usize, HashMap<String, SpecifiedDecl>> = HashMap::new();

    for rule in &rules {
        let Ok(selector) = scraper::Selector::parse(&rule.selector) else { continue };
        for el in html.select(&selector) {
            let Some(&idx) = index_of.get(&el.id()) else { continue };
            for (prop, value, important) in &rule.declarations {
                apply_static_declaration(
                    &mut specified,
                    &idx,
                    prop,
                    value,
                    DeclMeta {
                        important: *important,
                        inline: false,
                        specificity: rule.specificity,
                        order: rule.order,
                    },
                );
            }
        }
    }

    let mut inline_order = rules.len() as u32 + 1;
    for (idx, el) in elements.iter().enumerate() {
        let Some(style_text) = el.value().attr("style") else {
            inline_order += 1000;
            continue;
        };
        for decl in parse_static_style_attribute(style_text, inline_order) {
            apply_static_declaration(
                &mut specified,
                &idx,
                &decl.prop,
                &decl.value,
                DeclMeta {
                    important: decl.important,
                    inline: true,
                    specificity: [1, 0, 0],
                    order: decl.order,
                },
            );
        }
        inline_order += 1000;
    }

    let mut styles: Vec<Option<ComputedStyle>> = vec![None; elements.len()];

    // Iterative DFS: parents are always popped (and their style computed
    // and pushed for their children) before their children, so inheritance
    // sees a fully computed parent style regardless of stack order among
    // siblings.
    let mut stack: Vec<(scraper::ElementRef<'a>, Option<ComputedStyle>, HashMap<String, String>)> =
        vec![(html.root_element(), None, HashMap::new())];

    while let Some((el, parent_style, parent_custom)) = stack.pop() {
        let idx_opt = index_of.get(&el.id()).copied();
        let specified_map = idx_opt.and_then(|i| specified.get(&i));

        let mut custom_props = parent_custom.clone();
        if let Some(map) = specified_map {
            for (prop, decl) in map {
                if prop.starts_with("--") {
                    custom_props.insert(prop.clone(), resolve_var_refs(&decl.value, &custom_props, 0));
                }
            }
        }

        let mut values: HashMap<String, String> = HashMap::new();
        for (&prop, &default) in static_default_style().iter() {
            if static_inherited_props().contains(prop) {
                if let Some(v) = parent_style.as_ref().and_then(|p| p.0.get(prop)) {
                    values.insert(prop.to_string(), v.clone());
                    continue;
                }
            }
            values.insert(prop.to_string(), default.to_string());
        }
        if let Some(map) = specified_map {
            for (prop, decl) in map {
                if prop.starts_with("--") {
                    continue;
                }
                let current_snapshot = ComputedStyle(values.clone());
                let normalized = normalize_static_css_value(
                    prop,
                    &decl.value,
                    &custom_props,
                    parent_style.as_ref(),
                    Some(&current_snapshot),
                );
                values.insert(prop.clone(), normalized);
            }
        }

        let style = make_static_style(values);
        if let Some(i) = idx_opt {
            styles[i] = Some(style.clone());
        }

        for child in el.children().filter_map(scraper::ElementRef::wrap) {
            stack.push((child, Some(style.clone()), custom_props.clone()));
        }
    }

    let styles = styles
        .into_iter()
        .map(|s| s.unwrap_or_else(|| make_static_style(HashMap::new())))
        .collect();

    StaticDocument { html, elements, styles }
}

// ---------------------------------------------------------------------------
// buildBorderOverrideMap
// ---------------------------------------------------------------------------

/// A resolved border side: `{width, color}`, as recovered per side by
/// [`build_border_override_map`].
#[derive(Debug, Clone, PartialEq)]
pub struct BorderOverride {
    pub width: f64,
    pub color: String,
}

fn border_side_shorthand_prop(prop_lower: &str) -> Option<&'static str> {
    match prop_lower {
        "border-left" | "border-inline-start" => Some("Left"),
        "border-right" | "border-inline-end" => Some("Right"),
        "border-top" => Some("Top"),
        "border-bottom" => Some("Bottom"),
        _ => None,
    }
}

fn resolve_root_var(value: &str, root_props: &HashMap<String, String>, depth: u32) -> String {
    if depth > 10 || !value.contains("var(") {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut last = 0usize;
    for caps in var_ref_re().captures_iter(value) {
        let m = caps.get(0).unwrap();
        out.push_str(&value[last..m.start()]);
        let name = &caps[1];
        let v = root_props.get(name).map(|s| s.trim().to_string()).unwrap_or_default();
        let replacement = if !v.is_empty() {
            resolve_root_var(&v, root_props, depth + 1)
        } else if let Some(fallback) = caps.get(2) {
            resolve_root_var(fallback.as_str().trim(), root_props, depth + 1)
        } else {
            String::new()
        };
        out.push_str(&replacement);
        last = m.end();
    }
    out.push_str(&value[last..]);
    out
}

fn parse_border_shorthand_side(text: &str) -> Option<BorderOverride> {
    let caps = border_shorthand_re().captures(text.trim())?;
    let width: f64 = caps[1].parse().ok()?;
    let color = normalize_color_for_check(&caps[3]);
    Some(BorderOverride { width, color })
}

/// Port of `buildBorderOverrideMap(document, window)`. See the
/// module-level doc comment for why this reads `:root`/`html` custom
/// properties and border declarations from [`collect_static_css_rules`]'s
/// AST rather than a live jsdom CSSOM. Returns, per matched element, the
/// per-side `{width, color}` overrides recovered from any `border*`
/// declaration whose value contains `var(...)`.
pub fn build_border_override_map(
    html: &scraper::Html,
    css_text: &str,
) -> Vec<(scraper::ElementRef<'_>, HashMap<String, BorderOverride>)> {
    let rules = collect_static_css_rules(css_text);

    let mut root_props: HashMap<String, String> = HashMap::new();
    for rule in &rules {
        let sel = rule.selector.trim();
        if sel == ":root" || sel.eq_ignore_ascii_case("html") {
            for (prop, value, _important) in &rule.declarations {
                if let Some(name) = prop.strip_prefix("--") {
                    root_props.insert(format!("--{name}"), value.clone());
                }
            }
        }
    }

    let mut results: Vec<(scraper::ElementRef<'_>, HashMap<String, BorderOverride>)> = Vec::new();

    for rule in &rules {
        let mut per_side: HashMap<String, BorderOverride> = HashMap::new();

        for (prop, value, _important) in &rule.declarations {
            let lower = prop.to_lowercase();
            if !value.contains("var(") {
                continue;
            }
            if let Some(side) = border_side_shorthand_prop(&lower) {
                if let Some(parsed) = parse_border_shorthand_side(&resolve_root_var(value, &root_props, 0)) {
                    per_side.insert(side.to_string(), parsed);
                }
            }
        }

        if let Some((_, value, _)) = rule.declarations.iter().find(|(p, _, _)| p.eq_ignore_ascii_case("border")) {
            if value.contains("var(") {
                if let Some(parsed) = parse_border_shorthand_side(&resolve_root_var(value, &root_props, 0)) {
                    for side in ["Top", "Right", "Bottom", "Left"] {
                        per_side.entry(side.to_string()).or_insert_with(|| parsed.clone());
                    }
                }
            }
        }

        for (js_prop, side) in [
            ("border-left-color", "Left"),
            ("border-right-color", "Right"),
            ("border-top-color", "Top"),
            ("border-bottom-color", "Bottom"),
        ] {
            if let Some((_, value, _)) = rule.declarations.iter().find(|(p, _, _)| p.eq_ignore_ascii_case(js_prop)) {
                if value.contains("var(") {
                    let resolved = resolve_root_var(value, &root_props, 0).trim().to_string();
                    if !resolved.is_empty() {
                        per_side.entry(side.to_string()).or_insert_with(|| BorderOverride {
                            width: 0.0,
                            color: normalize_color_for_check(&resolved),
                        });
                    }
                }
            }
        }

        if per_side.is_empty() {
            continue;
        }

        let Ok(selector) = scraper::Selector::parse(&rule.selector) else { continue };
        for el in html.select(&selector) {
            if let Some((_, existing)) = results.iter_mut().find(|(e, _)| e.id() == el.id()) {
                for (k, v) in &per_side {
                    existing.insert(k.clone(), v.clone());
                }
            } else {
                results.push((el, per_side.clone()));
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_background_splits_image_and_color() {
        let out = expand_static_declaration("background", "linear-gradient(red, blue)");
        assert_eq!(out, vec![("backgroundImage".to_string(), "linear-gradient(red, blue)".to_string())]);

        let out = expand_static_declaration("background", "#ff0000");
        assert_eq!(out, vec![("backgroundColor".to_string(), "#ff0000".to_string())]);
    }

    #[test]
    fn expand_border_shorthand_all_sides() {
        let out = expand_static_declaration("border", "1px solid red");
        assert_eq!(out.len(), 8);
        assert!(out.contains(&("borderTopWidth".to_string(), "1px".to_string())));
        assert!(out.contains(&("borderLeftColor".to_string(), "red".to_string())));
    }

    #[test]
    fn expand_border_side_shorthand() {
        let out = expand_static_declaration("border-left", "5px solid #87a8ff");
        assert_eq!(
            out,
            vec![
                ("borderLeftWidth".to_string(), "5px".to_string()),
                ("borderLeftColor".to_string(), "#87a8ff".to_string()),
            ]
        );
    }

    #[test]
    fn expand_outline_zero_shorthand() {
        let out = expand_static_declaration("outline", "0");
        assert_eq!(out, vec![("outlineWidth".to_string(), "0px".to_string())]);
    }

    #[test]
    fn expand_padding_and_margin_box_values() {
        let out = expand_static_declaration("padding", "1px 2px");
        assert_eq!(
            out,
            vec![
                ("paddingTop".to_string(), "1px".to_string()),
                ("paddingRight".to_string(), "2px".to_string()),
                ("paddingBottom".to_string(), "1px".to_string()),
                ("paddingLeft".to_string(), "2px".to_string()),
            ]
        );
    }

    #[test]
    fn expand_custom_property_passthrough() {
        let out = expand_static_declaration("--brand", "#87a8ff");
        assert_eq!(out, vec![("--brand".to_string(), "#87a8ff".to_string())]);
    }

    #[test]
    fn expand_known_longhand_and_unknown_property() {
        let out = expand_static_declaration("color", "red");
        assert_eq!(out, vec![("color".to_string(), "red".to_string())]);

        let out = expand_static_declaration("totally-unknown-prop", "red");
        assert!(out.is_empty());

        // Empty value -> empty list regardless of property.
        assert!(expand_static_declaration("color", "").is_empty());
    }

    #[test]
    fn apply_static_declaration_respects_cascade_priority() {
        let mut specified: HashMap<u32, HashMap<String, SpecifiedDecl>> = HashMap::new();
        let node = 1u32;

        apply_static_declaration(
            &mut specified,
            &node,
            "color",
            "red",
            DeclMeta { important: false, inline: false, specificity: [0, 1, 0], order: 0 },
        );
        apply_static_declaration(
            &mut specified,
            &node,
            "color",
            "blue",
            DeclMeta { important: false, inline: false, specificity: [0, 0, 1], order: 1 },
        );
        // Lower specificity, later order: must NOT overwrite.
        assert_eq!(specified[&node]["color"].value, "red");

        apply_static_declaration(
            &mut specified,
            &node,
            "color",
            "green",
            DeclMeta { important: true, inline: false, specificity: [0, 0, 0], order: 2 },
        );
        // !important always wins.
        assert_eq!(specified[&node]["color"].value, "green");
    }

    #[test]
    fn static_default_style_and_inherited_props_have_expected_entries() {
        assert_eq!(static_default_style().get("fontSize"), Some(&"16px"));
        assert_eq!(static_default_style().get("position"), Some(&"static"));
        assert!(static_inherited_props().contains("lineHeight"));
        assert!(!static_inherited_props().contains("display"));
    }

    #[test]
    fn static_prop_map_matches_source_table() {
        assert_eq!(static_prop_map().get("background-color"), Some(&"backgroundColor"));
        assert_eq!(static_prop_map().get("-webkit-hyphens"), Some(&"webkitHyphens"));
    }

    #[test]
    fn static_named_colors_table() {
        assert_eq!(static_named_colors().get("transparent"), Some(&(0, 0, 0, 0.0)));
        assert_eq!(static_named_colors().get("white"), Some(&(255, 255, 255, 1.0)));
    }

    #[test]
    fn border_shorthand_regex_matches_expected_shape() {
        let caps = border_shorthand_re().captures("5px solid var(--brand)").unwrap();
        assert_eq!(&caps[1], "5");
        assert_eq!(&caps[2], "solid");
        assert_eq!(&caps[3], "var(--brand)");
        assert!(border_shorthand_re().captures("solid red").is_none());
    }

    // -- resolveVarRefs -----------------------------------------------------

    #[test]
    fn resolve_var_refs_substitutes_and_recurses() {
        let mut props = HashMap::new();
        props.insert("--brand".to_string(), "var(--base)".to_string());
        props.insert("--base".to_string(), "#87a8ff".to_string());
        assert_eq!(resolve_var_refs("var(--brand)", &props, 0), "#87a8ff");
    }

    #[test]
    fn resolve_var_refs_uses_fallback_when_missing() {
        let props = HashMap::new();
        assert_eq!(resolve_var_refs("var(--missing, red)", &props, 0), "red");
        // No custom prop and no fallback: literal var() passes through.
        assert_eq!(resolve_var_refs("var(--missing)", &props, 0), "var(--missing)");
    }

    // -- normalizeStaticCssValue --------------------------------------------

    #[test]
    fn normalize_static_css_value_resolves_color_and_length() {
        let props = HashMap::new();
        assert_eq!(
            normalize_static_css_value("color", "#ff0000", &props, None, None),
            "rgb(255, 0, 0)"
        );
        assert_eq!(
            normalize_static_css_value("fontSize", "2rem", &props, None, None),
            "32px"
        );
    }

    #[test]
    fn normalize_static_css_value_inherit_falls_back_to_parent() {
        let props = HashMap::new();
        let mut parent = HashMap::new();
        parent.insert("color".to_string(), "rgb(1, 2, 3)".to_string());
        let parent_style = ComputedStyle(parent);
        assert_eq!(
            normalize_static_css_value("color", "inherit", &props, Some(&parent_style), None),
            "rgb(1, 2, 3)"
        );
    }

    // -- collectStaticCssRules -----------------------------------------------

    #[test]
    fn collect_static_css_rules_unwraps_media_and_skips_keyframes() {
        let css = "@keyframes spin { from { opacity: 0; } to { opacity: 1; } } \
                    @media (min-width: 100px) { .card { color: red; } } \
                    .plain, .also { border: 1px solid blue; }";
        let rules = collect_static_css_rules(css);
        let selectors: Vec<&str> = rules.iter().map(|r| r.selector.as_str()).collect();
        assert!(selectors.contains(&".card"));
        assert!(selectors.contains(&".plain"));
        assert!(selectors.contains(&".also"));
        assert!(!selectors.iter().any(|s| s.contains("from") || s.contains("to")));
        let card = rules.iter().find(|r| r.selector == ".card").unwrap();
        assert_eq!(card.declarations, vec![("color".to_string(), "red".to_string(), false)]);
    }

    #[test]
    fn collect_static_css_rules_detects_important() {
        let rules = collect_static_css_rules(".x { color: red !important; }");
        assert_eq!(rules[0].declarations, vec![("color".to_string(), "red".to_string(), true)]);
    }

    // -- buildStaticStyleMap / StaticDocument / buildStaticWindow -----------

    #[test]
    fn build_static_style_map_applies_cascade_and_inheritance() {
        let html = scraper::Html::parse_document(
            r#"<html><body><div class="card" style="border-left: 5px solid #87a8ff;">
                 <span>text</span>
               </div></body></html>"#,
        );
        let css = ":root { --brand: #ff9900; } .card { color: var(--brand); font-size: 20px; }";
        let doc = build_static_style_map(&html, css);
        let window = build_static_window(&doc);

        let span_sel = scraper::Selector::parse("span").unwrap();
        let span = html.select(&span_sel).next().unwrap();
        let span_style = window.get_computed_style(&span);
        // color is inherited from .card's resolved var(--brand).
        assert_eq!(span_style.get_property_value("color"), "rgb(255, 153, 0)");
        // font-size inherits too.
        assert_eq!(span_style.get_property_value("font-size"), "20px");

        let div_sel = scraper::Selector::parse(".card").unwrap();
        let div = html.select(&div_sel).next().unwrap();
        let div_style = doc.get_style(&div);
        // Inline style="" wins for borderLeftWidth/-Color.
        assert_eq!(div_style.0.get("borderLeftWidth"), Some(&"5px".to_string()));
        assert_eq!(div_style.0.get("borderLeftColor"), Some(&"rgb(135, 168, 255)".to_string()));
    }

    #[test]
    fn collect_static_css_text_reads_inline_style_tags() {
        let html = scraper::Html::parse_document("<html><head><style>.a{color:red}</style></head><body></body></html>");
        let text = collect_static_css_text(&html, std::path::Path::new("."));
        assert!(text.contains(".a{color:red}"));
    }

    // -- buildBorderOverrideMap ----------------------------------------------

    #[test]
    fn build_border_override_map_resolves_root_var_border() {
        let html = scraper::Html::parse_document(
            r#"<html><body><div class="card">side tab</div></body></html>"#,
        );
        let css = ":root { --brand: #87a8ff; } .card { border-left: 5px solid var(--brand); border-radius: 4px; }";
        let overrides = build_border_override_map(&html, css);
        assert_eq!(overrides.len(), 1);
        let (_, sides) = &overrides[0];
        let left = sides.get("Left").expect("left side recovered");
        assert_eq!(left.width, 5.0);
        assert_eq!(left.color, "rgb(135, 168, 255)");
    }

    #[test]
    fn build_border_override_map_ignores_non_var_borders() {
        let html = scraper::Html::parse_document(r#"<html><body><div class="plain">no var</div></body></html>"#);
        let css = ".plain { border: 1px solid red; }";
        let overrides = build_border_override_map(&html, css);
        assert!(overrides.is_empty());
    }
}
