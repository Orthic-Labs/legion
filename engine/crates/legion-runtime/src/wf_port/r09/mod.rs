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
//! Genuinely unported (documented per-symbol below, unchanged from the
//! w2_012 assessment): the pieces that need a live DOM plus a CSS-AST
//! parser — `buildBorderOverrideMap` (walks `document.styleSheets` /
//! `window.getComputedStyle`), `StaticElement` / `StaticDocument` (a
//! `htmlparser2`-backed DOM wrapper), `collectStaticCssRules` (needs
//! `csstree`), `buildStaticStyleMap` / `collectStaticCssText`
//! (orchestrate the DOM + `fs` + the above), and `normalizeStaticCssValue`
//! (needs `resolveVarRefs`/`resolveLengthPx` from the separate
//! `rules/checks.mjs`, which no packet in this repo has ported). None of
//! the crates this port is allowed to add (`reqwest`, `scraper`,
//! `headless_chrome`, `image`) provide a raw CSS declaration/AST parser or
//! a mutable, jsdom-style computed-style DOM, so these stay unported, same
//! as they were left in `w2_012`.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use regex::Regex;

pub use crate::wf_port::w2_012::css_cascade::{
    compare_static_priority, css_prop_to_camel, expand_static_box_values, extract_static_color,
    normalize_color_for_check, parse_static_animation, parse_static_border, parse_static_color,
    parse_static_font, parse_static_style_attribute, parse_static_transition, split_css_list,
    split_css_tokens, static_color_to_css, static_specificity, unwrap_css_at_layer, DeclMeta,
    InlineDecl, StaticBorder, TransitionParts, NAMED_COLORS,
};

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
}
