//! Integration tests for the ported `wf_port::r09` module (packet r09),
//! porting `skills/designer/engine/scripts/detector/engines/static-html/
//! css-cascade.mjs`.
//!
//! NOTE: per the port brief, `wf_port/mod.rs` is not edited by this
//! packet, and it does not yet declare `pub mod r09;`. Until a
//! module-wiring pass adds that line, this test file (and the r09 module
//! itself) is not reachable from `legion_runtime::wf_port::r09` and this
//! crate will not compile with this file included. This mirrors the
//! current state of sibling directories `r00`/`r04`/`r06`/`r11`/`r12`/
//! `r13` in the same tree, which are also present on disk but not yet
//! declared.

use legion_runtime::wf_port::r09::{
    apply_static_declaration, border_shorthand_re, compare_static_priority, css_prop_to_camel,
    expand_static_box_values, expand_static_declaration, extract_static_color,
    normalize_color_for_check, parse_static_animation, parse_static_border, parse_static_color,
    parse_static_font, parse_static_style_attribute, parse_static_transition, split_css_list,
    split_css_tokens, static_color_to_css, static_default_style, static_inherited_props,
    static_named_colors, static_prop_map, static_specificity, unwrap_css_at_layer, DeclMeta,
    SpecifiedDecl,
};
use std::collections::HashMap;

#[test]
fn unwrap_css_at_layer_flattens_tailwind_style_layers() {
    let src = "@layer base, utilities;\n@layer utilities { .p-4 { padding: 1rem; } } .x { color: red; }";
    let out = unwrap_css_at_layer(src);
    assert!(!out.contains("@layer utilities {"));
    assert!(out.contains(".p-4 { padding: 1rem; }"));
    assert!(out.contains(".x { color: red; }"));
}

#[test]
fn normalize_color_for_check_roundtrip() {
    assert_eq!(normalize_color_for_check("#87a8ff"), "rgb(135, 168, 255)");
    assert_eq!(normalize_color_for_check("blue"), "rgb(0, 0, 255)");
}

#[test]
fn split_css_list_and_tokens() {
    assert_eq!(split_css_list("a, b, c"), vec!["a", "b", "c"]);
    assert_eq!(split_css_tokens("1px solid red"), vec!["1px", "solid", "red"]);
}

#[test]
fn css_prop_to_camel_known_and_generic() {
    assert_eq!(css_prop_to_camel("border-top-width"), "borderTopWidth");
    assert_eq!(css_prop_to_camel("foo-bar-baz"), "fooBarBaz");
}

#[test]
fn static_color_to_css_and_parse_static_color() {
    assert_eq!(static_color_to_css(0.0, 128.0, 0.0, 1.0), "rgb(0, 128, 0)");
    assert_eq!(parse_static_color("green"), Some((0.0, 128.0, 0.0, 1.0)));
}

#[test]
fn extract_static_color_and_parse_static_border() {
    assert_eq!(extract_static_color("2px dashed blue"), "blue");
    let b = parse_static_border("2px dashed blue");
    assert_eq!(b.width, "2px");
    assert_eq!(b.color, "blue");
}

#[test]
fn expand_static_box_values_all_arities() {
    let t = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(expand_static_box_values(&t(&[])), ["0px", "0px", "0px", "0px"]);
    assert_eq!(expand_static_box_values(&t(&["1px", "2px", "3px"])), ["1px", "2px", "3px", "2px"]);
}

#[test]
fn parse_static_font_and_transition_and_animation() {
    let font = parse_static_font("bold 14px/1.2 Arial, sans-serif");
    assert!(font.contains(&("fontWeight", "bold".to_string())));
    assert!(font.contains(&("fontSize", "14px".to_string())));
    assert!(font.contains(&("lineHeight", "1.2".to_string())));

    let transition = parse_static_transition("opacity .2s ease-out");
    assert_eq!(transition.property, "opacity");
    assert_eq!(transition.timing, "ease-out");

    let animation = parse_static_animation("spin 2s linear infinite");
    assert_eq!(animation.property, "spin");
    assert_eq!(animation.timing, "linear");
}

#[test]
fn compare_static_priority_and_specificity() {
    assert_eq!(static_specificity("#id .cls[data-x] span"), [1, 2, 1]);
    let base = DeclMeta { important: false, inline: false, specificity: [0, 1, 0], order: 0 };
    let inline_wins = DeclMeta { important: false, inline: true, specificity: [0, 0, 0], order: 0 };
    assert!(compare_static_priority(Some(&base), &inline_wins));
}

#[test]
fn parse_static_style_attribute_multi_decl() {
    let decls = parse_static_style_attribute("color:red;background:blue !important", 10);
    assert_eq!(decls.len(), 2);
    assert_eq!(decls[0].order, 10);
    assert!(decls[1].important);
}

#[test]
fn border_shorthand_regex_is_exported() {
    assert!(border_shorthand_re().is_match("2.5px dotted rgb(1,2,3)"));
}

#[test]
fn static_style_tables_are_exported() {
    assert_eq!(static_default_style().get("display"), Some(&""));
    assert!(static_inherited_props().contains("fontFamily"));
    assert_eq!(static_prop_map().get("border-radius"), Some(&"borderRadius"));
    assert!(static_named_colors().contains_key("silver"));
}

// ---------------------------------------------------------------------------
// expandStaticDeclaration / applyStaticDeclaration — the shorthand
// expansion + cascade-application pair this packet adds on top of the
// w2_012 partial port.
// ---------------------------------------------------------------------------

#[test]
fn expand_static_declaration_covers_every_shorthand_family() {
    assert_eq!(
        expand_static_declaration("margin", "1px 2px 3px 4px"),
        vec![
            ("marginTop".to_string(), "1px".to_string()),
            ("marginRight".to_string(), "2px".to_string()),
            ("marginBottom".to_string(), "3px".to_string()),
            ("marginLeft".to_string(), "4px".to_string()),
        ]
    );
    assert_eq!(
        expand_static_declaration("border-color", "red green"),
        vec![
            ("borderTopColor".to_string(), "red".to_string()),
            ("borderRightColor".to_string(), "green".to_string()),
            ("borderBottomColor".to_string(), "red".to_string()),
            ("borderLeftColor".to_string(), "green".to_string()),
        ]
    );
    let anim = expand_static_declaration("animation", "fade-in 1s ease-in");
    assert!(anim.contains(&("animationName".to_string(), "fade-in".to_string())));
    assert!(anim.contains(&("animationTimingFunction".to_string(), "ease-in".to_string())));
}

#[test]
fn full_cascade_pipeline_selects_highest_priority_declaration_per_element() {
    // Simulates the outer `for (rule of rules) { for (node of matched) {
    // applyStaticDeclaration(...) } }` loop in `buildStaticStyleMap`,
    // using integer node ids in place of real DOM nodes.
    let mut specified: HashMap<u32, HashMap<String, SpecifiedDecl>> = HashMap::new();
    let node = 42u32;

    // Rule 1: `.card { border: 1px solid black; }` — specificity [0,1,0].
    apply_static_declaration(
        &mut specified,
        &node,
        "border",
        "1px solid black",
        DeclMeta { important: false, inline: false, specificity: [0, 1, 0], order: 0 },
    );
    // Rule 2: `.card.featured { border-left-color: red; }` — higher
    // specificity [0,2,0], later order: wins for borderLeftColor only.
    apply_static_declaration(
        &mut specified,
        &node,
        "border-left-color",
        "red",
        DeclMeta { important: false, inline: false, specificity: [0, 2, 0], order: 1 },
    );
    // Inline style always wins regardless of specificity.
    apply_static_declaration(
        &mut specified,
        &node,
        "border-top-width",
        "3px",
        DeclMeta { important: false, inline: true, specificity: [1, 0, 0], order: 2 },
    );

    let map = &specified[&node];
    assert_eq!(map["borderLeftColor"].value, "red");
    assert_eq!(map["borderRightColor"].value, "black"); // untouched by rule 2
    assert_eq!(map["borderTopWidth"].value, "3px"); // inline beats specificity
    assert_eq!(map["borderTopColor"].value, "black");
}
