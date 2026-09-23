//! Integration tests for the w2_022 port of the Impeccable Live Mode Svelte
//! scripts (`skills/designer/engine/scripts/live/{svelte-component,
//! sveltekit-adapter,ui-core,vocabulary}.mjs`).
//!
//! NOTE: requires the integrator to wire `pub mod wf_port;` (if not already
//! present) and `pub mod w2_022;` into `legion-runtime::wf_port`
//! (see `engine/crates/legion-runtime/src/wf_port/mod.rs`) before this file
//! will compile/run.

use std::collections::HashMap;

use legion_runtime::wf_port::w2_022::svelte_component::{
    append_css_to_svelte_style, bake_param_values_in_css, build_insert_variant_stub,
    build_prop_contract, build_props_script, build_svelte_component_css_authoring,
    build_variant_stub, extract_mustache_expressions, match_opening_tag,
    merge_original_top_level_attrs, parse_attr_segments, parse_css_rules,
    parse_svelte_component_file, sanitize_accepted_svelte_css, substitute_exprs_with_props,
    substitute_props_with_exprs, svelte_markup_has_visible_content, ParamValue,
    DEFERRED_ACCEPTS_FILE, SVELTE_COMPONENT_ROOT,
};
use legion_runtime::wf_port::w2_022::sveltekit_adapter::{
    build_svelte_live_root_component, patch_svelte_layout, unpatch_svelte_layout,
    SVELTE_LAYOUT_MARKER_CLOSE, SVELTE_LAYOUT_MARKER_OPEN, SVELTE_LIVE_ROOT_COMPONENT,
    SVELTE_ROOT_IMPORT,
};
use legion_runtime::wf_port::w2_022::ui_core::{
    escape_css_ident, live_ui_component_ids, LIVE_CHROME_MOUNT_CONTRACT, LIVE_UI_SURFACES,
};
use legion_runtime::wf_port::w2_022::vocabulary::{live_commands, visual_actions};

// --- vocabulary.mjs -----------------------------------------------------

#[test]
fn vocabulary_has_twelve_commands_matching_js_order() {
    let values: Vec<&str> = live_commands().iter().map(|c| c.value).collect();
    assert_eq!(
        values,
        vec![
            "impeccable", "bolder", "quieter", "distill", "polish", "typeset", "colorize",
            "layout", "morph", "animate", "delight", "overdrive",
        ]
    );
    assert_eq!(visual_actions(), values);
}

// --- ui-core.mjs ---------------------------------------------------------

#[test]
fn ui_core_mount_contract_and_surfaces() {
    assert_eq!(LIVE_CHROME_MOUNT_CONTRACT, ["root", "transport", "state", "actions"]);
    assert_eq!(LIVE_UI_SURFACES.len(), 14);
    let ids = live_ui_component_ids();
    assert!(ids.contains(&"impeccable-live-picker"));
    // Deduped: "impeccable-live-bar" appears in 3 surfaces but once in ids.
    assert_eq!(ids.iter().filter(|id| **id == "impeccable-live-bar").count(), 1);
}

#[test]
fn ui_core_escape_css_ident() {
    assert_eq!(escape_css_ident("a.b#c"), "a\\.b\\#c");
}

// --- svelte-component.mjs -------------------------------------------------

#[test]
fn svelte_component_constants() {
    assert_eq!(SVELTE_COMPONENT_ROOT, "node_modules/.impeccable-live");
    assert_eq!(DEFERRED_ACCEPTS_FILE, ".impeccable/live/deferred-svelte-component-accepts.json");
}

#[test]
fn svelte_component_prop_contract_round_trip() {
    let markup = "<p>{user.name}</p><span>{count}</span>";
    let exprs = extract_mustache_expressions(markup);
    assert_eq!(exprs, vec!["user.name".to_string(), "count".to_string()]);

    let contract = build_prop_contract(&exprs);
    assert_eq!(contract[0].prop, "name");
    // Spec (`svelte-component.mjs` `derivePropName`, confirmed against the JS
    // source directly): the tail-name regex only matches after `.` or `[`, so
    // a bare identifier expression like `count` falls through to the
    // index-based fallback `prop${index}` rather than keeping its own name.
    assert_eq!(contract[1].prop, "prop1");

    let with_props = substitute_exprs_with_props(markup, &contract);
    assert_eq!(with_props, "<p>{name}</p><span>{prop1}</span>");

    let restored = substitute_props_with_exprs(&with_props, &contract);
    assert_eq!(restored, markup);
}

#[test]
fn svelte_component_parse_and_stub_pipeline() {
    let source = "<script>\n  let x = 1;\n</script>\n<div class=\"row\">{item.label}</div>\n<style>\n  .row { padding: 4px; }\n</style>\n";
    let parsed = parse_svelte_component_file(source);
    assert_eq!(parsed.markup, r#"<div class="row">{item.label}</div>"#);
    assert_eq!(parsed.css_lines, vec!["  .row { padding: 4px; }".to_string()]);

    let contract = build_prop_contract(&extract_mustache_expressions(&parsed.markup));
    let original_with_props = substitute_exprs_with_props(&parsed.markup, &contract);
    let stub = build_variant_stub(1, &original_with_props, &contract);
    assert!(stub.contains("let { label } = $props();"));
    assert!(stub.contains("<!-- Props: label <- {item.label} -->"));
    assert!(stub.contains(r#"<div class="row">{label}</div>"#));

    let insert_stub = build_insert_variant_stub(1);
    assert!(insert_stub.contains("Insert variant 1"));
    assert_eq!(build_props_script(&[]).contains("let {} = $props();"), true);
}

#[test]
fn svelte_component_attr_merge_and_opening_tag() {
    let tag = match_opening_tag(r#"<div class="a" id="b">x</div>"#).unwrap();
    assert_eq!(tag.tag, "div");
    let segs = parse_attr_segments(&tag.attrs);
    assert_eq!(segs.len(), 2);

    let merged = merge_original_top_level_attrs(
        r#"<div class="foo">x</div>"#,
        r#"<div class="bar" data-testid="row">y</div>"#,
    );
    assert!(merged.contains(r#"class="foo bar""#));
    assert!(merged.contains(r#"data-testid="row""#));
}

#[test]
fn svelte_component_visible_content_check() {
    assert!(svelte_markup_has_visible_content("<p>Hello</p>"));
    assert!(!svelte_markup_has_visible_content("<!-- nothing -->"));
    assert!(svelte_markup_has_visible_content(r#"<img src="a.png" />"#));
}

#[test]
fn svelte_component_css_rule_parsing() {
    let rules = parse_css_rules(".a { color: red; } .b { color: blue; }");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].prelude, ".a");
}

#[test]
fn svelte_component_accepted_css_sanitizer_filters_by_variant() {
    let css = vec![
        r#"@scope ([data-impeccable-variant="1"]) { .row { padding: 4px; } }"#.to_string(),
        r#"@scope ([data-impeccable-variant="2"]) { .row { padding: 8px; } }"#.to_string(),
    ];
    let out = sanitize_accepted_svelte_css(&css, 1, None, "div");
    let joined = out.join("\n");
    assert!(joined.contains("padding: 4px"));
    assert!(!joined.contains("padding: 8px"));
}

#[test]
fn svelte_component_bake_param_values() {
    let mut params: HashMap<String, ParamValue> = HashMap::new();
    params.insert("size".to_string(), ParamValue::Num(24.0));
    let css = vec!["  width: var(--p-size, 16px);".to_string()];
    assert_eq!(bake_param_values_in_css(&css, Some(&params)), vec!["  width: 24;".to_string()]);
}

#[test]
fn svelte_component_append_css_to_style_block() {
    let lines: Vec<String> = vec!["<div>x</div>".to_string()];
    let out = append_css_to_svelte_style(&lines, &["a { color: red; }".to_string()]);
    assert_eq!(out.last().unwrap(), "</style>");
}

#[test]
fn svelte_component_css_authoring_payload() {
    let payload = build_svelte_component_css_authoring(2);
    assert_eq!(payload.mode, "svelte-component");
    assert_eq!(payload.selector_examples.len(), 2);
}

// --- sveltekit-adapter.mjs -------------------------------------------------

#[test]
fn sveltekit_adapter_constants() {
    assert_eq!(SVELTE_LIVE_ROOT_COMPONENT, "src/lib/designer/ImpeccableLiveRoot.svelte");
    assert_eq!(SVELTE_LAYOUT_MARKER_OPEN, "<!-- impeccable-live-svelte-start -->");
    assert_eq!(SVELTE_LAYOUT_MARKER_CLOSE, "<!-- impeccable-live-svelte-end -->");
    assert!(SVELTE_ROOT_IMPORT.contains("ImpeccableLiveRoot"));
}

#[test]
fn sveltekit_adapter_patch_and_unpatch_round_trip() {
    let before = "<script>\n  let { children } = $props();\n</script>\n\n{@render children?.()}\n";
    let patched = patch_svelte_layout(before);
    assert!(patched.contains(SVELTE_ROOT_IMPORT));
    assert!(patched.contains("<ImpeccableLiveRoot />"));

    // Idempotent: patching an already-patched layout changes nothing.
    assert_eq!(patch_svelte_layout(&patched), patched);

    let unpatched = unpatch_svelte_layout(&patched);
    assert!(!unpatched.contains(SVELTE_ROOT_IMPORT));
    assert!(!unpatched.contains("<ImpeccableLiveRoot"));
    assert!(unpatched.contains("{@render children?.()}"));
}

#[test]
fn sveltekit_adapter_builds_root_component_template() {
    let out = build_svelte_live_root_component(4321);
    assert!(out.contains("http://localhost:4321/live.js"));
    assert!(out.trim_end().ends_with("</script>"));
}
