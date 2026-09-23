//! Integration tests for the ported `wf_port::w2_012` module, mirroring
//! `skills/designer/engine/scripts/detector/engines/{browser,regex,site,
//! static-html}/*` (chunk w2_012).

use legion_runtime::wf_port::w2_012::browser_url::{
    browser_executable_candidates, find_browser_executable, is_mobile_viewport, make_frame,
    read_frames, serialize_design_system_for_browser, DesignSystemInput,
};
use legion_runtime::wf_port::w2_012::css_cascade::{
    compare_static_priority, css_prop_to_camel, expand_static_box_values, extract_static_color,
    normalize_color_for_check, parse_static_animation, parse_static_border, parse_static_font,
    parse_static_style_attribute, parse_static_transition, split_css_list, split_css_tokens,
    static_color_to_css, static_specificity, unwrap_css_at_layer, DeclMeta,
};
use legion_runtime::wf_port::w2_012::detect_text::{
    analyze_dark_glow, analyze_em_dash_overuse, analyze_flat_type_hierarchy,
    analyze_marketing_buzzword, analyze_monotonous_spacing, analyze_numbered_section_markers,
    analyze_single_font, ext_from_file_path, has_border_radius, has_rounded, is_neutral_border_color,
    is_safe_element, run_page_level_analyzers, should_run_page_analyzers, strip_html_to_text,
};
use legion_runtime::wf_port::w2_012::sweep::{
    extract_links, missing_required_pages, page_is_linked, profiles_for, url_origin, url_pathname,
    UNIVERSAL_PAGES,
};

// ---------------------------------------------------------------------------
// sweep.mjs
// ---------------------------------------------------------------------------

#[test]
fn sweep_extract_links_matches_js_filtering_rules() {
    let html = std::fs::read_to_string(
        "tests/fixtures/wf_w2_012/sweep_sample_page.html",
    )
    .unwrap();
    let links = extract_links(&html, "https://example.com/");
    // 3 real internal links; mailto/tel/js/#/cdn-cgi all skipped.
    assert_eq!(links.len(), 3);
    assert!(links.iter().any(|l| l.href == "/pricing"));
    assert!(links.iter().any(|l| l.href == "/about"));
    assert!(links.iter().any(|l| l.href == "https://example.com/terms"));
}

#[test]
fn sweep_required_pages_end_to_end_for_ecommerce_profile() {
    let html = std::fs::read_to_string(
        "tests/fixtures/wf_w2_012/sweep_sample_page.html",
    )
    .unwrap();
    let links = extract_links(&html, "https://example.com/");
    let base_origin = url_origin("https://example.com/").unwrap();
    let internal: Vec<_> = links
        .into_iter()
        .filter(|l| url_origin(&l.resolved).as_deref() == Some(base_origin.as_str()))
        .collect();
    let profiles = profiles_for(Some("ecommerce"));
    let missing = missing_required_pages(&profiles, &internal);
    // Page links pricing/about/terms only: privacy, returns/refunds,
    // shipping, contact are all missing; "about" and "terms" are present.
    let missing_names: Vec<&str> = missing.iter().map(|(_, p)| p.name).collect();
    assert!(missing_names.contains(&"privacy policy"));
    assert!(missing_names.contains(&"returns/refunds"));
    assert!(missing_names.contains(&"shipping"));
    assert!(missing_names.contains(&"contact"));
    assert!(!missing_names.contains(&"about"));
    assert!(!missing_names.contains(&"terms / T&C"));
}

#[test]
fn sweep_page_is_linked_case_insensitive_on_path_or_text() {
    let page = UNIVERSAL_PAGES[1]; // terms / T&C
    let links = extract_links(r#"<a href="/TOS">Legal stuff</a>"#, "https://example.com/");
    assert!(page_is_linked(&page, &links));
    assert_eq!(url_pathname("https://example.com/TOS?x=1"), "/TOS");
}

// ---------------------------------------------------------------------------
// browser (detect-url.mjs / detect-url-cdp.mjs)
// ---------------------------------------------------------------------------

#[test]
fn browser_serialize_design_system_matches_js_shape() {
    let ds = DesignSystemInput {
        present: true,
        has_fonts: true,
        allowed_fonts: vec!["Inter".into()],
        has_colors: true,
        allowed_color_values: vec![Some((1.0, 2.0, 3.0))],
        has_radii: false,
        allowed_radii: vec![],
        has_pill_radius: false,
    };
    let out = serialize_design_system_for_browser(&ds).expect("present design system serializes");
    assert_eq!(out.allowed_colors, vec![(1.0, 2.0, 3.0)]);
    assert!(!DesignSystemInput::default().present);
    assert!(serialize_design_system_for_browser(&DesignSystemInput::default()).is_none());
}

#[test]
fn browser_cdp_frame_roundtrip_and_executable_lookup() {
    let mask = [9, 8, 7, 6];
    let frame = make_frame("{\"id\":1,\"method\":\"Page.enable\"}", mask);
    let (frames, rest) = read_frames(&frame);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].text.contains("Page.enable"));
    assert!(rest.is_empty());

    let candidates = browser_executable_candidates(true, Some("C:\\PF"), Some("C:\\PF86"), "");
    assert_eq!(candidates[0], "C:\\PF\\Google\\Chrome\\Application\\chrome.exe");
    let found = find_browser_executable(None, &candidates, |p| p.ends_with("msedge.exe"));
    assert!(found.unwrap().ends_with("msedge.exe"));

    assert!(is_mobile_viewport(375));
    assert!(!is_mobile_viewport(1280));
}

// ---------------------------------------------------------------------------
// css-cascade.mjs
// ---------------------------------------------------------------------------

#[test]
fn css_cascade_unwrap_at_layer_then_reparse_specificity() {
    let source = "@layer utilities { .btn#primary { color: red; } }";
    let unwrapped = unwrap_css_at_layer(source);
    assert_eq!(unwrapped.trim(), ".btn#primary { color: red; }");
    assert_eq!(static_specificity(".btn#primary"), [1, 1, 0]);
}

#[test]
fn css_cascade_border_shorthand_to_camel_and_priority() {
    let border = parse_static_border("2px dashed #336699");
    assert_eq!(border.width, "2px");
    assert_eq!(border.color, "#336699");
    assert_eq!(css_prop_to_camel("border-left-color"), "borderLeftColor");
    assert_eq!(normalize_color_for_check("#336699"), "rgb(51, 102, 153)");
    assert_eq!(extract_static_color("2px dashed #336699"), "#336699");

    let base = DeclMeta { important: false, inline: false, specificity: [0, 1, 0], order: 2 };
    let stronger = DeclMeta { important: true, inline: false, specificity: [0, 0, 0], order: 0 };
    assert!(compare_static_priority(Some(&base), &stronger));
}

#[test]
fn css_cascade_box_font_transition_animation_and_style_attr() {
    assert_eq!(
        expand_static_box_values(&["4px".into(), "8px".into()]),
        ["4px", "8px", "4px", "8px"]
    );
    let font = parse_static_font("bold 18px/1.4 'Helvetica Neue', sans-serif");
    assert!(font.iter().any(|(p, v)| *p == "fontSize" && v == "18px"));
    let transition = parse_static_transition("width .2s ease, opacity .2s linear");
    assert_eq!(transition.property, "width, opacity");
    let animation = parse_static_animation("spin 2s linear infinite");
    assert_eq!(animation.property, "spin");
    let decls = parse_static_style_attribute("color:red!important", 5);
    assert_eq!(decls[0].order, 5);
    assert!(decls[0].important);
    assert_eq!(static_color_to_css(0.0, 0.0, 0.0, 0.5), "rgba(0, 0, 0, 0.5)");
    assert_eq!(split_css_list("a, b(1, 2), c"), vec!["a", "b(1, 2)", "c"]);
    assert_eq!(split_css_tokens("solid 1px red"), vec!["solid", "1px", "red"]);
}

// ---------------------------------------------------------------------------
// detect-text.mjs
// ---------------------------------------------------------------------------

#[test]
fn detect_text_gating_predicates() {
    assert_eq!(ext_from_file_path("Component.TSX"), ".tsx");
    assert!(should_run_page_analyzers(true, "page.astro"));
    assert!(!should_run_page_analyzers(true, "component.jsx"));
    assert!(has_rounded("rounded-full"));
    assert!(has_border_radius("border-radius:8px"));
    assert!(is_safe_element("<code>x</code>"));
    assert!(is_neutral_border_color("border-right: 4px solid silver"));
    assert!(!is_neutral_border_color("border-right: 4px solid #ff00aa"));
    assert_eq!(strip_html_to_text("<b>Bold</b>  text"), " Bold text");
}

#[test]
fn detect_text_page_level_analyzers_on_fixture_page() {
    let html = std::fs::read_to_string(
        "tests/fixtures/wf_w2_012/detect_text_ai_generated_page.html",
    )
    .unwrap();
    let findings = run_page_level_analyzers(&html);
    let ids: Vec<&str> = findings.iter().map(|f| f.antipattern).collect();
    assert!(ids.contains(&"single-font"));
    assert!(ids.contains(&"marketing-buzzword"));
    assert!(ids.contains(&"em-dash-overuse"));
    assert!(ids.contains(&"numbered-section-markers"));
}

#[test]
fn detect_text_individual_analyzer_thresholds() {
    assert!(analyze_em_dash_overuse("a—b—c—d").is_none()); // 4 < 5
    assert!(analyze_em_dash_overuse("a—b—c—d—e—f").is_some()); // 6 >= 5

    let css = "h1{font-size:22px}h2{font-size:20px}p{font-size:18px}";
    assert!(analyze_flat_type_hierarchy(css).is_some()); // ratio < 2
    let wide = "h1{font-size:64px}p{font-size:12px}span{font-size:10px}";
    assert!(analyze_flat_type_hierarchy(wide).is_none());

    let repeated: String = (0..15).map(|_| "div{margin:24px}").collect::<Vec<_>>().join("");
    assert!(analyze_monotonous_spacing(&repeated).is_some());

    let dark = "body{background-color:#0a0a0a}.x{box-shadow:0 0 30px rgba(255,0,150,0.6)}";
    assert!(analyze_dark_glow(dark).is_some());

    assert!(analyze_numbered_section_markers("01 02 03 done").is_some());
    assert!(analyze_marketing_buzzword("this is industry-leading and world-class").is_some());
    assert!(analyze_single_font("plain text with no font-family", &[]).is_none());
}
