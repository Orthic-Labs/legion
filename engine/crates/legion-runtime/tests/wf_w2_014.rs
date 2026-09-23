//! Integration tests for the ported `wf_port::w2_014` module, mirroring
//! `skills/designer/engine/scripts/detector/{shared/color.mjs,
//! registry/antipatterns.mjs}`.
//!
//! `shared/constants.mjs` and `shared/page.mjs` are not re-tested here:
//! they are already covered by `p8_designer_smoke.rs` against
//! `p8_designer::constants` / `p8_designer::page`. `rules/checks.mjs` is
//! covered where already ported by `l6_designer_checks_smoke.rs`.

use legion_runtime::wf_port::w2_014::antipatterns::{
    filter_by_providers, get_antipattern, get_rule_engine_support, get_rules_for_category,
    Category, HasAntipatternId, Severity, ANTIPATTERNS, GATED_PROVIDERS,
};
use legion_runtime::wf_port::w2_014::color::{
    color_to_hex, contrast_ratio, get_hue, has_chroma, is_neutral_color, parse_gradient_colors,
    parse_rgb, relative_luminance, Rgba,
};

// ─── color.mjs ──────────────────────────────────────────────────────────

#[test]
fn is_neutral_color_matches_js_across_formats() {
    assert!(is_neutral_color(None));
    assert!(is_neutral_color(Some("transparent")));
    assert!(is_neutral_color(Some("rgb(120, 120, 130)")));
    assert!(!is_neutral_color(Some("rgb(10, 10, 200)")));
    assert!(is_neutral_color(Some("oklch(60% 0.01 20)")));
    assert!(!is_neutral_color(Some("oklch(60% 0.2 20)")));
    assert!(is_neutral_color(Some("hsl(10, 4%, 50%)")));
    assert!(!is_neutral_color(Some("hsl(10, 40%, 50%)")));
}

#[test]
fn parse_rgb_extracts_channels_and_alpha() {
    let c = parse_rgb(Some("rgba(12, 34, 56, 0.25)")).unwrap();
    assert_eq!((c.r, c.g, c.b, c.a), (12.0, 34.0, 56.0, 0.25));
    assert!(parse_rgb(Some("not-a-color")).is_none());
}

#[test]
fn contrast_ratio_is_symmetric_and_bounded() {
    let black = Rgba { r: 0.0, g: 0.0, b: 0.0, a: 1.0 };
    let white = Rgba { r: 255.0, g: 255.0, b: 255.0, a: 1.0 };
    let ratio = contrast_ratio(black, white);
    assert!((ratio - 21.0).abs() < 1e-6);
    assert_eq!(ratio, contrast_ratio(white, black));
    assert!((relative_luminance(black)).abs() < 1e-9);
}

#[test]
fn parse_gradient_colors_reads_rgb_and_hex_stops() {
    let stops = parse_gradient_colors(Some(
        "linear-gradient(90deg, rgba(1,2,3,0.5), #abcdef)",
    ));
    assert_eq!(stops.len(), 2);
    assert_eq!(stops[0], Rgba { r: 1.0, g: 2.0, b: 3.0, a: 0.5 });
}

#[test]
fn has_chroma_and_get_hue_and_hex_roundtrip() {
    let tinted = Rgba { r: 200.0, g: 50.0, b: 50.0, a: 1.0 };
    assert!(has_chroma(Some(tinted), 30.0));
    assert_eq!(get_hue(Some(tinted)), 0.0);
    assert_eq!(color_to_hex(Some(tinted)), "#c83232");
}

// ─── antipatterns.mjs ───────────────────────────────────────────────────

#[test]
fn registry_ids_are_unique_and_nonempty() {
    let mut ids: Vec<&str> = ANTIPATTERNS.iter().map(|r| r.id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), before, "duplicate antipattern id");
    assert!(!ANTIPATTERNS.is_empty());
}

#[test]
fn get_antipattern_looks_up_known_and_unknown_ids() {
    assert!(get_antipattern("low-contrast").is_some());
    assert!(get_antipattern("nonexistent-rule").is_none());
}

#[test]
fn get_rules_for_category_partitions_registry() {
    let slop = get_rules_for_category(Category::Slop).len();
    let quality = get_rules_for_category(Category::Quality).len();
    let structure = get_rules_for_category(Category::Structure).len();
    assert_eq!(slop + quality + structure, ANTIPATTERNS.len());
}

#[test]
fn advisory_severity_present_and_default_is_common() {
    let advisory = ANTIPATTERNS
        .iter()
        .filter(|r| r.severity == Severity::Advisory)
        .count();
    assert!(advisory > 0);
    assert!(advisory < ANTIPATTERNS.len());
}

#[test]
fn rule_engine_support_covers_documented_engines() {
    assert!(!get_rule_engine_support("regex").is_empty());
    assert!(!get_rule_engine_support("static-html").is_empty());
    assert!(!get_rule_engine_support("browser").is_empty());
    assert!(!get_rule_engine_support("visual").is_empty());
    assert!(get_rule_engine_support("nope").is_empty());
}

#[test]
fn gated_providers_matches_registry_gated_tags() {
    let expected: std::collections::HashSet<&str> =
        ANTIPATTERNS.iter().filter_map(|r| r.gated).collect();
    assert_eq!(GATED_PROVIDERS.clone(), expected);
}

struct Finding {
    antipattern: String,
}
impl HasAntipatternId for Finding {
    fn antipattern_id(&self) -> &str {
        &self.antipattern
    }
}

#[test]
fn filter_by_providers_keeps_ungated_and_matching_gated_only() {
    let findings = vec![
        Finding { antipattern: "low-contrast".into() },
        Finding { antipattern: "gpt-thin-border-wide-shadow".into() },
        Finding { antipattern: "image-hover-transform".into() },
    ];
    let kept = filter_by_providers(findings, &["gemini"]);
    let ids: Vec<&str> = kept.iter().map(|f| f.antipattern.as_str()).collect();
    assert_eq!(ids, vec!["low-contrast", "image-hover-transform"]);
}
