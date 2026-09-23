//! Crate-root public API smoke tests for the L6 designer-checks port.
//! Mirrors `skills/designer/engine/scripts/detector/rules/checks.mjs`
//! behavior for the functions ported so far (local CSS/shadow color parsing
//! and the pure checks built on it). See `full-L6.md` for the packet report.

use legion_runtime::l6_designer_checks::{
    check_gpt_thin_border_wide_shadow, check_italic_serif, check_oversized_h1,
    is_card_like_from_props, is_emoji_only_text, parse_any_color, resolve_serif, ItalicSerifInput,
    OversizedH1Input,
};

#[test]
fn parse_any_color_round_trips_hex() {
    let c = parse_any_color("#336699").expect("parses");
    assert_eq!((c.r, c.g, c.b), (51.0, 102.0, 153.0));
}

#[test]
fn is_emoji_only_text_public_api() {
    assert!(is_emoji_only_text("🎉"));
    assert!(!is_emoji_only_text("party 🎉"));
}

#[test]
fn is_card_like_from_props_public_api() {
    assert!(is_card_like_from_props(true, false, true, false));
    assert!(!is_card_like_from_props(false, false, true, true));
}

#[test]
fn resolve_serif_public_api() {
    let r = resolve_serif(Some("Times New Roman, serif"));
    assert!(r.is_serif);
}

#[test]
fn check_italic_serif_public_api_hero() {
    let findings = check_italic_serif(ItalicSerifInput {
        tag: "h1",
        font_style: "italic",
        font_family: Some("Georgia, serif"),
        font_size: 64.0,
        heading_text: "A big serif hero headline",
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "italic-serif-display");
}

#[test]
fn check_oversized_h1_public_api() {
    let findings = check_oversized_h1(OversizedH1Input {
        tag: "h1",
        font_size: 90.0,
        heading_text: &"a very long hero headline that runs on and on".repeat(1),
        rect: None,
        viewport_width: 0.0,
        viewport_height: 0.0,
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "oversized-h1");
}

#[test]
fn check_gpt_thin_border_wide_shadow_public_api() {
    let widths = [1.0, 1.0, 0.0, 0.0];
    let colors = ["rgba(0,0,0,0.5)", "rgba(0,0,0,0.5)", "", ""];
    let findings = check_gpt_thin_border_wide_shadow(&widths, &colors, "0 4px 20px rgba(0,0,0,0.3)");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "gpt-thin-border-wide-shadow");
}
