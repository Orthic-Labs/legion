//! Integration tests for the ported `wf_port::w2_011` module (production
//! entry points), mirroring
//! `skills/designer/engine/scripts/detector/cli/main.mjs` (output
//! formatting only) and `skills/designer/engine/scripts/detector/design-system.mjs`.
//!
//! See `src/wf_port/w2_011/mod.rs` for what this chunk does and does not
//! port (browser-injected DOM scripts are out of scope by nature).

use legion_runtime::wf_port::w2_011::{
    check_source_design_system, format_finding_summary, format_findings, is_allowed_color_raw,
    is_allowed_font, is_allowed_radius_raw, merge_design_system_findings,
    normalize_design_system, parse_frontmatter, usage_text, DesignFinding, Finding,
};

fn finding(file: &str, line: u32, antipattern: &str, snippet: &str, description: &str) -> Finding {
    Finding {
        file: file.to_string(),
        line,
        antipattern: antipattern.to_string(),
        snippet: snippet.to_string(),
        description: description.to_string(),
        imported_by: Vec::new(),
    }
}

#[test]
fn format_finding_summary_matches_js_pluralization() {
    assert_eq!(format_finding_summary(0), "0 anti-patterns found.");
    assert_eq!(format_finding_summary(1), "1 anti-pattern found.");
    assert_eq!(format_finding_summary(5), "5 anti-patterns found.");
}

#[test]
fn format_findings_text_mode_matches_js_shape() {
    let findings = vec![finding(
        "src/App.jsx",
        12,
        "border-glow",
        "box-shadow: 0 0 8px",
        "Glow border detected",
    )];
    let out = format_findings(&findings, false);
    let expected = "\nsrc/App.jsx\n  line 12: [border-glow] box-shadow: 0 0 8px\n    \u{2192} Glow border detected\n\n1 anti-pattern found.";
    assert_eq!(out, expected);
}

#[test]
fn format_findings_json_mode_is_valid_json() {
    let findings = vec![finding("a.html", 0, "x", "s", "d")];
    let json = format_findings(&findings, true);
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}

#[test]
fn usage_text_lists_documented_flags() {
    let text = usage_text();
    for flag in [
        "--json",
        "--quiet",
        "--gpt",
        "--gemini",
        "--no-config",
        "--no-design-system",
        "--viewport=WxH",
        "--mobile",
        "--tablet",
        "--site",
        "--site-type=T",
        "--help",
    ] {
        assert!(text.contains(flag), "usage text missing {flag}");
    }
}

const DESIGN_MD: &str = "---\ntypography:\n  body:\n    fontFamily: \"Inter, sans-serif\"\ncolors:\n  brand: \"#336699\"\n  accent: \"oklch(70% 0.15 30)\"\nrounded:\n  full: 999px\n  sm: 4px\n---\n\n# Design\n";

#[test]
fn design_system_end_to_end_from_markdown_frontmatter() {
    let frontmatter = parse_frontmatter(DESIGN_MD).expect("frontmatter parses");
    let ds = normalize_design_system(&frontmatter, Some("DESIGN.md".to_string()), None, false);

    assert!(ds.has_fonts && ds.has_colors && ds.has_radii);
    assert!(is_allowed_font("inter", Some(&ds)));
    assert!(!is_allowed_font("papyrus", Some(&ds)));
    assert!(is_allowed_color_raw("#336699", Some(&ds)));
    assert!(!is_allowed_color_raw("#123456", Some(&ds)));
    assert!(is_allowed_radius_raw("4px", Some(&ds)));
    assert!(!is_allowed_radius_raw("20px", Some(&ds)));

    let source = "h1 { font-family: Papyrus, serif; color: #123456; border-radius: 20px; }\n";
    let findings = check_source_design_system(source, "styles.css", Some(&ds));
    let kinds: Vec<&str> = findings.iter().map(|f| f.antipattern.as_str()).collect();
    assert!(kinds.contains(&"design-system-font"));
    assert!(kinds.contains(&"design-system-color"));
    assert!(kinds.contains(&"design-system-radius"));
}

#[test]
fn design_system_absent_allows_everything() {
    assert!(is_allowed_font("papyrus", None));
    assert!(is_allowed_color_raw("#123456", None));
    assert!(is_allowed_radius_raw("20px", None));
    let findings = check_source_design_system("color: #123456;", "a.css", None);
    assert!(findings.is_empty());
}

#[test]
fn merge_design_system_findings_dedupes_across_groups() {
    let group_a = vec![DesignFinding {
        antipattern: "design-system-color".to_string(),
        file: "a.css".to_string(),
        snippet: "s".to_string(),
        line: 0,
        ignore_value: "#123456".to_string(),
    }];
    let group_b = vec![DesignFinding {
        antipattern: "design-system-color".to_string(),
        file: "a.css".to_string(),
        snippet: "s".to_string(),
        line: 7,
        ignore_value: "#123456".to_string(),
    }];
    let merged = merge_design_system_findings(vec![group_a, group_b]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].line, 7); // backfilled from the second group
}

#[test]
fn parse_frontmatter_rejects_documents_without_a_closing_fence() {
    assert!(parse_frontmatter("---\ncolors:\n  brand: red\n").is_none());
    assert!(parse_frontmatter("no frontmatter here at all").is_none());
}
