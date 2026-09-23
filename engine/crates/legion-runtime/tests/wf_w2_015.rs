//! Integration tests for the w2_015 port of the Impeccable design hook's
//! shared library (`skills/designer/engine/scripts/hook-lib.mjs`).
//!
//! NOTE: requires the integrator to wire `pub mod w2_015;` into
//! `legion-runtime::wf_port` (see `engine/crates/legion-runtime/src/wf_port/mod.rs`)
//! before this file will compile/run.

use std::collections::HashSet;

use legion_runtime::wf_port::w2_015::{
    color_ignore_key, dedupe_against_cache, extract_finding_ignore_value, filter_findings,
    finding_cache_key, format_finding_ignore_command, format_finding_line, matches_any_glob,
    normalize_ignore_value, parse_ignore_color, payload, should_emit_ack_for_file,
    suppression_notice, truthy, Finding, Harness, IgnoreValueEntry, EDIT_COUNT_THRESHOLD,
    ENVELOPE_PREFIX,
};

fn finding(antipattern: &str, line: i64) -> Finding {
    Finding {
        antipattern: antipattern.to_string(),
        line,
        ..Default::default()
    }
}

#[test]
fn constants_match_js_source() {
    assert_eq!(ENVELOPE_PREFIX, "[impeccable@1]");
    assert_eq!(EDIT_COUNT_THRESHOLD, 6);
}

#[test]
fn truthy_env_values() {
    assert!(truthy("1"));
    assert!(truthy("true"));
    assert!(truthy("YES"));
    assert!(!truthy("0"));
    assert!(!truthy(""));
}

#[test]
fn glob_matching_double_star_basename_and_alternation() {
    let globs = vec!["*.generated.tsx".to_string()];
    // Basename convenience match: `*.generated.tsx` catches a nested file
    // without requiring `**/`, per hook-lib.mjs's matchesAnyGlob comment.
    assert!(matches_any_glob("src/foo.generated.tsx", &globs));
    assert!(!matches_any_glob("src/foo.tsx", &globs));

    let alt = vec!["**/{a,b}.css".to_string()];
    assert!(matches_any_glob("dir/sub/a.css", &alt));
    assert!(matches_any_glob("dir/sub/b.css", &alt));
    assert!(!matches_any_glob("dir/sub/c.css", &alt));
}

#[test]
fn ignore_value_normalization_round_trip() {
    assert_eq!(normalize_ignore_value("\"Inter+UI\""), "inter ui");
    assert_eq!(normalize_ignore_value("  Roboto  Mono "), "roboto mono");
}

#[test]
fn color_parsing_hex_rgb_hsl_agree() {
    let hex = parse_ignore_color("#00ff00").unwrap();
    let rgb = parse_ignore_color("rgb(0, 255, 0)").unwrap();
    let hsl = parse_ignore_color("hsl(120, 100%, 50%)").unwrap();
    assert_eq!((hex.r, hex.g, hex.b), (rgb.r, rgb.g, rgb.b));
    assert_eq!((hex.r, hex.g, hex.b), (hsl.r, hsl.g, hsl.b));

    let key_hex = color_ignore_key("#00ff00");
    let key_rgb = color_ignore_key("rgb(0, 255, 0)");
    assert_eq!(key_hex, key_rgb);
}

#[test]
fn filter_findings_end_to_end_with_rule_and_scoped_value_ignores() {
    let mut f1 = finding("side-tab", 3);
    f1.file = Some("src/App.tsx".to_string());

    let mut f2 = finding("overused-font", 5);
    f2.value = Some("Comic Sans".to_string());
    f2.file = Some("src/App.tsx".to_string());

    let mut f3 = finding("overused-font", 9);
    f3.value = Some("Comic Sans".to_string());
    f3.file = Some("other/Widget.tsx".to_string());

    let mut ignore_rules = HashSet::new();
    ignore_rules.insert("side-tab".to_string());

    let ignore_values = vec![IgnoreValueEntry {
        rule: "overused-font".to_string(),
        value: "comic sans".to_string(),
        files: vec!["src/*.tsx".to_string()],
    }];

    let out = filter_findings(&[f1, f2, f3], &ignore_rules, &ignore_values);
    // f1 dropped by rule ignore, f2 dropped by scoped value ignore,
    // f3 survives because its file doesn't match the scope glob.
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].line, 9);
}

#[test]
fn dedupe_against_cache_and_cache_key_are_consistent() {
    let mut f = finding("overused-font", 5);
    f.value = Some("Inter".to_string());
    let key = finding_cache_key(&f);
    assert_eq!(key, "overused-font:5:inter");
    assert_eq!(extract_finding_ignore_value(&f), "inter");

    let known: HashSet<String> = HashSet::new();
    let (fresh, updated) = dedupe_against_cache(&[f.clone()], &known);
    assert_eq!(fresh.len(), 1);
    assert!(updated.contains(&key));

    // Second pass with the updated known set: no longer fresh.
    let (fresh2, _) = dedupe_against_cache(&[f], &updated);
    assert!(fresh2.is_empty());
}

#[test]
fn ignore_command_and_finding_line_render_together() {
    let mut f = finding("design-system-color", 12);
    f.value = Some("#ff0000".to_string());
    f.name = Some("Off design-system color".to_string());
    f.description = Some("Color not in the design system palette.".to_string());

    let cmd = format_finding_ignore_command(&f);
    assert!(cmd.contains("ignore-value design-system-color"));
    assert!(cmd.contains("--shared"));

    let line = format_finding_line(&f);
    assert!(line.starts_with("- L12 [design-system-color] Off design-system color."));
    assert!(line.contains(&cmd));
}

#[test]
fn suppression_notice_and_ack_ext_gate() {
    let notice = suppression_notice("src/Widget.tsx");
    assert!(notice.starts_with(ENVELOPE_PREFIX));
    assert!(notice.contains("src/Widget.tsx"));

    assert!(should_emit_ack_for_file("Widget.tsx"));
    assert!(!should_emit_ack_for_file("data.json"));
}

#[test]
fn payload_shapes_by_harness() {
    let claude: serde_json::Value =
        serde_json::from_str(&payload("hi", "PostToolUse", Harness::Claude)).unwrap();
    assert_eq!(claude["hookSpecificOutput"]["additionalContext"], "hi");

    let cursor: serde_json::Value =
        serde_json::from_str(&payload("hi", "PostToolUse", Harness::Cursor)).unwrap();
    assert_eq!(cursor["additional_context"], "hi");

    let github: serde_json::Value =
        serde_json::from_str(&payload("hi", "PostToolUse", Harness::Github)).unwrap();
    assert_eq!(github["additionalContext"], "hi");
}
