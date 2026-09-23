//! Port of `tests/arcane-package-policy-compiler.test.mjs` for chunk wf008
//! (`src/lib/guard/compat/rules/policy-compiler.mjs`).

use legion_policy::wf_port::wf008::{compile_policy_rules, parse_policy_rules, ParsedRule};
use serde_json::Value;

fn base() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wf_wf008/arcane-policy-v1.json"
    ))
    .expect("fixture readable");
    serde_json::from_str(&text).expect("fixture is valid JSON")
}

fn source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wf_wf008/arcane-policy-v1.rules"
    ))
    .expect("fixture readable")
}

#[test]
fn canonical_controlled_english_rules_reproduce_every_policy_effect_rule() {
    let base = base();
    let compiled = compile_policy_rules(&source(), &base).expect("compiles");
    assert_eq!(compiled.get("effectRules"), base.get("effectRules"));
}

#[test]
fn compiler_rejects_unknown_effect_class() {
    let base = base();
    // JS `String.prototype.replace` with a string pattern replaces only the
    // first match; `replacen(.., 1)` is the faithful Rust equivalent (plain
    // `.replace` would rewrite every occurrence).
    let bad = source().replacen("FILE_WRITE", "UNKNOWN", 1);
    let err = compile_policy_rules(&bad, &base).unwrap_err();
    assert!(err.0.contains("unknown effect class"), "{}", err.0);
}

#[test]
fn compiler_rejects_duplicate_effect_class() {
    let base = base();
    let bad = format!(
        "{}\nallow FILE_WRITE approval=none trust=capability-signature enforcement=strong",
        source()
    );
    let err = compile_policy_rules(&bad, &base).unwrap_err();
    assert!(err.0.contains("duplicate effect class"), "{}", err.0);
}

#[test]
fn compiler_rejects_missing_effect_class() {
    let base = base();
    let src = source();
    // Mirrors the JS test's `source.replace(/^.*FILE_WRITE.*\n/m, '')`:
    // drop the first line that mentions FILE_WRITE.
    let mut dropped = false;
    let bad: String = src
        .lines()
        .filter(|line| {
            if !dropped && line.contains("FILE_WRITE") {
                dropped = true;
                false
            } else {
                true
            }
        })
        .map(|line| format!("{line}\n"))
        .collect();
    assert!(dropped, "fixture must contain a FILE_WRITE line");
    let err = compile_policy_rules(&bad, &base).unwrap_err();
    assert!(err.0.contains("missing effect class"), "{}", err.0);
}

#[test]
fn compiler_rejects_schema_invalid_enforcement_value() {
    let base = base();
    let bad = source().replacen("enforcement=strong", "enforcement=advisory", 1);
    let err = compile_policy_rules(&bad, &base).unwrap_err();
    assert!(err.0.contains("compiled policy failed validation"), "{}", err.0);
}

#[test]
fn parser_permits_comments_blanks_and_escaped_note_text_only() {
    let parsed = parse_policy_rules(
        "# comment\n\nallow FILE_WRITE approval=none trust=capability-signature enforcement=strong note=\"quoted \\\"note\\\"\"",
    )
    .expect("parses");
    assert_eq!(
        parsed,
        vec![ParsedRule {
            effect_class: "FILE_WRITE".to_string(),
            rule: "allow".to_string(),
            approval_required: false,
            trust_minimum: "capability-signature".to_string(),
            required_enforcement: "strong".to_string(),
            note: Some("quoted \"note\"".to_string()),
        }]
    );
}

#[test]
fn parser_rejects_invalid_trust_value() {
    let err = parse_policy_rules("allow FILE_WRITE approval=none trust=other enforcement=strong").unwrap_err();
    assert!(err.0.contains("invalid rule"), "{}", err.0);
}
