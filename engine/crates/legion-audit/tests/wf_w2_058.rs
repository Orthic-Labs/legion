//! Integration-level assertions for the w2_058 port
//! (`src/providers/accessibility/contrast.mjs`).
//!
//! The pure behavior-level assertions live as unit tests inside
//! `src/wf_port/w2_058/mod.rs` (co-located with the function they exercise,
//! per this crate's existing wf_port convention). This file adds a
//! fixture-driven check that runs `analyze_contrast` over a realistic set
//! of foreground/background pairs, as `accessibility/contrast.mjs` would
//! receive from its callers.
//!
//! NOTE: `legion_audit::wf_port::w2_058` is expected to be wired by the
//! integrator via `pub mod wf_port;` / `pub mod w2_058;` in the crate's
//! module tree (see chunk instructions). This file is written against that
//! path and will start compiling once that wiring lands.

use std::fs;
use std::path::PathBuf;

use legion_audit::wf_port::w2_058::analyze_contrast;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_058")
}

fn sample_pairs() -> Vec<serde_json::Value> {
    let raw = fs::read_to_string(fixtures_dir().join("sample_pairs.json"))
        .expect("fixture should exist");
    serde_json::from_str(&raw).expect("sample_pairs.json must be valid JSON")
}

#[test]
fn sample_pairs_fixture_is_well_formed() {
    let pairs = sample_pairs();
    assert_eq!(pairs.len(), 4);
    for pair in &pairs {
        assert!(pair.get("foreground").is_some());
        assert!(pair.get("background").is_some());
    }
}

#[test]
fn analyze_contrast_over_sample_pairs_matches_expected_shape() {
    let pairs = sample_pairs();
    let out = analyze_contrast(&pairs);

    // provider is always overridden to the accessibility-domain name,
    // regardless of the delegate's own provider label.
    assert_eq!(out["provider"], serde_json::json!("accessibility.contrast"));

    // 4 pairs total; one is unresolved (var(--fg)) so only 3 are examined.
    assert_eq!(out["denominator"]["kind"], serde_json::json!("color-pairs"));
    assert_eq!(out["denominator"]["expected"], serde_json::json!(4));
    assert_eq!(out["denominator"]["examined"], serde_json::json!(3));

    // The muted caption (#cccccc on #ffffff) fails the 4.5 minimum.
    let findings = out["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["selector"], serde_json::json!(".muted-caption"));
    assert!(findings[0]["ratio"].as_f64().unwrap() < 4.5);

    // The unresolved pair produces exactly one coverage gap.
    let gaps = out["coverageGaps"].as_array().expect("coverageGaps array");
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0], serde_json::json!("color-pair-unresolved"));

    // findings present -> status is "candidates"; coverage gap present -> incomplete.
    assert_eq!(out["status"], serde_json::json!("candidates"));
    assert_eq!(out["complete"], serde_json::json!(false));
}

#[test]
fn analyze_contrast_all_passing_pairs_is_complete_and_pass() {
    let pairs = vec![
        serde_json::json!({ "foreground": "#000000", "background": "#ffffff" }),
        serde_json::json!({ "foreground": "#1a73e8", "background": "#ffffff" }),
    ];
    let out = analyze_contrast(&pairs);
    assert_eq!(out["status"], serde_json::json!("pass"));
    assert_eq!(out["complete"], serde_json::json!(true));
    assert!(out["findings"].as_array().unwrap().is_empty());
    assert!(out["coverageGaps"].as_array().unwrap().is_empty());
}
