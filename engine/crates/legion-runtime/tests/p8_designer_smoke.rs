//! Packet P8-designer integration smoke test against the production entry
//! points in `legion_runtime::p8_designer`.
//!
//! This exercises the module's public API through the crate root the way an
//! external caller (a future `legion` subcommand) would, rather than only
//! the in-file unit tests.

use legion_runtime::p8_designer::{
    is_brand_font_on_own_domain, is_full_page, is_generated_file, parse_target_path,
    IsGeneratedOptions, WCAG_LARGE_TEXT_PX,
};

#[test]
fn target_args_round_trip_through_crate_root() {
    let args: Vec<String> = vec!["--target".into(), "src/index.html".into()];
    assert_eq!(
        parse_target_path(&args, false).unwrap(),
        Some("src/index.html".to_string())
    );
}

#[test]
fn page_detection_through_crate_root() {
    assert!(is_full_page("<!doctype html><html><body></body></html>"));
    assert!(!is_full_page("<section><p>partial</p></section>"));
}

#[test]
fn brand_font_and_wcag_constant_through_crate_root() {
    assert!(is_brand_font_on_own_domain("mona sans", Some("github.com")));
    assert!((WCAG_LARGE_TEXT_PX - 24.0).abs() < 1e-9);
}

#[test]
fn is_generated_file_missing_path_through_crate_root() {
    let opts = IsGeneratedOptions {
        cwd: Some(std::env::temp_dir()),
    };
    assert!(!is_generated_file("definitely-missing-file.html", &opts));
}
