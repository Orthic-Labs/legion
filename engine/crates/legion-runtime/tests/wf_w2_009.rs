//! Integration tests for the ported `wf_port::w2_009` module (production
//! entry points), mirroring `skills/designer/engine/huashu/scripts/verify.py`.

use legion_runtime::wf_port::w2_009::{
    default_output_dir, format_console_event, parse_viewport, parse_viewports_arg,
    slide_screenshot_filename, viewport_screenshot_filenames, viewport_suffix, Args, Viewport,
    VerifyReport, DEFAULT_VIEWPORT, DEFAULT_VIEWPORTS_ARG,
};
use std::path::{Path, PathBuf};

#[test]
fn cli_single_viewport_default_matches_python_default() {
    let a = Args::defaults_for("skills/designer/huashu/design.html");
    let vs = parse_viewports_arg(&a.viewports).unwrap();
    assert_eq!(vs, vec![DEFAULT_VIEWPORT]);
    assert_eq!(a.viewports, DEFAULT_VIEWPORTS_ARG);
}

#[test]
fn cli_multi_viewport_parses_each_token() {
    let vs = parse_viewports_arg("1920x1080,375x667").unwrap();
    assert_eq!(
        vs,
        vec![
            Viewport {
                width: 1920,
                height: 1080
            },
            Viewport {
                width: 375,
                height: 667
            },
        ]
    );
}

#[test]
fn cli_bad_viewport_token_is_rejected() {
    assert!(parse_viewport("bogus").is_err());
    assert!(parse_viewports_arg("1920x1080,bogus").is_err());
}

#[test]
fn output_dir_defaults_to_screenshots_sibling_of_html() {
    let html = Path::new("/repo/skills/designer/huashu/design.html");
    assert_eq!(
        default_output_dir(html),
        PathBuf::from("/repo/skills/designer/huashu/screenshots")
    );
}

#[test]
fn slides_mode_filenames_are_one_based_zero_padded() {
    let names: Vec<String> = (1..=3).map(|i| slide_screenshot_filename("deck", i)).collect();
    assert_eq!(
        names,
        vec!["deck-slide-01.png", "deck-slide-02.png", "deck-slide-03.png"]
    );
}

#[test]
fn single_viewport_non_slides_filenames_have_no_suffix() {
    let suffix = viewport_suffix(DEFAULT_VIEWPORT, 1);
    let (clipped, full) = viewport_screenshot_filenames("design", &suffix);
    assert_eq!(clipped, "design.png");
    assert_eq!(full, "design-full.png");
}

#[test]
fn multi_viewport_non_slides_filenames_include_dimensions() {
    let vp = Viewport {
        width: 375,
        height: 667,
    };
    let suffix = viewport_suffix(vp, 2);
    let (clipped, full) = viewport_screenshot_filenames("design", &suffix);
    assert_eq!(clipped, "design-375x667.png");
    assert_eq!(full, "design-375x667-full.png");
}

#[test]
fn console_event_filter_keeps_only_error_and_warning() {
    assert!(format_console_event("error", "x").is_some());
    assert!(format_console_event("warning", "x").is_some());
    assert!(format_console_event("log", "x").is_none());
    assert!(format_console_event("info", "x").is_none());
}

#[test]
fn report_exit_code_and_text_follow_page_errors_only() {
    let clean = VerifyReport {
        console_errors: vec!["[warning] noisy".to_string()],
        output_dir: PathBuf::from("out"),
        ..Default::default()
    };
    assert_eq!(clean.exit_code(), 0);

    let broken = VerifyReport {
        page_errors: vec!["TypeError: boom".to_string()],
        output_dir: PathBuf::from("out"),
        ..Default::default()
    };
    assert_eq!(broken.exit_code(), 1);
    assert!(broken.render().contains("TypeError: boom"));
}
