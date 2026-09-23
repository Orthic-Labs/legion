//! Integration tests for the wf_port w2_007 chunk: port of
//! `skills/designer/engine/huashu/scripts/{export_deck_stage_pdf.mjs,
//! fetch_images.py, gen_deck_thumbs.mjs, html2pptx.js, mix-voiceover.sh}`.
//!
//! NOTE: these tests reference `legion_runtime::wf_port::w2_007`, which
//! requires the integrator wiring described in the w2_007 report
//! (`pub mod wf_port;` in lib.rs already exists; `pub mod w2_007;` needs
//! adding to `engine/crates/legion-runtime/src/wf_port/mod.rs`).

use legion_runtime::wf_port::w2_007::{export_deck_stage_pdf, fetch_images, gen_deck_thumbs, html2pptx, mix_voiceover};
use std::path::{Path, PathBuf};

// ---- export_deck_stage_pdf.mjs -------------------------------------------

#[test]
fn export_deck_stage_pdf_full_cli_round_trip() {
    let argv: Vec<String> = vec!["--html", "deck.html", "--out", "deck.pdf", "--width", "1600", "--height", "900"]
        .into_iter()
        .map(String::from)
        .collect();
    let args = export_deck_stage_pdf::parse_args(&argv).expect("valid args");
    assert_eq!(args.width, 1600);
    assert_eq!(args.height, 900);

    let (html_abs, out_abs) = export_deck_stage_pdf::resolve_paths(&args, Path::new("/decks/q3"));
    assert_eq!(html_abs, PathBuf::from("/decks/q3/deck.html"));
    assert_eq!(out_abs, PathBuf::from("/decks/q3/deck.pdf"));

    let summary = export_deck_stage_pdf::summary_line(&out_abs, 2048, 5);
    assert!(summary.contains("2 KB, 5 pages, vector"));
}

#[test]
fn export_deck_stage_pdf_missing_required_args_matches_usage_contract() {
    let err = export_deck_stage_pdf::parse_args(&[]).unwrap_err();
    assert_eq!(err, export_deck_stage_pdf::MissingRequiredArgs);
    assert!(export_deck_stage_pdf::USAGE.contains("--html"));
    assert!(export_deck_stage_pdf::USAGE.contains("--out"));
}

// ---- fetch_images.py ------------------------------------------------------

#[test]
fn fetch_images_end_to_end_candidate_pipeline() {
    use std::collections::HashMap;

    let mut extmetadata = HashMap::new();
    extmetadata.insert(
        "LicenseShortName".to_string(),
        fetch_images::ExtMetaValue { value: "CC BY-SA 4.0".to_string() },
    );
    extmetadata.insert(
        "Artist".to_string(),
        fetch_images::ExtMetaValue { value: "Jane Doe".to_string() },
    );
    let page = fetch_images::CommonsPage {
        title: Some("File:George Town street.jpg".to_string()),
        imageinfo: vec![fetch_images::CommonsImageInfo {
            thumburl: Some("https://upload.wikimedia.org/thumb/gt.jpg?width=1600".to_string()),
            url: None,
            descriptionurl: Some("https://commons.wikimedia.org/wiki/File:GT".to_string()),
            extmetadata,
        }],
    };

    let out_dir = Path::new("/project/assets/img");
    let candidates = fetch_images::build_candidates("George Town street", out_dir, &[page], 2);
    assert_eq!(candidates.len(), 1);

    let line = fetch_images::ok_log_line(&candidates[0]);
    assert!(line.starts_with("[OK] /project/assets/img/"));
    assert!(line.contains("CC BY-SA 4.0"));
    assert!(line.contains("Jane Doe"));

    assert_eq!(fetch_images::exit_code(candidates.len()), 0);
    assert_eq!(fetch_images::exit_code(0), 1);

    let summary = fetch_images::summary_lines(out_dir, candidates.len());
    assert!(summary[0].contains("共下载 1 张"));
}

#[test]
fn fetch_images_empty_result_uses_fallback_messages() {
    let empty_line = fetch_images::empty_log_line("nonexistent query xyz");
    assert!(empty_line.contains("nonexistent query xyz"));
    assert_eq!(fetch_images::exit_code(0), 1);
    assert!(fetch_images::ALL_FAILED_MESSAGE.contains("Phase 3.5"));
}

// ---- gen_deck_thumbs.mjs ---------------------------------------------------

#[test]
fn gen_deck_thumbs_discovers_sorts_and_derives_outputs() {
    let argv: Vec<String> = vec!["--slides", "slides", "--out", "thumbs"]
        .into_iter()
        .map(String::from)
        .collect();
    let opts = gen_deck_thumbs::Options::from_argv(&argv);
    assert_eq!(opts.slides_dir, "slides");
    assert_eq!(opts.width, 1600);

    let entries = vec![
        "02-body.html".to_string(),
        "01-cover.html".to_string(),
        "readme.md".to_string(),
    ];
    let files = gen_deck_thumbs::discover_html_files_checked(&opts.slides_dir, true, &entries).unwrap();
    assert_eq!(files, vec!["01-cover.html", "02-body.html"]);

    let out_path = gen_deck_thumbs::thumb_output_path(&opts.out_dir, &files[0]);
    assert_eq!(out_path, PathBuf::from("thumbs/01-cover.jpg"));

    let lines = gen_deck_thumbs::summary_lines(2, 2, &opts.out_dir);
    assert!(lines[0].contains("2/2"));
}

#[test]
fn gen_deck_thumbs_missing_dir_reports_error() {
    let err = gen_deck_thumbs::discover_html_files_checked("slides", false, &[]).unwrap_err();
    assert_eq!(
        err,
        gen_deck_thumbs::DiscoverError::SlidesDirMissing("slides".to_string())
    );
}

// ---- html2pptx.js -----------------------------------------------------------

#[test]
fn html2pptx_pipeline_from_computed_style_values_to_validation() {
    // rgba text color -> hex + transparency, feeding a text-box check.
    let color = "rgba(20, 20, 20, 0.9)";
    let hex = html2pptx::rgb_to_hex(color);
    let alpha = html2pptx::extract_alpha(color);
    assert_eq!(hex, "141414");
    assert_eq!(alpha, Some(10));

    // Body overflow + layout-size validation feed into one combined error.
    let overflow_errors = html2pptx::body_overflow_errors(1920.0, 1080.0, 1920.0, 1090.0);
    let dim_errors = html2pptx::validate_dimensions(1920.0, 1080.0, Some(10.0 * html2pptx::EMU_PER_IN), Some(5.625 * html2pptx::EMU_PER_IN));
    let mut all = Vec::new();
    all.extend(overflow_errors);
    all.extend(dim_errors);
    let combined = html2pptx::combined_error_message(&all).unwrap();
    assert!(combined.starts_with("Multiple validation errors found:"));

    let prefixed = html2pptx::prefix_error_with_file("slide.html", &combined);
    assert!(prefixed.starts_with("slide.html: Multiple validation errors found:"));
}

#[test]
fn html2pptx_rotation_and_shadow_and_radius_agree_with_js_semantics() {
    assert_eq!(html2pptx::get_rotation("none", "vertical-rl"), Some(90.0));
    let shadow = html2pptx::parse_box_shadow("rgba(0, 0, 0, 0.3) 2px 2px 8px 0px").unwrap();
    assert_eq!(shadow.angle, 45);
    assert_eq!(html2pptx::border_radius_to_rect_radius("100%", 40.0, 40.0), 1.0);
}

// ---- mix-voiceover.sh -------------------------------------------------------

#[test]
fn mix_voiceover_full_flow_voice_and_bgm_ducked() {
    let opts = mix_voiceover::parse_args([
        "anim.mp4",
        "--voiceover=v.mp3",
        "--bgm-mood=tech",
    ])
    .unwrap();
    let script_dir = Path::new("/skills/designer/engine/huashu/scripts");
    let bgm = mix_voiceover::validate(&opts, |_| true, |_| true, |_| true, script_dir).unwrap();
    assert_eq!(
        bgm,
        Some(PathBuf::from("/skills/designer/engine/huashu/scripts/../assets/bgm-tech.mp3"))
    );

    let output = opts.out.clone().unwrap_or_else(|| mix_voiceover::default_output_path(opts.input.as_deref().unwrap()));
    assert_eq!(output, "anim-voiced.mp4");

    let args = mix_voiceover::build_ffmpeg_args(
        opts.input.as_deref().unwrap(),
        opts.voiceover.as_deref().unwrap(),
        bgm.as_ref().and_then(|p| p.to_str()),
        &opts.voice_volume,
        &opts.bgm_volume,
        opts.ducking,
        &output,
    );
    assert!(args.iter().any(|a| a.contains("sidechaincompress")));
    assert_eq!(args.last().unwrap(), "anim-voiced.mp4");

    let block = mix_voiceover::status_block(&opts, bgm.as_deref(), &output);
    assert!(block.contains("ducking=1"));
    assert_eq!(mix_voiceover::done_line(&output), "✓ 完成：anim-voiced.mp4");
}

#[test]
fn mix_voiceover_missing_input_short_circuits_validation() {
    let opts = mix_voiceover::Options::default();
    let err = mix_voiceover::validate(&opts, |_| false, |_| false, |_| false, Path::new("/s")).unwrap_err();
    assert_eq!(err, mix_voiceover::ValidationError::MissingOrNoSuchInput);
}
