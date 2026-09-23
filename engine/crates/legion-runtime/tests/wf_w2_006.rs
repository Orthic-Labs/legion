//! Integration tests for wf_port chunk w2_006
//! (`skills/designer/engine/huashu/{assets/deck_stage.js,
//! scripts/add-music.sh, scripts/convert-formats.sh,
//! scripts/export_deck_pdf.mjs, scripts/export_deck_pptx.mjs}`).
//!
//! Each submodule's own `#[cfg(test)]` block already covers its unit-level
//! ports line-for-line against the original source; this file exercises the
//! public API the way a host embedding the engine actually would, end to
//! end through each module's small pipeline of pure functions.
//!
//! This test file depends on `legion_runtime::wf_port::w2_006`, which is not
//! yet wired into `legion-runtime`'s public module tree (the integrator adds
//! `pub mod wf_port;` in `src/lib.rs` and `pub mod w2_006;` in
//! `src/wf_port/mod.rs` per the w2_006 chunk assignment). Until that wiring
//! lands, this file will not compile as part of the crate's test target.

use std::path::{Path, PathBuf};

use legion_runtime::wf_port::w2_006::{
    add_music, convert_formats, deck_stage, export_deck_pdf, export_deck_pptx,
};

// ---------------------------------------------------------------------------
// deck_stage.js
// ---------------------------------------------------------------------------

#[test]
fn deck_stage_full_navigation_and_persistence_cycle() {
    // Simulate collecting 4 fresh <section> slides (no pre-existing attrs).
    let existing = vec![(None, None), (None, None), (None, None), (None, None)];
    let attrs = deck_stage::collect_slide_attrs(&existing);
    assert_eq!(
        attrs.iter().map(|a| a.screen_label.as_str()).collect::<Vec<_>>(),
        vec!["01", "02", "03", "04"]
    );

    let mut state = deck_stage::DeckStageState::new(attrs.len());

    // Hash navigation to slide 3 (#slide-3 -> index 2).
    let idx = deck_stage::parse_slide_hash("#slide-3", state.total_slides).unwrap();
    assert!(state.go_to(idx));
    assert_eq!(state.counter_text(), "3 / 4");

    // localStorage round trip: persist then restore into a fresh state.
    let persisted = state.current_slide.to_string();
    let restored = deck_stage::restore_slide(Some(&persisted), state.total_slides).unwrap();
    assert_eq!(restored, 2);

    // Viewport fit for a 1920x1080 stage inside a taller-than-wide window.
    let transform = deck_stage::compute_scale(1000.0, 2000.0, deck_stage::DEFAULT_WIDTH, deck_stage::DEFAULT_HEIGHT)
        .unwrap();
    assert!(transform.scale > 0.0);
    assert!(transform.to_css().starts_with("translate("));
}

// ---------------------------------------------------------------------------
// add-music.sh
// ---------------------------------------------------------------------------

#[test]
fn add_music_end_to_end_plan_and_ffmpeg_args() {
    let args = add_music::parse_args(["my.mp4", "--mood=ad", "--out=final.mp4"]);
    let plan = add_music::build_plan(&args, Path::new("/skill/assets")).unwrap();

    assert_eq!(plan.music, PathBuf::from("/skill/assets/bgm-ad.mp3"));
    assert_eq!(plan.output, PathBuf::from("final.mp4"));

    let ffmpeg_args = add_music::ffmpeg_args(&plan, 42.5);
    assert!(ffmpeg_args.contains(&"-shortest".to_string()));
    assert!(ffmpeg_args
        .iter()
        .any(|a| a.contains("afade=t=out:st=41.5:d=1")));
}

#[test]
fn add_music_missing_input_is_rejected() {
    let args = add_music::parse_args(["--mood=tech"]);
    assert_eq!(
        add_music::build_plan(&args, Path::new("/assets")),
        Err(add_music::AddMusicError::MissingOrUnreadableInput)
    );
}

// ---------------------------------------------------------------------------
// convert-formats.sh
// ---------------------------------------------------------------------------

#[test]
fn convert_formats_end_to_end_pipeline() {
    let args = convert_formats::parse_args(["clip.mp4", "480"]).unwrap();
    assert!(!args.use_minterpolate);

    let paths = convert_formats::resolve_paths(Path::new(&args.input));
    assert_eq!(paths.out_60fps, PathBuf::from("clip-60fps.mp4"));
    assert_eq!(paths.out_gif, PathBuf::from("clip.gif"));

    let sixty = convert_formats::ffmpeg_60fps_args(
        Path::new(&args.input),
        &paths.out_60fps,
        args.use_minterpolate,
    );
    assert!(sixty.iter().any(|a| a == "fps=60"));

    let gen = convert_formats::ffmpeg_palettegen_args(
        Path::new(&args.input),
        &args.gif_width,
        &paths.palette,
    );
    assert!(gen.iter().any(|a| a.contains("scale=480")));

    let use_ = convert_formats::ffmpeg_paletteuse_args(
        Path::new(&args.input),
        &args.gif_width,
        &paths.palette,
        &paths.out_gif,
    );
    assert!(use_.iter().any(|a| a.contains("paletteuse")));
}

#[test]
fn convert_formats_unknown_flag_is_rejected() {
    assert_eq!(
        convert_formats::parse_args(["clip.mp4", "--nope"]),
        Err(convert_formats::ArgError::UnknownFlag("--nope".into()))
    );
}

// ---------------------------------------------------------------------------
// export_deck_pdf.mjs
// ---------------------------------------------------------------------------

#[test]
fn export_deck_pdf_end_to_end_run() {
    let args = export_deck_pdf::parse_args([
        "--slides", "./decks/q3", "--out", "q3.pdf", "--width", "1280", "--height", "720",
    ])
    .unwrap();

    let entries = vec![
        "03-close.html".to_string(),
        "01-title.html".to_string(),
        "02-body.html".to_string(),
        "thumb.png".to_string(),
    ];
    let files = export_deck_pdf::select_and_sort_slides(&entries);
    assert_eq!(files.len(), 3);
    assert_eq!(files[0], "01-title.html");

    let opts = export_deck_pdf::page_pdf_options(args.width, args.height);
    assert_eq!(opts.width_css(), "1280px");

    let url = export_deck_pdf::slide_file_url(&args.slides.unwrap(), &files[0]);
    assert_eq!(url, "file://./decks/q3/01-title.html");

    let summary = export_deck_pdf::wrote_summary_line("q3.pdf", 51_200, files.len());
    assert!(summary.contains("50 KB"));
    assert!(summary.contains("3 pages"));
}

// ---------------------------------------------------------------------------
// export_deck_pptx.mjs
// ---------------------------------------------------------------------------

#[test]
fn export_deck_pptx_partial_failure_still_writes() {
    let args = export_deck_pptx::parse_args(["--slides", "./decks/q3", "--out", "q3.pptx"]).unwrap();
    let entries = vec!["02-body.html".to_string(), "01-title.html".to_string()];
    let files = export_deck_pptx::select_and_sort_slides(&entries);
    assert_eq!(files, vec!["01-title.html", "02-body.html"]);

    let total = files.len();
    let outcomes: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(i, f)| {
            export_deck_pptx::convert_slide(i, total, f, |file| {
                if file == "02-body.html" {
                    Err("div holds bare text".to_string())
                } else {
                    Ok(())
                }
            })
        })
        .collect();

    match export_deck_pptx::summarize(&outcomes) {
        export_deck_pptx::DeckOutcome::Write {
            succeeded,
            total,
            warning,
        } => {
            assert_eq!(succeeded, 1);
            assert_eq!(total, 2);
            assert!(warning.unwrap().contains("1 张 slide 转换失败"));
        }
        other => panic!("expected partial-success Write outcome, got {other:?}"),
    }

    let line = export_deck_pptx::wrote_summary_line(&args.out, 1, total);
    assert!(line.contains("1/2 slides"));
}

#[test]
fn export_deck_pptx_all_failed_blocks_write() {
    let outcomes = vec![
        export_deck_pptx::convert_slide(0, 1, "01-title.html", |_| Err("bad".into())),
    ];
    assert_eq!(
        export_deck_pptx::summarize(&outcomes),
        export_deck_pptx::DeckOutcome::AllFailed
    );
}
