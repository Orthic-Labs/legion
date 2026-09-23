//! Integration tests for the ported `wf_port::w2_035` module, mirroring
//! `src/lib/auto-jury.mjs`.

use legion_runtime::wf_port::w2_035::{
    build_council_input, clip, council_timeout_ms, final_decision_from_council_verdict,
    format_council_cli_error, format_qa_rubric, format_screen_composite, is_visual_kind,
    kind_to_skill, load_qa_rubrics_lib, BuildCouncilInputArgs, CouncilCliFailure,
    DEFAULT_COUNCIL_TIMEOUT_MS,
};
use serde_json::json;
use std::io::Write as _;
use std::path::PathBuf;

fn tmpdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wf_w2_035_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// -- clip ---------------------------------------------------------------

#[test]
fn clip_passes_short_strings_through() {
    assert_eq!(clip("hello", 1200), "hello");
}

#[test]
fn clip_truncates_and_appends_ellipsis() {
    let long = "a".repeat(10);
    assert_eq!(clip(&long, 4), "aaaa...");
}

// -- council_timeout_ms ---------------------------------------------------

#[test]
fn council_timeout_defaults_when_unset() {
    assert_eq!(council_timeout_ms(None), DEFAULT_COUNCIL_TIMEOUT_MS);
}

#[test]
fn council_timeout_parses_valid_override() {
    assert_eq!(council_timeout_ms(Some("5000")), 5000);
}

#[test]
fn council_timeout_falls_back_on_garbage_or_nonpositive() {
    assert_eq!(council_timeout_ms(Some("nope")), DEFAULT_COUNCIL_TIMEOUT_MS);
    assert_eq!(council_timeout_ms(Some("-5")), DEFAULT_COUNCIL_TIMEOUT_MS);
    assert_eq!(council_timeout_ms(Some("0")), DEFAULT_COUNCIL_TIMEOUT_MS);
}

// -- format_council_cli_error --------------------------------------------

#[test]
fn formats_timeout_error() {
    let err = CouncilCliFailure {
        stderr: Some("boom".to_string()),
        stdout: None,
        timed_out: true,
        status: None,
        signal: Some("SIGTERM".to_string()),
        code: None,
    };
    let msg = format_council_cli_error(&err, "jury-video", "final.mp4", 600_000);
    assert!(msg.starts_with("auto-jury: council CLI failed for jury-video on final.mp4."));
    assert!(msg.contains("timed out after 600s"));
    assert!(msg.contains("signal=SIGTERM"));
    assert!(msg.contains("stderr: boom"));
}

#[test]
fn formats_error_with_empty_stderr() {
    let err = CouncilCliFailure {
        stderr: None,
        stdout: None,
        timed_out: false,
        status: Some(1),
        signal: None,
        code: None,
    };
    let msg = format_council_cli_error(&err, "jury-plan", "p.md", 1000);
    assert!(msg.contains("status=1"));
    assert!(msg.contains("stderr: <empty>"));
}

// -- kind_to_skill / is_visual_kind ---------------------------------------

#[test]
fn kind_to_skill_matches_js_table() {
    assert_eq!(kind_to_skill("video"), Some("jury-video"));
    assert_eq!(kind_to_skill("copy"), Some("jury-blogs"));
    assert_eq!(kind_to_skill("blog"), Some("jury-blogs"));
    assert_eq!(kind_to_skill("code"), Some("jury-code"));
    assert_eq!(kind_to_skill("nonsense"), None);
}

#[test]
fn visual_kinds_match_js_set() {
    for k in ["video", "image", "design", "ad", "launch"] {
        assert!(is_visual_kind(k), "{k} should be visual");
    }
    for k in ["copy", "plan", "code", "brand"] {
        assert!(!is_visual_kind(k), "{k} should not be visual");
    }
}

// -- QA rubric loading/formatting -----------------------------------------

#[test]
fn qa_rubric_missing_file_yields_empty_lib() {
    let lib = load_qa_rubrics_lib(&PathBuf::from("/nonexistent/path/qa-rubrics.json"));
    assert_eq!(lib, json!({ "rubrics_by_shot_type": {} }));
}

#[test]
fn qa_rubric_unknown_key_lists_valid_keys() {
    let dir = tmpdir("rubrics");
    let path = dir.join("qa-rubrics.json");
    std::fs::write(
        &path,
        r#"{"rubrics_by_shot_type": {"hero": {"_use": "hero shots"}}}"#,
    )
    .unwrap();
    let lib = load_qa_rubrics_lib(&path);
    let out = format_qa_rubric(&lib, "missing");
    assert!(out.contains("unknown qaRubric key \"missing\""));
    assert!(out.contains("Valid keys: hero"));
}

#[test]
fn qa_rubric_formats_full_block() {
    let dir = tmpdir("rubrics_full");
    let path = dir.join("qa-rubrics.json");
    std::fs::write(
        &path,
        r#"{
          "rubrics_by_shot_type": {
            "hero": {
              "_use": "hero shots",
              "dimensions": {"clarity": "is it clear"},
              "must_pass": ["no artifacts"],
              "ship_threshold": "8/10",
              "note": "check carefully"
            }
          }
        }"#,
    )
    .unwrap();
    let lib = load_qa_rubrics_lib(&path);
    let out = format_qa_rubric(&lib, "hero");
    assert!(out.contains("Use case: hero shots"));
    assert!(out.contains("Dimensions (score each 1-10):"));
    assert!(out.contains("  - clarity: is it clear"));
    assert!(out.contains("Must pass (any failure = SHIP-WITH-FIXES at minimum):"));
    assert!(out.contains("  - no artifacts"));
    assert!(out.contains("Ship threshold: 8/10"));
    assert!(out.contains("Note: check carefully"));
}

// -- final_decision_from_council_verdict -----------------------------------

#[test]
fn any_error_forces_needs_revision() {
    let v = json!({ "synthesis": { "any_error": true }, "final_verdict": "SHIP" });
    assert_eq!(final_decision_from_council_verdict(&v), "NEEDS-REVISION");
}

#[test]
fn split_forces_needs_revision() {
    let v = json!({ "synthesis": { "split": true } });
    assert_eq!(final_decision_from_council_verdict(&v), "NEEDS-REVISION");
}

#[test]
fn majority_count_below_half_forces_needs_revision() {
    let v = json!({ "synthesis": { "majority_count": "1/3" }, "final_verdict": "SHIP" });
    assert_eq!(final_decision_from_council_verdict(&v), "NEEDS-REVISION");
}

#[test]
fn majority_count_above_half_uses_final_verdict() {
    let v = json!({ "synthesis": { "majority_count": "2/3" }, "final_verdict": "ship" });
    assert_eq!(final_decision_from_council_verdict(&v), "SHIP");
}

#[test]
fn falls_back_through_verdict_fields_in_order() {
    let v = json!({ "verdict": "ship-with-fixes" });
    assert_eq!(final_decision_from_council_verdict(&v), "SHIP-WITH-FIXES");

    let v = json!({ "decision": "revise" });
    assert_eq!(final_decision_from_council_verdict(&v), "REVISE");

    let v = json!({ "synthesis": { "majority_verdict": "ship" } });
    assert_eq!(final_decision_from_council_verdict(&v), "SHIP");

    let v = json!({});
    assert_eq!(final_decision_from_council_verdict(&v), "");
}

// -- format_screen_composite ------------------------------------------------

#[test]
fn screen_composite_returns_none_without_field() {
    let sc = json!({ "shotName": "s1" });
    assert!(format_screen_composite(&sc).is_none());
}

#[test]
fn screen_composite_formats_mask_and_overlays() {
    let sc = json!({
        "shotName": "intro",
        "shotStartS": 2,
        "screenComposite": {
            "screenMask": {
                "topLeft": {"x": 1, "y": 2},
                "topRight": {"x": 3, "y": 4},
                "bottomLeft": {"x": 5, "y": 6},
                "bottomRight": {"x": 7, "y": 8}
            },
            "overlays": [
                {"recipe": "wake_word_pulse", "pulseAt": 1.5},
                {"recipe": "sent_tick", "tickAt": 2},
                {"recipe": "screen_glow_only"},
                {"recipe": "mystery_recipe"}
            ]
        }
    });
    let out = format_screen_composite(&sc).unwrap();
    assert!(out.contains("### Shot `intro`"));
    assert!(out.contains("Shot start in final cut: 2s"));
    assert!(out.contains("TL(1,2) TR(3,4) BL(5,6) BR(7,8)"));
    assert!(out.contains("wake_word_pulse: pulseAt=1.5s"));
    assert!(out.contains("sent_tick: tickAt=2s"));
    assert!(out.contains("screen_glow_only: (no UI overlay"));
    assert!(out.contains("mystery_recipe: (unknown recipe"));
}

// -- build_council_input ----------------------------------------------------

#[test]
fn build_council_input_basic_fields() {
    let context = json!({ "brand": "HR", "campaign": "c1", "prompt": "do the thing" });
    let out = build_council_input(BuildCouncilInputArgs {
        kind: "video",
        artifact_path: "final.mp4",
        context: &context,
        qa_rubrics_lib: None,
    });
    assert!(out.starts_with("# Auto-jury input — video"));
    assert!(out.contains("Artifact: final.mp4"));
    assert!(out.contains("Brand: HR"));
    assert!(out.contains("Campaign: c1"));
    assert!(out.contains("## Prompt"));
    assert!(out.contains("do the thing"));
    // visual kind footer present
    assert!(out.contains("## Council vision input"));
}

#[test]
fn build_council_input_embeds_text_artifact_body() {
    let dir = tmpdir("embed");
    let path = dir.join("plan.md");
    std::fs::write(&path, "# The Plan\nDo X then Y.").unwrap();
    let context = json!({});
    let out = build_council_input(BuildCouncilInputArgs {
        kind: "plan",
        artifact_path: path.to_str().unwrap(),
        context: &context,
        qa_rubrics_lib: None,
    });
    assert!(out.contains("## Artifact contents"));
    assert!(out.contains("Do X then Y."));
    // non-visual kind: no vision footer
    assert!(!out.contains("## Council vision input"));
}

#[test]
fn build_council_input_reports_unreadable_artifact() {
    let context = json!({});
    let out = build_council_input(BuildCouncilInputArgs {
        kind: "plan",
        artifact_path: "/definitely/not/a/real/file.md",
        context: &context,
        qa_rubrics_lib: None,
    });
    assert!(out.contains("(could not read artifact:"));
}

#[test]
fn build_council_input_embeds_packet_fence() {
    let context = json!({
        "packet": {
            "ARTIFACT": "video.mp4",
            "SUCCESS_CRITERIA": ["clear CTA", "brand colors"]
        }
    });
    let out = build_council_input(BuildCouncilInputArgs {
        kind: "video",
        artifact_path: "video.mp4",
        context: &context,
        qa_rubrics_lib: None,
    });
    assert!(out.contains("```packet"));
    assert!(out.contains("ARTIFACT: video.mp4"));
    assert!(out.contains("SUCCESS_CRITERIA:"));
    assert!(out.contains("  - clear CTA"));
    assert!(out.contains("  - brand colors"));
}

#[test]
fn build_council_input_qa_rubric_overlay() {
    let lib = json!({
        "rubrics_by_shot_type": {
            "hero": { "_use": "hero shots", "ship_threshold": "8/10" }
        }
    });
    let context = json!({ "qaRubric": "hero" });
    let out = build_council_input(BuildCouncilInputArgs {
        kind: "video",
        artifact_path: "v.mp4",
        context: &context,
        qa_rubrics_lib: Some(&lib),
    });
    assert!(out.contains("## Shot-type rubric overlay"));
    assert!(out.contains("recipes/video/qa-rubrics.json#rubrics_by_shot_type.hero"));
    assert!(out.contains("Use case: hero shots"));
}

#[test]
fn build_council_input_audio_recipes_and_screen_composites() {
    let context = json!({
        "audioRecipes": [
            {"index": 0, "type": "vo", "namespace": "vo", "audioRecipe": "founder_direct", "derivedVoice": "voice-1"},
            {"index": 1, "type": "vo", "audioRecipe": "bad", "error": "not found.details"}
        ],
        "screenComposites": [
            {"shotName": "s1", "screenComposite": {"screenMask": {"topLeft":{"x":0,"y":0},"topRight":{"x":0,"y":0},"bottomLeft":{"x":0,"y":0},"bottomRight":{"x":0,"y":0}}, "overlays": []}}
        ]
    });
    let out = build_council_input(BuildCouncilInputArgs {
        kind: "video",
        artifact_path: "v.mp4",
        context: &context,
        qa_rubrics_lib: None,
    });
    assert!(out.contains("## Audio recipe references"));
    assert!(out.contains("layer 0 (vo) → vo:founder_direct  →  voice-1"));
    assert!(out.contains("✗ not found"));
    assert!(out.contains("## Screen composite specs"));
    assert!(out.contains("### Shot `s1`"));
}

// smoke: ensure a temp file write inside tests works (sanity for the harness itself)
#[test]
fn tmpdir_helper_is_writable() {
    let dir = tmpdir("sanity");
    let f = dir.join("x.txt");
    let mut fh = std::fs::File::create(&f).unwrap();
    writeln!(fh, "ok").unwrap();
    assert!(f.exists());
}
