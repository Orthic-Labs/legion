//! Integration tests for the ported `wf_port::w2_025` module, mirroring
//! `skills/seo/extensions/banana/scripts/{batch,cost_tracker,edit,generate,presets}.py`.

use legion_runtime::wf_port::w2_025::batch::{parse_batch_csv, BatchCsvError, DEFAULT_MODEL as BATCH_DEFAULT_MODEL};
use legion_runtime::wf_port::w2_025::cost_tracker::{
    estimate, last_n_days, log_entry, lookup_cost, reset_ledger, today_usage, truncate_prompt,
    CostLedger, CostWarning, DailyUsage,
};
use legion_runtime::wf_port::w2_025::edit::{
    build_edit_request_body, mime_type_for_suffix, output_filename as edit_output_filename,
};
use legion_runtime::wf_port::w2_025::generate::{
    build_request_body, extract_image, resolve_api_key, validate_inputs,
    output_filename as generate_output_filename, GenerateError, ResponsePart,
};
use legion_runtime::wf_port::w2_025::presets::{
    build_preset, format_list_row, require_confirm, sanitize_name, CreatePresetInput, PresetError,
};
use std::fs;
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/wf_w2_025");
    path.push(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {path:?}: {e}"))
}

// -- batch.py -----------------------------------------------------------

#[test]
fn batch_csv_from_readme_example_produces_expected_plan() {
    let csv = fixture("batch_example.csv");
    let plan = parse_batch_csv(&csv).unwrap();
    assert_eq!(plan.total_count, 3);
    assert!(plan.errors.is_empty());
    assert_eq!(plan.rows[0].prompt, "coffee shop hero image");
    assert_eq!(plan.rows[0].ratio, "16:9");
    assert_eq!(plan.rows[0].resolution, "2K");
    assert_eq!(plan.rows[0].model, BATCH_DEFAULT_MODEL);
    assert_eq!(plan.rows[1].prompt, "team photo placeholder");
    assert_eq!(plan.rows[2].prompt, "product shot on marble");
    assert_eq!(plan.rows[2].ratio, "4:3");
}

#[test]
fn batch_csv_missing_prompt_header_is_rejected() {
    let csv = "ratio,resolution\n16:9,2K\n";
    assert_eq!(parse_batch_csv(csv), Err(BatchCsvError::MissingPromptColumn));
}

#[test]
fn batch_csv_mixed_valid_and_invalid_rows() {
    let csv = fixture("batch_with_errors.csv");
    let plan = parse_batch_csv(&csv).unwrap();
    assert_eq!(plan.total_count, 1);
    assert_eq!(plan.errors.len(), 1);
    assert!(plan.errors[0].contains("missing prompt"));
}

// -- cost_tracker.py ------------------------------------------------------

#[test]
fn cost_tracker_full_session_matches_python_semantics() {
    let mut ledger = CostLedger::default();

    let (r1, w1) = log_entry(
        &mut ledger,
        "gemini-3.1-flash-image-preview",
        "2K",
        "a hero banner for a coffee shop landing page",
        false,
        "2026-09-23",
        "2026-09-23T10:00:00",
    );
    assert!(w1.is_empty());
    assert_eq!(r1.cost, 0.078);
    assert_eq!(ledger.entries[0].prompt.chars().count(), "a hero banner for a coffee shop landing page".chars().count());

    let (r2, w2) = log_entry(
        &mut ledger,
        "gemini-2.5-flash-image",
        "1K",
        "team photo",
        true,
        "2026-09-23",
        "2026-09-23T10:05:00",
    );
    assert!(w2.is_empty());
    assert_eq!(r2.cost, 0.039 * 0.5);
    assert_eq!(ledger.total_images, 2);

    let today = today_usage(&ledger, "2026-09-23");
    assert_eq!(today.count, 2);

    let days = last_n_days(&ledger, 7);
    assert_eq!(days.len(), 1);
    assert_eq!(days[0].0, "2026-09-23");

    let reset = reset_ledger();
    assert_eq!(reset.total_images, 0);
}

#[test]
fn cost_tracker_estimate_warns_on_unknown_model() {
    let (lookup, total, batch_total) = estimate("mystery-model", "1K", 5, false);
    assert_eq!(
        lookup.warnings,
        vec![CostWarning::UnknownModel("mystery-model".to_string())]
    );
    assert_eq!(total, 0.195);
    assert_eq!(batch_total, Some(0.098));
}

#[test]
fn cost_tracker_truncate_prompt_matches_python_slicing() {
    let prompt: String = "x".repeat(120);
    assert_eq!(truncate_prompt(&prompt).len(), 100);
}

#[test]
fn cost_tracker_lookup_cost_defaults_documented() {
    let lookup = lookup_cost("gemini-3.1-flash-image-preview", "1K", false);
    assert_eq!(lookup.cost, 0.039);
    let daily = DailyUsage::default();
    assert_eq!(daily.count, 0);
    assert_eq!(daily.cost, 0.0);
}

// -- presets.py -------------------------------------------------------------

#[test]
fn presets_create_show_delete_roundtrip() {
    let name = "tech-saas";
    assert_eq!(sanitize_name(name).unwrap(), name);

    let input = CreatePresetInput {
        name,
        colors: "#0A0A0A,#FFFFFF",
        style: "flat vector illustration",
        typography: "geometric sans",
        lighting: "even, soft",
        mood: "confident",
        description: "SaaS product marketing preset",
        ratio: "16:9",
        resolution: "2K",
    };
    let preset = build_preset(&input);
    assert_eq!(preset.name, "tech-saas");
    assert_eq!(preset.colors, vec!["#0A0A0A", "#FFFFFF"]);
    assert_eq!(preset.description, "SaaS product marketing preset");

    let row = format_list_row(name, Some(&preset));
    assert!(row.contains("SaaS product marketing preset"));

    assert_eq!(require_confirm(false), Err(PresetError::ConfirmRequired));
    assert_eq!(require_confirm(true), Ok(()));
}

#[test]
fn presets_sanitize_name_blocks_path_traversal() {
    assert_eq!(sanitize_name("../../etc/passwd").unwrap(), "etcpasswd");
    assert_eq!(sanitize_name("////"), Err(PresetError::EmptyName));
}

// -- generate.py --------------------------------------------------------

#[test]
fn generate_validate_inputs_matches_python_order_and_messages() {
    let err = validate_inputs("not-a-ratio", "1K", Some("key")).unwrap_err();
    assert_eq!(err, GenerateError::InvalidAspectRatio("not-a-ratio".to_string()));
    assert!(err.to_string().starts_with("Invalid aspect ratio"));

    let err = validate_inputs("1:1", "9001K", Some("key")).unwrap_err();
    assert_eq!(err, GenerateError::InvalidResolution("9001K".to_string()));

    let err = validate_inputs("1:1", "1K", None).unwrap_err();
    assert_eq!(err, GenerateError::MissingApiKey);
    assert_eq!(
        err.to_string(),
        "No API key. Set GOOGLE_AI_API_KEY env or pass --api-key"
    );
}

#[test]
fn generate_resolve_api_key_precedence() {
    assert_eq!(resolve_api_key(Some("cli"), Some("ai"), Some("plain")), Some("cli".to_string()));
    assert_eq!(resolve_api_key(None, Some("ai"), Some("plain")), Some("ai".to_string()));
    assert_eq!(resolve_api_key(None, None, None), None);
}

#[test]
fn generate_build_request_body_round_trips_through_json() {
    let body = build_request_body("a cat in space", "16:9", "1K", Some("medium"), false);
    let json = serde_json::to_value(&body).unwrap();
    assert_eq!(json["contents"][0]["parts"][0]["text"], "a cat in space");
    assert_eq!(json["generationConfig"]["imageConfig"]["aspectRatio"], "16:9");
    assert_eq!(json["generationConfig"]["thinkingConfig"]["thinkingLevel"], "medium");
    assert_eq!(
        json["generationConfig"]["responseModalities"],
        serde_json::json!(["TEXT", "IMAGE"])
    );
}

#[test]
fn generate_extract_image_and_output_filename() {
    let candidates = vec![(
        Some("STOP".to_string()),
        vec![ResponsePart {
            inline_data_b64: Some("aW1hZ2U=".to_string()),
            text: Some("done".to_string()),
        }],
    )];
    let extracted = extract_image(&candidates, None).unwrap();
    assert_eq!(extracted.image_data_b64, "aW1hZ2U=");
    assert_eq!(extracted.text, "done");
    assert_eq!(
        generate_output_filename("20260923_100000_000001"),
        "banana_20260923_100000_000001.png"
    );
}

// -- edit.py --------------------------------------------------------------

#[test]
fn edit_mime_type_and_request_body_and_filename() {
    assert_eq!(mime_type_for_suffix(".JPG"), "image/jpeg");

    let body = build_edit_request_body("remove the background", "QUJD", "image/png");
    let json = serde_json::to_value(&body).unwrap();
    assert_eq!(json["contents"][0]["parts"][0]["text"], "remove the background");
    assert_eq!(json["contents"][0]["parts"][1]["inlineData"]["mimeType"], "image/png");
    assert_eq!(json["contents"][0]["parts"][1]["inlineData"]["data"], "QUJD");
    assert_eq!(
        json["generationConfig"]["responseModalities"],
        serde_json::json!(["TEXT", "IMAGE"])
    );

    assert_eq!(
        edit_output_filename("20260923_100000_000001"),
        "banana_edit_20260923_100000_000001.png"
    );
}
