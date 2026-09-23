//! Tests for the w2_026 port of
//! `skills/seo/extensions/banana/scripts/setup_mcp.py` and
//! `skills/seo/extensions/banana/scripts/validate_setup.py`.

use legion_runtime::wf_port::w2_026::{
    apply_entry, check_api_key_set, check_command_is_npx, check_json_valid, check_model_set,
    check_mcp_configured, check_npx_available, check_output_dir, check_package_correct,
    check_settings_file_exists, describe_setup, mask_key, remove_entry, run_validation,
    OutputDirState, SetupError, DEFAULT_MODEL, MCP_NAME, MCP_PACKAGE,
};
use serde_json::json;

// ---------------------------------------------------------------------
// mask_key — matches `key[:8] + "..." + key[-4:] if len(key) > 12 else
// "(not set)"`.
// ---------------------------------------------------------------------

#[test]
fn mask_key_masks_long_keys() {
    assert_eq!(mask_key("AIzaSyABCDEFGHIJKLMNOP1234"), "AIzaSyAB...1234");
}

#[test]
fn mask_key_placeholders_short_or_empty_keys() {
    assert_eq!(mask_key(""), "(not set)");
    assert_eq!(mask_key("short"), "(not set)");
    // exactly 12 chars: Python's `len(key) > 12` is false, so still masked out.
    assert_eq!(mask_key("123456789012"), "(not set)");
}

#[test]
fn mask_key_boundary_at_13_chars() {
    // 13 chars: Python takes key[:8] + "..." + key[-4:].
    let key = "1234567890123";
    assert_eq!(mask_key(key), "12345678...0123");
}

// ---------------------------------------------------------------------
// describe_setup — port of `check_setup()`.
// ---------------------------------------------------------------------

#[test]
fn describe_setup_none_when_not_configured() {
    assert_eq!(describe_setup(&json!({})), None);
    assert_eq!(describe_setup(&json!({"mcpServers": {}})), None);
}

#[test]
fn describe_setup_reports_package_key_and_model() {
    let settings = json!({
        "mcpServers": {
            MCP_NAME: {
                "command": "npx",
                "args": ["-y", MCP_PACKAGE],
                "env": {
                    "GOOGLE_AI_API_KEY": "AIzaSyABCDEFGHIJKLMNOP1234",
                    "NANOBANANA_MODEL": "gemini-custom",
                }
            }
        }
    });
    let desc = describe_setup(&settings).expect("configured");
    assert_eq!(desc.package, MCP_PACKAGE);
    assert_eq!(desc.masked_api_key, "AIzaSyAB...1234");
    assert_eq!(desc.model, "gemini-custom");
}

#[test]
fn describe_setup_defaults_model_when_absent() {
    let settings = json!({
        "mcpServers": {
            MCP_NAME: { "command": "npx", "args": ["-y", MCP_PACKAGE], "env": {} }
        }
    });
    let desc = describe_setup(&settings).expect("configured");
    assert_eq!(desc.model, DEFAULT_MODEL);
    assert_eq!(desc.masked_api_key, "(not set)");
}

// ---------------------------------------------------------------------
// apply_entry — port of `setup_mcp(api_key)`.
// ---------------------------------------------------------------------

#[test]
fn apply_entry_rejects_empty_or_whitespace_key() {
    let mut settings = json!({});
    assert_eq!(apply_entry(&mut settings, ""), Err(SetupError::EmptyApiKey));
    assert_eq!(
        apply_entry(&mut settings, "   \t  "),
        Err(SetupError::EmptyApiKey)
    );
}

#[test]
fn apply_entry_trims_and_writes_expected_shape() {
    let mut settings = json!({});
    apply_entry(&mut settings, "  my-secret-key  ").unwrap();
    assert_eq!(
        settings,
        json!({
            "mcpServers": {
                MCP_NAME: {
                    "command": "npx",
                    "args": ["-y", MCP_PACKAGE],
                    "env": {
                        "GOOGLE_AI_API_KEY": "my-secret-key",
                        "NANOBANANA_MODEL": DEFAULT_MODEL,
                    }
                }
            }
        })
    );
}

#[test]
fn apply_entry_preserves_other_settings_and_other_mcp_servers() {
    let mut settings = json!({
        "otherTopLevel": true,
        "mcpServers": {
            "some-other-mcp": { "command": "foo" }
        }
    });
    apply_entry(&mut settings, "key").unwrap();
    assert_eq!(settings["otherTopLevel"], json!(true));
    assert_eq!(settings["mcpServers"]["some-other-mcp"]["command"], json!("foo"));
    assert_eq!(settings["mcpServers"][MCP_NAME]["command"], json!("npx"));
}

#[test]
fn apply_entry_overwrites_existing_entry() {
    let mut settings = json!({
        "mcpServers": { MCP_NAME: { "command": "stale", "args": [], "env": {} } }
    });
    apply_entry(&mut settings, "new-key").unwrap();
    assert_eq!(settings["mcpServers"][MCP_NAME]["command"], json!("npx"));
    assert_eq!(
        settings["mcpServers"][MCP_NAME]["env"]["GOOGLE_AI_API_KEY"],
        json!("new-key")
    );
}

// ---------------------------------------------------------------------
// remove_entry — port of `remove_mcp()`.
// ---------------------------------------------------------------------

#[test]
fn remove_entry_removes_when_present() {
    let mut settings = json!({ "mcpServers": { MCP_NAME: {"command": "npx"} } });
    assert!(remove_entry(&mut settings));
    assert_eq!(settings, json!({ "mcpServers": {} }));
}

#[test]
fn remove_entry_false_when_absent() {
    let mut settings = json!({});
    assert!(!remove_entry(&mut settings));
    let mut settings2 = json!({ "mcpServers": {} });
    assert!(!remove_entry(&mut settings2));
}

#[test]
fn remove_entry_leaves_other_servers_intact() {
    let mut settings = json!({
        "mcpServers": { MCP_NAME: {"command": "npx"}, "other": {"command": "bar"} }
    });
    assert!(remove_entry(&mut settings));
    assert_eq!(settings["mcpServers"]["other"]["command"], json!("bar"));
    assert!(settings["mcpServers"].get(MCP_NAME).is_none());
}

// ---------------------------------------------------------------------
// validate_setup.py's nine checks.
// ---------------------------------------------------------------------

#[test]
fn check_settings_file_exists_reports_path_as_detail() {
    let c = check_settings_file_exists(true, "/home/u/.claude/settings.json");
    assert!(c.passed);
    assert_eq!(c.detail, "/home/u/.claude/settings.json");

    let c = check_settings_file_exists(false, "/home/u/.claude/settings.json");
    assert!(!c.passed);
}

#[test]
fn check_json_valid_reports_parser_error_on_failure() {
    let c = check_json_valid(false, "Expecting value: line 1 column 1 (char 0)");
    assert!(!c.passed);
    assert_eq!(c.detail, "Expecting value: line 1 column 1 (char 0)");

    let c = check_json_valid(true, "");
    assert!(c.passed);
}

#[test]
fn check_mcp_configured_signals_downstream_checks() {
    let (check, has_mcp) = check_mcp_configured(&json!({}));
    assert!(!check.passed);
    assert!(!has_mcp);

    let (check, has_mcp) =
        check_mcp_configured(&json!({ "mcpServers": { MCP_NAME: {} } }));
    assert!(check.passed);
    assert!(has_mcp);
}

fn full_entry(command: &str, args: serde_json::Value, env: serde_json::Value) -> serde_json::Value {
    json!({ "mcpServers": { MCP_NAME: { "command": command, "args": args, "env": env } } })
}

#[test]
fn check_command_is_npx_passes_only_for_npx() {
    let settings = full_entry("npx", json!([]), json!({}));
    assert!(check_command_is_npx(&settings).passed);

    let settings = full_entry("node", json!([]), json!({}));
    let c = check_command_is_npx(&settings);
    assert!(!c.passed);
    assert_eq!(c.detail, "node");
}

#[test]
fn check_command_is_npx_missing_reports_placeholder() {
    let settings = json!({ "mcpServers": { MCP_NAME: {} } });
    let c = check_command_is_npx(&settings);
    assert!(!c.passed);
    assert_eq!(c.detail, "(missing)");
}

#[test]
fn check_package_correct_checks_membership_in_args() {
    let settings = full_entry("npx", json!(["-y", MCP_PACKAGE]), json!({}));
    assert!(check_package_correct(&settings).passed);

    let settings = full_entry("npx", json!(["-y", "@other/pkg"]), json!({}));
    assert!(!check_package_correct(&settings).passed);
}

#[test]
fn check_api_key_set_masks_long_keys_in_detail() {
    let settings = full_entry(
        "npx",
        json!([]),
        json!({ "GOOGLE_AI_API_KEY": "AIzaSyABCDEFGHIJKLMNOP1234" }),
    );
    let c = check_api_key_set(&settings);
    assert!(c.passed);
    assert_eq!(c.detail, "AIzaSyAB...1234");
}

#[test]
fn check_api_key_set_fails_and_labels_short_when_absent() {
    let settings = full_entry("npx", json!([]), json!({}));
    let c = check_api_key_set(&settings);
    assert!(!c.passed);
    assert_eq!(c.detail, "(empty or short)");
}

#[test]
fn check_model_set_reports_default_hint_when_absent() {
    let settings = full_entry("npx", json!([]), json!({}));
    let c = check_model_set(&settings);
    assert!(!c.passed);
    assert_eq!(c.detail, "(not set, will use package default)");
}

#[test]
fn check_model_set_passes_when_present() {
    let settings = full_entry("npx", json!([]), json!({ "NANOBANANA_MODEL": "m" }));
    let c = check_model_set(&settings);
    assert!(c.passed);
    assert_eq!(c.detail, "m");
}

#[test]
fn check_npx_available_reflects_which_result() {
    assert!(check_npx_available(Some("/usr/bin/npx")).passed);
    assert!(!check_npx_available(None).passed);
    assert_eq!(check_npx_available(None).detail, "not found");
}

#[test]
fn check_output_dir_states() {
    assert!(check_output_dir(&OutputDirState::AlreadyExists, "/d").passed);
    assert!(check_output_dir(&OutputDirState::Created, "/d").passed);
    let failed = check_output_dir(
        &OutputDirState::CreateFailed { detail: "Permission denied".to_string() },
        "/d",
    );
    assert!(!failed.passed);
    assert_eq!(failed.detail, "Permission denied");
}

// ---------------------------------------------------------------------
// run_validation — composition matching `main()`'s control flow.
// ---------------------------------------------------------------------

#[test]
fn run_validation_skips_checks_4_through_7_when_not_configured() {
    let checks = run_validation(&json!({}), Some("/usr/bin/npx"), &OutputDirState::AlreadyExists, "/d");
    // Only: mcp configured, npx available, output dir = 3 checks.
    assert_eq!(checks.len(), 3);
    assert!(!checks[0].passed);
}

#[test]
fn run_validation_runs_all_nine_analog_checks_when_fully_configured() {
    let settings = full_entry(
        "npx",
        json!(["-y", MCP_PACKAGE]),
        json!({ "GOOGLE_AI_API_KEY": "AIzaSyABCDEFGHIJKLMNOP1234", "NANOBANANA_MODEL": "m" }),
    );
    let checks = run_validation(&settings, Some("/usr/bin/npx"), &OutputDirState::AlreadyExists, "/d");
    // mcp configured, command, package, key, model, npx, output dir = 7.
    assert_eq!(checks.len(), 7);
    assert!(checks.iter().all(|c| c.passed));
}

#[test]
fn full_report_all_pass_matches_validate_setup_success_exit_code() {
    let settings = full_entry(
        "npx",
        json!(["-y", MCP_PACKAGE]),
        json!({ "GOOGLE_AI_API_KEY": "AIzaSyABCDEFGHIJKLMNOP1234", "NANOBANANA_MODEL": "m" }),
    );
    let mut checks = vec![
        check_settings_file_exists(true, "/home/u/.claude/settings.json"),
        check_json_valid(true, ""),
    ];
    checks.extend(run_validation(
        &settings,
        Some("/usr/bin/npx"),
        &OutputDirState::AlreadyExists,
        "/d",
    ));
    use legion_runtime::wf_port::w2_026::ValidationReport;
    let report = ValidationReport { checks };
    assert_eq!(report.passed(), report.total());
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn missing_settings_file_short_circuits_with_exit_1() {
    use legion_runtime::wf_port::w2_026::ValidationReport;
    // main(): `if not SETTINGS_PATH.exists(): return 1` — only the first
    // check ran.
    let checks = vec![check_settings_file_exists(false, "/home/u/.claude/settings.json")];
    let report = ValidationReport { checks };
    assert_eq!(report.exit_code(), 1);
}
