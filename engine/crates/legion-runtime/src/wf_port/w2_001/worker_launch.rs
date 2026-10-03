//! Portable input validation shared by host-native Alchemist runners.
//! for host-native runner input handling.

use regex::Regex;

/// Host-native runner exit codes, including bounded input/output failures.
pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_UNKNOWN_PROFILE: i32 = 5;
pub const EXIT_ZERO_EVENTS: i32 = 65;
pub const EXIT_INPUT_TOO_LARGE: i32 = 66;
pub const EXIT_OUTPUT_TOO_LARGE: i32 = 125;
pub const EXIT_TIMEOUT: i32 = 124;

/// Extracts first safe `model = "..."` value from Codex profile TOML.
pub fn extract_model(profile_toml: &str) -> Option<String> {
    // (?m) so `^`/`$` behaviour matches per-line scanning; only the first
    // match is used, matching `head -1` / `[regex]::Match` (first match).
    let re = Regex::new(r#"(?m)^[ \t]*model[ \t]*=[ \t]*"([A-Za-z0-9._:/-]+)""#).unwrap();
    re.captures(profile_toml)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

/// Rejects empty or whitespace-only runner briefs.
pub fn validate_brief(brief: &str) -> Result<(), &'static str> {
    if brief.trim().is_empty() {
        Err("Empty brief on stdin - refusing to spawn a worker with no task.")
    } else {
        Ok(())
    }
}

/// Enforces maximum UTF-8 input size.
pub fn validate_brief_size(brief: &str, max_input_bytes: usize) -> Result<(), String> {
    let byte_len = brief.len();
    if byte_len > max_input_bytes {
        Err(format!(
            "Worker input exceeded MaxInputBytes: {byte_len} > {max_input_bytes}."
        ))
    } else {
        Ok(())
    }
}

/// Selects bounded or explicitly full-access sandbox arguments. Bounded
/// default: `--sandbox workspace-write`;
/// explicit opt-in: `--dangerously-bypass-approvals-and-sandbox`.
pub fn access_args(full_access: bool) -> &'static str {
    if full_access {
        "--dangerously-bypass-approvals-and-sandbox"
    } else {
        "--sandbox workspace-write"
    }
}

/// Strips leading whitespace and BOM from one JSON event line.
pub fn remove_leading_json_preamble(line: &str) -> String {
    line.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
        .to_string()
}

/// Builds an event-log path from run directory, timestamp, and profile.
pub fn default_event_log_path(run_dir: &str, timestamp: &str, profile: &str) -> String {
    format!("{run_dir}/{timestamp}-{profile}.jsonl")
}

/// Builds a Codex profile config path.
pub fn profile_file_path(codex_home: &str, profile: &str) -> String {
    format!("{codex_home}/{profile}.config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_model_reads_first_quoted_model_line() {
        let toml = "profile = \"default\"\nmodel = \"gpt-5.6\"\nother = \"x\"\n";
        assert_eq!(extract_model(toml).as_deref(), Some("gpt-5.6"));
    }

    #[test]
    fn extract_model_ignores_indented_and_returns_first_match() {
        let toml = "  model = \"first-model\"\nmodel = \"second-model\"\n";
        assert_eq!(extract_model(toml).as_deref(), Some("first-model"));
    }

    #[test]
    fn extract_model_none_when_missing() {
        assert_eq!(extract_model("profile = \"default\"\n"), None);
    }

    #[test]
    fn extract_model_rejects_disallowed_characters_in_value() {
        // A value containing a character outside [A-Za-z0-9._:/-] (a space)
        // does not match, mirroring the sed/regex character class in both
        // runner inputs.
        assert_eq!(extract_model("model = \"bad value\"\n"), None);
    }

    #[test]
    fn validate_brief_rejects_blank_and_whitespace_only() {
        assert!(validate_brief("").is_err());
        assert!(validate_brief("   \n\t ").is_err());
        assert!(validate_brief("do the thing").is_ok());
    }

    #[test]
    fn validate_brief_size_enforces_max_input_bytes() {
        assert!(validate_brief_size("hi", 10).is_ok());
        let err = validate_brief_size("hello world", 5).unwrap_err();
        assert!(err.contains("Worker input exceeded MaxInputBytes: 11 > 5."));
    }

    #[test]
    fn access_args_default_is_bounded() {
        assert_eq!(access_args(false), "--sandbox workspace-write");
        assert_eq!(
            access_args(true),
            "--dangerously-bypass-approvals-and-sandbox"
        );
    }

    #[test]
    fn remove_leading_json_preamble_strips_bom_and_whitespace() {
        assert_eq!(
            remove_leading_json_preamble("\u{feff}  {\"a\":1}"),
            "{\"a\":1}"
        );
        assert_eq!(remove_leading_json_preamble("{\"a\":1}"), "{\"a\":1}");
    }

    #[test]
    fn default_event_log_path_matches_shared_shape() {
        assert_eq!(
            default_event_log_path("/home/u/.alchemist/runs", "20260923-101500", "fast"),
            "/home/u/.alchemist/runs/20260923-101500-fast.jsonl"
        );
    }

    #[test]
    fn profile_file_path_matches_codex_layout() {
        assert_eq!(
            profile_file_path("/home/u/.codex", "fast"),
            "/home/u/.codex/fast.config.toml"
        );
    }
}
