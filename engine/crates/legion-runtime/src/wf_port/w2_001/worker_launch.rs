//! Portable decision logic shared by `skills/alchemist/scripts/run-worker.sh`
//! and `run-worker.ps1`. See the module-level doc comment in `super` for why
//! the process-spawning/watchdog halves of those two scripts are not ported.

use regex::Regex;

/// Default OmniRoute gateway URL both scripts fall back to when
/// `OMNIROUTE_URL` is unset.
pub const DEFAULT_GATEWAY_URL: &str = "http://127.0.0.1:20128";

/// Documented exit codes from `run-worker.sh`'s header comment (the
/// PowerShell runner uses the same 0/2/4/5/124 values plus its own
/// byte/output-limit codes 65/66/125).
pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_GATEWAY_DOWN: i32 = 4;
pub const EXIT_UNKNOWN_PROFILE: i32 = 5;
pub const EXIT_ZERO_EVENTS: i32 = 65; // run-worker.ps1 only
pub const EXIT_INPUT_TOO_LARGE: i32 = 66; // run-worker.ps1 only
pub const EXIT_OUTPUT_TOO_LARGE: i32 = 125; // run-worker.ps1 only
pub const EXIT_TIMEOUT: i32 = 124;

/// Port of the `sed -nE 's/^[[:space:]]*model[[:space:]]*=[[:space:]]*"(...)".*/\1/p'`
/// pipeline in `run-worker.sh` and the equivalent `[regex]::Match` in
/// `run-worker.ps1`: both extract the first `model = "..."` line from a
/// Codex profile TOML file using the same character class
/// (`[A-Za-z0-9._:/-]+`). Returns `None` when the profile has no such line,
/// mirroring both scripts' "No safe model value in profile" failure.
pub fn extract_model(profile_toml: &str) -> Option<String> {
    // (?m) so `^`/`$` behaviour matches per-line scanning; only the first
    // match is used, matching `head -1` / `[regex]::Match` (first match).
    let re = Regex::new(r#"(?m)^[ \t]*model[ \t]*=[ \t]*"([A-Za-z0-9._:/-]+)""#).unwrap();
    re.captures(profile_toml)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

/// Result of probing `${GATEWAY}/healthz`.
#[derive(Debug, PartialEq, Eq)]
pub enum GatewayHealth {
    /// One of the status codes both scripts treat as "the gateway answered,
    /// proceed" (run-worker.sh: `200|204|301|302|307|401`).
    Reachable,
    /// No code, or a code outside the accepted set: exit
    /// [`EXIT_GATEWAY_DOWN`].
    Unreachable,
}

/// Port of `run-worker.sh`'s `case "$CODE" in 200|204|301|302|307|401) ;; *) exit 4 ;; esac`.
/// `code` is `None` when the probe itself failed (curl error, empty body),
/// matching the script's `${CODE:-none}` fallback.
pub fn classify_healthz(code: Option<u16>) -> GatewayHealth {
    match code {
        Some(200 | 204 | 301 | 302 | 307 | 401) => GatewayHealth::Reachable,
        _ => GatewayHealth::Unreachable,
    }
}

/// Port of both scripts' empty-brief guard:
/// bash: `[ -z "${BRIEF// }" ]` (empty after stripping spaces);
/// PowerShell: `[string]::IsNullOrWhiteSpace($brief)` (empty after
/// stripping *all* whitespace, a strictly broader check). This follows the
/// PowerShell (stricter) behaviour, which is a superset of the bash guard
/// and is the one that actually blocks the empty-brief exit path in both
/// runners.
pub fn validate_brief(brief: &str) -> Result<(), &'static str> {
    if brief.trim().is_empty() {
        Err("Empty brief on stdin - refusing to spawn a worker with no task.")
    } else {
        Ok(())
    }
}

/// Port of `run-worker.sh`'s `MaxInputBytes` guard in `run-worker.ps1`
/// (`$briefBytes -gt $MaxInputBytes`), measured in UTF-8 bytes as the
/// PowerShell script does (`[Text.Encoding]::UTF8.GetByteCount`).
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

/// Port of the bounded-vs-full-access sandbox argument selection shared by
/// both scripts: bash checks `ALCHEMIST_FULL_ACCESS=1`, PowerShell checks
/// the `-FullAccess` switch. Bounded default: `--sandbox workspace-write`;
/// explicit opt-in: `--dangerously-bypass-approvals-and-sandbox`.
pub fn access_args(full_access: bool) -> &'static str {
    if full_access {
        "--dangerously-bypass-approvals-and-sandbox"
    } else {
        "--sandbox workspace-write"
    }
}

/// Port of `run-worker.ps1`'s `Remove-LeadingJsonPreamble`: strips leading
/// whitespace and a leading BOM (`^[\s﻿]+`) from one line before it is
/// counted as a JSON event or forwarded to `parse_events.py --stream`.
pub fn remove_leading_json_preamble(line: &str) -> String {
    line.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
        .to_string()
}

/// Port of the event-log path both scripts build when the caller does not
/// supply one explicitly: `${RUN_DIR}/<timestamp>-<profile>.jsonl`
/// (bash: `date +%Y%m%d-%H%M%S`; PowerShell: `Get-Date -Format
/// 'yyyyMMdd-HHmmss'` — the same format). `timestamp` is supplied by the
/// caller (already formatted `yyyyMMdd-HHmmss`) so this stays a pure,
/// clock-free function.
pub fn default_event_log_path(run_dir: &str, timestamp: &str, profile: &str) -> String {
    format!("{run_dir}/{timestamp}-{profile}.jsonl")
}

/// Port of `run-worker.sh`'s `PROFILE_FILE="${CODEX_HOME_DIR}/${PROFILE}.config.toml"`
/// (and the equivalent `Join-Path $codexHome "$Profile.config.toml"`).
pub fn profile_file_path(codex_home: &str, profile: &str) -> String {
    format!("{codex_home}/{profile}.config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_model_reads_first_quoted_model_line() {
        let toml = "profile = \"default\"\nmodel = \"omniroute/gpt-5.6\"\nother = \"x\"\n";
        assert_eq!(extract_model(toml).as_deref(), Some("omniroute/gpt-5.6"));
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
        // scripts.
        assert_eq!(extract_model("model = \"bad value\"\n"), None);
    }

    #[test]
    fn classify_healthz_accepts_documented_codes() {
        for code in [200, 204, 301, 302, 307, 401] {
            assert_eq!(classify_healthz(Some(code)), GatewayHealth::Reachable);
        }
    }

    #[test]
    fn classify_healthz_rejects_other_codes_and_none() {
        assert_eq!(classify_healthz(Some(500)), GatewayHealth::Unreachable);
        assert_eq!(classify_healthz(Some(404)), GatewayHealth::Unreachable);
        assert_eq!(classify_healthz(None), GatewayHealth::Unreachable);
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
    fn profile_file_path_matches_both_scripts() {
        assert_eq!(
            profile_file_path("/home/u/.codex", "fast"),
            "/home/u/.codex/fast.config.toml"
        );
    }
}
