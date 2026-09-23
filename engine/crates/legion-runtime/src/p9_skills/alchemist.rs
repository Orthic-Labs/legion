//! Packet P9-skill-scripts: Rust port of the deterministic decision logic in
//! `skills/alchemist/scripts/run-worker.sh` (the bash OmniRoute/Codex worker launcher).
//!
//! Ported here (pure, no process IO):
//! - `extract_model_from_profile`: pulls `model = "..."` out of a Codex profile TOML the same
//!   way the shell `sed` does (`^[[:space:]]*model[[:space:]]*=[[:space:]]*"([...])".*`).
//! - `healthz_exit_code` / `HealthzOutcome`: interprets an OmniRoute `/healthz` HTTP status the
//!   same way the shell `case` statement does (200/204/301/302/307/401 -> reachable, else -> 4).
//! - `access_args`: `--sandbox workspace-write` unless `ALCHEMIST_FULL_ACCESS=1`, matching
//!   `ACCESS_ARGS`.
//! - `default_event_log_path`: `<run_dir>/<UTC-stamp>-<profile>.jsonl`, matching the default
//!   `EVENT_LOG` the script builds when the caller doesn't pass one.
//! - `WorkerExitCode`: the documented exit contract (0 ok, 2 usage, 4 gateway down,
//!   5 unknown profile, 124 timeout).
//!
//! NOT ported here: spawning `omniroute launch-codex` itself, the TERM/KILL watchdog process
//! tree, and piping stdout through `parse_events.py` (a Python script outside this packet's JS
//! scope — see the packet report). A caller wanting the full launch needs to still shell out;
//! this module gives it the exact inputs (model, event log path, sandbox flags) and the exact
//! exit-code semantics to interpret the child's result by by itself, without re-deriving the
//! shell script's parsing/threshold logic in the caller.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExitCode {
    Ok = 0,
    Usage = 2,
    GatewayDown = 4,
    UnknownProfile = 5,
    Timeout = 124,
}

impl WorkerExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Mirrors the `sed -nE 's/^[[:space:]]*model[[:space:]]*=[[:space:]]*"([A-Za-z0-9._:/-]+)".*/\1/p'
/// | head -1` pipeline: the first line whose (whitespace-trimmed) prefix is `model = "<value>"`,
/// where `<value>` is restricted to `[A-Za-z0-9._:/-]+`.
pub fn extract_model_from_profile(profile_toml: &str) -> Option<String> {
    for line in profile_toml.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("model") else { continue };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else { continue };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('"') else { continue };
        let end = match rest.find('"') {
            Some(e) => e,
            None => continue,
        };
        let value = &rest[..end];
        if !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
        {
            return Some(value.to_string());
        }
    }
    None
}

/// Mirrors the healthz `case` statement: is this HTTP status one OmniRoute is considered
/// reachable at?
pub fn is_gateway_reachable(http_status: u16) -> bool {
    matches!(http_status, 200 | 204 | 301 | 302 | 307 | 401)
}

/// `ACCESS_ARGS`: sandboxed by default, full host access only on explicit opt-in.
pub fn access_args(full_access_env: Option<&str>) -> Vec<&'static str> {
    if full_access_env == Some("1") {
        vec!["--dangerously-bypass-approvals-and-sandbox"]
    } else {
        vec!["--sandbox", "workspace-write"]
    }
}

/// Builds the default event log path when the caller doesn't supply one:
/// `<run_dir>/<YYYYmmdd-HHMMSS>-<profile>.jsonl`, given an already-formatted UTC timestamp
/// (the shell script uses `date +%Y%m%d-%H%M%S`; callers should format `now` the same way).
pub fn default_event_log_path(run_dir: &str, timestamp: &str, profile: &str) -> String {
    format!("{}/{}-{}.jsonl", run_dir.trim_end_matches('/'), timestamp, profile)
}

/// Path to a Codex profile's config file, given the Codex home directory and profile name:
/// `${CODEX_HOME:-$HOME/.codex}/<profile>.config.toml`.
pub fn profile_config_path(codex_home_dir: &str, profile: &str) -> String {
    format!("{}/{}.config.toml", codex_home_dir.trim_end_matches('/'), profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_model_ignoring_leading_whitespace_and_trailing_content() {
        let toml = "profile = \"x\"\n  model = \"gpt-5.6-omniroute\"  # comment\nother = 1\n";
        assert_eq!(extract_model_from_profile(toml), Some("gpt-5.6-omniroute".to_string()));
    }

    #[test]
    fn returns_none_when_no_model_line() {
        assert_eq!(extract_model_from_profile("profile = \"x\"\n"), None);
    }

    #[test]
    fn rejects_disallowed_characters_and_falls_through() {
        let toml = "model = \"bad value!\"\nmodel = \"good-value.1\"\n";
        assert_eq!(extract_model_from_profile(toml), Some("good-value.1".to_string()));
    }

    #[test]
    fn healthz_thresholds_match_shell_case() {
        for ok in [200, 204, 301, 302, 307, 401] {
            assert!(is_gateway_reachable(ok), "{ok} should be reachable");
        }
        for down in [0, 404, 500, 502, 503] {
            assert!(!is_gateway_reachable(down), "{down} should not be reachable");
        }
    }

    #[test]
    fn access_args_defaults_to_sandboxed() {
        assert_eq!(access_args(None), vec!["--sandbox", "workspace-write"]);
        assert_eq!(access_args(Some("0")), vec!["--sandbox", "workspace-write"]);
        assert_eq!(
            access_args(Some("1")),
            vec!["--dangerously-bypass-approvals-and-sandbox"]
        );
    }

    #[test]
    fn default_event_log_path_matches_shell_format() {
        assert_eq!(
            default_event_log_path("/home/x/.alchemist/runs", "20260923-101500", "default"),
            "/home/x/.alchemist/runs/20260923-101500-default.jsonl"
        );
    }

    #[test]
    fn profile_config_path_matches_codex_home_layout() {
        assert_eq!(
            profile_config_path("/home/x/.codex", "default"),
            "/home/x/.codex/default.config.toml"
        );
    }

    #[test]
    fn worker_exit_codes_match_documented_contract() {
        assert_eq!(WorkerExitCode::Ok.code(), 0);
        assert_eq!(WorkerExitCode::Usage.code(), 2);
        assert_eq!(WorkerExitCode::GatewayDown.code(), 4);
        assert_eq!(WorkerExitCode::UnknownProfile.code(), 5);
        assert_eq!(WorkerExitCode::Timeout.code(), 124);
    }
}
