//! Port of `src/lib/review/providers/subprocess_cli.py`
//! (`SubprocessProvider`, one-shot CLI jurors).
//!
//! **Ported faithfully (pure, process-free):**
//! - `{model}` / `{prompt}` command-template substitution and the
//!   stdin-vs-argv decision (`prompt_via_stdin = "{prompt}" not in
//!   " ".join(command_template)`) — [`build_command`], [`prompt_via_stdin`]
//! - the non-zero-exit error message, including the 4000-char stderr/stdout
//!   cap (`(proc.stderr or proc.stdout or "")[:4000]`) — [`exit_error_message`]
//! - the executable-resolution fallback order on Windows
//!   (`name`, then `name.cmd`/`.exe`/`.bat`/`.ps1`) as a pure *candidate
//!   list* — [`windows_executable_candidates`]; `shutil.which` itself is a
//!   filesystem/PATH lookup and stays with the caller.
//!
//! **Not ported (live process transport):** `subprocess.run` itself
//! (spawning the child, capturing stdout/stderr, the `timeout_s` deadline),
//! `shutil.which` PATH resolution, and the `agent_spawn.ensure_directive`
//! best-effort import used to prepend the machine-minimal JSON-mode
//! directive (`try: ... except Exception: user_enforced = user` — that
//! module lives outside this chunk's owned paths). A caller wiring this to
//! a live transport applies [`build_command`] to get argv, then spawns it
//! with `full_prompt` on stdin or substituted into argv per
//! [`prompt_via_stdin`].

/// Port of `prompt_via_stdin = "{prompt}" not in " ".join(command_template)`.
pub fn prompt_via_stdin(command_template: &[String]) -> bool {
    !command_template.join(" ").contains("{prompt}")
}

/// Port of the Windows-only fallback candidate order in
/// `_resolve_executable`: `name`, then `name.cmd`, `name.exe`, `name.bat`,
/// `name.ps1`. Each candidate is what the caller passes to a `shutil.which`
/// equivalent (`which::which` or similar); the first one that resolves
/// wins, and if none does, the Python returns `name` itself as "last
/// resort" (callers should fall back to `name` — `command_template[0]` —
/// when every candidate here misses, matching `return name`).
pub fn windows_executable_candidates(name: &str) -> Vec<String> {
    vec![
        name.to_string(),
        format!("{name}.cmd"),
        format!("{name}.exe"),
        format!("{name}.bat"),
        format!("{name}.ps1"),
    ]
}

/// Port of the `cmd` construction loop in `call`: substitutes `{model}` and
/// `{prompt}` into each `command_template` piece (element 0 is left as-is —
/// executable resolution is a separate, platform-dependent step the caller
/// applies to `cmd[0]`; the Python resolves it inline via
/// `_resolve_executable(piece)`, which this function does not perform since
/// it requires filesystem/PATH access).
///
/// Matches Python's `if/elif` order: a piece containing `{model}` is model-
/// substituted even if it also happens to contain `{prompt}` (mutually
/// exclusive in practice, but the precedence is preserved exactly).
pub fn build_command(command_template: &[String], model: &str, full_prompt: &str) -> Vec<String> {
    command_template
        .iter()
        .enumerate()
        .map(|(i, piece)| {
            if i == 0 {
                piece.clone()
            } else if piece.contains("{model}") {
                piece.replace("{model}", model)
            } else if piece.contains("{prompt}") {
                piece.replace("{prompt}", full_prompt)
            } else {
                piece.clone()
            }
        })
        .collect()
}

/// Cap applied to stderr/stdout on a non-zero exit, port of the literal
/// `4000` in `call`'s error-message construction (raised from 500 -> 4000
/// on 2026-05-05, per the Python comment, to match `engine.py` response
/// clipping).
pub const EXIT_ERROR_CAP: usize = 4000;

/// Port of `err = (proc.stderr or proc.stdout or "")[:4000]` plus the
/// message format `f"{self.name}/{model} exit {proc.returncode}: {err}"`.
/// Python's `str[:4000]` slices by Unicode code point; this slices by
/// `char`, matching that (not by byte, which could split a multi-byte
/// char).
pub fn exit_error_message(provider_name: &str, model: &str, returncode: i32, stderr: &str, stdout: &str) -> String {
    let raw: &str = if !stderr.is_empty() {
        stderr
    } else {
        stdout
    };
    let capped: String = raw.chars().take(EXIT_ERROR_CAP).collect();
    format!("{provider_name}/{model} exit {returncode}: {capped}")
}

/// Port of the `timeout_s` construction default: `int(config.get("timeout_s", 180))`.
pub const DEFAULT_TIMEOUT_S: u64 = 180;

/// Port of `full_prompt = f"{system}\n\n---\n\n{user_enforced}"` (with
/// `user_enforced` already resolved by the caller — the `ensure_directive`
/// best-effort call is outside this chunk's owned paths, see module docs).
pub fn build_full_prompt(system: &str, user_enforced: &str) -> String {
    format!("{system}\n\n---\n\n{user_enforced}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_via_stdin_true_when_template_has_no_prompt_placeholder() {
        let template = vec!["codex".to_string(), "exec".to_string(), "-".to_string()];
        assert!(prompt_via_stdin(&template));
    }

    #[test]
    fn prompt_via_stdin_false_when_template_has_prompt_placeholder() {
        let template = vec!["mycli".to_string(), "{prompt}".to_string()];
        assert!(!prompt_via_stdin(&template));
    }

    #[test]
    fn windows_candidates_in_order() {
        assert_eq!(
            windows_executable_candidates("gemini"),
            vec!["gemini", "gemini.cmd", "gemini.exe", "gemini.bat", "gemini.ps1"],
        );
    }

    #[test]
    fn build_command_substitutes_model_and_prompt_leaves_argv0() {
        let template = vec![
            "codex".to_string(),
            "exec".to_string(),
            "-m".to_string(),
            "{model}".to_string(),
            "-".to_string(),
        ];
        let cmd = build_command(&template, "gpt-5.5", "SYSTEM\n\n---\n\nUSER");
        assert_eq!(cmd, vec!["codex", "exec", "-m", "gpt-5.5", "-"]);
    }

    #[test]
    fn build_command_substitutes_prompt_placeholder() {
        let template = vec!["mycli".to_string(), "{prompt}".to_string()];
        let cmd = build_command(&template, "m", "the full prompt");
        assert_eq!(cmd, vec!["mycli", "the full prompt"]);
    }

    #[test]
    fn build_command_model_takes_precedence_over_prompt_in_same_piece() {
        // Mirrors the Python's if/elif order: a piece matching "{model}" is
        // never also prompt-substituted, even in the contrived case both
        // placeholders appear in one piece.
        let template = vec!["cli".to_string(), "{model}-{prompt}".to_string()];
        let cmd = build_command(&template, "M", "P");
        assert_eq!(cmd, vec!["cli", "M-{prompt}"]);
    }

    #[test]
    fn exit_error_message_prefers_stderr_over_stdout() {
        let msg = exit_error_message("codex", "gpt-5.5", 1, "boom", "should not appear");
        assert_eq!(msg, "codex/gpt-5.5 exit 1: boom");
    }

    #[test]
    fn exit_error_message_falls_back_to_stdout_when_stderr_empty() {
        let msg = exit_error_message("codex", "gpt-5.5", 2, "", "stdout text");
        assert_eq!(msg, "codex/gpt-5.5 exit 2: stdout text");
    }

    #[test]
    fn exit_error_message_empty_when_both_streams_empty() {
        let msg = exit_error_message("codex", "gpt-5.5", 3, "", "");
        assert_eq!(msg, "codex/gpt-5.5 exit 3: ");
    }

    #[test]
    fn exit_error_message_caps_at_4000_chars() {
        let long = "x".repeat(5000);
        let msg = exit_error_message("codex", "m", 1, &long, "");
        // "codex/m exit 1: " prefix + 4000 capped chars.
        let prefix = "codex/m exit 1: ";
        assert_eq!(msg.len(), prefix.len() + EXIT_ERROR_CAP);
        assert!(msg.ends_with(&"x".repeat(EXIT_ERROR_CAP)));
    }

    #[test]
    fn full_prompt_join_format() {
        assert_eq!(
            build_full_prompt("SYS", "USER"),
            "SYS\n\n---\n\nUSER",
        );
    }
}
