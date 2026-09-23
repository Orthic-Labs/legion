//! Port of `src/lib/review/quick-ask.py` (ad-hoc Codex/Gemini CLI
//! consultation wrapper, forced machine-minimal output).
//!
//! **Ported faithfully (pure, transport-free):**
//! - the `codex`/`gemini` command templates and their default models/
//!   timeouts (`CODEX_CONFIG`, `GEMINI_CONFIG`) — [`codex_command_template`],
//!   [`gemini_command_template`], [`DEFAULT_CODEX_MODEL`],
//!   [`DEFAULT_GEMINI_MODEL`], [`JUROR_TIMEOUT_S`]
//! - `--only` juror selection (`codex`/`gemini`/`both`) — [`JurorSelection`],
//!   [`selected_jurors`]
//! - empty-input validation (`if not question.strip(): ... sys.exit(1)`) —
//!   [`validate_question`]
//! - the machine-minimal directive prefix (`f"{directive}\n\n---\n\n{prompt}"`)
//!   — [`with_directive`]
//! - per-juror result ordering (`results.sort(key=lambda r: r[0])`, i.e. by
//!   juror name) and the `"CODEX (12.3s)"` / `"ERROR: ..."` output-block
//!   formatting — [`sort_results`], [`format_result_block`]
//!
//! **Not ported (live process/config transport):** the actual
//! `ThreadPoolExecutor`-parallel `SubprocessProvider.call` invocations
//! (spawning `codex`/`gemini`), reading `policy.toml` for
//! `MACHINE_MINIMAL_DIRECTIVE`, `argparse` flag parsing itself, and
//! stdin/file input reading. A caller wiring this to a live transport reads
//! the directive and question, calls [`with_directive`] then dispatches
//! through the w2_053 `subprocess_cli` port (or a live subprocess client)
//! for each juror in [`selected_jurors`], and renders results with
//! [`sort_results`] + [`format_result_block`].

/// Port of `CODEX_CONFIG["command_template"]`.
pub fn codex_command_template() -> Vec<String> {
    vec![
        "codex".to_string(),
        "exec".to_string(),
        "--skip-git-repo-check".to_string(),
        "-m".to_string(),
        "{model}".to_string(),
        "-".to_string(),
    ]
}

/// Port of `GEMINI_CONFIG["command_template"]`.
pub fn gemini_command_template() -> Vec<String> {
    vec!["gemini".to_string(), "-m".to_string(), "{model}".to_string(), "-y".to_string()]
}

/// Port of `CODEX_CONFIG["timeout_s"]` and `GEMINI_CONFIG["timeout_s"]`
/// (both `240`).
pub const JUROR_TIMEOUT_S: u64 = 240;

/// Port of `ap.add_argument("--codex-model", default="gpt-5.5", ...)`.
pub const DEFAULT_CODEX_MODEL: &str = "gpt-5.5";

/// Port of `ap.add_argument("--gemini-model", default="gemini-2.5-flash", ...)`.
pub const DEFAULT_GEMINI_MODEL: &str = "gemini-2.5-flash";

/// Port of `ap.add_argument("--only", choices=["codex", "gemini", "both"], default="both")`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JurorSelection {
    Codex,
    Gemini,
    Both,
}

impl JurorSelection {
    /// Port of the `--only` choice parsing (case-sensitive, matching
    /// argparse's exact `choices` list); returns `None` for anything not in
    /// `{"codex", "gemini", "both"}`, matching argparse's own rejection
    /// (the caller surfaces that as a usage error, as argparse does).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "codex" => Some(Self::Codex),
            "gemini" => Some(Self::Gemini),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

impl Default for JurorSelection {
    fn default() -> Self {
        Self::Both
    }
}

/// One juror name, in the order `main()` would build the `jurors` list
/// (`codex` before `gemini` when both are selected — the eventual sort by
/// name makes this order not user-visible, but it matches source order).
pub fn selected_jurors(selection: JurorSelection) -> Vec<&'static str> {
    match selection {
        JurorSelection::Codex => vec!["codex"],
        JurorSelection::Gemini => vec!["gemini"],
        JurorSelection::Both => vec!["codex", "gemini"],
    }
}

/// Port of `if not question.strip(): print("ERROR: empty input",
/// file=sys.stderr); sys.exit(1)`. `Ok(trimmed borrow)` mirrors the
/// non-empty pass-through (the Python does not actually trim `question`
/// before use elsewhere, only for the emptiness check); `Err(())` signals
/// the exit-1 path.
pub fn validate_question(question: &str) -> Result<(), ()> {
    if question.trim().is_empty() {
        return Err(());
    }
    Ok(())
}

/// Port of `full = f"{MACHINE_MINIMAL_DIRECTIVE}\n\n---\n\n{prompt}"` (built
/// in `call_juror` but never actually sent — the Python computes `full` and
/// then calls `provider.call(..., system=MACHINE_MINIMAL_DIRECTIVE,
/// user=prompt, ...)`, so `full` is dead in the original; ported anyway for
/// fidelity in case a future caller needs the same combined string).
pub fn with_directive(directive: &str, prompt: &str) -> String {
    format!("{directive}\n\n---\n\n{prompt}")
}

/// One juror's outcome, port of the `(name, out, elapsed, err)` tuple
/// `call_juror` returns.
#[derive(Clone, Debug, PartialEq)]
pub struct JurorOutcome {
    pub name: String,
    pub output: String,
    pub elapsed_s: f64,
    pub error: Option<String>,
}

/// Port of `results.sort(key=lambda r: r[0])`: stable sort by juror name.
pub fn sort_results(mut results: Vec<JurorOutcome>) -> Vec<JurorOutcome> {
    results.sort_by(|a, b| a.name.cmp(&b.name));
    results
}

/// Port of the per-result print block:
/// ```text
/// \n========== {NAME} ({elapsed:.1f}s) ==========
/// ERROR: {err}          # when err is set
/// {out.strip()}         # otherwise
/// ```
pub fn format_result_block(outcome: &JurorOutcome) -> String {
    let header = format!(
        "\n========== {} ({:.1}s) ==========",
        outcome.name.to_uppercase(),
        outcome.elapsed_s
    );
    let body = match &outcome.error {
        Some(err) => format!("ERROR: {err}"),
        None => outcome.output.trim().to_string(),
    };
    format!("{header}\n{body}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_and_gemini_templates_match_python_config() {
        assert_eq!(
            codex_command_template(),
            vec!["codex", "exec", "--skip-git-repo-check", "-m", "{model}", "-"],
        );
        assert_eq!(gemini_command_template(), vec!["gemini", "-m", "{model}", "-y"]);
    }

    #[test]
    fn defaults_match_python() {
        assert_eq!(DEFAULT_CODEX_MODEL, "gpt-5.5");
        assert_eq!(DEFAULT_GEMINI_MODEL, "gemini-2.5-flash");
        assert_eq!(JUROR_TIMEOUT_S, 240);
    }

    #[test]
    fn juror_selection_parses_valid_choices_only() {
        assert_eq!(JurorSelection::parse("codex"), Some(JurorSelection::Codex));
        assert_eq!(JurorSelection::parse("gemini"), Some(JurorSelection::Gemini));
        assert_eq!(JurorSelection::parse("both"), Some(JurorSelection::Both));
        assert_eq!(JurorSelection::parse("Codex"), None);
        assert_eq!(JurorSelection::parse("bogus"), None);
    }

    #[test]
    fn selected_jurors_matches_only_flag() {
        assert_eq!(selected_jurors(JurorSelection::Codex), vec!["codex"]);
        assert_eq!(selected_jurors(JurorSelection::Gemini), vec!["gemini"]);
        assert_eq!(selected_jurors(JurorSelection::Both), vec!["codex", "gemini"]);
    }

    #[test]
    fn validate_question_rejects_blank_and_whitespace_only() {
        assert!(validate_question("").is_err());
        assert!(validate_question("   \n\t").is_err());
        assert!(validate_question("hi").is_ok());
    }

    #[test]
    fn with_directive_join_format() {
        assert_eq!(with_directive("DIRECTIVE", "prompt"), "DIRECTIVE\n\n---\n\nprompt");
    }

    #[test]
    fn sort_results_orders_by_name() {
        let results = vec![
            JurorOutcome { name: "gemini".into(), output: "g".into(), elapsed_s: 1.0, error: None },
            JurorOutcome { name: "codex".into(), output: "c".into(), elapsed_s: 2.0, error: None },
        ];
        let sorted = sort_results(results);
        assert_eq!(sorted[0].name, "codex");
        assert_eq!(sorted[1].name, "gemini");
    }

    #[test]
    fn format_result_block_success() {
        let outcome = JurorOutcome {
            name: "codex".into(),
            output: "  the answer  \n".into(),
            elapsed_s: 12.34,
            error: None,
        };
        let block = format_result_block(&outcome);
        assert_eq!(
            block,
            "\n========== CODEX (12.3s) ==========\nthe answer",
        );
    }

    #[test]
    fn format_result_block_error() {
        let outcome = JurorOutcome {
            name: "gemini".into(),
            output: String::new(),
            elapsed_s: 0.5,
            error: Some("boom".into()),
        };
        let block = format_result_block(&outcome);
        assert_eq!(
            block,
            "\n========== GEMINI (0.5s) ==========\nERROR: boom",
        );
    }
}
