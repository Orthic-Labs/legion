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
//! **Ported (packet R61):**
//! - [`parse_args`] — the `argparse` flag parsing (`-i/--input`, `--only`,
//!   `--codex-model`, `--gemini-model`), including argparse's own
//!   `choices=[...]` rejection for `--only` and its "no such option"
//!   rejection for anything else.
//! - [`run`] — the full `main()` orchestration: reads the question (file via
//!   `-i`, else stdin), validates it via [`validate_question`], builds the
//!   selected jurors' [`SubprocessProvider`]s from [`codex_command_template`]
//!   / [`gemini_command_template`], calls each **sequentially** (stable/no
//!   extra crates means no thread pool here; output is unaffected since
//!   results are re-[`sort_results`]-ed by name before printing, matching
//!   the Python's `ThreadPoolExecutor` + `as_completed` + explicit sort),
//!   and prints each [`format_result_block`]. Errors from
//!   [`SubprocessProvider::call`] populate `JurorOutcome::error`, matching
//!   `call_juror`'s `except ProviderError as e: return name, "", elapsed,
//!   str(e)`.
//!
//! **Not ported:** reading `policy.toml` for `MACHINE_MINIMAL_DIRECTIVE` —
//! that file does not exist anywhere in this repository (only referenced by
//! this one Python module), so [`run`] takes the directive as a parameter;
//! callers load it from wherever `policy.toml` is provisioned, or pass
//! [`FALLBACK_DIRECTIVE`] as a last resort. `pyio.ensure_utf8_stdio()` is a
//! Windows-console-encoding workaround with no Rust equivalent needed —
//! `println!`/`print!` always write UTF-8 regardless of console code page.
//! Real parallelism (`ThreadPoolExecutor`) is intentionally not restored;
//! see above for why sequential execution is observably identical.

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

// ─── R61: argv parsing + run() orchestration ──────────────────────────────

use std::fs;
use std::io::{self, Read};
use std::time::Instant;

use super::subprocess_cli::{CommandRunner, SubprocessProvider, StdCommandRunner};

/// Directive to use when `policy.toml` (this repo has none) is not
/// available to a caller; documented as a last resort, not a silent
/// default masquerading as the real machine-minimal directive.
pub const FALLBACK_DIRECTIVE: &str = "Respond in machine-minimal key:value format. No prose.";

/// Parsed `argparse` flags, port of `ap.parse_args()`'s namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickAskArgs {
    pub input: Option<String>,
    pub only: JurorSelection,
    pub codex_model: String,
    pub gemini_model: String,
}

impl Default for QuickAskArgs {
    fn default() -> Self {
        Self {
            input: None,
            only: JurorSelection::Both,
            codex_model: DEFAULT_CODEX_MODEL.to_string(),
            gemini_model: DEFAULT_GEMINI_MODEL.to_string(),
        }
    }
}

/// Port of the `argparse.ArgumentParser` setup: `-i/--input`, `--only`
/// (restricted to `codex`/`gemini`/`both`), `--codex-model`,
/// `--gemini-model`. Returns `Err(message)` for an unknown flag or an
/// invalid `--only` choice, matching argparse's usage-error exit (this
/// port surfaces the message instead of calling `sys.exit(2)` directly, so
/// [`run`] controls the process exit code).
pub fn parse_args(args: &[String]) -> Result<QuickAskArgs, String> {
    let mut parsed = QuickAskArgs::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let mut take_value = |flag: &str| -> Result<String, String> {
            i += 1;
            args.get(i).cloned().ok_or_else(|| format!("argument {flag}: expected one argument"))
        };
        match arg.as_str() {
            "-i" | "--input" => parsed.input = Some(take_value("-i/--input")?),
            "--only" => {
                let value = take_value("--only")?;
                parsed.only = JurorSelection::parse(&value)
                    .ok_or_else(|| format!("argument --only: invalid choice: '{value}'"))?;
            }
            "--codex-model" => parsed.codex_model = take_value("--codex-model")?,
            "--gemini-model" => parsed.gemini_model = take_value("--gemini-model")?,
            other => return Err(format!("unrecognized arguments: {other}")),
        }
        i += 1;
    }
    Ok(parsed)
}

/// Port of `call_juror(name, provider, model, prompt)`: times the call,
/// maps a `ProviderError` to `JurorOutcome.error`, matching `except
/// ProviderError as e: return name, "", elapsed, str(e)`.
fn call_juror(
    runner: &dyn CommandRunner,
    name: &str,
    provider: &SubprocessProvider,
    model: &str,
    directive: &str,
    question: &str,
) -> JurorOutcome {
    let t0 = Instant::now();
    match provider.call(runner, model, directive, question, None) {
        Ok(out) => JurorOutcome { name: name.to_string(), output: out, elapsed_s: t0.elapsed().as_secs_f64(), error: None },
        Err(e) => JurorOutcome {
            name: name.to_string(),
            output: String::new(),
            elapsed_s: t0.elapsed().as_secs_f64(),
            error: Some(e.message),
        },
    }
}

/// Port of `main()`'s question-reading step: `-i FILE` reads that file
/// (UTF-8, matching `Path(args.input).read_text(encoding="utf-8")`), else
/// stdin is read to completion.
fn read_question(input: &Option<String>) -> io::Result<String> {
    match input {
        Some(path) => fs::read_to_string(path),
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
    }
}

/// Full port of `main()`, parameterized over the [`CommandRunner`] (spawn
/// boundary), the machine-minimal `directive` (see module docs — no
/// `policy.toml` exists in this repo), and `question` (already read from
/// `-i`/stdin by the caller via [`read_question`] in [`run`], or supplied
/// directly by a test). Returns the process exit code (`0` on success, `1`
/// on empty input, matching `sys.exit(1)`) and writes the formatted blocks
/// to `out`.
pub fn run_with(
    runner: &dyn CommandRunner,
    args: &QuickAskArgs,
    directive: &str,
    question: &str,
    out: &mut impl std::fmt::Write,
) -> i32 {
    if validate_question(question).is_err() {
        eprintln!("ERROR: empty input");
        return 1;
    }

    let jurors = selected_jurors(args.only);
    let mut results = Vec::with_capacity(jurors.len());
    for name in jurors {
        let (provider, model) = match name {
            "codex" => (
                SubprocessProvider::new("codex", codex_command_template(), Some(JUROR_TIMEOUT_S)),
                args.codex_model.as_str(),
            ),
            "gemini" => (
                SubprocessProvider::new("gemini", gemini_command_template(), Some(JUROR_TIMEOUT_S)),
                args.gemini_model.as_str(),
            ),
            _ => unreachable!("selected_jurors only returns \"codex\"/\"gemini\""),
        };
        results.push(call_juror(runner, name, &provider, model, directive, question));
    }

    for outcome in sort_results(results) {
        let _ = writeln!(out, "{}", format_result_block(&outcome));
    }
    0
}

/// CLI entrypoint: parses `args` (excluding argv\[0\]), reads the question
/// per [`read_question`], runs the real [`StdCommandRunner`] via
/// [`run_with`] with [`FALLBACK_DIRECTIVE`] (a caller that has
/// `policy.toml` available should read it and call [`run_with`] directly
/// instead), and prints the result blocks to stdout. Returns the process
/// exit code.
pub fn run(args: &[String]) -> i32 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("ERROR: {msg}");
            return 2;
        }
    };
    let question = match read_question(&parsed.input) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return 1;
        }
    };
    let mut buf = String::new();
    let code = run_with(&StdCommandRunner, &parsed, FALLBACK_DIRECTIVE, &question, &mut buf);
    print!("{buf}");
    code
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

    #[test]
    fn parse_args_defaults_when_empty() {
        let parsed = parse_args(&[]).unwrap();
        assert_eq!(parsed, QuickAskArgs::default());
    }

    #[test]
    fn parse_args_reads_all_flags() {
        let args: Vec<String> = [
            "-i", "q.txt", "--only", "gemini", "--codex-model", "gpt-x", "--gemini-model", "gem-y",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let parsed = parse_args(&args).unwrap();
        assert_eq!(parsed.input.as_deref(), Some("q.txt"));
        assert_eq!(parsed.only, JurorSelection::Gemini);
        assert_eq!(parsed.codex_model, "gpt-x");
        assert_eq!(parsed.gemini_model, "gem-y");
    }

    #[test]
    fn parse_args_rejects_invalid_only_choice() {
        let args: Vec<String> = ["--only", "bogus"].into_iter().map(String::from).collect();
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let args: Vec<String> = ["--nope".to_string()];
        assert!(parse_args(&args).is_err());
    }

    struct FakeRunner {
        by_argv0: std::collections::HashMap<String, Result<super::super::subprocess_cli::RunOutput, super::super::subprocess_cli::RunError>>,
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            cmd: &[String],
            _stdin: Option<&str>,
            _timeout_s: u64,
        ) -> Result<super::super::subprocess_cli::RunOutput, super::super::subprocess_cli::RunError> {
            let key = cmd.first().cloned().unwrap_or_default();
            self.by_argv0
                .get(&key)
                .cloned()
                .unwrap_or(Err(super::super::subprocess_cli::RunError::NotFound))
        }
    }

    #[test]
    fn run_with_empty_question_returns_exit_1() {
        let runner = FakeRunner { by_argv0: Default::default() };
        let mut out = String::new();
        let code = run_with(&runner, &QuickAskArgs::default(), FALLBACK_DIRECTIVE, "   ", &mut out);
        assert_eq!(code, 1);
        assert!(out.is_empty());
    }

    #[test]
    fn run_with_both_jurors_formats_sorted_blocks() {
        use super::super::subprocess_cli::RunOutput;
        let mut by_argv0 = std::collections::HashMap::new();
        by_argv0.insert(
            "codex".to_string(),
            Ok(RunOutput { stdout: "codex says hi".to_string(), stderr: String::new(), returncode: 0 }),
        );
        by_argv0.insert(
            "gemini".to_string(),
            Ok(RunOutput { stdout: "gemini says hi".to_string(), stderr: String::new(), returncode: 0 }),
        );
        let runner = FakeRunner { by_argv0 };
        let mut out = String::new();
        let code = run_with(&runner, &QuickAskArgs::default(), "DIRECTIVE", "what is up", &mut out);
        assert_eq!(code, 0);
        let codex_pos = out.find("CODEX").unwrap();
        let gemini_pos = out.find("GEMINI").unwrap();
        assert!(codex_pos < gemini_pos, "codex block should print before gemini (sorted by name)");
        assert!(out.contains("codex says hi"));
        assert!(out.contains("gemini says hi"));
    }

    #[test]
    fn run_with_only_codex_reports_provider_error() {
        use super::super::subprocess_cli::RunError;
        let mut by_argv0 = std::collections::HashMap::new();
        by_argv0.insert("codex".to_string(), Err(RunError::Timeout));
        let runner = FakeRunner { by_argv0 };
        let args = QuickAskArgs { only: JurorSelection::Codex, ..QuickAskArgs::default() };
        let mut out = String::new();
        let code = run_with(&runner, &args, "DIRECTIVE", "q", &mut out);
        assert_eq!(code, 0);
        assert!(out.contains("ERROR: codex/gpt-5.5 timeout after"));
        assert!(!out.contains("GEMINI"));
    }
}
