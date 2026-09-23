//! Ported from `src/lib/host/arcane/codex-escalation.mjs`.
//!
//! Absorbs `gate_codex_escalation.py`: the escalation ladder, enforced at the
//! point of escalation. Doctrine says resolve it yourself, then dispatch.
//! `codex exec` is the dispatch, so the gate asks for the "yourself" part in
//! evidence: two distinct attempts, each paired with what actually went
//! wrong. Prose intent is not evidence.
//!
//! The prompt is read from where the command actually carries it: an inline
//! quoted argument, a heredoc body, or a file piped in on stdin. A prompt
//! this gate cannot read is refused rather than waved through.

use regex::Regex;
use std::sync::LazyLock;

pub const REQUIRED_ATTEMPTS: u32 = 2;

static CODEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bcodex(?:\.exe)?\s+exec\b").unwrap());
// `python foo.py ... codex exec ...` is a script that MENTIONS codex, not an
// escalation: the interpreter owns the command line.
static INTERPRETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^\s*(?:py|python|python3|py\d|py\d\.\d+|node|nodejs|bash|sh|zsh|bun|tsx|deno|powershell|pwsh)(?:\.exe)?\b",
    )
    .unwrap()
});
static STDIN: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    [
        Regex::new(r"(?i)\|\s*codex(?:\.exe)?\s+exec\b").unwrap(),
        Regex::new(r"(?i)codex(?:\.exe)?\s+exec\b[^<]*<\s*\S").unwrap(),
        Regex::new(r"(?im)\bcodex(?:\.exe)?\s+exec\b[^|<>]*\s+-\s*$").unwrap(),
    ]
});
static FILES: LazyLock<[Regex; 2]> = LazyLock::new(|| {
    [
        Regex::new(r#"(?i)\b(?:cat|type|Get-Content)\s+([^\s|<>]+)\s*\|\s*codex(?:\.exe)?\s+exec\b"#).unwrap(),
        Regex::new(r"(?i)codex(?:\.exe)?\s+exec\b[^<]*<\s*([^\s|<>]+)").unwrap(),
    ]
});
static ATTEMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:tried|attempted|ran|launched|installed|pip\s+install|docker\s+run|executed|invoked|tested|reproduced)\b",
    )
    .unwrap()
});
static RESULT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:\bfailed\b|\berrors?\b|\bexception\b|\bcrashed?\b|\bhung\b|\bdidn'?t work\b|\b\w+Error\b|\b\w+Exception\b|\b(?:exit|return|rc)\s*(?:code\s*)?[1-9]\d*\b|\bdoesn'?t (?:exist|work|load|import|find)\b)",
    )
    .unwrap()
});

// The JS spec's heredoc pattern (`<<-?'?(\w+)'?\s*\n([\s\S]*?)\n\s*\1\s*$`)
// uses a `\1` backreference to the opening delimiter. Rust's `regex` crate
// has no backreference support (it can't be compiled), so the delimiter is
// captured with an opening-only regex and the matching closer is found with
// a second regex built from that captured word, which reproduces the same
// lazy "first line that is just the delimiter" behaviour.
static HEREDOC_OPEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)<<-?'?(\w+)'?\s*\n").unwrap());
static DQUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""((?:\\.|[^"\\])*)""#).unwrap());
static SQUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"'((?:\\.|[^'\\])*)'").unwrap());
static NOT_A_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:-|[A-Za-z]:[/\\]|/[a-z]+/|\.{1,2}/)").unwrap());

fn stronger_model(tier: &str) -> &'static str {
    match tier {
        "fast" => "balanced",
        "strong" => "strong",
        _ => "strong", // "balanced" and any unknown tier -> "strong"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationOutcome {
    pub escalated: bool,
    pub model_tier: String,
    pub executions: u32,
    pub workflow_artifact: bool,
    pub response_mode: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EscalationInput<'a> {
    pub uncertain: bool,
    pub current_tier: Option<&'a str>,
    pub prior_escalations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationRecursionError;

/// Port of `selectStrongerWorkingModel`. Throws (returns `Err`) with
/// `ARC_ESCALATION_RECURSION` when a route-uncertainty escalation was already
/// consumed once for this route.
pub fn select_stronger_working_model(
    input: EscalationInput,
) -> Result<EscalationOutcome, EscalationRecursionError> {
    let current_tier = input.current_tier.unwrap_or("balanced");
    if !input.uncertain {
        return Ok(EscalationOutcome {
            escalated: false,
            model_tier: current_tier.to_string(),
            executions: 0,
            workflow_artifact: false,
            response_mode: None,
        });
    }
    if input.prior_escalations != 0 {
        return Err(EscalationRecursionError);
    }
    Ok(EscalationOutcome {
        escalated: true,
        model_tier: stronger_model(current_tier).to_string(),
        executions: 1,
        workflow_artifact: false,
        response_mode: Some("DIRECT"),
    })
}

/// Count attempts that name a real outcome. An attempt verb only counts when
/// a failure appears within the next 120 characters, and two verbs closer
/// than 20 characters apart are one attempt described twice ("tried and
/// tested"). Offsets are byte offsets over the input, matching `.matchAll`
/// index semantics closely enough for ASCII/UTF-8 prompts.
pub fn evidence_count(prompt: &str) -> u32 {
    if prompt.is_empty() {
        return 0;
    }
    let mut count = 0u32;
    let mut last: i64 = -1000;
    for m in ATTEMPT.find_iter(prompt) {
        let idx = m.start() as i64;
        if idx - last < 20 {
            continue;
        }
        let end = (m.start() + 120).min(prompt.len());
        // clamp to a char boundary
        let mut end = end;
        while end < prompt.len() && !prompt.is_char_boundary(end) {
            end += 1;
        }
        if RESULT.is_match(&prompt[m.start()..end]) {
            count += 1;
            last = idx;
        }
    }
    count
}

/// Extracts a heredoc body from `command`, matching the JS spec's
/// `<<-?'?(\w+)'?\s*\n([\s\S]*?)\n\s*\1\s*$` (lazy body up to the first line
/// that is just the opening delimiter, optionally indented).
fn heredoc_body(command: &str) -> Option<String> {
    let open = HEREDOC_OPEN.captures(command)?;
    let delim = open.get(1)?.as_str();
    let body_start = open.get(0)?.end();
    let rest = &command[body_start..];
    let closer = Regex::new(&format!(r"(?m)^\s*{}\s*$", regex::escape(delim))).ok()?;
    let close_m = closer.find(rest)?;
    let mut body_end = close_m.start();
    if body_end > 0 && rest.as_bytes()[body_end - 1] == b'\n' {
        body_end -= 1;
    }
    Some(rest[..body_end].to_string())
}

/// The prompt body carried inline: a heredoc, else the longest quoted
/// string. Port of `promptArgument`.
pub fn prompt_argument(command: &str) -> String {
    let Some(m) = CODEX.find(command) else {
        return String::new();
    };
    if let Some(body) = heredoc_body(command) {
        return body;
    }
    let tail = &command[m.end()..];
    let mut longest = String::new();
    for cap in DQUOTED.captures_iter(tail).chain(SQUOTED.captures_iter(tail)) {
        let value = cap.get(1).map(|g| g.as_str()).unwrap_or("");
        if value.len() >= 50 && !NOT_A_PATH.is_match(value) && value.len() > longest.len() {
            longest = value.to_string();
        }
    }
    longest
}

/// The file a stdin-fed prompt comes from, if the command names one. Port of
/// `sourceFile`.
pub fn source_file(command: &str) -> String {
    for pattern in FILES.iter() {
        if let Some(cap) = pattern.captures(command) {
            let raw = cap.get(1).map(|g| g.as_str()).unwrap_or("");
            let trimmed = raw.trim_matches(|c| c == '\'' || c == '"');
            return trimmed.to_string();
        }
    }
    String::new()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationDenial {
    pub allowed: bool,
    pub evidence: Option<u32>,
    pub reason: Option<String>,
}

impl EscalationDenial {
    fn allow(evidence: Option<u32>) -> Self {
        Self { allowed: true, evidence, reason: None }
    }
    fn deny(evidence: Option<u32>, reason: String) -> Self {
        Self { allowed: false, evidence, reason: Some(reason) }
    }
}

/// Port of `evaluateCodexEscalation`. `read_source` resolves a stdin-fed
/// prompt (returns `None` when the source cannot be read).
pub fn evaluate_codex_escalation(
    command: &str,
    read_source: impl Fn(&str) -> Option<String>,
) -> EscalationDenial {
    if !CODEX.is_match(command) || INTERPRETER.is_match(command) {
        return EscalationDenial::allow(None);
    }
    let mut prompt = String::new();
    // Heredoc first, and deliberately AHEAD of the stdin check. `codex exec
    // <<'EOF'` matches the stdin patterns, but names no file, so the Python
    // original refused every heredoc as "unreadable source" — a false
    // refusal, since the prompt is sitting inline in the command.
    let heredoc = prompt_argument(command);
    if !heredoc.is_empty() {
        prompt = heredoc;
    } else if STDIN.iter().any(|p| p.is_match(command)) {
        match read_source(&source_file(command)) {
            Some(p) if !p.is_empty() => prompt = p,
            _ => {
                return EscalationDenial::deny(
                    None,
                    "BLOCKED [codex-escalation-gate]: stdin-fed prompt source could not be read for evidence verification; pass it inline with at least 2 tried-X/failed-Y logs.".to_string(),
                );
            }
        }
    }
    let found = evidence_count(&prompt);
    if found >= REQUIRED_ATTEMPTS {
        return EscalationDenial::allow(Some(found));
    }
    EscalationDenial::deny(
        Some(found),
        format!(
            "BLOCKED [codex-escalation-gate]: codex exec requires evidence of at least {REQUIRED_ATTEMPTS} self-attempts with actual failures in the prompt body. Found {found}. Document two specific attempted approaches and their errors, then re-spawn."
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_codex_command_is_allowed() {
        let r = evaluate_codex_escalation("ls -la", |_| None);
        assert_eq!(r, EscalationDenial::allow(None));
    }

    #[test]
    fn interpreter_mentioning_codex_is_allowed() {
        let r = evaluate_codex_escalation("python foo.py --run codex exec", |_| None);
        assert_eq!(r, EscalationDenial::allow(None));
    }

    #[test]
    fn inline_quoted_prompt_without_evidence_is_denied() {
        let r = evaluate_codex_escalation(
            "codex exec \"please just fix the bug in the parser module quickly for me today\"",
            |_| None,
        );
        assert!(!r.allowed);
        assert_eq!(r.evidence, Some(0));
    }

    #[test]
    fn inline_quoted_prompt_with_two_attempts_is_allowed() {
        // "errored" does not satisfy RESULT (`\berrors?\b` needs a word
        // boundary right after "error"/"errors", which "errored" lacks, and
        // it isn't a `\w+Error\b`/`\w+Exception\b` match either), confirmed
        // against the JS spec: `evidenceCount(...)` returns 1 for this
        // prompt, not 2. Use "errors out" so the second attempt names a
        // failure the RESULT pattern actually recognizes.
        let prompt = "I tried running the build and it failed with TypeError. I also attempted a clean install and it errors out with ENOENT.";
        let command = format!("codex exec \"{prompt}\"");
        let r = evaluate_codex_escalation(&command, |_| None);
        assert!(r.allowed);
        assert_eq!(r.evidence, Some(2));
    }

    #[test]
    fn heredoc_prompt_is_read_inline() {
        let command = "codex exec <<'EOF'\nI tried running pytest and it failed with AssertionError. I also attempted pip install and it errored with exit code 1.\nEOF";
        let r = evaluate_codex_escalation(command, |_| None);
        assert!(r.allowed);
        assert_eq!(r.evidence, Some(2));
    }

    #[test]
    fn stdin_fed_prompt_with_unreadable_source_is_denied() {
        let r = evaluate_codex_escalation("cat prompt.txt | codex exec", |_| None);
        assert!(!r.allowed);
        assert!(r.reason.unwrap().contains("stdin-fed prompt source"));
    }

    #[test]
    fn stdin_fed_prompt_reads_source_file() {
        let content = "I ran the tests and it failed with Error: boom. I tried again with docker run and it crashed.";
        let r = evaluate_codex_escalation("cat prompt.txt | codex exec", |path| {
            assert_eq!(path, "prompt.txt");
            Some(content.to_string())
        });
        assert!(r.allowed);
        assert_eq!(r.evidence, Some(2));
    }

    #[test]
    fn source_file_extracts_piped_filename() {
        assert_eq!(source_file("cat prompt.txt | codex exec"), "prompt.txt");
        // The capture group `[^\s|<>]+` stops at whitespace, so a quoted
        // path containing a space is only partially captured — confirmed
        // against the JS spec (`sourceFile("codex exec < 'my prompt.txt'")`
        // returns `"my"`, not the full quoted path).
        assert_eq!(source_file("codex exec < 'my prompt.txt'"), "my");
        assert_eq!(source_file("ls"), "");
    }

    #[test]
    fn prompt_argument_picks_longest_qualifying_quoted_string() {
        let command = r#"codex exec "short" "this is a much longer quoted string that clearly exceeds fifty characters""#;
        let arg = prompt_argument(command);
        assert!(arg.starts_with("this is a much longer"));
    }

    #[test]
    fn prompt_argument_ignores_flag_and_path_like_quotes() {
        let command = r#"codex exec "-some-flag-that-is-definitely-over-fifty-characters-long" "/abs/path/that/is/also/over/fifty/characters/long/x""#;
        assert_eq!(prompt_argument(command), "");
    }

    #[test]
    fn select_stronger_working_model_not_uncertain() {
        let out = select_stronger_working_model(EscalationInput {
            uncertain: false,
            current_tier: Some("fast"),
            prior_escalations: 0,
        })
        .unwrap();
        assert!(!out.escalated);
        assert_eq!(out.model_tier, "fast");
        assert_eq!(out.executions, 0);
    }

    #[test]
    fn select_stronger_working_model_escalates_once() {
        let out = select_stronger_working_model(EscalationInput {
            uncertain: true,
            current_tier: Some("fast"),
            prior_escalations: 0,
        })
        .unwrap();
        assert!(out.escalated);
        assert_eq!(out.model_tier, "balanced");
        assert_eq!(out.executions, 1);
        assert_eq!(out.response_mode, Some("DIRECT"));
    }

    #[test]
    fn select_stronger_working_model_rejects_recursion() {
        let err = select_stronger_working_model(EscalationInput {
            uncertain: true,
            current_tier: Some("balanced"),
            prior_escalations: 1,
        });
        assert_eq!(err, Err(EscalationRecursionError));
    }

    #[test]
    fn evidence_count_requires_result_within_120_chars() {
        let far = format!("I tried something. {}", "x".repeat(200) + "failed");
        assert_eq!(evidence_count(&far), 0);
    }

    #[test]
    fn evidence_count_collapses_adjacent_verbs() {
        // "tried and tested" within 20 chars of each other -> one attempt.
        let prompt = "I tried and tested it and it failed with an error.";
        assert_eq!(evidence_count(prompt), 1);
    }
}
