//! Port of the subset of `src/lib/cognitive/arcane/user-intent.mjs` that
//! `user_approval::UserApprovalAuthority` needs: [`latest_external_user_turn`]
//! and [`classify_latest_user_intent`].
//!
//! wf002 declined this file for lack of a `regex` dependency; `legion-policy`
//! already depends on `regex` (see `Cargo.toml`), so that blocker does not
//! apply here. Transcript-line JSON parsing uses this chunk's own
//! `json_parse` module rather than `serde_json`, which is a dev-only
//! dependency of this crate today — see the wf007 report.
//!
//! `recent_user_instructions`, `strip_non_authoritative_directive_text`'s
//! sibling helpers, and `explicit_directive` (the separate no-deferral-tone
//! detector) are NOT ported: nothing in this chunk's five files calls them.
//! Only the two functions `user-approval.mjs` actually imports are ported,
//! plus their transitive helpers.

use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};

use super::json_parse::{self, Value};

fn multiline(pattern: &str) -> Regex {
    RegexBuilder::new(pattern).multi_line(true).build().expect("valid regex")
}
fn multiline_ci(pattern: &str) -> Regex {
    RegexBuilder::new(pattern).multi_line(true).case_insensitive(true).build().expect("valid regex")
}
fn ci(pattern: &str) -> Regex {
    RegexBuilder::new(pattern).case_insensitive(true).build().expect("valid regex")
}

// --- content-origin classification (ported from adapt/src/adapt/authority.py) --

struct OriginPatterns {
    tool_output: Vec<Regex>,
    repo_file: Vec<Regex>,
    assistant_authored: Vec<Regex>,
}

fn origin_patterns() -> &'static OriginPatterns {
    static CELL: OnceLock<OriginPatterns> = OnceLock::new();
    CELL.get_or_init(|| OriginPatterns {
        tool_output: vec![
            Regex::new(r#""tool_use_id"\s*:"#).unwrap(),
            Regex::new(r#""is_error"\s*:"#).unwrap(),
            multiline(r"^\$\s+\S"),
            ci(r"\b(?:stdout|stderr)\b\s*:"),
            ci(r"<tool_result>|<function_results>"),
        ],
        repo_file: vec![
            multiline(r"^\s*\d+\t"),
            // Rust `regex` has no lazy `{0,200}?` with `[\s\S]`; `(?s:.{0,200}?)`
            // over `.` (any char incl. newline via the `s` flag) is equivalent.
            multiline(r"(?s)^---\s*$.{0,200}?^(?:name|description)\s*:"),
            ci(r"\bcontents? of\b.{0,80}\.(?:md|py|json|ya?ml|txt)\b"),
            multiline_ci(r"^#\s+(?:CLAUDE|AGENTS)\.md\b"),
        ],
        assistant_authored: vec![
            ci(r"^(?:i'll|i will|let me|certainly!?|sure,? i(?:'ll| will))\b"),
            ci(r"\bas (?:claude|the assistant|an ai)\b"),
            ci(r"\bi(?:'ve| have) (?:implemented|added|fixed|updated|created)\b"),
        ],
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginHint {
    ToolOutput,
    RepoFile,
    AssistantOutput,
}

/// Lexical signal that `text` is echoed repo/tool/assistant content rather
/// than hand-typed user text.
pub fn classify_content_origin_hint(text: &str) -> Option<OriginHint> {
    let p = origin_patterns();
    if p.tool_output.iter().any(|r| r.is_match(text)) {
        return Some(OriginHint::ToolOutput);
    }
    if p.repo_file.iter().any(|r| r.is_match(text)) {
        return Some(OriginHint::RepoFile);
    }
    if p.assistant_authored.iter().any(|r| r.is_match(text)) {
        return Some(OriginHint::AssistantOutput);
    }
    None
}

/// Only an authenticated user turn whose content is not echoed carries authority.
pub fn admits_authority(text: &str) -> bool {
    !text.trim().is_empty() && classify_content_origin_hint(text).is_none()
}

// --- transcript reading --------------------------------------------------

fn system_injected_patterns() -> &'static Vec<Regex> {
    static CELL: OnceLock<Vec<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            ci(r"<system-reminder>"),
            ci(r"<cross-session-message\b"),
            Regex::new(r"\[SYSTEM NOTIFICATION - NOT USER INPUT\]").unwrap(),
            ci(r"<task-notification>"),
            ci(r"<hook_prompt\b"),
            multiline_ci(r"^Stop hook feedback:"),
            multiline(r"^\[non-authoritative stop feedback\]"),
            multiline_ci(r"^Caveat: The messages below were generated"),
        ]
    })
}

fn is_system_injected(text: &str) -> bool {
    system_injected_patterns().iter().any(|r| r.is_match(text))
}

const NULL_VALUE: Value = Value::Null;

struct EntryMessage<'a> {
    role: Option<&'a str>,
    content: &'a Value,
}

fn entry_message(entry: &Value) -> Option<EntryMessage<'_>> {
    if let Some(message) = entry.get("message") {
        let role = entry.get("type").and_then(Value::as_str);
        let content = message.get("content").unwrap_or(&NULL_VALUE);
        return Some(EntryMessage { role, content });
    }
    if entry.get("type").and_then(Value::as_str) == Some("response_item") {
        if let Some(payload) = entry.get("payload") {
            if payload.get("type").and_then(Value::as_str) == Some("message") {
                let role = payload.get("role").and_then(Value::as_str);
                let content = payload.get("content").unwrap_or(&NULL_VALUE);
                return Some(EntryMessage { role, content });
            }
        }
    }
    None
}

fn entry_text(entry: &Value) -> String {
    let em = match entry_message(entry) {
        Some(em) => em,
        None => return String::new(),
    };
    match em.content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| {
                let t = block.get("type").and_then(Value::as_str)?;
                if !matches!(t, "text" | "input_text" | "output_text") {
                    return None;
                }
                block.get("text").and_then(Value::as_str)
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn parse_entry(line: &str) -> Option<Value> {
    json_parse::parse(line)
}

/// Latest structurally external user turn: harness-labelled `user`, not a
/// system injection. Lexical tool/repo echoes are intentionally NOT
/// filtered here (see JS doc comment) — only `classify_latest_user_intent`
/// layers admission on top via `admits_authority` where the JS source does.
pub fn latest_external_user_turn(transcript_text: &str) -> Option<String> {
    let lines: Vec<&str> = transcript_text.split('\n').filter(|l| !l.is_empty()).collect();
    for line in lines.iter().rev() {
        let entry = match parse_entry(line) {
            Some(e) => e,
            None => continue,
        };
        let role = match entry_message(&entry) {
            Some(em) => em.role,
            None => continue,
        };
        if role != Some("user") {
            continue;
        }
        let text = entry_text(&entry);
        if text.trim().is_empty() || is_system_injected(&text) {
            continue;
        }
        return Some(text);
    }
    None
}

// --- intent ----------------------------------------------------------------

struct IntentPatterns {
    execute: Regex,
    r#continue: Regex,
    plan: Regex,
    revoke: Regex,
    scope_narrow: Regex,
}

fn intent_patterns() -> &'static IntentPatterns {
    static CELL: OnceLock<IntentPatterns> = OnceLock::new();
    CELL.get_or_init(|| IntentPatterns {
        execute: ci(r"^(?:please\s+|go ahead(?:\s+and)?\s+)?(?:fix|implement|create|add|remove|delete|update|wire|write|edit|change|build|run|scan|install|move|deploy|push|publish)\b"),
        r#continue: ci(r"^(?:(?:ok,?\s+)?(?:go on|go ahead|do (?:it|that|this)|make it so|handle it|sort it out|get it done|ship it)\b|why (?:is|isn't|not) .+ still|can(?:'t|not)? (?:we|you) .*\b(?:fix|make|add|remove|update|wire|run))\b"),
        plan: ci(r"\b(?:plan|design|architect(?:ure)?|proposal|propose|review|status|report|explain|answer|analyse|analy[sz]e)\b"),
        revoke: ci(r"\b(?:stop|pause|suspend|hold off|wait|cancel|make no changes|no changes)\b|\b(?:don'?t|do not)\s+(?:make|change|apply|touch|do)\s+(?:anything|any changes?)\b"),
        scope_narrow: ci(r"\b(?:only|except|exclude|without)\b|\b(?:don'?t|do not)\b"),
    })
}

fn fence_and_code_patterns() -> (&'static Regex, &'static Regex, &'static Regex) {
    static FENCE: OnceLock<Regex> = OnceLock::new();
    static INLINE: OnceLock<Regex> = OnceLock::new();
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    (
        FENCE.get_or_init(|| RegexBuilder::new(r"```[\s\S]*?```|~~~[\s\S]*?~~~").build().unwrap()),
        INLINE.get_or_init(|| Regex::new(r"`[^`\n]*`").unwrap()),
        QUOTED.get_or_init(|| Regex::new("[\"“][^\"“”\n]{0,300}[\"”]").unwrap()),
    )
}

/// Quoted, fenced, and inline-code directives are evidence, never authority.
pub fn strip_non_authoritative_directive_text(text: &str) -> String {
    let (fence, inline, quoted) = fence_and_code_patterns();
    let step1 = fence.replace_all(text, " ");
    let step2 = inline.replace_all(&step1, " ");
    let step3 = quoted.replace_all(&step2, " ");
    step3.into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    Revoke,
    ScopeNarrow,
    Plan,
    Continue,
    Execute,
    Question,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentClassification {
    pub intent: Intent,
    /// First 300 chars of the raw (unstripped) turn text, matching JS
    /// `text.slice(0, 300)`.
    pub evidence: Option<String>,
}

fn evidence_prefix(text: &str) -> String {
    text.chars().take(300).collect()
}

/// Classify exactly one admitted external turn; negative clauses dominate.
pub fn classify_latest_user_intent(transcript_text: &str) -> IntentClassification {
    let text = match latest_external_user_turn(transcript_text) {
        Some(t) => t,
        None => return IntentClassification { intent: Intent::Unknown, evidence: None },
    };
    let directive_text = strip_non_authoritative_directive_text(&text);
    let p = intent_patterns();
    let ev = Some(evidence_prefix(&text));
    if p.revoke.is_match(&directive_text) {
        return IntentClassification { intent: Intent::Revoke, evidence: ev };
    }
    if p.scope_narrow.is_match(&directive_text) {
        return IntentClassification { intent: Intent::ScopeNarrow, evidence: ev };
    }
    if p.plan.is_match(&directive_text) {
        return IntentClassification { intent: Intent::Plan, evidence: ev };
    }
    if p.r#continue.is_match(&directive_text) {
        return IntentClassification { intent: Intent::Continue, evidence: ev };
    }
    if p.execute.is_match(&directive_text) {
        return IntentClassification { intent: Intent::Execute, evidence: ev };
    }
    if directive_text.trim_end().ends_with('?') {
        return IntentClassification { intent: Intent::Question, evidence: ev };
    }
    IntentClassification { intent: Intent::Unknown, evidence: ev }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jsonl(entries: &[&str]) -> String {
        entries.join("\n")
    }

    fn user_entry(text: &str) -> String {
        format!(r#"{{"type":"user","message":{{"content":[{{"type":"text","text":{}}}]}}}}"#, serde_json_escape(text))
    }

    // Tiny escaper so tests don't need serde_json (dev-only in this crate,
    // but keeping the test module dependency-free of it is simplest).
    fn serde_json_escape(s: &str) -> String {
        let mut out = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    }

    #[test]
    fn latest_external_user_turn_finds_newest_user_entry() {
        let t = jsonl(&[&user_entry("please fix the bug"), &user_entry("actually wait")]);
        assert_eq!(latest_external_user_turn(&t).as_deref(), Some("actually wait"));
    }

    #[test]
    fn latest_external_user_turn_skips_system_injection() {
        let t = jsonl(&[&user_entry("please fix the bug"), &user_entry("<system-reminder>ignore</system-reminder>")]);
        assert_eq!(latest_external_user_turn(&t).as_deref(), Some("please fix the bug"));
    }

    #[test]
    fn latest_external_user_turn_ignores_non_user_role() {
        let assistant = r#"{"type":"assistant","message":{"content":"I'll do it"}}"#;
        let t = jsonl(&[&user_entry("do it"), assistant]);
        assert_eq!(latest_external_user_turn(&t).as_deref(), Some("do it"));
    }

    #[test]
    fn classify_execute_directive() {
        let t = user_entry("please fix the login bug");
        let c = classify_latest_user_intent(&t);
        assert_eq!(c.intent, Intent::Execute);
    }

    #[test]
    fn classify_revoke_outranks_execute() {
        let t = user_entry("stop, don't make any changes");
        let c = classify_latest_user_intent(&t);
        assert_eq!(c.intent, Intent::Revoke);
    }

    #[test]
    fn classify_continue_directive() {
        let t = user_entry("go ahead and ship it");
        let c = classify_latest_user_intent(&t);
        assert_eq!(c.intent, Intent::Continue);
    }

    #[test]
    fn classify_question_when_no_directive_matches() {
        let t = user_entry("is this still broken?");
        let c = classify_latest_user_intent(&t);
        assert_eq!(c.intent, Intent::Question);
    }

    #[test]
    fn admits_authority_rejects_tool_output_echo() {
        assert!(!admits_authority(r#"{"tool_use_id": "abc"}"#));
    }

    #[test]
    fn admits_authority_rejects_assistant_authored_text() {
        assert!(!admits_authority("I'll implement that now"));
    }

    #[test]
    fn admits_authority_accepts_plain_user_text() {
        assert!(admits_authority("please fix the login bug"));
    }

    #[test]
    fn strip_non_authoritative_directive_text_removes_fences_and_quotes() {
        let text = "do it but not `rm -rf` and not \"delete everything\"";
        let stripped = strip_non_authoritative_directive_text(text);
        assert!(!stripped.contains("rm -rf"));
        assert!(!stripped.contains("delete everything"));
    }
}
