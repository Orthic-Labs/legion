//! Search before filing (Orthic-Labs/legion#136, part 1). Check id
//! `issue-search`, PreToolUse of a shell tool.
//!
//! `gh issue create` (and `gh api .../issues` with a POST) is denied unless the
//! command, or the `--body-file` it names, carries a line of the form
//!
//! ```text
//! Checked: #12, #34 (search "terms")
//! Checked: none found (search "terms")
//! ```
//!
//! so an agent searches existing issues before it files a new one. The label
//! and contract-state parts of #136 are not enforced here.
//!
//! The check reads the whole command text rather than only a parsed `--body`,
//! so heredocs and quoting cannot hide the line. It fails open: a command it
//! cannot parse, a body file it cannot read, or a body piped from stdin
//! allows the call.

use std::{fs, io::Read, path::PathBuf};

use serde_json::{Map, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::skills_gate::{check_disabled, str_field, tool_input, tool_name};

pub const CHECK: &str = "issue-search";

const SHELL_TOOLS: [&str; 4] = ["Bash", "exec_command", "shell", "local_shell"];
const MAX_BODY_FILE_BYTES: u64 = 256 * 1024;

// ---------------------------------------------------------------------------
// Shell lexing (just enough to find `gh` invocations)
// ---------------------------------------------------------------------------

struct Lexer {
    segments: Vec<Vec<String>>,
    tokens: Vec<String>,
    current: String,
    in_word: bool,
}

impl Lexer {
    fn flush_word(&mut self) {
        if self.in_word {
            self.tokens.push(std::mem::take(&mut self.current));
            self.in_word = false;
        }
    }

    fn end_segment(&mut self) {
        self.flush_word();
        if !self.tokens.is_empty() {
            self.segments.push(std::mem::take(&mut self.tokens));
        }
    }
}

/// Split a shell command into simple commands (segments) of words. Quotes
/// group words, `;` `&` `|` `(` `)` backticks and newlines end a segment, and
/// heredoc bodies are skipped, so `gh issue create` inside a quoted string or
/// a heredoc is not mistaken for a call.
fn shell_segments(command: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = command.chars().collect();
    let mut lexer = Lexer {
        segments: Vec::new(),
        tokens: Vec::new(),
        current: String::new(),
        in_word: false,
    };
    let mut heredocs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' => {
                lexer.in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    lexer.current.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                lexer.in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\'
                        && i + 1 < chars.len()
                        && matches!(chars[i + 1], '"' | '\\' | '$' | '`')
                    {
                        lexer.current.push(chars[i + 1]);
                        i += 2;
                    } else {
                        lexer.current.push(chars[i]);
                        i += 1;
                    }
                }
                i += 1;
            }
            '\\' => {
                if i + 1 < chars.len() && chars[i + 1] != '\n' {
                    lexer.current.push(chars[i + 1]);
                    lexer.in_word = true;
                }
                i += 2;
            }
            ' ' | '\t' | '\r' => {
                lexer.flush_word();
                i += 1;
            }
            '\n' => {
                lexer.end_segment();
                i += 1;
                for delimiter in std::mem::take(&mut heredocs) {
                    while i < chars.len() {
                        let start = i;
                        while i < chars.len() && chars[i] != '\n' {
                            i += 1;
                        }
                        let line: String = chars[start..i].iter().collect();
                        i = (i + 1).min(chars.len());
                        if line.trim() == delimiter {
                            break;
                        }
                    }
                }
            }
            ';' | '|' | '&' | '(' | ')' | '`' => {
                lexer.end_segment();
                i += 1;
            }
            '<' if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') => {
                lexer.flush_word();
                i += 2;
                if chars.get(i) == Some(&'-') {
                    i += 1;
                }
                while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                    i += 1;
                }
                let mut delimiter = String::new();
                while i < chars.len() && !chars[i].is_whitespace() && !";|&()<>".contains(chars[i])
                {
                    if !matches!(chars[i], '\'' | '"' | '\\') {
                        delimiter.push(chars[i]);
                    }
                    i += 1;
                }
                if !delimiter.is_empty() {
                    heredocs.push(delimiter);
                }
            }
            '#' if !lexer.in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            _ => {
                lexer.current.push(c);
                lexer.in_word = true;
                i += 1;
            }
        }
    }
    lexer.end_segment();
    lexer.segments
}

// ---------------------------------------------------------------------------
// Finding an issue-creating `gh` call
// ---------------------------------------------------------------------------

/// One detected `gh issue create` / `gh api .../issues` POST.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct IssueCreate {
    repo: Option<String>,
    body_files: Vec<String>,
}

const WRAPPERS: &[&str] = &["sudo", "command", "env", "time", "exec", "nohup", "builtin"];

/// Flags whose value is the next word (when not written `--flag=value`).
const VALUE_FLAGS: &[&str] = &[
    "R",
    "repo",
    "t",
    "title",
    "b",
    "body",
    "F",
    "body-file",
    "l",
    "label",
    "a",
    "assignee",
    "m",
    "milestone",
    "p",
    "project",
    "T",
    "template",
    "X",
    "method",
    "f",
    "field",
    "raw-field",
    "H",
    "header",
    "q",
    "jq",
    "hostname",
    "cache",
];

fn is_env_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn is_gh_program(word: &str) -> bool {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    base == "gh" || base == "gh.exe"
}

/// `repos/<owner>/<repo>/issues` (also with a leading slash or a query).
fn issue_collection_repo(endpoint: &str) -> Option<String> {
    let path = endpoint.split('?').next().unwrap_or(endpoint);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() == 4 && parts[0] == "repos" && parts[3] == "issues" {
        Some(format!("{}/{}", parts[1], parts[2]))
    } else {
        None
    }
}

/// Parse the arguments after `gh`. `None` when this is not an issue create.
fn parse_gh(args: &[String]) -> Option<IssueCreate> {
    let mut positionals: Vec<&str> = Vec::new();
    let mut repo: Option<String> = None;
    let mut method: Option<String> = None;
    let mut has_fields = false;
    let mut help = false;
    let mut body_files: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;
        if arg == "--" {
            positionals.extend(args[index..].iter().map(String::as_str));
            break;
        }
        let (name, inline): (&str, Option<String>) = if let Some(long) = arg.strip_prefix("--") {
            match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (long, None),
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            let flags = &arg[1..];
            let first_len = flags.chars().next().map(char::len_utf8).unwrap_or(0);
            let (short, rest) = flags.split_at(first_len);
            if rest.is_empty() {
                (short, None)
            } else {
                (short, Some(rest.trim_start_matches('=').to_owned()))
            }
        } else {
            positionals.push(arg);
            continue;
        };
        if matches!(name, "help" | "h") {
            help = true;
            continue;
        }
        let takes_value = VALUE_FLAGS.contains(&name) || name == "input";
        let value = if takes_value {
            match inline {
                Some(value) => Some(value),
                None => {
                    let next = args.get(index).cloned();
                    if next.is_some() {
                        index += 1;
                    }
                    next
                }
            }
        } else {
            None
        };
        let is_api = positionals.first() == Some(&"api");
        match (name, value) {
            ("R" | "repo", Some(value)) => repo = Some(value),
            ("X" | "method", Some(value)) => method = Some(value.to_ascii_uppercase()),
            ("body-file", Some(value)) => body_files.push(value),
            ("F", Some(value)) if !is_api => body_files.push(value),
            ("F" | "f" | "field" | "raw-field", Some(value)) if is_api => {
                has_fields = true;
                if let Some(path) = value.strip_prefix("body=@") {
                    body_files.push(path.to_owned());
                }
            }
            ("input", Some(value)) => {
                has_fields = true;
                body_files.push(value);
            }
            _ => {}
        }
    }
    if help {
        return None;
    }
    match positionals.as_slice() {
        ["issue", "create", ..] => Some(IssueCreate { repo, body_files }),
        ["api", endpoint, ..] => {
            let endpoint_repo = issue_collection_repo(endpoint)?;
            let is_post = match method.as_deref() {
                Some(method) => method == "POST",
                None => has_fields,
            };
            is_post.then(|| IssueCreate {
                repo: repo.or(Some(endpoint_repo)),
                body_files,
            })
        }
        _ => None,
    }
}

/// Every issue-creating `gh` call in `command`.
fn find_issue_creates(command: &str) -> Vec<IssueCreate> {
    let mut found = Vec::new();
    for segment in shell_segments(command) {
        let mut start = 0;
        while start < segment.len()
            && (is_env_assignment(&segment[start]) || WRAPPERS.contains(&segment[start].as_str()))
        {
            start += 1;
        }
        let Some(program) = segment.get(start) else {
            continue;
        };
        if !is_gh_program(program) {
            continue;
        }
        if let Some(call) = parse_gh(&segment[start + 1..]) {
            found.push(call);
        }
    }
    found
}

// ---------------------------------------------------------------------------
// The `Checked:` line
// ---------------------------------------------------------------------------

fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len()
        && text.is_char_boundary(prefix.len())
        && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn is_quote(c: char) -> bool {
    matches!(
        c,
        '"' | '\'' | '\u{201c}' | '\u{201d}' | '\u{2018}' | '\u{2019}'
    )
}

/// `#12`, `repo#12`, `owner/repo#12`, or an `.../issues/12` URL.
fn is_issue_ref(token: &str) -> bool {
    let token = token.trim_matches(|c: char| c == '*' || c == '`');
    let digits = token
        .rsplit_once('#')
        .map(|(_, digits)| digits)
        .or_else(|| token.rsplit_once("/issues/").map(|(_, digits)| digits));
    digits.is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
}

/// `(search "terms")` with non-empty terms, closed by `)`.
fn search_clause_ok(rest: &str) -> bool {
    let rest = rest.trim_start();
    if !starts_with_ci(rest, "(search") {
        return false;
    }
    let after = rest["(search".len()..].trim_start();
    let Some(open) = after.chars().next().filter(|c| is_quote(*c)) else {
        return false;
    };
    let body_start = open.len_utf8();
    let Some(close_rel) = after[body_start..].find(is_quote) else {
        return false;
    };
    let terms = &after[body_start..body_start + close_rel];
    if !terms.chars().any(|c| c.is_alphanumeric()) {
        return false;
    }
    let close_idx = body_start + close_rel;
    let close_len = after[close_idx..]
        .chars()
        .next()
        .map(char::len_utf8)
        .unwrap_or(1);
    after[close_idx + close_len..].trim_start().starts_with(')')
}

/// What follows `Checked:`: `#n[, #n...] (search "t")` or
/// `none found (search "t")`.
fn checked_tail_ok(tail: &str) -> bool {
    let mut rest = tail.trim_start();
    if starts_with_ci(rest, "none found") {
        rest = &rest["none found".len()..];
    } else {
        let mut count = 0;
        loop {
            rest = rest.trim_start();
            let end = rest
                .find(|c: char| c == ',' || c == '(' || c.is_whitespace())
                .unwrap_or(rest.len());
            if !is_issue_ref(&rest[..end]) {
                break;
            }
            count += 1;
            rest = rest[end..].trim_start();
            match rest.strip_prefix(',') {
                Some(after) => rest = after,
                None => break,
            }
        }
        if count == 0 {
            return false;
        }
    }
    search_clause_ok(rest)
}

/// Does any line of `text` carry a valid `Checked:` clause?
fn has_checked_line(text: &str) -> bool {
    let unescaped = text.replace("\\\"", "\"");
    unescaped.lines().any(|line| {
        let lowered = line.to_ascii_lowercase();
        lowered
            .match_indices("checked:")
            .any(|(index, marker)| checked_tail_ok(&line[index + marker.len()..]))
    })
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

fn denial_message(repo: Option<&str>) -> String {
    format!(
        "Search first: gh issue list -R {} --search '<terms>' --state all; then add a 'Checked:' line naming what you found. Line format: Checked: #12, #34 (search \"terms\") or Checked: none found (search \"terms\").",
        repo.unwrap_or("<repo>")
    )
}

/// The denial message when `command` files an issue without a `Checked:`
/// line, else `None`. `read_body_file` returns a body file's text, or `None`
/// when it cannot be read (then the call is allowed unless the command text
/// itself already fails the check and no body file is in play).
fn evaluate(command: &str, read_body_file: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let creates = find_issue_creates(command);
    if creates.is_empty() {
        return None;
    }
    let mut haystack = command.to_owned();
    let mut unverifiable = false;
    for create in &creates {
        for file in &create.body_files {
            if file == "-" {
                unverifiable = true;
            } else if let Some(text) = read_body_file(file) {
                haystack.push('\n');
                haystack.push_str(&text);
            } else {
                unverifiable = true;
            }
        }
    }
    if has_checked_line(&haystack) || unverifiable {
        return None;
    }
    let repo = creates.iter().find_map(|create| create.repo.as_deref());
    Some(denial_message(repo))
}

fn command_strings(input: &Map<String, Value>) -> Vec<String> {
    for key in ["command", "cmd"] {
        match input.get(key) {
            Some(Value::String(text)) => return vec![text.clone()],
            Some(Value::Array(parts)) => {
                let words: Vec<&str> = parts.iter().filter_map(Value::as_str).collect();
                if words.is_empty() {
                    continue;
                }
                // `["bash", "-lc", "gh issue create ..."]`: check the argv
                // joined and each element that is itself a command line.
                let mut out = vec![words.join(" ")];
                out.extend(
                    words
                        .iter()
                        .filter(|word| word.contains(char::is_whitespace))
                        .map(|word| (*word).to_owned()),
                );
                return out;
            }
            _ => {}
        }
    }
    Vec::new()
}

fn read_body_file(cwd: Option<&str>, file: &str) -> Option<String> {
    let mut path = PathBuf::from(file);
    if path.is_relative() {
        path = PathBuf::from(cwd?).join(path);
    }
    let handle = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    handle
        .take(MAX_BODY_FILE_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// PreToolUse of a shell tool: deny `gh issue create` without a `Checked:`
/// line (`ARC_ISSUE_SEARCH_FIRST`). Returns `None` to allow.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if check_disabled(CHECK) || !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = tool_name(payload)?;
    if !SHELL_TOOLS.contains(&tool.as_str()) {
        return None;
    }
    let commands = command_strings(tool_input(payload)?);
    let cwd = str_field(payload, &["cwd", "workdir"]);
    let reader = |file: &str| read_body_file(cwd.as_deref(), file);
    let message = commands
        .iter()
        .find_map(|command| evaluate(command, &reader))?;
    Some(HookResponse::denied(
        request.event_type.clone(),
        "ARC_ISSUE_SEARCH_FIRST",
        message,
        "strong",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn no_files(_: &str) -> Option<String> {
        None
    }

    fn denied(command: &str) -> Option<String> {
        evaluate(command, &no_files)
    }

    fn request(command: &str) -> HookRequest {
        HookRequest {
            schema_version: crate::protocol::SCHEMA_VERSION,
            kind: crate::protocol::REQUEST_KIND.to_owned(),
            event_type: "PreToolUse".to_owned(),
            payload: json!({
                "session_id": "s1",
                "tool_name": "Bash",
                "tool_input": {"command": command}
            }),
        }
    }

    #[test]
    fn checked_line_accepts_the_two_forms() {
        assert!(has_checked_line(
            r#"Checked: #12, #34 (search "broker cold start")"#
        ));
        assert!(has_checked_line(
            r#"Checked: none found (search "hook gate")"#
        ));
        assert!(has_checked_line(
            "Body\n\n- Checked: #7 (search 'x y')\nmore"
        ));
        assert!(has_checked_line(
            r#"Checked: rustright#129, Orthic-Labs/legion#136 (search "pretool")"#
        ));
        assert!(has_checked_line(
            "checked: NONE FOUND (search “smart quotes”)"
        ));
        // Escaped quotes inside a double-quoted shell string.
        assert!(has_checked_line(r#"--body "Checked: #1 (search \"a b\")""#));
    }

    #[test]
    fn checked_line_rejects_incomplete_clauses() {
        assert!(!has_checked_line("Checked: #12"));
        assert!(!has_checked_line("Checked: none found"));
        assert!(!has_checked_line(r#"Checked: (search "x")"#));
        assert!(!has_checked_line(r#"Checked: #abc (search "x")"#));
        assert!(!has_checked_line(r#"Checked: none found (search "")"#));
        assert!(!has_checked_line(r#"Checked: none found (search "x""#));
        assert!(!has_checked_line("I checked: nothing"));
        assert!(!has_checked_line(""));
    }

    #[test]
    fn issue_create_without_a_checked_line_is_denied_with_the_search_hint() {
        let message = denied(r#"gh issue create -R Orthic-Labs/legion --title "x" --body "y""#)
            .expect("deny");
        assert!(message.starts_with(
            "Search first: gh issue list -R Orthic-Labs/legion --search '<terms>' --state all;"
        ));
        assert!(message.contains("'Checked:' line"));
        let message = denied("gh issue create --title x").expect("deny");
        assert!(message.contains("-R <repo>"));
    }

    #[test]
    fn issue_create_with_a_checked_line_is_allowed() {
        assert!(denied(
            r#"gh issue create --title x --body "Details.

Checked: none found (search \"hook gate\")""#
        )
        .is_none());
        let heredoc = "gh issue create --title x --body \"$(cat <<'EOF'\nBody\nChecked: #3 (search \"a\")\nEOF\n)\"";
        assert!(denied(heredoc).is_none());
        let stdin = "gh issue create --title x --body-file - <<'EOF'\nBody\nChecked: #3 (search \"a\")\nEOF";
        assert!(denied(stdin).is_none());
    }

    #[test]
    fn body_file_contents_are_checked() {
        let command = "gh issue create --title x --body-file /tmp/body.md";
        let with_line = |_: &str| Some("Checked: #5 (search \"x\")\n".to_owned());
        let without_line = |_: &str| Some("no marker here".to_owned());
        assert!(evaluate(command, &with_line).is_none());
        assert!(evaluate(command, &without_line).is_some());
        // Unreadable file and stdin bodies cannot be verified: allow.
        assert!(evaluate(command, &no_files).is_none());
        assert!(denied("cat b.md | gh issue create --title x -F -").is_none());
    }

    #[test]
    fn gh_api_issue_posts_are_covered() {
        assert!(denied("gh api repos/o/r/issues -f title=x -f body=y").is_some());
        assert!(denied("gh api -X POST /repos/o/r/issues --input payload.json").is_none());
        assert!(denied("gh api repos/o/r/issues -X POST -f title=x").is_some());
        let message = denied("gh api repos/o/r/issues -f title=x").expect("deny");
        assert!(message.contains("-R o/r"));
        // Reads and other endpoints are not issue creation.
        assert!(denied("gh api repos/o/r/issues").is_none());
        assert!(denied("gh api repos/o/r/issues -X GET").is_none());
        assert!(denied("gh api repos/o/r/issues/12/comments -f body=x").is_none());
        assert!(
            denied(r#"gh api repos/o/r/issues -f body="Checked: #1 (search \"x\")""#).is_none()
        );
    }

    #[test]
    fn unrelated_and_quoted_mentions_are_not_calls() {
        for command in [
            "gh issue list -R o/r --search x",
            "gh issue create --help",
            "gh pr create --title x",
            r#"echo "gh issue create --title x""#,
            r#"git commit -m "document gh issue create""#,
            "grep -rn 'gh issue create' docs",
            "cat <<'EOF' > note.md\ngh issue create --title x\nEOF",
            "ls",
        ] {
            assert!(denied(command).is_none(), "{command}");
        }
    }

    #[test]
    fn wrappers_pipelines_and_global_flags_are_seen() {
        for command in [
            "cd repo && gh issue create --title x",
            "GH_TOKEN=abc gh issue create --title x",
            "sudo gh -R o/r issue create --title x",
            "echo hi; gh issue create --title x | cat",
            "gh --repo o/r issue create -t x -b y",
            "/opt/homebrew/bin/gh issue create -t x",
        ] {
            assert!(denied(command).is_some(), "{command}");
        }
    }

    #[test]
    fn pre_tool_wires_the_decision_to_a_denial() {
        let response = pre_tool(&request("gh issue create -t x -b y")).expect("deny");
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some("ARC_ISSUE_SEARCH_FIRST"));
        let ok = request(r#"gh issue create -t x -b "Checked: none found (search \"x\")""#);
        assert!(pre_tool(&ok).is_none());
        assert!(pre_tool(&request("cargo build")).is_none());
        let other_tool = HookRequest {
            payload: json!({"session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": "x"}}),
            ..request("")
        };
        assert!(pre_tool(&other_tool).is_none());
    }

    #[test]
    fn array_commands_are_unwrapped() {
        let strings = command_strings(
            json!({"command": ["bash", "-lc", "gh issue create -t x"]})
                .as_object()
                .expect("object"),
        );
        assert!(strings.iter().any(|s| denied(s).is_some()));
    }
}
