//! Port of `src/lib/review/packet.py`.
//!
//! Jury packet contract — structural lint + skeleton. Pure, network-free
//! validator: no model calls, no I/O beyond the CLI wrapper (not ported —
//! this crate exposes the library surface only). Faithfully mirrors the
//! Python section rules, bullet-counting, constraint-cite heuristic,
//! `sole_viable` escape hatch, and skeleton template.

use std::collections::BTreeMap;

/// Required packet sections, in the Python's declared order.
pub const PACKET_REQUIRED_SECTIONS: &[&str] = &[
    "ARTIFACT",
    "SUCCESS_CRITERIA",
    "NON_GOALS",
    "CONSTRAINTS",
    "ALTERNATIVES_CONSIDERED",
    "KNOWN_WEAKNESSES",
    "USER_INTENTION",
    "OMISSIONS",
];

/// Severity for a missing required section: `true` == hard error, `false` == warn.
fn section_is_error(name: &str) -> bool {
    !matches!(name, "CONSTRAINTS" | "USER_INTENTION" | "OMISSIONS")
}

/// Sentinel error string used when the input text carries no ```packet fence.
pub const NO_PACKET_FENCE: &str = "no_packet_fence";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketValidation {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub sections: BTreeMap<String, String>,
}

impl PacketValidation {
    /// True when the input carried NO packet fence at all — the marked
    /// legacy path (a disclosure, not a hard failure).
    pub fn is_legacy_no_packet(&self) -> bool {
        self.errors.len() == 1 && self.errors[0] == NO_PACKET_FENCE
    }
}

/// Find the first ```packet ... ``` fence and parse its body into
/// {SECTION_NAME: text}. Returns `None` if no fence is present.
///
/// Section headers inside the fence are lines of the form
/// `UPPER_CASE_NAME:` with no leading whitespace; everything until the
/// next header (or EOF) is that section's body, trimmed of surrounding
/// blank lines exactly as the Python's `"\n".join(buf).strip("\n")` does.
pub fn extract_packet(text: &str) -> Option<BTreeMap<String, String>> {
    let start_marker = "```packet";
    let start_idx = text.find(start_marker)?;
    let after_marker = &text[start_idx + start_marker.len()..];
    // Python's regex requires `\s*\n` after the fence tag, then `.*?\n```` (DOTALL).
    let nl_idx = after_marker.find('\n')?;
    let between = &after_marker[..nl_idx];
    if !between.trim().is_empty() {
        // characters other than whitespace before the newline: not a match
        return None;
    }
    let body_start = &after_marker[nl_idx + 1..];
    let end_idx = body_start.find("\n```")?;
    let body = &body_start[..end_idx];
    Some(parse_fence_body(body))
}

fn parse_fence_body(body: &str) -> BTreeMap<String, String> {
    let mut sections: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut buf: Vec<String> = Vec::new();

    for raw_line in body.split('\n') {
        let line = raw_line.trim_end();
        if let Some((name, tail)) = match_section_header(line) {
            if let Some(cur) = current.take() {
                sections.insert(cur, join_strip(&buf));
            }
            current = Some(name);
            buf.clear();
            if !tail.is_empty() {
                buf.push(tail);
            }
            continue;
        }
        if current.is_some() {
            buf.push(raw_line.to_string());
        }
    }
    if let Some(cur) = current.take() {
        sections.insert(cur, join_strip(&buf));
    }
    sections
}

fn join_strip(buf: &[String]) -> String {
    let joined = buf.join("\n");
    joined.trim_matches('\n').to_string()
}

/// `^([A-Z][A-Z0-9_]*)\s*:\s*(.*)$`, only matched when the line does not
/// start with a space or tab (mirrors `not line.startswith((" ", "\t"))`).
fn match_section_header(line: &str) -> Option<(String, String)> {
    if line.starts_with(' ') || line.starts_with('\t') {
        return None;
    }
    let mut chars = line.char_indices();
    let (_, first) = chars.next()?;
    if !first.is_ascii_uppercase() {
        return None;
    }
    let mut end = first.len_utf8();
    for (i, c) in chars {
        if c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' {
            end = i + c.len_utf8();
            continue;
        }
        break;
    }
    let name = &line[..end];
    let rest = &line[end..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?;
    let tail = rest.trim_start().to_string();
    Some((name.to_string(), tail))
}

/// Faithful `^\s*[-*]\s+` bullet-line matcher.
fn matches_bullet_re(line: &str) -> bool {
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c == ' ' || c == '\t' {
            chars.next();
        } else {
            break;
        }
    }
    let marker = chars.next();
    if marker != Some('-') && marker != Some('*') {
        return false;
    }
    let mut saw_ws = false;
    for c in chars {
        if c == ' ' || c == '\t' {
            saw_ws = true;
        } else {
            break;
        }
    }
    saw_ws
}

/// Count list bullets, stripping fenced code blocks first (non-greedy
/// ```` ```...``` ```` spans) so fenced code doesn't count.
fn bullet_count(text: &str) -> usize {
    let cleaned = strip_code_fences(text);
    cleaned.lines().filter(|l| matches_bullet_re(l)).count()
}

fn strip_code_fences(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    loop {
        match rest.find("```") {
            Some(start) => {
                out.push_str(&rest[..start]);
                let after = &rest[start + 3..];
                match after.find("```") {
                    Some(end) => {
                        rest = &after[end + 3..];
                    }
                    None => {
                        // unterminated fence: Python's DOTALL regex requires a
                        // closing ```; without one nothing is stripped here.
                        out.push_str("```");
                        out.push_str(after);
                        rest = "";
                    }
                }
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }
    out
}

/// `^file:\S+:\d+\b|^[A-Za-z][^:]*:[^:]+|^:[^:]+` — cite heuristic.
fn matches_cite_re(content: &str) -> bool {
    if matches_file_line_cite(content) {
        return true;
    }
    if matches_topic_cite(content) {
        return true;
    }
    // `^:[^:]+` — leading ':' followed by a non-empty run without ':'.
    content
        .strip_prefix(':')
        .map(|rest| !rest.is_empty() && !rest.starts_with(':'))
        .unwrap_or(false)
}

fn matches_file_line_cite(content: &str) -> bool {
    let Some(rest) = content.strip_prefix("file:") else {
        return false;
    };
    // \S+:\d+\b requires the whole match to lie within a single
    // whitespace-delimited token (since \S+ cannot cross whitespace), so
    // only the first token after "file:" is a candidate.
    let token = rest.split_whitespace().next().unwrap_or("");
    if token.is_empty() {
        return false;
    }
    let bytes = token.as_bytes();
    // Need at least one char before the final ':' for \S+ to match
    // (it requires 1+ chars), then 1+ digits, then a word boundary.
    for i in 1..token.len() {
        if bytes[i] != b':' {
            continue;
        }
        let mut j = i + 1;
        let digit_start = j;
        while j < token.len() && token.as_bytes()[j].is_ascii_digit() {
            j += 1;
        }
        if j == digit_start {
            continue;
        }
        let boundary_ok = j == token.len()
            || !(token.as_bytes()[j] as char).is_alphanumeric() && token.as_bytes()[j] != b'_';
        if boundary_ok {
            return true;
        }
    }
    false
}

fn matches_topic_cite(content: &str) -> bool {
    let Some(first) = content.chars().next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    // `^[A-Za-z][^:]*:[^:]+` — first ':' found by `find` is where `[^:]*`
    // ends (it cannot itself contain ':'), so the first match is decisive.
    match content.find(':') {
        Some(idx) => content[idx + 1..]
            .chars()
            .next()
            .map(|c| c != ':')
            .unwrap_or(false),
        None => false,
    }
}

/// `sole_viable\s*:` anywhere in the text (case-insensitive).
fn has_sole_viable_marker(text: &str) -> bool {
    let lower = text.to_lowercase();
    let needle = "sole_viable";
    let mut search_from = 0usize;
    while let Some(pos) = lower[search_from..].find(needle) {
        let abs = search_from + pos;
        let after = &lower[abs + needle.len()..];
        let after_trim = after.trim_start_matches([' ', '\t']);
        if after_trim.starts_with(':') {
            return true;
        }
        search_from = abs + needle.len();
        if search_from >= lower.len() {
            break;
        }
    }
    false
}

fn strip_bullet_prefix(line: &str) -> String {
    if matches_bullet_re(line) {
        let mut chars = line.chars().peekable();
        let mut idx = 0usize;
        while let Some(&c) = chars.peek() {
            if c == ' ' || c == '\t' {
                idx += c.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        // skip the marker
        if let Some(c) = chars.next() {
            idx += c.len_utf8();
        }
        while let Some(&c) = chars.peek() {
            if c == ' ' || c == '\t' {
                idx += c.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        line[idx..].to_string()
    } else {
        line.to_string()
    }
}

fn validate_artifact(name: &str, text: &str) -> (Vec<String>, Vec<String>) {
    if text.trim().is_empty() {
        (vec![format!("{name}: section is empty")], vec![])
    } else {
        (vec![], vec![])
    }
}

fn validate_bulleted_min(name: &str, text: &str, minimum: usize) -> (Vec<String>, Vec<String>) {
    let n = bullet_count(text);
    if n < minimum {
        (
            vec![format!("{name}: needs \u{2265}{minimum} bullets, found {n}")],
            vec![],
        )
    } else {
        (vec![], vec![])
    }
}

fn validate_constraints(name: &str, text: &str) -> (Vec<String>, Vec<String>) {
    let mut warnings = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        let idx = i + 1;
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let content = strip_bullet_prefix(stripped);
        let content = content.trim();
        if content.is_empty() {
            continue;
        }
        if !matches_cite_re(content) {
            warnings.push(format!(
                "{name} line {idx}: no file:line cite or `topic:` justification — \
consider `file:tools/foo.py:42 — short cite`"
            ));
        }
    }
    (vec![], warnings)
}

fn validate_alternatives(name: &str, text: &str) -> (Vec<String>, Vec<String>) {
    if has_sole_viable_marker(text) {
        return (
            vec![],
            vec![format!(
                "{name}: declared sole_viable — reviewer should challenge the dominance claim"
            )],
        );
    }
    let n = bullet_count(text);
    if n < 2 {
        (
            vec![format!(
                "{name}: needs \u{2265}2 alternatives OR a `sole_viable:` marker, found {n}"
            )],
            vec![],
        )
    } else {
        (vec![], vec![])
    }
}

fn validate_user_intention(name: &str, text: &str) -> (Vec<String>, Vec<String>) {
    let mut warnings = Vec::new();
    if text.trim().is_empty() {
        warnings.push(format!(
            "{name}: missing — without it jurors may confuse the want with the mechanism"
        ));
        return (vec![], warnings);
    }
    let lower = text.to_lowercase();
    let want_markers = ["want", "need", "goal", "outcome", "lighter", "faster", "simpler"]
        .iter()
        .filter(|m| lower.contains(**m))
        .count();
    if want_markers == 0 {
        warnings.push(format!(
            "{name}: no 'want' phrasing — state the user's underlying intent, not the proposal"
        ));
    }
    (vec![], warnings)
}

fn validate_omissions(name: &str, text: &str) -> (Vec<String>, Vec<String>) {
    if !text.trim().is_empty() || text.to_lowercase().contains("nothing") {
        (vec![], vec![])
    } else {
        (
            vec![],
            vec![format!(
                "{name}: missing — say either what's omitted or `nothing` for explicit disclosure"
            )],
        )
    }
}

fn run_validator(name: &str, body: &str) -> Option<(Vec<String>, Vec<String>)> {
    Some(match name {
        "ARTIFACT" => validate_artifact(name, body),
        "SUCCESS_CRITERIA" => validate_bulleted_min(name, body, 1),
        "NON_GOALS" => validate_bulleted_min(name, body, 1),
        "CONSTRAINTS" => validate_constraints(name, body),
        "ALTERNATIVES_CONSIDERED" => validate_alternatives(name, body),
        "KNOWN_WEAKNESSES" => validate_bulleted_min(name, body, 3),
        "USER_INTENTION" => validate_user_intention(name, body),
        "OMISSIONS" => validate_omissions(name, body),
        _ => return None,
    })
}

/// Validate the ```packet fence (if any) inside `text`.
///
/// If `text` has no ```packet fence, returns
/// `PacketValidation { ok: false, errors: ["no_packet_fence"], .. }`.
pub fn validate_packet(text: &str) -> PacketValidation {
    let Some(sections) = extract_packet(text) else {
        return PacketValidation {
            ok: false,
            errors: vec![NO_PACKET_FENCE.to_string()],
            warnings: vec![],
            sections: BTreeMap::new(),
        };
    };

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    for required in PACKET_REQUIRED_SECTIONS {
        if !sections.contains_key(*required) {
            let msg = format!("missing section: {required}");
            if section_is_error(required) {
                errors.push(msg);
            } else {
                warnings.push(msg);
            }
        }
    }

    for (name, body) in &sections {
        if let Some((section_errors, section_warnings)) = run_validator(name, body) {
            errors.extend(section_errors);
            warnings.extend(section_warnings);
        }
    }

    PacketValidation {
        ok: errors.is_empty(),
        errors,
        warnings,
        sections,
    }
}

/// Uniform skeleton template, verbatim from the Python `SKELETON_TEMPLATE`.
pub const SKELETON_TEMPLATE: &str = "```packet
ARTIFACT: <verbatim text or path to the artifact being reviewed>

SUCCESS_CRITERIA:
  - <one observable signal that proves the artifact achieved its goal>

NON_GOALS:
  - <one thing this work is NOT trying to do>

CONSTRAINTS:
  - file:<repo-relative path>:<line> — <why this constraint binds>
  - : <non-code constraint with topic and justification>

ALTERNATIVES_CONSIDERED:
  - <alternative A> — <why rejected or `sole_viable: ...`>
  - <alternative B> — <why rejected>

KNOWN_WEAKNESSES:
  - <author-disclosed weakness #1 — critique, don't validate>
  - <author-disclosed weakness #2>
  - <author-disclosed weakness #3>

USER_INTENTION:
  - Want: <what the user actually wants, separate from the chosen mechanism>
  - Mechanism: <the proposed way to deliver the want, one of several>

OMISSIONS:
  - <what this packet does NOT include that a reviewer might expect>
  - or: \"nothing\" if you considered and disclosed everything relevant
```
";

/// Return an empty ```packet skeleton. `kind` is accepted for parity with
/// the Python signature (`render_packet_skeleton(kind=None)`); for v1 the
/// skeleton is uniform across kinds, exactly as upstream.
pub fn render_packet_skeleton(_kind: Option<&str>) -> &'static str {
    SKELETON_TEMPLATE
}
