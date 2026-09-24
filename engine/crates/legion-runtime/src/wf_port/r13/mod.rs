//! Port of `skills/designer/engine/scripts/hook-before-edit.mjs` (packet r13).
//!
//! This module ports the pure, unit-testable core of the Cursor preToolUse
//! write gate: proposed file-path resolution, proposed-content projection
//! from Write/Edit/shell tool inputs (heredocs, `python -c`, `cp`, `tee`,
//! shell redirects, and fragment `old_string`/`new_string` edit projection),
//! and the project/sensitive/generated path checks. All I/O (reading an
//! existing project file's bytes from disk to project an edit against) is
//! behind the [`FileReader`] trait so tests can supply fakes instead of
//! touching the filesystem.
//!
//! NOT ported in this chunk (same gap noted by the w2_015 and Q1 packet
//! reports): the orchestration in `main()` that calls into `hook-lib.mjs`'s
//! `readConfig`/`readCache`/`persistCache`/`loadDetector`/`renderTemplate`/
//! `appendDesignSystemNote`/`designSystemOptions`/`writeAuditLog`/
//! `resolveProjectCwd` and the `SENSITIVE_PATH`/`GENERATED_PATH`/
//! `ALLOWED_EXTS` constants. Those all live in `hook-lib.mjs`'s config- and
//! detector-loading half, which is still NOT-PORTED per `full-Q1.md` (it
//! depends on the also-unported `lib/impeccable-config.mjs`). This module
//! ports everything in `hook-before-edit.mjs` that does not require that
//! config/detector plumbing: it is the piece a future `impeccable-config.mjs`
//! port can be wired up against without redoing this parsing logic.

use std::collections::HashMap;

/// Abstracts `fs.statSync`/`fs.readFileSync` so `readExistingProjectFile` can
/// be tested without touching disk. The real implementation should mirror
/// the JS: only regular files, capped at 1 MiB.
pub trait FileReader {
    /// Returns the file's UTF-8 contents, or `None` if it does not exist,
    /// is not a regular file, exceeds the 1 MiB cap, or is not valid UTF-8
    /// (matching `fs.readFileSync(filePath, 'utf-8')` failing softly via the
    /// `catch` in `readExistingProjectFile`).
    fn read_to_string(&self, path: &str) -> Option<String>;
}

/// A [`FileReader`] backed by an in-memory map, for tests.
#[derive(Default, Clone, Debug)]
pub struct FakeFileReader {
    files: HashMap<String, String>,
}

impl FakeFileReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_file(mut self, path: impl Into<String>, contents: impl Into<String>) -> Self {
        self.files.insert(path.into(), contents.into());
        self
    }
}

impl FileReader for FakeFileReader {
    fn read_to_string(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }
}

/// Result of projecting proposed content for a tool call. Mirrors the two
/// return shapes `proposedContent` uses in the JS: a plain string, or a
/// `{ skipped: '<reason>' }` marker object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposedContent {
    Content(String),
    Skipped(&'static str),
}

/// Minimal JSON-value view of a tool call's `tool_input`, mirroring the
/// fields `hook-before-edit.mjs` reads off it. Callers building this from a
/// real `serde_json::Value` should pull exactly these keys.
#[derive(Debug, Clone, Default)]
pub struct ToolInput {
    pub file_path: Option<String>,
    pub path: Option<String>,
    pub target_file: Option<String>,
    pub content: Option<String>,
    pub stream_content: Option<String>,
    pub text: Option<String>,
    pub command: Option<String>,
    pub args_command: Option<String>,
    pub old_string: Option<String>,
    pub new_string: Option<String>,
    pub edits: Option<Vec<EditFragment>>,
}

/// One entry of a `tool_input.edits` array.
#[derive(Debug, Clone, Default)]
pub struct EditFragment {
    pub old_string: Option<String>,
    pub new_string: Option<String>,
}

/// `event.file_path` fallback used by `proposedFilePath` when
/// `tool_input.file_path`/`path`/`target_file` are absent.
#[derive(Debug, Clone, Default)]
pub struct ToolEvent {
    pub tool_input: ToolInput,
    pub event_file_path: Option<String>,
}

// ---------------------------------------------------------------------
// Path resolution (`proposedFilePath`, `isInsideProject`, `relativePath`)
// ---------------------------------------------------------------------

/// Join `candidate` onto `cwd` the way `path.resolve(cwd, candidate)` would
/// for the POSIX-style paths this hook deals in: an absolute candidate is
/// returned unchanged, otherwise it is resolved against `cwd` with `.`/`..`
/// segments collapsed.
pub fn resolve_path(cwd: &str, candidate: &str) -> String {
    if candidate.starts_with('/') {
        return normalize_absolute(candidate);
    }
    let joined = format!("{}/{}", cwd.trim_end_matches('/'), candidate);
    normalize_absolute(&joined)
}

fn normalize_absolute(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    format!("/{}", stack.join("/"))
}

/// Mirrors `proposedFilePath`: prefer an explicit path field, else derive a
/// destination from a shell command (`shellWriteDestination`).
pub fn proposed_file_path(event: &ToolEvent, cwd: &str) -> String {
    let raw = event
        .tool_input
        .file_path
        .clone()
        .or_else(|| event.tool_input.path.clone())
        .or_else(|| event.tool_input.target_file.clone())
        .or_else(|| event.event_file_path.clone());

    let candidate = match raw {
        Some(ref s) if !s.trim().is_empty() => s.clone(),
        _ => {
            let command = shell_command(&event.tool_input);
            shell_write_destination(&command)
        }
    };

    if candidate.trim().is_empty() {
        return String::new();
    }
    resolve_path(cwd, &candidate)
}

/// Mirrors `isInsideProject`: true if `filePath` is `cwd` itself or a
/// descendant of it (no `..` escape).
pub fn is_inside_project(file_path: &str, cwd: &str) -> bool {
    let cwd_norm = normalize_absolute(cwd);
    let file_norm = normalize_absolute(file_path);
    if file_norm == cwd_norm {
        return true;
    }
    let prefix = if cwd_norm == "/" {
        "/".to_string()
    } else {
        format!("{cwd_norm}/")
    };
    file_norm.starts_with(&prefix)
}

/// Mirrors `relativePath`: a `/`-joined relative path, or the original
/// (absolute) path if it falls outside `cwd`.
pub fn relative_path(file_path: &str, cwd: &str) -> String {
    if !is_inside_project(file_path, cwd) {
        return file_path.to_string();
    }
    let cwd_norm = normalize_absolute(cwd);
    let file_norm = normalize_absolute(file_path);
    if file_norm == cwd_norm {
        return String::new();
    }
    let prefix = if cwd_norm == "/" {
        "/".to_string()
    } else {
        format!("{cwd_norm}/")
    };
    file_norm
        .strip_prefix(&prefix)
        .unwrap_or(&file_norm)
        .to_string()
}

// ---------------------------------------------------------------------
// Proposed content projection (`proposedContent`, `projectedEditContent`,
// fragment/edit helpers)
// ---------------------------------------------------------------------

fn shell_command(input: &ToolInput) -> String {
    input
        .command
        .clone()
        .or_else(|| input.args_command.clone())
        .unwrap_or_default()
}

/// Mirrors `hasFragmentEditContent`.
pub fn has_fragment_edit_content(input: &ToolInput) -> bool {
    if input.new_string.is_some() {
        return true;
    }
    if let Some(edits) = &input.edits {
        return edits.iter().any(|e| e.old_string.is_some() || e.new_string.is_some());
    }
    false
}

/// Mirrors `replaceOnce`: replace the first occurrence of `old` in
/// `original` with `new`. Returns `None` if `old` is empty or not found
/// (matching the JS `null` sentinel).
pub fn replace_once(original: &str, old: &str, new: &str) -> Option<String> {
    if old.is_empty() {
        return None;
    }
    let index = original.find(old)?;
    let mut out = String::with_capacity(original.len() - old.len() + new.len());
    out.push_str(&original[..index]);
    out.push_str(new);
    out.push_str(&original[index + old.len()..]);
    Some(out)
}

/// Mirrors `projectedEditContent`. Returns `None` when there is nothing to
/// project (no `old_string`/`edits` present at all), matching the JS
/// `undefined` return used to fall through to shell-content extraction.
pub fn projected_edit_content(
    input: &ToolInput,
    file_path: &str,
    cwd: &str,
    reader: &dyn FileReader,
    is_readable: impl Fn(&str, &str) -> bool,
) -> Option<ProposedContent> {
    if file_path.is_empty() {
        return None;
    }

    if input.old_string.is_some() || input.new_string.is_some() {
        let (old, new) = match (&input.old_string, &input.new_string) {
            (Some(o), Some(n)) => (o.clone(), n.clone()),
            _ => return Some(ProposedContent::Skipped("fragment-only-edit")),
        };
        let original = match read_existing_project_file(file_path, cwd, reader, &is_readable) {
            Some(text) => text,
            None => return Some(ProposedContent::Skipped("edit-original-unreadable")),
        };
        return Some(match replace_once(&original, &old, &new) {
            Some(projected) => ProposedContent::Content(projected),
            None => ProposedContent::Skipped("edit-old-string-missing"),
        });
    }

    let edits = input.edits.as_ref()?;
    let original = match read_existing_project_file(file_path, cwd, reader, &is_readable) {
        Some(text) => text,
        None => return Some(ProposedContent::Skipped("edit-original-unreadable")),
    };

    let mut projected = original;
    for edit in edits {
        let (old, new) = match (&edit.old_string, &edit.new_string) {
            (Some(o), Some(n)) => (o.clone(), n.clone()),
            _ => return Some(ProposedContent::Skipped("fragment-only-edit")),
        };
        match replace_once(&projected, &old, &new) {
            Some(next) => projected = next,
            None => return Some(ProposedContent::Skipped("edit-old-string-missing")),
        }
    }
    Some(ProposedContent::Content(projected))
}

/// Mirrors `readExistingProjectFile`: only files inside the project, not
/// matching the (caller-supplied) sensitive/generated predicate, capped at
/// 1 MiB by the `FileReader` implementation.
fn read_existing_project_file(
    file_path: &str,
    cwd: &str,
    reader: &dyn FileReader,
    is_readable: &impl Fn(&str, &str) -> bool,
) -> Option<String> {
    if !is_inside_project(file_path, cwd) {
        return None;
    }
    if !is_readable(file_path, cwd) {
        return None;
    }
    reader.read_to_string(file_path)
}

/// Mirrors `proposedContent`'s top-level dispatch, given the shell-derived
/// fallbacks already extracted (heredoc / python / cp). `edit_projection` is
/// the result of [`projected_edit_content`]; `fragment_only` is
/// [`has_fragment_edit_content`]; `shell_fallback` is whichever of
/// `shellPythonWriteContent` / `shellHereDocContent` / `shellCopiedFileContent`
/// produced a non-empty string first (or `None`).
pub fn proposed_content(
    input: &ToolInput,
    edit_projection: Option<ProposedContent>,
    shell_fallback: Option<String>,
) -> ProposedContent {
    if let Some(text) = &input.content {
        return ProposedContent::Content(text.clone());
    }
    if let Some(text) = &input.stream_content {
        return ProposedContent::Content(text.clone());
    }
    if let Some(text) = &input.text {
        return ProposedContent::Content(text.clone());
    }

    if let Some(projection) = edit_projection {
        return projection;
    }

    if has_fragment_edit_content(input) {
        return ProposedContent::Skipped("fragment-only-edit");
    }

    if let Some(text) = shell_fallback {
        return ProposedContent::Content(text);
    }

    ProposedContent::Content(String::new())
}

// ---------------------------------------------------------------------
// Shell command parsing (`shellWords`, `shellRedirectPath`,
// `shellTeeDestination`, `shellCopyPaths`, `shellWriteDestination`,
// `shellHereDocContent`, `pythonStringArg`, `shellPythonWriteContent`,
// `shellPythonWriteDestination`, `shellCopiedFileContent`)
// ---------------------------------------------------------------------

/// Mirrors `shellWords`: a minimal shell tokenizer handling single/double
/// quoted words and backslash-escaped quotes within them.
pub fn shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let chars: Vec<char> = command.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            let quote = c;
            let mut word = String::new();
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == quote {
                    word.push(quote);
                    i += 2;
                    continue;
                }
                if chars[i] == quote {
                    i += 1;
                    break;
                }
                word.push(chars[i]);
                i += 1;
            }
            words.push(word);
            continue;
        }
        let mut word = String::new();
        while i < chars.len() && !chars[i].is_whitespace() {
            word.push(chars[i]);
            i += 1;
        }
        words.push(word);
    }
    words
}

const SHELL_SEPARATORS: [&str; 4] = ["&&", "||", ";", "|"];

/// Mirrors `shellRedirectPath`: the target of a trailing `>`/`>>`/`1>`/`1>>`
/// redirect, honoring quoted paths.
pub fn shell_redirect_path(command: &str) -> String {
    if command.is_empty() {
        return String::new();
    }
    let re = regex::Regex::new(
        r#"(?:^|[\s;&|])(?:>>?|1>>?)\s*(?:"([^"]+)"|'([^']+)'|([^<>\s]+))"#,
    )
    .expect("static regex");
    if let Some(caps) = re.captures(command) {
        for i in 1..=3 {
            if let Some(m) = caps.get(i) {
                return m.as_str().trim().to_string();
            }
        }
    }
    String::new()
}

/// Mirrors `shellTeeDestination`.
pub fn shell_tee_destination(command: &str) -> String {
    let words = shell_words(command);
    let tee_index = words.iter().position(|w| basename(w) == "tee");
    let Some(tee_index) = tee_index else {
        return String::new();
    };
    for word in &words[tee_index + 1..] {
        if SHELL_SEPARATORS.contains(&word.as_str()) {
            break;
        }
        if word == "--" {
            continue;
        }
        if word.starts_with('-') {
            continue;
        }
        return word.clone();
    }
    String::new()
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Mirrors `shellCopyPaths`: returns `(source, dest)` for a leading `cp`
/// invocation, or `None`.
pub fn shell_copy_paths(command: &str) -> Option<(String, String)> {
    let words = shell_words(command);
    if words.len() < 3 || basename(&words[0]) != "cp" {
        return None;
    }
    let mut args = Vec::new();
    for word in &words[1..] {
        if SHELL_SEPARATORS.contains(&word.as_str()) {
            break;
        }
        if word == "--" {
            continue;
        }
        if word.starts_with('-') {
            continue;
        }
        args.push(word.clone());
    }
    if args.len() < 2 {
        return None;
    }
    let dest = args[args.len() - 1].clone();
    let source = args[args.len() - 2].clone();
    Some((source, dest))
}

fn first_match_group2(command: &str, re: &regex::Regex) -> String {
    re.captures(command)
        .and_then(|c| c.get(2))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default()
}

/// Mirrors `shellPythonWriteDestination`.
pub fn shell_python_write_destination(command: &str) -> String {
    let py_re = regex::Regex::new(r"\bpython(?:3)?\b").expect("static regex");
    if !py_re.is_match(command) {
        return String::new();
    }

    let direct_re = regex::Regex::new(
        r#"(?:^|[^\w.])(?:pathlib\.)?Path\(\s*(["'])(.*?)\1\s*\)\s*\.write_text\s*\("#,
    )
    .expect("static regex");
    let direct = first_match_group2(command, &direct_re);
    if !direct.is_empty() {
        return direct;
    }

    let assignment_re =
        regex::Regex::new(r#"\b([A-Za-z_]\w*)\s*=\s*(?:pathlib\.)?Path\(\s*(["'])(.*?)\2\s*\)"#)
            .expect("static regex");
    let mut paths_by_var: HashMap<String, String> = HashMap::new();
    for caps in assignment_re.captures_iter(command) {
        paths_by_var.insert(caps[1].to_string(), caps[3].to_string());
    }

    let write_var_re = regex::Regex::new(r"\b([A-Za-z_]\w*)\.write_text\s*\(").expect("static regex");
    for caps in write_var_re.captures_iter(command) {
        if let Some(candidate) = paths_by_var.get(&caps[1]) {
            return candidate.clone();
        }
    }

    let open_re =
        regex::Regex::new(r#"\bopen\(\s*(["'])(.*?)\1\s*,\s*(["'])[wax](?:\+)?b?\3"#).expect("static regex");
    first_match_group2(command, &open_re)
}

/// Mirrors `shellWriteDestination`.
pub fn shell_write_destination(command: &str) -> String {
    let redirect = shell_redirect_path(command);
    if !redirect.is_empty() {
        return redirect;
    }
    let tee = shell_tee_destination(command);
    if !tee.is_empty() {
        return tee;
    }
    if let Some((_, dest)) = shell_copy_paths(command) {
        if !dest.is_empty() {
            return dest;
        }
    }
    shell_python_write_destination(command)
}

/// Mirrors `shellHereDocContent`: the body of a `<<MARKER ... MARKER`
/// heredoc (also handles `<<-`/quoted markers), matching `[A-Za-z0-9_.-]+`
/// marker names.
pub fn shell_heredoc_content(command: &str) -> String {
    if command.is_empty() {
        return String::new();
    }
    let marker_re =
        regex::Regex::new(r#"<<-?\s*['"]?([A-Za-z0-9_.-]+)['"]?[^\r\n]*\r?\n"#).expect("static regex");
    let Some(marker_match) = marker_re.find(command) else {
        return String::new();
    };
    let marker = marker_re
        .captures(command)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .unwrap_or_default();
    let start = marker_match.end();
    let rest = &command[start..];
    let end_re = regex::Regex::new(&format!(r"\r?\n{}(?:\r?\n|$)", regex::escape(marker)))
        .expect("built regex");
    match end_re.find(rest) {
        Some(m) => rest[..m.start()].to_string(),
        None => String::new(),
    }
}

/// Mirrors `pythonStringArg`: extract the first string-literal argument
/// (single/double/triple quoted, with backslash-escape handling for the
/// simple-quote case) following each match of `prefix_re` in `script`.
fn python_string_arg(script: &str, prefix_re: &regex::Regex) -> String {
    for m in prefix_re.find_iter(script) {
        let start = m.end();
        let rest = &script[start..];
        let mut chars = rest.char_indices();
        let Some((_, quote_or_triple_start)) = chars.next() else {
            continue;
        };
        // Check for triple quotes.
        if rest.len() >= 3 && (&rest[0..3] == "'''" || &rest[0..3] == "\"\"\"") {
            let triple = &rest[0..3];
            if let Some(end_rel) = rest[3..].find(triple) {
                return rest[3..3 + end_rel].to_string();
            }
            continue;
        }
        let quote = quote_or_triple_start;
        if quote != '"' && quote != '\'' {
            continue;
        }
        let byte_chars: Vec<char> = rest.chars().collect();
        let mut out = String::new();
        let mut i = 1;
        let mut found = false;
        while i < byte_chars.len() {
            let ch = byte_chars[i];
            if ch == '\\' {
                if i + 1 < byte_chars.len() {
                    out.push(byte_chars[i + 1]);
                }
                i += 2;
            } else if ch == quote {
                found = true;
                break;
            } else {
                out.push(ch);
                i += 1;
            }
        }
        if found {
            return out;
        }
    }
    String::new()
}

/// Mirrors `shellPythonWriteContent`.
pub fn shell_python_write_content(command: &str) -> String {
    let py_re = regex::Regex::new(r"\bpython(?:3)?\b").expect("static regex");
    if !py_re.is_match(command) {
        return String::new();
    }
    let heredoc = shell_heredoc_content(command);
    let script = if heredoc.is_empty() { command } else { &heredoc };

    let write_text_re = regex::Regex::new(r"\.write_text\s*\(\s*").expect("static regex");
    let via_write_text = python_string_arg(script, &write_text_re);
    if !via_write_text.is_empty() {
        return via_write_text;
    }
    let write_re = regex::Regex::new(r"\.write\s*\(\s*").expect("static regex");
    python_string_arg(script, &write_re)
}

/// Mirrors `shellCopiedFileContent`. `is_readable` should encode the
/// `SENSITIVE_PATH`/`GENERATED_PATH` exclusion (from `hook-lib.mjs`, not yet
/// ported — see module docs) plus the 1 MiB regular-file cap; the size cap
/// itself is enforced by the `FileReader` implementation.
pub fn shell_copied_file_content(
    command: &str,
    cwd: &str,
    reader: &dyn FileReader,
    is_readable: impl Fn(&str, &str) -> bool,
) -> String {
    let Some((source, _dest)) = shell_copy_paths(command) else {
        return String::new();
    };
    if source.is_empty() {
        return String::new();
    }
    let source_path = resolve_path(cwd, &source);
    if !is_inside_project(&source_path, cwd) {
        return String::new();
    }
    if !is_readable(&source_path, cwd) {
        return String::new();
    }
    reader.read_to_string(&source_path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always_readable(_path: &str, _cwd: &str) -> bool {
        true
    }

    #[test]
    fn resolve_path_joins_relative_and_keeps_absolute() {
        assert_eq!(resolve_path("/proj", "src/a.tsx"), "/proj/src/a.tsx");
        assert_eq!(resolve_path("/proj", "/etc/passwd"), "/etc/passwd");
        assert_eq!(resolve_path("/proj", "./a/../b.tsx"), "/proj/b.tsx");
    }

    #[test]
    fn is_inside_project_rejects_escape() {
        assert!(is_inside_project("/proj/src/a.tsx", "/proj"));
        assert!(is_inside_project("/proj", "/proj"));
        assert!(!is_inside_project("/etc/passwd", "/proj"));
        assert!(!is_inside_project("/projother/a.tsx", "/proj"));
    }

    #[test]
    fn relative_path_strips_cwd_prefix() {
        assert_eq!(relative_path("/proj/src/a.tsx", "/proj"), "src/a.tsx");
        assert_eq!(relative_path("/etc/passwd", "/proj"), "/etc/passwd");
        assert_eq!(relative_path("/proj", "/proj"), "");
    }

    #[test]
    fn proposed_file_path_prefers_explicit_field() {
        let event = ToolEvent {
            tool_input: ToolInput {
                file_path: Some("src/a.tsx".to_string()),
                ..Default::default()
            },
            event_file_path: None,
        };
        assert_eq!(proposed_file_path(&event, "/proj"), "/proj/src/a.tsx");
    }

    #[test]
    fn proposed_file_path_falls_back_to_shell_redirect() {
        let event = ToolEvent {
            tool_input: ToolInput {
                command: Some("echo hi > src/out.tsx".to_string()),
                ..Default::default()
            },
            event_file_path: None,
        };
        assert_eq!(proposed_file_path(&event, "/proj"), "/proj/src/out.tsx");
    }

    #[test]
    fn proposed_file_path_empty_when_nothing_found() {
        let event = ToolEvent::default();
        assert_eq!(proposed_file_path(&event, "/proj"), "");
    }

    #[test]
    fn replace_once_replaces_first_only() {
        assert_eq!(
            replace_once("aXbXc", "X", "-"),
            Some("a-bXc".to_string())
        );
        assert_eq!(replace_once("abc", "z", "-"), None);
        assert_eq!(replace_once("abc", "", "-"), None);
    }

    #[test]
    fn has_fragment_edit_content_detects_single_and_array() {
        assert!(has_fragment_edit_content(&ToolInput {
            new_string: Some("x".into()),
            ..Default::default()
        }));
        assert!(has_fragment_edit_content(&ToolInput {
            edits: Some(vec![EditFragment {
                old_string: Some("a".into()),
                new_string: None
            }]),
            ..Default::default()
        }));
        assert!(!has_fragment_edit_content(&ToolInput::default()));
    }

    #[test]
    fn projected_edit_content_single_fragment_roundtrip() {
        let reader = FakeFileReader::new().with_file("/proj/a.tsx", "hello world");
        let input = ToolInput {
            old_string: Some("world".into()),
            new_string: Some("there".into()),
            ..Default::default()
        };
        let result =
            projected_edit_content(&input, "/proj/a.tsx", "/proj", &reader, always_readable);
        assert_eq!(
            result,
            Some(ProposedContent::Content("hello there".to_string()))
        );
    }

    #[test]
    fn projected_edit_content_missing_old_string_field_is_fragment_only() {
        let reader = FakeFileReader::new();
        let input = ToolInput {
            new_string: Some("there".into()),
            ..Default::default()
        };
        let result =
            projected_edit_content(&input, "/proj/a.tsx", "/proj", &reader, always_readable);
        assert_eq!(result, Some(ProposedContent::Skipped("fragment-only-edit")));
    }

    #[test]
    fn projected_edit_content_old_string_not_found() {
        let reader = FakeFileReader::new().with_file("/proj/a.tsx", "hello world");
        let input = ToolInput {
            old_string: Some("nope".into()),
            new_string: Some("x".into()),
            ..Default::default()
        };
        let result =
            projected_edit_content(&input, "/proj/a.tsx", "/proj", &reader, always_readable);
        assert_eq!(
            result,
            Some(ProposedContent::Skipped("edit-old-string-missing"))
        );
    }

    #[test]
    fn projected_edit_content_unreadable_original() {
        let reader = FakeFileReader::new();
        let input = ToolInput {
            old_string: Some("a".into()),
            new_string: Some("b".into()),
            ..Default::default()
        };
        let result =
            projected_edit_content(&input, "/proj/a.tsx", "/proj", &reader, always_readable);
        assert_eq!(
            result,
            Some(ProposedContent::Skipped("edit-original-unreadable"))
        );
    }

    #[test]
    fn projected_edit_content_multi_edit_array_applies_in_order() {
        let reader = FakeFileReader::new().with_file("/proj/a.tsx", "one two three");
        let input = ToolInput {
            edits: Some(vec![
                EditFragment {
                    old_string: Some("one".into()),
                    new_string: Some("1".into()),
                },
                EditFragment {
                    old_string: Some("three".into()),
                    new_string: Some("3".into()),
                },
            ]),
            ..Default::default()
        };
        let result =
            projected_edit_content(&input, "/proj/a.tsx", "/proj", &reader, always_readable);
        assert_eq!(
            result,
            Some(ProposedContent::Content("1 two 3".to_string()))
        );
    }

    #[test]
    fn projected_edit_content_none_when_no_edit_fields() {
        let reader = FakeFileReader::new();
        let input = ToolInput::default();
        let result =
            projected_edit_content(&input, "/proj/a.tsx", "/proj", &reader, always_readable);
        assert_eq!(result, None);
    }

    #[test]
    fn proposed_content_prefers_content_field() {
        let input = ToolInput {
            content: Some("direct".into()),
            ..Default::default()
        };
        assert_eq!(
            proposed_content(&input, None, None),
            ProposedContent::Content("direct".to_string())
        );
    }

    #[test]
    fn proposed_content_uses_edit_projection_when_present() {
        let input = ToolInput::default();
        assert_eq!(
            proposed_content(
                &input,
                Some(ProposedContent::Content("projected".into())),
                None
            ),
            ProposedContent::Content("projected".to_string())
        );
    }

    #[test]
    fn proposed_content_falls_back_to_shell_then_empty() {
        let input = ToolInput::default();
        assert_eq!(
            proposed_content(&input, None, Some("from-shell".into())),
            ProposedContent::Content("from-shell".to_string())
        );
        assert_eq!(
            proposed_content(&input, None, None),
            ProposedContent::Content(String::new())
        );
    }

    #[test]
    fn shell_words_handles_quotes_and_escapes() {
        assert_eq!(
            shell_words(r#"cp "a b.txt" 'c.txt' d.txt"#),
            vec!["cp", "a b.txt", "c.txt", "d.txt"]
        );
        assert_eq!(shell_words("echo \"x\""), vec!["echo", "x"]);
    }

    #[test]
    fn shell_redirect_path_matches_plain_and_quoted() {
        assert_eq!(shell_redirect_path("echo hi > out.txt"), "out.txt");
        assert_eq!(shell_redirect_path("echo hi >> \"a b.txt\""), "a b.txt");
        assert_eq!(shell_redirect_path("echo hi 1> out.txt"), "out.txt");
        assert_eq!(shell_redirect_path("echo hi"), "");
    }

    #[test]
    fn shell_tee_destination_skips_flags() {
        assert_eq!(shell_tee_destination("echo hi | tee -a out.txt"), "out.txt");
        assert_eq!(shell_tee_destination("echo hi | tee out.txt && true"), "out.txt");
        assert_eq!(shell_tee_destination("echo hi"), "");
    }

    #[test]
    fn shell_copy_paths_extracts_source_and_dest() {
        assert_eq!(
            shell_copy_paths("cp -v a.txt b.txt"),
            Some(("a.txt".to_string(), "b.txt".to_string()))
        );
        assert_eq!(shell_copy_paths("mv a.txt b.txt"), None);
        assert_eq!(shell_copy_paths("cp a.txt"), None);
    }

    #[test]
    fn shell_write_destination_precedence() {
        assert_eq!(
            shell_write_destination("echo hi > redirect.txt | tee tee.txt"),
            "redirect.txt"
        );
        assert_eq!(shell_write_destination("echo hi | tee tee.txt"), "tee.txt");
        assert_eq!(shell_write_destination("cp a.txt dest.txt"), "dest.txt");
    }

    #[test]
    fn shell_python_write_destination_direct_path() {
        assert_eq!(
            shell_python_write_destination(r#"python3 -c "Path('out.txt').write_text('x')""#),
            "out.txt"
        );
    }

    #[test]
    fn shell_python_write_destination_via_variable() {
        assert_eq!(
            shell_python_write_destination(
                r#"python3 -c "p = pathlib.Path('out.txt')
p.write_text('x')""#
            ),
            "out.txt"
        );
    }

    #[test]
    fn shell_python_write_destination_via_open() {
        assert_eq!(
            shell_python_write_destination(r#"python3 -c "open('out.txt', 'w').write('x')""#),
            "out.txt"
        );
    }

    #[test]
    fn shell_python_write_destination_requires_python() {
        assert_eq!(
            shell_python_write_destination("node -e \"open('out.txt', 'w')\""),
            ""
        );
    }

    #[test]
    fn shell_heredoc_content_extracts_body() {
        let command = "cat <<EOF > out.txt\nline one\nline two\nEOF\n";
        assert_eq!(shell_heredoc_content(command), "line one\nline two");
    }

    #[test]
    fn shell_heredoc_content_no_marker_is_empty() {
        assert_eq!(shell_heredoc_content("echo hi"), "");
    }

    #[test]
    fn shell_python_write_content_from_heredoc() {
        let command = "python3 <<'PY'\nPath('out.txt').write_text('hello there')\nPY\n";
        assert_eq!(shell_python_write_content(command), "hello there");
    }

    #[test]
    fn shell_python_write_content_from_inline_write() {
        assert_eq!(
            shell_python_write_content(r#"python3 -c "f.write('inline body')""#),
            "inline body"
        );
    }

    #[test]
    fn shell_copied_file_content_reads_source_inside_project() {
        let reader = FakeFileReader::new().with_file("/proj/src/a.txt", "source body");
        assert_eq!(
            shell_copied_file_content("cp src/a.txt dst.txt", "/proj", &reader, always_readable),
            "source body"
        );
    }

    #[test]
    fn shell_copied_file_content_rejects_outside_project() {
        let reader = FakeFileReader::new().with_file("/etc/passwd", "secret");
        assert_eq!(
            shell_copied_file_content("cp /etc/passwd dst.txt", "/proj", &reader, always_readable),
            ""
        );
    }

    #[test]
    fn shell_copied_file_content_respects_readability_gate() {
        let reader = FakeFileReader::new().with_file("/proj/.env", "SECRET=1");
        assert_eq!(
            shell_copied_file_content("cp .env dst.txt", "/proj", &reader, |_, _| false),
            ""
        );
    }
}
