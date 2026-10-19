//! Scoped file-excerpt slicing for lens packets, per `skills/audit/
//! references/lens-routing.md`'s Input contract and "Excerpt compression"
//! section: RAW excerpts (exact tokens, secret-redacted, `file:line`
//! anchored) for `security`/`schema`/`correctness`/`performance`/`minimize`
//! plus `doc-drift`/`architecture`/`ai-slop`; SKELETON excerpts
//! (signatures, type/struct/fn/class declarations, imports, no bodies) for
//! `naming`/`dead-file`. A requested skeleton of an original file no larger
//! than 4 KiB carries Raw content instead, preserving bounded bodies & contracts.
//!
//! Dependency-free by design: no `tree-sitter` (a new crate dependency is
//! out of scope for this packet — see the Cargo.toml patch in the report).
//! Skeletonization here is a line-based heuristic per language family
//! (Rust, TS/JS, Swift, Python) that keeps declaration lines and collapses
//! bodies, which is adequate for the structure/survey lenses that only
//! reason about shape.

use std::{cell::RefCell, io::Read, path::Path};

use super::lens_plan::ExcerptMode;
use crate::{
    snapshot::{FrozenSnapshot, SnapshotAdmission, SnapshotSide},
    AuditError,
};

/// Size of one chunk of a file, in redacted source bytes. A file larger than
/// this is split across consecutive chunks on line boundaries (never
/// truncated), and the chunks may land in consecutive packet parts.
pub const MAX_BYTES_PER_FILE: usize = 32 * 1024;

/// Whole original-file ceiling for replacing a requested Skeleton with Raw.
/// Resolve before redaction, hunk selection or chunking; small chunks of a
/// larger file never opt into this policy. Coverage estimates use the same rule.
pub(super) const SMALL_FILE_RAW_BYTES: u64 = 4096;

pub(super) fn effective_excerpt_mode(mode: ExcerptMode, original_bytes: u64) -> ExcerptMode {
    if mode == ExcerptMode::Skeleton && original_bytes <= SMALL_FILE_RAW_BYTES {
        ExcerptMode::Raw
    } else {
        mode
    }
}

/// Ceiling on the sum of all excerpt bytes carried by one packet part. When
/// the denominator needs more, `partition_excerpts` continues into the next
/// part instead of dropping paths.
pub const MAX_TOTAL_EXCERPT_BYTES: usize = 512 * 1024;

/// A single line longer than this cannot be reviewed as an excerpt (minified
/// bundles, data blobs); the file is omitted with reason `line-over-limit`.
pub const MAX_LINE_BYTES: usize = 256 * 1024;

/// Longest block (PEM body, multi-line quoted/heredoc secret) the redactor
/// will consume when no terminator is found.
pub const MAX_BLOCK_LINES: usize = 200;

/// Default provider-level ceiling on packet parts (`bounds.maxReasoningParts`
/// overrides it).
pub const DEFAULT_MAX_PARTS: usize = 400;

/// Source lines of context kept on each side of a changed hunk when a diff
/// scoped audit excerpts a file (overlapping or touching windows merge).
pub const HUNK_CONTEXT_LINES: usize = 20;

/// Changed line ranges per repository-relative path: 1-based inclusive
/// `(start, end)` source lines of the new file. A path without an entry is
/// excerpted whole.
pub type ChangedHunks = std::collections::BTreeMap<String, Vec<(usize, usize)>>;

/// Merges `hunks` widened by `context` lines on each side and clamped to
/// `1..=total_lines`. Returns sorted, non-overlapping, non-adjacent windows.
pub fn hunk_windows(
    hunks: &[(usize, usize)],
    context: usize,
    total_lines: usize,
) -> Vec<(usize, usize)> {
    if total_lines == 0 {
        return Vec::new();
    }
    let mut widened: Vec<(usize, usize)> = hunks
        .iter()
        .filter(|(start, end)| *start <= total_lines && end >= start)
        .map(|(start, end)| {
            (
                start.saturating_sub(context).max(1),
                (end + context).min(total_lines),
            )
        })
        .collect();
    widened.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in widened {
        match merged.last_mut() {
            Some(last) if start <= last.1 + 1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// What redaction did to one excerpt.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionCounts {
    /// Source lines replaced or rewritten.
    pub lines: usize,
    pub pem_blocks: usize,
    pub multiline_secrets: usize,
    pub continuation_lines: usize,
}

/// One file chunk's excerpt: RAW (bounded, `file:line` anchored,
/// secret-redacted) or SKELETON (signatures/declarations/imports only,
/// redacted before skeletonizing).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Excerpt {
    pub path: String,
    /// Explicit prior/current source identity; deleted files use frozen base bytes.
    pub source_side: &'static str,
    pub mode: ExcerptMode,
    pub language: &'static str,
    /// `file:line` anchors covering the source lines this chunk represents,
    /// e.g. `["src/x.rs:1-40", "src/x.rs:88-96"]` for a skeleton with gaps,
    /// or a single `["src/x.rs:1-400"]` span for a raw excerpt. Always in
    /// source-file line numbers, even after a block was collapsed.
    pub anchors: Vec<String>,
    pub content: String,
    /// Legacy flag, set only by `build_excerpt`'s first-chunk view when the
    /// file continues past the chunk. Packet parts never truncate.
    pub truncated: bool,
    /// True when anything was redacted from this chunk (RAW or SKELETON).
    pub redacted: bool,
    /// First and last source line of this chunk (0/0 for an empty file).
    pub start_line: usize,
    pub end_line: usize,
    /// 1-based chunk index and chunk count for the file.
    pub chunk: usize,
    pub chunks: usize,
    /// Source ranges (`path:start-end`) a collapsed redaction block replaced
    /// by a single content line. Content lines after such a block are offset
    /// from their source line numbers by the block's length minus one.
    pub redacted_ranges: Vec<String>,
    pub redaction: RedactionCounts,
}

fn language_for(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".rs") {
        "rust"
    } else if lower.ends_with(".ts") || lower.ends_with(".tsx") {
        "typescript"
    } else if lower.ends_with(".js")
        || lower.ends_with(".jsx")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
    {
        "javascript"
    } else if lower.ends_with(".swift") {
        "swift"
    } else if lower.ends_with(".py") {
        "python"
    } else {
        "unknown"
    }
}

/// Redacts secret-shaped tokens on one line: `KEY = "..."`/`KEY: "..."`
/// assignments whose value looks like a long opaque token, plus a few
/// well-known key-material markers. Conservative and line-local by design
/// — no cross-line PEM-block state machine, since a false negative here is
/// bounded by "the lens sees a redaction placeholder, not the secret",
/// while a false positive only costs a little excerpt fidelity.
pub(crate) fn redact_secrets(line: &str) -> (String, bool) {
    const SECRET_NAME_HINTS: &[&str] = &[
        "secret",
        "token",
        "apikey",
        "api_key",
        "password",
        "passwd",
        "private_key",
        "privatekey",
        "access_key",
        "accesskey",
        "client_secret",
        "auth",
    ];
    const KEY_MATERIAL_MARKERS: &[&str] = &["-----BEGIN", "AKIA", "ghp_", "sk-", "xox", "AIza"];

    let lower = line.to_ascii_lowercase();
    let mut redacted = false;
    let mut out = line.to_string();

    if KEY_MATERIAL_MARKERS
        .iter()
        .any(|marker| line.contains(marker))
    {
        out = "[REDACTED: key material]".into();
        return (out, true);
    }

    // Try the first `=` (assignment, covers typed declarations such as
    // `NAME: &str = "..."`) and the first `:` (key/value forms).
    for separator in ['=', ':'] {
        let Some(equals) = line.find(separator) else {
            continue;
        };
        let (name, rest) = line.split_at(equals);
        let name_lower = name.to_ascii_lowercase();
        let looks_like_secret_name = SECRET_NAME_HINTS
            .iter()
            .any(|hint| name_lower.contains(hint));
        let value = &rest[1..];
        // Strip quoting and JSON/array punctuation around the value so
        // `{ "api_key": "…" }` and `key = "…",` are both recognised, and
        // accept the base64 alphabet (`+`, `=`) as opaque token characters.
        let value_trimmed = value.trim_matches(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ';' | ',' | '{' | '}' | '[' | ']')
        });
        let looks_like_opaque_value = value_trimmed.len() >= 16
            && value_trimmed.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '+' | '=')
            });
        if looks_like_secret_name && looks_like_opaque_value {
            out = format!("{name}={}", "[REDACTED]");
            redacted = true;
            break;
        }
    }
    let _ = lower;
    (out, redacted)
}

// ---------------------------------------------------------------------------
// Block-aware redaction
// ---------------------------------------------------------------------------

/// Why a line carries redacted text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedKind {
    /// Untouched source line.
    Plain,
    /// Line-local token or key-material redaction (`redact_secrets`).
    Token,
    /// A `-----BEGIN ...-----` block (or its single-line form).
    Pem,
    /// First line of a multi-line secret assignment (value redacted).
    MultilineFirst,
    /// Collapsed body of a multi-line secret assignment.
    MultilineBody,
    /// Collapsed base64-looking lines that followed a redacted line.
    Continuation,
}

/// One post-redaction line. A collapsed block is a single `RedLine` whose
/// `start..=end` is the source range it replaced, so source line numbers
/// stay recoverable for anchors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedLine {
    pub text: String,
    pub start: usize,
    pub end: usize,
    pub kind: RedKind,
}

impl RedLine {
    fn collapsed(&self) -> bool {
        self.end > self.start
    }
}

enum Terminator {
    /// Closing quote token (`"`, `'`, backtick, triple quote, raw-string close).
    Quote(String),
    /// Heredoc delimiter.
    Heredoc(String),
    /// YAML block scalar: body is every following blank or deeper-indented line.
    Indented(usize),
}

fn has_secret_name_hint(name: &str) -> bool {
    const HINTS: &[&str] = &[
        "secret",
        "token",
        "apikey",
        "api_key",
        "password",
        "passwd",
        "private_key",
        "privatekey",
        "access_key",
        "accesskey",
        "client_secret",
        "auth",
    ];
    let lower = name.to_ascii_lowercase();
    HINTS.iter().any(|hint| lower.contains(hint))
}

/// `Some((label, text_after_BEGIN))` when the line opens a PEM-style block.
fn pem_begin(line: &str) -> Option<(String, &str)> {
    let index = line.find("-----BEGIN")?;
    let after = &line[index + "-----BEGIN".len()..];
    let label = after
        .trim_start()
        .split("-----")
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    Some((label, after))
}

fn pem_end_in(text: &str, label: &str) -> bool {
    if label.is_empty() {
        text.contains("-----END")
    } else {
        text.contains(&format!("-----END {label}"))
    }
}

fn is_base64_like(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.len() >= 20
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        && trimmed
            .chars()
            .any(|c| c.is_ascii_digit() || matches!(c, '+' | '/' | '='))
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// True when `text` contains `quote` not preceded by a backslash.
fn closes_quote(text: &str, quote: &str) -> bool {
    if quote.len() > 1 {
        return text.contains(quote);
    }
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if quote.starts_with(ch) {
            return true;
        }
    }
    false
}

/// Detects a secret-named assignment whose value runs past the line:
/// an unclosed quote (single, triple, raw-string, backtick), a heredoc, or a
/// YAML block scalar. Returns the rewritten first line and how the body ends.
fn multiline_secret_start(line: &str) -> Option<(String, Terminator)> {
    let separator = line.find(['=', ':'])?;
    let name = &line[..separator];
    if !has_secret_name_hint(name) {
        return None;
    }
    let value_start = line.find('=').map_or(separator + 1, |index| index + 1);
    let value = line[value_start..].trim_start();
    let first = format!("{name}=[REDACTED]");

    if matches!(value.trim(), "|" | "|-" | "|+" | ">" | ">-" | ">+") {
        return Some((first, Terminator::Indented(indent_of(line))));
    }
    if let Some(index) = value
        .find("<<")
        .filter(|index| value[..*index].ends_with(char::is_whitespace) || *index == 0)
    {
        let rest = value[index + 2..].trim_start_matches(['-', '~']);
        let quoted = rest.starts_with(['\'', '"']);
        let rest = rest.trim_start_matches(['\'', '"']);
        let ident: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let conventional = ident
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if ident.len() >= 2
            && ident
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && (quoted || conventional)
        {
            return Some((first, Terminator::Heredoc(ident)));
        }
    }
    for triple in ["\"\"\"", "'''"] {
        if let Some(body) = value.strip_prefix(triple) {
            if !body.contains(triple) {
                return Some((first, Terminator::Quote(triple.to_owned())));
            }
            return None;
        }
    }
    if let Some(stripped) = value.strip_prefix('r') {
        let hashes = stripped.chars().take_while(|c| *c == '#').count();
        if let Some(body) = stripped[hashes..].strip_prefix('"') {
            let close = format!("\"{}", "#".repeat(hashes));
            if !body.contains(&close) {
                return Some((first, Terminator::Quote(close)));
            }
            return None;
        }
    }
    let opener = value.chars().next()?;
    if matches!(opener, '"' | '\'' | '`') {
        let quote = opener.to_string();
        if !closes_quote(&value[1..], &quote) {
            return Some((first, Terminator::Quote(quote)));
        }
    }
    None
}

/// Block-aware redaction over a whole file (or excerpt). A line state
/// machine that:
///
/// * collapses `-----BEGIN ...-----` through the matching `-----END ...-----`
///   (or `MAX_BLOCK_LINES` / end of text when unterminated) into one
///   `[REDACTED PEM BLOCK n lines]` line;
/// * rewrites a secret-named assignment whose quoted/heredoc/block-scalar
///   value spans lines, collapsing the body into one
///   `[REDACTED MULTILINE SECRET n lines]` line;
/// * collapses base64-looking lines that directly follow any redacted line;
/// * applies the line-local `redact_secrets` to every other line.
///
/// Every output line records the source range it stands for, so a collapsed
/// block never shifts the line numbers a reviewer cites.
pub fn redact_lines(text: &str) -> Vec<RedLine> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<RedLine> = Vec::with_capacity(lines.len());
    let mut after_redaction = false;
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index];
        let number = index + 1;

        if let Some((label, after)) = pem_begin(line) {
            let limit = (index + MAX_BLOCK_LINES).min(lines.len());
            let end = if pem_end_in(after, &label) {
                index + 1
            } else {
                let mut end = limit;
                for (offset, candidate) in lines[index + 1..limit].iter().enumerate() {
                    if pem_end_in(candidate, &label) {
                        end = index + 2 + offset;
                        break;
                    }
                }
                end
            };
            let span = end - index;
            out.push(RedLine {
                text: if span == 1 {
                    "[REDACTED: key material]".to_owned()
                } else {
                    format!("[REDACTED PEM BLOCK {span} lines]")
                },
                start: number,
                end: number + span - 1,
                kind: RedKind::Pem,
            });
            index = end;
            after_redaction = true;
            continue;
        }

        if after_redaction && is_base64_like(line) {
            let mut end = index;
            while end < lines.len() && is_base64_like(lines[end]) {
                end += 1;
            }
            let span = end - index;
            out.push(RedLine {
                text: format!("[REDACTED base64 continuation {span} lines]"),
                start: number,
                end: number + span - 1,
                kind: RedKind::Continuation,
            });
            index = end;
            continue;
        }

        if let Some((first, terminator)) = multiline_secret_start(line) {
            let limit = (index + 1 + MAX_BLOCK_LINES).min(lines.len());
            let body_end = match &terminator {
                Terminator::Quote(quote) => {
                    let mut end = limit;
                    for (offset, candidate) in lines[index + 1..limit].iter().enumerate() {
                        if closes_quote(candidate, quote) {
                            end = index + 2 + offset;
                            break;
                        }
                    }
                    end
                }
                Terminator::Heredoc(ident) => {
                    let mut end = limit;
                    for (offset, candidate) in lines[index + 1..limit].iter().enumerate() {
                        if candidate.trim() == ident {
                            end = index + 2 + offset;
                            break;
                        }
                    }
                    end
                }
                Terminator::Indented(base) => {
                    let mut end = index + 1;
                    while end < limit
                        && (lines[end].trim().is_empty() || indent_of(lines[end]) > *base)
                    {
                        end += 1;
                    }
                    end
                }
            };
            out.push(RedLine {
                text: first,
                start: number,
                end: number,
                kind: RedKind::MultilineFirst,
            });
            let body = body_end - (index + 1);
            if body > 0 {
                out.push(RedLine {
                    text: format!("[REDACTED MULTILINE SECRET {body} lines]"),
                    start: number + 1,
                    end: number + body,
                    kind: RedKind::MultilineBody,
                });
            }
            index = body_end;
            after_redaction = true;
            continue;
        }

        let (text, hit) = redact_secrets(line);
        out.push(RedLine {
            text,
            start: number,
            end: number,
            kind: if hit { RedKind::Token } else { RedKind::Plain },
        });
        after_redaction = hit;
        index += 1;
    }
    out
}

/// Block-aware redaction of a whole text, joined back into one string (the
/// collapsed form; line numbers are not preserved — use `redact_lines` when
/// source ranges matter).
pub fn redact_text(text: &str) -> (String, RedactionCounts) {
    let lines = redact_lines(text);
    let counts = redaction_counts(&lines);
    let mut out = String::new();
    for line in &lines {
        out.push_str(&line.text);
        out.push('\n');
    }
    (out, counts)
}

fn redaction_counts(lines: &[RedLine]) -> RedactionCounts {
    let mut counts = RedactionCounts::default();
    for line in lines {
        let span = line.end + 1 - line.start;
        match line.kind {
            RedKind::Plain => {}
            RedKind::Token => counts.lines += 1,
            RedKind::Pem => {
                counts.pem_blocks += 1;
                counts.lines += span;
            }
            RedKind::MultilineFirst => {
                counts.multiline_secrets += 1;
                counts.lines += 1;
            }
            RedKind::MultilineBody => counts.lines += span,
            RedKind::Continuation => {
                counts.continuation_lines += span;
                counts.lines += span;
            }
        }
    }
    counts
}

/// A source line that a language's skeleton keeps: declarations,
/// signatures, imports. Everything else collapses into a single `{ ... }`
/// placeholder per contiguous dropped run so line numbers stay legible.
fn is_skeleton_line(language: &str, trimmed: &str) -> bool {
    match language {
        "rust" => {
            trimmed.starts_with("pub ")
                || trimmed.starts_with("fn ")
                || trimmed.starts_with("struct ")
                || trimmed.starts_with("enum ")
                || trimmed.starts_with("trait ")
                || trimmed.starts_with("impl ")
                || trimmed.starts_with("mod ")
                || trimmed.starts_with("use ")
                || trimmed.starts_with("type ")
                || trimmed.starts_with("const ")
                || trimmed.starts_with("static ")
                || trimmed.starts_with("#[")
                || trimmed.starts_with("//!")
                || trimmed.starts_with("///")
        }
        "typescript" | "javascript" => {
            trimmed.starts_with("export ")
                || trimmed.starts_with("import ")
                || trimmed.starts_with("function ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("interface ")
                || trimmed.starts_with("type ")
                || trimmed.starts_with("const ")
                || trimmed.starts_with("let ")
                || trimmed.starts_with("enum ")
                || trimmed.starts_with("async function ")
                || trimmed.starts_with("public ")
                || trimmed.starts_with("private ")
                || trimmed.starts_with("protected ")
        }
        "swift" => {
            trimmed.starts_with("import ")
                || trimmed.starts_with("func ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("struct ")
                || trimmed.starts_with("enum ")
                || trimmed.starts_with("protocol ")
                || trimmed.starts_with("extension ")
                || trimmed.starts_with("public ")
                || trimmed.starts_with("private ")
                || trimmed.starts_with("internal ")
                || trimmed.starts_with("static ")
                || trimmed.starts_with("@")
        }
        "python" => {
            trimmed.starts_with("import ")
                || trimmed.starts_with("from ")
                || trimmed.starts_with("def ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("@")
        }
        _ => false,
    }
}

/// Builds a SKELETON excerpt: kept declaration lines with their original
/// line numbers, dropped runs collapsed to a single `{ ... }` marker so the
/// lens still sees where bodies were, without their content.
fn skeletonize(
    language: &str,
    lines: &[RedLine],
    keep: &[(usize, usize)],
) -> (String, Vec<(usize, usize)>) {
    let mut out = String::new();
    let mut anchors = Vec::new();
    let mut in_drop_run = false;
    let mut drop_start = 0usize;
    let mut last_end = 0usize;

    for line in lines {
        let trimmed = line.text.trim_start();
        let forced = keep
            .iter()
            .any(|(start, end)| line.end >= *start && line.start <= *end);
        if forced || is_skeleton_line(language, trimmed) || trimmed.is_empty() {
            if in_drop_run {
                anchors.push((drop_start, line.start.saturating_sub(1)));
                out.push_str("    { ... }\n");
                in_drop_run = false;
            }
            out.push_str(&line.text);
            out.push('\n');
            anchors.push((line.start, line.end));
        } else if !in_drop_run {
            in_drop_run = true;
            drop_start = line.start;
        }
        last_end = line.end;
    }
    if in_drop_run {
        anchors.push((drop_start, last_end));
        out.push_str("    { ... }\n");
    }
    (out, anchors)
}

fn anchors_to_ranges(path: &str, anchors: &[(usize, usize)]) -> Vec<String> {
    // Merge adjacent/overlapping ranges into contiguous spans for a
    // compact anchor list.
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for &(start, end) in anchors {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 + 1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
        .into_iter()
        .map(|(start, end)| {
            if start == end {
                format!("{path}:{start}")
            } else {
                format!("{path}:{start}-{end}")
            }
        })
        .collect()
}

fn counts_for(lines: &[RedLine]) -> RedactionCounts {
    redaction_counts(lines)
}

/// Splits redacted lines into chunks of at most `MAX_BYTES_PER_FILE` bytes on
/// line boundaries. A chunk always holds at least one line. An empty file is
/// one empty chunk.
fn chunk_ranges_budgeted(lines: &[RedLine], cap_bytes: usize) -> Vec<std::ops::Range<usize>> {
    if lines.is_empty() {
        return vec![0..0];
    }
    let mut ranges = Vec::new();
    let mut start = 0usize;
    let mut size = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let bytes = line.text.len() + 1;
        if index > start && size + bytes > cap_bytes.max(1) {
            ranges.push(start..index);
            start = index;
            size = 0;
        }
        size += bytes;
    }
    ranges.push(start..lines.len());
    ranges
}

/// Substrings that mark an entrypoint or a dangerous sink; a `Regions`
/// excerpt keeps raw windows around the first few lines that carry one.
const SINK_MARKERS: &[&str] = &[
    "command::new",
    "std::process",
    "exec(",
    "spawn(",
    "eval(",
    "unsafe ",
    "unsafe{",
    "deserialize",
    "json.parse",
    "pickle.load",
    "yaml.load",
    "innerhtml",
    "child_process",
    "os.system",
    "subprocess",
    "tcplistener",
    "reqwest",
    "fetch(",
    "tauri::command",
    "fn main(",
    "decrypt",
    "keychain",
    "seckey",
];

/// Most sink windows one chunk keeps (flagged-finding and changed-hunk windows
/// are never capped).
const MAX_SINK_WINDOWS: usize = 6;

fn sink_ranges(lines: &[RedLine]) -> Vec<(usize, usize)> {
    lines
        .iter()
        .filter(|line| {
            let lower = line.text.to_ascii_lowercase();
            SINK_MARKERS.iter().any(|marker| lower.contains(marker))
        })
        .take(MAX_SINK_WINDOWS)
        .map(|line| (line.start, line.end))
        .collect()
}

/// Source-line windows a `Regions` chunk keeps raw: caller flags (findings,
/// changed hunks) plus entrypoint/sink lines, each widened by
/// `HUNK_CONTEXT_LINES`.
fn region_keep(lines: &[RedLine], flagged: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let total = lines.last().map_or(0, |line| line.end);
    let mut keep = hunk_windows(flagged, HUNK_CONTEXT_LINES, total);
    keep.extend(hunk_windows(&sink_ranges(lines), HUNK_CONTEXT_LINES, total));
    keep
}

fn excerpt_for_chunk(
    path: &str,
    mode: ExcerptMode,
    language: &'static str,
    lines: &[RedLine],
    chunk: usize,
    chunks: usize,
    flagged: &[(usize, usize)],
) -> Excerpt {
    let counts = counts_for(lines);
    let (content, anchors) = match mode {
        ExcerptMode::Raw => {
            let mut body = String::new();
            for line in lines {
                body.push_str(&line.text);
                body.push('\n');
            }
            let anchors = match (lines.first(), lines.last()) {
                (Some(first), Some(last)) => vec![format!("{path}:{}-{}", first.start, last.end)],
                _ => Vec::new(),
            };
            (body, anchors)
        }
        ExcerptMode::Skeleton => {
            let (body, ranges) = skeletonize(language, lines, &[]);
            (body, anchors_to_ranges(path, &ranges))
        }
        ExcerptMode::Regions => {
            let keep = region_keep(lines, flagged);
            let (body, ranges) = skeletonize(language, lines, &keep);
            (body, anchors_to_ranges(path, &ranges))
        }
    };
    Excerpt {
        path: path.to_owned(),
        source_side: "selected",
        mode,
        language,
        anchors,
        content,
        truncated: false,
        redacted: counts.lines > 0,
        start_line: lines.first().map_or(0, |line| line.start),
        end_line: lines.last().map_or(0, |line| line.end),
        chunk,
        chunks,
        redacted_ranges: lines
            .iter()
            .filter(|line| line.collapsed())
            .map(|line| format!("{path}:{}-{}", line.start, line.end))
            .collect(),
        redaction: counts,
    }
}

/// Resolve sealed source before excerpting. Baseline bytes never appear under
/// a selected-tree alias, and every snapshot read rechecks its bound digest.
pub(crate) fn source_bytes(
    root: &Path,
    path: &str,
    max_bytes: usize,
) -> Result<(Vec<u8>, crate::snapshot::SnapshotSide), &'static str> {
    let source = SourceReader::new(root).map_err(|_| "snapshot-invalid")?;
    let bytes = source.read(path, max_bytes)?;
    source.revalidate().map_err(|_| "snapshot-invalid")?;
    Ok(bytes)
}

/// One source admission spans all packet probes, providers & source-side
/// checks. Failed integrity is retained until the operation can return it.
pub(crate) struct SourceReader<'a> {
    root: &'a Path,
    snapshot: Option<(SnapshotAdmission, SnapshotSide)>,
    failure: RefCell<Option<AuditError>>,
}

impl<'a> SourceReader<'a> {
    pub(crate) fn admission(&self) -> Option<SnapshotAdmission> {
        self.snapshot
            .as_ref()
            .map(|(admission, _)| admission.clone())
    }
    pub(crate) fn new(root: &'a Path) -> Result<Self, AuditError> {
        let snapshot = crate::inventory::frozen_snapshot(root)
            .map_err(|error| {
                AuditError::SourceDrift(format!("Audit packet source admission failed: {error}"))
            })?
            .map(|(snapshot, side)| {
                FrozenSnapshot::operation_admission(&snapshot)
                    .map(|admission| (admission, side))
                    .map_err(|error| {
                        AuditError::SourceDrift(format!(
                            "Audit packet source admission failed: {error}"
                        ))
                    })
            })
            .transpose()?;
        Ok(Self {
            root,
            snapshot,
            failure: RefCell::new(None),
        })
    }

    fn failed(root: &'a Path, error: AuditError) -> Self {
        Self {
            root,
            snapshot: None,
            failure: RefCell::new(Some(error)),
        }
    }

    fn bounded(root: &'a Path) -> Self {
        Self::new(root).unwrap_or_else(|error| Self::failed(root, error))
    }

    pub(crate) fn source_sides(&self) -> std::collections::BTreeMap<String, String> {
        let mut sides = std::collections::BTreeMap::new();
        if let Some((admission, SnapshotSide::Selected)) = &self.snapshot {
            let snapshot = admission.snapshot();
            for path in &snapshot.manifest.scope.changed_paths {
                if !snapshot.manifest.files.contains_key(path)
                    && snapshot.manifest.base_files.contains_key(path)
                {
                    sides.insert(path.clone(), "base".into());
                }
            }
        }
        sides
    }

    pub(crate) fn revalidate(&self) -> Result<(), AuditError> {
        if let Some(error) = self.failure.borrow().as_ref() {
            return Err(error.clone());
        }
        if let Some((admission, side)) = &self.snapshot {
            let snapshot = admission.snapshot();
            let expected = match side {
                SnapshotSide::Selected => &snapshot.manifest.execution_root,
                SnapshotSide::Base => &snapshot.manifest.baseline_root,
            };
            let current = self.root.canonicalize().map_err(|error| {
                AuditError::SourceDrift(format!("Audit packet root changed: {error}"))
            })?;
            if &current != expected {
                return Err(AuditError::SourceDrift("Audit packet root changed".into()));
            }
            return admission.revalidate().map_err(|error| {
                AuditError::SourceDrift(format!("Audit packet source revalidation failed: {error}"))
            });
        }
        if crate::inventory::frozen_snapshot(self.root)
            .map_err(|error| {
                AuditError::SourceDrift(format!("Audit packet source revalidation failed: {error}"))
            })?
            .is_some()
        {
            return Err(AuditError::SourceDrift(
                "Audit packet source admission changed".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn read(
        &self,
        path: &str,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, SnapshotSide), &'static str> {
        if self.failure.borrow().is_some() {
            return Err("snapshot-invalid");
        }
        match &self.snapshot {
            Some((admission, root_side)) => {
                let snapshot = admission.snapshot();
                let side = if *root_side == SnapshotSide::Base
                    || !snapshot.manifest.files.contains_key(path)
                        && snapshot.manifest.scope.changed_paths.contains(path)
                        && snapshot.manifest.base_files.contains_key(path)
                {
                    SnapshotSide::Base
                } else {
                    SnapshotSide::Selected
                };
                let bytes = snapshot.read(path, side, max_bytes).map_err(|error| {
                if !matches!(&error, AuditError::Invalid(reason) if reason == "denied:snapshot-read-byte-cap") {
                    *self.failure.borrow_mut() = Some(AuditError::SourceDrift(format!("Audit packet source read failed: {error}")));
                }
                "snapshot-unavailable"
            })?;
                Ok((bytes, side))
            }
            None => {
                let root = self.root;
                let canonical_root = root.canonicalize().map_err(|_| "unreadable")?;
                let target = root.join(path).canonicalize().map_err(|_| "unreadable")?;
                if !target.starts_with(&canonical_root) {
                    return Err("path-outside-root");
                }
                let metadata = std::fs::metadata(&target).map_err(|_| "unreadable")?;
                if !metadata.is_file() || metadata.len() > max_bytes as u64 {
                    return Err("file-over-limit");
                }
                let bytes = std::fs::read(target).map_err(|_| "unreadable")?;
                if bytes.len() > max_bytes {
                    return Err("file-over-limit");
                }
                Ok((bytes, SnapshotSide::Selected))
            }
        }
    }

    pub(crate) fn head(&self, path: &str) -> Result<(String, bool), ()> {
        const CAP: usize = 64 * 1024;
        if self.snapshot.is_some() || self.failure.borrow().is_some() {
            let (bytes, _) = self.read(path, CAP).map_err(|_| ())?;
            return Ok((String::from_utf8_lossy(&bytes).into_owned(), false));
        }
        let root = self.root.canonicalize().map_err(|_| ())?;
        let path = self.root.join(path).canonicalize().map_err(|_| ())?;
        if !path.starts_with(root) {
            return Err(());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| ())?
            .take((CAP + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        let truncated = bytes.len() > CAP;
        bytes.truncate(CAP);
        Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
    }
}

/// Reads one file and returns every chunk of it, redacted before splitting
/// so a block can never straddle a chunk (or part) boundary unredacted.
/// `Err(reason)` names why the file cannot be excerpted at all: `unreadable`,
/// `binary` (NUL bytes), `non-utf8`, or `line-over-limit`.
fn prepare_file(root: &Path, path: &str, mode: ExcerptMode) -> Result<Vec<Excerpt>, &'static str> {
    prepare_file_scoped(root, path, mode, None, None)
}

/// `prepare_file`, optionally restricted to the merged hunk windows of a diff
/// scoped audit. Only RAW excerpts are windowed (a skeleton is already small
/// and gives the whole file's shape). The whole file is redacted first, so a
/// secret block can never straddle a window edge unredacted; each window is a
/// contiguous run of lines and is chunked on its own, so a chunk's anchors
/// stay exact.
fn prepare_file_scoped(
    root: &Path,
    path: &str,
    mode: ExcerptMode,
    hunks: Option<&[(usize, usize)]>,
    flagged: Option<&[(usize, usize)]>,
) -> Result<Vec<Excerpt>, &'static str> {
    prepare_file_scoped_budgeted(root, path, mode, hunks, flagged, MAX_BYTES_PER_FILE)
}

fn prepare_file_scoped_budgeted(
    root: &Path,
    path: &str,
    mode: ExcerptMode,
    hunks: Option<&[(usize, usize)]>,
    flagged: Option<&[(usize, usize)]>,
    chunk_cap: usize,
) -> Result<Vec<Excerpt>, &'static str> {
    let (bytes, side) = source_bytes(root, path, 32 * 1024 * 1024)?;
    prepare_validated_bytes(path, mode, hunks, flagged, chunk_cap, bytes, side)
}

fn prepare_file_with_source(
    source: &SourceReader<'_>,
    path: &str,
    mode: ExcerptMode,
    hunks: Option<&[(usize, usize)]>,
    flagged: Option<&[(usize, usize)]>,
    chunk_cap: usize,
) -> Result<Vec<Excerpt>, &'static str> {
    let (bytes, side) = source.read(path, 32 * 1024 * 1024)?;
    prepare_validated_bytes(path, mode, hunks, flagged, chunk_cap, bytes, side)
}

fn prepare_validated_bytes(
    path: &str,
    mode: ExcerptMode,
    hunks: Option<&[(usize, usize)]>,
    flagged: Option<&[(usize, usize)]>,
    chunk_cap: usize,
    bytes: Vec<u8>,
    side: SnapshotSide,
) -> Result<Vec<Excerpt>, &'static str> {
    if bytes.contains(&0) {
        return Err("binary");
    }
    let requested_mode = mode;
    let mode = effective_excerpt_mode(requested_mode, bytes.len() as u64);
    let text = String::from_utf8(bytes).map_err(|_| "non-utf8")?;
    let language = language_for(path);
    let lines = redact_lines(&text);
    if lines.iter().any(|line| line.text.len() > MAX_LINE_BYTES) {
        return Err("line-over-limit");
    }
    // Requested Skeleton already covers the whole file. Promotion preserves
    // that scope instead of silently restricting its newly Raw content to hunks.
    let hunks = hunks.filter(|hunks| !hunks.is_empty() && requested_mode == ExcerptMode::Raw);
    let mut ranges: Vec<std::ops::Range<usize>> = Vec::new();
    match hunks {
        None => ranges = chunk_ranges_budgeted(&lines, chunk_cap),
        Some(hunks) => {
            let total = lines.last().map_or(0, |line| line.end);
            let windows = hunk_windows(hunks, HUNK_CONTEXT_LINES, total);
            if windows.is_empty() {
                // Hunks outside the file (for example a pure deletion past
                // EOF): fall back to the whole file rather than excerpt nothing.
                ranges = chunk_ranges_budgeted(&lines, chunk_cap);
            }
            for (start, end) in windows {
                let first = lines.iter().position(|line| line.end >= start);
                let last = lines.iter().rposition(|line| line.start <= end);
                if let (Some(first), Some(last)) = (first, last) {
                    if first <= last {
                        for range in chunk_ranges_budgeted(&lines[first..=last], chunk_cap) {
                            ranges.push(first + range.start..first + range.end);
                        }
                    }
                }
            }
        }
    }
    let chunks = ranges.len();
    Ok(ranges
        .into_iter()
        .enumerate()
        .map(|(index, range)| {
            let mut excerpt = excerpt_for_chunk(
                path,
                mode,
                language,
                &lines[range],
                index + 1,
                chunks,
                flagged.unwrap_or(&[]),
            );
            excerpt.source_side = if side == crate::snapshot::SnapshotSide::Base {
                "base"
            } else {
                "selected"
            };
            excerpt
        })
        .collect())
}

/// Builds one file's FIRST chunk at `root`/`path` in the given mode, with
/// `truncated` set when the file continues past it. Returns `None` when the
/// file cannot be excerpted (unreadable, binary, non-UTF-8). Packets use
/// `partition_excerpts`, which never truncates.
pub fn build_excerpt(root: &Path, path: &str, mode: ExcerptMode) -> Option<Excerpt> {
    let mut chunks = prepare_file(root, path, mode).ok()?;
    let truncated = chunks.len() > 1;
    let mut first = chunks.swap_remove(0);
    first.truncated = truncated;
    Some(first)
}

/// Builds first-chunk excerpts for every path in `paths`, in order, applying
/// the total byte cap deterministically. Unreadable files are skipped rather
/// than aborting the whole batch. Packets use `partition_excerpts`.
pub fn build_excerpts(root: &Path, paths: &[String], mode: ExcerptMode) -> Vec<Excerpt> {
    build_excerpt_set(root, paths, mode).excerpts
}

/// A denominator path the packet carries no excerpt for.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OmittedExcerpt {
    pub path: String,
    /// `unreadable`, `binary`, `non-utf8`, `line-over-limit`, or (legacy
    /// `build_excerpt_set` only) `total-byte-cap`.
    pub reason: &'static str,
}

/// The excerpts one legacy batch carries plus every denominator path it does
/// not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExcerptSet {
    pub excerpts: Vec<Excerpt>,
    pub omitted: Vec<OmittedExcerpt>,
}

/// Single-batch, first-chunk-per-file builder with a total cap. Kept for
/// callers that want one bounded view; packets use `partition_excerpts`.
pub fn build_excerpt_set(root: &Path, paths: &[String], mode: ExcerptMode) -> ExcerptSet {
    let source = SourceReader::bounded(root);
    let mut total = 0usize;
    let mut excerpts = Vec::new();
    let mut omitted = Vec::new();
    for path in paths {
        if total >= MAX_TOTAL_EXCERPT_BYTES {
            omitted.push(OmittedExcerpt {
                path: path.clone(),
                reason: "total-byte-cap",
            });
            continue;
        }
        match prepare_file_with_source(&source, path, mode, None, None, MAX_BYTES_PER_FILE) {
            Ok(mut chunks) => {
                let truncated = chunks.len() > 1;
                let mut first = chunks.swap_remove(0);
                first.truncated = truncated;
                total += first.content.len();
                excerpts.push(first);
            }
            Err(reason) => omitted.push(OmittedExcerpt {
                path: path.clone(),
                reason,
            }),
        }
    }
    if source.revalidate().is_err() {
        return ExcerptSet {
            excerpts: Vec::new(),
            omitted: paths
                .iter()
                .map(|path| OmittedExcerpt {
                    path: path.clone(),
                    reason: "snapshot-invalid",
                })
                .collect(),
        };
    }
    ExcerptSet { excerpts, omitted }
}

/// One packet part: the excerpt chunks it carries, the denominator paths
/// "homed" in it (a path is homed where its first chunk, or its omission,
/// lands, so homed paths partition the denominator exactly), and the paths it
/// could not excerpt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExcerptPart {
    /// 1-based part number.
    pub number: usize,
    pub excerpts: Vec<Excerpt>,
    pub paths: Vec<String>,
    pub omitted: Vec<OmittedExcerpt>,
}

/// The whole denominator, partitioned deterministically into parts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Partition {
    /// At most `max_parts` parts, in stable path order.
    pub parts: Vec<ExcerptPart>,
    /// Parts the denominator needs. Exceeds `parts.len()` only when the
    /// provider ceiling dropped the tail.
    pub required_parts: usize,
    /// Paths with any chunk in a part the ceiling dropped (sorted).
    pub unscheduled_paths: Vec<String>,
}

/// Partitions `paths` (already in stable sorted order) into packet parts of
/// at most `MAX_TOTAL_EXCERPT_BYTES` of excerpt content each. Every path is
/// homed in exactly one part; files larger than `MAX_BYTES_PER_FILE` are
/// split into consecutive chunks, possibly across parts; only unreadable,
/// binary, non-UTF-8 or over-long-line files are omitted, with a named
/// reason. Deterministic: the same files and `max_parts` give identical
/// parts. Always returns at least one part.
pub fn partition_excerpts(
    root: &Path,
    paths: &[String],
    mode: ExcerptMode,
    max_parts: usize,
) -> Partition {
    partition_excerpts_scoped(root, paths, mode, max_parts, &ChangedHunks::new())
}

/// `partition_excerpts` for a diff scoped audit: a path with an entry in
/// `hunks` carries only its changed hunks plus `HUNK_CONTEXT_LINES` of context
/// (merged), every other path is excerpted whole.
pub fn partition_excerpts_scoped(
    root: &Path,
    paths: &[String],
    mode: ExcerptMode,
    max_parts: usize,
    hunks: &ChangedHunks,
) -> Partition {
    partition_excerpts_budgeted(root, paths, mode, max_parts, hunks, None)
}

/// Seat-derived sizing of one packet part. Without it a part holds at most
/// `MAX_TOTAL_EXCERPT_BYTES` of raw excerpt content. With it, each chunk is
/// charged its serialized JSON size plus `listing_copies` copies of the
/// per-path listings (`paths`, `examinedPaths`) every lens packet of the seat
/// carries, and a part closes at `cap_bytes` of that charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartBudget {
    pub cap_bytes: usize,
    pub listing_copies: usize,
}

// Model input contains canonical JSON excerpt values once. Pretty artifact
// indentation & transport-envelope escaping are not additional source cost.
// Final envelope sizing still measures contracts, listings & graph context.
fn rendered_excerpt_cost(excerpt: &Excerpt) -> usize {
    legion_contracts::canonical_json_bytes(excerpt)
        .map_or(usize::MAX, |bytes| bytes.len().saturating_add(1))
}

impl PartBudget {
    fn chunk_cost(&self, excerpt: &Excerpt) -> usize {
        rendered_excerpt_cost(excerpt) + self.listing_copies * (2 * excerpt.path.len() + 32)
    }
}

/// `partition_excerpts_scoped` with an optional seat-derived `PartBudget`.
pub fn partition_excerpts_budgeted(
    root: &Path,
    paths: &[String],
    mode: ExcerptMode,
    max_parts: usize,
    hunks: &ChangedHunks,
    budget: Option<PartBudget>,
) -> Partition {
    let source = SourceReader::bounded(root);
    let partition = partition_excerpts_with_source(&source, paths, mode, max_parts, hunks, budget);
    if let Err(error) = source.revalidate() {
        return partition_excerpts_with_source(
            &SourceReader::failed(root, error),
            paths,
            mode,
            max_parts,
            hunks,
            budget,
        );
    }
    partition
}

pub(crate) fn partition_excerpts_with_source(
    source: &SourceReader<'_>,
    paths: &[String],
    mode: ExcerptMode,
    max_parts: usize,
    hunks: &ChangedHunks,
    budget: Option<PartBudget>,
) -> Partition {
    let items: Vec<ReviewItem> = paths
        .iter()
        .map(|path| ReviewItem {
            path: path.clone(),
            mode,
        })
        .collect();
    partition_review_set_with_source(
        source,
        &items,
        &AliasMap::new(),
        max_parts,
        hunks,
        &FlaggedRegions::new(),
        budget,
    )
}

/// Serialized bytes `partition_review_set_budgeted` charges for `item`: every
/// chunk's JSON plus the per-copy path listings. It reads the file exactly as
/// the partition does (same mode, flagged regions and changed hunks), so
/// findings promotion can price promoted and displaced files in the cost the
/// dispatch estimator will see. An unreadable file costs only its listings.
pub fn review_item_cost(
    root: &Path,
    item: &ReviewItem,
    hunks: &ChangedHunks,
    flags: &FlaggedRegions,
    listing_copies: usize,
) -> usize {
    let source = SourceReader::bounded(root);
    let cost = review_item_cost_with_source(&source, item, hunks, flags, listing_copies);
    if source.revalidate().is_err() {
        return listing_copies * (2 * item.path.len() + 32);
    }
    cost
}

pub(crate) fn review_item_cost_with_source(
    source: &SourceReader<'_>,
    item: &ReviewItem,
    hunks: &ChangedHunks,
    flags: &FlaggedRegions,
    listing_copies: usize,
) -> usize {
    let path = &item.path;
    let mut regions: Vec<(usize, usize)> = Vec::new();
    if item.mode == ExcerptMode::Regions {
        if let Some(found) = flags.get(path) {
            regions.extend(found.iter().copied());
        }
        if let Some(found) = hunks.get(path) {
            regions.extend(found.iter().copied());
        }
    }
    let windowed = hunks.get(path).map(Vec::as_slice);
    let flagged = (!regions.is_empty()).then_some(regions.as_slice());
    let listing = |name: &str| listing_copies * (2 * name.len() + 32);
    match prepare_file_with_source(
        source,
        path,
        item.mode,
        windowed,
        flagged,
        MAX_BYTES_PER_FILE,
    ) {
        Err(_) => listing(path),
        Ok(chunks) => chunks
            .iter()
            .map(|excerpt| rendered_excerpt_cost(excerpt) + listing(&excerpt.path))
            .sum(),
    }
}

/// One review-set path and the excerpt mode it is read in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewItem {
    pub path: String,
    pub mode: ExcerptMode,
}

/// Source line ranges to keep raw in a `Regions` excerpt, per path (for
/// example deterministic findings), 1-based inclusive.
pub type FlaggedRegions = std::collections::BTreeMap<String, Vec<(usize, usize)>>;

/// Canonical path -> paths with identical content that are credited with the
/// canonical path's excerpt (content-digest dedup).
pub type AliasMap = std::collections::BTreeMap<String, Vec<String>>;

/// Partitions a frozen review set (path, mode) into packet parts. Behaves like
/// `partition_excerpts_scoped` (which delegates here) and additionally:
/// `Regions` items keep raw windows around `flags` and changed `hunks`;
/// `aliases` paths are homed (and omitted) with their canonical path, so the
/// homed paths still partition the credited set exactly.
pub fn partition_review_set(
    root: &Path,
    items: &[ReviewItem],
    aliases: &AliasMap,
    max_parts: usize,
    hunks: &ChangedHunks,
    flags: &FlaggedRegions,
) -> Partition {
    partition_review_set_budgeted(root, items, aliases, max_parts, hunks, flags, None)
}

/// `partition_review_set` with an optional seat-derived `PartBudget`; `None`
/// keeps the fixed `MAX_TOTAL_EXCERPT_BYTES` content cap.
pub fn partition_review_set_budgeted(
    root: &Path,
    items: &[ReviewItem],
    aliases: &AliasMap,
    max_parts: usize,
    hunks: &ChangedHunks,
    flags: &FlaggedRegions,
    budget: Option<PartBudget>,
) -> Partition {
    let source = SourceReader::bounded(root);
    let partition =
        partition_review_set_with_source(&source, items, aliases, max_parts, hunks, flags, budget);
    if let Err(error) = source.revalidate() {
        return partition_review_set_with_source(
            &SourceReader::failed(root, error),
            items,
            aliases,
            max_parts,
            hunks,
            flags,
            budget,
        );
    }
    partition
}

pub(crate) fn partition_review_set_with_source(
    source: &SourceReader<'_>,
    items: &[ReviewItem],
    aliases: &AliasMap,
    max_parts: usize,
    hunks: &ChangedHunks,
    flags: &FlaggedRegions,
    budget: Option<PartBudget>,
) -> Partition {
    let part_cap = budget.map_or(MAX_TOTAL_EXCERPT_BYTES, |budget| {
        budget.cap_bytes.min(MAX_TOTAL_EXCERPT_BYTES)
    });
    let max_parts = max_parts.max(1);
    let new_part = |number: usize| ExcerptPart {
        number,
        excerpts: Vec::new(),
        paths: Vec::new(),
        omitted: Vec::new(),
    };
    let mut parts = vec![new_part(1)];
    let mut bytes = 0usize;
    for item in items {
        let path = &item.path;
        let mut regions: Vec<(usize, usize)> = Vec::new();
        if item.mode == ExcerptMode::Regions {
            if let Some(found) = flags.get(path) {
                regions.extend(found.iter().copied());
            }
            if let Some(found) = hunks.get(path) {
                regions.extend(found.iter().copied());
            }
        }
        let windowed = hunks.get(path).map(Vec::as_slice);
        let flagged = (!regions.is_empty()).then_some(regions.as_slice());
        // Leave room for JSON escaping & source anchors. Small seat budgets
        // split source on whole lines instead of forcing a 32KiB chunk past
        // physical request limits. An indivisible long line refuses later.
        let chunk_cap = budget.map_or(MAX_BYTES_PER_FILE, |budget| {
            (budget.cap_bytes / 2).max(1).min(MAX_BYTES_PER_FILE)
        });
        match prepare_file_with_source(source, path, item.mode, windowed, flagged, chunk_cap) {
            Err(reason) => {
                let current = parts.last_mut().expect("at least one part");
                current.paths.push(path.clone());
                current.omitted.push(OmittedExcerpt {
                    path: path.clone(),
                    reason,
                });
                for alias in aliases.get(path).into_iter().flatten() {
                    current.paths.push(alias.clone());
                    current.omitted.push(OmittedExcerpt {
                        path: alias.clone(),
                        reason,
                    });
                }
            }
            Ok(chunks) => {
                for (index, excerpt) in chunks.into_iter().enumerate() {
                    let size =
                        budget.map_or(excerpt.content.len(), |budget| budget.chunk_cost(&excerpt));
                    if bytes > 0 && bytes + size > part_cap {
                        let number = parts.len() + 1;
                        parts.push(new_part(number));
                        bytes = 0;
                    }
                    let current = parts.last_mut().expect("at least one part");
                    if index == 0 {
                        current.paths.push(path.clone());
                        for alias in aliases.get(path).into_iter().flatten() {
                            current.paths.push(alias.clone());
                        }
                    }
                    bytes += size;
                    current.excerpts.push(excerpt);
                }
            }
        }
    }
    let required_parts = parts.len();
    let mut unscheduled = std::collections::BTreeSet::new();
    if required_parts > max_parts {
        for part in parts.drain(max_parts..) {
            unscheduled.extend(part.paths);
            unscheduled.extend(part.excerpts.into_iter().map(|excerpt| excerpt.path));
        }
    }
    Partition {
        parts,
        required_parts,
        unscheduled_paths: unscheduled.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct ScratchDir(PathBuf);
    impl ScratchDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "legion-audit-excerpts-test-{}-{}-{id}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let full = root.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, content).unwrap();
    }

    fn writable(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn packet_probes_share_admission_preserve_deleted_base_and_bound_structure_walks() {
        let fixture = crate::snapshot::tests::Fixture::new();
        let initial = fixture.capture(crate::scope::ScopeSpec::Local);
        let root = &initial.manifest.scope.source_root;
        let mut paths = vec!["file.rs".to_owned()];
        fs::remove_file(root.join("file.rs")).unwrap();
        for number in 0..24 {
            let path = format!("source-{number:02}.rs");
            write(root, &path, "pub fn source() { let value = 1; }\n");
            paths.push(path);
        }
        let snapshot = fixture.capture(crate::scope::ScopeSpec::Local);
        let before = crate::snapshot::structure_verification_count(&snapshot.manifest_path);
        let cold_before = crate::snapshot::full_verification_count(&snapshot.manifest_path);
        let source = SourceReader::new(&snapshot.manifest.execution_root).unwrap();
        assert_eq!(
            source.source_sides().get("file.rs").map(String::as_str),
            Some("base")
        );
        assert_eq!(
            source.read("file.rs", 5).unwrap(),
            (b"base\n".to_vec(), SnapshotSide::Base)
        );
        let hunks = ChangedHunks::new();
        let flags = FlaggedRegions::new();
        for probe in 1..=8 {
            for path in &paths {
                let item = ReviewItem {
                    path: path.clone(),
                    mode: ExcerptMode::Raw,
                };
                assert!(review_item_cost_with_source(&source, &item, &hunks, &flags, 3) > 0);
            }
            let partition = partition_excerpts_with_source(
                &source,
                &paths,
                ExcerptMode::Raw,
                128,
                &hunks,
                Some(PartBudget {
                    cap_bytes: probe * 256,
                    listing_copies: 3,
                }),
            );
            assert!(partition.unscheduled_paths.is_empty());
            assert!(partition.parts.iter().all(|part| part.omitted.is_empty()));
            assert_eq!(
                partition
                    .parts
                    .iter()
                    .map(|part| part.paths.len())
                    .sum::<usize>(),
                paths.len()
            );
            assert!(partition
                .parts
                .iter()
                .flat_map(|part| &part.excerpts)
                .any(|excerpt| excerpt.path == "file.rs" && excerpt.source_side == "base"));
        }
        source.revalidate().unwrap();
        let walks = crate::snapshot::structure_verification_count(&snapshot.manifest_path) - before;
        assert!((1..=5).contains(&walks));
        assert!(
            crate::snapshot::full_verification_count(&snapshot.manifest_path) - cold_before <= 2
        );
    }

    #[test]
    fn retained_packet_reader_rejects_boundary_drift_and_same_length_content_changes() {
        for mutation in ["manifest", "marker", "path-set", "root", "content"] {
            if mutation == "root" && !cfg!(unix) {
                continue;
            }
            let fixture = crate::snapshot::tests::Fixture::new();
            let snapshot = fixture.capture(crate::scope::ScopeSpec::Local);
            let root = &snapshot.manifest.execution_root;
            let source = SourceReader::new(root).unwrap();
            assert!(source.read("file.rs", 1).is_err()); // Raw byte cap stays enforced.
            source.revalidate().unwrap(); // Cap denial alone is an explicit omission.
            assert_eq!(source.read("file.rs", 5).unwrap().0, b"base\n");
            match mutation {
                "manifest" => {
                    writable(&snapshot.manifest_path);
                    let mut bytes = fs::read(&snapshot.manifest_path).unwrap();
                    bytes.push(b'\n');
                    fs::write(&snapshot.manifest_path, bytes).unwrap();
                }
                "marker" => {
                    let marker = root.join(".legion-audit-snapshot");
                    writable(&marker);
                    fs::write(marker, b"2\n").unwrap();
                }
                "path-set" => {
                    writable(root);
                    fs::write(root.join("added.rs"), b"added\n").unwrap();
                }
                "root" => {
                    writable(root.parent().unwrap());
                    writable(root);
                    fs::rename(root, root.with_file_name("selected-old")).unwrap();
                    fs::create_dir(root).unwrap();
                }
                "content" => {
                    let path = root.join("file.rs");
                    let modified = fs::metadata(&path).unwrap().modified().unwrap();
                    writable(&path);
                    fs::write(&path, b"fake\n").unwrap();
                    fs::OpenOptions::new()
                        .write(true)
                        .open(path)
                        .unwrap()
                        .set_times(fs::FileTimes::new().set_modified(modified))
                        .unwrap();
                    assert!(source.read("file.rs", 5).is_err());
                }
                _ => unreachable!(),
            }
            assert!(
                matches!(source.revalidate(), Err(AuditError::SourceDrift(_))),
                "{mutation}"
            );
        }
    }

    #[test]
    fn promotion_prices_same_canonical_excerpt_bytes_as_partition() {
        let dir = ScratchDir::new();
        let path = "source.rs";
        fs::write(
            dir.path().join(path),
            "pub fn quoted() { println!(\"quoted\"); }\n".repeat(8),
        )
        .unwrap();
        let item = ReviewItem {
            path: path.into(),
            mode: ExcerptMode::Raw,
        };
        let hunks = ChangedHunks::new();
        let flags = FlaggedRegions::new();
        let chunks = prepare_file_scoped(dir.path(), path, item.mode, None, None).unwrap();
        let canonical = chunks
            .iter()
            .map(|excerpt| {
                legion_contracts::canonical_json_bytes(excerpt)
                    .unwrap()
                    .len()
                    + 1
            })
            .sum::<usize>();
        assert_eq!(
            review_item_cost(dir.path(), &item, &hunks, &flags, 0),
            canonical
        );
        let listing_copies = 3;
        let listings = chunks.len() * listing_copies * (2 * path.len() + 32);
        assert_eq!(
            review_item_cost(dir.path(), &item, &hunks, &flags, listing_copies),
            canonical + listings
        );
        let budget = PartBudget {
            cap_bytes: 100_000,
            listing_copies,
        };
        assert_eq!(
            chunks
                .iter()
                .map(|excerpt| budget.chunk_cost(excerpt))
                .sum::<usize>(),
            canonical + listings
        );
        let pretty = chunks
            .iter()
            .map(|excerpt| serde_json::to_vec_pretty(excerpt).unwrap().len())
            .sum::<usize>();
        assert!(
            pretty > canonical,
            "artifact formatting must not buy extra promoted source"
        );
    }

    #[test]
    fn raw_excerpt_is_file_line_anchored_and_redacts_secrets() {
        // Built at runtime so secret scanners don't flag test data.
        let fake_key = ["sk", "live", "abcdefghijklmnopqrstuvwxyz"].join("_");
        let dir = ScratchDir::new();
        write(
            dir.path(),
            "src/x.rs",
            &format!(
                "fn a() {{}}\nlet API_KEY = \"{}\";\nfn b() {{}}\n",
                fake_key
            ),
        );
        let excerpt = build_excerpt(dir.path(), "src/x.rs", ExcerptMode::Raw).unwrap();
        assert_eq!(excerpt.mode, ExcerptMode::Raw);
        assert_eq!(excerpt.anchors, vec!["src/x.rs:1-3"]);
        assert!(excerpt.redacted);
        assert!(excerpt.content.contains("[REDACTED]"));
        assert!(!excerpt.content.contains(fake_key.as_str()));
    }

    #[test]
    fn skeleton_excerpt_keeps_signatures_and_drops_bodies() {
        let dir = ScratchDir::new();
        write(
            dir.path(),
            "src/y.rs",
            &format!("use std::fmt;\n\npub fn compute(x: i32) -> i32 {{\n    let y = x + 1;\n    y * 2\n}}\n{}", "\n".repeat(SMALL_FILE_RAW_BYTES as usize)),
        );
        let excerpt = build_excerpt(dir.path(), "src/y.rs", ExcerptMode::Skeleton).unwrap();
        assert_eq!(excerpt.mode, ExcerptMode::Skeleton);
        assert!(excerpt.content.contains("use std::fmt;"));
        assert!(excerpt.content.contains("pub fn compute(x: i32) -> i32 {"));
        assert!(!excerpt.content.contains("y * 2"));
        assert!(excerpt.content.contains("{ ... }"));
    }

    #[test]
    fn skeleton_covers_ts_swift_python() {
        let dir = ScratchDir::new();
        write(
            dir.path(),
            "a.ts",
            &format!(
                "export function f(x: number) {{\n  return x + 1;\n}}\n{}",
                "\n".repeat(SMALL_FILE_RAW_BYTES as usize)
            ),
        );
        write(
            dir.path(),
            "b.swift",
            &format!(
                "func f() {{\n  let y = 1\n}}\n{}",
                "\n".repeat(SMALL_FILE_RAW_BYTES as usize)
            ),
        );
        write(
            dir.path(),
            "c.py",
            &format!(
                "def f():\n    return 1\n{}",
                "\n".repeat(SMALL_FILE_RAW_BYTES as usize)
            ),
        );
        for (path, keep, drop) in [
            ("a.ts", "export function f(x: number) {", "return x + 1;"),
            ("b.swift", "func f() {", "let y = 1"),
            ("c.py", "def f():", "return 1"),
        ] {
            let excerpt = build_excerpt(dir.path(), path, ExcerptMode::Skeleton).unwrap();
            assert!(excerpt.content.contains(keep), "{path} missing {keep}");
            assert!(!excerpt.content.contains(drop), "{path} kept body {drop}");
        }
    }

    #[test]
    fn small_file_mode_uses_original_whole_bytes_before_chunking() {
        for size in [4095, 4096, 4097] {
            let mut bytes = b"pub fn boundary() {\n    body();\n}\n".to_vec();
            bytes.resize(size, b' ');
            let chunks = prepare_validated_bytes(
                "boundary.rs",
                ExcerptMode::Skeleton,
                None,
                None,
                64,
                bytes,
                SnapshotSide::Selected,
            )
            .unwrap();
            assert!(chunks.len() > 1);
            let expected = if size <= SMALL_FILE_RAW_BYTES as usize {
                ExcerptMode::Raw
            } else {
                ExcerptMode::Skeleton
            };
            assert!(chunks.iter().all(|chunk| chunk.mode == expected));
            assert!(chunks.iter().all(|chunk| chunk.source_side == "selected"));
        }
        assert_eq!(
            effective_excerpt_mode(ExcerptMode::Regions, 1),
            ExcerptMode::Regions
        );
        assert_eq!(
            effective_excerpt_mode(ExcerptMode::Raw, 4097),
            ExcerptMode::Raw
        );
        // Shrinking a large original via redaction must not trigger promotion.
        let mut bytes = b"password = <<EOT\n".to_vec();
        bytes.extend(std::iter::repeat_n(b'x', 4096));
        bytes.extend_from_slice(b"\nEOT\n");
        let chunks = prepare_validated_bytes(
            "secret.py",
            ExcerptMode::Skeleton,
            None,
            None,
            64,
            bytes,
            SnapshotSide::Selected,
        )
        .unwrap();
        assert!(chunks
            .iter()
            .all(|chunk| chunk.mode == ExcerptMode::Skeleton));
        assert!(chunks.iter().any(|chunk| chunk.redacted));
    }

    #[test]
    fn small_skeleton_preserves_whole_scope_base_identity_and_source_drift_refusal() {
        let text = "body();\n".repeat(100);
        let chunks = prepare_validated_bytes(
            "base.rs",
            ExcerptMode::Skeleton,
            Some(&[(80, 80)]),
            None,
            64,
            text.as_bytes().to_vec(),
            SnapshotSide::Base,
        )
        .unwrap();
        assert_eq!(chunks.first().unwrap().start_line, 1);
        assert_eq!(chunks.last().unwrap().end_line, 100);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.mode == ExcerptMode::Raw && chunk.source_side == "base"));
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.content.as_str())
                .collect::<String>(),
            text
        );
        assert_eq!(
            chunks.first().unwrap().anchors[0],
            format!("base.rs:1-{}", chunks.first().unwrap().end_line)
        );
        let fixture = crate::snapshot::tests::Fixture::new();
        let snapshot = fixture.capture(crate::scope::ScopeSpec::Local);
        let root = &snapshot.manifest.execution_root;
        let source = SourceReader::new(root).unwrap();
        let chunks =
            prepare_file_with_source(&source, "file.rs", ExcerptMode::Skeleton, None, None, 64)
                .unwrap();
        assert!(chunks.iter().all(|chunk| chunk.mode == ExcerptMode::Raw));
        let file = root.join("file.rs");
        writable(&file);
        fs::write(file, b"fake\n").unwrap();
        assert!(prepare_file_with_source(
            &source,
            "file.rs",
            ExcerptMode::Skeleton,
            None,
            None,
            64
        )
        .is_err());
        assert!(matches!(
            source.revalidate(),
            Err(AuditError::SourceDrift(_))
        ));
    }

    #[test]
    fn small_source_controls_deliver_contract_caller_and_body_spans() {
        // Real corpus bytes exercise all four naming/dead-file cases. Expectations
        // remain test input only; production mode selection knows file size alone.
        let corpus: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../../../evals/audit-bench/capsules/core.json"
        ))
        .unwrap();
        let dir = ScratchDir::new();
        let mut cases = 0;
        for capsule in corpus["capsules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|capsule| ["naming", "dead-file"].contains(&capsule["lens"].as_str().unwrap()))
        {
            for case in capsule["cases"].as_array().unwrap() {
                cases += 1;
                for (path, value) in case["files"].as_object().unwrap() {
                    let source = value.as_str().unwrap();
                    assert!(source.len() <= SMALL_FILE_RAW_BYTES as usize);
                    write(dir.path(), path, source);
                    let excerpt = build_excerpt(dir.path(), path, ExcerptMode::Skeleton).unwrap();
                    assert_eq!(excerpt.mode, ExcerptMode::Raw);
                    assert_eq!(excerpt.content, source);
                    assert!(!excerpt.redacted && !excerpt.truncated);
                    for span in case["requiredEvidence"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|span| span["path"] == path.as_str())
                    {
                        let range = span["lineRange"].as_array().unwrap();
                        for line in range[0].as_u64().unwrap()..=range[1].as_u64().unwrap() {
                            assert_eq!(
                                excerpt.content.lines().nth(line as usize - 1),
                                source.lines().nth(line as usize - 1)
                            );
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 4);
    }

    #[test]
    fn promoted_raw_cost_matches_delivery_under_tight_partition_limits() {
        let dir = ScratchDir::new();
        let text = "    body();\n".repeat(250);
        write(dir.path(), "small.rs", &text);
        let skeleton = ReviewItem {
            path: "small.rs".into(),
            mode: ExcerptMode::Skeleton,
        };
        let raw = ReviewItem {
            path: "small.rs".into(),
            mode: ExcerptMode::Raw,
        };
        let hunks = ChangedHunks::new();
        let flags = FlaggedRegions::new();
        assert_eq!(
            review_item_cost(dir.path(), &skeleton, &hunks, &flags, 3),
            review_item_cost(dir.path(), &raw, &hunks, &flags, 3)
        );
        let budget = PartBudget {
            cap_bytes: 1200,
            listing_copies: 3,
        };
        let partition = partition_review_set_budgeted(
            dir.path(),
            &[skeleton],
            &AliasMap::new(),
            128,
            &hunks,
            &flags,
            Some(budget),
        );
        assert!(partition.required_parts > 1);
        assert!(partition.unscheduled_paths.is_empty());
        assert!(partition.parts.iter().all(|part| part.omitted.is_empty()
            && part
                .excerpts
                .iter()
                .all(|excerpt| excerpt.mode == ExcerptMode::Raw)
            && part
                .excerpts
                .iter()
                .map(|excerpt| budget.chunk_cost(excerpt))
                .sum::<usize>()
                <= budget.cap_bytes));
        assert_eq!(
            partition
                .parts
                .iter()
                .flat_map(|part| &part.excerpts)
                .map(|excerpt| excerpt.content.as_str())
                .collect::<String>(),
            text
        );
        let bounded = partition_review_set_budgeted(
            dir.path(),
            &[raw],
            &AliasMap::new(),
            1,
            &hunks,
            &flags,
            Some(budget),
        );
        assert_eq!(bounded.parts.len(), 1);
        assert_eq!(bounded.unscheduled_paths, vec!["small.rs"]);
    }

    #[test]
    fn missing_file_returns_none() {
        let dir = ScratchDir::new();
        assert!(build_excerpt(dir.path(), "nope.rs", ExcerptMode::Raw).is_none());
    }

    #[test]
    fn build_excerpts_respects_total_byte_cap_deterministically() {
        let dir = ScratchDir::new();
        let big = "x".repeat(MAX_BYTES_PER_FILE);
        // 20 files at the per-file cap comfortably exceed MAX_TOTAL_EXCERPT_BYTES.
        let file_count = (MAX_TOTAL_EXCERPT_BYTES / MAX_BYTES_PER_FILE) + 4;
        let mut paths = Vec::new();
        for i in 0..file_count {
            let name = format!("f{i:02}.rs");
            write(dir.path(), &name, &big);
            paths.push(name);
        }
        let excerpts = build_excerpts(dir.path(), &paths, ExcerptMode::Raw);
        assert!(excerpts.len() < file_count, "cap did not bound the batch");
        assert_eq!(excerpts[0].path, "f00.rs");
    }

    #[test]
    fn excerpt_set_reconciles_every_path_it_does_not_carry() {
        let dir = ScratchDir::new();
        let big = "x".repeat(MAX_BYTES_PER_FILE);
        let file_count = (MAX_TOTAL_EXCERPT_BYTES / MAX_BYTES_PER_FILE) + 4;
        let mut paths = Vec::new();
        for i in 0..file_count {
            let name = format!("f{i:02}.rs");
            write(dir.path(), &name, &big);
            paths.push(name);
        }
        paths.push("gone.rs".to_owned());
        let set = build_excerpt_set(dir.path(), &paths, ExcerptMode::Raw);
        // Every denominator path is either excerpted or omitted with a reason.
        assert_eq!(set.excerpts.len() + set.omitted.len(), paths.len());
        assert!(set
            .omitted
            .iter()
            .any(|omitted| omitted.reason == "total-byte-cap"));
        // Cap omissions precede the unreadable file in input order, so the
        // unreadable path is reported by the cap, never silently dropped.
        assert!(set.omitted.iter().any(|omitted| omitted.path == "gone.rs"));
    }

    fn fake_pem_block(label: &str, body_lines: usize) -> String {
        // Assembled from fragments so this file holds no key-like literal.
        let dashes = "-".repeat(5);
        let mut out = format!("{dashes}BEGIN {label}{dashes}\n");
        for index in 0..body_lines {
            out.push_str(&format!(
                "QUJD{index:04}RUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3\n"
            ));
        }
        out.push_str(&format!("{dashes}END {label}{dashes}\n"));
        out
    }

    #[test]
    fn pem_block_collapses_to_one_line_and_keeps_source_numbering() {
        let source = format!(
            "fn a() {{}}\n{}fn b() {{}}\n",
            fake_pem_block("TEST BLOCK", 6)
        );
        let lines = redact_lines(&source);
        let block = lines
            .iter()
            .find(|line| line.kind == RedKind::Pem)
            .expect("block collapsed");
        assert_eq!(block.text, "[REDACTED PEM BLOCK 8 lines]");
        assert_eq!((block.start, block.end), (2, 9));
        assert_eq!(lines.last().unwrap().start, 10);
        assert!(!lines.iter().any(|line| line.text.contains("QUJD")));
    }

    #[test]
    fn unterminated_pem_block_stops_at_the_line_limit() {
        let dashes = "-".repeat(5);
        let mut source = format!("{dashes}BEGIN TEST BLOCK{dashes}\n");
        for index in 0..400 {
            source.push_str(&format!(
                "QUJD{index:04}RUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3\n"
            ));
        }
        let lines = redact_lines(&source);
        assert_eq!(lines[0].end - lines[0].start + 1, MAX_BLOCK_LINES);
        // The lines past the limit still look like base64 continuation of a
        // redacted line, so they are folded rather than leaked.
        assert!(lines.iter().all(|line| !line.text.contains("QUJD")));
    }

    #[test]
    fn multiline_quoted_and_heredoc_secrets_are_collapsed() {
        let source = "let api_key = \"first\nsecond-line-of-it\nthird\";\nafter();\n\
                      password = <<EOT\nhunter-two\nEOT\nend();\n";
        let (text, counts) = redact_text(source);
        assert!(!text.contains("second-line-of-it"));
        assert!(!text.contains("hunter-two"));
        assert!(text.contains("after();"));
        assert!(text.contains("end();"));
        assert_eq!(counts.multiline_secrets, 2);
    }

    #[test]
    fn promoted_skeleton_excerpts_are_redacted_too() {
        let dir = ScratchDir::new();
        let fake_key = ["sk", "live", "abcdefghijklmnopqrstuvwxyz"].join("_");
        write(
            dir.path(),
            "src/k.rs",
            &format!("pub const API_KEY: &str = \"{fake_key}\";\npub fn f() {{}}\n"),
        );
        let excerpt = build_excerpt(dir.path(), "src/k.rs", ExcerptMode::Skeleton).unwrap();
        assert_eq!(excerpt.mode, ExcerptMode::Raw);
        assert!(excerpt.redacted);
        assert!(!excerpt.content.contains(fake_key.as_str()));
    }

    #[test]
    fn large_file_is_chunked_on_line_boundaries_and_every_line_is_covered() {
        let dir = ScratchDir::new();
        let source = (1..=4000)
            .map(|index| format!("// line number {index:05} padding padding"))
            .collect::<Vec<_>>()
            .join("\n");
        write(dir.path(), "big.rs", &source);
        let partition = partition_excerpts(
            dir.path(),
            &["big.rs".to_owned()],
            ExcerptMode::Raw,
            DEFAULT_MAX_PARTS,
        );
        let chunks: Vec<&Excerpt> = partition
            .parts
            .iter()
            .flat_map(|part| part.excerpts.iter())
            .collect();
        assert!(chunks.len() > 1);
        let mut next = 1usize;
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.chunk, index + 1);
            assert_eq!(chunk.chunks, chunks.len());
            assert_eq!(chunk.start_line, next);
            assert!(chunk.content.len() <= MAX_BYTES_PER_FILE + 64);
            next = chunk.end_line + 1;
        }
        assert_eq!(next - 1, 4000);
    }

    #[test]
    fn hunk_windows_widen_clamp_and_merge() {
        // 30..32 widens to 10..52, 60..60 to 40..80 (merges), 300 is past EOF.
        assert_eq!(
            hunk_windows(&[(60, 60), (30, 32), (300, 301)], 20, 200),
            vec![(10, 80)]
        );
        // Clamped at both file edges; disjoint windows stay separate.
        assert_eq!(
            hunk_windows(&[(2, 3), (190, 200)], 20, 200),
            vec![(1, 23), (170, 200)]
        );
        // Touching windows merge (end + 1 == next start).
        assert_eq!(hunk_windows(&[(1, 1), (42, 42)], 20, 100), vec![(1, 62)]);
        assert!(hunk_windows(&[(1, 1)], 20, 0).is_empty());
    }

    #[test]
    fn diff_scoped_partition_carries_changed_hunks_with_context_not_whole_files() {
        let dir = ScratchDir::new();
        let body: String = (1..=500)
            .map(|n| format!("let line_{n} = {n};\n"))
            .collect();
        write(dir.path(), "src/changed.rs", &body);
        write(dir.path(), "src/untouched_by_diff.rs", &body);
        let paths = vec![
            "src/changed.rs".to_owned(),
            "src/untouched_by_diff.rs".to_owned(),
        ];
        let mut hunks = ChangedHunks::new();
        hunks.insert("src/changed.rs".into(), vec![(100, 102), (400, 400)]);
        let partition = partition_excerpts_scoped(dir.path(), &paths, ExcerptMode::Raw, 8, &hunks);
        assert_eq!(partition.parts.len(), 1);
        let carried = &partition.parts[0].excerpts;
        let changed: Vec<&Excerpt> = carried
            .iter()
            .filter(|excerpt| excerpt.path == "src/changed.rs")
            .collect();
        // Two disjoint windows: 80..122 and 380..420 (+/-20 context).
        assert_eq!(changed.len(), 2);
        assert_eq!((changed[0].start_line, changed[0].end_line), (80, 122));
        assert_eq!((changed[1].start_line, changed[1].end_line), (380, 420));
        assert_eq!(changed[0].anchors, vec!["src/changed.rs:80-122".to_owned()]);
        assert!(changed.iter().all(|excerpt| excerpt.chunks == 2));
        assert!(changed[0].content.contains("let line_100 = 100;"));
        assert!(!changed[0].content.contains("let line_79 = 79;"));
        assert!(!changed[1].content.contains("let line_500 = 500;"));
        // A path with no hunk entry is excerpted whole.
        let whole: Vec<&Excerpt> = carried
            .iter()
            .filter(|excerpt| excerpt.path == "src/untouched_by_diff.rs")
            .collect();
        assert_eq!(whole.len(), 1);
        assert_eq!((whole[0].start_line, whole[0].end_line), (1, 500));
        // Both paths are homed exactly once.
        assert_eq!(partition.parts[0].paths, paths);
    }

    #[test]
    fn regions_excerpt_keeps_flagged_window_anchors_and_redacts() {
        let fake_key = ["sk", "live", "abcdefghijklmnopqrstuvwxyz"].join("_");
        let dir = ScratchDir::new();
        let mut body = String::from("use std::fmt;\n");
        for n in 0..200 {
            body.push_str(&format!("let filler_{n} = {n};\n"));
        }
        body.push_str(&format!("let API_KEY = \"{fake_key}\";\n"));
        for n in 0..200 {
            body.push_str(&format!("let tail_{n} = {n};\n"));
        }
        write(dir.path(), "src/r.rs", &body);
        let items = vec![ReviewItem {
            path: "src/r.rs".into(),
            mode: ExcerptMode::Regions,
        }];
        let mut flags = FlaggedRegions::new();
        // Flag the line carrying the secret (line 202) plus one early line.
        flags.insert("src/r.rs".into(), vec![(202, 202), (50, 50)]);
        let partition = partition_review_set(
            dir.path(),
            &items,
            &AliasMap::new(),
            8,
            &ChangedHunks::new(),
            &flags,
        );
        let excerpt = &partition.parts[0].excerpts[0];
        assert_eq!(excerpt.mode, ExcerptMode::Regions);
        assert!(excerpt.content.contains("use std::fmt;"));
        assert!(
            excerpt.content.contains("let filler_49 = 49;"),
            "window around 50"
        );
        assert!(excerpt.content.contains("[REDACTED]"));
        assert!(!excerpt.content.contains(fake_key.as_str()));
        assert!(!excerpt.content.contains("let filler_120 = 120;"));
        assert!(excerpt.content.contains("{ ... }"));
        // Anchors are source-file line numbers and cover the secret window.
        assert!(excerpt.anchors.iter().any(|anchor| {
            let range = anchor.trim_start_matches("src/r.rs:");
            let (start, end) = range.split_once('-').unwrap_or((range, range));
            let (start, end): (usize, usize) = (start.parse().unwrap(), end.parse().unwrap());
            start <= 202 && 202 <= end
        }));
        assert!(excerpt.content.len() < body.len() / 2, "regions compress");
    }

    #[test]
    fn aliases_are_homed_with_their_canonical_path() {
        let dir = ScratchDir::new();
        write(dir.path(), "a/x.rs", "pub fn f() {}\n");
        write(dir.path(), "b/x.rs", "pub fn f() {}\n");
        let items = vec![ReviewItem {
            path: "a/x.rs".into(),
            mode: ExcerptMode::Skeleton,
        }];
        let mut aliases = AliasMap::new();
        aliases.insert("a/x.rs".into(), vec!["b/x.rs".into()]);
        let partition = partition_review_set(
            dir.path(),
            &items,
            &aliases,
            8,
            &ChangedHunks::new(),
            &FlaggedRegions::new(),
        );
        assert_eq!(partition.parts[0].paths, vec!["a/x.rs", "b/x.rs"]);
        assert_eq!(partition.parts[0].excerpts.len(), 1);
    }
}
