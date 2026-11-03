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
        return std::iter::once(0..0).collect();
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
    rightkit_evidence_contracts::canonical_json_bytes(excerpt)
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
            (budget.cap_bytes / 2).clamp(1, MAX_BYTES_PER_FILE)
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
