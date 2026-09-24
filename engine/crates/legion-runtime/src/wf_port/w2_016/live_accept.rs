//! Port of `skills/designer/engine/scripts/live-accept.mjs` (chunk w2_016,
//! packet r17).
//!
//! Deterministic accept/discard of "live variant" wrapper markers written
//! into a source file by `live-wrap` (not in this chunk). This port covers:
//! - the pure marker/HTML-parsing core: finding a session's marker block,
//!   extracting the original/variant/CSS content, deindenting, building the
//!   "carbonize" replacement, and applying discard/accept to a file's lines
//!   (HTML/JSX/Vue/Astro path);
//! - dispatch into [`crate::wf_port::w2_016::svelte_component`] for the
//!   Svelte-component accept path;
//! - the on-disk pending-manual-edits buffer read/write used by
//!   `scrub_manual_edits_against_original_block_on_disk`, mirroring just
//!   enough of `./live/manual-edits-buffer.mjs` (`readBuffer`/`writeBuffer`)
//!   for this file's own call site — the rest of that sibling module
//!   (`stageEntry`, `removeEntries`, `countByPage`, `truncateBuffer`) is a
//!   separate legacy file, out of this packet's scope;
//! - the `acceptCli()` CLI argv entrypoint, ported as [`run`] (parses
//!   `process.argv`-equivalent `&[String]`, returns `(exit_code, stdout)`
//!   instead of calling `process.exit`/`console.log` directly so callers can
//!   choose how to surface it).
//!
//! GAP: none remaining against the JS source for this file's owned scope.

use crate::p8_designer::{is_generated_file, IsGeneratedOptions};
use crate::wf_port::w2_016::impeccable_paths::get_live_dir;
use crate::wf_port::w2_016::svelte_component;
// Re-exported for parity with the JS module's own bottom-of-file export
// list (`export { ..., applyDeferredSvelteComponentAccepts }`).
pub use crate::wf_port::w2_016::svelte_component::apply_deferred_svelte_component_accepts;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

const EXTENSIONS: [&str; 5] = [".html", ".jsx", ".tsx", ".vue", ".svelte"];
// NOTE: JS EXTENSIONS also includes `.astro`; kept identical below via a
// separate list to avoid a magic mismatch with the JS array literal order.
const EXTENSIONS_WITH_ASTRO: [&str; 6] = [".html", ".jsx", ".tsx", ".vue", ".svelte", ".astro"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkerBlock {
    pub start: usize,
    pub end: usize,
}

/// Mirrors `findMarkerBlock(id, lines)`.
pub fn find_marker_block(id: &str, lines: &[String]) -> Option<MarkerBlock> {
    let start_pattern = format!("impeccable-variants-start {id}");
    let end_pattern = format!("impeccable-variants-end {id}");
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        if start.is_none() && line.contains(&start_pattern) {
            start = Some(i);
        }
        if line.contains(&end_pattern) {
            end = Some(i);
            break;
        }
    }
    match (start, end) {
        (Some(s), Some(e)) => Some(MarkerBlock { start: s, end: e }),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommentSyntax {
    pub open: &'static str,
    pub close: &'static str,
}

/// Mirrors `detectCommentSyntax(filePath)`.
pub fn detect_comment_syntax(file_path: &Path) -> CommentSyntax {
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    if ext == "jsx" || ext == "tsx" {
        CommentSyntax { open: "{/*", close: "*/}" }
    } else {
        CommentSyntax { open: "<!--", close: "-->" }
    }
}

fn escape_regex(value: &str) -> String {
    regex::escape(value)
}

fn is_variant_end_marker_line(line: &str, id: &str) -> bool {
    let re = Regex::new(&format!(
        r"impeccable-variants-end\s+{}(?:\s|--|\*/|$)",
        escape_regex(id)
    ))
    .unwrap();
    re.is_match(line)
}

fn has_variant_wrapper_attr(line: &str, id: &str) -> bool {
    let escaped = escape_regex(id);
    let re = Regex::new(&format!(
        r#"data-impeccable-variants\s*=\s*(?:"{escaped}"|'{escaped}'|\{{["']{escaped}["']\}})"#
    ))
    .unwrap();
    re.is_match(line)
}

/// Mirrors `expandReplaceRange(block, lines, isJsx)`.
pub fn expand_replace_range(block: MarkerBlock, lines: &[String], id: &str, is_jsx: bool) -> MarkerBlock {
    if !is_jsx {
        return block;
    }
    let mut start = block.start;
    let mut end = block.end;

    let mut i = start as isize - 1;
    while i >= 0 {
        let idx = i as usize;
        if is_variant_end_marker_line(&lines[idx], id) {
            break;
        }
        if has_variant_wrapper_attr(&lines[idx], id) {
            let mut opener = idx;
            let div_re = Regex::new(r"<div\b").unwrap();
            while opener > 0 && !div_re.is_match(&lines[opener]) && !is_variant_end_marker_line(&lines[opener], id) {
                opener -= 1;
            }
            if div_re.is_match(&lines[opener]) {
                start = opener;
            }
            break;
        }
        i -= 1;
    }

    let joined = lines[start..].join("\n");
    let tag_re = Regex::new(r"<div\b[^>]*?(/?)>|</div\s*>").unwrap();
    let mut depth: i64 = 0;
    for m in tag_re.captures_iter(&joined) {
        let whole = m.get(0).unwrap();
        let is_close = whole.as_str().starts_with("</");
        let is_self_close = !is_close && m.get(1).map(|g| g.as_str()) == Some("/");
        if is_close {
            depth -= 1;
        } else if !is_self_close {
            depth += 1;
        }
        if depth <= 0 {
            let end_byte = whole.end();
            let lines_before = joined[..end_byte].matches('\n').count();
            let candidate_end = start + lines_before;
            if candidate_end >= end {
                end = candidate_end;
                break;
            }
        }
    }

    MarkerBlock { start, end }
}

/// Join wrapper lines with `<style>` elements stripped, mirroring
/// `stripStyleAndJoin`.
fn strip_style_and_join(lines: &[String], block: MarkerBlock) -> String {
    static COMPLETE_STYLE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?s)<style\b[^>]*>.*?</style\s*>").unwrap());
    static SELF_CLOSE_STYLE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"<style\b[^>]*/\s*>").unwrap());
    static OPENER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<style\b").unwrap());
    static CLOSER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"</style\s*>").unwrap());

    let mut out: Vec<String> = Vec::new();
    let mut in_style = false;
    for line in &lines[block.start..=block.end] {
        let mut line = line.clone();
        if !in_style {
            line = COMPLETE_STYLE_RE.replace_all(&line, "").to_string();
            line = SELF_CLOSE_STYLE_RE.replace_all(&line, "").to_string();
            if let Some(m) = OPENER_RE.find(&line) {
                let opener_idx = m.start();
                line = line[..opener_idx].to_string();
                in_style = true;
            }
            out.push(line);
        } else if let Some(m) = CLOSER_RE.find(&line) {
            in_style = false;
            out.push(CLOSER_RE.replace(&line[m.start()..], "").to_string());
        }
        // else: skip line entirely (still inside multi-line style body)
    }
    out.join("\n")
}

/// Mirrors `extractInnerByAttr(text, attrMatch)`.
fn extract_inner_by_attr(text: &str, attr_match: &str) -> Option<String> {
    let opener_re =
        Regex::new(&format!(r"<([A-Za-z][A-Za-z0-9]*)\b[^>]*{attr_match}[^>]*>")).ok()?;
    let open_match = opener_re.find(text)?;
    let caps = opener_re.captures(text)?;
    let tag_name = caps.get(1)?.as_str();
    let inner_start = open_match.end();

    let tag_re = Regex::new(&format!(r"</?{}\b[^>]*>", regex::escape(tag_name))).ok()?;
    let mut depth = 1i64;
    for m in tag_re.find_iter(&text[inner_start..]) {
        let whole = m.as_str();
        let is_close = whole.starts_with("</");
        let is_self_close = !is_close && whole.trim_end().ends_with("/>");
        if is_close {
            depth -= 1;
            if depth == 0 {
                return Some(text[inner_start..inner_start + m.start()].to_string());
            }
        } else if !is_self_close {
            depth += 1;
        }
    }
    None
}

/// Mirrors `extractOriginal(lines, block)`.
pub fn extract_original(lines: &[String], block: MarkerBlock) -> Vec<String> {
    let text = strip_style_and_join(lines, block);
    match extract_inner_by_attr(&text, r#"data-impeccable-variant="original""#) {
        Some(inner) => inner.split('\n').map(|s| s.to_string()).collect(),
        None => Vec::new(),
    }
}

/// Mirrors `extractVariant(lines, block, variantNum)`.
pub fn extract_variant(lines: &[String], block: MarkerBlock, variant_num: &str) -> Option<Vec<String>> {
    let text = strip_style_and_join(lines, block);
    let attr = format!(r#"data-impeccable-variant="{variant_num}""#);
    let inner = extract_inner_by_attr(&text, &attr)?;
    let mut result: Vec<String> = inner.split('\n').map(|s| s.to_string()).collect();
    while result.len() > 1 && result.first().map(|s| s.trim().is_empty()).unwrap_or(false) {
        result.remove(0);
    }
    while result.len() > 1 && result.last().map(|s| s.trim().is_empty()).unwrap_or(false) {
        result.pop();
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Mirrors `extractCss(lines, block, id)`.
pub fn extract_css(lines: &[String], block: MarkerBlock, id: &str) -> Option<Vec<String>> {
    let style_attr = format!(r#"data-impeccable-css="{id}""#);
    let mut in_style = false;
    let mut content: Vec<String> = Vec::new();

    static SELF_CLOSE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"<style\b[^>]*/\s*>").unwrap());
    static SAME_LINE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?s)<style\b[^>]*>(.*?)</style\s*>").unwrap());

    for line in &lines[block.start..=block.end] {
        if !in_style && line.contains(&style_attr) {
            if SELF_CLOSE_RE.is_match(line) {
                return None;
            }
            if let Some(caps) = SAME_LINE_RE.captures(line) {
                let inner = strip_jsx_template_wrap(&caps[1]);
                return if inner.is_empty() {
                    None
                } else {
                    Some(inner.split('\n').map(|s| s.to_string()).collect())
                };
            }
            in_style = true;
            continue;
        }
        if in_style {
            if let Some(close_idx) = line.find("</style>") {
                let _ = close_idx;
                break;
            }
            content.push(line.clone());
        }
    }

    if content.is_empty() {
        None
    } else {
        strip_jsx_template_lines(&content)
    }
}

/// Mirrors `stripJsxTemplateLines(content)`.
fn strip_jsx_template_lines(content: &[String]) -> Option<Vec<String>> {
    let mut out: Vec<String> = content.to_vec();
    while out.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
        out.remove(0);
    }
    while out.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        out.pop();
    }
    if out.is_empty() {
        return None;
    }

    let first_trim = out[0].trim_start().to_string();
    if first_trim == "{`" {
        out.remove(0);
    } else if let Some(idx) = out[0].find("{`") {
        if first_trim.starts_with("{`") {
            let mut s = out[0].clone();
            s.replace_range(idx..idx + 2, "");
            if s.trim().is_empty() {
                out.remove(0);
            } else {
                out[0] = s;
            }
        }
    }
    if out.is_empty() {
        return None;
    }

    let last_idx = out.len() - 1;
    let last_trim = out[last_idx].trim_end().to_string();
    if last_trim == "`}" {
        out.pop();
    } else if last_trim.ends_with("`}") {
        let text = out[last_idx].clone();
        if let Some(idx) = text.rfind("`}") {
            let mut s = text;
            s.replace_range(idx..idx + 2, "");
            if s.trim().is_empty() {
                out.pop();
            } else {
                out[last_idx] = s;
            }
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn strip_jsx_template_wrap(text: &str) -> String {
    let lines: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
    match strip_jsx_template_lines(&lines) {
        Some(stripped) => stripped.join("\n"),
        None => String::new(),
    }
}

/// Mirrors `deindentContent(contentLines, baseIndent)`.
pub fn deindent_content(content_lines: &[String], base_indent: &str) -> Vec<String> {
    let mut min_indent = usize::MAX;
    for line in content_lines {
        if line.trim().is_empty() {
            continue;
        }
        let leading = line.len() - line.trim_start().len();
        min_indent = min_indent.min(leading);
    }
    if min_indent == usize::MAX {
        min_indent = 0;
    }
    content_lines
        .iter()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else {
                format!("{base_indent}{}", &line[min_indent.min(line.len())..])
            }
        })
        .collect()
}

fn reindent_content(content_lines: &[String], from_indent: &str, to_indent: &str) -> Vec<String> {
    content_lines
        .iter()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else if let Some(rest) = line.strip_prefix(from_indent) {
                format!("{to_indent}{rest}")
            } else {
                format!("{to_indent}{}", line.trim_start())
            }
        })
        .collect()
}

fn leading_indent(line: &str) -> String {
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

/// Result of `handleDiscard` / `handleAccept`: the new full file content
/// (join with `\n` to write), plus whether carbonize cleanup is required
/// (accept only) and the accepted-original block text (accept only, used by
/// `scrub_manual_edits_against_original_block`).
#[derive(Debug, Clone, Default)]
pub struct AcceptResult {
    pub handled: bool,
    pub error: Option<String>,
    pub new_lines: Vec<String>,
    pub carbonize: bool,
    pub accepted_original_text: String,
}

/// Mirrors `handleDiscard(id, lines, targetFile)`. `file_path` is used only
/// to pick comment syntax (extension-based), matching the JS.
pub fn handle_discard(id: &str, lines: &[String], file_path: &Path) -> AcceptResult {
    let Some(block) = find_marker_block(id, lines) else {
        return AcceptResult {
            handled: false,
            error: Some("Markers not found".to_string()),
            ..Default::default()
        };
    };

    let original = extract_original(lines, block);
    let is_jsx = detect_comment_syntax(file_path).open == "{/*";
    let replace_range = expand_replace_range(block, lines, id, is_jsx);

    let indent = leading_indent(&lines[replace_range.start]);
    let restored = deindent_content(&original, &indent);

    let mut new_lines: Vec<String> = Vec::new();
    new_lines.extend_from_slice(&lines[..replace_range.start]);
    new_lines.extend(restored);
    new_lines.extend_from_slice(&lines[replace_range.end + 1..]);

    AcceptResult {
        handled: true,
        new_lines,
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_carbonize_replacement(
    indent: &str,
    comment_syntax: CommentSyntax,
    is_jsx: bool,
    id: &str,
    variant_num: &str,
    css_content: Option<&[String]>,
    param_values: Option<&serde_json::Map<String, serde_json::Value>>,
    restored: &[String],
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let Some(css_content) = css_content else {
        lines.extend_from_slice(restored);
        return lines;
    };

    let variant_style_attr = if is_jsx {
        "style={{ display: 'contents' }}"
    } else {
        "style=\"display: contents\""
    };

    let push_carbonize_body = |lines: &mut Vec<String>, body_indent: &str| {
        let body_restored = reindent_content(restored, indent, &format!("{body_indent}  "));
        lines.push(format!(
            "{body_indent}{} impeccable-carbonize-start {id} {}",
            comment_syntax.open, comment_syntax.close
        ));
        lines.push(format!(
            "{body_indent}<style data-impeccable-css=\"{id}\">{}",
            if is_jsx { "{`" } else { "" }
        ));
        for css_line in css_content {
            lines.push(format!("{body_indent}{}", css_line.trim_start()));
        }
        lines.push(format!(
            "{body_indent}{}",
            if is_jsx { "`}</style>" } else { "</style>" }
        ));
        if let Some(pv) = param_values {
            if !pv.is_empty() {
                lines.push(format!(
                    "{body_indent}{} impeccable-param-values {id}: {} {}",
                    comment_syntax.open,
                    serde_json::to_string(&serde_json::Value::Object(pv.clone())).unwrap(),
                    comment_syntax.close
                ));
            }
        }
        lines.push(format!(
            "{body_indent}{} impeccable-carbonize-end {id} {}",
            comment_syntax.open, comment_syntax.close
        ));
        lines.push(format!(
            "{body_indent}<div data-impeccable-variant=\"{variant_num}\" {variant_style_attr}>"
        ));
        lines.extend(body_restored);
        lines.push(format!("{body_indent}</div>"));
    };

    if is_jsx {
        let wrapper_style = "style={{ display: \"contents\" }}";
        lines.push(format!(
            "{indent}<div data-impeccable-carbonize=\"{id}\" {wrapper_style}>"
        ));
        push_carbonize_body(&mut lines, &format!("{indent}  "));
        lines.push(format!("{indent}</div>"));
    } else {
        push_carbonize_body(&mut lines, indent);
    }

    lines
}

/// Mirrors `handleAccept(id, variantNum, lines, targetFile, paramValues)`.
pub fn handle_accept(
    id: &str,
    variant_num: &str,
    lines: &[String],
    file_path: &Path,
    param_values: Option<&serde_json::Map<String, serde_json::Value>>,
) -> AcceptResult {
    let Some(block) = find_marker_block(id, lines) else {
        return AcceptResult {
            handled: false,
            error: Some("Markers not found".to_string()),
            ..Default::default()
        };
    };

    let comment_syntax = detect_comment_syntax(file_path);
    let is_jsx = comment_syntax.open == "{/*";
    let replace_range = expand_replace_range(block, lines, id, is_jsx);
    let indent = leading_indent(&lines[replace_range.start]);

    let Some(variant_content) = extract_variant(lines, block, variant_num) else {
        return AcceptResult {
            handled: false,
            error: Some(format!("Variant {variant_num} not found")),
            ..Default::default()
        };
    };
    let original_content = extract_original(lines, block);
    let css_content = extract_css(lines, block, id);

    let variant_text = variant_content.join("\n");
    let has_helper_attrs = variant_text.contains("data-impeccable-variant");
    let needs_carbonize = css_content.is_some() || has_helper_attrs;

    let restored = deindent_content(&variant_content, &indent);
    let replacement = build_carbonize_replacement(
        &indent,
        comment_syntax,
        is_jsx,
        id,
        variant_num,
        css_content.as_deref(),
        param_values,
        &restored,
    );

    let mut new_lines: Vec<String> = Vec::new();
    new_lines.extend_from_slice(&lines[..replace_range.start]);
    new_lines.extend(replacement);
    new_lines.extend_from_slice(&lines[replace_range.end + 1..]);

    AcceptResult {
        handled: true,
        error: None,
        new_lines,
        carbonize: needs_carbonize,
        accepted_original_text: original_content.join("\n"),
    }
}

/// Applies [`handle_discard`] to a file on disk, writing the result back.
/// Mirrors the file I/O side of `acceptCli`'s discard branch.
pub fn discard_file(id: &str, file_path: &Path) -> std::io::Result<AcceptResult> {
    let content = fs::read_to_string(file_path)?;
    let lines: Vec<String> = content.split('\n').map(|s| s.to_string()).collect();
    let result = handle_discard(id, &lines, file_path);
    if result.handled {
        fs::write(file_path, result.new_lines.join("\n"))?;
    }
    Ok(result)
}

/// Applies [`handle_accept`] to a file on disk, writing the result back.
/// Mirrors the file I/O side of `acceptCli`'s accept branch.
pub fn accept_file(
    id: &str,
    variant_num: &str,
    file_path: &Path,
    param_values: Option<&serde_json::Map<String, serde_json::Value>>,
) -> std::io::Result<AcceptResult> {
    let content = fs::read_to_string(file_path)?;
    let lines: Vec<String> = content.split('\n').map(|s| s.to_string()).collect();
    let result = handle_accept(id, variant_num, &lines, file_path, param_values);
    if result.handled {
        fs::write(file_path, result.new_lines.join("\n"))?;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// File search (find the file containing session markers)
// ---------------------------------------------------------------------------

const SEARCH_DIRS: [&str; 8] = [
    "src", "app", "pages", "components", "public", "views", "templates", ".",
];

/// Mirrors `findSessionFile(id, cwd)`, returning the matching file's path
/// (relative-or-absolute, as passed in via `cwd`-joined search dirs).
pub fn find_session_file(id: &str, cwd: &Path) -> Option<PathBuf> {
    let marker = format!("impeccable-variants-start {id}");
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for dir in SEARCH_DIRS {
        let abs_dir = cwd.join(dir);
        if !abs_dir.exists() {
            continue;
        }
        if let Some(found) = search_dir(&abs_dir, &marker, &mut seen, 0) {
            return Some(found);
        }
    }
    None
}

fn search_dir(dir: &Path, query: &str, seen: &mut HashSet<PathBuf>, depth: u32) -> Option<PathBuf> {
    if depth > 5 {
        return None;
    }
    let real_dir = fs::canonicalize(dir).ok()?;
    if !seen.insert(real_dir) {
        return None;
    }

    let entries: Vec<_> = fs::read_dir(dir).ok()?.filter_map(|e| e.ok()).collect();

    for entry in &entries {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        if !EXTENSIONS_WITH_ASTRO.contains(&ext.as_str()) {
            continue;
        }
        if let Ok(content) = fs::read_to_string(&path) {
            if content.contains(query) {
                return Some(path);
            }
        }
    }

    for entry in &entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if ["node_modules", ".git", "dist", "build"].contains(&name.as_ref()) {
            continue;
        }
        if let Some(found) = search_dir(&path, query, seen, depth + 1) {
            return Some(found);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Manual-edits scrub (buffer entries supplied by the caller; see module GAP)
// ---------------------------------------------------------------------------

/// A single staged manual-edit op, mirroring the shape read from the manual
/// edits buffer (`{ originalText, newText }`).
#[derive(Debug, Clone, Default)]
pub struct ManualEditOp {
    pub original_text: Option<String>,
    pub new_text: Option<String>,
}

fn normalize_manual_edit_text(text: &str) -> String {
    static WS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
    WS_RE.replace_all(text, " ").trim().to_string()
}

fn manual_edit_text_segments(source: &str) -> Vec<String> {
    static TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]*>").unwrap());
    static JSX_COMMENT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?s)\{/\*.*?\*/\}").unwrap());
    static HTML_COMMENT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").unwrap());
    static SPLIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n+").unwrap());

    let step1 = TAG_RE.replace_all(source, "\n");
    let step2 = JSX_COMMENT_RE.replace_all(&step1, "\n");
    let step3 = HTML_COMMENT_RE.replace_all(&step2, "\n");
    SPLIT_RE
        .split(&step3)
        .map(normalize_manual_edit_text)
        .filter(|s| !s.is_empty())
        .collect()
}

fn original_block_has_exact_manual_text(original_block: &str, text: &str) -> bool {
    let needle = normalize_manual_edit_text(text);
    if needle.is_empty() {
        return false;
    }
    manual_edit_text_segments(original_block)
        .iter()
        .any(|segment| segment == &needle)
}

fn manual_edit_op_appears_in_block(op: &ManualEditOp, original_block: &str) -> bool {
    [op.new_text.as_deref(), op.original_text.as_deref()]
        .into_iter()
        .flatten()
        .filter(|t| !t.is_empty())
        .any(|text| original_block_has_exact_manual_text(original_block, text))
}

/// Mirrors `scrubManualEditsAgainstOriginalBlock`, minus the buffer I/O (see
/// module GAP note): given the accepted wrapper's original-block text and a
/// mutable slice of ops for the matching page, filters out ops whose text
/// appeared verbatim inside that original block. Returns `true` if any op
/// was removed (i.e. the caller should persist the mutation).
pub fn scrub_manual_edits_against_original_block(
    original_block_text: &str,
    ops: &mut Vec<ManualEditOp>,
) -> bool {
    if original_block_text.is_empty() {
        return false;
    }
    let before = ops.len();
    ops.retain(|op| !manual_edit_op_appears_in_block(op, original_block_text));
    ops.len() != before
}

// ---------------------------------------------------------------------------
// Manual-edits buffer I/O (mirrors just the `readBuffer`/`writeBuffer` slice
// of `./live/manual-edits-buffer.mjs` that this file's own scrub call needs)
// ---------------------------------------------------------------------------

fn manual_edits_buffer_path(root: &Path) -> PathBuf {
    get_live_dir(root).join("pending-manual-edits.json")
}

/// Mirrors `readBuffer(cwd)`: malformed/missing files fall back to an empty
/// `{ version: 1, entries: [] }`, matching the JS's non-strict reader.
fn read_manual_edits_buffer(root: &Path) -> serde_json::Value {
    if let Ok(raw) = fs::read_to_string(manual_edits_buffer_path(root)) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
            if parsed.get("entries").and_then(|e| e.as_array()).is_some() {
                return parsed;
            }
        }
    }
    serde_json::json!({ "version": 1, "entries": [] })
}

/// Mirrors `writeBuffer(cwd, buffer)`.
fn write_manual_edits_buffer(root: &Path, buffer: &serde_json::Value) -> std::io::Result<()> {
    let path = manual_edits_buffer_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let entries = buffer.get("entries").cloned().unwrap_or_else(|| serde_json::json!([]));
    let out = serde_json::json!({ "version": 1, "entries": entries });
    fs::write(path, serde_json::to_string_pretty(&out).unwrap())
}

/// Mirrors `scrubManualEditsAgainstOriginalBlock`, with the on-disk buffer
/// I/O this file's `acceptCli` call site needs (the pure filtering logic
/// lives in [`scrub_manual_edits_against_original_block`] above; this wraps
/// it with `readBuffer`/`writeBuffer`).
pub fn scrub_manual_edits_against_original_block_on_disk(
    root: &Path,
    original_block_text: &str,
    page_url: Option<&str>,
) {
    if original_block_text.is_empty() {
        return;
    }
    let Some(page_url) = page_url else {
        return;
    };
    let mut buffer = read_manual_edits_buffer(root);
    let Some(entries) = buffer.get_mut("entries").and_then(|e| e.as_array_mut()) else {
        return;
    };
    if entries.is_empty() {
        return;
    }

    let mut mutated = false;
    for entry in entries.iter_mut() {
        if entry.get("pageUrl").and_then(|v| v.as_str()) != Some(page_url) {
            continue;
        }
        let Some(ops) = entry.get_mut("ops").and_then(|o| o.as_array_mut()) else {
            continue;
        };
        let before = ops.len();
        ops.retain(|op| {
            let original_text = op.get("originalText").and_then(|v| v.as_str()).map(str::to_string);
            let new_text = op.get("newText").and_then(|v| v.as_str()).map(str::to_string);
            let mirrored = ManualEditOp { original_text, new_text };
            !manual_edit_op_appears_in_block(&mirrored, original_block_text)
        });
        if ops.len() != before {
            mutated = true;
        }
    }
    entries.retain(|entry| {
        entry
            .get("ops")
            .and_then(|o| o.as_array())
            .map(|ops| !ops.is_empty())
            .unwrap_or(false)
    });

    if mutated {
        let _ = write_manual_edits_buffer(root, &buffer);
    }
}

// ---------------------------------------------------------------------------
// Deprecated source-shadow-preview detection (`readSourceShadowPreviewMeta`)
// ---------------------------------------------------------------------------

/// Mirrors `readHtmlAttr(tag, name)`. The JS regex captures the opening
/// quote and backreferences it (`(["'])...\1`); `regex` has no
/// backreference support, so this matches double- and single-quoted forms
/// as separate alternatives instead (equivalent, since only the resulting
/// value is read, not which quote character was used).
fn read_html_attr(tag: &str, name: &str) -> Option<String> {
    let escaped = escape_regex(name);
    let re = Regex::new(&format!(
        r#"\s{escaped}\s*=\s*(?:"([^"]*)"|'([^']*)')"#
    ))
    .ok()?;
    let caps = re.captures(tag)?;
    let value = caps.get(1).or_else(|| caps.get(2))?.as_str();
    Some(decode_html_attr(value))
}

fn decode_html_attr(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Mirrors `readSourceShadowPreviewMeta(content, id)`. The JS regex uses a
/// `(["'])...\1` backreference to match either quote style around `id`; the
/// `regex` crate has no backreference support, so this builds two literal
/// (double-quote / single-quote) alternatives instead — equivalent because
/// `id` is a known, already-escaped literal, not a runtime capture.
fn read_source_shadow_preview_meta(content: &str, id: &str) -> Option<(String, i64, i64)> {
    let escaped = escape_regex(id);
    let dq = format!(r#"<[^>]+data-impeccable-variants="{escaped}"[^>]*>"#);
    let sq = format!(r"<[^>]+data-impeccable-variants='{escaped}'[^>]*>");
    let re = Regex::new(&format!("(?:{dq})|(?:{sq})")).ok()?;
    let tag = re.find(content)?.as_str();
    if read_html_attr(tag, "data-impeccable-preview").as_deref() != Some("source-shadow") {
        return None;
    }
    let source_file = read_html_attr(tag, "data-impeccable-source-file")?;
    let source_start_line: i64 = read_html_attr(tag, "data-impeccable-source-start")?.parse().ok()?;
    let source_end_line: i64 = read_html_attr(tag, "data-impeccable-source-end")?.parse().ok()?;
    Some((source_file, source_start_line, source_end_line))
}

// ---------------------------------------------------------------------------
// CLI entrypoint (`acceptCli`)
// ---------------------------------------------------------------------------

const HELP_TEXT: &str = "Usage: node live-accept.mjs [options]\n\n\
Deterministic accept/discard for live variant sessions.\n\n\
Modes:\n  \
--discard          Remove variants, restore original\n  \
--variant N        Accept variant N, discard the rest\n\n\
Required:\n  \
--id SESSION_ID    Session ID of the variant wrapper\n\n\
Options:\n  \
--page-url URL     Current browser page URL; scopes staged copy-edit cleanup\n  \
--defer-source-write\n                     \
Deprecated compatibility flag. Svelte component accepts\n                     \
now write the real source immediately.\n\n\
Output (JSON):\n  \
{ handled, file, carbonize }";

fn arg_val<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn rel_to_cwd(path: &Path, cwd: &Path) -> String {
    path.strip_prefix(cwd)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

fn carbonize_todo(file: &str) -> String {
    format!(
        "REQUIRED before next poll: carbonize cleanup in {file}. See reference/live.md \"Required after accept\"."
    )
}

/// Mirrors `acceptCli()`'s argv parsing and dispatch, minus the `process.*`
/// side effects: instead of `console.log` + `process.exit`, returns
/// `(exit_code, stdout_json_text)` for the caller to print/exit with.
/// `--defer-source-write` is accepted (and ignored) for CLI compatibility,
/// exactly as the JS help text documents it ("now write the real source
/// immediately").
pub fn run(args: &[String], cwd: &Path) -> (i32, String) {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return (0, HELP_TEXT.to_string());
    }

    let id = arg_val(args, "--id");
    let variant_num = arg_val(args, "--variant");
    let param_values_raw = arg_val(args, "--param-values");
    let page_url = arg_val(args, "--page-url");
    let is_discard = args.iter().any(|a| a == "--discard");

    let Some(id) = id else {
        return (1, "Missing --id".to_string());
    };
    if !is_discard && variant_num.is_none() {
        return (1, "Need --discard or --variant N".to_string());
    }

    // Malformed `--param-values` is skipped rather than failing the accept,
    // mirroring the JS `try { JSON.parse(...) } catch { paramValues = null; }`.
    let param_values: Option<serde_json::Map<String, serde_json::Value>> = param_values_raw
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|v| v.as_object().cloned());

    let found = find_session_file(id, cwd);
    let svelte_manifest = if found.is_none() {
        svelte_component::find_svelte_component_manifest(id, cwd)
    } else {
        None
    };

    if found.is_none() && svelte_manifest.is_none() {
        let out = serde_json::json!({
            "handled": false,
            "error": format!("Session markers not found for id: {id}"),
        });
        return (0, out.to_string());
    }

    if let Some(manifest) = svelte_manifest {
        if is_discard {
            svelte_component::remove_svelte_component_session(id, cwd);
            let out = serde_json::json!({
                "handled": true,
                "file": manifest.source_file,
                "carbonize": false,
                "previewMode": "svelte-component",
                "componentDir": manifest.component_dir,
            });
            return (0, out.to_string());
        }

        // `variant_num` is required here: the earlier `!is_discard &&
        // variant_num.is_none()` guard already returned when absent.
        let variant_num = variant_num.unwrap();
        let result = svelte_component::inline_svelte_component_accept(
            &manifest,
            variant_num,
            param_values.as_ref(),
            cwd,
        );
        let mut value = serde_json::to_value(&result).unwrap_or_default();
        if result.carbonize {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("todo".to_string(), serde_json::json!(carbonize_todo(&result.file)));
            }
        }
        return (0, value.to_string());
    }

    let found = found.unwrap();
    let rel_file = rel_to_cwd(&found, cwd);
    let content = match fs::read_to_string(&found) {
        Ok(c) => c,
        Err(e) => return (1, format!("io error reading {}: {e}", found.display())),
    };
    let lines: Vec<String> = content.split('\n').map(|s| s.to_string()).collect();
    let has_block = find_marker_block(id, &lines).is_some();
    let source_shadow_preview = if has_block {
        read_source_shadow_preview_meta(&content, id)
    } else {
        None
    };

    if source_shadow_preview.is_some() {
        let out = serde_json::json!({
            "handled": false,
            "error": "source_shadow_preview_deprecated",
            "hint": "Svelte live mode now uses svelte-component injection. Re-wrap the element and regenerate variants.",
        });
        return (0, out.to_string());
    }

    let is_generated_options = IsGeneratedOptions { cwd: Some(cwd.to_path_buf()) };
    if is_generated_file(&found.to_string_lossy(), &is_generated_options) {
        let out = serde_json::json!({
            "handled": false,
            "mode": "fallback",
            "file": rel_file,
            "hint": "Session is in a generated file. Persist the accepted variant in source; do not rely on this script.",
        });
        return (0, out.to_string());
    }

    if is_discard {
        match discard_file(id, &found) {
            Ok(result) if result.handled => {
                let out = serde_json::json!({ "handled": true, "file": rel_file, "carbonize": false });
                (0, out.to_string())
            }
            Ok(result) => {
                let out = serde_json::json!({ "handled": false, "file": rel_file, "error": result.error });
                (0, out.to_string())
            }
            Err(e) => (1, format!("io error: {e}")),
        }
    } else {
        let variant_num = variant_num.unwrap();
        match accept_file(id, variant_num, &found, param_values.as_ref()) {
            Ok(result) if result.handled => {
                let mut out = serde_json::json!({ "handled": true, "file": rel_file });
                if result.carbonize {
                    if let Some(obj) = out.as_object_mut() {
                        obj.insert("carbonize".to_string(), serde_json::json!(true));
                        obj.insert("todo".to_string(), serde_json::json!(carbonize_todo(&rel_file)));
                    }
                }
                scrub_manual_edits_against_original_block_on_disk(
                    cwd,
                    &result.accepted_original_text,
                    page_url,
                );
                (0, out.to_string())
            }
            Ok(result) => {
                let out = serde_json::json!({ "handled": false, "file": rel_file, "error": result.error });
                (0, out.to_string())
            }
            Err(e) => (1, format!("io error: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.split('\n').map(|s| s.to_string()).collect()
    }

    fn html_fixture(id: &str) -> String {
        format!(
            r#"<div class="hero">
  <!-- impeccable-variants-start {id} -->
  <div data-impeccable-variant="original">
    <h1>Original</h1>
  </div>
  <div data-impeccable-variant="1">
    <h1>Variant One</h1>
  </div>
  <!-- impeccable-variants-end {id} -->
</div>
"#
        )
    }

    #[test]
    fn find_marker_block_locates_start_and_end() {
        let id = "abc123";
        let l = lines(&html_fixture(id));
        let block = find_marker_block(id, &l).unwrap();
        assert!(l[block.start].contains("impeccable-variants-start"));
        assert!(l[block.end].contains("impeccable-variants-end"));
    }

    #[test]
    fn find_marker_block_none_when_missing() {
        let l = lines(&html_fixture("abc123"));
        assert!(find_marker_block("does-not-exist", &l).is_none());
    }

    #[test]
    fn detect_comment_syntax_jsx_vs_html() {
        assert_eq!(detect_comment_syntax(Path::new("a.jsx")).open, "{/*");
        assert_eq!(detect_comment_syntax(Path::new("a.tsx")).open, "{/*");
        assert_eq!(detect_comment_syntax(Path::new("a.html")).open, "<!--");
        assert_eq!(detect_comment_syntax(Path::new("a.vue")).open, "<!--");
    }

    #[test]
    fn extract_original_and_variant_round_trip_html() {
        let id = "abc123";
        let l = lines(&html_fixture(id));
        let block = find_marker_block(id, &l).unwrap();
        let original = extract_original(&l, block);
        assert!(original.iter().any(|line| line.contains("Original")));
        let variant = extract_variant(&l, block, "1").unwrap();
        assert!(variant.iter().any(|line| line.contains("Variant One")));
    }

    #[test]
    fn extract_variant_missing_returns_none() {
        let id = "abc123";
        let l = lines(&html_fixture(id));
        let block = find_marker_block(id, &l).unwrap();
        assert!(extract_variant(&l, block, "99").is_none());
    }

    #[test]
    fn extract_css_same_line() {
        let id = "abc123";
        let text = format!(
            r#"<div>
  <!-- impeccable-variants-start {id} -->
  <style data-impeccable-css="{id}">.a {{ color: red; }}</style>
  <div data-impeccable-variant="original"><p>orig</p></div>
  <div data-impeccable-variant="1"><p>v1</p></div>
  <!-- impeccable-variants-end {id} -->
</div>
"#
        );
        let l = lines(&text);
        let block = find_marker_block(id, &l).unwrap();
        let css = extract_css(&l, block, id).unwrap();
        assert_eq!(css.join("\n"), ".a { color: red; }");
    }

    #[test]
    fn extract_css_self_closing_returns_none() {
        let id = "abc123";
        let text = format!(
            r#"<div>
  <!-- impeccable-variants-start {id} -->
  <style data-impeccable-css="{id}" />
  <div data-impeccable-variant="original"><p>orig</p></div>
  <div data-impeccable-variant="1"><p>v1</p></div>
  <!-- impeccable-variants-end {id} -->
</div>
"#
        );
        let l = lines(&text);
        let block = find_marker_block(id, &l).unwrap();
        assert!(extract_css(&l, block, id).is_none());
    }

    #[test]
    fn deindent_content_strips_minimum_common_indent() {
        let content = vec!["    <p>a</p>".to_string(), "      <span>b</span>".to_string()];
        let out = deindent_content(&content, "  ");
        assert_eq!(out[0], "  <p>a</p>");
        assert_eq!(out[1], "    <span>b</span>");
    }

    #[test]
    fn handle_discard_restores_original_and_removes_wrapper() {
        let id = "abc123";
        let l = lines(&html_fixture(id));
        let result = handle_discard(id, &l, Path::new("a.html"));
        assert!(result.handled);
        let joined = result.new_lines.join("\n");
        assert!(joined.contains("<h1>Original</h1>"));
        assert!(!joined.contains("impeccable-variants-start"));
        assert!(!joined.contains("Variant One"));
    }

    #[test]
    fn handle_discard_missing_markers_reports_unhandled() {
        let l = lines("<div>no markers</div>");
        let result = handle_discard("missing", &l, Path::new("a.html"));
        assert!(!result.handled);
        assert_eq!(result.error.as_deref(), Some("Markers not found"));
    }

    #[test]
    fn handle_accept_replaces_wrapper_with_chosen_variant() {
        let id = "abc123";
        let l = lines(&html_fixture(id));
        let result = handle_accept(id, "1", &l, Path::new("a.html"), None);
        assert!(result.handled);
        let joined = result.new_lines.join("\n");
        assert!(joined.contains("Variant One"));
        assert!(!joined.contains("impeccable-variants-start"));
        assert!(!result.carbonize, "no CSS or helper attrs present");
    }

    #[test]
    fn handle_accept_missing_variant_reports_error() {
        let id = "abc123";
        let l = lines(&html_fixture(id));
        let result = handle_accept(id, "99", &l, Path::new("a.html"), None);
        assert!(!result.handled);
        assert_eq!(result.error.as_deref(), Some("Variant 99 not found"));
    }

    #[test]
    fn handle_accept_with_css_requires_carbonize() {
        let id = "abc123";
        let text = format!(
            r#"<div>
  <!-- impeccable-variants-start {id} -->
  <style data-impeccable-css="{id}">.a {{ color: red; }}</style>
  <div data-impeccable-variant="original"><p>orig</p></div>
  <div data-impeccable-variant="1"><p>v1</p></div>
  <!-- impeccable-variants-end {id} -->
</div>
"#
        );
        let l = lines(&text);
        let result = handle_accept(id, "1", &l, Path::new("a.html"), None);
        assert!(result.handled);
        assert!(result.carbonize);
        assert!(result.new_lines.join("\n").contains("impeccable-carbonize-start"));
    }

    #[test]
    fn accept_and_discard_file_round_trip_on_disk() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "w2-016-live-accept-{}-{}",
            std::process::id(),
            n
        ));
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("page.html");
        let id = "abc123";
        fs::write(&file_path, html_fixture(id)).unwrap();

        let result = accept_file(id, "1", &file_path, None).unwrap();
        assert!(result.handled);
        let content = fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("Variant One"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_session_file_locates_marker_under_search_dirs() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "w2-016-find-session-{}-{}",
            std::process::id(),
            n
        ));
        let src_dir = dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let id = "abc123";
        fs::write(src_dir.join("page.html"), html_fixture(id)).unwrap();

        let found = find_session_file(id, &dir).unwrap();
        assert_eq!(found, src_dir.join("page.html"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scrub_manual_edits_removes_ops_matching_original_block() {
        let original_block = "<p>Hello world</p>";
        let mut ops = vec![
            ManualEditOp {
                original_text: Some("Hello world".to_string()),
                new_text: None,
            },
            ManualEditOp {
                original_text: Some("Unrelated text".to_string()),
                new_text: None,
            },
        ];
        let mutated = scrub_manual_edits_against_original_block(original_block, &mut ops);
        assert!(mutated);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].original_text.as_deref(), Some("Unrelated text"));
    }

    fn r17_tmp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("r17-live-accept-{tag}-{}-{}", std::process::id(), n));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn manual_edits_buffer_round_trip_on_disk() {
        let root = r17_tmp_dir("buffer");
        let buffer = serde_json::json!({
            "version": 1,
            "entries": [{
                "id": "sess",
                "pageUrl": "/home",
                "element": {},
                "ops": [
                    { "ref": "r1", "originalText": "Hello world", "newText": "Hi" },
                    { "ref": "r2", "originalText": "Unrelated", "newText": "x" },
                ],
                "stagedAt": "2026-01-01T00:00:00.000Z",
            }],
        });
        write_manual_edits_buffer(&root, &buffer).unwrap();

        scrub_manual_edits_against_original_block_on_disk(&root, "<p>Hello world</p>", Some("/home"));

        let reread = read_manual_edits_buffer(&root);
        let entries = reread["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let ops = entries[0]["ops"].as_array().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["ref"], "r2");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn scrub_on_disk_noop_without_page_url_or_buffer() {
        let root = r17_tmp_dir("buffer-noop");
        // No buffer file at all: must not panic or create one.
        scrub_manual_edits_against_original_block_on_disk(&root, "<p>x</p>", Some("/home"));
        assert!(!manual_edits_buffer_path(&root).exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn read_source_shadow_preview_meta_detects_deprecated_wrapper() {
        let id = "abc123";
        let content = format!(
            r#"<div data-impeccable-variants="{id}" data-impeccable-preview="source-shadow" data-impeccable-source-file="src/App.tsx" data-impeccable-source-start="4" data-impeccable-source-end="9"></div>"#
        );
        let meta = read_source_shadow_preview_meta(&content, id).expect("meta found");
        assert_eq!(meta.0, "src/App.tsx");
        assert_eq!(meta.1, 4);
        assert_eq!(meta.2, 9);
    }

    #[test]
    fn read_source_shadow_preview_meta_none_for_non_shadow_wrapper() {
        let id = "abc123";
        let content = format!(r#"<div data-impeccable-variants="{id}"></div>"#);
        assert!(read_source_shadow_preview_meta(&content, id).is_none());
    }

    #[test]
    fn run_help_returns_zero_and_usage() {
        let (code, out) = run(&["--help".to_string()], Path::new("."));
        assert_eq!(code, 0);
        assert!(out.contains("Usage: node live-accept.mjs"));
    }

    #[test]
    fn run_missing_id_errors() {
        let (code, out) = run(&["--discard".to_string()], Path::new("."));
        assert_eq!(code, 1);
        assert_eq!(out, "Missing --id");
    }

    #[test]
    fn run_missing_mode_errors() {
        let (code, out) = run(&["--id".to_string(), "x".to_string()], Path::new("."));
        assert_eq!(code, 1);
        assert_eq!(out, "Need --discard or --variant N");
    }

    #[test]
    fn run_session_not_found_reports_unhandled_with_zero_exit() {
        let dir = r17_tmp_dir("run-not-found");
        let (code, out) = run(
            &["--id".to_string(), "missing-id".to_string(), "--discard".to_string()],
            &dir,
        );
        assert_eq!(code, 0);
        assert!(out.contains("\"handled\":false"));
        assert!(out.contains("Session markers not found"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_accept_marker_wrapper_end_to_end() {
        let dir = r17_tmp_dir("run-accept");
        let src_dir = dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let id = "abc123";
        fs::write(src_dir.join("page.html"), html_fixture(id)).unwrap();

        let (code, out) = run(
            &["--id".to_string(), id.to_string(), "--variant".to_string(), "1".to_string()],
            &dir,
        );
        assert_eq!(code, 0);
        assert!(out.contains("\"handled\":true"));
        let written = fs::read_to_string(src_dir.join("page.html")).unwrap();
        assert!(written.contains("Variant One"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_discard_marker_wrapper_end_to_end() {
        let dir = r17_tmp_dir("run-discard");
        let src_dir = dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let id = "abc123";
        fs::write(src_dir.join("page.html"), html_fixture(id)).unwrap();

        let (code, out) = run(&["--id".to_string(), id.to_string(), "--discard".to_string()], &dir);
        assert_eq!(code, 0);
        assert!(out.contains("\"handled\":true"));
        let written = fs::read_to_string(src_dir.join("page.html")).unwrap();
        assert!(written.contains("<h1>Original</h1>"));
        assert!(!written.contains("Variant One"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_dispatches_to_svelte_component_accept() {
        let dir = r17_tmp_dir("run-svelte");
        let comp_dir = dir
            .join("node_modules")
            .join(".impeccable-live")
            .join("sess-svelte");
        fs::create_dir_all(&comp_dir).unwrap();
        fs::write(
            comp_dir.join("manifest.json"),
            serde_json::json!({
                "id": "sess-svelte",
                "previewMode": "svelte-component",
                "sourceFile": "src/App.svelte",
                "sourceStartLine": 1,
                "sourceEndLine": 1,
                "count": 1,
                "propContract": [],
                "originalMarkup": "<div>orig</div>",
                "componentDir": "node_modules/.impeccable-live/sess-svelte",
                "runtimeModule": "/node_modules/.impeccable-live/__runtime.js",
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            comp_dir.join("v1.svelte"),
            "<script>\n  let {} = $props();\n</script>\n<div>svelte variant</div>\n",
        )
        .unwrap();
        let src_dir = dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("App.svelte"), "<div>orig</div>\n").unwrap();

        let (code, out) = run(
            &[
                "--id".to_string(),
                "sess-svelte".to_string(),
                "--variant".to_string(),
                "1".to_string(),
            ],
            &dir,
        );
        assert_eq!(code, 0);
        assert!(out.contains("\"handled\":true"), "{out}");
        assert!(out.contains("svelte-component"));
        let written = fs::read_to_string(src_dir.join("App.svelte")).unwrap();
        assert!(written.contains("svelte variant"));

        let _ = fs::remove_dir_all(&dir);
    }
}
