//! Port of `skills/designer/engine/scripts/live-wrap.mjs` (packet r26).
//!
//! `live-wrap.mjs` is a ~900-line CLI: `wrapCli()` parses `process.argv`,
//! walks the project filesystem (`findFileWithQuery`/`searchDir`, using
//! `./lib/is-generated.mjs`'s `isGeneratedFile`), reads/writes source files,
//! and consumes `./live/manual-edits-buffer.mjs`'s buffered entries and
//! `./live/svelte-component.mjs`'s scaffolding helpers.
//!
//! As of packet r26, `crate::p8_designer::is_generated` (port of
//! `lib/is-generated.mjs`) and `wf_port::w2_021::manual_edits_buffer` (port
//! of `live/manual-edits-buffer.mjs`) both exist in this crate, so the
//! filesystem walk (`find_file_with_query`/`search_dir`) and the
//! buffer-consuming functions (`pending_entries_that_may_affect_wrap`,
//! `manual_edit_may_affect_wrap`, `manual_edit_hint_falls_inside_selection`,
//! `manual_edit_locator_matches_selection`, `apply_buffered_manual_edit_to_lines`)
//! are now ported here too, faithfully against the JS.
//!
//! Still NOT ported: `wrapCli()`'s own argv-driven orchestration
//! (`console.log`/`console.error`/`process.exit` output shape, reading and
//! writing the target source file in place, and wiring the above functions
//! together end to end) and the `./live/svelte-component.mjs`-dependent
//! Svelte-component injection branch — both are CLI/process-boundary
//! concerns outside a unit-testable pure-function port, and the Svelte
//! scaffolding lives in a separate module (`wf_port::w2_022::svelte_component`)
//! not wired to a Rust CLI entry point anywhere in this crate.
//!
//! Ported, faithfully and with the JS's own exported test surface
//! (`buildSearchQueries`, `findElement`, `findClosingLine`,
//! `detectCommentSyntax`, plus the sibling pure helpers): every
//! self-contained string/line-array function (query building, comment/style
//! detection, CSS authoring templates, element/close-tag line-range search),
//! the manual-edit locator matcher (`lineMatchesManualEditLocator`,
//! `replaceOnce`, `countOccurrences`, `escapeRegExp`), the filesystem walk,
//! and the buffer-consuming selection-impact functions.

use std::path::Path;

/// Mirrors `argVal(args, flag)`: supports both `--flag value` and
/// `--flag=value` forms, first match wins for the `=` form (JS `find`
/// wouldn't be first-match for the two-token form since `indexOf` also picks
/// the first occurrence — this mirrors that exactly).
pub fn arg_val<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let prefix = format!("{flag}=");
    for arg in args {
        if let Some(rest) = arg.strip_prefix(&prefix) {
            return Some(rest);
        }
    }
    let idx = args.iter().position(|a| a == flag)?;
    args.get(idx + 1).map(String::as_str)
}

/// Mirrors `replaceOnce(value, needle, replacement)`.
pub fn replace_once(value: &str, needle: &str, replacement: &str) -> String {
    match value.find(needle) {
        Some(idx) => format!("{}{}{}", &value[..idx], replacement, &value[idx + needle.len()..]),
        None => value.to_string(),
    }
}

/// Mirrors `countOccurrences(value, needle)`.
pub fn count_occurrences(value: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut start = 0;
    while let Some(pos) = value[start..].find(needle) {
        count += 1;
        start += pos + needle.len();
    }
    count
}

/// Mirrors `escapeRegExp(value)`.
pub fn escape_regexp(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Manual-edit op fields relevant to `lineMatchesManualEditLocator`.
#[derive(Debug, Default, Clone)]
pub struct ManualEditLocator<'a> {
    pub tag: Option<&'a str>,
    pub element_id: Option<&'a str>,
    pub classes: &'a [String],
}

/// Mirrors `lineMatchesManualEditLocator(line, op)`.
pub fn line_matches_manual_edit_locator(line: &str, op: &ManualEditLocator) -> bool {
    if let Some(tag) = op.tag {
        let pattern = format!(r"(?i)<\s*{}(?:[\s>/]|$)", escape_regexp(tag));
        let re = regex::Regex::new(&pattern).expect("valid tag regex");
        if !re.is_match(line) {
            return false;
        }
    }
    if let Some(id) = op.element_id {
        let pattern = format!(r#"\bid\s*=\s*["']{}["']"#, escape_regexp(id));
        let re = regex::Regex::new(&pattern).expect("valid id regex");
        if !re.is_match(line) {
            return false;
        }
    }
    for class_name in op.classes.iter().filter(|c| !c.is_empty()) {
        if !line.contains(class_name.as_str()) {
            return false;
        }
    }
    true
}

/// Mirrors `splitClassList(classes)`.
pub fn split_class_list(classes: &str) -> Vec<String> {
    classes
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Mirrors `attrEscapeDouble(str)`.
pub fn attr_escape_double(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommentSyntax {
    pub open: &'static str,
    pub close: &'static str,
}

/// Mirrors `detectCommentSyntax(filePath)`.
pub fn detect_comment_syntax(file_path: &str) -> CommentSyntax {
    let ext = Path::new(file_path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if ext == "jsx" || ext == "tsx" {
        CommentSyntax { open: "{/*", close: "*/}" }
    } else {
        CommentSyntax { open: "<!--", close: "-->" }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StyleMode {
    pub mode: &'static str,
    pub style_tag: String,
}

/// Mirrors `detectStyleMode(filePath)`.
pub fn detect_style_mode(file_path: &str) -> StyleMode {
    let ext = Path::new(file_path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if ext == "astro" {
        StyleMode {
            mode: "astro-global-prefixed",
            style_tag: "<style is:inline data-impeccable-css=\"SESSION_ID\">".to_string(),
        }
    } else {
        StyleMode {
            mode: "scoped",
            style_tag: "<style data-impeccable-css=\"SESSION_ID\">".to_string(),
        }
    }
}

/// Mirrors `buildCssSelectorPrefixExamples(styleMode, count)`. Takes the
/// mode string (JS calls this with `styleMode` as the *string* `'astro-global-prefixed'`
/// or `'scoped'`, not the object — matched here by taking `mode: &str`).
pub fn build_css_selector_prefix_examples(mode: &str, count: u32) -> Vec<String> {
    if mode != "astro-global-prefixed" {
        return Vec::new();
    }
    (1..=count).map(|i| format!("[data-impeccable-variant=\"{i}\"]")).collect()
}

/// Mirrors `buildSearchQueries(elementId, classes, tag, query)`.
pub fn build_search_queries(
    element_id: Option<&str>,
    classes: Option<&str>,
    tag: Option<&str>,
    query: Option<&str>,
) -> Vec<String> {
    let mut queries = Vec::new();

    if let Some(id) = element_id {
        if !id.is_empty() {
            queries.push(format!("id=\"{id}\""));
        }
    }

    if let Some(classes) = classes {
        let class_list = split_class_list(classes);
        if class_list.len() > 1 {
            let joined = class_list.join(" ");
            let mut sorted = class_list.clone();
            sorted.sort_by(|a, b| b.len().cmp(&a.len()));
            queries.push(format!("class=\"{joined}\""));
            queries.push(format!("className=\"{joined}\""));
            for class_name in sorted {
                queries.push(class_name);
            }
        } else if let Some(first) = class_list.first() {
            queries.push(first.clone());
        }
    }

    if let (Some(tag), Some(classes)) = (tag, classes) {
        if let Some(first_class) = split_class_list(classes).first() {
            queries.push(format!("<{tag} class=\"{first_class}"));
            queries.push(format!("<{tag} className=\"{first_class}"));
        }
    }

    if let Some(query) = query {
        if !query.is_empty() {
            queries.push(query.to_string());
        }
    }

    queries
}

/// Mirrors `minLeadingSpaces(lines)`.
pub fn min_leading_spaces(lines: &[String]) -> usize {
    let mut min = usize::MAX;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let leading = line.chars().take_while(|c| c.is_whitespace()).count();
        if leading < min {
            min = leading;
        }
    }
    if min == usize::MAX {
        0
    } else {
        min
    }
}

// The JS `OPENER_RE = /<([A-Za-z][A-Za-z0-9]*)(?=[\s/>]|$)/` is a *search*
// (not anchored) regex used with `String.match`, which returns the first
// match anywhere in the line. Model that directly with `find_opener_match`.
fn find_opener_match(line: &str) -> Option<(usize, String)> {
    let re = regex::Regex::new(r"<([A-Za-z][A-Za-z0-9]*)(?:[\s/>]|$)").expect("valid opener regex");
    re.captures(line).map(|c| {
        let m = c.get(0).unwrap();
        (m.start(), c[1].to_string())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineRange {
    pub start_line: usize,
    pub end_line: usize,
}

/// Mirrors `findOpenerLine(lines, matchLine, tag)`. Returns `None` for `-1`.
pub fn find_opener_line(lines: &[String], match_line: usize, tag: Option<&str>) -> Option<usize> {
    if let Some((_, opener_tag)) = find_opener_match(&lines[match_line]) {
        return if tag.is_none() || tag == Some(opener_tag.as_str()) {
            Some(match_line)
        } else {
            None
        };
    }
    const MAX_BACKWALK: usize = 10;
    let floor = match_line.saturating_sub(MAX_BACKWALK);
    let mut i = match_line;
    while i > floor {
        i -= 1;
        if let Some((_, opener_tag)) = find_opener_match(&lines[i]) {
            return if tag.is_none() || tag == Some(opener_tag.as_str()) {
                Some(i)
            } else {
                None
            };
        }
    }
    None
}

/// Mirrors `findClosingLine(lines, start)`.
pub fn find_closing_line(lines: &[String], start: usize) -> usize {
    let tag_name = match find_opener_match(&lines[start]) {
        Some((_, t)) => t,
        None => return start,
    };
    let open_re = regex::Regex::new(&format!(r"<{}(?:[\s/>]|$)", regex::escape(&tag_name))).unwrap();
    let self_close_re = regex::Regex::new(&format!(r"<{}[^>]*/>", regex::escape(&tag_name))).unwrap();
    let close_re = regex::Regex::new(&format!(r"</{}\s*>", regex::escape(&tag_name))).unwrap();

    let mut depth: i64 = 0;
    for (i, line) in lines.iter().enumerate().skip(start) {
        let opens = open_re.find_iter(line).count() as i64;
        let self_closes = self_close_re.find_iter(line).count() as i64;
        let closes = close_re.find_iter(line).count() as i64;
        depth += opens - self_closes - closes;
        if depth <= 0 {
            return i;
        }
    }
    (start + 50).min(lines.len().saturating_sub(1))
}

/// Mirrors `findElement(lines, query, tag)`.
pub fn find_element(lines: &[String], query: &str, tag: Option<&str>) -> Option<LineRange> {
    for i in 0..lines.len() {
        if !lines[i].contains(query) {
            continue;
        }
        let stripped = lines[i].trim();
        if stripped.starts_with("<!--") || stripped.starts_with("{/*") || stripped.starts_with("//") {
            continue;
        }
        if lines[i].contains("data-impeccable-variant") {
            continue;
        }
        let opener_line = match find_opener_line(lines, i, tag) {
            Some(v) => v,
            None => continue,
        };
        let end_line = find_closing_line(lines, opener_line);
        return Some(LineRange { start_line: opener_line, end_line });
    }
    None
}

/// Mirrors `findAllElements(lines, query, tag)`.
pub fn find_all_elements(lines: &[String], query: &str, tag: Option<&str>) -> Vec<LineRange> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for i in 0..lines.len() {
        if !lines[i].contains(query) {
            continue;
        }
        let stripped = lines[i].trim();
        if stripped.starts_with("<!--") || stripped.starts_with("{/*") || stripped.starts_with("//") {
            continue;
        }
        if lines[i].contains("data-impeccable-variant") {
            continue;
        }
        let opener_line = match find_opener_line(lines, i, tag) {
            Some(v) => v,
            None => continue,
        };
        if !seen.insert(opener_line) {
            continue;
        }
        let end_line = find_closing_line(lines, opener_line);
        out.push(LineRange { start_line: opener_line, end_line });
    }
    out
}

/// Mirrors `filterByText(candidates, lines, text)`.
pub fn filter_by_text(candidates: &[LineRange], lines: &[String], text: &str) -> Vec<LineRange> {
    let trimmed: String = {
        let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
        collapsed.to_lowercase().chars().take(80).collect()
    };
    if trimmed.len() < 8 {
        return Vec::new();
    }
    let target_spaced = trimmed.clone();
    let target_compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();

    let tag_re = regex::Regex::new(r"<[^>]*>").unwrap();
    let brace_re = regex::Regex::new(r"\{[^}]*\}").unwrap();

    candidates
        .iter()
        .copied()
        .filter(|c| {
            let body = lines[c.start_line..=c.end_line].join(" ");
            let inner = brace_re.replace_all(&tag_re.replace_all(&body, " "), " ").to_lowercase();
            let source_spaced = inner.split_whitespace().collect::<Vec<_>>().join(" ");
            let source_compact: String = inner.chars().filter(|c| !c.is_whitespace()).collect();
            source_spaced.contains(&target_spaced) || source_compact.contains(&target_compact)
        })
        .collect()
}

/// Mirrors `buildCssAuthoring(styleMode, count)`.
pub struct CssAuthoring {
    pub mode: &'static str,
    pub style_tag: String,
    pub strategy: &'static str,
    pub rule_pattern: &'static str,
    pub selector_examples: Vec<String>,
    pub requirements: Vec<&'static str>,
    pub forbidden: Vec<&'static str>,
}

pub fn build_css_authoring(style_mode: &StyleMode, count: u32) -> CssAuthoring {
    let variant_numbers: Vec<u32> = (1..=count).collect();
    if style_mode.mode == "astro-global-prefixed" {
        CssAuthoring {
            mode: style_mode.mode,
            style_tag: style_mode.style_tag.clone(),
            strategy: "global-prefixed",
            rule_pattern: "[data-impeccable-variant=\"N\"] > .variant-class { ... }",
            selector_examples: variant_numbers
                .iter()
                .map(|n| format!("[data-impeccable-variant=\"{n}\"] > .variant-class"))
                .collect(),
            requirements: vec![
                "Use the styleTag exactly; the is:inline attribute is required for this file.",
                "Put raw CSS directly between the styleTag opening and a plain </style> close.",
                "Prefix every preview selector with the matching [data-impeccable-variant=\"N\"] selector.",
                "Keep selectors anchored to the generated variant wrapper; do not rely on component CSS scoping for preview rules.",
            ],
            forbidden: vec![
                "Do not use @scope for this styleMode.",
                "Do not wrap style content in a JSX/TSX template literal ({` ... `}); that syntax is for .tsx/.jsx only.",
                "Do not put { immediately after the style opening tag; Astro parses { as expression syntax.",
            ],
        }
    } else {
        CssAuthoring {
            mode: style_mode.mode,
            style_tag: style_mode.style_tag.clone(),
            strategy: "scope-rule",
            rule_pattern: "@scope ([data-impeccable-variant=\"N\"]) { :scope > .variant-class { ... } }",
            selector_examples: variant_numbers
                .iter()
                .map(|n| format!("@scope ([data-impeccable-variant=\"{n}\"]) {{ :scope > .variant-class {{ ... }} }}"))
                .collect(),
            requirements: vec![
                "Use @scope blocks keyed to each [data-impeccable-variant=\"N\"] wrapper.",
                "Inside each @scope block, make :scope rules step into the replacement element with a descendant combinator.",
                "Use the styleTag exactly; do not add framework-specific style attributes unless this object says to.",
            ],
            forbidden: vec![
                "Do not use global [data-impeccable-variant=\"N\"] selector prefixes for this styleMode.",
                "Do not add is:inline to the style tag for this styleMode.",
            ],
        }
    }
}

/// Strips the Windows `\\?\` verbatim-path prefix that
/// `std::fs::canonicalize` adds, so canonicalized paths compare equal to
/// ordinary (non-verbatim) paths built with `Path::join`.
fn strip_verbatim_prefix(path: std::path::PathBuf) -> std::path::PathBuf {
    match path.to_str() {
        Some(s) if s.starts_with(r"\\?\") => std::path::PathBuf::from(&s[4..]),
        _ => path,
    }
}

/// File extensions `findFileWithQuery`/`searchDir` will look inside.
pub const SEARCH_EXTENSIONS: &[&str] = &[".html", ".jsx", ".tsx", ".vue", ".svelte", ".astro"];

/// Mirrors `findFileWithQuery(query, cwd, genOpts)`. Walks a fixed set of
/// project subdirectories (falls back to `cwd` itself) looking for a file
/// whose content contains `query`, skipping generated files unless
/// `include_generated` is set (mirrors `genOpts.includeGenerated`).
pub fn find_file_with_query(
    query: &str,
    cwd: &Path,
    include_generated: bool,
) -> Option<std::path::PathBuf> {
    const SEARCH_DIRS: &[&str] = &["src", "app", "pages", "components", "public", "views", "templates", "."];
    let mut seen = std::collections::HashSet::new();
    for dir in SEARCH_DIRS {
        let abs_dir = cwd.join(dir);
        if !abs_dir.exists() {
            continue;
        }
        if let Some(found) = search_dir(&abs_dir, query, &mut seen, 0, include_generated) {
            return Some(found);
        }
    }
    None
}

/// Mirrors `searchDir(dir, query, seen, depth, genOpts)`.
fn search_dir(
    dir: &Path,
    query: &str,
    seen: &mut std::collections::HashSet<std::path::PathBuf>,
    depth: u32,
    include_generated: bool,
) -> Option<std::path::PathBuf> {
    if depth > 5 {
        return None;
    }
    let real_dir = strip_verbatim_prefix(std::fs::canonicalize(dir).ok()?);
    if !seen.insert(real_dir) {
        return None;
    }

    let entries: Vec<_> = std::fs::read_dir(dir).ok()?.filter_map(|e| e.ok()).collect();

    // Check files first.
    for entry in &entries {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !file_type.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        if !SEARCH_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        if !include_generated {
            let opts = crate::p8_designer::is_generated::IsGeneratedOptions { cwd: None };
            if crate::p8_designer::is_generated::is_generated_file(&path.to_string_lossy(), &opts) {
                continue;
            }
        }
        if let Ok(content) = std::fs::read_to_string(&path) {
            if content.contains(query) {
                return Some(path);
            }
        }
    }

    // Then recurse into directories, always skipping node_modules/.git.
    for entry in &entries {
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if name == "node_modules" || name == ".git" {
            continue;
        }
        if let Some(found) = search_dir(&entry.path(), query, seen, depth + 1, include_generated) {
            return Some(found);
        }
    }

    None
}

/// Reads `sourceHint.file`/`sourceHint.line`, `tag`, and `classes` out of a
/// `ManualEditOp`'s opaque `extra` map (these fields aren't named on the
/// struct because `manual-edits-buffer.mjs` treats ops as pass-through
/// blobs). Mirrors the ad-hoc property access the JS does on `op`.
fn op_source_hint(op: &crate::wf_port::w2_021::manual_edits_buffer::ManualEditOp) -> Option<(String, f64)> {
    let hint = op.extra.get("sourceHint")?;
    let file = hint.get("file")?.as_str()?.to_string();
    let line_value = hint.get("line")?;
    let line = line_value
        .as_f64()
        .or_else(|| line_value.as_str().and_then(|s| s.parse().ok()))?;
    Some((file, line))
}

fn op_tag(op: &crate::wf_port::w2_021::manual_edits_buffer::ManualEditOp) -> Option<String> {
    op.extra.get("tag")?.as_str().map(|s| s.to_string())
}

fn op_classes(op: &crate::wf_port::w2_021::manual_edits_buffer::ManualEditOp) -> Vec<String> {
    op.extra
        .get("classes")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|c| c.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

/// Mirrors `lineMatchesManualEditLocator(line, op)`, reading `tag`/`elementId`
/// (via `op_tag`) and `classes` (via `op_classes`) off the opaque op blob.
pub fn line_matches_manual_edit_locator_op(
    line: &str,
    op: &crate::wf_port::w2_021::manual_edits_buffer::ManualEditOp,
) -> bool {
    let element_id = op.extra.get("elementId").and_then(|v| v.as_str());
    let locator = ManualEditLocator {
        tag: op_tag(op).as_deref(),
        element_id,
        classes: &op_classes(op),
    };
    line_matches_manual_edit_locator(line, &locator)
}

/// Mirrors `manualEditHintFallsInsideSelection(op, targetAbs, originalLines, selectionStartLine, cwd)`.
pub fn manual_edit_hint_falls_inside_selection(
    op: &crate::wf_port::w2_021::manual_edits_buffer::ManualEditOp,
    target_abs: &Path,
    original_lines: &[String],
    selection_start_line: i64,
    cwd: &Path,
) -> bool {
    let Some((hint_file, hinted_line)) = op_source_hint(op) else {
        return false;
    };
    if hint_file.is_empty() || !hinted_line.is_finite() {
        return false;
    }
    let hint_path = Path::new(&hint_file);
    let hint_abs = if hint_path.is_absolute() {
        hint_path.to_path_buf()
    } else {
        cwd.join(hint_path)
    };
    let hint_abs = strip_verbatim_prefix(std::fs::canonicalize(&hint_abs).unwrap_or(hint_abs));
    let target_abs_resolved =
        strip_verbatim_prefix(std::fs::canonicalize(target_abs).unwrap_or_else(|_| target_abs.to_path_buf()));
    if hint_abs != target_abs_resolved {
        return false;
    }
    let hinted_index = hinted_line as i64 - 1 - selection_start_line;
    if hinted_index < 0 || hinted_index as usize >= original_lines.len() {
        return false;
    }
    match &op.original_text {
        Some(original_text) if !original_text.is_empty() => {
            original_lines[hinted_index as usize].contains(original_text.as_str())
        }
        _ => false,
    }
}

/// Mirrors `manualEditLocatorMatchesSelection(op, originalLines)`.
pub fn manual_edit_locator_matches_selection(
    op: &crate::wf_port::w2_021::manual_edits_buffer::ManualEditOp,
    original_lines: &[String],
) -> bool {
    let Some(original_text) = op.original_text.as_deref() else {
        return false;
    };
    if original_text.is_empty() {
        return false;
    }
    original_lines
        .iter()
        .any(|line| line.contains(original_text) && line_matches_manual_edit_locator_op(line, op))
}

/// Mirrors `manualEditMayAffectWrap(op, targetFile, originalLines, selectionStartLine, cwd)`.
pub fn manual_edit_may_affect_wrap(
    op: &crate::wf_port::w2_021::manual_edits_buffer::ManualEditOp,
    target_file: &Path,
    original_lines: &[String],
    selection_start_line: i64,
    cwd: &Path,
) -> bool {
    let target_abs = if target_file.is_absolute() {
        target_file.to_path_buf()
    } else {
        cwd.join(target_file)
    };
    if manual_edit_hint_falls_inside_selection(op, &target_abs, original_lines, selection_start_line, cwd) {
        return true;
    }
    if manual_edit_locator_matches_selection(op, original_lines) {
        return true;
    }
    match &op.original_text {
        Some(original_text) if !original_text.is_empty() => original_lines.join("\n").contains(original_text.as_str()),
        _ => false,
    }
}

/// Mirrors `pendingEntriesThatMayAffectWrap(entries, targetFile, originalLines, selectionStartLine, cwd)`.
pub fn pending_entries_that_may_affect_wrap<'a>(
    entries: &'a [crate::wf_port::w2_021::manual_edits_buffer::ManualEditEntry],
    target_file: &Path,
    original_lines: &[String],
    selection_start_line: i64,
    cwd: &Path,
) -> Vec<&'a crate::wf_port::w2_021::manual_edits_buffer::ManualEditEntry> {
    let target_abs = if target_file.is_absolute() {
        target_file.to_path_buf()
    } else {
        cwd.join(target_file)
    };
    entries
        .iter()
        .filter(|entry| {
            entry
                .ops
                .iter()
                .any(|op| manual_edit_may_affect_wrap(op, &target_abs, original_lines, selection_start_line, cwd))
        })
        .collect()
}

/// Mirrors `applyBufferedManualEditToLines(originalLines, selectionStartLine, op)`.
pub fn apply_buffered_manual_edit_to_lines(
    original_lines: &[String],
    selection_start_line: i64,
    op: &crate::wf_port::w2_021::manual_edits_buffer::ManualEditOp,
) -> (Vec<String>, bool) {
    let (original_text, new_text) = match (&op.original_text, &op.new_text) {
        (Some(ot), Some(nt)) if !ot.is_empty() => (ot.clone(), nt.clone()),
        _ => return (original_lines.to_vec(), false),
    };

    let replace_line = |line_index: usize| -> (Vec<String>, bool) {
        let lines = original_lines
            .iter()
            .enumerate()
            .map(|(i, l)| if i == line_index { replace_once(l, &original_text, &new_text) } else { l.clone() })
            .collect();
        (lines, true)
    };

    if let Some((_, hinted_line)) = op_source_hint(op) {
        if hinted_line.is_finite() {
            let hinted_index = hinted_line as i64 - 1 - selection_start_line;
            if hinted_index >= 0
                && (hinted_index as usize) < original_lines.len()
                && original_lines[hinted_index as usize].contains(&original_text)
            {
                return replace_line(hinted_index as usize);
            }
        }
    }

    let mut locator_matches = Vec::new();
    for (index, line) in original_lines.iter().enumerate() {
        if !line.contains(&original_text) {
            continue;
        }
        if !line_matches_manual_edit_locator_op(line, op) {
            continue;
        }
        locator_matches.push(index);
    }
    if locator_matches.len() == 1 {
        return replace_line(locator_matches[0]);
    }

    let original_block = original_lines.join("\n");
    if count_occurrences(&original_block, &original_text) == 1 {
        let replaced = replace_once(&original_block, &original_text, &new_text);
        return (replaced.split('\n').map(str::to_string).collect(), true);
    }

    (original_lines.to_vec(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<String> {
        s.lines().map(str::to_string).collect()
    }

    #[test]
    fn arg_val_supports_both_forms() {
        let args: Vec<String> = vec!["--id".into(), "abc".into(), "--count=3".into()];
        assert_eq!(arg_val(&args, "--id"), Some("abc"));
        assert_eq!(arg_val(&args, "--count"), Some("3"));
        assert_eq!(arg_val(&args, "--missing"), None);
    }

    #[test]
    fn replace_once_replaces_first_only() {
        assert_eq!(replace_once("aXaXa", "X", "-"), "a-aXa");
        assert_eq!(replace_once("abc", "z", "-"), "abc");
    }

    #[test]
    fn count_occurrences_counts_non_overlapping() {
        assert_eq!(count_occurrences("aXaXaX", "X"), 3);
        assert_eq!(count_occurrences("abc", ""), 0);
        assert_eq!(count_occurrences("aaaa", "aa"), 2);
    }

    #[test]
    fn escape_regexp_escapes_metacharacters() {
        assert_eq!(escape_regexp("a.b*c"), "a\\.b\\*c");
        assert_eq!(escape_regexp("plain"), "plain");
    }

    #[test]
    fn line_matches_manual_edit_locator_checks_tag_id_classes() {
        let classes = vec!["hero".to_string(), "card".to_string()];
        let op = ManualEditLocator { tag: Some("div"), element_id: Some("x"), classes: &classes };
        assert!(line_matches_manual_edit_locator(r#"<div id="x" class="hero card">"#, &op));
        assert!(!line_matches_manual_edit_locator(r#"<span id="x" class="hero card">"#, &op));
        assert!(!line_matches_manual_edit_locator(r#"<div id="y" class="hero card">"#, &op));
        assert!(!line_matches_manual_edit_locator(r#"<div id="x" class="hero">"#, &op));
    }

    #[test]
    fn split_class_list_handles_commas_and_whitespace() {
        assert_eq!(split_class_list("a, b   c"), vec!["a", "b", "c"]);
        assert_eq!(split_class_list(""), Vec::<String>::new());
    }

    #[test]
    fn attr_escape_double_escapes_html_entities() {
        assert_eq!(attr_escape_double(r#"<a href="x">&"#), "&lt;a href=&quot;x&quot;&gt;&amp;");
    }

    #[test]
    fn detect_comment_syntax_jsx_vs_html() {
        assert_eq!(detect_comment_syntax("x.tsx"), CommentSyntax { open: "{/*", close: "*/}" });
        assert_eq!(detect_comment_syntax("x.jsx"), CommentSyntax { open: "{/*", close: "*/}" });
        assert_eq!(detect_comment_syntax("x.html"), CommentSyntax { open: "<!--", close: "-->" });
        assert_eq!(detect_comment_syntax("x.astro"), CommentSyntax { open: "<!--", close: "-->" });
    }

    #[test]
    fn detect_style_mode_astro_vs_default() {
        let astro = detect_style_mode("x.astro");
        assert_eq!(astro.mode, "astro-global-prefixed");
        let scoped = detect_style_mode("x.html");
        assert_eq!(scoped.mode, "scoped");
    }

    #[test]
    fn build_css_selector_prefix_examples_only_for_astro_mode() {
        assert_eq!(
            build_css_selector_prefix_examples("astro-global-prefixed", 3),
            vec![
                "[data-impeccable-variant=\"1\"]",
                "[data-impeccable-variant=\"2\"]",
                "[data-impeccable-variant=\"3\"]"
            ]
        );
        assert!(build_css_selector_prefix_examples("scoped", 3).is_empty());
    }

    #[test]
    fn build_search_queries_priority_order() {
        let q = build_search_queries(Some("hero"), Some("a b"), Some("section"), Some("fallback"));
        assert_eq!(
            q,
            vec![
                "id=\"hero\"".to_string(),
                "class=\"a b\"".to_string(),
                "className=\"a b\"".to_string(),
                "a".to_string(),
                "b".to_string(),
                "<section class=\"a".to_string(),
                "<section className=\"a".to_string(),
                "fallback".to_string(),
            ]
        );
    }

    #[test]
    fn build_search_queries_single_class_no_tag() {
        let q = build_search_queries(None, Some("only"), None, None);
        assert_eq!(q, vec!["only".to_string()]);
    }

    #[test]
    fn min_leading_spaces_ignores_blank_lines() {
        let l = lines("  a\n\n    b\nc");
        assert_eq!(min_leading_spaces(&l), 0); // "c" has 0 leading spaces
        let l2 = lines("  a\n\n    b");
        assert_eq!(min_leading_spaces(&l2), 2);
    }

    #[test]
    fn find_element_locates_opener_and_matching_close() {
        let l = lines("<div>\n  <section class=\"hero\">\n    <p>hi</p>\n  </section>\n</div>");
        let found = find_element(&l, "hero", None).unwrap();
        assert_eq!(found.start_line, 1);
        assert_eq!(found.end_line, 3);
    }

    #[test]
    fn find_element_skips_comment_lines_and_existing_variants() {
        let l = lines("<!-- hero -->\n<div data-impeccable-variant=\"1\" class=\"hero\">x</div>\n<section class=\"hero\">y</section>");
        let found = find_element(&l, "hero", None).unwrap();
        assert_eq!(found.start_line, 2);
    }

    #[test]
    fn find_all_elements_returns_every_distinct_opener() {
        let l = lines("<div class=\"card\">a</div>\n<div class=\"card\">b</div>");
        let all = find_all_elements(&l, "card", None);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].start_line, 0);
        assert_eq!(all[1].start_line, 1);
    }

    #[test]
    fn filter_by_text_requires_min_length_and_matches_either_normalization() {
        let candidates = vec![LineRange { start_line: 0, end_line: 0 }];
        let l = lines("<h1>Hero Two</h1>");
        assert!(filter_by_text(&candidates, &l, "short").is_empty());
        let matches = filter_by_text(&candidates, &l, "Hero Two");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn find_closing_line_counts_nesting_depth() {
        let l = lines("<div>\n  <div>inner</div>\n</div>");
        assert_eq!(find_closing_line(&l, 0), 2);
    }
}
