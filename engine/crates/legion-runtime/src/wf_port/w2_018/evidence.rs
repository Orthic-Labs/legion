//! Port of `skills/designer/engine/scripts/live-manual-edit-evidence.mjs`
//! (chunk w2_018).
//!
//! Collects evidence for pending live copy edits: staged browser edits,
//! rendered context, and likely source candidates. Does not edit source
//! files and does not choose a winner.
//!
//! Depends on `readBuffer`/`getBufferPath` from
//! `skills/designer/engine/scripts/live/manual-edits-buffer.mjs`, ported
//! here as [`super::buffer`], and `isGeneratedFile` from
//! `skills/designer/engine/scripts/lib/is-generated.mjs`, which already has
//! a Rust port at `legion_runtime::p8_designer::is_generated`, reused here.

use crate::p8_designer::is_generated::{is_generated_file, IsGeneratedOptions};
use crate::wf_port::w2_018::buffer::{self, Entry};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const EVIDENCE_VERSION: u64 = 1;
const STRONG_LITERAL_MATCH_LIMIT: usize = 8;
const WEAK_LITERAL_MATCH_LIMIT: usize = 4;
const OBJECT_KEY_MATCH_LIMIT: usize = 8;
const LOCATOR_MATCH_LIMIT: usize = 4;
const CONTEXT_MATCH_LIMIT: usize = 8;
const CONTEXT_MATCH_PER_HINT: usize = 2;

const TEXT_EXTENSIONS: &[&str] = &[
    "html", "jsx", "tsx", "vue", "svelte", "astro", "js", "mjs", "ts",
];
const SEARCH_DIRS: &[&str] = &[
    "src", "app", "pages", "components", "public", "views", "templates", "site", "lib", "data",
];
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".impeccable",
    ".astro",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "dist",
    "build",
    "out",
    "coverage",
];

struct SearchFile {
    file: PathBuf,
    relative_file: String,
    content: String,
    lines: Vec<String>,
}

/// Mirrors `buildManualEditEvidence({ cwd, pageUrl })`.
pub fn build_manual_edit_evidence(cwd: &Path, live_dir: &Path, page_url: Option<&str>) -> Value {
    let buf = buffer::read_buffer(live_dir);
    let entries: Vec<&Entry> = match page_url {
        Some(p) => buf
            .entries
            .iter()
            .filter(|e| e.page_url.as_deref() == Some(p))
            .collect(),
        None => buf.entries.iter().collect(),
    };
    let op_count: usize = entries.iter().map(|e| e.ops.len()).sum();

    if op_count == 0 {
        return json!({
            "pageUrl": page_url,
            "count": 0,
            "entries": [],
            "ops": [],
            "candidates": [],
        });
    }

    let search_files = collect_search_files(cwd);
    let ops = flatten_ops(&entries);
    let candidates: Vec<Value> = ops
        .iter()
        .map(|op| build_candidates_for_op(op, cwd, &search_files))
        .collect();

    let entries_json: Vec<Value> = entries.iter().map(|e| entry_to_value(e)).collect();
    let ops_json: Vec<Value> = ops.iter().map(op_to_value).collect();

    json!({
        "version": EVIDENCE_VERSION,
        "pageUrl": page_url,
        "count": op_count,
        "entries": entries_json,
        "ops": ops_json,
        "context": {
            "cwd": cwd.to_string_lossy(),
            "bufferPath": relativize(cwd, &buffer::get_buffer_path(live_dir)),
            "totalEntries": entries.len(),
            "totalOps": op_count,
        },
        "candidates": candidates,
    })
}

fn entry_to_value(entry: &Entry) -> Value {
    let mut obj = entry.raw.clone();
    obj.insert("ops".to_string(), Value::Array(entry.ops.clone()));
    Value::Object(obj)
}

struct Op {
    entry_id: Option<String>,
    page_url: Option<String>,
    r#ref: Option<String>,
    context_ref: Option<String>,
    tag: Option<String>,
    element_id: Option<String>,
    classes: Vec<String>,
    original_text: Option<String>,
    new_text: Option<String>,
    deleted: bool,
    source_hint: Option<Value>,
    leaf: Option<Value>,
    nearby_editable_texts: Vec<Value>,
    container: Option<Value>,
    context_hints: Vec<String>,
}

fn op_to_value(op: &Op) -> Value {
    json!({
        "entryId": op.entry_id,
        "pageUrl": op.page_url,
        "ref": op.r#ref,
        "contextRef": op.context_ref,
        "tag": op.tag,
        "elementId": op.element_id,
        "classes": op.classes,
        "originalText": op.original_text,
        "newText": op.new_text,
        "deleted": op.deleted,
        "sourceHint": op.source_hint,
        "leaf": op.leaf,
        "nearbyEditableTexts": op.nearby_editable_texts,
        "container": op.container,
        "contextHints": op.context_hints,
    })
}

fn flatten_ops(entries: &[&Entry]) -> Vec<Op> {
    let mut out = Vec::new();
    for entry in entries {
        let hints_by_ref = build_context_hints_by_ref(entry);
        for raw_op in &entry.ops {
            let obj = raw_op.as_object().cloned().unwrap_or_default();
            let r#ref = obj.get("ref").and_then(Value::as_str).map(String::from);
            let classes = obj
                .get("classes")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let nearby = obj
                .get("nearbyEditableTexts")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            out.push(Op {
                entry_id: entry.id.clone(),
                page_url: entry.page_url.clone(),
                context_hints: r#ref
                    .as_ref()
                    .and_then(|r| hints_by_ref.get(r))
                    .cloned()
                    .unwrap_or_default(),
                context_ref: obj.get("contextRef").and_then(Value::as_str).map(String::from),
                tag: obj.get("tag").and_then(Value::as_str).map(String::from),
                element_id: obj.get("elementId").and_then(Value::as_str).map(String::from),
                classes,
                original_text: obj.get("originalText").and_then(Value::as_str).map(String::from),
                new_text: obj.get("newText").and_then(Value::as_str).map(String::from),
                deleted: obj.get("deleted").and_then(Value::as_bool).unwrap_or(false),
                source_hint: obj.get("sourceHint").cloned(),
                leaf: obj.get("leaf").cloned(),
                nearby_editable_texts: nearby,
                container: obj.get("container").cloned(),
                r#ref,
            });
        }
    }
    out
}

fn build_context_hints_by_ref(entry: &Entry) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for raw_op in &entry.ops {
        let obj = raw_op.as_object().cloned().unwrap_or_default();
        let Some(r#ref) = obj.get("ref").and_then(Value::as_str) else {
            continue;
        };
        let original_text = obj.get("originalText").and_then(Value::as_str).unwrap_or("");
        let new_text = obj.get("newText").and_then(Value::as_str).unwrap_or("");
        let mut hints: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        let mut add = |value: &str| {
            let text = normalize_text(&decode_basic_html(value));
            if text.len() < 3 || text.len() > 160 {
                return;
            }
            if text == normalize_text(original_text) || text == normalize_text(new_text) {
                return;
            }
            if seen.insert(text.clone()) {
                hints.push(text);
            }
        };

        if let Some(nearby) = obj.get("nearbyEditableTexts").and_then(Value::as_array) {
            for item in nearby {
                match item {
                    Value::String(s) => add(s),
                    Value::Object(o) => {
                        if let Some(text) = o.get("text").and_then(Value::as_str) {
                            add(text);
                        }
                    }
                    _ => {}
                }
            }
        }

        let outer_html = entry
            .raw
            .get("element")
            .and_then(|e| e.get("outerHTML"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let attr_re = Regex::new(r#"data-impeccable-original-text="([^"]*)""#).unwrap();
        for m in attr_re.captures_iter(outer_html) {
            add(m.get(1).unwrap().as_str());
        }

        if let Some(text_content) = entry
            .raw
            .get("element")
            .and_then(|e| e.get("textContent"))
            .and_then(Value::as_str)
        {
            let split_re = Regex::new(r"\s{2,}|\n|\t").unwrap();
            for chunk in split_re.split(text_content) {
                add(chunk);
            }
        }

        hints.truncate(16);
        map.insert(r#ref.to_string(), hints);
    }
    map
}

fn build_candidates_for_op(op: &Op, cwd: &Path, search_files: &[SearchFile]) -> Value {
    let original_text = op.original_text.clone().unwrap_or_default();
    let text_matches = if !original_text.is_empty() {
        find_literal_matches(search_files, &original_text, literal_match_limit(&original_text))
    } else {
        Vec::new()
    };
    let object_key_matches = if !original_text.is_empty() {
        find_object_key_matches(search_files, &original_text, OBJECT_KEY_MATCH_LIMIT)
    } else {
        Vec::new()
    };
    let locator_matches = find_locator_matches(search_files, op, LOCATOR_MATCH_LIMIT);
    let context_text_matches = find_context_matches(
        search_files,
        &op.context_hints,
        CONTEXT_MATCH_PER_HINT,
        CONTEXT_MATCH_LIMIT,
    );

    json!({
        "entryId": op.entry_id,
        "ref": op.r#ref,
        "originalText": original_text,
        "sourceHint": analyze_source_hint(op, cwd),
        "textMatches": text_matches,
        "objectKeyMatches": object_key_matches,
        "locatorMatches": locator_matches,
        "contextTextMatches": context_text_matches,
    })
}

fn literal_match_limit(text: &str) -> usize {
    if is_weak_source_needle(text) {
        WEAK_LITERAL_MATCH_LIMIT
    } else {
        STRONG_LITERAL_MATCH_LIMIT
    }
}

fn is_weak_source_needle(text: &str) -> bool {
    let normalized = normalize_text(text);
    if normalized.len() < 4 {
        return true;
    }
    Regex::new(r"^[\d.,+\-%\s]+$").unwrap().is_match(&normalized)
}

fn analyze_source_hint(op: &Op, cwd: &Path) -> Value {
    let Some(hint_obj) = op.source_hint.as_ref() else {
        return Value::Null;
    };
    let hint = normalize_source_hint(hint_obj);
    let Some(file_rel) = hint.get("file").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return Value::Null;
    };
    let file = cwd.join(file_rel);
    let relative_file = relativize(cwd, &file);
    if !is_path_inside_or_equal(cwd, &file) {
        let mut out = hint.clone();
        out["status"] = json!("outside_cwd");
        out["relativeFile"] = json!(file_rel);
        return out;
    }
    if !file.exists() {
        let mut out = hint.clone();
        out["status"] = json!("file_missing");
        out["relativeFile"] = json!(relative_file);
        return out;
    }
    if is_generated_file(
        &file.to_string_lossy(),
        &IsGeneratedOptions {
            cwd: Some(cwd.to_path_buf()),
        },
    ) {
        let mut out = hint.clone();
        out["status"] = json!("generated");
        out["relativeFile"] = json!(relative_file);
        return out;
    }

    let content = fs::read_to_string(&file).unwrap_or_default();
    let lines: Vec<&str> = content.split('\n').collect();
    let line = hint.get("line").and_then(Value::as_i64).unwrap_or(1).max(1) as usize;
    let start = line.saturating_sub(4);
    let end = (line + 3).min(lines.len());
    let window_text = lines.get(start..end).unwrap_or(&[]).join("\n");
    let contains_original_text = op
        .original_text
        .as_deref()
        .map(|t| !t.is_empty() && window_text.contains(t))
        .unwrap_or(false);

    let excerpt: Vec<Value> = lines
        .get(start..end)
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .map(|(i, text)| {
            json!({
                "line": start + i + 1,
                "text": text.chars().take(240).collect::<String>(),
            })
        })
        .collect();

    let mut out = hint.clone();
    out["status"] = json!(if contains_original_text {
        "ok"
    } else {
        "text_not_found_near_hint"
    });
    out["relativeFile"] = json!(relative_file);
    out["excerpt"] = json!(excerpt);
    out
}

fn normalize_source_hint(hint: &Value) -> Value {
    let Some(obj) = hint.as_object() else {
        return json!({});
    };
    let mut line = obj.get("line").and_then(Value::as_i64);
    let mut column = obj.get("column").and_then(Value::as_i64);
    if (line.is_none() || column.is_none()) {
        if let Some(loc) = obj.get("loc").and_then(Value::as_str) {
            let re = Regex::new(r"^(\d+)(?::(\d+))?").unwrap();
            if let Some(caps) = re.captures(loc) {
                line = caps.get(1).and_then(|m| m.as_str().parse().ok());
                if let Some(c) = caps.get(2) {
                    column = c.as_str().parse().ok();
                }
            }
        }
    }
    json!({
        "file": obj.get("file").and_then(Value::as_str).unwrap_or(""),
        "loc": obj.get("loc").and_then(Value::as_str).unwrap_or(""),
        "line": line,
        "column": column,
    })
}

fn collect_search_files(cwd: &Path) -> Vec<SearchFile> {
    let mut out = Vec::new();
    let mut seen_dirs = HashSet::new();
    let mut seen_files = HashSet::new();
    for dir in SEARCH_DIRS {
        scan_dir(&cwd.join(dir), cwd, &mut seen_dirs, &mut seen_files, &mut out, 0);
    }
    scan_root_files(cwd, &mut seen_files, &mut out);
    out
}

fn scan_dir(
    dir: &Path,
    cwd: &Path,
    seen_dirs: &mut HashSet<PathBuf>,
    seen_files: &mut HashSet<PathBuf>,
    out: &mut Vec<SearchFile>,
    depth: u32,
) {
    if depth > 7 || !dir.exists() {
        return;
    }
    let Ok(real_dir) = fs::canonicalize(dir) else {
        return;
    };
    if !seen_dirs.insert(real_dir) {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            let name = entry.file_name();
            if SKIP_DIRS.iter().any(|s| name == *s) {
                continue;
            }
            scan_dir(&path, cwd, seen_dirs, seen_files, out, depth + 1);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !TEXT_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        maybe_add_search_file(&path, cwd, seen_files, out);
    }
}

fn scan_root_files(cwd: &Path, seen_files: &mut HashSet<PathBuf>, out: &mut Vec<SearchFile>) {
    let Ok(entries) = fs::read_dir(cwd) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !TEXT_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        maybe_add_search_file(&path, cwd, seen_files, out);
    }
}

fn maybe_add_search_file(
    file: &Path,
    cwd: &Path,
    seen_files: &mut HashSet<PathBuf>,
    out: &mut Vec<SearchFile>,
) {
    let Ok(real_file) = fs::canonicalize(file) else {
        return;
    };
    if !seen_files.insert(real_file) {
        return;
    }
    if is_generated_file(
        &file.to_string_lossy(),
        &IsGeneratedOptions {
            cwd: Some(cwd.to_path_buf()),
        },
    ) {
        return;
    }
    let Ok(content) = fs::read_to_string(file) else {
        return;
    };
    let lines = content.split('\n').map(String::from).collect();
    out.push(SearchFile {
        file: file.to_path_buf(),
        relative_file: relativize(cwd, file),
        content,
        lines,
    });
}

fn find_literal_matches(search_files: &[SearchFile], needle: &str, max: usize) -> Vec<Value> {
    find_matches(search_files, needle, "text", max)
}

fn find_object_key_matches(search_files: &[SearchFile], text: &str, max: usize) -> Vec<Value> {
    let re = Regex::new(&format!(r#"(["'`]){}(?=\s*:)"#, regex::escape(text))).ok();
    let Some(re) = re else { return Vec::new() };
    let mut out = Vec::new();
    'outer: for file in search_files {
        for m in re.find_iter(&file.content) {
            out.push(match_for_index(file, m.start(), "object_key", text));
            if out.len() >= max {
                break 'outer;
            }
        }
    }
    out
}

fn find_locator_matches(search_files: &[SearchFile], op: &Op, max: usize) -> Vec<Value> {
    let mut needles: Vec<(&str, String)> = Vec::new();
    if let Some(id) = &op.element_id {
        needles.push(("id", id.clone()));
    }
    for cls in &op.classes {
        if !cls.is_empty() {
            needles.push(("class", cls.clone()));
        }
    }
    if let Some(tag) = &op.tag {
        needles.push(("tag", format!("<{tag}")));
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (kind, needle) in &needles {
        for m in find_matches(search_files, needle, kind, max) {
            let key = format!(
                "{}:{}:{}:{}",
                m["file"].as_str().unwrap_or(""),
                m["line"].as_u64().unwrap_or(0),
                kind,
                needle
            );
            if !seen.insert(key) {
                continue;
            }
            let mut m = m;
            m["needle"] = json!(needle);
            out.push(m);
            if out.len() >= max {
                return out;
            }
        }
    }
    out
}

fn find_context_matches(
    search_files: &[SearchFile],
    hints: &[String],
    max_per_hint: usize,
    max: usize,
) -> Vec<Value> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for hint in hints {
        for m in find_matches(search_files, hint, "context", max_per_hint) {
            let key = format!(
                "{}:{}:{}",
                m["file"].as_str().unwrap_or(""),
                m["line"].as_u64().unwrap_or(0),
                hint
            );
            if !seen.insert(key) {
                continue;
            }
            let mut m = m;
            m["needle"] = json!(hint);
            out.push(m);
            if out.len() >= max {
                return out;
            }
        }
    }
    out
}

fn find_matches(search_files: &[SearchFile], needle: &str, kind: &str, max: usize) -> Vec<Value> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for file in search_files {
        let mut index = 0usize;
        while out.len() < max {
            let Some(found) = file.content[index..].find(needle) else {
                break;
            };
            let abs = index + found;
            out.push(match_for_index(file, abs, kind, needle));
            index = abs + needle.len().max(1);
            if index > file.content.len() {
                break;
            }
        }
        if out.len() >= max {
            break;
        }
    }
    out
}

fn match_for_index(file: &SearchFile, index: usize, kind: &str, needle: &str) -> Value {
    let line = file.content[..index].matches('\n').count() + 1;
    let line_text = file.lines.get(line - 1).map(String::as_str).unwrap_or("");
    json!({
        "kind": kind,
        "file": file.relative_file,
        "line": line,
        "needle": needle,
        "excerpt": line_text.trim().chars().take(240).collect::<String>(),
    })
}

fn is_path_inside_or_equal(cwd: &Path, file: &Path) -> bool {
    match file.strip_prefix(cwd) {
        Ok(rel) => !rel.starts_with(".."),
        Err(_) => false,
    }
}

fn relativize(cwd: &Path, file: &Path) -> String {
    file.strip_prefix(cwd)
        .unwrap_or(file)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn normalize_text(value: &str) -> String {
    Regex::new(r"\s+")
        .unwrap()
        .replace_all(value, " ")
        .trim()
        .to_string()
}

fn decode_basic_html(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "legion-w2_018-evidence-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn normalize_text_collapses_whitespace() {
        assert_eq!(normalize_text("  a\n\tb   c "), "a b c");
    }

    #[test]
    fn decode_basic_html_handles_common_entities() {
        assert_eq!(decode_basic_html("Tom &amp; Jerry &quot;go&quot;"), "Tom & Jerry \"go\"");
    }

    #[test]
    fn is_weak_source_needle_flags_short_and_numeric_text() {
        assert!(is_weak_source_needle("12"));
        assert!(is_weak_source_needle("12.5%"));
        assert!(!is_weak_source_needle("Hello world"));
    }

    #[test]
    fn empty_buffer_yields_zero_count_and_empty_arrays() {
        let tmp = TempDir::new();
        let live_dir = tmp.0.join("live");
        let result = build_manual_edit_evidence(&tmp.0, &live_dir, None);
        assert_eq!(result["count"], json!(0));
        assert_eq!(result["entries"], json!([]));
        assert_eq!(result["candidates"], json!([]));
    }

    #[test]
    fn evidence_finds_literal_text_match_in_source_tree() {
        let tmp = TempDir::new();
        let live_dir = tmp.0.join("live");
        fs::create_dir_all(&live_dir).unwrap();
        fs::write(
            buffer::get_buffer_path(&live_dir),
            serde_json::to_string(&json!({
                "version": 1,
                "entries": [{
                    "id": "e1",
                    "pageUrl": "/",
                    "ops": [{
                        "ref": "r1",
                        "tag": "h1",
                        "originalText": "Welcome Friends",
                        "newText": "Welcome Strangers",
                    }],
                }],
            }))
            .unwrap(),
        )
        .unwrap();

        let src_dir = tmp.0.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("Hero.jsx"),
            "export default function Hero() {\n  return <h1>Welcome Friends</h1>;\n}\n",
        )
        .unwrap();

        let result = build_manual_edit_evidence(&tmp.0, &live_dir, None);
        assert_eq!(result["count"], json!(1));
        let candidates = result["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 1);
        let text_matches = candidates[0]["textMatches"].as_array().unwrap();
        assert_eq!(text_matches.len(), 1);
        assert_eq!(text_matches[0]["file"], json!("src/Hero.jsx"));
        assert_eq!(text_matches[0]["line"], json!(2));
    }

    #[test]
    fn evidence_filters_by_page_url() {
        let tmp = TempDir::new();
        let live_dir = tmp.0.join("live");
        fs::create_dir_all(&live_dir).unwrap();
        fs::write(
            buffer::get_buffer_path(&live_dir),
            serde_json::to_string(&json!({
                "version": 1,
                "entries": [
                    { "id": "e1", "pageUrl": "/", "ops": [{"ref": "r1", "originalText": "a"}] },
                    { "id": "e2", "pageUrl": "/x", "ops": [{"ref": "r2", "originalText": "b"}] },
                ],
            }))
            .unwrap(),
        )
        .unwrap();

        let result = build_manual_edit_evidence(&tmp.0, &live_dir, Some("/x"));
        assert_eq!(result["count"], json!(1));
        assert_eq!(result["entries"].as_array().unwrap().len(), 1);
    }
}
