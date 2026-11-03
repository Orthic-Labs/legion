//! Port of `skills/designer/engine/scripts/live-inject.mjs` (chunk w2_018 /
//! packet r21).
//!
//! Inserts/removes the live variant mode `<script>` tag in a project's HTML
//! entry point, and patches/reverts a Content-Security-Policy `<meta>` tag
//! to allow the injected script's origin.
//!
//! Ported in full: glob-to-regex file resolution (`resolveFiles`),
//! config validation, tag build/insert/remove, CSP meta patch/revert, the
//! `.gitignore`/`git/info/exclude` writer (`ensureLiveGitIgnores`), AND the
//! `injectCli()` driver itself as [`run`] — including its `--help`/`--check`/
//! `--remove`/`--port` argv handling, its SvelteKit branch (now wired to
//! `w2_022::sveltekit_adapter::{detect_sveltekit_project,
//! apply_sveltekit_live_adapter, remove_sveltekit_live_adapter}`), and its
//! config-path resolution (now wired to
//! `w2_016::impeccable_paths::resolve_live_config_path`). Every function in
//! the JS source is ported; nothing is PORTED-PARTIAL.

use crate::wf_port::w2_016::impeccable_paths;
use crate::wf_port::w2_022::sveltekit_adapter;
use regex::Regex;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub const MARKER_OPEN_TEXT: &str = "impeccable-live-start";
pub const MARKER_CLOSE_TEXT: &str = "impeccable-live-end";
const IGNORE_MARKER_OPEN: &str = "# impeccable-live-ignore-start";
const IGNORE_MARKER_CLOSE: &str = "# impeccable-live-ignore-end";

pub const LIVE_IGNORE_PATTERNS: &[&str] = &[
    ".impeccable/hook.cache.json",
    ".impeccable/hook.pending.json",
    ".impeccable/config.local.json",
    ".impeccable/live/server.json",
    ".impeccable/live/sessions/",
    ".impeccable/live/previews/",
    ".impeccable/live/annotations/",
    ".impeccable/live/cache/",
    ".impeccable/live/manual-edit-apply-transaction.json",
    ".impeccable/live/manual-edit-events.jsonl",
    ".impeccable/live/manual-edit-evidence/",
    ".impeccable/live/pending-manual-edits.json",
    ".impeccable/live/deferred-svelte-component-accepts.json",
    ".impeccable-live.json",
    ".impeccable-live/",
    "node_modules/.impeccable-live/",
    "src/lib/designer/ImpeccableLiveRoot.svelte",
    "src/lib/designer/__runtime.js",
    "src/lib/designer/[0-9a-f]*/",
];

const HARD_EXCLUDES: &[&str] = &["**/node_modules/**", "**/.git/**"];

/// Mirrors `validateConfig(cfg)`, using an `InjectConfig` already parsed
/// from JSON.
#[derive(Debug, Clone)]
pub struct InjectConfig {
    pub files: Vec<String>,
    pub exclude: Vec<String>,
    pub insert_before: Option<String>,
    pub insert_after: Option<String>,
    /// `"html"` or `"jsx"`.
    pub comment_syntax: String,
}

/// Structured result of removing the live browser injection from the current
/// project. `payload` retains per-file detail for both CLI output and the
/// live-server stop outcome; `ok` is false if any target failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalReport {
    pub ok: bool,
    pub payload: serde_json::Value,
}

fn removal_report(payload: serde_json::Value) -> RemovalReport {
    let ok = payload.get("ok").and_then(serde_json::Value::as_bool) == Some(true);
    RemovalReport { ok, payload }
}

fn removal_target(cwd: &Path, rel_file: &str) -> Result<PathBuf, &'static str> {
    let target =
        sveltekit_adapter::project_mutation_target(cwd, Path::new(rel_file)).map_err(|err| {
            match err.kind() {
                std::io::ErrorKind::PermissionDenied => "path_outside_project",
                std::io::ErrorKind::NotFound => "file_not_found",
                _ => "file_unreadable",
            }
        })?;
    match fs::symlink_metadata(&target) {
        Ok(_) => Ok(target),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err("file_not_found"),
        Err(_) => Err("file_unreadable"),
    }
}

fn remove_configured_files(
    cwd: &Path,
    resolved_files: &[String],
    config_files: &[String],
    svelte_kit: bool,
) -> RemovalReport {
    if svelte_kit {
        match sveltekit_adapter::remove_sveltekit_live_adapter(cwd, Some(config_files)) {
            Ok(Some(r)) => {
                return removal_report(json!({
                    "ok": true,
                    "adapter": "sveltekit",
                    "results": [{
                        "file": r.file,
                        "removed": r.removed,
                        "appHtmlUntouched": r.app_html_untouched,
                        "rootComponent": r.root_component,
                    }],
                }));
            }
            Err(err) => {
                return removal_report(json!({
                    "ok": false,
                    "error": "io_error",
                    "message": err.to_string(),
                    "results": [],
                }));
            }
            Ok(None) => {} // Detection can race a project edit; use configured file removal.
        }
    }

    let mut results = Vec::new();
    let mut targets = Vec::new();
    if resolved_files.is_empty() {
        results.push(json!({ "error": "no_files_resolved" }));
    }
    for rel_file in resolved_files {
        match removal_target(cwd, rel_file) {
            Ok(path) => targets.push((rel_file, path)),
            Err(error) => {
                results.push(json!({ "file": rel_file, "error": error }));
            }
        }
    }
    if !results.is_empty() {
        return removal_report(json!({ "ok": false, "results": results }));
    }
    for (rel_file, abs_file) in targets {
        let content = match fs::read_to_string(&abs_file) {
            Ok(c) => c,
            Err(err) => {
                results.push(json!({ "file": rel_file, "error": err.to_string() }));
                continue;
            }
        };
        let detagged = remove_tag(&content);
        let updated = revert_csp_meta(&detagged);
        if updated == content {
            results.push(json!({ "file": rel_file, "removed": false, "note": "no tag present" }));
            continue;
        }
        if let Err(err) = fs::write(&abs_file, &updated) {
            results.push(json!({ "file": rel_file, "error": err.to_string() }));
            continue;
        }
        results.push(json!({
            "file": rel_file,
            "removed": detagged != content,
            "cspReverted": updated != detagged,
        }));
    }
    let ok = results.iter().all(|result| result.get("error").is_none());
    removal_report(json!({ "ok": ok, "results": results }))
}

/// Resolve config against only `cwd` and remove that project's injection.
/// The running server record is intentionally not an input: it may already
/// have disappeared when a caller retries cleanup.
pub fn remove_project_injection(
    cwd: &Path,
    scripts_dir: Option<&Path>,
    env_live_config: Option<&str>,
) -> RemovalReport {
    let config_path =
        impeccable_paths::resolve_live_config_path(cwd, cwd, scripts_dir, env_live_config);
    if !config_path.exists() {
        // Preserve default SvelteKit cleanup when config was deleted before a
        // stop retry. Configured entry files are used whenever config remains.
        if sveltekit_adapter::detect_sveltekit_project(cwd, None).is_some() {
            return remove_configured_files(cwd, &[], &[], true);
        }
        return removal_report(json!({
            "ok": false,
            "error": "config_missing",
            "path": config_path.to_string_lossy(),
            "results": [],
        }));
    }
    let raw = match fs::read_to_string(&config_path) {
        Ok(raw) => raw,
        Err(err) => {
            return removal_report(json!({
                "ok": false,
                "error": "config_invalid",
                "message": err.to_string(),
                "path": config_path.to_string_lossy(),
                "results": [],
            }));
        }
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            return removal_report(json!({
                "ok": false,
                "error": "config_invalid",
                "message": err.to_string(),
                "path": config_path.to_string_lossy(),
                "results": [],
            }));
        }
    };
    let config = parse_inject_config(&parsed);
    if let Err(err) = validate_config(&config) {
        return removal_report(json!({
            "ok": false,
            "error": "config_invalid",
            "message": format!("{err:?}"),
            "path": config_path.to_string_lossy(),
            "results": [],
        }));
    }
    let resolved_files = resolve_files(cwd, &config);
    let svelte_kit =
        sveltekit_adapter::detect_sveltekit_project(cwd, Some(&config.files)).is_some();
    remove_configured_files(cwd, &resolved_files, &config.files, svelte_kit)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    FilesRequired,
    InsertAnchorRequired,
    InvalidCommentSyntax,
}

/// Mirrors `validateConfig(cfg)`'s structural checks that survive once JSON
/// has already been deserialized into `InjectConfig` (the JS's "must be a
/// non-empty string array"/"must be an object" type checks are subsumed by
/// Rust's type system at the deserialization boundary).
pub fn validate_config(cfg: &InjectConfig) -> Result<(), ConfigError> {
    if cfg.files.is_empty() || cfg.files.iter().any(|f| f.is_empty()) {
        return Err(ConfigError::FilesRequired);
    }
    if cfg.exclude.iter().any(|f| f.is_empty()) {
        return Err(ConfigError::FilesRequired);
    }
    if cfg.insert_before.is_none() && cfg.insert_after.is_none() {
        return Err(ConfigError::InsertAnchorRequired);
    }
    if cfg.comment_syntax != "html" && cfg.comment_syntax != "jsx" {
        return Err(ConfigError::InvalidCommentSyntax);
    }
    Ok(())
}

/// Mirrors `globToRegex(pattern)`.
pub fn glob_to_regex(pattern: &str) -> Regex {
    let mut re = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '*' {
            if chars.get(i + 1) == Some(&'*') {
                if chars.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    re.push_str(".*");
                    i += 2;
                }
            } else {
                re.push_str("[^/]*");
                i += 1;
            }
        } else if c == '?' {
            re.push_str("[^/]");
            i += 1;
        } else if ".+^${}()|[]\\".contains(c) {
            re.push('\\');
            re.push(c);
            i += 1;
        } else {
            re.push(c);
            i += 1;
        }
    }
    Regex::new(&format!("^{re}$")).expect("glob_to_regex produces a valid pattern")
}

fn is_glob(s: &str) -> bool {
    s.chars().any(|c| c == '*' || c == '?' || c == '[')
}

/// Mirrors `resolveFiles(rootDir, config)`. Expands `config.files` (literal
/// paths pass through unconditionally; globs are matched against files that
/// actually exist under `root_dir`) into a de-duplicated, order-preserving
/// list of paths relative to `root_dir` with forward slashes.
pub fn resolve_files(root_dir: &Path, config: &InjectConfig) -> Vec<String> {
    let all_excludes: Vec<&str> = HARD_EXCLUDES
        .iter()
        .copied()
        .chain(config.exclude.iter().map(String::as_str))
        .collect();
    let exclude_regexes: Vec<Regex> = all_excludes.iter().map(|p| glob_to_regex(p)).collect();
    let is_excluded = |rel: &str| exclude_regexes.iter().any(|re| re.is_match(rel));

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for pat in &config.files {
        if !is_glob(pat) {
            if seen.insert(pat.clone()) {
                out.push(pat.clone());
            }
            continue;
        }
        let matches = match glob_files(root_dir, pat) {
            Ok(m) => m,
            Err(_) => continue,
        };
        for abs in matches {
            let rel = abs
                .strip_prefix(root_dir)
                .unwrap_or(&abs)
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            if is_excluded(&rel) || seen.contains(&rel) {
                continue;
            }
            seen.insert(rel.clone());
            out.push(rel);
        }
    }
    out
}

/// Minimal recursive glob expansion sufficient for `**`, `*`, `?` file
/// patterns rooted at `root_dir`, mirroring `fs.globSync`'s file-only
/// results. This walks the directory tree; it does not attempt every glob
/// edge case `fs.globSync` supports, but matches the common `**/*.ext` and
/// `dir/*.ext` shapes used by live-inject configs.
fn glob_files(root_dir: &Path, pattern: &str) -> std::io::Result<Vec<PathBuf>> {
    let re = glob_to_regex(pattern);
    let mut out = Vec::new();
    walk(root_dir, root_dir, &re, &mut out)?;
    Ok(out)
}

fn walk(root: &Path, dir: &Path, re: &Regex, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            let name = entry.file_name();
            if name == "node_modules" || name == ".git" {
                continue;
            }
            walk(root, &path, re, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            if re.is_match(&rel) {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn comment_open(syntax: &str) -> &'static str {
    if syntax == "jsx" {
        "{/*"
    } else {
        "<!--"
    }
}
fn comment_close(syntax: &str) -> &'static str {
    if syntax == "jsx" {
        "*/}"
    } else {
        "-->"
    }
}

/// Mirrors `buildTagBlock(syntax, port, filePath)`.
pub fn build_tag_block(syntax: &str, port: u32, file_path: &str) -> String {
    let open = comment_open(syntax);
    let close = comment_close(syntax);
    let is_astro = file_path.ends_with(".astro");
    let script_attrs = if is_astro { "is:inline " } else { "" };
    format!(
        "{open} {MARKER_OPEN_TEXT} {close}\n<script {script_attrs}src=\"http://localhost:{port}/live.js\"></script>\n{open} {MARKER_CLOSE_TEXT} {close}\n",
    )
}

fn detect_line_ending(content: &str) -> &'static str {
    if content.contains("\r\n") {
        "\r\n"
    } else if content.contains('\r') {
        "\r"
    } else {
        "\n"
    }
}

fn normalize_line_endings(content: &str, line_ending: &str) -> String {
    if line_ending == "\n" {
        content.to_string()
    } else {
        content.replace('\n', line_ending)
    }
}

fn read_line_ending_at(bytes: &[u8], index: usize) -> &'static str {
    match (bytes.get(index), bytes.get(index + 1)) {
        (Some(b'\r'), Some(b'\n')) => "\r\n",
        (Some(b'\n'), _) => "\n",
        (Some(b'\r'), _) => "\r",
        _ => "",
    }
}

/// Mirrors `insertTag(content, config, port, filePath)`. Returns the
/// unchanged content when the configured anchor cannot be found (mirrors the
/// JS returning `content` unmodified in that case).
pub fn insert_tag(content: &str, config: &InjectConfig, port: u32, file_path: &str) -> String {
    let line_ending = detect_line_ending(content);
    let block = normalize_line_endings(
        &build_tag_block(&config.comment_syntax, port, file_path),
        line_ending,
    );

    if let Some(anchor) = &config.insert_before {
        return match content.rfind(anchor.as_str()) {
            Some(idx) => format!("{}{}{}", &content[..idx], block, &content[idx..]),
            None => content.to_string(),
        };
    }
    let anchor = match &config.insert_after {
        Some(a) => a,
        None => return content.to_string(),
    };
    match content.find(anchor.as_str()) {
        Some(idx) => {
            let after = idx + anchor.len();
            let bytes = content.as_bytes();
            let existing_newline = read_line_ending_at(bytes, after);
            let prefix_end = after + existing_newline.len();
            let prefix = if existing_newline.is_empty() {
                format!("{}{}", &content[..after], line_ending)
            } else {
                content[..prefix_end].to_string()
            };
            let rest = &content[prefix_end..];
            format!("{prefix}{block}{rest}")
        }
        None => content.to_string(),
    }
}

/// Mirrors `removeTag(content, _syntax)`: strips either an HTML or JSX
/// `impeccable-live-start`/`impeccable-live-end` block, preserving a
/// captured leading indent so it hands back to whatever followed.
pub fn remove_tag(content: &str) -> String {
    let patterns = [
        Regex::new(r"(?s)([ \t]*)<!--\s*impeccable-live-start\s*-->.*?<!--\s*impeccable-live-end\s*-->([ \t]*(?:\r\n|\n|\r)?)")
            .unwrap(),
        Regex::new(r"(?s)([ \t]*)\{/\*\s*impeccable-live-start\s*\*/\}.*?\{/\*\s*impeccable-live-end\s*\*/\}([ \t]*(?:\r\n|\n|\r)?)")
            .unwrap(),
    ];
    let mut content = content.to_string();
    for pat in &patterns {
        let mut changed = false;
        loop {
            let next = replace_first_removal(pat, &content);
            match next {
                Some(n) if n != content => {
                    content = n;
                    changed = true;
                }
                _ => break,
            }
        }
        if changed {
            return content;
        }
    }
    content
}

fn replace_first_removal(pat: &Regex, content: &str) -> Option<String> {
    let caps = pat.captures(content)?;
    let whole = caps.get(0).unwrap();
    let leading_indent = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let trailing = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let replacement =
        if trailing.contains('\n') || trailing.contains('\r') || !leading_indent.is_empty() {
            leading_indent.to_string()
        } else {
            trailing.to_string()
        };
    Some(format!(
        "{}{}{}",
        &content[..whole.start()],
        replacement,
        &content[whole.end()..]
    ))
}

// --- CSP meta-tag patch/revert -------------------------------------------

const CSP_MARKER_ATTR: &str = "data-impeccable-csp-original";

struct CspTag {
    start: usize,
    end: usize,
    full: String,
    attrs: String,
}

fn find_csp_meta_tags(content: &str) -> Vec<CspTag> {
    let tag_re = Regex::new(r"(?is)<meta\s+([^>]*?)/?>").unwrap();
    // JS uses a backreference (`(['"])Content-Security-Policy\2`) to require
    // the same quote character on both sides; the `regex` crate has no
    // backreference support, so this expands into an explicit alternation
    // over the two quote characters, which is equivalent.
    let http_equiv_re = Regex::new(
        r#"(?i)(http-equiv|httpEquiv)\s*=\s*('Content-Security-Policy'|"Content-Security-Policy")"#,
    )
    .unwrap();
    let mut out = Vec::new();
    for m in tag_re.captures_iter(content) {
        let whole = m.get(0).unwrap();
        let attrs = m.get(1).unwrap().as_str();
        if !http_equiv_re.is_match(attrs) {
            continue;
        }
        out.push(CspTag {
            start: whole.start(),
            end: whole.end(),
            full: whole.as_str().to_string(),
            attrs: attrs.to_string(),
        });
    }
    out
}

struct Attr {
    quote: char,
    value: String,
    full: String,
}

fn get_attr(attrs: &str, name: &str) -> Option<Attr> {
    // JS uses a backreference (`(['"])([\s\S]*?)\1`) to require the same
    // quote character on both sides; the `regex` crate has no backreference
    // support, so this expands into an explicit alternation over the two
    // quote characters (mirrors `http_equiv_re` above).
    let re = Regex::new(&format!(
        r#"(?i)\b{name}\s*=\s*(?:"([\s\S]*?)"|'([\s\S]*?)')"#
    ))
    .ok()?;
    let m = re.captures(attrs)?;
    let (quote, value) = if let Some(v) = m.get(1) {
        ('"', v.as_str())
    } else {
        ('\'', m.get(2)?.as_str())
    };
    Some(Attr {
        quote,
        value: value.to_string(),
        full: m.get(0)?.as_str().to_string(),
    })
}

fn append_origin_to_directive(csp: &str, directive: &str, origin: &str) -> String {
    let re = Regex::new(&format!(r"(?i)(^|;)(\s*)({directive})\s+([^;]*)")).unwrap();
    if let Some(m) = re.captures(csp) {
        let tokens_raw = m.get(4).unwrap().as_str().trim();
        let mut tokens: Vec<&str> = tokens_raw.split_whitespace().collect();
        if tokens.contains(&origin) {
            return csp.to_string();
        }
        tokens.push(origin);
        let replacement = format!(
            "{}{}{} {}",
            m.get(1).unwrap().as_str(),
            m.get(2).unwrap().as_str(),
            m.get(3).unwrap().as_str(),
            tokens.join(" ")
        );
        let whole = m.get(0).unwrap();
        return format!(
            "{}{}{}",
            &csp[..whole.start()],
            replacement,
            &csp[whole.end()..]
        );
    }
    let trimmed = Regex::new(r";?\s*$").unwrap().replace(csp.trim(), "");
    format!("{trimmed}; {directive} 'self' {origin}")
}

/// Mirrors `patchCspMeta(content, port)`.
pub fn patch_csp_meta(content: &str, port: u32) -> String {
    let tags = find_csp_meta_tags(content);
    if tags.is_empty() {
        return content.to_string();
    }
    let origin = format!("http://localhost:{port}");
    let mut result = content.to_string();
    for tag in tags.iter().rev() {
        let attrs = &tag.attrs;
        if get_attr(attrs, CSP_MARKER_ATTR).is_some() {
            continue;
        }
        let Some(content_attr) = get_attr(attrs, "content") else {
            continue;
        };
        let original = content_attr.value.clone();
        let mut patched = original.clone();
        patched = append_origin_to_directive(&patched, "script-src", &origin);
        patched = append_origin_to_directive(&patched, "connect-src", &origin);
        patched = append_origin_to_directive(&patched, "img-src", "blob:");
        if patched == original {
            continue;
        }

        let new_content_attr = format!(
            "content={q}{patched}{q}",
            q = content_attr.quote,
            patched = patched
        );
        let marker = format!(
            "{CSP_MARKER_ATTR}=\"{}\"",
            base64_encode(original.as_bytes())
        );
        let trailing_ws: String = attrs
            .chars()
            .rev()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let attrs_body = &attrs[..attrs.len() - trailing_ws.len()];
        let new_attrs = format!(
            "{}{trailing_ws}",
            attrs_body.replacen(&content_attr.full, &new_content_attr, 1) + " " + marker.as_str()
        );
        let new_tag = tag.full.replacen(attrs.as_str(), &new_attrs, 1);
        result = format!("{}{}{}", &result[..tag.start], new_tag, &result[tag.end..]);
    }
    result
}

/// Mirrors `revertCspMeta(content)`.
pub fn revert_csp_meta(content: &str) -> String {
    let tags = find_csp_meta_tags(content);
    if tags.is_empty() {
        return content.to_string();
    }
    let mut result = content.to_string();
    for tag in tags.iter().rev() {
        let Some(orig_attr) = get_attr(&tag.attrs, CSP_MARKER_ATTR) else {
            continue;
        };
        let Some(content_attr) = get_attr(&tag.attrs, "content") else {
            continue;
        };
        let Some(original_value) = base64_decode(&orig_attr.value) else {
            continue;
        };
        let new_content_attr = format!("content={q}{original_value}{q}", q = content_attr.quote);
        let mut new_attrs = tag.attrs.replacen(&content_attr.full, &new_content_attr, 1);
        let marker_re = Regex::new(&format!(r"\s*{}", regex::escape(&orig_attr.full))).unwrap();
        new_attrs = marker_re.replace(&new_attrs, "").to_string();
        let new_tag = tag.full.replacen(tag.attrs.as_str(), &new_attrs, 1);
        result = format!("{}{}{}", &result[..tag.start], new_tag, &result[tag.end..]);
    }
    result
}

// Standard base64 (no external crate dependency; legion-runtime does not
// currently depend on `base64`, though the workspace lock has it at 0.22.1
// for other crates — see the port report for the add-a-dependency note).
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(input: &str) -> Option<String> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|b| *b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        let mut valid = 0usize;
        for &c in chunk {
            n = (n << 6) | val(c)?;
            valid += 1;
        }
        n <<= 6 * (4 - valid);
        let total_bits = valid * 6;
        if total_bits >= 8 {
            out.push(((n >> 16) & 0xff) as u8);
        }
        if total_bits >= 16 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if total_bits >= 24 {
            out.push((n & 0xff) as u8);
        }
    }
    String::from_utf8(out).ok()
}

// --- .gitignore / git info/exclude management ----------------------------

pub struct GitIgnoreResult {
    pub file: String,
    pub mode: &'static str,
    pub changed: bool,
}

fn escape_regexp(value: &str) -> String {
    regex::escape(value)
}

fn resolve_git_info_exclude_path(cwd: &Path) -> std::io::Result<Option<PathBuf>> {
    let root = cwd.canonicalize()?;
    let dot_git = root.join(".git");
    let dot_git_target = sveltekit_adapter::project_mutation_target(&root, Path::new(".git"))?;
    let link_meta = match fs::symlink_metadata(&dot_git_target) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let meta = if link_meta.file_type().is_symlink() {
        fs::metadata(&dot_git_target)?
    } else {
        link_meta
    };
    if meta.is_dir() {
        return Ok(Some(sveltekit_adapter::project_mutation_target(
            &root,
            Path::new(".git/info/exclude"),
        )?));
    }
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            ".git is neither a directory nor a gitdir file",
        ));
    }
    let body = fs::read_to_string(&dot_git)?.trim().to_string();
    let re = Regex::new(r"(?i)^gitdir:\s*(.+)$").unwrap();
    let caps = re.captures(&body).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid .git gitdir file")
    })?;
    let raw = caps.get(1).expect("capture group exists").as_str();
    let git_dir = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        root.join(raw)
    };
    let canonical_git_dir = git_dir.canonicalize()?;
    if !canonical_git_dir.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            ".git gitdir target is not a directory",
        ));
    }
    if !canonical_git_dir.starts_with(&root) {
        return Ok(None);
    }
    let relative_git_dir = canonical_git_dir.strip_prefix(&root).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "gitdir escapes project")
    })?;
    let relative_exclude = relative_git_dir.join("info").join("exclude");
    Ok(Some(sveltekit_adapter::project_mutation_target(
        &root,
        &relative_exclude,
    )?))
}

fn resolve_ignore_target(cwd: &Path) -> std::io::Result<(PathBuf, &'static str)> {
    if let Some(path) = resolve_git_info_exclude_path(cwd)? {
        Ok((path, "git-info-exclude"))
    } else {
        Ok((
            sveltekit_adapter::project_mutation_target(cwd, Path::new(".gitignore"))?,
            "gitignore",
        ))
    }
}

/// Mirrors `ensureLiveGitIgnores(cwd)`.
pub fn ensure_live_gitignores(cwd: &Path) -> std::io::Result<GitIgnoreResult> {
    let canonical_cwd = cwd.canonicalize()?;
    let (target_path, mode) = resolve_ignore_target(&canonical_cwd)?;
    let existing = match fs::read_to_string(&target_path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err),
    };

    let mut block_lines = vec![IGNORE_MARKER_OPEN.to_string()];
    block_lines.extend(LIVE_IGNORE_PATTERNS.iter().map(|s| s.to_string()));
    block_lines.push(IGNORE_MARKER_CLOSE.to_string());
    let block = block_lines.join("\n");

    let marker_re = Regex::new(&format!(
        r"(?s){}[\s\S]*?{}",
        escape_regexp(IGNORE_MARKER_OPEN),
        escape_regexp(IGNORE_MARKER_CLOSE)
    ))
    .unwrap();

    let updated = if marker_re.is_match(&existing) {
        marker_re.replace(&existing, block.as_str()).to_string()
    } else {
        let prefix = if existing.is_empty() {
            String::new()
        } else if existing.ends_with('\n') {
            existing.clone()
        } else {
            format!("{existing}\n")
        };
        let extra_newline = if prefix.ends_with("\n\n") || prefix.is_empty() {
            ""
        } else {
            "\n"
        };
        format!("{prefix}{extra_newline}{block}\n")
    };

    let changed = updated != existing;
    if changed {
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target_path, &updated)?;
    }

    let file = target_path
        .strip_prefix(&canonical_cwd)
        .unwrap_or(&target_path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");

    Ok(GitIgnoreResult {
        file,
        mode,
        changed,
    })
}

// --- CLI driver ------------------------------------------------------------

/// Parses an [`InjectConfig`] out of the raw `config.json` `serde_json::Value`,
/// mirroring the JS's untyped `JSON.parse(...)` (missing/wrong-typed fields
/// fall back to JS-`undefined`-equivalent defaults, exactly as
/// `validateConfig` would then reject them).
fn parse_inject_config(v: &serde_json::Value) -> InjectConfig {
    let files = v
        .get("files")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let exclude = v
        .get("exclude")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let insert_before = v
        .get("insertBefore")
        .and_then(|f| f.as_str())
        .map(String::from);
    let insert_after = v
        .get("insertAfter")
        .and_then(|f| f.as_str())
        .map(String::from);
    let comment_syntax = v
        .get("commentSyntax")
        .and_then(|f| f.as_str())
        .unwrap_or_default()
        .to_string();
    InjectConfig {
        files,
        exclude,
        insert_before,
        insert_after,
        comment_syntax,
    }
}

fn gitignore_result_json(r: &GitIgnoreResult) -> serde_json::Value {
    json!({
        "file": r.file,
        "mode": r.mode,
        "changed": r.changed,
        "patterns": LIVE_IGNORE_PATTERNS,
    })
}

const USAGE: &str = "Usage: legion script designer/live-inject [options]\n\nInsert or remove the live mode script tag in the project's HTML entry point.\nReads configuration from .impeccable/live/config.json.\n\nModes:\n  --port PORT   Insert script tag pointing at http://localhost:PORT/live.js\n  --remove      Remove the script tag (if present)\n  --check       Print whether .impeccable/live/config.json exists and its content\n\nOutput (JSON):\n  { ok, file, inserted|removed, config? }";

/// Mirrors `injectCli()`: the full CLI entrypoint, argv handling, and
/// process orchestration of `live-inject.mjs`. `cwd` mirrors
/// `process.cwd()`; `scripts_dir` mirrors the caller's `__dirname` (used
/// only for the legacy config-path fallback); `env_live_config` is an explicit
/// override; production callers pass `None`. Prints the same JSON payloads the
/// JS prints to stdout/stderr via `println!`/`eprintln!`, and returns the
/// process exit code in place of the JS's `process.exit(code)`.
pub fn run(
    args: &[String],
    cwd: &Path,
    scripts_dir: Option<&Path>,
    env_live_config: Option<&str>,
) -> i32 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return 0;
    }

    let config_path =
        impeccable_paths::resolve_live_config_path(cwd, cwd, scripts_dir, env_live_config);

    if args.iter().any(|a| a == "--check") {
        if !config_path.exists() {
            println!(
                "{}",
                json!({ "ok": false, "error": "config_missing", "path": config_path.to_string_lossy() })
            );
            return 0;
        }
        let raw = match fs::read_to_string(&config_path) {
            Ok(s) => s,
            Err(err) => {
                println!(
                    "{}",
                    json!({ "ok": false, "error": "config_invalid", "message": err.to_string(), "path": config_path.to_string_lossy() })
                );
                return 0;
            }
        };
        let parsed: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(err) => {
                println!(
                    "{}",
                    json!({ "ok": false, "error": "config_invalid", "message": err.to_string(), "path": config_path.to_string_lossy() })
                );
                return 0;
            }
        };
        let cfg = parse_inject_config(&parsed);
        if let Err(e) = validate_config(&cfg) {
            println!(
                "{}",
                json!({ "ok": false, "error": "config_invalid", "message": format!("{e:?}"), "path": config_path.to_string_lossy() })
            );
            return 0;
        }
        println!(
            "{}",
            json!({ "ok": true, "config": parsed, "path": config_path.to_string_lossy() })
        );
        return 0;
    }

    if !config_path.exists() {
        eprintln!(
            "{}",
            json!({ "ok": false, "error": "config_missing", "path": config_path.to_string_lossy() })
        );
        return 1;
    }
    let raw = match fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "{}",
                json!({ "ok": false, "error": "config_invalid", "message": err.to_string() })
            );
            return 1;
        }
    };
    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "{}",
                json!({ "ok": false, "error": "config_invalid", "message": err.to_string() })
            );
            return 1;
        }
    };
    let config = parse_inject_config(&parsed);
    if let Err(e) = validate_config(&config) {
        eprintln!(
            "{}",
            json!({ "ok": false, "error": "config_invalid", "message": format!("{e:?}") })
        );
        return 1;
    }

    let resolved_files = resolve_files(cwd, &config);
    if args.iter().any(|a| a == "--remove") {
        let svelte_kit =
            sveltekit_adapter::detect_sveltekit_project(cwd, Some(&config.files)).is_some();
        let report = remove_configured_files(cwd, &resolved_files, &config.files, svelte_kit);
        println!("{}", report.payload);
        return if report.ok { 0 } else { 1 };
    }

    let svelte_kit = sveltekit_adapter::detect_sveltekit_project(cwd, Some(&config.files));

    // Insert mode — need --port.
    let port: Option<u32> = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u32>().ok());
    let Some(port) = port else {
        eprintln!("{}", json!({ "ok": false, "error": "missing_port" }));
        return 1;
    };

    let mut insert_targets = Vec::new();
    if let Some(detected) = &svelte_kit {
        for relative in [
            Path::new(&detected.layout_file),
            Path::new(sveltekit_adapter::SVELTE_LIVE_ROOT_COMPONENT),
        ] {
            if let Err(err) = sveltekit_adapter::project_mutation_target(cwd, relative) {
                eprintln!(
                    "{}",
                    json!({ "ok": false, "error": "path_outside_project", "message": err.to_string() })
                );
                return 1;
            }
        }
    } else {
        let mut target_errors = Vec::new();
        for rel_file in &resolved_files {
            match sveltekit_adapter::project_mutation_target(cwd, Path::new(rel_file)) {
                Ok(target) => match fs::symlink_metadata(&target) {
                    Ok(_) => insert_targets.push(target),
                    Err(err) => target_errors.push(json!({
                        "file": rel_file,
                        "error": if err.kind() == std::io::ErrorKind::NotFound { "file_not_found" } else { "file_unreadable" },
                    })),
                },
                Err(err) => target_errors.push(json!({
                    "file": rel_file,
                    "error": if err.kind() == std::io::ErrorKind::PermissionDenied { "path_outside_project" } else { "file_unreadable" },
                })),
            }
        }
        if !target_errors.is_empty() || resolved_files.is_empty() {
            if resolved_files.is_empty() {
                target_errors.push(json!({ "error": "no_files_resolved" }));
            }
            eprintln!("{}", json!({ "ok": false, "results": target_errors }));
            return 1;
        }
    }

    let git_ignore = match ensure_live_gitignores(cwd) {
        Ok(r) => r,
        Err(err) => {
            eprintln!(
                "{}",
                json!({ "ok": false, "error": "io_error", "message": err.to_string() })
            );
            return 1;
        }
    };
    let git_ignore_json = gitignore_result_json(&git_ignore);

    if svelte_kit.is_some() {
        let adapter_result = match sveltekit_adapter::apply_sveltekit_live_adapter(
            cwd,
            port as i64,
            Some(&config.files),
        ) {
            Ok(r) => r,
            Err(err) => {
                eprintln!(
                    "{}",
                    json!({ "ok": false, "error": "io_error", "message": err.to_string() })
                );
                return 1;
            }
        };
        let result_json = adapter_result.map(|r| {
            json!({
                "file": r.file,
                "adapter": "sveltekit",
                "inserted": r.inserted,
                "appHtmlUntouched": r.app_html_untouched,
                "rootComponent": r.root_component,
            })
        });
        println!(
            "{}",
            json!({ "ok": true, "port": port, "adapter": "sveltekit", "gitIgnore": git_ignore_json, "results": [result_json] })
        );
        return 0;
    }

    let mut results = Vec::new();
    let mut any_inserted = false;
    for (rel_file, abs_file) in resolved_files.iter().zip(insert_targets) {
        let content = match fs::read_to_string(&abs_file) {
            Ok(c) => c,
            Err(err) => {
                results.push(json!({ "file": rel_file, "error": err.to_string() }));
                continue;
            }
        };
        let without_old = revert_csp_meta(&remove_tag(&content));
        let with_tag = insert_tag(&without_old, &config, port, rel_file);
        if with_tag == without_old {
            let anchor = config
                .insert_before
                .as_deref()
                .or(config.insert_after.as_deref());
            results.push(
                json!({ "file": rel_file, "error": "insertion_point_not_found", "anchor": anchor }),
            );
            continue;
        }
        let updated = patch_csp_meta(&with_tag, port);
        if let Err(err) = fs::write(&abs_file, &updated) {
            results.push(json!({ "file": rel_file, "error": err.to_string() }));
            continue;
        }
        any_inserted = true;
        results.push(json!({
            "file": rel_file,
            "inserted": true,
            "cspPatched": updated != with_tag,
        }));
    }
    println!(
        "{}",
        json!({ "ok": any_inserted, "port": port, "gitIgnore": git_ignore_json, "results": results })
    );
    if any_inserted {
        0
    } else {
        1
    }
}
