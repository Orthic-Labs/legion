//! Port of `skills/designer/engine/scripts/live-inject.mjs` (chunk w2_018).
//!
//! Inserts/removes the live variant mode `<script>` tag in a project's HTML
//! entry point, and patches/reverts a Content-Security-Policy `<meta>` tag
//! to allow the injected script's origin.
//!
//! Ported in full: glob-to-regex file resolution (`resolveFiles`),
//! config validation, tag build/insert/remove, and CSP meta patch/revert —
//! all self-contained pure logic operating on strings.
//!
//! NOT ported: the `injectCli` driver's SvelteKit branch
//! (`detectSvelteKitProject`/`applySvelteKitLiveAdapter`/
//! `removeSvelteKitLiveAdapter` from `live/sveltekit-adapter.mjs`) and its
//! config-path resolution (`resolveLiveConfigPath` from
//! `lib/impeccable-paths.mjs`) — neither has an existing Rust port and
//! neither is in this chunk's owned scope. `ensureLiveGitIgnores` is ported
//! (self-contained: reads `.git`/`.gitignore` directly).

use regex::Regex;
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
    let replacement = if trailing.contains('\n') || trailing.contains('\r') {
        leading_indent.to_string()
    } else if !leading_indent.is_empty() {
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
    let http_equiv_re = Regex::new(
        r#"(?i)(http-equiv|httpEquiv)\s*=\s*(['"])Content-Security-Policy\2"#,
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
    let re = Regex::new(&format!(r#"(?i)\b{name}\s*=\s*(['"])([\s\S]*?)\1"#)).ok()?;
    let m = re.captures(attrs)?;
    let quote = m.get(1)?.as_str().chars().next()?;
    Some(Attr {
        quote,
        value: m.get(2)?.as_str().to_string(),
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
        let new_content_attr = format!(
            "content={q}{original_value}{q}",
            q = content_attr.quote
        );
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
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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
    let bytes: Vec<u8> = input.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()).collect();
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

fn resolve_git_info_exclude_path(cwd: &Path) -> Option<PathBuf> {
    let dot_git = cwd.join(".git");
    if !dot_git.exists() {
        return None;
    }
    let meta = fs::metadata(&dot_git).ok()?;
    if meta.is_dir() {
        return Some(dot_git.join("info").join("exclude"));
    }
    if !meta.is_file() {
        return None;
    }
    let body = fs::read_to_string(&dot_git).ok()?.trim().to_string();
    let re = Regex::new(r"(?i)^gitdir:\s*(.+)$").unwrap();
    let caps = re.captures(&body)?;
    let raw = caps.get(1)?.as_str();
    let git_dir = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        cwd.join(raw)
    };
    Some(git_dir.join("info").join("exclude"))
}

fn resolve_ignore_target(cwd: &Path) -> (PathBuf, &'static str) {
    if let Some(p) = resolve_git_info_exclude_path(cwd) {
        (p, "git-info-exclude")
    } else {
        (cwd.join(".gitignore"), "gitignore")
    }
}

/// Mirrors `ensureLiveGitIgnores(cwd)`.
pub fn ensure_live_gitignores(cwd: &Path) -> std::io::Result<GitIgnoreResult> {
    let (target_path, mode) = resolve_ignore_target(cwd);
    let existing = fs::read_to_string(&target_path).unwrap_or_default();

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
        .strip_prefix(cwd)
        .unwrap_or(&target_path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");

    Ok(GitIgnoreResult {
        file,
        mode,
        changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(insert_before: Option<&str>, insert_after: Option<&str>) -> InjectConfig {
        InjectConfig {
            files: vec!["index.html".to_string()],
            exclude: vec![],
            insert_before: insert_before.map(String::from),
            insert_after: insert_after.map(String::from),
            comment_syntax: "html".to_string(),
        }
    }

    #[test]
    fn validate_config_requires_files() {
        let mut c = cfg(Some("</body>"), None);
        c.files = vec![];
        assert_eq!(validate_config(&c), Err(ConfigError::FilesRequired));
    }

    #[test]
    fn validate_config_requires_an_anchor() {
        let c = cfg(None, None);
        assert_eq!(validate_config(&c), Err(ConfigError::InsertAnchorRequired));
    }

    #[test]
    fn validate_config_rejects_bad_comment_syntax() {
        let mut c = cfg(Some("</body>"), None);
        c.comment_syntax = "css".to_string();
        assert_eq!(validate_config(&c), Err(ConfigError::InvalidCommentSyntax));
    }

    #[test]
    fn validate_config_accepts_well_formed_config() {
        assert!(validate_config(&cfg(Some("</body>"), None)).is_ok());
    }

    #[test]
    fn glob_to_regex_matches_double_star() {
        let re = glob_to_regex("**/node_modules/**");
        assert!(re.is_match("a/node_modules/x.js"));
        assert!(re.is_match("node_modules/x.js"));
        assert!(!re.is_match("src/app.js"));
    }

    #[test]
    fn insert_before_uses_last_occurrence() {
        let content = "<html>\n</body>\n<!-- comment with </body> inside -->\n</body>\n</html>";
        let c = cfg(Some("</body>"), None);
        let out = insert_tag(content, &c, 4321, "index.html");
        assert!(out.contains(&format!("{MARKER_OPEN_TEXT}")));
        // Inserted right before the LAST </body>.
        let marker_idx = out.find(MARKER_OPEN_TEXT).unwrap();
        let last_body_idx = out.rfind("</body>").unwrap();
        assert!(marker_idx < last_body_idx);
        let first_body_idx = out.find("</body>").unwrap();
        assert!(marker_idx > first_body_idx);
    }

    #[test]
    fn insert_after_uses_first_occurrence() {
        let content = "<html><head></head><body>content</body></html>";
        let c = cfg(None, Some("<body>"));
        let out = insert_tag(content, &c, 4321, "index.html");
        assert!(out.contains("<script "));
        assert!(out.contains("http://localhost:4321/live.js"));
    }

    #[test]
    fn insert_tag_missing_anchor_is_a_no_op() {
        let content = "<html></html>";
        let c = cfg(Some("</body>"), None);
        assert_eq!(insert_tag(content, &c, 1, "index.html"), content);
    }

    #[test]
    fn insert_then_remove_round_trips() {
        let content = "<html><head></head><body>content</body></html>";
        let c = cfg(None, Some("<body>"));
        let inserted = insert_tag(content, &c, 4321, "index.html");
        assert_ne!(inserted, content);
        let removed = remove_tag(&inserted);
        assert_eq!(removed, content);
    }

    #[test]
    fn remove_tag_jsx_syntax() {
        let content = "<div>{/* impeccable-live-start */}\n<script src=\"x\"></script>\n{/* impeccable-live-end */}\n</div>";
        let removed = remove_tag(content);
        assert_eq!(removed, "<div>\n</div>");
    }

    #[test]
    fn build_tag_block_astro_adds_is_inline() {
        let block = build_tag_block("html", 5000, "src/pages/index.astro");
        assert!(block.contains("is:inline "));
        assert!(block.contains(MARKER_OPEN_TEXT));
    }

    #[test]
    fn build_tag_block_non_astro_has_no_is_inline() {
        let block = build_tag_block("html", 5000, "index.html");
        assert!(!block.contains("is:inline"));
    }

    #[test]
    fn patch_and_revert_csp_meta_round_trips() {
        let content = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'"></head></html>"#;
        let patched = patch_csp_meta(content, 4321);
        assert!(patched.contains("http://localhost:4321"));
        assert!(patched.contains(CSP_MARKER_ATTR));
        let reverted = revert_csp_meta(&patched);
        assert_eq!(reverted, content);
    }

    #[test]
    fn patch_csp_meta_no_meta_tag_is_a_no_op() {
        let content = "<html></html>";
        assert_eq!(patch_csp_meta(content, 1), content);
    }

    #[test]
    fn patch_csp_meta_is_idempotent_when_already_patched() {
        let content = r#"<meta http-equiv="Content-Security-Policy" content="script-src 'self'">"#;
        let once = patch_csp_meta(content, 4321);
        let twice = patch_csp_meta(&once, 4321);
        assert_eq!(once, twice);
    }

    #[test]
    fn base64_round_trip() {
        for s in ["", "a", "ab", "abc", "script-src 'self'; connect-src 'self' http://x"] {
            let enc = base64_encode(s.as_bytes());
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(dec, s);
        }
    }
}
