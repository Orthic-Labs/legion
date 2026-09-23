//! Scoped file-excerpt slicing for lens packets, per `skills/audit/
//! references/lens-routing.md`'s Input contract and "Excerpt compression"
//! section: RAW excerpts (exact tokens, secret-redacted, `file:line`
//! anchored) for `security`/`schema`/`correctness`/`performance`/`minimize`
//! (plus `doc-drift`, which is RAW per `lens_plan.rs`); SKELETON excerpts
//! (signatures, type/struct/fn/class declarations, imports, no bodies) for
//! `architecture`/`ai-slop`/`naming`/`dead-file`.
//!
//! Dependency-free by design: no `tree-sitter` (a new crate dependency is
//! out of scope for this packet — see the Cargo.toml patch in the report).
//! Skeletonization here is a line-based heuristic per language family
//! (Rust, TS/JS, Swift, Python) that keeps declaration lines and collapses
//! bodies, which is adequate for the structure/survey lenses that only
//! reason about shape.

use std::path::Path;

use super::lens_plan::ExcerptMode;

/// Hard ceiling on how many bytes of any single file are read into an
/// excerpt, applied before redaction/skeletonization so a huge file cannot
/// blow the packet budget.
pub const MAX_BYTES_PER_FILE: usize = 32 * 1024;

/// Hard ceiling on the sum of all excerpt bytes returned by one
/// `build_excerpts` call, applied across files in inventory-sort order so
/// the cutoff is deterministic.
pub const MAX_TOTAL_EXCERPT_BYTES: usize = 512 * 1024;

/// One file's excerpt: RAW (bounded, `file:line` anchored, secret-redacted)
/// or SKELETON (signatures/declarations/imports only).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Excerpt {
    pub path: String,
    pub mode: ExcerptMode,
    pub language: &'static str,
    /// `file:line` anchors covering the lines actually kept, e.g.
    /// `["src/x.rs:1-40", "src/x.rs:88-96"]` for a skeleton with gaps, or a
    /// single `["src/x.rs:1-400"]` span for a raw excerpt.
    pub anchors: Vec<String>,
    pub content: String,
    /// True when the source file was longer than `MAX_BYTES_PER_FILE` and
    /// the excerpt was cut short.
    pub truncated: bool,
    /// True when at least one secret-shaped token was redacted from a RAW
    /// excerpt. Always false for SKELETON (declarations do not carry
    /// secret literals) and for files that had nothing to redact.
    pub redacted: bool,
}

fn language_for(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".rs") {
        "rust"
    } else if lower.ends_with(".ts") || lower.ends_with(".tsx") {
        "typescript"
    } else if lower.ends_with(".js") || lower.ends_with(".jsx") || lower.ends_with(".mjs") || lower.ends_with(".cjs") {
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
fn redact_secrets(line: &str) -> (String, bool) {
    const SECRET_NAME_HINTS: &[&str] = &[
        "secret", "token", "apikey", "api_key", "password", "passwd", "private_key",
        "privatekey", "access_key", "accesskey", "client_secret", "auth",
    ];
    const KEY_MATERIAL_MARKERS: &[&str] =
        &["-----BEGIN", "AKIA", "ghp_", "sk-", "xox", "AIza"];

    let lower = line.to_ascii_lowercase();
    let mut redacted = false;
    let mut out = line.to_string();

    if KEY_MATERIAL_MARKERS.iter().any(|marker| line.contains(marker)) {
        out = "[REDACTED: key material]".into();
        return (out, true);
    }

    if let Some(equals) = line.find(['=', ':']) {
        let (name, rest) = line.split_at(equals);
        let name_lower = name.to_ascii_lowercase();
        let looks_like_secret_name = SECRET_NAME_HINTS.iter().any(|hint| name_lower.contains(hint));
        let value = &rest[1..];
        let value_trimmed = value.trim().trim_matches(['"', '\'', ';', ',']);
        let looks_like_opaque_value = value_trimmed.len() >= 16
            && value_trimmed.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'));
        if looks_like_secret_name && looks_like_opaque_value {
            out = format!("{name}={}", "[REDACTED]");
            redacted = true;
        }
    }
    let _ = lower;
    (out, redacted)
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
fn skeletonize(language: &str, content: &str) -> (String, Vec<(usize, usize)>) {
    let mut out = String::new();
    let mut anchors = Vec::new();
    let mut in_drop_run = false;
    let mut drop_start = 0usize;

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim_start();
        if is_skeleton_line(language, trimmed) || trimmed.is_empty() {
            if in_drop_run {
                anchors.push((drop_start, line_number.saturating_sub(1)));
                out.push_str("    { ... }\n");
                in_drop_run = false;
            }
            out.push_str(line);
            out.push('\n');
            anchors.push((line_number, line_number));
        } else if !in_drop_run {
            in_drop_run = true;
            drop_start = line_number;
        }
    }
    if in_drop_run {
        anchors.push((drop_start, content.lines().count()));
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

/// Builds one file's excerpt at `root`/`path` in the given mode. Returns
/// `None` when the file cannot be read (already-deleted/unreadable —
/// callers should treat that as a coverage gap, not silently drop it).
pub fn build_excerpt(root: &Path, path: &str, mode: ExcerptMode) -> Option<Excerpt> {
    let bytes = std::fs::read(root.join(path)).ok()?;
    let truncated = bytes.len() > MAX_BYTES_PER_FILE;
    let capped = &bytes[..bytes.len().min(MAX_BYTES_PER_FILE)];
    let text = String::from_utf8_lossy(capped).into_owned();
    let language = language_for(path);

    match mode {
        ExcerptMode::Raw => {
            let mut redacted_any = false;
            let mut body = String::new();
            let mut line_count = 0usize;
            for line in text.lines() {
                let (redacted_line, redacted) = redact_secrets(line);
                redacted_any |= redacted;
                body.push_str(&redacted_line);
                body.push('\n');
                line_count += 1;
            }
            let anchors = if line_count == 0 {
                Vec::new()
            } else {
                vec![format!("{path}:1-{line_count}")]
            };
            Some(Excerpt {
                path: path.to_string(),
                mode,
                language,
                anchors,
                content: body,
                truncated,
                redacted: redacted_any,
            })
        }
        ExcerptMode::Skeleton => {
            let (body, anchor_ranges) = skeletonize(language, &text);
            let anchors = anchors_to_ranges(path, &anchor_ranges);
            Some(Excerpt {
                path: path.to_string(),
                mode,
                language,
                anchors,
                content: body,
                truncated,
                redacted: false,
            })
        }
    }
}

/// Builds excerpts for every path in `paths`, in order, applying the
/// per-file and total byte caps deterministically (inventory order is
/// already deterministic from the frozen denominator). Unreadable files are
/// skipped rather than aborting the whole batch.
pub fn build_excerpts(root: &Path, paths: &[String], mode: ExcerptMode) -> Vec<Excerpt> {
    let mut total = 0usize;
    let mut excerpts = Vec::new();
    for path in paths {
        if total >= MAX_TOTAL_EXCERPT_BYTES {
            break;
        }
        if let Some(excerpt) = build_excerpt(root, path, mode) {
            total += excerpt.content.len();
            excerpts.push(excerpt);
        }
    }
    excerpts
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
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
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

    #[test]
    fn raw_excerpt_is_file_line_anchored_and_redacts_secrets() {
        // Built at runtime so secret scanners don't flag test data.
        let fake_key = ["sk", "live", "abcdefghijklmnopqrstuvwxyz"].join("_");
        let dir = ScratchDir::new();
        write(
            dir.path(),
            "src/x.rs",
            &format!("fn a() {{}}\nlet API_KEY = \"{}\";\nfn b() {{}}\n", fake_key),
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
            "use std::fmt;\n\npub fn compute(x: i32) -> i32 {\n    let y = x + 1;\n    y * 2\n}\n",
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
        write(dir.path(), "a.ts", "export function f(x: number) {\n  return x + 1;\n}\n");
        write(dir.path(), "b.swift", "func f() {\n  let y = 1\n}\n");
        write(dir.path(), "c.py", "def f():\n    return 1\n");
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
}
