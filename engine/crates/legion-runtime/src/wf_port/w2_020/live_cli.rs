//! Port of the pure logic in `skills/designer/engine/scripts/live.mjs`.
//!
//! `live.mjs`'s `liveCli()` is a CLI orchestrator: it shells out to sibling
//! scripts (`live-inject.mjs`, `live-server.mjs`) via `execSync`, reads
//! `.impeccable/live/config.json` through `./lib/impeccable-paths.mjs`, and
//! calls `loadContext`/`resolveTargetSelection` from `./context.mjs` and
//! `resolveLiveTarget` from `./live-target.mjs` — all outside this chunk's
//! owned files. That process/argv/exit-code shell (`liveCli`, `runScript`,
//! `ensureServerRunning`) is NOT ported here.
//!
//! What IS ported, faithfully:
//!   - [`missing_live_context`] — `missingLiveContext(ctx)`.
//!   - [`glob_to_regex`] — the glob-pattern-to-regex compiler shared (by
//!     comment, intentionally duplicated to avoid a circular import) with
//!     `live-inject.mjs`.
//!   - [`scan_for_drift`] — `scanForDrift(rootDir, resolvedFiles, config)`,
//!     with the recursive directory walk (`fs.readdirSync`) taken as an
//!     injectable `walk` closure so the matching/orphan logic stays testable
//!     without real disk I/O; wire a real walker (see `DirEntry`) for actual
//!     CLI use. Behavior matches the JS: same `SCAN_ROOTS`, same
//!     `IGNORE_DIRS`, same dotdir skip, same `.html`-only filter, same
//!     20-item cap and hint string, same `null` (`None`) when there are no
//!     orphans.

use std::collections::HashSet;

/// Mirrors `missingLiveContext(ctx)`. `has_product`/`has_design` correspond
/// to `ctx.hasProduct` / `ctx.hasDesign`.
pub fn missing_live_context(has_product: bool, has_design: bool) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !has_product {
        missing.push("PRODUCT.md");
    }
    if !has_design {
        missing.push("DESIGN.md");
    }
    missing
}

/// Mirrors `globToRegex(pattern)`. Returns an anchored regex source string
/// (`^...$`) equivalent to the JS-built pattern; compile with `regex::Regex`.
pub fn glob_to_regex_source(pattern: &str) -> String {
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
    format!("^{re}$")
}

/// Compiles [`glob_to_regex_source`] into a `regex::Regex`.
pub fn glob_to_regex(pattern: &str) -> regex::Regex {
    regex::Regex::new(&glob_to_regex_source(pattern)).expect("glob_to_regex_source always produces a valid pattern")
}

#[derive(Debug, Clone)]
pub struct DriftReport {
    pub orphans: Vec<String>,
    pub orphan_count: usize,
    pub hint: String,
}

const SCAN_ROOTS: &[&str] = &["public", "src", "app", "pages"];

fn ignore_dirs() -> &'static HashSet<&'static str> {
    static SET: std::sync::OnceLock<HashSet<&'static str>> = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        [
            "node_modules", ".git", ".next", ".nuxt", ".svelte-kit", ".astro", ".turbo", ".vercel", ".cache",
            "coverage", "dist", "build",
        ]
        .into_iter()
        .collect()
    })
}

/// One directory entry as seen by an injected walker: `name` is the bare
/// file/dir name, `is_dir` distinguishes directories from files.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
}

/// Mirrors `scanForDrift(rootDir, resolvedFiles, config)`.
///
/// `resolved_files` mirrors the JS's `resolvedFiles` (already forward-slash
/// or platform-separated paths — the JS normalizes with
/// `f.split(path.sep).join('/')`; callers should pass forward-slash paths
/// here to match `list_dir`'s `rel` paths, which are always built with `/`).
/// `exclude_globs` mirrors `config.exclude`. `list_dir(dir) -> Vec<DirEntry>`
/// replaces `fs.readdirSync`; return an empty vec for a directory that
/// doesn't exist or can't be read (same as the JS's `catch { return; }`).
pub fn scan_for_drift(
    resolved_files: &[String],
    exclude_globs: &[String],
    mut list_dir: impl FnMut(&str) -> Vec<DirEntry>,
) -> Option<DriftReport> {
    let resolved_set: HashSet<&str> = resolved_files.iter().map(String::as_str).collect();
    let user_exclude_regexes: Vec<regex::Regex> = exclude_globs.iter().map(|p| glob_to_regex(p)).collect();
    let is_user_excluded = |rel: &str| user_exclude_regexes.iter().any(|re| re.is_match(rel));

    let mut orphans = Vec::new();

    fn walk(
        dir: &str,
        rel_base: &str,
        list_dir: &mut impl FnMut(&str) -> Vec<DirEntry>,
        resolved_set: &HashSet<&str>,
        is_user_excluded: &dyn Fn(&str) -> bool,
        orphans: &mut Vec<String>,
    ) {
        for entry in list_dir(dir) {
            let rel = if rel_base.is_empty() {
                entry.name.clone()
            } else {
                format!("{rel_base}/{}", entry.name)
            };
            if entry.is_dir {
                if ignore_dirs().contains(entry.name.as_str()) || entry.name.starts_with('.') {
                    continue;
                }
                let child_dir = format!("{dir}/{}", entry.name);
                walk(&child_dir, &rel, list_dir, resolved_set, is_user_excluded, orphans);
            } else if entry.name.ends_with(".html") {
                if resolved_set.contains(rel.as_str()) {
                    continue;
                }
                if is_user_excluded(&rel) {
                    continue;
                }
                orphans.push(rel);
            }
        }
    }

    for root in SCAN_ROOTS {
        walk(root, root, &mut list_dir, &resolved_set, &is_user_excluded, &mut orphans);
    }

    if orphans.is_empty() {
        return None;
    }
    let orphan_count = orphans.len();
    let capped: Vec<String> = orphans.into_iter().take(20).collect();
    let hint = format!(
        "{orphan_count} HTML file(s) exist but aren't in config.files. Consider adding them, or use a glob pattern like \"public/**/*.html\"."
    );
    Some(DriftReport { orphans: capped, orphan_count, hint })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_live_context_reports_absent_files() {
        assert_eq!(missing_live_context(false, false), vec!["PRODUCT.md", "DESIGN.md"]);
        assert_eq!(missing_live_context(true, false), vec!["DESIGN.md"]);
        assert_eq!(missing_live_context(true, true), Vec::<&str>::new());
    }

    #[test]
    fn glob_to_regex_handles_star_doublestar_and_escapes() {
        assert!(glob_to_regex("public/**/*.html").is_match("public/a/b/c.html"));
        assert!(glob_to_regex("public/**/*.html").is_match("public/c.html"));
        assert!(glob_to_regex("*.html").is_match("index.html"));
        assert!(!glob_to_regex("*.html").is_match("sub/index.html"));
        assert!(glob_to_regex("a.b").is_match("a.b"));
        assert!(!glob_to_regex("a.b").is_match("aXb"));
        assert!(glob_to_regex("file?.html").is_match("file1.html"));
        assert!(!glob_to_regex("file?.html").is_match("file12.html"));
    }

    fn fake_fs<'f>(files: &'f [(&'f str, &'f [&'f str])]) -> impl for<'a> FnMut(&'a str) -> Vec<DirEntry> + 'f {
        move |dir: &str| {
            let mut entries = Vec::new();
            let mut seen_dirs = HashSet::new();
            for (path, _) in files {
                if let Some(rest) = path.strip_prefix(&format!("{dir}/")) {
                    let first = rest.split('/').next().unwrap();
                    let is_dir = rest.contains('/');
                    if is_dir {
                        if seen_dirs.insert(first) {
                            entries.push(DirEntry { name: first.to_string(), is_dir: true });
                        }
                    } else {
                        entries.push(DirEntry { name: first.to_string(), is_dir: false });
                    }
                }
            }
            entries
        }
    }

    #[test]
    fn scan_for_drift_returns_none_when_all_covered() {
        let files = [("public/index.html", &[][..])];
        let resolved = vec!["public/index.html".to_string()];
        let report = scan_for_drift(&resolved, &[], fake_fs(&files));
        assert!(report.is_none());
    }

    #[test]
    fn scan_for_drift_reports_orphans_and_skips_excluded_and_ignored_dirs() {
        let files = [
            ("public/index.html", &[][..]),
            ("public/orphan.html", &[][..]),
            ("public/skip-me.html", &[][..]),
            ("public/node_modules/junk.html", &[][..]),
        ];
        let resolved = vec!["public/index.html".to_string()];
        let exclude = vec!["public/skip-me.html".to_string()];
        let report = scan_for_drift(&resolved, &exclude, fake_fs(&files)).unwrap();
        assert_eq!(report.orphans, vec!["public/orphan.html".to_string()]);
        assert_eq!(report.orphan_count, 1);
        assert!(report.hint.contains("1 HTML file"));
    }

    #[test]
    fn scan_for_drift_caps_orphans_at_20_but_reports_true_count() {
        let mut file_list: Vec<(String, &[&str])> = Vec::new();
        for i in 0..25 {
            file_list.push((format!("public/o{i}.html"), &[][..]));
        }
        let files_ref: Vec<(&str, &[&str])> = file_list.iter().map(|(p, _)| (p.as_str(), &[][..])).collect();
        let report = scan_for_drift(&[], &[], fake_fs(&files_ref)).unwrap();
        assert_eq!(report.orphans.len(), 20);
        assert_eq!(report.orphan_count, 25);
    }
}
