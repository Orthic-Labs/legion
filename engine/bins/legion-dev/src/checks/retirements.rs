// Retirement-ledger gate. AGENTS.md requires every deleted skill file, script,
// hook, or rule to get a row in `docs/provenance/retirements.md`.
//
// For every path deleted after `BASELINE` (read from
// `git log --diff-filter=D --name-only BASELINE..HEAD`) under `skills/`,
// `scripts/`, `hooks/`, `doctrine/`, `docs/agent-rules*`, or
// `engine/bins/*/src/commands/`, the ledger must hold a row whose first column
// names the path, a parent directory of it, or a glob that matches it.
// Paths that exist again at HEAD (moved or restored) and derived
// `skills/manifests/` files are exempt.
//
// Shallow clones cannot answer the question, so the check reports SKIPPED
// rather than passing silently. CI's `ci` job checks out with `fetch-depth: 0`.

use regex::Regex;
use std::path::Path;
use std::process::Command;

/// Deletions at or before this commit are covered by the audit-seeded ledger.
pub const BASELINE: &str = "c1d80c9d";
const LEDGER: &str = "docs/provenance/retirements.md";
const EXEMPT_PREFIXES: [&str; 1] = ["skills/manifests/"];

/// Whether a deleted path belongs to a surface the ledger must account for.
pub fn is_ledger_surface(path: &str) -> bool {
    if EXEMPT_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return false;
    }
    if path.starts_with("skills/")
        || path.starts_with("scripts/")
        || path.starts_with("hooks/")
        || path.starts_with("doctrine/")
        || path.starts_with("docs/agent-rules")
    {
        return true;
    }
    Regex::new(r"^engine/bins/[^/]+/src/commands/")
        .unwrap()
        .is_match(path)
}

/// Paths from `git log --name-only --format=` output that are still deleted
/// (per `exists`) and on a ledger surface. Sorted, deduplicated.
pub fn deleted_paths(log_output: &str, exists: impl Fn(&str) -> bool) -> Vec<String> {
    let mut out: Vec<String> = log_output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| is_ledger_surface(l) && !exists(l))
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Backtick-quoted spans in the first column of every ledger table row.
pub fn ledger_entries(text: &str) -> Vec<String> {
    let span = Regex::new(r"`([^`]+)`").unwrap();
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let Some(cell) = line.split('|').nth(1) else {
            continue;
        };
        for cap in span.captures_iter(cell) {
            let entry = cap[1].trim().trim_start_matches("./");
            if !entry.is_empty() {
                entries.push(entry.to_string());
            }
        }
    }
    entries
}

/// `*` matches within a path segment, `**` across segments.
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    let mut re = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '*' {
            if chars.get(i + 1) == Some(&'*') {
                re.push_str(".*");
                i += 2;
            } else {
                re.push_str("[^/]*");
                i += 1;
            }
        } else {
            re.push_str(&regex::escape(&chars[i].to_string()));
            i += 1;
        }
    }
    re.push_str("(?:/.*)?$");
    Regex::new(&re).map(|r| r.is_match(path)).unwrap_or(false)
}

pub fn is_covered(path: &str, entries: &[String]) -> bool {
    entries.iter().any(|entry| {
        if entry.contains('*') {
            glob_matches(entry, path)
        } else {
            let entry = entry.trim_end_matches('/');
            path == entry || path.starts_with(&format!("{entry}/"))
        }
    })
}

pub fn missing_rows(deleted: &[String], entries: &[String]) -> Vec<String> {
    deleted
        .iter()
        .filter(|p| !is_covered(p, entries))
        .cloned()
        .collect()
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(["-c", "core.quotepath=off"])
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        None
    }
}

pub fn run(root: &Path) -> bool {
    match git(root, &["rev-parse", "--is-shallow-repository"]) {
        Some(out) if out.trim() == "false" => {}
        Some(_) => {
            println!(
                "check-retirements: SKIPPED (shallow clone; deleted paths cannot be enumerated). Not verified."
            );
            return true;
        }
        None => {
            println!("check-retirements: SKIPPED (not a git checkout). Not verified.");
            return true;
        }
    }
    let baseline = format!("{BASELINE}^{{commit}}");
    if git(root, &["cat-file", "-e", baseline.as_str()]).is_none()
        || git(root, &["merge-base", "--is-ancestor", BASELINE, "HEAD"]).is_none()
    {
        println!(
            "check-retirements: SKIPPED (baseline {BASELINE} is not an ancestor of HEAD). Not verified."
        );
        return true;
    }
    let range = format!("{BASELINE}..HEAD");
    let Some(log) = git(
        root,
        &[
            "log",
            "-M",
            "--diff-filter=D",
            "--name-only",
            "--format=",
            range.as_str(),
        ],
    ) else {
        eprintln!("check-retirements: git log {range} failed");
        return false;
    };
    let deleted = deleted_paths(&log, |p| root.join(p).exists());
    let ledger = match std::fs::read_to_string(root.join(LEDGER)) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("check-retirements: cannot read {LEDGER}: {e}");
            return false;
        }
    };
    let entries = ledger_entries(&ledger);
    let missing = missing_rows(&deleted, &entries);
    if missing.is_empty() {
        println!(
            "retirements ok: {} deleted path(s) since {BASELINE} accounted for in {LEDGER}",
            deleted.len()
        );
        return true;
    }
    for path in &missing {
        eprintln!("{path}: deleted since {BASELINE} with no row in {LEDGER}");
    }
    eprintln!(
        "\ncheck-retirements failed: {} deleted path(s) lack a ledger row (first column must name the path or a parent directory)",
        missing.len()
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEDGER_TEXT: &str = "\
# Retirements ledger

| Path or rule | Retired in commit | Successor | Reason |
|---|---|---|---|
| `skills/content` | see audit | none | dropped |
| `scripts/*.mjs`, `docs/canon/**` | `abc` | none | dropped |
| Hooks `hooks/arcane-hook.mjs` | `abc` | none | dropped |
| `doctrine/old.md` | `abc` | `doctrine/new.md` | successor |
";

    #[test]
    fn surfaces_cover_the_named_trees_only() {
        for p in [
            "skills/x/SKILL.md",
            "scripts/a.sh",
            "hooks/h.py",
            "doctrine/d.md",
            "docs/agent-rules.md",
            "docs/agent-rules/legion.md",
            "engine/bins/legion/src/commands/script.rs",
        ] {
            assert!(is_ledger_surface(p), "{p}");
        }
        for p in [
            "docs/other.md",
            "engine/bins/legion/src/main.rs",
            "skills/manifests/x.json",
            "src/registry/a.json",
        ] {
            assert!(!is_ledger_surface(p), "{p}");
        }
    }

    #[test]
    fn deleted_paths_drop_restored_files_and_other_surfaces() {
        let log = "skills/a/x.md\n\nskills/a/x.md\nscripts/b.sh\nREADME.md\nskills/back.md\n";
        let got = deleted_paths(log, |p| p == "skills/back.md");
        assert_eq!(
            got,
            vec!["scripts/b.sh".to_string(), "skills/a/x.md".to_string()]
        );
    }

    #[test]
    fn ledger_entries_read_first_column_spans_only() {
        let entries = ledger_entries(LEDGER_TEXT);
        assert!(entries.contains(&"skills/content".to_string()));
        assert!(entries.contains(&"scripts/*.mjs".to_string()));
        assert!(entries.contains(&"docs/canon/**".to_string()));
        assert!(entries.contains(&"hooks/arcane-hook.mjs".to_string()));
        assert!(entries.contains(&"doctrine/old.md".to_string()));
        // successor column and commit column are not entries
        assert!(!entries.contains(&"doctrine/new.md".to_string()));
        assert!(!entries.contains(&"abc".to_string()));
    }

    #[test]
    fn coverage_by_exact_path_parent_prefix_and_glob() {
        let entries = ledger_entries(LEDGER_TEXT);
        assert!(is_covered("skills/content/SKILL.md", &entries));
        assert!(is_covered("skills/content", &entries));
        assert!(is_covered("doctrine/old.md", &entries));
        assert!(is_covered("scripts/run.mjs", &entries));
        assert!(is_covered("docs/canon/a/b.md", &entries));
        assert!(is_covered("hooks/arcane-hook.mjs", &entries));
        assert!(
            !is_covered("skills/contents/x.md", &entries),
            "prefix must end at a segment"
        );
        assert!(
            !is_covered("scripts/sub/run.mjs", &entries),
            "single * stays in a segment"
        );
        assert!(!is_covered("scripts/run.sh", &entries));
        assert!(!is_covered("doctrine/new.md", &entries));
    }

    #[test]
    fn missing_rows_lists_each_uncovered_path() {
        let entries = ledger_entries(LEDGER_TEXT);
        let deleted = vec![
            "skills/content/a.md".to_string(),
            "skills/qa/scripts/shot.mjs".to_string(),
            "hooks/new.py".to_string(),
        ];
        assert_eq!(
            missing_rows(&deleted, &entries),
            vec![
                "skills/qa/scripts/shot.mjs".to_string(),
                "hooks/new.py".to_string()
            ]
        );
    }

    #[test]
    fn glob_special_characters_are_literal() {
        assert!(glob_matches("docs/a.b/**", "docs/a.b/c"));
        assert!(!glob_matches("docs/a.b/**", "docs/aXb/c"));
    }
}
