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

/// A check that cannot enumerate its input is a failure in CI, where the
/// workflow must provide full history, and a labelled skip for local runs.
fn cannot_verify(reason: &str) -> bool {
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        eprintln!(
            "check-retirements: cannot verify in CI ({reason}); CI checkout must provide full history reaching {BASELINE}"
        );
        return false;
    }
    println!("check-retirements: SKIPPED ({reason}). Not verified.");
    true
}

pub fn run(root: &Path) -> bool {
    match git(root, &["rev-parse", "--is-shallow-repository"]) {
        Some(out) if out.trim() == "false" => {}
        Some(_) => {
            return cannot_verify("shallow clone; deleted paths cannot be enumerated");
        }
        None => {
            return cannot_verify("not a git checkout");
        }
    }
    let baseline = format!("{BASELINE}^{{commit}}");
    if git(root, &["cat-file", "-e", baseline.as_str()]).is_none()
        || git(root, &["merge-base", "--is-ancestor", BASELINE, "HEAD"]).is_none()
    {
        return cannot_verify(&format!("baseline {BASELINE} is not an ancestor of HEAD"));
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
