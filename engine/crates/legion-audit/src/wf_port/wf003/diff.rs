// Phase 6.7 — diff extractor.
//
// Faithful Rust port of `src/lib/gauntlet/lib/diff.mjs`.
//
// Bounded to the frozen diff: returns per-file added-line numbers so the
// mutation engine and the coverage filter do not touch the rest of the
// repo. Cost stays proportional to the diff, never repo-wide.
//
// Source precedence:
//   1. `diff_file` (explicit frozen diff, preferred for /commit)
//   2. `base` (git diff <base>...<head> or <base>, CI mode)
//   3. (default) git diff against HEAD (working tree only)

use std::fs;
use std::path::Path;
use std::process::Command;

use super::GauntletError;

/// One changed file: its repo-relative path and the 1-based line numbers
/// that were added by the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffFile {
    pub path: String,
    pub lines: Vec<u64>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DiffSummary {
    pub files: usize,
    pub lines: usize,
}

#[derive(Debug, Default)]
pub struct LoadDiffOptions<'a> {
    pub cwd: Option<&'a Path>,
    pub base: Option<&'a str>,
    pub head: Option<&'a str>,
    pub diff_file: Option<&'a Path>,
}

/// Mirrors `loadDiff({ cwd, base, head, diffFile })` from diff.mjs.
pub fn load_diff(opts: LoadDiffOptions<'_>) -> Result<Vec<DiffFile>, GauntletError> {
    let raw = if let Some(diff_file) = opts.diff_file {
        let path = match opts.cwd {
            Some(cwd) => cwd.join(diff_file),
            None => diff_file.to_path_buf(),
        };
        fs::read_to_string(&path)
            .map_err(|e| GauntletError::Io(format!("read diff file {}: {e}", path.display())))?
    } else if let Some(base) = opts.base {
        let range = match opts.head {
            Some(head) => format!("{base}...{head}"),
            None => base.to_string(),
        };
        run_git_diff(opts.cwd, &range)?
    } else {
        run_git_diff(opts.cwd, "HEAD")?
    };
    Ok(parse_unified(&raw))
}

fn run_git_diff(cwd: Option<&Path>, range: &str) -> Result<String, GauntletError> {
    let mut cmd = Command::new("git");
    cmd.arg("diff").arg("--unified=0").arg(range);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let output = cmd
        .output()
        .map_err(|e| GauntletError::Io(format!("spawn git diff {range}: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GauntletError::GitDiffFailed {
            range: range.to_string(),
            stderr: stderr.to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

struct RawFile {
    path: Option<String>,
    added: Vec<u64>,
}

/// Parses `git diff --unified=0` output: hunk headers and the file paths
/// they belong to. Mirrors `parseUnified` from diff.mjs exactly, including
/// dropping pure-deletion files (no surviving line to mutate or cover).
pub fn parse_unified(raw: &str) -> Vec<DiffFile> {
    let mut files: Vec<RawFile> = Vec::new();
    let mut current: Option<RawFile> = None;

    for line in raw.split(['\n']).map(strip_cr) {
        if line.starts_with("diff --git ") {
            if let Some(c) = current.take() {
                files.push(c);
            }
            current = Some(RawFile { path: None, added: Vec::new() });
            continue;
        }
        if line.starts_with("+++ ") {
            if let Some(cur) = current.as_mut() {
                // +++ b/path  (or +++ /dev/null for deletions)
                if let Some(rest) = line.strip_prefix("+++ ") {
                    if rest == "/dev/null" {
                        cur.path = None;
                    } else if let Some(p) = rest.strip_prefix("b/") {
                        cur.path = if p.is_empty() { None } else { Some(p.to_string()) };
                    }
                }
            }
            continue;
        }
        if line.starts_with("@@") {
            if let Some(cur) = current.as_mut() {
                if cur.path.is_some() {
                    if let Some((start, count)) = parse_hunk_header(line) {
                        for i in 0..count {
                            cur.added.push(start + i);
                        }
                    }
                }
            }
            continue;
        }
    }
    if let Some(c) = current.take() {
        files.push(c);
    }

    files
        .into_iter()
        .filter_map(|f| match f.path {
            Some(path) if !f.added.is_empty() => Some(DiffFile { path, lines: f.added }),
            _ => None,
        })
        .collect()
}

fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// Parses `@@ -x,y +start,count @@` (count defaults to 1 when omitted).
fn parse_hunk_header(line: &str) -> Option<(u64, u64)> {
    // Expected shape: "@@ -<old> +<start>(,<count>)? @@..."
    let rest = line.strip_prefix("@@ ")?;
    let plus_idx = rest.find('+')?;
    let after_plus = &rest[plus_idx + 1..];
    let end_idx = after_plus.find(' ')?;
    let new_range = &after_plus[..end_idx];
    let mut parts = new_range.splitn(2, ',');
    let start: u64 = parts.next()?.parse().ok()?;
    let count: u64 = match parts.next() {
        Some(c) => c.parse().ok()?,
        None => 1,
    };
    Some((start, count))
}

/// Mirrors `summarise(files)` from diff.mjs.
pub fn summarise(files: &[DiffFile]) -> DiffSummary {
    DiffSummary {
        files: files.len(),
        lines: files.iter().map(|f| f.lines.len()).sum(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_hunk_added_lines() {
        let raw = "diff --git a/src/sum.js b/src/sum.js\n\
index 111..222 100644\n\
--- a/src/sum.js\n\
+++ b/src/sum.js\n\
@@ -1,2 +1,4 @@\n\
+line one\n\
+line two\n\
+line three\n\
+line four\n";
        let files = parse_unified(raw);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/sum.js");
        assert_eq!(files[0].lines, vec![1, 2, 3, 4]);
    }

    #[test]
    fn implicit_count_defaults_to_one() {
        let raw = "diff --git a/a.js b/a.js\n\
--- a/a.js\n\
+++ b/a.js\n\
@@ -5 +5 @@\n\
+x\n";
        let files = parse_unified(raw);
        assert_eq!(files[0].lines, vec![5]);
    }

    #[test]
    fn drops_pure_deletion_files() {
        let raw = "diff --git a/gone.js b/gone.js\n\
--- a/gone.js\n\
+++ /dev/null\n\
@@ -1,2 +0,0 @@\n\
-old line\n\
-old line 2\n";
        let files = parse_unified(raw);
        assert!(files.is_empty());
    }

    #[test]
    fn multiple_files_and_hunks_accumulate() {
        let raw = "diff --git a/a.js b/a.js\n\
--- a/a.js\n\
+++ b/a.js\n\
@@ -1 +1,2 @@\n\
+a1\n\
+a2\n\
diff --git a/b.js b/b.js\n\
--- a/b.js\n\
+++ b/b.js\n\
@@ -10 +12,2 @@\n\
+b1\n\
+b2\n";
        let files = parse_unified(raw);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "a.js");
        assert_eq!(files[0].lines, vec![1, 2]);
        assert_eq!(files[1].path, "b.js");
        assert_eq!(files[1].lines, vec![12, 13]);
    }

    #[test]
    fn empty_diff_yields_no_files() {
        assert!(parse_unified("").is_empty());
    }

    #[test]
    fn summarise_counts_files_and_lines() {
        let files = vec![
            DiffFile { path: "a".to_string(), lines: vec![1, 2] },
            DiffFile { path: "b".to_string(), lines: vec![3] },
        ];
        let s = summarise(&files);
        assert_eq!(s.files, 2);
        assert_eq!(s.lines, 3);
    }
}
