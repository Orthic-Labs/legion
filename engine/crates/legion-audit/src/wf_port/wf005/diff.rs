//! Faithful Rust port of `src/lib/gauntlet/lib/diff.mjs`.
//!
//! Bounded to the frozen diff: returns per-file added-line numbers so the
//! mutation engine and the coverage filter do not touch the rest of the
//! repo.
//!
//! Source precedence:
//!   1. `diff_file` (explicit frozen diff)
//!   2. `base` (`git diff <base>...<head>` or `<base>`)
//!   3. (default) `git diff --unified=0 HEAD`

use std::fs;
use std::path::Path;
use std::process::Command;

/// One changed file: its repo-relative path and the 1-based line numbers
/// added by the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffFile {
    pub path: String,
    pub lines: Vec<usize>,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
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

/// Mirrors `loadDiff({ cwd, base, head, diffFile })`.
pub fn load_diff(opts: LoadDiffOptions<'_>) -> Result<Vec<DiffFile>, String> {
    let raw = if let Some(diff_file) = opts.diff_file {
        let path = match opts.cwd {
            Some(cwd) => cwd.join(diff_file),
            None => diff_file.to_path_buf(),
        };
        fs::read_to_string(&path).map_err(|e| format!("read diff file {}: {e}", path.display()))?
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

fn run_git_diff(cwd: Option<&Path>, range: &str) -> Result<String, String> {
    let mut cmd = Command::new("git");
    cmd.arg("diff").arg("--unified=0").arg(range);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let output = cmd
        .output()
        .map_err(|e| format!("spawn git diff {range}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git diff {range} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse `git diff --unified=0` hunk headers and the `+++` file headers.
///
/// This is a hand-rolled equivalent of the JS regex parsing (no `regex`
/// crate dependency is available to this chunk), matching:
///   `/^\+\+\+ (?:\/dev\/null|b\/)(.*)$/`
///   `/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/`
pub fn parse_unified(raw: &str) -> Vec<DiffFile> {
    #[derive(Default)]
    struct Cur {
        path: Option<String>,
        added: Vec<usize>,
    }
    let mut files: Vec<Cur> = Vec::new();
    let mut current: Option<Cur> = None;

    for raw_line in raw.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.starts_with("diff --git ") {
            if let Some(c) = current.take() {
                files.push(c);
            }
            current = Some(Cur::default());
            continue;
        }
        if let Some(rest) = line.strip_prefix("+++ ") {
            if let Some(cur) = current.as_mut() {
                cur.path = if rest == "/dev/null" {
                    None
                } else if let Some(p) = rest.strip_prefix("b/") {
                    Some(p.to_string())
                } else {
                    None
                };
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
        }
    }
    if let Some(c) = current.take() {
        files.push(c);
    }

    files
        .into_iter()
        .filter(|f| f.path.is_some() && !f.added.is_empty())
        .map(|f| DiffFile {
            path: f.path.unwrap(),
            lines: f.added,
        })
        .collect()
}

/// Parses `@@ -a[,b] +c[,d] @@...` returning `(c, d)` (`d` defaults to 1).
fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    let plus_idx = line.find('+')?;
    let rest = &line[plus_idx + 1..];
    let end = rest.find(|c: char| c == ' ' || c == '@').unwrap_or(rest.len());
    let spec = &rest[..end];
    if spec.is_empty() {
        return None;
    }
    let (start_str, count_str) = match spec.split_once(',') {
        Some((s, c)) => (s, c),
        None => (spec, "1"),
    };
    let start: usize = start_str.parse().ok()?;
    let count: usize = count_str.parse().ok()?;
    Some((start, count))
}

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
    fn parses_added_lines_and_drops_pure_deletions() {
        let raw = "diff --git a/src/sum.js b/src/sum.js\n\
--- a/src/sum.js\n\
+++ b/src/sum.js\n\
@@ -9,0 +10,6 @@ export function sum(values) {\n\
+\n\
+// New addition\n\
+export function mean(values) {\n\
+  if (values.length === 0) return 0;\n\
+  return sum(values) / values.length;\n\
+}\n\
diff --git a/src/dead.js b/src/dead.js\n\
deleted file mode 100644\n\
--- a/src/dead.js\n\
+++ /dev/null\n\
@@ -1,3 +0,0 @@\n\
-old\n";
        let files = parse_unified(raw);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/sum.js");
        assert_eq!(files[0].lines, vec![10, 11, 12, 13, 14, 15]);
    }
}
