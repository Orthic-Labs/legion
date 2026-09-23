//! Faithful Rust port of `src/lib/gauntlet/lib/coverage.mjs`.
//!
//! Drives node's built-in coverage via `NODE_V8_COVERAGE` and parses the
//! resulting JSON, same as the JS implementation. Coverage is reported as
//! the fraction of added lines in the diff that were executed at least
//! once by the test command.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::diff::DiffFile;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoverageLineResult {
    pub file: String,
    pub line: usize,
    pub count: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoverageLayer {
    pub ok: bool,
    pub passed: usize,
    pub failed: usize,
    pub total: usize,
    pub percent: f64,
    pub error: Option<String>,
    pub results: Vec<CoverageLineResult>,
}

pub struct RunCoverageOptions<'a> {
    pub cwd: &'a Path,
    pub files: &'a [DiffFile],
    pub test_command: &'a str,
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}-{}",
        std::process::id(),
        nanos,
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Mirrors `runCoverage({ cwd, files, testCommand })`.
pub fn run_coverage(opts: RunCoverageOptions<'_>) -> CoverageLayer {
    let tmp = unique_temp_dir("gauntlet-cov");
    let output = Command::new("sh")
        .arg("-c")
        .arg(opts.test_command)
        .current_dir(opts.cwd)
        .env("NODE_V8_COVERAGE", &tmp)
        .output();

    let result = match output {
        Ok(out) if !out.status.success() => {
            let layer = CoverageLayer {
                ok: false,
                passed: 0,
                failed: 0,
                total: 0,
                percent: 0.0,
                error: Some(format!(
                    "test_command_failed:exit_{}",
                    out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "null".into())
                )),
                results: Vec::new(),
            };
            let _ = fs::remove_dir_all(&tmp);
            return layer;
        }
        Ok(_) => summarise_coverage(opts.cwd, opts.files, &tmp),
        Err(e) => {
            let layer = CoverageLayer {
                ok: false,
                passed: 0,
                failed: 0,
                total: 0,
                percent: 0.0,
                error: Some(format!("spawn_failed:{e}")),
                results: Vec::new(),
            };
            let _ = fs::remove_dir_all(&tmp);
            return layer;
        }
    };
    let _ = fs::remove_dir_all(&tmp);
    result
}

fn summarise_coverage(cwd: &Path, files: &[DiffFile], coverage_dir: &Path) -> CoverageLayer {
    use std::collections::HashMap;
    let file_set: HashMap<PathBuf, std::collections::HashSet<usize>> = files
        .iter()
        .map(|f| (cwd.join(&f.path), f.lines.iter().copied().collect()))
        .collect();

    let mut per_line: Vec<CoverageLineResult> = Vec::new();
    if !coverage_dir.exists() {
        return CoverageLayer {
            ok: false,
            passed: 0,
            failed: 0,
            total: 0,
            percent: 0.0,
            error: None,
            results: per_line,
        };
    }

    let entries = read_coverage_entries(coverage_dir);
    for entry in entries {
        let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("");
        let file_path = url_to_path(url);
        let Some(wanted) = file_set.get(&file_path) else {
            continue;
        };
        let Ok(source_text) = fs::read_to_string(&file_path) else {
            continue;
        };
        let functions = entry.get("functions").and_then(|v| v.as_array());
        if let Some(functions) = functions {
            for func in functions {
                let ranges = func.get("ranges").and_then(|v| v.as_array());
                let Some(ranges) = ranges else { continue };
                for range in ranges {
                    let start = range.get("startOffset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    let end = range.get("endOffset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    let count = range.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let start_line = offset_to_line(&source_text, start);
                    let end_line = offset_to_line(&source_text, end);
                    for line in start_line..=end_line {
                        if !wanted.contains(&line) {
                            continue;
                        }
                        per_line.push(CoverageLineResult {
                            file: file_path.to_string_lossy().into_owned(),
                            line,
                            count,
                        });
                    }
                }
            }
        }
    }

    let total = per_line.len();
    let covered = per_line.iter().filter(|r| r.count > 0).count();
    CoverageLayer {
        ok: covered == total && total > 0,
        passed: covered,
        failed: total - covered,
        total,
        percent: if total == 0 {
            0.0
        } else {
            ((covered as f64 / total as f64) * 10000.0).round() / 100.0
        },
        error: None,
        results: per_line,
    }
}

fn url_to_path(url: &str) -> PathBuf {
    if let Some(rest) = url.strip_prefix("file://") {
        PathBuf::from(rest)
    } else {
        PathBuf::from(url)
    }
}

fn read_coverage_entries(dir: &Path) -> Vec<Value> {
    let mut entries = Vec::new();
    let Ok(read_dir) = fs::read_dir(dir) else {
        return entries;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(data) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if let Some(result) = data.get("result").and_then(|r| r.as_array()).and_then(|a| a.first()) {
            entries.push(result.clone());
        }
    }
    entries
}

fn offset_to_line(text: &str, offset: usize) -> usize {
    let mut line = 1usize;
    for (i, c) in text.char_indices() {
        if i >= offset {
            break;
        }
        if c == '\n' {
            line += 1;
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_to_line_counts_newlines() {
        let text = "a\nb\nc\n";
        assert_eq!(offset_to_line(text, 0), 1);
        assert_eq!(offset_to_line(text, 2), 2);
        assert_eq!(offset_to_line(text, 4), 3);
    }
}
