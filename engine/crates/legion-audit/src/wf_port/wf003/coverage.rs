// Phase 6.7 — changed-lines-only coverage.
//
// Faithful Rust port of `src/lib/gauntlet/lib/coverage.mjs`.
//
// We drive node's built-in coverage via NODE_V8_COVERAGE and parse the
// resulting JSON. Coverage is reported as the fraction of added lines in
// the diff that were executed at least once by the test command.
// Whole-repo coverage is intentionally discarded.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::GauntletError;
use super::diff::DiffFile;

#[derive(Debug, Clone, Serialize)]
pub struct CoveredLine {
    pub file: String,
    pub line: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageLayer {
    pub ok: bool,
    pub passed: usize,
    pub failed: usize,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_tail: Option<String>,
    #[serde(default)]
    pub results: Vec<CoveredLine>,
}

/// Mirrors `runCoverage({ cwd, files, testCommand })`.
pub fn run_coverage(cwd: Option<&Path>, files: &[DiffFile], test_command: &str) -> Result<CoverageLayer, GauntletError> {
    let tmp = make_temp_dir("gauntlet-cov-")?;
    let result = (|| -> Result<CoverageLayer, GauntletError> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(test_command);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        cmd.env("NODE_V8_COVERAGE", &tmp);
        let output = cmd
            .output()
            .map_err(|e| GauntletError::Io(format!("spawn test command: {e}")))?;
        if !output.status.success() {
            return Ok(CoverageLayer {
                ok: false,
                passed: 0,
                failed: 0,
                total: 0,
                percent: None,
                error: Some(format!(
                    "test_command_failed:exit_{}",
                    output.status.code().map(|c| c.to_string()).unwrap_or_else(|| "null".to_string())
                )),
                stderr_tail: Some(tail(&String::from_utf8_lossy(&output.stderr), 200)),
                results: Vec::new(),
            });
        }
        let summary = summarise_coverage(cwd, files, &tmp)?;
        let percent = if summary.total == 0 {
            0.0
        } else {
            (summary.covered as f64 / summary.total as f64) * 100.0
        };
        Ok(CoverageLayer {
            ok: summary.covered == summary.total && summary.total > 0,
            passed: summary.covered,
            failed: summary.total - summary.covered,
            total: summary.total,
            percent: Some((percent * 100.0).round() / 100.0),
            error: None,
            stderr_tail: None,
            results: summary.per_line,
        })
    })();
    let _ = fs::remove_dir_all(&tmp);
    result
}

struct CoverageSummary {
    covered: usize,
    total: usize,
    per_line: Vec<CoveredLine>,
}

#[derive(Debug, Deserialize)]
struct V8CoverageFile {
    result: Option<Vec<V8ScriptCoverage>>,
}

#[derive(Debug, Deserialize)]
struct V8ScriptCoverage {
    url: String,
    #[serde(default)]
    functions: Vec<V8FunctionCoverage>,
}

#[derive(Debug, Deserialize)]
struct V8FunctionCoverage {
    #[serde(default)]
    ranges: Vec<V8Range>,
}

#[derive(Debug, Deserialize)]
struct V8Range {
    #[serde(rename = "startOffset")]
    start_offset: u64,
    #[serde(rename = "endOffset")]
    end_offset: u64,
    count: u64,
}

fn summarise_coverage(cwd: Option<&Path>, files: &[DiffFile], coverage_dir: &Path) -> Result<CoverageSummary, GauntletError> {
    let mut per_line = Vec::new();
    let mut wanted: HashMap<PathBuf, std::collections::HashSet<u64>> = HashMap::new();
    for f in files {
        let abs = match cwd {
            Some(cwd) => cwd.join(&f.path),
            None => PathBuf::from(&f.path),
        };
        wanted.insert(normalize_path(&abs), f.lines.iter().copied().collect());
    }
    if !coverage_dir.exists() {
        return Ok(CoverageSummary { covered: 0, total: 0, per_line });
    }
    let entries = read_coverage_entries(coverage_dir);
    let mut source_cache: HashMap<PathBuf, Option<String>> = HashMap::new();
    for entry in entries {
        let file_path = url_to_path(&entry.url);
        let file_path = normalize_path(&file_path);
        let Some(wanted_lines) = wanted.get(&file_path) else { continue };
        for func in &entry.functions {
            for range in &func.ranges {
                let source_text = source_cache
                    .entry(file_path.clone())
                    .or_insert_with(|| fs::read_to_string(&file_path).ok());
                let Some(source_text) = source_text.as_ref() else { continue };
                let start_line = offset_to_line(source_text, range.start_offset);
                let end_line = offset_to_line(source_text, range.end_offset);
                for line in start_line..=end_line {
                    if !wanted_lines.contains(&line) {
                        continue;
                    }
                    per_line.push(CoveredLine {
                        file: file_path.to_string_lossy().into_owned(),
                        line,
                        count: range.count,
                    });
                }
            }
        }
    }
    let total = per_line.len();
    let covered = per_line.iter().filter(|r| r.count > 0).count();
    Ok(CoverageSummary { covered, total, per_line })
}

fn read_coverage_entries(dir: &Path) -> Vec<V8ScriptCoverage> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else { continue };
        let Ok(data) = serde_json::from_str::<V8CoverageFile>(&raw) else { continue };
        if let Some(mut results) = data.result {
            if !results.is_empty() {
                out.push(results.remove(0));
            }
        }
    }
    out
}

/// V8 coverage `url` is typically a `file://` URL; `resolve()` in Node
/// would also accept a plain path. We handle both.
fn url_to_path(url: &str) -> PathBuf {
    if let Some(rest) = url.strip_prefix("file://") {
        PathBuf::from(rest)
    } else {
        PathBuf::from(url)
    }
}

fn normalize_path(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn offset_to_line(text: &str, offset: u64) -> u64 {
    let mut line = 1u64;
    for (i, b) in text.bytes().enumerate() {
        if i as u64 >= offset {
            break;
        }
        if b == b'\n' {
            line += 1;
        }
    }
    line
}

fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[s.len() - n..].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_to_line_counts_newlines_before_offset() {
        let text = "line1\nline2\nline3\n";
        assert_eq!(offset_to_line(text, 0), 1);
        assert_eq!(offset_to_line(text, 6), 2); // right after first \n
        assert_eq!(offset_to_line(text, 12), 3);
    }

    #[test]
    fn coverage_reports_zero_when_dir_missing() {
        let files = vec![DiffFile { path: "x.js".to_string(), lines: vec![1] }];
        let missing = std::env::temp_dir().join("wf003-nonexistent-coverage-dir-xyz");
        let summary = summarise_coverage(None, &files, &missing).unwrap();
        assert_eq!(summary.covered, 0);
        assert_eq!(summary.total, 0);
    }

    #[test]
    fn summarise_coverage_matches_wanted_lines_only() {
        let dir = std::env::temp_dir().join(format!("wf003-cov-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let source_path = dir.join("src.js");
        fs::write(&source_path, "a\nb\nc\nd\n").unwrap();

        // Build a minimal NODE_V8_COVERAGE-shaped JSON file covering the
        // whole source (offset 0..8) with count 1, and a range with count 0
        // covering nothing wanted, to exercise both covered/uncovered.
        let cov_json = format!(
            r#"{{"result":[{{"url":"file://{}","functions":[{{"ranges":[{{"startOffset":0,"endOffset":2,"count":1}},{{"startOffset":4,"endOffset":6,"count":0}}]}}]}}]}}"#,
            source_path.display()
        );
        fs::write(dir.join("cov.json"), cov_json).unwrap();

        let files = vec![DiffFile { path: "src.js".to_string(), lines: vec![1, 3] }];
        let summary = summarise_coverage(None, &files, &dir).unwrap();
        // line 1 covered (count 1), line 3 uncovered (count 0); line 2/4 not wanted.
        assert_eq!(summary.total, 2);
        assert_eq!(summary.covered, 1);

        let _ = fs::remove_dir_all(&dir);
    }
}

fn make_temp_dir(prefix: &str) -> Result<PathBuf, GauntletError> {
    let base = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for attempt in 0..64u32 {
        let candidate = base.join(format!("{prefix}{nanos}-{}-{}", std::process::id(), attempt));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(GauntletError::Io(format!("mkdtemp: {e}"))),
        }
    }
    Err(GauntletError::Io("mkdtemp: exhausted attempts".to_string()))
}
