//! Receipt-gated, single-file unified-diff application for Research drafts.
//!
//! Every check and hunk application completes in memory before the draft is
//! atomically replaced. A successful content-changing apply invalidates its
//! receipt through the source hash; this is integrity binding, not a general
//! single-use authorization or hook attestation.

use super::patch_guard::{self, PatchGuardError};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

const MAX_DIFF_BYTES: usize = 65_536;
const MAX_RECEIPT_BYTES: usize = 65_536;

#[derive(Debug)]
pub struct PatcherError(pub String);

impl fmt::Display for PatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PatcherError {}

fn error(message: impl Into<String>) -> PatcherError {
    PatcherError(message.into())
}

impl From<PatchGuardError> for PatcherError {
    fn from(value: PatchGuardError) -> Self {
        Self(value.0)
    }
}

#[derive(Clone, Debug)]
struct Hunk {
    header: String,
    old_start: usize,
    old_count: usize,
    old: Vec<String>,
    new: Vec<String>,
    body_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyReport {
    pub draft_path: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub diff_sha256: String,
    pub applied_hunks: u32,
}

fn hunk_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
            .expect("valid hunk regex")
    })
}

fn split_keepends(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            lines.push(text[start..=index].to_owned());
            start = index + 1;
        }
    }
    if start < text.len() {
        lines.push(text[start..].to_owned());
    }
    lines
}

fn line_without_ending(line: &str) -> &str {
    let without_lf = line.strip_suffix('\n').unwrap_or(line);
    without_lf.strip_suffix('\r').unwrap_or(without_lf)
}

fn hunk_counts(header: &str) -> Result<(usize, usize, usize), PatcherError> {
    let captures = hunk_regex()
        .captures(header)
        .ok_or_else(|| error(format!("invalid hunk header: {header}")))?;
    let old_start = captures[1]
        .parse::<usize>()
        .map_err(|_| error("hunk old start is out of range"))?;
    let new_start = captures[3]
        .parse::<usize>()
        .map_err(|_| error("hunk new start is out of range"))?;
    let old_count = captures
        .get(2)
        .map(|value| value.as_str().parse::<usize>())
        .transpose()
        .map_err(|_| error("hunk old count is out of range"))?
        .unwrap_or(1);
    let new_count = captures
        .get(4)
        .map(|value| value.as_str().parse::<usize>())
        .transpose()
        .map_err(|_| error("hunk new count is out of range"))?
        .unwrap_or(1);
    if (old_count > 0 && old_start == 0) || (new_count > 0 && new_start == 0) {
        return Err(error("nonempty hunk ranges must start at line 1 or later"));
    }
    if i64::try_from(old_start).is_err() || i64::try_from(new_start).is_err() {
        return Err(error("hunk line start is out of supported range"));
    }
    Ok((old_start, old_count, new_count))
}

fn diff_path_identity(path: &str, prefix: Option<char>) -> Result<String, PatcherError> {
    let path = path.trim_end_matches('\r');
    if path.is_empty() || path == "/dev/null" || path.starts_with('/') || path.contains('\\') {
        return Err(error("patch must modify one named relative file"));
    }
    let path = match prefix {
        Some(expected) => path
            .strip_prefix(expected)
            .and_then(|value| value.strip_prefix('/'))
            .ok_or_else(|| error("diff file headers use inconsistent path prefixes"))?,
        None => path,
    };
    if path.is_empty()
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(error("patch file path is not normalized"));
    }
    Ok(path.to_owned())
}

fn parse_file_header(
    line: &str,
    marker: &str,
    prefix: Option<char>,
) -> Result<String, PatcherError> {
    let path = line
        .strip_prefix(marker)
        .ok_or_else(|| error("unified diff must have one --- and one +++ header"))?;
    // Unified diff permits a tab-delimited timestamp after the path. Quoted
    // paths and space-delimited timestamps are rejected to avoid ambiguity.
    let path = path.split_once('\t').map(|(name, _)| name).unwrap_or(path);
    if path.contains('"') {
        return Err(error("quoted diff paths are not supported"));
    }
    diff_path_identity(path, prefix)
}

/// Parse a single-file unified diff, reject extra file sections, and validate
/// declared hunk counts against actual old/new body lines.
fn parse_unified(diff: &str) -> Result<Vec<Hunk>, PatcherError> {
    if diff.len() > MAX_DIFF_BYTES {
        return Err(error("diff exceeds 65536 bytes"));
    }
    let lines = split_keepends(diff);
    let mut old_path = None;
    let mut new_path = None;
    let mut git_file_header_seen = false;
    let mut hunks = Vec::new();
    let mut current: Option<Hunk> = None;
    let mut expected_new_count = 0usize;

    for line in &lines {
        let without_ending = line_without_ending(line);
        if without_ending.starts_with("diff --git ") {
            if git_file_header_seen || !hunks.is_empty() || current.is_some() {
                return Err(error("multi-file diffs are not allowed"));
            }
            git_file_header_seen = true;
            let mut paths = without_ending[11..].split_whitespace();
            let old = paths
                .next()
                .ok_or_else(|| error("invalid diff --git header"))?;
            let new = paths
                .next()
                .ok_or_else(|| error("invalid diff --git header"))?;
            if paths.next().is_some() {
                return Err(error("quoted or ambiguous diff paths are not supported"));
            }
            let old = diff_path_identity(old, Some('a'))?;
            let new = diff_path_identity(new, Some('b'))?;
            if old != new {
                return Err(error("diff changes more than one file path"));
            }
            continue;
        }
        if current.is_none() && without_ending.starts_with("--- ") {
            if old_path.is_some() || !hunks.is_empty() || current.is_some() {
                return Err(error("multi-file diffs are not allowed"));
            }
            let path = parse_file_header(without_ending, "--- ", Some('a'))
                .or_else(|_| parse_file_header(without_ending, "--- ", None))?;
            old_path = Some(path);
            continue;
        }
        if current.is_none() && without_ending.starts_with("+++ ") {
            if new_path.is_some() || !hunks.is_empty() || current.is_some() {
                return Err(error("multi-file diffs are not allowed"));
            }
            let path = parse_file_header(without_ending, "+++ ", Some('b'))
                .or_else(|_| parse_file_header(without_ending, "+++ ", None))?;
            new_path = Some(path);
            continue;
        }
        if without_ending.starts_with("index ") {
            if !hunks.is_empty() || current.is_some() {
                return Err(error("unexpected diff metadata after hunks"));
            }
            continue;
        }
        if without_ending.starts_with("@@") {
            if old_path.is_none() || new_path.is_none() {
                return Err(error(
                    "unified diff must name exactly one source and target file",
                ));
            }
            if old_path != new_path {
                return Err(error("diff changes more than one file path"));
            }
            if let Some(previous) = current.take() {
                if previous.old.len() != previous.old_count
                    || previous.new.len() != expected_new_count
                {
                    return Err(error(format!(
                        "hunk line counts do not match {}",
                        previous.header
                    )));
                }
                hunks.push(previous);
            }
            let header = without_ending.to_owned();
            let (old_start, old_count, new_count) = hunk_counts(&header)?;
            current = Some(Hunk {
                header,
                old_start,
                old_count,
                old: Vec::new(),
                new: Vec::new(),
                body_bytes: 0,
            });
            expected_new_count = new_count;
            continue;
        }
        let Some(hunk) = current.as_mut() else {
            if without_ending.is_empty() {
                continue;
            }
            // The only pre-hunk metadata accepted by this implementation is
            // the conventional git/index header plus the two file headers.
            return Err(error(format!(
                "unexpected unified-diff line: {without_ending}"
            )));
        };
        hunk.body_bytes = hunk.body_bytes.saturating_add(line.len());
        if hunk.body_bytes > patch_guard::DEFAULT_MAX_HUNK_BYTES as usize {
            return Err(error(format!(
                "hunk too large: {} > {}",
                hunk.body_bytes,
                patch_guard::DEFAULT_MAX_HUNK_BYTES
            )));
        }
        if without_ending == "\\ No newline at end of file" {
            return Err(error(
                "no-newline unified-diff markers are not supported; draft is unchanged",
            ));
        }
        match line.as_bytes().first().copied() {
            Some(b' ') => {
                hunk.old.push(line[1..].to_owned());
                hunk.new.push(line[1..].to_owned());
            }
            Some(b'-') => hunk.old.push(line[1..].to_owned()),
            Some(b'+') => hunk.new.push(line[1..].to_owned()),
            _ => return Err(error(format!("invalid hunk line: {without_ending:?}"))),
        }
    }
    if let Some(previous) = current {
        if previous.old.len() != previous.old_count || previous.new.len() != expected_new_count {
            return Err(error(format!(
                "hunk line counts do not match {}",
                previous.header
            )));
        }
        hunks.push(previous);
    }
    if hunks.is_empty() {
        return Err(error("patch contains no hunks"));
    }
    if hunks.len() > patch_guard::DEFAULT_MAX_HUNKS as usize {
        return Err(error(format!("too many hunks: {} > 8", hunks.len())));
    }
    Ok(hunks)
}

fn locate(
    lines: &[String],
    block: &[String],
    expected: usize,
    lower_bound: usize,
) -> Option<usize> {
    if block.is_empty() {
        return (expected.max(lower_bound) <= lines.len()).then_some(expected.max(lower_bound));
    }
    let near_start = expected.saturating_sub(8).max(lower_bound);
    let near_end = expected.saturating_add(8).min(lines.len());
    let mut candidates = Vec::new();
    candidates.push(expected);
    for radius in 1..=8 {
        candidates.push(expected.saturating_sub(radius));
        candidates.push(expected.saturating_add(radius));
    }
    candidates.extend(near_start..=near_end);
    candidates.extend(lower_bound..=lines.len().saturating_sub(block.len()));
    let mut seen = std::collections::HashSet::new();
    for index in candidates {
        if index < lower_bound || index + block.len() > lines.len() || !seen.insert(index) {
            continue;
        }
        if lines[index..index + block.len()] == *block {
            return Some(index);
        }
    }
    None
}

fn apply_patch(
    source: &str,
    diff: &str,
    max_hunks: u32,
    max_hunk_bytes: u32,
) -> Result<(String, u32), PatcherError> {
    let hunks = parse_unified(diff)?;
    if hunks.len() > max_hunks as usize {
        return Err(error(format!(
            "too many hunks: {} > {max_hunks}",
            hunks.len()
        )));
    }
    let mut lines = split_keepends(source);
    let mut offset: i64 = 0;
    let mut lower_bound = 0usize;
    for hunk in &hunks {
        if hunk.body_bytes > max_hunk_bytes as usize {
            return Err(error(format!(
                "hunk too large: {} > {max_hunk_bytes}",
                hunk.body_bytes
            )));
        }
        let declared = if hunk.old_count == 0 {
            hunk.old_start as i64
        } else {
            hunk.old_start.saturating_sub(1) as i64
        };
        let expected = declared.saturating_add(offset).max(0) as usize;
        let index = locate(&lines, &hunk.old, expected, lower_bound)
            .ok_or_else(|| error(format!("context not found for {}", hunk.header)))?;
        let end = index + hunk.old.len();
        lines.splice(index..end, hunk.new.iter().cloned());
        offset += hunk.new.len() as i64 - hunk.old.len() as i64;
        lower_bound = index + hunk.new.len();
    }
    Ok((lines.concat(), hunks.len() as u32))
}

fn atomic_replace(path: &Path, contents: &[u8], expected_source: &[u8]) -> std::io::Result<()> {
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("draft");
    let permissions = fs::metadata(path)?.permissions();
    let (temp_path, mut temp_file) = loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.{}.{}.research-patch.tmp",
            std::process::id(),
            sequence
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    let write_result = (|| {
        temp_file.write_all(contents)?;
        temp_file.flush()?;
        temp_file.set_permissions(permissions)?;
        temp_file.sync_all()?;
        drop(temp_file);
        // Check again after preparing the temporary file so a concurrent edit
        // during validation cannot be overwritten by the rename.
        if fs::read(path)? != expected_source {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "draft changed during patch validation",
            ));
        }
        fs::rename(&temp_path, path)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

/// Validate every input, calculate the full result, re-read the bound draft,
/// then atomically replace only that draft file.
pub fn apply_file(
    draft: &Path,
    run_id: &str,
    key_file: &Path,
    receipt_file: &Path,
    diff_file: &Path,
) -> Result<ApplyReport, PatcherError> {
    let canonical_draft = patch_guard::canonical_draft_path(draft)?;
    let canonical_key =
        fs::canonicalize(key_file).map_err(|e| error(format!("cannot resolve --key-file: {e}")))?;
    let canonical_receipt = fs::canonicalize(receipt_file)
        .map_err(|e| error(format!("cannot resolve --receipt: {e}")))?;
    let canonical_diff =
        fs::canonicalize(diff_file).map_err(|e| error(format!("cannot resolve --diff: {e}")))?;
    let input_paths = [
        &canonical_draft,
        &canonical_key,
        &canonical_receipt,
        &canonical_diff,
    ];
    for left in 0..input_paths.len() {
        for right in left + 1..input_paths.len() {
            if input_paths[left] == input_paths[right] {
                return Err(error(
                    "--draft, --key-file, --receipt, and --diff must be distinct files",
                ));
            }
        }
    }

    let source_bytes =
        fs::read(&canonical_draft).map_err(|e| error(format!("cannot read draft: {e}")))?;
    let source =
        std::str::from_utf8(&source_bytes).map_err(|_| error("draft must be UTF-8 text"))?;
    let receipt_bytes =
        fs::read(&canonical_receipt).map_err(|e| error(format!("cannot read --receipt: {e}")))?;
    if receipt_bytes.len() > MAX_RECEIPT_BYTES {
        return Err(error("patch receipt exceeds 65536 bytes"));
    }
    let receipt: Value = serde_json::from_slice(&receipt_bytes)
        .map_err(|e| error(format!("invalid patch receipt JSON: {e}")))?;
    let diff_bytes =
        fs::read(&canonical_diff).map_err(|e| error(format!("cannot read --diff: {e}")))?;
    if diff_bytes.len() > MAX_DIFF_BYTES {
        return Err(error("diff exceeds 65536 bytes"));
    }
    let diff = std::str::from_utf8(&diff_bytes).map_err(|_| error("diff must be UTF-8 text"))?;
    let key = patch_guard::read_key(&canonical_key)?;
    let (max_hunks, max_hunk_bytes) =
        patch_guard::validate_receipt(&receipt, run_id, &canonical_draft, &source_bytes, &key)?;
    let (output, applied_hunks) = apply_patch(source, diff, max_hunks, max_hunk_bytes)?;
    let output_bytes = output.as_bytes();
    if output_bytes == source_bytes {
        return Err(error("patch must change draft content"));
    }
    let current = fs::read(&canonical_draft)
        .map_err(|e| error(format!("cannot re-read draft before apply: {e}")))?;
    if current != source_bytes {
        return Err(error("draft changed during patch validation"));
    }

    let draft_path = patch_guard::path_text(&canonical_draft)?;
    atomic_replace(&canonical_draft, output_bytes, &source_bytes)
        .map_err(|e| error(format!("cannot atomically replace draft: {e}")))?;
    Ok(ApplyReport {
        draft_path,
        before_sha256: patch_guard::sha256(&source_bytes),
        after_sha256: patch_guard::sha256(output_bytes),
        diff_sha256: hex::encode(Sha256::digest(&diff_bytes)),
        applied_hunks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "legion-research-patcher-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn files(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let dir = fixture(name);
        let draft = dir.join("draft.md");
        let key = dir.join("key");
        let receipt = dir.join("receipt.json");
        let diff = dir.join("change.diff");
        fs::write(&draft, b"alpha\nbeta\ngamma\n").unwrap();
        fs::write(&key, [5u8; 32]).unwrap();
        (dir, draft, key, receipt, diff)
    }

    fn write_receipt(draft: &Path, key: &Path, output: &Path) {
        let receipt = patch_guard::issue_receipt(draft, "run-test", key).unwrap();
        fs::write(output, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    }

    fn valid_diff() -> &'static str {
        "--- a/draft.md\n+++ b/draft.md\n@@ -2,1 +2,1 @@\n-beta\n+BETA\n"
    }

    #[test]
    fn valid_patch_changes_only_bound_draft_and_reports_digests() {
        let (dir, draft, key, receipt, diff) = files("valid");
        write_receipt(&draft, &key, &receipt);
        fs::write(&diff, valid_diff()).unwrap();
        let result = apply_file(&draft, "run-test", &key, &receipt, &diff).unwrap();
        assert_eq!(fs::read_to_string(&draft).unwrap(), "alpha\nBETA\ngamma\n");
        assert_eq!(result.applied_hunks, 1);
        assert_ne!(result.before_sha256, result.after_sha256);
        assert_eq!(
            result.diff_sha256,
            hex::encode(Sha256::digest(valid_diff().as_bytes()))
        );
        assert!(apply_file(&draft, "run-test", &key, &receipt, &diff).is_err());
        assert_eq!(fs::read_to_string(&draft).unwrap(), "alpha\nBETA\ngamma\n");
        assert!(!dir.join("key").metadata().unwrap().is_dir());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn context_lines_are_preserved_in_both_hunk_blocks() {
        let diff =
            "--- a/draft.md\n+++ b/draft.md\n@@ -1,3 +1,3 @@\n alpha\n-beta\n+BETA\n gamma\n";
        let (output, count) = apply_patch("alpha\nbeta\ngamma\n", diff, 8, 4096).unwrap();
        assert_eq!(output, "alpha\nBETA\ngamma\n");
        assert_eq!(count, 1);
    }

    #[test]
    fn no_newline_marker_is_rejected_before_draft_write() {
        let (dir, draft, key, receipt, diff) = files("no-newline");
        write_receipt(&draft, &key, &receipt);
        let no_newline = "--- a/draft.md\n+++ b/draft.md\n@@ -2,1 +2,1 @@\n-beta\n\\ No newline at end of file\n+BETA\n";
        fs::write(&diff, no_newline).unwrap();
        let before = fs::read(&draft).unwrap();
        let failure = apply_file(&draft, "run-test", &key, &receipt, &diff).unwrap_err();
        assert!(failure.to_string().contains("no-newline"));
        assert_eq!(fs::read(&draft).unwrap(), before);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_wrong_run_changed_draft_replay_and_noop_without_more_writes() {
        let (dir, draft, key, receipt, diff) = files("reject-bind");
        write_receipt(&draft, &key, &receipt);
        fs::write(&diff, valid_diff()).unwrap();
        let original = fs::read(&draft).unwrap();
        assert!(apply_file(&draft, "other-run", &key, &receipt, &diff).is_err());
        assert_eq!(fs::read(&draft).unwrap(), original);
        fs::write(&draft, b"changed\n").unwrap();
        let changed = fs::read(&draft).unwrap();
        assert!(apply_file(&draft, "run-test", &key, &receipt, &diff).is_err());
        assert_eq!(fs::read(&draft).unwrap(), changed);

        fs::write(&draft, b"alpha\nbeta\ngamma\n").unwrap();
        write_receipt(&draft, &key, &receipt);
        let noop = "--- a/draft.md\n+++ b/draft.md\n@@ -2,1 +2,1 @@\n-beta\n+beta\n";
        fs::write(&diff, noop).unwrap();
        let unchanged = fs::read(&draft).unwrap();
        assert!(apply_file(&draft, "run-test", &key, &receipt, &diff).is_err());
        assert_eq!(fs::read(&draft).unwrap(), unchanged);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_multi_file_wrong_context_tamper_and_hunk_count_mismatch() {
        for (name, diff_text, tamper_receipt) in [
            (
                "multi",
                "diff --git a/one b/one\n--- a/one\n+++ b/one\n@@ -1,1 +1,1 @@\n-a\n+A\ndiff --git a/two b/two\n",
                false,
            ),
            ("context", "--- a/draft.md\n+++ b/draft.md\n@@ -2,1 +2,1 @@\n-missing\n+new\n", false),
            ("count", "--- a/draft.md\n+++ b/draft.md\n@@ -2,2 +2,1 @@\n-beta\n+BETA\n", false),
            ("tamper", valid_diff(), true),
        ] {
            let (dir, draft, key, receipt, diff) = files(name);
            write_receipt(&draft, &key, &receipt);
            if tamper_receipt {
                let mut value: Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
                value["max_hunks"] = json!(1);
                fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            fs::write(&diff, diff_text).unwrap();
            let before = fs::read(&draft).unwrap();
            assert!(apply_file(&draft, "run-test", &key, &receipt, &diff).is_err(), "{name}");
            assert_eq!(fs::read(&draft).unwrap(), before, "{name}");
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn rejects_eight_plus_one_hunks_and_oversized_hunk() {
        let mut many = String::from("--- a/draft.md\n+++ b/draft.md\n");
        for index in 0..9 {
            many.push_str(&format!(
                "@@ -{},1 +{},1 @@\n-x{index}\n+y{index}\n",
                index + 1,
                index + 1
            ));
        }
        assert!(parse_unified(&many)
            .unwrap_err()
            .to_string()
            .contains("too many hunks"));
        let big_line = "x".repeat(4096);
        let oversized =
            format!("--- a/draft.md\n+++ b/draft.md\n@@ -1,1 +1,1 @@\n-{big_line}\n+z\n");
        assert!(parse_unified(&oversized)
            .unwrap_err()
            .to_string()
            .contains("hunk too large"));
    }

    #[test]
    fn hunk_parser_preserves_crlf_and_non_ascii_bytes() {
        let diff = "--- a/draft.md\r\n+++ b/draft.md\r\n@@ -1,1 +1,1 @@\r\n-é\r\n+É\r\n";
        let (out, count) = apply_patch("é\r\n", diff, 8, 4096).unwrap();
        assert_eq!(out, "É\r\n");
        assert_eq!(count, 1);
    }
}
