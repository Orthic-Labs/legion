//! Port of `src/lib/research-core/patcher.py`.
//!
//! Mechanical, receipt-gated unified-diff patch application with hunk-count
//! and hunk-size caps, and fuzzy context relocation matching the Python
//! `_locate` search order exactly (declared position first, then expanding
//! radius, then a full forward scan from `lower_bound`).
//!
//! See `patch_guard.rs` for the `issued_by` mismatch this port preserves
//! rather than fixes: `validate_correction_receipt` here requires
//! `issued_by == "rhook.research-patch-guard"`, which
//! `patch_guard::issue_receipt` never produces.

use hmac::{Hmac, Mac};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::patch_guard::canonical_payload;

pub const DEFAULT_MAX_HUNKS: u32 = 8;
pub const DEFAULT_MAX_HUNK_BYTES: u32 = 4096;

#[derive(Debug)]
pub struct PatcherError(pub String);

impl fmt::Display for PatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PatcherError {}

#[derive(Clone, Debug)]
pub struct Hunk {
    pub header: String,
    pub old_start: i64,
    #[allow(dead_code)]
    pub new_start: i64,
    pub old: Vec<String>,
    pub new: Vec<String>,
    pub body: String,
}

fn hunk_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@").unwrap())
}

/// Mirrors `parse_unified()`. Lines are matched with their trailing newline
/// kept (Python's `splitlines(keepends=True)`), so `body` accumulates the
/// exact hunk text including line endings, matching the byte-size cap check.
pub fn parse_unified(diff: &str) -> Result<Vec<Hunk>, PatcherError> {
    let mut hunks = Vec::new();
    let mut current: Option<Hunk> = None;
    for line in split_keepends(diff) {
        if line.starts_with("--- ") || line.starts_with("+++ ") {
            continue;
        }
        if line.starts_with("@@") {
            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
            let caps = hunk_re()
                .captures(trimmed)
                .ok_or_else(|| PatcherError(format!("invalid hunk header: {}", trimmed.trim())))?;
            if let Some(prev) = current.take() {
                hunks.push(prev);
            }
            current = Some(Hunk {
                header: trimmed.trim().to_string(),
                old_start: caps[1].parse().unwrap(),
                new_start: caps[3].parse().unwrap(),
                old: Vec::new(),
                new: Vec::new(),
                body: String::new(),
            });
            continue;
        }
        let Some(hunk) = current.as_mut() else {
            continue;
        };
        hunk.body.push_str(&line);
        if line.starts_with("\\ No newline") {
            continue;
        }
        if let Some(rest) = line.strip_prefix('-') {
            hunk.old.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix('+') {
            hunk.new.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix(' ') {
            hunk.old.push(rest.to_string());
            hunk.new.push(rest.to_string());
        } else {
            let preview: String = line.chars().take(80).collect();
            return Err(PatcherError(format!("invalid hunk line: {preview:?}")));
        }
    }
    if let Some(prev) = current.take() {
        hunks.push(prev);
    }
    Ok(hunks)
}

/// `str.splitlines(keepends=True)` equivalent: splits on `\n`, keeping the
/// `\n` on every line but the (possibly absent) final one.
fn split_keepends(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            out.push(text[start..=i].to_string());
            start = i + 1;
        }
    }
    if start < text.len() {
        out.push(text[start..].to_string());
    }
    out
}

/// Mirrors `_locate()`: tries the expected index, then an expanding radius
/// of +/-1..=8 around it, then every remaining index from `lower_bound`
/// onward, in that exact order, returning the first index whose slice
/// matches `block`.
fn locate(lines: &[String], block: &[String], expected: i64, lower_bound: usize) -> Option<usize> {
    if block.is_empty() {
        return Some(expected.max(lower_bound as i64).min(lines.len() as i64) as usize);
    }
    let mut candidates: Vec<i64> = vec![expected];
    for radius in 1..=8i64 {
        candidates.push(expected - radius);
        candidates.push(expected + radius);
    }
    for index in lower_bound..lines.len().saturating_sub(block.len()) + 1 {
        candidates.push(index as i64);
    }
    let mut seen = std::collections::HashSet::new();
    for index in candidates {
        if !seen.insert(index) {
            continue;
        }
        if index < lower_bound as i64 || index < 0 {
            continue;
        }
        let index = index as usize;
        if index + block.len() > lines.len() {
            continue;
        }
        if lines[index..index + block.len()] == *block {
            return Some(index);
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub applied: u32,
    pub output: Option<String>,
}

impl ApplyResult {
    pub fn to_json(&self, include_output: bool) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("ok".into(), json!(self.ok));
        if let Some(reason) = &self.reason {
            obj.insert("reason".into(), json!(reason));
        }
        obj.insert("applied".into(), json!(self.applied));
        if include_output {
            if let Some(output) = &self.output {
                obj.insert("output".into(), json!(output));
            }
        }
        Value::Object(obj)
    }
}

/// Mirrors `apply_patch()`.
pub fn apply_patch(
    source: &str,
    diff: &str,
    max_hunks: u32,
    max_hunk_bytes: u32,
) -> ApplyResult {
    let hunks = match parse_unified(diff) {
        Ok(h) => h,
        Err(e) => {
            return ApplyResult {
                ok: false,
                reason: Some(e.0),
                applied: 0,
                output: None,
            }
        }
    };
    if hunks.is_empty() {
        return ApplyResult {
            ok: false,
            reason: Some("patch contains no hunks".into()),
            applied: 0,
            output: None,
        };
    }
    if hunks.len() as u32 > max_hunks {
        return ApplyResult {
            ok: false,
            reason: Some(format!("too many hunks: {} > {max_hunks}", hunks.len())),
            applied: 0,
            output: None,
        };
    }

    let mut lines = split_keepends(source);
    let mut offset: i64 = 0;
    let mut lower_bound: usize = 0;
    let mut applied: u32 = 0;

    for hunk in &hunks {
        let body_bytes = hunk.body.as_bytes().len() as u32;
        if body_bytes > max_hunk_bytes {
            return ApplyResult {
                ok: false,
                reason: Some(format!("hunk too large: {body_bytes} > {max_hunk_bytes}")),
                applied,
                output: None,
            };
        }
        let expected = (hunk.old_start - 1 + offset).max(0);
        let index = match locate(&lines, &hunk.old, expected, lower_bound) {
            Some(i) => i,
            None => {
                return ApplyResult {
                    ok: false,
                    reason: Some(format!("context not found for {}", hunk.header)),
                    applied,
                    output: None,
                }
            }
        };
        let end = index + hunk.old.len();
        lines.splice(index..end, hunk.new.iter().cloned());
        offset += hunk.new.len() as i64 - hunk.old.len() as i64;
        lower_bound = index + hunk.new.len();
        applied += 1;
    }

    ApplyResult {
        ok: true,
        reason: None,
        applied,
        output: Some(lines.concat()),
    }
}

fn default_key_path() -> PathBuf {
    super::patch_guard::default_key_path()
}

/// Mirrors `validate_correction_receipt()`. `source_bytes`, when given, must
/// hash to the receipt's bound `sourced_draft_sha256`.
pub fn validate_correction_receipt(
    receipt: &Value,
    source_bytes: Option<&[u8]>,
    key_path: Option<&Path>,
) -> (bool, String) {
    let issued_by = receipt.get("issued_by").and_then(Value::as_str).unwrap_or("");
    if receipt.get("receipt_version") != Some(&json!(2)) || issued_by != "rhook.research-patch-guard" {
        return (false, "receipt must be an authenticated rhook patch receipt v2".into());
    }
    if receipt.get("stage").and_then(Value::as_str) != Some("patch") {
        return (false, "receipt stage must be patch".into());
    }
    let allowed: std::collections::BTreeSet<String> = receipt
        .get("allowed_tools")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let expected_allowed: std::collections::BTreeSet<String> =
        ["Read".to_string(), "Edit".to_string()].into_iter().collect();
    if allowed != expected_allowed {
        let mut sorted: Vec<&String> = allowed.iter().collect();
        sorted.sort();
        return (
            false,
            format!(
                "patch stage allowed_tools must be exactly Read+Edit, got [{}]",
                sorted
                    .iter()
                    .map(|s| format!("'{s}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    let bound = receipt
        .get("sourced_draft_sha256")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let hex64 = Regex::new(r"^[0-9a-f]{64}$").unwrap();
    if !hex64.is_match(&bound) {
        return (false, "receipt must bind the sourced draft sha256".into());
    }
    if let Some(source_bytes) = source_bytes {
        let mut hasher = Sha256::new();
        hasher.update(source_bytes);
        let actual = hex::encode(hasher.finalize());
        if actual != bound {
            return (false, "receipt draft hash does not match source bytes".into());
        }
    }
    let path = key_path.map(PathBuf::from).unwrap_or_else(default_key_path);
    let key = match std::fs::read(&path) {
        Ok(k) => k,
        Err(_) => return (false, format!("patch signing key unavailable: {}", path.display())),
    };
    let signature = receipt.get("signature").and_then(Value::as_str).unwrap_or("").to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&canonical_payload(receipt));
    let expected = format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()));
    if signature != expected {
        return (false, "patch receipt signature mismatch".into());
    }
    (true, "ok".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::wf026::patch_guard::sign;

    #[test]
    fn single_hunk_applies_cleanly() {
        let source = "line1\nline2\nline3\n";
        let diff = "--- a\n+++ b\n@@ -1,3 +1,3 @@\n line1\n-line2\n+LINE2\n line3\n";
        let result = apply_patch(source, diff, DEFAULT_MAX_HUNKS, DEFAULT_MAX_HUNK_BYTES);
        assert!(result.ok);
        assert_eq!(result.applied, 1);
        assert_eq!(result.output.unwrap(), "line1\nLINE2\nline3\n");
    }

    #[test]
    fn context_shifted_by_radius_is_still_located() {
        // Declared old_start points one line too early; the real match is
        // two lines further down, inside the +/-8 radius search.
        let source = "a\nb\nc\nd\ne\nf\n";
        let diff = "--- a\n+++ b\n@@ -1,1 +1,1 @@\n-c\n+C\n";
        let result = apply_patch(source, diff, DEFAULT_MAX_HUNKS, DEFAULT_MAX_HUNK_BYTES);
        assert!(result.ok, "reason: {:?}", result.reason);
        assert_eq!(result.output.unwrap(), "a\nb\nC\nd\ne\nf\n");
    }

    #[test]
    fn missing_context_is_reported_as_not_found() {
        let source = "a\nb\nc\n";
        let diff = "--- a\n+++ b\n@@ -1,1 +1,1 @@\n-zzz\n+Z\n";
        let result = apply_patch(source, diff, DEFAULT_MAX_HUNKS, DEFAULT_MAX_HUNK_BYTES);
        assert!(!result.ok);
        assert!(result.reason.unwrap().starts_with("context not found for"));
    }

    #[test]
    fn empty_diff_is_rejected_as_no_hunks() {
        let result = apply_patch("a\n", "--- a\n+++ b\n", DEFAULT_MAX_HUNKS, DEFAULT_MAX_HUNK_BYTES);
        assert!(!result.ok);
        assert_eq!(result.reason.unwrap(), "patch contains no hunks");
    }

    #[test]
    fn too_many_hunks_is_rejected() {
        let mut diff = String::from("--- a\n+++ b\n");
        for i in 0..3 {
            diff.push_str(&format!("@@ -{},1 +{},1 @@\n-x{i}\n+y{i}\n", i + 1, i + 1));
        }
        let result = apply_patch("x0\nx1\nx2\n", &diff, 2, DEFAULT_MAX_HUNK_BYTES);
        assert!(!result.ok);
        assert_eq!(result.reason.unwrap(), "too many hunks: 3 > 2");
    }

    #[test]
    fn oversized_hunk_body_is_rejected() {
        let diff = "--- a\n+++ b\n@@ -1,1 +1,1 @@\n-a\n+b\n";
        let result = apply_patch("a\n", diff, DEFAULT_MAX_HUNKS, 1);
        assert!(!result.ok);
        assert!(result.reason.unwrap().starts_with("hunk too large:"));
    }

    #[test]
    fn invalid_hunk_header_is_a_parse_error() {
        let result = apply_patch("a\n", "--- a\n+++ b\n@@ bogus @@\n-a\n+b\n", DEFAULT_MAX_HUNKS, DEFAULT_MAX_HUNK_BYTES);
        assert!(!result.ok);
        assert!(result.reason.unwrap().starts_with("invalid hunk header:"));
    }

    fn valid_receipt(key_path: &Path, draft_sha256: &str) -> Value {
        let mut receipt = json!({
            "receipt_version": 2,
            "issued_by": "rhook.research-patch-guard",
            "issued_at": "2026-01-01T00:00:00Z",
            "run_id": "run-test",
            "stage": "patch",
            "allowed_tools": ["Read", "Edit"],
            "sourced_draft_sha256": draft_sha256,
            "max_hunks": 8,
            "max_hunk_bytes": 4096,
        });
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        let key = super::super::patch_guard::load_or_create_key(Some(key_path)).unwrap();
        let signature = sign(&receipt, &key);
        receipt["signature"] = json!(signature);
        receipt
    }

    #[test]
    fn valid_receipt_and_matching_source_validates() {
        let dir = std::env::temp_dir().join(format!(
            "legion-wf026-patcher-valid-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let key_path = dir.join("key");
        let source = b"hello\n";
        let mut hasher = Sha256::new();
        hasher.update(source);
        let sha = hex::encode(hasher.finalize());
        let receipt = valid_receipt(&key_path, &sha);

        let (ok, reason) = validate_correction_receipt(&receipt, Some(source), Some(&key_path));
        assert!(ok, "reason: {reason}");
    }

    #[test]
    fn receipt_with_wrong_issuer_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "legion-wf026-patcher-wrong-issuer-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let key_path = dir.join("key");
        // The exact receipt patch_guard::issue_receipt produces.
        let draft = dir.join("draft.md");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&draft, b"hello\n").unwrap();
        let receipt = super::super::patch_guard::issue_receipt(&draft, "run-test", Some(&key_path)).unwrap();

        let (ok, reason) = validate_correction_receipt(&receipt, Some(b"hello\n"), Some(&key_path));
        assert!(!ok);
        assert_eq!(reason, "receipt must be an authenticated rhook patch receipt v2");
    }

    #[test]
    fn receipt_hash_mismatch_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "legion-wf026-patcher-hash-mismatch-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let key_path = dir.join("key");
        let mut hasher = Sha256::new();
        hasher.update(b"original\n");
        let sha = hex::encode(hasher.finalize());
        let receipt = valid_receipt(&key_path, &sha);

        let (ok, reason) = validate_correction_receipt(&receipt, Some(b"tampered\n"), Some(&key_path));
        assert!(!ok);
        assert_eq!(reason, "receipt draft hash does not match source bytes");
    }

    #[test]
    fn receipt_signature_mismatch_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "legion-wf026-patcher-sig-mismatch-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let key_path = dir.join("key");
        let mut hasher = Sha256::new();
        hasher.update(b"hello\n");
        let sha = hex::encode(hasher.finalize());
        let mut receipt = valid_receipt(&key_path, &sha);
        receipt["signature"] = json!("hmac-sha256:deadbeef");

        let (ok, reason) = validate_correction_receipt(&receipt, Some(b"hello\n"), Some(&key_path));
        assert!(!ok);
        assert_eq!(reason, "patch receipt signature mismatch");
    }
}
