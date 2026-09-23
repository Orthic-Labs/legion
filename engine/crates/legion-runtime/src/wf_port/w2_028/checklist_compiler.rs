//! Port of `skills/seo/scripts/checklist_compiler.py`.
//!
//! Fully ported: this script is pure text/JSON transformation (regex
//! parsing, sha256 digest, semantic diff). The Python CLI wraps three
//! subcommands (`compile`, `verify`, `diff`) around file I/O; the file I/O
//! itself is not ported (no CLI surface in this chunk), but every function
//! it calls is, with the same return shapes (`CompileResult` mirrors the
//! Python `compile_text` dict; `SemanticDiff` mirrors `semantic_diff`).

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Digest;

fn check_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*-\s*\[\s*\]\s+(.+?)\s*$").unwrap())
}

fn heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(#{1,6})\s+(.+?)\s*$").unwrap())
}

fn phase_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^PHASE\s+(\d+)\b").unwrap())
}

/// Mirrors Python `digest`: sha256 hex digest of `text`.
pub fn digest(text: &str) -> String {
    let hash = sha2::Sha256::digest(text.as_bytes());
    hex::encode(hash)
}

/// Mirrors Python `slug`: casefold, collapse non-`[a-z0-9]` runs to `-`,
/// trim `-`, truncate to `max_len` then trim trailing `-` again, default
/// to `"control"` when empty.
pub fn slug(text: &str, max_len: usize) -> String {
    static NON_ALNUM: OnceLock<Regex> = OnceLock::new();
    let re = NON_ALNUM.get_or_init(|| Regex::new(r"[^a-z0-9]+").unwrap());
    let folded = text.to_lowercase();
    let collapsed = re.replace_all(&folded, "-");
    let trimmed = collapsed.trim_matches('-');
    let truncated: String = trimmed.chars().take(max_len).collect();
    let truncated = truncated.trim_end_matches('-');
    if truncated.is_empty() {
        "control".to_string()
    } else {
        truncated.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Candidate {
    pub candidate_id: String,
    pub source: String,
    pub phase: Option<i64>,
    pub heading_path: Vec<String>,
    pub line_start: usize,
    pub line_end: usize,
    pub text: String,
    pub promotion_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompileResult {
    pub source: String,
    pub sha256: String,
    pub line_count: usize,
    pub candidate_count: usize,
    pub candidates: Vec<Candidate>,
}

/// Mirrors Python `compile_text`.
pub fn compile_text(text: &str, source_name: &str) -> CompileResult {
    let lines: Vec<&str> = text.lines().collect();
    // Python's heading_stack is a dict keyed by level; BTreeMap keeps the
    // same "sorted by level" iteration order used to build heading_path.
    let mut heading_stack: std::collections::BTreeMap<usize, String> =
        std::collections::BTreeMap::new();
    let mut phase: Option<i64> = None;
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut candidates = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let lineno = idx + 1;
        if let Some(hm) = heading_re().captures(line) {
            let level = hm.get(1).unwrap().as_str().len();
            let title = hm.get(2).unwrap().as_str().trim().to_string();
            heading_stack.retain(|&k, _| k < level);
            let pm = phase_re().captures(&title);
            if let Some(pm) = pm {
                phase = pm.get(1).unwrap().as_str().parse::<i64>().ok();
            }
            heading_stack.insert(level, title);
            continue;
        }
        let cm = match check_re().captures(line) {
            Some(c) => c,
            None => continue,
        };
        let text_value = cm.get(1).unwrap().as_str().trim().to_string();
        let base = format!(
            "phase-{:02}.{}",
            phase.unwrap_or(0),
            slug(&text_value, 56)
        );
        let count = seen.entry(base.clone()).or_insert(0);
        *count += 1;
        let cid = if *count == 1 {
            base.clone()
        } else {
            format!("{}-{}", base, count)
        };
        candidates.push(Candidate {
            candidate_id: cid,
            source: source_name.to_string(),
            phase,
            heading_path: heading_stack.values().cloned().collect(),
            line_start: lineno,
            line_end: lineno,
            text: text_value,
            promotion_state: "candidate".to_string(),
        });
    }

    CompileResult {
        source: source_name.to_string(),
        sha256: digest(text),
        line_count: lines.len(),
        candidate_count: candidates.len(),
        candidates,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Changed {
    pub id: String,
    pub before: Candidate,
    pub after: Candidate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SemanticDiff {
    pub added: Vec<Candidate>,
    pub removed: Vec<Candidate>,
    pub changed: Vec<Changed>,
}

/// Mirrors Python `semantic_diff`.
pub fn semantic_diff(old: &CompileResult, new: &CompileResult) -> SemanticDiff {
    use std::collections::BTreeMap;
    let old_map: BTreeMap<&str, &Candidate> = old
        .candidates
        .iter()
        .map(|c| (c.candidate_id.as_str(), c))
        .collect();
    let new_map: BTreeMap<&str, &Candidate> = new
        .candidates
        .iter()
        .map(|c| (c.candidate_id.as_str(), c))
        .collect();

    let added: Vec<Candidate> = new_map
        .keys()
        .filter(|k| !old_map.contains_key(*k))
        .map(|k| new_map[k].clone())
        .collect();
    let removed: Vec<Candidate> = old_map
        .keys()
        .filter(|k| !new_map.contains_key(*k))
        .map(|k| old_map[k].clone())
        .collect();
    let mut changed = Vec::new();
    for key in old_map.keys().filter(|k| new_map.contains_key(*k)) {
        let before = old_map[key];
        let after = new_map[key];
        if before.text != after.text || before.heading_path != after.heading_path {
            changed.push(Changed {
                id: key.to_string(),
                before: before.clone(),
                after: after.clone(),
            });
        }
    }

    SemanticDiff {
        added,
        removed,
        changed,
    }
}

/// Mirrors the `verify` subcommand's check: does `text` match the recorded
/// `sha256` and `line_count`. Returns `(matches, got_sha256, got_line_count)`.
pub fn verify(text: &str, expected_sha256: &str, expected_line_count: usize) -> (bool, String, usize) {
    let got_sha = digest(text);
    let got_lines = text.lines().count();
    let ok = got_sha == expected_sha256 && got_lines == expected_line_count;
    (ok, got_sha, got_lines)
}
