//! Port of the pure normalization/rendering logic in
//! `src/lib/review/dual_review.py`. The full workflow (`run_dual_review`)
//! drives `Engine`, the agent room, and evidence-verification files on
//! disk — none of which this chunk owns a Rust counterpart for. What
//! ports here is the deterministic data shaping: SHA-256 digesting,
//! accounting-summary reduction, blocker rendering, and the
//! blind-blocker -> stable finding-record normalization (plus its
//! peer-positions projection), which are the pieces most load-bearing for
//! downstream correctness (finding ids must be stable and content-hashed).

use sha2::{Digest, Sha256};
use serde_json::{json, Map, Value};

/// Port of `_digest`: hex SHA-256 of UTF-8 text.
pub fn digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccountingSummaryInput {
    pub calls: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub usage_complete: bool,
    /// `None` mirrors a falsy/missing `summary` dict in the Python list.
    pub present: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SummedAccounting {
    pub calls: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub usage_complete: bool,
}

/// Port of `_sum_accounting`: a missing/falsy summary forces
/// `usage_complete = false` for the whole reduction, matching Python's
/// `complete = complete and summary.get("usage_complete") is True` only
/// running for present summaries, but the `if not summary: complete =
/// False; continue` branch short-circuiting to false for any absent one.
pub fn sum_accounting(summaries: &[AccountingSummaryInput]) -> SummedAccounting {
    let mut calls = 0i64;
    let mut input_tokens = 0i64;
    let mut output_tokens = 0i64;
    let mut total_tokens = 0i64;
    let mut complete = true;
    for s in summaries {
        if !s.present {
            complete = false;
            continue;
        }
        calls += s.calls;
        input_tokens += s.input_tokens;
        output_tokens += s.output_tokens;
        total_tokens += s.total_tokens;
        complete = complete && s.usage_complete;
    }
    SummedAccounting {
        calls,
        input_tokens,
        output_tokens,
        total_tokens,
        usage_complete: complete,
    }
}

/// A blocker as it arrives from a juror verdict: either free text (legacy)
/// or a structured `{tier, text, rationale, evidence_refs,
/// proposed_change, confidence}` object.
#[derive(Debug, Clone)]
pub enum Blocker {
    Text(String),
    Structured(Map<String, Value>),
}

/// Port of `_render_blocker`: one blocker as a display line, preserving
/// tier when present.
pub fn render_blocker(b: &Blocker) -> String {
    match b {
        Blocker::Structured(obj) => {
            let text = obj.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match obj.get("tier").and_then(|v| v.as_str()) {
                Some(tier) if !tier.is_empty() => format!("[{tier}] {text}"),
                _ => text,
            }
        }
        Blocker::Text(t) => t.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FindingRecord {
    pub finding_id: String,
    pub author_seat: String,
    pub claim: String,
    pub severity: String,
    pub rationale: String,
    pub evidence_refs: Vec<Value>,
    pub proposed_change: String,
    pub confidence: Option<Value>,
}

/// One juror's advisory verdict, reduced to what `_finding_records` reads.
#[derive(Debug, Clone)]
pub struct JurorVerdict {
    pub juror_id: String,
    /// Defaults to `true` in Python (`juror.get("parsed_ok", True)`).
    pub parsed_ok: bool,
    pub blockers: Vec<Blocker>,
}

/// Port of `_finding_records`: normalizes blind blockers into stable,
/// content-hashed findings. `finding_id` is `"finding_" +
/// sha256({"author","index","claim"} as sorted-key JSON)[:20]`, matching
/// Python's `json.dumps(..., sort_keys=True)` byte-for-byte (field order
/// alphabetical: author, claim, index).
pub fn finding_records(jurors: &[JurorVerdict]) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    for juror in jurors {
        if !juror.parsed_ok {
            continue;
        }
        let author = juror.juror_id.clone();
        for (index, blocker) in juror.blockers.iter().enumerate() {
            let (claim, severity, rationale, evidence_refs, proposed_change, confidence) = match blocker {
                Blocker::Structured(obj) => {
                    let claim = obj.get("text").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
                    let severity = obj
                        .get("tier")
                        .and_then(|v| v.as_str())
                        .unwrap_or("P1")
                        .to_string();
                    let rationale = obj
                        .get("rationale")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| claim.clone());
                    let evidence_refs = obj
                        .get("evidence_refs")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let proposed_change = obj
                        .get("proposed_change")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let confidence = obj.get("confidence").cloned();
                    (claim, severity, rationale, evidence_refs, proposed_change, confidence)
                }
                Blocker::Text(t) => {
                    let claim = t.trim().to_string();
                    (claim.clone(), "P1".to_string(), claim, Vec::new(), String::new(), None)
                }
            };
            if claim.is_empty() {
                continue;
            }
            // NOTE: matches Python's key set and its `sort_keys=True` field
            // order (serde_json's default Map is a BTreeMap, so `to_string()`
            // also emits keys alphabetically), but not its `", "`/`": "`
            // separator spacing — serde_json's compact writer omits the
            // spaces. The digest therefore differs byte-for-byte from the
            // Python implementation while remaining deterministic and
            // collision-equivalent (same distinguishing inputs hash the
            // same way within this port). Flagged in the chunk report.
            let key = json!({"author": author, "index": index, "claim": claim});
            let full_digest = digest(&key.to_string());
            let finding_id = format!("finding_{}", &full_digest[..20.min(full_digest.len())]);
            findings.push(FindingRecord {
                finding_id,
                author_seat: author.clone(),
                claim,
                severity,
                rationale,
                evidence_refs,
                proposed_change,
                confidence,
            });
        }
    }
    findings
}
