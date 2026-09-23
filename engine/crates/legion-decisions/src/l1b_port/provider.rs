//! L1b literal port of `src/lib/decision_provider.py`.
//!
//! Architect-owned decision lifecycle provider: reads `DecisionRecord`s
//! (already loaded from a `DecisionStore`, e.g. via `DecisionStore::all()`)
//! and produces a `ContextCandidateSet` plus lifecycle warnings, honoring
//! the same fail-closed rules as the Python provider:
//!
//! * At most one candidate is admitted per stable decision id — the
//!   current (highest-priority non-superseded) sibling.
//! * A stale `proposed`-only lineage that has been superseded is dropped
//!   entirely (no candidate, no omission).
//! * `implemented` records missing `implementationRefs` still admit but
//!   raise a `ProviderWarning`.
//! * Records whose `linkedGraphGeneration` does not match the request
//!   scope are downgraded to omissions.
//! * Provider ceilings (`maxCandidates`, `maxEstimatedTokens`) are
//!   enforced fail-closed: exceeding the token ceiling raises
//!   `LifecycleError` rather than silently truncating.

use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

use crate::model::{DecisionRecord, DecisionStatus, DECISION_ID_PREFIX};

pub const LAYER: u32 = 5;
pub const PROVIDER_NAME: &str = "architect";
pub const SOURCE_KIND: &str = "architect_decision";
pub const TRUST_CLASS: &str = "agent_verified";
pub const INSTRUCTION_POLICY: &str = "data_only";
pub const SCHEMA_VERSION_CONTRACT: u32 = 1;

#[derive(Debug, Clone)]
pub struct LifecycleError(pub String);

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for LifecycleError {}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderWarning {
    pub code: String,
    pub decision_id: String,
    pub detail: String,
}

impl ProviderWarning {
    pub fn as_json(&self) -> Value {
        json!({
            "code": self.code,
            "decisionId": self.decision_id,
            "detail": self.detail,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CandidateSpec {
    pub task: String,
    pub repository_id: String,
    pub scope_id: String,
    pub linked_graph_generation: Option<String>,
    pub trace_id: Option<String>,
    pub provider: String,
    pub max_candidates: usize,
    pub max_estimated_tokens: u64,
}

impl Default for CandidateSpec {
    fn default() -> Self {
        Self {
            task: String::new(),
            repository_id: String::new(),
            scope_id: String::new(),
            linked_graph_generation: None,
            trace_id: None,
            provider: PROVIDER_NAME.to_string(),
            max_candidates: 40,
            max_estimated_tokens: 8000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContextCandidateSet {
    pub schema_version: u32,
    pub trace_id: String,
    pub task: String,
    pub mode: String,
    pub provider: String,
    pub freshness: Value,
    pub provider_ceiling: Value,
    pub candidates: Vec<Value>,
    pub omissions: Vec<Value>,
    pub warnings: Vec<ProviderWarning>,
}

impl ContextCandidateSet {
    pub fn as_json(&self) -> Value {
        let mut payload = json!({
            "schemaVersion": self.schema_version,
            "traceId": self.trace_id,
            "task": self.task,
            "mode": self.mode,
            "provider": self.provider,
            "freshness": self.freshness,
            "providerCeiling": self.provider_ceiling,
            "candidates": self.candidates,
            "omissions": self.omissions,
        });
        if !self.warnings.is_empty() {
            payload["warnings"] = Value::Array(self.warnings.iter().map(|w| w.as_json()).collect());
        }
        payload
    }
}

fn candidate_id_for(record: &DecisionRecord) -> String {
    if record.id.starts_with(DECISION_ID_PREFIX) {
        if record.current_status == DecisionStatus::Proposed {
            return format!("{}:proposed", record.id);
        }
        return record.id.clone();
    }
    record.id.clone()
}

fn text_for(record: &DecisionRecord) -> String {
    let status = status_str(record.current_status);
    format!(
        "Architect decision ({status}): task={} rationale={}",
        record.task_id, record.rationale
    )
}

fn estimated_tokens(text: &str) -> u64 {
    (((text.chars().count() as u64) + 3) / 4).max(1)
}

fn status_str(status: DecisionStatus) -> &'static str {
    match status {
        DecisionStatus::Proposed => "proposed",
        DecisionStatus::Accepted => "accepted",
        DecisionStatus::Implemented => "implemented",
        DecisionStatus::Superseded => "superseded",
    }
}

fn score_for_status(status: DecisionStatus) -> f64 {
    match status {
        DecisionStatus::Implemented => 0.97,
        DecisionStatus::Accepted => 0.94,
        DecisionStatus::Proposed => 0.71,
        DecisionStatus::Superseded => 0.0,
    }
}

fn build_candidate(record: &DecisionRecord, exact: bool, provider_score: f64) -> Value {
    let body = text_for(record);
    let source_hash = record
        .compute_source_hash()
        .unwrap_or_else(|_| String::from("sha256:0"));
    json!({
        "id": candidate_id_for(record),
        "layer": LAYER,
        "sourceKind": SOURCE_KIND,
        "sourceRef": format!("architect://decision:{}", record.id),
        "sourceHash": source_hash,
        "trustClass": TRUST_CLASS,
        "instructionPolicy": INSTRUCTION_POLICY,
        "providerScore": provider_score,
        "scoreComponents": {
            "lifecycle": score_for_status(record.current_status),
            "scope": if record.repository_id.is_empty() { 0.0 } else { 1.0 },
        },
        "estimatedTokens": estimated_tokens(&body),
        "protected": false,
        "exact": exact,
        "recoverable": true,
        "resolver": format!("architect resolve {}", candidate_id_for(record)),
        "text": body,
    })
}

fn trace_id(spec: &CandidateSpec) -> String {
    if let Some(id) = &spec.trace_id {
        if !id.is_empty() {
            return id.clone();
        }
    }
    let payload = format!("{}|{}|{}", spec.task, spec.repository_id, spec.scope_id);
    let digest = sha256_hex(payload.as_bytes());
    digest[..24].to_string()
}

fn freshness(records: &[DecisionRecord]) -> Value {
    let mut latest: Option<&str> = None;
    for record in records {
        if record.created_at.is_empty() {
            continue;
        }
        let created = record.created_at.as_str();
        let replace = match latest {
            None => true,
            Some(l) => created > l,
        };
        if replace {
            latest = Some(created);
        }
    }
    let latest_owned = latest
        .map(|s| s.to_string())
        .unwrap_or_else(now_utc_seconds);
    json!({
        "revision": format!("architect-{latest_owned}"),
        "indexedAt": latest_owned,
        "stale": false,
    })
}

fn now_utc_seconds() -> String {
    // Matches Python's `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")`
    // shape; wall-clock source is intentionally left to the caller's runtime
    // (std has no timezone-aware clock), so this falls back to the Unix
    // epoch offset formatted the same way when no record supplies a
    // timestamp — callers needing precise "now" should supply
    // `created_at` on at least one record, matching the Python provider's
    // corpus-driven usage.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let (h, m, s) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);
    // Civil-from-days (Howard Hinnant's algorithm), UTC, no external crate.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_ = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m_ <= 2 { y + 1 } else { y };
    format!("{y:04}-{m_:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn index_active(
    records: &[DecisionRecord],
    repository_id: &str,
) -> (
    BTreeMap<String, DecisionRecord>,
    BTreeMap<String, Vec<DecisionRecord>>,
) {
    let mut siblings: BTreeMap<String, Vec<DecisionRecord>> = BTreeMap::new();
    for record in records {
        if record.repository_id != repository_id {
            continue;
        }
        siblings.entry(record.id.clone()).or_default().push(record.clone());
    }
    let mut current: BTreeMap<String, DecisionRecord> = BTreeMap::new();
    for (stable_id, group) in &siblings {
        let has_superseded = group.iter().any(|r| r.current_status == DecisionStatus::Superseded);
        let has_accepted_or_implemented = group.iter().any(|r| {
            matches!(r.current_status, DecisionStatus::Accepted | DecisionStatus::Implemented)
        });
        if has_superseded && !has_accepted_or_implemented {
            continue;
        }
        let best = group
            .iter()
            .max_by_key(|r| r.current_status.rank())
            .expect("group is non-empty");
        if best.current_status != DecisionStatus::Superseded {
            current.insert(stable_id.clone(), best.clone());
        }
    }
    (current, siblings)
}

fn supersedes_chain(
    record: &DecisionRecord,
    siblings: &BTreeMap<String, Vec<DecisionRecord>>,
) -> HashSet<String> {
    let mut chain: HashSet<String> = HashSet::new();
    for sibling_id in &record.supersedes {
        chain.insert(sibling_id.clone());
        for group in siblings.values() {
            for candidate in group {
                if chain.contains(&candidate.id) {
                    chain.extend(candidate.supersedes.iter().cloned());
                }
            }
        }
    }
    chain
}

/// Pure port of `produce_candidate_set`. The caller supplies `records`
/// (e.g. `DecisionStore::all()?`) instead of a store handle, since store
/// I/O is not part of this literal-logic port.
pub fn produce_candidate_set(
    spec: &CandidateSpec,
    records: &[DecisionRecord],
    mode: &str,
) -> Result<ContextCandidateSet, LifecycleError> {
    let (current, siblings) = index_active(records, &spec.repository_id);

    let mut warnings: Vec<ProviderWarning> = Vec::new();
    let mut candidates: Vec<Value> = Vec::new();
    let mut omissions: Vec<Value> = Vec::new();

    for (stable_id, current_record) in &current {
        let chain = supersedes_chain(current_record, &siblings);

        if let Some(generation) = &spec.linked_graph_generation {
            if &current_record.linked_graph_generation != generation {
                omissions.push(json!({
                    "id": candidate_id_for(current_record),
                    "layer": LAYER.to_string(),
                    "reason": "stale_graph_generation",
                }));
                continue;
            }
        }

        if current_record.current_status == DecisionStatus::Implemented
            && current_record.implementation_refs.is_empty()
        {
            warnings.push(ProviderWarning {
                code: "implementation_refs_missing".to_string(),
                decision_id: candidate_id_for(current_record),
                detail: "implemented record has empty implementationRefs".to_string(),
            });
        }

        candidates.push(build_candidate(
            current_record,
            matches!(
                current_record.current_status,
                DecisionStatus::Accepted | DecisionStatus::Implemented
            ),
            score_for_status(current_record.current_status),
        ));

        if let Some(group) = siblings.get(stable_id) {
            for sibling in group {
                if sibling == current_record {
                    continue;
                }
                if sibling.current_status == DecisionStatus::Superseded {
                    continue;
                }
                omissions.push(json!({
                    "id": candidate_id_for(sibling),
                    "layer": LAYER.to_string(),
                    "reason": "superseded_by_current",
                }));
            }
        }
        for superseded_id in &chain {
            omissions.push(json!({
                "id": format!("{DECISION_ID_PREFIX}:{superseded_id}"),
                "layer": LAYER.to_string(),
                "reason": "supersession_chain",
            }));
        }
    }

    candidates.sort_by(|a, b| {
        let sa = a["providerScore"].as_f64().unwrap_or(0.0);
        let sb = b["providerScore"].as_f64().unwrap_or(0.0);
        sb.partial_cmp(&sa)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a["id"].as_str().unwrap_or("").cmp(b["id"].as_str().unwrap_or("")))
    });

    let ceiling_candidates: Vec<Value> = candidates.iter().take(spec.max_candidates).cloned().collect();
    if candidates.len() > spec.max_candidates {
        for dropped in candidates.iter().skip(spec.max_candidates) {
            omissions.push(json!({
                "id": dropped["id"].clone(),
                "layer": LAYER.to_string(),
                "reason": "max_candidates_exceeded",
            }));
        }
    }

    let admitted_tokens: u64 = ceiling_candidates
        .iter()
        .map(|c| c["estimatedTokens"].as_u64().unwrap_or(0))
        .sum();
    if admitted_tokens > spec.max_estimated_tokens {
        return Err(LifecycleError(format!(
            "admitted tokens {admitted_tokens} exceed ceiling {}",
            spec.max_estimated_tokens
        )));
    }

    Ok(ContextCandidateSet {
        schema_version: SCHEMA_VERSION_CONTRACT,
        trace_id: trace_id(spec),
        task: spec.task.clone(),
        mode: mode.to_string(),
        provider: spec.provider.clone(),
        freshness: freshness(records),
        provider_ceiling: json!({
            "maxCandidates": spec.max_candidates,
            "maxEstimatedTokens": spec.max_estimated_tokens,
        }),
        candidates: ceiling_candidates,
        omissions,
        warnings,
    })
}

// Kept local so this literal port does not add a second crypto dependency
// beyond what `legion-decisions` already uses for id derivation; identical
// implementation to `model::sha256_hex` (private there).
fn sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut data = input.to_vec();
    let bit_len = (data.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
}
