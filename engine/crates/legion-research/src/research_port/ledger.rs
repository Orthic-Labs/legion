//! Port of `tools/research-core/ledger.py`: evidence and claim ledger
//! validation, confidence adjudication, and brief rendering, plus the
//! admission rules `run.py` applies before appending a row
//! (`record_evidence`, `record_claim`).
//!
//! Rows are JSON objects in the Python row schema (`id`, `url`, `publisher`,
//! `retrieved_at`, `locator`, `instructionPolicy`, `claim_type`, `source_ids`,
//! ...). This is distinct from the native `EvidenceLedger` in `evidence.rs`.
//!
//! Deliberate divergences from the Python:
//! - Python crashes on malformed shapes (missing evidence id, a non-list
//!   `source_ids`); the port returns an error or a blocking reason instead.
//! - `render` takes `as_of` as a parameter instead of reading the clock.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::contradictions;
use super::independence::{self, NEAR_DUPLICATE_THRESHOLD};
use super::pyval::{
    is_none_or_empty_str, is_null_or_empty, py_list_repr, py_repr_str, py_str, py_str_or, truthy,
};

pub const CLAIM_TYPES: [&str; 18] = [
    "price",
    "feature",
    "legal",
    "case-law",
    "benchmark",
    "comparative",
    "causal",
    "prevalence",
    "observation",
    "inference",
    "recommendation",
    "effect-size",
    "adverse-event",
    "interaction",
    "dosing",
    "regulatory",
    "guideline",
    "mechanistic",
];
const STATUSES: [&str; 4] = ["supported", "contested", "unresolved", "superseded"];
const PRIMARY_REQUIRED: [&str; 7] = [
    "price",
    "feature",
    "legal",
    "case-law",
    "benchmark",
    "regulatory",
    "guideline",
];
const MULTI_SOURCE_HIGH: [&str; 7] = [
    "benchmark",
    "comparative",
    "causal",
    "prevalence",
    "effect-size",
    "adverse-event",
    "dosing",
];
const LEAD_ONLY_SOURCE_TYPES: [&str; 6] = [
    "search-hit",
    "search-snippet",
    "snippet",
    "ai-summary",
    "provider-answer",
    "notebooklm-answer",
];
const PASSAGE_FIELDS: [&str; 4] = [
    "quote_or_paraphrase",
    "evidence_text",
    "body_plain",
    "located_text",
];

/// Output of `check`, mirroring the Python result dict.
#[derive(Clone, Debug)]
pub struct Checked {
    pub overall_ok: bool,
    pub evidence: Vec<Value>,
    pub claims: Vec<Value>,
    pub clusters: Vec<Value>,
    pub evidence_verdicts: Vec<Value>,
    pub verdicts: Vec<Value>,
    pub views: Value,
}

impl Checked {
    pub fn to_json(&self) -> Value {
        json!({
            "overall_ok": self.overall_ok,
            "evidence": self.evidence,
            "claims": self.claims,
            "clusters": self.clusters,
            "evidence_verdicts": self.evidence_verdicts,
            "verdicts": self.verdicts,
            "views": self.views,
        })
    }
}

/// Confidence rank; unknown values rank as 1, as `CONFIDENCE_RANK.get(x, 1)`.
fn rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn is_confidence(value: &str) -> bool {
    matches!(value, "low" | "medium" | "high")
}

fn normalize_confidence(value: &str) -> String {
    if is_confidence(value) {
        value.to_string()
    } else {
        "low".to_string()
    }
}

fn is_load_bearing(claim_type: &str) -> bool {
    CLAIM_TYPES.contains(&claim_type) && claim_type != "inference" && claim_type != "recommendation"
}

/// `parse_jsonl`: non-blank lines, each a JSON object.
pub fn parse_jsonl(label: &str, text: &str) -> Result<Vec<Value>, String> {
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("{label}:{}: invalid JSON: {error}", index + 1))?;
        if !value.is_object() {
            return Err(format!("{label}:{}: row must be an object", index + 1));
        }
        rows.push(value);
    }
    Ok(rows)
}

/// `_date`: a strict `YYYY-MM-DD` calendar date. Python's `fromisoformat`
/// also accepts compact `YYYYMMDD` and week forms; those are rejected here.
pub fn is_iso_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let all_digits = |range: &[u8]| range.iter().all(|byte| byte.is_ascii_digit());
    if !all_digits(&bytes[0..4]) || !all_digits(&bytes[5..7]) || !all_digits(&bytes[8..10]) {
        return false;
    }
    let year: u32 = match text[0..4].parse() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let month: u32 = match text[5..7].parse() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let day: u32 = match text[8..10].parse() {
        Ok(value) => value,
        Err(_) => return false,
    };
    if year == 0 || !(1..=12).contains(&month) {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if leap {
                29
            } else {
                28
            }
        }
    };
    (1..=max_day).contains(&day)
}

/// `validate_evidence`: one verdict object per row (`ok` or `block`).
pub fn validate_evidence(evidence: &[Value]) -> Vec<Value> {
    let mut verdicts = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for row in evidence {
        let eid = py_str_or(row.get("id"), "");
        let mut errors: Vec<String> = Vec::new();
        if eid.is_empty() || seen.contains(&eid) {
            errors.push("missing or duplicate id".to_string());
        }
        seen.insert(eid.clone());

        for key in [
            "url",
            "publisher",
            "retrieved_at",
            "locator",
            "suggested_by",
            "seed_chain",
        ] {
            if is_null_or_empty(row.get(key)) {
                errors.push(format!("missing {key}"));
            }
        }
        if truthy(row.get("retrieved_at")) && !is_iso_date(&py_str(row.get("retrieved_at"))) {
            errors.push("retrieved_at is not ISO date".to_string());
        }

        let policy = row.get("instructionPolicy");
        if is_none_or_empty_str(policy) {
            errors.push("missing instructionPolicy".to_string());
        } else if policy.and_then(Value::as_str) != Some("data_only") {
            errors.push("instructionPolicy must be data_only".to_string());
        }

        let has_passage = PASSAGE_FIELDS
            .iter()
            .any(|key| !py_str_or(row.get(*key), "").trim().is_empty());
        if !has_passage {
            errors.push("missing opened passage text".to_string());
        }
        if truthy(row.get("body_is_not_from_source")) && !truthy(row.get("body_substitution")) {
            errors.push("body substitution disclosure missing".to_string());
        }

        let evidence_status = py_str_or(row.get("evidence_status"), "evidence").to_lowercase();
        let source_type = py_str_or(row.get("source_type"), "").to_lowercase();
        let provider = py_str_or(row.get("provider"), "").to_lowercase();
        if evidence_status == "lead" {
            errors.push("lead-only record cannot enter the evidence ledger".to_string());
        }
        if LEAD_ONLY_SOURCE_TYPES.contains(&source_type.as_str()) {
            errors.push(format!(
                "lead-only source_type cannot enter the evidence ledger: {source_type}"
            ));
        }
        if provider == "notebooklm" {
            errors.push(
                "NotebookLM answers are leads; record the separately opened underlying source instead"
                    .to_string(),
            );
        }

        let verdict = if errors.is_empty() { "ok" } else { "block" };
        verdicts.push(json!({"id": eid, "verdict": verdict, "reasons": errors}));
    }
    verdicts
}

/// `_is_primary_for`: whether an opened source is primary for a claim type.
fn is_primary_for(claim_type: &str, evidence: &Value) -> bool {
    if !truthy(evidence.get("url"))
        || !truthy(evidence.get("retrieved_at"))
        || !truthy(evidence.get("locator"))
    {
        return false;
    }
    if evidence.get("is_primary") == Some(&Value::Bool(true)) {
        return true;
    }
    let role_text = py_str_or(evidence.get("authority_role"), "").to_lowercase();
    let role = role_text.as_str();
    match claim_type {
        "price" | "feature" => matches!(role, "vendor-official" | "publisher-of-record"),
        "legal" | "regulatory" | "guideline" => {
            matches!(
                role,
                "statute" | "regulator" | "official-guideline" | "official"
            )
        }
        "case-law" => matches!(role, "court" | "official-judgment"),
        "benchmark" => matches!(role, "measurement" | "benchmark-owner" | "study"),
        _ => matches!(role, "study" | "regulator" | "official" | "measurement"),
    }
}

/// `_independent_clusters`: distinct `independence_cluster` values (or the id
/// itself when unclustered) across the given evidence ids.
fn independent_clusters(ids: &[String], ev_by_id: &BTreeMap<String, Value>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for sid in ids {
        if let Some(evidence) = ev_by_id.get(sid) {
            out.insert(py_str_or(evidence.get("independence_cluster"), sid));
        }
    }
    out
}

/// `_supporting_confidence`: the confidence each source id contributes to a
/// recommendation's support ceiling. Claims are read at their current state.
fn supporting_confidence(
    source_ids: &[String],
    claim_index: &BTreeMap<String, usize>,
    claims: &[Value],
    ev_by_id: &BTreeMap<String, Value>,
) -> Vec<String> {
    let mut out = Vec::new();
    for sid in source_ids {
        let value: String = if let Some(&index) = claim_index.get(sid) {
            match claims[index].get("confidence") {
                None => "low".to_string(),
                Some(found) => py_str(Some(found)),
            }
        } else if let Some(evidence) = ev_by_id.get(sid) {
            let grade: &str = if truthy(evidence.get("url")) && truthy(evidence.get("locator")) {
                "high"
            } else {
                "low"
            };
            grade.to_string()
        } else {
            "low".to_string()
        };
        out.push(normalize_confidence(&value));
    }
    out
}

fn downgrade(claim_id: &str, reason: &str, from: &str, to: &str) -> Value {
    json!({"id": claim_id, "verdict": "downgrade", "reason": reason, "from": from, "to": to})
}

/// Reads `source_ids` as a list of strings. Missing means empty; a non-list is
/// reported by the caller as a blocking reason.
fn source_ids_of(claim: &Value) -> Result<Vec<String>, ()> {
    match claim.get("source_ids") {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.iter().map(|item| py_str(Some(item))).collect()),
        Some(_) => Err(()),
    }
}

/// `check`: validate evidence and claims, adjudicate confidence, and return the
/// checked evidence (with independence clusters) and claims.
pub fn check(evidence: &[Value], claims_in: &[Value]) -> Result<Checked, String> {
    let clustered = independence::cluster(evidence, NEAR_DUPLICATE_THRESHOLD)?;
    let evidence_rows = clustered.evidence;

    let mut ev_by_id: BTreeMap<String, Value> = BTreeMap::new();
    for row in &evidence_rows {
        ev_by_id.insert(py_str(row.get("id")), row.clone());
    }
    let mut claims: Vec<Value> = claims_in.to_vec();
    let mut claim_index: BTreeMap<String, usize> = BTreeMap::new();
    for (index, claim) in claims.iter().enumerate() {
        claim_index.insert(py_str(claim.get("id")), index);
    }

    let evidence_verdicts = validate_evidence(&evidence_rows);
    let mut overall_ok = !evidence_verdicts
        .iter()
        .any(|verdict| verdict["verdict"] == "block");
    let mut verdicts: Vec<Value> = Vec::new();

    for index in 0..claims.len() {
        let claim = claims[index].clone();
        let cid = py_str_or(claim.get("id"), "");
        let ctype = py_str_or(claim.get("claim_type"), "");
        let mut reasons: Vec<String> = Vec::new();

        if cid.is_empty() {
            reasons.push("missing id".to_string());
        }
        if !CLAIM_TYPES.contains(&ctype.as_str()) {
            reasons.push(format!("unknown claim_type: {}", py_repr_str(&ctype)));
        }
        if py_str_or(claim.get("text"), "").trim().is_empty() {
            reasons.push("missing text".to_string());
        }

        let mut confidence = py_str_or(claim.get("confidence"), "low");
        if !is_confidence(&confidence) {
            reasons.push("invalid confidence".to_string());
            confidence = "low".to_string();
        }
        let status = py_str_or(claim.get("status"), "supported");
        if !STATUSES.contains(&status.as_str()) {
            reasons.push("invalid status".to_string());
        }

        let as_of_value: Option<&Value> = if truthy(claim.get("as_of")) {
            claim.get("as_of")
        } else if truthy(claim.get("as_of_date")) {
            claim.get("as_of_date")
        } else {
            None
        };
        let as_of_text = as_of_value
            .map(|value| py_str(Some(value)))
            .unwrap_or_default();
        if as_of_text.is_empty() || !is_iso_date(&as_of_text) {
            reasons.push("missing or invalid as_of date".to_string());
        }

        let source_ids = match source_ids_of(&claim) {
            Ok(ids) => ids,
            Err(()) => {
                reasons.push("source_ids must be a list".to_string());
                Vec::new()
            }
        };

        let missing_sources: Vec<String> = source_ids
            .iter()
            .filter(|sid| !ev_by_id.contains_key(*sid) && !claim_index.contains_key(*sid))
            .cloned()
            .collect();
        if !missing_sources.is_empty() {
            reasons.push(format!(
                "unknown source ids: {}",
                py_list_repr(&missing_sources)
            ));
        }
        if is_load_bearing(&ctype) && source_ids.is_empty() {
            reasons.push("load-bearing claim has no source_ids".to_string());
        }

        let evidence_sources: Vec<Value> = source_ids
            .iter()
            .filter_map(|sid| ev_by_id.get(sid).cloned())
            .collect();
        let primary_sources: Vec<Value> = evidence_sources
            .iter()
            .filter(|evidence| is_primary_for(&ctype, evidence))
            .cloned()
            .collect();
        if PRIMARY_REQUIRED.contains(&ctype.as_str()) && primary_sources.is_empty() {
            reasons.push("primary-source fetch missing".to_string());
        }

        let evidence_ids: Vec<String> = evidence_sources
            .iter()
            .map(|evidence| py_str(evidence.get("id")))
            .collect();
        let clusters = independent_clusters(&evidence_ids, &ev_by_id);

        let declared = confidence.clone();
        if MULTI_SOURCE_HIGH.contains(&ctype.as_str()) && confidence == "high" && clusters.len() < 2
        {
            confidence = "medium".to_string();
            verdicts.push(downgrade(
                &cid,
                &format!(
                    "{ctype} high confidence requires 2+ independent sources, got {}",
                    clusters.len()
                ),
                &declared,
                &confidence,
            ));
        }
        if ctype == "mechanistic" && rank(&confidence) > rank("medium") {
            confidence = "medium".to_string();
            verdicts.push(downgrade(
                &cid,
                "mechanistic claims cap at medium",
                &declared,
                &confidence,
            ));
        }
        if (ctype == "legal" || ctype == "case-law") && confidence == "high" {
            if primary_sources.is_empty() {
                confidence = "medium".to_string();
            } else if ctype == "case-law"
                && primary_sources.iter().any(|evidence| {
                    !truthy(evidence.get("current_as_of"))
                        || matches!(
                            evidence.get("negative_treatment").and_then(Value::as_str),
                            Some("overruled") | Some("doubted")
                        )
                })
            {
                confidence = "medium".to_string();
                verdicts.push(downgrade(
                    &cid,
                    "case-law currentness/negative-treatment verification incomplete",
                    &declared,
                    &confidence,
                ));
            }
        }
        if (ctype == "effect-size" || ctype == "adverse-event" || ctype == "dosing")
            && confidence == "high"
        {
            let primary_ids: Vec<String> = primary_sources
                .iter()
                .map(|evidence| py_str(evidence.get("id")))
                .collect();
            if independent_clusters(&primary_ids, &ev_by_id).len() < 2 {
                confidence = "medium".to_string();
                verdicts.push(downgrade(
                    &cid,
                    "medical high confidence requires 2+ independent primary studies",
                    &declared,
                    &confidence,
                ));
            }
        }

        if ctype == "recommendation" {
            if source_ids.is_empty() {
                reasons.push("recommendation with no source_ids".to_string());
            } else {
                let supporting =
                    supporting_confidence(&source_ids, &claim_index, &claims, &ev_by_id);
                let ceiling = supporting
                    .iter()
                    .min_by_key(|value| rank(value.as_str()))
                    .cloned()
                    .unwrap_or_else(|| "low".to_string());
                if rank(&confidence) > rank(&ceiling) {
                    verdicts.push(downgrade(
                        &cid,
                        &format!("recommendation confidence exceeds support ceiling {ceiling}"),
                        &confidence,
                        &ceiling,
                    ));
                    confidence = ceiling.clone();
                }
            }
        }

        let mut updated = claim.clone();
        if let Value::Object(map) = &mut updated {
            map.insert("confidence".to_string(), Value::String(confidence.clone()));
            map.insert("status".to_string(), Value::String(status.clone()));
            map.insert("as_of".to_string(), Value::String(as_of_text.clone()));
        }
        claims[index] = updated;

        if reasons.is_empty() {
            verdicts.push(json!({
                "id": cid,
                "verdict": "ok",
                "confidence": confidence,
                "independent_clusters": clusters.len(),
            }));
        } else {
            verdicts.push(json!({"id": cid, "verdict": "block", "reasons": reasons}));
            overall_ok = false;
        }
    }

    let views = contradictions::derive(&claims, &evidence_rows);
    Ok(Checked {
        overall_ok,
        evidence: evidence_rows,
        claims,
        clusters: clustered.clusters,
        evidence_verdicts,
        verdicts,
        views,
    })
}

fn reason_strings(verdict: &Value) -> Vec<String> {
    verdict["reasons"]
        .as_array()
        .map(|items| items.iter().map(|item| py_str(Some(item))).collect())
        .unwrap_or_default()
}

/// `render`: the Markdown brief. Refuses when the ledger has blocking violations.
pub fn render(
    evidence: &[Value],
    claims: &[Value],
    title: &str,
    as_of: &str,
) -> Result<String, String> {
    let checked = check(evidence, claims)?;
    if !checked.overall_ok {
        return Err("ledger contains blocking violations".to_string());
    }
    let known_ids: BTreeSet<String> = checked
        .evidence
        .iter()
        .map(|row| py_str(row.get("id")))
        .collect();

    let mut lines: Vec<String> = vec![
        format!("# {title}"),
        String::new(),
        format!("_as of {as_of}_"),
        String::new(),
        "## Findings".to_string(),
        String::new(),
    ];
    for claim in &checked.claims {
        let ctype = py_str(claim.get("claim_type"));
        let prefix = match ctype.as_str() {
            "observation" => "[OBS]".to_string(),
            "inference" => "[INF]".to_string(),
            "recommendation" => "[REC]".to_string(),
            other => format!("[{}]", other.to_uppercase()),
        };
        let cited: Vec<String> = source_ids_of(claim)
            .unwrap_or_default()
            .into_iter()
            .filter(|sid| known_ids.contains(sid))
            .collect();
        let cites: String = cited.iter().map(|sid| format!("[+{sid}]")).collect();
        lines.push(format!(
            "- {prefix} {} {cites} [confidence: {}] [status: {}]",
            py_str(claim.get("text")),
            py_str(claim.get("confidence")),
            py_str(claim.get("status")),
        ));
    }
    lines.push(String::new());
    lines.push("## Sources".to_string());
    lines.push(String::new());
    for evidence in &checked.evidence {
        let disclosure = if truthy(evidence.get("body_is_not_from_source")) {
            let substitution = match evidence.get("body_substitution") {
                Some(value) => py_str(Some(value)),
                None => "disclosed replacement".to_string(),
            };
            format!(" — substituted body: {substitution}")
        } else {
            String::new()
        };
        let display = if truthy(evidence.get("title")) {
            py_str(evidence.get("title"))
        } else {
            py_str(evidence.get("url"))
        };
        let url = match evidence.get("url") {
            Some(value) => py_str(Some(value)),
            None => "local".to_string(),
        };
        lines.push(format!(
            "- [{}] {display} — {} — {url} — retrieved {}{disclosure}",
            py_str(evidence.get("id")),
            py_str(evidence.get("publisher")),
            py_str(evidence.get("retrieved_at")),
        ));
        lines.push(format!(
            "  - locator: {}; suggested_by: {}; cluster: {}",
            py_str(evidence.get("locator")),
            py_str(evidence.get("suggested_by")),
            py_str(evidence.get("independence_cluster")),
        ));
    }
    Ok(lines.join("\n") + "\n")
}

/// `run.record_evidence` admission: duplicate-id refusal, then row validation.
/// The caller appends the row with `common::append_jsonl` on success.
pub fn admit_evidence(existing: &[Value], row: &Value) -> Result<(), String> {
    let id = py_str(row.get("id"));
    if existing.iter().any(|item| py_str(item.get("id")) == id) {
        return Err(format!("duplicate evidence id: {}", py_repr_str(&id)));
    }
    let verdicts = validate_evidence(std::slice::from_ref(row));
    let verdict = &verdicts[0];
    if verdict["verdict"] != "ok" {
        return Err(format!(
            "evidence record blocked: {}",
            py_list_repr(&reason_strings(verdict))
        ));
    }
    Ok(())
}

/// `run.record_claim` admission: returns the normalised claim row to append.
pub fn admit_claim(evidence: &[Value], existing: &[Value], row: &Value) -> Result<Value, String> {
    let id = py_str(row.get("id"));
    if existing.iter().any(|item| py_str(item.get("id")) == id) {
        return Err(format!("duplicate claim id: {}", py_repr_str(&id)));
    }
    let mut all: Vec<Value> = existing.to_vec();
    all.push(row.clone());
    let checked = check(evidence, &all)?;
    let blocks: Vec<Value> = checked
        .verdicts
        .iter()
        .filter(|verdict| verdict["id"] == id.as_str() && verdict["verdict"] == "block")
        .cloned()
        .collect();
    if !blocks.is_empty() {
        return Err(format!(
            "claim record blocked: {}",
            serde_json::to_string(&blocks).unwrap_or_default()
        ));
    }
    checked
        .claims
        .iter()
        .find(|claim| py_str(claim.get("id")) == id)
        .cloned()
        .ok_or_else(|| "normalised claim missing from check result".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_evidence(id: &str, url: &str, cluster_body: &str) -> Value {
        json!({
            "id": id,
            "url": url,
            "publisher": "Publisher",
            "retrieved_at": "2026-08-01",
            "locator": "section 2",
            "suggested_by": "search",
            "seed_chain": ["seed"],
            "instructionPolicy": "data_only",
            "body_plain": cluster_body,
            "source_type": "web",
        })
    }

    fn claim(id: &str, claim_type: &str, confidence: &str, source_ids: &[&str]) -> Value {
        json!({
            "id": id,
            "claim_type": claim_type,
            "text": "a sourced statement",
            "confidence": confidence,
            "as_of": "2026-08-01",
            "source_ids": source_ids,
        })
    }

    #[test]
    fn parse_jsonl_skips_blank_lines_and_rejects_non_objects() {
        let rows = parse_jsonl("ev.jsonl", "{\"id\":\"a\"}\n\n{\"id\":\"b\"}\n").unwrap();
        assert_eq!(rows.len(), 2);
        assert!(parse_jsonl("ev.jsonl", "[1]\n").is_err());
    }

    #[test]
    fn iso_date_is_strict_and_calendar_aware() {
        assert!(is_iso_date("2026-08-01"));
        assert!(is_iso_date("2024-02-29"));
        assert!(!is_iso_date("2025-02-29"));
        assert!(!is_iso_date("2026-13-01"));
        assert!(!is_iso_date("20260801"));
    }

    #[test]
    fn validate_evidence_blocks_leads_and_missing_fields() {
        let ok = good_evidence("e1", "https://a.test/1", "alpha body");
        let mut lead = good_evidence("e2", "https://a.test/2", "beta body");
        lead["source_type"] = json!("search-hit");
        let verdicts = validate_evidence(&[ok, lead]);
        assert_eq!(verdicts[0]["verdict"], "ok");
        assert_eq!(verdicts[1]["verdict"], "block");
        assert_eq!(
            verdicts[1]["reasons"],
            json!(["lead-only source_type cannot enter the evidence ledger: search-hit"])
        );
    }

    #[test]
    fn ledger_check_serializes_derived_contradiction_and_consensus_views() {
        let checked = check(&[], &[]).unwrap();
        assert_eq!(
            checked.to_json()["views"],
            json!({"contradictions": [], "consensus": []})
        );
    }

    #[test]
    fn high_benchmark_with_one_cluster_is_downgraded() {
        let mut primary = good_evidence("e1", "https://a.test/1", "alpha body");
        primary["is_primary"] = json!(true);
        let evidence = vec![primary];
        let claims = vec![claim("c1", "benchmark", "high", &["e1"])];
        let checked = check(&evidence, &claims).unwrap();
        assert!(checked.overall_ok);
        assert_eq!(checked.claims[0]["confidence"], "medium");
        assert_eq!(checked.verdicts[0]["verdict"], "downgrade");
        assert_eq!(checked.verdicts[0]["from"], "high");
        assert_eq!(checked.verdicts[0]["to"], "medium");
    }

    #[test]
    fn load_bearing_claim_without_sources_blocks_and_render_refuses() {
        let evidence = vec![good_evidence("e1", "https://a.test/1", "alpha body")];
        let claims = vec![claim("c1", "inference", "low", &[])];
        let checked = check(&evidence, &claims).unwrap();
        assert!(checked.overall_ok, "an inference is not load-bearing");

        let blocked = vec![claim("c2", "price", "low", &[])];
        let checked = check(&evidence, &blocked).unwrap();
        assert!(!checked.overall_ok);
        assert!(render(&evidence, &blocked, "Brief", "2026-08-02").is_err());
    }

    #[test]
    fn render_writes_sections_and_citations() {
        let evidence = vec![good_evidence("e1", "https://a.test/1", "alpha body")];
        let claims = vec![claim("c1", "observation", "low", &["e1"])];
        let text = render(&evidence, &claims, "Brief", "2026-08-02").unwrap();
        assert!(text.starts_with("# Brief\n\n_as of 2026-08-02_\n\n## Findings\n\n"));
        assert!(text
            .contains("- [OBS] a sourced statement [+e1] [confidence: low] [status: supported]\n"));
        assert!(text.contains(
            "- [e1] https://a.test/1 — Publisher — https://a.test/1 — retrieved 2026-08-01\n"
        ));
        assert!(text.ends_with("\n"));
    }

    #[test]
    fn admit_evidence_refuses_duplicates_and_blocked_rows() {
        let existing = vec![good_evidence("e1", "https://a.test/1", "alpha body")];
        let duplicate = good_evidence("e1", "https://a.test/9", "other body");
        assert!(admit_evidence(&existing, &duplicate).is_err());
        let fresh = good_evidence("e2", "https://a.test/2", "other body");
        assert!(admit_evidence(&existing, &fresh).is_ok());
    }

    #[test]
    fn admit_claim_returns_normalised_row() {
        let mut primary = good_evidence("e1", "https://a.test/1", "alpha body");
        primary["is_primary"] = json!(true);
        let evidence = vec![primary];
        let row = claim("c1", "benchmark", "high", &["e1"]);
        let normalised = admit_claim(&evidence, &[], &row).unwrap();
        assert_eq!(normalised["confidence"], "medium");
    }
}
