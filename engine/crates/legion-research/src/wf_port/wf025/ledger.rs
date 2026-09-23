//! Faithful Rust port of `src/lib/research-core/ledger.py`: evidence/claim
//! ledger validation, confidence adjudication, and Markdown rendering.
//! Operates on loose JSON objects (the script's schema), matching wf025's
//! sibling modules; only the pure `validate_evidence` / `check` / `render`
//! functions are ported (the CLI's file/argparse plumbing is not — this is
//! a library crate).

use std::collections::HashSet;

use serde_json::{Map, Value};

use super::independence::cluster as cluster_independence;
use super::iso_date::is_valid_iso_date;

const CONFIDENCE_LOW: i32 = 1;
const CONFIDENCE_MEDIUM: i32 = 2;
const CONFIDENCE_HIGH: i32 = 3;

fn confidence_rank(s: &str) -> i32 {
    match s {
        "low" => CONFIDENCE_LOW,
        "medium" => CONFIDENCE_MEDIUM,
        "high" => CONFIDENCE_HIGH,
        _ => CONFIDENCE_LOW,
    }
}

fn is_known_confidence(s: &str) -> bool {
    matches!(s, "low" | "medium" | "high")
}

const STATUSES: &[&str] = &["supported", "contested", "unresolved", "superseded"];
const CLAIM_TYPES: &[&str] = &[
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
const PRIMARY_REQUIRED: &[&str] = &[
    "price",
    "feature",
    "legal",
    "case-law",
    "benchmark",
    "regulatory",
    "guideline",
];
const MULTI_SOURCE_HIGH: &[&str] = &[
    "benchmark",
    "comparative",
    "causal",
    "prevalence",
    "effect-size",
    "adverse-event",
    "dosing",
];
const LEAD_ONLY_SOURCE_TYPES: &[&str] = &[
    "search-hit",
    "search-snippet",
    "snippet",
    "ai-summary",
    "provider-answer",
    "notebooklm-answer",
];
const PASSAGE_FIELDS: &[&str] = &[
    "quote_or_paraphrase",
    "evidence_text",
    "body_plain",
    "located_text",
];

fn is_load_bearing(claim_type: &str) -> bool {
    CLAIM_TYPES.contains(&claim_type) && claim_type != "inference" && claim_type != "recommendation"
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn is_empty_value(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        _ => false,
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
    }
}

pub struct EvidenceVerdict {
    pub id: String,
    pub blocked: bool,
    pub reasons: Vec<String>,
}

/// Ports `ledger.py`'s `validate_evidence()`.
pub fn validate_evidence(evidence: &[Value]) -> Vec<EvidenceVerdict> {
    let mut verdicts = Vec::with_capacity(evidence.len());
    let mut seen: HashSet<String> = HashSet::new();
    for row in evidence {
        let eid = str_field(row, "id");
        let mut errors = Vec::new();
        if eid.is_empty() || seen.contains(&eid) {
            errors.push("missing or duplicate id".to_string());
        }
        seen.insert(eid.clone());
        for key in ["url", "publisher", "retrieved_at", "locator", "suggested_by", "seed_chain"] {
            if is_empty_value(row.get(key)) {
                errors.push(format!("missing {key}"));
            }
        }
        let retrieved_at = str_field(row, "retrieved_at");
        if !retrieved_at.is_empty() && !is_valid_iso_date(&retrieved_at) {
            errors.push("retrieved_at is not ISO date".to_string());
        }

        let policy = row.get("instructionPolicy");
        if is_empty_value(policy) {
            errors.push("missing instructionPolicy".to_string());
        } else if policy.and_then(Value::as_str) != Some("data_only") {
            errors.push("instructionPolicy must be data_only".to_string());
        }
        let has_passage = PASSAGE_FIELDS
            .iter()
            .any(|key| !str_field(row, key).trim().is_empty());
        if !has_passage {
            errors.push("missing opened passage text".to_string());
        }
        if truthy(row.get("body_is_not_from_source")) && !truthy(row.get("body_substitution")) {
            errors.push("body substitution disclosure missing".to_string());
        }

        let evidence_status = str_field(row, "evidence_status").to_lowercase();
        let evidence_status = if evidence_status.is_empty() {
            "evidence".to_string()
        } else {
            evidence_status
        };
        let source_type = str_field(row, "source_type").to_lowercase();
        let provider = str_field(row, "provider").to_lowercase();
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

        let blocked = !errors.is_empty();
        verdicts.push(EvidenceVerdict {
            id: eid,
            blocked,
            reasons: errors,
        });
    }
    verdicts
}

fn independent_clusters(source_ids: &[String], by_id: &std::collections::HashMap<String, &Value>) -> HashSet<String> {
    source_ids
        .iter()
        .filter_map(|sid| by_id.get(sid))
        .map(|ev| {
            let ic = str_field(ev, "independence_cluster");
            if ic.is_empty() {
                str_field(ev, "id")
            } else {
                ic
            }
        })
        .collect()
}

fn is_primary_for(claim_type: &str, ev: &Value) -> bool {
    if is_empty_value(ev.get("url")) || is_empty_value(ev.get("retrieved_at")) || is_empty_value(ev.get("locator")) {
        return false;
    }
    if ev.get("is_primary") == Some(&Value::Bool(true)) {
        return true;
    }
    let role = str_field(ev, "authority_role").to_lowercase();
    match claim_type {
        "price" | "feature" => role == "vendor-official" || role == "publisher-of-record",
        "legal" | "regulatory" | "guideline" => {
            role == "statute" || role == "regulator" || role == "official-guideline" || role == "official"
        }
        "case-law" => role == "court" || role == "official-judgment",
        "benchmark" => role == "measurement" || role == "benchmark-owner" || role == "study",
        _ => role == "study" || role == "regulator" || role == "official" || role == "measurement",
    }
}

fn supporting_confidence(
    source_ids: &[String],
    claim_by_id: &std::collections::HashMap<String, &Value>,
    ev_by_id: &std::collections::HashMap<String, &Value>,
) -> Vec<String> {
    source_ids
        .iter()
        .map(|sid| {
            if let Some(c) = claim_by_id.get(sid) {
                let conf = str_field(c, "confidence");
                if conf.is_empty() {
                    "low".to_string()
                } else {
                    conf
                }
            } else if let Some(ev) = ev_by_id.get(sid) {
                if truthy(ev.get("url")) && truthy(ev.get("locator")) {
                    "high".to_string()
                } else {
                    "low".to_string()
                }
            } else {
                "low".to_string()
            }
        })
        .collect()
}

pub struct ClaimVerdict {
    pub id: String,
    pub kind: &'static str, // "ok" | "block" | "downgrade"
    pub reasons: Vec<String>,
    pub reason: Option<String>,
    pub confidence: Option<String>,
    pub independent_clusters: Option<usize>,
    pub from: Option<String>,
    pub to: Option<String>,
}

pub struct LedgerCheck {
    pub overall_ok: bool,
    pub evidence: Vec<Value>,
    pub claims: Vec<Value>,
    pub clusters: Vec<super::independence::ClusterRow>,
    pub evidence_verdicts: Vec<EvidenceVerdict>,
    pub verdicts: Vec<ClaimVerdict>,
}

/// Ports `ledger.py`'s `check()`. `claims` are mutated copies (confidence,
/// status, and as_of normalized), matching the Python script's in-place
/// mutation semantics but applied to owned clones here.
pub fn check(evidence: &[Value], claims: &[Value]) -> LedgerCheck {
    let clustered = cluster_independence(evidence);
    let evidence = clustered.evidence;
    let ev_by_id: std::collections::HashMap<String, &Value> =
        evidence.iter().map(|e| (str_field(e, "id"), e)).collect();
    let claim_by_id: std::collections::HashMap<String, &Value> =
        claims.iter().map(|c| (str_field(c, "id"), c)).collect();
    let evidence_verdicts = validate_evidence(&evidence);
    let mut overall_ok = !evidence_verdicts.iter().any(|v| v.blocked);

    let mut verdicts: Vec<ClaimVerdict> = Vec::new();
    let mut out_claims: Vec<Value> = Vec::with_capacity(claims.len());

    for claim in claims {
        let cid = str_field(claim, "id");
        let ctype = str_field(claim, "claim_type");
        let mut reasons: Vec<String> = Vec::new();
        if cid.is_empty() {
            reasons.push("missing id".to_string());
        }
        if !CLAIM_TYPES.contains(&ctype.as_str()) {
            reasons.push(format!("unknown claim_type: {ctype:?}"));
        }
        if str_field(claim, "text").trim().is_empty() {
            reasons.push("missing text".to_string());
        }
        let mut confidence = {
            let c = str_field(claim, "confidence");
            if c.is_empty() {
                "low".to_string()
            } else {
                c
            }
        };
        if !is_known_confidence(&confidence) {
            reasons.push("invalid confidence".to_string());
            confidence = "low".to_string();
        }
        let status = {
            let s = str_field(claim, "status");
            if s.is_empty() {
                "supported".to_string()
            } else {
                s
            }
        };
        if !STATUSES.contains(&status.as_str()) {
            reasons.push("invalid status".to_string());
        }
        let as_of = {
            let a = str_field(claim, "as_of");
            if !a.is_empty() {
                a
            } else {
                str_field(claim, "as_of_date")
            }
        };
        if as_of.is_empty() || !is_valid_iso_date(&as_of) {
            reasons.push("missing or invalid as_of date".to_string());
        }
        let source_ids = claim
            .get("source_ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect::<Vec<_>>())
            .unwrap_or_default();
        let missing_sources: Vec<String> = source_ids
            .iter()
            .filter(|sid| !ev_by_id.contains_key(*sid) && !claim_by_id.contains_key(*sid))
            .cloned()
            .collect();
        if !missing_sources.is_empty() {
            reasons.push(format!("unknown source ids: {missing_sources:?}"));
        }
        if is_load_bearing(&ctype) && source_ids.is_empty() {
            reasons.push("load-bearing claim has no source_ids".to_string());
        }

        let evidence_sources: Vec<&Value> = source_ids
            .iter()
            .filter_map(|sid| ev_by_id.get(sid).copied())
            .collect();
        let primary_sources: Vec<&Value> = evidence_sources
            .iter()
            .filter(|ev| is_primary_for(&ctype, ev))
            .copied()
            .collect();
        if PRIMARY_REQUIRED.contains(&ctype.as_str()) && primary_sources.is_empty() {
            reasons.push("primary-source fetch missing".to_string());
        }

        let evidence_source_ids: Vec<String> = evidence_sources.iter().map(|ev| str_field(ev, "id")).collect();
        let clusters = independent_clusters(&evidence_source_ids, &ev_by_id);
        let declared = confidence.clone();

        if MULTI_SOURCE_HIGH.contains(&ctype.as_str()) && confidence == "high" && clusters.len() < 2 {
            confidence = "medium".to_string();
            verdicts.push(ClaimVerdict {
                id: cid.clone(),
                kind: "downgrade",
                reasons: Vec::new(),
                reason: Some(format!(
                    "{ctype} high confidence requires 2+ independent sources, got {}",
                    clusters.len()
                )),
                confidence: None,
                independent_clusters: None,
                from: Some(declared.clone()),
                to: Some(confidence.clone()),
            });
        }
        if ctype == "mechanistic" && confidence_rank(&confidence) > CONFIDENCE_MEDIUM {
            confidence = "medium".to_string();
            verdicts.push(ClaimVerdict {
                id: cid.clone(),
                kind: "downgrade",
                reasons: Vec::new(),
                reason: Some("mechanistic claims cap at medium".to_string()),
                confidence: None,
                independent_clusters: None,
                from: Some(declared.clone()),
                to: Some(confidence.clone()),
            });
        }
        if (ctype == "legal" || ctype == "case-law") && confidence == "high" {
            if primary_sources.is_empty() {
                confidence = "medium".to_string();
            } else if ctype == "case-law"
                && primary_sources.iter().any(|ev| {
                    !truthy(ev.get("current_as_of"))
                        || matches!(
                            ev.get("negative_treatment").and_then(Value::as_str),
                            Some("overruled") | Some("doubted")
                        )
                })
            {
                confidence = "medium".to_string();
                verdicts.push(ClaimVerdict {
                    id: cid.clone(),
                    kind: "downgrade",
                    reasons: Vec::new(),
                    reason: Some(
                        "case-law currentness/negative-treatment verification incomplete".to_string(),
                    ),
                    confidence: None,
                    independent_clusters: None,
                    from: Some(declared.clone()),
                    to: Some(confidence.clone()),
                });
            }
        }
        if (ctype == "effect-size" || ctype == "adverse-event" || ctype == "dosing") && confidence == "high" {
            let primary_ids: Vec<String> = primary_sources.iter().map(|ev| str_field(ev, "id")).collect();
            let primary_clusters = independent_clusters(&primary_ids, &ev_by_id);
            if primary_clusters.len() < 2 {
                confidence = "medium".to_string();
                verdicts.push(ClaimVerdict {
                    id: cid.clone(),
                    kind: "downgrade",
                    reasons: Vec::new(),
                    reason: Some(
                        "medical high confidence requires 2+ independent primary studies".to_string(),
                    ),
                    confidence: None,
                    independent_clusters: None,
                    from: Some(declared.clone()),
                    to: Some(confidence.clone()),
                });
            }
        }

        if ctype == "recommendation" {
            if source_ids.is_empty() {
                reasons.push("recommendation with no source_ids".to_string());
            } else {
                let supporting = supporting_confidence(&source_ids, &claim_by_id, &ev_by_id);
                let ceiling = supporting
                    .iter()
                    .min_by_key(|c| confidence_rank(c))
                    .cloned()
                    .unwrap_or_else(|| "low".to_string());
                if confidence_rank(&confidence) > confidence_rank(&ceiling) {
                    verdicts.push(ClaimVerdict {
                        id: cid.clone(),
                        kind: "downgrade",
                        reasons: Vec::new(),
                        reason: Some(format!(
                            "recommendation confidence exceeds support ceiling {ceiling}"
                        )),
                        confidence: None,
                        independent_clusters: None,
                        from: Some(confidence.clone()),
                        to: Some(ceiling.clone()),
                    });
                    confidence = ceiling;
                }
            }
        }

        let mut updated_claim: Map<String, Value> = claim.as_object().cloned().unwrap_or_default();
        updated_claim.insert("confidence".to_string(), Value::String(confidence.clone()));
        updated_claim.insert("status".to_string(), Value::String(status.clone()));
        updated_claim.insert("as_of".to_string(), Value::String(as_of.clone()));
        out_claims.push(Value::Object(updated_claim));

        if !reasons.is_empty() {
            verdicts.push(ClaimVerdict {
                id: cid,
                kind: "block",
                reasons,
                reason: None,
                confidence: None,
                independent_clusters: None,
                from: None,
                to: None,
            });
            overall_ok = false;
        } else {
            verdicts.push(ClaimVerdict {
                id: cid,
                kind: "ok",
                reasons: Vec::new(),
                reason: None,
                confidence: Some(confidence),
                independent_clusters: Some(clusters.len()),
                from: None,
                to: None,
            });
        }
    }

    LedgerCheck {
        overall_ok,
        evidence,
        claims: out_claims,
        clusters: clustered.clusters,
        evidence_verdicts,
        verdicts,
    }
}

/// Ports `ledger.py`'s `render()`. Returns `Err` (mirroring the Python
/// `ValueError`) when the ledger has blocking violations.
pub fn render(evidence: &[Value], claims: &[Value], title: &str) -> Result<String, String> {
    let checked = check(evidence, claims);
    if !checked.overall_ok {
        return Err("ledger contains blocking violations".to_string());
    }
    let ev_by_id: std::collections::HashMap<String, &Value> =
        checked.evidence.iter().map(|e| (str_field(e, "id"), e)).collect();

    let today_str = super::iso_date::today_iso_date();

    let mut lines = vec![
        format!("# {title}"),
        String::new(),
        format!("_as of {today_str}_"),
        String::new(),
        "## Findings".to_string(),
        String::new(),
    ];
    for claim in &checked.claims {
        let claim_type = str_field(claim, "claim_type");
        let prefix = match claim_type.as_str() {
            "observation" => "[OBS]".to_string(),
            "inference" => "[INF]".to_string(),
            "recommendation" => "[REC]".to_string(),
            other => format!("[{}]", other.to_uppercase()),
        };
        let source_ids = claim
            .get("source_ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();
        let cited: Vec<&str> = source_ids
            .into_iter()
            .filter(|sid| ev_by_id.contains_key(*sid))
            .collect();
        let cites: String = cited.iter().map(|sid| format!("[+{sid}]")).collect();
        let text = str_field(claim, "text");
        let confidence = str_field(claim, "confidence");
        let status = str_field(claim, "status");
        lines.push(format!(
            "- {prefix} {text} {cites} [confidence: {confidence}] [status: {status}]"
        ));
    }
    lines.push(String::new());
    lines.push("## Sources".to_string());
    lines.push(String::new());
    for ev in &checked.evidence {
        let mut disclosure = String::new();
        if truthy(ev.get("body_is_not_from_source")) {
            let sub = {
                let s = str_field(ev, "body_substitution");
                if s.is_empty() {
                    "disclosed replacement".to_string()
                } else {
                    s
                }
            };
            disclosure = format!(" — substituted body: {sub}");
        }
        let title_or_url = {
            let t = str_field(ev, "title");
            if !t.is_empty() {
                t
            } else {
                str_field(ev, "url")
            }
        };
        let url = {
            let u = str_field(ev, "url");
            if u.is_empty() {
                "local".to_string()
            } else {
                u
            }
        };
        lines.push(format!(
            "- [{}] {} — {} — {} — retrieved {}{}",
            str_field(ev, "id"),
            title_or_url,
            str_field(ev, "publisher"),
            url,
            str_field(ev, "retrieved_at"),
            disclosure
        ));
        lines.push(format!(
            "  - locator: {}; suggested_by: {}; cluster: {}",
            str_field(ev, "locator"),
            str_field(ev, "suggested_by"),
            str_field(ev, "independence_cluster")
        ));
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok_evidence() -> Value {
        json!({
            "id": "e1", "url": "https://example.com/a", "publisher": "Example",
            "retrieved_at": "2024-01-01", "locator": "p1", "suggested_by": "user",
            "seed_chain": ["seed"], "instructionPolicy": "data_only",
            "quote_or_paraphrase": "text", "is_primary": true
        })
    }

    #[test]
    fn validate_evidence_flags_missing_fields() {
        let verdicts = validate_evidence(&[json!({"id": "e1"})]);
        assert!(verdicts[0].blocked);
        assert!(verdicts[0].reasons.contains(&"missing url".to_string()));
    }

    #[test]
    fn validate_evidence_accepts_well_formed_row() {
        let verdicts = validate_evidence(&[ok_evidence()]);
        assert!(!verdicts[0].blocked, "{:?}", verdicts[0].reasons);
    }

    #[test]
    fn validate_evidence_rejects_lead_only_source_type() {
        let mut row = ok_evidence();
        row["source_type"] = json!("search-snippet");
        let verdicts = validate_evidence(&[row]);
        assert!(verdicts[0].blocked);
    }

    #[test]
    fn check_downgrades_multi_source_high_without_two_clusters() {
        let evidence = vec![ok_evidence()];
        let claims = vec![json!({
            "id": "c1", "claim_type": "benchmark", "text": "x",
            "confidence": "high", "status": "supported", "as_of": "2024-01-01",
            "source_ids": ["e1"]
        })];
        let checked = check(&evidence, &claims);
        assert!(checked.overall_ok);
        assert_eq!(checked.claims[0]["confidence"], "medium");
        assert!(checked
            .verdicts
            .iter()
            .any(|v| v.kind == "downgrade"));
    }

    #[test]
    fn check_blocks_unknown_claim_type() {
        let claims = vec![json!({
            "id": "c1", "claim_type": "nonsense", "text": "x",
            "confidence": "low", "status": "supported", "as_of": "2024-01-01"
        })];
        let checked = check(&[], &claims);
        assert!(!checked.overall_ok);
    }

    #[test]
    fn render_fails_on_blocking_ledger() {
        let claims = vec![json!({"id": "c1", "claim_type": "nonsense", "text": "x"})];
        let result = render(&[], &claims, "Test");
        assert!(result.is_err());
    }

    #[test]
    fn render_succeeds_on_clean_ledger() {
        let evidence = vec![ok_evidence()];
        let claims = vec![json!({
            "id": "c1", "claim_type": "observation", "text": "hello",
            "confidence": "low", "status": "supported", "as_of": "2024-01-01",
            "source_ids": ["e1"]
        })];
        let out = render(&evidence, &claims, "Test brief").unwrap();
        assert!(out.contains("# Test brief"));
        assert!(out.contains("[OBS] hello"));
        assert!(out.contains("## Sources"));
    }
}
