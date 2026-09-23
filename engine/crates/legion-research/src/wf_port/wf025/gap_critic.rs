//! Faithful Rust port of `src/lib/research-core/gap_critic.py`: evidence-aware
//! overturn review plus targeted blocking-gap queries. Every claim records
//! what could overturn it; only an actual evidence deficiency blocks a
//! verified run — the mere possibility of future supersession is an
//! overturn condition, not a permanent gap.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use super::iso_date::iso_age_days;

const MULTI: &[&str] = &[
    "comparative",
    "causal",
    "prevalence",
    "benchmark",
    "effect-size",
    "adverse-event",
    "dosing",
];

pub struct GapFinding {
    pub claim_id: String,
    pub text: String,
    pub gaps: Vec<String>,
    pub what_would_overturn_it: Vec<String>,
    pub targeted_query: Option<String>,
    pub status: &'static str,
}

pub struct TargetedQuery {
    pub claim_id: String,
    pub query: String,
}

pub struct GapReview {
    pub findings: Vec<GapFinding>,
    pub blocking_findings: Vec<usize>, // indices into `findings`
    pub targeted_queries: Vec<TargetedQuery>,
    pub complete: bool,
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn str_ids(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
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

/// Ports `gap_critic.py`'s `review()`. `claims` and `evidence` are JSON
/// objects (the script's loose schema); `contradictions`, if present, is
/// the `{"contradictions": [{"claim_ids": [...]}, ...]}` shape.
pub fn review(claims: &[Value], evidence: &[Value], contradictions: Option<&Value>) -> GapReview {
    let by_id: HashMap<String, &Value> = evidence
        .iter()
        .map(|e| (str_field(e, "id"), e))
        .collect();

    let contested_ids: HashSet<String> = contradictions
        .and_then(|c| c.get("contradictions"))
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .flat_map(|row| str_ids(row, "claim_ids"))
                .collect()
        })
        .unwrap_or_default();

    let mut findings = Vec::with_capacity(claims.len());
    let mut targeted_queries = Vec::new();

    for claim in claims {
        let claim_id = str_field(claim, "id");
        let source_ids = str_ids(claim, "source_ids");
        let sources: Vec<&Value> = source_ids
            .iter()
            .filter_map(|sid| by_id.get(sid).copied())
            .collect();
        let clusters: HashSet<String> = sources
            .iter()
            .map(|s| {
                let ic = str_field(s, "independence_cluster");
                if ic.is_empty() {
                    str_field(s, "id")
                } else {
                    ic
                }
            })
            .collect();
        let primary: Vec<&Value> = sources
            .iter()
            .filter(|s| truthy(s.get("is_primary")) || truthy(s.get("authority_role")))
            .copied()
            .collect();

        let mut gaps: Vec<String> = Vec::new();
        let mut overturners: Vec<String> = Vec::new();
        let ctype = str_field(claim, "claim_type");

        if primary.is_empty() && ctype != "inference" && ctype != "recommendation" {
            gaps.push("no proposition-fit primary source".to_string());
        }
        if MULTI.contains(&ctype.as_str()) {
            overturners.push(
                "methodologically sound independent evidence with a materially different result"
                    .to_string(),
            );
            if clusters.len() < 2 {
                gaps.push("fewer than two independent evidence clusters".to_string());
            }
        }
        let status = str_field(claim, "status");
        if contested_ids.contains(&claim_id) || status == "contested" || status == "unresolved" {
            gaps.push("claim is contradicted or unresolved".to_string());
            overturners
                .push("resolution of the recorded contradiction against this position".to_string());
        }
        if ctype == "price" || ctype == "feature" {
            overturners.push("a newer official vendor page or version-specific record".to_string());
            let as_of = str_field(claim, "as_of");
            let age = iso_age_days(&as_of);
            if age.is_none() || age.unwrap() > 45 {
                gaps.push("volatile vendor claim is not current within 45 days".to_string());
            }
        }
        if ctype == "legal" || ctype == "case-law" {
            overturners.push(
                "a binding higher-court authority, amendment, repeal, or negative treatment"
                    .to_string(),
            );
            if primary.iter().any(|s| !truthy(s.get("current_as_of"))) {
                gaps.push("legal authority currentness is unverified".to_string());
            }
        }
        if ctype == "effect-size" || ctype == "adverse-event" || ctype == "dosing" {
            overturners.push(
                "a larger, better-controlled, or more patient-applicable primary study".to_string(),
            );
            if primary.iter().any(|s| !truthy(s.get("applicability"))) {
                gaps.push("patient/population applicability is unrecorded".to_string());
            }
        }
        if overturners.is_empty() {
            overturners.push("new proposition-fit primary evidence that contradicts the claim".to_string());
        }

        let query = if gaps.is_empty() {
            None
        } else {
            Some(build_query(claim, &ctype))
        };
        if let Some(q) = &query {
            targeted_queries.push(TargetedQuery {
                claim_id: claim_id.clone(),
                query: q.clone(),
            });
        }

        let finding_status = if gaps.is_empty() {
            "complete"
        } else {
            "gap-fetch-required"
        };
        findings.push(GapFinding {
            claim_id,
            text: str_field(claim, "text"),
            gaps,
            what_would_overturn_it: overturners,
            targeted_query: query,
            status: finding_status,
        });
    }

    let blocking_findings: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.gaps.is_empty())
        .map(|(i, _)| i)
        .collect();
    let complete = blocking_findings.is_empty();

    GapReview {
        findings,
        blocking_findings,
        targeted_queries,
        complete,
    }
}

fn build_query(claim: &Value, ctype: &str) -> String {
    let target = {
        let t = str_field(claim, "stance_target");
        if t.is_empty() {
            str_field(claim, "text")
        } else {
            t
        }
    };
    let as_of = {
        let a = str_field(claim, "as_of");
        if a.is_empty() {
            super::iso_date::today_iso_date()
        } else {
            a
        }
    };
    match ctype {
        "legal" | "case-law" => {
            format!("current binding authority negative treatment amendment {target} as of {as_of}")
        }
        "effect-size" | "adverse-event" | "dosing" => {
            format!("primary randomized trial replication applicability adverse events {target}")
        }
        "price" | "feature" => format!("official current {target} {as_of}"),
        _ => format!("independent proposition-fit primary evidence contradicting {target}"),
    }
}

/// Builds the `{"findings": [...], "blocking_findings": [...],
/// "targeted_queries": [...], "complete": bool}` JSON exactly as the Python
/// CLI prints it (field order matches `json.dumps(..., sort_keys=True)`).
pub fn review_to_json(claims: &[Value], evidence: &[Value], contradictions: Option<&Value>) -> Value {
    let result = review(claims, evidence, contradictions);
    let finding_to_json = |f: &GapFinding| {
        let mut obj = Map::new();
        obj.insert("claim_id".to_string(), Value::String(f.claim_id.clone()));
        obj.insert("text".to_string(), Value::String(f.text.clone()));
        obj.insert(
            "gaps".to_string(),
            Value::Array(f.gaps.iter().cloned().map(Value::String).collect()),
        );
        obj.insert(
            "what_would_overturn_it".to_string(),
            Value::Array(
                f.what_would_overturn_it
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        obj.insert(
            "targeted_query".to_string(),
            f.targeted_query.clone().map(Value::String).unwrap_or(Value::Null),
        );
        obj.insert("status".to_string(), Value::String(f.status.to_string()));
        Value::Object(obj)
    };
    let findings_json: Vec<Value> = result.findings.iter().map(finding_to_json).collect();
    let blocking_json: Vec<Value> = result
        .blocking_findings
        .iter()
        .map(|&i| findings_json[i].clone())
        .collect();
    let queries_json: Vec<Value> = result
        .targeted_queries
        .iter()
        .map(|q| {
            let mut obj = Map::new();
            obj.insert("claim_id".to_string(), Value::String(q.claim_id.clone()));
            obj.insert("query".to_string(), Value::String(q.query.clone()));
            Value::Object(obj)
        })
        .collect();
    let mut out = Map::new();
    out.insert("findings".to_string(), Value::Array(findings_json));
    out.insert("blocking_findings".to_string(), Value::Array(blocking_json));
    out.insert("targeted_queries".to_string(), Value::Array(queries_json));
    out.insert("complete".to_string(), Value::Bool(result.complete));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn complete_when_primary_source_present_and_uncontested() {
        let evidence = vec![json!({"id": "e1", "is_primary": true})];
        let claims = vec![json!({
            "id": "c1", "text": "x", "claim_type": "observation",
            "source_ids": ["e1"], "status": "supported"
        })];
        let review = review(&claims, &evidence, None);
        assert!(review.complete);
        assert_eq!(review.findings[0].status, "complete");
    }

    #[test]
    fn missing_primary_source_blocks() {
        let claims = vec![json!({"id": "c1", "text": "x", "claim_type": "observation", "source_ids": []})];
        let review = review(&claims, &[], None);
        assert!(!review.complete);
        assert!(review.findings[0]
            .gaps
            .contains(&"no proposition-fit primary source".to_string()));
    }

    #[test]
    fn multi_source_claim_type_requires_two_clusters() {
        let evidence = vec![
            json!({"id": "e1", "is_primary": true, "independence_cluster": "ind:1"}),
        ];
        let claims = vec![json!({
            "id": "c1", "text": "x", "claim_type": "benchmark", "source_ids": ["e1"]
        })];
        let review = review(&claims, &evidence, None);
        assert!(!review.complete);
        assert!(review.findings[0]
            .gaps
            .iter()
            .any(|g| g.contains("independent evidence clusters")));
    }

    #[test]
    fn contested_claim_blocks_and_notes_overturner() {
        let claims = vec![json!({
            "id": "c1", "text": "x", "claim_type": "inference", "status": "contested"
        })];
        let review = review(&claims, &[], None);
        assert!(!review.complete);
        assert!(review.findings[0]
            .what_would_overturn_it
            .iter()
            .any(|o| o.contains("resolution of the recorded contradiction")));
    }

    #[test]
    fn contradictions_input_marks_claim_contested() {
        let claims = vec![json!({"id": "c1", "text": "x", "claim_type": "inference"})];
        let contradictions = json!({"contradictions": [{"claim_ids": ["c1"]}]});
        let review = review(&claims, &[], Some(&contradictions));
        assert!(!review.complete);
    }

    #[test]
    fn json_shape_matches_python_field_names() {
        let claims = vec![json!({"id": "c1", "text": "x", "claim_type": "inference"})];
        let out = review_to_json(&claims, &[], None);
        for key in ["findings", "blocking_findings", "targeted_queries", "complete"] {
            assert!(out.get(key).is_some(), "missing key {key}");
        }
    }
}
