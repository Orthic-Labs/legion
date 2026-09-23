//! Port of `research-core/contradictions.py`: derive contradiction and
//! consensus views from atomic claims.
//!
//! Faithful port of `_target`, `_scope`, `_stance`, `_numbers`, and
//! `derive`. The CLI wrapper (`main`) is not ported for the same reason as
//! `citecheck.rs`: this crate is a library.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::Value;

fn number_re() -> Regex {
    Regex::new(r"[-+]?\d[\d,]*(?:\.\d+)?%?").expect("static regex")
}

fn bracket_re() -> Regex {
    Regex::new(r"\[[^\]]+\]").expect("static regex")
}

fn word_re() -> Regex {
    Regex::new(r"[a-z0-9]{3,}").expect("static regex")
}

const TARGET_STOP_WORDS: &[&str] = &["this", "that", "with", "from", "than", "into", "does", "have"];

/// A scope is the claim's `scope` map, restricted to non-empty values and
/// sorted, matching Python's `tuple(sorted(...))` grouping key.
pub type Scope = Vec<(String, String)>;

fn target(claim: &Value) -> String {
    let explicit = claim
        .get("stance_target")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| claim.get("metric").and_then(Value::as_str).filter(|s| !s.trim().is_empty()));
    if let Some(explicit) = explicit {
        return explicit.trim().to_lowercase();
    }
    let text = claim.get("text").and_then(Value::as_str).unwrap_or("").to_lowercase();
    let stripped = bracket_re().replace_all(&text, " ").to_string();
    let words: Vec<&str> = word_re()
        .find_iter(&stripped)
        .map(|m| m.as_str())
        .filter(|w| !TARGET_STOP_WORDS.contains(w))
        .take(8)
        .collect();
    words.join(" ")
}

fn scope(claim: &Value) -> Scope {
    let mut out: Scope = claim
        .get("scope")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| {
                    if v.is_null() {
                        return None;
                    }
                    let s = value_to_scope_string(v);
                    if s.is_empty() {
                        None
                    } else {
                        Some((k.clone(), s))
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn value_to_scope_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn stance(claim: &Value) -> String {
    claim
        .get("stance")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase()
}

fn numbers(claim: &Value) -> Vec<String> {
    let text = claim.get("text").and_then(Value::as_str).unwrap_or("");
    number_re().find_iter(text).map(|m| m.as_str().to_string()).collect()
}

fn claim_id(claim: &Value) -> String {
    claim.get("id").map(value_to_scope_string).unwrap_or_default()
}

/// A stance-or-numeric contradiction, mirroring the Python dict shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contradiction {
    pub target: String,
    pub scope: Scope,
    pub claim_ids: Vec<String>,
    pub kind: &'static str,
    /// stance -> claim ids, sorted by stance key (matches `sorted(sides.items())`).
    pub positions: Vec<(String, Vec<String>)>,
    pub numeric_values: Vec<Vec<String>>,
    pub resolution_status: &'static str,
    pub decision_relevance: String,
}

/// A corroborated-consensus row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consensus {
    pub target: String,
    pub scope: Scope,
    pub claim_ids: Vec<String>,
    pub independent_voices: usize,
    pub status: &'static str,
}

/// Mirrors the dict `derive()` returns.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeriveResult {
    pub contradictions: Vec<Contradiction>,
    pub consensus: Vec<Consensus>,
}

/// Production entry point: port of `derive(claims, evidence)`.
pub fn derive(claims: &[Value], evidence: &[Value]) -> DeriveResult {
    let evidence_by_id: BTreeMap<String, &Value> = evidence
        .iter()
        .filter_map(|e| e.get("id").map(|id| (value_to_scope_string(id), e)))
        .collect();

    // Preserve first-seen group order, matching Python's `defaultdict` +
    // dict iteration order (insertion order).
    let mut order: Vec<(String, Scope)> = Vec::new();
    let mut groups: BTreeMap<(String, Scope), Vec<&Value>> = BTreeMap::new();
    for claim in claims {
        let key = (target(claim), scope(claim));
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(claim);
    }

    let mut contradictions = Vec::new();
    let mut consensus = Vec::new();

    for key @ (tgt, scp) in &order {
        let rows = &groups[key];
        if tgt.is_empty() || rows.len() < 2 {
            continue;
        }
        let mut sides: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for row in rows.iter() {
            let st = stance(row);
            if !st.is_empty() {
                sides.entry(st).or_default().push(claim_id(row));
            }
        }
        let number_sets: BTreeSet<Vec<String>> = rows
            .iter()
            .map(|row| numbers(row))
            .filter(|n| !n.is_empty())
            .collect();
        let genuine_stance_conflict = sides.get("supports").is_some_and(|v| !v.is_empty())
            && sides.get("refutes").is_some_and(|v| !v.is_empty());
        let numeric_conflict = number_sets.len() > 1;

        if genuine_stance_conflict || numeric_conflict {
            let decision_relevance = rows
                .iter()
                .map(|r| {
                    r.get("decision_relevance")
                        .and_then(Value::as_str)
                        .unwrap_or("medium")
                        .to_string()
                })
                .max()
                .unwrap_or_else(|| "medium".to_string());
            let mut numeric_values: Vec<Vec<String>> = number_sets.into_iter().collect();
            numeric_values.sort();
            contradictions.push(Contradiction {
                target: tgt.clone(),
                scope: scp.clone(),
                claim_ids: rows.iter().map(|r| claim_id(r)).collect(),
                kind: if genuine_stance_conflict { "stance" } else { "numeric" },
                positions: sides.into_iter().collect(),
                numeric_values,
                resolution_status: "unresolved",
                decision_relevance,
            });
            continue;
        }

        let mut clusters: BTreeSet<String> = BTreeSet::new();
        for row in rows.iter() {
            if let Some(source_ids) = row.get("source_ids").and_then(Value::as_array) {
                for sid in source_ids {
                    let sid = value_to_scope_string(sid);
                    if let Some(ev) = evidence_by_id.get(&sid) {
                        let cluster = ev
                            .get("independence_cluster")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| sid.clone());
                        clusters.insert(cluster);
                    }
                }
            }
        }
        let all_supported = rows.iter().all(|r| {
            r.get("status").and_then(Value::as_str).unwrap_or("supported") == "supported"
        });
        if clusters.len() >= 2 && all_supported {
            consensus.push(Consensus {
                target: tgt.clone(),
                scope: scp.clone(),
                claim_ids: rows.iter().map(|r| claim_id(r)).collect(),
                independent_voices: clusters.len(),
                status: "corroborated",
            });
        }
    }

    DeriveResult { contradictions, consensus }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stance_conflict_is_a_contradiction() {
        let claims = vec![
            json!({"id": "c1", "stance_target": "pricing", "stance": "supports", "text": "Vendor X is cheap"}),
            json!({"id": "c2", "stance_target": "pricing", "stance": "refutes", "text": "Vendor X is expensive"}),
        ];
        let result = derive(&claims, &[]);
        assert_eq!(result.contradictions.len(), 1);
        assert_eq!(result.contradictions[0].kind, "stance");
        assert_eq!(result.contradictions[0].claim_ids, vec!["c1", "c2"]);
    }

    #[test]
    fn differing_numbers_for_same_target_are_a_numeric_contradiction() {
        let claims = vec![
            json!({"id": "c1", "stance_target": "price", "text": "Costs 10 dollars"}),
            json!({"id": "c2", "stance_target": "price", "text": "Costs 20 dollars"}),
        ];
        let result = derive(&claims, &[]);
        assert_eq!(result.contradictions.len(), 1);
        assert_eq!(result.contradictions[0].kind, "numeric");
    }

    #[test]
    fn corroborated_claims_from_independent_clusters_are_consensus() {
        let evidence = vec![
            json!({"id": "e1", "independence_cluster": "clusterA"}),
            json!({"id": "e2", "independence_cluster": "clusterB"}),
        ];
        let claims = vec![
            json!({"id": "c1", "stance_target": "price", "text": "no numbers here", "source_ids": ["e1"]}),
            json!({"id": "c2", "stance_target": "price", "text": "no numbers here either", "source_ids": ["e2"]}),
        ];
        let result = derive(&claims, &evidence);
        assert!(result.contradictions.is_empty());
        assert_eq!(result.consensus.len(), 1);
        assert_eq!(result.consensus[0].independent_voices, 2);
    }

    #[test]
    fn single_claim_group_produces_neither() {
        let claims = vec![json!({"id": "c1", "stance_target": "price", "text": "Costs 10 dollars"})];
        let result = derive(&claims, &[]);
        assert!(result.contradictions.is_empty());
        assert!(result.consensus.is_empty());
    }

    #[test]
    fn empty_target_group_is_skipped() {
        let claims = vec![
            json!({"id": "c1", "text": "   ", "stance": "supports"}),
            json!({"id": "c2", "text": "   ", "stance": "refutes"}),
        ];
        let result = derive(&claims, &[]);
        assert!(result.contradictions.is_empty());
    }
}
