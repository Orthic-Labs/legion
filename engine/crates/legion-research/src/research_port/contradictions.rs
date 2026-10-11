//! Deterministic contradiction and consensus views over atomic claim rows.
//!
//! Port of the retired research prototype's `contradictions.py`. The view
//! groups claims by explicit stance target (or a bounded text-derived target)
//! and normalized scope. Consensus counts independent evidence clusters, not
//! claim rows or raw source records.

use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn number_pattern() -> &'static Regex {
    static PATTERN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"[-+]?\d[\d,]*(?:\.\d+)?%?").expect("valid number regex"))
}

fn target(claim: &Value) -> String {
    for key in ["stance_target", "metric"] {
        if let Some(value) = claim.get(key).filter(|value| !value.is_null()) {
            let explicit = value.to_string();
            let explicit = value.as_str().unwrap_or(&explicit).trim().to_lowercase();
            if !explicit.is_empty() {
                return explicit;
            }
        }
    }

    let text = claim
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let without_brackets = Regex::new(r"\[[^\]]+\]")
        .expect("valid bracket regex")
        .replace_all(&text, " ");
    let ignored = [
        "this", "that", "with", "from", "than", "into", "does", "have",
    ];
    without_brackets
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| word.len() >= 3 && !ignored.contains(word))
        .take(8)
        .collect::<Vec<_>>()
        .join(" ")
}

fn scope(claim: &Value) -> BTreeMap<String, String> {
    let mut normalized = BTreeMap::new();
    if let Some(fields) = claim.get("scope").and_then(Value::as_object) {
        for (key, value) in fields {
            if value.is_null() || value.as_str() == Some("") {
                continue;
            }
            let text = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            normalized.insert(key.clone(), text);
        }
    }
    normalized
}

fn numbers(claim: &Value) -> Vec<String> {
    number_pattern()
        .find_iter(claim.get("text").and_then(Value::as_str).unwrap_or(""))
        .map(|matched| matched.as_str().to_owned())
        .collect()
}

fn string_field<'a>(claim: &'a Value, key: &str) -> &'a str {
    claim.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Derive unresolved contradictions and corroborated consensus groups.
pub fn derive(claims: &[Value], evidence: &[Value]) -> Value {
    let evidence_by_id: BTreeMap<String, &Value> = evidence
        .iter()
        .filter_map(|row| row.get("id").map(|id| (id.to_string_id(), row)))
        .collect();
    let mut groups: BTreeMap<(String, BTreeMap<String, String>), Vec<&Value>> = BTreeMap::new();
    for claim in claims {
        groups
            .entry((target(claim), scope(claim)))
            .or_default()
            .push(claim);
    }

    let mut contradictions = Vec::new();
    let mut consensus = Vec::new();
    for ((target, scope), rows) in groups {
        if target.is_empty() || rows.len() < 2 {
            continue;
        }
        let mut positions: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut number_sets = BTreeSet::new();
        for row in &rows {
            let stance = string_field(row, "stance").to_lowercase();
            if !stance.is_empty() {
                positions
                    .entry(stance)
                    .or_default()
                    .push(string_field(row, "id").to_owned());
            }
            let found_numbers = numbers(row);
            if !found_numbers.is_empty() {
                number_sets.insert(found_numbers);
            }
        }
        let stance_conflict =
            positions.contains_key("supports") && positions.contains_key("refutes");
        if stance_conflict || number_sets.len() > 1 {
            let relevance = rows
                .iter()
                .map(|row| string_field(row, "decision_relevance"))
                .max()
                .filter(|value| !value.is_empty())
                .unwrap_or("medium");
            contradictions.push(json!({
                "target": target,
                "scope": scope,
                "claim_ids": rows.iter().map(|row| string_field(row, "id")).collect::<Vec<_>>(),
                "kind": if stance_conflict { "stance" } else { "numeric" },
                "positions": positions,
                "numeric_values": number_sets,
                "resolution_status": "unresolved",
                "decision_relevance": relevance,
            }));
            continue;
        }

        let mut independent_voices = BTreeSet::new();
        for row in &rows {
            if let Some(source_ids) = row.get("source_ids").and_then(Value::as_array) {
                for source_id in source_ids.iter().filter_map(Value::as_str) {
                    if let Some(source) = evidence_by_id.get(source_id) {
                        let cluster = source
                            .get("independence_cluster")
                            .and_then(Value::as_str)
                            .filter(|cluster| !cluster.is_empty())
                            .unwrap_or(source_id);
                        independent_voices.insert(cluster.to_owned());
                    }
                }
            }
        }
        if independent_voices.len() >= 2
            && rows.iter().all(|row| {
                row.get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("supported")
                    == "supported"
            })
        {
            consensus.push(json!({
                "target": target,
                "scope": scope,
                "claim_ids": rows.iter().map(|row| string_field(row, "id")).collect::<Vec<_>>(),
                "independent_voices": independent_voices.len(),
                "status": "corroborated",
            }));
        }
    }
    json!({"contradictions": contradictions, "consensus": consensus})
}

trait JsonId {
    fn to_string_id(&self) -> String;
}

impl JsonId for Value {
    fn to_string_id(&self) -> String {
        self.as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::derive;
    use serde_json::json;

    #[test]
    fn reports_stance_conflict_within_matching_scope() {
        let claims = vec![
            json!({"id":"yes", "stance_target":"policy", "stance":"supports", "scope":{"year":2025}, "text":"Policy works 20%"}),
            json!({"id":"no", "stance_target":"policy", "stance":"refutes", "scope":{"year":2025}, "text":"Policy fails 30%"}),
        ];
        let view = derive(&claims, &[]);
        assert_eq!(view["contradictions"][0]["kind"], "stance");
        assert_eq!(view["contradictions"][0]["resolution_status"], "unresolved");
        assert_eq!(
            view["contradictions"][0]["numeric_values"],
            json!([["20%"], ["30%"]])
        );
        assert!(view["consensus"].as_array().unwrap().is_empty());
    }

    #[test]
    fn corroboration_counts_clusters_and_requires_supported_claims() {
        let claims = vec![
            json!({"id":"c1", "stance_target":"availability", "text":"Available", "source_ids":["s1"]}),
            json!({"id":"c2", "stance_target":"availability", "text":"Available", "source_ids":["s2"]}),
        ];
        let evidence = vec![
            json!({"id":"s1", "independence_cluster":"cluster-a"}),
            json!({"id":"s2", "independence_cluster":"cluster-b"}),
        ];
        let view = derive(&claims, &evidence);
        assert_eq!(view["consensus"][0]["independent_voices"], 2);
        assert_eq!(view["consensus"][0]["status"], "corroborated");

        let duplicate_evidence = vec![
            json!({"id":"s1", "independence_cluster":"same"}),
            json!({"id":"s2", "independence_cluster":"same"}),
        ];
        assert!(derive(&claims, &duplicate_evidence)["consensus"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn numeric_conflicts_preserve_value_order_and_repeated_values() {
        let swapped = vec![
            json!({"id":"c1", "metric":"costs", "text":"A costs 10; B costs 20"}),
            json!({"id":"c2", "metric":"costs", "text":"A costs 20; B costs 10"}),
        ];
        let view = derive(&swapped, &[]);
        assert_eq!(view["contradictions"][0]["kind"], "numeric");
        assert_eq!(
            view["contradictions"][0]["numeric_values"],
            json!([["10", "20"], ["20", "10"]])
        );

        let repeated = vec![
            json!({"id":"c3", "metric":"rate", "text":"Rate is 10 then 10"}),
            json!({"id":"c4", "metric":"rate", "text":"Rate is 10"}),
        ];
        let repeated_view = derive(&repeated, &[]);
        assert_eq!(repeated_view["contradictions"][0]["kind"], "numeric");
        assert_eq!(
            repeated_view["contradictions"][0]["numeric_values"],
            json!([["10"], ["10", "10"]])
        );
    }
}
