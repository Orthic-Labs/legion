//! Port of `skills/seo/scripts/question_inventory.py`.
//!
//! Fully ported: builds an AEO question inventory from first-party query
//! evidence (GSC rows) plus optional supplied questions. Pure data
//! transform.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Row {
    pub query: Option<String>,
    #[serde(default)]
    pub clicks: Option<f64>,
    #[serde(default)]
    pub impressions: Option<f64>,
    #[serde(default)]
    pub position: Option<Value>,
    pub page: Option<String>,
}

pub fn rows_from_payload(payload: &Value) -> Result<Vec<Row>, String> {
    let arr = if payload.is_array() {
        payload.clone()
    } else if let Some(rows) = payload.get("rows").filter(|r| r.is_array()) {
        rows.clone()
    } else {
        return Err("input must be a list or object with rows[]".to_string());
    };
    serde_json::from_value(arr).map_err(|e| e.to_string())
}

/// Mirrors `QUESTION_RE`: a leading interrogative word (case-insensitive).
fn starts_with_question_word(s: &str) -> bool {
    const WORDS: &[&str] = &[
        "who", "what", "when", "where", "why", "how", "can", "could", "does", "do", "did",
        "is", "are", "should", "which", "will", "would",
    ];
    let lower = s.to_lowercase();
    WORDS.iter().any(|w| {
        lower.starts_with(*w)
            && lower
                .as_bytes()
                .get(w.len())
                .map(|b| !b.is_ascii_alphanumeric() && *b != b'_')
                .unwrap_or(true)
    })
}

pub fn is_question(q: &str) -> bool {
    starts_with_question_word(q.trim_start()) || q.ends_with('?')
}

pub fn intent(q: &str) -> &'static str {
    let s = q.to_lowercase();
    let s = s.trim();
    if ["price", "pricing", "cost", "buy", "book", "download", "signup", "sign up"]
        .iter()
        .any(|x| s.contains(*x))
    {
        return "transactional";
    }
    if ["best ", " vs ", " versus ", "alternative", "compare", "review"]
        .iter()
        .any(|x| s.contains(*x))
    {
        return "commercial";
    }
    if s.starts_with("where ") || s.starts_with("login ") || s.starts_with("website ") {
        return "navigational";
    }
    "informational"
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct QuestionEntry {
    pub question: String,
    pub intent: &'static str,
    pub source: &'static str,
    pub clicks: Option<f64>,
    pub impressions: Option<f64>,
    pub best_position: Option<f64>,
    pub intended_page: Option<String>,
    pub answer_present: Option<bool>,
    pub extractable: Option<bool>,
    pub source_evidence_present: Option<bool>,
    pub traditional_visibility: &'static str,
    pub generative_visibility: &'static str,
}

fn normalize_question(q: &str) -> String {
    format!("{}?", q.trim_end_matches('?').trim_end())
}

fn dedupe_key(q: &str) -> String {
    q.to_lowercase().trim_end_matches('?').trim().to_string()
}

pub fn build(rows: &[Row], extras: &[String]) -> Vec<QuestionEntry> {
    let mut found: BTreeMap<String, QuestionEntry> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();

    for row in rows {
        let q = row.query.clone().unwrap_or_default();
        let q = q.trim();
        if q.is_empty() || !is_question(q) {
            continue;
        }
        let key = dedupe_key(q);
        if !found.contains_key(&key) {
            order.push(key.clone());
        }
        let entry = found.entry(key).or_insert_with(|| QuestionEntry {
            question: normalize_question(q),
            intent: intent(q),
            source: "gsc",
            clicks: Some(0.0),
            impressions: Some(0.0),
            best_position: None,
            intended_page: None,
            answer_present: None,
            extractable: None,
            source_evidence_present: None,
            traditional_visibility: "observed",
            generative_visibility: "not_tested",
        });
        entry.clicks = Some(entry.clicks.unwrap_or(0.0) + row.clicks.unwrap_or(0.0));
        entry.impressions = Some(entry.impressions.unwrap_or(0.0) + row.impressions.unwrap_or(0.0));
        if let Some(pos) = position_of(row) {
            entry.best_position = Some(match entry.best_position {
                Some(cur) => cur.min(pos),
                None => pos,
            });
        }
        if entry.intended_page.is_none() {
            if let Some(page) = &row.page {
                if !page.is_empty() {
                    entry.intended_page = Some(page.clone());
                }
            }
        }
    }

    for q in extras {
        let q = q.trim();
        if q.is_empty() {
            continue;
        }
        let key = dedupe_key(q);
        if found.contains_key(&key) {
            continue;
        }
        order.push(key.clone());
        found.insert(
            key,
            QuestionEntry {
                question: normalize_question(q),
                intent: intent(q),
                source: "supplied",
                clicks: None,
                impressions: None,
                best_position: None,
                intended_page: None,
                answer_present: None,
                extractable: None,
                source_evidence_present: None,
                traditional_visibility: "not_tested",
                generative_visibility: "not_tested",
            },
        );
    }

    let mut items: Vec<QuestionEntry> = order.into_iter().filter_map(|k| found.remove(&k)).collect();
    items.sort_by(|a, b| {
        let ia = -(a.impressions.unwrap_or(0.0));
        let ib = -(b.impressions.unwrap_or(0.0));
        ia.partial_cmp(&ib)
            .unwrap()
            .then(a.question.to_lowercase().cmp(&b.question.to_lowercase()))
    });
    items
}

fn position_of(row: &Row) -> Option<f64> {
    match &row.position {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) if !s.is_empty() => s.parse::<f64>().ok(),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryReport {
    pub questions: Vec<QuestionEntry>,
    pub count: usize,
    pub contract: &'static str,
}

pub fn build_report(rows: &[Row], extras: &[String]) -> InventoryReport {
    let questions = build(rows, extras);
    InventoryReport {
        count: questions.len(),
        questions,
        contract: "question -> intent -> intended page -> answer present -> extractable -> evidence -> traditional visibility -> generative visibility",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_leading_question_word() {
        assert!(is_question("How do I reset my password"));
        assert!(is_question("what is seo?"));
        assert!(!is_question("reset my password"));
    }

    #[test]
    fn detects_trailing_question_mark() {
        assert!(is_question("reset my password?"));
    }

    #[test]
    fn intent_classification() {
        assert_eq!(intent("what is the pricing for pro"), "transactional");
        assert_eq!(intent("best crm vs competitor"), "commercial");
        assert_eq!(intent("where login page"), "navigational");
        assert_eq!(intent("how does seo work"), "informational");
    }

    #[test]
    fn gsc_rows_aggregate_by_normalized_question() {
        let payload = json!([
            {"query": "how does seo work?", "clicks": 5, "impressions": 50, "position": 3.0, "page": "/seo"},
            {"query": "How does SEO work", "clicks": 2, "impressions": 20, "position": 1.5}
        ]);
        let rows = rows_from_payload(&payload).unwrap();
        let items = build(&rows, &[]);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].clicks, Some(7.0));
        assert_eq!(items[0].impressions, Some(70.0));
        assert_eq!(items[0].best_position, Some(1.5));
        assert_eq!(items[0].intended_page.as_deref(), Some("/seo"));
        assert_eq!(items[0].question, "how does seo work?");
    }

    #[test]
    fn non_question_rows_are_skipped() {
        let payload = json!([{"query": "seo tools", "clicks": 100}]);
        let rows = rows_from_payload(&payload).unwrap();
        assert!(build(&rows, &[]).is_empty());
    }

    #[test]
    fn extras_do_not_override_existing_gsc_entry() {
        let payload = json!([{"query": "how does seo work?", "clicks": 5, "impressions": 50}]);
        let rows = rows_from_payload(&payload).unwrap();
        let items = build(&rows, &["How does SEO work?".to_string()]);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].source, "gsc");
    }

    #[test]
    fn extras_added_when_not_present() {
        let items = build(&[], &["Why is my rank dropping?".to_string()]);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].source, "supplied");
        assert_eq!(items[0].clicks, None);
    }

    #[test]
    fn sorted_by_impressions_desc_then_question_asc() {
        let payload = json!([
            {"query": "what is a", "impressions": 5},
            {"query": "what is b", "impressions": 50}
        ]);
        let rows = rows_from_payload(&payload).unwrap();
        let items = build(&rows, &[]);
        assert_eq!(items[0].question, "what is b?");
        assert_eq!(items[1].question, "what is a?");
    }
}
