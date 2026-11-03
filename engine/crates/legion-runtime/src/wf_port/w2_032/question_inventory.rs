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
        "who", "what", "when", "where", "why", "how", "can", "could", "does", "do", "did", "is",
        "are", "should", "which", "will", "would",
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
    if [
        "price", "pricing", "cost", "buy", "book", "download", "signup", "sign up",
    ]
    .iter()
    .any(|x| s.contains(*x))
    {
        return "transactional";
    }
    if [
        "best ",
        " vs ",
        " versus ",
        "alternative",
        "compare",
        "review",
    ]
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

    let mut items: Vec<QuestionEntry> =
        order.into_iter().filter_map(|k| found.remove(&k)).collect();
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

/// CLI entry point mirroring `question_inventory.py`'s `main()`: positional `input` (GSC
/// normalized JSON), `--questions` (optional newline-delimited supplied questions file),
/// `--out` (optional output file). Prints the pretty JSON report to stdout and returns the
/// exit code `main()` returns (0 on success, 2 on a usage/IO/parse error).
pub fn run(argv: &[String]) -> i32 {
    let mut input: Option<&str> = None;
    let mut questions: Option<&str> = None;
    let mut out: Option<&str> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--questions" => {
                i += 1;
                questions = argv.get(i).map(String::as_str);
            }
            "--out" => {
                i += 1;
                out = argv.get(i).map(String::as_str);
            }
            other => input = Some(other),
        }
        i += 1;
    }
    let input_path = match input {
        Some(p) => p,
        None => {
            eprintln!("error: input path is required");
            return 2;
        }
    };
    let text = match std::fs::read_to_string(input_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let payload: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let rows = match rows_from_payload(&payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let extras: Vec<String> = match questions {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(t) => t.lines().map(str::to_string).collect(),
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        },
        None => Vec::new(),
    };
    let report = build_report(&rows, &extras);
    let text_out = serde_json::to_string_pretty(&report).unwrap_or_default();
    if let Some(path) = out {
        if let Err(e) = std::fs::write(path, format!("{text_out}\n")) {
            eprintln!("error: {e}");
            return 2;
        }
    }
    println!("{text_out}");
    0
}
