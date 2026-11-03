//! Port of `skills/seo/scripts/query_ownership.py`.
//!
//! Fully ported: classifies GSC query ownership and cannibalization from
//! query/page/clicks/impressions/position/date rows. Pure data transform;
//! preserves evidence and does not decide redirects itself.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Row {
    pub query: Option<String>,
    pub page: Option<String>,
    #[serde(default)]
    pub clicks: Option<f64>,
    #[serde(default)]
    pub impressions: Option<f64>,
    #[serde(default)]
    pub position: Option<Value>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub period: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UrlEvidence {
    pub url: String,
    pub clicks: f64,
    pub impressions: f64,
    pub avg_position: Option<f64>,
    pub observed_periods: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct QueryOwnership {
    pub query: String,
    pub urls: Vec<UrlEvidence>,
    pub dominant_url: Option<String>,
    pub dominant_share: Option<f64>,
    pub stability: &'static str,
    pub classification: &'static str,
    pub reason: &'static str,
}

/// Extracts rows from either a bare array or `{"rows": [...]}`, mirroring `_rows`.
pub fn rows_from_payload(payload: &Value) -> Result<Vec<Row>, String> {
    let arr = if payload.is_array() {
        payload.clone()
    } else if let Some(rows) = payload.get("rows").filter(|r| r.is_array()) {
        rows.clone()
    } else {
        return Err("input must be a list or an object containing rows[]".to_string());
    };
    serde_json::from_value(arr).map_err(|e| e.to_string())
}

fn metric(row: &Row) -> f64 {
    let clicks = row.clicks.unwrap_or(0.0);
    if clicks > 0.0 {
        clicks
    } else {
        row.impressions.unwrap_or(0.0)
    }
}

fn position_of(row: &Row) -> Option<f64> {
    match &row.position {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) if !s.is_empty() => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn period_key(row: &Row) -> String {
    row.date
        .clone()
        .or_else(|| row.period.clone())
        .unwrap_or_else(|| "single".to_string())
}

pub fn classify(rows: &[Row]) -> Vec<QueryOwnership> {
    let mut by_query: BTreeMap<String, Vec<&Row>> = BTreeMap::new();
    for row in rows {
        let q = row.query.clone().unwrap_or_default().trim().to_string();
        let page = row.page.clone().unwrap_or_default().trim().to_string();
        if !q.is_empty() && !page.is_empty() {
            by_query.entry(q).or_default().push(row);
        }
    }

    let mut output = Vec::new();
    for (query, qrows) in by_query {
        let mut by_url: BTreeMap<String, Vec<&Row>> = BTreeMap::new();
        // periods[period][url] += metric
        let mut periods: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
        for row in &qrows {
            let url = row.page.clone().unwrap_or_default();
            by_url.entry(url.clone()).or_default().push(row);
            let period = period_key(row);
            *periods.entry(period).or_default().entry(url).or_insert(0.0) += metric(row);
        }

        let mut evidence: Vec<UrlEvidence> = Vec::new();
        let mut totals: BTreeMap<String, f64> = BTreeMap::new();
        for (url, urows) in &by_url {
            let clicks: f64 = urows.iter().map(|r| r.clicks.unwrap_or(0.0)).sum();
            let impressions: f64 = urows.iter().map(|r| r.impressions.unwrap_or(0.0)).sum();
            let positions: Vec<f64> = urows.iter().filter_map(|r| position_of(r)).collect();
            totals.insert(url.clone(), if clicks > 0.0 { clicks } else { impressions });
            let avg_position = if positions.is_empty() {
                None
            } else {
                let sum: f64 = positions.iter().sum();
                Some((sum / positions.len() as f64 * 1000.0).round() / 1000.0)
            };
            let observed_periods: HashSet<String> = urows.iter().map(|r| period_key(r)).collect();
            evidence.push(UrlEvidence {
                url: url.clone(),
                clicks,
                impressions,
                avg_position,
                observed_periods: observed_periods.len(),
            });
        }

        // sort by (total, impressions) descending, stable for ties (mirrors Python's
        // stable sort with reverse=True on a tuple key).
        evidence.sort_by(|a, b| {
            let ta = totals.get(&a.url).copied().unwrap_or(0.0);
            let tb = totals.get(&b.url).copied().unwrap_or(0.0);
            tb.partial_cmp(&ta)
                .unwrap()
                .then(b.impressions.partial_cmp(&a.impressions).unwrap())
        });

        let total_metric: f64 = totals.values().sum();
        let dominant = evidence.first().map(|e| e.url.clone());
        let share = match &dominant {
            Some(d) if total_metric > 0.0 => totals.get(d).map(|t| t / total_metric),
            _ => None,
        };

        let mut period_winners: Vec<String> = Vec::new();
        for scores in periods.values() {
            if let Some((winner, _)) = scores.iter().max_by(|a, b| a.1.partial_cmp(b.1).unwrap()) {
                period_winners.push(winner.clone());
            }
        }
        let winner_changes = (1..period_winners.len())
            .filter(|&i| period_winners[i] != period_winners[i - 1])
            .count();
        let unique_winners: HashSet<&String> = period_winners.iter().collect();

        let (stability, classification, reason): (&str, &str, &str) = if evidence.len() == 1 {
            (
                "high",
                "stable owner",
                "only one observed URL owns the query",
            )
        } else if period_winners.len() >= 2 && unique_winners.len() > 1 && winner_changes > 0 {
            (
                "low",
                "ownership switching",
                "dominant URL changes across observed periods",
            )
        } else if share.map(|s| s >= 0.80).unwrap_or(false) {
            (
                "high",
                "benign overlap",
                "one URL owns at least 80% of observed demand while secondary URLs are minor",
            )
        } else if share.map(|s| s >= 0.60).unwrap_or(false) {
            (
                "medium",
                "ambiguous ownership",
                "one URL leads but ownership is not decisive",
            )
        } else {
            (
                "low",
                "probable duplicate target",
                "multiple URLs split query demand with no strong owner",
            )
        };

        output.push(QueryOwnership {
            query,
            urls: evidence,
            dominant_url: dominant,
            dominant_share: share.map(|s| (s * 10000.0).round() / 10000.0),
            stability,
            classification,
            reason,
        });
    }
    output
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnershipReport {
    pub query_count: usize,
    pub ownership: Vec<QueryOwnership>,
    pub limitations: Vec<&'static str>,
}

pub fn build_report(rows: &[Row]) -> OwnershipReport {
    let items = classify(rows);
    OwnershipReport {
        query_count: items.len(),
        ownership: items,
        limitations: vec![
            "Classification is first-party evidence triage, not automatic redirect/consolidation authority. Intent and page-family evidence are required for remediation.",
        ],
    }
}

/// CLI entry point mirroring `query_ownership.py`'s `main()`: positional `input`, optional
/// `--out`. Prints the pretty JSON report to stdout; returns 0 on success, 2 on a
/// usage/IO/parse error.
pub fn run(argv: &[String]) -> i32 {
    let mut input: Option<&str> = None;
    let mut out: Option<&str> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
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
    let report = build_report(&rows);
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
