//! Port of `skills/seo/scripts/templated_metadata.py`.
//!
//! Fully ported: `analyze()` is a pure function over already-parsed page rows
//! (`url`/`title`/`meta_desc` or `meta_description`). Reading the input JSON file and
//! writing `--json` output are host IO and are left to the caller.

use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Stock CTA phrases anchored at the end of the description, matching the Python
/// `CTA_RE` (case-insensitive, allows a trailing `.`, `!`, or space run).
const CTA_PHRASES: &[&str] = &[
    "learn more",
    "find out more",
    "get started",
    "discover more",
    "read more",
    "shop now",
    "buy now",
    "contact us",
    "book now",
    "try now",
    "sign up",
    "explore now",
    "start today",
    "see more",
];

fn cta_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let alts = CTA_PHRASES.join("|");
        Regex::new(&format!(r"(?i)\b({alts})\b[.! ]*$")).expect("static CTA regex")
    })
}

fn punct_or_symbol_to_space() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Python's `[^\w\s]` under `re` (ASCII `\w` semantics for this use — titles/descriptions
    // are plain text); Rust's `regex` crate needs Unicode word-char classes spelled out.
    RE.get_or_init(|| Regex::new(r"[^\w\s]").expect("static punctuation regex"))
}

fn whitespace_run() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+").expect("static whitespace regex"))
}

/// Port of `norm(text)`: casefold, strip punctuation to spaces, collapse whitespace, trim.
pub fn norm(text: &str) -> String {
    let stripped = punct_or_symbol_to_space().replace_all(text, " ");
    let collapsed = whitespace_run().replace_all(&stripped, " ");
    // Python's `.casefold()` is closest to Rust's `to_lowercase()` for this input class
    // (plain ASCII/Latin marketing copy); full Unicode casefolding is not pulled in as a
    // new dependency here.
    collapsed.trim().to_lowercase()
}

/// One input row, matching the Python shape read from `pages`/top-level list.
#[derive(Debug, Clone, Default)]
pub struct PageRow {
    pub url: Option<Value>,
    pub title: Option<String>,
    pub meta_desc: Option<String>,
}

impl PageRow {
    /// Builds a row from a parsed JSON object, mirroring `row.get("title")` /
    /// `row.get("meta_desc") or row.get("meta_description")`.
    pub fn from_value(row: &Value) -> PageRow {
        let str_field = |key: &str| -> Option<String> {
            row.get(key).and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Null => None,
                other => Some(other.to_string()),
            })
        };
        PageRow {
            url: row.get("url").cloned(),
            title: str_field("title"),
            meta_desc: str_field("meta_desc").or_else(|| str_field("meta_description")),
        }
    }
}

/// One entry in `findings`, matching the Python finding dict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub url: Value,
    pub title: String,
    pub meta_description: String,
    pub signals: Vec<&'static str>,
    pub cta: String,
    pub method: &'static str,
}

/// The full `analyze()` result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AnalysisResult {
    pub method: &'static str,
    pub pages_checked: usize,
    pub templated_pages: usize,
    pub templated_ratio: f64,
    /// `Counter.most_common(10)`: (phrase, count) pairs, ties broken by first-seen order
    /// like Python's `Counter` (insertion order among equal counts).
    pub shared_cta_phrases: Vec<(String, usize)>,
    pub site_risk: &'static str,
    pub findings: Vec<Finding>,
}

/// Port of `analyze(rows)`.
pub fn analyze(rows: &[PageRow]) -> AnalysisResult {
    let mut findings = Vec::new();
    let mut cta_counts: HashMap<String, usize> = HashMap::new();
    let mut cta_order: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for row in rows {
        let title = row.title.clone().unwrap_or_default().trim().to_string();
        let desc = row.meta_desc.clone().unwrap_or_default().trim().to_string();
        if desc.is_empty() {
            continue;
        }
        checked += 1;
        let ntitle = norm(&title);
        let ndesc = norm(&desc);
        let restates = !ntitle.is_empty()
            && (ndesc.starts_with(ntitle.as_str()) || {
                let window_end = (ntitle.chars().count() + 25).max(60);
                let window: String = ndesc.chars().take(window_end).collect();
                window.contains(ntitle.as_str())
            });
        let cta = cta_regex()
            .captures(&desc)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_lowercase());
        if let Some(ref c) = cta {
            if !cta_counts.contains_key(c) {
                cta_order.push(c.clone());
            }
            *cta_counts.entry(c.clone()).or_insert(0) += 1;
        }
        if restates {
            if let Some(c) = cta {
                findings.push(Finding {
                    url: row.url.clone().unwrap_or(Value::Null),
                    title,
                    meta_description: desc,
                    signals: vec!["title_restatement", "stock_cta"],
                    cta: c,
                    method: "heuristic",
                });
            }
        }
    }

    let ratio = if checked > 0 {
        findings.len() as f64 / checked as f64
    } else {
        0.0
    };
    let site_risk = if ratio >= 0.5 && checked >= 4 {
        "high"
    } else if ratio >= 0.2 && checked >= 4 {
        "medium"
    } else if !findings.is_empty() {
        "low"
    } else {
        "none"
    };

    let mut most_common: Vec<(String, usize)> = cta_order
        .into_iter()
        .map(|k| {
            let c = cta_counts[&k];
            (k, c)
        })
        .collect();
    // `Counter.most_common` sorts by count descending, stable on insertion order for ties.
    most_common.sort_by(|a, b| b.1.cmp(&a.1));
    most_common.truncate(10);

    AnalysisResult {
        method: "heuristic",
        pages_checked: checked,
        templated_pages: findings.len(),
        templated_ratio: (ratio * 10000.0).round() / 10000.0,
        shared_cta_phrases: most_common,
        site_risk,
        findings,
    }
}

/// Port of the `rows = payload.get("pages", []) if isinstance(payload, dict) else payload`
/// input-shape handling in `main()`. Returns an error message matching
/// `raise SystemExit("input must be a list or object with pages[]")` when neither shape
/// matches.
pub fn rows_from_payload(payload: &Value) -> Result<Vec<PageRow>, &'static str> {
    let arr = match payload {
        Value::Object(map) => map.get("pages").cloned().unwrap_or(Value::Array(vec![])),
        Value::Array(_) => payload.clone(),
        _ => return Err("input must be a list or object with pages[]"),
    };
    match arr {
        Value::Array(items) => Ok(items.iter().map(PageRow::from_value).collect()),
        _ => Err("input must be a list or object with pages[]"),
    }
}

/// CLI entry point mirroring `templated_metadata.py`'s `main()`: positional `input` (JSON
/// list or object with `pages[]`), `--json <out>`. Prints the pretty JSON result to stdout.
/// Returns 2 for a missing input argument or unreadable/unparseable input file, 1 for the
/// `SystemExit("input must be a list or object with pages[]")` shape error, 0 on success.
pub fn run(argv: &[String]) -> i32 {
    let mut input: Option<&str> = None;
    let mut out: Option<&str> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json" => {
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
            eprintln!("{e}");
            return 1;
        }
    };
    let result = analyze(&rows);
    let text_out = serde_json::to_string_pretty(&result).unwrap_or_default();
    if let Some(path) = out {
        if let Err(e) = std::fs::write(path, format!("{text_out}\n")) {
            eprintln!("error: {e}");
            return 2;
        }
    }
    println!("{text_out}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_title_restatement_with_stock_cta() {
        let rows = vec![PageRow {
            url: Some(json!("https://example.com/a")),
            title: Some("Best Widgets Online".to_string()),
            meta_desc: Some("Best Widgets Online. Learn more.".to_string()),
        }];
        let result = analyze(&rows);
        assert_eq!(result.pages_checked, 1);
        assert_eq!(result.templated_pages, 1);
        assert_eq!(result.findings[0].cta, "learn more");
        assert_eq!(result.site_risk, "low");
    }

    #[test]
    fn no_restatement_no_finding() {
        let rows = vec![PageRow {
            url: Some(json!("https://example.com/a")),
            title: Some("Widgets".to_string()),
            meta_desc: Some("A totally unrelated unique description of our product line.".to_string()),
        }];
        let result = analyze(&rows);
        assert_eq!(result.templated_pages, 0);
        assert_eq!(result.site_risk, "none");
    }

    #[test]
    fn empty_description_rows_are_skipped_from_checked_count() {
        let rows = vec![
            PageRow { url: None, title: Some("T".into()), meta_desc: None },
            PageRow { url: None, title: Some("T".into()), meta_desc: Some("".into()) },
        ];
        let result = analyze(&rows);
        assert_eq!(result.pages_checked, 0);
        assert_eq!(result.templated_ratio, 0.0);
    }

    #[test]
    fn risk_bands_follow_ratio_and_minimum_sample() {
        // 4 checked, all templated -> ratio 1.0 -> high.
        let mut rows = Vec::new();
        for i in 0..4 {
            rows.push(PageRow {
                url: Some(json!(format!("https://example.com/{i}"))),
                title: Some("Same Title".to_string()),
                meta_desc: Some("Same Title. Buy now.".to_string()),
            });
        }
        let result = analyze(&rows);
        assert_eq!(result.templated_pages, 4);
        assert_eq!(result.site_risk, "high");
    }

    #[test]
    fn rows_from_payload_accepts_list_or_pages_object() {
        let list = json!([{"url": "a", "title": "t", "meta_desc": "d"}]);
        assert_eq!(rows_from_payload(&list).unwrap().len(), 1);
        let obj = json!({"pages": [{"url": "a", "title": "t", "meta_description": "d"}]});
        let rows = rows_from_payload(&obj).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].meta_desc.as_deref(), Some("d"));
        assert!(rows_from_payload(&json!("nope")).is_err());
    }

    #[test]
    fn norm_matches_python_casefold_strip_collapse() {
        assert_eq!(norm("  Best   Widgets!! Online.  "), "best widgets online");
    }

    #[test]
    fn run_missing_input_returns_2() {
        assert_eq!(run(&[]), 2);
    }

    #[test]
    fn run_writes_result_for_valid_input() {
        let dir = std::env::temp_dir().join(format!(
            "legion-w2034-tm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("in.json");
        std::fs::write(&input, r#"[{"url":"https://x.com/a","title":"Widgets","meta_desc":"Widgets. Learn more"}]"#).unwrap();
        assert_eq!(run(&[input.to_str().unwrap().to_string()]), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
