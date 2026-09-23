//! Port of `skills/seo/scripts/ai_visibility_import.py`.
//!
//! Fully ported: normalization of Google Search Console Generative AI and
//! Bing Webmaster AI Performance exports is pure row-mapping logic. File
//! I/O (reading the CSV/JSON export, writing the normalized JSON) and CLI
//! argument parsing are not ported — no CLI surface in this chunk — but
//! `load_rows_from_csv`/`load_rows_from_json`, `value`, `num`, `google`, and
//! `bing` all mirror the Python functions' behavior, including error
//! messages.
//!
//! `serde_json` is built with `preserve_order` in this workspace, so
//! `serde_json::Map` preserves field order the same way a Python dict
//! (insertion-ordered) does for the `raw` passthrough row.

use serde_json::{Map, Value};

/// Mirrors Python `value`: case-insensitive lookup of `row` by any name in
/// `names`, in order, returning the first hit.
pub fn value<'a>(row: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    // Python folds the whole row into a casefold-keyed dict first; we walk
    // it directly since Map lookups here are small.
    for name in names {
        let needle = name.to_lowercase();
        for (k, v) in row.iter() {
            if k.trim().to_lowercase() == needle {
                return Some(v);
            }
        }
    }
    None
}

fn value_as_str(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// Mirrors Python `num`: parses a numeric-ish value after stripping `,` and
/// `%` and surrounding whitespace; `None`/`""` and unparsable values become
/// `None`.
pub fn num(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    if matches!(v, Value::Null) {
        return None;
    }
    let s = value_as_str(v)?;
    let cleaned = s.replace(',', "").replace('%', "");
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return None;
    }
    cleaned.parse::<f64>().ok()
}

/// One normalized Google Search Console Generative AI row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GoogleRow {
    pub date: Option<String>,
    pub page: Option<String>,
    pub country: Option<String>,
    pub device: Option<String>,
    pub impressions: Option<f64>,
    pub raw: Map<String, Value>,
}

/// One normalized Bing Webmaster AI Performance row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BingRow {
    pub date: Option<String>,
    pub page: Option<String>,
    pub grounding_query: Option<String>,
    pub topic: Option<String>,
    pub intent: Option<String>,
    pub citations: Option<f64>,
    pub citation_share: Option<f64>,
    pub raw: Map<String, Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportResult<T> {
    pub schema_version: u32,
    pub provider: &'static str,
    pub surface: &'static str,
    pub measurement: &'static str,
    pub source_file: String,
    pub rows: Vec<T>,
    pub limitations: Vec<&'static str>,
}

/// Mirrors Python `google`. `imported_at` is intentionally omitted (it is a
/// wall-clock timestamp, not decision logic — callers that need it stamp it
/// themselves, matching `now()`'s isolation from the pure transform).
pub fn google(rows: &[Map<String, Value>], source: &str) -> ImportResult<GoogleRow> {
    let out = rows
        .iter()
        .map(|row| GoogleRow {
            date: value(row, &["date", "day"]).and_then(value_as_str),
            page: value(row, &["page", "url", "landing page"]).and_then(value_as_str),
            country: value(row, &["country"]).and_then(value_as_str),
            device: value(row, &["device"]).and_then(value_as_str),
            impressions: num(value(
                row,
                &["impressions", "generative ai impressions", "ai impressions"],
            )),
            raw: row.clone(),
        })
        .collect();
    ImportResult {
        schema_version: 1,
        provider: "google",
        surface: "search_console_generative_ai",
        measurement: "impressions",
        source_file: source.to_string(),
        rows: out,
        limitations: vec![
            "Generative impressions are visibility evidence, not citations, clicks, rankings, visits, or conversions.",
            "Report availability and dimensions depend on Google's current product and property eligibility.",
        ],
    }
}

/// Mirrors Python `bing`.
pub fn bing(rows: &[Map<String, Value>], source: &str) -> ImportResult<BingRow> {
    let out = rows
        .iter()
        .map(|row| BingRow {
            date: value(row, &["date", "day"]).and_then(value_as_str),
            page: value(row, &["cited page", "page", "url"]).and_then(value_as_str),
            grounding_query: value(row, &["grounding query", "query"]).and_then(value_as_str),
            topic: value(row, &["topic"]).and_then(value_as_str),
            intent: value(row, &["intent"]).and_then(value_as_str),
            citations: num(value(
                row,
                &["citations", "citation count", "total citations"],
            )),
            citation_share: num(value(row, &["citation share", "share"])),
            raw: row.clone(),
        })
        .collect();
    ImportResult {
        schema_version: 1,
        provider: "bing",
        surface: "webmaster_ai_performance",
        measurement: "citations",
        source_file: source.to_string(),
        rows: out,
        limitations: vec![
            "Bing AI Performance is aggregated/sampled citation activity, not ranking, authority, visits, or conversions.",
            "Grounding queries are provider-derived retrieval phrases, not exact user prompts.",
            "Citation Share is not market share or traffic share.",
        ],
    }
}

/// Mirrors Python `load_rows` for the JSON branch: accepts a top-level JSON
/// array, or an object with a `rows`/`data`/`items` array field. Returns
/// `Err` with the same message `SystemExit` used on a shape mismatch.
pub fn load_rows_from_json(text: &str) -> Result<Vec<Map<String, Value>>, String> {
    let data: Value =
        serde_json::from_str(text).map_err(|e| format!("invalid JSON export: {e}"))?;
    match data {
        Value::Array(items) => items
            .into_iter()
            .map(|v| match v {
                Value::Object(m) => Ok(m),
                _ => Err("JSON export rows must be objects".to_string()),
            })
            .collect(),
        Value::Object(obj) => {
            for key in ["rows", "data", "items"] {
                if let Some(Value::Array(items)) = obj.get(key) {
                    return items
                        .clone()
                        .into_iter()
                        .map(|v| match v {
                            Value::Object(m) => Ok(m),
                            _ => Err("JSON export rows must be objects".to_string()),
                        })
                        .collect();
                }
            }
            Err("JSON export must be a list or contain rows/data/items[]".to_string())
        }
        _ => Err("JSON export must be a list or contain rows/data/items[]".to_string()),
    }
}

/// Mirrors Python `load_rows` for the CSV branch: a minimal RFC 4180 parser
/// (quoted fields, `""` escaping, `\n`/`\r\n` line endings) matching
/// `csv.DictReader`'s field-per-header behavior. A row shorter than the
/// header is padded with `null` values (Python's `DictReader` pads missing
/// trailing fields with `None`); a row longer than the header collects the
/// extras is not modeled (Python puts them under a `None` key via
/// `restkey`, which is never read by this script).
pub fn load_rows_from_csv(text: &str) -> Vec<Map<String, Value>> {
    let records = parse_csv(text);
    let mut iter = records.into_iter();
    let header = match iter.next() {
        Some(h) => h,
        None => return Vec::new(),
    };
    iter.map(|record| {
        let mut m = Map::new();
        for (i, key) in header.iter().enumerate() {
            let v = record
                .get(i)
                .map(|s| Value::String(s.clone()))
                .unwrap_or(Value::Null);
            m.insert(key.clone(), v);
        }
        m
    })
    .collect()
}

fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut field = String::new();
    let mut row = Vec::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    let mut any_field_content = false;

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => {
                    in_quotes = true;
                    any_field_content = true;
                }
                ',' => {
                    row.push(std::mem::take(&mut field));
                    any_field_content = true;
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    any_field_content = false;
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    any_field_content = false;
                }
                _ => {
                    field.push(c);
                    any_field_content = true;
                }
            }
        }
    }
    if any_field_content || !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}
