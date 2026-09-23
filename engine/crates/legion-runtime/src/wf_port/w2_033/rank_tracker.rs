//! Rust port of the pure, deterministic core of `skills/seo/scripts/rank_tracker.py`.
//!
//! `rank_tracker.py` is a provider-neutral longitudinal rank observation store: it reads
//! JSON/CSV observation rows, normalizes them, writes dated snapshot files under
//! `.legion/seo/rank-tracking/`, and diffs the two most recent snapshots. The snapshot
//! read/write and CSV/JSON file parsing are filesystem IO and are not ported here; what is
//! ported verbatim is the pure `normalize()` row-shaping logic and the pure `compare()`
//! diff logic, both of which operate only on already-parsed data. Callers that need the
//! filesystem behaviour keep using the Python tool, or a host wrapper supplies the parsed
//! rows/snapshots to these functions.

use serde::Serialize;
use serde_json::Value;

/// Defaults applied when a row omits a field, mirroring the Python `defaults` dict built
/// from `--market/--language/--device/--provider/--collected-at`.
#[derive(Debug, Clone, Default)]
pub struct NormalizeDefaults {
    pub market: Option<String>,
    pub language: Option<String>,
    pub device: Option<String>,
    pub provider: Option<String>,
    pub collected_at: Option<String>,
}

/// The normalized shape written into a snapshot, matching the Python `normalize()` output
/// dict field-for-field.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NormalizedObservation {
    pub keyword: String,
    pub market: String,
    pub language: String,
    pub device: String,
    pub intended_page: Option<String>,
    pub observed_url: Option<String>,
    pub organic_position: Option<f64>,
    pub serp_features: Vec<Value>,
    pub provider: String,
    pub collected_at: String,
}

fn str_field(row: &Value, key: &str) -> Option<String> {
    match row.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(v) if !v.is_null() => Some(v.to_string()),
        _ => None,
    }
}

fn trim_or_empty(v: Option<String>) -> String {
    v.map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Error raised for a row missing both `keyword` and `query`, matching the Python
/// `ValueError('rank observation missing keyword/query')`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("rank observation missing keyword/query")]
pub struct MissingKeywordError;

/// Port of `normalize(row, defaults)`.
pub fn normalize(
    row: &Value,
    defaults: &NormalizeDefaults,
    now: &str,
) -> Result<NormalizedObservation, MissingKeywordError> {
    let keyword = trim_or_empty(str_field(row, "keyword").or_else(|| str_field(row, "query")));
    if keyword.is_empty() {
        return Err(MissingKeywordError);
    }

    let position_raw = row.get("position");
    let organic_position = match position_raw {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.parse::<f64>().ok(),
        _ => None,
    };

    let serp_features = match row.get("serp_features") {
        Some(Value::Array(arr)) => arr.clone(),
        _ => Vec::new(),
    };

    Ok(NormalizedObservation {
        keyword,
        market: trim_or_empty(str_field(row, "market").or_else(|| defaults.market.clone())),
        language: trim_or_empty(str_field(row, "language").or_else(|| defaults.language.clone())),
        device: {
            let d = str_field(row, "device")
                .or_else(|| defaults.device.clone())
                .unwrap_or_else(|| "desktop".to_string());
            d.trim().to_string()
        },
        intended_page: str_field(row, "intended_page").or_else(|| str_field(row, "target_url")),
        observed_url: str_field(row, "observed_url")
            .or_else(|| str_field(row, "url"))
            .or_else(|| str_field(row, "page")),
        organic_position,
        serp_features,
        provider: str_field(row, "provider")
            .or_else(|| defaults.provider.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        collected_at: str_field(row, "collected_at")
            .or_else(|| defaults.collected_at.clone())
            .unwrap_or_else(|| now.to_string()),
    })
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RankChange {
    New {
        #[serde(rename = "type")]
        change_type: &'static str,
        current: NormalizedObservation,
    },
    Tracked {
        keyword: String,
        market: String,
        language: String,
        device: String,
        previous_position: Option<f64>,
        current_position: Option<f64>,
        position_improvement: Option<f64>,
        previous_url: Option<String>,
        current_url: Option<String>,
        ownership_changed: bool,
        intended_page_mismatch: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompareResult {
    pub status: &'static str,
    pub changes: Vec<RankChange>,
    pub ownership_changes: usize,
    pub intended_page_mismatches: usize,
}

/// Port of the diff loop inside `compare()` — given the previous and current snapshot's
/// already-parsed observation lists, produce the same change records. The "fewer than two
/// snapshots exist" `not_testable` branch is filesystem-driven (snapshot discovery) and is
/// the caller's responsibility.
pub fn compare(prev: &[NormalizedObservation], curr: &[NormalizedObservation]) -> CompareResult {
    use std::collections::HashMap;

    let key = |o: &NormalizedObservation| -> (String, String, String, String) {
        (
            o.keyword.clone(),
            o.market.clone(),
            o.language.clone(),
            o.device.clone(),
        )
    };

    let pmap: HashMap<_, _> = prev.iter().map(|o| (key(o), o)).collect();
    let mut changes = Vec::with_capacity(curr.len());
    let mut ownership_changes = 0usize;
    let mut intended_page_mismatches = 0usize;

    for cur in curr {
        match pmap.get(&key(cur)) {
            None => {
                changes.push(RankChange::New {
                    change_type: "new_keyword_observation",
                    current: cur.clone(),
                });
            }
            Some(old) => {
                let old_pos = old.organic_position;
                let new_pos = cur.organic_position;
                let delta = match (old_pos, new_pos) {
                    (Some(o), Some(n)) => Some(round3(o - n)),
                    _ => None,
                };
                let ownership_changed = matches!(
                    (&old.observed_url, &cur.observed_url),
                    (Some(o), Some(c)) if !o.is_empty() && !c.is_empty() && o != c
                );
                let intended_mismatch = matches!(
                    (&cur.intended_page, &cur.observed_url),
                    (Some(i), Some(o)) if !i.is_empty() && !o.is_empty() && i != o
                );
                if ownership_changed {
                    ownership_changes += 1;
                }
                if intended_mismatch {
                    intended_page_mismatches += 1;
                }
                changes.push(RankChange::Tracked {
                    keyword: cur.keyword.clone(),
                    market: cur.market.clone(),
                    language: cur.language.clone(),
                    device: cur.device.clone(),
                    previous_position: old_pos,
                    current_position: new_pos,
                    position_improvement: delta,
                    previous_url: old.observed_url.clone(),
                    current_url: cur.observed_url.clone(),
                    ownership_changed,
                    intended_page_mismatch: intended_mismatch,
                });
            }
        }
    }

    CompareResult {
        status: "ok",
        changes,
        ownership_changes,
        intended_page_mismatches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_requires_keyword_or_query() {
        let err = normalize(&json!({}), &NormalizeDefaults::default(), "now").unwrap_err();
        assert_eq!(err, MissingKeywordError);
    }

    #[test]
    fn normalize_applies_defaults_and_trims() {
        let row = json!({"query": "  buy widgets  ", "position": "4.5"});
        let defaults = NormalizeDefaults {
            market: Some("US".into()),
            language: Some("en".into()),
            device: None,
            provider: Some("acme".into()),
            collected_at: Some("2026-01-01T00:00:00Z".into()),
        };
        let out = normalize(&row, &defaults, "unused").unwrap();
        assert_eq!(out.keyword, "buy widgets");
        assert_eq!(out.market, "US");
        assert_eq!(out.device, "desktop");
        assert_eq!(out.organic_position, Some(4.5));
        assert_eq!(out.provider, "acme");
        assert_eq!(out.collected_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn compare_flags_new_ownership_and_mismatch() {
        let defaults = NormalizeDefaults::default();
        let prev = vec![normalize(
            &json!({"keyword": "k1", "market": "US", "language": "en", "device": "desktop",
                     "organic_position": 5, "position": 5, "observed_url": "https://a.example/x"}),
            &defaults,
            "t",
        )
        .unwrap()];
        let curr = vec![
            normalize(
                &json!({"keyword": "k1", "market": "US", "language": "en", "device": "desktop",
                         "position": 3, "observed_url": "https://a.example/y",
                         "intended_page": "https://a.example/x"}),
                &defaults,
                "t",
            )
            .unwrap(),
            normalize(&json!({"keyword": "k2", "position": 10}), &defaults, "t").unwrap(),
        ];
        let result = compare(&prev, &curr);
        assert_eq!(result.status, "ok");
        assert_eq!(result.ownership_changes, 1);
        assert_eq!(result.intended_page_mismatches, 1);
        assert_eq!(result.changes.len(), 2);
        match &result.changes[0] {
            RankChange::Tracked {
                position_improvement,
                ownership_changed,
                intended_page_mismatch,
                ..
            } => {
                assert_eq!(*position_improvement, Some(2.0));
                assert!(*ownership_changed);
                assert!(*intended_page_mismatch);
            }
            other => panic!("expected Tracked, got {other:?}"),
        }
        match &result.changes[1] {
            RankChange::New { change_type, .. } => assert_eq!(*change_type, "new_keyword_observation"),
            other => panic!("expected New, got {other:?}"),
        }
    }
}
