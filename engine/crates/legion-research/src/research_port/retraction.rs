//! Port of `tools/research-core/retraction.py`: DOI retraction verification
//! against OpenAlex and Crossref.
//!
//! Only the retraction signal is in the Python. It has no separate correction
//! or patch classification for DOIs. Draft patching lives in `patcher.py`,
//! which is not ported. This module does not invent a correction class.
//!
//! The network step is an injected callback, `fetch(verifier, doi)`, that
//! returns the decoded JSON payload or an error string. The CLI passes
//! [`network_unavailable`], so a DOI that no fixture resolves is reported as
//! `unavailable:network-step-not-run` and never as a clean result.

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

use super::pyval::{py_str, py_str_or, quote, truthy};

/// Gap token used when no authorised transport performs the fetch.
pub const UNAVAILABLE_NETWORK: &str = "unavailable:network-step-not-run";

/// The two retraction sources the Python consults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verifier {
    OpenAlex,
    Crossref,
}

impl Verifier {
    /// The checker name the Python records in error strings.
    pub fn python_name(self) -> &'static str {
        match self {
            Self::OpenAlex => "_openalex",
            Self::Crossref => "_crossref",
        }
    }
}

/// Request URL for a verifier, as the Python builds it.
pub fn request_url(verifier: Verifier, doi: &str) -> String {
    match verifier {
        Verifier::OpenAlex => format!(
            "https://api.openalex.org/works/{}",
            quote(&format!("https://doi.org/{doi}"), ":/")
        ),
        Verifier::Crossref => format!("https://api.crossref.org/works/{}", quote(doi, "")),
    }
}

/// Fetch callback that performs no network I/O. Every call yields the gap token.
pub fn network_unavailable(_verifier: Verifier, _doi: &str) -> Result<Value, String> {
    Err(UNAVAILABLE_NETWORK.to_string())
}

/// `_openalex` classification of a decoded OpenAlex work payload.
pub fn parse_openalex(data: &Value) -> Result<Value, String> {
    let object = data
        .as_object()
        .ok_or_else(|| "openalex payload is not an object".to_string())?;
    let retracted = truthy(object.get("is_retracted"));
    let work_id = object.get("id").cloned().unwrap_or(Value::Null);
    Ok(json!({"source": "openalex", "retracted": retracted, "work_id": work_id}))
}

/// `_crossref` classification of a decoded Crossref works payload.
///
/// Retracted when any `update-to` entry has type `retraction`, or when
/// `relation.is-retracted-by` is truthy. Like Python `any()` and `or`, it stops
/// reading as soon as the answer is known.
pub fn parse_crossref(data: &Value) -> Result<Value, String> {
    let object = data
        .as_object()
        .ok_or_else(|| "crossref payload is not an object".to_string())?;
    let message_value = object.get("message").cloned().unwrap_or_else(|| json!({}));
    let message = message_value
        .as_object()
        .ok_or_else(|| "crossref message is not an object".to_string())?;

    let update_to: Value = match message.get("update-to") {
        Some(value) if truthy(Some(value)) => value.clone(),
        _ => json!([]),
    };
    let mut retracted = false;
    let entries = update_to
        .as_array()
        .ok_or_else(|| "crossref update-to is not a list".to_string())?;
    for entry in entries {
        let entry_object = entry
            .as_object()
            .ok_or_else(|| "crossref update-to entry is not an object".to_string())?;
        if py_str_or(entry_object.get("type"), "").to_lowercase() == "retraction" {
            retracted = true;
            break;
        }
    }

    let relation: Value = match message.get("relation") {
        Some(value) if truthy(Some(value)) => value.clone(),
        _ => json!({}),
    };
    if !retracted {
        let relation_object = relation
            .as_object()
            .ok_or_else(|| "crossref relation is not an object".to_string())?;
        retracted = truthy(relation_object.get("is-retracted-by"));
    }

    Ok(json!({
        "source": "crossref",
        "retracted": retracted,
        "update_to": update_to,
        "relation": relation,
    }))
}

/// Strip, lowercase, and remove `https://doi.org/` then `doi:` prefixes.
pub fn normalize_doi(raw: &str) -> String {
    let lowered = raw.trim().to_lowercase();
    let without_resolver = lowered
        .strip_prefix("https://doi.org/")
        .unwrap_or(lowered.as_str());
    without_resolver
        .strip_prefix("doi:")
        .unwrap_or(without_resolver)
        .to_string()
}

fn truncate_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// `check_doi`: one DOI's verdict, with an optional fixture map consulted first.
pub fn check_doi(
    raw: &str,
    fixture: Option<&Map<String, Value>>,
    fetch: &dyn Fn(Verifier, &str) -> Result<Value, String>,
) -> Value {
    let doi = normalize_doi(raw);
    if doi.is_empty() {
        return json!({
            "doi": doi,
            "status": "invalid",
            "retracted": null,
            "errors": ["empty DOI"],
        });
    }

    if let Some(entry) = fixture.and_then(|map| map.get(&doi)) {
        return match entry.as_object() {
            Some(fields) => {
                let mut row = Map::new();
                row.insert("doi".to_string(), Value::String(doi.clone()));
                row.insert("status".to_string(), Value::String("verified".to_string()));
                for (key, value) in fields {
                    row.insert(key.clone(), value.clone());
                }
                row.insert("sources".to_string(), json!(["fixture"]));
                Value::Object(row)
            }
            None => json!({
                "doi": doi,
                "status": "invalid",
                "retracted": null,
                "errors": ["fixture entry is not an object"],
            }),
        };
    }

    let mut results: Vec<Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for verifier in [Verifier::OpenAlex, Verifier::Crossref] {
        let outcome = fetch(verifier, &doi).and_then(|payload| match verifier {
            Verifier::OpenAlex => parse_openalex(&payload),
            Verifier::Crossref => parse_crossref(&payload),
        });
        match outcome {
            Ok(row) => results.push(row),
            Err(message) => errors.push(format!(
                "{}: {}",
                verifier.python_name(),
                truncate_chars(&message, 200)
            )),
        }
    }

    if results.is_empty() {
        return json!({
            "doi": doi,
            "status": "unknown",
            "retracted": null,
            "errors": errors,
        });
    }
    let retracted = results.iter().any(|row| truthy(row.get("retracted")));
    json!({
        "doi": doi,
        "status": "verified",
        "retracted": retracted,
        "sources": results,
        "errors": errors,
    })
}

/// `sweep`: check each distinct DOI, mark disclosed ones, and block on
/// undisclosed retractions and, when `block_unknown` is set, on unknown status.
pub fn sweep(
    dois: &[String],
    disclosed: &[String],
    block_unknown: bool,
    fixture: Option<&Map<String, Value>>,
    fetch: &dyn Fn(Verifier, &str) -> Result<Value, String>,
) -> Value {
    let disclosed_set: BTreeSet<String> = disclosed
        .iter()
        .map(|raw| {
            let lowered = raw.to_lowercase();
            lowered
                .strip_prefix("https://doi.org/")
                .unwrap_or(lowered.as_str())
                .to_string()
        })
        .collect();

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut ordered: Vec<String> = Vec::new();
    for raw in dois {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            ordered.push(trimmed.to_string());
        }
    }

    let mut results: Vec<Value> = Vec::new();
    for doi in &ordered {
        let mut row = check_doi(doi, fixture, fetch);
        let normalized = py_str(row.get("doi"));
        let is_disclosed = disclosed_set.contains(&normalized);
        let retracted = truthy(row.get("retracted"));
        let unknown = row.get("status").and_then(Value::as_str) == Some("unknown");
        let block = (retracted && !is_disclosed) || (block_unknown && unknown);
        if let Value::Object(map) = &mut row {
            map.insert("disclosed".to_string(), json!(is_disclosed));
            map.insert("block".to_string(), json!(block));
        }
        results.push(row);
    }

    let block_brief = results.iter().any(|row| truthy(row.get("block")));
    let unknown_count = results
        .iter()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("unknown"))
        .count();
    json!({
        "dois_checked": results.len(),
        "results": results,
        "block_brief": block_brief,
        "unknown_count": unknown_count,
    })
}

/// True when any row recorded the gap token, meaning a fetch was never run.
pub fn has_unavailable_gap(sweep_result: &Value) -> bool {
    sweep_result["results"]
        .as_array()
        .map(|rows| {
            rows.iter().any(|row| {
                row["errors"]
                    .as_array()
                    .map(|errors| {
                        errors.iter().any(|error| {
                            error
                                .as_str()
                                .is_some_and(|text| text.contains(UNAVAILABLE_NETWORK))
                        })
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_network(verifier: Verifier, doi: &str) -> Result<Value, String> {
        network_unavailable(verifier, doi)
    }

    #[test]
    fn crossref_retraction_notice_and_relation_both_classify_as_retracted() {
        let notice = json!({"message": {"update-to": [{"type": "Retraction"}]}});
        let parsed = parse_crossref(&notice).unwrap();
        assert_eq!(parsed["retracted"], true);

        let relation = json!({"message": {"relation": {"is-retracted-by": [{"id": "x"}]}}});
        assert_eq!(parse_crossref(&relation).unwrap()["retracted"], true);

        let clean = json!({"message": {"update-to": [{"type": "correction"}]}});
        assert_eq!(parse_crossref(&clean).unwrap()["retracted"], false);
    }

    #[test]
    fn openalex_flag_uses_python_truthiness() {
        assert_eq!(
            parse_openalex(&json!({"is_retracted": true, "id": "W1"})).unwrap()["retracted"],
            true
        );
        assert_eq!(
            parse_openalex(&json!({"is_retracted": 0})).unwrap()["retracted"],
            false
        );
        assert_eq!(parse_openalex(&json!({})).unwrap()["work_id"], Value::Null);
    }

    #[test]
    fn normalize_strips_resolver_then_doi_prefix() {
        assert_eq!(normalize_doi("  https://doi.org/10.1/ABC "), "10.1/abc");
        assert_eq!(normalize_doi("doi:10.1/abc"), "10.1/abc");
        assert_eq!(normalize_doi("   "), "");
    }

    #[test]
    fn unavailable_network_yields_unknown_and_blocks_by_default() {
        let result = sweep(&["10.1/x".to_string()], &[], true, None, &no_network);
        assert_eq!(result["results"][0]["status"], "unknown");
        assert_eq!(result["block_brief"], true);
        assert_eq!(result["unknown_count"], 1);
        assert!(has_unavailable_gap(&result));
        let allowed = sweep(&["10.1/x".to_string()], &[], false, None, &no_network);
        assert_eq!(allowed["block_brief"], false);
    }

    #[test]
    fn undisclosed_retraction_blocks_and_disclosed_one_does_not() {
        let fixture: Map<String, Value> = serde_json::from_value(json!({
            "10.1/retracted": {"retracted": true},
            "10.1/clean": {"retracted": false},
        }))
        .unwrap();
        let dois = vec!["10.1/retracted".to_string(), "10.1/clean".to_string()];
        let undisclosed = sweep(&dois, &[], true, Some(&fixture), &no_network);
        assert_eq!(undisclosed["block_brief"], true);
        assert_eq!(undisclosed["results"][0]["block"], true);
        assert_eq!(undisclosed["results"][1]["block"], false);
        assert!(!has_unavailable_gap(&undisclosed));

        let disclosed = sweep(
            &dois,
            &["https://doi.org/10.1/retracted".to_string()],
            true,
            Some(&fixture),
            &no_network,
        );
        assert_eq!(disclosed["results"][0]["disclosed"], true);
        assert_eq!(disclosed["results"][0]["block"], false);
        assert_eq!(disclosed["block_brief"], false);
    }

    #[test]
    fn duplicate_and_blank_dois_are_dropped_in_order() {
        let dois = vec![
            " 10.1/a ".to_string(),
            "".to_string(),
            "10.1/a".to_string(),
            "10.1/b".to_string(),
        ];
        let result = sweep(&dois, &[], false, None, &no_network);
        assert_eq!(result["dois_checked"], 2);
        assert_eq!(result["results"][0]["doi"], "10.1/a");
        assert_eq!(result["results"][1]["doi"], "10.1/b");
    }

    #[test]
    fn request_urls_match_python_quoting() {
        assert_eq!(
            request_url(Verifier::OpenAlex, "10.1/a b"),
            "https://api.openalex.org/works/https://doi.org/10.1/a%20b"
        );
        assert_eq!(
            request_url(Verifier::Crossref, "10.1/a"),
            "https://api.crossref.org/works/10.1%2Fa"
        );
    }
}
