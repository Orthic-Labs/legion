//! Port of `src/lib/research-core/retraction.py`.
//!
//! A verified run blocks when a DOI is retracted without disclosure or when
//! every configured verifier fails and the retraction status remains
//! unknown.
//!
//! Network transport (OpenAlex and Crossref works lookups) is injected
//! through [`RetractionTransport`], for the same reason as
//! `super::scholarly::ScholarlyTransport`: no HTTP client crate is a
//! workspace dependency of `legion-research`, and this packet is read-only
//! on `Cargo.toml`. See `wf028.md` for the dependency patch this needs to
//! talk to OpenAlex/Crossref for real.
//!
//! The Python's `RESEARCH_RETRACTION_FIXTURE` environment-variable escape
//! hatch (a JSON file mapping DOI -> pre-verified result, used instead of
//! live network calls) is ported as an explicit `fixture: Option<&Value>`
//! parameter rather than reading the environment directly, since env-var
//! reads are a poor fit for a library crate; callers reproduce the Python
//! CLI behaviour by reading `RESEARCH_RETRACTION_FIXTURE` themselves and
//! passing the parsed JSON in.

use serde_json::{json, Map, Value};
use std::fmt;

#[derive(Debug)]
pub struct TransportError(pub String);
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for TransportError {}

/// Injected external transport for the two verifiers.
pub trait RetractionTransport {
    fn openalex(&self, doi: &str) -> Result<Value, TransportError>;
    fn crossref(&self, doi: &str) -> Result<Value, TransportError>;
}

/// Python's `bool(x)` truthiness for a JSON value: `null`/`false` are
/// falsy, `0`/`0.0` are falsy, empty string/array/object are falsy,
/// everything else is truthy.
fn python_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Port of `_openalex()`'s response shaping (the request itself is
/// `transport.openalex`'s job).
pub fn openalex_result(response: &Value) -> Value {
    json!({
        "source": "openalex",
        "retracted": response.get("is_retracted").and_then(Value::as_bool).unwrap_or(false),
        "work_id": response.get("id").cloned().unwrap_or(Value::Null),
    })
}

/// Port of `_crossref()`'s response shaping.
pub fn crossref_result(response: &Value) -> Value {
    let message = response.get("message").cloned().unwrap_or_else(|| json!({}));
    let update_to = message
        .get("update-to")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let relation = message.get("relation").cloned().unwrap_or_else(|| json!({}));
    let update_to_retracted = update_to.iter().any(|item| {
        item.get("type")
            .and_then(Value::as_str)
            .map(|t| t.to_lowercase() == "retraction")
            .unwrap_or(false)
    });
    let relation_retracted = relation
        .get("is-retracted-by")
        .map(python_truthy)
        .unwrap_or(false);
    json!({
        "source": "crossref",
        "retracted": update_to_retracted || relation_retracted,
        "update_to": update_to,
        "relation": relation,
    })
}

/// Port of `check_doi()`. `fixture` mirrors `RESEARCH_RETRACTION_FIXTURE`:
/// a DOI -> result-fields map; a hit short-circuits verifier calls exactly
/// as the Python does.
pub fn check_doi(
    transport: &dyn RetractionTransport,
    doi: &str,
    fixture: Option<&Map<String, Value>>,
) -> Value {
    let lowered = doi.trim().to_lowercase();
    let stripped_url = lowered
        .strip_prefix("https://doi.org/")
        .unwrap_or(&lowered)
        .to_string();
    let normalized = stripped_url
        .strip_prefix("doi:")
        .unwrap_or(&stripped_url)
        .to_string();

    if normalized.is_empty() {
        return json!({
            "doi": normalized,
            "status": "invalid",
            "retracted": Value::Null,
            "errors": ["empty DOI"],
        });
    }

    if let Some(fixture) = fixture {
        if let Some(entry) = fixture.get(&normalized) {
            let mut out = Map::new();
            out.insert("doi".to_string(), json!(normalized));
            out.insert("status".to_string(), json!("verified"));
            if let Value::Object(fields) = entry {
                for (k, v) in fields {
                    out.insert(k.clone(), v.clone());
                }
            }
            out.insert("sources".to_string(), json!(["fixture"]));
            return Value::Object(out);
        }
    }

    let mut results = Vec::new();
    let mut errors = Vec::new();
    match transport.openalex(&normalized) {
        Ok(resp) => results.push(openalex_result(&resp)),
        Err(e) => errors.push(format!("_openalex: {e}")),
    }
    match transport.crossref(&normalized) {
        Ok(resp) => results.push(crossref_result(&resp)),
        Err(e) => errors.push(format!("_crossref: {e}")),
    }

    if results.is_empty() {
        return json!({
            "doi": normalized,
            "status": "unknown",
            "retracted": Value::Null,
            "errors": errors,
        });
    }
    let retracted = results
        .iter()
        .any(|r| r.get("retracted").and_then(Value::as_bool).unwrap_or(false));
    json!({
        "doi": normalized,
        "status": "verified",
        "retracted": retracted,
        "sources": results,
        "errors": errors,
    })
}

/// Port of `sweep()`. `dois` may contain duplicates and blanks, matching the
/// Python's `dict.fromkeys(d.strip() for d in dois if d.strip())`
/// dedup-preserving-order behaviour.
pub fn sweep(
    transport: &dyn RetractionTransport,
    dois: &[String],
    disclosed: &[String],
    block_unknown: bool,
    fixture: Option<&Map<String, Value>>,
) -> Value {
    let disclosed_set: std::collections::HashSet<String> = disclosed
        .iter()
        .map(|d| {
            let lower = d.to_lowercase();
            lower.strip_prefix("https://doi.org/").unwrap_or(&lower).to_string()
        })
        .collect();

    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();
    for raw in dois {
        let doi = raw.trim();
        if doi.is_empty() || !seen.insert(doi.to_string()) {
            continue;
        }
        let mut row = check_doi(transport, doi, fixture);
        let row_doi = row["doi"].as_str().unwrap_or_default().to_string();
        let disclosed_flag = disclosed_set.contains(&row_doi);
        let status = row["status"].as_str().unwrap_or_default().to_string();
        let retracted = row["retracted"].as_bool().unwrap_or(false);
        let block = (retracted && !disclosed_flag) || (block_unknown && status == "unknown");
        row["disclosed"] = json!(disclosed_flag);
        row["block"] = json!(block);
        results.push(row);
    }
    let block_brief = results.iter().any(|r| r["block"].as_bool().unwrap_or(false));
    let unknown_count = results
        .iter()
        .filter(|r| r["status"].as_str() == Some("unknown"))
        .count();
    json!({
        "dois_checked": results.len(),
        "results": results,
        "block_brief": block_brief,
        "unknown_count": unknown_count,
    })
}

/// Port of `main()`'s exit-code convention: `0` when nothing blocks, `2`
/// when `sweep()['block_brief']` is true.
pub fn exit_code(sweep_result: &Value) -> i32 {
    if sweep_result["block_brief"].as_bool().unwrap_or(false) {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTransport {
        openalex_retracted: bool,
        crossref_retracted: bool,
        openalex_fails: bool,
        crossref_fails: bool,
    }

    impl RetractionTransport for FakeTransport {
        fn openalex(&self, _doi: &str) -> Result<Value, TransportError> {
            if self.openalex_fails {
                return Err(TransportError("boom".into()));
            }
            Ok(json!({"is_retracted": self.openalex_retracted, "id": "https://openalex.org/W1"}))
        }
        fn crossref(&self, _doi: &str) -> Result<Value, TransportError> {
            if self.crossref_fails {
                return Err(TransportError("boom".into()));
            }
            let update_to = if self.crossref_retracted {
                json!([{"type": "Retraction"}])
            } else {
                json!([])
            };
            Ok(json!({"message": {"update-to": update_to, "relation": {}}}))
        }
    }

    #[test]
    fn check_doi_normalizes_prefixes() {
        let t = FakeTransport {
            openalex_retracted: false,
            crossref_retracted: false,
            openalex_fails: false,
            crossref_fails: false,
        };
        let r = check_doi(&t, "https://doi.org/DOI:10.1/ABC", None);
        // normalization strips "https://doi.org/" first, then "doi:" is not
        // a prefix any more (case mismatch), matching the Python's ordered
        // `.removeprefix` calls exactly.
        assert_eq!(r["doi"], json!("doi:10.1/abc"));
    }

    #[test]
    fn check_doi_empty_is_invalid() {
        let t = FakeTransport {
            openalex_retracted: false,
            crossref_retracted: false,
            openalex_fails: false,
            crossref_fails: false,
        };
        let r = check_doi(&t, "   ", None);
        assert_eq!(r["status"], json!("invalid"));
    }

    #[test]
    fn check_doi_uses_fixture_when_present() {
        let t = FakeTransport {
            openalex_retracted: true,
            crossref_retracted: true,
            openalex_fails: false,
            crossref_fails: false,
        };
        let mut fixture = Map::new();
        fixture.insert("10.1/abc".to_string(), json!({"retracted": false}));
        let r = check_doi(&t, "10.1/abc", Some(&fixture));
        assert_eq!(r["status"], json!("verified"));
        assert_eq!(r["retracted"], json!(false));
        assert_eq!(r["sources"], json!(["fixture"]));
    }

    #[test]
    fn check_doi_retracted_if_any_source_says_so() {
        let t = FakeTransport {
            openalex_retracted: false,
            crossref_retracted: true,
            openalex_fails: false,
            crossref_fails: false,
        };
        let r = check_doi(&t, "10.1/abc", None);
        assert_eq!(r["status"], json!("verified"));
        assert_eq!(r["retracted"], json!(true));
    }

    #[test]
    fn check_doi_unknown_when_both_verifiers_fail() {
        let t = FakeTransport {
            openalex_retracted: false,
            crossref_retracted: false,
            openalex_fails: true,
            crossref_fails: true,
        };
        let r = check_doi(&t, "10.1/abc", None);
        assert_eq!(r["status"], json!("unknown"));
        assert_eq!(r["errors"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn sweep_blocks_on_undisclosed_retraction() {
        let t = FakeTransport {
            openalex_retracted: true,
            crossref_retracted: false,
            openalex_fails: false,
            crossref_fails: false,
        };
        let result = sweep(&t, &["10.1/abc".to_string()], &[], true, None);
        assert_eq!(result["block_brief"], json!(true));
        assert_eq!(exit_code(&result), 2);
    }

    #[test]
    fn sweep_does_not_block_disclosed_retraction() {
        let t = FakeTransport {
            openalex_retracted: true,
            crossref_retracted: false,
            openalex_fails: false,
            crossref_fails: false,
        };
        let result = sweep(
            &t,
            &["10.1/abc".to_string()],
            &["10.1/abc".to_string()],
            true,
            None,
        );
        assert_eq!(result["block_brief"], json!(false));
        assert_eq!(exit_code(&result), 0);
    }

    #[test]
    fn sweep_blocks_on_unknown_unless_allowed() {
        let t = FakeTransport {
            openalex_retracted: false,
            crossref_retracted: false,
            openalex_fails: true,
            crossref_fails: true,
        };
        let blocked = sweep(&t, &["10.1/abc".to_string()], &[], true, None);
        assert_eq!(blocked["block_brief"], json!(true));
        assert_eq!(blocked["unknown_count"], json!(1));

        let allowed = sweep(&t, &["10.1/abc".to_string()], &[], false, None);
        assert_eq!(allowed["block_brief"], json!(false));
    }

    #[test]
    fn sweep_dedups_preserving_first_occurrence_and_skips_blank() {
        let t = FakeTransport {
            openalex_retracted: false,
            crossref_retracted: false,
            openalex_fails: false,
            crossref_fails: false,
        };
        let result = sweep(
            &t,
            &["10.1/abc".to_string(), "  ".to_string(), "10.1/abc".to_string()],
            &[],
            true,
            None,
        );
        assert_eq!(result["dois_checked"], json!(1));
    }
}
