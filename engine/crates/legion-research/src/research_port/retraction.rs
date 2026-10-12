//! Port of `tools/research-core/retraction.py`: DOI retraction verification
//! against OpenAlex and Crossref.
//!
//! Only the retraction signal is in the Python. It has no separate correction
//! or patch classification for DOIs. Draft patching lives in `patcher.py`,
//! which is not ported. This module does not invent a correction class.
//!
//! The network step is an injected callback, `fetch(verifier, doi)`, that
//! returns a decoded payload plus transport provenance, or an error string.
//! The CLI uses fixed public endpoints and an explicit offline/fixture path.

use crate::{budget::BudgetAccount, workflow::Cancellation};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

use super::pyval::{py_str, py_str_or, quote, truthy};

/// Gap token used when no authorised transport performs the fetch.
pub const UNAVAILABLE_NETWORK: &str = "unavailable:network-step-not-run";
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq)]
pub struct FetchResponse {
    pub payload: Value,
    pub provenance: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchError {
    pub message: String,
    pub terminal: bool,
}

impl FetchError {
    fn terminal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            terminal: true,
        }
    }
}

impl From<String> for FetchError {
    fn from(message: String) -> Self {
        Self {
            message,
            terminal: false,
        }
    }
}

impl From<&str> for FetchError {
    fn from(message: &str) -> Self {
        Self::from(message.to_string())
    }
}

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
pub fn network_unavailable(_verifier: Verifier, _doi: &str) -> Result<FetchResponse, FetchError> {
    Err(UNAVAILABLE_NETWORK.into())
}

/// Build a client that cannot follow server-controlled redirects.
pub fn live_client() -> Result<Client, String> {
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(REQUEST_TIMEOUT)
        .user_agent("legion-research/0.3")
        .build()
        .map_err(|error| format!("HTTP client unavailable: {error}"))
}

/// Fetch one DOI from one fixed provider under the shared call, byte, deadline,
/// and cancellation limits. `reserve_source` is handled once per DOI by the
/// caller; each provider request reserves its own call and response bytes.
pub fn fetch_live(
    client: &Client,
    verifier: Verifier,
    doi: &str,
    budget: &mut BudgetAccount,
    cancellation: &Cancellation,
) -> Result<FetchResponse, FetchError> {
    validate_doi_path(doi)?;
    if budget.remaining().bytes == 0 {
        return Err(FetchError::terminal("research byte budget exhausted"));
    }
    budget
        .reserve_call(cancellation)
        .map_err(|error| FetchError::terminal(error.to_string()))?;
    let url = request_url(verifier, doi);
    let parsed_url =
        reqwest::Url::parse(&url).map_err(|error| format!("invalid provider URL: {error}"))?;
    let expected_host = match verifier {
        Verifier::OpenAlex => "api.openalex.org",
        Verifier::Crossref => "api.crossref.org",
    };
    if parsed_url.scheme() != "https"
        || parsed_url.host_str() != Some(expected_host)
        || parsed_url.port_or_known_default() != Some(443)
        || !parsed_url.username().is_empty()
        || parsed_url.password().is_some()
    {
        return Err("provider URL escaped fixed HTTPS endpoint".into());
    }
    let timeout = budget
        .deadline()
        .saturating_duration_since(std::time::Instant::now())
        .min(REQUEST_TIMEOUT);
    if timeout.is_zero() {
        return Err(FetchError::terminal("research deadline exceeded"));
    }
    let mut response = client
        .get(parsed_url)
        .timeout(timeout)
        .send()
        .map_err(|error| classify_transport_error(budget, cancellation, "HTTP request", error))?;
    budget
        .ensure_available(cancellation)
        .map_err(|error| FetchError::terminal(error.to_string()))?;
    let response_url = response.url();
    if response_url.scheme() != "https" || response_url.host_str() != Some(expected_host) {
        return Err("provider response URL escaped fixed HTTPS endpoint".into());
    }
    if !response.status().is_success() {
        return Err(format!("HTTP status {}", response.status().as_u16()).into());
    }
    let global_remaining = budget.remaining().bytes;
    let response_limit = global_remaining.min(MAX_RESPONSE_BYTES);
    if response_limit == 0 {
        return Err(FetchError::terminal("research byte budget exhausted"));
    }
    if let Some(length) = response.content_length() {
        if length > global_remaining {
            return Err(FetchError::terminal(format!(
                "research byte budget exceeded: response has {length} bytes, {global_remaining} remain"
            )));
        }
        if length > MAX_RESPONSE_BYTES {
            return Err(format!("HTTP response exceeds {MAX_RESPONSE_BYTES} byte limit").into());
        }
    }
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        budget
            .ensure_available(cancellation)
            .map_err(|error| FetchError::terminal(error.to_string()))?;
        let remaining = response_limit.saturating_sub(body.len() as u64);
        if remaining == 0 {
            if response.content_length() == Some(body.len() as u64) {
                break;
            }
            if global_remaining < MAX_RESPONSE_BYTES {
                return Err(FetchError::terminal(
                    "research byte budget exhausted during response",
                ));
            }
            return Err(format!("HTTP response reached {response_limit} byte limit").into());
        }
        let read_limit = remaining.min(chunk.len() as u64) as usize;
        let read = response.read(&mut chunk[..read_limit]).map_err(|error| {
            classify_transport_error(budget, cancellation, "HTTP response read", error)
        })?;
        if read == 0 {
            break;
        }
        budget
            .reserve_bytes(read as u64, cancellation)
            .map_err(|error| FetchError::terminal(error.to_string()))?;
        body.extend_from_slice(&chunk[..read]);
    }
    budget
        .ensure_available(cancellation)
        .map_err(|error| FetchError::terminal(error.to_string()))?;
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|error| format!("malformed provider JSON: {error}"))?;
    validate_live_payload(verifier, doi, &payload)?;
    Ok(FetchResponse {
        payload,
        provenance: json!({
            "provider": verifier.python_name().trim_start_matches('_'),
            "url": url,
            "retrieved_at": super::utc_now(),
            "payload_sha256": hex::encode(Sha256::digest(&body)),
            "bytes": body.len(),
        }),
    })
}

fn validate_doi_path(doi: &str) -> Result<(), String> {
    if doi.is_empty()
        || doi
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err("DOI contains an invalid or traversal path segment".into());
    }
    Ok(())
}

fn classify_transport_error(
    budget: &BudgetAccount,
    cancellation: &Cancellation,
    phase: &str,
    error: impl std::fmt::Display,
) -> FetchError {
    if cancellation.is_cancelled() {
        FetchError::terminal(format!(
            "research workflow cancelled during {phase}: {error}"
        ))
    } else if std::time::Instant::now() >= budget.deadline() {
        FetchError::terminal(format!(
            "research workflow deadline exceeded during {phase}: {error}"
        ))
    } else {
        FetchError::from(format!("{phase} failed: {error}"))
    }
}

/// Require identity and typed provider fields before treating live metadata as
/// a verification result. Fixture data remains explicitly labeled separately.
pub fn validate_live_payload(verifier: Verifier, doi: &str, payload: &Value) -> Result<(), String> {
    let object = payload
        .as_object()
        .ok_or_else(|| "provider payload is not an object".to_string())?;
    match verifier {
        Verifier::OpenAlex => {
            let response_doi = object
                .get("doi")
                .and_then(Value::as_str)
                .ok_or_else(|| "openalex response doi is missing or not a string".to_string())?;
            if normalize_doi(response_doi) != normalize_doi(doi) {
                return Err("openalex response DOI does not match request".into());
            }
            if object.get("id").and_then(Value::as_str).is_none() {
                return Err("openalex response id is missing or not a string".into());
            }
            if object
                .get("is_retracted")
                .and_then(Value::as_bool)
                .is_none()
            {
                return Err("openalex is_retracted is missing or not a boolean".into());
            }
        }
        Verifier::Crossref => {
            let message = object
                .get("message")
                .and_then(Value::as_object)
                .ok_or_else(|| "crossref message is missing or not an object".to_string())?;
            let response_doi = message
                .get("DOI")
                .and_then(Value::as_str)
                .ok_or_else(|| "crossref response DOI is missing or not a string".to_string())?;
            if normalize_doi(response_doi) != normalize_doi(doi) {
                return Err("crossref response DOI does not match request".into());
            }
            let mut has_typed_retraction_metadata = false;
            if let Some(update_to) = message.get("update-to") {
                match update_to {
                    Value::Null => {}
                    Value::Array(entries) => {
                        has_typed_retraction_metadata = true;
                        for entry in entries {
                            let entry = entry.as_object().ok_or_else(|| {
                                "crossref update-to entry is not an object".to_string()
                            })?;
                            if entry.get("type").and_then(Value::as_str).is_none() {
                                return Err(
                                    "crossref update-to type is missing or not a string".into()
                                );
                            }
                        }
                    }
                    _ => return Err("crossref update-to is not a list".to_string()),
                }
            }
            if let Some(relation) = message.get("relation") {
                match relation {
                    Value::Null => {}
                    Value::Object(relation) => {
                        has_typed_retraction_metadata = true;
                        if let Some(retracted_by) = relation.get("is-retracted-by") {
                            match retracted_by {
                                Value::Null => {}
                                Value::Array(entries) => {
                                    has_typed_retraction_metadata = true;
                                    if entries.iter().any(|entry| !entry.is_object()) {
                                        return Err(
                                            "crossref is-retracted-by entry is not an object"
                                                .into(),
                                        );
                                    }
                                }
                                _ => return Err("crossref is-retracted-by is not a list".into()),
                            }
                        }
                    }
                    _ => return Err("crossref relation is not an object".to_string()),
                }
            }
            if !has_typed_retraction_metadata {
                return Err("crossref retraction metadata is missing".into());
            }
        }
    }
    Ok(())
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
    fetch: &dyn Fn(Verifier, &str) -> Result<FetchResponse, FetchError>,
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
                let fixture_bytes = serde_json::to_vec(entry).unwrap_or_default();
                row.insert(
                    "provenance".to_string(),
                    json!({
                        "kind": "fixture",
                        "provider": "caller-supplied",
                        "payload_sha256": hex::encode(Sha256::digest(fixture_bytes)),
                    }),
                );
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
    let mut terminal_error = None;
    for verifier in [Verifier::OpenAlex, Verifier::Crossref] {
        let outcome = fetch(verifier, &doi).and_then(|fetched| {
            let mut parsed = match verifier {
                Verifier::OpenAlex => parse_openalex(&fetched.payload),
                Verifier::Crossref => parse_crossref(&fetched.payload),
            }
            .map_err(FetchError::from)?;
            if let Value::Object(fields) = &mut parsed {
                fields.insert("provenance".into(), fetched.provenance);
            }
            Ok(parsed)
        });
        match outcome {
            Ok(row) => results.push(row),
            Err(error) => {
                let message = format!(
                    "{}: {}",
                    verifier.python_name(),
                    truncate_chars(&error.message, 200)
                );
                errors.push(message.clone());
                if error.terminal {
                    terminal_error = Some(message);
                    break;
                }
            }
        }
    }

    if let Some(reason) = terminal_error {
        return json!({
            "doi": doi,
            "status": "unknown",
            "retracted": null,
            "sources": results,
            "errors": errors,
            "terminal_failure": reason,
        });
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
    if !retracted && !errors.is_empty() {
        return json!({
            "doi": doi,
            "status": "unknown",
            "retracted": null,
            "sources": results,
            "errors": errors,
        });
    }
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
    fetch: &dyn Fn(Verifier, &str) -> Result<FetchResponse, FetchError>,
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
    let terminal_failure = results
        .iter()
        .any(|row| row.get("terminal_failure").is_some());
    let unknown_count = results
        .iter()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("unknown"))
        .count();
    json!({
        "dois_checked": results.len(),
        "results": results,
        "block_brief": block_brief,
        "unknown_count": unknown_count,
        "terminal_failure": terminal_failure,
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

/// True when a cancellation, deadline, or budget stop interrupted verification.
pub fn has_terminal_failure(sweep_result: &Value) -> bool {
    sweep_result["terminal_failure"].as_bool() == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_network(verifier: Verifier, doi: &str) -> Result<FetchResponse, FetchError> {
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
        assert_eq!(undisclosed["results"][0]["provenance"]["kind"], "fixture");
        assert!(undisclosed["results"][0]["provenance"]["payload_sha256"]
            .as_str()
            .is_some());

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
        assert!(validate_doi_path("10.1/../../authors").is_err());
        assert!(validate_doi_path("10.1/valid.path").is_ok());
    }

    #[test]
    fn live_payload_requires_matching_identity_and_typed_retraction_metadata() {
        assert!(validate_live_payload(
            Verifier::OpenAlex,
            "10.1/example",
            &json!({"doi":"https://doi.org/10.1/example", "id":"W1", "is_retracted":false})
        )
        .is_ok());
        assert!(validate_live_payload(
            Verifier::OpenAlex,
            "10.1/example",
            &json!({"doi":"10.1/other", "id":"W1", "is_retracted":false})
        )
        .is_err());
        assert!(validate_live_payload(
            Verifier::OpenAlex,
            "10.1/example",
            &json!({"doi":"10.1/example", "id":"W1", "is_retracted":"false"})
        )
        .is_err());
        assert!(validate_live_payload(
            Verifier::Crossref,
            "10.1/example",
            &json!({"message":{"DOI":"10.1/example", "update-to":[{"type":"retraction"}]}})
        )
        .is_ok());
        assert!(validate_live_payload(
            Verifier::Crossref,
            "10.1/example",
            &json!({"message":{"DOI":"10.1/example", "update-to":[{"type":4}]}})
        )
        .is_err());
        assert!(validate_live_payload(
            Verifier::Crossref,
            "10.1/example",
            &json!({"message":{"DOI":"10.1/example"}})
        )
        .is_err());
    }

    #[test]
    fn partial_clean_verification_is_unknown_but_positive_retraction_still_blocks() {
        let fetch = |verifier, _doi: &str| match verifier {
            Verifier::OpenAlex => Ok(FetchResponse {
                payload: json!({"is_retracted": false, "id": "W1"}),
                provenance: json!({"kind":"test"}),
            }),
            Verifier::Crossref => Err("HTTP status 503".into()),
        };
        let partial_clean = check_doi("10.1/example", None, &fetch);
        assert_eq!(partial_clean["status"], "unknown");
        assert_eq!(partial_clean["retracted"], Value::Null);

        let positive = |verifier, _doi: &str| match verifier {
            Verifier::OpenAlex => Ok(FetchResponse {
                payload: json!({"is_retracted": true, "id": "W1"}),
                provenance: json!({"kind":"test"}),
            }),
            Verifier::Crossref => Err("malformed provider JSON".into()),
        };
        let confirmed = check_doi("10.1/example", None, &positive);
        assert_eq!(confirmed["status"], "verified");
        assert_eq!(confirmed["retracted"], true);
    }

    #[test]
    fn terminal_stop_overrides_allow_unknown_and_partial_positive_results() {
        let terminal = |verifier, _doi: &str| match verifier {
            Verifier::OpenAlex => Ok(FetchResponse {
                payload: json!({"is_retracted": true, "id": "W1"}),
                provenance: json!({"kind":"test"}),
            }),
            Verifier::Crossref => Err(FetchError::terminal("research workflow cancelled")),
        };
        let result = sweep(&["10.1/example".into()], &[], false, None, &terminal);
        assert_eq!(result["results"][0]["status"], "unknown");
        assert_eq!(result["results"][0]["retracted"], Value::Null);
        assert_eq!(result["block_brief"], false);
        assert!(has_terminal_failure(&result));
    }
}
