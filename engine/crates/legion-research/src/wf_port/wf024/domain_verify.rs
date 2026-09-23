//! Port of `src/lib/research-core/domain_verify.py`.
//!
//! Domain-specific verified-assurance checks for medical and legal routes.
//! Operates on loose JSON documents (route / evidence records / claims) the
//! way the Python CLI did, using `serde_json::Value` rather than this
//! crate's strict typed `ResearchRoute`/`EvidenceRecord`/`Claim` (those use
//! `deny_unknown_fields` and do not carry the domain-specific keys this
//! script reads, such as `study_design`, `pico`, `authority_type`, etc.).

use std::fs;
use std::io;
use std::path::Path;

use serde_json::{json, Map, Value};

/// Mirrors Python's `_present`: falsy-ish emptiness check for `None`, `""`,
/// and `[]` (a JSON null, empty string, or empty array). Any other value,
/// including `0`, `false`, and `{}`, counts as present, matching the
/// original's `value not in (None, "", [])`.
fn present(value: Option<&Value>) -> bool {
    match value {
        None => false,
        Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(_) => true,
    }
}

fn get<'a>(obj: &'a Value, key: &str) -> Option<&'a Value> {
    obj.get(key)
}

/// Mirrors Python's `_legal_authority_ok`.
fn legal_authority_ok(claim_type: &str, evidence: &Value) -> bool {
    if !(present(get(evidence, "authority_type")) && present(get(evidence, "current_as_of"))) {
        return false;
    }
    if claim_type != "case-law" {
        return true;
    }
    present(get(evidence, "forum"))
        && present(get(evidence, "precedential_status"))
        && present(get(evidence, "negative_treatment"))
}

fn str_field<'a>(obj: &'a Value, key: &str) -> &'a str {
    obj.get(key).and_then(Value::as_str).unwrap_or("")
}

fn bool_field(obj: &Value, key: &str) -> bool {
    obj.get(key).map(truthy).unwrap_or(false)
}

/// Python truthiness for an arbitrary JSON value, used where the script
/// relies on `bool(x)` / implicit truthiness (e.g. `route['subject'].get('issue')`,
/// `e.get('patient_history')`, `subject.get(k)`).
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn source_ids(claim: &Value) -> Vec<String> {
    claim
        .get("source_ids")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn matching_sources<'a>(evidence: &'a [Value], claim: &Value) -> Vec<&'a Value> {
    let ids = source_ids(claim);
    evidence
        .iter()
        .filter(|e| {
            e.get("id")
                .and_then(Value::as_str)
                .map(|id| ids.iter().any(|want| want == id))
                .unwrap_or(false)
        })
        .collect()
}

/// Faithful port of `verify(route, evidence, claims)`.
pub fn verify(route: &Value, evidence: &[Value], claims: &[Value]) -> Value {
    let mut checks: Vec<Value> = Vec::new();
    let domain = str_field(route, "domain");

    if domain == "medical" {
        let subject = route.get("subject").cloned().unwrap_or(Value::Null);
        // Python indexes `route['subject']['patient']` unconditionally for
        // the medical branch (a KeyError if absent is the original's
        // behaviour); we mirror that by treating an absent patient as an
        // empty object rather than panicking, since this port must not
        // crash the calling workflow. `checks` below only reads `.get`.
        let issue_ok = truthy(subject.get("issue").unwrap_or(&Value::Null));
        checks.push(json!({"name": "medical.issue", "ok": issue_ok}));

        let patient = subject.get("patient").cloned().unwrap_or(Value::Null);
        let patient_kind = str_field(&patient, "kind");
        let anonymous_has_history = patient_kind == "anonymous"
            && evidence.iter().any(|e| bool_field(e, "patient_history"));
        checks.push(json!({
            "name": "medical.anonymous-no-history",
            "ok": !anonymous_has_history,
        }));

        for claim in claims {
            let claim_type = str_field(claim, "claim_type");
            if matches!(claim_type, "effect-size" | "adverse-event" | "dosing") {
                let sources = matching_sources(evidence, claim);
                let ok = sources.iter().all(|e| {
                    truthy(e.get("study_design").unwrap_or(&Value::Null))
                        && truthy(e.get("pico").unwrap_or(&Value::Null))
                        && truthy(e.get("applicability").unwrap_or(&Value::Null))
                });
                let claim_id = str_field(claim, "id");
                checks.push(json!({
                    "name": format!("medical.pico.{claim_id}"),
                    "ok": ok,
                }));
            }
        }
    } else if domain == "legal" {
        let subject = route.get("subject").cloned().unwrap_or(Value::Null);
        let context_ok = ["country", "area", "issue"]
            .iter()
            .all(|k| truthy(subject.get(*k).unwrap_or(&Value::Null)));
        checks.push(json!({"name": "legal.context", "ok": context_ok}));

        let forbidden = route
            .get("forbidden_resources")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let country = subject.get("country").and_then(Value::as_str);
        let area = subject.get("area").and_then(Value::as_str);
        if country == Some("IN") && area == Some("criminal") {
            checks.push(json!({
                "name": "legal.criminal-consumer-isolation",
                "ok": !forbidden.is_empty(),
            }));
        }

        for claim in claims {
            let claim_type = str_field(claim, "claim_type");
            if matches!(claim_type, "legal" | "case-law") {
                let sources = matching_sources(evidence, claim);
                let ok = sources.iter().all(|e| legal_authority_ok(claim_type, e));
                let claim_id = str_field(claim, "id");
                checks.push(json!({
                    "name": format!("legal.authority.{claim_id}"),
                    "ok": ok,
                }));
            }
        }
    }

    let ok = checks.iter().all(|c| bool_field(c, "ok"));
    let mut out = Map::new();
    out.insert("ok".into(), Value::Bool(ok));
    out.insert("checks".into(), Value::Array(checks));
    Value::Object(out)
}

/// Errors from the file-based entry point, mirroring the CLI's failure
/// modes (I/O and JSON parsing) without the `argparse`/`SystemExit` layer.
#[derive(Debug)]
pub enum RunError {
    Io(io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Io(e) => write!(f, "{e}"),
            RunError::Json(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<io::Error> for RunError {
    fn from(e: io::Error) -> Self {
        RunError::Io(e)
    }
}

impl From<serde_json::Error> for RunError {
    fn from(e: serde_json::Error) -> Self {
        RunError::Json(e)
    }
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>, RunError> {
    let text = fs::read_to_string(path)?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(RunError::from))
        .collect()
}

/// Port of `main`'s file-handling: reads route (JSON), evidence and claims
/// (JSON Lines), runs `verify`, optionally writes the pretty-printed,
/// key-sorted result to `out_path`, and returns `(result, exit_ok)` where
/// `exit_ok` mirrors the original's `0 if result['ok'] else 2` exit code
/// (`true` for 0, `false` for 2).
pub fn run_paths(
    route_path: &Path,
    evidence_path: &Path,
    claims_path: &Path,
    out_path: Option<&Path>,
) -> Result<(Value, bool), RunError> {
    let route: Value = serde_json::from_str(&fs::read_to_string(route_path)?)?;
    let evidence = read_jsonl(evidence_path)?;
    let claims = read_jsonl(claims_path)?;
    let result = verify(&route, &evidence, &claims);
    let ok = bool_field(&result, "ok");
    if let Some(out) = out_path {
        let text = serde_json::to_string_pretty(&sorted_keys(&result))?;
        fs::write(out, format!("{text}\n"))?;
    }
    Ok((result, ok))
}

/// `json.dumps(..., sort_keys=True)` sorts object keys recursively; serde_json's
/// `Value::Object` is a `Map` (insertion-ordered by default) so we rebuild
/// with `BTreeMap` ordering only where it matters for the pretty file. The
/// in-memory `result` returned from `verify` keeps its original key order,
/// only the on-disk copy is re-sorted, matching Python's `sort_keys=True`
/// argument to `json.dumps`.
fn sorted_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), sorted_keys(v));
            }
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sorted_keys).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medical_all_checks_pass() {
        let route = json!({
            "domain": "medical",
            "subject": {
                "issue": "chest pain",
                "patient": {"kind": "named"}
            }
        });
        let evidence = vec![json!({
            "id": "e1",
            "study_design": "RCT",
            "pico": {"p": "adults"},
            "applicability": "general"
        })];
        let claims = vec![json!({
            "id": "c1",
            "claim_type": "effect-size",
            "source_ids": ["e1"]
        })];
        let result = verify(&route, &evidence, &claims);
        assert_eq!(result["ok"], json!(true));
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 3);
        assert_eq!(checks[0], json!({"name": "medical.issue", "ok": true}));
        assert_eq!(
            checks[1],
            json!({"name": "medical.anonymous-no-history", "ok": true})
        );
        assert_eq!(checks[2]["name"], json!("medical.pico.c1"));
        assert_eq!(checks[2]["ok"], json!(true));
    }

    #[test]
    fn medical_anonymous_with_history_fails() {
        let route = json!({
            "domain": "medical",
            "subject": {"issue": "x", "patient": {"kind": "anonymous"}}
        });
        let evidence = vec![json!({"id": "e1", "patient_history": true})];
        let claims: Vec<Value> = vec![];
        let result = verify(&route, &evidence, &claims);
        assert_eq!(result["ok"], json!(false));
        assert_eq!(
            result["checks"][1],
            json!({"name": "medical.anonymous-no-history", "ok": false})
        );
    }

    #[test]
    fn medical_missing_pico_fields_fails_claim() {
        let route = json!({
            "domain": "medical",
            "subject": {"issue": "x", "patient": {"kind": "named"}}
        });
        let evidence = vec![json!({"id": "e1"})];
        let claims = vec![json!({"id": "c1", "claim_type": "dosing", "source_ids": ["e1"]})];
        let result = verify(&route, &evidence, &claims);
        assert_eq!(result["ok"], json!(false));
        assert_eq!(result["checks"][2]["ok"], json!(false));
    }

    #[test]
    fn legal_context_and_authority_pass() {
        let route = json!({
            "domain": "legal",
            "subject": {"country": "US", "area": "civil", "issue": "contract"},
            "forbidden_resources": []
        });
        let evidence = vec![json!({
            "id": "e1",
            "authority_type": "statute",
            "current_as_of": "2026-01-01"
        })];
        let claims = vec![json!({"id": "c1", "claim_type": "legal", "source_ids": ["e1"]})];
        let result = verify(&route, &evidence, &claims);
        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["checks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn legal_in_criminal_requires_forbidden_resources() {
        let route = json!({
            "domain": "legal",
            "subject": {"country": "IN", "area": "criminal", "issue": "x"},
            "forbidden_resources": []
        });
        let result = verify(&route, &[], &[]);
        assert_eq!(result["ok"], json!(false));
        assert_eq!(
            result["checks"][1],
            json!({"name": "legal.criminal-consumer-isolation", "ok": false})
        );
    }

    #[test]
    fn legal_case_law_requires_full_authority_fields() {
        let route = json!({
            "domain": "legal",
            "subject": {"country": "US", "area": "civil", "issue": "x"},
            "forbidden_resources": []
        });
        let evidence = vec![json!({
            "id": "e1",
            "authority_type": "case",
            "current_as_of": "2026-01-01"
            // forum/precedential_status/negative_treatment missing
        })];
        let claims = vec![json!({"id": "c1", "claim_type": "case-law", "source_ids": ["e1"]})];
        let result = verify(&route, &evidence, &claims);
        assert_eq!(result["ok"], json!(false));
        assert_eq!(result["checks"][1]["ok"], json!(false));
    }

    #[test]
    fn unknown_domain_produces_no_checks_and_ok() {
        let route = json!({"domain": "general"});
        let result = verify(&route, &[], &[]);
        assert_eq!(result, json!({"ok": true, "checks": []}));
    }

    #[test]
    fn run_paths_roundtrip_and_exit_code() {
        let dir = std::env::temp_dir().join(format!(
            "legion_wf024_domain_verify_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let route_path = dir.join("route.json");
        let evidence_path = dir.join("evidence.jsonl");
        let claims_path = dir.join("claims.jsonl");
        let out_path = dir.join("out.json");

        fs::write(&route_path, json!({"domain": "general"}).to_string()).unwrap();
        fs::write(&evidence_path, "").unwrap();
        fs::write(&claims_path, "").unwrap();

        let (result, ok) =
            run_paths(&route_path, &evidence_path, &claims_path, Some(&out_path)).unwrap();
        assert!(ok);
        assert_eq!(result, json!({"ok": true, "checks": []}));
        let written = fs::read_to_string(&out_path).unwrap();
        let parsed: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed, json!({"checks": [], "ok": true}));

        let _ = fs::remove_dir_all(&dir);
    }
}
