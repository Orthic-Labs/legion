//! Port of src/lib/coverage/index.mjs.
//!
//! `validateCoverageEvidence` is pure and ported directly. `validateCoverageRegistry`
//! in JS reads corpus/artifact/qualification files off disk (`corpusDigest`,
//! `readFileSync`) and a provider registry; those reads are injected here via
//! `CoverageIo` so the tier-ordering and cross-record rules are testable
//! without a real repository tree. `accountCoverage` is pure and ported
//! directly.

use serde_json::{Map, Value};

pub const TIERS: [&str; 7] = [
    "inventory", "parser", "native", "cross-file", "measured-pack", "runtime", "remediation",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageError(pub String);
impl std::fmt::Display for CoverageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CoverageError {}

/// Port of `validateCoverageEvidence`.
pub fn validate_coverage_evidence(record: &Value, qualification: &Value, artifact: &Value, corpus: &Value) -> Result<(), CoverageError> {
    let id = record.get("id").and_then(Value::as_str).unwrap_or_default();
    let err = |msg: &str| Err(CoverageError(format!("{id} {msg}")));

    if qualification.get("recordId").and_then(Value::as_str) != Some(id)
        || artifact.get("recordId").and_then(Value::as_str) != Some(id)
    {
        return err("qualification record mismatch");
    }
    let same = |a: &str, b: &str| {
        qualification.get(a).and_then(Value::as_str) == record.get(b).and_then(Value::as_str)
    };
    if !same("corpusRoot", "corpusRoot") || !same("corpusDigest", "corpusDigest") || !same("artifactDigest", "artifactDigest") {
        return err("qualification digest binding mismatch");
    }
    let equal_json = |a: Option<&Value>, b: Option<&Value>| {
        serde_json::to_string(&a.cloned().unwrap_or(Value::Null)).ok()
            == serde_json::to_string(&b.cloned().unwrap_or(Value::Null)).ok()
    };
    if !equal_json(qualification.get("providerVersions"), record.get("providerVersions"))
        || !equal_json(artifact.get("providerVersions"), record.get("providerVersions"))
    {
        return err("qualification provider versions mismatch");
    }
    let mut required: Vec<String> = qualification
        .get("casesRequired")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    required.sort();
    let mut cases: Vec<String> = corpus
        .get("cases")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|c| c.get("id").and_then(Value::as_str).map(String::from)).collect())
        .unwrap_or_default();
    cases.sort();
    if required.is_empty() || required != cases {
        return err("qualification cases mismatch");
    }
    let raw_log_digest_ok = artifact
        .get("rawLog")
        .and_then(|r| r.get("digest"))
        .and_then(Value::as_str)
        .is_some_and(|d| is_sha256(d));
    let status_ok = artifact.get("status").and_then(Value::as_str) == Some("pass");
    let test_path_ok = artifact.get("testPath").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    let raw_log_path_ok = artifact.get("rawLog").and_then(|r| r.get("path")).and_then(Value::as_str).is_some();
    let bytes_ok = artifact
        .get("rawLog")
        .and_then(|r| r.get("bytes"))
        .is_some_and(|b| b.is_i64() || b.is_u64());
    if !status_ok || !test_path_ok || !raw_log_path_ok || !raw_log_digest_ok || !bytes_ok {
        return err("qualification test artifact invalid");
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
}

fn tiers_monotone(tiers: &Map<String, Value>) -> bool {
    let get = |k: &str| tiers.get(k).and_then(Value::as_i64).unwrap_or(i64::MIN);
    get("parser") <= get("inventory")
        && get("native") <= get("parser")
        && get("cross-file") <= get("native")
        && get("runtime") <= get("measured-pack")
        && get("remediation") <= get("runtime")
}

/// Port of `validateCoverageRegistry`'s record-shape checks (tier integer
/// bounds, tier-schema parity, monotonicity, selected-scope accounting rule,
/// and the runtime→qualificationVersion requirement). The disk-bound
/// measured-pack digest/binding verification (corpus/artifact/qualification
/// file reads) is intentionally not reproduced here — see module docs.
pub fn validate_coverage_record_shape(
    record: &Value,
    providers: &[Value],
) -> Result<(), CoverageError> {
    let id = record.get("id").and_then(Value::as_str).unwrap_or_default();
    let tiers = record
        .get("tiers")
        .and_then(Value::as_object)
        .ok_or_else(|| CoverageError(format!("{id} missing tiers")))?;
    for tier in TIERS {
        let ok = tiers.get(tier).and_then(Value::as_i64).is_some_and(|v| v >= 0);
        if !ok {
            return Err(CoverageError(format!("invalid tier {id}:{tier}")));
        }
    }
    let mut keys: Vec<&String> = tiers.keys().collect();
    keys.sort();
    let mut expected: Vec<&str> = TIERS.to_vec();
    expected.sort();
    if keys.iter().map(|s| s.as_str()).collect::<Vec<_>>() != expected {
        return Err(CoverageError(format!("{id} tier schema parity mismatch")));
    }
    if !tiers_monotone(tiers) {
        return Err(CoverageError(format!("{id} coverage tiers must be monotone")));
    }
    let measured_pack = tiers.get("measured-pack").and_then(Value::as_i64).unwrap_or(0) != 0;
    if measured_pack {
        let record_providers: Vec<&str> = record
            .get("providers")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let accounting: Vec<&str> = record_providers
            .iter()
            .filter(|pid| {
                providers
                    .iter()
                    .find(|p| p.get("id").and_then(Value::as_str) == Some(*pid))
                    .and_then(|p| p.get("denominatorKind"))
                    .and_then(Value::as_str)
                    == Some("selected-scope")
            })
            .copied()
            .collect();
        if !accounting.is_empty() && accounting.len() == record_providers.len() {
            return Err(CoverageError(format!(
                "{id} claims measured-pack over accounting-only providers ({}); that tier measures rule output, which these do not emit",
                accounting.join(", ")
            )));
        }
    }
    let runtime = tiers.get("runtime").and_then(Value::as_i64).unwrap_or(0) != 0;
    if runtime && record.get("qualificationVersion").is_none() {
        return Err(CoverageError("runtime tier requires qualification".to_string()));
    }
    Ok(())
}

/// Port of `accountCoverage`.
pub fn account_coverage(detected: &[String], registry_records: &[Value]) -> Vec<Value> {
    let mut by_alias: std::collections::HashMap<String, &Value> = std::collections::HashMap::new();
    for record in registry_records {
        let id = record.get("id").and_then(Value::as_str).unwrap_or_default();
        by_alias.insert(id.to_string(), record);
        for key in ["aliases", "extensions"] {
            if let Some(arr) = record.get(key).and_then(Value::as_array) {
                for alias in arr.iter().filter_map(Value::as_str) {
                    by_alias.insert(alias.to_string(), record);
                }
            }
        }
    }
    detected
        .iter()
        .map(|value| {
            by_alias.get(value).cloned().cloned().unwrap_or_else(|| {
                let mut tiers = Map::new();
                for tier in TIERS {
                    tiers.insert(tier.to_string(), Value::from(0));
                }
                Value::Object(Map::from_iter([
                    ("id".to_string(), Value::from(format!("unknown.{value}"))),
                    ("kind".to_string(), Value::from("unknown")),
                    ("tiers".to_string(), Value::Object(tiers)),
                    ("limitations".to_string(), Value::Array(vec![Value::from("unaccounted format")])),
                    ("cleanClaim".to_string(), Value::from("never")),
                ]))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok_bundle() -> (Value, Value, Value, Value) {
        let record = json!({"id": "r1", "corpusRoot": "corpus", "corpusDigest": "cd", "artifactDigest": "ad", "providerVersions": {"eslint": "1.0"}});
        let qualification = json!({"recordId": "r1", "corpusRoot": "corpus", "corpusDigest": "cd", "artifactDigest": "ad", "providerVersions": {"eslint": "1.0"}, "casesRequired": ["c1"]});
        let artifact = json!({"recordId": "r1", "providerVersions": {"eslint": "1.0"}, "status": "pass", "testPath": "t.rs", "rawLog": {"path": "log.txt", "digest": format!("sha256:{}", "a".repeat(64)), "bytes": 10}});
        let corpus = json!({"cases": [{"id": "c1"}]});
        (record, qualification, artifact, corpus)
    }

    #[test]
    fn validate_coverage_evidence_accepts_bound_bundle() {
        let (record, qualification, artifact, corpus) = ok_bundle();
        assert!(validate_coverage_evidence(&record, &qualification, &artifact, &corpus).is_ok());
    }

    #[test]
    fn validate_coverage_evidence_rejects_record_id_mismatch() {
        let (record, mut qualification, artifact, corpus) = ok_bundle();
        qualification["recordId"] = json!("other");
        assert!(validate_coverage_evidence(&record, &qualification, &artifact, &corpus).is_err());
    }

    #[test]
    fn validate_coverage_evidence_rejects_bad_raw_log_digest() {
        let (record, qualification, mut artifact, corpus) = ok_bundle();
        artifact["rawLog"]["digest"] = json!("not-a-digest");
        assert!(validate_coverage_evidence(&record, &qualification, &artifact, &corpus).is_err());
    }

    fn sample_tiers(measured_pack: i64, runtime: i64) -> Value {
        json!({
            "inventory": 10, "parser": 8, "native": 6, "cross-file": 4,
            "measured-pack": measured_pack, "runtime": runtime, "remediation": 0,
        })
    }

    #[test]
    fn record_shape_rejects_non_monotone_tiers() {
        let record = json!({"id": "r1", "tiers": {
            "inventory": 1, "parser": 5, "native": 0, "cross-file": 0,
            "measured-pack": 0, "runtime": 0, "remediation": 0,
        }});
        assert!(validate_coverage_record_shape(&record, &[]).is_err());
    }

    #[test]
    fn record_shape_requires_qualification_version_for_runtime_tier() {
        let record = json!({"id": "r1", "tiers": sample_tiers(1, 1)});
        assert!(validate_coverage_record_shape(&record, &[]).is_err());
        let record2 = json!({"id": "r1", "tiers": sample_tiers(1, 1), "qualificationVersion": "v1"});
        assert!(validate_coverage_record_shape(&record2, &[]).is_ok());
    }

    #[test]
    fn record_shape_rejects_measured_pack_over_accounting_only_providers() {
        let record = json!({"id": "r1", "tiers": sample_tiers(2, 0), "providers": ["scope-provider"]});
        let providers = vec![json!({"id": "scope-provider", "denominatorKind": "selected-scope"})];
        assert!(validate_coverage_record_shape(&record, &providers).is_err());
    }

    #[test]
    fn account_coverage_falls_back_to_unknown_for_unaccounted_formats() {
        let out = account_coverage(&["mystery-ext".to_string()], &[]);
        assert_eq!(out[0]["id"], "unknown.mystery-ext");
        assert_eq!(out[0]["cleanClaim"], "never");
    }

    #[test]
    fn account_coverage_resolves_via_alias() {
        let registry = vec![json!({"id": "rust", "aliases": ["rs"]})];
        let out = account_coverage(&["rs".to_string()], &registry);
        assert_eq!(out[0]["id"], "rust");
    }
}
