// Behavioural parity test for `imported.sarif` against
// src/providers/imported-sarif/index.mjs, exercised on the production dispatch path
// (SecurityProviderExecutor::analyze).
//
// JS `ingestSarif` throws `'immutable SARIF raw bytes required'` whenever `rawBytes`
// is not a `Buffer` — checked unconditionally, before the digest is computed, even if
// `artifact` was supplied directly. A prior Rust port had no equivalent check:
// `analyze` defaulted a missing/non-string `rawBytes` to an empty byte slice and fell
// straight through to digest comparison, so a SARIF item with an `artifact` payload
// but no real raw bytes could pass validation whenever `expectedDigest` happened to
// equal the digest of the empty byte string, silently bypassing the "raw bytes are
// immutable and were supplied" guarantee the provider exists to enforce.
use std::collections::BTreeMap;

use legion_audit::native_providers::security::adapter::SecurityProviderExecutor;
use legion_audit::native_providers::security::common::digest;
use legion_audit::plan::AuditProvider;
use serde_json::json;

fn provider(id: &str) -> AuditProvider {
    serde_json::from_value(json!({
        "id": id,
        "version": "1.0.0",
        "role": "security",
        "phase": "analysis",
        "lensIds": [],
        "dependencies": [],
        "kind": "typed-external-project-tool",
        "configuration": {},
        "bounds": {},
        "cleanClaim": "candidates-only",
        "benchmarkStatus": "not-required",
        "benchmarkRequiredForCleanClaim": false,
        "qualificationDigest": null,
        "required": false
    }))
    .expect("AuditProvider must deserialize from test fixture")
}

#[test]
fn missing_raw_bytes_is_rejected_even_when_artifact_and_digest_of_empty_bytes_match() {
    let empty_digest = digest(&[]);
    let binding = json!({"revision": "r1", "root": "/repo"});
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "imported.sarif".to_string(),
        json!({
            "plan": {"repositoryBinding": binding},
            "artifacts": {
                "importedSarif": [
                    {
                        // artifact supplied directly, matching binding, and an
                        // expectedDigest that happens to equal sha256("") — the
                        // digest of what an omitted `rawBytes` would default to.
                        "artifact": {"revision": "r1", "baseUri": "/repo", "results": [{"ruleId": "x"}]},
                        "expectedDigest": empty_digest,
                        "toolIdentity": {"name": "tool", "version": "1.0.0"}
                        // rawBytes intentionally absent
                    }
                ]
            }
        }),
    );
    let executor = SecurityProviderExecutor::new(artifacts);
    let result = executor.analyze(&provider("imported.sarif")).unwrap();

    // Must be rejected as a coverage gap, not accepted as a normalized finding.
    assert_eq!(result["complete"], json!(false));
    assert_eq!(result["denominator"]["examined"], json!(0));
    assert!(result["findings"].as_array().unwrap().is_empty());
    let gaps = result["coverageGaps"].as_array().unwrap();
    let reasons: Vec<&str> = gaps
        .iter()
        .filter_map(|g| g["reason"].as_str())
        .collect();
    assert!(
        reasons.contains(&"immutable SARIF raw bytes required"),
        "expected the JS-parity 'immutable SARIF raw bytes required' reason, got {gaps:?}"
    );
}

#[test]
fn valid_matching_raw_bytes_still_ingests_successfully() {
    let raw = b"{\"schemaVersion\":\"2.1.0\",\"revision\":\"r1\",\"baseUri\":\"/repo\",\"results\":[{\"ruleId\":\"ok\"}]}";
    let expected = digest(raw);
    let binding = json!({"revision": "r1", "root": "/repo"});
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "imported.sarif".to_string(),
        json!({
            "plan": {"repositoryBinding": binding},
            "artifacts": {
                "importedSarif": [
                    {
                        "rawBytes": String::from_utf8(raw.to_vec()).unwrap(),
                        "expectedDigest": expected,
                        "toolIdentity": {"name": "tool", "version": "1.0.0"}
                    }
                ]
            }
        }),
    );
    let executor = SecurityProviderExecutor::new(artifacts);
    let result = executor.analyze(&provider("imported.sarif")).unwrap();

    assert_eq!(result["complete"], json!(true));
    assert_eq!(result["denominator"]["examined"], json!(1));
    let findings = result["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["ruleId"], json!("ok"));
    assert!(result["coverageGaps"].as_array().unwrap().is_empty());
}
