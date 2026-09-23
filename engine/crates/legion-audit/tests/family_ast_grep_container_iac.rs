// Behavioural parity tests for `structural.ast-grep` and `container.iac`
// against src/providers/ast-grep/index.mjs and src/providers/container-iac/index.mjs,
// exercised on the production dispatch path (SecurityProviderExecutor::analyze).
use std::collections::BTreeMap;

use legion_audit::native_providers::security::adapter::SecurityProviderExecutor;
use legion_audit::native_providers::security::ast_grep::normalize_match;
use legion_audit::AuditProvider;
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

// JS `normalizeMatch` returns an object with exactly these keys: ruleId, severity,
// message, file, range, metavariables, fingerprint, rawArtifactRef. It never includes
// a `provider` field. A prior Rust port added a stray "provider" key not present in
// the JS shape.
#[test]
fn ast_grep_normalize_match_has_no_stray_provider_field() {
    let line = json!({"file": "src/a.rs", "ruleId": "r1", "line": 3, "column": 1});
    let normalized = normalize_match(&line, "r1", Some("ast-grep.structural"), None);
    let obj = normalized.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "fingerprint",
            "file",
            "message",
            "metavariables",
            "range",
            "rawArtifactRef",
            "ruleId",
            "severity",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
    assert!(obj.get("provider").is_none());
}

// JS `analyze` for container-iac does `denominator.gaps.map((kind) => ({ kind }))`
// before pushing further {kind:...} objects onto coverageGaps. Every entry in
// coverageGaps must be a {kind: ...} object, never a bare string.
#[test]
fn container_iac_analyze_wraps_denominator_gaps_as_kind_objects() {
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "container.iac".to_string(),
        json!({
            "projection": {"files": ["Dockerfile"]},
            "artifacts": {
                // no renderedInfrastructure -> denominator gap "rendered-resources-absent"
                // no iacEvidence -> additional "iac-evidence-invalid" gap
            },
            "plan": {}
        }),
    );
    let executor = SecurityProviderExecutor::new(artifacts);
    let result = executor.analyze(&provider("container.iac")).unwrap();
    let gaps = result["coverageGaps"].as_array().unwrap();
    assert!(!gaps.is_empty());
    for gap in gaps {
        assert!(
            gap.is_object() && gap.get("kind").is_some(),
            "every coverageGaps entry must be a {{kind: ...}} object, got {gap:?}"
        );
    }
    let kinds: Vec<&str> = gaps
        .iter()
        .map(|g| g["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"rendered-resources-absent"));
    assert!(kinds.contains(&"iac-evidence-invalid"));
}
