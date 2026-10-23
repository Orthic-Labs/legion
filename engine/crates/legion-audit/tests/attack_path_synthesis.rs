use std::{fs, path::PathBuf};

use legion_audit::native_providers::security::attack_paths::{synthesize, Bounds, Registry};
use serde_json::{json, Value};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/attack-paths")
        .join(name);
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn registry() -> Registry {
    Registry::embedded().unwrap()
}

fn gap_codes(doc: &Value) -> Vec<String> {
    doc["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["code"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn ssrf_metadata_credential_chain_is_a_hypothesis_not_a_finding() {
    let doc = synthesize(
        Some(&fixture("model.json")),
        Some(&fixture("candidates-ssrf-chain.json")),
        &Bounds::default(),
        &registry(),
    );
    assert_eq!(doc["coverage"], "BOUNDED_COMPLETE");
    assert!(doc["coverageGaps"].as_array().unwrap().is_empty());
    assert_eq!(doc["claims"]["exhaustive"], false);
    assert_eq!(doc["authority"]["publishesFindings"], false);
    let hyps = doc["hypotheses"].as_array().unwrap();
    assert_eq!(hyps.len(), 1, "{doc:#}");
    let h = &hyps[0];
    assert_eq!(h["status"], "hypothesis");
    assert_eq!(h["adjudicationState"], "PROPOSED");
    assert_eq!(h["priority"], "PRIVILEGE_ESCALATION");
    assert_eq!(
        h["memberCandidateIds"],
        json!([
            "sha256:c1-ssrf",
            "sha256:c2-metadata-read",
            "sha256:c3-control-plane"
        ])
    );
    assert_eq!(h["start"]["entrypoint"], "source:http.fetch-url");
    assert_eq!(h["hops"], 2);
    assert_eq!(h["unsupportedEdgeCount"], 0);
    let edges = h["edges"].as_array().unwrap();
    assert_eq!(edges[0]["bridge"], "bridge.internal-reach-to-service-entry");
    assert_eq!(
        edges[0]["modelRelationIds"],
        json!(["rel:fetch-can-reach-metadata"])
    );
    assert_eq!(edges[1]["bridge"], "bridge.credential-data-to-possession");
    assert_eq!(
        h["missingRequiredControls"],
        json!(["control:egress-allowlist"])
    );
    assert!(h["templateIds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "template.ssrf-to-credential-to-control-plane"));
    assert!(h["id"].as_str().unwrap().starts_with("sha256:"));
    let text = doc.to_string();
    assert!(!text.contains("\"verdict\"") && !text.contains("\"PROVEN\""));
}

#[test]
fn missing_model_relation_makes_the_edge_unsupported() {
    let mut model = fixture("model.json");
    model["relations"] = json!([]);
    let doc = synthesize(
        Some(&model),
        Some(&fixture("candidates-ssrf-chain.json")),
        &Bounds::default(),
        &registry(),
    );
    let h = &doc["hypotheses"][0];
    assert_eq!(h["unsupportedEdgeCount"], 1);
    assert_eq!(h["edges"][0]["evidenceState"], "unsupported");
    assert_eq!(h["weakestEdgeStrength"], "possible");
    assert!(!h["unsupportedAssertions"].as_array().unwrap().is_empty());
}

#[test]
fn non_composable_pair_yields_no_hypothesis_and_no_assurance_claim() {
    let doc = synthesize(
        Some(&fixture("model.json")),
        Some(&fixture("candidates-non-composable.json")),
        &Bounds::default(),
        &registry(),
    );
    assert!(doc["hypotheses"].as_array().unwrap().is_empty());
    assert_eq!(doc["claims"]["exhaustive"], false);
    assert_eq!(doc["claims"]["pathsProven"], 0);
}

#[test]
fn missing_model_is_unproven_not_no_paths() {
    let doc = synthesize(
        None,
        Some(&fixture("candidates-ssrf-chain.json")),
        &Bounds::default(),
        &registry(),
    );
    assert_eq!(doc["coverage"], "UNPROVEN");
    assert!(gap_codes(&doc).contains(&"security-model-missing".to_owned()));
    assert!(doc["hypotheses"].as_array().unwrap().is_empty());
}

#[test]
fn zero_candidates_is_unproven() {
    let doc = synthesize(
        Some(&fixture("model.json")),
        Some(&json!([])),
        &Bounds::default(),
        &registry(),
    );
    assert_eq!(doc["coverage"], "UNPROVEN");
    assert!(gap_codes(&doc).contains(&"no-candidates".to_owned()));
    let doc = synthesize(
        Some(&fixture("model.json")),
        None,
        &Bounds::default(),
        &registry(),
    );
    assert_eq!(doc["coverage"], "UNPROVEN");
}

#[test]
fn invalid_bounds_are_unproven() {
    let bounds = Bounds {
        max_hops: 0,
        ..Bounds::default()
    };
    let doc = synthesize(
        Some(&fixture("model.json")),
        Some(&fixture("candidates-ssrf-chain.json")),
        &bounds,
        &registry(),
    );
    assert_eq!(doc["coverage"], "UNPROVEN");
    assert!(gap_codes(&doc).contains(&"bounds-invalid".to_owned()));
}

#[test]
fn hop_bound_truncation_is_reported_as_gap() {
    let bounds = Bounds {
        max_hops: 1,
        ..Bounds::default()
    };
    let doc = synthesize(
        Some(&fixture("model.json")),
        Some(&fixture("candidates-ssrf-chain.json")),
        &bounds,
        &registry(),
    );
    assert_eq!(doc["coverage"], "TRUNCATED");
    assert!(gap_codes(&doc).contains(&"max-hops-reached".to_owned()));
    assert!(doc["hypotheses"].as_array().unwrap().is_empty());
}

fn fan_out(count: usize) -> Value {
    let mut list = vec![json!({
        "id": "sha256:start",
        "chainRoles": ["starter"],
        "sources": ["source:http.fetch-url"],
        "effects": [{ "kind": "control-bypass", "action": "bypass" }]
    })];
    for i in 0..count {
        list.push(json!({
            "id": format!("sha256:exec-{i:03}"),
            "preconditions": [{ "kind": "control-bypass", "action": "bypass" }],
            "effects": [{ "kind": "code-execution", "action": "execute" }]
        }));
    }
    Value::Array(list)
}

#[test]
fn branching_and_hypothesis_bounds_report_gaps() {
    let model = fixture("model.json");
    let doc = synthesize(
        Some(&model),
        Some(&fan_out(15)),
        &Bounds::default(),
        &registry(),
    );
    assert!(gap_codes(&doc).contains(&"max-branching-reached".to_owned()));
    assert_eq!(doc["hypotheses"].as_array().unwrap().len(), 12);
    assert_eq!(doc["coverage"], "TRUNCATED");

    let bounds = Bounds {
        max_hypotheses: 5,
        max_per_objective: 8,
        ..Bounds::default()
    };
    let doc = synthesize(Some(&model), Some(&fan_out(10)), &bounds, &registry());
    let codes = gap_codes(&doc);
    assert!(codes.contains(&"max-per-objective-reached".to_owned()));
    assert_eq!(doc["hypotheses"].as_array().unwrap().len(), 8.min(5));

    let bounds = Bounds {
        max_visited_paths: 3,
        ..Bounds::default()
    };
    let doc = synthesize(Some(&model), Some(&fan_out(10)), &bounds, &registry());
    assert!(gap_codes(&doc).contains(&"visit-budget-exhausted".to_owned()));
}

#[test]
fn output_is_deterministic_and_input_order_independent() {
    let model = fixture("model.json");
    let candidates = fixture("candidates-ssrf-chain.json");
    let first = synthesize(
        Some(&model),
        Some(&candidates),
        &Bounds::default(),
        &registry(),
    );
    let second = synthesize(
        Some(&model),
        Some(&candidates),
        &Bounds::default(),
        &registry(),
    );
    assert_eq!(first, second);

    let mut reversed = candidates.clone();
    reversed["candidates"].as_array_mut().unwrap().reverse();
    let third = synthesize(
        Some(&model),
        Some(&reversed),
        &Bounds::default(),
        &registry(),
    );
    assert_eq!(first["hypotheses"], third["hypotheses"]);

    let big = fan_out(9);
    let mut shuffled = big.as_array().unwrap().clone();
    shuffled.reverse();
    let a = synthesize(Some(&model), Some(&big), &Bounds::default(), &registry());
    let b = synthesize(
        Some(&model),
        Some(&Value::Array(shuffled)),
        &Bounds::default(),
        &registry(),
    );
    assert_eq!(a["hypotheses"], b["hypotheses"]);
}
