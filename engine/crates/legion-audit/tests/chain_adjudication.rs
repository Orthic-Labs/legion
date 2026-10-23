use legion_audit::native_providers::security::chain_adjudication::{
    adjudicate_chain, build_adjudication_packet, ChainAdjudicationError, ChainAdjudicationInput,
    Strength, NEGATIVE_CONTROL_OUTCOME,
};
use serde_json::{json, Value};

fn binding() -> Value {
    json!({
        "planDigest": "sha256:plan",
        "repositoryRevision": "rev1",
        "dirtyPatchDigest": null,
        "blueprintGenerationId": "gen1",
        "blueprintManifestDigest": "sha256:manifest",
        "registryDigest": "sha256:registry",
    })
}

fn hypothesis() -> Value {
    json!({
        "id": "path-1",
        "binding": binding(),
        "memberCandidateIds": ["c1", "c2"],
        "steps": [{"candidateId": "c1"}, {"candidateId": "c2"}],
        "joins": [{"id": "j1"}],
        "objective": "account takeover",
        "controls": ["waf"],
    })
}

fn member(id: &str, verdict: &str, strength: &str) -> Value {
    json!({
        "candidateId": id,
        "verdict": verdict,
        "evidenceStrength": strength,
        "adjudicatorProvider": "security.adjudication",
        "adjudicatorContextId": format!("member-ctx-{id}"),
    })
}

fn members() -> Vec<Value> {
    vec![
        member("c1", "TRUE_POSITIVE", "verified"),
        member("c2", "TRUE_POSITIVE", "verified"),
    ]
}

fn synthesizer() -> Value {
    json!({"provider": "security.attack-paths", "contextId": "syn-ctx"})
}

fn adjudicator() -> Value {
    json!({"provider": "security.chain-adjudication", "contextId": "adj-ctx"})
}

fn proven_raw() -> Value {
    json!({
        "pathId": "path-1",
        "contextId": "adj-ctx",
        "verdict": "PROVEN",
        "evidenceStrength": "verified",
        "severity": "high",
        "terminalImpact": "account takeover",
        "objectiveReached": true,
        "proof": {"digest": "sha256:proof"},
        "negativeControl": {"kind": "break-join", "rationale": "token rejected", "outcome": NEGATIVE_CONTROL_OUTCOME},
        "compatibility": {"identity": "COMPATIBLE", "environment": "COMPATIBLE", "tenant": "COMPATIBLE", "timing": "COMPATIBLE"},
        "stepAssessments": [
            {"candidateId": "c1", "usableInChain": true},
            {"candidateId": "c2", "usableInChain": true},
        ],
        "joinAssessments": [{"joinId": "j1", "verdict": "VERIFIED"}],
        "controlAssessments": [{"controlId": "waf", "status": "INEFFECTIVE"}],
        "rationale": "composes",
        "devilsAdvocate": "benign explanation rejected",
    })
}

fn run(
    h: &Value,
    m: &[Value],
    syn: &Value,
    adj: &Value,
    raw: &Value,
) -> (String, Vec<String>, Value) {
    let b = binding();
    let v = adjudicate_chain(ChainAdjudicationInput {
        hypothesis: h,
        member_verdicts: m,
        expected_binding: &b,
        synthesizer: syn,
        adjudicator: adj,
        raw_assessment: raw,
        required_strength: Strength::Verified,
    });
    (v.verdict, v.reasons, v.value)
}

fn expect_unproven(reasons: &[String], verdict: &str, needle: &str) {
    assert_eq!(verdict, "UNPROVEN", "{reasons:?}");
    assert!(
        reasons.iter().any(|r| r.contains(needle)),
        "{needle}: {reasons:?}"
    );
}

#[test]
fn fully_supported_chain_is_proven() {
    let (verdict, reasons, value) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &proven_raw(),
    );
    assert_eq!(verdict, "PROVEN", "{reasons:?}");
    assert_eq!(value["severity"], json!("high"));
    assert_eq!(
        value["memberVerdicts"][0]["verdict"],
        json!("TRUE_POSITIVE")
    );
    assert!(value["verdictDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn missing_negative_control_is_unproven() {
    let mut raw = proven_raw();
    raw.as_object_mut().unwrap().remove("negativeControl");
    let (v, r, value) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "negative control");
    assert_eq!(value["severity"], Value::Null);
}

#[test]
fn untyped_or_unconfirmed_negative_control_is_unproven() {
    let mut raw = proven_raw();
    raw["negativeControl"] = json!({"rationale": "x"});
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "negative control");
    raw["negativeControl"] =
        json!({"kind": "break-join", "rationale": "x", "outcome": "chain-still-works"});
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "negative control");
}

#[test]
fn self_synthesis_same_provider_is_unproven() {
    let adj = json!({"provider": "security.attack-paths", "contextId": "adj-ctx"});
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adj,
        &proven_raw(),
    );
    expect_unproven(&r, &v, "own path");
}

#[test]
fn same_or_missing_context_is_unproven() {
    let adj = json!({"provider": "security.chain-adjudication", "contextId": "syn-ctx"});
    let mut raw = proven_raw();
    raw["contextId"] = json!("syn-ctx");
    let (v, r, _) = run(&hypothesis(), &members(), &synthesizer(), &adj, &raw);
    expect_unproven(&r, &v, "synthesizing context");

    let adj = json!({"provider": "security.chain-adjudication"});
    let mut raw = proven_raw();
    raw.as_object_mut().unwrap().remove("contextId");
    let (v, r, _) = run(&hypothesis(), &members(), &synthesizer(), &adj, &raw);
    expect_unproven(&r, &v, "context id is missing");
}

#[test]
fn weak_member_blocks_proof_and_is_never_upgraded() {
    let mut m = members();
    m[1] = member("c2", "TRUE_POSITIVE", "strong-inference");
    let (v, r, value) = run(
        &hypothesis(),
        &m,
        &synthesizer(),
        &adjudicator(),
        &proven_raw(),
    );
    expect_unproven(&r, &v, "below required");
    assert_eq!(
        value["memberVerdicts"][1]["evidenceStrength"],
        json!("strong-inference")
    );
}

#[test]
fn chain_strength_cannot_exceed_weakest_member() {
    let mut m = members();
    m[0] = member("c1", "LIKELY_TRUE_POSITIVE", "strong-inference");
    let b = binding();
    let raw = proven_raw();
    let v = adjudicate_chain(ChainAdjudicationInput {
        hypothesis: &hypothesis(),
        member_verdicts: &m,
        expected_binding: &b,
        synthesizer: &synthesizer(),
        adjudicator: &adjudicator(),
        raw_assessment: &raw,
        required_strength: Strength::StrongInference,
    });
    expect_unproven(&v.reasons, &v.verdict, "exceeds its weakest member");
}

#[test]
fn false_positive_missing_or_self_adjudicated_member_is_unproven() {
    let mut m = members();
    m[0] = member("c1", "FALSE_POSITIVE", "verified");
    let (v, r, _) = run(
        &hypothesis(),
        &m,
        &synthesizer(),
        &adjudicator(),
        &proven_raw(),
    );
    expect_unproven(&r, &v, "did not survive");

    let m = vec![member("c1", "TRUE_POSITIVE", "verified")];
    let (v, r, _) = run(
        &hypothesis(),
        &m,
        &synthesizer(),
        &adjudicator(),
        &proven_raw(),
    );
    expect_unproven(&r, &v, "no adjudicated verdict");

    let mut m = members();
    m[1]["adjudicatorContextId"] = json!("syn-ctx");
    let (v, r, _) = run(
        &hypothesis(),
        &m,
        &synthesizer(),
        &adjudicator(),
        &proven_raw(),
    );
    expect_unproven(&r, &v, "independently adjudicated");
}

#[test]
fn unverified_join_effective_control_and_incompatibility_are_unproven() {
    let mut raw = proven_raw();
    raw["joinAssessments"] = json!([{"joinId": "j1", "verdict": "UNVERIFIED"}]);
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "VERIFIED");

    let mut raw = proven_raw();
    raw["controlAssessments"] = json!([{"controlId": "waf", "status": "EFFECTIVE"}]);
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "control");

    let mut raw = proven_raw();
    raw["controlAssessments"] = json!([]);
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "not evaluated");

    let mut raw = proven_raw();
    raw["compatibility"]["tenant"] = json!("UNKNOWN");
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "tenant");
}

#[test]
fn binding_mismatch_and_wrong_path_are_unproven() {
    let mut h = hypothesis();
    h["binding"]["repositoryRevision"] = json!("other");
    let (v, r, _) = run(
        &h,
        &members(),
        &synthesizer(),
        &adjudicator(),
        &proven_raw(),
    );
    expect_unproven(&r, &v, "binding");

    let mut raw = proven_raw();
    raw["pathId"] = json!("not-path-1");
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "pathId");
}

#[test]
fn incomplete_assessments_and_single_member_chains_are_unproven() {
    let mut raw = proven_raw();
    raw["stepAssessments"] = json!([{"candidateId": "c1", "usableInChain": true}]);
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "every member step");

    let mut h = hypothesis();
    h["memberCandidateIds"] = json!(["c1"]);
    h["steps"] = json!([{"candidateId": "c1"}]);
    h["joins"] = json!([]);
    let mut raw = proven_raw();
    raw["stepAssessments"] = json!([{"candidateId": "c1", "usableInChain": true}]);
    raw["joinAssessments"] = json!([]);
    let (v, r, _) = run(&h, &members(), &synthesizer(), &adjudicator(), &raw);
    expect_unproven(&r, &v, "at least two");
}

#[test]
fn refuted_without_refutation_and_severity_on_non_proven_fail_closed() {
    let mut raw = proven_raw();
    raw["verdict"] = json!("REFUTED");
    raw["severity"] = Value::Null;
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "REFUTED");

    let mut raw = proven_raw();
    raw["verdict"] = json!("PARTIALLY_SUPPORTED");
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    expect_unproven(&r, &v, "severity");

    let mut raw = proven_raw();
    raw["verdict"] = json!("REFUTED");
    raw["severity"] = Value::Null;
    raw["joinAssessments"] = json!([{"joinId": "j1", "verdict": "REFUTED"}]);
    let (v, _, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &raw,
    );
    assert_eq!(v, "REFUTED");
}

#[test]
fn malformed_assessment_is_unproven() {
    let (v, r, _) = run(
        &hypothesis(),
        &members(),
        &synthesizer(),
        &adjudicator(),
        &json!("PROVEN"),
    );
    expect_unproven(&r, &v, "not an object");
}

#[test]
fn packet_rejects_self_synthesis_and_same_context_and_missing_verdict() {
    let b = binding();
    let model = json!({"binding": b.clone(), "entities": [], "relations": [], "evidence": []});
    let candidates = vec![json!({"id": "c1"}), json!({"id": "c2"})];
    let h = hypothesis();
    let ok = build_adjudication_packet(
        &h,
        &candidates,
        &members(),
        &model,
        &b,
        &synthesizer(),
        &adjudicator(),
    );
    assert!(ok.is_ok());
    assert_eq!(ok.unwrap()["pathId"], json!("path-1"));

    let same_provider = json!({"provider": "security.attack-paths", "contextId": "adj-ctx"});
    assert!(matches!(
        build_adjudication_packet(
            &h,
            &candidates,
            &members(),
            &model,
            &b,
            &synthesizer(),
            &same_provider
        ),
        Err(ChainAdjudicationError::SelfSynthesis)
    ));
    let same_ctx = json!({"provider": "security.chain-adjudication", "contextId": "syn-ctx"});
    assert!(matches!(
        build_adjudication_packet(
            &h,
            &candidates,
            &members(),
            &model,
            &b,
            &synthesizer(),
            &same_ctx
        ),
        Err(ChainAdjudicationError::SameContext)
    ));
    assert!(matches!(
        build_adjudication_packet(
            &h,
            &candidates,
            &members()[..1],
            &model,
            &b,
            &synthesizer(),
            &adjudicator()
        ),
        Err(ChainAdjudicationError::MissingCandidateOrVerdict(_))
    ));
}
