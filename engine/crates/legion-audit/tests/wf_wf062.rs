//! Ported tests for chunk wf062 (area `src/providers/security`, target crate
//! `legion-audit`):
//!   - `src/providers/security/packs/pattern-pack.mjs`
//!   - `src/providers/security/packs/repository-footprint.mjs`
//!   - `src/providers/security/packs/request-boundaries.mjs`
//!   - `src/providers/security/packs/smart-contract.mjs`
//!   - `src/providers/security/packs/ssrf-egress.mjs`
//!
//! Source coverage:
//!   - `tests/security-l4/b7-018-supply-developer.test.mjs`'s `footprintFixtures`
//!     table (one representative fixture per `repository-footprint.mjs` rule),
//!     its "no committed secrets/db/source-maps/hooks" clean-repository assertion,
//!     its hostile-precondition/authority/executionPath acceptance test, and its
//!     execution-chain sandbox-receipt-gate assertions for
//!     `footprint.malicious-repository-boundary` are ported below as
//!     `repository_footprint_*`.
//!   - `tests/security-l4/b7-015-boundaries.test.mjs`'s `HAZARD_FIXTURES` entries
//!     for `requestBoundariesPack`/`ssrfEgressPack`, its schema-validation-control
//!     downgrade test, its egress-environment-cap and allowlist-downgrade tests,
//!     and its size-capped-body-parser mitigation test are ported below as
//!     `request_boundaries_*` / `ssrf_egress_*`.
//!   - `tests/security-l4/b7-020-specialist-security.test.mjs`'s
//!     `smartContractFixtures` table (positive + mitigated fixture per rule) and
//!     its non-Solidity-file silence assertion are ported below as
//!     `smart_contract_*`.
//!   - Every pack's shared "neutral source produces zero candidates" regression
//!     (asserted per-pack across all three source test files) is ported once per
//!     pack below.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf062;`
//! inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf062::{
    pattern_pack, repository_footprint, request_boundaries, smart_contract, ssrf_egress, AuditFacts, Context, Entity,
    Relation,
};

fn find<'a, T>(candidates: &'a [T], rule_id: &str, get_id: impl Fn(&T) -> &str) -> Option<&'a T> {
    candidates.iter().find(|c| get_id(*c) == rule_id)
}

// ---------------------------------------------------------------------------
// pattern-pack.mjs
// ---------------------------------------------------------------------------

#[test]
fn pattern_pack_build_rejects_a_non_security_id_an_empty_family_and_empty_rules() {
    // Constructing a working (non-empty-rules) pack here would need the
    // `regex` crate directly in this integration-test binary, which is not
    // a listed dev-dependency of this crate (only a dependency of the
    // library itself, not transitively visible to `tests/*.rs`); the
    // positive-construction path is covered by `pattern_pack.rs`'s own
    // `#[cfg(test)]` module instead, which links against `regex` as the
    // library's own dependency.
    assert!(pattern_pack::build("not-security.x", "family", "d", vec![]).is_err());
    assert!(pattern_pack::build("security.x", "", "d", vec![]).is_err());
    assert!(pattern_pack::build("security.x", "family", "d", vec![]).is_err());
}

// ---------------------------------------------------------------------------
// repository-footprint.mjs
// ---------------------------------------------------------------------------

#[test]
fn repository_footprint_each_rule_fires_on_its_representative_positive_fixture() {
    let fixtures: [(&str, &str, &str); 5] = [
        ("footprint.sourcemap-included", "dist/app.js.map", r#"{"version":3,"sources":["app.js"],"mappings":"AAAA"}"#),
        ("footprint.local-db-committed", "data/app.sqlite", "SQLite format 3"),
        (
            "footprint.internal-endpoint-exposed",
            "docs/architecture.md",
            "Internal admin panel at http://10.0.0.5/admin for debugging.",
        ),
        ("footprint.sensitive-file-committed", ".env", "API_KEY=xxxx"),
        ("footprint.malicious-repository-boundary", ".git/hooks/pre-commit", "#!/bin/sh\nexec malicious-payload\n"),
    ];
    for (rule_id, file, content) in fixtures {
        let context = Context::new().with_file(file, content);
        let observations = repository_footprint::analyze(&context);
        let candidate = find(&observations, rule_id, |o| o.rule_id.as_str());
        assert!(candidate.is_some(), "{rule_id} missed its fixture");
        let candidate = candidate.unwrap();
        assert!(!candidate.evidence_refs.is_empty(), "{rule_id} candidate must carry evidence");
    }
}

#[test]
fn repository_footprint_no_hazards_repository_produces_no_candidates() {
    let context = Context::new()
        .with_file("src/index.mjs", "export function main() { return 1; }")
        .with_file("README.md", "This project has no sensitive material committed.")
        .with_file(".devcontainer/devcontainer.json", r#"{"image": "node:20"}"#);
    assert!(repository_footprint::analyze(&context).is_empty());
}

#[test]
fn repository_footprint_every_candidate_carries_hostile_precondition_and_named_authority_execution_path() {
    let context = Context::new().with_file(".env", "API_KEY=xxxx");
    for candidate in repository_footprint::analyze(&context) {
        let hostile = candidate
            .preconditions
            .iter()
            .find(|p| p.kind == "attacker-position" || p.kind == "knowledge")
            .expect("hostile precondition");
        assert_eq!(hostile.subject, "actor:repository-content");
        assert_eq!(candidate.detector_metadata["authority"], serde_json::json!("repository-content"));
        assert!(candidate.detector_metadata["executionPath"].as_str().unwrap().contains('\u{2192}'));
    }
}

#[test]
fn repository_footprint_execution_chain_rule_is_blocked_absent_a_sandbox_receipt() {
    let context = Context::new().with_file(".git/hooks/pre-commit", "#!/bin/sh\nexec malicious-payload\n");
    let observations = repository_footprint::analyze(&context);
    let candidate = find(&observations, "footprint.malicious-repository-boundary", |o| o.rule_id.as_str()).unwrap();
    assert_eq!(candidate.detector_metadata["requiresSandboxReceipt"], serde_json::json!(true));
    assert!(candidate.uncertainty.iter().any(|u| u.contains("BLOCKED") && u.to_lowercase().contains("sandbox execution receipt")));
}

#[test]
fn repository_footprint_a_supplied_sandbox_receipt_never_upgrades_to_a_clean_claim() {
    let context = Context::new()
        .with_file(".git/hooks/pre-commit", "#!/bin/sh\nexec malicious-payload\n")
        .with_audit_facts(AuditFacts {
            sandbox_receipt: Some(serde_json::json!({ "schemaVersion": 1, "kind": "remediation-sandbox-receipt" })),
            ..Default::default()
        });
    let observations = repository_footprint::analyze(&context);
    let candidate = find(&observations, "footprint.malicious-repository-boundary", |o| o.rule_id.as_str()).unwrap();
    assert_eq!(candidate.detector_metadata["requiresSandboxReceipt"], serde_json::json!(true));
    assert!(candidate.uncertainty.iter().any(|u| u.to_lowercase().contains("independent adjudication")));
}

#[test]
fn repository_footprint_neutral_source_produces_no_candidates() {
    let context = Context::new().with_file("src/neutral.mjs", "export const value = 1;");
    assert!(repository_footprint::analyze(&context).is_empty());
}

// ---------------------------------------------------------------------------
// request-boundaries.mjs
// ---------------------------------------------------------------------------

#[test]
fn request_boundaries_hazard_fixture_matches_and_is_adjudication_only() {
    let context = Context::new().with_file("app.mjs", "fetch(request.query.url)");
    let observations = request_boundaries::analyze(&context);
    assert!(!observations.is_empty());
    for candidate in &observations {
        assert!(!candidate.evidence_refs.is_empty());
        assert!(!candidate.preconditions.is_empty());
        for pre in &candidate.preconditions {
            assert_eq!(pre.kind, "attacker-position");
            assert_eq!(pre.subject, "actor:external");
        }
    }
}

#[test]
fn request_boundaries_an_observed_schema_validation_control_downgrades_instead_of_hiding() {
    let source = Context::new().with_file("handler.mjs", "fetch(request.query.url)");
    let baseline = request_boundaries::analyze(&source);
    let baseline_candidate = find(&baseline, "request.unvalidated-input-to-sink", |o| o.rule_id.as_str()).unwrap();
    assert_eq!(baseline_candidate.severity_hint, "medium");
    assert!(baseline_candidate.observed_controls.is_empty());

    let downgraded_ctx = Context::new()
        .with_file("handler.mjs", "fetch(request.query.url)")
        .with_entity(Entity::control("ctrl:1", "request-schema-validation", "joi request schema", vec!["ev:control".into()]))
        .with_relation(Relation { kind: "protects".to_string(), from: "ctrl:1".to_string(), to: "artifact:handler.mjs".to_string() });
    let downgraded = request_boundaries::analyze(&downgraded_ctx);
    let downgraded_candidate = find(&downgraded, "request.unvalidated-input-to-sink", |o| o.rule_id.as_str()).unwrap();
    assert_ne!(downgraded_candidate.severity_hint, "medium");
    assert_eq!(downgraded_candidate.observed_controls, vec!["ctrl:1".to_string()]);
    assert!(downgraded_candidate.uncertainty.iter().any(|u| u.to_lowercase().contains("observed") && u.to_lowercase().contains("control")));
}

#[test]
fn request_boundaries_size_capped_body_parser_suppresses_the_rule() {
    let context = Context::new().with_file("app.mjs", "app.use(express.json({ limit: '100kb' }));");
    let observations = request_boundaries::analyze(&context);
    assert!(find(&observations, "request.body-size-unbounded", |o| o.rule_id.as_str()).is_none());
}

#[test]
fn request_boundaries_every_candidate_names_exact_file_line_source_expr_sink_api_and_control_observed() {
    let context = Context::new().with_file("app.mjs", "fetch(request.query.url)");
    for candidate in request_boundaries::analyze(&context) {
        let meta = &candidate.detector_metadata;
        assert_eq!(meta["file"], "app.mjs");
        assert!(meta["line"].is_number());
        assert!(!meta["sourceExpr"].as_str().unwrap().is_empty());
        assert!(!meta["sinkApi"].as_str().unwrap().is_empty());
        assert!(meta.get("controlObserved").is_some());
    }
}

#[test]
fn request_boundaries_neutral_source_produces_no_candidates() {
    let context = Context::new().with_file("neutral.mjs", "export const value = 1;");
    assert!(request_boundaries::analyze(&context).is_empty());
}

// ---------------------------------------------------------------------------
// ssrf-egress.mjs
// ---------------------------------------------------------------------------

#[test]
fn ssrf_egress_hazard_fixture_matches_and_is_adjudication_only() {
    let context = Context::new().with_file("egress.mjs", "fetch(request.query.url)");
    let observations = ssrf_egress::analyze(&context);
    assert!(!observations.is_empty());
    for candidate in &observations {
        assert!(!candidate.evidence_refs.is_empty());
    }
}

#[test]
fn ssrf_egress_no_environment_evidence_caps_severity_at_medium_and_marks_unproven() {
    let context = Context::new().with_file("egress.mjs", "fetch(request.query.url)");
    let observations = ssrf_egress::analyze(&context);
    let candidate = find(&observations, "ssrf.request-controlled-destination", |o| o.rule_id.as_str()).unwrap();
    let rank = |s: &str| match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        _ => 4,
    };
    assert!(rank(&candidate.severity_hint) <= rank("medium"));
    assert!(candidate.uncertainty.iter().any(|u| u.to_lowercase().contains("unknown") && u.to_lowercase().contains("egress")));
}

#[test]
fn ssrf_egress_deployment_evidence_lifts_the_medium_cap() {
    let context = Context::new()
        .with_file("egress.mjs", "fetch(request.query.url)")
        .with_audit_facts(AuditFacts { deployment: Some(serde_json::json!({ "httpsEnforced": true })), ..Default::default() });
    let observations = ssrf_egress::analyze(&context);
    let candidate = find(&observations, "ssrf.request-controlled-destination", |o| o.rule_id.as_str()).unwrap();
    assert_eq!(candidate.severity_hint, "high");
}

#[test]
fn ssrf_egress_observed_allowlist_control_downgrades_and_references_it() {
    let context = Context::new()
        .with_file("egress.mjs", "fetch(request.query.url)")
        .with_entity(Entity::control("ctrl:1", "egress-allowlist", "outbound host allowlist", vec!["ev:control".into()]))
        .with_relation(Relation { kind: "protects".to_string(), from: "ctrl:1".to_string(), to: "artifact:egress.mjs".to_string() });
    let observations = ssrf_egress::analyze(&context);
    let candidate = find(&observations, "ssrf.request-controlled-destination", |o| o.rule_id.as_str()).unwrap();
    assert_eq!(candidate.severity_hint, "low");
    assert_eq!(candidate.observed_controls, vec!["ctrl:1".to_string()]);
}

#[test]
fn ssrf_egress_neutral_source_produces_no_candidates() {
    let context = Context::new().with_file("neutral.mjs", "export const value = 1;");
    assert!(ssrf_egress::analyze(&context).is_empty());
}

// ---------------------------------------------------------------------------
// smart-contract.mjs
// ---------------------------------------------------------------------------

#[test]
fn smart_contract_pack_covers_every_category_with_a_positive_and_mitigated_fixture() {
    let fixtures: [(&str, &str, &str); 6] = [
        (
            "smart-contract.access-control.tx-origin-authorization",
            "function withdraw() public { require(tx.origin == owner); payable(msg.sender).transfer(1); }",
            "function withdraw() public { require(msg.sender == owner); payable(msg.sender).transfer(1); }",
        ),
        (
            "smart-contract.access-control.privileged-function-unprotected",
            "function mint(address to, uint amount) external { _mint(to, amount); }",
            "function mint(address to, uint amount) external onlyOwner { _mint(to, amount); }",
        ),
        (
            "smart-contract.reentrancy.external-call-before-guard",
            "function withdraw() external { (bool ok, ) = msg.sender.call{value: balance}(\"\"); }",
            "function withdraw() external nonReentrant { (bool ok, ) = msg.sender.call{value: balance}(\"\"); }",
        ),
        (
            "smart-contract.oracle.single-source-price-trust",
            "function price() public view returns (int) { return feed.latestAnswer(); }",
            "function price() public view returns (int) { (, int p,, uint updatedAt,) = feed.latestRoundData(); require(block.timestamp - updatedAt < heartbeat); return p; }",
        ),
        (
            "smart-contract.upgradeability.unprotected-upgrade-authorization",
            "function _authorizeUpgrade(address newImpl) internal override {}",
            "function _authorizeUpgrade(address newImpl) internal override onlyOwner {}",
        ),
        (
            "smart-contract.signature.replay-missing-nonce",
            "function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s) external { address signer = ecrecover(h, v, r, s); }",
            "function claim(bytes32 h, uint8 v, bytes32 r, bytes32 s, uint nonce) external { require(!used[nonce]); address signer = ecrecover(h, v, r, s); }",
        ),
    ];

    for (rule_id, positive, mitigated) in fixtures {
        let wrap = |body: &str| format!("pragma solidity ^0.8.0;\ncontract C {{\n  {body}\n}}");

        let positive_ctx = Context::new().with_file("Contract.sol", &wrap(positive));
        let positive_obs = smart_contract::analyze(&positive_ctx);
        let candidate = find(&positive_obs, rule_id, |o| o.rule_id.as_str());
        assert!(candidate.is_some(), "{rule_id} did not fire on its positive fixture");
        assert!(!candidate.unwrap().evidence_refs.is_empty());

        let mitigated_ctx = Context::new().with_file("Contract.sol", &wrap(mitigated));
        let mitigated_obs = smart_contract::analyze(&mitigated_ctx);
        assert!(find(&mitigated_obs, rule_id, |o| o.rule_id.as_str()).is_none(), "{rule_id} still fired on its mitigated fixture");
    }
}

#[test]
fn smart_contract_emits_nothing_for_a_non_solidity_file_even_with_a_risky_looking_pattern() {
    let context = Context::new().with_file("notes.md", "require(tx.origin == owner);");
    assert!(smart_contract::analyze(&context).is_empty());
}

#[test]
fn smart_contract_neutral_source_produces_no_candidates() {
    let context = Context::new().with_file("neutral.sol", "pragma solidity ^0.8.0;\ncontract Empty {}");
    assert!(smart_contract::analyze(&context).is_empty());
}

// ---------------------------------------------------------------------------
// Structural invariant shared by all four full packs in this chunk (not
// counting the generic `pattern_pack` factory, which has no fixed rule
// table of its own): declared rule ids are stable and non-empty.
// ---------------------------------------------------------------------------

#[test]
fn every_pack_declares_a_stable_non_empty_rule_id_set() {
    assert_eq!(repository_footprint::rule_ids().len(), 5);
    assert_eq!(request_boundaries::rule_ids().len(), 4);
    assert_eq!(smart_contract::rule_ids().len(), 6);
    assert_eq!(ssrf_egress::rule_ids().len(), 3);
}
