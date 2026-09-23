//! Ported tests for chunk wf058 (area `src/providers/security`, target crate
//! `legion-audit`):
//!   - `src/providers/security/packs/browser-http.mjs`
//!   - `src/providers/security/packs/business-logic.mjs`
//!   - `src/providers/security/packs/cicd-automation.mjs`
//!   - `src/providers/security/packs/credentials.mjs`
//!   - `src/providers/security/packs/crypto-data-privacy.mjs`
//!
//! Source coverage:
//!   - `tests/security-end-to-end.test.mjs` drives `browserHttp`/`cicd`/`businessLogic`/
//!     `cryptoPrivacy` (via the shared `fixtures` table in
//!     `tests/security-packs/extended-packs.test.mjs`-style tests) with one representative
//!     hazard fixture each, asserting a non-empty `UNADJUDICATED` candidate list with
//!     non-empty `evidenceRefs`, and asserts each pack emits zero candidates for the
//!     neutral fixture `'export const value = 1;'`. `*_hazard_fixture_matches` and
//!     `*_neutral_fixture_is_silent` below port those two assertions per pack directly
//!     against this crate's `analyze`.
//!   - `tests/security-end-to-end.test.mjs`'s credentials fixtures assert
//!     `const key = "AKIAIOSFODNN7EXAMPLE";` produces a candidate and
//!     `const label = "api key example";` produces none; `credentials_*` below ports
//!     both, plus `tests/security-candidate-v2.test.mjs`'s assertion that the
//!     `credentials.format` rule id and `credentials` candidate class are exactly what
//!     the AKIA fixture reports.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf058;` inside
//! it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf058::{
    browser_http, business_logic, cicd_automation, credentials, crypto_data_privacy, Entity,
    PackContext, Relation, SecurityModel,
};
use std::collections::BTreeMap;

fn artifact(file: &str) -> Entity {
    Entity {
        id: format!("artifact:{file}"),
        kind: "repository-artifact".to_string(),
        name: file.to_string(),
        attributes: BTreeMap::from([("path".to_string(), serde_json::json!(file))]),
        evidence_refs: vec!["ev".to_string()],
    }
}

fn ctx<'a>(file: &str, text: &str, model: &'a SecurityModel, relations: &'a [Relation]) -> PackContext<'a> {
    PackContext {
        files: vec![file.to_string()],
        source_text: BTreeMap::from([(file.to_string(), text.to_string())]),
        model,
        relations,
        denominator_digest: "sha256:denom".to_string(),
    }
}

const NEUTRAL: &str = "export const value = 1;";

// =================================================================================================
// browser-http.mjs
// =================================================================================================

#[test]
fn browser_http_hazard_fixture_matches() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let text = "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true";
    let context = ctx("app.mjs", text, &model, &[]);
    let observations = browser_http::analyze(&context);
    assert!(!observations.is_empty());
    assert!(observations.iter().any(|o| o.rule_id == "http.cors-wildcard-credentials"));
    for o in &observations {
        assert_eq!(o.candidate_class, "browser-http");
        assert!(!o.evidence_refs.is_empty());
    }
}

#[test]
fn browser_http_neutral_fixture_is_silent() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let context = ctx("app.mjs", NEUTRAL, &model, &[]);
    assert!(browser_http::analyze(&context).is_empty());
}

#[test]
fn browser_http_trust_forwarded_host_rule() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let text = "const target = host; redirect(target);";
    let context = ctx("app.mjs", text, &model, &[]);
    let observations = browser_http::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "http.trust-forwarded-host"));
}

#[test]
fn browser_http_sensitive_public_cache_rule() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let text = "Cache-Control: public, max-age=600\nSet-Cookie: authorization=abc";
    let context = ctx("app.mjs", text, &model, &[]);
    let observations = browser_http::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "http.sensitive-public-cache"));
}

// =================================================================================================
// business-logic.mjs
// =================================================================================================

#[test]
fn business_logic_hazard_fixture_matches() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let text = "const amount = request.body.amount";
    let context = ctx("app.mjs", text, &model, &[]);
    let observations = business_logic::analyze(&context);
    assert!(!observations.is_empty());
    assert!(observations.iter().any(|o| o.rule_id == "logic.client-controlled-price"));
    for o in &observations {
        assert_eq!(o.candidate_class, "business-logic");
        assert!(!o.evidence_refs.is_empty());
    }
}

#[test]
fn business_logic_neutral_fixture_is_silent() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let context = ctx("app.mjs", NEUTRAL, &model, &[]);
    assert!(business_logic::analyze(&context).is_empty());
}

#[test]
fn business_logic_payment_without_idempotency_rule() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let text = "await charge(customer, amount);";
    let context = ctx("app.mjs", text, &model, &[]);
    let observations = business_logic::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "logic.payment-without-idempotency"));
}

// =================================================================================================
// cicd-automation.mjs
// =================================================================================================

#[test]
fn cicd_automation_hazard_fixture_matches() {
    let model = SecurityModel { entities: vec![artifact(".github/workflows/ci.yml")] };
    let text = "steps:\n  - uses: actions/checkout@v4";
    let context = ctx(".github/workflows/ci.yml", text, &model, &[]);
    let observations = cicd_automation::analyze(&context);
    assert!(!observations.is_empty());
    assert!(observations.iter().any(|o| o.rule_id == "cicd.action-unpinned"));
    for o in &observations {
        assert_eq!(o.candidate_class, "cicd-automation");
        assert!(!o.evidence_refs.is_empty());
    }
}

#[test]
fn cicd_automation_neutral_fixture_is_silent() {
    let model = SecurityModel { entities: vec![artifact(".github/workflows/ci.yml")] };
    let context = ctx(".github/workflows/ci.yml", NEUTRAL, &model, &[]);
    assert!(cicd_automation::analyze(&context).is_empty());
}

#[test]
fn cicd_automation_pull_request_target_write_rule() {
    let model = SecurityModel { entities: vec![artifact("ci.yml")] };
    let text = "on: pull_request_target\npermissions:\n  contents: write\n";
    let context = ctx("ci.yml", text, &model, &[]);
    let observations = cicd_automation::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "cicd.pull-request-target-write"));
}

#[test]
fn cicd_automation_verifier_bypass_rule() {
    let model = SecurityModel { entities: vec![artifact("ci.yml")] };
    let text = "continue-on-error: true";
    let context = ctx("ci.yml", text, &model, &[]);
    let observations = cicd_automation::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "cicd.verifier-bypass"));
}

// =================================================================================================
// crypto-data-privacy.mjs
// =================================================================================================

#[test]
fn crypto_data_privacy_hazard_fixture_matches() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let text = "logger.info(user.email)";
    let context = ctx("app.mjs", text, &model, &[]);
    let observations = crypto_data_privacy::analyze(&context);
    assert!(!observations.is_empty());
    assert!(observations.iter().any(|o| o.rule_id == "privacy.pii-log"));
    for o in &observations {
        assert_eq!(o.candidate_class, "crypto-data-privacy");
        assert!(!o.evidence_refs.is_empty());
    }
}

#[test]
fn crypto_data_privacy_neutral_fixture_is_silent() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let context = ctx("app.mjs", NEUTRAL, &model, &[]);
    assert!(crypto_data_privacy::analyze(&context).is_empty());
}

#[test]
fn crypto_data_privacy_weak_hash_password_rule() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let text = "const digest = md5(password);";
    let context = ctx("app.mjs", text, &model, &[]);
    let observations = crypto_data_privacy::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "crypto.weak-hash-password"));
}

#[test]
fn crypto_data_privacy_static_iv_rule() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let text = "const iv = Buffer.alloc(16, 0);";
    let context = ctx("app.mjs", text, &model, &[]);
    let observations = crypto_data_privacy::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "crypto.static-iv"));
}

// =================================================================================================
// credentials.mjs
// =================================================================================================

#[test]
fn credentials_hazard_fixture_matches() {
    let model = SecurityModel { entities: vec![artifact("app.ts")] };
    let text = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;
    let context = ctx("app.ts", text, &model, &[]);
    let observations = credentials::analyze(&context);
    assert!(!observations.is_empty());
    let hit = observations.iter().find(|o| o.rule_id == "credentials.format").unwrap();
    assert_eq!(hit.candidate_class, "credentials");
    assert_eq!(hit.severity_hint, "high");
    assert_eq!(hit.detector_metadata["file"], "app.ts");
    assert_eq!(hit.detector_metadata["line"], 1);
}

#[test]
fn credentials_neutral_fixture_is_silent() {
    // JS fixture: 'const label = "api key example";' — no credential-shaped value,
    // no 12+ char secret-like literal assignment, no private-key block.
    let model = SecurityModel { entities: vec![artifact("app.ts")] };
    let text = r#"const label = "api key example";"#;
    let context = ctx("app.ts", text, &model, &[]);
    assert!(credentials::analyze(&context).is_empty());
}

#[test]
fn credentials_reports_every_match_not_only_the_first() {
    // Two AKIA-shaped literals in one file must produce two observations, mirroring
    // the JS `while ((match = rule.pattern.exec(text)) !== null)` loop rather than a
    // single `.test()`/`.match()` call.
    let model = SecurityModel { entities: vec![artifact("app.ts")] };
    let text = "const a = \"AKIAIOSFODNN7EXAMPLE\";\nconst b = \"AKIAIOSFODNN7EXAMPLF\";";
    let context = ctx("app.ts", text, &model, &[]);
    let observations = credentials::analyze(&context);
    let format_hits: Vec<_> = observations.iter().filter(|o| o.rule_id == "credentials.format").collect();
    assert_eq!(format_hits.len(), 2);
    assert_eq!(format_hits[0].detector_metadata["line"], 1);
    assert_eq!(format_hits[1].detector_metadata["line"], 2);
}

#[test]
fn credentials_assignment_rule() {
    let model = SecurityModel { entities: vec![artifact("app.ts")] };
    let text = r#"const password = "correct horse battery staple";"#;
    let context = ctx("app.ts", text, &model, &[]);
    let observations = credentials::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "credentials.assignment"));
}

#[test]
fn credentials_private_key_rule() {
    let model = SecurityModel { entities: vec![artifact("id_rsa")] };
    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----";
    let context = ctx("id_rsa", text, &model, &[]);
    let observations = credentials::analyze(&context);
    assert!(observations.iter().any(|o| o.rule_id == "credentials.private-key"));
}

#[test]
fn credentials_never_emits_evidence_refs_or_sinks() {
    // JS: `evidenceRefs: []` and `sinks: []` unconditionally, unlike the pattern-pack
    // packs which forward the bound artifact's evidenceRefs/id.
    let model = SecurityModel { entities: vec![artifact("app.ts")] };
    let text = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;
    let context = ctx("app.ts", text, &model, &[]);
    let observations = credentials::analyze(&context);
    for o in &observations {
        assert!(o.evidence_refs.is_empty());
        assert!(o.sinks.is_empty());
    }
}

#[test]
fn credentials_match_digest_is_literal_prefix_of_matched_text() {
    let model = SecurityModel { entities: vec![artifact("app.ts")] };
    let text = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;
    let context = ctx("app.ts", text, &model, &[]);
    let observations = credentials::analyze(&context);
    let hit = observations.iter().find(|o| o.rule_id == "credentials.format").unwrap();
    // Matched text is "AKIAIOSFODNN7EXAMPLE" (20 chars); slice(0, 16) keeps the first 16.
    assert_eq!(hit.detector_metadata["matchDigest"], "sha256:AKIAIOSFODNN7EXA");
}

#[test]
fn credentials_enumerate_format_matches_reproduces_variant_strategy() {
    let model = SecurityModel { entities: vec![artifact("app.ts")] };
    let text = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;
    let context = ctx("app.ts", text, &model, &[]);
    let matches = credentials::enumerate_format_matches(&context);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].file, "app.ts");
    assert_eq!(matches[0].line, 1);
    assert_eq!(matches[0].disposition, "CONFIRMED");
    assert_eq!(matches[0].semantic_fingerprint, "sha256:AKIAIOSFODNN7EXAMPLE");
}
