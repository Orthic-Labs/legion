//! Ported tests for chunk wf056 (area `src/providers/security`, target crate
//! `legion-audit`):
//!   - `src/providers/security/packs/ai-excessive-agency.mjs`
//!   - `src/providers/security/packs/ai-integrity.mjs`
//!   - `src/providers/security/packs/ai-model-abuse.mjs`
//!   - `src/providers/security/packs/ai-output-handling.mjs`
//!   - `src/providers/security/packs/ai-poisoning-rag.mjs`
//!
//! The only JS test file with fixture coverage that reaches one of these five packs is
//! `tests/security-packs/extended-packs.test.mjs`, which drives `ai-integrity.mjs`
//! (via `runSecurityPack`) with the fixture `vectorStore.upsert(userUpload)` and asserts
//! a non-empty, all-`UNADJUDICATED` candidate list, plus a neutral-source fixture
//! (`export const value = 1;`) asserting zero candidates. `ai_integrity_*` below ports
//! those two assertions directly against this crate's `ai_integrity::analyze`. No JS
//! test file targets the other four packs directly, so their tests are derived from the
//! packs' own documented rules (the "Pinned: ruleId ... relied on by a pre-existing
//! test" comments in `ai-excessive-agency.mjs` and `ai-output-handling.mjs` are honored
//! verbatim below) plus each rule's suppress-when-a-matching-control-is-present
//! contract, which every one of these packs' own header comments documents as "no
//! clean verdict, only insufficient model evidence".
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf056;` inside it)
//! into `legion_audit`'s crate root.

use legion_audit::wf_port::wf056::{
    ai_excessive_agency, ai_integrity, ai_model_abuse, ai_output_handling, ai_poisoning_rag,
    Entity, PackContext, Relation, SecurityModel,
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

fn control(id: &str, control_type: &str) -> Entity {
    Entity {
        id: id.to_string(),
        kind: "control".to_string(),
        name: id.to_string(),
        attributes: BTreeMap::from([("controlType".to_string(), serde_json::json!(control_type))]),
        evidence_refs: vec![],
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

// ---------------------------------------------------------------------
// ai-integrity.mjs — ported from tests/security-packs/extended-packs.test.mjs
// ---------------------------------------------------------------------

#[test]
fn ai_integrity_emits_candidate_for_untrusted_ingestion_fixture() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("app.mjs", "vectorStore.upsert(userUpload)", &model, &relations);
    let observations = ai_integrity::analyze(&c);
    assert!(!observations.is_empty(), "extended pack fixture missed by ai-integrity");
    assert!(observations.iter().all(|o| !o.evidence_refs.is_empty()));
    assert!(observations.iter().any(|o| o.rule_id == "ai.rag-untrusted-ingestion"));
}

#[test]
fn ai_integrity_emits_no_candidates_for_neutral_source() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("app.mjs", "export const value = 1;", &model, &relations);
    assert_eq!(ai_integrity::analyze(&c).len(), 0);
}

#[test]
fn ai_integrity_model_output_policy_rule() {
    let model = SecurityModel { entities: vec![artifact("app.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("app.mjs", "if (completion.assistantMessage.approve: true) {}", &model, &relations);
    let observations = ai_integrity::analyze(&c);
    assert!(observations.iter().any(|o| o.rule_id == "ai.model-output-policy" && o.severity_hint == "high"));
}

// ---------------------------------------------------------------------
// ai-excessive-agency.mjs — pinned ruleId/claim/detectorMetadata.action per source comment
// ---------------------------------------------------------------------

#[test]
fn agency_destructive_tool_without_approval_pinned_shape() {
    let model = SecurityModel { entities: vec![artifact("agent.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("agent.mjs", "deploy(target)", &model, &relations);
    let observations = ai_excessive_agency::analyze(&c);
    let hit = observations
        .iter()
        .find(|o| o.rule_id == "ai.agency.destructive-tool-without-approval")
        .expect("destructive tool without approval must be detected");
    assert_eq!(
        hit.claim,
        "A destructive deploy tool is available to the agent without a visible approval or reauthentication control."
    );
    assert_eq!(hit.detector_metadata["action"], "deploy");
}

#[test]
fn agency_destructive_tool_suppressed_when_approval_present() {
    let model = SecurityModel { entities: vec![artifact("agent.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("agent.mjs", "deploy(target) // requires approval before running", &model, &relations);
    assert!(ai_excessive_agency::analyze(&c)
        .iter()
        .all(|o| o.rule_id != "ai.agency.destructive-tool-without-approval"));
}

#[test]
fn agency_destructive_tool_suppressed_when_control_entity_bound() {
    let mut art = artifact("agent.mjs");
    art.id = "artifact:agent.mjs".to_string();
    let ctl = control("ctl:approval", "human-approval");
    let model = SecurityModel { entities: vec![art.clone(), ctl.clone()] };
    let relations = vec![Relation { kind: "protects".to_string(), from: ctl.id.clone(), to: art.id.clone() }];
    let c = ctx("agent.mjs", "deploy(target)", &model, &relations);
    assert!(ai_excessive_agency::analyze(&c)
        .iter()
        .all(|o| o.rule_id != "ai.agency.destructive-tool-without-approval"));
}

#[test]
fn agency_shared_high_scope_identity_rule() {
    let model = SecurityModel { entities: vec![artifact("agent.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("agent.mjs", "const token = env.API_TOKEN; tool.run(token);", &model, &relations);
    let observations = ai_excessive_agency::analyze(&c);
    assert!(observations.iter().any(|o| o.rule_id == "ai.agency.shared-high-scope-identity"));
}

#[test]
fn agency_missing_side_effect_budget_rule() {
    let model = SecurityModel { entities: vec![artifact("agent.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("agent.mjs", "while (true) { tool.invoke(x); }", &model, &relations);
    let observations = ai_excessive_agency::analyze(&c);
    assert!(observations.iter().any(|o| o.rule_id == "ai.agency.missing-side-effect-budget"));
}

#[test]
fn agency_neutral_source_emits_nothing() {
    let model = SecurityModel { entities: vec![artifact("agent.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("agent.mjs", "export const value = 1;", &model, &relations);
    assert_eq!(ai_excessive_agency::analyze(&c).len(), 0);
}

// ---------------------------------------------------------------------
// ai-model-abuse.mjs
// ---------------------------------------------------------------------

#[test]
fn model_abuse_provider_retention_rule() {
    let model = SecurityModel { entities: vec![artifact("svc.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("svc.mjs", "anthropic.messages.create({ input: user.email })", &model, &relations);
    let observations = ai_model_abuse::analyze(&c);
    assert!(observations
        .iter()
        .any(|o| o.rule_id == "ai.model-abuse.provider-data-retention-unbounded" && o.severity_hint == "high"));
}

#[test]
fn model_abuse_provider_retention_suppressed_with_zero_retention() {
    let model = SecurityModel { entities: vec![artifact("svc.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx(
        "svc.mjs",
        "anthropic.messages.create({ input: user.email, zero_retention: true })",
        &model,
        &relations,
    );
    assert!(ai_model_abuse::analyze(&c)
        .iter()
        .all(|o| o.rule_id != "ai.model-abuse.provider-data-retention-unbounded"));
}

#[test]
fn model_abuse_uncapped_cost_loop_rule() {
    let model = SecurityModel { entities: vec![artifact("svc.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("svc.mjs", "while (true) { model.complete(prompt); }", &model, &relations);
    let observations = ai_model_abuse::analyze(&c);
    assert!(observations.iter().any(|o| o.rule_id == "ai.model-abuse.uncapped-cost-loop"));
}

#[test]
fn model_abuse_shared_credential_rule() {
    let model = SecurityModel { entities: vec![artifact("svc.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("svc.mjs", "const apiKey = process.env.OPENAI_API_KEY; // global", &model, &relations);
    let observations = ai_model_abuse::analyze(&c);
    assert!(observations.iter().any(|o| o.rule_id == "ai.model-abuse.shared-provider-credential"));
}

// ---------------------------------------------------------------------
// ai-output-handling.mjs — pinned ruleId/pattern for shell and html sinks
// ---------------------------------------------------------------------

#[test]
fn output_handling_model_output_to_shell_pinned() {
    let model = SecurityModel { entities: vec![artifact("handler.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("handler.mjs", "exec(`run ${completion}`)", &model, &relations);
    let observations = ai_output_handling::analyze(&c);
    let hit = observations
        .iter()
        .find(|o| o.rule_id == "ai.output-handling.model-output-to-shell")
        .expect("model output to shell must be detected");
    assert_eq!(hit.detector_metadata["sink"], "shell");
    assert_eq!(
        hit.claim,
        "Model output may reach a shell sink without a visible schema-validation or sanitization control."
    );
}

#[test]
fn output_handling_model_output_to_html_pinned() {
    let model = SecurityModel { entities: vec![artifact("view.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("view.mjs", "el.innerHTML = response.text", &model, &relations);
    let observations = ai_output_handling::analyze(&c);
    assert!(observations.iter().any(|o| o.rule_id == "ai.output-handling.model-output-to-html"));
}

#[test]
fn output_handling_suppressed_when_validation_control_bound() {
    let mut art = artifact("handler.mjs");
    art.id = "artifact:handler.mjs".to_string();
    let ctl = control("ctl:sanitize", "output-schema-validation");
    let model = SecurityModel { entities: vec![art.clone(), ctl.clone()] };
    let relations = vec![Relation { kind: "validates".to_string(), from: ctl.id.clone(), to: art.id.clone() }];
    let c = ctx("handler.mjs", "exec(`run ${completion}`)", &model, &relations);
    assert!(ai_output_handling::analyze(&c)
        .iter()
        .all(|o| o.rule_id != "ai.output-handling.model-output-to-shell"));
}

#[test]
fn output_handling_six_rules_cover_six_distinct_sinks() {
    let model = SecurityModel { entities: vec![artifact("h.mjs")] };
    let relations: Vec<Relation> = vec![];
    let samples = [
        ("exec(`${response.text}`)", "shell"),
        ("el.innerHTML = message.body", "html"),
        ("db.query(`${completion}`)", "sql"),
        ("fs.write(path, response.data)", "filesystem"),
        ("fetch(response.url)", "url"),
        ("applyPatch(response.patch)", "patch"),
    ];
    for (text, expected_sink) in samples {
        let c = ctx("h.mjs", text, &model, &relations);
        let observations = ai_output_handling::analyze(&c);
        assert!(
            observations.iter().any(|o| o.detector_metadata["sink"] == expected_sink),
            "expected sink {expected_sink} for text {text:?}, got {observations:?}"
        );
    }
}

// ---------------------------------------------------------------------
// ai-poisoning-rag.mjs
// ---------------------------------------------------------------------

#[test]
fn poisoning_rag_ingestion_rule() {
    let model = SecurityModel { entities: vec![artifact("ingest.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("ingest.mjs", "vectorStore.upsert(externalUpload)", &model, &relations);
    let observations = ai_poisoning_rag::analyze(&c);
    let hit = observations
        .iter()
        .find(|o| o.rule_id == "ai.poisoning.rag-ingestion-untrusted-provenance")
        .expect("rag ingestion must be detected");
    assert_eq!(hit.severity_hint, "high");
    assert_eq!(hit.chain_roles, vec!["starter".to_string(), "enabler".to_string()]);
}

#[test]
fn poisoning_cross_tenant_retrieval_rule() {
    let model = SecurityModel { entities: vec![artifact("retrieve.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("retrieve.mjs", "vectorStore.query(userQuery)", &model, &relations);
    let observations = ai_poisoning_rag::analyze(&c);
    assert!(observations.iter().any(|o| o.rule_id == "ai.poisoning.cross-tenant-retrieval"));
}

#[test]
fn poisoning_cross_tenant_retrieval_suppressed_with_tenant_scope() {
    let model = SecurityModel { entities: vec![artifact("retrieve.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("retrieve.mjs", "vectorStore.query(userQuery, { tenantId })", &model, &relations);
    assert!(ai_poisoning_rag::analyze(&c)
        .iter()
        .all(|o| o.rule_id != "ai.poisoning.cross-tenant-retrieval"));
}

#[test]
fn poisoning_destructive_action_from_retrieved_content_is_critical() {
    let model = SecurityModel { entities: vec![artifact("agent.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("agent.mjs", "const p = search_result.path; deleteFile(p)", &model, &relations);
    let observations = ai_poisoning_rag::analyze(&c);
    let hit = observations
        .iter()
        .find(|o| o.rule_id == "ai.poisoning.destructive-action-from-retrieved-content")
        .expect("destructive-from-retrieved-content must be detected");
    assert_eq!(hit.severity_hint, "critical");
}

#[test]
fn poisoning_durable_memory_untrusted_write_rule() {
    let model = SecurityModel { entities: vec![artifact("memory.mjs")] };
    let relations: Vec<Relation> = vec![];
    let c = ctx("memory.mjs", "agent_memory.push(userInput)", &model, &relations);
    let observations = ai_poisoning_rag::analyze(&c);
    assert!(observations.iter().any(|o| o.rule_id == "ai.poisoning.durable-memory-untrusted-write"));
}

// ---------------------------------------------------------------------
// digest determinism (contracts.mjs `digest` reproduction)
// ---------------------------------------------------------------------

#[test]
fn digest_is_deterministic_and_key_order_independent() {
    use legion_audit::wf_port::wf056::digest;
    let a = digest(&serde_json::json!({ "ruleId": "x", "file": "y" }));
    let b = digest(&serde_json::json!({ "file": "y", "ruleId": "x" }));
    assert_eq!(a, b);
}
