//! Tests for chunk wf057 (`legion_audit::wf_port::wf057`): ports of
//! `authentication-session.mjs`, `authorization-tenant.mjs`, `automation.mjs`,
//! `browser-client.mjs`, and `ai-prompt-injection.mjs`.
//!
//! Assertions for `browser-client` mirror
//! `tests/security-l4/b7-014-browser-http.test.mjs` in the JS repository
//! (same fixtures, same expected rule ids / severities / metadata). The
//! other four packs have no dedicated JS test file at port time (only
//! smoke-tested indirectly via `tests/security-packs/*.test.mjs` and
//! `tests/security-l4/b7-019-ai-security.test.mjs`), so their tests here are
//! written directly against each `.mjs` source's own rule logic.

use std::collections::BTreeMap;

use legion_audit::wf_port::wf057::{
    ai_prompt_injection, authentication_session, authorization_tenant, automation, browser_client, Entity,
    PackContext, SecurityModel,
};

fn artifact_entity(file: &str) -> Entity {
    let mut attributes = BTreeMap::new();
    attributes.insert("path".to_string(), serde_json::Value::String(file.to_string()));
    Entity {
        id: format!("artifact:{file}"),
        kind: "repository-artifact".to_string(),
        name: file.to_string(),
        attributes,
        evidence_refs: vec![format!("ev:{file}")],
    }
}

fn ctx<'a>(model: &'a SecurityModel, files: &[(&str, &str)]) -> PackContext<'a> {
    let mut source_text = BTreeMap::new();
    let mut names: Vec<String> = Vec::new();
    for (file, text) in files {
        source_text.insert(file.to_string(), text.to_string());
        names.push(file.to_string());
    }
    names.sort();
    PackContext {
        files: names,
        source_text,
        model,
        relations: &[],
        denominator_digest: "sha256:denom".to_string(),
        sandbox_receipt: false,
        runtime_headers: None,
        deployment_evidence: false,
    }
}

fn model_for(files: &[&str]) -> SecurityModel {
    SecurityModel { entities: files.iter().map(|f| artifact_entity(f)).collect() }
}

// =================================================================================================
// authentication-session.mjs
// =================================================================================================

#[test]
fn authentication_session_flags_jwt_decode_without_verification() {
    let model = model_for(&["auth.mjs"]);
    let c = ctx(&model, &[("auth.mjs", "const claims = jwt.decode(token);")]);
    let out = authentication_session::analyze(&c);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rule_id, "auth.jwt-without-verification");
    assert_eq!(out[0].severity_hint, "high");
    assert_eq!(out[0].candidate_class, "authentication-session");
    assert_eq!(out[0].sources, vec!["artifact:auth.mjs".to_string()]);
}

#[test]
fn authentication_session_flags_weak_session_cookie() {
    let model = model_for(&["s.mjs"]);
    let c = ctx(&model, &[("s.mjs", "session.cookie({ secure: false, httpOnly: true });")]);
    let out = authentication_session::analyze(&c);
    assert!(out.iter().any(|o| o.rule_id == "auth.session-cookie-weak"));
}

#[test]
fn authentication_session_flags_reset_token_logged() {
    let model = model_for(&["l.mjs"]);
    let c = ctx(&model, &[("l.mjs", "logger.info('reset', resetToken);")]);
    let out = authentication_session::analyze(&c);
    assert!(out.iter().any(|o| o.rule_id == "auth.reset-token-log"));
}

#[test]
fn authentication_session_clean_on_unrelated_text() {
    let model = model_for(&["x.mjs"]);
    let c = ctx(&model, &[("x.mjs", "const a = 1 + 1;")]);
    assert!(authentication_session::analyze(&c).is_empty());
}

#[test]
fn authentication_session_rule_ids_are_the_three_declared() {
    assert_eq!(
        authentication_session::rule_ids(),
        vec!["auth.jwt-without-verification", "auth.session-cookie-weak", "auth.reset-token-log"]
    );
}

// =================================================================================================
// authorization-tenant.mjs
// =================================================================================================

#[test]
fn authorization_flags_object_write_missing_owner_check() {
    let model = model_for(&["h.mjs"]);
    let c = ctx(&model, &[("h.mjs", "function update(id, params) { db.save(id, params); }")]);
    let out = authorization_tenant::analyze(&c);
    assert!(out.iter().any(|o| o.rule_id == "authorization.object-write.missing-owner-check"));
}

#[test]
fn authorization_clean_when_owner_check_present() {
    let model = model_for(&["h.mjs"]);
    let c = ctx(&model, &[("h.mjs", "function update(id, params) { if (!authorize(owner)) return; db.save(id, params); }")]);
    let out = authorization_tenant::analyze(&c);
    assert!(!out.iter().any(|o| o.rule_id == "authorization.object-write.missing-owner-check"));
}

#[test]
fn authorization_flags_privileged_function_without_role_check() {
    let model = model_for(&["h.mjs"]);
    let c = ctx(&model, &[("h.mjs", "function deleteUser(id) { db.remove(id); }")]);
    let out = authorization_tenant::analyze(&c);
    let hits: Vec<_> = out.iter().filter(|o| o.rule_id == "authorization.privileged-function.missing-role-check").collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "high");
}

#[test]
fn authorization_clean_when_role_check_present() {
    let model = model_for(&["h.mjs"]);
    let c = ctx(&model, &[("h.mjs", "function deleteUser(id) { requireAdmin(); db.remove(id); }")]);
    let out = authorization_tenant::analyze(&c);
    assert!(!out.iter().any(|o| o.rule_id == "authorization.privileged-function.missing-role-check"));
}

#[test]
fn authorization_declared_rule_ids_include_unimplemented_pair() {
    // Mirrors the JS pack's `rules` list: four ids declared, only two ever
    // implemented by `analyze`.
    assert_eq!(
        authorization_tenant::DECLARED_RULE_IDS,
        [
            "authorization.object-write.missing-owner-check",
            "authorization.object-read.missing-owner-check",
            "authorization.privileged-function.missing-role-check",
            "authorization.mass-assignment",
        ]
    );
}

#[test]
fn authorization_enumerate_matches_object_write_finding() {
    let model = model_for(&["h.mjs"]);
    let c = ctx(&model, &[("h.mjs", "function update(id, params) { db.save(id, params); }")]);
    let result = authorization_tenant::enumerate_object_write_missing_owner_check(&c);
    let matches = result["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["file"], "h.mjs");
    assert_eq!(matches[0]["disposition"], "CONFIRMED");
}

// =================================================================================================
// automation.mjs
// =================================================================================================

#[test]
fn automation_flags_publish_workflow_without_permissions() {
    let model = model_for(&[".github/workflows/release.yml"]);
    let c = ctx(
        &model,
        &[(".github/workflows/release.yml", "jobs:\n  release:\n    steps:\n      - run: npm publish\n")],
    );
    let out = automation::analyze(&c);
    assert!(out.iter().any(|o| o.rule_id == "automation.release.unresolved-identity-scope"));
}

#[test]
fn automation_clean_when_permissions_block_present() {
    let model = model_for(&[".github/workflows/release.yml"]);
    let c = ctx(
        &model,
        &[(".github/workflows/release.yml", "permissions:\n  contents: read\njobs:\n  release:\n    steps:\n      - run: npm publish\n")],
    );
    let out = automation::analyze(&c);
    assert!(!out.iter().any(|o| o.rule_id == "automation.release.unresolved-identity-scope"));
}

#[test]
fn automation_flags_updater_insecure_transport() {
    let model = model_for(&["app-update.yml"]);
    let c = ctx(&model, &[("app-update.yml", "url: http://cdn.example.com/update\n")]);
    let out = automation::analyze(&c);
    let hits: Vec<_> = out
        .iter()
        .filter(|o| o.rule_id == "automation.updater.insecure-transport-or-unverified-signature")
        .collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "high");
}

#[test]
fn automation_flags_disabled_signature_verification() {
    let model = model_for(&["app-update.yml"]);
    let c = ctx(&model, &[("app-update.yml", "verifyUpdateCodeSignature: false\n")]);
    let out = automation::analyze(&c);
    assert!(out
        .iter()
        .any(|o| o.rule_id == "automation.updater.insecure-transport-or-unverified-signature"));
    assert!(out.iter().any(|o| o.rule_id == "automation.release.signing-disabled-or-unenforced"));
}

#[test]
fn automation_flags_hostile_trigger_with_elevated_write_and_requires_sandbox_receipt_marker() {
    let model = model_for(&[".github/workflows/pr.yml"]);
    let text = "on:\n  pull_request_target: {}\npermissions:\n  contents: write\n";
    let c = ctx(&model, &[(".github/workflows/pr.yml", text)]);
    let out = automation::analyze(&c);
    let hits: Vec<_> = out
        .iter()
        .filter(|o| o.rule_id == "automation.privileged-automation.hostile-trigger-with-write")
        .collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].detector_metadata["requiresSandboxReceipt"], true);
    assert!(hits[0].uncertainty.iter().any(|u| u.contains("BLOCKED")));
}

#[test]
fn automation_hostile_trigger_note_changes_with_sandbox_receipt() {
    let model = model_for(&[".github/workflows/pr.yml"]);
    let text = "on:\n  pull_request_target: {}\npermissions:\n  contents: write\n";
    let mut c = ctx(&model, &[(".github/workflows/pr.yml", text)]);
    c.sandbox_receipt = true;
    let out = automation::analyze(&c);
    let hit = out
        .iter()
        .find(|o| o.rule_id == "automation.privileged-automation.hostile-trigger-with-write")
        .unwrap();
    assert!(!hit.uncertainty.iter().any(|u| u.contains("BLOCKED")));
}

#[test]
fn automation_flags_automerge_without_review_gate() {
    let model = model_for(&[".github/dependabot.yml"]);
    let c = ctx(&model, &[(".github/dependabot.yml", "automerge: true\n")]);
    let out = automation::analyze(&c);
    assert!(out.iter().any(|o| o.rule_id == "automation.dependency-update.automerge-without-review"));
}

#[test]
fn automation_clean_automerge_with_review_gate() {
    let model = model_for(&[".github/dependabot.yml"]);
    let c = ctx(&model, &[(".github/dependabot.yml", "automerge: true\nrequiredReviews: 1\n")]);
    let out = automation::analyze(&c);
    assert!(!out.iter().any(|o| o.rule_id == "automation.dependency-update.automerge-without-review"));
}

#[test]
fn automation_ignores_files_outside_declared_config_shapes() {
    let model = model_for(&["notes.txt"]);
    let c = ctx(&model, &[("notes.txt", "npm publish\nautomerge: true\n")]);
    assert!(automation::analyze(&c).is_empty());
}

#[test]
fn automation_rule_ids_match_the_five_declared() {
    assert_eq!(
        automation::rule_ids(),
        vec![
            "automation.release.unresolved-identity-scope",
            "automation.updater.insecure-transport-or-unverified-signature",
            "automation.release.signing-disabled-or-unenforced",
            "automation.privileged-automation.hostile-trigger-with-write",
            "automation.dependency-update.automerge-without-review",
        ]
    );
}

#[test]
fn automation_enumerate_returns_matches_for_signing_disabled() {
    let model = model_for(&["release.config.js"]);
    let c = ctx(&model, &[("release.config.js", "module.exports = { sign: false };\n")]);
    let result = automation::enumerate(&c, "automation.release.signing-disabled-or-unenforced").unwrap();
    let matches = result["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["file"], "release.config.js");
}

// =================================================================================================
// browser-client.mjs (mirrors b7-014-browser-http.test.mjs)
// =================================================================================================

#[test]
fn browser_client_flags_state_changing_route_missing_csrf_token() {
    let model = model_for(&["routes.mjs"]);
    let c = ctx(
        &model,
        &[("routes.mjs", "app.post('/transfer', (req, res) => { res.cookie('session', token); doTransfer(req.body); });")],
    );
    let out = browser_client::analyze(&c);
    let hits: Vec<_> = out.iter().filter(|o| o.rule_id == "csrf.state-changing-route.missing-token").collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].detector_metadata["primitiveClass"], "exploitable-primitive");
    assert_eq!(hits[0].detector_metadata["method"], "POST");
    assert_eq!(hits[0].detector_metadata["path"], "/transfer");
    assert_eq!(hits[0].detector_metadata["file"], "routes.mjs");
    assert!(!hits[0].evidence_refs.is_empty());
}

#[test]
fn browser_client_clean_when_csrf_token_check_present() {
    let model = model_for(&["routes.mjs"]);
    let c = ctx(
        &model,
        &[("routes.mjs", "app.post('/transfer', (req, res) => { res.cookie('session', token); csrfProtection(req); doTransfer(req.body); });")],
    );
    let out = browser_client::analyze(&c);
    assert!(out.iter().filter(|o| o.rule_id == "csrf.state-changing-route.missing-token").next().is_none());
}

#[test]
fn browser_client_flags_samesite_none_without_secure_and_missing_samesite() {
    let model = model_for(&["cookies.mjs"]);
    let c = ctx(
        &model,
        &[("cookies.mjs", "res.cookie('sessionToken', v, { SameSite=None });\nres.cookie('authToken', v, { httpOnly: true });")],
    );
    let out = browser_client::analyze(&c);
    assert!(out.iter().filter(|o| o.rule_id == "csrf.samesite-none-without-secure").count() >= 1);
    assert!(out.iter().filter(|o| o.rule_id == "csrf.samesite-missing").count() >= 1);
}

#[test]
fn browser_client_flags_cors_wildcard_origin_with_credentials() {
    let model = model_for(&["cors.mjs"]);
    let c = ctx(
        &model,
        &[("cors.mjs", "res.setHeader('Access-Control-Allow-Origin', '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true');")],
    );
    let out = browser_client::analyze(&c);
    let hits: Vec<_> = out.iter().filter(|o| o.rule_id == "cors.wildcard-origin-with-credentials").collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "critical");
    assert_eq!(hits[0].detector_metadata["primitiveClass"], "exploitable-primitive");
    assert_eq!(
        hits[0].detector_metadata["header"],
        "Access-Control-Allow-Origin + Access-Control-Allow-Credentials"
    );
    assert_eq!(hits[0].detector_metadata["file"], "cors.mjs");
    assert!(hits[0].detector_metadata["line"].is_number());
}

#[test]
fn browser_client_flags_reflected_origin_without_allowlist() {
    let model = model_for(&["cors.mjs"]);
    let c = ctx(&model, &[("cors.mjs", "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);")]);
    let out = browser_client::analyze(&c);
    assert_eq!(out.iter().filter(|o| o.rule_id == "cors.reflected-origin-without-allowlist").count(), 1);
}

#[test]
fn browser_client_flags_missing_frame_protection_and_csp_as_capped_defense_in_depth() {
    let model = model_for(&["page.mjs"]);
    let c = ctx(&model, &[("page.mjs", "app.get('/', (req, res) => { res.render('index'); });")]);
    let out = browser_client::analyze(&c);
    let clickjack: Vec<_> = out.iter().filter(|o| o.rule_id == "clickjacking.missing-frame-protection").collect();
    let csp: Vec<_> = out.iter().filter(|o| o.rule_id == "csp.missing").collect();
    assert_eq!(clickjack.len(), 1);
    assert_eq!(csp.len(), 1);
    for hit in clickjack.into_iter().chain(csp.into_iter()) {
        assert_eq!(hit.detector_metadata["primitiveClass"], "defense-in-depth");
        assert!(["info", "low"].contains(&hit.severity_hint.as_str()));
        assert!(hit.detector_metadata.get("deploymentAssumption").is_some());
        assert!(hit.uncertainty.iter().any(|u| u.contains("Deployment assumption")));
    }
}

#[test]
fn browser_client_clean_when_frame_options_and_csp_both_present() {
    let model = model_for(&["page.mjs"]);
    let c = ctx(
        &model,
        &[(
            "page.mjs",
            "app.get('/', (req, res) => { res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Content-Security-Policy', \"default-src 'self'\"); res.render('index'); });",
        )],
    );
    let out = browser_client::analyze(&c);
    assert_eq!(out.iter().filter(|o| o.rule_id == "clickjacking.missing-frame-protection").count(), 0);
    assert_eq!(out.iter().filter(|o| o.rule_id == "csp.missing").count(), 0);
}

#[test]
fn browser_client_flags_csp_unsafe_inline_unsafe_eval_and_wildcard_source() {
    let model = model_for(&["inline.mjs", "eval.mjs", "wildcard.mjs"]);
    let c = ctx(
        &model,
        &[
            ("inline.mjs", "res.setHeader('Content-Security-Policy', \"script-src 'self' 'unsafe-inline'\");"),
            ("eval.mjs", "res.setHeader('Content-Security-Policy', \"script-src 'self' 'unsafe-eval'\");"),
            ("wildcard.mjs", "res.setHeader('Content-Security-Policy', \"script-src *\");"),
        ],
    );
    let out = browser_client::analyze(&c);
    for rule_id in ["csp.unsafe-inline", "csp.unsafe-eval", "csp.wildcard-source"] {
        let hits: Vec<_> = out.iter().filter(|o| o.rule_id == rule_id).collect();
        assert_eq!(hits.len(), 1, "{rule_id}");
        assert_eq!(hits[0].detector_metadata["primitiveClass"], "defense-in-depth");
        assert!(["info", "low"].contains(&hits[0].severity_hint.as_str()), "{rule_id}");
    }
}

#[test]
fn browser_client_flags_open_redirect_and_oauth_redirect_uri() {
    let model = model_for(&["redirect.mjs", "oauth.mjs"]);
    let c = ctx(
        &model,
        &[
            ("redirect.mjs", "res.redirect(req.query.next);"),
            ("oauth.mjs", "const redirect_uri = req.query.redirect_uri;"),
        ],
    );
    let out = browser_client::analyze(&c);
    assert_eq!(out.iter().filter(|o| o.rule_id == "open-redirect.unvalidated-target").count(), 1);
    assert_eq!(out.iter().filter(|o| o.rule_id == "oauth.redirect-uri.unvalidated").count(), 1);
}

#[test]
fn browser_client_clean_when_redirect_and_oauth_targets_allowlisted() {
    let model = model_for(&["redirect.mjs", "oauth.mjs"]);
    let c = ctx(
        &model,
        &[
            ("redirect.mjs", "if (isValidRedirect(req.query.next)) res.redirect(req.query.next);"),
            ("oauth.mjs", "const redirect_uri = req.query.redirect_uri; if (redirect_uri === 'https://app.example.com/callback') {}"),
        ],
    );
    let out = browser_client::analyze(&c);
    assert_eq!(out.iter().filter(|o| o.rule_id == "open-redirect.unvalidated-target").count(), 0);
    assert_eq!(out.iter().filter(|o| o.rule_id == "oauth.redirect-uri.unvalidated").count(), 0);
}

#[test]
fn browser_client_missing_deployment_evidence_never_exceeds_medium() {
    let model = model_for(&["page.mjs"]);
    let c = ctx(&model, &[("page.mjs", "app.get('/', (req, res) => { res.render('index'); });")]);
    let out = browser_client::analyze(&c);
    let rank = |s: &str| match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    };
    for o in &out {
        assert!(rank(&o.severity_hint) <= rank("medium"), "{}", o.rule_id);
    }
}

#[test]
fn browser_client_stays_clean_on_a_fully_mitigated_fixture() {
    let model = model_for(&["app.mjs"]);
    let text = [
        "app.get('/', (req, res) => { res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Content-Security-Policy', \"default-src 'self'\"); res.render('index'); });",
        "app.post('/update', (req, res) => { res.cookie('session', v, { SameSite: 'Strict', Secure: true }); csrfProtection(req); doUpdate(req.body); });",
    ]
    .join("\n");
    let c = ctx(&model, &[("app.mjs", text.as_str())]);
    let out = browser_client::analyze(&c);
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn browser_client_rule_ids_match_the_twelve_declared() {
    assert_eq!(browser_client::RULE_IDS.len(), 12);
    assert!(browser_client::RULE_IDS.contains(&"csrf.state-changing-route.missing-token"));
    assert!(browser_client::RULE_IDS.contains(&"csp.wildcard-source"));
}

// =================================================================================================
// ai-prompt-injection.mjs (mirrors the shape asserted by
// tests/security-l4/b7-019-ai-security.test.mjs's
// "detects each rule as a typed, bound candidate")
// =================================================================================================

#[test]
fn ai_prompt_injection_flags_indirect_untrusted_content() {
    let model = model_for(&["agent.mjs"]);
    let c = ctx(&model, &[("agent.mjs", "const prompt = `Answer this: ${request.body}`;")]);
    let out = ai_prompt_injection::analyze(&c);
    let hits: Vec<_> = out.iter().filter(|o| o.rule_id == "ai.prompt-injection.indirect-untrusted-content").collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity_hint, "high");
    assert!(hits[0].uncertainty[0].contains("not tool compromise"));
}

#[test]
fn ai_prompt_injection_suppressed_when_trust_label_hint_present() {
    let model = model_for(&["agent.mjs"]);
    let c = ctx(&model, &[("agent.mjs", "const prompt = sanitize(`Answer this: ${request.body}`);")]);
    let out = ai_prompt_injection::analyze(&c);
    assert!(!out.iter().any(|o| o.rule_id == "ai.prompt-injection.indirect-untrusted-content"));
}

#[test]
fn ai_prompt_injection_flags_retrieved_content_untrusted() {
    let model = model_for(&["rag.mjs"]);
    let c = ctx(&model, &[("rag.mjs", "const context = vectorStore.query(q);\nprompt: context;")]);
    let out = ai_prompt_injection::analyze(&c);
    assert!(out.iter().any(|o| o.rule_id == "ai.prompt-injection.retrieved-content-untrusted"));
}

#[test]
fn ai_prompt_injection_flags_memory_context_untrusted() {
    let model = model_for(&["mem.mjs"]);
    let c = ctx(&model, &[("mem.mjs", "const data = agent_memory.recall();\nmessages: data;")]);
    let out = ai_prompt_injection::analyze(&c);
    assert!(out.iter().any(|o| o.rule_id == "ai.prompt-injection.memory-context-untrusted"));
}

#[test]
fn ai_prompt_injection_flags_dynamic_tool_schema_untrusted() {
    let model = model_for(&["tools.mjs"]);
    let c = ctx(&model, &[("tools.mjs", "tools.push(JSON.parse(response.body));")]);
    let out = ai_prompt_injection::analyze(&c);
    assert!(out.iter().any(|o| o.rule_id == "ai.prompt-injection.dynamic-tool-schema-untrusted"));
}

#[test]
fn ai_prompt_injection_suppressed_when_control_entity_grounds_the_sink() {
    use legion_audit::wf_port::wf057::Relation;

    let artifact = artifact_entity("agent.mjs");
    let mut control_attrs = BTreeMap::new();
    control_attrs.insert("controlType".to_string(), serde_json::Value::String("prompt-trust-boundary".to_string()));
    let control = Entity {
        id: "control:trust-boundary".to_string(),
        kind: "control".to_string(),
        name: "prompt trust boundary".to_string(),
        attributes: control_attrs,
        evidence_refs: vec![],
    };
    let model = SecurityModel { entities: vec![artifact.clone(), control] };
    let relations = vec![Relation {
        kind: "protects".to_string(),
        from: "control:trust-boundary".to_string(),
        to: artifact.id.clone(),
    }];
    let mut c = ctx(&model, &[("agent.mjs", "const prompt = `Answer this: ${request.body}`;")]);
    c.relations = &relations;
    let out = ai_prompt_injection::analyze(&c);
    assert!(!out.iter().any(|o| o.rule_id == "ai.prompt-injection.indirect-untrusted-content"));
}

#[test]
fn ai_prompt_injection_rule_ids_match_the_four_declared() {
    assert_eq!(
        ai_prompt_injection::rule_ids(),
        vec![
            "ai.prompt-injection.indirect-untrusted-content",
            "ai.prompt-injection.retrieved-content-untrusted",
            "ai.prompt-injection.memory-context-untrusted",
            "ai.prompt-injection.dynamic-tool-schema-untrusted",
        ]
    );
}

#[test]
fn ai_prompt_injection_clean_on_unrelated_text() {
    let model = model_for(&["x.mjs"]);
    let c = ctx(&model, &[("x.mjs", "const a = 1 + 1;")]);
    assert!(ai_prompt_injection::analyze(&c).is_empty());
}
