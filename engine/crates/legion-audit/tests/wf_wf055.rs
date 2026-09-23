//! Ported tests for chunk wf055 (area `src/providers/security`, target
//! crate `legion-audit`):
//!   - `src/providers/security/model-extractors/identity.mjs`
//!   - `src/providers/security/model-extractors/mobile.mjs`
//!   - `src/providers/security/model-extractors/native-workspace.mjs`
//!   - `src/providers/security/packs/abuse-observability.mjs`
//!   - `src/providers/security/packs/abuse-resilience.mjs`
//!
//! The abuse-resilience assertions below are ported from
//! `tests/security-l4/b7-017-abuse-observability.test.mjs`'s
//! `abuse-resilience` section (the file also covers
//! `observability-forensics.mjs`, which is outside this chunk and not
//! ported here). No JS `.test.mjs` file targeting `identity.mjs`,
//! `mobile.mjs` (the security model extractor — `tests/providers/mobile/mobile.test.mjs`
//! exercises an unrelated `code/apple` language analyzer that happens to
//! share the word "mobile"), `native-workspace.mjs`, or
//! `abuse-observability.mjs` directly was found under `tests/`, so those
//! assertions are derived from each source file's own documented behaviour,
//! matching the wf050 precedent for this same situation.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod
//! wf055;` inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf055::abuse_observability::{analyze as observability_analyze, ObservabilityFile};
use legion_audit::wf_port::wf055::abuse_resilience::{
    analyze as resilience_analyze, variant_rate_limit_operation_missing, variant_webhook_signature_missing,
    PerformanceTrace, ResilienceContext, ResilienceFile, RULE_IDS,
};
use legion_audit::wf_port::wf055::identity::extract_identity;
use legion_audit::wf_port::wf055::mobile::extract_mobile;
use legion_audit::wf_port::wf055::native_workspace::extract_native_workspace;

fn resilience_file(path: &str, text: &str) -> ResilienceFile {
    ResilienceFile {
        path: path.to_string(),
        text: text.to_string(),
        artifact_id: format!("artifact:{path}"),
        artifact_evidence_refs: vec![format!("ev:{path}")],
    }
}

fn resilience_context(files: Vec<ResilienceFile>) -> ResilienceContext {
    ResilienceContext { files, performance_traces: vec![] }
}

fn candidates_by_id<'a>(observations: &'a [serde_json::Value], rule_id: &str) -> Vec<&'a serde_json::Value> {
    observations.iter().filter(|o| o["ruleId"] == rule_id).collect()
}

// --- abuse-resilience: ported from b7-017-abuse-observability.test.mjs ------

#[test]
fn abuse_resilience_flags_global_rate_limit_missing_as_capped_design_recommendation() {
    let ctx = resilience_context(vec![resilience_file("server.mjs", "app.listen(3000);")]);
    let hits = resilience_analyze(&ctx);
    let hits = candidates_by_id(&hits, "abuse.rate-limit.global-missing");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "design-recommendation");
    assert!(["info", "low"].contains(&hits[0]["severityHint"].as_str().unwrap()));
    assert_eq!(hits[0]["detectorMetadata"]["resource"], "all HTTP endpoints");
    assert_eq!(hits[0]["detectorMetadata"]["attackerControlledInput"], "request volume");
    assert!(!hits[0]["attackerCapabilities"].as_array().unwrap().is_empty());
}

#[test]
fn abuse_resilience_stays_clean_on_global_rate_limit_when_a_limiter_is_present() {
    let ctx = resilience_context(vec![resilience_file(
        "server.mjs",
        "app.use(rateLimit({ windowMs: 60000 }));\napp.listen(3000);",
    )]);
    let hits = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&hits, "abuse.rate-limit.global-missing").len(), 0);
}

#[test]
fn abuse_resilience_upgrades_global_rate_limit_claim_with_cost_evidence() {
    let mut ctx = resilience_context(vec![resilience_file("server.mjs", "app.listen(3000);")]);
    ctx.performance_traces.push(PerformanceTrace {
        file: None,
        route: Some("global".to_string()),
        cost_evidence: true,
        note: Some("search endpoint measured at 40x baseline cost per request".to_string()),
    });
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.rate-limit.global-missing");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "proven-primitive");
}

#[test]
fn abuse_resilience_flags_identity_operation_missing_rate_limit_and_names_resource() {
    let ctx = resilience_context(vec![resilience_file(
        "auth.mjs",
        "app.post('/login', (req, res) => { doLogin(req.body); });",
    )]);
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.rate-limit.operation-missing");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["resource"], "POST /login");
    assert_eq!(hits[0]["detectorMetadata"]["attackerControlledInput"], "request volume against this operation");
    assert!(!hits[0]["attackerCapabilities"].as_array().unwrap().is_empty());
}

#[test]
fn abuse_resilience_stays_clean_on_per_operation_rate_limit_when_registered_near_route() {
    let ctx = resilience_context(vec![resilience_file(
        "auth.mjs",
        "app.post('/login', loginRateLimit, (req, res) => { doLogin(req.body); });",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.rate-limit.operation-missing").len(), 0);
}

#[test]
fn abuse_resilience_flags_graphql_server_with_no_depth_or_cost_limit() {
    let ctx = resilience_context(vec![resilience_file(
        "schema.mjs",
        "const server = new ApolloServer({ typeDefs, resolvers });",
    )]);
    let obs = resilience_analyze(&ctx);
    let depth = candidates_by_id(&obs, "abuse.graphql.depth-unbounded");
    let cost = candidates_by_id(&obs, "abuse.graphql.cost-unbounded");
    assert_eq!(depth.len(), 1);
    assert_eq!(cost.len(), 1);
    for hit in depth.iter().chain(cost.iter()) {
        assert_eq!(hit["detectorMetadata"]["claimClass"], "design-recommendation");
        assert!(["info", "low"].contains(&hit["severityHint"].as_str().unwrap()));
    }
}

#[test]
fn abuse_resilience_stays_clean_on_graphql_depth_cost_when_limits_configured() {
    let ctx = resilience_context(vec![resilience_file(
        "schema.mjs",
        "const server = new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(5), createComplexityLimitRule(1000)] });",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.graphql.depth-unbounded").len(), 0);
    assert_eq!(candidates_by_id(&obs, "abuse.graphql.cost-unbounded").len(), 0);
}

#[test]
fn abuse_resilience_flags_graphql_introspection_true_as_proven_low() {
    let ctx = resilience_context(vec![resilience_file(
        "schema.mjs",
        "const server = new ApolloServer({ typeDefs, resolvers, introspection: true });",
    )]);
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.graphql.introspection-enabled");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "proven-primitive");
    assert_eq!(hits[0]["severityHint"], "low");
}

#[test]
fn abuse_resilience_flags_unbounded_pagination_from_request_input() {
    let ctx = resilience_context(vec![resilience_file(
        "list.mjs",
        "app.get('/items', (req, res) => { db.items.find().limit(req.query.limit); });",
    )]);
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.pagination.unbounded");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "proven-primitive");
    assert_eq!(hits[0]["detectorMetadata"]["resource"], "list.mjs pagination endpoint");
}

#[test]
fn abuse_resilience_stays_clean_on_pagination_when_capped() {
    let ctx = resilience_context(vec![resilience_file(
        "list.mjs",
        "app.get('/items', (req, res) => { db.items.find().limit(Math.min(req.query.limit, 100)); });",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.pagination.unbounded").len(), 0);
}

#[test]
fn abuse_resilience_flags_over_exposed_fields() {
    let ctx = resilience_context(vec![resilience_file(
        "profile.mjs",
        "const passwordHash = user.passwordHash;\napp.get('/profile', (req, res) => { res.json(user); });",
    )]);
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.data.over-exposed-fields");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "proven-primitive");
}

#[test]
fn abuse_resilience_stays_clean_on_over_exposed_fields_with_allowlist() {
    let ctx = resilience_context(vec![resilience_file(
        "profile.mjs",
        "const passwordHash = user.passwordHash;\napp.get('/profile', (req, res) => { res.json(_.pick(user, ['id', 'name'])); });",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.data.over-exposed-fields").len(), 0);
}

#[test]
fn abuse_resilience_flags_webhook_with_no_signature_verification() {
    let ctx = resilience_context(vec![resilience_file(
        "webhook.mjs",
        "router.post('/stripe/webhook', (req, res) => { process(req.body); });",
    )]);
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.webhook.signature-missing");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "proven-primitive");
    assert_eq!(hits[0]["detectorMetadata"]["resource"], "webhook.mjs webhook receiver");
}

#[test]
fn abuse_resilience_flags_webhook_body_used_before_signature_verified() {
    let ctx = resilience_context(vec![resilience_file(
        "webhook.mjs",
        "router.post('/stripe/webhook', (req, res) => { process(req.body); verifySignature(req); });",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.webhook.signature-missing").len(), 0);
    let hits = candidates_by_id(&obs, "abuse.webhook.signature-verified-after-use");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "proven-primitive");
}

#[test]
fn abuse_resilience_stays_clean_when_webhook_verifies_before_using_body() {
    let ctx = resilience_context(vec![resilience_file(
        "webhook.mjs",
        "router.post('/stripe/webhook', (req, res) => { verifySignature(req); process(req.body); });",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.webhook.signature-missing").len(), 0);
    assert_eq!(candidates_by_id(&obs, "abuse.webhook.signature-verified-after-use").len(), 0);
}

#[test]
fn abuse_resilience_flags_payment_mutation_with_no_idempotency_key() {
    let ctx = resilience_context(vec![resilience_file(
        "charge.mjs",
        "app.post('/charge', (req, res) => { chargeCard(req.body.amount); });",
    )]);
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.mutation.idempotency-key-missing");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "proven-primitive");
}

#[test]
fn abuse_resilience_stays_clean_on_idempotency_when_key_present() {
    let ctx = resilience_context(vec![resilience_file(
        "charge.mjs",
        "app.post('/charge', (req, res) => { const key = req.headers['idempotency-key']; chargeCard(req.body.amount); });",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.mutation.idempotency-key-missing").len(), 0);
}

#[test]
fn abuse_resilience_flags_unbounded_resource_exhaustion() {
    let ctx = resilience_context(vec![resilience_file(
        "export.mjs",
        "app.post('/export', (req, res) => { const buf = new Array(req.body.count); });",
    )]);
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.resource.exhaustion-unbounded-input");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "proven-primitive");
}

#[test]
fn abuse_resilience_stays_clean_on_resource_exhaustion_when_capped() {
    let ctx = resilience_context(vec![resilience_file(
        "export.mjs",
        "app.post('/export', (req, res) => { const buf = new Array(Math.min(req.body.count, 1000)); });",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.resource.exhaustion-unbounded-input").len(), 0);
}

#[test]
fn abuse_resilience_flags_circuit_breaker_absent_always_capped_low() {
    let mut ctx = resilience_context(vec![resilience_file(
        "client.mjs",
        "const data = await axios.get('https://payments.example.com/charge');",
    )]);
    ctx.performance_traces.push(PerformanceTrace {
        file: None,
        route: Some("global".to_string()),
        cost_evidence: true,
        note: Some("irrelevant to circuit breaker".to_string()),
    });
    let obs = resilience_analyze(&ctx);
    let hits = candidates_by_id(&obs, "abuse.resilience.circuit-breaker-absent");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["detectorMetadata"]["claimClass"], "design-recommendation");
    assert_eq!(hits[0]["severityHint"], "low");
}

#[test]
fn abuse_resilience_stays_clean_on_circuit_breaker_when_present() {
    let ctx = resilience_context(vec![resilience_file(
        "client.mjs",
        "const breaker = new CircuitBreaker(callPaymentGateway);\nconst data = await axios.get('https://payments.example.com/charge');",
    )]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(candidates_by_id(&obs, "abuse.resilience.circuit-breaker-absent").len(), 0);
}

#[test]
fn abuse_resilience_every_candidate_names_resource_and_attacker_control() {
    let files = vec![
        resilience_file("server.mjs", "app.listen(3000);"),
        resilience_file("auth.mjs", "app.post('/login', (req, res) => { doLogin(req.body); });"),
        resilience_file("schema.mjs", "const server = new ApolloServer({ typeDefs, resolvers, introspection: true });"),
        resilience_file("list.mjs", "app.get('/items', (req, res) => { db.items.find().limit(req.query.limit); });"),
        resilience_file(
            "profile.mjs",
            "const password = user.password;\napp.get('/profile', (req, res) => { res.json(user); });",
        ),
        resilience_file("webhook.mjs", "router.post('/stripe/webhook', (req, res) => { process(req.body); });"),
        resilience_file("charge.mjs", "app.post('/charge', (req, res) => { chargeCard(req.body.amount); });"),
        resilience_file("export.mjs", "app.post('/export', (req, res) => { const buf = new Array(req.body.count); });"),
        resilience_file("client.mjs", "const data = await axios.get('https://payments.example.com/charge');"),
    ];
    let ctx = resilience_context(files);
    let obs = resilience_analyze(&ctx);
    assert!(!obs.is_empty());
    for candidate in &obs {
        assert!(candidate["detectorMetadata"]["resource"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(candidate["detectorMetadata"]["attackerControlledInput"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(!candidate["attackerCapabilities"].as_array().unwrap().is_empty());
        assert!(candidate["detectorMetadata"]["claimClass"].is_string());
    }
}

#[test]
fn abuse_resilience_design_recommendations_never_exceed_low_severity() {
    let files = vec![
        resilience_file("server.mjs", "app.listen(3000);"),
        resilience_file("schema.mjs", "const server = new ApolloServer({ typeDefs, resolvers });"),
        resilience_file("client.mjs", "const data = await axios.get('https://payments.example.com/charge');"),
    ];
    let ctx = resilience_context(files);
    let obs = resilience_analyze(&ctx);
    let design_recs: Vec<_> = obs.iter().filter(|c| c["detectorMetadata"]["claimClass"] == "design-recommendation").collect();
    assert!(design_recs.len() >= 3);
    for candidate in &design_recs {
        assert!(["info", "low"].contains(&candidate["severityHint"].as_str().unwrap()));
    }
    let proven: Vec<_> = obs.iter().filter(|c| c["detectorMetadata"]["claimClass"] == "proven-primitive").collect();
    assert_eq!(proven.len(), 0);
}

#[test]
fn abuse_resilience_variant_strategies_enumerate_equivalent_endpoints() {
    let ctx = resilience_context(vec![resilience_file(
        "a.mjs",
        "app.post('/login', (req, res) => { doLogin(req.body); });",
    )]);
    let matches = variant_rate_limit_operation_missing(&ctx);
    assert!(!matches.is_empty());

    let ctx2 = resilience_context(vec![resilience_file(
        "w.mjs",
        "router.post('/x/webhook', (req, res) => { process(req.body); });",
    )]);
    let matches2 = variant_webhook_signature_missing(&ctx2);
    assert_eq!(matches2.len(), 1);
}

#[test]
fn abuse_resilience_stays_fully_clean_on_fully_mitigated_fixture() {
    let text = [
        "app.use(rateLimit({ windowMs: 60000 }));",
        "app.listen(3000);",
        "app.post('/login', loginRateLimit, (req, res) => {",
        "  doLogin(req.body);",
        "});",
        "const server = new ApolloServer({ typeDefs, resolvers, introspection: false, validationRules: [depthLimit(5), createComplexityLimitRule(1000)] });",
        "app.get('/items', (req, res) => { db.items.find().limit(Math.min(req.query.limit, 100)); });",
        "app.get('/profile', (req, res) => { res.json(_.pick(user, ['id', 'name'])); });",
        "router.post('/stripe/webhook', (req, res) => { verifySignature(req); process(req.body); });",
        "app.post('/charge', (req, res) => { const key = req.headers['idempotency-key']; chargeCard(req.body.amount); });",
        "app.post('/export', (req, res) => { const buf = new Array(Math.min(req.body.count, 1000)); });",
        "const breaker = new CircuitBreaker(callPaymentGateway);",
    ]
    .join("\n");
    let ctx = resilience_context(vec![resilience_file("app.mjs", &text)]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(obs.len(), 0);
}

#[test]
fn abuse_resilience_emits_nothing_for_neutral_source() {
    let ctx = resilience_context(vec![resilience_file("plain.mjs", "export const value = 1;")]);
    let obs = resilience_analyze(&ctx);
    assert_eq!(obs.len(), 0);
}

#[test]
fn abuse_resilience_rule_id_list_has_twelve_entries() {
    assert_eq!(RULE_IDS.len(), 12);
}

// --- identity.mjs: derived from source's own documented behaviour ----------

#[test]
fn identity_auth_marker_produces_control_and_principal() {
    let out = extract_identity(&[(
        "src/middleware/auth.js".to_string(),
        "export function requireAuth(req, res, next) {}".to_string(),
    )]);
    assert_eq!(out.entities.len(), 2);
    assert!(out.entities.iter().any(|e| e["kind"] == "control" && e["attributes"]["controlType"] == "authentication"));
    assert!(out.entities.iter().any(|e| e["kind"] == "principal"));
    assert_eq!(out.relations.len(), 1);
    assert_eq!(out.relations[0]["kind"], "protected-by");
}

#[test]
fn identity_tenant_marker_produces_trust_boundary() {
    let out = extract_identity(&[("src/scope.js".to_string(), "const tenantId = req.headers['x-tenant'];".to_string())]);
    assert_eq!(out.entities.len(), 1);
    assert_eq!(out.entities[0]["kind"], "trust-boundary");
}

#[test]
fn identity_no_markers_yields_nothing() {
    let out = extract_identity(&[("src/math.js".to_string(), "export const add = (a, b) => a + b;".to_string())]);
    assert!(out.entities.is_empty());
}

// --- mobile.mjs: derived from source's own documented behaviour ------------

#[test]
fn mobile_no_signal_reports_context_not_detected() {
    let out = extract_mobile(&[("src/index.js".to_string(), Some("console.log('hi')".to_string()))], &[]);
    assert_eq!(out.coverage_gaps.len(), 1);
    assert_eq!(out.coverage_gaps[0]["kind"], "mobile-context-not-detected");
}

#[test]
fn mobile_android_manifest_permission_extraction() {
    let text = r#"<manifest><uses-permission android:name="android.permission.CAMERA"/></manifest>"#;
    let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".to_string(), Some(text.to_string()))], &[]);
    assert!(out
        .entities
        .iter()
        .any(|e| e["kind"] == "permission-scope" && e["attributes"]["permission"] == "android.permission.CAMERA"));
}

#[test]
fn mobile_exported_component_produces_inter_app_reachability_fact() {
    let text = r#"<activity android:name=".Main" android:exported="true"/>"#;
    let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".to_string(), Some(text.to_string()))], &[]);
    assert_eq!(out.initial_facts.len(), 1);
    assert_eq!(out.initial_facts[0]["attributes"]["vector"], "on-device-inter-app");
}

#[test]
fn mobile_matched_config_file_with_missing_text_reports_coverage_gap() {
    // `sawMobileSignal` is never set on the `text === undefined` branch
    // (`src/providers/security/model-extractors/mobile.mjs`, the `continue`
    // right after pushing `missing-rendered-configuration`), so with no
    // other mobile signal in the denominator the trailing `if
    // (!sawMobileSignal)` also fires, giving two coverage gaps here, not
    // one.
    let out = extract_mobile(&[("app/src/main/AndroidManifest.xml".to_string(), None)], &[]);
    assert_eq!(out.coverage_gaps.len(), 2);
    assert!(out.coverage_gaps.iter().any(|g| g["kind"] == "missing-rendered-configuration"));
    assert!(out.coverage_gaps.iter().any(|g| g["kind"] == "mobile-context-not-detected"));
}

// --- native-workspace.mjs: derived from source's own documented behaviour --

#[test]
fn native_workspace_env_file_produces_workspace_config() {
    let out = extract_native_workspace(&[(".env".to_string(), "SECRET=1".to_string())]);
    assert!(out.entities.iter().any(|e| e["kind"] == "entrypoint"));
    assert!(out.entities.iter().any(|e| e["kind"] == "repository-artifact"));
    assert_eq!(out.relations.len(), 1);
}

#[test]
fn native_workspace_process_execution_sink_detected() {
    let out = extract_native_workspace(&[("src/runner.js".to_string(), "child_process.exec('ls')".to_string())]);
    assert!(out.entities.iter().any(|e| e["kind"] == "sink" && e["attributes"]["sinkKind"] == "process"));
}

#[test]
fn native_workspace_irrelevant_file_produces_nothing() {
    let out = extract_native_workspace(&[("src/math.js".to_string(), "export const add = (a, b) => a + b;".to_string())]);
    assert!(out.entities.is_empty());
}

// --- abuse-observability.mjs: derived from source's own documented behaviour

#[test]
fn abuse_observability_login_call_site_produces_finding() {
    let files = [ObservabilityFile {
        path: "src/auth.js",
        text: "function login(req, res) { db.find(req.body.user); }",
        artifact_id: None,
        artifact_evidence_refs: &[],
    }];
    let obs = observability_analyze(&files);
    assert_eq!(candidates_by_id(&obs, "abuse.login-without-rate-limit").len(), 1);
}

#[test]
fn abuse_observability_webhook_call_site_is_high_severity() {
    // The rule's pattern (`src/providers/security/packs/abuse-observability.mjs`)
    // is `/(?:webhook|callback)\s*\([^\n]*(?!signature|hmac|verify)/i`, which
    // needs "webhook"/"callback" immediately followed by `(` (a function
    // call/definition site), not the word appearing inside a route string.
    let files = [ObservabilityFile {
        path: "src/webhooks.js",
        text: "function webhook(req, res) { handle(req.body); }",
        artifact_id: None,
        artifact_evidence_refs: &[],
    }];
    let obs = observability_analyze(&files);
    let hits = candidates_by_id(&obs, "abuse.webhook-without-signature");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["severityHint"], "high");
}

#[test]
fn abuse_observability_clean_file_produces_nothing() {
    let files = [ObservabilityFile {
        path: "src/math.js",
        text: "export const add = (a, b) => a + b;",
        artifact_id: None,
        artifact_evidence_refs: &[],
    }];
    assert!(observability_analyze(&files).is_empty());
}
