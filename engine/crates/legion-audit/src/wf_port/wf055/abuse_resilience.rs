//! Port of `src/providers/security/packs/abuse-resilience.mjs`.
//!
//! Abuse & resilience security pack: global/per-operation rate limiting,
//! GraphQL depth/cost/introspection exposure, pagination caps,
//! over-exposed response fields, webhook signature verification, mutation
//! idempotency keys, resource exhaustion, and circuit-breaker absence.
//!
//! No network imports, no live probing, no load generation — every
//! observation is derived from source text already loaded into the frozen
//! denominator, plus, when available, upstream performance/cost evidence
//! ([`PerformanceTrace`], standing in for `context.projection.auditFacts.performanceTraces`).
//! A missing rate limit, missing circuit breaker, or unbounded GraphQL
//! depth/cost with NO observed cost or amplification evidence is reported
//! as a capped, explicitly labelled `design-recommendation`
//! (`severityHint` never exceeds `low`) rather than a `proven-primitive`
//! denial-of-service claim. Rules where the source itself is the
//! amplification evidence (an attacker-controlled loop/allocation size, an
//! attacker-controlled page size funnelled directly into a query, a
//! webhook body used before its signature is checked, a payment mutation
//! with no idempotency key) are reported as `proven-primitive` because the
//! exploit mechanics are directly observed, not merely recommended
//! against.

use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::sync::LazyLock;

use crate::wf_port::wf052::contracts::digest;

const CANDIDATE_CLASS: &str = "abuse-resilience";

// --- patterns -----------------------------------------------------------

static SERVER_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bapp\.listen\(|createServer\(|fastify\s*\(|new\s+Koa\(\)").expect("valid regex"));
static RATE_LIMIT_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)rate.?limit|RateLimiter(?:Memory|Redis)|slowDown\(|throttle").expect("valid regex"));

static IDENTITY_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:app|router)\.(post|put)\(\s*['"]([^'"]*(?:login|signin|sign-in|register|signup|reset-password|resetPassword|forgot-password|send-otp|sendOtp|verify-otp|verifyOtp)[^'"]*)['"]"#,
    )
    .expect("valid regex")
});

static GRAPHQL_SERVER_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"new\s+ApolloServer\(|new\s+GraphQLSchema\(|graphqlHTTP\(|buildSchema\(").expect("valid regex"));
static GRAPHQL_DEPTH_LIMIT_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)depthLimit\(|queryDepthLimit|maxDepth\s*:").expect("valid regex"));
static GRAPHQL_COST_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)costAnalysis|queryComplexity|createComplexityLimitRule|costLimit\s*:").expect("valid regex")
});
static GRAPHQL_INTROSPECTION_TRUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"introspection\s*:\s*true").expect("valid regex"));

static PAGINATION_UNBOUNDED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\.(?:limit|take)\s*\(\s*(?:req|request)\.(?:query|params|body)\.\w+\s*\)|(?:take|limit)\s*:\s*(?:req|request)\.(?:query|params|body)\.\w+\b",
    )
    .expect("valid regex")
});
static PAGINATION_CAP_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Math\.min\(").expect("valid regex"));

static SENSITIVE_FIELD_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)password(?:Hash)?|\bssn\b|apiKey|secret|privateKey|creditCard").expect("valid regex"));
static RESPONSE_FULL_OBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)res\.(?:json|send)\(\s*(user|account|profile|customer|record|entity)\s*\)").expect("valid regex")
});
static FIELD_ALLOWLIST_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.pick\(|\.omit\(|toSafeJSON|sanitizeUser|select\s*:|serialize\(").expect("valid regex")
});

static WEBHOOK_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.(?:post|all)\(\s*['"][^'"]*(?:webhook|callback)[^'"]*['"]"#).expect("valid regex")
});
static BODY_USE_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:process|save|handle|charge|apply|persist|fulfill|db\.\w+|JSON\.parse)\s*\(\s*(?:req|request)\.body")
        .expect("valid regex")
});
static SIGNATURE_VERIFY_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"verify(?:Webhook)?Signature\(|hmac\.|crypto\.timingSafeEqual\(|\.webhooks\.constructEvent\(").expect("valid regex")
});

static MUTATION_PAYMENT_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.post\(\s*['"][^'"]*(?:charge|payment|order|transfer|refund)[^'"]*['"]"#).expect("valid regex")
});
static IDEMPOTENCY_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)idempotencyKey|Idempotency-Key|idempotency_key").expect("valid regex"));

static UNBOUNDED_ALLOCATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"new\s+Array\(\s*(?:req|request)\.(?:query|body|params)\.\w+\s*\)|Buffer\.alloc\(\s*(?:req|request)\.(?:query|body|params)\.\w+\s*\)|for\s*\(\s*(?:let|var)\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(?:req|request)\.(?:query|body|params)\.\w+",
    )
    .expect("valid regex")
});
static RESOURCE_CAP_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Math\.min\(").expect("valid regex"));

static OUTBOUND_CALL_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"axios\.(?:get|post|put|delete|patch)\(|fetch\(\s*['"]https?://|http\.request\(|https\.request\("#).expect("valid regex")
});
static CIRCUIT_BREAKER_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)opossum|CircuitBreaker\(|new\s+CircuitBreaker|retry\(\s*\{|backoff\(").expect("valid regex")
});

// --- context types --------------------------------------------------------

/// One repository file plus its already-modeled `repository-artifact`
/// entity (id + evidence refs), mirroring `artifactFor(context, file)`.
#[derive(Clone)]
pub struct ResilienceFile {
    pub path: String,
    pub text: String,
    pub artifact_id: String,
    pub artifact_evidence_refs: Vec<String>,
}

/// Stand-in for `context.projection.auditFacts.performanceTraces`: an
/// optional upstream cost-evidence record keyed by file or route.
pub struct PerformanceTrace {
    pub file: Option<String>,
    pub route: Option<String>,
    pub cost_evidence: bool,
    pub note: Option<String>,
}

pub struct ResilienceContext {
    pub files: Vec<ResilienceFile>,
    pub performance_traces: Vec<PerformanceTrace>,
}

fn severity_rank(sev: &str) -> i32 {
    match sev {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

fn cap_severity(base: &str, cap: Option<&str>) -> String {
    match cap {
        None => base.to_string(),
        Some(cap) => {
            if severity_rank(base) <= severity_rank(cap) {
                base.to_string()
            } else {
                cap.to_string()
            }
        }
    }
}

fn line_of(text: &str, byte_index: usize) -> usize {
    text.as_bytes()[..byte_index.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

fn slice_around(text: &str, index: usize, match_len: usize, before: usize, after: usize) -> String {
    let start = index.saturating_sub(before);
    let end = (index + match_len + after).min(text.len());
    // Byte-safe: clamp to char boundaries so we never panic on a slice cut
    // through a multi-byte UTF-8 sequence.
    let mut start = start.min(text.len());
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = end.min(text.len());
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    text[start..end].to_string()
}

fn test_around(pattern: &Regex, text: &str, index: usize, match_len: usize, before: usize, after: usize) -> bool {
    pattern.is_match(&slice_around(text, index, match_len, before, after))
}

fn repo_wide_evidence_refs(context: &ResilienceContext) -> Vec<Value> {
    let mut refs: BTreeSet<String> = BTreeSet::new();
    for file in &context.files {
        refs.extend(file.artifact_evidence_refs.iter().cloned());
    }
    refs.into_iter().map(Value::String).collect()
}

fn performance_evidence_for<'a>(context: &'a ResilienceContext, key: &str) -> Option<&'a PerformanceTrace> {
    context
        .performance_traces
        .iter()
        .find(|t| t.file.as_deref() == Some(key) || t.route.as_deref() == Some(key))
}

struct ClaimGate {
    claim_class: &'static str,
    severity_cap: Option<&'static str>,
    trace_note: Option<String>,
}

fn availability_claim_class(context: &ResilienceContext, key: &str, has_direct_amplification_evidence: bool) -> ClaimGate {
    if has_direct_amplification_evidence {
        return ClaimGate { claim_class: "proven-primitive", severity_cap: None, trace_note: None };
    }
    if let Some(trace) = performance_evidence_for(context, key) {
        if trace.cost_evidence {
            return ClaimGate { claim_class: "proven-primitive", severity_cap: None, trace_note: trace.note.clone() };
        }
    }
    ClaimGate { claim_class: "design-recommendation", severity_cap: Some("low"), trace_note: None }
}

#[allow(clippy::too_many_arguments)]
fn base_observation(
    rule_id: &str,
    claim: &str,
    severity_hint: &str,
    claim_class: &str,
    resource: &str,
    attacker_controlled_input: &str,
    sources: Vec<Value>,
    sinks: Vec<Value>,
    attacker_capabilities: Vec<&str>,
    preconditions: Vec<Value>,
    effects: Vec<Value>,
    chain_roles: Vec<&str>,
    evidence_refs: Vec<Value>,
    detector_metadata: Map<String, Value>,
    uncertainty: Vec<String>,
) -> Value {
    debug_assert!(!attacker_capabilities.is_empty(), "{rule_id}: attackerCapabilities must be non-empty");
    debug_assert!(!resource.is_empty(), "{rule_id}: detectorMetadata.resource is required");
    debug_assert!(
        !attacker_controlled_input.is_empty(),
        "{rule_id}: detectorMetadata.attackerControlledInput is required"
    );

    let mut metadata = detector_metadata;
    metadata.insert("claimClass".into(), Value::String(claim_class.into()));
    metadata.insert("resource".into(), Value::String(resource.into()));
    metadata.insert("attackerControlledInput".into(), Value::String(attacker_controlled_input.into()));

    json!({
        "ruleId": rule_id,
        "candidateClass": CANDIDATE_CLASS,
        "claim": claim,
        "severityHint": severity_hint,
        "sources": sources,
        "sinks": sinks,
        "attackerCapabilities": attacker_capabilities,
        "preconditions": preconditions,
        "effects": effects,
        "assets": [],
        "trustBoundaryCrossings": [],
        "requiredControls": [],
        "observedControls": [],
        "chainRoles": chain_roles,
        "evidenceRefs": evidence_refs,
        "detectorMetadata": Value::Object(metadata),
        "uncertainty": uncertainty,
    })
}

fn precondition_supply_input(environment: &str) -> Value {
    json!({ "kind": "attacker-position", "subject": "actor:external", "action": "supply-input", "environment": environment })
}

fn effect(kind: &str, action: &str, object: Option<&str>, scope: &str, environment: &str) -> Value {
    json!({
        "kind": kind,
        "subject": "actor:external",
        "action": action,
        "object": object,
        "scope": scope,
        "environment": environment,
        "tenant": Value::Null,
    })
}

/// Port of the pack's `analyze(context)`.
pub fn analyze(context: &ResilienceContext) -> Vec<Value> {
    let mut observations = Vec::new();
    let combined_text = context
        .files
        .iter()
        .map(|f| f.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    // --- whole-repository boolean-state rules ------------------------

    if SERVER_MARKER.is_match(&combined_text) && !RATE_LIMIT_MARKER.is_match(&combined_text) {
        let gate = availability_claim_class(context, "global", false);
        observations.push(base_observation(
            "abuse.rate-limit.global-missing",
            "The application serves HTTP requests with no visible global rate limiter.",
            &cap_severity("medium", gate.severity_cap),
            gate.claim_class,
            "all HTTP endpoints",
            "request volume",
            vec![],
            vec![],
            vec!["submit-high-volume-requests"],
            vec![precondition_supply_input("network")],
            vec![effect("availability-impact", "exhaust", None, "http-request-capacity", "network")],
            vec!["enabler"],
            repo_wide_evidence_refs(context),
            Map::from_iter([("scope".to_string(), json!("repository")), ("filesExamined".to_string(), json!(context.files.len()))]),
            vec![
                "No global rate-limiter marker is not proof of no rate limiting; a reverse proxy, API gateway, or CDN could enforce it outside this repository.".to_string(),
                if gate.claim_class == "design-recommendation" {
                    "No cost or amplification evidence was observed for this surface; reported as an availability design recommendation, not a proven denial-of-service primitive.".to_string()
                } else {
                    format!("Cost/amplification evidence observed: {}.", gate.trace_note.unwrap_or_else(|| "elevated per-request cost recorded upstream".to_string()))
                },
            ],
        ));
    }

    if OUTBOUND_CALL_MARKER.is_match(&combined_text) && !CIRCUIT_BREAKER_MARKER.is_match(&combined_text) {
        observations.push(base_observation(
            "abuse.resilience.circuit-breaker-absent",
            "The application makes outbound calls to a downstream dependency with no visible circuit breaker, timeout backoff, or retry-budget pattern.",
            "low",
            "design-recommendation",
            "downstream dependency calls",
            "indirect — request volume amplifies a slow or failing downstream dependency",
            vec![],
            vec![],
            vec!["submit-high-volume-requests"],
            vec![precondition_supply_input("network")],
            vec![effect("availability-impact", "exhaust", None, "downstream-dependency-capacity", "network")],
            vec!["enabler"],
            repo_wide_evidence_refs(context),
            Map::from_iter([("scope".to_string(), json!("repository")), ("filesExamined".to_string(), json!(context.files.len()))]),
            vec!["Static analysis cannot prove a downstream dependency will actually degrade; this is a resilience design recommendation, never a proven denial-of-service primitive, and is always capped at low severity.".to_string()],
        ));
    }

    if GRAPHQL_SERVER_MARKER.is_match(&combined_text) {
        if !GRAPHQL_DEPTH_LIMIT_MARKER.is_match(&combined_text) {
            let gate = availability_claim_class(context, "graphql-depth", false);
            observations.push(base_observation(
                "abuse.graphql.depth-unbounded",
                "A GraphQL server is configured with no visible query-depth limit.",
                &cap_severity("medium", gate.severity_cap),
                gate.claim_class,
                "graphql schema",
                "query nesting depth",
                vec![],
                vec![],
                vec!["craft-graphql-query"],
                vec![precondition_supply_input("application")],
                vec![effect("availability-impact", "exhaust", None, "graphql-resolver-recursion", "application")],
                vec!["enabler"],
                repo_wide_evidence_refs(context),
                Map::from_iter([("scope".to_string(), json!("repository")), ("filesExamined".to_string(), json!(context.files.len()))]),
                vec![if gate.claim_class == "design-recommendation" {
                    "No resolver cost or amplification evidence was observed; reported as a design recommendation, not a proven denial-of-service primitive.".to_string()
                } else {
                    format!("Cost/amplification evidence observed: {}.", gate.trace_note.unwrap_or_else(|| "elevated resolver cost recorded upstream".to_string()))
                }],
            ));
        }
        if !GRAPHQL_COST_MARKER.is_match(&combined_text) {
            let gate = availability_claim_class(context, "graphql-cost", false);
            observations.push(base_observation(
                "abuse.graphql.cost-unbounded",
                "A GraphQL server is configured with no visible query cost/complexity limit.",
                &cap_severity("medium", gate.severity_cap),
                gate.claim_class,
                "graphql schema",
                "query field selection and arguments",
                vec![],
                vec![],
                vec!["craft-graphql-query"],
                vec![precondition_supply_input("application")],
                vec![effect("availability-impact", "exhaust", None, "graphql-resolver-cost", "application")],
                vec!["enabler"],
                repo_wide_evidence_refs(context),
                Map::from_iter([("scope".to_string(), json!("repository")), ("filesExamined".to_string(), json!(context.files.len()))]),
                vec![if gate.claim_class == "design-recommendation" {
                    "No resolver cost or amplification evidence was observed; reported as a design recommendation, not a proven denial-of-service primitive.".to_string()
                } else {
                    format!("Cost/amplification evidence observed: {}.", gate.trace_note.unwrap_or_else(|| "elevated resolver cost recorded upstream".to_string()))
                }],
            ));
        }
    }

    // --- per-file / per-occurrence rules ------------------------------
    for file in &context.files {
        let text = file.text.as_str();
        if text.is_empty() || file.artifact_evidence_refs.is_empty() {
            continue;
        }
        let evidence_refs: Vec<Value> = file.artifact_evidence_refs.iter().cloned().map(Value::String).collect();

        // abuse.rate-limit.operation-missing
        for caps in IDENTITY_ROUTE.captures_iter(text) {
            let whole = caps.get(0).unwrap();
            if test_around(&RATE_LIMIT_MARKER, text, whole.start(), whole.len(), 0, 300) {
                continue;
            }
            let method = caps[1].to_uppercase();
            let route_key = &caps[2];
            let gate = availability_claim_class(context, route_key, false);
            observations.push(base_observation(
                "abuse.rate-limit.operation-missing",
                &format!("The identity-sensitive operation {method} {route_key} has no visible per-operation rate limit."),
                &cap_severity("high", gate.severity_cap),
                gate.claim_class,
                &format!("{method} {route_key}"),
                "request volume against this operation",
                vec![Value::String(file.artifact_id.clone())],
                vec![Value::String(file.artifact_id.clone())],
                vec!["submit-high-volume-requests"],
                vec![precondition_supply_input("application")],
                vec![effect("availability-impact", "exhaust", Some(file.artifact_id.as_str()), "identity-operation-capacity", "application")],
                vec!["enabler"],
                evidence_refs.clone(),
                Map::from_iter([
                    ("file".to_string(), json!(file.path)),
                    ("line".to_string(), json!(line_of(text, whole.start()))),
                    ("method".to_string(), json!(method)),
                    ("path".to_string(), json!(route_key)),
                ]),
                vec![
                    "A rate limiter registered globally elsewhere in the application is not visible from this file alone.".to_string(),
                    if gate.claim_class == "design-recommendation" {
                        "No cost or amplification evidence was observed for this operation; reported as a design recommendation, not a proven denial-of-service primitive.".to_string()
                    } else {
                        format!("Cost/amplification evidence observed: {}.", gate.trace_note.clone().unwrap_or_else(|| "elevated per-request cost recorded upstream".to_string()))
                    },
                ],
            ));
        }

        // abuse.graphql.introspection-enabled
        for m in GRAPHQL_INTROSPECTION_TRUE.find_iter(text) {
            observations.push(base_observation(
                "abuse.graphql.introspection-enabled",
                "A GraphQL server explicitly enables introspection.",
                "low",
                "proven-primitive",
                "graphql schema",
                "introspection query",
                vec![Value::String(file.artifact_id.clone())],
                vec![Value::String(file.artifact_id.clone())],
                vec!["craft-graphql-query"],
                vec![precondition_supply_input("application")],
                vec![effect("confidentiality-impact", "read", Some(file.artifact_id.as_str()), "graphql-schema-metadata", "application")],
                vec!["enabler"],
                evidence_refs.clone(),
                Map::from_iter([
                    ("file".to_string(), json!(file.path)),
                    ("line".to_string(), json!(line_of(text, m.start()))),
                    ("config".to_string(), json!("introspection: true")),
                ]),
                vec!["Introspection exposure is a reconnaissance aid, not itself a proven denial-of-service or data-access primitive; whether this deployment intends introspection to be public must be adjudicated.".to_string()],
            ));
        }

        // abuse.pagination.unbounded
        for m in PAGINATION_UNBOUNDED.find_iter(text) {
            if test_around(&PAGINATION_CAP_MARKER, text, m.start(), m.len(), 80, 80) {
                continue;
            }
            observations.push(base_observation(
                "abuse.pagination.unbounded",
                "A list endpoint takes its page size directly from request input with no visible upper-bound cap.",
                "medium",
                "proven-primitive",
                &format!("{} pagination endpoint", file.path),
                "page-size / limit / take query parameter",
                vec![Value::String(file.artifact_id.clone())],
                vec![Value::String(file.artifact_id.clone())],
                vec!["control-request-input"],
                vec![precondition_supply_input("application")],
                vec![effect("availability-impact", "exhaust", Some(file.artifact_id.as_str()), "query-result-size", "application")],
                vec!["starter", "impact"],
                evidence_refs.clone(),
                Map::from_iter([
                    ("file".to_string(), json!(file.path)),
                    ("line".to_string(), json!(line_of(text, m.start()))),
                    ("config".to_string(), json!(truncate(m.as_str(), 60))),
                ]),
                vec!["Impact depends on the backing data volume and whether a database-level default limit exists outside this file.".to_string()],
            ));
        }

        // abuse.data.over-exposed-fields
        if SENSITIVE_FIELD_NAME.is_match(text) && !FIELD_ALLOWLIST_MARKER.is_match(text) {
            for caps in RESPONSE_FULL_OBJECT.captures_iter(text) {
                let whole = caps.get(0).unwrap();
                let kind = &caps[1];
                observations.push(base_observation(
                    "abuse.data.over-exposed-fields",
                    &format!("A {kind} record is serialized directly into a response with no visible field allowlist, and the file contains a sensitive-looking field name."),
                    "medium",
                    "proven-primitive",
                    &format!("{} response serialization", file.path),
                    "endpoint invocation (which fields are returned is server-controlled, not attacker-selected)",
                    vec![Value::String(file.artifact_id.clone())],
                    vec![Value::String(file.artifact_id.clone())],
                    vec!["invoke-authorized-or-unauthorized-endpoint"],
                    vec![json!({ "kind": "attacker-position", "subject": "actor:external", "action": "invoke-endpoint", "environment": "application" })],
                    vec![effect("confidentiality-impact", "read", Some(file.artifact_id.as_str()), "over-exposed-response-fields", "application")],
                    vec!["starter", "impact"],
                    evidence_refs.clone(),
                    Map::from_iter([
                        ("file".to_string(), json!(file.path)),
                        ("line".to_string(), json!(line_of(text, whole.start()))),
                        ("config".to_string(), json!(whole.as_str())),
                    ]),
                    vec!["Whether the sensitive-looking field actually reaches the serialized object (rather than being unrelated code in the same file) requires adjudication of the object shape.".to_string()],
                ));
            }
        }

        // abuse.webhook.signature-missing / abuse.webhook.signature-verified-after-use
        for m in WEBHOOK_ROUTE.find_iter(text) {
            let window_text = slice_around(text, m.start(), m.len(), 0, 600);
            let has_signature_check = SIGNATURE_VERIFY_MARKER.is_match(&window_text);
            if !has_signature_check {
                observations.push(base_observation(
                    "abuse.webhook.signature-missing",
                    "A webhook/callback receiver has no visible signature or authenticity verification anywhere in its handler.",
                    "high",
                    "proven-primitive",
                    &format!("{} webhook receiver", file.path),
                    "webhook payload body",
                    vec![Value::String(file.artifact_id.clone())],
                    vec![Value::String(file.artifact_id.clone())],
                    vec!["submit-forged-webhook-request"],
                    vec![json!({ "kind": "attacker-position", "subject": "actor:external", "action": "submit-forged-request", "environment": "application" })],
                    vec![effect("integrity-impact", "forge", Some(file.artifact_id.as_str()), "webhook-event-trust", "application")],
                    vec!["starter", "control-bypass"],
                    evidence_refs.clone(),
                    Map::from_iter([
                        ("file".to_string(), json!(file.path)),
                        ("line".to_string(), json!(line_of(text, m.start()))),
                        ("route".to_string(), json!(m.as_str())),
                    ]),
                    vec!["A signature check performed by an upstream gateway or middleware not visible in this file cannot be ruled out.".to_string()],
                ));
            } else if let Some(use_match) = BODY_USE_MARKER.find(&window_text) {
                if let Some(verify_match) = SIGNATURE_VERIFY_MARKER.find(&window_text) {
                    if use_match.start() < verify_match.start() {
                        observations.push(base_observation(
                            "abuse.webhook.signature-verified-after-use",
                            "A webhook/callback receiver uses the request body before its signature is verified.",
                            "high",
                            "proven-primitive",
                            &format!("{} webhook receiver", file.path),
                            "webhook payload body",
                            vec![Value::String(file.artifact_id.clone())],
                            vec![Value::String(file.artifact_id.clone())],
                            vec!["submit-forged-webhook-request"],
                            vec![json!({ "kind": "attacker-position", "subject": "actor:external", "action": "submit-forged-request", "environment": "application" })],
                            vec![effect("integrity-impact", "forge", Some(file.artifact_id.as_str()), "webhook-event-trust", "application")],
                            vec!["starter", "control-bypass"],
                            evidence_refs.clone(),
                            Map::from_iter([
                                ("file".to_string(), json!(file.path)),
                                ("line".to_string(), json!(line_of(text, m.start()))),
                                ("route".to_string(), json!(m.as_str())),
                            ]),
                            vec!["The verification call is present but its ordering relative to body use is inferred from linear text proximity, not a control-flow graph.".to_string()],
                        ));
                    }
                }
            }
        }

        // abuse.mutation.idempotency-key-missing
        for m in MUTATION_PAYMENT_ROUTE.find_iter(text) {
            if test_around(&IDEMPOTENCY_MARKER, text, m.start(), m.len(), 0, 400) {
                continue;
            }
            observations.push(base_observation(
                "abuse.mutation.idempotency-key-missing",
                "A payment/order mutation endpoint has no visible idempotency-key check, so a replayed request can duplicate the mutation.",
                "medium",
                "proven-primitive",
                m.as_str(),
                "request replay / retry count",
                vec![Value::String(file.artifact_id.clone())],
                vec![Value::String(file.artifact_id.clone())],
                vec!["replay-request"],
                vec![json!({ "kind": "attacker-position", "subject": "actor:external", "action": "replay-request", "environment": "application" })],
                vec![effect("integrity-impact", "duplicate", Some(file.artifact_id.as_str()), "financial-mutation", "application")],
                vec!["starter", "impact"],
                evidence_refs.clone(),
                Map::from_iter([
                    ("file".to_string(), json!(file.path)),
                    ("line".to_string(), json!(line_of(text, m.start()))),
                    ("route".to_string(), json!(m.as_str())),
                ]),
                vec!["A database-level unique constraint or an upstream gateway-level idempotency layer not visible in this file could still prevent duplication.".to_string()],
            ));
        }

        // abuse.resource.exhaustion-unbounded-input
        for m in UNBOUNDED_ALLOCATION.find_iter(text) {
            if test_around(&RESOURCE_CAP_MARKER, text, m.start(), m.len(), 100, 200) {
                continue;
            }
            observations.push(base_observation(
                "abuse.resource.exhaustion-unbounded-input",
                "A loop bound or memory allocation size is taken directly from request input with no visible upper-bound cap.",
                "high",
                "proven-primitive",
                &format!("{} allocation/loop", file.path),
                "size/count parameter from request",
                vec![Value::String(file.artifact_id.clone())],
                vec![Value::String(file.artifact_id.clone())],
                vec!["control-request-input"],
                vec![precondition_supply_input("application")],
                vec![effect("availability-impact", "exhaust", Some(file.artifact_id.as_str()), "process-memory-or-cpu", "application")],
                vec!["starter", "impact"],
                evidence_refs.clone(),
                Map::from_iter([
                    ("file".to_string(), json!(file.path)),
                    ("line".to_string(), json!(line_of(text, m.start()))),
                    ("config".to_string(), json!(truncate(m.as_str(), 80))),
                ]),
                vec!["Actual impact depends on the process memory/CPU limits and whether an upstream body-size limit already bounds the input.".to_string()],
            ));
        }
    }

    observations
}

fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

// --- variant strategies ---------------------------------------------------

/// One matched location for a variant strategy, mirroring the JS
/// `{ file, line, semanticFingerprint, disposition }` match shape.
#[derive(Debug, PartialEq, Eq)]
pub struct VariantMatch {
    pub file: String,
    pub line: usize,
    pub semantic_fingerprint: String,
    pub disposition: &'static str,
}

/// Port of `lexicalVariantStrategy('abuse.rate-limit.operation-missing', ...)`'s `enumerate`.
pub fn variant_rate_limit_operation_missing(context: &ResilienceContext) -> Vec<VariantMatch> {
    let mut matches = Vec::new();
    for file in &context.files {
        let text = file.text.as_str();
        if text.is_empty() {
            continue;
        }
        for caps in IDENTITY_ROUTE.captures_iter(text) {
            let whole = caps.get(0).unwrap();
            if test_around(&RATE_LIMIT_MARKER, text, whole.start(), whole.len(), 0, 300) {
                continue;
            }
            let route_key = &caps[2];
            matches.push(VariantMatch {
                file: file.path.clone(),
                line: line_of(text, whole.start()),
                semantic_fingerprint: digest(&json!({ "file": file.path, "route": route_key })),
                disposition: "CONFIRMED",
            });
        }
    }
    matches
}

/// Port of `lexicalVariantStrategy('abuse.webhook.signature-missing', ...)`'s `enumerate`.
pub fn variant_webhook_signature_missing(context: &ResilienceContext) -> Vec<VariantMatch> {
    let mut matches = Vec::new();
    for file in &context.files {
        let text = file.text.as_str();
        if text.is_empty() {
            continue;
        }
        for m in WEBHOOK_ROUTE.find_iter(text) {
            let window_text = slice_around(text, m.start(), m.len(), 0, 600);
            if SIGNATURE_VERIFY_MARKER.is_match(&window_text) {
                continue;
            }
            matches.push(VariantMatch {
                file: file.path.clone(),
                line: line_of(text, m.start()),
                semantic_fingerprint: digest(&json!({ "file": file.path, "route": m.as_str() })),
                disposition: "CONFIRMED",
            });
        }
    }
    matches
}

/// Port of `lexicalVariantStrategy('abuse.webhook.signature-verified-after-use', ...)`'s `enumerate`.
pub fn variant_webhook_signature_verified_after_use(context: &ResilienceContext) -> Vec<VariantMatch> {
    let mut matches = Vec::new();
    for file in &context.files {
        let text = file.text.as_str();
        if text.is_empty() {
            continue;
        }
        for m in WEBHOOK_ROUTE.find_iter(text) {
            let window_text = slice_around(text, m.start(), m.len(), 0, 600);
            if !SIGNATURE_VERIFY_MARKER.is_match(&window_text) {
                continue;
            }
            let Some(use_match) = BODY_USE_MARKER.find(&window_text) else { continue };
            let Some(verify_match) = SIGNATURE_VERIFY_MARKER.find(&window_text) else { continue };
            if use_match.start() < verify_match.start() {
                matches.push(VariantMatch {
                    file: file.path.clone(),
                    line: line_of(text, m.start()),
                    semantic_fingerprint: digest(&json!({ "file": file.path, "route": m.as_str() })),
                    disposition: "CONFIRMED",
                });
            }
        }
    }
    matches
}

/// Port of `lexicalVariantStrategy('abuse.mutation.idempotency-key-missing', ...)`'s `enumerate`.
pub fn variant_mutation_idempotency_key_missing(context: &ResilienceContext) -> Vec<VariantMatch> {
    let mut matches = Vec::new();
    for file in &context.files {
        let text = file.text.as_str();
        if text.is_empty() {
            continue;
        }
        for m in MUTATION_PAYMENT_ROUTE.find_iter(text) {
            if test_around(&IDEMPOTENCY_MARKER, text, m.start(), m.len(), 0, 400) {
                continue;
            }
            matches.push(VariantMatch {
                file: file.path.clone(),
                line: line_of(text, m.start()),
                semantic_fingerprint: digest(&json!({ "file": file.path, "route": m.as_str() })),
                disposition: "CONFIRMED",
            });
        }
    }
    matches
}

/// Port of `lexicalVariantStrategy('abuse.pagination.unbounded', ...)`'s `enumerate`.
pub fn variant_pagination_unbounded(context: &ResilienceContext) -> Vec<VariantMatch> {
    let mut matches = Vec::new();
    for file in &context.files {
        let text = file.text.as_str();
        if text.is_empty() {
            continue;
        }
        for m in PAGINATION_UNBOUNDED.find_iter(text) {
            if test_around(&PAGINATION_CAP_MARKER, text, m.start(), m.len(), 80, 80) {
                continue;
            }
            matches.push(VariantMatch {
                file: file.path.clone(),
                line: line_of(text, m.start()),
                semantic_fingerprint: digest(&json!({ "file": file.path, "config": m.as_str() })),
                disposition: "CONFIRMED",
            });
        }
    }
    matches
}

/// Port of `lexicalVariantStrategy('abuse.resource.exhaustion-unbounded-input', ...)`'s `enumerate`.
pub fn variant_resource_exhaustion_unbounded_input(context: &ResilienceContext) -> Vec<VariantMatch> {
    let mut matches = Vec::new();
    for file in &context.files {
        let text = file.text.as_str();
        if text.is_empty() {
            continue;
        }
        for m in UNBOUNDED_ALLOCATION.find_iter(text) {
            if test_around(&RESOURCE_CAP_MARKER, text, m.start(), m.len(), 100, 200) {
                continue;
            }
            matches.push(VariantMatch {
                file: file.path.clone(),
                line: line_of(text, m.start()),
                semantic_fingerprint: digest(&json!({ "file": file.path, "config": m.as_str() })),
                disposition: "CONFIRMED",
            });
        }
    }
    matches
}

/// Static rule id list, mirroring the JS pack's frozen `rules` array
/// (id-only entries).
pub const RULE_IDS: &[&str] = &[
    "abuse.rate-limit.global-missing",
    "abuse.rate-limit.operation-missing",
    "abuse.graphql.depth-unbounded",
    "abuse.graphql.cost-unbounded",
    "abuse.graphql.introspection-enabled",
    "abuse.pagination.unbounded",
    "abuse.data.over-exposed-fields",
    "abuse.webhook.signature-missing",
    "abuse.webhook.signature-verified-after-use",
    "abuse.mutation.idempotency-key-missing",
    "abuse.resource.exhaustion-unbounded-input",
    "abuse.resilience.circuit-breaker-absent",
];

pub fn pack_id() -> &'static str {
    "security.abuse-resilience"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> ResilienceFile {
        ResilienceFile {
            path: path.to_string(),
            text: text.to_string(),
            artifact_id: format!("artifact:{path}"),
            artifact_evidence_refs: vec![format!("ev:{path}")],
        }
    }

    fn context(files: Vec<ResilienceFile>) -> ResilienceContext {
        ResilienceContext { files, performance_traces: vec![] }
    }

    #[test]
    fn server_without_rate_limiter_is_flagged_as_design_recommendation_by_default() {
        let ctx = context(vec![file("src/server.js", "app.listen(3000)")]);
        let obs = analyze(&ctx);
        let finding = obs.iter().find(|o| o["ruleId"] == "abuse.rate-limit.global-missing").expect("finding present");
        assert_eq!(finding["severityHint"], "low");
        assert_eq!(finding["detectorMetadata"]["claimClass"], "design-recommendation");
    }

    #[test]
    fn server_with_rate_limiter_is_not_flagged() {
        let ctx = context(vec![file("src/server.js", "app.listen(3000); app.use(rateLimit())")]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.rate-limit.global-missing"));
    }

    #[test]
    fn performance_cost_evidence_upgrades_global_rate_limit_finding_to_proven_primitive() {
        let mut ctx = context(vec![file("src/server.js", "app.listen(3000)")]);
        ctx.performance_traces.push(PerformanceTrace {
            file: None,
            route: Some("global".to_string()),
            cost_evidence: true,
            note: Some("p99 800ms".to_string()),
        });
        let obs = analyze(&ctx);
        let finding = obs.iter().find(|o| o["ruleId"] == "abuse.rate-limit.global-missing").expect("finding present");
        assert_eq!(finding["severityHint"], "medium");
        assert_eq!(finding["detectorMetadata"]["claimClass"], "proven-primitive");
    }

    #[test]
    fn login_route_without_rate_limit_nearby_is_flagged() {
        let ctx = context(vec![file(
            "src/routes/auth.js",
            "router.post('/login', (req, res) => { doLogin(req, res); })",
        )]);
        let obs = analyze(&ctx);
        let finding = obs
            .iter()
            .find(|o| o["ruleId"] == "abuse.rate-limit.operation-missing")
            .expect("finding present");
        assert_eq!(finding["detectorMetadata"]["method"], "POST");
        assert_eq!(finding["detectorMetadata"]["path"], "/login");
        assert_eq!(finding["severityHint"], "low"); // capped design-recommendation
    }

    #[test]
    fn login_route_with_nearby_rate_limit_marker_is_not_flagged() {
        let ctx = context(vec![file(
            "src/routes/auth.js",
            "router.post('/login', loginRateLimit, (req, res) => { doLogin(req, res); })",
        )]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.rate-limit.operation-missing"));
    }

    #[test]
    fn graphql_server_without_depth_or_cost_limit_flags_both() {
        let ctx = context(vec![file("src/graphql.js", "new ApolloServer({ schema })")]);
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o["ruleId"] == "abuse.graphql.depth-unbounded"));
        assert!(obs.iter().any(|o| o["ruleId"] == "abuse.graphql.cost-unbounded"));
    }

    #[test]
    fn graphql_introspection_true_is_always_proven_and_low_severity() {
        let ctx = context(vec![file("src/graphql.js", "new ApolloServer({ introspection: true })")]);
        let obs = analyze(&ctx);
        let finding = obs
            .iter()
            .find(|o| o["ruleId"] == "abuse.graphql.introspection-enabled")
            .expect("finding present");
        assert_eq!(finding["severityHint"], "low");
        assert_eq!(finding["detectorMetadata"]["claimClass"], "proven-primitive");
    }

    #[test]
    fn pagination_unbounded_without_math_min_is_flagged() {
        let ctx = context(vec![file("src/list.js", "db.find().limit(req.query.limit)")]);
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o["ruleId"] == "abuse.pagination.unbounded"));
    }

    #[test]
    fn pagination_unbounded_with_nearby_math_min_is_not_flagged() {
        let ctx = context(vec![file(
            "src/list.js",
            "const take = Math.min(req.query.limit, 100); db.find().limit(req.query.limit)",
        )]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.pagination.unbounded"));
    }

    #[test]
    fn sensitive_field_with_unallowlisted_full_object_response_is_flagged() {
        let ctx = context(vec![file(
            "src/users.js",
            "const password = user.password; app.get('/me', (req, res) => { res.json(user) })",
        )]);
        let obs = analyze(&ctx);
        let finding = obs.iter().find(|o| o["ruleId"] == "abuse.data.over-exposed-fields").expect("finding present");
        assert_eq!(finding["detectorMetadata"]["config"], "res.json(user)");
    }

    #[test]
    fn sensitive_field_with_allowlist_marker_is_not_flagged() {
        let ctx = context(vec![file(
            "src/users.js",
            "const password = user.password; res.json(sanitizeUser(user))",
        )]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.data.over-exposed-fields"));
    }

    #[test]
    fn webhook_without_any_signature_check_is_flagged_missing() {
        let ctx = context(vec![file(
            "src/webhooks.js",
            "app.post('/webhook', (req, res) => { process(req.body); })",
        )]);
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o["ruleId"] == "abuse.webhook.signature-missing"));
    }

    #[test]
    fn webhook_verifying_signature_before_body_use_is_clean() {
        let ctx = context(vec![file(
            "src/webhooks.js",
            "app.post('/webhook', (req, res) => { verifyWebhookSignature(req); process(req.body); })",
        )]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"].as_str().unwrap_or("").starts_with("abuse.webhook")));
    }

    #[test]
    fn webhook_using_body_before_verifying_signature_is_flagged_verified_after_use() {
        let ctx = context(vec![file(
            "src/webhooks.js",
            "app.post('/webhook', (req, res) => { process(req.body); verifyWebhookSignature(req); })",
        )]);
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o["ruleId"] == "abuse.webhook.signature-verified-after-use"));
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.webhook.signature-missing"));
    }

    #[test]
    fn payment_mutation_without_idempotency_key_is_flagged() {
        let ctx = context(vec![file(
            "src/payments.js",
            "router.post('/charge', (req, res) => { chargeCard(req.body); })",
        )]);
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o["ruleId"] == "abuse.mutation.idempotency-key-missing"));
    }

    #[test]
    fn payment_mutation_with_nearby_idempotency_key_is_not_flagged() {
        let ctx = context(vec![file(
            "src/payments.js",
            "router.post('/charge', (req, res) => { const key = req.headers['Idempotency-Key']; chargeCard(req.body); })",
        )]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.mutation.idempotency-key-missing"));
    }

    #[test]
    fn unbounded_array_allocation_from_request_input_is_flagged() {
        let ctx = context(vec![file("src/buf.js", "const arr = new Array(req.query.count)")]);
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o["ruleId"] == "abuse.resource.exhaustion-unbounded-input"));
    }

    #[test]
    fn unbounded_allocation_with_nearby_math_min_is_not_flagged() {
        let ctx = context(vec![file(
            "src/buf.js",
            "const n = Math.min(req.query.count, 1000); const arr = new Array(req.query.count)",
        )]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.resource.exhaustion-unbounded-input"));
    }

    #[test]
    fn outbound_call_without_circuit_breaker_is_flagged_low_and_capped() {
        let ctx = context(vec![file("src/client.js", "axios.get('https://api.example.com')")]);
        let obs = analyze(&ctx);
        let finding = obs
            .iter()
            .find(|o| o["ruleId"] == "abuse.resilience.circuit-breaker-absent")
            .expect("finding present");
        assert_eq!(finding["severityHint"], "low");
    }

    #[test]
    fn outbound_call_with_circuit_breaker_is_not_flagged() {
        let ctx = context(vec![file(
            "src/client.js",
            "const breaker = new CircuitBreaker(fn); axios.get('https://api.example.com')",
        )]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.resilience.circuit-breaker-absent"));
    }

    #[test]
    fn file_with_no_artifact_evidence_refs_is_skipped_by_per_file_rules() {
        let ctx = context(vec![ResilienceFile {
            path: "src/orphan.js".into(),
            text: "router.post('/login', (req, res) => {})".into(),
            artifact_id: "artifact:orphan".into(),
            artifact_evidence_refs: vec![],
        }]);
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o["ruleId"] == "abuse.rate-limit.operation-missing"));
    }

    #[test]
    fn analysis_is_deterministic_across_runs() {
        let ctx = context(vec![file("src/server.js", "app.listen(3000)")]);
        let a = analyze(&ctx);
        let b = analyze(&ctx);
        assert_eq!(a, b);
    }

    #[test]
    fn variant_strategy_rate_limit_operation_missing_matches_analyze() {
        let ctx = context(vec![file(
            "src/routes/auth.js",
            "router.post('/login', (req, res) => { doLogin(req, res); })",
        )]);
        let matches = variant_rate_limit_operation_missing(&ctx);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].file, "src/routes/auth.js");
        assert_eq!(matches[0].disposition, "CONFIRMED");
    }

    #[test]
    fn variant_strategy_webhook_signature_missing_matches_analyze() {
        let ctx = context(vec![file(
            "src/webhooks.js",
            "app.post('/webhook', (req, res) => { process(req.body); })",
        )]);
        let matches = variant_webhook_signature_missing(&ctx);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn variant_strategy_pagination_unbounded_matches_analyze() {
        let ctx = context(vec![file("src/list.js", "db.find().limit(req.query.limit)")]);
        let matches = variant_pagination_unbounded(&ctx);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn rule_ids_list_has_all_twelve_rules() {
        assert_eq!(RULE_IDS.len(), 12);
        assert_eq!(pack_id(), "security.abuse-resilience");
    }
}
