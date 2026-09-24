//! Port of `src/providers/security/packs/browser-client.mjs`: browser-facing
//! surface controls — CSRF, CORS, cookie SameSite, clickjacking, open
//! redirect, OAuth redirect-URI handling, and Content-Security-Policy. No
//! network imports, no live probing — every observation is derived from
//! source text already loaded into the frozen denominator ([`Context::read_file`])
//! plus, when available, upstream runtime-header / deployment evidence
//! (B5-021) surfaced on [`Context::runtime_header`] / [`Context::has_deployment_evidence`].
//! That evidence is optional: every rule that depends on "what is actually
//! served" degrades to a capped, explicitly-flagged assumption when it is
//! absent, and never fails because it is missing.
//!
//! Scope: `analyze(context)` is ported faithfully. `variantStrategies`
//! (`rootCause`/`enumerate`, present for three of the twelve rule ids in the
//! JS source) is coverage-report bookkeeping over the same matches
//! `analyze()` already finds; it is not ported here, mirroring the scope
//! decision documented in wf060's `common.rs`.
//!
//! Two of the JS source's regexes use JS-only lookaround
//! (`SAMESITE_NONE_WITHOUT_SECURE`'s negative lookahead, and
//! `CSP_WILDCARD_SOURCE`'s lookbehind/lookahead word-boundary guards) that
//! the `regex` crate does not support. Both are reproduced with equivalent
//! hand-written scanners ([`find_samesite_none_without_secure`],
//! [`find_csp_wildcard_source`]) rather than a regex, preserving the exact
//! same match semantics.

use super::{cap_severity, line_of, Context, Fact, Observation};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

fn deployment_assumption_uncertainty(subject: &str) -> String {
    format!(
        "Deployment assumption: no runtime header or deployment evidence was available for {subject}; \
this claim assumes the observed source configuration is what is actually served, but a reverse \
proxy, CDN, load balancer, or platform default could add, strip, or override it at runtime."
    )
}

/// Mirrors JS `Boolean(value)` for the JSON value shapes a runtime header
/// snapshot can carry (string / bool / number / null; anything else, such
/// as an object, is truthy).
fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// Mirrors `runtimeHeaderCompliance(context, headerKey, isCompliant)`.
fn runtime_header_compliance(context: &Context, header_key: &str, is_compliant: impl Fn(&Value) -> bool) -> Option<bool> {
    let value = context.runtime_header(header_key)?;
    Some(is_compliant(value))
}

struct DeploymentOutcome {
    severity_cap: Option<&'static str>,
    uncertainty: Vec<String>,
    deployment_assumption: Option<Value>,
    disagreement: Option<Value>,
}

/// Mirrors `evaluateDeploymentAwareClaim`. Returns `None` when the claim is
/// clean (nothing to emit).
fn evaluate_deployment_aware_claim(
    subject: &str,
    source_compliant: bool,
    runtime_compliant: Option<bool>,
    compliant_label: &str,
    non_compliant_label: &str,
) -> Option<DeploymentOutcome> {
    match runtime_compliant {
        None => {
            if source_compliant {
                None
            } else {
                Some(DeploymentOutcome {
                    severity_cap: Some("medium"),
                    uncertainty: vec![deployment_assumption_uncertainty(subject)],
                    deployment_assumption: Some(json!({ "assumption": "source-config-reflects-served-state", "subject": subject })),
                    disagreement: None,
                })
            }
        }
        Some(runtime_compliant) => {
            if source_compliant == runtime_compliant {
                if runtime_compliant {
                    None
                } else {
                    Some(DeploymentOutcome { severity_cap: None, uncertainty: vec![], deployment_assumption: None, disagreement: None })
                }
            } else {
                Some(DeploymentOutcome {
                    severity_cap: Some("medium"),
                    uncertainty: vec![format!(
                        "Source configuration and observed runtime evidence disagree for {subject}; both are recorded rather than one being treated as authoritative."
                    )],
                    deployment_assumption: None,
                    disagreement: Some(json!({
                        "subject": subject,
                        "sourceValue": if source_compliant { compliant_label } else { non_compliant_label },
                        "runtimeValue": if runtime_compliant { compliant_label } else { non_compliant_label },
                    })),
                })
            }
        }
    }
}

/// Mirrors `deploymentGate(context, subject)`.
fn deployment_gate(context: &Context, subject: &str) -> DeploymentOutcome {
    if context.has_deployment_evidence() {
        DeploymentOutcome { severity_cap: None, uncertainty: vec![], deployment_assumption: None, disagreement: None }
    } else {
        DeploymentOutcome {
            severity_cap: Some("medium"),
            uncertainty: vec![deployment_assumption_uncertainty(subject)],
            deployment_assumption: Some(json!({ "assumption": "source-config-reflects-served-state", "subject": subject })),
            disagreement: None,
        }
    }
}

fn repo_wide_evidence_refs(context: &Context) -> Vec<String> {
    let mut refs = std::collections::BTreeSet::new();
    for file in &context.files {
        if let Some(artifact) = context.find_artifact(file) {
            for r in &artifact.evidence_refs {
                refs.insert(r.clone());
            }
        }
    }
    refs.into_iter().collect()
}

static CSRF_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)csrf|csurf|xsrf|_csrf|antiforgery").unwrap());
static COOKIE_SESSION_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)cookie-session|req\.session|res\.cookie|express-session").unwrap());
static STATE_CHANGING_ROUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(?:app|router)\.(post|put|patch|delete)\(\s*['"]([^'"]+)['"]"#).unwrap());

static SESSION_COOKIE_STATEMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:res\.cookie|Set-Cookie)[^\n]{0,40}(?:session|auth|token|jwt)[^\n]{0,150}").unwrap());

static CORS_WILDCARD_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]?\*[\s\S]{0,300}Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?(?:true|1)"#).unwrap()
});
static CORS_REFLECTED_ORIGIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)Access-Control-Allow-Origin['"]?\s*[:,]\s*(?:req|request|ctx)\.(?:headers\.)?origin"#).unwrap());
static CORS_ALLOWLIST_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)allow(?:ed)?Origins?|origin\s*===|includes\(\s*origin\s*\)").unwrap());

static FRAME_PROTECTION_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)X-Frame-Options|frame-ancestors").unwrap());
static SERVES_HTML_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)<html|res\.render|getServerSideProps|\.ejs\b|\.hbs\b|app\.get\(\s*['"]/"#).unwrap());

static OPEN_REDIRECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)res\.redirect\(\s*(?:req|request)\.(?:query|params|body)\.[a-zA-Z_][\w]*").unwrap());
static REDIRECT_ALLOWLIST_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)allowedRedirects|isValidRedirect|startsWith\(\s*['"]/"#).unwrap());

static OAUTH_REDIRECT_FROM_REQUEST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)redirect_uri['"]?\s*[:=]\s*(?:req|request)\.(?:query|params|body)"#).unwrap());
static OAUTH_ALLOWLIST_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)redirectUriAllowlist|exact.?match|===\s*['"]https?://"#).unwrap());

static CSP_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Content-Security-Policy").unwrap());
static CSP_UNSAFE_INLINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Content-Security-Policy[^\n]*unsafe-inline").unwrap());
static CSP_UNSAFE_EVAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Content-Security-Policy[^\n]*unsafe-eval").unwrap());
static CSP_HEADER_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Content-Security-Policy").unwrap());
static CSP_WILDCARD_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)script-src|default-src|connect-src").unwrap());

/// Word-class used by `CSP_WILDCARD_SOURCE`'s lookaround guards
/// (`[\w.-]`): word char, `.`, or `-`.
fn is_wildcard_boundary_char(c: char) -> bool {
    !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Reproduces `SAMESITE_NONE_WITHOUT_SECURE = /SameSite=None(?![\s\S]{0,80}Secure)/gi`
/// without lookaround: for each `SameSite=None` occurrence, the match holds
/// only when `Secure` does not appear within the following 80 characters.
/// Returns the byte-index of each match's start.
fn find_samesite_none_without_secure(text: &str) -> Vec<usize> {
    static SAMESITE_NONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)SameSite=None").unwrap());
    static SECURE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Secure").unwrap());
    let mut out = Vec::new();
    for m in SAMESITE_NONE.find_iter(text) {
        let window_start = m.end();
        let mut window_end = window_start;
        for _ in 0..80 {
            if window_end >= text.len() {
                break;
            }
            window_end += 1;
            while window_end < text.len() && !text.is_char_boundary(window_end) {
                window_end += 1;
            }
        }
        let window = &text[window_start..window_end.min(text.len())];
        if !SECURE.is_match(window) {
            out.push(m.start());
        }
    }
    out
}

/// Reproduces
/// `CSP_WILDCARD_SOURCE = /Content-Security-Policy[^;\n]*(?:script-src|default-src|connect-src)[^;\n]*(?<![\w.-])\*(?![\w.-])/gi`
/// without lookaround. For each `Content-Security-Policy` occurrence, scans
/// forward to the first `;` or newline (the JS `[^;\n]*` boundary), then
/// within that window looks for a wildcard-directive name followed by a
/// `*` whose neighboring characters are not word/`.`/`-`.
/// Returns each match's byte-index (the `Content-Security-Policy` start).
fn find_csp_wildcard_source(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for m in CSP_HEADER_MARKER.find_iter(text) {
        let start = m.start();
        let mut window_end = start;
        for (i, ch) in text[start..].char_indices() {
            if ch == ';' || ch == '\n' {
                window_end = start + i;
                break;
            }
            window_end = start + i + ch.len_utf8();
        }
        let window = &text[start..window_end];
        let Some(directive_match) = CSP_WILDCARD_DIRECTIVE.find(window) else { continue };
        let after_directive = &window[directive_match.end()..];
        let mut found = false;
        for (byte_off, ch) in after_directive.char_indices() {
            if ch != '*' {
                continue;
            }
            let abs = start + directive_match.end() + byte_off;
            let prev_ok = text[..abs].chars().next_back().map(is_wildcard_boundary_char).unwrap_or(true);
            let next_idx = abs + ch.len_utf8();
            let next_ok = text[next_idx..].chars().next().map(is_wildcard_boundary_char).unwrap_or(true);
            if prev_ok && next_ok {
                found = true;
                break;
            }
        }
        if found {
            out.push(start);
        }
    }
    out
}

pub const ID: &str = "security.browser-client";
pub const CANDIDATE_CLASS: &str = "browser-client";

#[allow(clippy::too_many_arguments)]
fn base_observation(
    rule_id: &str,
    claim: String,
    severity_hint: String,
    primitive_class: &str,
    sources: Vec<String>,
    sinks: Vec<String>,
    attacker_capabilities: Vec<&str>,
    preconditions: Vec<Fact>,
    effects: Vec<Fact>,
    chain_roles: Vec<&str>,
    evidence_refs: Vec<String>,
    mut detector_metadata: Value,
    uncertainty: Vec<String>,
) -> Observation {
    if let Value::Object(map) = &mut detector_metadata {
        map.insert("primitiveClass".to_string(), Value::String(primitive_class.to_string()));
    }
    Observation {
        rule_id: rule_id.to_string(),
        candidate_class: CANDIDATE_CLASS.to_string(),
        claim,
        severity_hint,
        sources,
        sinks,
        attacker_capabilities: attacker_capabilities.into_iter().map(String::from).collect(),
        preconditions,
        effects,
        assets: vec![],
        trust_boundary_crossings: vec![],
        required_controls: vec![],
        observed_controls: vec![],
        chain_roles: chain_roles.into_iter().map(String::from).collect(),
        evidence_refs,
        detector_metadata,
        uncertainty,
    }
}

fn attacker_position_fact(action: &str) -> Fact {
    Fact {
        kind: "attacker-position".to_string(),
        subject: "actor:external".to_string(),
        action: action.to_string(),
        object: None,
        scope: None,
        environment: "application".to_string(),
        tenant: None,
    }
}

fn effect_fact(kind: &str, action: &str, object: Option<String>, scope: &str) -> Fact {
    Fact {
        kind: kind.to_string(),
        subject: "actor:external".to_string(),
        action: action.to_string(),
        object,
        scope: Some(scope.to_string()),
        environment: "application".to_string(),
        tenant: None,
    }
}

/// Mirrors the JS pack's `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    let combined_text = context.files.iter().map(|f| context.read_file(f)).collect::<Vec<_>>().join("\n");

    // --- Per-file, code-logic rules (not deployment-dependent) -----------
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let Some(artifact) = context.find_artifact(file) else { continue };
        let evidence_refs = artifact.evidence_refs.clone();
        if evidence_refs.is_empty() {
            continue;
        }
        let artifact_id = artifact.id.clone();

        // csrf.state-changing-route.missing-token
        if COOKIE_SESSION_MARKER.is_match(text) && !CSRF_MARKER.is_match(text) {
            for cap in STATE_CHANGING_ROUTE.captures_iter(text) {
                let m = cap.get(0).unwrap();
                let method = cap.get(1).unwrap().as_str().to_uppercase();
                let path = cap.get(2).unwrap().as_str();
                observations.push(base_observation(
                    "csrf.state-changing-route.missing-token",
                    format!("A cookie-session-authenticated {method} {path} route has no visible CSRF token check."),
                    "high".to_string(),
                    "exploitable-primitive",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["cross-origin-page-load", "induce-victim-navigation"],
                    vec![attacker_position_fact("induce-cross-origin-request")],
                    vec![effect_fact("control-bypass", "bypass", Some(artifact_id.clone()), "csrf-protection")],
                    vec!["starter", "impact"],
                    evidence_refs.clone(),
                    json!({ "file": file, "line": line_of(text, m.start()), "method": method, "path": path }),
                    vec!["A CSRF middleware registered globally elsewhere in the application is not visible from this file alone.".to_string()],
                ));
            }
        }

        // csrf.samesite-none-without-secure
        for idx in find_samesite_none_without_secure(text) {
            observations.push(base_observation(
                "csrf.samesite-none-without-secure",
                "A cookie sets SameSite=None without a nearby Secure attribute.".to_string(),
                "medium".to_string(),
                "exploitable-primitive",
                vec![artifact_id.clone()],
                vec![artifact_id.clone()],
                vec!["cross-origin-page-load"],
                vec![attacker_position_fact("induce-cross-origin-request")],
                vec![effect_fact("control-bypass", "bypass", Some(artifact_id.clone()), "samesite-cookie-protection")],
                vec!["enabler"],
                evidence_refs.clone(),
                json!({ "file": file, "line": line_of(text, idx), "cookieAttribute": "SameSite=None" }),
                vec!["Modern browsers reject SameSite=None cookies without Secure outright; impact depends on the serving browser and transport.".to_string()],
            ));
        }

        // csrf.samesite-missing
        for m in SESSION_COOKIE_STATEMENT.find_iter(text) {
            let stmt = m.as_str();
            if Regex::new(r"(?i)SameSite").unwrap().is_match(stmt) {
                continue;
            }
            let snippet: String = stmt.chars().take(60).collect();
            observations.push(base_observation(
                "csrf.samesite-missing",
                "A session or auth cookie is set without any SameSite attribute.".to_string(),
                "medium".to_string(),
                "exploitable-primitive",
                vec![artifact_id.clone()],
                vec![artifact_id.clone()],
                vec!["cross-origin-page-load"],
                vec![attacker_position_fact("induce-cross-origin-request")],
                vec![effect_fact("control-bypass", "bypass", Some(artifact_id.clone()), "samesite-cookie-protection")],
                vec!["enabler"],
                evidence_refs.clone(),
                json!({ "file": file, "line": line_of(text, m.start()), "cookieStatement": snippet }),
                vec!["The framework default SameSite value (if any) is not visible from this statement alone.".to_string()],
            ));
        }

        // cors.wildcard-origin-with-credentials
        for m in CORS_WILDCARD_CREDENTIALS.find_iter(text) {
            observations.push(base_observation(
                "cors.wildcard-origin-with-credentials",
                "Access-Control-Allow-Origin: * is combined with Access-Control-Allow-Credentials: true.".to_string(),
                "critical".to_string(),
                "exploitable-primitive",
                vec![artifact_id.clone()],
                vec![artifact_id.clone()],
                vec!["cross-origin-page-load"],
                vec![attacker_position_fact("induce-cross-origin-request")],
                vec![effect_fact("confidentiality-impact", "read", Some(artifact_id.clone()), "cross-origin-credentialed-response")],
                vec!["starter", "impact"],
                evidence_refs.clone(),
                json!({ "file": file, "line": line_of(text, m.start()), "header": "Access-Control-Allow-Origin + Access-Control-Allow-Credentials" }),
                vec!["Browsers reject this exact header combination for credentialed requests in current CORS implementations; impact depends on client behavior.".to_string()],
            ));
        }

        // cors.reflected-origin-without-allowlist
        if !CORS_ALLOWLIST_MARKER.is_match(text) {
            for m in CORS_REFLECTED_ORIGIN.find_iter(text) {
                observations.push(base_observation(
                    "cors.reflected-origin-without-allowlist",
                    "The request Origin header is reflected into Access-Control-Allow-Origin with no visible allowlist check.".to_string(),
                    "high".to_string(),
                    "exploitable-primitive",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["cross-origin-page-load"],
                    vec![attacker_position_fact("induce-cross-origin-request")],
                    vec![effect_fact("confidentiality-impact", "read", Some(artifact_id.clone()), "cross-origin-credentialed-response")],
                    vec!["starter", "impact"],
                    evidence_refs.clone(),
                    json!({ "file": file, "line": line_of(text, m.start()), "header": "Access-Control-Allow-Origin" }),
                    vec!["An allowlist check applied before this statement is executed may exist outside the matched line.".to_string()],
                ));
            }
        }

        // open-redirect.unvalidated-target
        if !REDIRECT_ALLOWLIST_MARKER.is_match(text) {
            for m in OPEN_REDIRECT.find_iter(text) {
                observations.push(base_observation(
                    "open-redirect.unvalidated-target",
                    "A redirect target is taken directly from request input without a visible allowlist or relative-path check.".to_string(),
                    "medium".to_string(),
                    "exploitable-primitive",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["craft-malicious-link"],
                    vec![attacker_position_fact("supply-input")],
                    vec![effect_fact("integrity-impact", "redirect", Some(artifact_id.clone()), "redirect-target")],
                    vec!["starter", "enabler"],
                    evidence_refs.clone(),
                    json!({ "file": file, "line": line_of(text, m.start()), "config": "res.redirect target" }),
                    vec!["Open redirects are typically chained with phishing or OAuth token theft; standalone impact depends on what trusts the redirecting origin.".to_string()],
                ));
            }
        }

        // oauth.redirect-uri.unvalidated
        if !OAUTH_ALLOWLIST_MARKER.is_match(text) {
            for m in OAUTH_REDIRECT_FROM_REQUEST.find_iter(text) {
                observations.push(base_observation(
                    "oauth.redirect-uri.unvalidated",
                    "An OAuth redirect_uri is built from request input with no visible exact-match allowlist.".to_string(),
                    "high".to_string(),
                    "exploitable-primitive",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["craft-malicious-link"],
                    vec![attacker_position_fact("supply-input")],
                    vec![effect_fact("confidentiality-impact", "intercept", Some(artifact_id.clone()), "oauth-authorization-code")],
                    vec!["starter", "impact"],
                    evidence_refs.clone(),
                    json!({ "file": file, "line": line_of(text, m.start()), "config": "redirect_uri" }),
                    vec!["The OAuth provider may independently enforce a registered redirect_uri allowlist outside this repository.".to_string()],
                ));
            }
        }

        // csp.unsafe-inline / csp.unsafe-eval / csp.wildcard-source
        for (rule_id, matches, token) in [
            ("csp.unsafe-inline", CSP_UNSAFE_INLINE.find_iter(text).map(|m| m.start()).collect::<Vec<_>>(), "'unsafe-inline'"),
            ("csp.unsafe-eval", CSP_UNSAFE_EVAL.find_iter(text).map(|m| m.start()).collect::<Vec<_>>(), "'unsafe-eval'"),
            ("csp.wildcard-source", find_csp_wildcard_source(text), "*"),
        ] {
            for idx in matches {
                let gate = deployment_gate(context, &format!("Content-Security-Policy {token}"));
                let mut metadata = json!({
                    "file": file,
                    "line": line_of(text, idx),
                    "header": "Content-Security-Policy",
                    "directive": token,
                });
                if let Some(da) = &gate.deployment_assumption {
                    metadata["deploymentAssumption"] = da.clone();
                }
                let mut uncertainty = vec!["A CSP weakness is only exploitable in combination with an independent injection point; it is not itself proof of one.".to_string()];
                uncertainty.extend(gate.uncertainty.clone());
                observations.push(base_observation(
                    rule_id,
                    format!("The Content-Security-Policy configuration includes {token}, weakening script-source restriction."),
                    cap_severity("low", gate.severity_cap),
                    "defense-in-depth",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["inject-html-or-script"],
                    vec![attacker_position_fact("inject-content")],
                    vec![effect_fact("control-bypass", "bypass", Some(artifact_id.clone()), "content-security-policy")],
                    vec!["enabler"],
                    evidence_refs.clone(),
                    metadata,
                    uncertainty,
                ));
            }
        }
    }

    // --- Whole-repository, deployment-aware boolean-state rules ----------

    // clickjacking.missing-frame-protection
    if SERVES_HTML_MARKER.is_match(&combined_text) {
        let source_compliant = FRAME_PROTECTION_MARKER.is_match(&combined_text);
        let runtime_compliant = runtime_header_compliance(context, "x-frame-options", js_truthy)
            .or_else(|| runtime_header_compliance(context, "content-security-policy", |v| Regex::new(r"(?i)frame-ancestors").unwrap().is_match(v.as_str().unwrap_or_default())));
        if let Some(outcome) = evaluate_deployment_aware_claim("X-Frame-Options / frame-ancestors", source_compliant, runtime_compliant, "present", "absent") {
            let mut metadata = json!({
                "scope": "repository",
                "header": "X-Frame-Options / Content-Security-Policy frame-ancestors",
                "filesExamined": context.files.len(),
            });
            if let Some(d) = &outcome.disagreement {
                metadata["disagreement"] = d.clone();
            }
            if let Some(da) = &outcome.deployment_assumption {
                metadata["deploymentAssumption"] = da.clone();
            }
            observations.push(base_observation(
                "clickjacking.missing-frame-protection",
                "No X-Frame-Options header or CSP frame-ancestors directive was found across the scanned, HTML-serving surface.".to_string(),
                cap_severity("low", outcome.severity_cap),
                "defense-in-depth",
                vec![],
                vec![],
                vec!["embed-victim-page-in-frame"],
                vec![attacker_position_fact("host-malicious-page")],
                vec![effect_fact("control-bypass", "bypass", None, "frame-protection")],
                vec!["enabler"],
                repo_wide_evidence_refs(context),
                metadata,
                outcome.uncertainty,
            ));
        }
    }

    // csp.missing
    {
        let source_compliant = CSP_MARKER.is_match(&combined_text);
        let runtime_compliant = runtime_header_compliance(context, "content-security-policy", js_truthy);
        if let Some(outcome) = evaluate_deployment_aware_claim("Content-Security-Policy header", source_compliant, runtime_compliant, "present", "absent") {
            let mut metadata = json!({
                "scope": "repository",
                "header": "Content-Security-Policy",
                "filesExamined": context.files.len(),
            });
            if let Some(d) = &outcome.disagreement {
                metadata["disagreement"] = d.clone();
            }
            if let Some(da) = &outcome.deployment_assumption {
                metadata["deploymentAssumption"] = da.clone();
            }
            observations.push(base_observation(
                "csp.missing",
                "No Content-Security-Policy was found across the scanned surface.".to_string(),
                cap_severity("low", outcome.severity_cap),
                "defense-in-depth",
                vec![],
                vec![],
                vec!["inject-html-or-script"],
                vec![attacker_position_fact("inject-content")],
                vec![effect_fact("control-bypass", "bypass", None, "content-security-policy")],
                vec!["enabler"],
                repo_wide_evidence_refs(context),
                metadata,
                outcome.uncertainty,
            ));
        }
    }

    observations
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn csrf_missing_token_on_state_changing_route() {
        let ctx = Context::new().with_file(
            "routes.mjs",
            "req.session.user = 1;\napp.post('/account', (req, res) => { res.cookie('x', '1'); });",
        );
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o.rule_id == "csrf.state-changing-route.missing-token"));
    }

    #[test]
    fn csrf_marker_present_suppresses_state_changing_route_rule() {
        let ctx = Context::new().with_file(
            "routes.mjs",
            "req.session.user = 1;\napp.use(csrf());\napp.post('/account', (req, res) => {});",
        );
        assert!(!analyze(&ctx).iter().any(|o| o.rule_id == "csrf.state-changing-route.missing-token"));
    }

    #[test]
    fn samesite_none_without_secure_flagged() {
        let ctx = Context::new().with_file("app.mjs", "res.header('Set-Cookie', 'sid=1; SameSite=None; Path=/');");
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o.rule_id == "csrf.samesite-none-without-secure"));
    }

    #[test]
    fn samesite_none_with_nearby_secure_is_not_flagged() {
        let ctx = Context::new().with_file("app.mjs", "res.header('Set-Cookie', 'sid=1; SameSite=None; Secure; Path=/');");
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o.rule_id == "csrf.samesite-none-without-secure"));
    }

    #[test]
    fn cors_wildcard_with_credentials_is_critical() {
        let ctx = Context::new().with_file(
            "cors.mjs",
            "res.setHeader('Access-Control-Allow-Origin', '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
        );
        let obs = analyze(&ctx);
        let hit = obs.iter().find(|o| o.rule_id == "cors.wildcard-origin-with-credentials").unwrap();
        assert_eq!(hit.severity_hint, "critical");
    }

    #[test]
    fn cors_reflected_origin_without_allowlist() {
        let ctx = Context::new().with_file("cors.mjs", "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);");
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o.rule_id == "cors.reflected-origin-without-allowlist"));
    }

    #[test]
    fn cors_reflected_origin_suppressed_by_allowlist_marker() {
        let ctx = Context::new().with_file(
            "cors.mjs",
            "if (allowedOrigins.includes(origin)) { res.setHeader('Access-Control-Allow-Origin', req.headers.origin); }",
        );
        assert!(!analyze(&ctx).iter().any(|o| o.rule_id == "cors.reflected-origin-without-allowlist"));
    }

    #[test]
    fn open_redirect_unvalidated_target() {
        let ctx = Context::new().with_file("redirect.mjs", "res.redirect(req.query.next);");
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o.rule_id == "open-redirect.unvalidated-target"));
    }

    #[test]
    fn oauth_redirect_uri_unvalidated() {
        let ctx = Context::new().with_file("oauth.mjs", "const redirect_uri = req.query.redirect_uri;");
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o.rule_id == "oauth.redirect-uri.unvalidated"));
    }

    #[test]
    fn csp_unsafe_inline_capped_without_deployment_evidence() {
        let ctx = Context::new().with_file("headers.mjs", "res.setHeader('Content-Security-Policy', \"script-src 'unsafe-inline'\");");
        let obs = analyze(&ctx);
        let hit = obs.iter().find(|o| o.rule_id == "csp.unsafe-inline").unwrap();
        assert_eq!(hit.severity_hint, "low");
    }

    #[test]
    fn csp_wildcard_source_detected() {
        let ctx = Context::new().with_file("headers.mjs", "res.setHeader('Content-Security-Policy', 'script-src *');");
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o.rule_id == "csp.wildcard-source"));
    }

    #[test]
    fn csp_wildcard_source_not_flagged_when_part_of_a_word() {
        let ctx = Context::new().with_file("headers.mjs", "res.setHeader('Content-Security-Policy', 'script-src abc*def.com');");
        let obs = analyze(&ctx);
        assert!(!obs.iter().any(|o| o.rule_id == "csp.wildcard-source"));
    }

    #[test]
    fn csp_missing_across_repository() {
        let ctx = Context::new().with_file("app.mjs", "app.get('/', (req, res) => res.render('index'));");
        let obs = analyze(&ctx);
        let hit = obs.iter().find(|o| o.rule_id == "csp.missing").unwrap();
        assert_eq!(hit.severity_hint, "low");
        assert!(hit.uncertainty[0].contains("Deployment assumption"));
    }

    #[test]
    fn csp_missing_suppressed_when_runtime_header_present() {
        let mut headers = HashMap::new();
        headers.insert("content-security-policy".to_string(), Value::String("default-src 'self'".to_string()));
        let ctx = Context::new()
            .with_file("app.mjs", "app.get('/', (req, res) => res.render('index'));")
            .with_audit_facts(super::super::AuditFacts { deployment: None, runtime_headers: Some(headers) });
        assert!(!analyze(&ctx).iter().any(|o| o.rule_id == "csp.missing"));
    }

    #[test]
    fn clickjacking_missing_frame_protection_only_when_serving_html() {
        let ctx = Context::new().with_file("lib.mjs", "export function add(a, b) { return a + b; }");
        assert!(!analyze(&ctx).iter().any(|o| o.rule_id == "clickjacking.missing-frame-protection"));
    }

    #[test]
    fn empty_evidence_refs_file_is_skipped_for_per_file_rules() {
        let mut ctx = Context::new();
        ctx.files.push("noev.mjs".to_string());
        ctx = ctx.with_entity(super::super::Entity {
            id: "artifact:noev.mjs".to_string(),
            kind: "repository-artifact".to_string(),
            name: "noev.mjs".to_string(),
            attributes: json!({ "path": "noev.mjs" }),
            evidence_refs: vec![],
        });
        // No content registered, so read_file returns "" and the loop's
        // `if text.is_empty() { continue }` skips it before the
        // evidence-refs check is even reached; this exercises that path.
        assert!(analyze(&ctx).is_empty());
    }
}
