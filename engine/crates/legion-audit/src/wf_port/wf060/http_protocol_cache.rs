//! Port of `src/providers/security/packs/http-protocol-cache.mjs`:
//! transport/protocol/cache/proxy security — HSTS, HTTPS enforcement,
//! security response headers, caching of sensitive content, proxy trust and
//! forwarded-header handling, request-smuggling preconditions, and
//! content-type behaviour. No network imports, no live probing — every
//! observation is derived from source text already loaded, plus, when
//! available, upstream runtime-header / deployment evidence surfaced on
//! `context.projection.auditFacts`. This pack is inherently
//! deployment-shaped: every rule degrades to a capped, explicitly-flagged
//! assumption when runtime/deployment evidence is absent, and never fails
//! because it is missing.
//!
//! Only `analyze()` is ported (see `wf060/common.rs` module doc for why
//! `variantStrategies` is out of scope for this chunk).

use super::common::{cap_severity, digest, line_of, Context, Fact, Observation};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

pub const ID: &str = "security.http-protocol-cache";
pub const CANDIDATE_CLASS: &str = "http-protocol";

fn hsts_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)Strict-Transport-Security").unwrap())
}
fn http_create_server() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)http\.createServer\(").unwrap())
}
fn https_enforcement_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)https\.createServer\(|forceSSL|requireHTTPS|express-sslify|helmet(?:\s*\(|\.hsts)")
            .unwrap()
    })
}
fn content_type_options_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)X-Content-Type-Options[^\n]*nosniff").unwrap())
}
fn content_type_missing_charset() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)Content-Type['"]?\s*[:,]\s*['"]text/(?:html|plain)(?:;[^'"]*)?['"]"#).unwrap()
    })
}
fn sensitive_route_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)req\.(?:session|user)|Authorization|\baccount\b|\bprofile\b|\bbilling\b|\badmin\b")
            .unwrap()
    })
}
fn cache_no_store() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)Cache-Control['"]?\s*[:,]\s*['"][^'"]*no-store"#).unwrap())
}
fn cache_public_or_maxage() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)Cache-Control['"]?\s*[:,]\s*['"][^'"]*(?:public|max-age)"#).unwrap()
    })
}
fn trust_proxy_true() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)trust proxy['"]?\s*,\s*true"#).unwrap())
}
fn forwarded_for_security_use() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)X-Forwarded-For").unwrap())
}
fn security_decision_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)rateLimit|isAdmin|allowlist|ipWhitelist|\bauth\b").unwrap())
}
fn trusted_proxy_count_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)trustedProxies|proxyCount|numProxies").unwrap())
}
fn content_length_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"Content-Length['"]?\s*[:=]"#).unwrap())
}
fn transfer_encoding_chunked() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)Transfer-Encoding['"]?\s*[:=][^\n]*chunked"#).unwrap())
}
fn forwarded_header_naive_split() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:X-Forwarded-For|X-Forwarded-Host)['"]?\][^\n]*split\(\s*['"],['"]\s*\)\s*\[\s*0\s*\]"#,
        )
        .unwrap()
    })
}
fn forwarded_header_validation_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)trustedProxies|proxyCount|numProxies|validateForwardedHeader").unwrap()
    })
}

fn deployment_assumption_uncertainty(subject: &str) -> String {
    format!(
        "Deployment assumption: no runtime header or deployment evidence was available for {subject}; \
this claim assumes the observed source configuration is what is actually served, but a reverse \
proxy, CDN, load balancer, or platform default could add, strip, or override it at runtime."
    )
}

fn runtime_header_snapshot(context: &Context) -> Option<&std::collections::HashMap<String, String>> {
    context.audit_facts.runtime_headers.as_ref().map(|h| &h.headers)
}

/// Mirrors `runtimeHeaderCompliance(context, headerKey, isCompliant)`.
fn runtime_header_compliance(
    context: &Context,
    header_key: &str,
    is_compliant: impl Fn(&str) -> bool,
) -> Option<bool> {
    let snapshot = runtime_header_snapshot(context)?;
    let value = snapshot.get(header_key)?;
    Some(is_compliant(value))
}

struct DeploymentOutcome {
    severity_cap: Option<&'static str>,
    uncertainty: Vec<String>,
    deployment_assumption: Option<Value>,
    disagreement: Option<Value>,
}

/// Mirrors `evaluateDeploymentAwareClaim`. Returns `None` when the claim is
/// clean (no observation should be emitted).
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
                return None;
            }
            Some(DeploymentOutcome {
                severity_cap: Some("medium"),
                uncertainty: vec![deployment_assumption_uncertainty(subject)],
                deployment_assumption: Some(
                    json!({ "assumption": "source-config-reflects-served-state", "subject": subject }),
                ),
                disagreement: None,
            })
        }
        Some(runtime) => {
            if source_compliant == runtime {
                if runtime {
                    return None;
                }
                return Some(DeploymentOutcome {
                    severity_cap: None,
                    uncertainty: Vec::new(),
                    deployment_assumption: None,
                    disagreement: None,
                });
            }
            Some(DeploymentOutcome {
                severity_cap: Some("medium"),
                uncertainty: vec![format!(
                    "Source configuration and observed runtime evidence disagree for {subject}; both are recorded rather than one being treated as authoritative."
                )],
                deployment_assumption: None,
                disagreement: Some(json!({
                    "subject": subject,
                    "sourceValue": if source_compliant { compliant_label } else { non_compliant_label },
                    "runtimeValue": if runtime { compliant_label } else { non_compliant_label },
                })),
            })
        }
    }
}

struct Gate {
    severity_cap: Option<&'static str>,
    uncertainty: Vec<String>,
    deployment_assumption: Option<Value>,
}

/// Mirrors `deploymentGate(context, subject)`.
fn deployment_gate(context: &Context, subject: &str) -> Gate {
    let has_evidence =
        runtime_header_snapshot(context).is_some() || context.audit_facts.deployment.is_some();
    if has_evidence {
        Gate { severity_cap: None, uncertainty: Vec::new(), deployment_assumption: None }
    } else {
        Gate {
            severity_cap: Some("medium"),
            uncertainty: vec![deployment_assumption_uncertainty(subject)],
            deployment_assumption: Some(
                json!({ "assumption": "source-config-reflects-served-state", "subject": subject }),
            ),
        }
    }
}

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
    detector_metadata["primitiveClass"] = json!(primitive_class);
    Observation {
        rule_id: rule_id.to_string(),
        candidate_class: CANDIDATE_CLASS.to_string(),
        claim,
        severity_hint,
        sources,
        sinks,
        attacker_capabilities: attacker_capabilities.into_iter().map(str::to_string).collect(),
        preconditions,
        effects,
        assets: Vec::new(),
        trust_boundary_crossings: Vec::new(),
        required_controls: Vec::new(),
        observed_controls: Vec::new(),
        chain_roles: chain_roles.into_iter().map(str::to_string).collect(),
        evidence_refs,
        detector_metadata,
        uncertainty,
    }
}

/// Ports `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    let combined_text: String = context
        .files
        .iter()
        .map(|f| context.read_file(f))
        .collect::<Vec<_>>()
        .join("\n");

    // --- Whole-repository, deployment-aware boolean-state rules ----------

    // hsts.missing
    {
        let source_compliant = hsts_marker().is_match(&combined_text);
        let runtime_compliant =
            runtime_header_compliance(context, "strict-transport-security", |v| !v.is_empty());
        if let Some(outcome) = evaluate_deployment_aware_claim(
            "Strict-Transport-Security header",
            source_compliant,
            runtime_compliant,
            "present",
            "absent",
        ) {
            let mut metadata = json!({
                "scope": "repository",
                "header": "Strict-Transport-Security",
                "filesExamined": context.files.len(),
            });
            if let Some(d) = &outcome.disagreement {
                metadata["disagreement"] = d.clone();
            }
            if let Some(a) = &outcome.deployment_assumption {
                metadata["deploymentAssumption"] = a.clone();
            }
            observations.push(base_observation(
                "hsts.missing",
                "No Strict-Transport-Security header was found across the scanned surface.".to_string(),
                cap_severity("low", outcome.severity_cap),
                "defense-in-depth",
                Vec::new(),
                Vec::new(),
                vec!["active-network-position"],
                vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "intercept-network-traffic".to_string(),
                    object: None,
                    scope: None,
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec![Fact {
                    kind: "control-bypass".to_string(),
                    subject: "actor:external".to_string(),
                    action: "downgrade".to_string(),
                    object: None,
                    scope: Some("transport-security".to_string()),
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec!["enabler"],
                context.repo_wide_evidence_refs(),
                metadata,
                outcome.uncertainty,
            ));
        }
    }

    // https.not-enforced
    {
        let source_insecure =
            http_create_server().is_match(&combined_text) && !https_enforcement_marker().is_match(&combined_text);
        let runtime_compliant = context.audit_facts.deployment.as_ref().and_then(|d| d.https_enforced);
        let source_compliant = !source_insecure;
        if let Some(outcome) = evaluate_deployment_aware_claim(
            "HTTPS enforcement",
            source_compliant,
            runtime_compliant,
            "enforced",
            "not-enforced",
        ) {
            let mut metadata = json!({
                "scope": "repository",
                "config": "http.createServer without HTTPS enforcement",
                "filesExamined": context.files.len(),
            });
            if let Some(d) = &outcome.disagreement {
                metadata["disagreement"] = d.clone();
            }
            if let Some(a) = &outcome.deployment_assumption {
                metadata["deploymentAssumption"] = a.clone();
            }
            observations.push(base_observation(
                "https.not-enforced",
                "A plain HTTP server is created with no visible HTTPS enforcement or redirect.".to_string(),
                cap_severity("high", outcome.severity_cap),
                "exploitable-primitive",
                Vec::new(),
                Vec::new(),
                vec!["active-network-position"],
                vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "intercept-network-traffic".to_string(),
                    object: None,
                    scope: None,
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec![Fact {
                    kind: "confidentiality-impact".to_string(),
                    subject: "actor:external".to_string(),
                    action: "intercept".to_string(),
                    object: None,
                    scope: Some("transport-confidentiality".to_string()),
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec!["starter", "enabler"],
                context.repo_wide_evidence_refs(),
                metadata,
                outcome.uncertainty,
            ));
        }
    }

    // headers.missing-content-type-options
    {
        let source_compliant = content_type_options_marker().is_match(&combined_text);
        let runtime_compliant = runtime_header_compliance(context, "x-content-type-options", |v| {
            v.to_lowercase().contains("nosniff")
        });
        if let Some(outcome) = evaluate_deployment_aware_claim(
            "X-Content-Type-Options header",
            source_compliant,
            runtime_compliant,
            "present",
            "absent",
        ) {
            let mut metadata = json!({
                "scope": "repository",
                "header": "X-Content-Type-Options",
                "filesExamined": context.files.len(),
            });
            if let Some(d) = &outcome.disagreement {
                metadata["disagreement"] = d.clone();
            }
            if let Some(a) = &outcome.deployment_assumption {
                metadata["deploymentAssumption"] = a.clone();
            }
            observations.push(base_observation(
                "headers.missing-content-type-options",
                "No X-Content-Type-Options: nosniff header was found across the scanned surface.".to_string(),
                cap_severity("low", outcome.severity_cap),
                "defense-in-depth",
                Vec::new(),
                Vec::new(),
                vec!["host-attacker-controlled-content"],
                vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "supply-content".to_string(),
                    object: None,
                    scope: None,
                    environment: "application".to_string(),
                    tenant: None,
                }],
                vec![Fact {
                    kind: "control-bypass".to_string(),
                    subject: "actor:external".to_string(),
                    action: "bypass".to_string(),
                    object: None,
                    scope: Some("mime-sniffing-protection".to_string()),
                    environment: "application".to_string(),
                    tenant: None,
                }],
                vec!["enabler"],
                context.repo_wide_evidence_refs(),
                metadata,
                outcome.uncertainty,
            ));
        }
    }

    // --- Per-file, deployment-gated rules ---------------------------------
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

        // headers.content-type-missing-charset
        for m in content_type_missing_charset().find_iter(text) {
            if m.as_str().to_lowercase().contains("charset") {
                continue;
            }
            let gate = deployment_gate(context, "Content-Type charset");
            let mut metadata = json!({
                "file": file,
                "line": line_of(text, m.start()),
                "header": "Content-Type",
                "value": m.as_str(),
            });
            if let Some(a) = &gate.deployment_assumption {
                metadata["deploymentAssumption"] = a.clone();
            }
            let mut uncertainty = vec![
                "A missing charset primarily matters for legacy browser content-type sniffing; modern browsers are largely unaffected.".to_string(),
            ];
            uncertainty.extend(gate.uncertainty);
            observations.push(base_observation(
                "headers.content-type-missing-charset",
                "A text response Content-Type is set without an explicit charset.".to_string(),
                cap_severity("low", gate.severity_cap),
                "defense-in-depth",
                vec![artifact.id.clone()],
                vec![artifact.id.clone()],
                vec!["host-attacker-controlled-content"],
                vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "supply-content".to_string(),
                    object: None,
                    scope: None,
                    environment: "application".to_string(),
                    tenant: None,
                }],
                vec![Fact {
                    kind: "control-bypass".to_string(),
                    subject: "actor:external".to_string(),
                    action: "bypass".to_string(),
                    object: Some(artifact.id.clone()),
                    scope: Some("content-type-charset".to_string()),
                    environment: "application".to_string(),
                    tenant: None,
                }],
                vec!["enabler"],
                evidence_refs.clone(),
                metadata,
                uncertainty,
            ));
        }

        // cache.sensitive-content-cacheable
        if sensitive_route_marker().is_match(text) && !cache_no_store().is_match(text) {
            let explicit_public_match = cache_public_or_maxage().find(text);
            let line = explicit_public_match.map(|m| line_of(text, m.start())).unwrap_or(1);
            let gate = deployment_gate(context, "Cache-Control on a sensitive route");
            let mut metadata = json!({ "file": file, "line": line, "header": "Cache-Control" });
            if let Some(a) = &gate.deployment_assumption {
                metadata["deploymentAssumption"] = a.clone();
            }
            let mut uncertainty = vec![
                "Whether an intermediary shared cache is actually present between the attacker and this response depends on the deployment topology.".to_string(),
            ];
            uncertainty.extend(gate.uncertainty);
            let claim = if explicit_public_match.is_some() {
                "A route handling authenticated/sensitive data sets a publicly cacheable Cache-Control value instead of no-store."
            } else {
                "A route handling authenticated/sensitive data has no Cache-Control: no-store, leaving default caching behavior in effect."
            };
            observations.push(base_observation(
                "cache.sensitive-content-cacheable",
                claim.to_string(),
                cap_severity("high", gate.severity_cap),
                "exploitable-primitive",
                vec![artifact.id.clone()],
                vec![artifact.id.clone()],
                vec!["shared-cache-or-proxy-access"],
                vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "access-shared-cache".to_string(),
                    object: None,
                    scope: None,
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec![Fact {
                    kind: "confidentiality-impact".to_string(),
                    subject: "actor:external".to_string(),
                    action: "read".to_string(),
                    object: Some(artifact.id.clone()),
                    scope: Some("cached-sensitive-response".to_string()),
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec!["enabler", "impact"],
                evidence_refs.clone(),
                metadata,
                uncertainty,
            ));
        }

        // proxy.trust-misconfigured
        let blind_trust_match = trust_proxy_true().find(text);
        let raw_forwarded_for_use = forwarded_for_security_use().is_match(text)
            && security_decision_marker().is_match(text)
            && !trusted_proxy_count_marker().is_match(text);
        if blind_trust_match.is_some() || raw_forwarded_for_use {
            let deployment = context.audit_facts.deployment.as_ref();
            let gate = deployment_gate(context, "X-Forwarded-For trust / proxy topology");
            let line = blind_trust_match.map(|m| line_of(text, m.start())).unwrap_or(1);
            let mut severity_hint = cap_severity("high", gate.severity_cap);
            if deployment.and_then(|d| d.reverse_proxy) == Some(false) {
                severity_hint = "critical".to_string();
            }
            let config = if blind_trust_match.is_some() {
                "trust proxy: true"
            } else {
                "X-Forwarded-For security decision"
            };
            let mut metadata = json!({
                "file": file,
                "line": line,
                "config": config,
                "reverseProxyKnown": deployment.is_some(),
            });
            if let Some(a) = &gate.deployment_assumption {
                metadata["deploymentAssumption"] = a.clone();
            }
            let mut uncertainty = vec![
                "Exploitability depends on whether a trusted reverse proxy actually sits in front of this service and strips client-supplied forwarded headers.".to_string(),
            ];
            uncertainty.extend(gate.uncertainty);
            let claim = if blind_trust_match.is_some() {
                "Proxy trust is enabled unconditionally ('trust proxy', true), accepting forwarded headers from any hop."
            } else {
                "X-Forwarded-For is used for a security decision without a configured trusted-proxy count."
            };
            observations.push(base_observation(
                "proxy.trust-misconfigured",
                claim.to_string(),
                severity_hint,
                "exploitable-primitive",
                vec![artifact.id.clone()],
                vec![artifact.id.clone()],
                vec!["control-request-headers"],
                vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "supply-forwarded-header".to_string(),
                    object: None,
                    scope: None,
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec![Fact {
                    kind: "control-bypass".to_string(),
                    subject: "actor:external".to_string(),
                    action: "spoof".to_string(),
                    object: Some(artifact.id.clone()),
                    scope: Some("client-ip-trust".to_string()),
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec!["starter", "control-bypass"],
                evidence_refs.clone(),
                metadata,
                uncertainty,
            ));
        }

        // smuggling.conflicting-content-length-transfer-encoding
        if content_length_marker().is_match(text) && transfer_encoding_chunked().is_match(text) {
            let te_index = transfer_encoding_chunked().find(text).map(|m| m.start()).unwrap_or(0);
            let gate = deployment_gate(context, "Content-Length / Transfer-Encoding handling");
            let mut metadata = json!({
                "file": file,
                "line": line_of(text, te_index),
                "header": "Content-Length / Transfer-Encoding",
            });
            if let Some(a) = &gate.deployment_assumption {
                metadata["deploymentAssumption"] = a.clone();
            }
            let mut uncertainty = vec![
                "This is a precondition only: full request smuggling requires an actual front-end/back-end HTTP parser disagreement across a real proxy chain, which cannot be confirmed by static analysis alone.".to_string(),
            ];
            uncertainty.extend(gate.uncertainty);
            observations.push(base_observation(
                "smuggling.conflicting-content-length-transfer-encoding",
                "Both Content-Length and Transfer-Encoding: chunked are handled by custom request code, a precondition for request-smuggling desync when chained through a front-end/back-end proxy pair with disagreeing HTTP parsers.".to_string(),
                cap_severity("medium", gate.severity_cap),
                "exploitable-primitive",
                vec![artifact.id.clone()],
                vec![artifact.id.clone()],
                vec!["control-request-headers"],
                vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "supply-conflicting-length-headers".to_string(),
                    object: None,
                    scope: None,
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec![Fact {
                    kind: "control-bypass".to_string(),
                    subject: "actor:external".to_string(),
                    action: "desync".to_string(),
                    object: Some(artifact.id.clone()),
                    scope: Some("http-request-boundary".to_string()),
                    environment: "network".to_string(),
                    tenant: None,
                }],
                vec!["enabler"],
                evidence_refs.clone(),
                metadata,
                uncertainty,
            ));
        }

        // smuggling.ambiguous-proxy-chain
        if !forwarded_header_validation_marker().is_match(text) {
            for m in forwarded_header_naive_split().find_iter(text) {
                let gate = deployment_gate(context, "forwarded-header proxy-chain parsing");
                let mut metadata = json!({
                    "file": file,
                    "line": line_of(text, m.start()),
                    "config": "forwarded-header parsing",
                });
                if let Some(a) = &gate.deployment_assumption {
                    metadata["deploymentAssumption"] = a.clone();
                }
                let mut uncertainty = vec![
                    "Ambiguity is only exploitable if an untrusted hop can inject its own forwarded-header value ahead of the trusted proxy; the real proxy chain topology is not visible from source.".to_string(),
                ];
                uncertainty.extend(gate.uncertainty);
                observations.push(base_observation(
                    "smuggling.ambiguous-proxy-chain",
                    "A forwarded header is parsed by naively taking the first comma-separated value, which is ambiguous when multiple untrusted hops can append their own values.".to_string(),
                    cap_severity("medium", gate.severity_cap),
                    "exploitable-primitive",
                    vec![artifact.id.clone()],
                    vec![artifact.id.clone()],
                    vec!["control-request-headers"],
                    vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: "supply-forwarded-header".to_string(),
                        object: None,
                        scope: None,
                        environment: "network".to_string(),
                        tenant: None,
                    }],
                    vec![Fact {
                        kind: "control-bypass".to_string(),
                        subject: "actor:external".to_string(),
                        action: "spoof".to_string(),
                        object: Some(artifact.id.clone()),
                        scope: Some("http-request-boundary".to_string()),
                        environment: "network".to_string(),
                        tenant: None,
                    }],
                    vec!["enabler"],
                    evidence_refs.clone(),
                    metadata,
                    uncertainty,
                ));
            }
        }
    }

    observations
}
