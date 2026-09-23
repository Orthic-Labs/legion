//! Port of `src/providers/security/packs/ssrf-egress.mjs`: request-
//! controlled outbound destinations, unbounded redirect-following, and
//! DNS-rebinding preconditions. Every rule is a lexical (pattern-only)
//! detector: it never issues a network request, never resolves a hostname,
//! never calls a model, and never certifies a finding.
//!
//! The egress *environment* (network topology, egress allowlist, deployment
//! context) is frequently invisible from source alone. When no allowlist
//! control and no deployment/egress-allowlist evidence
//! (`context.audit_facts.deployment` / `context.audit_facts.egress_allowlist`)
//! is available, every candidate here is capped at `medium` and carries an
//! explicit "environment unknown" uncertainty entry rather than being
//! asserted at its uncapped severity. When an allowlist IS observed —
//! either as a model control entity or via `egress_allowlist` — it is
//! modeled as `observedControls`, never silently assumed safe.

use super::{cap_severity, digest, line_of, window_around, Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

pub const CANDIDATE_CLASS: &str = "ssrf-egress";

const EGRESS_CALLEES: &str =
    r"fetch|axios(?:\.\w+)?|request|http\.request|https\.request|http\.get|https\.get|urlopen|got|requests\.(?:get|post|put|delete)";

fn request_controlled_destination() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)\b({EGRESS_CALLEES})\s*\(\s*([^()\n]*\b(?:request|req)\.(?:query|body|params)(?:\.[\w]+)?\b[^()\n]*)\)"
        ))
        .unwrap()
    })
}

fn redirect_following_unbounded() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\b(redirect\s*:\s*['"]follow['"]|maxRedirects\s*:\s*[1-9]\d*|followRedirects\s*:\s*true)\b"#).unwrap()
    })
}

fn egress_sink_scan() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!(r"(?i)\b({EGRESS_CALLEES})\s*\(")).unwrap())
}

fn dns_pinning_marker() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)dns\.lookup\s*\(|dnsCache|ssrf-req-filter|safeLookup|pinDns|resolve4Safe|blockPrivateIp|isPrivateIp").unwrap()
    })
}

fn ssrf_allowlist_lexical() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:isAllowedHost|allowlist|urlAllowList|ssrf-req-filter|validateUrl|isPrivateIp|blockPrivateIp)\b").unwrap()
    })
}

fn redirect_allowlist_lexical() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:isAllowedHost|allowlist|urlAllowList|ssrf-req-filter|validateUrl|revalidateRedirect)\b").unwrap()
    })
}

/// Mirrors `egressEnvironmentEvidence(context)`.
fn egress_environment_has_evidence(context: &Context) -> bool {
    context.audit_facts.deployment.is_some() || context.audit_facts.egress_allowlist.is_some()
}

/// Mirrors `environmentGate(context, controlSignal)`: `(cap, uncertainty)`.
fn environment_gate(context: &Context, control_signal: bool) -> (Option<&'static str>, Vec<String>) {
    if egress_environment_has_evidence(context) || control_signal {
        return (None, Vec::new());
    }
    (
        Some("medium"),
        vec!["Egress destination environment (network topology, egress allowlist, deployment context) is unknown; this claim is bounded to medium severity until that evidence is available.".to_string()],
    )
}

struct Downgrade {
    control_types: &'static [&'static str],
    severity_hint: &'static str,
    lexical_pattern: fn() -> &'static Regex,
    lexical_note: &'static str,
    radius: usize,
}

struct Rule {
    id: &'static str,
    pattern: fn() -> &'static Regex,
    claim: &'static str,
    severity_hint: &'static str,
    attacker_capabilities: &'static [&'static str],
    precondition_action: &'static str,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
    uncertainty: &'static str,
    downgrade: Downgrade,
    sink_api_group: usize,
    source_group: usize,
}

fn rules() -> [Rule; 2] {
    [
        Rule {
            id: "ssrf.request-controlled-destination",
            pattern: request_controlled_destination,
            claim: "Request-controlled data may determine the destination of a server-side outbound request (SSRF).",
            severity_hint: "high",
            attacker_capabilities: &["control-request-input"],
            precondition_action: "supply-destination",
            effect_kind: "network-reachability",
            effect_action: "reach",
            effect_scope: "server-side-egress",
            chain_roles: &["starter", "pivot"],
            uncertainty: "A request-controlled URL argument is not automatically SSRF; internal network topology and allowlisting must be adjudicated.",
            downgrade: Downgrade {
                control_types: &["egress-allowlist", "url-allowlist", "ssrf-guard"],
                severity_hint: "low",
                lexical_pattern: ssrf_allowlist_lexical,
                lexical_note: "An allowlist/SSRF-guard call is present near the outbound request; treated as a mitigating signal pending adjudication.",
                radius: 300,
            },
            sink_api_group: 1,
            source_group: 2,
        },
        Rule {
            id: "ssrf.redirect-following-unbounded",
            pattern: redirect_following_unbounded,
            claim: "An HTTP client is configured to follow redirects without a hop cap, allowing a server-side request to be redirected to an internal or unexpected destination after initial validation.",
            severity_hint: "medium",
            attacker_capabilities: &["control-request-input", "control-redirect-target"],
            precondition_action: "supply-destination",
            effect_kind: "network-reachability",
            effect_action: "redirect",
            effect_scope: "server-side-egress-redirect",
            chain_roles: &["enabler", "pivot"],
            uncertainty: "Redirect-following alone is not automatically exploitable; whether the initial destination is attacker-influenced and whether redirect targets are re-validated at each hop must be adjudicated.",
            downgrade: Downgrade {
                control_types: &["egress-allowlist", "url-allowlist", "ssrf-guard"],
                severity_hint: "low",
                lexical_pattern: redirect_allowlist_lexical,
                lexical_note: "An allowlist/SSRF-guard call is present near the redirect configuration; treated as a mitigating signal pending adjudication.",
                radius: 300,
            },
            sink_api_group: 0,
            source_group: 1,
        },
    ]
}

pub fn rule_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = rules().iter().map(|r| r.id).collect();
    ids.push("ssrf.dns-rebinding-unprotected");
    ids
}

/// Ports `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);

        for rule in rules() {
            for cap in (rule.pattern)().captures_iter(text) {
                let whole = cap.get(0).unwrap();
                let sink_api = if rule.sink_api_group == 0 {
                    "http-client-redirect-config".to_string()
                } else {
                    cap.get(rule.sink_api_group).unwrap().as_str().to_string()
                };
                let source_expr = cap.get(rule.source_group).unwrap().as_str().trim().to_string();

                let mut severity_hint = rule.severity_hint.to_string();
                let mut observed_controls = Vec::new();
                let mut control_observed: Option<String> = None;
                let mut control_signal = false;
                let mut uncertainty = vec![rule.uncertainty.to_string()];

                if let Some(control) =
                    context.find_related_control(artifact.map(|a| a.id.as_str()), rule.downgrade.control_types)
                {
                    severity_hint = rule.downgrade.severity_hint.to_string();
                    observed_controls = vec![control.id.clone()];
                    control_observed = Some(control.name.clone());
                    control_signal = true;
                    let control_type = control.attr_str("controlType").unwrap_or("mitigating");
                    uncertainty.push(format!(
                        "Observed {control_type} control ({}) on this path; downgraded pending adjudication of coverage completeness.",
                        control.name
                    ));
                } else if (rule.downgrade.lexical_pattern)()
                    .is_match(window_around(text, whole.start(), whole.len(), rule.downgrade.radius))
                {
                    severity_hint = rule.downgrade.severity_hint.to_string();
                    control_observed = Some("lexical-signal".to_string());
                    control_signal = true;
                    uncertainty.push(rule.downgrade.lexical_note.to_string());
                } else if context.audit_facts.egress_allowlist.is_some() {
                    control_signal = true;
                    control_observed = Some("auditFacts.egressAllowlist".to_string());
                    uncertainty.push("An egress allowlist was observed in upstream deployment facts; whether this specific destination is covered must still be adjudicated.".to_string());
                }

                let (cap_to, gate_uncertainty) = environment_gate(context, control_signal);
                if cap_to.is_some() {
                    severity_hint = cap_severity(&severity_hint, cap_to);
                    uncertainty.extend(gate_uncertainty);
                }

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint,
                    sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    attacker_capabilities: rule.attacker_capabilities.iter().map(|s| s.to_string()).collect(),
                    preconditions: vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.precondition_action.to_string(),
                        object: None,
                        scope: None,
                        environment: "network".to_string(),
                        tenant: None,
                    }],
                    effects: vec![Fact {
                        kind: rule.effect_kind.to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.effect_action.to_string(),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some(rule.effect_scope.to_string()),
                        environment: "network".to_string(),
                        tenant: None,
                    }],
                    assets: Vec::new(),
                    trust_boundary_crossings: Vec::new(),
                    required_controls: Vec::new(),
                    observed_controls,
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: json!({
                        "file": file,
                        "line": line_of(text, whole.start()),
                        "sourceExpr": source_expr,
                        "sinkApi": sink_api,
                        "controlObserved": control_observed,
                        "matchDigest": digest(whole.as_str()),
                    }),
                    uncertainty,
                });
            }
        }

        // ssrf.dns-rebinding-unprotected: a whole-file structural absence
        // check — an egress call exists but no DNS-pinning / post-resolution
        // IP revalidation marker is present anywhere in the file.
        if let Some(egress_caps) = egress_sink_scan().captures(text) {
            let egress_match = egress_caps.get(0).unwrap();
            let egress_callee = egress_caps.get(1).unwrap().as_str();
            if !dns_pinning_marker().is_match(text) {
                let mut severity_hint = "medium".to_string();
                let mut uncertainty = vec![
                    "DNS-rebinding requires the attacker to control a DNS record that resolves to a different (internal) address between validation and the actual connection; whether the destination host is attacker-controlled must be adjudicated.".to_string(),
                ];
                let (cap_to, gate_uncertainty) = environment_gate(context, false);
                if cap_to.is_some() {
                    severity_hint = cap_severity(&severity_hint, cap_to);
                    uncertainty.extend(gate_uncertainty);
                }

                observations.push(Observation {
                    rule_id: "ssrf.dns-rebinding-unprotected".to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: "A server-side outbound request has no visible DNS-pinning or post-resolution IP revalidation, leaving the destination vulnerable to DNS-rebinding between validation and connection.".to_string(),
                    severity_hint,
                    sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    attacker_capabilities: vec!["control-dns-response".to_string(), "control-request-input".to_string()],
                    preconditions: vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: "control-dns-resolution".to_string(),
                        object: None,
                        scope: None,
                        environment: "network".to_string(),
                        tenant: None,
                    }],
                    effects: vec![Fact {
                        kind: "network-reachability".to_string(),
                        subject: "actor:external".to_string(),
                        action: "rebind".to_string(),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some("server-side-egress-dns".to_string()),
                        environment: "network".to_string(),
                        tenant: None,
                    }],
                    assets: Vec::new(),
                    trust_boundary_crossings: Vec::new(),
                    required_controls: Vec::new(),
                    observed_controls: Vec::new(),
                    chain_roles: vec!["starter".to_string(), "pivot".to_string()],
                    evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: json!({
                        "file": file,
                        "line": line_of(text, egress_match.start()),
                        "sourceExpr": "resolved-egress-hostname",
                        "sinkApi": egress_callee,
                        "controlObserved": Option::<String>::None,
                        "matchDigest": digest(egress_match.as_str()),
                    }),
                    uncertainty,
                });
            }
        }
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{AuditFacts, Entity, Relation};

    fn find<'a>(obs: &'a [Observation], rule_id: &str) -> Option<&'a Observation> {
        obs.iter().find(|o| o.rule_id == rule_id)
    }

    #[test]
    fn request_controlled_destination_is_capped_at_medium_with_no_egress_environment_evidence() {
        let context = Context::new().with_file("egress.mjs", "fetch(request.query.url)");
        let obs = analyze(&context);
        let candidate = find(&obs, "ssrf.request-controlled-destination").unwrap();
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
    fn a_deployment_evidenced_egress_environment_lifts_the_medium_cap() {
        let context = Context::new()
            .with_file("egress.mjs", "fetch(request.query.url)")
            .with_audit_facts(AuditFacts { deployment: Some(json!({ "httpsEnforced": true })), ..Default::default() });
        let obs = analyze(&context);
        let candidate = find(&obs, "ssrf.request-controlled-destination").unwrap();
        assert_eq!(candidate.severity_hint, "high");
    }

    #[test]
    fn an_observed_egress_allowlist_control_downgrades_and_references_the_control() {
        let context = Context::new()
            .with_file("egress.mjs", "fetch(request.query.url)")
            .with_entity(Entity::control("ctrl:1", "egress-allowlist", "outbound host allowlist", vec!["ev:control".into()]))
            .with_relation(Relation { kind: "protects".to_string(), from: "ctrl:1".to_string(), to: "artifact:egress.mjs".to_string() });
        let obs = analyze(&context);
        let candidate = find(&obs, "ssrf.request-controlled-destination").unwrap();
        assert_eq!(candidate.severity_hint, "low");
        assert_eq!(candidate.observed_controls, vec!["ctrl:1".to_string()]);
    }

    #[test]
    fn redirect_following_unbounded_fires_on_a_true_follow_redirect_config() {
        let context = Context::new().with_file("client.mjs", "const opts = { followRedirects: true };");
        let obs = analyze(&context);
        assert!(find(&obs, "ssrf.redirect-following-unbounded").is_some());
    }

    #[test]
    fn dns_rebinding_unprotected_fires_when_an_egress_call_has_no_pinning_marker() {
        let context = Context::new().with_file("egress.mjs", "fetch('https://example.com')");
        let obs = analyze(&context);
        assert!(find(&obs, "ssrf.dns-rebinding-unprotected").is_some());
    }

    #[test]
    fn dns_rebinding_unprotected_is_silent_when_a_pinning_marker_is_present() {
        let context = Context::new().with_file("egress.mjs", "blockPrivateIp(host); fetch('https://example.com')");
        let obs = analyze(&context);
        assert!(find(&obs, "ssrf.dns-rebinding-unprotected").is_none());
    }

    #[test]
    fn a_neutral_source_produces_no_candidates() {
        let context = Context::new().with_file("neutral.mjs", "export const value = 1;");
        assert!(analyze(&context).is_empty());
    }

    #[test]
    fn rule_ids_include_all_three_documented_rule_ids() {
        let ids = rule_ids();
        assert!(ids.contains(&"ssrf.request-controlled-destination"));
        assert!(ids.contains(&"ssrf.redirect-following-unbounded"));
        assert!(ids.contains(&"ssrf.dns-rebinding-unprotected"));
        assert_eq!(ids.len(), 3);
    }
}
