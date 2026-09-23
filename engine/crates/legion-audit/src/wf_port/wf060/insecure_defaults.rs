//! Port of `src/providers/security/packs/insecure-defaults.mjs`: fail-open
//! debug, transport, and authentication defaults. Built through the generic
//! `createPatternPack` helper in `pattern-pack.mjs`; this module replicates
//! that helper's `analyze()` behaviour inline for this pack's three rules.

use super::common::{Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

pub const ID: &str = "security.insecure-defaults";
pub const CANDIDATE_CLASS: &str = "insecure-defaults";

struct Rule {
    id: &'static str,
    claim: &'static str,
    severity_hint: &'static str,
    pattern: fn() -> &'static Regex,
}

fn debug_enabled() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:DEBUG|debug)\s*[:=]\s*(?:true|1)|NODE_ENV\s*!==?\s*['"]production"#).unwrap()
    })
}

fn tls_verification_disabled() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CERT_NONE"#).unwrap()
    })
}

fn authentication_optional() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)auth(?:entication)?\s*[:=]\s*(?:false|optional)|ALLOW_ANONYMOUS\s*[:=]\s*(?:true|1)"#)
            .unwrap()
    })
}

fn rules() -> [Rule; 3] {
    [
        Rule {
            id: "defaults.debug-enabled",
            claim: "Debug behavior may be enabled by a production-reachable default.",
            severity_hint: "medium",
            pattern: debug_enabled,
        },
        Rule {
            id: "defaults.tls-verification-disabled",
            claim: "TLS verification is explicitly disabled.",
            severity_hint: "high",
            pattern: tls_verification_disabled,
        },
        Rule {
            id: "defaults.authentication-optional",
            claim: "Authentication may default to optional or disabled.",
            severity_hint: "high",
            pattern: authentication_optional,
        },
    ]
}

/// Ports `createPatternPack(...).analyze(context)` for this pack's rules.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        for rule in rules() {
            if !(rule.pattern)().is_match(text) {
                continue;
            }
            let artifact_ids: Vec<String> = artifact.map(|a| vec![a.id.clone()]).unwrap_or_default();
            observations.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: CANDIDATE_CLASS.to_string(),
                claim: rule.claim.to_string(),
                severity_hint: rule.severity_hint.to_string(),
                sources: artifact_ids.clone(),
                sinks: artifact_ids.clone(),
                attacker_capabilities: vec!["control-request-input".to_string()],
                preconditions: vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "supply-input".to_string(),
                    object: None,
                    scope: None,
                    environment: "application".to_string(),
                    tenant: None,
                }],
                effects: vec![Fact {
                    kind: "control-bypass".to_string(),
                    subject: "actor:external".to_string(),
                    action: "bypass".to_string(),
                    object: artifact.map(|a| a.id.clone()),
                    scope: Some(CANDIDATE_CLASS.to_string()),
                    environment: "application".to_string(),
                    tenant: None,
                }],
                assets: Vec::new(),
                trust_boundary_crossings: Vec::new(),
                required_controls: Vec::new(),
                observed_controls: Vec::new(),
                chain_roles: vec!["starter".to_string(), "impact".to_string()],
                evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                detector_metadata: json!({ "file": file, "patternFamily": CANDIDATE_CLASS }),
                uncertainty: vec![
                    "Reachability and compensating controls require independent adjudication.".to_string(),
                ],
            });
        }
    }
    observations
}
