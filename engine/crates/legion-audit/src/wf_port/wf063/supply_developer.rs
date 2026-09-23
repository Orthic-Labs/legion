//! Port of `src/providers/security/packs/supply-developer.mjs`: a
//! three-rule pack built through `createPatternPack` (`pattern-pack.mjs`).
//! `pattern-pack.mjs` is shared JS infrastructure outside this chunk's
//! owned file list; this module reproduces the minimal slice of its
//! `analyze(context)` behaviour this pack needs — a per-file, per-rule
//! `pattern.test(text)` boolean check (not an `exec` loop: at most one
//! observation per rule per file) plus the helper's default field values —
//! mirroring the precedent set by the sibling `wf055` chunk's
//! `abuse_observability.rs`.

use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

use super::common::{Context, Fact, Observation};

pub const ID: &str = "security.supply-developer";
pub const CANDIDATE_CLASS: &str = "supply-developer";

fn download_execute_unverified() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:curl|wget)[^\n]*(?:\||&&)\s*(?:sh|bash|python|node)|Invoke-WebRequest[^\n]*\|[^\n]*iex")
            .unwrap()
    })
}

fn mutable_container_tag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:image:|FROM)\s+[^\s@]+:(?:latest|main|master)\b").unwrap())
}

fn global_config_write() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:\.gitconfig|\.npmrc|\.cargo/config|Library/LaunchAgents)[^\n]*(?:write|append|>|Set-Content)")
            .unwrap()
    })
}

struct Rule {
    id: &'static str,
    claim: &'static str,
    severity_hint: &'static str,
    effect_kind: &'static str,
    effect_action: &'static str,
    pattern: fn() -> &'static Regex,
}

const RULES: &[Rule] = &[
    Rule {
        id: "supply.download-execute-unverified",
        claim: "Downloaded content may execute without an integrity check.",
        severity_hint: "high",
        effect_kind: "code-execution",
        effect_action: "bypass",
        pattern: download_execute_unverified,
    },
    Rule {
        id: "supply.mutable-container-tag",
        claim: "A build or runtime dependency uses a mutable container tag.",
        // pattern-pack.mjs default: `rule.severityHint ?? 'medium'`.
        severity_hint: "medium",
        // pattern-pack.mjs defaults: `rule.effectKind ?? 'control-bypass'`, `rule.effectAction ?? 'bypass'`.
        effect_kind: "control-bypass",
        effect_action: "bypass",
        pattern: mutable_container_tag,
    },
    Rule {
        id: "developer.global-config-write",
        claim: "Automation may mutate durable developer-machine configuration.",
        severity_hint: "medium",
        effect_kind: "persistence",
        effect_action: "bypass",
        pattern: global_config_write,
    },
];

/// Faithful port of `createPatternPack({...}).analyze(context)` for this
/// pack's three rules and default field values.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        for rule in RULES {
            let re = (rule.pattern)();
            if !re.is_match(text) {
                continue;
            }
            observations.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: CANDIDATE_CLASS.to_string(),
                claim: rule.claim.to_string(),
                severity_hint: rule.severity_hint.to_string(),
                sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
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
                    kind: rule.effect_kind.to_string(),
                    subject: "actor:external".to_string(),
                    action: rule.effect_action.to_string(),
                    object: artifact.map(|a| a.id.clone()),
                    scope: Some(CANDIDATE_CLASS.to_string()),
                    environment: "application".to_string(),
                    tenant: None,
                }],
                assets: vec![],
                trust_boundary_crossings: vec![],
                required_controls: vec![],
                observed_controls: vec![],
                chain_roles: vec!["starter".to_string(), "impact".to_string()],
                evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                detector_metadata: json!({ "file": file, "patternFamily": CANDIDATE_CLASS }),
                uncertainty: vec!["Reachability and compensating controls require independent adjudication.".to_string()],
            });
        }
    }
    observations
}

#[allow(dead_code)]
pub fn rule_ids() -> Vec<&'static str> {
    RULES.iter().map(|r| r.id).collect()
}
