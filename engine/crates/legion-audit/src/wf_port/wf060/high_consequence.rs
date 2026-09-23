//! Port of `src/providers/security/packs/high-consequence.mjs`:
//! smart-contract, embedded, industrial, and high-consequence safety
//! boundaries. Built through the generic `createPatternPack` helper; this
//! module replicates that helper's `analyze()` behaviour inline for this
//! pack's three rules.

use super::common::{Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

pub const ID: &str = "security.high-consequence";
pub const CANDIDATE_CLASS: &str = "high-consequence";

struct Rule {
    id: &'static str,
    claim: &'static str,
    severity_hint: &'static str,
    effect_kind: &'static str,
    pattern: fn() -> &'static Regex,
}

fn tx_origin_auth() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)tx\.origin\s*==|require\s*\(\s*tx\.origin").unwrap())
}

fn update_without_verification() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // JS: /(?:firmware|ota|flash)[\s\S]{0,180}(?:download|apply)(?![\s\S]{0,120}(?:signature|verify|digest))/i
    // The `regex` crate has no lookahead; the negative-lookahead guard is
    // applied post-match below (see `no_verification_within`).
    RE.get_or_init(|| {
        Regex::new(r"(?is)(?:firmware|ota|flash)[\s\S]{0,180}(?:download|apply)").unwrap()
    })
}

fn command_without_interlock() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // JS: /(?:actuator|motor|valve|relay)\.(?:start|open|enable|write)\s*\((?![^)]*(?:interlock|limit|safe))/i
    // Same lookahead limitation: matched here, guard applied post-match.
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:actuator|motor|valve|relay)\.(?:start|open|enable|write)\s*\(").unwrap()
    })
}

/// Mirrors the JS negative lookahead `(?![\s\S]{0,120}(?:signature|verify|digest))`
/// applied at the match end: true when no verification keyword appears in
/// the next 120 characters after the match.
fn no_verification_within_120(text: &str, match_end: usize) -> bool {
    let end = (match_end + 120).min(text.len());
    let end = ceil_char_boundary(text, end);
    let window = &text[match_end..end];
    !window.to_lowercase().contains("signature")
        && !window.to_lowercase().contains("verify")
        && !window.to_lowercase().contains("digest")
}

/// Mirrors the JS negative lookahead `(?![^)]*(?:interlock|limit|safe))`
/// applied at the match end: true when no interlock keyword appears before
/// the next `)`.
fn no_interlock_before_close_paren(text: &str, match_end: usize) -> bool {
    let rest = &text[match_end..];
    let scope = match rest.find(')') {
        Some(idx) => &rest[..idx],
        None => rest,
    };
    let lower = scope.to_lowercase();
    !lower.contains("interlock") && !lower.contains("limit") && !lower.contains("safe")
}

fn ceil_char_boundary(text: &str, mut idx: usize) -> usize {
    while idx < text.len() && !text.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn rules() -> [Rule; 3] {
    [
        Rule {
            id: "smart-contract.tx-origin-auth",
            claim: "A smart contract may authorize callers through tx.origin.",
            severity_hint: "high",
            effect_kind: "principal-access",
            pattern: tx_origin_auth,
        },
        Rule {
            id: "embedded.update-without-verification",
            claim: "A firmware update path has no visible authenticity verification.",
            severity_hint: "high",
            effect_kind: "code-execution",
            pattern: update_without_verification,
        },
        Rule {
            id: "safety.command-without-interlock",
            claim: "A physical control command has no visible safety interlock.",
            severity_hint: "high",
            effect_kind: "integrity-impact",
            pattern: command_without_interlock,
        },
    ]
}

/// Ports `createPatternPack(...).analyze(context)` for this pack's rules.
///
/// The generic helper only ever tests `pattern.test(text)` once per file
/// (a plain boolean, not `exec`-looped), so this mirrors that: at most one
/// observation per rule per file, gated additionally by the lookahead
/// guards the `regex` crate cannot express directly.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        for rule in rules() {
            let re = (rule.pattern)();
            let Some(m) = re.find(text) else { continue };
            let matched = match rule.id {
                "embedded.update-without-verification" => no_verification_within_120(text, m.end()),
                "safety.command-without-interlock" => no_interlock_before_close_paren(text, m.end()),
                _ => true,
            };
            if !matched {
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
                    kind: rule.effect_kind.to_string(),
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
