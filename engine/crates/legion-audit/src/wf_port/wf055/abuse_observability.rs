//! Port of `src/providers/security/packs/abuse-observability.mjs`, built on
//! the pattern-pack shape from `src/providers/security/packs/pattern-pack.mjs`
//! (`createPatternPack`). `pattern-pack.mjs` is shared infrastructure used
//! by several packs and is not itself one of this chunk's owned files, so
//! only the minimal slice `abuse-observability.mjs` actually exercises is
//! ported here (a bespoke `analyze` rather than a reusable generic
//! `create_pattern_pack` helper — a second pack chunk that also needs
//! `pattern-pack.mjs` should port the shared helper itself in its own
//! owned module rather than reuse this one, since this file is owned by
//! chunk wf055's `abuse-observability.mjs` port specifically).

use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

const CANDIDATE_CLASS: &str = "abuse-observability";
const PACK_ID: &str = "security.abuse-observability";
const PACK_DESCRIPTION: &str = "Abuse resistance, webhook integrity, resilience, and forensics.";

pub struct Rule {
    pub id: &'static str,
    pub pattern: &'static LazyLock<Regex>,
    pub claim: &'static str,
    pub severity_hint: &'static str,
    pub effect_kind: &'static str,
}

static LOGIN_WITHOUT_RATE_LIMIT: LazyLock<Regex> = LazyLock::new(|| {
    // JS: /(?:login|signin|resetPassword|sendOtp)\s*\([^\n]*(?!rateLimit|throttle)/i
    // The trailing negative lookahead is a zero-width assertion satisfied
    // at essentially every position (it does not require the absence of
    // `rateLimit`/`throttle` anywhere in the rest of the match — it only
    // asserts the very next characters aren't that literal string), so in
    // practice this pattern matches whenever the call-site text itself is
    // present; ported literally including that JS-source quirk (`(?!...)`)
    // via the Rust `regex` crate, which does not support lookahead, by
    // dropping the trivially-always-satisfied lookahead and matching the
    // call-site alone — behaviourally equivalent for every input, since
    // the lookahead in the JS pattern never actually excludes a match.
    Regex::new(r"(?i)(?:login|signin|resetPassword|sendOtp)\s*\(").expect("valid regex")
});
static WEBHOOK_WITHOUT_SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
    // Same zero-width-lookahead quirk as above; ported the same way.
    Regex::new(r"(?i)(?:webhook|callback)\s*\(").expect("valid regex")
});
static SWALLOWED_SECURITY_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)catch\s*\([^)]*\)\s*\{\s*(?:return\s+(?:null|false|undefined)|\})").expect("valid regex")
});

pub static RULES: &[Rule] = &[
    Rule {
        id: "abuse.login-without-rate-limit",
        pattern: &LOGIN_WITHOUT_RATE_LIMIT,
        claim: "An abuse-sensitive identity operation has no visible rate limit.",
        severity_hint: "medium",
        effect_kind: "availability-impact",
    },
    Rule {
        id: "abuse.webhook-without-signature",
        pattern: &WEBHOOK_WITHOUT_SIGNATURE,
        claim: "A webhook receiver has no visible authenticity verification.",
        severity_hint: "high",
        effect_kind: "integrity-impact",
    },
    Rule {
        id: "observability.swallowed-security-error",
        pattern: &SWALLOWED_SECURITY_ERROR,
        claim: "An exception may be swallowed without durable diagnostic evidence.",
        severity_hint: "medium",
        effect_kind: "control-bypass",
    },
];

/// One repository file's text plus, if the model already carries a
/// `repository-artifact` entity for it, that entity's id and evidence
/// refs — mirrors `artifactFor(context, file)` / `artifact?.id` /
/// `artifact?.evidenceRefs`.
pub struct ObservabilityFile<'a> {
    pub path: &'a str,
    pub text: &'a str,
    pub artifact_id: Option<&'a str>,
    pub artifact_evidence_refs: &'a [String],
}

/// Port of the pattern pack's `analyze(context)` for the
/// `abuse-observability` family specifically.
pub fn analyze(files: &[ObservabilityFile]) -> Vec<Value> {
    let mut observations = Vec::new();
    for file in files {
        if file.text.is_empty() {
            continue;
        }
        for rule in RULES {
            if !rule.pattern.is_match(file.text) {
                continue;
            }
            let source_sink: Vec<Value> = file
                .artifact_id
                .map(|id| vec![Value::String(id.to_string())])
                .unwrap_or_default();
            observations.push(json!({
                "ruleId": rule.id,
                "candidateClass": CANDIDATE_CLASS,
                "claim": rule.claim,
                "severityHint": rule.severity_hint,
                "sources": source_sink,
                "sinks": source_sink,
                "attackerCapabilities": ["control-request-input"],
                "preconditions": [{
                    "kind": "attacker-position",
                    "subject": "actor:external",
                    "action": "supply-input",
                    "scope": Value::Null,
                    "environment": "application",
                    "tenant": Value::Null,
                }],
                "effects": [{
                    "kind": rule.effect_kind,
                    "subject": "actor:external",
                    "action": "bypass",
                    "object": file.artifact_id,
                    "scope": CANDIDATE_CLASS,
                    "environment": "application",
                    "tenant": Value::Null,
                }],
                "assets": [],
                "trustBoundaryCrossings": [],
                "requiredControls": [],
                "observedControls": [],
                "chainRoles": ["starter", "impact"],
                "evidenceRefs": file.artifact_evidence_refs,
                "detectorMetadata": { "file": file.path, "patternFamily": CANDIDATE_CLASS },
                "uncertainty": ["Reachability and compensating controls require independent adjudication."],
            }));
        }
    }
    observations
}

/// Static pack descriptor mirroring the JS `export default
/// createPatternPack({ id, family, description, rules })`'s frozen shape
/// (id/version/candidateClass/description/rule-id list).
pub fn pack_descriptor() -> Value {
    json!({
        "id": PACK_ID,
        "version": "1.0.0",
        "candidateClass": CANDIDATE_CLASS,
        "description": PACK_DESCRIPTION,
        "rules": RULES.iter().map(|r| json!({ "id": r.id })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_descriptor_lists_all_three_rule_ids() {
        let descriptor = pack_descriptor();
        assert_eq!(descriptor["id"], PACK_ID);
        let ids: Vec<&str> = descriptor["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            vec![
                "abuse.login-without-rate-limit",
                "abuse.webhook-without-signature",
                "observability.swallowed-security-error",
            ]
        );
    }

    #[test]
    fn login_call_site_produces_availability_impact_observation() {
        let files = [ObservabilityFile {
            path: "src/auth.js",
            text: "function login(req, res) { db.find(req.body.user); }",
            artifact_id: Some("artifact-1"),
            artifact_evidence_refs: &["ev-1".to_string()],
        }];
        let obs = analyze(&files);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0]["ruleId"], "abuse.login-without-rate-limit");
        assert_eq!(obs[0]["severityHint"], "medium");
        assert_eq!(obs[0]["effects"][0]["kind"], "availability-impact");
        assert_eq!(obs[0]["sources"], json!(["artifact-1"]));
        assert_eq!(obs[0]["evidenceRefs"], json!(["ev-1"]));
    }

    #[test]
    fn webhook_call_site_produces_high_severity_integrity_observation() {
        let files = [ObservabilityFile {
            path: "src/webhooks.js",
            text: "function webhook(req, res) { handle(req.body); }",
            artifact_id: None,
            artifact_evidence_refs: &[],
        }];
        let obs = analyze(&files);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0]["ruleId"], "abuse.webhook-without-signature");
        assert_eq!(obs[0]["severityHint"], "high");
        assert_eq!(obs[0]["sources"], json!([]));
    }

    #[test]
    fn swallowed_catch_block_is_detected() {
        let files = [ObservabilityFile {
            path: "src/handler.js",
            text: "try { doThing(); } catch (e) { return null; }",
            artifact_id: None,
            artifact_evidence_refs: &[],
        }];
        let obs = analyze(&files);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0]["ruleId"], "observability.swallowed-security-error");
    }

    #[test]
    fn empty_text_produces_no_observations() {
        let files = [ObservabilityFile {
            path: "src/empty.js",
            text: "",
            artifact_id: None,
            artifact_evidence_refs: &[],
        }];
        assert!(analyze(&files).is_empty());
    }

    #[test]
    fn clean_file_produces_no_observations() {
        let files = [ObservabilityFile {
            path: "src/math.js",
            text: "export const add = (a, b) => a + b;",
            artifact_id: None,
            artifact_evidence_refs: &[],
        }];
        assert!(analyze(&files).is_empty());
    }

    #[test]
    fn a_single_file_can_trigger_multiple_rules() {
        let files = [ObservabilityFile {
            path: "src/combo.js",
            text: "function login(req) {} function webhook(req) {} try {} catch (e) { return false; }",
            artifact_id: None,
            artifact_evidence_refs: &[],
        }];
        let obs = analyze(&files);
        assert_eq!(obs.len(), 3);
    }
}
