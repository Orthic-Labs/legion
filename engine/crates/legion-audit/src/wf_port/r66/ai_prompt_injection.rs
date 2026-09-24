//! Port of `src/providers/security/packs/ai-prompt-injection.mjs` per
//! Security Appendix §50.7: untrusted prompts, retrieved (RAG/search)
//! content, durable agent memory, and dynamically constructed tool/function
//! schemas entering a model invocation without a visible trust label.
//!
//! Scope: `analyze(context)` — the pure lexical detection producing
//! `UNADJUDICATED` candidate observations — is ported faithfully (same rule
//! order, same regex-shaped triggers, same claim text, same severity hints,
//! same `detectorMetadata` fields, same control-suppression logic).
//! `variantStrategies` (`rootCause`/`enumerate`) is coverage-report
//! bookkeeping over the same matches `analyze()` already finds; it is not
//! ported here, mirroring the scope decision documented in wf060's
//! `common.rs`.
//!
//! Every rule requires a source+sink COMBINATION (an untrusted-origin
//! pattern feeding a prompt/schema-construction sink); a bare mention of
//! "prompt" or "llm" alone never produces a candidate. Every rule only ever
//! emits an UNADJUDICATED candidate: it never runs a payload, never calls a
//! model, and never certifies a finding.

use super::{digest, Context, Fact, Observation};
use regex::Regex;
use std::sync::LazyLock;

/// Lexical trust-labeling hint: when present near the untrusted-content
/// combination, treated as an explicit (if unverified) trust boundary and
/// the candidate is suppressed rather than downgraded, mirroring the pinned
/// pre-existing behaviour of this rule.
static TRUST_LABEL_HINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)trust_label|sanitize|escape|allowlist|provenance|content_filter").unwrap());

static INDIRECT_UNTRUSTED_CONTENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:prompt|messages|system_prompt|instructions?)\s*[:=]\s*[^\n]*(?:request|input|issue|body|content|document|description)")
        .unwrap()
});

static RETRIEVED_CONTENT_UNTRUSTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:retriever|vectorStore|search_result|retrieved[-_ ]?content|rag[-_ ]?context|document[-_ ]?content)[\s\S]{0,160}(?:prompt|messages|context)\s*[:=+]")
        .unwrap()
});

static MEMORY_CONTEXT_UNTRUSTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:conversation_history|memory_store|session_memory|agent_memory|long[-_ ]?term memory)[\s\S]{0,160}(?:prompt|messages|context)\s*[:=+]")
        .unwrap()
});

static DYNAMIC_TOOL_SCHEMA_UNTRUSTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:tools|inputSchema|tool_use)\s*(?:\.push|\[|=)[^\n]*(?:JSON\.parse|retrieved|document|request\.|response\.|externalContent)")
        .unwrap()
});

#[derive(Clone, Copy)]
enum SourceKind {
    UntrustedContent,
    RetrievedContent,
    MemoryContent,
}

impl SourceKind {
    fn as_str(self) -> &'static str {
        match self {
            SourceKind::UntrustedContent => "untrusted-content",
            SourceKind::RetrievedContent => "retrieved-content",
            SourceKind::MemoryContent => "memory-content",
        }
    }
}

struct Rule {
    id: &'static str,
    claim: &'static str,
    severity_hint: &'static str,
    source_kind: SourceKind,
    sink_kind: &'static str,
    control_types: &'static [&'static str],
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
    uncertainty: &'static [&'static str],
    pattern: &'static LazyLock<Regex>,
}

static RULES: &[Rule] = &[
    Rule {
        id: "ai.prompt-injection.indirect-untrusted-content",
        claim: "Untrusted content is mixed into a model prompt without a visible trust label.",
        severity_hint: "high",
        source_kind: SourceKind::UntrustedContent,
        sink_kind: "prompt",
        control_types: &["content-provenance-label", "prompt-trust-boundary"],
        effect_kind: "control-bypass",
        effect_action: "influence-model",
        effect_scope: "prompt",
        chain_roles: &["starter"],
        uncertainty: &["Influence alone is not tool compromise; downstream output handling must be adjudicated."],
        pattern: &INDIRECT_UNTRUSTED_CONTENT,
    },
    Rule {
        id: "ai.prompt-injection.retrieved-content-untrusted",
        claim: "Retrieved (RAG/search) content reaches the model prompt or context without a trust boundary marker.",
        severity_hint: "high",
        source_kind: SourceKind::RetrievedContent,
        sink_kind: "retrieval-context",
        control_types: &["content-provenance-label", "retrieval-trust-boundary"],
        effect_kind: "control-bypass",
        effect_action: "influence-model",
        effect_scope: "retrieval-context",
        chain_roles: &["starter"],
        uncertainty: &["Retrieval alone does not confirm attacker control of the corpus; corpus write access must be adjudicated against ai-poisoning-rag candidates."],
        pattern: &RETRIEVED_CONTENT_UNTRUSTED,
    },
    Rule {
        id: "ai.prompt-injection.memory-context-untrusted",
        claim: "Durable agent memory content is re-injected into a prompt without a trust label.",
        severity_hint: "medium",
        source_kind: SourceKind::MemoryContent,
        sink_kind: "memory-context",
        control_types: &["content-provenance-label", "memory-trust-boundary"],
        effect_kind: "control-bypass",
        effect_action: "influence-model",
        effect_scope: "memory-context",
        chain_roles: &["starter"],
        uncertainty: &["A prior turn writing untrusted content into memory is a distinct precondition adjudicated by ai-poisoning-rag candidates, not this rule."],
        pattern: &MEMORY_CONTEXT_UNTRUSTED,
    },
    Rule {
        id: "ai.prompt-injection.dynamic-tool-schema-untrusted",
        claim: "A tool/function schema is constructed at runtime from untrusted content rather than a fixed definition.",
        severity_hint: "high",
        source_kind: SourceKind::UntrustedContent,
        sink_kind: "tool-schema",
        control_types: &["tool-schema-allowlist", "content-provenance-label"],
        effect_kind: "control-bypass",
        effect_action: "redefine-tool-schema",
        effect_scope: "tool-capability",
        chain_roles: &["starter", "enabler"],
        uncertainty: &["A dynamically built schema is not automatically attacker-controlled; the content source must be adjudicated."],
        pattern: &DYNAMIC_TOOL_SCHEMA_UNTRUSTED,
    },
];

pub const ID: &str = "security.ai-prompt-injection";
pub const CANDIDATE_CLASS: &str = "ai-prompt-injection";

/// Mirrors the JS pack's `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        let invocation = context.find_invocation_process(file);
        let untrusted_source = context.find_untrusted_source(file);
        let rag_store = context.find_data_store("rag");
        let memory_store = context.find_data_store("memory");

        for rule in RULES {
            if !rule.pattern.is_match(text) {
                continue;
            }
            if TRUST_LABEL_HINT.is_match(text) {
                continue;
            }

            let sink_entity = invocation.or(artifact);
            let mut source_entity = untrusted_source.or(artifact);
            if matches!(rule.source_kind, SourceKind::RetrievedContent) {
                if let Some(rag_store) = rag_store {
                    source_entity = Some(rag_store);
                }
            }
            if matches!(rule.source_kind, SourceKind::MemoryContent) {
                if let Some(memory_store) = memory_store {
                    source_entity = Some(memory_store);
                }
            }

            let control = context.find_control(sink_entity.map(|e| e.id.as_str()), rule.control_types);
            if control.is_some() {
                // Observed, model-grounded control suppresses the candidate entirely.
                continue;
            }

            let sources = source_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
            let sinks = sink_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
            let mut evidence_refs: Vec<String> = source_entity
                .map(|e| e.evidence_refs.clone())
                .unwrap_or_default()
                .into_iter()
                .chain(sink_entity.map(|e| e.evidence_refs.clone()).unwrap_or_default())
                .collect();
            evidence_refs.sort();
            evidence_refs.dedup();

            observations.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: CANDIDATE_CLASS.to_string(),
                claim: rule.claim.to_string(),
                severity_hint: rule.severity_hint.to_string(),
                sources,
                sinks,
                attacker_capabilities: vec!["control-untrusted-content".to_string()],
                preconditions: vec![Fact {
                    kind: "attacker-position".to_string(),
                    subject: "actor:external".to_string(),
                    action: "supply-content".to_string(),
                    object: None,
                    scope: Some(rule.sink_kind.to_string()),
                    environment: "agent".to_string(),
                    tenant: None,
                }],
                effects: vec![Fact {
                    kind: rule.effect_kind.to_string(),
                    subject: "actor:external".to_string(),
                    action: rule.effect_action.to_string(),
                    object: sink_entity.map(|e| e.id.clone()),
                    scope: Some(rule.effect_scope.to_string()),
                    environment: "agent".to_string(),
                    tenant: None,
                }],
                assets: vec![],
                trust_boundary_crossings: vec![],
                required_controls: vec![],
                observed_controls: vec![],
                chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                evidence_refs,
                detector_metadata: serde_json::json!({
                    "file": file,
                    "untrustedOrigin": rule.source_kind.as_str(),
                    "sink": rule.sink_kind,
                    "detectionMethod": "lexical-pattern",
                    "matchDigest": digest(format!("{}{}", rule.id, file)),
                }),
                uncertainty: rule.uncertainty.iter().map(|s| s.to_string()).collect(),
            });
        }
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::r66::Entity;

    #[test]
    fn indirect_untrusted_content_emits_candidate() {
        let ctx = Context::new().with_file(
            "agent.mjs",
            "const prompt = `Answer this: ${request.body.description}`;",
        );
        let obs = analyze(&ctx);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].rule_id, "ai.prompt-injection.indirect-untrusted-content");
        assert!(obs[0].uncertainty[0].contains("not tool compromise"));
    }

    #[test]
    fn trust_label_hint_suppresses_candidate() {
        let ctx = Context::new().with_file(
            "agent.mjs",
            "const prompt = sanitize(`Answer this: ${request.body.description}`);",
        );
        assert!(analyze(&ctx).is_empty());
    }

    #[test]
    fn observed_control_suppresses_candidate() {
        let ctx = Context::new()
            .with_file("agent.mjs", "const prompt = `Answer this: ${request.body.description}`;")
            .with_entity(Entity::control(
                "ctrl:1",
                "prompt-trust-boundary",
                "prompt boundary",
                vec!["ev:c".into()],
            ));
        assert!(analyze(&ctx).is_empty());
    }

    #[test]
    fn retrieved_content_untrusted_emits_candidate() {
        let ctx = Context::new().with_file(
            "rag.mjs",
            "const messages = [{ role: 'system', content: retrieved_content }];\nmessages.push({ context: search_result });",
        );
        let obs = analyze(&ctx);
        assert!(obs.iter().any(|o| o.rule_id == "ai.prompt-injection.retrieved-content-untrusted"));
    }

    #[test]
    fn dynamic_tool_schema_untrusted_emits_candidate() {
        let ctx = Context::new().with_file("agent.mjs", "tools.push(JSON.parse(response.body));");
        let obs = analyze(&ctx);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].rule_id, "ai.prompt-injection.dynamic-tool-schema-untrusted");
        assert_eq!(obs[0].chain_roles, vec!["starter".to_string(), "enabler".to_string()]);
    }

    #[test]
    fn empty_file_is_skipped() {
        let ctx = Context::new().with_file("empty.mjs", "");
        assert!(analyze(&ctx).is_empty());
    }
}
