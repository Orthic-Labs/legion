//! Port of five AI security packs (chunk wf056, area `src/providers/security`):
//!
//! - `src/providers/security/packs/ai-excessive-agency.mjs` — Security Appendix §53:
//!   destructive tools without approval, shared high-scope identities, cross-tenant tool
//!   boundaries, agentic loops without a side-effect budget.
//! - `src/providers/security/packs/ai-integrity.mjs` — a two-rule `createPatternPack`
//!   instance (RAG untrusted ingestion, model-output-as-policy-decision).
//! - `src/providers/security/packs/ai-model-abuse.mjs` — model/provider data retention,
//!   uncapped cost loops, shared provider credentials.
//! - `src/providers/security/packs/ai-output-handling.mjs` — Security Appendix §50.8:
//!   model output reaching HTML/shell/SQL/filesystem/URL/patch sinks without a
//!   validated-at-sink control.
//! - `src/providers/security/packs/ai-poisoning-rag.mjs` — RAG/memory poisoning,
//!   cross-tenant retrieval, durable-memory untrusted writes, and the
//!   prompt-injection-to-sensitive-action chain (retrieved content driving a destructive
//!   tool call).
//!
//! `git grep` over `engine/` for these packs' rule ids, candidate classes, and pack ids
//! found no prior native port, so all five are ported fresh here.
//!
//! Every pack here follows the same shape found in the JS source: a pure `analyze`
//! function that walks a caller-supplied set of files/text, looks up bound
//! `SecurityModel` entities (repository-artifact / tool-capability / process /
//! data-store / source), and — for the four hand-written packs — checks whether a
//! `protects`/`validates` relation into the candidate sink already terminates at a
//! `control` entity of one of the rule's accepted `controlType`s, suppressing the
//! candidate entirely when so (the "no clean verdict, only insufficient model evidence"
//! contract each pack's own header documents). `ai-integrity.mjs` instead delegates to
//! `pattern-pack.mjs`'s simpler `createPatternPack` factory (source-text match only, no
//! control lookup), reproduced here as `ai_integrity::analyze`.
//!
//! This module is intentionally self-contained: it defines its own minimal
//! `SecurityModel`/`Entity`/`Relation`/`PackContext`/`Observation` types rather than
//! reaching into another chunk's model types, since no shared security-context module
//! was found under this crate at port time. The `digest`/`stable_id`/`canonicalize`
//! helpers reproduce `src/providers/security/contracts.mjs`'s `digest(value)` exactly
//! (namespace `"digest"`, `sha256:` + hex of `` `${namespace}\0${JSON.stringify(canonicalize(value))}` ``)
//! so `matchDigest` values are bit-for-bit comparable with the JS implementation given
//! the same inputs.
//!
//! Everything here is pure: no filesystem walk, no model call, no tool execution, no
//! network access — matching every source file's own header comment.

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

// =================================================================================================
// contracts.mjs subset: canonicalize / stable_id / digest
// =================================================================================================

/// Mirrors `canonicalize`: arrays map element-wise, objects get their keys sorted
/// (recursively), everything else passes through unchanged.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Mirrors `stableId(namespace, value)`.
pub fn stable_id(namespace: &str, value: &Value) -> String {
    let body = serde_json::to_string(&canonicalize(value)).expect("json values always serialize");
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Mirrors `digest(value)`.
pub fn digest(value: &Value) -> String {
    stable_id("digest", value)
}

// =================================================================================================
// Minimal shared security-model types (self-contained: no prior port of
// model-builder.mjs's context/entity/relation types was found under this crate).
// =================================================================================================

#[derive(Debug, Clone, Default)]
pub struct Entity {
    pub id: String,
    pub kind: String,
    pub name: String,
    /// Free-form attributes (mirrors `entity.attributes`); looked up by key.
    pub attributes: BTreeMap<String, Value>,
    pub evidence_refs: Vec<String>,
}

impl Entity {
    pub fn attr_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(Value::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityModel {
    pub entities: Vec<Entity>,
}

/// Mirrors the subset of the JS `context` object every one of these five packs'
/// `analyze(context)` actually reads: `context.files`, `context.readFile(file)`,
/// `context.model.entities`, `context.relationsTo(id)`, `context.entityById.get(id)`,
/// and `context.denominatorDigest` (used only by `variantStrategies.enumerate`).
pub struct PackContext<'a> {
    pub files: Vec<String>,
    pub source_text: BTreeMap<String, String>,
    pub model: &'a SecurityModel,
    pub relations: &'a [Relation],
    pub denominator_digest: String,
}

impl<'a> PackContext<'a> {
    pub fn read_file(&self, file: &str) -> Option<&str> {
        self.source_text.get(file).map(String::as_str)
    }

    pub fn entity_by_id(&self, id: &str) -> Option<&Entity> {
        self.model.entities.iter().find(|e| e.id == id)
    }

    /// Mirrors `context.relationsTo(id)`: relations whose `to` is `id`.
    pub fn relations_to(&self, id: &str) -> impl Iterator<Item = &Relation> {
        self.relations.iter().filter(move |r| r.to == id)
    }

    fn find_entity<F: Fn(&Entity) -> bool>(&self, pred: F) -> Option<&Entity> {
        self.model.entities.iter().find(|e| pred(e))
    }
}

/// Mirrors the observation object each pack's `analyze` pushes.
#[derive(Debug, Clone)]
pub struct Observation {
    pub rule_id: String,
    pub candidate_class: String,
    pub claim: String,
    pub severity_hint: String,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub attacker_capabilities: Vec<String>,
    pub effect_kind: String,
    pub effect_action: String,
    pub effect_object: Option<String>,
    pub effect_scope: String,
    pub effect_environment: String,
    pub chain_roles: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub detector_metadata: Value,
    pub uncertainty: Vec<String>,
}

/// Dedupe-preserving insert-order union of two evidence-ref lists (mirrors
/// `[...new Set([...a, ...b])]`).
fn union_refs(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for x in a.iter().chain(b.iter()) {
        if !out.contains(x) {
            out.push(x.clone());
        }
    }
    out
}

fn find_control<'a>(
    ctx: &'a PackContext<'a>,
    sink_id: Option<&str>,
    control_types: &[&str],
) -> Option<&'a Entity> {
    if let Some(sink_id) = sink_id {
        for rel in ctx.relations_to(sink_id) {
            if rel.kind != "protects" && rel.kind != "validates" {
                continue;
            }
            if let Some(control) = ctx.entity_by_id(&rel.from) {
                if control.kind == "control"
                    && control
                        .attr_str("controlType")
                        .map(|t| control_types.contains(&t))
                        .unwrap_or(false)
                {
                    return Some(control);
                }
            }
        }
    }
    ctx.find_entity(|e| {
        e.kind == "control"
            && e.attr_str("controlType")
                .map(|t| control_types.contains(&t))
                .unwrap_or(false)
    })
}

// =================================================================================================
// ai-excessive-agency.mjs
// =================================================================================================

pub mod ai_excessive_agency {
    use super::*;

    pub const DESTRUCTIVE: &[&str] = &[
        "delete", "publish", "deploy", "send", "transfer", "approve", "merge", "release",
        "sign", "execute", "write-secret",
    ];

    struct Rule {
        id: &'static str,
        severity_hint: &'static str,
        control_types: &'static [&'static str],
        effect_kind: &'static str,
        effect_action: &'static str,
        effect_scope: &'static str,
        chain_roles: &'static [&'static str],
        uncertainty: &'static [&'static str],
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "ai.agency.destructive-tool-without-approval",
            severity_hint: "high",
            control_types: &["human-approval"],
            effect_kind: "principal-access",
            effect_action: "act-as",
            effect_scope: "service-identity",
            chain_roles: &["enabler", "privilege-escalation", "impact"],
            uncertainty: &["A runtime policy outside the repository may require approval."],
        },
        Rule {
            id: "ai.agency.shared-high-scope-identity",
            severity_hint: "medium",
            control_types: &["identity-scoping"],
            effect_kind: "principal-access",
            effect_action: "act-as",
            effect_scope: "shared-identity",
            chain_roles: &["enabler"],
            uncertainty: &["Excessive agency amplifies other candidates; alone it may be a misuse hazard."],
        },
        Rule {
            id: "ai.agency.cross-tenant-tool-boundary",
            severity_hint: "high",
            control_types: &["tenant-scope-check"],
            effect_kind: "confidentiality-impact",
            effect_action: "cross-tenant-act",
            effect_scope: "tool-capability",
            chain_roles: &["enabler", "control-bypass"],
            uncertainty: &["A missing local tenant-scope argument does not confirm cross-tenant reach; the tool implementation must be adjudicated."],
        },
        Rule {
            id: "ai.agency.missing-side-effect-budget",
            severity_hint: "medium",
            control_types: &["side-effect-budget"],
            effect_kind: "availability-impact",
            effect_action: "exhaust",
            effect_scope: "tool-invocation-loop",
            chain_roles: &["enabler"],
            uncertainty: &["A missing local budget pattern does not confirm an unbounded loop; a runtime orchestrator budget may exist outside the repository."],
        },
    ];

    fn destructive_pattern() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            let alt = DESTRUCTIVE.join("|");
            Regex::new(&format!(
                r#"(?i)\b(?:name\s*:\s*["']({alt})["']|\b(?:{alt})\w*\s*(?:\(|:))"#
            ))
            .expect("valid regex")
        })
    }

    fn detect_destructive_tool_without_approval(text: &str) -> Option<String> {
        let re = destructive_pattern();
        let action = re
            .captures(text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .or_else(|| {
                DESTRUCTIVE.iter().find_map(|action| {
                    let single = Regex::new(&format!(r"(?i)\b{action}\w*\s*(?:\(|:)")).ok()?;
                    if single.is_match(text) {
                        Some(action.to_string())
                    } else {
                        None
                    }
                })
            })?;
        if Regex::new(r"(?i)approval|reauthenticate|requireConfirm|human_in_the_loop|allowlist")
            .unwrap()
            .is_match(text)
        {
            return None;
        }
        Some(action)
    }

    fn detect_shared_high_scope_identity(text: &str) -> bool {
        Regex::new(r"(?i)\b(?:token|credential|secret|api_key)\b").unwrap().is_match(text)
            && Regex::new(r"(?i)\b(?:tool|agent|assistant)\b").unwrap().is_match(text)
            && !Regex::new(r"scope|least|rotate|readonly").unwrap().is_match(text)
    }

    fn detect_cross_tenant_tool_boundary(text: &str) -> bool {
        Regex::new(r"(?i)\btool\b[\s\S]{0,120}\b(?:run|execute|invoke)\s*\(").unwrap().is_match(text)
            && Regex::new(r"(?i)\b(?:delete|write|update|transfer|deploy)\w*\s*\(").unwrap().is_match(text)
            && !Regex::new(r"(?i)\btenant(?:Id)?\b").unwrap().is_match(text)
    }

    fn detect_missing_side_effect_budget(text: &str) -> bool {
        Regex::new(r"(?i)\bwhile\s*\(\s*true\s*\)|\bfor\s*\(;;\)|\bagent[_ ]?loop\b").unwrap().is_match(text)
            && Regex::new(r"(?i)\btool\b|\.run\(|\.invoke\(").unwrap().is_match(text)
            && !Regex::new(r"(?i)max_calls|max_steps|maxSteps|rate_limit|token_budget|spend_limit|\bquota\b|step_budget").unwrap().is_match(text)
    }

    fn find_artifact<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }

    fn find_tool_capability<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "tool-capability" && e.attr_str("file") == Some(file))
            .or_else(|| ctx.find_entity(|e| e.kind == "tool-capability"))
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            let tool = find_tool_capability(ctx, file);

            for rule in RULES {
                let matched_action: Option<Option<String>> = match rule.id {
                    "ai.agency.destructive-tool-without-approval" => {
                        detect_destructive_tool_without_approval(text).map(Some)
                    }
                    "ai.agency.shared-high-scope-identity" => {
                        if detect_shared_high_scope_identity(text) { Some(None) } else { None }
                    }
                    "ai.agency.cross-tenant-tool-boundary" => {
                        if detect_cross_tenant_tool_boundary(text) { Some(None) } else { None }
                    }
                    "ai.agency.missing-side-effect-budget" => {
                        if detect_missing_side_effect_budget(text) { Some(None) } else { None }
                    }
                    _ => None,
                };
                let Some(action) = matched_action else { continue };

                let sink_entity = tool.or(artifact);
                if find_control(ctx, sink_entity.map(|e| e.id.as_str()), rule.control_types).is_some() {
                    continue;
                }

                let sources: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let sinks: Vec<String> = sink_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let evidence_refs = union_refs(
                    artifact.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                    sink_entity.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                );

                let claim = match rule.id {
                    "ai.agency.destructive-tool-without-approval" => format!(
                        "A destructive {} tool is available to the agent without a visible approval or reauthentication control.",
                        action.as_deref().unwrap_or("")
                    ),
                    "ai.agency.shared-high-scope-identity" => {
                        "A shared high-scope identity is exposed to tool execution without visible scoping.".to_string()
                    }
                    "ai.agency.cross-tenant-tool-boundary" => {
                        "A tool available to the agent performs a state-changing action without a visible tenant-scope argument.".to_string()
                    }
                    "ai.agency.missing-side-effect-budget" => {
                        "An agentic tool-invocation loop is present without a visible step, call, spend, or token budget control.".to_string()
                    }
                    _ => unreachable!(),
                };

                let mut detector_metadata = json!({
                    "file": file,
                    "detectionMethod": "lexical-pattern",
                    "matchDigest": digest(&json!({ "ruleId": rule.id, "file": file })),
                });
                if let Some(action) = &action {
                    detector_metadata["action"] = json!(action);
                }

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: "ai-agent-agency".to_string(),
                    claim,
                    severity_hint: rule.severity_hint.to_string(),
                    sources,
                    sinks,
                    attacker_capabilities: vec!["influence-model-input-or-retrieval".to_string()],
                    effect_kind: rule.effect_kind.to_string(),
                    effect_action: rule.effect_action.to_string(),
                    effect_object: sink_entity.map(|e| e.id.clone()),
                    effect_scope: rule.effect_scope.to_string(),
                    effect_environment: "agent".to_string(),
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs,
                    detector_metadata,
                    uncertainty: rule.uncertainty.iter().map(|s| s.to_string()).collect(),
                });
            }
        }
        observations
    }
}

// =================================================================================================
// ai-model-abuse.mjs
// =================================================================================================

pub mod ai_model_abuse {
    use super::*;

    struct Rule {
        id: &'static str,
        severity_hint: &'static str,
        control_types: &'static [&'static str],
        effect_kind: &'static str,
        effect_action: &'static str,
        effect_scope: &'static str,
        chain_roles: &'static [&'static str],
        claim: &'static str,
        uncertainty: &'static str,
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "ai.model-abuse.provider-data-retention-unbounded",
            severity_hint: "high",
            control_types: &["data-retention-opt-out", "zero-retention-agreement"],
            effect_kind: "confidentiality-impact",
            effect_action: "retain-third-party",
            effect_scope: "model-provider",
            chain_roles: &["starter", "impact"],
            claim: "A model-provider call includes personal/customer data without a visible data-retention opt-out or zero-retention control.",
            uncertainty: "A per-account or contractual retention setting outside the repository may already govern this call; that must be adjudicated.",
        },
        Rule {
            id: "ai.model-abuse.uncapped-cost-loop",
            severity_hint: "medium",
            control_types: &["side-effect-budget", "rate-limit"],
            effect_kind: "availability-impact",
            effect_action: "exhaust-spend",
            effect_scope: "model-provider",
            chain_roles: &["starter", "impact"],
            claim: "A model invocation sits inside a loop/retry construct without a visible call, step, retry, or spend budget, enabling a cost-abuse amplification loop.",
            uncertainty: "A missing local budget pattern does not confirm the loop is attacker-reachable or unbounded at runtime; both must be adjudicated.",
        },
        Rule {
            id: "ai.model-abuse.shared-provider-credential",
            severity_hint: "medium",
            control_types: &["identity-scoping", "tenant-scope-check"],
            effect_kind: "principal-access",
            effect_action: "act-as",
            effect_scope: "model-provider-credential",
            chain_roles: &["enabler"],
            claim: "A model-provider credential is referenced as a global/shared/static value without per-tenant or per-user scoping.",
            uncertainty: "A single global credential is not automatically abusable; whether callers can bind it to attacker-chosen inputs across tenants must be adjudicated.",
        },
    ];

    fn matches(rule_id: &str, text: &str) -> bool {
        match rule_id {
            "ai.model-abuse.provider-data-retention-unbounded" => {
                Regex::new(r"(?i)(?:openai|anthropic|\.chat\.completions\.create|messages\.create)\s*\(").unwrap().is_match(text)
                    && Regex::new(r"(?i)\b(?:email|ssn|creditCard|user\.|customer\.|pii)\b").unwrap().is_match(text)
                    && !Regex::new(r"(?i)zero_retention|retention\s*:\s*['\x22]?none|dataResidency|optOutTraining|store\s*:\s*false").unwrap().is_match(text)
            }
            "ai.model-abuse.uncapped-cost-loop" => {
                Regex::new(r"(?i)\b(?:while\s*\(|for\s*\(|retry|\.map\()").unwrap().is_match(text)
                    && Regex::new(r"(?i)\.create\(|\.complete\(|\.generate\(").unwrap().is_match(text)
                    && !Regex::new(r"(?i)max_calls|max_steps|maxSteps|rate_limit|token_budget|spend_limit|\bquota\b|step_budget|maxRetries").unwrap().is_match(text)
            }
            "ai.model-abuse.shared-provider-credential" => {
                Regex::new(r"(?i)(?:api_key|apiKey|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*[:=]").unwrap().is_match(text)
                    && Regex::new(r"(?i)\bglobal\b|\bshared\b|\bstatic\b|process\.env\.").unwrap().is_match(text)
                    && !Regex::new(r"(?i)\btenant(?:Id)?\b|\bperUser\b|\bscopedKey\b").unwrap().is_match(text)
            }
            _ => false,
        }
    }

    fn find_artifact<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }

    fn find_invocation_process<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        let name = format!("model invocation {file}");
        ctx.find_entity(|e| {
            e.kind == "process" && e.attr_str("processKind") == Some("model-invocation") && e.name == name
        })
        .or_else(|| ctx.find_entity(|e| e.kind == "process" && e.attr_str("processKind") == Some("model-invocation")))
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            let invocation = find_invocation_process(ctx, file);

            for rule in RULES {
                if !matches(rule.id, text) {
                    continue;
                }
                let sink_entity = invocation.or(artifact);
                if find_control(ctx, sink_entity.map(|e| e.id.as_str()), rule.control_types).is_some() {
                    continue;
                }

                let sources: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let sinks: Vec<String> = sink_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let evidence_refs = union_refs(
                    artifact.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                    sink_entity.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                );

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: "ai-model-abuse".to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources,
                    sinks,
                    attacker_capabilities: vec!["influence-model-invocation-volume-or-payload".to_string()],
                    effect_kind: rule.effect_kind.to_string(),
                    effect_action: rule.effect_action.to_string(),
                    effect_object: sink_entity.map(|e| e.id.clone()),
                    effect_scope: rule.effect_scope.to_string(),
                    effect_environment: "agent".to_string(),
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs,
                    detector_metadata: json!({
                        "file": file,
                        "sink": "model-provider",
                        "detectionMethod": "lexical-pattern",
                        "matchDigest": digest(&json!({ "ruleId": rule.id, "file": file })),
                    }),
                    uncertainty: vec![rule.uncertainty.to_string()],
                });
            }
        }
        observations
    }
}

// =================================================================================================
// ai-output-handling.mjs
// =================================================================================================

pub mod ai_output_handling {
    use super::*;

    struct Rule {
        id: &'static str,
        sink_kind: &'static str,
        severity_hint: &'static str,
        pattern: fn(&str) -> bool,
        control_types: &'static [&'static str],
        effect_kind: &'static str,
        effect_action: &'static str,
        effect_scope: &'static str,
        chain_roles: &'static [&'static str],
    }

    fn p_shell(t: &str) -> bool {
        Regex::new(r"(?i)(?:exec|spawn|system|child_process)\s*\([^\n]*(?:model|output|completion|response|message|tool_result)")
            .unwrap()
            .is_match(t)
    }
    fn p_html(t: &str) -> bool {
        Regex::new(r"(?i)(?:innerHTML|dangerouslySetInnerHTML|v-html|render_template_string|\.html_safe)\s*[^\n]*(?:model|output|completion|response|message)")
            .unwrap()
            .is_match(t)
    }
    fn p_sql(t: &str) -> bool {
        Regex::new(r"(?i)(?:execute|query|raw|FromSqlRaw)\s*\([^\n]*(?:model|output|completion|response|message|tool_result)")
            .unwrap()
            .is_match(t)
    }
    fn p_path(t: &str) -> bool {
        Regex::new(r"(?i)(?:writeFile|open|readFile|fs\.write|Path\.)\s*\([^\n]*(?:model|output|completion|response|message)")
            .unwrap()
            .is_match(t)
    }
    fn p_url(t: &str) -> bool {
        Regex::new(r"(?i)(?:fetch|redirect|location\.href|axios\.get)\s*\([^\n]*(?:model|output|completion|response|message|tool_result)")
            .unwrap()
            .is_match(t)
    }
    fn p_patch(t: &str) -> bool {
        Regex::new(r"(?i)(?:applyPatch|git\.apply|autoApply|writeFile\([^\n]*diff)\s*\([^\n]*(?:model|output|completion|response|message|patch)")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "ai.output-handling.model-output-to-shell",
            sink_kind: "shell",
            severity_hint: "high",
            pattern: p_shell,
            control_types: &["shell-argument-escaping", "output-schema-validation"],
            effect_kind: "code-execution",
            effect_action: "execute",
            effect_scope: "sink-process",
            chain_roles: &["enabler", "impact"],
        },
        Rule {
            id: "ai.output-handling.model-output-to-html",
            sink_kind: "html",
            severity_hint: "high",
            pattern: p_html,
            control_types: &["html-sanitization", "output-schema-validation"],
            effect_kind: "code-execution",
            effect_action: "render",
            effect_scope: "dom",
            chain_roles: &["enabler", "impact"],
        },
        Rule {
            id: "ai.output-handling.model-output-to-sql",
            sink_kind: "sql",
            severity_hint: "high",
            pattern: p_sql,
            control_types: &["sql-parameterization", "output-schema-validation"],
            effect_kind: "data-access",
            effect_action: "query",
            effect_scope: "sql-sink",
            chain_roles: &["enabler", "impact"],
        },
        Rule {
            id: "ai.output-handling.model-output-to-path",
            sink_kind: "filesystem",
            severity_hint: "high",
            pattern: p_path,
            control_types: &["path-allowlist", "output-schema-validation"],
            effect_kind: "integrity-impact",
            effect_action: "write",
            effect_scope: "filesystem",
            chain_roles: &["enabler", "impact"],
        },
        Rule {
            id: "ai.output-handling.model-output-to-url",
            sink_kind: "url",
            severity_hint: "medium",
            pattern: p_url,
            control_types: &["redirect-allowlist", "output-schema-validation"],
            effect_kind: "control-bypass",
            effect_action: "bypass",
            effect_scope: "redirect-or-egress",
            chain_roles: &["enabler", "control-bypass"],
        },
        Rule {
            id: "ai.output-handling.model-output-to-patch",
            sink_kind: "patch",
            severity_hint: "high",
            pattern: p_patch,
            control_types: &["patch-review", "human-approval"],
            effect_kind: "integrity-impact",
            effect_action: "apply-patch",
            effect_scope: "repository",
            chain_roles: &["enabler", "impact"],
        },
    ];

    fn find_artifact<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }

    fn find_model_output_source<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| {
            e.kind == "source" && e.attr_str("sourceKind") == Some("model-output") && e.attr_str("file") == Some(file)
        })
        .or_else(|| ctx.find_entity(|e| e.kind == "source" && e.attr_str("sourceKind") == Some("model-output")))
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            let model_output = find_model_output_source(ctx, file);

            for rule in RULES {
                if !(rule.pattern)(text) {
                    continue;
                }
                let sink_entity = artifact;
                if find_control(ctx, sink_entity.map(|e| e.id.as_str()), rule.control_types).is_some() {
                    continue; // validated at the sink: no candidate, not "clean".
                }

                let source_entity = model_output.or(artifact);
                let sources: Vec<String> = source_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let sinks: Vec<String> = sink_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let evidence_refs = union_refs(
                    source_entity.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                    sink_entity.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                );

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: "ai-output-handling".to_string(),
                    claim: format!(
                        "Model output may reach a {} sink without a visible schema-validation or sanitization control.",
                        rule.sink_kind
                    ),
                    severity_hint: rule.severity_hint.to_string(),
                    sources,
                    sinks,
                    attacker_capabilities: vec!["influence-model-output".to_string()],
                    effect_kind: rule.effect_kind.to_string(),
                    effect_action: rule.effect_action.to_string(),
                    effect_object: sink_entity.map(|e| e.id.clone()),
                    effect_scope: rule.effect_scope.to_string(),
                    effect_environment: "application".to_string(),
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs,
                    detector_metadata: json!({
                        "file": file,
                        "untrustedOrigin": "model-output",
                        "sink": rule.sink_kind,
                        "detectionMethod": "lexical-pattern",
                        "matchDigest": digest(&json!({ "ruleId": rule.id, "file": file })),
                    }),
                    uncertainty: vec!["Model output reaching this sink is not automatically exploitable; whether the output is schema-validated/allowlisted downstream must be adjudicated.".to_string()],
                });
            }
        }
        observations
    }
}

// =================================================================================================
// ai-poisoning-rag.mjs
// =================================================================================================

pub mod ai_poisoning_rag {
    use super::*;

    struct Rule {
        id: &'static str,
        severity_hint: &'static str,
        control_types: &'static [&'static str],
        effect_kind: &'static str,
        effect_action: &'static str,
        effect_scope: &'static str,
        chain_roles: &'static [&'static str],
        store_kind: &'static str,
        claim: &'static str,
        uncertainty: &'static str,
        matcher: fn(&str) -> bool,
    }

    fn m_ingestion(t: &str) -> bool {
        Regex::new(r"(?i)(?:embed|vectorStore|indexDocuments|upsert)\s*\([^\n]*(?:url|upload|user|external|web|scraped)")
            .unwrap()
            .is_match(t)
    }
    fn m_cross_tenant(t: &str) -> bool {
        Regex::new(r"(?i)\b(?:retriever|vectorStore|index)\.(?:query|search|similaritySearch)\s*\(").unwrap().is_match(t)
            && !Regex::new(r"(?i)\btenant(?:Id)?\b|\bnamespace\b").unwrap().is_match(t)
    }
    fn m_memory(t: &str) -> bool {
        Regex::new(r"(?i)(?:memory_store|session_memory|agent_memory|conversation_history)\s*\.(?:push|save|append|set)\s*\([^\n]*(?:request|input|user|external|retrieved|document)")
            .unwrap()
            .is_match(t)
    }
    fn m_destructive(t: &str) -> bool {
        Regex::new(r"(?i)(?:retrieved[-_ ]?content|search_result|document[-_ ]?content)[\s\S]{0,120}\b(?:delete|deleteFile|dropTable|rm\s*\(|deploy|transfer)\w*\s*\(")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "ai.poisoning.rag-ingestion-untrusted-provenance",
            severity_hint: "high",
            control_types: &["provenance-filter", "content-integrity-check"],
            effect_kind: "integrity-impact",
            effect_action: "poison-corpus",
            effect_scope: "rag-store",
            chain_roles: &["starter", "enabler"],
            store_kind: "rag",
            claim: "Untrusted content may enter a retrieval corpus without a provenance or integrity filter.",
            uncertainty: "Ingestion alone does not confirm the corpus is later retrieved into a prompt; the retrieval path must be adjudicated.",
            matcher: m_ingestion,
        },
        Rule {
            id: "ai.poisoning.cross-tenant-retrieval",
            severity_hint: "high",
            control_types: &["tenant-scope-check"],
            effect_kind: "confidentiality-impact",
            effect_action: "cross-tenant-retrieve",
            effect_scope: "rag-store",
            chain_roles: &["starter", "control-bypass"],
            store_kind: "rag",
            claim: "A retrieval query reaches the vector/RAG store without a visible tenant or namespace scope.",
            uncertainty: "A missing local tenant filter does not confirm the store is multi-tenant; the store's partitioning must be adjudicated.",
            matcher: m_cross_tenant,
        },
        Rule {
            id: "ai.poisoning.durable-memory-untrusted-write",
            severity_hint: "high",
            control_types: &["memory-write-validation"],
            effect_kind: "persistence",
            effect_action: "poison-memory",
            effect_scope: "memory-store",
            chain_roles: &["starter", "enabler"],
            store_kind: "memory",
            claim: "Durable agent memory is written from request/external/retrieved content without validation, enabling persistent (multi-turn) poisoning.",
            uncertainty: "A write alone does not confirm the content is later replayed into a prompt; the read path must be adjudicated.",
            matcher: m_memory,
        },
        Rule {
            id: "ai.poisoning.destructive-action-from-retrieved-content",
            severity_hint: "critical",
            control_types: &["human-approval"],
            effect_kind: "integrity-impact",
            effect_action: "destructive-tool-call",
            effect_scope: "tool-capability",
            chain_roles: &["starter", "pivot", "impact"],
            store_kind: "rag",
            claim: "Retrieved (RAG/search) content flows directly into a destructive tool call without an approval gate — the prompt-injection-to-sensitive-action pattern.",
            uncertainty: "Textual adjacency is not proof of a data-flow edge from the retrieved value to the call argument; the flow must be adjudicated.",
            matcher: m_destructive,
        },
    ];

    fn find_artifact<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }

    fn find_data_store<'a>(ctx: &'a PackContext<'a>, store_kind: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "data-store" && e.attr_str("storeKind") == Some(store_kind))
    }

    fn find_untrusted_source<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "source" && e.attr_str("trust") == Some("untrusted") && e.attr_str("file") == Some(file))
            .or_else(|| ctx.find_entity(|e| e.kind == "source" && e.attr_str("trust") == Some("untrusted")))
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            let untrusted_source = find_untrusted_source(ctx, file);

            for rule in RULES {
                if !(rule.matcher)(text) {
                    continue;
                }
                let store = find_data_store(ctx, rule.store_kind);
                let sink_entity = store.or(artifact);
                if find_control(ctx, sink_entity.map(|e| e.id.as_str()), rule.control_types).is_some() {
                    continue;
                }

                let source_entity = untrusted_source.or(artifact);
                let sources: Vec<String> = source_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let sinks: Vec<String> = sink_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let evidence_refs = union_refs(
                    source_entity.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                    sink_entity.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                );

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: "ai-poisoning-rag".to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources,
                    sinks,
                    attacker_capabilities: vec!["control-untrusted-content".to_string()],
                    effect_kind: rule.effect_kind.to_string(),
                    effect_action: rule.effect_action.to_string(),
                    effect_object: sink_entity.map(|e| e.id.clone()),
                    effect_scope: rule.effect_scope.to_string(),
                    effect_environment: "agent".to_string(),
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs,
                    detector_metadata: json!({
                        "file": file,
                        "untrustedOrigin": if rule.store_kind == "memory" { "memory-content" } else { "retrieved-content" },
                        "sink": rule.store_kind,
                        "detectionMethod": "lexical-pattern",
                        "matchDigest": digest(&json!({ "ruleId": rule.id, "file": file })),
                    }),
                    uncertainty: vec![rule.uncertainty.to_string()],
                });
            }
        }
        observations
    }
}

// =================================================================================================
// ai-integrity.mjs (a `createPatternPack` instance — pattern-pack.mjs's simpler shape:
// source-text match only, no control lookup, artifact used as both source and sink).
// =================================================================================================

pub mod ai_integrity {
    use super::*;

    struct Rule {
        id: &'static str,
        pattern: fn(&str) -> bool,
        claim: &'static str,
        severity_hint: &'static str,
        effect_kind: &'static str,
    }

    fn p_rag_untrusted_ingestion(t: &str) -> bool {
        Regex::new(r"(?i)(?:embed|vectorStore|indexDocuments|upsert)\s*\([^\n]*(?:url|upload|user|external|web)")
            .unwrap()
            .is_match(t)
    }
    fn p_model_output_policy(t: &str) -> bool {
        Regex::new(r"(?i)(?:completion|modelOutput|assistantMessage)[\s\S]{0,120}(?:approve|allow|authorize|isSafe)\s*[:=]")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "ai.rag-untrusted-ingestion",
            pattern: p_rag_untrusted_ingestion,
            claim: "Untrusted content may enter a retrieval corpus without a provenance or trust filter.",
            severity_hint: "medium",
            effect_kind: "integrity-impact",
        },
        Rule {
            id: "ai.model-output-policy",
            pattern: p_model_output_policy,
            claim: "Model output may directly determine a policy or authorization decision.",
            severity_hint: "high",
            effect_kind: "control-bypass",
        },
    ];

    pub const CANDIDATE_CLASS: &str = "ai-integrity";

    fn find_artifact<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }

    /// Mirrors `createPatternPack({ id: 'security.ai-integrity', family: 'ai-integrity', ... }).analyze`.
    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            for rule in RULES {
                if !(rule.pattern)(text) {
                    continue;
                }
                let ids: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();
                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources: ids.clone(),
                    sinks: ids,
                    attacker_capabilities: vec!["control-request-input".to_string()],
                    effect_kind: rule.effect_kind.to_string(),
                    effect_action: "bypass".to_string(),
                    effect_object: artifact.map(|e| e.id.clone()),
                    effect_scope: CANDIDATE_CLASS.to_string(),
                    effect_environment: "application".to_string(),
                    chain_roles: vec!["starter".to_string(), "impact".to_string()],
                    evidence_refs: artifact.map(|e| e.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: json!({ "file": file, "patternFamily": CANDIDATE_CLASS }),
                    uncertainty: vec!["Reachability and compensating controls require independent adjudication.".to_string()],
                });
            }
        }
        observations
    }
}

#[cfg(test)]
mod digest_self_check {
    use super::*;

    #[test]
    fn digest_matches_known_js_shape() {
        // Sanity check only: the JS `digest` is `sha256:` + 64 hex chars.
        let d = digest(&json!({ "ruleId": "ai.agency.destructive-tool-without-approval", "file": "app.mjs" }));
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
    }
}
