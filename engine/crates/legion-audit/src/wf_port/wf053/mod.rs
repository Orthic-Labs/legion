//! Port of the security-surface-model provider (chunk wf053):
//!
//! - `src/providers/security/evidence.mjs` — bounded excerpt/digest evidence helpers
//!   (Security Appendix §9).
//! - `src/providers/security/model-builder.mjs` — deterministic surface-model assembly
//!   (Security Appendix §10): runs each registered extractor, dedupes entities/relations/
//!   evidence/facts by content-derived id, asserts every relation references a known
//!   entity, and reports coverage.
//! - `src/providers/security/model-extractors/ai-agent.mjs` — AI-agent surface extractor
//!   (B7-007): model invocation sites, tool/MCP capability grants, approval controls,
//!   RAG/memory stores, side-effect budgets, and untrusted-content provenance.
//! - `src/providers/security/model-extractors/automation.mjs` — automation/package/
//!   update/release extractor (B7-006): CI/CD pipeline configuration, Jenkinsfiles,
//!   package manifests, release-tool configuration, dependency-update automation,
//!   application auto-updaters, npm registry config, lockfiles, Dockerfiles.
//! - `src/providers/security/model-extractors/cicd.mjs` — the earlier, narrower CI/CD
//!   extractor (Security Appendix §11.5) that `model-builder.mjs`'s `EXTRACTORS` list does
//!   **not** wire in (that list calls `extractCicd` from `./cicd.mjs` — this file — for
//!   nothing; the registered CI/CD-ish coverage instead comes from `extractAutomation`'s
//!   pipeline scanner). Ported faithfully anyway per the per-file assignment, exposed as
//!   `cicd::extract`, and flagged as dead/superseded in the report rather than silently
//!   dropped.
//!
//! `model-builder.mjs`'s `EXTRACTORS` array wires eight extractors; this chunk owns only
//! `ai-agent.mjs`, `automation.mjs`, and (separately) `cicd.mjs`. `common.mjs`, `http.mjs`,
//! `identity.mjs`, `data.mjs`, `cloud.mjs`, and `native-workspace.mjs` are owned by other
//! wf chunks and are not present here. `build_security_model` below is therefore ported as
//! a standalone, generically-typed assembly function — it reproduces `buildSecurityModel`'s
//! dedupe/reference-check/coverage algorithm exactly, parameterized over whatever extractor
//! outputs are supplied — rather than a fixed eight-extractor pipeline. Wiring the full
//! eight-extractor `EXTRACTORS` list is an integration step outside this chunk's owned
//! paths (`model-builder.mjs`'s own `denominator`/`plan`/`projection`/`lensRegistry` reads
//! are also plan/Blueprint-shaped inputs the integrator supplies).
//!
//! Everything here is pure: it reads only the `root`/`files`/`source_text` values the
//! caller passes in (mirroring `projection.sourceText`), does no filesystem walk beyond
//! `read_frozen_text`'s single bounded read, and makes no model call, tool execution, MCP
//! connection, or network probe of any kind — matching every source file's own header
//! comment.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

// =================================================================================================
// contracts.mjs (the subset evidence.mjs / common.mjs / the extractors in this chunk depend on)
// =================================================================================================

pub const ENTITY_KINDS: &[&str] = &[
    "actor",
    "principal",
    "identity",
    "entrypoint",
    "asset",
    "crown-jewel",
    "trust-boundary",
    "control",
    "source",
    "sink",
    "service",
    "process",
    "repository-artifact",
    "data-store",
    "tool-capability",
    "permission-scope",
    "deployment-context",
    "workflow-state",
];

pub const RELATION_KINDS: &[&str] = &[
    "assumes-role",
    "authenticates-as",
    "authorizes",
    "calls",
    "contains",
    "crosses",
    "delegates-to",
    "derives-from",
    "executes",
    "exposes",
    "flows-to",
    "grants",
    "loads",
    "protects",
    "publishes-to",
    "reaches",
    "reads",
    "retrieves-from",
    "runs-as",
    "stores",
    "trusts",
    "validates",
    "writes",
];

pub const FACT_KINDS: &[&str] = &[
    "attacker-position",
    "knowledge",
    "capability",
    "credential-possession",
    "principal-access",
    "network-reachability",
    "data-access",
    "object-access",
    "code-execution",
    "workflow-state",
    "control-bypass",
    "persistence",
    "availability-impact",
    "integrity-impact",
    "confidentiality-impact",
];

pub const CONTROL_STATES: &[&str] = &[
    "enforced",
    "present-unenforced",
    "misconfigured",
    "absent",
    "unknown",
    "not-applicable",
];

/// Mirrors `assertEnum` / `assertEntityKind`.
pub fn assert_entity_kind(value: &str) -> Result<&str, String> {
    if ENTITY_KINDS.contains(&value) {
        Ok(value)
    } else {
        Err(format!("unknown security entity kind: {value}"))
    }
}

/// Mirrors `assertRelationKind`.
pub fn assert_relation_kind(value: &str) -> Result<&str, String> {
    if RELATION_KINDS.contains(&value) {
        Ok(value)
    } else {
        Err(format!("unknown security relation kind: {value}"))
    }
}

/// Mirrors `assertFactKind`.
pub fn assert_fact_kind(value: &str) -> Result<&str, String> {
    if FACT_KINDS.contains(&value) {
        Ok(value)
    } else {
        Err(format!("unknown security fact kind: {value}"))
    }
}

/// Mirrors `assertControlState`.
pub fn assert_control_state(value: &str) -> Result<&str, String> {
    if CONTROL_STATES.contains(&value) {
        Ok(value)
    } else {
        Err(format!("unknown security control state: {value}"))
    }
}

/// Mirrors `canonicalize`: arrays map element-wise, objects get their keys sorted
/// (recursively), everything else passes through unchanged. `serde_json::Map` preserves
/// insertion order, so inserting in sorted-key order reproduces
/// `Object.fromEntries(Object.keys(value).sort().map(...))` exactly.
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

/// Mirrors `stableId(namespace, value)`: `sha256:` + hex sha256 of
/// `` `${namespace}\0${JSON.stringify(canonicalize(value))}` ``.
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
// evidence.mjs
// =================================================================================================

const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;

/// Mirrors `excerptDigest(text)`: `sha256:` + hex sha256 of the raw excerpt text (not JSON
/// encoded — the JS hashes the string bytes directly).
pub fn excerpt_digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Mirrors `lineNumber(text, index)`: 1-based line number of `index` within `text`, where
/// `index` is clamped to `>= 0` first (JS `Math.max(0, index)`). Matches JS `String#slice`
/// semantics: `index` and length are counted in UTF-16 code units, so `index` here is a
/// UTF-16 offset, not a byte offset.
pub fn line_number(text: &str, index: i64) -> usize {
    let clamped = index.max(0) as usize;
    let units: Vec<u16> = text.encode_utf16().collect();
    let end = clamped.min(units.len());
    let prefix = String::from_utf16_lossy(&units[..end]);
    prefix.split('\n').count()
}

/// Mirrors `boundedExcerpt(text, index, radius = 240)`. `index`/`radius` operate on UTF-16
/// code units to match JS `String#slice`.
pub fn bounded_excerpt(text: &str, index: i64, radius: i64) -> String {
    let units: Vec<u16> = text.encode_utf16().collect();
    let len = units.len() as i64;
    let start = (index - radius).max(0).min(len) as usize;
    let end = (index + radius).max(0).min(len) as usize;
    let end = end.max(start);
    String::from_utf16_lossy(&units[start..end])
}

/// Default radius mirrors the JS default parameter `radius = 240`.
pub fn bounded_excerpt_default(text: &str, index: i64) -> String {
    bounded_excerpt(text, index, 240)
}

pub struct SourceEvidenceInput<'a> {
    pub file: &'a str,
    pub text: &'a str,
    pub index: i64,
    pub end_index: Option<i64>,
    pub description: &'a str,
}

/// Mirrors `sourceEvidence({ file, text, index = 0, endIndex = index, description })`.
/// Returns the same shape as the JS record (with `id` computed last, as the JS spreads
/// `record` then appends `id`), as a `serde_json::Value` object.
pub fn source_evidence(input: SourceEvidenceInput<'_>) -> Value {
    let end_index = input.end_index.unwrap_or(input.index);
    let excerpt = bounded_excerpt_default(input.text, input.index);
    let record = json!({
        "kind": "source-location",
        "file": input.file,
        "line": line_number(input.text, input.index),
        "endLine": line_number(input.text, input.index.max(end_index)),
        "excerptDigest": excerpt_digest(&excerpt),
        "description": input.description,
        "strength": "verified",
    });
    let id = stable_id("security-evidence", &record);
    let mut out = record.as_object().cloned().unwrap();
    out.insert("id".to_string(), Value::String(id));
    Value::Object(out)
}

/// Mirrors `readFrozenText(root, relativePath)`: reads the file, returns `None` if it is
/// larger than `MAX_EVIDENCE_BYTES * 32` (2 MiB) or contains a NUL byte, otherwise the
/// UTF-8 decoding of its bytes (JS `Buffer#toString('utf8')` is lossy on invalid sequences,
/// so this uses `String::from_utf8_lossy` to match rather than erroring).
pub fn read_frozen_text(root: &Path, relative_path: &str) -> std::io::Result<Option<String>> {
    let buffer = fs::read(root.join(relative_path))?;
    if buffer.len() as u64 > MAX_EVIDENCE_BYTES * 32 {
        return Ok(None);
    }
    if buffer.contains(&0u8) {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&buffer).into_owned()))
}

// =================================================================================================
// model-extractors/common.mjs (constructors only — `extractCommon` is owned by another chunk)
// =================================================================================================

fn sorted_unique_refs(evidence_refs: &[String]) -> Vec<String> {
    let set: BTreeSet<String> = evidence_refs.iter().cloned().collect();
    set.into_iter().collect()
}

#[derive(Default, Clone, Copy)]
pub struct EntityOptions<'a> {
    pub assertion: Option<&'a str>,
    pub evidence_strength: Option<&'a str>,
}

/// Mirrors `entity(kind, name, attributes, evidenceRefs, options = {})`. Panics if `kind`
/// is not a known entity kind, matching the JS `assertEntityKind` throw in the typed
/// wrapper each extractor uses (`typedEntity`).
pub fn entity(
    kind: &str,
    name: &str,
    attributes: Value,
    evidence_refs: &[String],
    options: EntityOptions<'_>,
) -> Value {
    assert_entity_kind(kind).expect("entity kind must be valid");
    let body = json!({
        "kind": kind,
        "name": name,
        "attributes": attributes,
        "assertion": options.assertion.unwrap_or("observed"),
        "evidenceStrength": options.evidence_strength.unwrap_or("verified"),
        "evidenceRefs": sorted_unique_refs(evidence_refs),
    });
    let id = stable_id("security-model-entity", &body);
    let mut out = body.as_object().cloned().unwrap();
    out.insert("id".to_string(), Value::String(id));
    Value::Object(out)
}

/// Mirrors `relation(kind, from, to, evidenceRefs, attributes = {}, options = {})`.
pub fn relation(
    kind: &str,
    from: &str,
    to: &str,
    evidence_refs: &[String],
    attributes: Value,
    options: EntityOptions<'_>,
) -> Value {
    assert_relation_kind(kind).expect("relation kind must be valid");
    let body = json!({
        "kind": kind,
        "from": from,
        "to": to,
        "attributes": attributes,
        "assertion": options.assertion.unwrap_or("observed"),
        "evidenceStrength": options.evidence_strength.unwrap_or("verified"),
        "evidenceRefs": sorted_unique_refs(evidence_refs),
    });
    let id = stable_id("security-model-relation", &body);
    let mut out = body.as_object().cloned().unwrap();
    out.insert("id".to_string(), Value::String(id));
    Value::Object(out)
}

pub struct FactFields<'a> {
    pub subject: Option<&'a str>,
    pub action: Option<&'a str>,
    pub object: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub tenant: Option<&'a str>,
    pub attributes: Value,
}

/// Mirrors `fact(kind, fields, evidenceRefs = [])`.
pub fn fact(kind: &str, fields: FactFields<'_>, evidence_refs: &[String]) -> Value {
    assert_fact_kind(kind).expect("fact kind must be valid");
    let body = json!({
        "kind": kind,
        "subject": fields.subject,
        "action": fields.action,
        "object": fields.object,
        "scope": fields.scope,
        "environment": fields.environment,
        "tenant": fields.tenant,
        "attributes": fields.attributes,
        "evidenceRefs": sorted_unique_refs(evidence_refs),
    });
    let id = stable_id("security-fact", &body);
    let mut out = body.as_object().cloned().unwrap();
    out.insert("id".to_string(), Value::String(id));
    Value::Object(out)
}

/// Mirrors `controlEntity(controlType, name, evidenceRefs, attributes = {})`: an `entity`
/// of kind `control` with `controlType` merged into `attributes`.
pub fn control_entity(control_type: &str, name: &str, evidence_refs: &[String], attributes: Value) -> Value {
    let mut attrs = match attributes {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    attrs.insert("controlType".to_string(), Value::String(control_type.to_string()));
    entity("control", name, Value::Object(attrs), evidence_refs, EntityOptions::default())
}

/// The five arrays every extractor returns, ported as one struct.
#[derive(Default, Clone, Debug)]
pub struct ExtractorOutput {
    pub entities: Vec<Value>,
    pub relations: Vec<Value>,
    pub evidence: Vec<Value>,
    pub initial_facts: Vec<Value>,
    pub coverage_gaps: Vec<Value>,
}

// =================================================================================================
// model-extractors/ai-agent.mjs
// =================================================================================================

pub mod ai_agent {
    use super::*;

    fn model_invocation_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)llm|model|openai|anthropic|claude|gpt|prompt|completion").unwrap())
    }
    fn tool_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\btool\b|function_call|\btools\b").unwrap())
    }
    fn mcp_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\bmcp\b|@modelcontextprotocol|inputSchema|tool_use").unwrap())
    }
    fn approval_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)approval|human_in_the_loop|requireApproval|confirm").unwrap())
    }
    fn rag_store_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)\bvector\b|embedding|pinecone|chroma|weaviate|qdrant|faiss|milvus|retriever|\bRAG\b")
                .unwrap()
        })
    }
    fn memory_store_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)conversation_history|memory_store|session_memory|long[-_ ]?term memory|agent_memory")
                .unwrap()
        })
    }
    fn side_effect_budget_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)max_calls|max_steps|maxSteps|rate_limit|token_budget|spend_limit|\bquota\b|step_budget")
                .unwrap()
        })
    }
    fn untrusted_path_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)(^|/)(SKILL\.md|AGENTS\.md|\.claude/skills/|/skills/|/prompts/)").unwrap()
        })
    }
    fn untrusted_text_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)retrieved[- ]?content|rag[- ]?context|search_result|document[- ]?content|untrusted")
                .unwrap()
        })
    }

    fn refs(id: &str) -> Vec<String> {
        vec![id.to_string()]
    }

    /// Mirrors `extractAiAgent({ root, plan, projection, files, lensRegistry })`. `source_text`
    /// stands in for `projection.sourceText`.
    pub fn extract(files: &[String], source_text: &std::collections::HashMap<String, String>) -> ExtractorOutput {
        let mut out = ExtractorOutput::default();
        let mut saw_agent_signal = false;

        for file in files {
            let text = match source_text.get(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };

            let mut invocation_process_id: Option<String> = None;

            if model_invocation_re().is_match(text) {
                saw_agent_signal = true;
                let evidence_ref = stable_id("model-evidence", &json!({ "file": file }));
                let invocation_process = entity(
                    "process",
                    &format!("model invocation {file}"),
                    json!({ "processKind": "model-invocation", "environment": "agent" }),
                    &refs(&evidence_ref),
                    EntityOptions::default(),
                );
                let invocation_id = invocation_process["id"].as_str().unwrap().to_string();
                out.entities.push(invocation_process);
                out.evidence.push(json!({
                    "id": evidence_ref, "kind": "source-location", "file": file, "description": "Model invocation",
                }));

                let output_ref = stable_id("model-output-evidence", &json!({ "file": file }));
                let model_output = entity(
                    "source",
                    &format!("model output {file}"),
                    json!({ "sourceKind": "model-output", "trust": "untrusted", "file": file }),
                    &refs(&output_ref),
                    EntityOptions::default(),
                );
                let model_output_id = model_output["id"].as_str().unwrap().to_string();
                out.entities.push(model_output);
                out.evidence.push(json!({
                    "id": output_ref, "kind": "source-location", "file": file, "description": "Model output",
                }));
                out.relations.push(relation(
                    "derives-from",
                    &model_output_id,
                    &invocation_id,
                    &refs(&output_ref),
                    json!({}),
                    EntityOptions::default(),
                ));
                out.initial_facts.push(fact(
                    "knowledge",
                    FactFields {
                        subject: Some(&model_output_id),
                        action: Some("produce"),
                        object: Some(&invocation_id),
                        scope: Some("agent"),
                        environment: None,
                        tenant: None,
                        attributes: json!({ "kind": "model-output" }),
                    },
                    &refs(&output_ref),
                ));

                invocation_process_id = Some(invocation_id);
            }

            if tool_re().is_match(text) {
                saw_agent_signal = true;
                let evidence_ref = stable_id("tool-evidence", &json!({ "file": file }));
                let tool = entity(
                    "tool-capability",
                    &format!("tool {file}"),
                    json!({ "environment": "agent", "mcp": mcp_re().is_match(text), "file": file }),
                    &refs(&evidence_ref),
                    EntityOptions::default(),
                );
                let tool_id = tool["id"].as_str().unwrap().to_string();
                out.entities.push(tool);
                out.evidence.push(json!({
                    "id": evidence_ref, "kind": "source-location", "file": file, "description": "Tool capability",
                }));
                let subject = invocation_process_id.clone().unwrap_or_else(|| "actor:agent".to_string());
                out.initial_facts.push(fact(
                    "capability",
                    FactFields {
                        subject: Some(&subject),
                        action: Some("invoke"),
                        object: Some(&tool_id),
                        scope: Some("agent"),
                        environment: None,
                        tenant: None,
                        attributes: json!({}),
                    },
                    &refs(&evidence_ref),
                ));
                if let Some(ref proc_id) = invocation_process_id {
                    out.relations.push(relation(
                        "calls",
                        proc_id,
                        &tool_id,
                        &refs(&evidence_ref),
                        json!({}),
                        EntityOptions::default(),
                    ));
                }
            }

            if approval_re().is_match(text) {
                saw_agent_signal = true;
                let evidence_ref = stable_id("approval-evidence", &json!({ "file": file }));
                let control = control_entity(
                    "human-approval",
                    &format!("approval control {file}"),
                    &refs(&evidence_ref),
                    json!({}),
                );
                out.entities.push(control);
                out.evidence.push(json!({
                    "id": evidence_ref, "kind": "source-location", "file": file, "description": "Approval control",
                }));
            }

            if rag_store_re().is_match(text) {
                saw_agent_signal = true;
                let evidence_ref = stable_id("rag-store-evidence", &json!({ "file": file }));
                let store = entity(
                    "data-store",
                    &format!("RAG store {file}"),
                    json!({ "environment": "agent", "storeKind": "rag" }),
                    &refs(&evidence_ref),
                    EntityOptions::default(),
                );
                let store_id = store["id"].as_str().unwrap().to_string();
                out.entities.push(store);
                out.evidence.push(json!({
                    "id": evidence_ref, "kind": "source-location", "file": file, "description": "RAG store",
                }));
                if let Some(ref proc_id) = invocation_process_id {
                    out.relations.push(relation(
                        "retrieves-from",
                        proc_id,
                        &store_id,
                        &refs(&evidence_ref),
                        json!({}),
                        EntityOptions::default(),
                    ));
                }
            }

            if memory_store_re().is_match(text) {
                saw_agent_signal = true;
                let evidence_ref = stable_id("memory-store-evidence", &json!({ "file": file }));
                let store = entity(
                    "data-store",
                    &format!("agent memory store {file}"),
                    json!({ "environment": "agent", "storeKind": "memory" }),
                    &refs(&evidence_ref),
                    EntityOptions::default(),
                );
                let store_id = store["id"].as_str().unwrap().to_string();
                out.entities.push(store);
                out.evidence.push(json!({
                    "id": evidence_ref, "kind": "source-location", "file": file, "description": "Agent memory store",
                }));
                if let Some(ref proc_id) = invocation_process_id {
                    out.relations.push(relation(
                        "stores",
                        proc_id,
                        &store_id,
                        &refs(&evidence_ref),
                        json!({}),
                        EntityOptions::default(),
                    ));
                }
            }

            if side_effect_budget_re().is_match(text) {
                saw_agent_signal = true;
                let evidence_ref = stable_id("side-effect-budget-evidence", &json!({ "file": file }));
                let control = control_entity(
                    "side-effect-budget",
                    &format!("side-effect budget {file}"),
                    &refs(&evidence_ref),
                    json!({}),
                );
                out.entities.push(control);
                out.evidence.push(json!({
                    "id": evidence_ref, "kind": "source-location", "file": file,
                    "description": "Side-effect budget control",
                }));
            }

            if untrusted_path_re().is_match(file) || untrusted_text_re().is_match(text) {
                let evidence_ref = stable_id("untrusted-content-evidence", &json!({ "file": file }));
                let untrusted = entity(
                    "source",
                    &format!("untrusted agent-context content {file}"),
                    json!({
                        "file": file, "sourceKind": "skill-or-document", "trust": "untrusted", "hostile": "possible",
                    }),
                    &refs(&evidence_ref),
                    EntityOptions::default(),
                );
                let untrusted_id = untrusted["id"].as_str().unwrap().to_string();
                out.entities.push(untrusted);
                out.evidence.push(json!({
                    "id": evidence_ref, "kind": "source-location", "file": file,
                    "description": "Untrusted skill/document/retrieved content",
                }));
                out.initial_facts.push(fact(
                    "attacker-position",
                    FactFields {
                        subject: Some("actor:external"),
                        action: Some("influence"),
                        object: Some(&untrusted_id),
                        scope: Some("agent-context"),
                        environment: None,
                        tenant: None,
                        attributes: json!({ "vector": "untrusted-content-injection" }),
                    },
                    &refs(&evidence_ref),
                ));
            }
        }

        if !saw_agent_signal {
            out.coverage_gaps.push(json!({
                "kind": "ai-agent-context-not-detected",
                "domain": "ai-agent",
                "reason": "no model invocation, tool, MCP, memory, or RAG evidence found in the denominator",
            }));
        }

        out
    }
}

// =================================================================================================
// model-extractors/cicd.mjs
//
// The narrower, earlier extractor. `model-builder.mjs`'s `EXTRACTORS` array does not import
// this file — it imports `./model-extractors/cicd.mjs` as `extractCicd` and never adds it to
// `EXTRACTORS`. So in the shipped JS this function is dead code, unreferenced by any
// pipeline; `automation.mjs`'s `scanPipelineConfig` (in `EXTRACTORS` via `extractAutomation`)
// covers the same file set with materially more detail. Ported faithfully regardless, per
// the per-file assignment; flagged as dead/superseded in the report.
// =================================================================================================

pub mod cicd {
    use super::*;

    fn workflow_file_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\.github/workflows/|\.gitlab-ci|azure-pipelines|Jenkinsfile").unwrap())
    }
    fn write_all_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"permissions:\s*write-all").unwrap())
    }
    fn pull_request_target_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"pull_request_target").unwrap())
    }

    fn refs(id: &str) -> Vec<String> {
        vec![id.to_string()]
    }

    /// Mirrors `extractCicd({ root, plan, projection, files, lensRegistry })`.
    pub fn extract(files: &[String], source_text: &std::collections::HashMap<String, String>) -> ExtractorOutput {
        let mut out = ExtractorOutput::default();

        for file in files {
            if !workflow_file_re().is_match(file) {
                continue;
            }
            let text = match source_text.get(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let evidence_ref = stable_id("cicd-evidence", &json!({ "file": file }));
            let trigger = entity(
                "entrypoint",
                &format!("workflow trigger {file}"),
                json!({ "entrypointType": "ci-trigger" }),
                &refs(&evidence_ref),
                EntityOptions::default(),
            );
            let workflow_identity = entity(
                "identity",
                &format!("workflow identity {file}"),
                json!({ "environment": "ci" }),
                &refs(&evidence_ref),
                EntityOptions::default(),
            );
            let shell_sink = entity(
                "sink",
                &format!("shell sink {file}"),
                json!({ "sinkKind": "shell" }),
                &refs(&evidence_ref),
                EntityOptions::default(),
            );
            let trigger_id = trigger["id"].as_str().unwrap().to_string();
            let identity_id = workflow_identity["id"].as_str().unwrap().to_string();
            let sink_id = shell_sink["id"].as_str().unwrap().to_string();
            out.entities.push(trigger);
            out.entities.push(workflow_identity);
            out.entities.push(shell_sink);
            out.relations.push(relation(
                "executes",
                &trigger_id,
                &sink_id,
                &refs(&evidence_ref),
                json!({}),
                EntityOptions::default(),
            ));
            out.relations.push(relation(
                "runs-as",
                &sink_id,
                &identity_id,
                &refs(&evidence_ref),
                json!({}),
                EntityOptions::default(),
            ));

            if write_all_re().is_match(text) {
                out.initial_facts.push(fact(
                    "capability",
                    FactFields {
                        subject: Some(&identity_id),
                        action: Some("write-all"),
                        object: Some("repository"),
                        scope: None,
                        environment: Some("ci"),
                        tenant: None,
                        attributes: json!({}),
                    },
                    &refs(&evidence_ref),
                ));
            }
            if pull_request_target_re().is_match(text) {
                out.initial_facts.push(fact(
                    "attacker-position",
                    FactFields {
                        subject: Some("actor:external"),
                        action: Some("control-pr-content"),
                        object: Some(file),
                        scope: None,
                        environment: Some("ci"),
                        tenant: None,
                        attributes: json!({}),
                    },
                    &refs(&evidence_ref),
                ));
            }

            out.evidence.push(json!({
                "id": evidence_ref, "kind": "source-location", "file": file, "description": "CI/CD workflow",
            }));
        }

        out
    }
}

// =================================================================================================
// model-extractors/automation.mjs
// =================================================================================================

pub mod automation {
    use super::*;
    use std::collections::HashMap;

    // ---- file classification -------------------------------------------------------------

    fn workflow_file_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(
                r"(?i)(^|/)\.github/workflows/[^/]+\.ya?ml$|(^|/)\.gitlab-ci\.ya?ml$|(^|/)azure-pipelines\.ya?ml$|(^|/)\.circleci/config\.ya?ml$|(^|/)bitbucket-pipelines\.ya?ml$",
            )
            .unwrap()
        })
    }
    fn jenkinsfile_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(^|/)Jenkinsfile$").unwrap())
    }
    fn package_manifest_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(^|/)package\.json$").unwrap())
    }
    fn release_config_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)(^|/)\.releaserc(\.[a-zA-Z0-9]+)?$|(^|/)release\.config\.[cm]?js$|(^|/)\.goreleaser\.ya?ml$")
                .unwrap()
        })
    }
    fn dependency_update_config_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(
                r"(?i)(^|/)renovate\.json5?$|(^|/)\.github/renovate\.json5?$|(^|/)\.github/dependabot\.ya?ml$|(^|/)\.dependabot/config\.ya?ml$",
            )
            .unwrap()
        })
    }
    fn updater_config_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)electron-builder\.(ya?ml|json5?|toml)$|(^|/)app-update\.ya?ml$").unwrap())
    }
    fn npm_config_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(^|/)\.npmrc$").unwrap())
    }
    fn lockfile_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$").unwrap())
    }
    fn dockerfile_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(^|/)Dockerfile(\.[A-Za-z0-9._-]+)?$").unwrap())
    }

    // ---- text-pattern detectors -----------------------------------------------------------

    fn hostile_trigger_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bpull_request_target\b|\bworkflow_run\b|\bissue_comment\b").unwrap())
    }

    fn looks_like_hostile_trigger(text: &str) -> bool {
        hostile_trigger_re().is_match(text)
    }

    fn release_push_tags_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?s)\bpush\s*:\s*.{0,80}?\btags\s*:").unwrap())
    }
    fn release_types_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?s)\brelease\s*:\s*.{0,80}?\btypes\s*:").unwrap())
    }
    fn workflow_dispatch_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bworkflow_dispatch\b").unwrap())
    }

    fn looks_like_release_trigger(text: &str) -> bool {
        release_push_tags_re().is_match(text) || release_types_re().is_match(text) || workflow_dispatch_re().is_match(text)
    }

    fn release_step_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(
                r"\bnpm publish\b|\bdocker push\b|docker/build-push-action|\bgoreleaser\b|\bsemantic-release\b|electron-builder\s+--publish|\bgh release create\b|actions/create-release|upload-artifact",
            )
            .unwrap()
        })
    }
    fn looks_like_release_step(text: &str) -> bool {
        release_step_re().is_match(text)
    }

    fn signing_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(
                r"(?i)\bcodesign\b|\bnotarize\b|\bCSC_LINK\b|\bWIN_CSC_LINK\b|\bAPPLE_ID\b|\bcosign\b|\bsigstore\b|gpg\s+--sign|--provenance\b|npm_config_provenance",
            )
            .unwrap()
        })
    }
    fn looks_like_signing(text: &str) -> bool {
        signing_re().is_match(text)
    }

    fn disabled_signing_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"\bsign\s*:\s*false\b|\bskipSign\s*:\s*true\b|verifyUpdateCodeSignature\s*:\s*false").unwrap()
        })
    }
    fn explicitly_disabled_signing(text: &str) -> bool {
        disabled_signing_re().is_match(text)
    }

    fn permissions_key_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bpermissions\s*:").unwrap())
    }
    fn write_all_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"write-all").unwrap())
    }
    fn read_all_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"read-all").unwrap())
    }
    fn scope_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\b([a-z][a-z0-9-]*)\s*:\s*(write|read|none)\b").unwrap())
    }

    /// Mirrors `detectPermissionScopes`. UTF-16-code-unit windowing to match `text.slice`.
    /// `None` = no `permissions:` key anywhere; `Some(vec![])` = explicit deny; otherwise
    /// the resolved `{scope, level}` pairs.
    fn detect_permission_scopes(text: &str) -> Option<Vec<(String, String)>> {
        let units: Vec<u16> = text.encode_utf16().collect();
        let m = permissions_key_re().find(text)?;
        // `text.search` returns a UTF-16 code-unit index; the match's byte start is on a
        // char boundary (regex is ASCII-only here), so counting UTF-16 units of the prefix
        // up to it gives the exact JS `search` offset. Window by UTF-16 units from there for
        // parity with the 400-unit slice.
        let start_units = text[..m.start()].encode_utf16().count();
        let end_units = (start_units + 400).min(units.len());
        let window = String::from_utf16_lossy(&units[start_units..end_units]);
        if write_all_re().is_match(&window) {
            return Some(vec![("all".to_string(), "write".to_string())]);
        }
        if read_all_re().is_match(&window) {
            return Some(vec![("all".to_string(), "read".to_string())]);
        }
        let mut scopes = Vec::new();
        for cap in scope_re().captures_iter(&window) {
            let scope = cap[1].to_lowercase();
            if scope != "permissions" {
                scopes.push((scope, cap[2].to_lowercase()));
            }
        }
        Some(scopes)
    }

    fn permission_scope_label(scopes: &Option<Vec<(String, String)>>) -> String {
        match scopes {
            None => "unknown".to_string(),
            Some(s) if s.is_empty() => "none".to_string(),
            Some(s) => {
                let set: BTreeSet<String> = s.iter().map(|(scope, level)| format!("{scope}:{level}")).collect();
                set.into_iter().collect::<Vec<_>>().join(",")
            }
        }
    }

    fn secrets_ref_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bsecrets\.([A-Za-z0-9_]+)").unwrap())
    }
    fn env_secret_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"\$\{?([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIALS))\}?").unwrap()
        })
    }
    fn credentials_call_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r#"credentials\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap())
    }

    /// Mirrors `detectSecretRefs`.
    fn detect_secret_refs(text: &str) -> Vec<String> {
        let mut names: BTreeSet<String> = BTreeSet::new();
        for cap in secrets_ref_re().captures_iter(text) {
            names.insert(cap[1].to_string());
        }
        for cap in env_secret_re().captures_iter(text) {
            names.insert(cap[1].to_string());
        }
        for cap in credentials_call_re().captures_iter(text) {
            names.insert(cap[1].to_string());
        }
        names.into_iter().collect()
    }

    fn npmjs_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"registry\.npmjs\.org").unwrap())
    }
    fn ghcr_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"ghcr\.io").unwrap())
    }
    fn docker_hub_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bdocker\.io\b|hub\.docker\.com").unwrap())
    }
    fn npmrc_registry_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?m)^\s*registry\s*=\s*(\S+)").unwrap())
    }
    fn provider_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r#"\bprovider\s*:\s*["']?([a-zA-Z0-9_-]+)["']?"#).unwrap())
    }
    fn npm_publish_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bnpm publish\b").unwrap())
    }
    fn docker_push_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bdocker push\b|docker/build-push-action").unwrap())
    }

    /// Mirrors `detectPublicationTarget`.
    fn detect_publication_target(text: &str) -> Option<String> {
        if npmjs_re().is_match(text) {
            return Some("npm-registry".to_string());
        }
        if ghcr_re().is_match(text) {
            return Some("container-registry".to_string());
        }
        if docker_hub_re().is_match(text) {
            return Some("container-registry".to_string());
        }
        if let Some(cap) = npmrc_registry_re().captures(text) {
            return Some(cap[1].to_string());
        }
        if let Some(cap) = provider_re().captures(text) {
            return Some(format!("updater:{}", &cap[1]));
        }
        if npm_publish_re().is_match(text) {
            return Some("npm-registry".to_string());
        }
        if docker_push_re().is_match(text) {
            return Some("container-registry".to_string());
        }
        None
    }

    fn cache_action_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"actions/cache\b").unwrap())
    }
    fn cache_dep_path_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bcache-dependency-path\b").unwrap())
    }
    fn cache_key_line_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?m)^\s*cache:\s*$").unwrap())
    }
    fn install_script_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?s)\b(curl|wget)\b.*?\|\s*(sh|bash)\b").unwrap())
    }
    fn upload_download_artifact_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"upload-artifact|download-artifact").unwrap())
    }
    fn dockerfile_installer_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\b(curl|wget)\b[^\n]*\|\s*(sh|bash)\b").unwrap())
    }
    fn from_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"\bFROM\b").unwrap())
    }
    fn direct_url_dep_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"^(git\+|https?:|github:)").unwrap())
    }
    fn automerge_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r#""automerge"\s*:\s*true|\bautomerge\s*:\s*true\b"#).unwrap())
    }
    fn verify_sig_false_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"verifyUpdateCodeSignature\s*:\s*false").unwrap())
    }
    fn verify_sig_true_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"verifyUpdateCodeSignature\s*:\s*true").unwrap())
    }
    fn auth_token_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"_authToken\s*=").unwrap())
    }

    // ---- extraction context ---------------------------------------------------------------

    struct Ctx {
        entities: HashMap<String, Value>,
        relations: HashMap<String, Value>,
        evidence: HashMap<String, Value>,
        facts: HashMap<String, Value>,
        coverage_gaps: Vec<Value>,
    }

    impl Ctx {
        fn new() -> Self {
            Ctx {
                entities: HashMap::new(),
                relations: HashMap::new(),
                evidence: HashMap::new(),
                facts: HashMap::new(),
                coverage_gaps: Vec::new(),
            }
        }
        fn add_entity(&mut self, item: Value) -> Value {
            let id = item["id"].as_str().unwrap().to_string();
            self.entities.insert(id, item.clone());
            item
        }
        fn add_relation(&mut self, item: Value) -> Value {
            let id = item["id"].as_str().unwrap().to_string();
            self.relations.insert(id, item.clone());
            item
        }
        fn add_fact(&mut self, item: Value) -> Value {
            let id = item["id"].as_str().unwrap().to_string();
            self.facts.insert(id, item.clone());
            item
        }
        fn add_evidence(&mut self, file: &str, description: &str) -> String {
            let id = stable_id("automation-evidence", &json!({ "file": file, "description": description }));
            self.evidence.entry(id.clone()).or_insert_with(|| {
                json!({ "id": id, "kind": "source-location", "file": file, "description": description })
            });
            id
        }
        fn add_gap(&mut self, gap: Value) {
            self.coverage_gaps.push(gap);
        }
        fn finalize(self) -> ExtractorOutput {
            let mut entities: Vec<Value> = self.entities.into_values().collect();
            entities.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
            let mut relations: Vec<Value> = self.relations.into_values().collect();
            relations.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
            let mut evidence: Vec<Value> = self.evidence.into_values().collect();
            evidence.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
            let mut initial_facts: Vec<Value> = self.facts.into_values().collect();
            initial_facts.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
            ExtractorOutput {
                entities,
                relations,
                evidence,
                initial_facts,
                coverage_gaps: self.coverage_gaps,
            }
        }
    }

    fn refs(id: &str) -> Vec<String> {
        vec![id.to_string()]
    }

    #[allow(clippy::too_many_arguments)]
    struct ReleaseChainInput<'a> {
        file: &'a str,
        evidence_ref: &'a str,
        sink_id: &'a str,
        trigger_label: String,
        trigger_type: &'a str,
        scopes: Option<Vec<(String, String)>>,
        credential_refs: Vec<String>,
        publication_target: Option<String>,
        artifact_label: String,
    }

    /// Mirrors `buildReleaseChain`.
    fn build_release_chain(ctx: &mut Ctx, input: ReleaseChainInput<'_>) {
        let ev = refs(input.evidence_ref);
        let trigger = ctx.add_entity(entity(
            "entrypoint",
            &input.trigger_label,
            json!({ "entrypointType": input.trigger_type, "environment": "ci" }),
            &ev,
            EntityOptions::default(),
        ));
        let principal = ctx.add_entity(entity(
            "principal",
            &format!("automation service principal {}", input.file),
            json!({ "environment": "ci" }),
            &ev,
            EntityOptions::default(),
        ));
        let permission_scope = permission_scope_label(&input.scopes);
        let credentials_set: BTreeSet<String> = input.credential_refs.into_iter().collect();
        let sorted_credentials: Vec<String> = credentials_set.into_iter().collect();
        let identity = ctx.add_entity(entity(
            "identity",
            &format!("release identity {}", input.file),
            json!({
                "environment": "ci",
                "permissionScope": permission_scope,
                "credentialRefs": sorted_credentials,
            }),
            &ev,
            EntityOptions::default(),
        ));
        let capability = ctx.add_entity(entity(
            "tool-capability",
            &format!("publish capability {}", input.file),
            json!({ "capabilityKind": "package-publish" }),
            &ev,
            EntityOptions::default(),
        ));
        let artifact = ctx.add_entity(entity(
            "asset",
            &input.artifact_label,
            json!({
                "assetKind": "published-artifact",
                "publicationTarget": input.publication_target.clone().unwrap_or_else(|| "unknown".to_string()),
            }),
            &ev,
            EntityOptions::default(),
        ));

        let trigger_id = trigger["id"].as_str().unwrap().to_string();
        let principal_id = principal["id"].as_str().unwrap().to_string();
        let identity_id = identity["id"].as_str().unwrap().to_string();
        let capability_id = capability["id"].as_str().unwrap().to_string();
        let artifact_id = artifact["id"].as_str().unwrap().to_string();

        ctx.add_relation(relation("executes", &trigger_id, input.sink_id, &ev, json!({}), EntityOptions::default()));
        ctx.add_relation(relation(
            "assumes-role",
            &principal_id,
            &identity_id,
            &ev,
            json!({}),
            EntityOptions::default(),
        ));
        ctx.add_relation(relation("runs-as", input.sink_id, &identity_id, &ev, json!({}), EntityOptions::default()));
        ctx.add_relation(relation("grants", &identity_id, &capability_id, &ev, json!({}), EntityOptions::default()));
        ctx.add_relation(relation(
            "publishes-to",
            &identity_id,
            &artifact_id,
            &ev,
            json!({}),
            EntityOptions::default(),
        ));

        if permission_scope == "unknown" {
            ctx.add_gap(json!({ "kind": "unresolved-permission-scope", "file": input.file }));
        }
        let creds_empty = identity["attributes"]["credentialRefs"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true);
        if creds_empty {
            ctx.add_gap(json!({ "kind": "unresolved-identity", "file": input.file, "entityId": identity_id }));
        }
        if input.publication_target.is_none() {
            ctx.add_gap(json!({ "kind": "unresolved-publication-target", "file": input.file }));
        }
    }

    fn scan_pipeline_config(ctx: &mut Ctx, file: &str, text: &str) {
        let ev = ctx.add_evidence(file, "Automation pipeline configuration");
        let step = ctx.add_entity(entity(
            "sink",
            &format!("pipeline step {file}"),
            json!({ "sinkKind": "automation-step" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let step_id = step["id"].as_str().unwrap().to_string();

        if looks_like_hostile_trigger(text) {
            let hostile_trigger = ctx.add_entity(entity(
                "entrypoint",
                &format!("untrusted-content trigger {file}"),
                json!({ "entrypointType": "hostile-trigger", "environment": "ci" }),
                &refs(&ev),
                EntityOptions::default(),
            ));
            let boundary = ctx.add_entity(entity(
                "trust-boundary",
                &format!("fork/external-content boundary {file}"),
                json!({ "boundaryType": "untrusted-contribution" }),
                &refs(&ev),
                EntityOptions::default(),
            ));
            let hostile_trigger_id = hostile_trigger["id"].as_str().unwrap().to_string();
            let boundary_id = boundary["id"].as_str().unwrap().to_string();
            ctx.add_relation(relation(
                "executes",
                &hostile_trigger_id,
                &step_id,
                &refs(&ev),
                json!({}),
                EntityOptions::default(),
            ));
            ctx.add_relation(relation(
                "crosses",
                &hostile_trigger_id,
                &boundary_id,
                &refs(&ev),
                json!({}),
                EntityOptions::default(),
            ));
            ctx.add_fact(fact(
                "attacker-position",
                FactFields {
                    subject: Some("actor:external-contributor"),
                    action: Some("control-repository-content"),
                    object: Some(file),
                    scope: None,
                    environment: Some("ci"),
                    tenant: None,
                    attributes: json!({}),
                },
                &refs(&ev),
            ));
        }

        if looks_like_release_trigger(text) && looks_like_release_step(text) {
            build_release_chain(
                ctx,
                ReleaseChainInput {
                    file,
                    evidence_ref: &ev,
                    sink_id: &step_id,
                    trigger_label: format!("release trigger {file}"),
                    trigger_type: "release-trigger",
                    scopes: detect_permission_scopes(text),
                    credential_refs: detect_secret_refs(text),
                    publication_target: detect_publication_target(text),
                    artifact_label: format!("published artifact {file}"),
                },
            );
        }

        if cache_action_re().is_match(text) || cache_dep_path_re().is_match(text) || cache_key_line_re().is_match(text) {
            let cache = ctx.add_entity(entity(
                "data-store",
                &format!("build cache {file}"),
                json!({ "dataStoreKind": "build-cache" }),
                &refs(&ev),
                EntityOptions::default(),
            ));
            let cache_id = cache["id"].as_str().unwrap().to_string();
            ctx.add_relation(relation("stores", &step_id, &cache_id, &refs(&ev), json!({}), EntityOptions::default()));
        }

        for name in detect_secret_refs(text) {
            ctx.add_fact(fact(
                "credential-possession",
                FactFields {
                    subject: Some(&step_id),
                    action: Some("reference-secret"),
                    object: Some(&name),
                    scope: None,
                    environment: Some("ci"),
                    tenant: None,
                    attributes: json!({}),
                },
                &refs(&ev),
            ));
        }

        if looks_like_signing(text) {
            let control_state = if explicitly_disabled_signing(text) { "absent" } else { "present-unenforced" };
            let signing = ctx.add_entity(entity(
                "control",
                &format!("release signing {file}"),
                json!({ "controlType": "signing", "controlState": control_state }),
                &refs(&ev),
                EntityOptions::default(),
            ));
            let signing_id = signing["id"].as_str().unwrap().to_string();
            ctx.add_relation(relation("protects", &signing_id, &step_id, &refs(&ev), json!({}), EntityOptions::default()));
        }

        if upload_download_artifact_re().is_match(text) {
            let build_output = ctx.add_entity(entity(
                "asset",
                &format!("build output {file}"),
                json!({ "assetKind": "build-artifact" }),
                &refs(&ev),
                EntityOptions::default(),
            ));
            let build_output_id = build_output["id"].as_str().unwrap().to_string();
            ctx.add_relation(relation(
                "flows-to",
                &build_output_id,
                &step_id,
                &refs(&ev),
                json!({}),
                EntityOptions::default(),
            ));
        }
    }

    fn scan_jenkinsfile(ctx: &mut Ctx, file: &str, text: &str) {
        let ev = ctx.add_evidence(file, "Jenkins pipeline (unparsed DSL)");
        ctx.add_entity(entity(
            "repository-artifact",
            &format!("Jenkins pipeline {file}"),
            json!({ "automationFormat": "jenkinsfile" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        for name in detect_secret_refs(text) {
            ctx.add_fact(fact(
                "credential-possession",
                FactFields {
                    subject: Some("identity:jenkins-pipeline"),
                    action: Some("reference-credential"),
                    object: Some(&name),
                    scope: None,
                    environment: Some("ci"),
                    tenant: None,
                    attributes: json!({}),
                },
                &refs(&ev),
            ));
        }
        ctx.add_gap(json!({ "kind": "unparsed-automation-format", "file": file, "format": "jenkinsfile" }));
    }

    fn scan_package_manifest(ctx: &mut Ctx, file: &str, text: &str, files: &[String]) {
        let ev = ctx.add_evidence(file, "Package manifest");
        let pkg: Value = match serde_json::from_str(text) {
            Ok(Value::Object(m)) => Value::Object(m),
            _ => {
                ctx.add_gap(json!({ "kind": "unparsed-automation-format", "file": file, "format": "package.json" }));
                return;
            }
        };

        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
        let is_private = pkg.get("private") == Some(&Value::Bool(true));
        let manifest_entity = ctx.add_entity(entity(
            "repository-artifact",
            &format!("package manifest {file}"),
            json!({ "manifest": true, "name": name, "private": is_private }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let manifest_id = manifest_entity["id"].as_str().unwrap().to_string();

        let empty_scripts = Map::new();
        let scripts = pkg.get("scripts").and_then(|v| v.as_object()).unwrap_or(&empty_scripts);
        for key in ["preinstall", "install", "postinstall"] {
            if let Some(script) = scripts.get(key).and_then(|v| v.as_str()) {
                if install_script_re().is_match(script) {
                    let source = ctx.add_entity(entity(
                        "source",
                        &format!("remote installer script {file}#{key}"),
                        json!({ "sourceKind": "network-fetch" }),
                        &refs(&ev),
                        EntityOptions::default(),
                    ));
                    let sink = ctx.add_entity(entity(
                        "sink",
                        &format!("installer shell exec {file}#{key}"),
                        json!({ "sinkKind": "shell" }),
                        &refs(&ev),
                        EntityOptions::default(),
                    ));
                    let source_id = source["id"].as_str().unwrap().to_string();
                    let sink_id = sink["id"].as_str().unwrap().to_string();
                    ctx.add_relation(relation(
                        "flows-to",
                        &source_id,
                        &sink_id,
                        &refs(&ev),
                        json!({}),
                        EntityOptions::default(),
                    ));
                    ctx.add_fact(fact(
                        "capability",
                        FactFields {
                            subject: Some(&sink_id),
                            action: Some("execute-remote-script"),
                            object: Some(file),
                            scope: None,
                            environment: Some("install"),
                            tenant: None,
                            attributes: json!({}),
                        },
                        &refs(&ev),
                    ));
                }
            }
        }

        let publish_script = scripts
            .get("publish")
            .and_then(|v| v.as_str())
            .or_else(|| scripts.get("release").and_then(|v| v.as_str()));
        let publish_config = pkg.get("publishConfig").and_then(|v| v.as_object());
        if publish_script.is_some() || publish_config.is_some() {
            let publication_target = publish_config
                .and_then(|pc| pc.get("registry"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| detect_publication_target(text));
            let step = ctx.add_entity(entity(
                "sink",
                &format!("manual publish script {file}"),
                json!({ "sinkKind": "automation-step" }),
                &refs(&ev),
                EntityOptions::default(),
            ));
            let step_id = step["id"].as_str().unwrap().to_string();
            build_release_chain(
                ctx,
                ReleaseChainInput {
                    file,
                    evidence_ref: &ev,
                    sink_id: &step_id,
                    trigger_label: format!("manual publish invocation {file}"),
                    trigger_type: "manual-trigger",
                    scopes: None,
                    credential_refs: Vec::new(),
                    publication_target,
                    artifact_label: format!("published package {name}"),
                },
            );
        }

        for dep_field in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(deps) = pkg.get(dep_field).and_then(|v| v.as_object()) {
                for (dep_name, spec) in deps {
                    if let Some(spec_str) = spec.as_str() {
                        if direct_url_dep_re().is_match(spec_str) {
                            let source = ctx.add_entity(entity(
                                "source",
                                &format!("non-registry dependency {dep_name}"),
                                json!({ "sourceKind": "direct-url-dependency", "spec": spec_str }),
                                &refs(&ev),
                                EntityOptions::default(),
                            ));
                            let source_id = source["id"].as_str().unwrap().to_string();
                            ctx.add_relation(relation(
                                "flows-to",
                                &source_id,
                                &manifest_id,
                                &refs(&ev),
                                json!({}),
                                EntityOptions::default(),
                            ));
                        }
                    }
                }
            }
        }

        if !files.iter().any(|f| lockfile_re().is_match(f)) {
            ctx.add_gap(json!({ "kind": "missing-dependency-lockfile", "file": file }));
        }
    }

    fn scan_release_config(ctx: &mut Ctx, file: &str, text: &str) {
        let ev = ctx.add_evidence(file, "Release-tool configuration");
        let publication_target = detect_publication_target(text);
        let step = ctx.add_entity(entity(
            "sink",
            &format!("release-config publish step {file}"),
            json!({ "sinkKind": "automation-step" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let step_id = step["id"].as_str().unwrap().to_string();
        build_release_chain(
            ctx,
            ReleaseChainInput {
                file,
                evidence_ref: &ev,
                sink_id: &step_id,
                trigger_label: format!("release-config invocation {file}"),
                trigger_type: "release-config-trigger",
                scopes: None,
                credential_refs: detect_secret_refs(text),
                publication_target: publication_target.clone(),
                artifact_label: format!("published release artifact {file}"),
            },
        );
        if publication_target.is_none() {
            ctx.add_gap(json!({ "kind": "externally-configured-release-service", "file": file }));
        }
    }

    fn scan_dependency_update_config(ctx: &mut Ctx, file: &str, text: &str) {
        let ev = ctx.add_evidence(file, "Dependency update automation configuration");
        let trigger = ctx.add_entity(entity(
            "entrypoint",
            &format!("scheduled dependency update {file}"),
            json!({ "entrypointType": "scheduled-update", "environment": "ci" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let sink = ctx.add_entity(entity(
            "sink",
            &format!("dependency update PR {file}"),
            json!({ "sinkKind": "dependency-update" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let principal = ctx.add_entity(entity(
            "principal",
            &format!("dependency update bot principal {file}"),
            json!({ "environment": "ci" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let identity = ctx.add_entity(entity(
            "identity",
            &format!("dependency update bot identity {file}"),
            json!({ "environment": "ci", "permissionScope": "unknown" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let trigger_id = trigger["id"].as_str().unwrap().to_string();
        let sink_id = sink["id"].as_str().unwrap().to_string();
        let principal_id = principal["id"].as_str().unwrap().to_string();
        let identity_id = identity["id"].as_str().unwrap().to_string();
        ctx.add_relation(relation("executes", &trigger_id, &sink_id, &refs(&ev), json!({}), EntityOptions::default()));
        ctx.add_relation(relation(
            "assumes-role",
            &principal_id,
            &identity_id,
            &refs(&ev),
            json!({}),
            EntityOptions::default(),
        ));
        ctx.add_relation(relation("runs-as", &sink_id, &identity_id, &refs(&ev), json!({}), EntityOptions::default()));
        ctx.add_gap(json!({ "kind": "unresolved-permission-scope", "file": file }));

        if automerge_re().is_match(text) {
            ctx.add_fact(fact(
                "capability",
                FactFields {
                    subject: Some(&identity_id),
                    action: Some("auto-merge-dependency-update"),
                    object: Some("repository"),
                    scope: None,
                    environment: Some("ci"),
                    tenant: None,
                    attributes: json!({}),
                },
                &refs(&ev),
            ));
        }
    }

    fn scan_updater_config(ctx: &mut Ctx, file: &str, text: &str) {
        let ev = ctx.add_evidence(file, "Application auto-update configuration");
        let publication_target = detect_publication_target(text);
        let update_server = ctx.add_entity(entity(
            "service",
            &format!("update server {file}"),
            json!({
                "serviceKind": "auto-update-endpoint",
                "endpoint": publication_target.clone().unwrap_or_else(|| "unknown".to_string()),
            }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let capability = ctx.add_entity(entity(
            "tool-capability",
            &format!("apply downloaded update {file}"),
            json!({ "capabilityKind": "auto-update-execute" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let identity = ctx.add_entity(entity(
            "identity",
            &format!("installed application identity {file}"),
            json!({ "environment": "end-user-device" }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let update_server_id = update_server["id"].as_str().unwrap().to_string();
        let capability_id = capability["id"].as_str().unwrap().to_string();
        let identity_id = identity["id"].as_str().unwrap().to_string();
        ctx.add_relation(relation(
            "grants",
            &identity_id,
            &capability_id,
            &refs(&ev),
            json!({}),
            EntityOptions::default(),
        ));
        ctx.add_relation(relation(
            "retrieves-from",
            &capability_id,
            &update_server_id,
            &refs(&ev),
            json!({}),
            EntityOptions::default(),
        ));

        let signature_state = if verify_sig_false_re().is_match(text) {
            "absent"
        } else if verify_sig_true_re().is_match(text) {
            "enforced"
        } else if looks_like_signing(text) {
            "present-unenforced"
        } else {
            "unknown"
        };

        let signing = ctx.add_entity(entity(
            "control",
            &format!("update signature verification {file}"),
            json!({ "controlType": "signing", "controlState": signature_state }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let signing_id = signing["id"].as_str().unwrap().to_string();
        ctx.add_relation(relation(
            "protects",
            &signing_id,
            &capability_id,
            &refs(&ev),
            json!({}),
            EntityOptions::default(),
        ));

        if signature_state == "unknown" {
            ctx.add_gap(json!({ "kind": "unresolved-updater-signature-state", "file": file }));
        }
        if publication_target.is_none() {
            ctx.add_gap(json!({ "kind": "unresolved-publication-target", "file": file }));
        }
    }

    fn scan_npmrc(ctx: &mut Ctx, file: &str, text: &str) {
        let ev = ctx.add_evidence(file, "npm registry configuration");
        let registry = npmrc_registry_re().captures(text).map(|c| c[1].to_string());
        let has_auth_token = auth_token_re().is_match(text);
        let scope = ctx.add_entity(entity(
            "permission-scope",
            &format!("npm registry auth scope {file}"),
            json!({
                "registry": registry.clone().unwrap_or_else(|| "unknown".to_string()),
                "hasAuthToken": has_auth_token,
            }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let scope_id = scope["id"].as_str().unwrap().to_string();
        if has_auth_token {
            ctx.add_fact(fact(
                "credential-possession",
                FactFields {
                    subject: Some(&scope_id),
                    action: Some("possess-registry-auth-token"),
                    object: Some(file),
                    scope: None,
                    environment: Some("ci"),
                    tenant: None,
                    attributes: json!({}),
                },
                &refs(&ev),
            ));
        }
        if registry.is_none() {
            ctx.add_gap(json!({ "kind": "unresolved-publication-target", "file": file }));
        }
    }

    fn scan_lockfile(ctx: &mut Ctx, file: &str) {
        let ev = ctx.add_evidence(file, "Dependency lockfile");
        let lock = ctx.add_entity(entity(
            "repository-artifact",
            &format!("dependency lockfile {file}"),
            json!({ "lockfile": true }),
            &refs(&ev),
            EntityOptions::default(),
        ));
        let lock_id = lock["id"].as_str().unwrap().to_string();
        ctx.add_fact(fact(
            "capability",
            FactFields {
                subject: Some(&lock_id),
                action: Some("pin-dependency-resolution"),
                object: Some(file),
                scope: None,
                environment: Some("build"),
                tenant: None,
                attributes: json!({}),
            },
            &refs(&ev),
        ));
    }

    fn scan_dockerfile(ctx: &mut Ctx, file: &str, text: &str) {
        let ev = ctx.add_evidence(file, "Container build configuration");
        if dockerfile_installer_re().is_match(text) {
            let source = ctx.add_entity(entity(
                "source",
                &format!("remote installer script {file}"),
                json!({ "sourceKind": "network-fetch" }),
                &refs(&ev),
                EntityOptions::default(),
            ));
            let sink = ctx.add_entity(entity(
                "sink",
                &format!("container build shell exec {file}"),
                json!({ "sinkKind": "shell" }),
                &refs(&ev),
                EntityOptions::default(),
            ));
            let source_id = source["id"].as_str().unwrap().to_string();
            let sink_id = sink["id"].as_str().unwrap().to_string();
            ctx.add_relation(relation(
                "flows-to",
                &source_id,
                &sink_id,
                &refs(&ev),
                json!({}),
                EntityOptions::default(),
            ));
            ctx.add_fact(fact(
                "capability",
                FactFields {
                    subject: Some(&sink_id),
                    action: Some("execute-remote-script"),
                    object: Some(file),
                    scope: None,
                    environment: Some("build"),
                    tenant: None,
                    attributes: json!({}),
                },
                &refs(&ev),
            ));
        }
        let publication_target = detect_publication_target(text);
        if from_re().is_match(text) {
            if let Some(publication_target) = publication_target {
                let image = ctx.add_entity(entity(
                    "asset",
                    &format!("container image {file}"),
                    json!({ "assetKind": "container-image", "publicationTarget": publication_target.clone() }),
                    &refs(&ev),
                    EntityOptions::default(),
                ));
                let registry = ctx.add_entity(entity(
                    "service",
                    &format!("container registry {publication_target}"),
                    json!({ "serviceKind": "container-registry" }),
                    &refs(&ev),
                    EntityOptions::default(),
                ));
                let image_id = image["id"].as_str().unwrap().to_string();
                let registry_id = registry["id"].as_str().unwrap().to_string();
                ctx.add_relation(relation(
                    "publishes-to",
                    &image_id,
                    &registry_id,
                    &refs(&ev),
                    json!({}),
                    EntityOptions::default(),
                ));
            }
        }
    }

    /// Mirrors `extractAutomation({ root, plan, projection, files, lensRegistry })`.
    /// `source_text` stands in for `projection.sourceText`.
    pub fn extract(files: &[String], source_text: &HashMap<String, String>) -> ExtractorOutput {
        let mut ctx = Ctx::new();

        for file in files {
            let text = match source_text.get(file) {
                Some(t) if !t.is_empty() => t.as_str(),
                _ => continue,
            };

            if workflow_file_re().is_match(file) {
                scan_pipeline_config(&mut ctx, file, text);
            } else if jenkinsfile_re().is_match(file) {
                scan_jenkinsfile(&mut ctx, file, text);
            } else if package_manifest_re().is_match(file) {
                scan_package_manifest(&mut ctx, file, text, files);
            } else if release_config_re().is_match(file) {
                scan_release_config(&mut ctx, file, text);
            } else if dependency_update_config_re().is_match(file) {
                scan_dependency_update_config(&mut ctx, file, text);
            } else if updater_config_re().is_match(file) {
                scan_updater_config(&mut ctx, file, text);
            } else if npm_config_re().is_match(file) {
                scan_npmrc(&mut ctx, file, text);
            } else if lockfile_re().is_match(file) {
                scan_lockfile(&mut ctx, file);
            } else if dockerfile_re().is_match(file) {
                scan_dockerfile(&mut ctx, file, text);
            }
        }

        ctx.finalize()
    }
}

// =================================================================================================
// model-builder.mjs (generic assembly algorithm; extractor-list wiring is an integration step
// outside this chunk's owned paths — see module doc comment)
// =================================================================================================

fn dedupe(items: Vec<Value>) -> Vec<Value> {
    let mut by_id: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for item in items {
        let id = item["id"].as_str().unwrap_or_default().to_string();
        by_id.insert(id, item);
    }
    let mut out: Vec<Value> = by_id.into_values().collect();
    out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    out
}

/// Mirrors `assertReferences(entities, relations)`.
pub fn assert_references(entities: &[Value], relations: &[Value]) -> Result<(), String> {
    let ids: BTreeSet<&str> = entities.iter().filter_map(|e| e["id"].as_str()).collect();
    for relation in relations {
        let from = relation["from"].as_str().unwrap_or_default();
        let to = relation["to"].as_str().unwrap_or_default();
        if !ids.contains(from) {
            return Err(format!("unknown relation.from {from}"));
        }
        if !ids.contains(to) {
            return Err(format!("unknown relation.to {to}"));
        }
    }
    Ok(())
}

pub struct BuildSecurityModelInput {
    pub binding: Value,
    pub denominator_digest: String,
    pub expected_files: Option<u64>,
    pub examined_files: u64,
    pub parts: Vec<ExtractorOutput>,
}

/// Mirrors `buildSecurityModel`'s assembly step (dedupe → `assertReferences` → coverage →
/// final model), generically over the extractor outputs supplied by the caller rather than
/// a fixed `EXTRACTORS` list — see the module doc comment for why.
pub fn build_security_model(input: BuildSecurityModelInput) -> Result<Value, String> {
    let entities = dedupe(input.parts.iter().flat_map(|p| p.entities.clone()).collect());
    let relations = dedupe(input.parts.iter().flat_map(|p| p.relations.clone()).collect());
    let evidence = dedupe(input.parts.iter().flat_map(|p| p.evidence.clone()).collect());
    let initial_facts = dedupe(input.parts.iter().flat_map(|p| p.initial_facts.clone()).collect());
    let coverage_gaps: Vec<Value> = input.parts.iter().flat_map(|p| p.coverage_gaps.clone()).collect();

    assert_references(&entities, &relations)?;

    let model_digest = digest(&json!({
        "entities": entities, "relations": relations, "initialFacts": initial_facts,
    }));

    Ok(json!({
        "schemaVersion": 1,
        "kind": "security-surface-model",
        "provider": "security.surface-model",
        "providerVersion": "1",
        "binding": input.binding,
        "denominatorDigest": input.denominator_digest,
        "complete": coverage_gaps.is_empty(),
        "entities": entities,
        "relations": relations,
        "initialFacts": initial_facts,
        "evidence": evidence,
        "coverage": {
            "expectedFiles": input.expected_files,
            "examinedFiles": input.examined_files,
            "entityCount": entities.len(),
            "relationCount": relations.len(),
            "evidenceCount": evidence.len(),
            "modelDigest": model_digest,
        },
        "coverageGaps": coverage_gaps,
    }))
}
