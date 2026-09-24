//! Port of packet r66 (three files, area `src/providers/security/packs`):
//!
//! - `ai-prompt-injection.mjs` — untrusted prompts, retrieved (RAG/search)
//!   content, durable agent memory, and dynamically constructed tool/function
//!   schemas entering a model invocation without a visible trust label.
//!   Ported as [`ai_prompt_injection`].
//! - `authorization-tenant.mjs` — object write / privileged-function calls
//!   with no visible ownership, tenant, or role control. Ported as
//!   [`authorization_tenant`].
//! - `browser-client.mjs` — CSRF, CORS, cookie SameSite, clickjacking, open
//!   redirect, OAuth redirect-URI, and Content-Security-Policy. Ported as
//!   [`browser_client`].
//!
//! `git grep` over `engine/` for each pack's id/rule ids found no prior
//! native port, so all three are ported fresh here.
//!
//! Following the precedent set by wf056/wf058/wf059/wf060/wf062, this module
//! is self-contained: it defines its own minimal `Entity` / `Relation` /
//! `Context` / `Fact` / `Observation` types rather than depending on any
//! sibling `wf_port` chunk's (private) module.
//!
//! Every port here is pure: no filesystem walk beyond the in-memory
//! `Context`, no model call, no network access, no tool execution — matching
//! each source file's own header comment. Every rule emits only an
//! UNADJUDICATED-style [`Observation`] candidate, matching the JS packs.

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

pub mod ai_prompt_injection;
pub mod authorization_tenant;
pub mod browser_client;

// =================================================================================================
// Shared context / observation types (mirrors the subset of the JS
// `context` object, and the observation object literal, that all three
// packs in this chunk read/produce). Structurally identical to wf062's
// shared types; duplicated here per the "self-contained chunk" precedent
// rather than reaching across `wf_port` chunks.
// =================================================================================================

#[derive(Debug, Clone)]
pub struct Entity {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub attributes: Value,
    pub evidence_refs: Vec<String>,
}

impl Entity {
    pub fn attr_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(Value::as_str)
    }

    pub fn control(id: impl Into<String>, control_type: &str, name: &str, evidence_refs: Vec<String>) -> Self {
        Self {
            id: id.into(),
            kind: "control".to_string(),
            name: name.to_string(),
            attributes: serde_json::json!({ "controlType": control_type }),
            evidence_refs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

/// Mirrors `context.projection.auditFacts`: `runtimeHeaders.headers` (read
/// by `browser-client.mjs`) and `deployment` (read by its deployment gate).
#[derive(Debug, Clone, Default)]
pub struct AuditFacts {
    pub deployment: Option<Value>,
    pub runtime_headers: Option<HashMap<String, Value>>,
}

#[derive(Debug, Clone, Default)]
pub struct Context {
    pub files: Vec<String>,
    contents: HashMap<String, String>,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    pub audit_facts: AuditFacts,
    pub denominator_digest: String,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_file(mut self, path: &str, content: &str) -> Self {
        self.files.push(path.to_string());
        self.contents.insert(path.to_string(), content.to_string());
        self.entities.push(Entity {
            id: format!("artifact:{path}"),
            kind: "repository-artifact".to_string(),
            name: path.to_string(),
            attributes: serde_json::json!({ "path": path }),
            evidence_refs: vec![format!("ev:{path}")],
        });
        self
    }

    pub fn with_entity(mut self, entity: Entity) -> Self {
        self.entities.push(entity);
        self
    }

    pub fn with_relation(mut self, relation: Relation) -> Self {
        self.relations.push(relation);
        self
    }

    pub fn with_audit_facts(mut self, audit_facts: AuditFacts) -> Self {
        self.audit_facts = audit_facts;
        self
    }

    /// Mirrors `context.readFile(file) ?? ''`.
    pub fn read_file(&self, file: &str) -> &str {
        self.contents.get(file).map(String::as_str).unwrap_or("")
    }

    /// Mirrors `findArtifact(context, file)` / `artifactFor(context, file)`.
    pub fn find_artifact(&self, file: &str) -> Option<&Entity> {
        self.entities
            .iter()
            .find(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }

    /// Mirrors `context.relationsTo(id)`.
    pub fn relations_to<'a>(&'a self, to: &'a str) -> impl Iterator<Item = &'a Relation> {
        self.relations.iter().filter(move |r| r.to == to)
    }

    pub fn entity_by_id(&self, id: &str) -> Option<&Entity> {
        self.entities.iter().find(|e| e.id == id)
    }

    /// Mirrors `findControl(context, sinkId, controlTypes)` in
    /// `ai-prompt-injection.mjs`: prefer a `protects`/`validates` relation
    /// into the given sink whose source is a matching `control` entity;
    /// otherwise fall back to any matching `control` entity in the model.
    pub fn find_control(&self, sink_id: Option<&str>, control_types: &[&str]) -> Option<&Entity> {
        if let Some(sink_id) = sink_id {
            for rel in self.relations_to(sink_id) {
                if rel.kind != "protects" && rel.kind != "validates" {
                    continue;
                }
                if let Some(control) = self.entity_by_id(&rel.from) {
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
        self.entities.iter().find(|e| {
            e.kind == "control"
                && e.attr_str("controlType")
                    .map(|t| control_types.contains(&t))
                    .unwrap_or(false)
        })
    }

    /// Mirrors `findUntrustedSource(context, file)`: prefer an
    /// untrusted-content `source` entity scoped to `file`; fall back to any
    /// untrusted-content source in the model.
    pub fn find_untrusted_source(&self, file: &str) -> Option<&Entity> {
        self.entities
            .iter()
            .find(|e| e.kind == "source" && e.attr_str("trust") == Some("untrusted") && e.attr_str("file") == Some(file))
            .or_else(|| self.entities.iter().find(|e| e.kind == "source" && e.attr_str("trust") == Some("untrusted")))
    }

    /// Mirrors `findInvocationProcess(context, file)`.
    pub fn find_invocation_process(&self, file: &str) -> Option<&Entity> {
        self.entities.iter().find(|e| {
            e.kind == "process"
                && e.attr_str("processKind") == Some("model-invocation")
                && e.name == format!("model invocation {file}")
        })
    }

    /// Mirrors `findDataStore(context, storeKind)`.
    pub fn find_data_store(&self, store_kind: &str) -> Option<&Entity> {
        self.entities
            .iter()
            .find(|e| e.kind == "data-store" && e.attr_str("storeKind") == Some(store_kind))
    }

    /// Mirrors `runtimeHeaderCompliance(context, headerKey, isCompliant)`'s
    /// snapshot lookup: `context.projection?.auditFacts?.runtimeHeaders?.headers`.
    pub fn runtime_header(&self, key: &str) -> Option<&Value> {
        self.audit_facts.runtime_headers.as_ref().and_then(|h| h.get(key))
    }

    /// Mirrors `deploymentGate`'s evidence check:
    /// `Boolean(runtimeHeaderSnapshot(context)) || Boolean(context.projection?.auditFacts?.deployment)`.
    pub fn has_deployment_evidence(&self) -> bool {
        self.audit_facts.runtime_headers.is_some() || self.audit_facts.deployment.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Fact {
    pub kind: String,
    pub subject: String,
    pub action: String,
    pub object: Option<String>,
    pub scope: Option<String>,
    pub environment: String,
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Observation {
    pub rule_id: String,
    pub candidate_class: String,
    pub claim: String,
    pub severity_hint: String,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub attacker_capabilities: Vec<String>,
    pub preconditions: Vec<Fact>,
    pub effects: Vec<Fact>,
    pub assets: Vec<String>,
    pub trust_boundary_crossings: Vec<String>,
    pub required_controls: Vec<String>,
    pub observed_controls: Vec<String>,
    pub chain_roles: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub detector_metadata: Value,
    pub uncertainty: Vec<String>,
}

/// 1-based line number of byte-`index` within `text`.
pub fn line_of(text: &str, index: usize) -> usize {
    text[..index.min(text.len())].matches('\n').count() + 1
}

/// Mirrors `digest(value)` from `contracts.mjs`: a content-derived
/// fingerprint. The exact JS hash algorithm is internal (never asserted on
/// by any pack test); this uses a plain SHA-256 hex digest of the input's
/// string form, preserving the "same input -> same digest" contract.
pub fn digest(value: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref().as_bytes());
    hex::encode(hasher.finalize())
}

/// Mirrors `capSeverity(base, cap)` in `browser-client.mjs`.
pub fn cap_severity(base: &str, cap: Option<&str>) -> String {
    fn rank(s: &str) -> i32 {
        match s {
            "info" => 0,
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            "critical" => 4,
            _ => 2,
        }
    }
    match cap {
        None => base.to_string(),
        Some(cap) => {
            if rank(base) <= rank(cap) {
                base.to_string()
            } else {
                cap.to_string()
            }
        }
    }
}

#[cfg(test)]
mod common_tests {
    use super::*;

    #[test]
    fn line_of_counts_newlines_before_index() {
        let text = "a\nb\nc";
        assert_eq!(line_of(text, 0), 1);
        assert_eq!(line_of(text, 2), 2);
        assert_eq!(line_of(text, 4), 3);
    }

    #[test]
    fn cap_severity_clamps_down_only() {
        assert_eq!(cap_severity("high", Some("medium")), "medium");
        assert_eq!(cap_severity("low", Some("medium")), "low");
        assert_eq!(cap_severity("high", None), "high");
    }

    #[test]
    fn digest_is_stable_and_distinguishing() {
        assert_eq!(digest("a"), digest("a"));
        assert_ne!(digest("a"), digest("b"));
    }
}
