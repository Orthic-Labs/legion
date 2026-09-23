//! Port of five security packs (chunk wf062, area `src/providers/security`):
//!
//! - `src/providers/security/packs/pattern-pack.mjs` — the generic
//!   `createPatternPack` factory used by several other packs (none owned by
//!   this chunk) to build a lexical detector from a `{ id, family,
//!   description, rules }` spec. Reproduced here as [`pattern_pack::build`]
//!   / [`pattern_pack::PatternPack::analyze`].
//! - `src/providers/security/packs/repository-footprint.mjs` — sensitive
//!   files committed and the malicious-repository boundary; repository
//!   content is modeled as hostile evidence.
//! - `src/providers/security/packs/request-boundaries.mjs` — request-body
//!   validation gaps, unbounded body size, mass assignment, response header
//!   injection.
//! - `src/providers/security/packs/smart-contract.mjs` — Solidity/Vyper
//!   source-text-only lexical detectors: access control, reentrancy, oracle
//!   trust, upgradeability, signature replay.
//! - `src/providers/security/packs/ssrf-egress.mjs` — request-controlled
//!   outbound destinations, unbounded redirect-following, DNS-rebinding
//!   preconditions.
//!
//! `git grep` over `engine/` for each pack's rule ids, pack id, and the
//! `createPatternPack`/`repositoryFootprint`/`requestBoundaries`/
//! `smartContract`/`ssrfEgress` names found no prior native port (the only
//! unrelated hit was `legion-topology`'s own, differently-scoped `ssrf`
//! substring match in `inspect.rs`), so all five are ported fresh here.
//!
//! This module is self-contained, mirroring the precedent set by wf056,
//! wf058, wf059, and wf060: it defines its own minimal `Entity` / `Relation`
//! / `Context` / `Fact` / `Observation` types rather than reaching into any
//! sibling wf-port chunk's (private, and not guaranteed present) module,
//! since `wf_port` itself is not yet wired into this crate (no
//! `wf_port/mod.rs` exists yet; the integrator adds `pub mod wf_port;` with
//! `pub mod wf062;` inside it, per the chunk assignment).
//!
//! Every port here is pure: no filesystem walk beyond the in-memory
//! `Context`, no model call, no network access, no tool execution — matching
//! each source file's own header comment. Every rule module below emits only
//! `UNADJUDICATED`-style [`Observation`] candidates (severity hints, never
//! final severities), matching the JS packs' own contract.

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

pub mod pattern_pack;
pub mod repository_footprint;
pub mod request_boundaries;
pub mod smart_contract;
pub mod ssrf_egress;

// =================================================================================================
// Shared context / observation types (mirrors the subset of the JS
// `context` object, and the observation object literal, that all five packs
// in this chunk read/produce).
// =================================================================================================

/// Mirrors a `model.entities[]` element: a `repository-artifact` (one per
/// scanned file) or a `control` entity (the downgrade lookups in
/// `request-boundaries.mjs` / `ssrf-egress.mjs`). `attributes` is kept as a
/// free-form JSON object exactly like the JS `attributes` bag.
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

    /// Mirrors the JS test helper `controlEntity(controlType, name, evidenceRefs)`.
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

/// A relation edge, mirroring what `context.relationsTo(id)` returns
/// (only the `protects` kind is read by either pack in this chunk).
#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

/// Mirrors `context.projection.auditFacts.deployment`: presence alone is
/// what `ssrf-egress.mjs`'s `egressEnvironmentEvidence` treats as evidence
/// (`Boolean(deployment)`); its shape is otherwise opaque to this chunk.
#[derive(Debug, Clone, Default)]
pub struct AuditFacts {
    pub deployment: Option<Value>,
    pub egress_allowlist: Option<Value>,
    /// Mirrors `context.projection.auditFacts.sandboxReceipt`, read by
    /// `repository-footprint.mjs`'s `sandboxGate`.
    pub sandbox_receipt: Option<Value>,
}

/// Self-contained stand-in for the JS `context` object passed to every
/// pack's `analyze(context)`.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Scanned file paths, in the order `context.files` iterates them.
    pub files: Vec<String>,
    contents: HashMap<String, String>,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    pub audit_facts: AuditFacts,
    /// Mirrors `context.denominatorDigest` (opaque pass-through; unused
    /// since `variantStrategies` is not ported in this chunk, matching the
    /// scope decision documented in wf060's `common.rs`).
    pub denominator_digest: String,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a scanned file with its content, and an accompanying
    /// `repository-artifact` entity carrying one evidence ref, mirroring
    /// the fixture setup every JS pack test builds via `model-extractors/
    /// common.mjs`'s `entity('repository-artifact', file, { path: file },
    /// [evidenceRef])`.
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

    /// Mirrors `findRelatedControl(context, artifactId, controlTypes)`,
    /// shared by `request-boundaries.mjs` and `ssrf-egress.mjs`: prefer a
    /// `protects` relation into the given artifact whose source is a
    /// matching `control` entity; otherwise fall back to any matching
    /// `control` entity anywhere in the model.
    pub fn find_related_control(&self, artifact_id: Option<&str>, control_types: &[&str]) -> Option<&Entity> {
        if let Some(artifact_id) = artifact_id {
            for rel in self.relations_to(artifact_id) {
                if rel.kind != "protects" {
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
}

/// One precondition / effect entry, mirroring the JS object literal shape.
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

/// A candidate observation, mirroring the object literal every pack's
/// `analyze` pushes.
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

/// 1-based line number of byte-`index` within `text`, mirroring
/// `text.slice(0, index).split('\n').length`.
pub fn line_of(text: &str, index: usize) -> usize {
    text[..index.min(text.len())].matches('\n').count() + 1
}

/// Mirrors `windowAround(text, index, matchLength, radius)`: a byte-index
/// window, clamped to the string bounds and snapped to a char boundary.
pub fn window_around(text: &str, index: usize, match_len: usize, radius: usize) -> &str {
    let start = index.saturating_sub(radius);
    let end = (index + match_len + radius).min(text.len());
    let start = floor_char_boundary(text, start);
    let end = ceil_char_boundary(text, end);
    &text[start..end]
}

fn floor_char_boundary(text: &str, mut idx: usize) -> usize {
    while idx > 0 && !text.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(text: &str, mut idx: usize) -> usize {
    while idx < text.len() && !text.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

/// Mirrors `digest(value)` from `contracts.mjs` (`stableId('digest',
/// value)`): a content-derived fingerprint. The JS implementation's exact
/// hash algorithm is internal (never asserted on by any pack test), so this
/// uses a plain SHA-256 hex digest of the input's string form, preserving
/// the "same input -> same digest, different input -> different digest"
/// contract every caller relies on.
pub fn digest(value: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref().as_bytes());
    hex::encode(hasher.finalize())
}

/// Mirrors the `capSeverity(base, cap)` helper in `ssrf-egress.mjs`: clamps
/// `base` down to `cap` when `base` outranks `cap` on the severity scale
/// (`info < low < medium < high < critical`); a `None` cap is a no-op.
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

    #[test]
    fn find_related_control_prefers_protects_relation_over_global_fallback() {
        let ctx = Context::new()
            .with_file("app.mjs", "x")
            .with_entity(Entity::control("ctrl:1", "egress-allowlist", "global allowlist", vec!["ev:c".into()]))
            .with_entity(Entity::control(
                "ctrl:2",
                "egress-allowlist",
                "scoped allowlist",
                vec!["ev:c2".into()],
            ))
            .with_relation(Relation { kind: "protects".to_string(), from: "ctrl:2".to_string(), to: "artifact:app.mjs".to_string() });
        let found = ctx.find_related_control(Some("artifact:app.mjs"), &["egress-allowlist"]);
        assert_eq!(found.map(|e| e.id.as_str()), Some("ctrl:2"));
    }
}
