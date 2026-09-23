//! Shared context/observation types for the five
//! `src/providers/security/packs/*.mjs` lexical detectors ported under this
//! module (chunk wf060): `high-consequence.mjs`, `http-protocol-cache.mjs`,
//! `ics-ot.mjs`, `injection.mjs`, `insecure-defaults.mjs`.
//!
//! Scope of this port: each pack's `analyze(context)` — the pure lexical
//! detection producing `UNADJUDICATED` candidate observations — is ported
//! faithfully (same regex-shaped triggers, same claim text, same severity
//! hints, same `detectorMetadata` fields, same suppression/downgrade logic).
//! The `variantStrategies` (`rootCause`/`enumerate`) plumbing that the JS
//! packs also export is coverage-report bookkeeping over the same matches
//! `analyze()` already finds; it is not ported here to keep this chunk
//! bounded (mirroring the precedent set by the sibling wf059 chunk's
//! `common.rs`, which documents the same scope decision).
//!
//! JS `context` (`context.model.entities`, `context.readFile`,
//! `context.relationsTo`, `context.projection.auditFacts`, ...) is modeled
//! here as a plain, self-contained [`Context`] carrying an in-memory file
//! map and a flat entity list — no dependency on any other in-repository
//! candidate-engine type, since none is shared across the wf-port chunks
//! (this module is self-contained and does not depend on the sibling
//! `wf059` module, which is not yet wired into the crate).

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

/// Mirrors a `model.entities[]` element the JS packs read: a
/// `repository-artifact` (one per scanned file) or a `control` entity
/// (injection.mjs's downgrade lookup). `attributes` is kept as a free-form
/// JSON object exactly like the JS `attributes` bag.
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
}

/// A relation edge, mirroring what `context.relationsTo(id)` returns
/// (`protects`, `reaches`, `flows-to`, ...).
#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

/// Mirrors `context.projection.auditFacts.runtimeHeaders.headers` from
/// `http-protocol-cache.mjs`: a lowercase-header-name -> raw value map.
#[derive(Debug, Clone, Default)]
pub struct RuntimeHeaders {
    pub headers: HashMap<String, String>,
}

/// Mirrors `context.projection.auditFacts.deployment`.
#[derive(Debug, Clone, Default)]
pub struct Deployment {
    pub https_enforced: Option<bool>,
    pub reverse_proxy: Option<bool>,
}

/// Mirrors one `context.projection.auditFacts.injectionTraces[]` entry from
/// `injection.mjs`.
#[derive(Debug, Clone)]
pub struct InjectionTrace {
    pub file: String,
    pub sink_class: String,
}

/// Mirrors `context.projection.auditFacts` (only the sub-facts the five
/// packs in this chunk actually read).
#[derive(Debug, Clone, Default)]
pub struct AuditFacts {
    pub runtime_headers: Option<RuntimeHeaders>,
    pub deployment: Option<Deployment>,
    pub injection_traces: Vec<InjectionTrace>,
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
    /// Mirrors `context.denominatorDigest` (an opaque pass-through value;
    /// unused by this chunk since `variantStrategies` is not ported).
    pub denominator_digest: String,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a scanned file with its content, and an accompanying
    /// `repository-artifact` entity carrying one evidence ref, mirroring
    /// the fixture setup every JS pack test builds (`context.files` + a
    /// matching `model.entities` artifact with `attributes.path` and a
    /// non-empty `evidenceRefs`).
    pub fn with_file(mut self, path: &str, content: &str) -> Self {
        self.files.push(path.to_string());
        self.contents.insert(path.to_string(), content.to_string());
        self.entities.push(Entity {
            id: format!("artifact:{path}"),
            kind: "repository-artifact".to_string(),
            name: path.to_string(),
            attributes: json!({ "path": path }),
            evidence_refs: vec![format!("ev:{path}")],
        });
        self
    }

    /// Adds a scanned file with no accompanying evidence refs (used to
    /// exercise `http-protocol-cache.mjs`'s per-file
    /// `if (evidenceRefs.length === 0) continue;` guard).
    pub fn with_file_no_evidence(mut self, path: &str, content: &str) -> Self {
        self.files.push(path.to_string());
        self.contents.insert(path.to_string(), content.to_string());
        self.entities.push(Entity {
            id: format!("artifact:{path}"),
            kind: "repository-artifact".to_string(),
            name: path.to_string(),
            attributes: json!({ "path": path }),
            evidence_refs: Vec::new(),
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

    /// Mirrors `repoWideEvidenceRefs(context)`: every distinct
    /// `evidenceRefs` entry across every scanned file's artifact, sorted.
    pub fn repo_wide_evidence_refs(&self) -> Vec<String> {
        let mut refs: Vec<String> = self
            .files
            .iter()
            .filter_map(|f| self.find_artifact(f))
            .flat_map(|a| a.evidence_refs.iter().cloned())
            .collect();
        refs.sort();
        refs.dedup();
        refs
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
/// `makeObservation`/inline builder returns.
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

/// 1-based line number of `index` within `text`, mirroring
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

/// Mirrors `digest(value)` (`stableId('digest', value)`): a content-derived
/// fingerprint. The JS implementation's exact hash algorithm is internal
/// (never asserted on by any pack test), so this uses a plain SHA-256 hex
/// digest of the input's string form, preserving the "same input -> same
/// digest, different input -> different digest" contract every caller
/// relies on.
pub fn digest(value: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref().as_bytes());
    hex::encode(hasher.finalize())
}

/// Mirrors the `capSeverity(base, cap)` helper in `http-protocol-cache.mjs`:
/// clamps `base` down to `cap` when `base` outranks `cap` on the severity
/// scale (`info < low < medium < high < critical`); a `None` cap is a no-op.
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
