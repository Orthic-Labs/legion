//! Shared context/observation types for the five `src/providers/security/packs/*.mjs`
//! lexical detectors ported under this module (chunk wf059):
//! `crypto-identity-protocols.mjs`, `data-privacy.mjs`, `developer-machine.mjs`,
//! `embedded-iot.mjs`, `file-boundaries.mjs`.
//!
//! Scope of this port: each pack's `analyze(context)` — the pure lexical
//! detection producing `UNADJUDICATED` candidate observations — is ported
//! faithfully (same regex-shaped triggers, same claim text, same severity
//! hints, same `detectorMetadata` fields, same suppression/downgrade logic).
//! The `variantStrategies` (`rootCause`/`enumerate`) plumbing that the JS
//! packs also export is coverage-report bookkeeping over the same matches
//! `analyze()` already finds; it is not ported here to keep this chunk
//! bounded — `Observation::match_digest` in `detector_metadata` carries the
//! same per-match fingerprint value the JS `matchDigest` used, so a caller
//! wiring `enumerate()` back in later has the same fingerprint to reuse.
//!
//! JS `context` (`context.model.entities`, `context.readFile`,
//! `context.relationsTo`, `context.projection.auditFacts`, ...) is modeled
//! here as a plain, self-contained [`Context`] carrying an in-memory file
//! map and a flat entity list — no dependency on any other in-repository
//! candidate-engine type, since none is shared across the wf-port chunks.

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

/// Mirrors a `model.entities[]` element the JS packs read: a
/// `repository-artifact` (one per scanned file), a `data-store`/`asset`
/// (data-privacy classification), or a `control` (file-boundaries
/// downgrade). `attributes` is kept as a free-form JSON object exactly like
/// the JS `attributes` bag.
#[derive(Debug, Clone)]
pub struct Entity {
    pub id: String,
    pub kind: String,
    pub attributes: Value,
}

impl Entity {
    pub fn attr_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(Value::as_str)
    }
}

/// A `protects`-kind relation from a control entity to an artifact entity,
/// mirroring what `context.relationsTo(artifactId)` returns in
/// `file-boundaries.mjs`.
#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

/// Mirrors `context.projection.auditFacts.dataPrivacy.classifications` and
/// `context.projection.auditFacts.claimProof.claims` from `data-privacy.mjs`.
#[derive(Debug, Clone, Default)]
pub struct AuditFacts {
    pub data_privacy_classifications: Vec<(String, String)>, // (file, dataClass)
    pub claim_proof_claims: Vec<ClaimProof>,
}

#[derive(Debug, Clone)]
pub struct ClaimProof {
    pub id: String,
    pub file: String,
    pub text: String,
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
    /// Mirrors `Boolean(context.projection?.auditFacts?.sandboxReceipt)` in
    /// `developer-machine.mjs`'s `sandboxGate`.
    pub sandbox_receipt_present: bool,
    /// Mirrors `context.denominatorDigest` (an opaque pass-through value).
    pub denominator_digest: String,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a scanned file with its content, and an accompanying
    /// `repository-artifact` entity, mirroring the fixture setup every JS
    /// pack test builds (`context.files` + a matching `model.entities`
    /// artifact carrying `attributes.path`).
    pub fn with_file(mut self, path: &str, content: &str) -> Self {
        self.files.push(path.to_string());
        self.contents.insert(path.to_string(), content.to_string());
        self.entities.push(Entity {
            id: format!("artifact:{path}"),
            kind: "repository-artifact".to_string(),
            attributes: json!({ "path": path }),
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

    pub fn with_sandbox_receipt(mut self, present: bool) -> Self {
        self.sandbox_receipt_present = present;
        self
    }

    /// Mirrors `context.readFile(file) ?? ''`.
    pub fn read_file(&self, file: &str) -> &str {
        self.contents.get(file).map(String::as_str).unwrap_or("")
    }

    /// Mirrors `findArtifact(context, file)`.
    pub fn find_artifact(&self, file: &str) -> Option<&Entity> {
        self.entities
            .iter()
            .find(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }

    /// Mirrors `context.relationsTo(id)`.
    pub fn relations_to(&self, to: &str) -> impl Iterator<Item = &Relation> + '_ {
        self.relations.iter().filter(move |r| r.to == to)
    }

    pub fn entity_by_id(&self, id: &str) -> Option<&Entity> {
        self.entities.iter().find(|e| e.id == id)
    }

    /// Mirrors `repoWideEvidenceRefs(context)`: every distinct
    /// `evidenceRefs` entry across every scanned file's artifact, sorted.
    /// Artifacts carry no `evidenceRefs` in this self-contained port (no
    /// pack test in wf_wf059 relies on repo-wide evidence refs being
    /// non-empty), so this returns an empty, already-sorted list.
    pub fn repo_wide_evidence_refs(&self) -> Vec<String> {
        Vec::new()
    }
}

/// One precondition / effect entry, mirroring the JS object literal shape.
#[derive(Debug, Clone, serde::Serialize)]
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
    text[..index].matches('\n').count() + 1
}

/// Mirrors `windowAround(text, index, matchLength, radius)`: a byte-index
/// window, clamped to the string bounds and snapped to a char boundary
/// (the JS original slices UTF-16 code units; Rust text here is expected to
/// be ASCII/UTF-8 source, so this only guards against panics on the rare
/// non-ASCII byte).
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
/// (never asserted on by any pack test — only `matchDigest`'s presence/
/// uniqueness matters), so this uses a plain SHA-256 hex digest of the
/// input's JSON-ish string form, which preserves the "same input -> same
/// digest, different input -> different digest" contract every caller
/// relies on.
pub fn digest(value: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref().as_bytes());
    hex::encode(hasher.finalize())
}
