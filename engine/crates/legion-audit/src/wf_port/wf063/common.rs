//! Shared context/observation types for the three lexical detector packs
//! ported under this module (chunk wf063):
//! `src/providers/security/packs/supply-chain.mjs`,
//! `src/providers/security/packs/supply-developer.mjs`, and
//! `src/providers/security/packs/uploads.mjs`.
//!
//! Modeled the same way as the sibling `wf060` chunk's `common.rs`: a
//! self-contained, in-memory stand-in for the JS `context` object passed to
//! every pack's `analyze(context)`, with no dependency on any other
//! in-repository candidate-engine type (this module does not depend on the
//! sibling `wf059`/`wf060` modules, which are not yet wired into the crate
//! either).

use serde_json::{json, Value};
use std::collections::HashMap;

/// Mirrors a `model.entities[]` element the JS packs read: a
/// `repository-artifact` (one per scanned file) or a `control` entity
/// (`uploads.mjs`'s downgrade lookup).
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
/// (`uploads.mjs` reads `protects` relations to look up mitigating
/// controls).
#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

/// Mirrors `context.projection.auditFacts` (only the sub-fact
/// `supply-chain.mjs`'s `sandboxGate` reads: `auditFacts.sandboxReceipt`).
#[derive(Debug, Clone, Default)]
pub struct AuditFacts {
    pub sandbox_receipt: bool,
}

/// Self-contained stand-in for the JS `context` object.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Scanned file paths, in the order `context.files` iterates them.
    pub files: Vec<String>,
    contents: HashMap<String, String>,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    pub audit_facts: AuditFacts,
    /// Mirrors `context.denominatorDigest`.
    pub denominator_digest: String,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a scanned file with its content, and an accompanying
    /// `repository-artifact` entity carrying one evidence ref (mirrors the
    /// fixture setup every JS pack test builds).
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

    pub fn with_entity(mut self, entity: Entity) -> Self {
        self.entities.push(entity);
        self
    }

    pub fn with_relation(mut self, relation: Relation) -> Self {
        self.relations.push(relation);
        self
    }

    pub fn with_sandbox_receipt(mut self, present: bool) -> Self {
        self.audit_facts.sandbox_receipt = present;
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
/// `analyze()` pushes onto `observations`.
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

/// Mirrors `digest(value)` (`stableId('digest', value)`) for the string
/// snippets these packs digest. Uses the crate's canonical
/// `wf052::contracts::digest` over a JSON string value so the hashing
/// algorithm matches the one other wf-port security modules already use.
pub fn digest(value: impl AsRef<str>) -> String {
    crate::wf_port::wf052::contracts::digest(&json!(value.as_ref()))
}

/// One `pattern.exec()`-loop match, mirroring the JS `RegExpExecArray`
/// slice this module's rules read (`match[0]`, `match.index`, and — for
/// `uploads.mjs` — capture groups 1/2).
#[derive(Debug, Clone)]
pub struct RawMatch {
    pub index: usize,
    pub whole: String,
    pub groups: Vec<Option<String>>,
}

/// Faithful port of `rawMatches(pattern, text)`: a non-global pattern
/// contributes at most one match (mirrors `pattern.exec` never advancing
/// `lastIndex` when the JS `RegExp` has no `g` flag), a global pattern
/// contributes every non-overlapping match, skipping zero-length matches
/// exactly as the JS `lastIndex += 1` guard does.
pub fn raw_matches(re: &regex::Regex, text: &str, global: bool) -> Vec<RawMatch> {
    if !global {
        // Mirrors the JS non-global branch: a single `pattern.exec(text)`
        // call, returned as-is even if it happens to be zero-length (the
        // zero-length-skip guard only applies to the global exec loop).
        return match re.captures(text) {
            Some(caps) => {
                let whole = caps.get(0).expect("whole match always present");
                let groups = (1..caps.len())
                    .map(|i| caps.get(i).map(|m| m.as_str().to_string()))
                    .collect();
                vec![RawMatch { index: whole.start(), whole: whole.as_str().to_string(), groups }]
            }
            None => vec![],
        };
    }
    let mut out = Vec::new();
    for caps in re.captures_iter(text) {
        let whole = caps.get(0).expect("whole match always present");
        if whole.as_str().is_empty() {
            continue;
        }
        let groups = (1..caps.len())
            .map(|i| caps.get(i).map(|m| m.as_str().to_string()))
            .collect();
        out.push(RawMatch {
            index: whole.start(),
            whole: whole.as_str().to_string(),
            groups,
        });
    }
    out
}
