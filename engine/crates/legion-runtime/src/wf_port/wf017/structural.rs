//! Port of src/lib/remediation/producers/structural.mjs (B7-031).
//!
//! Each producer is bound to specific rule ids and performs one narrow,
//! well-understood rewrite. There is deliberately no generic search-and-replace
//! producer: a transform that cannot name the rule it fixes does not belong
//! here. Producers only PREVIEW - this module performs no filesystem I/O and
//! has no apply path.

use regex::Regex;
use std::sync::LazyLock;

/// One line-level edit produced by a structural preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralEdit {
    /// 1-based line number, matching the JS `line: index + 1` convention.
    pub line: usize,
    pub before: String,
    pub after: String,
}

/// The result of running a structural producer's `preview` over one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralPreview {
    pub path: String,
    pub edits: Vec<StructuralEdit>,
    /// Mirrors the JS `publicSurfaceChanges: []` field; structural producers
    /// never change a public surface.
    pub public_surface_changes: Vec<String>,
}

/// Find every line where `pattern` changes the line when replaced with
/// `replacement` (all matches on the line are replaced, matching a JS global
/// regex `.replace`).
fn edits_for(text: &str, pattern: &Regex, replacement: &str) -> Vec<StructuralEdit> {
    let mut edits = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        let after = pattern.replace_all(line, replacement);
        if after == line {
            continue;
        }
        edits.push(StructuralEdit {
            line: index + 1,
            before: line.to_string(),
            after: after.into_owned(),
        });
    }
    edits
}

/// Apply preview edits to text. Pure and idempotent: an edit whose `before`
/// line no longer matches is skipped rather than re-applied, and every
/// unrelated byte is copied through untouched.
pub fn render_structural_preview(text: &str, edits: &[StructuralEdit]) -> String {
    if edits.is_empty() {
        return text.to_string();
    }
    let mut lines: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
    for edit in edits {
        if edit.line == 0 {
            continue;
        }
        let index = edit.line - 1;
        if let Some(slot) = lines.get_mut(index) {
            if *slot == edit.before {
                *slot = edit.after.clone();
            }
        }
    }
    lines.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerRisk {
    Low,
    Medium,
    High,
}

/// A qualified structural remediation producer, mirroring one frozen object
/// literal from `STRUCTURAL_PRODUCERS` in the JS source.
pub struct StructuralProducer {
    pub id: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub risk: ProducerRisk,
    pub rule_ids: &'static [&'static str],
    pub description: &'static str,
    pub preconditions: &'static [&'static str],
    pub expected_behavior: &'static [&'static str],
    pub affected_families: &'static [&'static str],
    pub validation_plan: &'static [&'static str],
    preview_fn: fn(path: &str, text: &str) -> StructuralPreview,
}

impl StructuralProducer {
    pub fn preview(&self, path: &str, text: &str) -> StructuralPreview {
        (self.preview_fn)(path, text)
    }
}

static REJECT_UNAUTHORIZED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\brejectUnauthorized\s*:\s*false\b").expect("valid regex"));

static INNER_HTML_ASSIGN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.innerHTML(\s*)=").expect("valid regex"));

fn preview_tls_reject_unauthorized(path: &str, text: &str) -> StructuralPreview {
    StructuralPreview {
        path: path.to_string(),
        edits: edits_for(text, &REJECT_UNAUTHORIZED, "rejectUnauthorized: true"),
        public_surface_changes: Vec::new(),
    }
}

fn preview_dom_innerhtml_to_textcontent(path: &str, text: &str) -> StructuralPreview {
    StructuralPreview {
        path: path.to_string(),
        edits: edits_for(text, &INNER_HTML_ASSIGN, ".textContent$1="),
        public_surface_changes: Vec::new(),
    }
}

pub static STRUCTURAL_PRODUCERS: &[StructuralProducer] = &[
    StructuralProducer {
        id: "structural.tls-reject-unauthorized",
        version: "1.0.0",
        kind: "structural",
        risk: ProducerRisk::Low,
        rule_ids: &["insecure-defaults.tls-reject-unauthorized"],
        description: "Restore TLS certificate verification by setting rejectUnauthorized back to true.",
        preconditions: &[
            "the literal `rejectUnauthorized: false` appears in the finding file",
            "the enclosing object is a TLS/HTTPS agent or request option object",
        ],
        expected_behavior: &["TLS peer certificates are verified again"],
        affected_families: &["security"],
        validation_plan: &["parse-check", "affected-provider-rerun:security.insecure-defaults"],
        preview_fn: preview_tls_reject_unauthorized,
    },
    StructuralProducer {
        id: "structural.dom-innerhtml-to-textcontent",
        version: "1.0.0",
        kind: "structural",
        risk: ProducerRisk::Low,
        rule_ids: &["output-handling.dom-innerhtml"],
        description: "Replace an innerHTML sink assignment with textContent so the value is not parsed as markup.",
        preconditions: &[
            "the assignment target is a DOM element",
            "the assigned value is not intentionally-trusted markup",
        ],
        expected_behavior: &["the assigned value renders as text, not markup"],
        affected_families: &["security", "ux"],
        validation_plan: &["parse-check", "affected-provider-rerun:security.output-handling"],
        preview_fn: preview_dom_innerhtml_to_textcontent,
    },
];

pub fn find_producer(id: &str) -> Option<&'static StructuralProducer> {
    STRUCTURAL_PRODUCERS.iter().find(|producer| producer.id == id)
}
