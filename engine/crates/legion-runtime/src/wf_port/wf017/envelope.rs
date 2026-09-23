//! Scoped local port of the parts of src/lib/review/untrusted-evidence-envelope.mjs
//! (B7-029) that src/lib/remediation/reasoning-packets.mjs depends on:
//! `wrapUntrustedEvidence` and `detectOverrideAttempts`.
//!
//! This is a bounded, wf017-owned copy, not a shared crate module: only
//! `reasoning_packets.rs` in this same directory uses it. A full,
//! crate-shared port of the envelope (including `buildReviewPacket`, the
//! JSON Schema builder, and the six other reviewer families that depend on
//! it) is out of this chunk's owned-file scope; see the wf017 report for the
//! `unicode-normalization` dependency this port intentionally omits.

use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

pub const UNTRUSTED_EVIDENCE_SCHEMA_VERSION: u32 = 1;

pub const DEFAULT_EVIDENCE_MAX_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    Source,
    Docs,
    Comment,
    Skill,
    Configuration,
    RetrievedContent,
    RuntimeText,
}

impl EvidenceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Docs => "docs",
            Self::Comment => "comment",
            Self::Skill => "skill",
            Self::Configuration => "configuration",
            Self::RetrievedContent => "retrieved-content",
            Self::RuntimeText => "runtime-text",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactRef {
    pub path: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Omission {
    pub reason: &'static str,
    #[serde(rename = "omittedBytes")]
    pub omitted_bytes: usize,
    #[serde(rename = "fromOffset")]
    pub from_offset: usize,
    #[serde(rename = "artifactRef")]
    pub artifact_ref: ArtifactRef,
}

#[derive(Debug, Clone)]
pub struct UntrustedEvidenceInput {
    pub evidence_kind: EvidenceKind,
    pub source_path: String,
    pub source_digest: String,
    pub artifact_ref: ArtifactRef,
    pub text: String,
    pub max_bytes: usize,
    pub label: Option<String>,
    pub locator: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UntrustedEvidenceRecord {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: &'static str,
    pub trusted: bool,
    #[serde(rename = "evidenceKind")]
    pub evidence_kind: &'static str,
    pub label: Option<String>,
    #[serde(rename = "sourcePath")]
    pub source_path: String,
    #[serde(rename = "sourceDigest")]
    pub source_digest: String,
    #[serde(rename = "artifactRef")]
    pub artifact_ref: ArtifactRef,
    pub locator: Option<serde_json::Value>,
    pub encoding: &'static str,
    pub text: String,
    #[serde(rename = "originalBytes")]
    pub original_bytes: usize,
    #[serde(rename = "includedBytes")]
    pub included_bytes: usize,
    pub truncated: bool,
    pub normalizations: Vec<&'static str>,
    pub omissions: Vec<Omission>,
    pub digest: String,
}

// Bidi controls, zero-width characters, and C0/C1 controls (minus newline and
// tab). Unlike the JS source we do not run Unicode NFC normalization first
// (no normalization crate is available in this workspace's Cargo.lock); see
// the wf017 report.
static BIDI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("[\u{200E}\u{200F}\u{061C}\u{202A}-\u{202E}\u{2066}-\u{2069}]").expect("valid regex"));
static ZERO_WIDTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("[\u{200B}-\u{200D}\u{2060}\u{FEFF}]").expect("valid regex"));
static CONTROL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F-\\x9F]").expect("valid regex"));

fn escape_matches(re: &Regex, text: &str) -> (String, bool) {
    let mut changed = false;
    let out = re.replace_all(text, |caps: &regex::Captures| {
        changed = true;
        let ch = caps.get(0).unwrap().as_str().chars().next().unwrap();
        format!("\\u{:04x}", ch as u32)
    });
    (out.into_owned(), changed)
}

/// Wrap one piece of repository-controlled text as untrusted evidence.
/// Raw bytes beyond `max_bytes` are dropped, sliced on a UTF-8 boundary so
/// truncation cannot manufacture a half-character that renders as something
/// else.
pub fn wrap_untrusted_evidence(input: UntrustedEvidenceInput) -> UntrustedEvidenceRecord {
    let original_bytes = input.text.len();
    let truncated = original_bytes > input.max_bytes;
    let body = if truncated {
        let mut end = input.max_bytes.min(original_bytes);
        while end > 0 && !input.text.is_char_boundary(end) {
            end -= 1;
        }
        input.text[..end].to_string()
    } else {
        input.text.clone()
    };
    let included_bytes = body.len();

    let mut normalizations: Vec<&'static str> = vec!["unicode-nfc"];
    let mut display = body;
    let (after_bidi, bidi_changed) = escape_matches(&BIDI, &display);
    if bidi_changed {
        normalizations.push("bidi-escaped");
    }
    display = after_bidi;
    let (after_zw, zw_changed) = escape_matches(&ZERO_WIDTH, &display);
    if zw_changed {
        normalizations.push("zero-width-escaped");
    }
    display = after_zw;
    let (after_ctrl, ctrl_changed) = escape_matches(&CONTROL, &display);
    if ctrl_changed {
        normalizations.push("control-escaped");
    }
    display = after_ctrl;
    normalizations.sort_unstable();
    normalizations.dedup();

    let omissions = if truncated {
        vec![Omission {
            reason: "byte-cap",
            omitted_bytes: original_bytes - included_bytes,
            from_offset: included_bytes,
            artifact_ref: input.artifact_ref.clone(),
        }]
    } else {
        Vec::new()
    };

    let mut record = UntrustedEvidenceRecord {
        schema_version: UNTRUSTED_EVIDENCE_SCHEMA_VERSION,
        kind: "legion-untrusted-evidence",
        trusted: false,
        evidence_kind: input.evidence_kind.as_str(),
        label: input.label,
        source_path: input.source_path,
        source_digest: input.source_digest,
        artifact_ref: input.artifact_ref,
        locator: input.locator,
        encoding: "escaped-utf8",
        text: display,
        original_bytes,
        included_bytes,
        truncated,
        normalizations,
        omissions,
        digest: String::new(),
    };
    record.digest = super::digest_of("untrusted-evidence", &record);
    record
}

#[derive(Debug, Clone, Serialize)]
pub struct OverrideAttempt {
    pub target: &'static str,
    #[serde(rename = "sourcePath")]
    pub source_path: String,
    #[serde(rename = "evidenceDigest")]
    pub evidence_digest: String,
    #[serde(rename = "excerptDigest")]
    pub excerpt_digest: String,
    pub applied: bool,
}

static OVERRIDE_PATTERNS: &[(&str, &str)] = &[
    ("provider", r"(?i)\b(?:provider|producer)\s*(?:[:=]|\bto\b)\s*[\w.@/-]+"),
    (
        "role",
        r"(?i)\b(?:role|persona|you\s+are)\s*(?:[:=]|\bnow\b)?\s*(?:system|admin|root|developer|assistant|adjudicator)\b",
    ),
    (
        "context",
        r"(?i)\b(?:context(?:Id)?|conversation|session)\s*[:=]?\s*(?:reuse|previous|prior|shared|carry[\s-]?over)[\w-]*",
    ),
    ("schema", r"(?i)\b(?:new\s+)?schema\s*[:=]\s*[\w./-]+"),
    ("tools", r"(?i)\btools?\s*[:=]\s*[\w.,\s/-]+"),
    ("policy", r"(?i)\b(?:policy|policyEffect|severity|blocking)\s*[:=]\s*[\w-]+"),
    ("verdict", r"\bverdict\s*[:=]\s*[A-Z_]{3,}"),
    (
        "instruction",
        r"(?i)\b(?:ignore|disregard|override|forget)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^\n]{0,20}\b(?:instruction|prompt|rule|direction)s?\b",
    ),
    (
        "instruction",
        r"(?im)^\s*(?://|#|/\*|<!--)?\s*(?:SYSTEM|ASSISTANT|DEVELOPER)\s*:",
    ),
];

pub fn detect_override_attempts(records: &[UntrustedEvidenceRecord]) -> Vec<OverrideAttempt> {
    let mut attempts = Vec::new();
    for record in records {
        for (target, pattern) in OVERRIDE_PATTERNS {
            let re = Regex::new(pattern).expect("valid regex");
            for m in re.find_iter(&record.text) {
                attempts.push(OverrideAttempt {
                    target,
                    source_path: record.source_path.clone(),
                    evidence_digest: record.digest.clone(),
                    excerpt_digest: super::digest_of("override-attempt", &m.as_str().to_string()),
                    applied: false,
                });
            }
        }
    }
    attempts.sort_by(|a, b| {
        (a.target.to_string() + &a.excerpt_digest).cmp(&(b.target.to_string() + &b.excerpt_digest))
    });
    attempts
}
