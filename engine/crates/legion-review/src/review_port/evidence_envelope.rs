//! Port of `src/lib/review/untrusted-evidence-envelope.mjs` (B7-029).
//!
//! Hostile evidence envelope for every reviewer family. Repository text —
//! source, docs, comments, skills, configuration, retrieved content, runtime
//! output — is DATA, never instruction. This module is the one place that
//! turns such text into a reviewer-safe record: escaped, normalized,
//! byte-capped, digest-preserving, and structurally separated from the
//! trusted instruction fields of a judgment packet (SNIP-13).
//!
//! The defence is structural, not lexical: [`build_review_packet`] composes
//! the packet's authority fields (provider, role, context, schema, tools,
//! policy, verdict vocabulary) exclusively from its own trusted arguments and
//! never reads them out of evidence. Override attempts found in evidence are
//! recorded as visible artefacts so a reviewer can see the repository tried,
//! but they can never take effect.

use std::fmt;
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const UNTRUSTED_EVIDENCE_SCHEMA_VERSION: u64 = 1;

pub const UNTRUSTED_EVIDENCE_KINDS: &[&str] = &[
    "source",
    "docs",
    "comment",
    "skill",
    "configuration",
    "retrieved-content",
    "runtime-text",
];

pub const REVIEW_FAMILIES: &[&str] = &["security", "copy", "narrative", "ux", "visual"];

pub const DEFAULT_EVIDENCE_MAX_BYTES: usize = 8192;

/// Errors mirroring the JS `TypeError`/`Error` throws in the source module.
/// Variant payloads carry the exact message text the JS threw, so callers
/// that pattern-match on the ported error strings keep working.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    Type(String),
    Invalid(String),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(message) | Self::Invalid(message) => out.write_str(message),
        }
    }
}

impl std::error::Error for EnvelopeError {}

fn require_string(value: &str, label: &str) -> Result<(), EnvelopeError> {
    if value.is_empty() {
        return Err(EnvelopeError::Type(format!(
            "{label} must be a non-empty string"
        )));
    }
    Ok(())
}

// Characters that can rewrite what a human or a model believes it is
// reading, transcribed from the exact code points in the JS source's
// `BIDI`/`ZERO_WIDTH`/`CONTROL` character classes.
fn is_bidi(c: char) -> bool {
    matches!(c as u32, 0x200E | 0x200F | 0x061C | 0x202A..=0x202E | 0x2066..=0x2069)
}

fn is_zero_width(c: char) -> bool {
    matches!(c as u32, 0x200B | 0x200C..=0x200D | 0x2060 | 0xFEFF)
}

fn is_control(c: char) -> bool {
    matches!(c as u32, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F..=0x9F)
}

fn escape_code_point(c: char) -> String {
    format!("\\u{:04x}", c as u32)
}

/// `digestOf(namespace, value)` from the JS source: sha256 of
/// `"{namespace}\0{JSON.stringify(value)}"`. `serde_json` is built with the
/// `preserve_order` feature workspace-wide, so object key order here matches
/// insertion order the same way `JSON.stringify` walks own-enumerable keys.
fn digest_of(namespace: &str, value: &Value) -> String {
    let payload = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(payload.as_bytes());
    format!("sha256:{}", hex_bytes(&hasher.finalize()))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ArtifactRef {
    pub path: String,
    pub digest: String,
}

impl ArtifactRef {
    fn validate(&self) -> Result<(), EnvelopeError> {
        require_string(&self.path, "artifactRef.path")?;
        require_string(&self.digest, "artifactRef.digest")?;
        Ok(())
    }

    fn to_value(&self) -> Value {
        json!({ "path": self.path, "digest": self.digest })
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Omission {
    pub reason: &'static str,
    pub omitted_bytes: usize,
    pub from_offset: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<ArtifactRef>,
}

impl Omission {
    fn to_value(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("reason".into(), json!(self.reason));
        object.insert("omittedBytes".into(), json!(self.omitted_bytes));
        object.insert("fromOffset".into(), json!(self.from_offset));
        if let Some(artifact_ref) = &self.artifact_ref {
            object.insert("artifactRef".into(), artifact_ref.to_value());
        }
        Value::Object(object)
    }
}

/// Arguments for [`wrap_untrusted_evidence`], mirroring the JS destructured
/// options object.
#[derive(Clone, Debug)]
pub struct WrapUntrustedEvidenceArgs {
    pub evidence_kind: String,
    pub source_path: String,
    pub source_digest: String,
    pub artifact_ref: Option<ArtifactRef>,
    pub text: String,
    pub max_bytes: usize,
    pub label: Option<String>,
    pub locator: Option<Value>,
}

impl Default for WrapUntrustedEvidenceArgs {
    fn default() -> Self {
        Self {
            evidence_kind: String::new(),
            source_path: String::new(),
            source_digest: String::new(),
            artifact_ref: None,
            text: String::new(),
            max_bytes: DEFAULT_EVIDENCE_MAX_BYTES,
            label: None,
            locator: None,
        }
    }
}

/// A wrapped, reviewer-safe untrusted evidence record. Field order and names
/// mirror the JS record shape and the committed
/// `src/schemas/core/untrusted-evidence-v1.schema.json`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UntrustedEvidenceRecord {
    pub schema_version: u64,
    pub kind: &'static str,
    pub trusted: bool,
    pub evidence_kind: String,
    pub label: Option<String>,
    pub source_path: String,
    pub source_digest: String,
    pub artifact_ref: ArtifactRef,
    pub locator: Option<Value>,
    pub encoding: &'static str,
    pub text: String,
    pub original_bytes: usize,
    pub included_bytes: usize,
    pub truncated: bool,
    pub normalizations: Vec<&'static str>,
    pub omissions: Vec<Omission>,
    pub digest: String,
}

impl UntrustedEvidenceRecord {
    /// Value form excluding `digest`, used as the digest preimage exactly as
    /// the JS source computes `digestOf('untrusted-evidence', record)` before
    /// `record.digest` is assigned.
    fn predigest_value(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("schemaVersion".into(), json!(self.schema_version));
        object.insert("kind".into(), json!(self.kind));
        object.insert("trusted".into(), json!(self.trusted));
        object.insert("evidenceKind".into(), json!(self.evidence_kind));
        object.insert("label".into(), json!(self.label));
        object.insert("sourcePath".into(), json!(self.source_path));
        object.insert("sourceDigest".into(), json!(self.source_digest));
        object.insert("artifactRef".into(), self.artifact_ref.to_value());
        object.insert("locator".into(), self.locator.clone().unwrap_or(Value::Null));
        object.insert("encoding".into(), json!(self.encoding));
        object.insert("text".into(), json!(self.text));
        object.insert("originalBytes".into(), json!(self.original_bytes));
        object.insert("includedBytes".into(), json!(self.included_bytes));
        object.insert("truncated".into(), json!(self.truncated));
        object.insert("normalizations".into(), json!(self.normalizations));
        object.insert(
            "omissions".into(),
            Value::Array(self.omissions.iter().map(Omission::to_value).collect()),
        );
        Value::Object(object)
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.predigest_value();
        if let Value::Object(object) = &mut value {
            object.insert("digest".into(), json!(self.digest));
        }
        value
    }
}

/// Wrap one piece of repository-controlled text as untrusted evidence. Raw
/// bytes beyond the cap are never carried in the record — the full content
/// remains reachable only through the bound artifact reference.
pub fn wrap_untrusted_evidence(
    args: WrapUntrustedEvidenceArgs,
) -> Result<UntrustedEvidenceRecord, EnvelopeError> {
    if !UNTRUSTED_EVIDENCE_KINDS.contains(&args.evidence_kind.as_str()) {
        return Err(EnvelopeError::Type(format!(
            "unknown untrusted evidence kind: {}",
            args.evidence_kind
        )));
    }
    require_string(&args.source_path, "sourcePath")?;
    require_string(&args.source_digest, "sourceDigest")?;
    let artifact_ref = args.artifact_ref.ok_or_else(|| {
        EnvelopeError::Type(
            "artifactRef is required: raw source is reachable only through a bound artifact"
                .to_string(),
        )
    })?;
    artifact_ref.validate()?;
    if args.max_bytes == 0 {
        return Err(EnvelopeError::Type(
            "maxBytes must be a positive integer".to_string(),
        ));
    }

    let text = args.text;
    let original_bytes = text.len();
    let truncated = original_bytes > args.max_bytes;
    let body = if truncated {
        // Slice on a UTF-8 boundary so truncation cannot manufacture a
        // half-character that renders as something else, matching the JS
        // `TextDecoder('utf8', { fatal: false })` + trailing replacement
        // stripping behaviour.
        let mut end = args.max_bytes;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    } else {
        text
    };
    let included_bytes = if truncated { args.max_bytes } else { original_bytes };

    let mut normalizations: Vec<&'static str> = vec!["unicode-nfc"];
    let display_nfc: String = icu_normalizer::ComposingNormalizer::new_nfc().normalize(&body).into_owned();

    let mut saw_bidi = false;
    let mut saw_zero_width = false;
    let mut saw_control = false;
    let mut display = String::with_capacity(display_nfc.len());
    for c in display_nfc.chars() {
        if is_bidi(c) {
            saw_bidi = true;
            display.push_str(&escape_code_point(c));
        } else if is_zero_width(c) {
            saw_zero_width = true;
            display.push_str(&escape_code_point(c));
        } else if is_control(c) {
            saw_control = true;
            display.push_str(&escape_code_point(c));
        } else {
            display.push(c);
        }
    }
    if saw_bidi {
        normalizations.push("bidi-escaped");
    }
    if saw_zero_width {
        normalizations.push("zero-width-escaped");
    }
    if saw_control {
        normalizations.push("control-escaped");
    }
    // JS does `[...new Set(normalizations)].sort()`; `unicode-nfc` is always
    // first here and the rest are pushed in fixed detection order, so a
    // plain sort matches.
    normalizations.sort_unstable();
    normalizations.dedup();

    let omissions = if truncated {
        vec![Omission {
            reason: "byte-cap",
            omitted_bytes: original_bytes - included_bytes,
            from_offset: included_bytes,
            artifact_ref: Some(artifact_ref.clone()),
        }]
    } else {
        Vec::new()
    };

    let mut record = UntrustedEvidenceRecord {
        schema_version: UNTRUSTED_EVIDENCE_SCHEMA_VERSION,
        kind: "legion-untrusted-evidence",
        trusted: false,
        evidence_kind: args.evidence_kind,
        label: args.label,
        source_path: args.source_path,
        source_digest: args.source_digest,
        artifact_ref,
        locator: args.locator,
        encoding: "escaped-utf8",
        text: display,
        original_bytes,
        included_bytes,
        truncated,
        normalizations,
        omissions,
        digest: String::new(),
    };
    let preimage = record.predigest_value();
    record.digest = digest_of("untrusted-evidence", &preimage);
    Ok(record)
}

struct OverridePattern {
    target: &'static str,
    regex: fn() -> &'static Regex,
}

macro_rules! override_pattern {
    ($name:ident, $target:literal, $pattern:literal) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            CELL.get_or_init(|| Regex::new($pattern).expect("static override pattern compiles"))
        }
    };
}

override_pattern!(
    provider_pattern,
    "provider",
    r"(?i)\b(?:provider|producer)\s*(?:[:=]|\bto\b)\s*[\w.@/-]+"
);
override_pattern!(
    role_pattern,
    "role",
    r"(?i)\b(?:role|persona|you\s+are)\s*(?:[:=]|\bnow\b)?\s*(?:system|admin|root|developer|assistant|adjudicator)\b"
);
override_pattern!(
    context_pattern,
    "context",
    r"(?i)\b(?:context(?:Id)?|conversation|session)\s*[:=]?\s*(?:reuse|previous|prior|shared|carry[\s-]?over)[\w-]*"
);
override_pattern!(
    schema_pattern,
    "schema",
    r"(?i)\b(?:new\s+)?schema\s*[:=]\s*[\w./-]+"
);
override_pattern!(
    tools_pattern,
    "tools",
    r"(?i)\btools?\s*[:=]\s*[\w.,\s/-]+"
);
override_pattern!(
    policy_pattern,
    "policy",
    r"(?i)\b(?:policy|policyEffect|severity|blocking)\s*[:=]\s*[\w-]+"
);
override_pattern!(verdict_pattern, "verdict", r"\bverdict\s*[:=]\s*[A-Z_]{3,}");
override_pattern!(
    instruction_pattern,
    "instruction",
    r"(?i)\b(?:ignore|disregard|override|forget)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^\n]{0,20}\b(?:instruction|prompt|rule|direction)s?\b"
);
override_pattern!(
    instruction_prefix_pattern,
    "instruction",
    r"(?im)^\s*(?://|#|/\*|<!--)?\s*(?:SYSTEM|ASSISTANT|DEVELOPER)\s*:"
);

fn override_patterns() -> &'static [OverridePattern] {
    static PATTERNS: OnceLock<Vec<OverridePattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            OverridePattern { target: "provider", regex: provider_pattern },
            OverridePattern { target: "role", regex: role_pattern },
            OverridePattern { target: "context", regex: context_pattern },
            OverridePattern { target: "schema", regex: schema_pattern },
            OverridePattern { target: "tools", regex: tools_pattern },
            OverridePattern { target: "policy", regex: policy_pattern },
            OverridePattern { target: "verdict", regex: verdict_pattern },
            OverridePattern { target: "instruction", regex: instruction_pattern },
            OverridePattern { target: "instruction", regex: instruction_prefix_pattern },
        ]
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InjectionAttempt {
    pub target: &'static str,
    pub source_path: String,
    pub evidence_digest: String,
    pub excerpt_digest: String,
    pub applied: bool,
}

impl InjectionAttempt {
    fn to_value(&self) -> Value {
        json!({
            "target": self.target,
            "sourcePath": self.source_path,
            "evidenceDigest": self.evidence_digest,
            "excerptDigest": self.excerpt_digest,
            "applied": self.applied,
        })
    }
}

/// Detect (for visibility only — never for effect) repository attempts to
/// override packet authority fields.
pub fn detect_override_attempts(records: &[UntrustedEvidenceRecord]) -> Vec<InjectionAttempt> {
    let mut attempts = Vec::new();
    for record in records {
        for pattern in override_patterns() {
            let regex = (pattern.regex)();
            for capture in regex.find_iter(&record.text) {
                attempts.push(InjectionAttempt {
                    target: pattern.target,
                    source_path: record.source_path.clone(),
                    evidence_digest: record.digest.clone(),
                    excerpt_digest: digest_of("override-attempt", &json!(capture.as_str())),
                    applied: false,
                });
            }
        }
    }
    attempts.sort_by(|a, b| {
        let key_a = format!("{}{}", a.target, a.excerpt_digest);
        let key_b = format!("{}{}", b.target, b.excerpt_digest);
        key_a.cmp(&key_b)
    });
    attempts
}

/// Guard against the one mistake the envelope cannot survive: pasting
/// untrusted text into a trusted field.
pub fn assert_no_untrusted_interpolation(
    instructions: &[String],
    records: &[UntrustedEvidenceRecord],
) -> Result<bool, EnvelopeError> {
    let haystack = serde_json::to_string(instructions).unwrap_or_default();
    for record in records {
        for line in record.text.split('\n') {
            let candidate = line.trim();
            if candidate.len() < 8 {
                continue;
            }
            if haystack.contains(candidate) {
                return Err(EnvelopeError::Invalid(format!(
                    "untrusted evidence must not be interpolated into instructions ({})",
                    record.source_path
                )));
            }
        }
    }
    Ok(true)
}

#[derive(Clone, Debug)]
pub struct Reviewer {
    pub role: String,
    pub context_id: String,
    pub fresh: bool,
}

/// Arguments for [`build_review_packet`]. `policy`, `budget`, and `tools` stay
/// as raw JSON values, matching the JS function's untyped object/array
/// passthrough of trusted caller-supplied fields.
#[derive(Clone, Debug)]
pub struct BuildReviewPacketArgs {
    pub family: String,
    pub subject_id: String,
    pub candidate_id: Option<String>,
    pub instructions: Vec<String>,
    pub reviewer: Reviewer,
    pub schema: String,
    pub verdict_vocabulary: Vec<String>,
    pub policy: Value,
    pub budget: Option<Value>,
    pub tools: Vec<Value>,
    pub evidence: Vec<UntrustedEvidenceRecord>,
    pub binding: Value,
}

impl Default for BuildReviewPacketArgs {
    fn default() -> Self {
        Self {
            family: String::new(),
            subject_id: String::new(),
            candidate_id: None,
            instructions: Vec::new(),
            reviewer: Reviewer { role: String::new(), context_id: String::new(), fresh: false },
            schema: String::new(),
            verdict_vocabulary: Vec::new(),
            policy: json!({}),
            budget: None,
            tools: Vec::new(),
            evidence: Vec::new(),
            binding: Value::Null,
        }
    }
}

/// A reviewer packet whose authority fields come only from trusted arguments.
/// Applies to security, copy, narrative, UX, and visual review alike.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewPacket {
    pub schema_version: u64,
    pub kind: &'static str,
    pub family: String,
    pub subject_id: String,
    pub candidate_id: Option<String>,
    pub instructions: Vec<String>,
    pub reviewer: Value,
    pub schema: String,
    pub verdict_vocabulary: Vec<String>,
    pub policy: Value,
    pub budget: Option<Value>,
    pub tools: Vec<Value>,
    pub evidence: Vec<UntrustedEvidenceRecord>,
    pub omitted_evidence: Vec<Omission>,
    pub truncated: bool,
    pub injection_attempts: Vec<InjectionAttempt>,
    pub binding: Value,
    pub digest: String,
}

impl ReviewPacket {
    fn predigest_value(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("schemaVersion".into(), json!(self.schema_version));
        object.insert("kind".into(), json!(self.kind));
        object.insert("family".into(), json!(self.family));
        object.insert("subjectId".into(), json!(self.subject_id));
        object.insert("candidateId".into(), json!(self.candidate_id));
        object.insert("instructions".into(), json!(self.instructions));
        object.insert("reviewer".into(), self.reviewer.clone());
        object.insert("schema".into(), json!(self.schema));
        object.insert("verdictVocabulary".into(), json!(self.verdict_vocabulary));
        object.insert("policy".into(), self.policy.clone());
        object.insert("budget".into(), self.budget.clone().unwrap_or(Value::Null));
        object.insert("tools".into(), Value::Array(self.tools.clone()));
        object.insert(
            "evidence".into(),
            Value::Array(self.evidence.iter().map(UntrustedEvidenceRecord::to_value).collect()),
        );
        object.insert(
            "omittedEvidence".into(),
            Value::Array(self.omitted_evidence.iter().map(Omission::to_value).collect()),
        );
        object.insert("truncated".into(), json!(self.truncated));
        object.insert(
            "injectionAttempts".into(),
            Value::Array(self.injection_attempts.iter().map(InjectionAttempt::to_value).collect()),
        );
        object.insert("binding".into(), self.binding.clone());
        Value::Object(object)
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.predigest_value();
        if let Value::Object(object) = &mut value {
            object.insert("digest".into(), json!(self.digest));
        }
        value
    }
}

/// Build a reviewer packet whose authority fields come only from trusted
/// arguments. Applies to security, copy, narrative, UX, and visual review
/// alike.
pub fn build_review_packet(args: BuildReviewPacketArgs) -> Result<ReviewPacket, EnvelopeError> {
    if !REVIEW_FAMILIES.contains(&args.family.as_str()) {
        return Err(EnvelopeError::Type(format!(
            "unknown reviewer family: {}",
            args.family
        )));
    }
    require_string(&args.subject_id, "subjectId")?;
    require_string(&args.schema, "schema")?;
    if args.verdict_vocabulary.is_empty() {
        return Err(EnvelopeError::Type(
            "verdictVocabulary must be a non-empty array".to_string(),
        ));
    }
    require_string(&args.reviewer.role, "reviewer.role")?;
    require_string(&args.reviewer.context_id, "reviewer.contextId")?;
    if !args.reviewer.fresh {
        return Err(EnvelopeError::Invalid("reviewer context must be fresh".to_string()));
    }
    if args.binding.is_null() {
        return Err(EnvelopeError::Type("binding is required".to_string()));
    }

    // All evidence entries are already typed `UntrustedEvidenceRecord`, so the
    // JS runtime "packet evidence must be wrapped untrusted-evidence records"
    // guard is structural here rather than a runtime check.
    assert_no_untrusted_interpolation(&args.instructions, &args.evidence)?;

    let omitted_evidence: Vec<Omission> = args
        .evidence
        .iter()
        .flat_map(|record| record.omissions.clone())
        .collect();
    let truncated = args.evidence.iter().any(|record| record.truncated);
    let injection_attempts = detect_override_attempts(&args.evidence);

    let reviewer_value = json!({
        "role": args.reviewer.role,
        "contextId": args.reviewer.context_id,
        "fresh": args.reviewer.fresh,
    });

    let mut packet = ReviewPacket {
        schema_version: 1,
        kind: "legion-review-packet",
        family: args.family,
        subject_id: args.subject_id,
        candidate_id: args.candidate_id,
        instructions: args.instructions,
        reviewer: reviewer_value,
        schema: args.schema,
        verdict_vocabulary: args.verdict_vocabulary,
        policy: args.policy,
        budget: args.budget,
        tools: args.tools,
        evidence: args.evidence,
        omitted_evidence,
        truncated,
        injection_attempts,
        binding: args.binding,
        digest: String::new(),
    };
    let preimage = packet.predigest_value();
    packet.digest = digest_of("review-packet", &preimage);
    Ok(packet)
}

/// The committed JSON Schema for [`UntrustedEvidenceRecord`], matching
/// `src/schemas/core/untrusted-evidence-v1.schema.json` field-for-field.
pub fn build_untrusted_evidence_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://orthic.dev/schemas/core/untrusted-evidence-v1.json",
        "title": "UntrustedEvidenceV1",
        "type": "object",
        "required": [
            "schemaVersion", "kind", "trusted", "evidenceKind", "sourcePath", "sourceDigest",
            "artifactRef", "encoding", "text", "originalBytes", "includedBytes", "truncated",
            "normalizations", "omissions", "digest",
        ],
        "properties": {
            "schemaVersion": { "const": UNTRUSTED_EVIDENCE_SCHEMA_VERSION },
            "kind": { "const": "legion-untrusted-evidence" },
            "trusted": { "const": false },
            "evidenceKind": { "enum": UNTRUSTED_EVIDENCE_KINDS },
            "label": { "type": ["string", "null"] },
            "sourcePath": { "type": "string", "minLength": 1 },
            "sourceDigest": { "type": "string", "pattern": "^sha256:" },
            "artifactRef": {
                "type": "object",
                "required": ["path", "digest"],
                "properties": {
                    "path": { "type": "string", "minLength": 1 },
                    "digest": { "type": "string", "pattern": "^sha256:" },
                },
                "additionalProperties": false,
            },
            "locator": { "type": ["object", "string", "null"] },
            "encoding": { "const": "escaped-utf8" },
            "text": { "type": "string" },
            "originalBytes": { "type": "integer", "minimum": 0 },
            "includedBytes": { "type": "integer", "minimum": 0 },
            "truncated": { "type": "boolean" },
            "normalizations": { "type": "array", "items": { "type": "string" } },
            "omissions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["reason", "omittedBytes", "fromOffset"],
                    "properties": {
                        "reason": { "enum": ["byte-cap", "policy-redaction", "binary-content"] },
                        "omittedBytes": { "type": "integer", "minimum": 0 },
                        "fromOffset": { "type": "integer", "minimum": 0 },
                        "artifactRef": { "type": "object" },
                    },
                    "additionalProperties": false,
                },
            },
            "digest": { "type": "string", "pattern": "^sha256:" },
        },
        "additionalProperties": false,
    })
}
