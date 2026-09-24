//! Port of `src/providers/security/packs/uploads.mjs`: content-type
//! validation, size caps, storage location, filename handling, and
//! execution of uploaded content. Every rule is a lexical (pattern-only)
//! detector; it never accepts a file, never writes to disk, and never
//! certifies a finding — it only ever emits `UNADJUDICATED` candidates.
//!
//! `variant_root_cause`/`variant_enumerate` near the bottom of this file
//! port the pack's `variantStrategies` (`rootCause`/`enumerate`), reusing
//! the same `RULES`/`exec_loop` dispatch `analyze()` uses.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

use super::common::{digest, line_of, window_around, Context, Entity, Fact, Observation};

pub const ID: &str = "security.uploads";
pub const CANDIDATE_CLASS: &str = "uploads";

fn upload_middleware() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(multer|formidable|busboy)\s*\(\s*(\{[^{}]*\})?\s*\)").unwrap())
}

fn storage_in_webroot() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bdestination\s*:\s*['"`]([^'"`]*(?:public|static|www|assets)[^'"`]*)['"`]"#).unwrap()
    })
}

fn filename_unsanitized() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(fs\.writeFile(?:Sync)?|fs\.rename(?:Sync)?|path\.join)\s*\(\s*([^()\n]*\.originalname\b[^()\n]*)\)")
            .unwrap()
    })
}

fn executable_content_served() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bexpress\.static\s*\(\s*([^()\n]*upload[^()\n]*)\)").unwrap())
}

fn content_type_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(?:fileFilter|mimetype|accept)\s*:").unwrap())
}

fn size_suppress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(?:limits|maxFileSize|fileSize)\s*:").unwrap())
}

fn filename_sanitization_lexical() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)sanitize-filename|sanitizeFilename|path\.basename|uuid\(|crypto\.randomUUID|randomBytes")
            .unwrap()
    })
}

fn content_disposition_lexical() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)Content-Disposition[\s\S]{0,40}attachment|contentDisposition\(|setHeader\(\s*['"]Content-Disposition['"]"#)
            .unwrap()
    })
}

/// One `RegExp.exec()` loop match with its groups, for the four capture
/// slots this module's rules read (`m[1]`, `m[2]`).
struct RawMatch {
    index: usize,
    whole: String,
    g1: Option<String>,
    g2: Option<String>,
}

fn exec_loop(re: &Regex, text: &str) -> Vec<RawMatch> {
    let mut out = Vec::new();
    for caps in re.captures_iter(text) {
        let whole = caps.get(0).unwrap();
        if whole.as_str().is_empty() {
            continue;
        }
        out.push(RawMatch {
            index: whole.start(),
            whole: whole.as_str().to_string(),
            g1: caps.get(1).map(|m| m.as_str().to_string()),
            g2: caps.get(2).map(|m| m.as_str().to_string()),
        });
    }
    out
}

enum Downgrade {
    None,
    Some {
        control_types: &'static [&'static str],
        severity_hint: &'static str,
        lexical_pattern: fn() -> &'static Regex,
        lexical_note: &'static str,
        radius: usize,
    },
}

struct Rule {
    id: &'static str,
    pattern: fn() -> &'static Regex,
    sink_api_of: fn(&RawMatch) -> String,
    source_expr_of: fn(&RawMatch) -> String,
    custom_suppress: Option<fn(&RawMatch) -> bool>,
    claim: &'static str,
    severity_hint: &'static str,
    precondition_action: &'static str,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
    downgrade: Downgrade,
    uncertainty: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        id: "upload.content-type-unvalidated",
        pattern: upload_middleware,
        sink_api_of: |m| m.g1.clone().unwrap_or_default(),
        source_expr_of: |_| "multipart-upload-stream".to_string(),
        custom_suppress: Some(|m| m.g2.as_deref().is_some_and(|g2| content_type_suppress().is_match(g2))),
        claim: "An upload handler is configured without a visible content-type/MIME allowlist (fileFilter), accepting any uploaded file type.",
        severity_hint: "medium",
        precondition_action: "supply-upload",
        effect_kind: "integrity-impact",
        effect_action: "accept-unvalidated-type",
        effect_scope: "upload-content-type",
        chain_roles: &["starter", "enabler"],
        downgrade: Downgrade::None,
        uncertainty: "Absence of a fileFilter in this call does not prove no validation exists; it may be applied in a separate middleware step.",
    },
    Rule {
        id: "upload.size-unbounded",
        pattern: upload_middleware,
        sink_api_of: |m| m.g1.clone().unwrap_or_default(),
        source_expr_of: |_| "multipart-upload-stream".to_string(),
        custom_suppress: Some(|m| m.g2.as_deref().is_some_and(|g2| size_suppress().is_match(g2))),
        claim: "An upload handler is configured without a visible size cap (limits/maxFileSize), allowing an oversized upload to exhaust disk or memory.",
        severity_hint: "medium",
        precondition_action: "supply-oversized-upload",
        effect_kind: "availability-impact",
        effect_action: "exhaust",
        effect_scope: "upload-storage",
        chain_roles: &["starter", "impact"],
        downgrade: Downgrade::None,
        uncertainty: "Absence of a size limit in this call does not prove no cap exists; it may be enforced by an upstream proxy or platform default.",
    },
    Rule {
        id: "upload.storage-in-webroot",
        pattern: storage_in_webroot,
        sink_api_of: |_| "upload-destination-config".to_string(),
        source_expr_of: |m| m.g1.clone().unwrap_or_default(),
        custom_suppress: None,
        claim: "Uploaded files are stored inside a publicly web-served directory, making any uploaded content directly retrievable — and potentially executable — by URL.",
        severity_hint: "high",
        precondition_action: "supply-upload",
        effect_kind: "data-access",
        effect_action: "expose",
        effect_scope: "public-web-root",
        chain_roles: &["starter", "impact"],
        downgrade: Downgrade::None,
        uncertainty: "Whether the web server actually serves this directory statically, and whether execution of uploaded content is possible, must be adjudicated.",
    },
    Rule {
        id: "upload.filename-unsanitized",
        pattern: filename_unsanitized,
        sink_api_of: |m| m.g1.clone().unwrap_or_default(),
        source_expr_of: |_| "file.originalname".to_string(),
        custom_suppress: None,
        claim: "The original uploaded filename is used directly to construct a storage path without visible sanitization, risking path traversal or overwrite via a crafted filename.",
        severity_hint: "high",
        precondition_action: "supply-crafted-filename",
        effect_kind: "data-access",
        effect_action: "write",
        effect_scope: "filesystem-outside-intended-directory",
        chain_roles: &["starter", "impact"],
        downgrade: Downgrade::Some {
            control_types: &["filename-sanitization"],
            severity_hint: "low",
            lexical_pattern: filename_sanitization_lexical,
            lexical_note: "A filename-sanitization/rename call is present near the sink; treated as a mitigating signal pending adjudication.",
            radius: 200,
        },
        uncertainty: "Whether the filename is sanitized or replaced elsewhere in the pipeline before this call must be adjudicated.",
    },
    Rule {
        id: "upload.executable-content-served",
        pattern: executable_content_served,
        sink_api_of: |_| "express.static".to_string(),
        source_expr_of: |m| m.g1.clone().unwrap_or_default().trim().to_string(),
        custom_suppress: None,
        claim: "An upload directory is served as static content, allowing any successfully uploaded file (including scripts or HTML) to be directly requested and potentially executed by a browser or misconfigured server.",
        severity_hint: "high",
        precondition_action: "supply-executable-upload",
        effect_kind: "code-execution",
        effect_action: "serve",
        effect_scope: "uploaded-content",
        chain_roles: &["starter", "impact"],
        downgrade: Downgrade::Some {
            control_types: &["content-disposition-attachment"],
            severity_hint: "low",
            lexical_pattern: content_disposition_lexical,
            lexical_note: "A Content-Disposition: attachment control is present near the static-serving configuration; treated as a mitigating signal pending adjudication.",
            radius: 300,
        },
        uncertainty: "Whether the web server executes served files (e.g. via a misconfigured handler) as opposed to merely serving them as static bytes must be adjudicated.",
    },
];

/// Faithful port of `findRelatedControl(context, artifactId, controlTypes)`.
fn find_related_control<'a>(context: &'a Context, artifact_id: Option<&str>, control_types: &[&str]) -> Option<&'a Entity> {
    if let Some(artifact_id) = artifact_id {
        for rel in context.relations_to(artifact_id) {
            if rel.kind != "protects" {
                continue;
            }
            if let Some(control) = context.entity_by_id(&rel.from) {
                if control.kind == "control"
                    && control
                        .attr_str("controlType")
                        .is_some_and(|ct| control_types.contains(&ct))
                {
                    return Some(control);
                }
            }
        }
    }
    context.entities.iter().find(|e| {
        e.kind == "control" && e.attr_str("controlType").is_some_and(|ct| control_types.contains(&ct))
    })
}

/// Faithful port of `analyze(context)`.
pub fn analyze(context: &Context) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        let artifact = context.find_artifact(file);
        for rule in RULES {
            let re = (rule.pattern)();
            for m in exec_loop(re, text) {
                if let Some(suppress) = rule.custom_suppress {
                    if suppress(&m) {
                        continue;
                    }
                }

                let mut severity_hint = rule.severity_hint.to_string();
                let mut observed_controls: Vec<String> = vec![];
                let mut control_observed: Option<String> = None;
                let mut uncertainty = vec![rule.uncertainty.to_string()];

                if let Downgrade::Some { control_types, severity_hint: dg_severity, lexical_pattern, lexical_note, radius } = &rule.downgrade {
                    let control = find_related_control(context, artifact.map(|a| a.id.as_str()), *control_types);
                    if let Some(control) = control {
                        severity_hint = (*dg_severity).to_string();
                        observed_controls = vec![control.id.clone()];
                        control_observed = Some(control.name.clone());
                        let control_type = control.attr_str("controlType").unwrap_or("mitigating");
                        uncertainty.push(format!(
                            "Observed {control_type} control ({}) on this path; downgraded pending adjudication of coverage completeness.",
                            control.name
                        ));
                    } else {
                        let window = window_around(text, m.index, m.whole.len(), *radius);
                        if lexical_pattern().is_match(window) {
                            severity_hint = (*dg_severity).to_string();
                            control_observed = Some("lexical-signal".to_string());
                            uncertainty.push((*lexical_note).to_string());
                        }
                    }
                }

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint,
                    sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                    attacker_capabilities: vec!["supply-upload-content".to_string()],
                    preconditions: vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.precondition_action.to_string(),
                        object: None,
                        scope: None,
                        environment: "application".to_string(),
                        tenant: None,
                    }],
                    effects: vec![Fact {
                        kind: rule.effect_kind.to_string(),
                        subject: "actor:external".to_string(),
                        action: rule.effect_action.to_string(),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some(rule.effect_scope.to_string()),
                        environment: "application".to_string(),
                        tenant: None,
                    }],
                    assets: vec![],
                    trust_boundary_crossings: vec![],
                    required_controls: vec![],
                    observed_controls,
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: json!({
                        "file": file,
                        "line": line_of(text, m.index),
                        "sourceExpr": (rule.source_expr_of)(&m),
                        "sinkApi": (rule.sink_api_of)(&m),
                        "controlObserved": control_observed,
                        "matchDigest": digest(&m.whole),
                    }),
                    uncertainty,
                });
            }
        }
    }
    observations
}

#[allow(dead_code)]
pub fn rule_ids() -> Vec<&'static str> {
    RULES.iter().map(|r| r.id).collect()
}

/// Port of `buildVariantStrategy(rule).rootCause(candidate)`: identical
/// shape for every `upload.*` rule, parameterized only by `rule.id` and the
/// candidate's `detectorMetadata.sinkApi`.
pub fn variant_root_cause(rule_id: &str, candidate_sink_api: Option<&str>) -> Option<Value> {
    RULES.iter().find(|r| r.id == rule_id).map(|rule| {
        json!({
            "class": format!("{}-unmitigated", rule.id),
            "semanticFeatures": ["upload-boundary", rule.id, candidate_sink_api.unwrap_or(rule.id)],
        })
    })
}

/// Port of `buildVariantStrategy(rule).enumerate(context)`: independently
/// re-scans every file for `rule.pattern`, applying `rule.customSuppress`
/// (mirrors `MITIGATED` vs `CONFIRMED` disposition) exactly as `analyze()`
/// does, but without the downgrade/control lookup `analyze()` performs.
pub fn variant_enumerate(context: &Context, rule_id: &str) -> Option<Value> {
    let rule = RULES.iter().find(|r| r.id == rule_id)?;
    let re = (rule.pattern)();
    let mut matches = Vec::new();
    for file in &context.files {
        let text = context.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in exec_loop(re, text) {
            let suppressed = rule.custom_suppress.is_some_and(|f| f(&m));
            matches.push(json!({
                "file": file,
                "line": line_of(text, m.index),
                "semanticFingerprint": digest(&format!("{}{}{}", rule.id, file, m.whole)),
                "disposition": if suppressed { "MITIGATED" } else { "CONFIRMED" },
            }));
        }
    }
    Some(json!({
        "denominator": {
            "kind": "source-files",
            "digest": context.denominator_digest,
            "expected": context.files.len(),
            "examined": context.files.len(),
            "unexamined": [],
        },
        "strategies": [{
            "id": format!("{}-search", rule.id),
            "kind": "lexical-fallback",
            "description": format!("Enumerate every {} occurrence across the denominator.", rule.id),
            "queryDigest": digest(rule.id),
            "complete": true,
            "coverageGaps": [],
        }],
        "matches": matches,
        "coverageGaps": [],
    }))
}
