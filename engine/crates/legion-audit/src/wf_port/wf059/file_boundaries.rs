//! Port of `src/providers/security/packs/file-boundaries.mjs`.
//!
//! Path traversal, archive traversal (zip-slip), and unchecked symlink
//! following. When a normalization/containment-check signal is observed on
//! the same path, the candidate is downgraded with the observed control
//! referenced in `observedControls` (a model control entity was found) or
//! noted in `uncertainty` (only a lexical mitigating signal was found).

use super::common::{digest, line_of, window_around, Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::LazyLock;

static PATH_TRAVERSAL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(fs\.readFile(?:Sync)?|fs\.writeFile(?:Sync)?|fs\.createReadStream|fs\.createWriteStream|fs\.open(?:Sync)?|res\.sendFile|res\.download)\s*\(\s*([^()\n]*\b(?:request|req)\.(?:query|body|params)(?:\.[\w]+)?\b[^()\n]*)\)").unwrap()
});
static ZIP_SLIP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(fs\.writeFile(?:Sync)?|fs\.createWriteStream|path\.join)\s*\(\s*([^()\n]*\b(?:entry|zipEntry|file)\.(?:path|fileName|name)\b[^()\n]*)\)").unwrap()
});
static SYMLINK_UNCHECKED_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(followSymlinks\s*:\s*true|dereference\s*:\s*true)\b").unwrap());

static PATH_TRAVERSAL_DOWNGRADE_LEXICAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)path\.normalize|path\.resolve|\.startsWith\(|sanitize-filename|sanitizeFilename|path\.basename").unwrap());
static ZIP_SLIP_DOWNGRADE_LEXICAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)path\.normalize|\.startsWith\(|resolvedPath|isInsideDir|zip-slip|sanitizeEntry").unwrap());
static SYMLINK_DOWNGRADE_LEXICAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)isSymbolicLink\(\)|lstat|realpath.{0,80}startsWith").unwrap());

struct Rule {
    id: &'static str,
    claim: &'static str,
    severity_hint: &'static str,
    attacker_capabilities: &'static [&'static str],
    precondition_action: &'static str,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: &'static [&'static str],
    downgrade_control_types: &'static [&'static str],
    downgrade_severity_hint: &'static str,
    downgrade_lexical: &'static LazyLock<Regex>,
    downgrade_radius: usize,
    downgrade_note: &'static str,
    uncertainty: &'static str,
}

const RULE_PATH_TRAVERSAL: Rule = Rule {
    id: "file.path-traversal-unvalidated",
    claim: "Request-controlled path data reaches a filesystem operation without a visible normalization/containment check, risking path traversal outside the intended directory.",
    severity_hint: "high",
    attacker_capabilities: &["control-request-input"],
    precondition_action: "supply-path",
    effect_kind: "data-access",
    effect_action: "access",
    effect_scope: "filesystem-outside-intended-directory",
    chain_roles: &["starter", "impact"],
    downgrade_control_types: &["path-traversal-containment", "path-normalization"],
    downgrade_severity_hint: "low",
    downgrade_lexical: &PATH_TRAVERSAL_DOWNGRADE_LEXICAL,
    downgrade_radius: 300,
    downgrade_note: "A path normalization/containment check is present near the sink; treated as a mitigating signal pending adjudication.",
    uncertainty: "A request-controlled path argument is not automatically traversal; whether the value is normalized and confined to an intended base directory elsewhere in the call path must be adjudicated.",
};

const RULE_ZIP_SLIP: Rule = Rule {
    id: "file.archive-zip-slip",
    claim: "An archive entry path is written to the filesystem without a visible containment check against the extraction directory, risking a zip-slip path-traversal write.",
    severity_hint: "high",
    attacker_capabilities: &["supply-malicious-archive"],
    precondition_action: "supply-archive-entry",
    effect_kind: "integrity-impact",
    effect_action: "overwrite",
    effect_scope: "filesystem-outside-extraction-directory",
    chain_roles: &["starter", "impact"],
    downgrade_control_types: &["zip-slip-containment", "archive-path-validation"],
    downgrade_severity_hint: "low",
    downgrade_lexical: &ZIP_SLIP_DOWNGRADE_LEXICAL,
    downgrade_radius: 300,
    downgrade_note: "A resolved-path containment check is present near the sink; treated as a mitigating signal pending adjudication.",
    uncertainty: "Whether the archive source is attacker-controlled, and whether the resolved entry path is validated to remain inside the extraction directory, must be adjudicated.",
};

const RULE_SYMLINK: Rule = Rule {
    id: "file.symlink-unchecked",
    claim: "Archive/file extraction is configured to follow symbolic links, allowing an entry to write through a symlink to a location outside the intended target directory.",
    severity_hint: "medium",
    attacker_capabilities: &["supply-malicious-archive"],
    precondition_action: "supply-symlink-entry",
    effect_kind: "integrity-impact",
    effect_action: "traverse-symlink",
    effect_scope: "filesystem-outside-intended-directory",
    chain_roles: &["starter", "impact"],
    downgrade_control_types: &["symlink-containment-check"],
    downgrade_severity_hint: "low",
    downgrade_lexical: &SYMLINK_DOWNGRADE_LEXICAL,
    downgrade_radius: 300,
    downgrade_note: "A symlink/realpath containment check is present near the extraction option; treated as a mitigating signal pending adjudication.",
    uncertainty: "Whether the archive/file source can be attacker-controlled, and whether a symlink-containment check exists elsewhere in the extraction pipeline, must be adjudicated.",
};

fn matches_for(rule: &Rule, ctx: &Context) -> Vec<(String, usize, usize, usize, String, String, String)> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        let (source_of, sink_of, captures): (
            fn(&regex::Captures<'_>) -> String,
            fn(&regex::Captures<'_>) -> String,
            Vec<regex::Captures<'_>>,
        ) =
            match rule.id {
                "file.path-traversal-unvalidated" => (
                    |c| c.get(2).map(|g| g.as_str().trim().to_string()).unwrap_or_default(),
                    |c| c.get(1).map(|g| g.as_str().to_string()).unwrap_or_default(),
                    PATH_TRAVERSAL_PATTERN.captures_iter(text).collect(),
                ),
                "file.archive-zip-slip" => (
                    |c| c.get(2).map(|g| g.as_str().trim().to_string()).unwrap_or_default(),
                    |c| c.get(1).map(|g| g.as_str().to_string()).unwrap_or_default(),
                    ZIP_SLIP_PATTERN.captures_iter(text).collect(),
                ),
                "file.symlink-unchecked" => (
                    |c| c.get(1).map(|g| g.as_str().to_string()).unwrap_or_default(),
                    |_| "archive-extraction-symlink-option".to_string(),
                    SYMLINK_UNCHECKED_PATTERN.captures_iter(text).collect(),
                ),
                _ => (|_| String::new(), |_| String::new(), Vec::new()),
            };
        for m in captures {
            let whole = m.get(0).unwrap();
            out.push((
                file.clone(),
                whole.start(),
                whole.len(),
                line_of(text, whole.start()),
                source_of(&m),
                sink_of(&m),
                whole.as_str().to_string(),
            ));
        }
    }
    out
}

/// Faithful port of `analyze(context)`.
pub fn analyze(ctx: &Context) -> Vec<Observation> {
    let mut out = Vec::new();
    for rule in [&RULE_PATH_TRAVERSAL, &RULE_ZIP_SLIP, &RULE_SYMLINK] {
        for (file, index, len, line, source_expr, sink_api, matched) in matches_for(rule, ctx) {
            let text = ctx.read_file(&file);
            let artifact = ctx.find_artifact(&file);

            let mut severity_hint = rule.severity_hint.to_string();
            let mut observed_controls: Vec<String> = vec![];
            let mut control_observed: Option<String> = None;
            let mut uncertainty = vec![rule.uncertainty.to_string()];

            let control = artifact.and_then(|a| {
                ctx.relations_to(&a.id)
                    .filter(|r| r.kind == "protects")
                    .find_map(|r| {
                        ctx.entity_by_id(&r.from).filter(|c| {
                            c.kind == "control"
                                && c.attr_str("controlType")
                                    .map(|t| rule.downgrade_control_types.contains(&t))
                                    .unwrap_or(false)
                        })
                    })
            }).or_else(|| {
                ctx.entities.iter().find(|e| {
                    e.kind == "control"
                        && e.attr_str("controlType")
                            .map(|t| rule.downgrade_control_types.contains(&t))
                            .unwrap_or(false)
                })
            });

            if let Some(control) = control {
                severity_hint = rule.downgrade_severity_hint.to_string();
                observed_controls = vec![control.id.clone()];
                let control_type = control.attr_str("controlType").unwrap_or("mitigating");
                let control_name = control.attr_str("name").unwrap_or(&control.id);
                control_observed = Some(control_name.to_string());
                uncertainty.push(format!(
                    "Observed {control_type} control ({control_name}) on this path; downgraded pending adjudication of coverage completeness."
                ));
            } else if rule.downgrade_lexical.is_match(window_around(text, index, len, rule.downgrade_radius)) {
                severity_hint = rule.downgrade_severity_hint.to_string();
                control_observed = Some("lexical-signal".to_string());
                uncertainty.push(rule.downgrade_note.to_string());
            }

            out.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: "file-boundaries".to_string(),
                claim: rule.claim.to_string(),
                severity_hint,
                sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
                attacker_capabilities: rule.attacker_capabilities.iter().map(|s| s.to_string()).collect(),
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
                evidence_refs: Vec::new(),
                detector_metadata: json!({
                    "file": file,
                    "line": line,
                    "sourceExpr": source_expr,
                    "sinkApi": sink_api,
                    "controlObserved": control_observed,
                    "matchDigest": digest(&matched),
                }),
                uncertainty,
            });
        }
    }
    out
}

pub const PACK_ID: &str = "security.file-boundaries";
pub const PACK_VERSION: &str = "1.0.0";
pub const CANDIDATE_CLASS: &str = "file-boundaries";
