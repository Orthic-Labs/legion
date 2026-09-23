//! Port of `src/providers/security/packs/data-privacy.mjs`.
//!
//! Sensitive-data lifecycle handling: logs, collection, storage,
//! transmission, retention, backups, export, tenant separation, and
//! marketing/privacy-claim mismatches. Every candidate binds a data class
//! and a lifecycle stage; a high-impact claim is capped at `medium` with an
//! explicit uncertainty entry unless an *observed* classification is
//! available (see [`classification_gate`], porting `classificationGate`).

use super::common::{digest, line_of, window_around, Context, Fact, Observation};
use regex::Regex;
use serde_json::json;
use std::sync::LazyLock;

static DATA_CLASS_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        ("financial", Regex::new(r"(?i)credit[_-]?card|card[_-]?number|\bcvv\b|bank[_-]?account|\biban\b|routing[_-]?number").unwrap()),
        ("health", Regex::new(r"(?i)diagnosis|health[_-]?record|medical[_-]?record|prescription").unwrap()),
        ("credential", Regex::new(r"(?i)\bpassword\b|\bapi[_-]?key\b|\btoken\b|\bsecret\b").unwrap()),
        ("pii", Regex::new(r"(?i)\bemail\b|\bphone\b|\baddress\b|\bssn\b|full[_-]?name|date[_-]?of[_-]?birth|\bdob\b").unwrap()),
    ]
});

fn classify_data_class(text: &str) -> &'static str {
    for (cls, pattern) in DATA_CLASS_PATTERNS.iter() {
        if pattern.is_match(text) {
            return cls;
        }
    }
    "unspecified-sensitive"
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

fn cap_severity(base: &str, cap: &str) -> String {
    if severity_rank(base) <= severity_rank(cap) {
        base.to_string()
    } else {
        cap.to_string()
    }
}

/// Port of `observedClassification`: looks for an observed classification
/// from a `data-store`/`asset` model entity touching `file`, or from
/// `context.audit_facts.data_privacy_classifications`. Falls back to `None`
/// (lexical-only inference) rather than throwing.
fn observed_classification(ctx: &Context, file: Option<&str>) -> Option<String> {
    for e in &ctx.entities {
        if (e.kind == "data-store" || e.kind == "asset") && e.attributes.get("dataClass").is_some() {
            let touches_file = if let Some(file) = file {
                let related_touches = ctx.relations_to(&e.id).any(|r| {
                    ctx.entity_by_id(&r.from)
                        .map(|from| from.kind == "repository-artifact" && from.attr_str("path") == Some(file))
                        .unwrap_or(false)
                });
                related_touches || e.attr_str("file") == Some(file)
            } else {
                false
            };
            if touches_file {
                return e.attr_str("dataClass").map(String::from);
            }
        }
    }
    if let Some(file) = file {
        for (f, class) in &ctx.audit_facts.data_privacy_classifications {
            if f == file {
                return Some(class.clone());
            }
        }
    }
    None
}

struct Gate {
    severity_hint: String,
    data_class: String,
    classification_observed: bool,
    uncertainty: Vec<String>,
}

/// Port of `classificationGate`.
fn classification_gate(ctx: &Context, file: Option<&str>, lexical_text: &str, base_severity: &str) -> Gate {
    let observed = observed_classification(ctx, file);
    let data_class = observed.clone().unwrap_or_else(|| classify_data_class(lexical_text).to_string());
    if severity_rank(base_severity) < severity_rank("high") {
        return Gate { severity_hint: base_severity.to_string(), data_class, classification_observed: observed.is_some(), uncertainty: vec![] };
    }
    if observed.is_some() {
        return Gate { severity_hint: base_severity.to_string(), data_class, classification_observed: true, uncertainty: vec![] };
    }
    Gate {
        severity_hint: cap_severity(base_severity, "medium"),
        data_class,
        classification_observed: false,
        uncertainty: vec!["No observed sensitive-data classification (a data-privacy audit-facts artifact or a model data-store/asset entity carrying a data class) was available; the data class is lexically inferred and this claim is capped pending classification.".to_string()],
    }
}

static LOG_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:console|logger)\.(?:log|info|warn|debug|error)\s*\(([^;\n]{0,200})\)").unwrap());
static LOG_SENSITIVE_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(email|phone|address|ssn|password|token|apiKey|api_key|secret|creditCard|card_?number)\b").unwrap()
});
static REDACTION_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)redact|mask\(|sanitize|scrub|anonymiz").unwrap());

static CONSENT_DESTRUCTURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:const|let)\s*\{[^}]*\b(?:email|phone|ssn|address)\b[^}]*\}\s*=\s*(?:req|request)\.body").unwrap()
});
static CONSENT_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)consent|opt[_-]?in|agree(?:d)?ToTerms").unwrap());

static STORE_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.(?:save|insert|create|put)\s*\(\s*\{([^}]{0,200})\}").unwrap());
static ENCRYPTION_FIELD_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)encrypt|cipher|kms\.|sealField").unwrap());

static HTTP_SEND_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:fetch|axios\.\w+|http\.request)\s*\(\s*['"]http://[^'"]+['"][^;\n]{0,200}"#).unwrap());

static BACKUP_FILE_GUARD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)backup").unwrap());

static EXPORT_FUNCTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:export|download)\w*\s*\([^)]{0,120}\)\s*\{[^}]{0,200}").unwrap());
static EXPORT_CONTROL_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)authorize|requireRole|redact|mask\(").unwrap());

static RETENTION_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)retention[_-]?period|\bttl\b|expiresAt|purgeAfter|deleteAfter|retention[_-]?policy").unwrap());

static ERASURE_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)deleteUser|eraseUser|purgeUser|anonymizeUser|dataErasure|rightToErasure").unwrap());

static TENANT_QUERY_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.(?:find|findOne|findAll|query)\s*\(\s*\{([^}]{0,150})\}").unwrap());
static TENANT_SCOPE_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)tenant[_-]?id|organization[_-]?id|org[_-]?id").unwrap());
static MULTI_TENANT_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)tenant[_-]?id|organization[_-]?id|org[_-]?id").unwrap());

static PII_STORAGE_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(?:save|insert|create|put)\s*\(\s*\{[^}]{0,200}\b(?:email|phone|address|ssn|creditCard)\b").unwrap()
});

static PRIVACY_CLAIM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)we\s+(?:do\s+not|don't|never)\s+(sell|share|store|track|collect|retain)\b[^.\n]{0,80}").unwrap());

fn contradiction_pattern(verb: &str) -> Option<Regex> {
    let src = match verb {
        "sell" => r"(?i)third[_-]?party|dataBroker|sellData",
        "share" => r"(?i)segment\.track|mixpanel\.track|fbq\(|partner(?:Api|Share)",
        "store" => r"(?i)\.(?:save|insert|create)\s*\(",
        "track" => r"(?i)ga\(|gtag\(|mixpanel\.track|segment\.track|fbq\(",
        "collect" => r"(?i)ga\(|gtag\(|mixpanel\.track|segment\.track|fbq\(",
        "retain" => r"(?i)\.(?:save|insert|create)\s*\(",
        _ => return None,
    };
    Regex::new(src).ok()
}

fn lifecycle_by_verb(verb: &str) -> &'static str {
    match verb {
        "sell" | "share" => "export",
        "store" | "retain" => "store",
        "track" | "collect" => "collect",
        _ => "store",
    }
}

struct RawFinding {
    file: Option<String>,
    line: Option<usize>,
    claim: String,
    gate_severity: String,
    gate_data_class: String,
    gate_classification_observed: bool,
    lifecycle_stage: &'static str,
    uncertainty: Vec<String>,
    effect_kind: &'static str,
    effect_action: &'static str,
    effect_scope: &'static str,
    chain_roles: Vec<&'static str>,
    extra_meta: serde_json::Value,
}

fn make_observation(rule_id: &str, ctx: &Context, f: RawFinding) -> Observation {
    let artifact = f.file.as_deref().and_then(|file| ctx.find_artifact(file));
    let mut metadata = json!({
        "file": f.file,
        "line": f.line,
        "dataClass": f.gate_data_class,
        "lifecycleStage": f.lifecycle_stage,
        "classificationObserved": f.gate_classification_observed,
    });
    if let serde_json::Value::Object(extra) = f.extra_meta {
        if let serde_json::Value::Object(m) = &mut metadata {
            for (k, v) in extra {
                m.insert(k, v);
            }
        }
    }
    Observation {
        rule_id: rule_id.to_string(),
        candidate_class: "data-privacy".to_string(),
        claim: f.claim,
        severity_hint: f.gate_severity,
        sources: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
        sinks: artifact.map(|a| vec![a.id.clone()]).unwrap_or_default(),
        attacker_capabilities: vec!["read-repository".to_string(), "observe-application-output".to_string()],
        preconditions: vec![Fact {
            kind: "attacker-position".to_string(),
            subject: "actor:external".to_string(),
            action: "observe-data-handling".to_string(),
            object: None,
            scope: None,
            environment: "application".to_string(),
            tenant: None,
        }],
        effects: vec![Fact {
            kind: f.effect_kind.to_string(),
            subject: "actor:external".to_string(),
            action: f.effect_action.to_string(),
            object: artifact.map(|a| a.id.clone()),
            scope: Some(f.effect_scope.to_string()),
            environment: "application".to_string(),
            tenant: None,
        }],
        assets: vec![],
        trust_boundary_crossings: vec![],
        required_controls: vec![],
        observed_controls: vec![],
        chain_roles: f.chain_roles.into_iter().map(String::from).collect(),
        evidence_refs: Vec::new(),
        detector_metadata: metadata,
        uncertainty: f.uncertainty,
    }
}

fn detect_log_sensitive(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in LOG_CALL.captures_iter(text) {
            let whole = m.get(0).unwrap();
            let args = m.get(1).map(|g| g.as_str()).unwrap_or("");
            let Some(field_m) = LOG_SENSITIVE_FIELD.captures(args) else { continue };
            if REDACTION_MARKER.is_match(whole.as_str()) {
                continue;
            }
            let field = field_m.get(1).unwrap().as_str();
            let gate = classification_gate(ctx, Some(file.as_str()), whole.as_str(), "high");
            let mut uncertainty = vec![format!(
                "A log-pipeline redaction/scrubbing filter applied outside this call site is not visible from this file alone."
            )];
            uncertainty.extend(gate.uncertainty.clone());
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, whole.start())),
                claim: format!("A log statement writes a sensitive field ({field}) without a visible redaction call."),
                gate_severity: gate.severity_hint,
                gate_data_class: gate.data_class,
                gate_classification_observed: gate.classification_observed,
                lifecycle_stage: "process",
                uncertainty,
                effect_kind: "confidentiality-impact",
                effect_action: "read",
                effect_scope: "log-output",
                chain_roles: vec!["starter", "impact"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

fn detect_pii_without_consent(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        if CONSENT_MARKER.is_match(text) {
            continue;
        }
        for m in CONSENT_DESTRUCTURE.find_iter(text) {
            let gate = classification_gate(ctx, Some(file.as_str()), m.as_str(), "medium");
            let mut uncertainty = vec!["A consent-capture step upstream (e.g. a form-level opt-in) is not visible from this file alone.".to_string()];
            uncertainty.extend(gate.uncertainty.clone());
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, m.start())),
                claim: "Personal data fields are read from a request body with no visible consent capture in this file.".to_string(),
                gate_severity: gate.severity_hint,
                gate_data_class: gate.data_class,
                gate_classification_observed: gate.classification_observed,
                lifecycle_stage: "collect",
                uncertainty,
                effect_kind: "data-access",
                effect_action: "collect",
                effect_scope: "pii-collection",
                chain_roles: vec!["starter"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

static STORE_SENSITIVE_FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:email|phone|address|ssn|creditCard|card_?number|password)\b").unwrap());

fn detect_unencrypted_pii_storage(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in STORE_CALL.captures_iter(text) {
            let whole = m.get(0).unwrap();
            let fields = m.get(1).map(|g| g.as_str()).unwrap_or("");
            if !STORE_SENSITIVE_FIELD.is_match(fields) {
                continue;
            }
            if ENCRYPTION_FIELD_MARKER.is_match(window_around(text, whole.start(), whole.len(), 150)) {
                continue;
            }
            let gate = classification_gate(ctx, Some(file.as_str()), fields, "high");
            let mut uncertainty = vec!["Encryption applied at the storage/driver layer rather than the field level is not visible from this call site alone.".to_string()];
            uncertainty.extend(gate.uncertainty.clone());
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, whole.start())),
                claim: "A persistence call writes a sensitive field with no visible field-level encryption.".to_string(),
                gate_severity: gate.severity_hint,
                gate_data_class: gate.data_class,
                gate_classification_observed: gate.classification_observed,
                lifecycle_stage: "store",
                uncertainty,
                effect_kind: "confidentiality-impact",
                effect_action: "persist-unencrypted",
                effect_scope: "pii-storage",
                chain_roles: vec!["enabler", "impact"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

static HTTP_SEND_SENSITIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:email|phone|address|ssn|password|token)\b").unwrap());

fn detect_unencrypted_transmission(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in HTTP_SEND_CALL.find_iter(text) {
            if !HTTP_SEND_SENSITIVE.is_match(m.as_str()) {
                continue;
            }
            let gate = classification_gate(ctx, Some(file.as_str()), m.as_str(), "high");
            let mut uncertainty = vec!["A transport-level TLS-terminating proxy in front of this endpoint is not visible from source alone.".to_string()];
            uncertainty.extend(gate.uncertainty.clone());
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, m.start())),
                claim: "Sensitive data appears to be sent over a plaintext http:// channel.".to_string(),
                gate_severity: gate.severity_hint,
                gate_data_class: gate.data_class,
                gate_classification_observed: gate.classification_observed,
                lifecycle_stage: "transmit",
                uncertainty,
                effect_kind: "confidentiality-impact",
                effect_action: "intercept",
                effect_scope: "unencrypted-transmission",
                chain_roles: vec!["starter", "impact"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

fn detect_unbounded_retention(ctx: &Context) -> Vec<RawFinding> {
    let combined: String = ctx.files.iter().map(|f| ctx.read_file(f)).collect::<Vec<_>>().join("\n");
    if !PII_STORAGE_MARKER.is_match(&combined) {
        return vec![];
    }
    if RETENTION_MARKER.is_match(&combined) {
        return vec![];
    }
    let gate = classification_gate(ctx, None, &combined, "medium");
    vec![RawFinding {
        file: None,
        line: None,
        claim: "Personal data storage was observed with no visible retention period or purge policy anywhere in the scanned surface.".to_string(),
        gate_severity: gate.severity_hint,
        gate_data_class: gate.data_class,
        gate_classification_observed: gate.classification_observed,
        lifecycle_stage: "retain",
        uncertainty: {
            let mut u = vec!["A retention policy enforced by an external data-lifecycle system is not visible from this repository alone.".to_string()];
            u.extend(gate.uncertainty);
            u
        },
        effect_kind: "persistence",
        effect_action: "retain-indefinitely",
        effect_scope: "unbounded-retention",
        chain_roles: vec!["enabler"],
        extra_meta: json!({ "scope": "repository" }),
    }]
}

fn detect_backup_unencrypted(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        if !BACKUP_FILE_GUARD.is_match(file) {
            continue;
        }
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        if !STORE_SENSITIVE_FIELD.is_match(text) {
            continue;
        }
        if ENCRYPTION_FIELD_MARKER.is_match(text) {
            continue;
        }
        let gate = classification_gate(ctx, Some(file.as_str()), text, "high");
        let mut uncertainty = vec!["Encryption applied by the backup storage layer itself (e.g. an encrypted bucket) is not visible from this file alone.".to_string()];
        uncertainty.extend(gate.uncertainty.clone());
        out.push(RawFinding {
            file: Some(file.clone()),
            line: Some(1),
            claim: "A backup artifact references sensitive fields with no visible encryption marker.".to_string(),
            gate_severity: gate.severity_hint,
            gate_data_class: gate.data_class,
            gate_classification_observed: gate.classification_observed,
            lifecycle_stage: "retain",
            uncertainty,
            effect_kind: "confidentiality-impact",
            effect_action: "read",
            effect_scope: "unencrypted-backup",
            chain_roles: vec!["enabler", "impact"],
            extra_meta: json!({}),
        });
    }
    out
}

static EXPORT_PII_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:email|phone|address|ssn|creditCard|users?)\b").unwrap());

fn detect_unrestricted_export(ctx: &Context) -> Vec<RawFinding> {
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in EXPORT_FUNCTION.find_iter(text) {
            if !EXPORT_PII_MARKER.is_match(m.as_str()) {
                continue;
            }
            if EXPORT_CONTROL_MARKER.is_match(m.as_str()) {
                continue;
            }
            let gate = classification_gate(ctx, Some(file.as_str()), m.as_str(), "high");
            let mut uncertainty = vec!["An authorization check enforced by route middleware rather than inside this function is not visible from this file alone.".to_string()];
            uncertainty.extend(gate.uncertainty.clone());
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, m.start())),
                claim: "A data-export function includes personal data fields with no visible authorization or redaction control.".to_string(),
                gate_severity: gate.severity_hint,
                gate_data_class: gate.data_class,
                gate_classification_observed: gate.classification_observed,
                lifecycle_stage: "export",
                uncertainty,
                effect_kind: "confidentiality-impact",
                effect_action: "export",
                effect_scope: "unrestricted-export",
                chain_roles: vec!["starter", "impact"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

fn detect_no_erasure_path(ctx: &Context) -> Vec<RawFinding> {
    let combined: String = ctx.files.iter().map(|f| ctx.read_file(f)).collect::<Vec<_>>().join("\n");
    if !PII_STORAGE_MARKER.is_match(&combined) {
        return vec![];
    }
    if ERASURE_MARKER.is_match(&combined) {
        return vec![];
    }
    let gate = classification_gate(ctx, None, &combined, "medium");
    vec![RawFinding {
        file: None,
        line: None,
        claim: "Personal data storage was observed with no visible deletion/erasure function anywhere in the scanned surface.".to_string(),
        gate_severity: gate.severity_hint,
        gate_data_class: gate.data_class,
        gate_classification_observed: gate.classification_observed,
        lifecycle_stage: "delete",
        uncertainty: {
            let mut u = vec!["A deletion path implemented in an external service (e.g. a data-processor callback) is not visible from this repository alone.".to_string()];
            u.extend(gate.uncertainty);
            u
        },
        effect_kind: "persistence",
        effect_action: "retain-without-erasure-path",
        effect_scope: "missing-erasure",
        chain_roles: vec!["enabler"],
        extra_meta: json!({ "scope": "repository" }),
    }]
}

fn detect_tenant_crossover(ctx: &Context) -> Vec<RawFinding> {
    let combined: String = ctx.files.iter().map(|f| ctx.read_file(f)).collect::<Vec<_>>().join("\n");
    if !MULTI_TENANT_MARKER.is_match(&combined) {
        return vec![];
    }
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in TENANT_QUERY_CALL.captures_iter(text) {
            let whole = m.get(0).unwrap();
            let fields = m.get(1).map(|g| g.as_str()).unwrap_or("");
            if TENANT_SCOPE_FIELD.is_match(fields) {
                continue;
            }
            let lexical = if fields.is_empty() { "tenant-scoped-data" } else { fields };
            let gate = classification_gate(ctx, Some(file.as_str()), lexical, "high");
            let mut uncertainty = vec!["Tenant scoping enforced by a query middleware/interceptor rather than inline in this call is not visible from this call site alone.".to_string()];
            uncertainty.extend(gate.uncertainty.clone());
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, whole.start())),
                claim: "A data-store query has no visible tenant/organization scoping filter, though tenant scoping is used elsewhere in the repository.".to_string(),
                gate_severity: gate.severity_hint,
                gate_data_class: gate.data_class,
                gate_classification_observed: gate.classification_observed,
                lifecycle_stage: "process",
                uncertainty,
                effect_kind: "confidentiality-impact",
                effect_action: "read",
                effect_scope: "cross-tenant-data-access",
                chain_roles: vec!["starter", "impact"],
                extra_meta: json!({}),
            });
        }
    }
    out
}

fn detect_marketing_mismatch(ctx: &Context) -> Vec<RawFinding> {
    let combined: String = ctx.files.iter().map(|f| ctx.read_file(f)).collect::<Vec<_>>().join("\n");
    let mut out = Vec::new();
    for file in &ctx.files {
        let text = ctx.read_file(file);
        if text.is_empty() {
            continue;
        }
        for m in PRIVACY_CLAIM.captures_iter(text) {
            let whole = m.get(0).unwrap();
            let verb = m.get(1).unwrap().as_str().to_lowercase();
            let Some(contradiction) = contradiction_pattern(&verb) else { continue };
            if !contradiction.is_match(&combined) {
                continue;
            }
            let lifecycle_stage = lifecycle_by_verb(&verb);
            let gate = classification_gate(ctx, Some(file.as_str()), whole.as_str(), "medium");
            let claim_artifact = ctx
                .audit_facts
                .claim_proof_claims
                .iter()
                .find(|c| c.file == *file && c.text.contains(whole.as_str()));
            let mut uncertainty = gate.uncertainty.clone();
            uncertainty.push(if claim_artifact.is_some() {
                "Cross-linked to a recorded claim-proof artifact; the contradiction itself is still subject to adjudication.".to_string()
            } else {
                "No claim-proof/copy artifact was available to cross-link this claim; the reference is a same-file lexical location only.".to_string()
            });
            out.push(RawFinding {
                file: Some(file.clone()),
                line: Some(line_of(text, whole.start())),
                claim: format!("A privacy claim (\"{}\") appears alongside behavior in the repository that may contradict it.", whole.as_str().trim()),
                gate_severity: gate.severity_hint,
                gate_data_class: gate.data_class,
                gate_classification_observed: gate.classification_observed,
                lifecycle_stage,
                uncertainty,
                effect_kind: "integrity-impact",
                effect_action: "contradict-disclosed-claim",
                effect_scope: "privacy-claim-mismatch",
                chain_roles: vec!["enabler"],
                extra_meta: json!({ "claimRefs": claim_artifact.map(|c| vec![c.id.clone()]).unwrap_or_default() }),
            });
        }
    }
    out
}

/// Faithful port of the module default export's `analyze(context)`.
pub fn analyze(ctx: &Context) -> Vec<Observation> {
    let mut out = Vec::new();
    for f in detect_log_sensitive(ctx) {
        out.push(make_observation("privacy.log.sensitive-data-unredacted", ctx, f));
    }
    for f in detect_pii_without_consent(ctx) {
        out.push(make_observation("privacy.collect.pii-without-consent", ctx, f));
    }
    for f in detect_unencrypted_pii_storage(ctx) {
        out.push(make_observation("privacy.store.unencrypted-pii", ctx, f));
    }
    for f in detect_unencrypted_transmission(ctx) {
        out.push(make_observation("privacy.transmit.unencrypted-channel", ctx, f));
    }
    for f in detect_unbounded_retention(ctx) {
        out.push(make_observation("privacy.retain.unbounded-retention", ctx, f));
    }
    for f in detect_backup_unencrypted(ctx) {
        out.push(make_observation("privacy.retain.backup-unencrypted", ctx, f));
    }
    for f in detect_unrestricted_export(ctx) {
        out.push(make_observation("privacy.export.unrestricted-data-export", ctx, f));
    }
    for f in detect_no_erasure_path(ctx) {
        out.push(make_observation("privacy.delete.no-erasure-path", ctx, f));
    }
    for f in detect_tenant_crossover(ctx) {
        out.push(make_observation("privacy.process.tenant-data-crossover", ctx, f));
    }
    for f in detect_marketing_mismatch(ctx) {
        out.push(make_observation("privacy.claim.marketing-mismatch", ctx, f));
    }
    out
}

pub const PACK_ID: &str = "security.data-privacy";
pub const PACK_VERSION: &str = "1.0.0";

#[allow(dead_code)]
fn _unused_digest_reexport() -> String {
    digest("unused")
}
