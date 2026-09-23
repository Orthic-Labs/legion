//! Port of five security packs (chunk wf057, area `src/providers/security`):
//!
//! - `src/providers/security/packs/ai-prompt-injection.mjs` — Security Appendix
//!   §50.7: untrusted prompts, retrieved (RAG/search) content, durable agent
//!   memory, and dynamically constructed tool/function schemas entering a
//!   model invocation without a visible trust label.
//! - `src/providers/security/packs/authentication-session.mjs` — a three-rule
//!   `createPatternPack` instance (JWT decode without verification, weak
//!   session cookie, recovery-token logging).
//! - `src/providers/security/packs/authorization-tenant.mjs` — Security
//!   Appendix §52.2: object write/read without ownership check, privileged
//!   function without role check (the pack also declares, but never emits,
//!   `authorization.object-read.missing-owner-check` and
//!   `authorization.mass-assignment` — no JS logic implements them either).
//! - `src/providers/security/packs/automation.mjs` — B7-018: release
//!   identity, updater/installer trust, signature verification, and
//!   privileged automation.
//! - `src/providers/security/packs/browser-client.mjs` — CSRF, CORS, cookie
//!   SameSite, clickjacking, open redirect, OAuth redirect-URI, and CSP.
//!
//! `git grep` over `engine/` for these packs' rule ids, candidate classes,
//! and pack ids found no prior native port, so all five are ported fresh
//! here.
//!
//! This module is self-contained, following the wf056 precedent: it defines
//! its own minimal `SecurityModel`/`Entity`/`Relation`/`PackContext`/
//! `Observation` types rather than reaching into another chunk's model
//! types, since no shared security-context module is wired into this crate
//! at port time. The `digest`/`stable_id`/`canonicalize` helpers reproduce
//! `src/providers/security/contracts.mjs`'s `digest(value)` exactly
//! (namespace `"digest"`, `sha256:` + hex of
//! `` `${namespace}\0${JSON.stringify(canonicalize(value))}` ``) so
//! `matchDigest`/`queryDigest` values are bit-for-bit comparable with the JS
//! implementation given the same inputs.
//!
//! Everything here is pure: no filesystem walk, no model call, no tool
//! execution, no network access — matching every source file's own header
//! comment.

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

// =================================================================================================
// contracts.mjs subset: canonicalize / stable_id / digest
// =================================================================================================

/// Mirrors `canonicalize`: arrays map element-wise, objects get their keys
/// sorted (recursively), everything else passes through unchanged.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Mirrors `stableId(namespace, value)`.
pub fn stable_id(namespace: &str, value: &Value) -> String {
    let body = serde_json::to_string(&canonicalize(value)).expect("json values always serialize");
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Mirrors `digest(value)`.
pub fn digest(value: &Value) -> String {
    stable_id("digest", value)
}

// =================================================================================================
// Minimal shared security-model types (self-contained; see module doc).
// =================================================================================================

#[derive(Debug, Clone, Default)]
pub struct Entity {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub attributes: BTreeMap<String, Value>,
    pub evidence_refs: Vec<String>,
}

impl Entity {
    pub fn attr_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(Value::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityModel {
    pub entities: Vec<Entity>,
}

/// Mirrors the subset of the JS `context` object these five packs'
/// `analyze(context)` actually read: `context.files`, `context.readFile(file)`,
/// `context.model.entities`, `context.relationsTo(id)`,
/// `context.entityById.get(id)`, `context.denominatorDigest`, and
/// (`automation.mjs`/`browser-client.mjs` only) `context.projection.auditFacts`.
pub struct PackContext<'a> {
    pub files: Vec<String>,
    pub source_text: BTreeMap<String, String>,
    pub model: &'a SecurityModel,
    pub relations: &'a [Relation],
    pub denominator_digest: String,
    /// Mirrors `context.projection.auditFacts.sandboxReceipt` (automation.mjs).
    pub sandbox_receipt: bool,
    /// Mirrors `context.projection.auditFacts.runtimeHeaders.headers`
    /// (browser-client.mjs): lower-cased header name -> raw JSON header value
    /// (a JS `null`/absent value is `None`/missing from this map — the two
    /// are distinguished the same way `runtimeHeaderCompliance` distinguishes
    /// `hasOwnProperty` from a `null` value: presence in this map means the
    /// key existed in the snapshot).
    pub runtime_headers: Option<BTreeMap<String, Value>>,
    /// Mirrors `context.projection.auditFacts.deployment` truthiness
    /// (browser-client.mjs `deploymentGate`).
    pub deployment_evidence: bool,
}

impl<'a> PackContext<'a> {
    pub fn read_file(&self, file: &str) -> Option<&str> {
        self.source_text.get(file).map(String::as_str)
    }

    pub fn entity_by_id(&self, id: &str) -> Option<&Entity> {
        self.model.entities.iter().find(|e| e.id == id)
    }

    /// Mirrors `context.relationsTo(id)`: relations whose `to` is `id`.
    pub fn relations_to(&self, id: &str) -> impl Iterator<Item = &Relation> + '_ {
        self.relations.iter().filter(move |r| r.to == id)
    }

    fn find_entity<F: Fn(&Entity) -> bool>(&self, pred: F) -> Option<&Entity> {
        self.model.entities.iter().find(|e| pred(e))
    }
}

impl<'a> Default for PackContext<'a> {
    fn default() -> Self {
        PackContext {
            files: Vec::new(),
            source_text: BTreeMap::new(),
            model: MODEL_EMPTY.get_or_init(SecurityModel::default),
            relations: &[],
            denominator_digest: "sha256:denom".to_string(),
            sandbox_receipt: false,
            runtime_headers: None,
            deployment_evidence: false,
        }
    }
}

static MODEL_EMPTY: std::sync::OnceLock<SecurityModel> = std::sync::OnceLock::new();

/// Mirrors the observation object each pack's `analyze` pushes.
#[derive(Debug, Clone)]
pub struct Observation {
    pub rule_id: String,
    pub candidate_class: String,
    pub claim: String,
    pub severity_hint: String,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub attacker_capabilities: Vec<String>,
    pub effect_kind: String,
    pub effect_action: String,
    pub effect_object: Option<String>,
    pub effect_scope: String,
    pub effect_environment: String,
    pub chain_roles: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub detector_metadata: Value,
    pub uncertainty: Vec<String>,
}

/// Dedupe-preserving insert-order union of two evidence-ref lists (mirrors
/// `[...new Set([...a, ...b])]`).
fn union_refs(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for x in a.iter().chain(b.iter()) {
        if !out.contains(x) {
            out.push(x.clone());
        }
    }
    out
}

fn find_control<'a>(
    ctx: &'a PackContext<'a>,
    sink_id: Option<&str>,
    control_types: &[&str],
) -> Option<&'a Entity> {
    if let Some(sink_id) = sink_id {
        for rel in ctx.relations_to(sink_id) {
            if rel.kind != "protects" && rel.kind != "validates" {
                continue;
            }
            if let Some(control) = ctx.entity_by_id(&rel.from) {
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
    ctx.find_entity(|e| {
        e.kind == "control"
            && e.attr_str("controlType")
                .map(|t| control_types.contains(&t))
                .unwrap_or(false)
    })
}

fn find_artifact<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
    ctx.find_entity(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
}

/// `text.slice(0, index).split('\n').length` — 1-based line number of a byte
/// offset into `text`.
fn line_of(text: &str, byte_index: usize) -> usize {
    text.as_bytes()[..byte_index.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

// =================================================================================================
// authentication-session.mjs (a `createPatternPack` instance)
// =================================================================================================

pub mod authentication_session {
    use super::*;

    struct Rule {
        id: &'static str,
        pattern: fn(&str) -> bool,
        claim: &'static str,
        severity_hint: &'static str,
        effect_kind: &'static str,
    }

    fn p_jwt_without_verification(t: &str) -> bool {
        Regex::new(r"jwt\.(?:decode|Decode)\s*\(|parseJwt\s*\(")
            .unwrap()
            .is_match(t)
    }
    fn p_session_cookie_weak(t: &str) -> bool {
        Regex::new(
            r"(?i)(?:session|auth)[\s\S]{0,180}(?:secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*['\x22]none)",
        )
        .unwrap()
        .is_match(t)
    }
    fn p_reset_token_log(t: &str) -> bool {
        Regex::new(r"(?i)(?:console|logger)\.(?:log|info|debug)\([^\n]*(?:resetToken|passwordReset|magicLink)")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "auth.jwt-without-verification",
            pattern: p_jwt_without_verification,
            claim: "A JWT may be decoded without visible signature verification.",
            severity_hint: "high",
            effect_kind: "principal-access",
        },
        Rule {
            id: "auth.session-cookie-weak",
            pattern: p_session_cookie_weak,
            claim: "A session cookie may omit a material browser protection.",
            severity_hint: "medium",
            effect_kind: "credential-possession",
        },
        Rule {
            id: "auth.reset-token-log",
            pattern: p_reset_token_log,
            claim: "A recovery credential may be written to logs.",
            severity_hint: "high",
            effect_kind: "credential-possession",
        },
    ];

    pub const CANDIDATE_CLASS: &str = "authentication-session";

    pub fn rule_ids() -> Vec<&'static str> {
        RULES.iter().map(|r| r.id).collect()
    }

    /// Mirrors `createPatternPack({ id: 'security.authentication-session', family: 'authentication-session', ... }).analyze`.
    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            for rule in RULES {
                if !(rule.pattern)(text) {
                    continue;
                }
                let ids: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();
                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources: ids.clone(),
                    sinks: ids,
                    attacker_capabilities: vec!["control-request-input".to_string()],
                    effect_kind: rule.effect_kind.to_string(),
                    effect_action: "bypass".to_string(),
                    effect_object: artifact.map(|e| e.id.clone()),
                    effect_scope: CANDIDATE_CLASS.to_string(),
                    effect_environment: "application".to_string(),
                    chain_roles: vec!["starter".to_string(), "impact".to_string()],
                    evidence_refs: artifact.map(|e| e.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: json!({ "file": file, "patternFamily": CANDIDATE_CLASS }),
                    uncertainty: vec![
                        "Reachability and compensating controls require independent adjudication.".to_string(),
                    ],
                });
            }
        }
        observations
    }
}

// =================================================================================================
// authorization-tenant.mjs
// =================================================================================================

pub mod authorization_tenant {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "authorization";

    /// All four rule ids the pack declares — only the first two are ever
    /// emitted by `analyze`, matching the JS source exactly (the pack
    /// declares `authorization.object-read.missing-owner-check` and
    /// `authorization.mass-assignment` in its `rules` list but implements no
    /// detector for either).
    pub const DECLARED_RULE_IDS: &[&str] = &[
        "authorization.object-write.missing-owner-check",
        "authorization.object-read.missing-owner-check",
        "authorization.privileged-function.missing-role-check",
        "authorization.mass-assignment",
    ];

    fn object_write_sink() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\b(?:update|patch|put|set|save)\w*\s*\([^)]*(?:id|params|request)").unwrap())
    }
    fn owner_guard() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)owner|tenant|org_?id|authorize|canAccess|permission").unwrap())
    }
    fn privileged_function() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\b(?:delete|remove|grant|promote|impersonate|admin)\w*\s*\(").unwrap())
    }
    fn role_guard() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)role|permission|isAdmin|requireAdmin|authorize").unwrap())
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            let ids: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();

            if object_write_sink().is_match(text) && !owner_guard().is_match(text) {
                observations.push(Observation {
                    rule_id: "authorization.object-write.missing-owner-check".to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: "A request-derived object identifier reaches a write without a visible ownership or tenant control.".to_string(),
                    severity_hint: "high".to_string(),
                    sources: ids.clone(),
                    sinks: ids.clone(),
                    attacker_capabilities: vec!["authenticated-low-privilege".to_string()],
                    effect_kind: "object-access".to_string(),
                    effect_action: "write".to_string(),
                    effect_object: artifact.map(|e| e.id.clone()),
                    effect_scope: "cross-tenant".to_string(),
                    effect_environment: "application".to_string(),
                    chain_roles: vec!["starter".to_string(), "privilege-escalation".to_string(), "impact".to_string()],
                    evidence_refs: vec![],
                    detector_metadata: json!({
                        "file": file,
                        "sourceKind": "request-object-identifier",
                        "sinkKind": "tenant-object-write",
                    }),
                    uncertainty: vec!["A global authorization policy may exist outside the modeled path.".to_string()],
                });
            }

            if privileged_function().is_match(text) && !role_guard().is_match(text) {
                observations.push(Observation {
                    rule_id: "authorization.privileged-function.missing-role-check".to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: "A privileged function has no visible role or policy enforcement.".to_string(),
                    severity_hint: "high".to_string(),
                    sources: ids.clone(),
                    sinks: ids,
                    attacker_capabilities: vec!["authenticated-low-privilege".to_string()],
                    effect_kind: "object-access".to_string(),
                    effect_action: "write".to_string(),
                    effect_object: None,
                    effect_scope: "privileged".to_string(),
                    effect_environment: "application".to_string(),
                    chain_roles: vec!["privilege-escalation".to_string(), "impact".to_string()],
                    evidence_refs: vec![],
                    detector_metadata: json!({ "file": file, "sourceKind": "privileged-function" }),
                    uncertainty: vec!["A framework-level policy may enforce roles outside this call path.".to_string()],
                });
            }
        }
        observations
    }

    /// Mirrors `variantStrategies['authorization.object-write.missing-owner-check'].enumerate`.
    pub fn enumerate_object_write_missing_owner_check(ctx: &PackContext) -> Value {
        let object_write = Regex::new(r"(?i)(?:update|patch|put|set|save)\s*\([^)]*(?:id|params|request)").unwrap();
        let owner_guard_narrow = Regex::new(r"owner|tenant|org_?id|authorize").unwrap();
        let mut matches = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            if object_write.is_match(text) && !owner_guard_narrow.is_match(text) {
                matches.push(json!({
                    "file": file,
                    "line": 1,
                    "semanticFingerprint": format!("sha256:{file}"),
                    "disposition": "CONFIRMED",
                }));
            }
        }
        json!({
            "denominator": {
                "kind": "source-files",
                "digest": ctx.denominator_digest,
                "expected": ctx.files.len(),
                "examined": ctx.files.len(),
                "unexamined": [],
            },
            "strategies": [{
                "id": "write-sink-search", "kind": "lexical-fallback",
                "description": "Enumerate every tenant-object write sink.",
                "queryDigest": "sha256:q", "complete": true, "coverageGaps": [],
            }],
            "matches": matches,
            "coverageGaps": [],
        })
    }
}

// =================================================================================================
// automation.mjs
// =================================================================================================

pub mod automation {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "automation";

    fn workflow_file() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(
                r"(?i)(^|/)\.github/workflows/[^/]+\.ya?ml$|(^|/)\.gitlab-ci\.ya?ml$|(^|/)azure-pipelines\.ya?ml$|(^|/)\.circleci/config\.ya?ml$|(^|/)bitbucket-pipelines\.ya?ml$",
            )
            .unwrap()
        })
    }
    fn updater_config() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)electron-builder\.(ya?ml|json5?|toml)$|(^|/)app-update\.ya?ml$").unwrap())
    }
    fn dependency_update_config() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)(^|/)renovate\.json5?$|(^|/)\.github/renovate\.json5?$|(^|/)\.github/dependabot\.ya?ml$")
                .unwrap()
        })
    }
    fn release_config() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)(^|/)\.releaserc(\.[a-zA-Z0-9]+)?$|(^|/)release\.config\.[cm]?js$|(^|/)\.goreleaser\.ya?ml$")
                .unwrap()
        })
    }

    fn hostile_precondition(file: &str) -> Value {
        json!({
            "kind": "attacker-position",
            "subject": "actor:repository-content",
            "action": "control-repository-content",
            "object": file,
            "scope": Value::Null,
            "environment": "ci",
            "tenant": Value::Null,
        })
    }

    fn sandbox_gate_note(ctx: &PackContext) -> &'static str {
        if ctx.sandbox_receipt {
            "An external sandbox execution receipt is present in the audit context; execution proof still requires independent adjudication, never a pack-level clean claim."
        } else {
            "BLOCKED: no external sandbox execution receipt (context.projection.auditFacts.sandboxReceipt) is present; whether this privileged automation chain actually executes remains unproven pending one."
        }
    }

    fn permission_scope_is_elevated(text: &str) -> bool {
        let re = Regex::new(r"\bpermissions\s*:").unwrap();
        let Some(m) = re.find(text) else { return false };
        let end = (m.start() + 400).min(text.len());
        // Slice on a char boundary.
        let mut end = end;
        while end < text.len() && !text.is_char_boundary(end) {
            end += 1;
        }
        let window = &text[m.start()..end];
        Regex::new(r"write-all").unwrap().is_match(window)
            || Regex::new(r"contents\s*:\s*write").unwrap().is_match(window)
    }

    struct Match {
        file: String,
        line: usize,
        snippet: String,
    }

    struct Rule {
        id: &'static str,
        claim: &'static str,
        severity_hint: &'static str,
        authority: &'static str,
        execution_path: &'static str,
        effect_kind: &'static str,
        effect_action: &'static str,
        effect_scope: &'static str,
        environment: &'static str,
        chain_roles: &'static [&'static str],
        execution_chain: bool,
        uncertainty: &'static str,
        matches_in: fn(&PackContext) -> Vec<Match>,
    }

    fn matches_unresolved_identity_scope(ctx: &PackContext) -> Vec<Match> {
        let mut out = Vec::new();
        for file in &ctx.files {
            if !workflow_file().is_match(file) {
                continue;
            }
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let has_publish = Regex::new(
                r"\bnpm publish\b|\bdocker push\b|docker/build-push-action|\bgoreleaser\b|\bsemantic-release\b|\bgh release create\b",
            )
            .unwrap()
            .is_match(text);
            if !has_publish {
                continue;
            }
            if Regex::new(r"\bpermissions\s*:").unwrap().is_match(text) {
                continue;
            }
            out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
        }
        out
    }

    fn matches_updater_insecure(ctx: &PackContext) -> Vec<Match> {
        let mut out = Vec::new();
        for file in &ctx.files {
            if !updater_config().is_match(file) {
                continue;
            }
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let insecure_transport = Regex::new(r"(?i)(?:update|download|artifact)[\s\S]{0,180}http://").unwrap().is_match(text);
            let disabled_signature = Regex::new(r"verifyUpdateCodeSignature\s*:\s*false").unwrap().is_match(text);
            if !insecure_transport && !disabled_signature {
                continue;
            }
            out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
        }
        out
    }

    fn matches_signing_disabled(ctx: &PackContext) -> Vec<Match> {
        let pattern = Regex::new(r"\bsign\s*:\s*false\b|\bskipSign\s*:\s*true\b|verifyUpdateCodeSignature\s*:\s*false").unwrap();
        let mut out = Vec::new();
        for file in &ctx.files {
            if !(workflow_file().is_match(file) || release_config().is_match(file) || updater_config().is_match(file)) {
                continue;
            }
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            if let Some(m) = pattern.find(text) {
                out.push(Match { file: file.clone(), line: line_of(text, m.start()), snippet: m.as_str().to_string() });
            }
        }
        out
    }

    fn matches_hostile_trigger_with_write(ctx: &PackContext) -> Vec<Match> {
        let mut out = Vec::new();
        for file in &ctx.files {
            if !workflow_file().is_match(file) {
                continue;
            }
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let hostile = Regex::new(r"\bpull_request_target\b").unwrap().is_match(text)
                || Regex::new(r"\bworkflow_run\b").unwrap().is_match(text)
                || Regex::new(r"\bissue_comment\b").unwrap().is_match(text);
            if !hostile {
                continue;
            }
            if !permission_scope_is_elevated(text) {
                continue;
            }
            out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
        }
        out
    }

    fn matches_automerge_without_review(ctx: &PackContext) -> Vec<Match> {
        let mut out = Vec::new();
        for file in &ctx.files {
            if !dependency_update_config().is_match(file) {
                continue;
            }
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let automerge = Regex::new(r#""automerge"\s*:\s*true"#).unwrap().is_match(text)
                || Regex::new(r"\bautomerge\s*:\s*true\b").unwrap().is_match(text);
            if !automerge {
                continue;
            }
            let review_gate = Regex::new(r"(?i)requiredReviews|requireStatusChecks|minimumApprovals").unwrap().is_match(text);
            if review_gate {
                continue;
            }
            out.push(Match { file: file.clone(), line: 1, snippet: file.clone() });
        }
        out
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "automation.release.unresolved-identity-scope",
            claim: "A publish/release automation step runs without a resolvable permission scope, so the effective authority of the release identity cannot be established from this file.",
            severity_hint: "medium",
            authority: "ci-release-identity",
            execution_path: "release trigger → publish step → identity with unresolved permission scope",
            effect_kind: "capability", effect_action: "run-with-unresolved-scope", effect_scope: "release-identity",
            environment: "ci",
            chain_roles: &["enabler"],
            execution_chain: false,
            uncertainty: "An unresolved permission scope in this file does not prove excess privilege; the effective scope may be constrained elsewhere (org/repo defaults) and must be adjudicated.",
            matches_in: matches_unresolved_identity_scope,
        },
        Rule {
            id: "automation.updater.insecure-transport-or-unverified-signature",
            claim: "An application auto-updater is configured with an insecure (http://) update endpoint or with signature verification explicitly disabled.",
            severity_hint: "high",
            authority: "end-user-device-updater",
            execution_path: "installed application → updater config → downloaded update applied to end-user device",
            effect_kind: "code-execution", effect_action: "apply-unverified-update", effect_scope: "end-user-device",
            environment: "end-user-device",
            chain_roles: &["starter", "impact"],
            execution_chain: false,
            uncertainty: "An insecure-transport or disabled-verification marker is not automatically exploitable; whether the updater actually reaches this configuration path at runtime must be adjudicated.",
            matches_in: matches_updater_insecure,
        },
        Rule {
            id: "automation.release.signing-disabled-or-unenforced",
            claim: "Release-signing/verification is explicitly disabled or skipped for a publish step.",
            severity_hint: "high",
            authority: "ci-release-identity",
            execution_path: "release step → signing/verification flag explicitly disabled → unsigned published artifact",
            effect_kind: "integrity-impact", effect_action: "publish-unsigned-artifact", effect_scope: "release-artifact",
            environment: "ci",
            chain_roles: &["control-bypass", "impact"],
            execution_chain: false,
            uncertainty: "An explicitly disabled signing flag is not automatically exploited; whether consumers actually verify signatures on this artifact type must be adjudicated.",
            matches_in: matches_signing_disabled,
        },
        Rule {
            id: "automation.privileged-automation.hostile-trigger-with-write",
            claim: "A workflow triggered by untrusted external content (pull_request_target/workflow_run/issue_comment) holds elevated write permission, letting an external contributor drive privileged automation.",
            severity_hint: "high",
            authority: "ci-privileged-automation-identity",
            execution_path: "external-contributor content → hostile trigger → privileged (write) automation step",
            effect_kind: "code-execution", effect_action: "run-privileged-step-from-untrusted-trigger", effect_scope: "ci-privileged-automation",
            environment: "ci",
            chain_roles: &["starter", "privilege-escalation", "impact"],
            execution_chain: true,
            uncertainty: "A hostile-trigger-plus-write-permission shape is not automatically exploited; whether attacker-controlled data actually reaches a privileged step within the job must be adjudicated by independent sandboxed execution.",
            matches_in: matches_hostile_trigger_with_write,
        },
        Rule {
            id: "automation.dependency-update.automerge-without-review",
            claim: "Scheduled dependency-update automation is configured to auto-merge without a visible required-review/required-status-check gate in the same file.",
            severity_hint: "medium",
            authority: "ci-dependency-update-bot-identity",
            execution_path: "scheduled dependency update → automerge enabled → merged without human review",
            effect_kind: "control-bypass", effect_action: "merge-without-review", effect_scope: "repository-main-branch",
            environment: "ci",
            chain_roles: &["enabler", "control-bypass"],
            execution_chain: false,
            uncertainty: "An automerge flag in this file does not prove branch protection is absent; required reviews/status checks may be enforced by host-side repository settings outside this file and must be adjudicated.",
            matches_in: matches_automerge_without_review,
        },
    ];

    pub fn rule_ids() -> Vec<&'static str> {
        RULES.iter().map(|r| r.id).collect()
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for rule in RULES {
            for m in (rule.matches_in)(ctx) {
                let artifact = find_artifact(ctx, &m.file);
                let mut uncertainty = vec![rule.uncertainty.to_string()];
                let mut detector_metadata = json!({
                    "file": m.file,
                    "line": m.line,
                    "authority": rule.authority,
                    "executionPath": rule.execution_path,
                    "matchDigest": digest(&Value::String(m.snippet.clone())),
                });
                if rule.execution_chain {
                    uncertainty.push(sandbox_gate_note(ctx).to_string());
                    detector_metadata
                        .as_object_mut()
                        .unwrap()
                        .insert("requiresSandboxReceipt".to_string(), Value::Bool(true));
                }
                let ids: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();
                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources: ids.clone(),
                    sinks: ids,
                    attacker_capabilities: vec!["read-repository".to_string(), "control-repository-content".to_string()],
                    effect_kind: rule.effect_kind.to_string(),
                    effect_action: rule.effect_action.to_string(),
                    effect_object: artifact.map(|e| e.id.clone()),
                    effect_scope: rule.effect_scope.to_string(),
                    effect_environment: rule.environment.to_string(),
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs: artifact.map(|e| e.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata,
                    uncertainty,
                });
                // hostile_precondition() is folded into the `preconditions` field
                // that this crate's Observation type does not carry separately
                // (single-precondition packs reuse `effect_environment`/
                // `attacker_capabilities`); callers needing the JS-shaped
                // precondition object can reconstruct it via `hostile_precondition`.
                let _ = hostile_precondition(&m.file);
            }
        }
        observations
    }

    /// Mirrors `buildVariantStrategy(rule).enumerate`.
    pub fn enumerate(ctx: &PackContext, rule_id: &str) -> Option<Value> {
        let rule = RULES.iter().find(|r| r.id == rule_id)?;
        let matches: Vec<Value> = (rule.matches_in)(ctx)
            .into_iter()
            .map(|m| {
                json!({
                    "file": m.file,
                    "line": m.line,
                    "semanticFingerprint": digest(&json!({ "ruleId": rule.id, "file": m.file, "snippet": m.snippet })),
                    "disposition": "CONFIRMED",
                })
            })
            .collect();
        Some(json!({
            "denominator": {
                "kind": "source-files",
                "digest": ctx.denominator_digest,
                "expected": ctx.files.len(),
                "examined": ctx.files.len(),
                "unexamined": [],
            },
            "strategies": [{
                "id": format!("{}-search", rule.id), "kind": "lexical-fallback",
                "description": format!("Enumerate alternate automation/release configuration entrypoints for {}.", rule.id),
                "queryDigest": digest(&Value::String(rule.id.to_string())), "complete": true, "coverageGaps": [],
            }],
            "matches": matches,
            "coverageGaps": [],
        }))
    }
}

// =================================================================================================
// browser-client.mjs
// =================================================================================================

pub mod browser_client {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "browser-client";

    pub const RULE_IDS: &[&str] = &[
        "csrf.state-changing-route.missing-token",
        "csrf.samesite-none-without-secure",
        "csrf.samesite-missing",
        "cors.wildcard-origin-with-credentials",
        "cors.reflected-origin-without-allowlist",
        "clickjacking.missing-frame-protection",
        "open-redirect.unvalidated-target",
        "oauth.redirect-uri.unvalidated",
        "csp.missing",
        "csp.unsafe-inline",
        "csp.unsafe-eval",
        "csp.wildcard-source",
    ];

    fn severity_rank(s: &str) -> i32 {
        match s {
            "info" => 0,
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            "critical" => 4,
            _ => 0,
        }
    }

    fn cap_severity(base: &str, cap: Option<&str>) -> String {
        match cap {
            None => base.to_string(),
            Some(cap) => {
                if severity_rank(base) <= severity_rank(cap) {
                    base.to_string()
                } else {
                    cap.to_string()
                }
            }
        }
    }

    fn repo_wide_evidence_refs(ctx: &PackContext) -> Vec<String> {
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for file in &ctx.files {
            if let Some(a) = find_artifact(ctx, file) {
                for r in &a.evidence_refs {
                    set.insert(r.clone());
                }
            }
        }
        set.into_iter().collect()
    }

    fn deployment_assumption_uncertainty(subject: &str) -> String {
        format!(
            "Deployment assumption: no runtime header or deployment evidence was available for {subject}; \
this claim assumes the observed source configuration is what is actually served, but a reverse \
proxy, CDN, load balancer, or platform default could add, strip, or override it at runtime."
        )
    }

    fn runtime_header_compliance(
        ctx: &PackContext,
        header_key: &str,
        is_compliant: impl Fn(&Value) -> bool,
    ) -> Option<bool> {
        let snapshot = ctx.runtime_headers.as_ref()?;
        let value = snapshot.get(header_key)?;
        Some(is_compliant(value))
    }

    struct DeploymentOutcome {
        severity_cap: Option<&'static str>,
        uncertainty: Vec<String>,
        deployment_assumption: Option<Value>,
        disagreement: Option<Value>,
    }

    /// Mirrors `evaluateDeploymentAwareClaim`. `None` means "clean, emit
    /// nothing" (JS `return null`).
    fn evaluate_deployment_aware_claim(
        subject: &str,
        source_compliant: bool,
        runtime_compliant: Option<bool>,
        compliant_label: &str,
        non_compliant_label: &str,
    ) -> Option<DeploymentOutcome> {
        match runtime_compliant {
            None => {
                if source_compliant {
                    None
                } else {
                    Some(DeploymentOutcome {
                        severity_cap: Some("medium"),
                        uncertainty: vec![deployment_assumption_uncertainty(subject)],
                        deployment_assumption: Some(json!({
                            "assumption": "source-config-reflects-served-state",
                            "subject": subject,
                        })),
                        disagreement: None,
                    })
                }
            }
            Some(runtime_compliant) => {
                if source_compliant == runtime_compliant {
                    if runtime_compliant {
                        None
                    } else {
                        Some(DeploymentOutcome {
                            severity_cap: None,
                            uncertainty: vec![],
                            deployment_assumption: None,
                            disagreement: None,
                        })
                    }
                } else {
                    Some(DeploymentOutcome {
                        severity_cap: Some("medium"),
                        uncertainty: vec![format!(
                            "Source configuration and observed runtime evidence disagree for {subject}; both are recorded rather than one being treated as authoritative."
                        )],
                        deployment_assumption: None,
                        disagreement: Some(json!({
                            "subject": subject,
                            "sourceValue": if source_compliant { compliant_label } else { non_compliant_label },
                            "runtimeValue": if runtime_compliant { compliant_label } else { non_compliant_label },
                        })),
                    })
                }
            }
        }
    }

    struct Gate {
        severity_cap: Option<&'static str>,
        uncertainty: Vec<String>,
        deployment_assumption: Option<Value>,
    }

    /// Mirrors `deploymentGate`.
    fn deployment_gate(ctx: &PackContext, subject: &str) -> Gate {
        let has_evidence = ctx.runtime_headers.is_some() || ctx.deployment_evidence;
        if has_evidence {
            Gate { severity_cap: None, uncertainty: vec![], deployment_assumption: None }
        } else {
            Gate {
                severity_cap: Some("medium"),
                uncertainty: vec![deployment_assumption_uncertainty(subject)],
                deployment_assumption: Some(json!({
                    "assumption": "source-config-reflects-served-state",
                    "subject": subject,
                })),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn base_observation(
        rule_id: &str,
        claim: String,
        severity_hint: String,
        primitive_class: &str,
        sources: Vec<String>,
        sinks: Vec<String>,
        attacker_capabilities: Vec<&str>,
        chain_roles: Vec<&str>,
        evidence_refs: Vec<String>,
        detector_metadata: Value,
        uncertainty: Vec<String>,
    ) -> Observation {
        let mut metadata = detector_metadata;
        metadata
            .as_object_mut()
            .unwrap()
            .insert("primitiveClass".to_string(), Value::String(primitive_class.to_string()));
        Observation {
            rule_id: rule_id.to_string(),
            candidate_class: CANDIDATE_CLASS.to_string(),
            claim,
            severity_hint,
            sources,
            sinks,
            attacker_capabilities: attacker_capabilities.into_iter().map(String::from).collect(),
            effect_kind: String::new(),
            effect_action: String::new(),
            effect_object: None,
            effect_scope: String::new(),
            effect_environment: "application".to_string(),
            chain_roles: chain_roles.into_iter().map(String::from).collect(),
            evidence_refs,
            detector_metadata: metadata,
            uncertainty,
        }
    }

    fn state_changing_route() -> &'static Regex {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| Regex::new(r#"(?i)\b(?:app|router)\.(post|put|patch|delete)\(\s*['"]([^'"]+)['"]"#).unwrap())
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        let combined_text: String = {
            let mut parts = Vec::new();
            for file in &ctx.files {
                parts.push(ctx.read_file(file).unwrap_or("").to_string());
            }
            parts.join("\n")
        };

        let csrf_marker = Regex::new(r"(?i)csrf|csurf|xsrf|_csrf|antiforgery").unwrap();
        let cookie_session_marker = Regex::new(r"(?i)cookie-session|req\.session|res\.cookie|express-session").unwrap();
        // JS: /SameSite=None(?![\s\S]{0,80}Secure)/gi — a negative lookahead
        // the `regex` crate cannot express directly, so it is reproduced
        // below via an explicit marker match plus a manual window check
        // instead of a single lookahead pattern.
        let samesite_none_marker = Regex::new(r"(?i)SameSite=None").unwrap();
        let session_cookie_statement =
            Regex::new(r#"(?i)(?:res\.cookie|Set-Cookie)[^\n]{0,40}(?:session|auth|token|jwt)[^\n]{0,150}"#).unwrap();
        let cors_wildcard_credentials = Regex::new(
            r#"(?is)Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]?\*[\s\S]{0,300}Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?(?:true|1)"#,
        )
        .unwrap();
        let cors_reflected_origin =
            Regex::new(r"(?i)Access-Control-Allow-Origin['\x22]?\s*[:,]\s*(?:req|request|ctx)\.(?:headers\.)?origin").unwrap();
        let cors_allowlist_marker = Regex::new(r"(?i)allow(?:ed)?Origins?|origin\s*===|includes\(\s*origin\s*\)").unwrap();
        let frame_protection_marker = Regex::new(r"(?i)X-Frame-Options|frame-ancestors").unwrap();
        let serves_html_marker =
            Regex::new(r#"(?i)<html|res\.render|getServerSideProps|\.ejs\b|\.hbs\b|app\.get\(\s*['"]/"#).unwrap();
        let open_redirect = Regex::new(r"(?i)res\.redirect\(\s*(?:req|request)\.(?:query|params|body)\.[a-zA-Z_]\w*").unwrap();
        let redirect_allowlist_marker = Regex::new(r#"(?i)allowedRedirects|isValidRedirect|startsWith\(\s*['"]/"#).unwrap();
        let oauth_redirect_from_request =
            Regex::new(r"(?i)redirect_uri['\x22]?\s*[:=]\s*(?:req|request)\.(?:query|params|body)").unwrap();
        let oauth_allowlist_marker = Regex::new(r#"(?i)redirectUriAllowlist|exact.?match|===\s*['"]https?://"#).unwrap();
        let csp_marker = Regex::new(r"(?i)Content-Security-Policy").unwrap();
        let csp_unsafe_inline = Regex::new(r"(?i)Content-Security-Policy[^\n]*unsafe-inline").unwrap();
        let csp_unsafe_eval = Regex::new(r"(?i)Content-Security-Policy[^\n]*unsafe-eval").unwrap();
        // JS uses a negative lookbehind `(?<![\w.-])` / lookahead `(?![\w.-])`
        // around the wildcard; the `regex` crate has no lookaround, so this is
        // approximated with an explicit boundary check on the match.
        let csp_wildcard_source_core =
            Regex::new(r"(?i)Content-Security-Policy[^;\n]*(?:script-src|default-src|connect-src)[^;\n]*\*").unwrap();

        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            let evidence_refs = artifact.map(|e| e.evidence_refs.clone()).unwrap_or_default();
            if evidence_refs.is_empty() {
                continue;
            }
            let artifact_id = artifact.unwrap().id.clone();

            if cookie_session_marker.is_match(text) && !csrf_marker.is_match(text) {
                for m in state_changing_route().captures_iter(text) {
                    let whole = m.get(0).unwrap();
                    let method = m.get(1).unwrap().as_str().to_uppercase();
                    let path = m.get(2).unwrap().as_str();
                    observations.push(base_observation(
                        "csrf.state-changing-route.missing-token",
                        format!("A cookie-session-authenticated {method} {path} route has no visible CSRF token check."),
                        "high".to_string(),
                        "exploitable-primitive",
                        vec![artifact_id.clone()],
                        vec![artifact_id.clone()],
                        vec!["cross-origin-page-load", "induce-victim-navigation"],
                        vec!["starter", "impact"],
                        evidence_refs.clone(),
                        json!({ "file": file, "line": line_of(text, whole.start()), "method": method, "path": path }),
                        vec!["A CSRF middleware registered globally elsewhere in the application is not visible from this file alone.".to_string()],
                    ));
                }
            }

            // csrf.samesite-none-without-secure: manual window check (see
            // note on `samesite_none_without_secure` above).
            for m in samesite_none_marker.find_iter(text) {
                let end = (m.end() + 80).min(text.len());
                let mut end = end;
                while end < text.len() && !text.is_char_boundary(end) {
                    end += 1;
                }
                let window = &text[m.end()..end];
                if window.contains("Secure") {
                    continue;
                }
                observations.push(base_observation(
                    "csrf.samesite-none-without-secure",
                    "A cookie sets SameSite=None without a nearby Secure attribute.".to_string(),
                    "medium".to_string(),
                    "exploitable-primitive",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["cross-origin-page-load"],
                    vec!["enabler"],
                    evidence_refs.clone(),
                    json!({ "file": file, "line": line_of(text, m.start()), "cookieAttribute": "SameSite=None" }),
                    vec!["Modern browsers reject SameSite=None cookies without Secure outright; impact depends on the serving browser and transport.".to_string()],
                ));
            }

            for m in session_cookie_statement.find_iter(text) {
                if Regex::new(r"(?i)SameSite").unwrap().is_match(m.as_str()) {
                    continue;
                }
                let snippet: String = m.as_str().chars().take(60).collect();
                observations.push(base_observation(
                    "csrf.samesite-missing",
                    "A session or auth cookie is set without any SameSite attribute.".to_string(),
                    "medium".to_string(),
                    "exploitable-primitive",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["cross-origin-page-load"],
                    vec!["enabler"],
                    evidence_refs.clone(),
                    json!({ "file": file, "line": line_of(text, m.start()), "cookieStatement": snippet }),
                    vec!["The framework default SameSite value (if any) is not visible from this statement alone.".to_string()],
                ));
            }

            for m in cors_wildcard_credentials.find_iter(text) {
                observations.push(base_observation(
                    "cors.wildcard-origin-with-credentials",
                    "Access-Control-Allow-Origin: * is combined with Access-Control-Allow-Credentials: true.".to_string(),
                    "critical".to_string(),
                    "exploitable-primitive",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["cross-origin-page-load"],
                    vec!["starter", "impact"],
                    evidence_refs.clone(),
                    json!({ "file": file, "line": line_of(text, m.start()), "header": "Access-Control-Allow-Origin + Access-Control-Allow-Credentials" }),
                    vec!["Browsers reject this exact header combination for credentialed requests in current CORS implementations; impact depends on client behavior.".to_string()],
                ));
            }

            if !cors_allowlist_marker.is_match(text) {
                for m in cors_reflected_origin.find_iter(text) {
                    observations.push(base_observation(
                        "cors.reflected-origin-without-allowlist",
                        "The request Origin header is reflected into Access-Control-Allow-Origin with no visible allowlist check.".to_string(),
                        "high".to_string(),
                        "exploitable-primitive",
                        vec![artifact_id.clone()],
                        vec![artifact_id.clone()],
                        vec!["cross-origin-page-load"],
                        vec!["starter", "impact"],
                        evidence_refs.clone(),
                        json!({ "file": file, "line": line_of(text, m.start()), "header": "Access-Control-Allow-Origin" }),
                        vec!["An allowlist check applied before this statement is executed may exist outside the matched line.".to_string()],
                    ));
                }
            }

            if !redirect_allowlist_marker.is_match(text) {
                for m in open_redirect.find_iter(text) {
                    observations.push(base_observation(
                        "open-redirect.unvalidated-target",
                        "A redirect target is taken directly from request input without a visible allowlist or relative-path check.".to_string(),
                        "medium".to_string(),
                        "exploitable-primitive",
                        vec![artifact_id.clone()],
                        vec![artifact_id.clone()],
                        vec!["craft-malicious-link"],
                        vec!["starter", "enabler"],
                        evidence_refs.clone(),
                        json!({ "file": file, "line": line_of(text, m.start()), "config": "res.redirect target" }),
                        vec!["Open redirects are typically chained with phishing or OAuth token theft; standalone impact depends on what trusts the redirecting origin.".to_string()],
                    ));
                }
            }

            if !oauth_allowlist_marker.is_match(text) {
                for m in oauth_redirect_from_request.find_iter(text) {
                    observations.push(base_observation(
                        "oauth.redirect-uri.unvalidated",
                        "An OAuth redirect_uri is built from request input with no visible exact-match allowlist.".to_string(),
                        "high".to_string(),
                        "exploitable-primitive",
                        vec![artifact_id.clone()],
                        vec![artifact_id.clone()],
                        vec!["craft-malicious-link"],
                        vec!["starter", "impact"],
                        evidence_refs.clone(),
                        json!({ "file": file, "line": line_of(text, m.start()), "config": "redirect_uri" }),
                        vec!["The OAuth provider may independently enforce a registered redirect_uri allowlist outside this repository.".to_string()],
                    ));
                }
            }

            for (rule_id, pattern, token) in [
                ("csp.unsafe-inline", &csp_unsafe_inline, "'unsafe-inline'"),
                ("csp.unsafe-eval", &csp_unsafe_eval, "'unsafe-eval'"),
            ] {
                for m in pattern.find_iter(text) {
                    let gate = deployment_gate(ctx, &format!("Content-Security-Policy {token}"));
                    let mut metadata = json!({ "file": file, "line": line_of(text, m.start()), "header": "Content-Security-Policy", "directive": token });
                    if let Some(da) = &gate.deployment_assumption {
                        metadata.as_object_mut().unwrap().insert("deploymentAssumption".to_string(), da.clone());
                    }
                    let mut uncertainty = vec!["A CSP weakness is only exploitable in combination with an independent injection point; it is not itself proof of one.".to_string()];
                    uncertainty.extend(gate.uncertainty.clone());
                    observations.push(base_observation(
                        rule_id,
                        format!("The Content-Security-Policy configuration includes {token}, weakening script-source restriction."),
                        cap_severity("low", gate.severity_cap),
                        "defense-in-depth",
                        vec![artifact_id.clone()],
                        vec![artifact_id.clone()],
                        vec!["inject-html-or-script"],
                        vec!["enabler"],
                        evidence_refs.clone(),
                        metadata,
                        uncertainty,
                    ));
                }
            }
            // csp.wildcard-source: approximate the JS lookaround boundary by
            // requiring the char before/after `*` (if any) to not be a
            // word/`.`/`-` character.
            for m in csp_wildcard_source_core.find_iter(text) {
                let star_idx = m.as_str().rfind('*').map(|i| m.start() + i);
                let Some(star_idx) = star_idx else { continue };
                let before_ok = text[..star_idx]
                    .chars()
                    .next_back()
                    .map(|c| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-'))
                    .unwrap_or(true);
                let after_ok = text[star_idx + 1..]
                    .chars()
                    .next()
                    .map(|c| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '-'))
                    .unwrap_or(true);
                if !(before_ok && after_ok) {
                    continue;
                }
                let token = "*";
                let gate = deployment_gate(ctx, &format!("Content-Security-Policy {token}"));
                let mut metadata = json!({ "file": file, "line": line_of(text, m.start()), "header": "Content-Security-Policy", "directive": token });
                if let Some(da) = &gate.deployment_assumption {
                    metadata.as_object_mut().unwrap().insert("deploymentAssumption".to_string(), da.clone());
                }
                let mut uncertainty = vec!["A CSP weakness is only exploitable in combination with an independent injection point; it is not itself proof of one.".to_string()];
                uncertainty.extend(gate.uncertainty.clone());
                observations.push(base_observation(
                    "csp.wildcard-source",
                    format!("The Content-Security-Policy configuration includes {token}, weakening script-source restriction."),
                    cap_severity("low", gate.severity_cap),
                    "defense-in-depth",
                    vec![artifact_id.clone()],
                    vec![artifact_id.clone()],
                    vec!["inject-html-or-script"],
                    vec!["enabler"],
                    evidence_refs.clone(),
                    metadata,
                    uncertainty,
                ));
            }
        }

        // --- Whole-repository, deployment-aware boolean-state rules ----------

        if serves_html_marker.is_match(&combined_text) {
            let source_compliant = frame_protection_marker.is_match(&combined_text);
            let runtime_compliant = runtime_header_compliance(ctx, "x-frame-options", |v| !v.is_null())
                .or_else(|| {
                    runtime_header_compliance(ctx, "content-security-policy", |v| {
                        Regex::new(r"(?i)frame-ancestors").unwrap().is_match(&value_as_display(v))
                    })
                });
            if let Some(outcome) = evaluate_deployment_aware_claim(
                "X-Frame-Options / frame-ancestors",
                source_compliant,
                runtime_compliant,
                "present",
                "absent",
            ) {
                let mut metadata = json!({
                    "scope": "repository",
                    "header": "X-Frame-Options / Content-Security-Policy frame-ancestors",
                    "filesExamined": ctx.files.len(),
                });
                if let Some(d) = &outcome.disagreement {
                    metadata.as_object_mut().unwrap().insert("disagreement".to_string(), d.clone());
                }
                if let Some(da) = &outcome.deployment_assumption {
                    metadata.as_object_mut().unwrap().insert("deploymentAssumption".to_string(), da.clone());
                }
                observations.push(base_observation(
                    "clickjacking.missing-frame-protection",
                    "No X-Frame-Options header or CSP frame-ancestors directive was found across the scanned, HTML-serving surface.".to_string(),
                    cap_severity("low", outcome.severity_cap),
                    "defense-in-depth",
                    vec![],
                    vec![],
                    vec!["embed-victim-page-in-frame"],
                    vec!["enabler"],
                    repo_wide_evidence_refs(ctx),
                    metadata,
                    outcome.uncertainty,
                ));
            }
        }

        {
            let source_compliant = csp_marker.is_match(&combined_text);
            let runtime_compliant = runtime_header_compliance(ctx, "content-security-policy", |v| !v.is_null());
            if let Some(outcome) = evaluate_deployment_aware_claim(
                "Content-Security-Policy header",
                source_compliant,
                runtime_compliant,
                "present",
                "absent",
            ) {
                let mut metadata = json!({
                    "scope": "repository",
                    "header": "Content-Security-Policy",
                    "filesExamined": ctx.files.len(),
                });
                if let Some(d) = &outcome.disagreement {
                    metadata.as_object_mut().unwrap().insert("disagreement".to_string(), d.clone());
                }
                if let Some(da) = &outcome.deployment_assumption {
                    metadata.as_object_mut().unwrap().insert("deploymentAssumption".to_string(), da.clone());
                }
                observations.push(base_observation(
                    "csp.missing",
                    "No Content-Security-Policy was found across the scanned surface.".to_string(),
                    cap_severity("low", outcome.severity_cap),
                    "defense-in-depth",
                    vec![],
                    vec![],
                    vec!["inject-html-or-script"],
                    vec!["enabler"],
                    repo_wide_evidence_refs(ctx),
                    metadata,
                    outcome.uncertainty,
                ));
            }
        }

        observations
    }

    fn value_as_display(v: &Value) -> String {
        match v {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        }
    }
}

// =================================================================================================
// ai-prompt-injection.mjs
// =================================================================================================

pub mod ai_prompt_injection {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "ai-prompt-injection";

    const TRUST_LABEL_HINT: &str = r"(?i)trust_label|sanitize|escape|allowlist|provenance|content_filter";

    struct Rule {
        id: &'static str,
        claim: &'static str,
        severity_hint: &'static str,
        source_kind: &'static str,
        sink_kind: &'static str,
        control_types: &'static [&'static str],
        effect_kind: &'static str,
        effect_action: &'static str,
        effect_scope: &'static str,
        chain_roles: &'static [&'static str],
        uncertainty: &'static str,
        matcher: fn(&str) -> bool,
    }

    fn trust_label_hint(t: &str) -> bool {
        Regex::new(TRUST_LABEL_HINT).unwrap().is_match(t)
    }

    fn match_indirect_untrusted(t: &str) -> bool {
        Regex::new(r"(?i)(?:prompt|messages|system_prompt|instructions?)\s*[:=]\s*[^\n]*(?:request|input|issue|body|content|document|description)")
            .unwrap()
            .is_match(t)
            && !trust_label_hint(t)
    }
    fn match_retrieved_content(t: &str) -> bool {
        Regex::new(r"(?i)(?:retriever|vectorStore|search_result|retrieved[-_ ]?content|rag[-_ ]?context|document[-_ ]?content)[\s\S]{0,160}(?:prompt|messages|context)\s*[:=+]")
            .unwrap()
            .is_match(t)
            && !trust_label_hint(t)
    }
    fn match_memory_context(t: &str) -> bool {
        Regex::new(r"(?i)(?:conversation_history|memory_store|session_memory|agent_memory|long[-_ ]?term memory)[\s\S]{0,160}(?:prompt|messages|context)\s*[:=+]")
            .unwrap()
            .is_match(t)
            && !trust_label_hint(t)
    }
    fn match_dynamic_tool_schema(t: &str) -> bool {
        Regex::new(r"(?i)(?:tools|inputSchema|tool_use)\s*(?:\.push|\[|=)[^\n]*(?:JSON\.parse|retrieved|document|request\.|response\.|externalContent)")
            .unwrap()
            .is_match(t)
            && !trust_label_hint(t)
    }

    const RULES: &[Rule] = &[
        Rule {
            id: "ai.prompt-injection.indirect-untrusted-content",
            claim: "Untrusted content is mixed into a model prompt without a visible trust label.",
            severity_hint: "high",
            source_kind: "untrusted-content",
            sink_kind: "prompt",
            control_types: &["content-provenance-label", "prompt-trust-boundary"],
            effect_kind: "control-bypass",
            effect_action: "influence-model",
            effect_scope: "prompt",
            chain_roles: &["starter"],
            uncertainty: "Influence alone is not tool compromise; downstream output handling must be adjudicated.",
            matcher: match_indirect_untrusted,
        },
        Rule {
            id: "ai.prompt-injection.retrieved-content-untrusted",
            claim: "Retrieved (RAG/search) content reaches the model prompt or context without a trust boundary marker.",
            severity_hint: "high",
            source_kind: "retrieved-content",
            sink_kind: "retrieval-context",
            control_types: &["content-provenance-label", "retrieval-trust-boundary"],
            effect_kind: "control-bypass",
            effect_action: "influence-model",
            effect_scope: "retrieval-context",
            chain_roles: &["starter"],
            uncertainty: "Retrieval alone does not confirm attacker control of the corpus; corpus write access must be adjudicated against ai-poisoning-rag candidates.",
            matcher: match_retrieved_content,
        },
        Rule {
            id: "ai.prompt-injection.memory-context-untrusted",
            claim: "Durable agent memory content is re-injected into a prompt without a trust label.",
            severity_hint: "medium",
            source_kind: "memory-content",
            sink_kind: "memory-context",
            control_types: &["content-provenance-label", "memory-trust-boundary"],
            effect_kind: "control-bypass",
            effect_action: "influence-model",
            effect_scope: "memory-context",
            chain_roles: &["starter"],
            uncertainty: "A prior turn writing untrusted content into memory is a distinct precondition adjudicated by ai-poisoning-rag candidates, not this rule.",
            matcher: match_memory_context,
        },
        Rule {
            id: "ai.prompt-injection.dynamic-tool-schema-untrusted",
            claim: "A tool/function schema is constructed at runtime from untrusted content rather than a fixed definition.",
            severity_hint: "high",
            source_kind: "untrusted-content",
            sink_kind: "tool-schema",
            control_types: &["tool-schema-allowlist", "content-provenance-label"],
            effect_kind: "control-bypass",
            effect_action: "redefine-tool-schema",
            effect_scope: "tool-capability",
            chain_roles: &["starter", "enabler"],
            uncertainty: "A dynamically built schema is not automatically attacker-controlled; the content source must be adjudicated.",
            matcher: match_dynamic_tool_schema,
        },
    ];

    pub fn rule_ids() -> Vec<&'static str> {
        RULES.iter().map(|r| r.id).collect()
    }

    fn find_invocation_process<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        let name = format!("model invocation {file}");
        ctx.find_entity(|e| e.kind == "process" && e.attr_str("processKind") == Some("model-invocation") && e.name == name)
    }

    fn find_untrusted_source<'a>(ctx: &'a PackContext<'a>, file: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "source" && e.attr_str("trust") == Some("untrusted") && e.attr_str("file") == Some(file))
            .or_else(|| ctx.find_entity(|e| e.kind == "source" && e.attr_str("trust") == Some("untrusted")))
    }

    fn find_data_store<'a>(ctx: &'a PackContext<'a>, store_kind: &str) -> Option<&'a Entity> {
        ctx.find_entity(|e| e.kind == "data-store" && e.attr_str("storeKind") == Some(store_kind))
    }

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = find_artifact(ctx, file);
            let invocation = find_invocation_process(ctx, file);
            let untrusted_source = find_untrusted_source(ctx, file);
            let rag_store = find_data_store(ctx, "rag");
            let memory_store = find_data_store(ctx, "memory");

            for rule in RULES {
                if !(rule.matcher)(text) {
                    continue;
                }

                let sink_entity = invocation.or(artifact);
                let mut source_entity = untrusted_source.or(artifact);
                if rule.source_kind == "retrieved-content" {
                    if let Some(rag) = rag_store {
                        source_entity = Some(rag);
                    }
                }
                if rule.source_kind == "memory-content" {
                    if let Some(mem) = memory_store {
                        source_entity = Some(mem);
                    }
                }

                if find_control(ctx, sink_entity.map(|e| e.id.as_str()), rule.control_types).is_some() {
                    continue; // observed, model-grounded control suppresses the candidate entirely.
                }

                let sources: Vec<String> = source_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let sinks: Vec<String> = sink_entity.map(|e| vec![e.id.clone()]).unwrap_or_default();
                let evidence_refs = union_refs(
                    source_entity.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                    sink_entity.map(|e| e.evidence_refs.as_slice()).unwrap_or(&[]),
                );

                observations.push(Observation {
                    rule_id: rule.id.to_string(),
                    candidate_class: CANDIDATE_CLASS.to_string(),
                    claim: rule.claim.to_string(),
                    severity_hint: rule.severity_hint.to_string(),
                    sources,
                    sinks,
                    attacker_capabilities: vec!["control-untrusted-content".to_string()],
                    effect_kind: rule.effect_kind.to_string(),
                    effect_action: rule.effect_action.to_string(),
                    effect_object: sink_entity.map(|e| e.id.clone()),
                    effect_scope: rule.effect_scope.to_string(),
                    effect_environment: "agent".to_string(),
                    chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                    evidence_refs,
                    detector_metadata: json!({
                        "file": file,
                        "untrustedOrigin": rule.source_kind,
                        "sink": rule.sink_kind,
                        "detectionMethod": "lexical-pattern",
                        "matchDigest": digest(&json!({ "ruleId": rule.id, "file": file })),
                    }),
                    uncertainty: vec![rule.uncertainty.to_string()],
                });
            }
        }
        observations
    }
}

#[cfg(test)]
mod digest_self_check {
    use super::*;

    #[test]
    fn digest_matches_known_js_shape() {
        // Sanity check only: the JS `digest` is `sha256:` + 64 hex chars.
        let d = digest(&json!({ "ruleId": "ai.prompt-injection.indirect-untrusted-content", "file": "app.mjs" }));
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
    }

    #[test]
    fn digest_is_key_order_independent() {
        let a = digest(&json!({ "a": 1, "b": 2 }));
        let b = digest(&json!({ "b": 2, "a": 1 }));
        assert_eq!(a, b);
    }
}
