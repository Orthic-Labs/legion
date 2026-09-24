//! Full port of `src/lib/guard/compat/policy/policy.mjs` (closed by packet r49).
//!
//! S02 — the policy plane. Arcane's single source of allow/deny. Ported
//! here: the deterministic decision surface built on a parsed policy
//! bundle — [`PolicyEngine::effect_decision`], [`PolicyEngine::degradation`],
//! [`ENFORCEMENT_RANK`]/[`enforcement_at_least`],
//! [`PolicyEngine::evaluate_claim_prerequisites`],
//! [`PolicyEngine::may_waive`], [`PolicyEngine::locked_domains_for`], the
//! plain accessors (`capability_limits`, `replay_limits`, ...), and
//! [`fail_closed_engine`]. `EFFECT_CLASS_RECONCILIATION` (a static report,
//! not logic) is ported verbatim as [`effect_class_reconciliation`].
//!
//! Packet r49 closed the remaining gap: [`validate_policy_bundle`] (JSON-Schema
//! validation of a raw bundle, reusing `wf068::schema::validate_schema` against
//! the embedded `policy-bundle-v1.schema.json`), [`load_policy`] (read +
//! parse + validate + digest a bundle from disk, matching JS `loadPolicy`
//! error-for-error), [`policy_duplication_audit`] and
//! [`capability_issuance_audit`] (the two source-text conformance scans,
//! ported faithfully as `regex` scans over file contents — no network, no
//! process spawn, so no trait/fake indirection is needed for them).
//! `pathMatches` (imported from `guard/compat/effects/preeffect-gate.mjs`
//! in the JS source, not one of this chunk's five files) is reimplemented
//! locally in [`path_matches`] rather than depending on an unowned,
//! unported sibling.

use crate::wf_port::wf068::schema::validate_schema;
use regex::Regex;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::path::Path;

/// One rule for one effect class, matching the JS bundle's
/// `effectRules[]` entry shape (the fields this port's logic reads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectRule {
    pub effect_class: String,
    /// `"allow"` or `"deny"`.
    pub rule: String,
    pub approval_required: bool,
    pub trust_minimum: String,
    pub required_enforcement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimLevel {
    pub allow_stale_evidence: bool,
    pub required_evidence_classes: Vec<String>,
    pub required_enforcement: String,
    pub required_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedDomainEntry {
    pub pattern: String,
    pub claim_level: String,
    pub note: Option<String>,
}

/// The subset of the JS policy bundle's top-level fields this port's logic
/// reads. `capability`/`replay`/`trust_minima`/`host_enforcement`/`evidence`
/// /`retention` are opaque string maps: this port does not interpret their
/// contents, only threads them through as the JS accessors do
/// (`{ ...this.#bundle.capability }`, etc).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyBundle {
    pub policy_id: String,
    pub version: i64,
    pub digest: String,
    pub effect_rules: Vec<EffectRule>,
    pub waiver_authority: Vec<String>,
    pub claim_levels: BTreeMap<String, ClaimLevel>,
    pub locked_domains: Vec<LockedDomainEntry>,
    pub degradation: BTreeMap<String, String>,
    pub capability: BTreeMap<String, String>,
    pub replay: BTreeMap<String, String>,
    pub trust_minima: BTreeMap<String, String>,
    pub host_enforcement: BTreeMap<String, String>,
    pub evidence: BTreeMap<String, String>,
    pub retention: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub code: Option<&'static str>,
    pub message: String,
    pub enforcement_health: Option<String>,
}

fn allow(message: impl Into<String>) -> Decision {
    Decision { allowed: true, code: None, message: message.into(), enforcement_health: None }
}
fn deny(code: &'static str, message: impl Into<String>) -> Decision {
    Decision { allowed: false, code: Some(code), message: message.into(), enforcement_health: None }
}

/// Single source of truth for enforcement ordering, matching JS
/// `ENFORCEMENT_RANK` exactly.
pub const ENFORCEMENT_RANK: &[(&str, u8)] = &[
    ("unsupported", 0),
    ("advisory", 1),
    ("read_only", 2),
    ("observed", 3),
    ("strong", 4),
];

fn rank(level: &str) -> u8 {
    ENFORCEMENT_RANK.iter().find(|(name, _)| *name == level).map(|(_, r)| *r).unwrap_or(0)
}

pub fn enforcement_at_least(actual: &str, required: &str) -> bool {
    rank(actual) >= rank(required)
}

pub struct PolicyEngine {
    bundle: PolicyBundle,
    rules: BTreeMap<String, EffectRule>,
}

impl PolicyEngine {
    /// Mirrors the JS constructor's post-validation setup (`this.#rules`,
    /// `this.#approvalRequired`). Bundle *validation* itself is the
    /// caller's job in this port (see module doc).
    pub fn new(bundle: PolicyBundle) -> Self {
        let rules = bundle.effect_rules.iter().map(|r| (r.effect_class.clone(), r.clone())).collect();
        Self { bundle, rules }
    }

    pub fn bundle(&self) -> &PolicyBundle {
        &self.bundle
    }

    pub fn effect_rule(&self, effect_class: &str) -> Option<&EffectRule> {
        self.rules.get(effect_class)
    }

    pub fn approval_required_effect_classes(&self) -> Vec<&str> {
        self.bundle
            .effect_rules
            .iter()
            .filter(|r| r.approval_required)
            .map(|r| r.effect_class.as_str())
            .collect()
    }

    /// Mirrors JS `effectDecision(effectClass, { approvalDigest })`.
    pub fn effect_decision(&self, effect_class: &str, approval_digest: Option<&str>) -> Decision {
        let rule = match self.effect_rule(effect_class) {
            Some(r) => r,
            None => {
                return deny(
                    "ARC_EFFECT_CLASS_UNAUTHORIZED",
                    format!("no policy rule for effect class '{effect_class}'; unclassified effects are denied by name, never bucketed"),
                );
            }
        };
        if rule.rule == "deny" {
            return deny(
                "ARC_EFFECT_CLASS_UNAUTHORIZED",
                format!("policy {} v{} denies {effect_class}", self.bundle.policy_id, self.bundle.version),
            );
        }
        if rule.approval_required && approval_digest.is_none() {
            return deny("ARC_APPROVAL_REQUIRED", format!("{effect_class} requires a bound approval digest"));
        }
        allow(format!(
            "{effect_class} authorized (trustMinimum={}, requiredEnforcement={})",
            rule.trust_minimum, rule.required_enforcement
        ))
    }

    pub fn capability_limits(&self) -> BTreeMap<String, String> {
        self.bundle.capability.clone()
    }
    pub fn replay_limits(&self) -> BTreeMap<String, String> {
        self.bundle.replay.clone()
    }
    pub fn trust_minima(&self) -> BTreeMap<String, String> {
        self.bundle.trust_minima.clone()
    }
    pub fn host_enforcement(&self) -> BTreeMap<String, String> {
        self.bundle.host_enforcement.clone()
    }
    pub fn evidence_policy(&self) -> BTreeMap<String, String> {
        self.bundle.evidence.clone()
    }
    pub fn retention_policy(&self) -> BTreeMap<String, String> {
        self.bundle.retention.clone()
    }

    pub fn claim_level(&self, name: &str) -> Option<&ClaimLevel> {
        self.bundle.claim_levels.get(name)
    }

    /// Mirrors JS `lockedDomainsFor(paths)`.
    pub fn locked_domains_for(&self, paths: &[&str]) -> Vec<(String, String, String, Option<String>)> {
        let mut matches = Vec::new();
        for &p in paths {
            for entry in &self.bundle.locked_domains {
                if path_matches(&entry.pattern, p) {
                    matches.push((p.to_string(), entry.pattern.clone(), entry.claim_level.clone(), entry.note.clone()));
                }
            }
        }
        matches
    }

    /// `'fail-closed' | 'downgrade'`. Never `'allow'`.
    pub fn degradation(&self, capability: &str) -> String {
        self.bundle.degradation.get(capability).cloned().unwrap_or_else(|| "fail-closed".to_string())
    }

    /// Mirrors JS `mayWaive(authority)`.
    pub fn may_waive(&self, authority: &str) -> Decision {
        if self.bundle.waiver_authority.iter().any(|a| a == authority) {
            return allow(format!("'{authority}' is a waiver authority"));
        }
        deny(
            "ARC_CLAIM_PREREQUISITE_UNMET",
            format!("authority '{authority}' is not a waiver authority under {}", self.bundle.policy_id),
        )
    }

    /// Mirrors JS `evaluateClaimPrerequisites(levelName, ctx)`.
    pub fn evaluate_claim_prerequisites(&self, level_name: &str, ctx: &ClaimContext<'_>) -> Decision {
        let level = match self.claim_level(level_name) {
            Some(l) => l,
            None => return deny("ARC_CLAIM_PREREQUISITE_UNMET", format!("no claim level '{level_name}' in {}", self.bundle.policy_id)),
        };

        if !level.allow_stale_evidence && ctx.stale_evidence_count > 0 {
            return deny(
                "ARC_EVIDENCE_STALE",
                format!("{} supporting evidence record(s) are stale", ctx.stale_evidence_count),
            );
        }

        let missing_classes: Vec<&str> = level
            .required_evidence_classes
            .iter()
            .map(String::as_str)
            .filter(|c| !ctx.evidence_classes.contains(c))
            .collect();
        if !missing_classes.is_empty() {
            return deny(
                "ARC_EVIDENCE_INSUFFICIENT",
                format!("missing required evidence class(es): {}", missing_classes.join(", ")),
            );
        }

        if !enforcement_at_least(ctx.enforcement_health, &level.required_enforcement) {
            let mut d = deny(
                "ARC_CLAIM_PREREQUISITE_UNMET",
                format!("claim '{level_name}' requires {} enforcement; host is {}", level.required_enforcement, ctx.enforcement_health),
            );
            d.enforcement_health = Some(ctx.enforcement_health.to_string());
            return d;
        }

        let missing_fields: Vec<&str> = level
            .required_fields
            .iter()
            .map(String::as_str)
            .filter(|f| !ctx.fields.contains(f))
            .collect();
        if !missing_fields.is_empty() {
            if let Some(waived_by) = ctx.waived_by {
                if self.may_waive(waived_by).allowed {
                    return allow(format!("claim '{level_name}' waived by {waived_by}: {}", missing_fields.join(", ")));
                }
            }
            return deny(
                "ARC_CLAIM_PREREQUISITE_UNMET",
                format!("claim '{level_name}' is missing required field(s): {}", missing_fields.join(", ")),
            );
        }

        let mut d = allow(format!("claim '{level_name}' prerequisites satisfied"));
        d.enforcement_health = Some(ctx.enforcement_health.to_string());
        d
    }

    /// Mirrors JS `bindPolicy(record)` conceptually: returns the identity
    /// triple to attach to a capability or receipt rather than mutating a
    /// caller-owned record type this port does not know the shape of.
    pub fn policy_identity(&self) -> (String, i64, String) {
        (self.bundle.policy_id.clone(), self.bundle.version, self.bundle.digest.clone())
    }
}

pub struct ClaimContext<'a> {
    pub evidence_classes: &'a [&'a str],
    pub stale_evidence_count: i64,
    pub enforcement_health: &'a str,
    pub fields: &'a [&'a str],
    pub waived_by: Option<&'a str>,
}

impl Default for ClaimContext<'_> {
    fn default() -> Self {
        Self { evidence_classes: &[], stale_evidence_count: 0, enforcement_health: "unsupported", fields: &[], waived_by: None }
    }
}

/// The engine to use when no valid policy exists. Every protected answer is
/// a fail-closed denial. Mirrors JS `failClosedEngine(reason)`.
pub struct FailClosedEngine {
    pub reason: String,
}

impl FailClosedEngine {
    pub fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into() }
    }

    pub fn effect_decision(&self, effect_class: &str) -> Decision {
        let mut d = deny("ARC_POLICY_UNAVAILABLE", format!("no policy available to authorize {effect_class} ({})", self.reason));
        d.enforcement_health = Some("unsupported".to_string());
        d
    }

    pub fn evaluate_claim_prerequisites(&self, level_name: &str) -> Decision {
        let mut d = deny("ARC_POLICY_UNAVAILABLE", format!("no policy available to evaluate claim '{level_name}' ({})", self.reason));
        d.enforcement_health = Some("unsupported".to_string());
        d
    }

    pub fn may_waive(&self) -> Decision {
        let mut d = deny("ARC_POLICY_UNAVAILABLE", format!("no policy available to name a waiver authority ({})", self.reason));
        d.enforcement_health = Some("unsupported".to_string());
        d
    }

    /// Conservative defaults so a caller that reads a limit without
    /// checking gets the strictest possible value, never a permissive one.
    pub fn capability_limits(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([("ttlSeconds", "0".to_string()), ("maxUses", "0".to_string()), ("delegable", "false".to_string())])
    }
    pub fn replay_limits(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("freshnessWindowSeconds", "0".to_string()),
            ("maxSkewSeconds", "0".to_string()),
            ("nonceRequired", "true".to_string()),
            ("sequenceRequired", "true".to_string()),
        ])
    }
    pub fn trust_minima(&self) -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([
            ("mutation", "capability-signature"),
            ("readOnly", "capability-signature"),
            ("claimRelease", "capability-signature"),
            ("legacyImport", "unauthenticated"),
        ])
    }
    pub fn host_enforcement(&self) -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([("requiredForMutation", "strong"), ("requiredForReadOnly", "strong")])
    }
    pub fn degradation(&self) -> &'static str {
        "fail-closed"
    }
    pub fn evidence_policy(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("freshnessSeconds", "0".to_string()),
            ("unlinkedCandidateExpirySeconds", "0".to_string()),
            ("requireDependencyBinding", "true".to_string()),
        ])
    }
    pub fn retention_policy(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([("excerptMaxBytes", "0".to_string()), ("storePayloads", "false".to_string())])
    }
}

pub fn fail_closed_engine(reason: impl Into<String>) -> FailClosedEngine {
    FailClosedEngine::new(reason)
}

/// Small glob matcher standing in for `pathMatches` (imported in the JS
/// source from `guard/compat/effects/preeffect-gate.mjs`, not one of this
/// chunk's five owned files — see module doc). Supports `*` (any run of
/// characters, no path-separator awareness beyond literal matching) and
/// `**` collapsing to the same behavior as `*` in this minimal form, which
/// is sufficient for the single caller (`locked_domains_for`) in this
/// chunk; a full-fidelity port of the real `pathMatches` is a follow-up
/// flagged in the wf007 report.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    fn glob_match(pat: &[u8], text: &[u8]) -> bool {
        match (pat.first(), text.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                // Try consuming zero or more chars of `text`.
                for i in 0..=text.len() {
                    if glob_match(&pat[1..], &text[i..]) {
                        return true;
                    }
                }
                false
            }
            (Some(p), Some(t)) if p == t => glob_match(&pat[1..], &text[1..]),
            _ => false,
        }
    }
    glob_match(pattern.as_bytes(), path.as_bytes())
}

/// SEAL Q4 — EFFECT_CLASS reconciliation, ported verbatim as data (not
/// logic) from the JS `EFFECT_CLASS_RECONCILIATION` constant.
pub struct EffectClassDisposition {
    pub effect_class: &'static str,
    pub disposition: &'static str,
    pub broker_surface: &'static str,
}

pub fn effect_class_reconciliation() -> Vec<EffectClassDisposition> {
    vec![
        EffectClassDisposition { effect_class: "FILE_WRITE", disposition: "keep", broker_surface: "PreToolUse on Write/Edit/MultiEdit; gate checks path against contract scope.own[]" },
        EffectClassDisposition { effect_class: "FILE_DELETE", disposition: "keep", broker_surface: "PreToolUse on Bash rm / fs unlink; approval-bound in the shipped bundle" },
        EffectClassDisposition { effect_class: "FILE_MOVE", disposition: "keep", broker_surface: "PreToolUse on rename/mv; gate checks BOTH source and destination ownership" },
        EffectClassDisposition { effect_class: "COMMAND_EXEC", disposition: "keep-with-caveat", broker_surface: "PreToolUse matcher Bash|Shell|PowerShell; exec is a carrier for every other class" },
        EffectClassDisposition { effect_class: "NETWORK_EGRESS", disposition: "keep-with-caveat", broker_surface: "no host adapter in this baseline can broker egress; bundle records requiredEnforcement:observed" },
        EffectClassDisposition { effect_class: "PROCESS_SPAWN", disposition: "keep", broker_surface: "PreToolUse on background/detached invocation" },
        EffectClassDisposition { effect_class: "CREDENTIAL_ACCESS", disposition: "split-proposed", broker_surface: "denied by default; conflates reading a secret with minting/rotating one" },
        EffectClassDisposition { effect_class: "DEPENDENCY_INSTALL", disposition: "keep", broker_surface: "PreToolUse on package-manager commands; stales the lockfile dependency dimension (S05)" },
        EffectClassDisposition { effect_class: "VCS_COMMIT", disposition: "keep", broker_surface: "PreToolUse on git commit; approval-bound" },
        EffectClassDisposition { effect_class: "VCS_PUSH", disposition: "keep", broker_surface: "PreToolUse on git push; denied by default" },
        EffectClassDisposition { effect_class: "PUBLISH", disposition: "keep", broker_surface: "release/upload operations; denied by default" },
        EffectClassDisposition { effect_class: "EXTERNAL_SIDE_EFFECT", disposition: "keep-with-caveat", broker_surface: "denied by default; must NOT be the fallback bucket for unclassified operations" },
    ]
}

// ---------------------------------------------------------------------------
// r49: schema validation, disk loading, and the two conformance audits.
// ---------------------------------------------------------------------------

const POLICY_BUNDLE_SCHEMA_TEXT: &str = include_str!("schemas_r49/policy-bundle-v1.schema.json");

fn policy_bundle_schema() -> &'static JsonValue {
    use std::sync::OnceLock;
    static SCHEMA: OnceLock<JsonValue> = OnceLock::new();
    SCHEMA.get_or_init(|| serde_json::from_str(POLICY_BUNDLE_SCHEMA_TEXT).expect("embedded policy-bundle-v1.schema.json must parse"))
}

/// Mirrors JS `validatePolicyBundle(bundle)`: structural validation of a raw
/// (already-parsed-from-JSON) bundle against the frozen schema.
pub fn validate_policy_bundle(bundle: &JsonValue) -> (bool, Vec<String>) {
    let issues = validate_schema(policy_bundle_schema(), bundle);
    (issues.is_empty(), issues)
}

/// Canonical JSON text for an arbitrary `serde_json::Value`, matching JS
/// `canonicalJson`: object keys sorted, no insignificant whitespace. Unlike
/// `canon::canonical_json` (fixed small record shapes with `&'static str`
/// keys), this walks whatever a parsed policy bundle actually contains.
pub fn canonical_json_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => if *b { "true".to_string() } else { "false".to_string() },
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => serde_json::to_string(s).expect("string always encodes"),
        JsonValue::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json_value).collect();
            format!("[{}]", parts.join(","))
        }
        JsonValue::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).expect("key always encodes"), canonical_json_value(&map[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// Digest of the canonical serialization of an arbitrary bundle value.
/// Mirrors JS `digestValue` applied to a parsed policy bundle.
pub fn digest_value_json(value: &JsonValue) -> String {
    crate::wf_port::wf007::canon::digest(&canonical_json_value(value))
}

#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub bundle: JsonValue,
    pub policy_id: String,
    pub version: i64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLoadError {
    pub code: &'static str,
    pub message: String,
    pub path: String,
    pub issues: Vec<String>,
}

/// Mirrors JS `loadPolicy({ path })`: read the bundle off disk, parse it,
/// validate it against the frozen schema, and digest the canonical form.
/// Every failure mode fails closed with the same `ARC_POLICY_*` code JS
/// throws, never a partially-understood bundle.
pub fn load_policy(bundle_path: &Path) -> Result<LoadedPolicy, PolicyLoadError> {
    let raw = std::fs::read_to_string(bundle_path).map_err(|err| PolicyLoadError {
        code: "ARC_POLICY_UNAVAILABLE",
        message: format!("policy bundle unreadable: {}", bundle_path.display()),
        path: bundle_path.display().to_string(),
        issues: vec![err.to_string()],
    })?;
    let bundle: JsonValue = serde_json::from_str(&raw).map_err(|err| PolicyLoadError {
        code: "ARC_POLICY_MALFORMED",
        message: format!("policy bundle is not valid JSON: {}", bundle_path.display()),
        path: bundle_path.display().to_string(),
        issues: vec![err.to_string()],
    })?;
    let (valid, issues) = validate_policy_bundle(&bundle);
    if !valid {
        return Err(PolicyLoadError {
            code: "ARC_POLICY_MALFORMED",
            message: format!("policy bundle failed validation: {}", bundle_path.display()),
            path: bundle_path.display().to_string(),
            issues,
        });
    }
    let policy_id = bundle.get("policyId").and_then(JsonValue::as_str).unwrap_or_default().to_string();
    let version = bundle.get("version").and_then(JsonValue::as_i64).unwrap_or_default();
    let digest = digest_value_json(&bundle);
    Ok(LoadedPolicy { bundle, policy_id, version, digest })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditViolation {
    pub file: String,
    pub pattern: String,
    pub why: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditResult {
    pub scanned: Vec<String>,
    pub violations: Vec<AuditViolation>,
}

/// Faithful port of the JS `policyDuplicationAudit` regex table. `files` are
/// file paths; contents are read by this function (I/O, but plain
/// `std::fs::read_to_string` over caller-supplied paths — no network, no
/// process spawn — so no trait indirection is warranted, matching how the
/// JS original works directly against the filesystem).
pub fn policy_duplication_audit(files: &[&Path]) -> AuditResult {
    let forbidden: [(&str, &'static str); 6] = [
        (r"\ballowed\s*:\s*true\b", "mints an allow decision outside the policy engine"),
        (r"\beffectRules\b", "reads the policy rule table directly"),
        (r"\bwaiverAuthority\b", "reimplements waiver authority"),
        (r"\bclaimLevels\b", "reimplements claim-level policy"),
        (r"\blockedDomains\b", "reimplements locked-domain policy"),
        (r"ENFORCEMENT_RANK\s*=", "re-declares the enforcement ordering instead of importing it"),
    ];
    let compiled: Vec<(Regex, &'static str)> = forbidden.iter().map(|(p, why)| (Regex::new(p).expect("static pattern"), *why)).collect();

    let mut result = AuditResult::default();
    for file in files {
        let Ok(src) = std::fs::read_to_string(file) else { continue };
        let file_str = file.display().to_string();
        result.scanned.push(file_str.clone());
        for (re, why) in &compiled {
            if re.is_match(&src) {
                result.violations.push(AuditViolation { file: file_str.clone(), pattern: re.as_str().to_string(), why });
            }
        }
    }
    result
}

/// Faithful port of the JS `capabilityIssuanceAudit`: only
/// `preeffect-gate.mjs`/`receipt-store.mjs` (by basename) may call
/// `.issue(...)`; a const-bound `AuthorityInvocationProofIssuer` receiver is
/// exempt everywhere (unrelated `.issue()` API on that type).
pub fn capability_issuance_audit(files: &[&Path]) -> AuditResult {
    let allowed_basenames = ["preeffect-gate.mjs", "receipt-store.mjs"];
    let issue_call = Regex::new(r"\.issue\(").expect("static pattern");
    let receiver_of_issue = Regex::new(r"\b([A-Za-z_$][\w$]*)\.issue\(").expect("static pattern");
    let proof_issuer_binding = Regex::new(r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+AuthorityInvocationProofIssuer\s*\(").expect("static pattern");

    let mut result = AuditResult::default();
    for file in files {
        let Ok(src) = std::fs::read_to_string(file) else { continue };
        let file_str = file.display().to_string();
        result.scanned.push(file_str.clone());

        let basename = file.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if allowed_basenames.contains(&basename) {
            continue;
        }

        let proof_issuers: std::collections::HashSet<String> =
            proof_issuer_binding.captures_iter(&src).map(|c| c[1].to_string()).collect();

        let unexempted = src.lines().any(|line| {
            if !issue_call.is_match(line) {
                return false;
            }
            match receiver_of_issue.captures(line) {
                Some(cap) => !proof_issuers.contains(&cap[1]),
                None => true,
            }
        });

        if unexempted {
            result.violations.push(AuditViolation {
                file: file_str,
                pattern: issue_call.as_str().to_string(),
                why: "mints a capability outside lib/preeffect-gate.mjs and lib/receipt-store.mjs",
            });
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> PolicyBundle {
        PolicyBundle {
            policy_id: "test-policy".into(),
            version: 1,
            digest: "sha256:deadbeef".into(),
            effect_rules: vec![
                EffectRule { effect_class: "FILE_WRITE".into(), rule: "allow".into(), approval_required: false, trust_minimum: "capability-signature".into(), required_enforcement: "strong".into() },
                EffectRule { effect_class: "FILE_DELETE".into(), rule: "allow".into(), approval_required: true, trust_minimum: "capability-signature".into(), required_enforcement: "strong".into() },
                EffectRule { effect_class: "VCS_PUSH".into(), rule: "deny".into(), approval_required: false, trust_minimum: "capability-signature".into(), required_enforcement: "strong".into() },
            ],
            waiver_authority: vec!["operator".into()],
            claim_levels: BTreeMap::from([(
                "L1".to_string(),
                ClaimLevel {
                    allow_stale_evidence: false,
                    required_evidence_classes: vec!["test-run".into()],
                    required_enforcement: "observed".into(),
                    required_fields: vec!["sha".into()],
                },
            )]),
            locked_domains: vec![LockedDomainEntry { pattern: "docs/*".into(), claim_level: "L1".into(), note: None }],
            degradation: BTreeMap::from([("capabilityX".to_string(), "downgrade".to_string())]),
            ..Default::default()
        }
    }

    #[test]
    fn effect_decision_denies_unclassified_effect() {
        let engine = PolicyEngine::new(bundle());
        let d = engine.effect_decision("NOT_A_CLASS", None);
        assert!(!d.allowed);
        assert_eq!(d.code, Some("ARC_EFFECT_CLASS_UNAUTHORIZED"));
    }

    #[test]
    fn effect_decision_denies_rule_deny() {
        let engine = PolicyEngine::new(bundle());
        let d = engine.effect_decision("VCS_PUSH", None);
        assert!(!d.allowed);
    }

    #[test]
    fn effect_decision_requires_approval_digest() {
        let engine = PolicyEngine::new(bundle());
        let denied = engine.effect_decision("FILE_DELETE", None);
        assert_eq!(denied.code, Some("ARC_APPROVAL_REQUIRED"));
        let allowed = engine.effect_decision("FILE_DELETE", Some("sha256:xyz"));
        assert!(allowed.allowed);
    }

    #[test]
    fn effect_decision_allows_plain_allow_rule() {
        let engine = PolicyEngine::new(bundle());
        assert!(engine.effect_decision("FILE_WRITE", None).allowed);
    }

    #[test]
    fn degradation_defaults_to_fail_closed_for_unknown_capability() {
        let engine = PolicyEngine::new(bundle());
        assert_eq!(engine.degradation("unknownCapability"), "fail-closed");
        assert_eq!(engine.degradation("capabilityX"), "downgrade");
    }

    #[test]
    fn enforcement_rank_orders_strong_above_advisory() {
        assert!(enforcement_at_least("strong", "observed"));
        assert!(!enforcement_at_least("advisory", "observed"));
        assert!(enforcement_at_least("observed", "observed"));
    }

    #[test]
    fn may_waive_checks_bundle_waiver_authority() {
        let engine = PolicyEngine::new(bundle());
        assert!(engine.may_waive("operator").allowed);
        assert!(!engine.may_waive("model").allowed);
    }

    #[test]
    fn evaluate_claim_prerequisites_denies_stale_evidence() {
        let engine = PolicyEngine::new(bundle());
        let ctx = ClaimContext { stale_evidence_count: 1, evidence_classes: &["test-run"], enforcement_health: "observed", fields: &["sha"], waived_by: None };
        let d = engine.evaluate_claim_prerequisites("L1", &ctx);
        assert_eq!(d.code, Some("ARC_EVIDENCE_STALE"));
    }

    #[test]
    fn evaluate_claim_prerequisites_denies_missing_evidence_class() {
        let engine = PolicyEngine::new(bundle());
        let ctx = ClaimContext { evidence_classes: &[], enforcement_health: "observed", fields: &["sha"], ..Default::default() };
        let d = engine.evaluate_claim_prerequisites("L1", &ctx);
        assert_eq!(d.code, Some("ARC_EVIDENCE_INSUFFICIENT"));
    }

    #[test]
    fn evaluate_claim_prerequisites_denies_insufficient_enforcement() {
        let engine = PolicyEngine::new(bundle());
        let ctx = ClaimContext { evidence_classes: &["test-run"], enforcement_health: "advisory", fields: &["sha"], ..Default::default() };
        let d = engine.evaluate_claim_prerequisites("L1", &ctx);
        assert_eq!(d.code, Some("ARC_CLAIM_PREREQUISITE_UNMET"));
    }

    #[test]
    fn evaluate_claim_prerequisites_allows_missing_field_when_waived() {
        let engine = PolicyEngine::new(bundle());
        let ctx = ClaimContext { evidence_classes: &["test-run"], enforcement_health: "observed", fields: &[], waived_by: Some("operator"), stale_evidence_count: 0 };
        let d = engine.evaluate_claim_prerequisites("L1", &ctx);
        assert!(d.allowed);
    }

    #[test]
    fn evaluate_claim_prerequisites_denies_missing_field_without_waiver() {
        let engine = PolicyEngine::new(bundle());
        let ctx = ClaimContext { evidence_classes: &["test-run"], enforcement_health: "observed", fields: &[], waived_by: None, stale_evidence_count: 0 };
        let d = engine.evaluate_claim_prerequisites("L1", &ctx);
        assert_eq!(d.code, Some("ARC_CLAIM_PREREQUISITE_UNMET"));
    }

    #[test]
    fn evaluate_claim_prerequisites_unknown_level_denies() {
        let engine = PolicyEngine::new(bundle());
        let ctx = ClaimContext::default();
        let d = engine.evaluate_claim_prerequisites("NOPE", &ctx);
        assert_eq!(d.code, Some("ARC_CLAIM_PREREQUISITE_UNMET"));
    }

    #[test]
    fn locked_domains_for_matches_glob_pattern() {
        let engine = PolicyEngine::new(bundle());
        let matches = engine.locked_domains_for(&["docs/readme.md", "src/lib.rs"]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "docs/readme.md");
    }

    #[test]
    fn path_matches_supports_star_glob() {
        assert!(path_matches("docs/*", "docs/readme.md"));
        assert!(!path_matches("docs/*", "src/lib.rs"));
        assert!(path_matches("*", "anything"));
    }

    #[test]
    fn fail_closed_engine_denies_every_effect() {
        let engine = fail_closed_engine("no bundle on disk");
        let d = engine.effect_decision("FILE_WRITE");
        assert!(!d.allowed);
        assert_eq!(d.code, Some("ARC_POLICY_UNAVAILABLE"));
        assert_eq!(engine.degradation(), "fail-closed");
    }

    #[test]
    fn effect_class_reconciliation_has_twelve_frozen_values() {
        assert_eq!(effect_class_reconciliation().len(), 12);
    }
}
