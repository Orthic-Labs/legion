//! r48: faithful port of `src/lib/guard/compat/effects/preeffect-gate.mjs`
//! (deliverable 6 — the pre-effect gate), extending the wf006 utility-only
//! port with the `PreEffectGate` class itself.
//!
//! Covers: the mutating-effect-class enum, the scope-pattern glob matcher
//! (`pathMatches`), the workspace-relative path normalizer
//! (`workspaceRelative`), and now `PreEffectGate::evaluate`/`authorize`/
//! `evaluate_read_only`/`health`, wired to the sibling ports this crate
//! already carries:
//!   - `wf068::validate::validate_against("effect-request-v1", ...)` for
//!     step 1 structural validation;
//!   - `wf067::authority::require_authority` for step 3 authority;
//!   - `wf007::policy::PolicyEngine`/`FailClosedEngine` for the policy
//!     plane (step 8 and `capabilityLimits()`);
//!   - this module's own `CapabilityStore` for capability check/consume/
//!     issue (step 10, and minting in `authorize()`);
//!   - `wf067::ids::ulid` for capability id minting.
//!
//! `ExecutionContract` is a plain Rust struct here rather than a
//! schema-validated JSON value: the JS gate never runs `validateAgainst` on
//! the contract it is handed (only on the effect request), so this port
//! does not either — faithful to that asymmetry.

use std::collections::BTreeMap;

use super::capability_store::{CapabilityInput, CapabilityStore, CheckCtx};
use crate::wf_port::wf007::policy::{FailClosedEngine, PolicyEngine};
use crate::wf_port::wf067::authority::{require_authority, AuthorityLedger, RequireAuthorityOpts};
use crate::wf_port::wf067::ids::ulid;
use crate::wf_port::wf068::validate::validate_against;

/// Every value in the frozen `EFFECT_CLASS` enum that mutates product state
/// or may do so. Read-only work never arrives as an effect request at all.
pub const MUTATING_EFFECT_CLASSES: &[&str] = &[
    "FILE_WRITE", "FILE_DELETE", "FILE_MOVE", "COMMAND_EXEC", "NETWORK_EGRESS",
    "PROCESS_SPAWN", "CREDENTIAL_ACCESS", "DEPENDENCY_INSTALL", "VCS_COMMIT",
    "VCS_PUSH", "PUBLISH", "EXTERNAL_SIDE_EFFECT",
];

pub fn is_mutating(effect_class: &str) -> bool {
    MUTATING_EFFECT_CLASSES.contains(&effect_class)
}

/// Effect classes whose request carries a second path that must also be owned.
pub const TWO_PATH_EFFECTS: &[&str] = &["FILE_MOVE"];

#[allow(dead_code)]
pub fn is_two_path_effect(effect_class: &str) -> bool {
    TWO_PATH_EFFECTS.contains(&effect_class)
}

fn normalize_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut last_was_slash = false;
    for c in p.chars() {
        let c = if c == '\\' { '/' } else { c };
        if c == '/' {
            if last_was_slash {
                continue;
            }
            last_was_slash = true;
        } else {
            last_was_slash = false;
        }
        out.push(c);
    }
    out
}

fn regex_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Translate a `pathMatches` scope pattern into a compiled matcher, then
/// test `target` against it. Deliberately small: `**` (any number of
/// segments), `*` (within one segment), a trailing `/` (directory prefix),
/// literal paths. A target containing a `..` segment never matches.
pub fn path_matches(pattern: &str, target: &str) -> bool {
    let t = normalize_path(target);
    if t.split('/').any(|seg| seg == "..") {
        return false;
    }
    let mut p = normalize_path(pattern);
    if p.ends_with('/') {
        p.push_str("**");
    }
    let segments: Vec<&str> = p.split('/').collect();
    let mut rx = String::from("^");
    for (index, segment) in segments.iter().enumerate() {
        let separator = if index > 0 && segments[index - 1] != "**" { "/" } else { "" };
        if *segment == "**" {
            rx.push_str(separator);
            if index == segments.len() - 1 {
                rx.push_str(".*");
            } else {
                rx.push_str("(?:[^/]+/)*");
            }
        } else {
            rx.push_str(separator);
            // Split on `*`, escaping literal runs and mapping `*` -> `[^/]*`.
            let mut chars = segment.chars().peekable();
            let mut literal = String::new();
            while let Some(c) = chars.next() {
                if c == '*' {
                    rx.push_str(&regex_escape(&literal));
                    literal.clear();
                    rx.push_str("[^/]*");
                } else {
                    literal.push(c);
                }
            }
            rx.push_str(&regex_escape(&literal));
        }
    }
    rx.push('$');
    simple_glob_regex_match(&rx, &t)
}

/// Minimal backtracking matcher for the small regex subset `path_matches`
/// produces (`^`, `$`, literal chars, `[^/]*`, `(?:[^/]+/)*`, `.*`) — kept
/// dependency-free rather than pulling in the `regex` crate for wf006.
fn simple_glob_regex_match(rx: &str, text: &str) -> bool {
    // Reduce the small generated grammar back into matcher tokens instead of
    // interpreting arbitrary regex syntax.
    #[derive(Debug)]
    enum Tok {
        Lit(char),
        StarNonSlash,   // [^/]*
        StarAny,        // .*
        StarSegments,   // (?:[^/]+/)*
    }
    let mut toks = Vec::new();
    let body = &rx[1..rx.len() - 1]; // strip ^ and $
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' && chars.clone().take(3).collect::<String>() == "^/]" {
            chars.next();
            chars.next();
            chars.next();
            if chars.peek() == Some(&'*') {
                chars.next();
                toks.push(Tok::StarNonSlash);
            }
        } else if c == '.' && chars.peek() == Some(&'*') {
            chars.next();
            toks.push(Tok::StarAny);
        } else if c == '(' {
            // expect "?:[^/]+/)*"
            let rest: String = chars.by_ref().take(10).collect();
            if rest == "?:[^/]+/)*" {
                toks.push(Tok::StarSegments);
            }
        } else if c == '\\' {
            if let Some(next) = chars.next() {
                toks.push(Tok::Lit(next));
            }
        } else {
            toks.push(Tok::Lit(c));
        }
    }
    let text_chars: Vec<char> = text.chars().collect();
    fn matches_from(toks: &[Tok], ti: usize, text: &[char], si: usize) -> bool {
        if ti == toks.len() {
            return si == text.len();
        }
        match &toks[ti] {
            Tok::Lit(c) => si < text.len() && text[si] == *c && matches_from(toks, ti + 1, text, si + 1),
            Tok::StarNonSlash => {
                let mut end = si;
                loop {
                    if matches_from(toks, ti + 1, text, end) {
                        return true;
                    }
                    if end >= text.len() || text[end] == '/' {
                        return false;
                    }
                    end += 1;
                }
            }
            Tok::StarAny => {
                let mut end = si;
                loop {
                    if matches_from(toks, ti + 1, text, end) {
                        return true;
                    }
                    if end >= text.len() {
                        return false;
                    }
                    end += 1;
                }
            }
            Tok::StarSegments => {
                // Zero or more `[^/]+/` groups.
                let mut end = si;
                loop {
                    if matches_from(toks, ti + 1, text, end) {
                        return true;
                    }
                    // Try to consume one more segment.
                    let seg_start = end;
                    let mut seg_end = end;
                    while seg_end < text.len() && text[seg_end] != '/' {
                        seg_end += 1;
                    }
                    if seg_end == seg_start || seg_end >= text.len() || text[seg_end] != '/' {
                        return false;
                    }
                    end = seg_end + 1;
                }
            }
        }
    }
    matches_from(&toks, 0, &text_chars, 0)
}

pub fn matches_any(patterns: &[&str], target: &str) -> bool {
    patterns.iter().any(|p| path_matches(p, target))
}

/// Bring a host-supplied path into the same frame as `scope.own`. A path
/// outside the workspace is returned unchanged (still fails to match, still
/// denied). Drive-letter/prefix comparison is case-insensitive, matching the
/// JS source's rationale (host payload vs. contract casing can differ).
pub fn workspace_relative(target: &str, workspace: Option<&str>) -> String {
    let t = normalize_path(target);
    let workspace = match workspace {
        Some(w) if !w.is_empty() => w,
        _ => return t,
    };
    let mut root = normalize_path(workspace);
    if root.ends_with('/') {
        root.pop();
    }
    if root.is_empty() {
        return t;
    }
    let prefix = format!("{root}/");
    if t.len() >= prefix.len() && t[..prefix.len()].to_lowercase() == prefix.to_lowercase() {
        t[prefix.len()..].to_string()
    } else {
        t
    }
}

// ---------------------------------------------------------------------
// The pre-effect gate itself.
// ---------------------------------------------------------------------

/// A pre-effect decision. Mirrors JS `decision()`'s shape (`allowed`,
/// `code`, `message`, `detail`, `enforcementHealth`); `detail` is JSON here
/// so it can carry the same nested shapes (arrays, nested objects) the JS
/// call sites attach.
#[derive(Debug, Clone, PartialEq)]
pub struct GateDecision {
    pub allowed: bool,
    pub code: Option<String>,
    pub message: String,
    pub detail: serde_json::Value,
    pub enforcement_health: Option<String>,
}

fn gd(
    allowed: bool,
    code: Option<&str>,
    message: impl Into<String>,
    detail: serde_json::Value,
    health: Option<&str>,
) -> GateDecision {
    GateDecision {
        allowed,
        code: code.map(str::to_string),
        message: message.into(),
        detail,
        enforcement_health: health.map(str::to_string),
    }
}

fn detail_pairs(pairs: &[(String, String)]) -> serde_json::Value {
    serde_json::Value::Object(pairs.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect())
}

/// `effect-request-v1`. Faithful to the schema's required fields (see
/// `wf068/schemas_contracts/effect-request-v1.schema.json`); optional
/// fields (`preview`, `idempotencyKey`, `approvalRequired`) are omitted
/// since nothing in the gate's own check order reads them.
#[derive(Debug, Clone)]
pub struct EffectRequest {
    pub request_id: String,
    pub run_id: String,
    pub contract_id: String,
    pub task_id: String,
    pub requested_by: String,
    pub effect_class: String,
    pub target: String,
    pub operation: String,
    pub latitude: String,
    pub source_revision: String,
    pub requested_at: String,
}

impl EffectRequest {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-effect-request",
            "requestId": self.request_id,
            "runId": self.run_id,
            "contractId": self.contract_id,
            "taskId": self.task_id,
            "requestedBy": self.requested_by,
            "effectClass": self.effect_class,
            "target": self.target,
            "operation": self.operation,
            "latitude": self.latitude,
            "sourceRevision": self.source_revision,
            "requestedAt": self.requested_at,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ContractScope {
    pub own: Vec<String>,
    pub forbidden: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AdvisoryProfile {
    pub bundle_id: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub mutation_allowed: bool,
    pub publish_allowed: bool,
}

#[derive(Debug, Clone)]
pub struct ArtifactUnit {
    pub id: String,
    pub path: String,
}

#[derive(Debug, Clone, Default)]
pub struct ContractArtifacts {
    pub exact: Vec<ArtifactUnit>,
    pub bounded: Vec<ArtifactUnit>,
}

/// The subset of `execution-contract-v1` the gate's own logic reads. Not
/// schema-validated here — see module doc.
#[derive(Debug, Clone)]
pub struct ExecutionContract {
    pub contract_id: String,
    pub version: i64,
    pub source_revision: String,
    pub open_question_ids: Vec<String>,
    pub scope: ContractScope,
    pub authorized_effect_classes: Vec<String>,
    pub advisory_profile: Option<AdvisoryProfile>,
    pub artifacts: ContractArtifacts,
}

/// Context for `evaluate()`/`authorize()`. Mirrors the JS `ctx` object.
/// `approval_digest` is accepted for signature fidelity with the JS
/// destructure but is never read: approval is host-derived only (see
/// `#runChecks` in the JS source), matching the original's own dead field.
#[derive(Debug, Clone, Default)]
pub struct EvalCtx<'a> {
    pub contract: Option<&'a ExecutionContract>,
    pub turn_id: &'a str,
    pub capability_id: Option<&'a str>,
    pub approval_digest: Option<&'a str>,
    pub destination: Option<&'a str>,
    pub expected_contract_version: Option<i64>,
    pub workspace: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub contract_digest: Option<&'a str>,
}

/// Result of a successful (non-denied) approval derivation.
pub struct ApprovalGrant {
    pub approval_digest: String,
    pub evidence: serde_json::Value,
}

/// Host-derived approval evidence. Mirrors the JS `approvalAuthority`
/// dependency: `derive()` returns `Ok(grant)` when approval is bound,
/// `Err(deny)` when it is refused, or `None` when unavailable (in which
/// case the gate synthesizes its own `ARC_APPROVAL_REQUIRED` denial, exactly
/// as the JS `approval ?? decision({...})` fallback does).
pub trait ApprovalAuthority {
    fn derive(&self, request: &EffectRequest, ctx: &EvalCtx<'_>) -> Option<Result<ApprovalGrant, GateDecision>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    Enforcing,
    Advisory,
}

/// Either a real policy plane or the fail-closed stand-in, mirroring the JS
/// gate's `available()` check (`this.#policy && !this.#policy.failClosed`):
/// only `Engine` counts as "policy available".
pub enum PolicyHandle {
    Engine(PolicyEngine),
    FailClosed(FailClosedEngine),
}

impl PolicyHandle {
    fn available(&self) -> bool {
        matches!(self, PolicyHandle::Engine(_))
    }

    fn effect_decision(&self, effect_class: &str, approval_digest: Option<&str>) -> GateDecision {
        match self {
            PolicyHandle::Engine(e) => {
                let d = e.effect_decision(effect_class, approval_digest);
                gd(d.allowed, d.code, d.message, serde_json::Value::Null, d.enforcement_health.as_deref())
            }
            PolicyHandle::FailClosed(f) => {
                let d = f.effect_decision(effect_class);
                gd(d.allowed, d.code, d.message, serde_json::Value::Null, d.enforcement_health.as_deref())
            }
        }
    }

    fn capability_limits(&self) -> BTreeMap<String, String> {
        match self {
            PolicyHandle::Engine(e) => e.capability_limits(),
            PolicyHandle::FailClosed(f) => f.capability_limits().into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        }
    }

    fn policy_identity(&self) -> Option<(String, i64, String)> {
        match self {
            PolicyHandle::Engine(e) => Some(e.policy_identity()),
            PolicyHandle::FailClosed(_) => None,
        }
    }
}

/// Result of steps 1-9 (`#runChecks` in the JS source), shared by
/// `evaluate()` and `authorize()`.
enum RunChecks<'a> {
    /// Enforcement could not even run — never advisory-overridable.
    HardFail(GateDecision),
    /// Checks ran to completion. `deny` is the first failing decision, or
    /// `None` when every check passed. `approval_evidence` is populated
    /// only alongside a passing run that required approval.
    Ran { deny: Option<GateDecision>, contract: Option<&'a ExecutionContract>, approval_evidence: Option<serde_json::Value> },
}

pub struct PreEffectGate {
    policy: PolicyHandle,
    capability_store: Option<CapabilityStore>,
    authority: Option<AuthorityLedger>,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
    enforcement_mode: EnforcementMode,
    approval_authority: Option<Box<dyn ApprovalAuthority>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateHealth {
    pub policy: &'static str,
    pub capability: &'static str,
    pub authority: &'static str,
    pub overall: &'static str,
}

impl PreEffectGate {
    pub fn new(
        policy: PolicyHandle,
        capability_store: Option<CapabilityStore>,
        authority: Option<AuthorityLedger>,
        approval_authority: Option<Box<dyn ApprovalAuthority>>,
        clock: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> Self {
        Self {
            policy,
            capability_store,
            authority,
            clock: Box::new(clock),
            enforcement_mode: EnforcementMode::Enforcing,
            approval_authority,
        }
    }

    pub fn with_enforcement_mode(mut self, mode: EnforcementMode) -> Self {
        self.enforcement_mode = mode;
        self
    }

    /// True when the gate can actually enforce.
    pub fn available(&self) -> bool {
        self.policy.available() && self.capability_store.is_some() && self.authority.is_some()
    }

    /// The pre-effect decision (mirrors JS `evaluate(effectRequest, ctx)`).
    pub fn evaluate(&mut self, request: &EffectRequest, ctx: &EvalCtx<'_>) -> GateDecision {
        let capability_id = ctx.capability_id;

        let (deny, contract, _approval_evidence) = match self.run_checks(request, ctx) {
            RunChecks::HardFail(d) => return d,
            RunChecks::Ran { deny, contract, approval_evidence } => (deny, contract, approval_evidence),
        };
        if let Some(d) = deny {
            return d;
        }
        let contract = contract.expect("deny is None only when contract checks passed");

        // 10. Capability.
        let Some(capability_id) = capability_id else {
            return gd(
                false,
                Some("ARC_CAPABILITY_UNKNOWN"),
                "mutation requires an Arcane-issued capability",
                serde_json::json!({ "effectClass": request.effect_class }),
                None,
            );
        };
        let now_ms = (self.clock)();
        let now_iso = capability_store_stamp(now_ms);
        let store = self.capability_store.as_mut().expect("available() checked Some above");
        let authority_now = self.authority.as_ref().and_then(|a| a.current(ctx.turn_id)).map(|a| a.authority.clone());
        let check_ctx = CheckCtx {
            now: Some(now_iso.clone()),
            run_id: Some(request.run_id.clone()),
            task_id: Some(request.task_id.clone()),
            workspace: ctx.workspace.map(str::to_string),
            contract_id: Some(request.contract_id.clone()),
            contract_version: Some(ctx.expected_contract_version.unwrap_or(contract.version).to_string()),
            contract_digest: ctx.contract_digest.map(str::to_string),
            source_revision: Some(request.source_revision.clone()),
            authority: authority_now,
            turn_id: Some(ctx.turn_id.to_string()),
            operation: Some(request.operation.clone()),
            effect_class: Some(request.effect_class.clone()),
            target: Some(request.target.clone()),
        };
        let cap_call = store.check(capability_id, &check_ctx);
        if !cap_call.allowed {
            return gd(false, cap_call.code.map(|c| c.as_str()), cap_call.message, detail_pairs(&cap_call.detail), None);
        }

        if let Err(error) = store.consume(capability_id, &check_ctx) {
            return gd(
                false,
                Some(error.code.as_str()),
                error.message.clone(),
                serde_json::json!({ "capabilityId": capability_id }),
                Some("strong"),
            );
        }

        let (policy_id, _version, policy_digest) = self.policy.policy_identity().expect("policy available in a passing run");
        gd(
            true,
            None,
            "authorized",
            serde_json::json!({
                "contractId": contract.contract_id,
                "contractVersion": contract.version,
                "effectClass": request.effect_class,
                "target": request.target,
                "latitude": request.latitude,
                "capabilityId": capability_id,
                "policyId": policy_id,
                "policyDigest": policy_digest,
            }),
            Some("strong"),
        )
    }

    /// CONTRACT A — the capability mint authority (mirrors JS `authorize`).
    pub fn authorize(&mut self, request: &EffectRequest, ctx: &EvalCtx<'_>) -> GateDecision {
        let (deny, contract, approval_evidence) = match self.run_checks(request, ctx) {
            RunChecks::HardFail(d) => return d,
            RunChecks::Ran { deny, contract, approval_evidence } => (deny, contract, approval_evidence),
        };
        if deny.is_some() && self.enforcement_mode != EnforcementMode::Advisory {
            return deny.unwrap();
        }

        let workspace = ctx.workspace;
        let destination = ctx.destination;
        let mut targets = vec![request.target.clone()];
        if TWO_PATH_EFFECTS.contains(&request.effect_class.as_str()) {
            if let Some(d) = destination {
                targets.push(d.to_string());
            }
        }

        let limits = self.policy.capability_limits();
        let ttl_seconds: i64 = limits.get("ttlSeconds").and_then(|v| v.parse().ok()).unwrap_or(0);
        let max_uses: Option<i64> = limits.get("maxUses").and_then(|v| v.parse().ok());
        let now_ms = (self.clock)();
        let now_iso = capability_store_stamp(now_ms);
        let expires_at = if ttl_seconds > 0 { Some(capability_store_stamp(now_ms + ttl_seconds * 1000)) } else { None };
        let capability_id = format!("cap_{}", ulid(now_ms.max(0) as u64));

        let (policy_id, policy_version, policy_digest) = self.policy.policy_identity().expect("policy available in a passing run");
        let authority_now = self.authority.as_ref().and_then(|a| a.current(ctx.turn_id)).map(|a| a.authority.clone());
        let contract_version = contract.map(|c| c.version);

        let store = self.capability_store.as_mut().expect("available() checked Some above");
        if let Err(err) = store.issue(CapabilityInput {
            capability_id: capability_id.clone(),
            run_id: Some(request.run_id.clone()),
            task_id: Some(request.task_id.clone()),
            workspace: workspace.map(str::to_string),
            contract_id: Some(request.contract_id.clone()),
            contract_version: contract_version.map(|v| v.to_string()),
            contract_digest: ctx.contract_digest.map(str::to_string),
            source_revision: Some(request.source_revision.clone()),
            authority: authority_now.clone(),
            turn_id: Some(ctx.turn_id.to_string()),
            operation: Some(request.operation.clone()),
            effect_class: Some(request.effect_class.clone()),
            targets: Some(targets),
            policy_id: Some(policy_id.clone()),
            policy_version: Some(policy_version.to_string()),
            policy_digest: Some(policy_digest.clone()),
            issued_at: Some(now_iso.clone()),
            expires_at: expires_at.clone(),
            max_uses,
            delegable: Some(false),
        }) {
            return gd(false, Some(err.code.as_str()), err.message.clone(), serde_json::json!({ "capabilityId": capability_id }), None);
        }

        // Self-check: a capability this method just minted must itself pass
        // the same binding checks a real effect would be held to.
        let self_check_ctx = CheckCtx {
            now: Some(now_iso),
            run_id: Some(request.run_id.clone()),
            task_id: Some(request.task_id.clone()),
            workspace: workspace.map(str::to_string),
            contract_id: Some(request.contract_id.clone()),
            contract_version: contract_version.map(|v| v.to_string()),
            contract_digest: ctx.contract_digest.map(str::to_string),
            source_revision: Some(request.source_revision.clone()),
            authority: authority_now,
            turn_id: Some(ctx.turn_id.to_string()),
            operation: Some(request.operation.clone()),
            effect_class: Some(request.effect_class.clone()),
            target: Some(request.target.clone()),
        };
        let self_check = self.capability_store.as_ref().unwrap().check(&capability_id, &self_check_ctx);
        if !self_check.allowed {
            let mut detail = detail_pairs(&self_check.detail);
            if let serde_json::Value::Object(map) = &mut detail {
                map.insert("capabilityId".into(), serde_json::Value::String(capability_id.clone()));
            }
            return gd(false, self_check.code.map(|c| c.as_str()), format!("minted capability failed its own self-check: {}", self_check.message), detail, Some("unsupported"));
        }

        let detail = serde_json::json!({
            "contractId": contract.map(|c| c.contract_id.clone()),
            "contractVersion": contract.map(|c| c.version),
            "effectClass": request.effect_class,
            "target": request.target,
            "latitude": request.latitude,
            "capabilityId": capability_id,
            "policyId": policy_id,
            "policyDigest": policy_digest,
        });

        if let Some(deny) = deny {
            // Advisory mode: the real decision would have denied, but
            // advisory enforcement skips ENFORCING the deny, not the
            // minting. The denial is carried verbatim.
            let mut with_would_have_denied = detail;
            if let serde_json::Value::Object(map) = &mut with_would_have_denied {
                map.insert(
                    "wouldHaveDenied".into(),
                    serde_json::json!({ "code": deny.code, "message": deny.message, "detail": deny.detail }),
                );
            }
            return gd(
                true,
                None,
                "authorized under advisory enforcement; the underlying check would have denied",
                with_would_have_denied,
                Some("advisory"),
            );
        }

        let _ = approval_evidence; // carried through run_checks for parity; minted capability itself carries the binding.
        gd(true, None, "authorized", detail, Some("strong"))
    }

    /// Steps 1-9 of the pre-effect decision (mirrors JS `#runChecks`).
    fn run_checks<'a>(&self, request: &EffectRequest, ctx: &EvalCtx<'a>) -> RunChecks<'a> {
        // 1. Structure.
        match validate_against("effect-request-v1", &request.to_json()) {
            Ok(outcome) if !outcome.valid => {
                return RunChecks::HardFail(gd(
                    false,
                    Some("ARC_SCHEMA_INVALID"),
                    "effect request does not satisfy effect-request-v1",
                    serde_json::json!({ "issues": outcome.issues }),
                    None,
                ));
            }
            Err(err) => {
                return RunChecks::HardFail(gd(false, Some(err.code.as_str()), err.message, serde_json::Value::Null, None));
            }
            Ok(_) => {}
        }

        // 2. Enforcement availability.
        if !self.available() {
            return RunChecks::HardFail(gd(
                false,
                Some("ARC_GATE_UNAVAILABLE"),
                "pre-effect gate unavailable; mutation-bearing operations fail closed",
                serde_json::json!({
                    "policy": self.policy.available(),
                    "capabilityStore": self.capability_store.is_some(),
                    "authorityLedger": self.authority.is_some(),
                    "effectClass": request.effect_class,
                }),
                Some("unsupported"),
            ));
        }
        let ledger = self.authority.as_ref().expect("checked Some above");

        // 3. Authority.
        let auth = require_authority(
            ledger,
            ctx.turn_id,
            &["alchemist", "sage", "oracle", "legion"],
            RequireAuthorityOpts { claimed_authority: Some(request.requested_by.as_str()), require_per_message: true },
        );
        if !auth.allowed {
            return RunChecks::Ran {
                deny: Some(gd(false, auth.code.map(|c| c.as_str()), auth.message, detail_pairs(&auth.detail), None)),
                contract: ctx.contract,
                approval_evidence: None,
            };
        }

        // 4. Mutations require a bound executable contract.
        let Some(contract) = ctx.contract else {
            return RunChecks::Ran {
                deny: Some(gd(
                    false,
                    Some("ARC_NO_CONTRACT"),
                    "mutation requested with no execution contract",
                    serde_json::json!({ "contractId": request.contract_id, "effectClass": request.effect_class }),
                    None,
                )),
                contract: None,
                approval_evidence: None,
            };
        };

        // 5. Contract identity, version, and revision binding.
        if contract.contract_id != request.contract_id {
            return RunChecks::Ran {
                deny: Some(gd(
                    false,
                    Some("ARC_CONTRACT_VERSION_MISMATCH"),
                    "effect request names a different contract than the one supplied",
                    serde_json::json!({ "requested": request.contract_id, "supplied": contract.contract_id }),
                    None,
                )),
                contract: Some(contract),
                approval_evidence: None,
            };
        }
        if let Some(expected) = ctx.expected_contract_version {
            if contract.version != expected {
                return RunChecks::Ran {
                    deny: Some(gd(
                        false,
                        Some("ARC_CONTRACT_VERSION_MISMATCH"),
                        "contract version does not match the version this effect was authorized against",
                        serde_json::json!({ "expected": expected, "actual": contract.version }),
                        None,
                    )),
                    contract: Some(contract),
                    approval_evidence: None,
                };
            }
        }
        if contract.source_revision != request.source_revision {
            return RunChecks::Ran {
                deny: Some(gd(
                    false,
                    Some("ARC_CONTRACT_VERSION_MISMATCH"),
                    "effect request source revision does not match the contract it cites",
                    serde_json::json!({ "request": request.source_revision, "contract": contract.source_revision }),
                    None,
                )),
                contract: Some(contract),
                approval_evidence: None,
            };
        }

        // 6. Open questions make a contract non-executable.
        if !contract.open_question_ids.is_empty() {
            return RunChecks::Ran {
                deny: Some(gd(
                    false,
                    Some("ARC_CONTRACT_NOT_EXECUTABLE"),
                    format!("contract {} has {} unresolved open question(s)", contract.contract_id, contract.open_question_ids.len()),
                    serde_json::json!({ "openQuestions": contract.open_question_ids }),
                    None,
                )),
                contract: Some(contract),
                approval_evidence: None,
            };
        }

        // 7. Path ownership. Forbidden wins outright.
        let root = ctx.workspace;
        let mut paths = vec![("target", workspace_relative(&request.target, root))];
        if TWO_PATH_EFFECTS.contains(&request.effect_class.as_str()) {
            if let Some(destination) = ctx.destination {
                paths.push(("destination", workspace_relative(destination, root)));
            }
        }
        for (which, value) in &paths {
            let forbidden: Vec<&str> = contract.scope.forbidden.iter().map(String::as_str).collect();
            if matches_any(&forbidden, value) {
                return RunChecks::Ran {
                    deny: Some(gd(
                        false,
                        Some("ARC_PATH_FORBIDDEN"),
                        format!("{which} path is in the contract's forbidden scope"),
                        serde_json::json!({ "which": which, "path": value, "forbidden": contract.scope.forbidden }),
                        None,
                    )),
                    contract: Some(contract),
                    approval_evidence: None,
                };
            }
            let own: Vec<&str> = contract.scope.own.iter().map(String::as_str).collect();
            if !matches_any(&own, value) {
                return RunChecks::Ran {
                    deny: Some(gd(
                        false,
                        Some("ARC_PATH_NOT_OWNED"),
                        format!("{which} path is not inside the contract's own[] scope"),
                        serde_json::json!({ "which": which, "path": value, "own": contract.scope.own }),
                        None,
                    )),
                    contract: Some(contract),
                    approval_evidence: None,
                };
            }
        }

        // 8. Effect-class authorization: contract first, then policy.
        if !contract.authorized_effect_classes.iter().any(|c| c == &request.effect_class) {
            return RunChecks::Ran {
                deny: Some(gd(
                    false,
                    Some("ARC_EFFECT_CLASS_UNAUTHORIZED"),
                    format!("contract {} does not authorize {}", contract.contract_id, request.effect_class),
                    serde_json::json!({
                        "deniedBy": "contract",
                        "effectClass": request.effect_class,
                        "authorized": contract.authorized_effect_classes,
                    }),
                    None,
                )),
                contract: Some(contract),
                approval_evidence: None,
            };
        }
        let denied_profile_field = contract.advisory_profile.as_ref().and_then(|p| {
            if request.effect_class == "PUBLISH" && !p.publish_allowed {
                Some("publishAllowed")
            } else if is_mutating(&request.effect_class) && !p.mutation_allowed {
                Some("mutationAllowed")
            } else {
                None
            }
        });
        if let Some(field) = denied_profile_field {
            let profile = contract.advisory_profile.as_ref().unwrap();
            return RunChecks::Ran {
                deny: Some(gd(
                    false,
                    Some("ARC_PROFILE_EFFECT_FORBIDDEN"),
                    format!("advisory profile {}/{} forbids {}", profile.bundle_id, profile.profile_id, request.effect_class),
                    serde_json::json!({
                        "deniedBy": "advisory-profile",
                        "effectClass": request.effect_class,
                        "profileDigest": profile.profile_digest,
                        "restriction": field,
                    }),
                    None,
                )),
                contract: Some(contract),
                approval_evidence: None,
            };
        }

        // Approval is host-derived only; ignore any caller-carried digest.
        let mut derived_approval_digest: Option<String> = None;
        let mut approval_evidence: Option<serde_json::Value> = None;
        let requires_approval = match &self.policy {
            PolicyHandle::Engine(e) => e.effect_decision(&request.effect_class, None).code == Some("ARC_APPROVAL_REQUIRED"),
            PolicyHandle::FailClosed(f) => f.effect_decision(&request.effect_class).code == Some("ARC_APPROVAL_REQUIRED"),
        };
        if requires_approval {
            match self.approval_authority.as_ref().map(|a| a.derive(request, ctx)) {
                Some(Some(Ok(grant))) => {
                    derived_approval_digest = Some(grant.approval_digest);
                    approval_evidence = Some(grant.evidence);
                }
                Some(Some(Err(deny))) => {
                    return RunChecks::Ran { deny: Some(deny), contract: Some(contract), approval_evidence: None };
                }
                Some(None) | None => {
                    return RunChecks::Ran {
                        deny: Some(gd(
                            false,
                            Some("ARC_APPROVAL_REQUIRED"),
                            "required approval authority unavailable",
                            serde_json::Value::Null,
                            None,
                        )),
                        contract: Some(contract),
                        approval_evidence: None,
                    };
                }
            }
        }
        let policy_call = self.policy.effect_decision(&request.effect_class, derived_approval_digest.as_deref());
        if !policy_call.allowed {
            let mut detail = policy_call.detail;
            if !detail.is_object() {
                detail = serde_json::json!({});
            }
            if let serde_json::Value::Object(map) = &mut detail {
                map.insert("deniedBy".into(), serde_json::Value::String("policy".into()));
            }
            return RunChecks::Ran {
                deny: Some(gd(
                    false,
                    policy_call.code.as_deref(),
                    policy_call.message,
                    detail,
                    policy_call.enforcement_health.as_deref(),
                )),
                contract: Some(contract),
                approval_evidence: None,
            };
        }

        // 9. Latitude.
        let latitude_call = self.check_latitude(contract, request);
        if !latitude_call.allowed {
            return RunChecks::Ran { deny: Some(latitude_call), contract: Some(contract), approval_evidence: None };
        }

        RunChecks::Ran { deny: None, contract: Some(contract), approval_evidence }
    }

    fn check_latitude(&self, contract: &ExecutionContract, request: &EffectRequest) -> GateDecision {
        let exact = contract.artifacts.exact.iter().find(|a| a.path == request.target);
        let bounded = contract.artifacts.bounded.iter().find(|a| a.path == request.target);
        let declared = if exact.is_some() { Some("EXACT") } else if bounded.is_some() { Some("BOUNDED") } else { None };

        match declared {
            None => {
                if request.latitude == "BOUNDED" {
                    gd(true, None, "", serde_json::json!({ "latitude": "BOUNDED", "artifact": null }), None)
                } else {
                    gd(
                        false,
                        Some("ARC_LATITUDE_VIOLATION"),
                        "EXACT latitude claimed for a path the contract declares no artifact unit for",
                        serde_json::json!({ "target": request.target, "requested": request.latitude, "declared": null }),
                        None,
                    )
                }
            }
            Some(declared) if declared != request.latitude => gd(
                false,
                Some("ARC_LATITUDE_VIOLATION"),
                format!("contract declares {declared} latitude for this artifact; request claims {}", request.latitude),
                serde_json::json!({
                    "target": request.target,
                    "requested": request.latitude,
                    "declared": declared,
                    "artifactId": exact.or(bounded).unwrap().id,
                }),
                None,
            ),
            Some(declared) => gd(
                true,
                None,
                "",
                serde_json::json!({ "latitude": declared, "artifact": exact.or(bounded).unwrap().id }),
                None,
            ),
        }
    }

    /// Read-only operations may continue when the gate is unavailable,
    /// provided the downgrade is recorded (mirrors JS `evaluateReadOnly`).
    pub fn evaluate_read_only(&self, target: &str, turn_id: &str, contract: Option<&ExecutionContract>) -> GateDecision {
        if !self.available() {
            return gd(
                true,
                None,
                "read-only operation continuing with recorded degraded enforcement",
                serde_json::json!({ "target": target, "turnId": turn_id, "degraded": true, "reason": "gate unavailable" }),
                Some("read_only"),
            );
        }
        if let Some(contract) = contract {
            let forbidden: Vec<&str> = contract.scope.forbidden.iter().map(String::as_str).collect();
            if matches_any(&forbidden, target) {
                return gd(
                    false,
                    Some("ARC_PATH_FORBIDDEN"),
                    "read target is in the contract's forbidden scope",
                    serde_json::json!({ "target": target }),
                    None,
                );
            }
        }
        gd(true, None, "", serde_json::json!({ "target": target, "turnId": turn_id, "degraded": false }), Some("strong"))
    }

    /// Per-capability enforcement health, reported honestly (mirrors JS
    /// `health()`).
    pub fn health(&self) -> GateHealth {
        GateHealth {
            policy: if self.policy.available() { "strong" } else { "unsupported" },
            capability: if self.capability_store.is_some() { "strong" } else { "unsupported" },
            authority: if self.authority.is_some() { "strong" } else { "unsupported" },
            overall: if self.available() { "strong" } else { "unsupported" },
        }
    }
}

/// RFC3339-millisecond stamp matching `CapabilityStore`'s own (kept local
/// to avoid making the store's private formatter `pub`).
fn capability_store_stamp(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days_local(days);
    let hh = day_secs / 3600;
    let mm = (day_secs % 3600) / 60;
    let ss = day_secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

fn civil_from_days_local(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutating_effect_classes_contains_file_write_not_file_read() {
        assert!(is_mutating("FILE_WRITE"));
        assert!(!is_mutating("FILE_READ"));
    }

    #[test]
    fn path_matches_literal() {
        assert!(path_matches("src/lib/guard/mod.rs", "src/lib/guard/mod.rs"));
        assert!(!path_matches("src/lib/guard/mod.rs", "src/lib/other.rs"));
    }

    #[test]
    fn path_matches_single_star_stays_within_segment() {
        assert!(path_matches("src/*.rs", "src/lib.rs"));
        assert!(!path_matches("src/*.rs", "src/sub/lib.rs"));
    }

    #[test]
    fn path_matches_double_star_crosses_segments() {
        assert!(path_matches("src/**/mod.rs", "src/a/b/mod.rs"));
        assert!(path_matches("src/**/mod.rs", "src/mod.rs"));
    }

    #[test]
    fn path_matches_trailing_slash_is_directory_prefix() {
        assert!(path_matches("engine/crates/", "engine/crates/legion-policy/src/lib.rs"));
        assert!(!path_matches("engine/crates/", "other/legion-policy/src/lib.rs"));
    }

    #[test]
    fn path_matches_rejects_dot_dot_traversal() {
        assert!(!path_matches("**", "a/../b"));
    }

    #[test]
    fn matches_any_checks_every_pattern() {
        assert!(matches_any(&["a/*.rs", "b/*.rs"], "b/x.rs"));
        assert!(!matches_any(&["a/*.rs", "b/*.rs"], "c/x.rs"));
    }

    #[test]
    fn workspace_relative_strips_matching_prefix_case_insensitively() {
        assert_eq!(workspace_relative("/Work/Repo/src/lib.rs", Some("/work/repo")), "src/lib.rs");
    }

    #[test]
    fn workspace_relative_leaves_outside_paths_unchanged() {
        assert_eq!(workspace_relative("/elsewhere/lib.rs", Some("/work/repo")), "/elsewhere/lib.rs");
    }

    #[test]
    fn workspace_relative_without_workspace_returns_normalized_target() {
        assert_eq!(workspace_relative("a//b\\c", None), "a/b/c");
    }

    // -------------------------------------------------------------
    // PreEffectGate end-to-end tests.
    // -------------------------------------------------------------

    use crate::wf_port::wf007::policy::{EffectRule, PolicyBundle};
    use crate::wf_port::wf067::authority::AssertForTurnInput;
    use std::collections::BTreeMap;

    const VALID_ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    fn bundle() -> PolicyBundle {
        PolicyBundle {
            policy_id: "test-policy".into(),
            version: 1,
            digest: "sha256:deadbeef".into(),
            effect_rules: vec![EffectRule {
                effect_class: "FILE_WRITE".into(),
                rule: "allow".into(),
                approval_required: false,
                trust_minimum: "capability-signature".into(),
                required_enforcement: "strong".into(),
            }],
            capability: BTreeMap::from([("ttlSeconds".to_string(), "900".to_string()), ("maxUses".to_string(), "1".to_string())]),
            ..Default::default()
        }
    }

    fn ledger_with_alchemist(turn_id: &str) -> AuthorityLedger {
        let mut ledger = AuthorityLedger::new(|| 1_700_000_000_000);
        ledger
            .assert_for_turn(AssertForTurnInput {
                turn_id,
                authority: "alchemist",
                asserted_by: "host:test",
                verification_method: "capability-signature",
                per_message: true,
                source: "host",
            })
            .unwrap();
        ledger
    }

    fn contract() -> ExecutionContract {
        ExecutionContract {
            contract_id: "EC-1".into(),
            version: 1,
            source_revision: "abcdefg1".into(),
            open_question_ids: vec![],
            scope: ContractScope { own: vec!["src/**".into()], forbidden: vec![] },
            authorized_effect_classes: vec!["FILE_WRITE".into()],
            advisory_profile: None,
            artifacts: ContractArtifacts::default(),
        }
    }

    fn request() -> EffectRequest {
        EffectRequest {
            request_id: format!("req_{VALID_ULID}"),
            run_id: format!("run_{VALID_ULID}"),
            contract_id: "EC-1".into(),
            task_id: "T-1".into(),
            requested_by: "alchemist".into(),
            effect_class: "FILE_WRITE".into(),
            target: "src/lib.rs".into(),
            operation: "edit".into(),
            latitude: "BOUNDED".into(),
            source_revision: "abcdefg1".into(),
            requested_at: "2024-01-01T00:00:00Z".into(),
        }
    }

    fn gate(ledger: AuthorityLedger) -> PreEffectGate {
        PreEffectGate::new(
            PolicyHandle::Engine(PolicyEngine::new(bundle())),
            Some(CapabilityStore::new_in_memory()),
            Some(ledger),
            None,
            || 1_700_000_000_000,
        )
    }

    #[test]
    fn gate_unavailable_when_capability_store_missing_fails_closed() {
        let mut g = PreEffectGate::new(
            PolicyHandle::Engine(PolicyEngine::new(bundle())),
            None,
            Some(ledger_with_alchemist("t1")),
            None,
            || 0,
        );
        assert!(!g.available());
        let req = request();
        let ctx = EvalCtx { contract: None, turn_id: "t1", ..Default::default() };
        let d = g.evaluate(&req, &ctx);
        assert_eq!(d.code.as_deref(), Some("ARC_GATE_UNAVAILABLE"));
        assert_eq!(d.enforcement_health.as_deref(), Some("unsupported"));
    }

    #[test]
    fn authorize_mints_a_capability_and_evaluate_consumes_it() {
        let mut g = gate(ledger_with_alchemist("t1"));
        let req = request();
        let c = contract();
        let ctx = EvalCtx { contract: Some(&c), turn_id: "t1", ..Default::default() };

        let authorized = g.authorize(&req, &ctx);
        assert!(authorized.allowed, "expected allow, got {authorized:?}");
        let capability_id = authorized.detail.get("capabilityId").and_then(|v| v.as_str()).unwrap().to_string();
        assert!(capability_id.starts_with("cap_"));

        let mut eval_ctx = ctx;
        eval_ctx.capability_id = Some(&capability_id);
        let evaluated = g.evaluate(&req, &eval_ctx);
        assert!(evaluated.allowed, "expected allow, got {evaluated:?}");
        assert_eq!(evaluated.enforcement_health.as_deref(), Some("strong"));
    }

    #[test]
    fn evaluate_without_capability_id_denies_unknown() {
        let mut g = gate(ledger_with_alchemist("t1"));
        let req = request();
        let c = contract();
        let ctx = EvalCtx { contract: Some(&c), turn_id: "t1", ..Default::default() };
        let d = g.evaluate(&req, &ctx);
        assert_eq!(d.code.as_deref(), Some("ARC_CAPABILITY_UNKNOWN"));
    }

    #[test]
    fn no_contract_denies_mutation() {
        let mut g = gate(ledger_with_alchemist("t1"));
        let req = request();
        let ctx = EvalCtx { contract: None, turn_id: "t1", ..Default::default() };
        let d = g.authorize(&req, &ctx);
        assert_eq!(d.code.as_deref(), Some("ARC_NO_CONTRACT"));
    }

    #[test]
    fn path_outside_own_scope_is_denied() {
        let mut g = gate(ledger_with_alchemist("t1"));
        let mut req = request();
        req.target = "other/lib.rs".into();
        let c = contract();
        let ctx = EvalCtx { contract: Some(&c), turn_id: "t1", ..Default::default() };
        let d = g.authorize(&req, &ctx);
        assert_eq!(d.code.as_deref(), Some("ARC_PATH_NOT_OWNED"));
    }

    #[test]
    fn forbidden_path_wins_over_owned_pattern() {
        let mut g = gate(ledger_with_alchemist("t1"));
        let mut req = request();
        req.target = "src/secret.rs".into();
        let mut c = contract();
        c.scope.forbidden.push("src/secret.rs".into());
        let ctx = EvalCtx { contract: Some(&c), turn_id: "t1", ..Default::default() };
        let d = g.authorize(&req, &ctx);
        assert_eq!(d.code.as_deref(), Some("ARC_PATH_FORBIDDEN"));
    }

    #[test]
    fn exact_latitude_without_declared_artifact_is_a_violation() {
        let mut g = gate(ledger_with_alchemist("t1"));
        let mut req = request();
        req.latitude = "EXACT".into();
        let c = contract();
        let ctx = EvalCtx { contract: Some(&c), turn_id: "t1", ..Default::default() };
        let d = g.authorize(&req, &ctx);
        assert_eq!(d.code.as_deref(), Some("ARC_LATITUDE_VIOLATION"));
    }

    #[test]
    fn unauthorized_authority_is_denied_before_contract_is_consulted() {
        let mut ledger = AuthorityLedger::new(|| 0);
        ledger
            .assert_for_turn(AssertForTurnInput {
                turn_id: "t1",
                authority: "kernel",
                asserted_by: "host:test",
                verification_method: "capability-signature",
                per_message: true,
                source: "host",
            })
            .unwrap();
        let mut g = gate(ledger);
        let mut req = request();
        req.requested_by = "kernel".into();
        let ctx = EvalCtx { contract: None, turn_id: "t1", ..Default::default() };
        let d = g.authorize(&req, &ctx);
        assert_eq!(d.code.as_deref(), Some("ARC_AUTHORITY_NOT_ASSERTED"));
    }

    #[test]
    fn malformed_effect_request_fails_schema_validation() {
        let mut g = gate(ledger_with_alchemist("t1"));
        let mut req = request();
        req.effect_class = "NOT_A_REAL_CLASS".into();
        let c = contract();
        let ctx = EvalCtx { contract: Some(&c), turn_id: "t1", ..Default::default() };
        let d = g.evaluate(&req, &ctx);
        assert_eq!(d.code.as_deref(), Some("ARC_SCHEMA_INVALID"));
    }

    #[test]
    fn read_only_continues_degraded_when_gate_unavailable() {
        let g = PreEffectGate::new(PolicyHandle::Engine(PolicyEngine::new(bundle())), None, None, None, || 0);
        let d = g.evaluate_read_only("src/lib.rs", "t1", None);
        assert!(d.allowed);
        assert_eq!(d.enforcement_health.as_deref(), Some("read_only"));
        assert_eq!(d.detail.get("degraded").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn health_reports_unsupported_per_missing_dependency() {
        let g = PreEffectGate::new(PolicyHandle::Engine(PolicyEngine::new(bundle())), None, Some(ledger_with_alchemist("t1")), None, || 0);
        let h = g.health();
        assert_eq!(h.capability, "unsupported");
        assert_eq!(h.authority, "strong");
        assert_eq!(h.overall, "unsupported");
    }
}
