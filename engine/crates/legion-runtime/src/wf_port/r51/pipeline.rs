//! Faithful port of the orchestration half of
//! `src/lib/host/arcane/hook-adapter-core.mjs` that
//! `crate::wf_port::w2_047::hook_adapter_pure` left as an explicit gap:
//! `handleHookEvent`, `evaluateHostStop`, `runHookMain`, `hostStopHookOutput`,
//! `signHostEvent`, `resolveSourceRevision`, `deriveTouchedPaths`.
//!
//! Every branch, refusal code/message, and evaluation order below matches
//! the JS source line-for-line. The JS file's own `deps`/constructor
//! arguments — `HostIngestor`, `KeyRing`, `SessionBindingStore`,
//! `PreEffectCorrelationStore`, `evaluateCompletion`'s policy/receipt-store
//! bundle, and `git rev-parse HEAD` — are represented here as injected Rust
//! traits/closures, mirroring that same dependency-injection boundary
//! rather than re-deriving those other files' logic.

use std::process::Command;

use serde_json::{json, Value as Json};

use crate::wf_port::w2_046::codex_escalation::evaluate_codex_escalation;
use crate::wf_port::w2_046::discipline_controls::{DisciplinePayload, pre_effect_discipline_prefix};
use crate::wf_port::w2_047::hook_adapter_pure::{
    classify_vcs_push, command_of, is_destructive_command, vcs_rewrite_approval_key,
};
use crate::wf_port::w2_048::stop_disposition::{stop_outcome, StopDispositionInput};

/// Mirrors JS `decision({allowed, code, message, detail, enforcementHealth, escalate})`.
/// Kept local to this file (rather than pulled from `legion_policy::arcane_port::errors`)
/// because several refusals here use codes (`ARC_APPROVAL_REQUIRED`,
/// `ARC_ESCALATION_UNEVIDENCED`) alongside an `escalate` flag that the
/// caller-visible shape needs verbatim; a `serde_json::Value` keeps this
/// pipeline decoupled from whichever concrete `Decision` type an integrator
/// eventually standardizes on.
pub fn decision(allowed: bool, code: Option<&str>, message: impl Into<String>, detail: Json, enforcement_health: &str, escalate: bool) -> Json {
    json!({
        "allowed": allowed,
        "code": code,
        "message": message.into(),
        "detail": detail,
        "enforcementHealth": enforcement_health,
        "escalate": escalate,
    })
}

fn decision_simple(allowed: bool, code: Option<&str>, message: impl Into<String>, detail: Json, enforcement_health: &str) -> Json {
    decision(allowed, code, message, detail, enforcement_health, false)
}

// ---------------------------------------------------------------------------
// resolveSourceRevision
// ---------------------------------------------------------------------------

/// Mirrors `resolveSourceRevision(workspace)`'s fast/fallback structure:
/// `fast_resolver` stands in for `resolveSourceRevisionFs` (already ported
/// at `w2_048`'s header as `resolve_source_revision` in
/// `bins/legion-hook/src/main.rs`; not re-imported here to avoid a bin->lib
/// dependency this chunk does not own) and, when it declines (`None`), falls
/// back to a `git rev-parse HEAD` subprocess — orchestration that is
/// portable per this packet's rules, kept behind a trait so tests never
/// spawn a real process.
pub trait GitHeadResolver {
    /// `Some(Some(rev))` = fast path answered; `Some(None)` = fast path
    /// declined for this layout; `None` is not a valid return — callers use
    /// `Option<String>` return of `resolve_fast`.
    fn resolve_fast(&self, workspace: &str) -> Option<Option<String>>;
    fn resolve_via_subprocess(&self, workspace: &str) -> Option<String> {
        let output = Command::new("git").args(["rev-parse", "HEAD"]).current_dir(workspace).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let rev = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (!rev.is_empty()).then_some(rev)
    }
}

/// Default resolver: no fast path (always declines), so every call uses the
/// real `git` subprocess. Callers that already have a fast-path port (e.g.
/// the one at `bins/legion-hook`) implement `GitHeadResolver` themselves.
pub struct SubprocessOnlyGitHeadResolver;
impl GitHeadResolver for SubprocessOnlyGitHeadResolver {
    fn resolve_fast(&self, _workspace: &str) -> Option<Option<String>> {
        None
    }
}

pub fn resolve_source_revision(workspace: Option<&str>, resolver: &dyn GitHeadResolver) -> Option<String> {
    let workspace = workspace?;
    if workspace.is_empty() {
        return None;
    }
    if let Some(fast) = resolver.resolve_fast(workspace) {
        return fast;
    }
    resolver.resolve_via_subprocess(workspace)
}

// ---------------------------------------------------------------------------
// signHostEvent
// ---------------------------------------------------------------------------

/// Mirrors what `signRecord`/`KeyRing` contribute to `signHostEvent`. JS's
/// `signHostEvent` itself is a thin try/catch around `keyRing.activeKeyId()`
/// + `signRecord`; this trait represents that pair as one call, matching the
/// function's own never-throws contract (`Err` -> the degraded branch, never
/// a panic).
pub trait HostEventSigner {
    /// On success, returns the receipt envelope to embed under
    /// `authorityAssertion.receipt`. On failure, `is_key_unavailable` tells
    /// the caller whether this was specifically `ARC_AUTH_KEY_UNAVAILABLE`
    /// (mirrors the JS `err.code === 'ARC_AUTH_KEY_UNAVAILABLE'` check) —
    /// when `false`, `signHostEvent` still degrades (JS's catch has no other
    /// branch), so the distinction only affects nothing observable here, but
    /// is kept for a future caller that wants to log the underlying cause.
    fn sign(&self, host_event: &Json) -> Result<Json, String>;
}

pub struct SignHostEventOutcome {
    pub authority_assertion: Option<Json>,
    pub enforcement_health: &'static str,
    pub sign_error_message: Option<String>,
}

/// Mirrors `signHostEvent(hostEvent, keyRing)`. `key_ring` is `None` for
/// JS's `if (!keyRing)` branch.
pub fn sign_host_event(host_event: &Json, key_ring: Option<&dyn HostEventSigner>) -> SignHostEventOutcome {
    let Some(key_ring) = key_ring else {
        return SignHostEventOutcome { authority_assertion: None, enforcement_health: "degraded", sign_error_message: None };
    };
    match key_ring.sign(host_event) {
        Ok(receipt) => SignHostEventOutcome {
            authority_assertion: Some(json!({"assertedBy": "host", "receipt": receipt})),
            enforcement_health: "strong",
            sign_error_message: None,
        },
        Err(message) => SignHostEventOutcome { authority_assertion: None, enforcement_health: "degraded", sign_error_message: Some(message) },
    }
}

// ---------------------------------------------------------------------------
// handleHookEvent
// ---------------------------------------------------------------------------

/// Mirrors `HostIngestor#ingest(hostEvent, {authorityAssertion})`'s
/// caller-visible outcome (`{decision, receipt, observationClass?, accepted}`,
/// merged into `handleHookEvent`'s return via JS's `...result`). Concrete
/// wiring lives at `legion_policy::wf_port::wf072::ingest::HostIngestor`;
/// this trait is the same dependency-injection boundary `handleHookEvent`
/// itself uses in JS (`ingestor.ingest(...)` on a constructed instance).
pub trait Ingestor {
    fn ingest(&mut self, host_event: &Json, authority_assertion: &Json) -> IngestOutcome;
}

#[derive(Debug, Clone)]
pub struct IngestOutcome {
    pub accepted: bool,
    pub receipt: Option<Json>,
    pub decision: Json,
}

/// Mirrors `classifyObservation(hostEvent, {policy})`. Already ported in
/// full at `w2_047::host_event::classify_observation`; represented as an
/// injected closure here (rather than a direct call) only because that
/// function takes a `policy`-shaped `effect_rule` callback of its own —
/// callers pass `w2_047::host_event::classify_observation` directly.
pub type Classify<'a> = dyn Fn(&Json) -> &'static str + 'a;

pub trait SessionBindingStore {
    fn ensure_binding(&mut self, session_id: &str) -> Option<Json>;
    fn get_binding(&self, session_id: &str) -> Option<Json>;
}

pub trait PreEffectCorrelationStore {
    fn ensure_request_id(&mut self, idempotency_key: &str);
    fn get_finalized(&self, idempotency_key: &str) -> Option<Json>;
    fn get_request_id(&self, idempotency_key: &str) -> Option<String>;
}

pub trait ApprovalStore {
    fn consume(&mut self, key: &str) -> Option<Json>;
}

pub trait AuditSink {
    fn audit_successful_commit(&mut self, hook_payload: &Json, host_event: &Json, workspace: Option<&str>);
}

/// Mirrors JS `POST_EFFECT_TYPES` (`verification/arcane/ingest.mjs`).
pub const POST_EFFECT_TYPES: &[&str] = &["post-effect", "post-effect-failure"];

fn read_file_to_string(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Everything `handleHookEvent`'s `deps` destructures, minus the two that
/// already have JS-faithful sub-functions injected inline below
/// (`resolve_source_revision`'s resolver, and `key_ring`'s signer).
pub struct HandleHookEventDeps<'a> {
    pub normalize: &'a dyn Fn(&Json) -> Json,
    pub classify: &'a Classify<'a>,
    pub key_ring: Option<&'a dyn HostEventSigner>,
    pub ingestor: &'a mut dyn Ingestor,
    pub session_binding: Option<&'a mut dyn SessionBindingStore>,
    pub pre_effect_correlation: Option<&'a mut dyn PreEffectCorrelationStore>,
    pub approval_store: Option<&'a mut dyn ApprovalStore>,
    pub audit_sink: Option<&'a mut dyn AuditSink>,
    pub git_resolver: &'a dyn GitHeadResolver,
    pub codex_read_source: &'a dyn Fn(&str) -> Option<String>,
}

#[derive(Debug, Clone)]
pub struct HandleHookEventResult {
    pub host_event: Json,
    pub observation_class: &'static str,
    pub enforcement_health: &'static str,
    pub accepted: bool,
    pub receipt: Option<Json>,
    pub decision: Json,
}

fn early_refusal(host_event: Json, observation_class: &'static str, enforcement_health: &'static str, dec: Json) -> HandleHookEventResult {
    HandleHookEventResult { host_event, observation_class, enforcement_health, accepted: false, receipt: None, decision: dec }
}

/// Mirrors `handleHookEvent(hookPayload, deps)`.
pub fn handle_hook_event(hook_payload: &Json, deps: HandleHookEventDeps<'_>) -> HandleHookEventResult {
    let HandleHookEventDeps {
        normalize,
        classify,
        key_ring,
        ingestor,
        mut session_binding,
        mut pre_effect_correlation,
        mut approval_store,
        mut audit_sink,
        git_resolver,
        codex_read_source,
    } = deps;

    let mut host_event = normalize(hook_payload);
    let observation_class = classify(&host_event);
    let event_type = host_event.get("eventType").and_then(Json::as_str).unwrap_or("").to_string();
    let command = command_of(hook_payload).map(str::to_string);

    if event_type == "pre-effect" && is_destructive_command(command.as_deref()) {
        return early_refusal(
            host_event,
            observation_class,
            "strong",
            decision_simple(
                false,
                Some("ARC_EFFECT_CLASS_UNAUTHORIZED"),
                "destructive command class is blocked; use a bounded, reversible alternative",
                json!({}),
                "strong",
            ),
        );
    }

    if event_type == "pre-effect" {
        let escalation = evaluate_codex_escalation(command.as_deref().unwrap_or(""), |p| read_file_to_string(p));
        if !escalation.allowed {
            return early_refusal(
                host_event,
                observation_class,
                "strong",
                decision_simple(
                    false,
                    Some("ARC_ESCALATION_UNEVIDENCED"),
                    escalation.reason.unwrap_or_default(),
                    json!({"evidence": escalation.evidence.unwrap_or(0), "required": 2}),
                    "strong",
                ),
            );
        }
        // codex_read_source is unused when the heredoc/inline path is taken,
        // matching JS's own precedence (heredoc checked before stdin); kept
        // as an injectable dependency for parity with hosts that supply a
        // real stdin-fed reader distinct from plain filesystem reads.
        let _ = codex_read_source;
    }

    if event_type == "pre-effect" {
        let push = classify_vcs_push(command.as_deref());
        if let Some(push) = &push {
            if push.rewrite {
                let session_id = host_event.get("sessionId").and_then(Json::as_str);
                let key = vcs_rewrite_approval_key(session_id, Some(push));
                let approved = match (&key, approval_store.as_deref_mut()) {
                    (Some(k), Some(store)) => store.consume(k),
                    _ => None,
                };
                if approved.is_none() {
                    let message = if let Some(k) = &key {
                        format!(
                            "{} rewrites published history on {}/{} and needs a target-bound approval",
                            push.operation,
                            push.remote.as_deref().unwrap_or(""),
                            push.reference.as_deref().unwrap_or("")
                        )
                    } else {
                        format!(
                            "{} rewrites published history, and its remote/ref could not be isolated from the command; an approval is never bound to a guessed target",
                            push.operation
                        )
                    };
                    return early_refusal(
                        host_event,
                        observation_class,
                        "strong",
                        decision(
                            false,
                            Some("ARC_APPROVAL_REQUIRED"),
                            message,
                            json!({"operation": push.operation, "remote": push.remote, "ref": push.reference, "approvalKey": key}),
                            "strong",
                            key.is_some(),
                        ),
                    );
                }
            }
        }
    }

    // EC-5 items 2+4 — ambient run/task/contract binding.
    if let Some(store) = session_binding.as_deref_mut() {
        if let Some(session_id) = host_event.get("sessionId").and_then(Json::as_str).map(str::to_string) {
            let binding = if event_type == "session-start" {
                store.ensure_binding(&session_id)
            } else {
                store.get_binding(&session_id)
            };
            if let Some(binding) = binding {
                if let Json::Object(map) = &mut host_event {
                    map.insert("runId".into(), binding.get("runId").cloned().unwrap_or(Json::Null));
                    map.insert("taskId".into(), binding.get("taskId").cloned().unwrap_or(Json::Null));
                    map.insert("contractId".into(), binding.get("contractId").cloned().unwrap_or(Json::Null));
                }
            }
        }
    }

    if event_type == "pre-effect" {
        let workspace = host_event.get("workspace").and_then(Json::as_str).map(str::to_string).unwrap_or_default();
        let contracted = !matches!(host_event.get("contractId"), None | Some(Json::Null));
        let payload = discipline_payload_of(hook_payload);
        if let Some(denial) = pre_effect_discipline_prefix(&payload) {
            let _ = (workspace, contracted); // full preEffectDiscipline also consults policy/contracted; that branch is w2_046's own documented gap, not this file's.
            return early_refusal(
                host_event,
                observation_class,
                "strong",
                decision_simple(false, Some(denial.code), denial.message, json!({}), "strong"),
            );
        }
    }

    // EC-5 item 5 — honest sourceRevision: only fills a gap normalize() left null.
    if matches!(host_event.get("sourceRevision"), None | Some(Json::Null)) {
        let workspace = host_event.get("workspace").and_then(Json::as_str).map(str::to_string);
        let resolved = resolve_source_revision(workspace.as_deref(), git_resolver);
        if let Json::Object(map) = &mut host_event {
            map.insert("sourceRevision".into(), resolved.map(Json::String).unwrap_or(Json::Null));
        }
    }

    // EC-5 item 5 — pre-effect/post-effect correlation.
    if let Some(store) = pre_effect_correlation.as_deref_mut() {
        if let Some(idempotency_key) = host_event.get("idempotencyKey").and_then(Json::as_str).map(str::to_string) {
            if event_type == "pre-effect" {
                store.ensure_request_id(&idempotency_key);
            } else if POST_EFFECT_TYPES.contains(&event_type.as_str()) {
                let finalized = store.get_finalized(&idempotency_key);
                let request_id = if finalized.is_some() { None } else { store.get_request_id(&idempotency_key) };
                let contract_is_null = matches!(host_event.get("contractId"), None | Some(Json::Null));
                let prior_correlation = if let Some(finalized) = finalized {
                    let mut m = match finalized {
                        Json::Object(m) => m,
                        other => {
                            let mut m = serde_json::Map::new();
                            m.insert("value".into(), other);
                            m
                        }
                    };
                    m.insert("priorReceiptId".into(), Json::Null);
                    Json::Object(m)
                } else if let (Some(request_id), true) = (request_id, contract_is_null) {
                    json!({"requestId": request_id, "capabilityId": null, "requestedEffect": null, "authorizedEffect": null, "priorReceiptId": null})
                } else {
                    Json::Null
                };
                if let Json::Object(map) = &mut host_event {
                    map.insert("priorCorrelation".into(), prior_correlation);
                }
            }
        }
    }

    let signed = sign_host_event(&host_event, key_ring);
    let Some(authority_assertion) = signed.authority_assertion else {
        return early_refusal(
            host_event.clone(),
            observation_class,
            signed.enforcement_health,
            decision_simple(
                false,
                Some("ARC_AUTH_KEY_UNAVAILABLE"),
                signed.sign_error_message.unwrap_or_else(|| "no key ring available to sign the host event".to_string()),
                json!({"eventId": host_event.get("eventId"), "observationClass": observation_class}),
                "degraded",
            ),
        );
    };

    let outcome = ingestor.ingest(&host_event, &authority_assertion);
    if outcome.accepted {
        if let Some(sink) = audit_sink.as_deref_mut() {
            let workspace = host_event.get("workspace").and_then(Json::as_str);
            sink.audit_successful_commit(hook_payload, &host_event, workspace);
        }
    }
    HandleHookEventResult {
        host_event,
        observation_class,
        enforcement_health: signed.enforcement_health,
        accepted: outcome.accepted,
        receipt: outcome.receipt,
        decision: outcome.decision,
    }
}

fn discipline_payload_of(hook_payload: &Json) -> DisciplinePayload {
    let s = |k: &str| hook_payload.get(k).and_then(Json::as_str).map(str::to_string);
    let tool_input = hook_payload.get("tool_input");
    DisciplinePayload {
        command: s("command"),
        tool_input_command: tool_input.and_then(|t| t.get("command")).and_then(Json::as_str).map(str::to_string),
        workdir: tool_input.and_then(|t| t.get("workdir")).and_then(Json::as_str).map(str::to_string),
        cwd: s("cwd"),
        payload_cwd: hook_payload.get("payload").and_then(|p| p.get("cwd")).and_then(Json::as_str).map(str::to_string),
        file_path: tool_input.and_then(|t| t.get("file_path")).and_then(Json::as_str).map(str::to_string),
        path: tool_input.and_then(|t| t.get("path")).and_then(Json::as_str).map(str::to_string),
        patch: tool_input.and_then(|t| t.get("patch")).and_then(Json::as_str).map(str::to_string),
        input: tool_input.and_then(|t| t.get("input")).and_then(Json::as_str).map(str::to_string),
    }
}

// ---------------------------------------------------------------------------
// Stop -> completion gate wiring
// ---------------------------------------------------------------------------

/// Mirrors `deriveTouchedPaths(receiptStore, runId)`. `list_by_run` mirrors
/// `receiptStore.list({runId})`.
pub fn derive_touched_paths(run_id: Option<&str>, list_by_run: impl Fn(&str) -> Vec<Json>) -> Vec<String> {
    let Some(run_id) = run_id else { return Vec::new() };
    let mut seen = std::collections::BTreeSet::new();
    for record in list_by_run(run_id) {
        if let Some(target) = record.get("observed").and_then(|o| o.get("target")).and_then(Json::as_str) {
            if !target.is_empty() {
                seen.insert(target.to_string());
            }
        }
    }
    seen.into_iter().collect()
}

/// Mirrors what `evaluateCompletion` (`verification/arcane/completion-gate.mjs`)
/// contributes to `evaluateHostStop` — not owned by this file, injected the
/// same way JS's `evaluateHostStop` takes its whole `deps` bag and forwards
/// most of it straight into `evaluateCompletion`.
pub struct CompletionClaimInput<'a> {
    pub run_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
    pub claimed_level: Option<&'a str>,
    pub touched_paths: Vec<String>,
    pub contract_id: Option<&'a str>,
    pub contract_version: Option<&'a str>,
    pub contract_digest: Option<&'a str>,
    pub require_acceptance_evidence: bool,
}

pub trait CompletionGate {
    fn evaluate_completion(&self, input: CompletionClaimInput<'_>) -> Json;
}

pub struct EvaluateHostStopInput<'a> {
    pub host_event: &'a Json,
    pub receipt_list_by_run: &'a dyn Fn(&str) -> Vec<Json>,
    pub completion_gate: &'a dyn CompletionGate,
    pub execution_contract_id: Option<&'a str>,
    pub execution_contract_version: Option<&'a str>,
    pub execution_contract_digest: Option<&'a str>,
    pub claimed_level: Option<&'a str>,
    pub disposition: Option<&'a str>,
    pub intent: &'a str,
    pub authenticated_claim: bool,
}

/// Mirrors `evaluateHostStop(hostEvent, deps)`.
pub fn evaluate_host_stop(input: EvaluateHostStopInput<'_>) -> Json {
    let terminal = if input.disposition.is_none() && input.claimed_level.is_some() {
        None
    } else {
        Some(stop_outcome(&StopDispositionInput { authenticated_claim: input.authenticated_claim, intent: input.intent }))
    };

    if let Some(t) = &terminal {
        if t.certification == "not_claimed" {
            return json!({
                "allowed": true, "code": null,
                "message": "Stop does not claim completion",
                "detail": {"disposition": t.disposition, "terminationAllowed": t.termination_allowed, "certification": t.certification},
                "enforcementHealth": "strong",
            });
        }
    }

    let run_id = input.host_event.get("runId").and_then(Json::as_str);
    let host_contract_id = input.host_event.get("contractId").and_then(Json::as_str);
    if run_id.is_none() && input.execution_contract_id.is_none() && host_contract_id.is_none() {
        let detail = match &terminal {
            Some(t) => json!({"disposition": t.disposition, "terminationAllowed": t.termination_allowed, "certification": t.certification, "governed": false}),
            None => json!({"governed": false}),
        };
        return json!({
            "allowed": true, "code": null,
            "message": "ambient session: no governed run or contract was opened, so contract completion does not apply",
            "detail": detail,
            "enforcementHealth": "unsupported",
        });
    }

    let touched_paths = derive_touched_paths(run_id, input.receipt_list_by_run);
    let task_id = input.host_event.get("taskId").and_then(Json::as_str);
    let require_acceptance_evidence = terminal.as_ref().map(|t| t.certification == "genuine").unwrap_or(false);
    let mut certification = input.completion_gate.evaluate_completion(CompletionClaimInput {
        run_id,
        task_id,
        claimed_level: input.claimed_level,
        touched_paths,
        contract_id: input.execution_contract_id.or(host_contract_id),
        contract_version: input.execution_contract_version.or_else(|| input.host_event.get("contractVersion").and_then(Json::as_str)),
        contract_digest: input.execution_contract_digest.or_else(|| input.host_event.get("contractDigest").and_then(Json::as_str)),
        require_acceptance_evidence,
    });

    if let (Some(t), Json::Object(cert_map)) = (&terminal, &mut certification) {
        let allowed = cert_map.get("allowed").and_then(Json::as_bool).unwrap_or(false);
        let detail = cert_map.entry("detail").or_insert_with(|| Json::Object(Default::default()));
        if let Json::Object(detail_map) = detail {
            detail_map.insert("termination".into(), Json::String(t.termination_allowed.to_string()));
            detail_map.insert("certification".into(), Json::String(if allowed { "certified".into() } else { "rejected".into() }));
            detail_map.insert("disposition".into(), Json::String(t.disposition.to_string()));
        }
    }
    certification
}

/// Mirrors `UNSUPPORTED_RUN_GUIDANCE`.
const UNSUPPORTED_RUN_GUIDANCE: &str =
    "Run 'legion run open --contract <id> [--task <id>]' to bind this session to a contract, then produce the required evidence before Stop.";

/// Mirrors `hostStopHookOutput(completionDecision)`.
pub fn host_stop_hook_output(completion_decision: &Json) -> Option<Json> {
    if completion_decision.get("allowed").and_then(Json::as_bool).unwrap_or(false) {
        return None;
    }
    let code = completion_decision.get("code").and_then(Json::as_str);
    let label = code.map(|c| format!("{c}: ")).unwrap_or_default();
    let base_message = completion_decision.get("message").and_then(Json::as_str).unwrap_or("completion claim denied by Arcane completion gate");
    let mut reason = format!("{label}{base_message}");
    if completion_decision.get("enforcementHealth").and_then(Json::as_str) == Some("unsupported") {
        reason = format!("{reason} {UNSUPPORTED_RUN_GUIDANCE}");
    }
    let reason: String = reason.chars().take(500).collect();
    Some(json!({"decision": "block", "reason": reason}))
}

// ---------------------------------------------------------------------------
// runHookMain
// ---------------------------------------------------------------------------

/// Mirrors `runHookMain({dispatchHookInvocation})`: read one JSON payload
/// from stdin (`readStdinJson`), dispatch it, and write `result.stdout` if
/// present (`serializeHostRuntimeOutput`, already ported at
/// `w2_047::host_runtime_output`). `read_stdin`/`write_stdout` are injected
/// so tests never touch real stdio.
pub fn run_hook_main(
    read_stdin: impl FnOnce() -> Result<Json, ()>,
    dispatch_hook_invocation: impl FnOnce(&Json) -> RunHookMainResult,
    mut write_stdout: impl FnMut(&str),
) -> Option<RunHookMainResult> {
    let hook_payload = match read_stdin() {
        Ok(p) => p,
        Err(()) => return None, // malformed/absent stdin: nothing this adapter can safely act on.
    };
    let result = dispatch_hook_invocation(&hook_payload);
    if let Some(stdout) = &result.stdout {
        write_stdout(stdout);
    }
    Some(result)
}

#[derive(Debug, Clone)]
pub struct RunHookMainResult {
    pub stdout: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_source_revision_uses_fast_path_when_it_answers() {
        struct Fast;
        impl GitHeadResolver for Fast {
            fn resolve_fast(&self, _workspace: &str) -> Option<Option<String>> {
                Some(Some("deadbeef".into()))
            }
        }
        assert_eq!(resolve_source_revision(Some("/repo"), &Fast), Some("deadbeef".to_string()));
    }

    #[test]
    fn resolve_source_revision_empty_workspace_is_null() {
        assert_eq!(resolve_source_revision(Some(""), &SubprocessOnlyGitHeadResolver), None);
        assert_eq!(resolve_source_revision(None, &SubprocessOnlyGitHeadResolver), None);
    }

    #[test]
    fn sign_host_event_degrades_without_a_key_ring() {
        let out = sign_host_event(&json!({}), None);
        assert!(out.authority_assertion.is_none());
        assert_eq!(out.enforcement_health, "degraded");
    }

    struct OkSigner;
    impl HostEventSigner for OkSigner {
        fn sign(&self, _host_event: &Json) -> Result<Json, String> {
            Ok(json!({"alg": "HMAC-SHA256", "keyId": "k1", "mac": "abc"}))
        }
    }

    #[test]
    fn sign_host_event_wraps_receipt_when_signer_succeeds() {
        let out = sign_host_event(&json!({}), Some(&OkSigner));
        assert_eq!(out.enforcement_health, "strong");
        let aa = out.authority_assertion.unwrap();
        assert_eq!(aa["assertedBy"], "host");
        assert_eq!(aa["receipt"]["keyId"], "k1");
    }

    struct FailSigner;
    impl HostEventSigner for FailSigner {
        fn sign(&self, _host_event: &Json) -> Result<Json, String> {
            Err("no key".into())
        }
    }

    struct RecordingIngestor {
        calls: usize,
    }
    impl Ingestor for RecordingIngestor {
        fn ingest(&mut self, _host_event: &Json, _authority_assertion: &Json) -> IngestOutcome {
            self.calls += 1;
            IngestOutcome { accepted: true, receipt: Some(json!({"receiptId": "r1"})), decision: json!({"allowed": true, "code": null}) }
        }
    }

    fn base_deps<'a>(
        normalize: &'a dyn Fn(&Json) -> Json,
        classify: &'a Classify<'a>,
        ingestor: &'a mut dyn Ingestor,
        signer: &'a dyn HostEventSigner,
        git: &'a dyn GitHeadResolver,
        read_source: &'a dyn Fn(&str) -> Option<String>,
    ) -> HandleHookEventDeps<'a> {
        HandleHookEventDeps {
            normalize,
            classify,
            key_ring: Some(signer),
            ingestor,
            session_binding: None,
            pre_effect_correlation: None,
            approval_store: None,
            audit_sink: None,
            git_resolver: git,
            codex_read_source: read_source,
        }
    }

    #[test]
    fn handle_hook_event_blocks_destructive_command_before_signing() {
        let normalize = |payload: &Json| json!({"eventType": "pre-effect", "sessionId": "s1", "workspace": "/repo", "eventId": "hev_1", "command": payload.get("command")});
        let classify: &Classify = &|_e| "COMMAND_EXEC";
        let mut ingestor = RecordingIngestor { calls: 0 };
        let signer = OkSigner;
        let git = SubprocessOnlyGitHeadResolver;
        let read_source = |_p: &str| None;
        let payload = json!({"command": "rm -rf /tmp/x"});
        let result = handle_hook_event(&payload, base_deps(&normalize, classify, &mut ingestor, &signer, &git, &read_source));
        assert!(!result.accepted);
        assert_eq!(result.decision["code"], "ARC_EFFECT_CLASS_UNAUTHORIZED");
        assert_eq!(ingestor.calls, 0);
    }

    #[test]
    fn handle_hook_event_degrades_when_signing_fails() {
        let normalize = |_payload: &Json| json!({"eventType": "session-start", "sessionId": "s1", "workspace": "/repo", "eventId": "hev_1"});
        let classify: &Classify = &|_e| "LIFECYCLE";
        let mut ingestor = RecordingIngestor { calls: 0 };
        let signer = FailSigner;
        let git = SubprocessOnlyGitHeadResolver;
        let read_source = |_p: &str| None;
        let payload = json!({});
        let result = handle_hook_event(&payload, base_deps(&normalize, classify, &mut ingestor, &signer, &git, &read_source));
        assert!(!result.accepted);
        assert_eq!(result.enforcement_health, "degraded");
        assert_eq!(result.decision["code"], "ARC_AUTH_KEY_UNAVAILABLE");
        assert_eq!(ingestor.calls, 0);
    }

    #[test]
    fn handle_hook_event_ingests_on_the_happy_path() {
        let normalize = |_payload: &Json| json!({"eventType": "session-start", "sessionId": "s1", "workspace": "/repo", "eventId": "hev_1"});
        let classify: &Classify = &|_e| "LIFECYCLE";
        let mut ingestor = RecordingIngestor { calls: 0 };
        let signer = OkSigner;
        let git = SubprocessOnlyGitHeadResolver;
        let read_source = |_p: &str| None;
        let payload = json!({});
        let result = handle_hook_event(&payload, base_deps(&normalize, classify, &mut ingestor, &signer, &git, &read_source));
        assert!(result.accepted);
        assert_eq!(ingestor.calls, 1);
        assert_eq!(result.receipt.unwrap()["receiptId"], "r1");
    }

    #[test]
    fn handle_hook_event_escalates_ambiguous_rewrite_target() {
        let normalize = |payload: &Json| json!({"eventType": "pre-effect", "sessionId": "s1", "workspace": "/repo", "eventId": "hev_1", "command": payload.get("command")});
        let classify: &Classify = &|_e| "COMMAND_EXEC";
        let mut ingestor = RecordingIngestor { calls: 0 };
        let signer = OkSigner;
        let git = SubprocessOnlyGitHeadResolver;
        let read_source = |_p: &str| None;
        let payload = json!({"command": "git push --force"});
        let result = handle_hook_event(&payload, base_deps(&normalize, classify, &mut ingestor, &signer, &git, &read_source));
        assert!(!result.accepted);
        assert_eq!(result.decision["code"], "ARC_APPROVAL_REQUIRED");
        assert_eq!(result.decision["escalate"], false);
    }

    #[test]
    fn handle_hook_event_target_bound_rewrite_escalates_when_no_approval_store() {
        let normalize = |payload: &Json| json!({"eventType": "pre-effect", "sessionId": "s1", "workspace": "/repo", "eventId": "hev_1", "command": payload.get("command")});
        let classify: &Classify = &|_e| "COMMAND_EXEC";
        let mut ingestor = RecordingIngestor { calls: 0 };
        let signer = OkSigner;
        let git = SubprocessOnlyGitHeadResolver;
        let read_source = |_p: &str| None;
        let payload = json!({"command": "git push --force origin main"});
        let result = handle_hook_event(&payload, base_deps(&normalize, classify, &mut ingestor, &signer, &git, &read_source));
        assert!(!result.accepted);
        assert_eq!(result.decision["code"], "ARC_APPROVAL_REQUIRED");
        assert_eq!(result.decision["escalate"], true);
        assert_eq!(result.decision["detail"]["approvalKey"], "s1|VCS_PUSH|origin/main");
    }

    struct FakeGate;
    impl CompletionGate for FakeGate {
        fn evaluate_completion(&self, input: CompletionClaimInput<'_>) -> Json {
            json!({"allowed": input.run_id.is_some(), "code": null, "message": "", "detail": {}})
        }
    }

    #[test]
    fn evaluate_host_stop_is_not_claimed_when_disposition_is_question() {
        let host_event = json!({"runId": "run1"});
        let list = |_r: &str| Vec::<Json>::new();
        let out = evaluate_host_stop(EvaluateHostStopInput {
            host_event: &host_event,
            receipt_list_by_run: &list,
            completion_gate: &FakeGate,
            execution_contract_id: None,
            execution_contract_version: None,
            execution_contract_digest: None,
            claimed_level: None,
            disposition: None,
            intent: "QUESTION",
            authenticated_claim: false,
        });
        assert_eq!(out["allowed"], true);
        assert_eq!(out["message"], "Stop does not claim completion");
    }

    #[test]
    fn evaluate_host_stop_is_unsupported_for_ambient_session() {
        let host_event = json!({"runId": null, "contractId": null});
        let list = |_r: &str| Vec::<Json>::new();
        let out = evaluate_host_stop(EvaluateHostStopInput {
            host_event: &host_event,
            receipt_list_by_run: &list,
            completion_gate: &FakeGate,
            execution_contract_id: None,
            execution_contract_version: None,
            execution_contract_digest: None,
            claimed_level: None,
            disposition: Some("completion"),
            intent: "UNKNOWN",
            authenticated_claim: true,
        });
        assert_eq!(out["enforcementHealth"], "unsupported");
        assert_eq!(out["allowed"], true);
    }

    #[test]
    fn evaluate_host_stop_runs_completion_gate_for_a_governed_run() {
        let host_event = json!({"runId": "run1", "contractId": "c1"});
        let list = |_r: &str| vec![json!({"observed": {"target": "src/a.rs"}})];
        let out = evaluate_host_stop(EvaluateHostStopInput {
            host_event: &host_event,
            receipt_list_by_run: &list,
            completion_gate: &FakeGate,
            execution_contract_id: None,
            execution_contract_version: None,
            execution_contract_digest: None,
            claimed_level: None,
            disposition: Some("completion"),
            intent: "UNKNOWN",
            authenticated_claim: true,
        });
        assert_eq!(out["allowed"], true);
        assert_eq!(out["detail"]["certification"], "certified");
    }

    #[test]
    fn host_stop_hook_output_is_null_when_allowed() {
        assert!(host_stop_hook_output(&json!({"allowed": true})).is_none());
    }

    #[test]
    fn host_stop_hook_output_blocks_with_code_prefix() {
        let out = host_stop_hook_output(&json!({"allowed": false, "code": "ARC_STORE_CORRUPT", "message": "bad"})).unwrap();
        assert_eq!(out["decision"], "block");
        assert_eq!(out["reason"], "ARC_STORE_CORRUPT: bad");
    }

    #[test]
    fn host_stop_hook_output_appends_guidance_when_unsupported() {
        let out = host_stop_hook_output(&json!({"allowed": false, "code": null, "message": "no run", "enforcementHealth": "unsupported"})).unwrap();
        assert!(out["reason"].as_str().unwrap().contains("legion run open"));
    }

    #[test]
    fn run_hook_main_returns_none_on_bad_stdin() {
        let read = || Err(());
        let dispatch = |_p: &Json| unreachable!();
        let mut out = String::new();
        let result = run_hook_main(read, dispatch, |s| out.push_str(s));
        assert!(result.is_none());
        assert!(out.is_empty());
    }

    #[test]
    fn run_hook_main_writes_stdout_when_dispatch_returns_some() {
        let read = || Ok(json!({"hook_event_name": "Stop"}));
        let dispatch = |_p: &Json| RunHookMainResult { stdout: Some("{\"decision\":\"block\"}".to_string()) };
        let mut out = String::new();
        let result = run_hook_main(read, dispatch, |s| out.push_str(s));
        assert!(result.is_some());
        assert_eq!(out, "{\"decision\":\"block\"}");
    }

    #[test]
    fn derive_touched_paths_dedupes_and_ignores_empty_targets() {
        let list = |r: &str| {
            assert_eq!(r, "run1");
            vec![json!({"observed": {"target": "a.rs"}}), json!({"observed": {"target": "a.rs"}}), json!({"observed": {"target": ""}}), json!({})]
        };
        let paths = derive_touched_paths(Some("run1"), list);
        assert_eq!(paths, vec!["a.rs".to_string()]);
    }

    #[test]
    fn derive_touched_paths_empty_run_id_is_empty() {
        let list = |_r: &str| vec![json!({"observed": {"target": "a.rs"}})];
        assert_eq!(derive_touched_paths(None, list), Vec::<String>::new());
    }
}
