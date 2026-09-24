//! Port of `skills/designer/engine/scripts/live/manual-edit-routes.mjs`.
//!
//! `createManualEditRoutes` wires Node's raw HTTP `req`/`res` to five
//! routes. Its own dependencies (`getToken`, `manualApply`,
//! `recordManualEditActivity`, `getManualEditStatus`,
//! `chatAgentLikelyActive`, `cwd`, `env`) were already injected as closures
//! in the JS constructor; here they are the [`ManualEditRoutesDeps`] trait,
//! so the whole dispatch is testable with fakes and hits no real HTTP
//! socket, subprocess, or browser. `validateEvent` (from
//! `./event-validation.mjs`, outside this chunk) and `buildManualEditEvidence`
//! / `commitManualEdits` (from `../live-manual-edit-evidence.mjs` and
//! `../live-commit-manual-edits.mjs`, also outside this chunk) are exactly
//! as external to `manual-edit-routes.mjs` in JS as they are here, so they
//! are likewise trait methods rather than direct calls, which keeps this
//! port's behaviour (route matching, status codes, field names, event
//! payloads) faithful without inlining logic this file doesn't own.
//!
//! Node reads the POST body as a stream (`req.on('data'/'end')`) before
//! parsing JSON; that plumbing is not portable I/O and is modelled here as
//! the caller having already collected the body into
//! [`ManualEditRequest::body`] (`None` = no body / GET, `Some(Err(_))` =
//! present but invalid JSON, matching the `catch` -> 400 branch).
//!
//! `/manual-edit-commit`'s async branch in JS sends the 202 response
//! immediately and then continues the commit in the background with no
//! further HTTP response (the socket is already closed). That is modelled
//! by [`handle_manual_edit_route`] still running the full commit (so the
//! same `recordManualEditActivity` side effects fire, matching the real
//! background execution) but returning the 202 body as the route's result
//! when `async=1`, discarding the eventual 200/500 body exactly as the real
//! server does (nothing is written to `res` a second time).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::manual_apply::{summarize_manual_apply_failures, summarize_manual_diagnostics};
use super::manual_edits_buffer::{
    count_by_page, read_buffer, remove_entries, stage_entry, truncate_buffer,
};

/// Views a JSON `Value` as an array slice, treating anything that is not a
/// JSON array (including `Value::Null`, the common "field absent" case
/// here) as an empty array.
fn as_value_slice(value: &Value) -> &[Value] {
    static EMPTY: Vec<Value> = Vec::new();
    value.as_array().map(|a| a.as_slice()).unwrap_or(&EMPTY)
}

#[derive(Debug, Clone, PartialEq)]
pub struct PendingManualEditBatchSummary {
    pub pending_entry_count: usize,
    pub pending_op_count: usize,
}

/// Port of `summarizePendingManualEditBatch(cwd, pageUrl = null)`. The JS
/// version wraps the read in try/catch and returns
/// `{ pendingSummaryError }` on failure; `read_buffer` here never errors
/// (unreadable/invalid buffers degrade to empty, matching `readBuffer`, not
/// `readBufferStrict`), so this always succeeds.
pub fn summarize_pending_manual_edit_batch(
    cwd: &Path,
    page_url: Option<&str>,
) -> PendingManualEditBatchSummary {
    let buffer = read_buffer(cwd);
    let entries: Vec<_> = buffer
        .entries
        .into_iter()
        .filter(|entry| match page_url {
            Some(p) => entry.page_url.as_deref() == Some(p),
            None => true,
        })
        .collect();
    let pending_op_count = entries.iter().map(|e| e.ops.len()).sum();
    PendingManualEditBatchSummary {
        pending_entry_count: entries.len(),
        pending_op_count,
    }
}

/// An incoming request, pre-parsed exactly as far as Node's HTTP layer
/// parses it before handing off to `handleManualEditRoute`: method, `url`
/// pathname, `url.searchParams`, and (for the two JSON-body routes) the
/// already-collected body, JSON-parsed or not.
#[derive(Debug, Clone, Default)]
pub struct ManualEditRequest {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    /// `None` for GET routes / bodyless routes. `Some(Err(..))` mirrors the
    /// `JSON.parse` throwing inside the route's own `try`/`catch`.
    pub body: Option<Result<Value, String>>,
}

impl ManualEditRequest {
    pub fn query(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Value,
}

impl HttpResponse {
    fn json(status: u16, body: Value) -> Self {
        Self { status, body }
    }
}

/// Args for [`ManualEditRoutesDeps::commit_manual_edits`], mirroring the
/// options object passed to `commitManualEdits` in
/// `../live-commit-manual-edits.mjs` (outside this chunk).
#[derive(Debug, Clone)]
pub struct CommitManualEditsArgs {
    pub page_url: Option<String>,
    pub provider: Option<String>,
    pub use_chat_route: bool,
    pub timeout_ms: i64,
    pub repair_only: bool,
    pub transaction_id: Option<String>,
    pub batch: Option<Value>,
}

/// Everything `createManualEditRoutes({ ... })` took as constructor
/// arguments in JS, plus the two out-of-chunk direct imports
/// (`buildManualEditEvidence`, `commitManualEdits`) and `validateEvent`,
/// all as trait methods so tests supply fakes instead of touching the
/// filesystem, a subprocess, or a browser.
pub trait ManualEditRoutesDeps {
    fn token(&self) -> String;
    fn project_cwd(&self) -> PathBuf;
    /// `IMPECCABLE_LIVE_COPY_AGENT` (lowercased, trimmed) and
    /// `IMPECCABLE_LIVE_COPY_AGENT_TIMEOUT_MS`, matching `env()` usage in
    /// the commit route.
    fn copy_agent_mode(&self) -> String;
    fn copy_agent_timeout_ms(&self) -> i64;
    fn chat_agent_likely_active(&self) -> bool;
    fn record_manual_edit_activity(&self, event: &str, payload: Value);
    fn manual_edit_status(&self) -> PendingManualEditBatchSummaryTotals;

    /// Port of `validateEvent({ ...msg, type: 'manual_edits' })`.
    fn validate_manual_edits_event(&self, msg: &Value) -> Option<String>;

    // -- `manualApply` controller (from `manual-apply.mjs`, stateful I/O) --
    fn read_transaction(&self) -> Option<Value>;
    fn rollback_transaction(&self, page_url: Option<&str>, reason: &str) -> Option<Value>;
    fn write_transaction(&self, page_url: Option<&str>, batch: &Value) -> Value;
    fn clear_transaction(&self, transaction_id: &str);
    fn cancel_pending_events(&self, page_url: Option<&str>) -> Vec<Value>;

    // -- outside-chunk direct imports --
    fn build_manual_edit_evidence(&self, page_url: Option<&str>) -> Value;
    fn commit_manual_edits(&self, args: CommitManualEditsArgs) -> Result<Value, String>;
}

#[derive(Debug, Clone, Default)]
pub struct PendingManualEditBatchSummaryTotals {
    pub total_count: usize,
    /// `pageUrl -> count`.
    pub per_page: Vec<(String, usize)>,
}

impl PendingManualEditBatchSummaryTotals {
    fn per_page_value(&self) -> Value {
        Value::Object(
            self.per_page
                .iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect(),
        )
    }
    fn for_page(&self, page_url: Option<&str>) -> usize {
        match page_url {
            None => self.total_count,
            Some(p) => self
                .per_page
                .iter()
                .find(|(k, _)| k == p)
                .map(|(_, v)| *v)
                .unwrap_or(0),
        }
    }
}

fn is_truthy_flag(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.to_ascii_lowercase()),
        Some(ref s) if s == "1" || s == "true" || s == "yes"
    )
}

/// Port of `handleManualEditRoute(req, res, url)`. Returns `None` when no
/// route matched (JS `return false`, meaning the caller should try the next
/// handler in the chain).
pub fn handle_manual_edit_route(
    deps: &dyn ManualEditRoutesDeps,
    req: &ManualEditRequest,
) -> Option<HttpResponse> {
    let cwd = deps.project_cwd();

    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/manual-edit-stash") => Some(handle_stash(deps, req, &cwd)),
        ("GET", "/manual-edit-stash") => Some(handle_stash_get(deps, req, &cwd)),
        ("POST", "/manual-edit-commit") => Some(handle_commit(deps, req, &cwd)),
        ("POST", "/manual-edit-repair-decision") => Some(handle_repair_decision(deps, req, &cwd)),
        ("POST", "/manual-edit-discard") => Some(handle_discard(deps, req, &cwd)),
        ("POST", "/manual-edit") => Some(HttpResponse::json(
            410,
            json!({
                "error": "/manual-edit is removed; use /manual-edit-stash and /manual-edit-commit for staged copy edits.",
            }),
        )),
        _ => None,
    }
}

fn handle_stash(deps: &dyn ManualEditRoutesDeps, req: &ManualEditRequest, cwd: &Path) -> HttpResponse {
    let msg = match &req.body {
        Some(Ok(v)) => v.clone(),
        _ => return HttpResponse::json(400, json!({ "error": "Invalid JSON" })),
    };
    if msg.get("token").and_then(Value::as_str) != Some(deps.token().as_str()) {
        return HttpResponse::json(401, json!({ "error": "Unauthorized" }));
    }
    let mut validated = msg.clone();
    if let Value::Object(ref mut map) = validated {
        map.insert("type".into(), json!("manual_edits"));
    }
    if let Some(error) = deps.validate_manual_edits_event(&validated) {
        return HttpResponse::json(400, json!({ "error": error }));
    }

    let id = msg.get("id").and_then(Value::as_str).unwrap_or_default();
    let page_url = msg.get("pageUrl").and_then(Value::as_str).unwrap_or_default();
    let element = msg.get("element").cloned();
    let ops: Vec<super::manual_edits_buffer::ManualEditOp> = msg
        .get("ops")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|op| serde_json::from_value(op).unwrap_or_default())
        .collect();
    let op_count = ops.len();

    if let Err(err) = stage_entry(cwd, id, page_url, element, ops) {
        return HttpResponse::json(
            500,
            json!({ "error": "stash_write_failed", "message": err.to_string() }),
        );
    }

    let counts = count_by_page(cwd);
    let pending_count = counts.per_page.get(page_url).copied().unwrap_or(0);
    let total_count = counts.total_count;

    let hinted_file_count = msg
        .get("ops")
        .and_then(Value::as_array)
        .map(|ops| {
            let mut files = std::collections::HashSet::new();
            for op in ops {
                if let Some(file) = op
                    .get("sourceHint")
                    .and_then(|h| h.get("file"))
                    .and_then(Value::as_str)
                {
                    if let Some(summarized) =
                        super::manual_apply::summarize_manual_log_file(Some(file), cwd)
                    {
                        files.insert(summarized);
                    }
                }
            }
            files.len()
        })
        .unwrap_or(0);

    deps.record_manual_edit_activity(
        "manual_edit_stashed",
        json!({
            "id": id,
            "pageUrl": page_url,
            "opCount": op_count,
            "pendingCount": pending_count,
            "totalCount": total_count,
            "hintedFileCount": hinted_file_count,
        }),
    );

    HttpResponse::json(
        200,
        json!({
            "ok": true,
            "pendingCount": pending_count,
            "totalCount": total_count,
            "perPage": per_page_json(&counts),
        }),
    )
}

fn handle_stash_get(
    deps: &dyn ManualEditRoutesDeps,
    req: &ManualEditRequest,
    cwd: &Path,
) -> HttpResponse {
    if req.query("token") != Some(deps.token().as_str()) {
        return HttpResponse::json(401, json!({ "error": "Unauthorized" }));
    }
    let page_url = req.query("pageUrl").unwrap_or("");
    let counts = count_by_page(cwd);
    let buffer = read_buffer(cwd);
    let entries: Vec<_> = if page_url.is_empty() {
        buffer.entries
    } else {
        buffer
            .entries
            .into_iter()
            .filter(|e| e.page_url.as_deref() == Some(page_url))
            .collect()
    };
    let count = if page_url.is_empty() {
        counts.total_count
    } else {
        counts.per_page.get(page_url).copied().unwrap_or(0)
    };
    HttpResponse::json(
        200,
        json!({
            "count": count,
            "totalCount": counts.total_count,
            "perPage": per_page_json(&counts),
            "entries": entries,
        }),
    )
}

fn handle_commit(deps: &dyn ManualEditRoutesDeps, req: &ManualEditRequest, cwd: &Path) -> HttpResponse {
    if req.query("token") != Some(deps.token().as_str()) {
        return HttpResponse::json(401, json!({ "error": "Unauthorized" }));
    }
    let page_url = req.query("pageUrl").map(|s| s.to_string());
    let async_mode = is_truthy_flag(req.query("async"));
    let repair_only = is_truthy_flag(req.query("repair"));

    let existing_transaction = deps.read_transaction();
    if repair_only && existing_transaction.is_none() {
        return HttpResponse::json(409, json!({ "error": "manual_edit_repair_transaction_missing" }));
    }
    let recovered_transaction = if repair_only {
        None
    } else {
        deps.rollback_transaction(
            page_url.as_deref(),
            "manual_edit_commit_recovered_abandoned_transaction",
        )
    };

    let before = deps.manual_edit_status();
    let pending_count = before.for_page(page_url.as_deref());
    let pending_summary = summarize_pending_manual_edit_batch(cwd, page_url.as_deref());

    let recovered_json = recovered_transaction.as_ref().map(|t| {
        json!({
            "id": t.get("id").cloned().unwrap_or(Value::Null),
            "reason": t.get("reason").cloned().unwrap_or(Value::Null),
            "skipped": t.get("skipped").cloned().unwrap_or(Value::Null),
            "rolledBackFiles": t.get("rolledBackFiles").cloned().unwrap_or(Value::Null),
            "rollbackFailures": summarize_manual_diagnostics(
                as_value_slice(t.get("rollbackFailures").unwrap_or(&Value::Null)),
                cwd,
            ),
        })
    });

    deps.record_manual_edit_activity(
        "manual_edit_commit_started",
        json!({
            "pageUrl": page_url,
            "repairOnly": repair_only,
            "pendingCount": pending_count,
            "totalCount": before.total_count,
            "recoveredTransaction": recovered_json,
            "pendingEntryCount": pending_summary.pending_entry_count,
            "pendingOpCount": pending_summary.pending_op_count,
        }),
    );

    let async_response = HttpResponse::json(
        202,
        json!({
            "status": "started",
            "pendingCount": pending_count,
            "totalCount": before.total_count,
            "perPage": before.per_page_value(),
        }),
    );

    // The rest mirrors the JS async IIFE: it always runs, whether or not
    // the caller already received a 202. Its own result is only turned
    // into an HTTP response when `!asyncMode`.
    let mut routed_provider = "subprocess".to_string();
    let mut transaction: Option<Value> = None;
    let mut commit_batch: Option<Value> = None;
    let commit_outcome: Result<Value, (String, String)> = (|| {
        if pending_count > 0 {
            let transaction_batch = deps.build_manual_edit_evidence(page_url.as_deref());
            commit_batch = Some(transaction_batch.clone());
            let op_count = super::manual_apply::count_manual_apply_ops(&transaction_batch);
            if !repair_only && op_count > 0 {
                transaction = Some(deps.write_transaction(page_url.as_deref(), &transaction_batch));
            } else if repair_only {
                transaction = existing_transaction.clone();
            }
        }

        let requested_mode = deps.copy_agent_mode();
        let use_chat_route =
            requested_mode == "chat" || (requested_mode == "auto" && deps.chat_agent_likely_active());
        let timeout_ms = deps.copy_agent_timeout_ms();
        let transaction_id = transaction
            .as_ref()
            .and_then(|t| t.get("id").and_then(Value::as_str))
            .or_else(|| existing_transaction.as_ref().and_then(|t| t.get("id").and_then(Value::as_str)))
            .map(|s| s.to_string());

        if use_chat_route {
            routed_provider = "chat".to_string();
        }
        let provider = if use_chat_route {
            Some("chat".to_string())
        } else {
            let m = requested_mode.as_str();
            if ["codex", "claude", "mock"].contains(&m) {
                Some(m.to_string())
            } else {
                None
            }
        };

        deps.commit_manual_edits(CommitManualEditsArgs {
            page_url: page_url.clone(),
            provider,
            use_chat_route,
            timeout_ms,
            repair_only,
            transaction_id,
            batch: commit_batch.clone(),
        })
        .map_err(|message| (routed_provider.clone(), message))
    })();

    let result = match commit_outcome {
        Err((provider, message)) => {
            if let Some(t) = &transaction {
                deps.rollback_transaction(page_url.as_deref(), "manual_edit_commit_exception");
                let _ = t;
            }
            deps.record_manual_edit_activity(
                "manual_edit_commit_failed",
                json!({
                    "pageUrl": page_url,
                    "provider": provider,
                    "error": "manual_edit_commit_failed",
                    "message": message,
                    "transactionId": transaction.as_ref().and_then(|t| t.get("id").cloned()),
                }),
            );
            if async_mode {
                return async_response;
            }
            return HttpResponse::json(
                500,
                json!({ "error": "manual_edit_commit_failed", "message": message }),
            );
        }
        Ok(result) => result,
    };

    if let Some(t) = &transaction {
        let should_keep = result.get("needsManualDecision") == Some(&Value::Bool(true));
        if !should_keep {
            if let Some(id) = t.get("id").and_then(Value::as_str) {
                deps.clear_transaction(id);
            }
        }
    }

    let after = deps.manual_edit_status();
    let remaining = after.for_page(page_url.as_deref());

    if result.get("needsManualDecision") == Some(&Value::Bool(true)) {
        deps.record_manual_edit_activity(
            "manual_edit_repair_needs_decision",
            json!({
                "pageUrl": page_url,
                "provider": routed_provider,
                "transactionId": transaction.as_ref().or(existing_transaction.as_ref()).and_then(|t| t.get("id").cloned()),
                "repair": result.get("repair").cloned().unwrap_or(Value::Null),
                "failed": summarize_manual_apply_failures(as_value_slice(result.get("failed").unwrap_or(&Value::Null)), cwd),
                "files": summarize_files(&result, cwd),
                "remainingCount": remaining,
                "totalCount": after.total_count,
            }),
        );
    } else {
        deps.record_manual_edit_activity(
            "manual_edit_commit_done",
            json!({
                "pageUrl": page_url,
                "provider": routed_provider,
                "reason": result.get("reason").cloned().unwrap_or(Value::Null),
                "repair": result.get("repair").cloned().unwrap_or(Value::Null),
                "appliedCount": result.get("applied").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                "failedCount": result.get("failed").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                "failed": summarize_manual_apply_failures(as_value_slice(result.get("failed").unwrap_or(&Value::Null)), cwd),
                "files": summarize_files(&result, cwd),
                "warnings": summarize_manual_diagnostics(as_value_slice(result.get("warnings").unwrap_or(&Value::Null)), cwd),
                "rolledBackFiles": summarize_named_files(&result, "rolledBackFiles", cwd),
                "rollbackFailures": summarize_manual_diagnostics(as_value_slice(result.get("rollbackFailures").unwrap_or(&Value::Null)), cwd),
                "unreportedFiles": result.get("unreportedFiles").and_then(Value::as_array).map(|_| summarize_named_files(&result, "unreportedFiles", cwd)),
                "noteCount": result.get("notes").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                "cleared": result.get("cleared").cloned().unwrap_or(json!(0)),
                "remainingCount": remaining,
                "totalCount": after.total_count,
            }),
        );
    }

    if async_mode {
        return async_response;
    }
    let mut body = result;
    if let Value::Object(ref mut map) = body {
        map.insert("totalCount".into(), json!(after.total_count));
        map.insert("perPage".into(), after.per_page_value());
    }
    HttpResponse::json(200, body)
}

fn summarize_files(result: &Value, cwd: &Path) -> Vec<Value> {
    summarize_named_files(result, "files", cwd)
}

fn summarize_named_files(result: &Value, key: &str, cwd: &Path) -> Vec<Value> {
    result
        .get(key)
        .and_then(Value::as_array)
        .map(|files| {
            files
                .iter()
                .take(20)
                .filter_map(|f| {
                    super::manual_apply::summarize_manual_log_file(f.as_str(), cwd).map(Value::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn handle_repair_decision(
    deps: &dyn ManualEditRoutesDeps,
    req: &ManualEditRequest,
    cwd: &Path,
) -> HttpResponse {
    let payload = match &req.body {
        Some(Ok(v)) => v.clone(),
        Some(Err(_)) => return HttpResponse::json(400, json!({ "error": "Invalid JSON" })),
        None => json!({}),
    };
    let token = payload
        .get("token")
        .and_then(Value::as_str)
        .or_else(|| req.query("token"));
    if token != Some(deps.token().as_str()) {
        return HttpResponse::json(401, json!({ "error": "Unauthorized" }));
    }
    let page_url = payload
        .get("pageUrl")
        .and_then(Value::as_str)
        .or_else(|| req.query("pageUrl"))
        .map(|s| s.to_string());
    let action = payload
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| req.query("action"))
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if action != "rollback" {
        return HttpResponse::json(
            400,
            json!({ "error": "unsupported_manual_edit_repair_decision", "action": action }),
        );
    }
    let rollback = deps.rollback_transaction(page_url.as_deref(), "manual_edit_user_requested_rollback");
    let counts = count_by_page(cwd);
    let remaining = if let Some(p) = &page_url {
        counts.per_page.get(p).copied().unwrap_or(0)
    } else {
        counts.total_count
    };
    let response = json!({
        "action": action,
        "pageUrl": page_url,
        "rollback": rollback,
        "remainingCount": remaining,
        "totalCount": counts.total_count,
        "perPage": per_page_json(&counts),
    });
    deps.record_manual_edit_activity("manual_edit_repair_rollback_done", response.clone());
    HttpResponse::json(200, response)
}

fn handle_discard(deps: &dyn ManualEditRoutesDeps, req: &ManualEditRequest, cwd: &Path) -> HttpResponse {
    if req.query("token") != Some(deps.token().as_str()) {
        return HttpResponse::json(401, json!({ "error": "Unauthorized" }));
    }
    let page_url = req.query("pageUrl").map(|s| s.to_string());

    let buffer = read_buffer(cwd);
    let transaction_rollback =
        deps.rollback_transaction(page_url.as_deref(), "manual_edit_discarded");
    let (discarded, discarded_entries) = if let Some(p) = &page_url {
        let entries: Vec<_> = buffer
            .entries
            .iter()
            .filter(|e| e.page_url.as_deref() == Some(p.as_str()))
            .cloned()
            .collect();
        let p = p.clone();
        let removed = remove_entries(cwd, |e| e.page_url.as_deref() == Some(p.as_str()));
        (removed, entries)
    } else {
        let entries = buffer.entries.clone();
        let removed = truncate_buffer(cwd);
        (removed, entries)
    };
    let canceled_apply_events = deps.cancel_pending_events(page_url.as_deref());

    let counts = count_by_page(cwd);
    let transaction_rollback_json = transaction_rollback.as_ref().map(|t| {
        let files: Vec<Value> = t
            .get("rolledBackFiles")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        super::manual_apply::summarize_manual_log_file(f.as_str(), cwd).map(Value::from)
                    })
                    .collect()
            })
            .unwrap_or_default();
        json!({
            "id": t.get("id").cloned().unwrap_or(Value::Null),
            "rolledBackFiles": files,
            "rollbackFailures": summarize_manual_diagnostics(as_value_slice(t.get("rollbackFailures").unwrap_or(&Value::Null)), cwd),
            "skipped": t.get("skipped").cloned().unwrap_or(Value::Null),
        })
    });

    deps.record_manual_edit_activity(
        "manual_edit_discarded",
        json!({
            "pageUrl": page_url,
            "discarded": discarded,
            "canceledApplyIds": canceled_apply_events
                .iter()
                .map(|e| e.get("id").cloned().unwrap_or(Value::Null))
                .collect::<Vec<_>>(),
            "transactionRollback": transaction_rollback_json,
            "totalCount": counts.total_count,
        }),
    );

    HttpResponse::json(
        200,
        json!({
            "discarded": discarded,
            "entries": discarded_entries,
            "canceledApplyEvents": canceled_apply_events,
            "totalCount": counts.total_count,
            "perPage": per_page_json(&counts),
        }),
    )
}

fn per_page_json(counts: &super::manual_edits_buffer::PageCounts) -> Value {
    Value::Object(
        counts
            .per_page
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect(),
    )
}
