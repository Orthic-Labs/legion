//! Port of `resumeCli()` in
//! `skills/designer/engine/scripts/live-resume.mjs`, the piece
//! [`super::live_resume`] left unported: loading the durable session-store
//! journal via `createLiveSessionStore`/`getSnapshot`/`listActiveSessions`
//! (ported as [`crate::wf_port::w2_021::session_store::LiveSessionStore`])
//! and deriving `nextAction` from the resulting snapshot, then printing the
//! `{ active, snapshot, pendingEvent, nextAction }` JSON. Packet r23.

use std::path::Path;

use serde_json::{json, Value};

use super::live_resume::{manual_apply_resume_hint, parse_args, ChunkRef, ManualApplyEvent};
use crate::wf_port::w2_021::session_store::LiveSessionStore;

/// Converts a raw `pendingEvent` JSON value into a [`ManualApplyEvent`] for
/// [`manual_apply_resume_hint`], mirroring the destructuring JS does
/// implicitly when it passes `pending` straight through.
fn to_manual_apply_event(pending: &Value) -> ManualApplyEvent {
    let chunk = pending.get("chunk").and_then(|c| {
        let index = c.get("index")?.as_i64()?;
        let total = c.get("total")?.as_i64()?;
        Some(ChunkRef { index, total })
    });
    ManualApplyEvent {
        id: pending
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string),
        page_url: pending
            .get("pageUrl")
            .and_then(Value::as_str)
            .map(str::to_string),
        chunk,
        batch: pending.get("batch").cloned(),
    }
}

/// Port of the `nextAction` derivation inside `resumeCli()`.
pub fn compute_next_action(snapshot: &Value) -> String {
    let pending = snapshot.get("pendingEvent").filter(|v| !v.is_null());
    if let Some(pending) = pending {
        let ev_type = pending.get("type").and_then(Value::as_str).unwrap_or("");
        let ev_id = pending.get("id").and_then(Value::as_str).unwrap_or("");
        return if ev_type == "manual_edit_apply" {
            manual_apply_resume_hint(&to_manual_apply_event(pending))
        } else {
            format!(
                "Run legion script designer/live-poll, handle {ev_type} {ev_id}, then acknowledge with legion script designer/live-poll --reply {ev_id} done."
            )
        };
    }

    let phase = snapshot.get("phase").and_then(Value::as_str).unwrap_or("");
    let id = snapshot.get("id").and_then(Value::as_str).unwrap_or("");
    match phase {
        "carbonize_required" => {
            let source_file = snapshot.get("sourceFile").and_then(Value::as_str);
            let suffix = source_file.map(|f| format!(" in {f}")).unwrap_or_default();
            format!("Finish carbonize cleanup{suffix}, then run legion script designer/live-complete --id {id}.")
        }
        "accept_requested" => {
            format!(
                "Run legion script designer/live-complete --id {id} after verifying the accepted variant is written."
            )
        }
        _ => format!("Inspect {id}; no pending agent event is currently queued."),
    }
}

/// Port of `resumeCli()`'s snapshot lookup: `args.id ? store.getSnapshot(args.id)
/// : store.listActiveSessions()[0] || null`.
pub fn load_snapshot(cwd: &Path, id: Option<&str>) -> Result<Option<Value>, String> {
    let mut store =
        LiveSessionStore::new(cwd, id.map(str::to_string)).map_err(|e| e.to_string())?;
    if let Some(id) = id {
        store.get_snapshot(Some(id), false)
    } else {
        Ok(store.list_active_sessions().into_iter().next())
    }
}

/// Port of `resumeCli()`. Returns the JSON that would be printed via
/// `console.log(JSON.stringify(..., null, 2))`; printing itself is left to
/// the caller (see [`run`]).
pub fn resume_output(cwd: &Path, id: Option<&str>) -> Result<Value, String> {
    let snapshot = load_snapshot(cwd, id)?;
    let Some(snapshot) = snapshot else {
        return Ok(json!({
            "active": false,
            "nextAction": "No active durable live session found.",
        }));
    };
    let pending = snapshot.get("pendingEvent").cloned().unwrap_or(Value::Null);
    let next_action = compute_next_action(&snapshot);
    Ok(json!({
        "active": true,
        "snapshot": snapshot,
        "pendingEvent": pending,
        "nextAction": next_action,
    }))
}

/// Port of `resumeCli()` including the `--help` branch and argv parsing,
/// suitable for a CLI `main`. Mirrors `console.log` by returning the text to
/// print, and mirrors the implicit exit code 0 (this script never sets
/// `process.exitCode`).
pub fn run(cwd: &Path, argv: &[String]) -> (i32, String) {
    let args = parse_args(argv);
    if args.help {
        return (
            0,
            "Usage: legion script designer/live-resume [--id SESSION_ID]\n\nPrint the active durable session checkpoint and the next safe agent action.".to_string(),
        );
    }
    match resume_output(cwd, args.id.as_deref()) {
        Ok(output) => (0, serde_json::to_string_pretty(&output).unwrap()),
        Err(err) => (
            1,
            serde_json::to_string_pretty(&json!({
                "active": false,
                "nextAction": format!("Error: {err}"),
            }))
            .unwrap(),
        ),
    }
}
