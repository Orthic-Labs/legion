//! Port of `resumeCli()` in
//! `skills/designer/engine/scripts/live-resume.mjs`, the piece
//! [`super::live_resume`] left unported: loading the durable session-store
//! journal via `createLiveSessionStore`/`getSnapshot`/`listActiveSessions`
//! (ported as [`crate::wf_port::w2_021::session_store::LiveSessionStore`])
//! and deriving `nextAction` from the resulting snapshot, then printing the
//! `{ active, snapshot, pendingEvent, nextAction }` JSON. Packet r23.

use std::path::Path;

use serde_json::{json, Value};

use super::live_resume::{manual_apply_resume_hint, parse_args, ManualApplyEvent, ChunkRef};
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
        id: pending.get("id").and_then(Value::as_str).map(str::to_string),
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
                "Run live-poll.mjs, handle {ev_type} {ev_id}, then acknowledge with live-poll.mjs --reply {ev_id} done."
            )
        };
    }

    let phase = snapshot.get("phase").and_then(Value::as_str).unwrap_or("");
    let id = snapshot.get("id").and_then(Value::as_str).unwrap_or("");
    match phase {
        "carbonize_required" => {
            let source_file = snapshot.get("sourceFile").and_then(Value::as_str);
            let suffix = source_file
                .map(|f| format!(" in {f}"))
                .unwrap_or_default();
            format!("Finish carbonize cleanup{suffix}, then run live-complete.mjs --id {id}.")
        }
        "accept_requested" => {
            format!("Run live-complete.mjs --id {id} after verifying the accepted variant is written.")
        }
        _ => format!("Inspect {id}; no pending agent event is currently queued."),
    }
}

/// Port of `resumeCli()`'s snapshot lookup: `args.id ? store.getSnapshot(args.id)
/// : store.listActiveSessions()[0] || null`.
pub fn load_snapshot(cwd: &Path, id: Option<&str>) -> Result<Option<Value>, String> {
    let mut store = LiveSessionStore::new(cwd, id.map(str::to_string)).map_err(|e| e.to_string())?;
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
            "Usage: node live-resume.mjs [--id SESSION_ID]\n\nPrint the active durable session checkpoint and the next safe agent action.".to_string(),
        );
    }
    match resume_output(cwd, args.id.as_deref()) {
        Ok(output) => (0, serde_json::to_string_pretty(&output).unwrap()),
        Err(err) => (
            0,
            serde_json::to_string_pretty(&json!({
                "active": false,
                "nextAction": format!("Error: {err}"),
            }))
            .unwrap(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "legion-r23-resume-{}-{}-{}",
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn no_active_session_reports_inactive() {
        let dir = temp_dir();
        let out = resume_output(&dir, None).unwrap();
        assert_eq!(out["active"], json!(false));
        assert_eq!(out["nextAction"], json!("No active durable live session found."));
    }

    #[test]
    fn pending_manual_edit_apply_uses_resume_hint() {
        let dir = temp_dir();
        let mut store = LiveSessionStore::new(&dir, None).unwrap();
        store
            .append_event(
                json!({
                    "id": "sess1",
                    "type": "generate",
                    "pageUrl": "http://localhost:5173/",
                    "count": 2,
                }),
                None,
            )
            .unwrap();
        // Force a manual_edit_apply pending event by writing directly
        // through append_event (mirrors how live-poll.mjs enqueues one).
        store
            .append_event(
                json!({
                    "id": "sess1",
                    "type": "manual_edit_apply",
                    "batch": { "entries": [{ "ops": [{ "sourceHint": { "file": "src/A.svelte" } }] }] },
                }),
                None,
            )
            .unwrap();

        let out = resume_output(&dir, Some("sess1")).unwrap();
        assert_eq!(out["active"], json!(true));
        let next_action = out["nextAction"].as_str().unwrap();
        assert!(next_action.starts_with("Manual Apply pending"));
        assert!(next_action.contains("likely files: src/A.svelte"));
    }

    #[test]
    fn pending_non_manual_event_uses_generic_hint() {
        let dir = temp_dir();
        let mut store = LiveSessionStore::new(&dir, None).unwrap();
        store
            .append_event(json!({ "id": "sess2", "type": "generate", "count": 1 }), None)
            .unwrap();
        let out = resume_output(&dir, Some("sess2")).unwrap();
        assert_eq!(
            out["nextAction"],
            json!("Run live-poll.mjs, handle generate sess2, then acknowledge with live-poll.mjs --reply sess2 done.")
        );
    }

    #[test]
    fn carbonize_required_phase_hint() {
        let snapshot = json!({
            "id": "sess3",
            "phase": "carbonize_required",
            "sourceFile": "src/Foo.svelte",
            "pendingEvent": null,
        });
        assert_eq!(
            compute_next_action(&snapshot),
            "Finish carbonize cleanup in src/Foo.svelte, then run live-complete.mjs --id sess3."
        );
    }

    #[test]
    fn carbonize_required_no_source_file() {
        let snapshot = json!({ "id": "sess4", "phase": "carbonize_required", "pendingEvent": null });
        assert_eq!(
            compute_next_action(&snapshot),
            "Finish carbonize cleanup, then run live-complete.mjs --id sess4."
        );
    }

    #[test]
    fn accept_requested_phase_hint() {
        let snapshot = json!({ "id": "sess5", "phase": "accept_requested", "pendingEvent": null });
        assert_eq!(
            compute_next_action(&snapshot),
            "Run live-complete.mjs --id sess5 after verifying the accepted variant is written."
        );
    }

    #[test]
    fn other_phase_falls_back_to_inspect() {
        let snapshot = json!({ "id": "sess6", "phase": "variants_ready", "pendingEvent": null });
        assert_eq!(
            compute_next_action(&snapshot),
            "Inspect sess6; no pending agent event is currently queued."
        );
    }

    #[test]
    fn run_help_flag() {
        let dir = temp_dir();
        let (code, text) = run(&dir, &["--help".to_string()]);
        assert_eq!(code, 0);
        assert!(text.starts_with("Usage: node live-resume.mjs"));
    }

    #[test]
    fn run_no_session_json_output() {
        let dir = temp_dir();
        let (code, text) = run(&dir, &[]);
        assert_eq!(code, 0);
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["active"], json!(false));
    }

    #[test]
    fn run_with_id_flag_picks_specific_session() {
        let dir = temp_dir();
        let mut store = LiveSessionStore::new(&dir, None).unwrap();
        store
            .append_event(json!({ "id": "sessA", "type": "generate", "count": 1 }), None)
            .unwrap();
        let (code, text) = run(&dir, &["--id".to_string(), "sessA".to_string()]);
        assert_eq!(code, 0);
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["active"], json!(true));
        assert_eq!(parsed["snapshot"]["id"], json!("sessA"));
    }

    #[test]
    fn list_active_sessions_picks_first_when_no_id() {
        let dir = temp_dir();
        let mut store = LiveSessionStore::new(&dir, None).unwrap();
        store
            .append_event(json!({ "id": "sessB", "type": "generate", "count": 1 }), None)
            .unwrap();
        let out = resume_output(&dir, None).unwrap();
        assert_eq!(out["active"], json!(true));
        assert_eq!(out["snapshot"]["id"], json!("sessB"));
    }
}
