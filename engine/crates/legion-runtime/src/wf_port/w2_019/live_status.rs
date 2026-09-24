//! Port of the pure logic in
//! `skills/designer/engine/scripts/live-status.mjs`.
//!
//! `statusCli` also performs the `fetch(.../status)` HTTP call, reads the
//! live-server info file (`readLiveServerInfo`, from
//! `lib/impeccable-paths.mjs`) and the durable session store
//! (`live/session-store.mjs`) — both owned by other, unported files. Those
//! are abstracted here behind [`StatusEnv`] so the CLI entrypoint itself
//! (argv-free; `live-status.mjs` takes none) is ported and testable with
//! fakes, mirroring [`build_status_payload`]'s pure assembly of the JSON
//! payload `statusCli` prints.
//!
//! See [`crate::wf_port::w2_019`] for what is and isn't ported from this
//! file.

use crate::wf_port::w2_016::impeccable_paths::read_live_server_info;
use crate::wf_port::w2_019::live_resume::{manual_apply_resume_hint, ManualApplyEvent};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Real [`StatusEnv`] for production use: reads `.impeccable/live/server.json`
/// (or its legacy fallback) under `root` via the existing
/// `w2_016::impeccable_paths` port, then performs the same
/// `GET http://localhost:{port}/status?token={token}` `statusCli` makes,
/// treating any non-2xx response or transport error as `None` (mirrors the
/// JS `try { ... } catch { return null; }`). `list_active_sessions`
/// currently has no ported durable-session-store client in this crate to
/// call into, so it returns an empty list — real callers get the
/// `pendingEvents`/`activeSessions` view straight from the live server's
/// own response, same as `statusCli` does whenever a server is running;
/// only the "no server, but a durable session exists" fallback branch is
/// unavailable here.
pub struct HttpStatusEnv {
    pub root: PathBuf,
}

impl HttpStatusEnv {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self { root: root.as_ref().to_path_buf() }
    }
}

impl StatusEnv for HttpStatusEnv {
    fn server_info(&self) -> Option<(u16, String)> {
        let info = read_live_server_info(&self.root)?;
        let port = info.raw.get("port")?.as_u64()? as u16;
        let token = info.raw.get("token")?.as_str()?.to_string();
        Some((port, token))
    }

    fn fetch_server_status(&self, port: u16, token: &str) -> Option<Value> {
        let url = format!("http://localhost:{port}/status?token={token}");
        let resp = reqwest::blocking::get(url).ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<Value>().ok()
    }

    fn list_active_sessions(&self) -> Vec<Value> {
        Vec::new()
    }
}

/// What `statusCli` needs from the outside world, kept behind a trait so
/// the orchestration in [`run`] never touches the filesystem or network
/// directly (per the port brief: I/O behind a trait, tested with fakes).
pub trait StatusEnv {
    /// Port of `readLiveServerInfo(cwd)?.info` — `None` when no live
    /// server info file exists (or its pid is unreachable).
    fn server_info(&self) -> Option<(u16, String)>;
    /// Port of `fetchServerStatus(info)`: a GET to
    /// `http://localhost:{port}/status?token={token}`, returning the
    /// parsed JSON body, or `None` on any non-ok response or network
    /// error (mirrors the JS `try { ... } catch { return null; }`).
    fn fetch_server_status(&self, port: u16, token: &str) -> Option<Value>;
    /// Port of `store.listActiveSessions()`.
    fn list_active_sessions(&self) -> Vec<Value>;
}

/// Port of `statusCli()`'s full body: gather server info, fetch server
/// status, list active sessions, and assemble the printed JSON payload.
/// Returns the same object `statusCli` serializes with
/// `JSON.stringify(payload, null, 2)`.
pub fn run(env: &dyn StatusEnv) -> Value {
    let server = env
        .server_info()
        .and_then(|(port, token)| env.fetch_server_status(port, token.as_str()));
    let active_sessions = env.list_active_sessions();
    build_status_payload(server.as_ref(), &active_sessions)
}

/// Port of `statusCli`'s payload assembly (everything after
/// `fetchServerStatus`/`listActiveSessions` have already produced their
/// results): the `liveServer` field subset, the `activeSessions`
/// fallback, and the `recoveryHint` three-way branch.
pub fn build_status_payload(server: Option<&Value>, active_sessions: &[Value]) -> Value {
    let manual_apply = find_pending_manual_apply(
        server.and_then(|s| s.get("pendingEvents")).and_then(Value::as_array).map(|v| v.as_slice()),
        &active_sessions
            .iter()
            .map(|s| s.get("pendingEvent").cloned())
            .collect::<Vec<_>>(),
    );

    let live_server = server.map(|s| {
        json!({
            "status": s.get("status").cloned().unwrap_or(Value::Null),
            "port": s.get("port").cloned().unwrap_or(Value::Null),
            "connectedClients": s.get("connectedClients").cloned().unwrap_or(Value::Null),
            "agentPolling": s.get("agentPolling").cloned().unwrap_or(Value::Null),
            "pendingEvents": s.get("pendingEvents").cloned().unwrap_or(Value::Null),
        })
    });

    let active_sessions_out = server
        .and_then(|s| s.get("activeSessions").cloned())
        .unwrap_or_else(|| Value::Array(active_sessions.to_vec()));

    let recovery_hint = if let Some(event) = manual_apply.as_ref() {
        Value::String(manual_apply_resume_hint(&manual_apply_event_from_value(event)))
    } else if server.is_some() {
        Value::String(
            "Run live-poll.mjs to continue pending work, or live-complete.mjs --id <session> after manual cleanup."
                .to_string(),
        )
    } else {
        Value::String(
            "Start live-server.mjs to requeue pending durable events, then run live-poll.mjs.".to_string(),
        )
    };

    json!({
        "liveServer": live_server,
        "activeSessions": active_sessions_out,
        "recoveryHint": recovery_hint,
    })
}

/// Rebuilds the typed [`ManualApplyEvent`] shape `manualApplyResumeHint`
/// expects from the raw `Value` `findPendingManualApply` returned.
fn manual_apply_event_from_value(event: &Value) -> ManualApplyEvent {
    use crate::wf_port::w2_019::live_resume::ChunkRef;
    ManualApplyEvent {
        id: event.get("id").and_then(Value::as_str).map(String::from),
        page_url: event.get("pageUrl").and_then(Value::as_str).map(String::from),
        chunk: event.get("chunk").and_then(|c| {
            Some(ChunkRef {
                index: c.get("index")?.as_i64()?,
                total: c.get("total")?.as_i64()?,
            })
        }),
        batch: event.get("batch").cloned(),
    }
}

/// Port of `findPendingManualApply(server, activeSessions)`: prefer the
/// live server's own `pendingEvents` view; fall back to the durable
/// session store's per-session `pendingEvent`. Returns the first
/// `manual_edit_apply`-typed event found, or `None`.
pub fn find_pending_manual_apply(
    server_pending_events: Option<&[Value]>,
    active_session_pending_events: &[Option<Value>],
) -> Option<Value> {
    if let Some(events) = server_pending_events {
        if let Some(found) = events
            .iter()
            .find(|event| event.get("type").and_then(Value::as_str) == Some("manual_edit_apply"))
        {
            return Some(found.clone());
        }
    }
    active_session_pending_events
        .iter()
        .flatten()
        .find(|event| event.get("type").and_then(Value::as_str) == Some("manual_edit_apply"))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn prefers_server_pending_events_when_present() {
        let server = vec![
            json!({"type": "generate", "id": "g1"}),
            json!({"type": "manual_edit_apply", "id": "m1"}),
        ];
        let sessions = vec![Some(json!({"type": "manual_edit_apply", "id": "m2"}))];
        let found = find_pending_manual_apply(Some(&server), &sessions).unwrap();
        assert_eq!(found["id"], "m1");
    }

    #[test]
    fn falls_back_to_session_store_when_server_has_none() {
        let server = vec![json!({"type": "generate", "id": "g1"})];
        let sessions = vec![None, Some(json!({"type": "manual_edit_apply", "id": "m2"}))];
        let found = find_pending_manual_apply(Some(&server), &sessions).unwrap();
        assert_eq!(found["id"], "m2");
    }

    #[test]
    fn returns_none_without_server_and_empty_sessions() {
        assert_eq!(find_pending_manual_apply(None, &[]), None);
    }

    #[test]
    fn returns_none_when_nothing_matches() {
        let server = vec![json!({"type": "generate", "id": "g1"})];
        assert_eq!(find_pending_manual_apply(Some(&server), &[]), None);
    }

    #[test]
    fn payload_prefers_manual_apply_hint_when_pending() {
        let server = json!({
            "status": "ok",
            "port": 5170,
            "connectedClients": 1,
            "agentPolling": true,
            "pendingEvents": [
                {"type": "manual_edit_apply", "id": "m1", "pageUrl": "http://localhost:5173/"}
            ],
        });
        let payload = build_status_payload(Some(&server), &[]);
        assert_eq!(payload["liveServer"]["status"], "ok");
        assert_eq!(payload["liveServer"]["port"], 5170);
        let hint = payload["recoveryHint"].as_str().unwrap();
        assert!(hint.contains("page http://localhost:5173/"));
        assert!(hint.contains("--reply m1 done"));
    }

    #[test]
    fn payload_falls_back_to_generic_server_hint_without_manual_apply() {
        let server = json!({"status": "ok", "port": 5170, "connectedClients": 0, "agentPolling": false, "pendingEvents": []});
        let payload = build_status_payload(Some(&server), &[]);
        assert_eq!(
            payload["recoveryHint"],
            "Run live-poll.mjs to continue pending work, or live-complete.mjs --id <session> after manual cleanup."
        );
    }

    #[test]
    fn payload_reports_no_server_hint_when_server_is_absent() {
        let payload = build_status_payload(None, &[]);
        assert_eq!(payload["liveServer"], Value::Null);
        assert_eq!(
            payload["recoveryHint"],
            "Start live-server.mjs to requeue pending durable events, then run live-poll.mjs."
        );
    }

    #[test]
    fn payload_active_sessions_falls_back_to_store_list_when_server_omits_it() {
        let sessions = vec![json!({"id": "s1", "pendingEvent": null})];
        let payload = build_status_payload(None, &sessions);
        assert_eq!(payload["activeSessions"], json!(sessions));
    }

    struct FakeEnv {
        info: Option<(u16, String)>,
        status: Option<Value>,
        sessions: Vec<Value>,
    }

    impl StatusEnv for FakeEnv {
        fn server_info(&self) -> Option<(u16, String)> {
            self.info.clone()
        }
        fn fetch_server_status(&self, _port: u16, _token: &str) -> Option<Value> {
            self.status.clone()
        }
        fn list_active_sessions(&self) -> Vec<Value> {
            self.sessions.clone()
        }
    }

    #[test]
    fn run_with_no_server_info_yields_start_server_hint() {
        let env = FakeEnv { info: None, status: None, sessions: vec![] };
        let payload = run(&env);
        assert_eq!(
            payload["recoveryHint"],
            "Start live-server.mjs to requeue pending durable events, then run live-poll.mjs."
        );
    }

    #[test]
    fn run_wires_server_info_through_to_fetch_and_payload() {
        let env = FakeEnv {
            info: Some((5170, "tok".to_string())),
            status: Some(json!({
                "status": "ok", "port": 5170, "connectedClients": 2,
                "agentPolling": true, "pendingEvents": []
            })),
            sessions: vec![],
        };
        let payload = run(&env);
        assert_eq!(payload["liveServer"]["connectedClients"], 2);
    }
}
