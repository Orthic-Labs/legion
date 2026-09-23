//! Port of the pure logic in
//! `skills/designer/engine/scripts/live-status.mjs`.
//!
//! See [`crate::wf_port::w2_019`] for what is and isn't ported from this
//! file.

use serde_json::Value;

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
}
