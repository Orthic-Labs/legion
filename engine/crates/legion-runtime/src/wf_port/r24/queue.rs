//! Port of the pending-event / long-poll queue state machine from
//! `live-server.mjs`'s module-level `state` object: `state.pendingEvents`,
//! `state.pendingPolls`, `state.nextEventSeq`, and the functions
//! `enqueueEvent`, `findAvailablePendingEvent`, `leaseEvent`,
//! `acknowledgePendingEvent`, `findPendingEventById`,
//! `cancelQueuedAnonymousExitEvents`, and `scheduleLeaseFlush`'s pure
//! "what's the next deadline" computation (`nextLeaseDeadline` below; the
//! JS `setTimeout` wiring itself is effectful and lives in `http_server`).
//!
//! JS uses `serde_json::Value` in place of untyped JS objects for `event`
//! bodies, since the wire format (`/events` POST body forwarded verbatim to
//! `/poll` responses) is caller-defined JSON, not a fixed Rust struct.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One entry in `state.pendingEvents`: `{ event, leaseUntil, seq }`.
#[derive(Debug, Clone)]
pub struct PendingEventEntry {
    pub event: Value,
    /// 0 means "not leased" (JS: `leaseUntil: 0`).
    pub lease_until_ms: u64,
    pub seq: u64,
}

impl PendingEventEntry {
    pub fn id(&self) -> Option<&str> {
        self.event.get("id").and_then(Value::as_str)
    }

    pub fn event_type(&self) -> Option<&str> {
        self.event.get("type").and_then(Value::as_str)
    }
}

/// Thread-safe port of `state.pendingEvents` + `state.pendingPolls` +
/// `state.nextEventSeq`. The JS version is single-threaded (Node event
/// loop); this server is a synchronous multi-threaded `TcpListener` server
/// (one thread per connection, per the port brief's `TcpListener` guidance),
/// so the queue is protected by a `Mutex` rather than relying on
/// single-threaded ordering. Locking granularity mirrors each JS function
/// one-for-one so the behavior (not just the shape) matches.
pub struct QueueState {
    inner: Mutex<Inner>,
    next_event_seq: AtomicU64,
}

struct Inner {
    pending_events: Vec<PendingEventEntry>,
}

impl QueueState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                pending_events: Vec::new(),
            }),
            next_event_seq: AtomicU64::new(1),
        }
    }

    /// `enqueueEvent(event)`: dedupe on `(event.id, event.type)` already
    /// present and unleased-or-leased (JS dedupes on id+type unconditionally
    /// of lease state — `state.pendingEvents.some(...)` scans everything),
    /// then push with `leaseUntil: 0`.
    pub fn enqueue_event(&self, event: Value) {
        let id = event.get("id").and_then(Value::as_str).map(str::to_owned);
        let ty = event.get("type").and_then(Value::as_str).map(str::to_owned);
        let mut inner = self.inner.lock().unwrap();
        if let Some(id) = &id {
            let dup = inner.pending_events.iter().any(|entry| {
                entry.id() == Some(id.as_str()) && entry.event_type().as_deref() == ty.as_deref()
            });
            if dup {
                return;
            }
        }
        let seq = self.next_event_seq.fetch_add(1, Ordering::SeqCst);
        inner.pending_events.push(PendingEventEntry {
            event,
            lease_until_ms: 0,
            seq,
        });
    }

    /// `findAvailablePendingEvent(now)`: first entry whose lease has expired
    /// (or was never leased), in insertion order.
    pub fn find_available_pending_event(&self) -> Option<PendingEventEntry> {
        let now = now_ms();
        let inner = self.inner.lock().unwrap();
        inner
            .pending_events
            .iter()
            .find(|entry| !(entry.lease_until_ms > 0 && entry.lease_until_ms > now))
            .cloned()
    }

    /// `leaseEvent(entry, leaseMs)`: if the event has no `id`, it is
    /// consumed immediately (removed from the queue, since there is no way
    /// to ack an anonymous event later); otherwise its `leaseUntil` is
    /// bumped forward. Returns the event body either way.
    pub fn lease_event(&self, seq: u64, lease_ms: u64) -> Option<Value> {
        let mut inner = self.inner.lock().unwrap();
        let idx = inner.pending_events.iter().position(|e| e.seq == seq)?;
        if inner.pending_events[idx].id().is_none() {
            let entry = inner.pending_events.remove(idx);
            return Some(entry.event);
        }
        inner.pending_events[idx].lease_until_ms = now_ms() + lease_ms;
        Some(inner.pending_events[idx].event.clone())
    }

    /// `acknowledgePendingEvent(id)`: remove the matching event by id;
    /// returns the removed event, or `None` if not found (JS returns
    /// `false`).
    pub fn acknowledge_pending_event(&self, id: &str) -> Option<Value> {
        let mut inner = self.inner.lock().unwrap();
        let idx = inner
            .pending_events
            .iter()
            .position(|entry| entry.id() == Some(id))?;
        Some(inner.pending_events.remove(idx).event)
    }

    /// `findPendingEventById(id)`.
    pub fn find_pending_event_by_id(&self, id: &str) -> Option<Value> {
        let inner = self.inner.lock().unwrap();
        inner
            .pending_events
            .iter()
            .find(|entry| entry.id() == Some(id))
            .map(|entry| entry.event.clone())
    }

    /// `cancelQueuedAnonymousExitEvents()`: drop every queued event with
    /// `type === 'exit'` and no `id` (anonymous exit broadcasts superseded
    /// by a newer one). Returns the count removed, matching the JS return
    /// value.
    pub fn cancel_queued_anonymous_exit_events(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.pending_events.len();
        inner
            .pending_events
            .retain(|entry| !(entry.event_type() == Some("exit") && entry.id().is_none()));
        before - inner.pending_events.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().pending_events.len()
    }

    /// Port of `summarizePendingEventForStatus` mapped over
    /// `state.pendingEvents`, for the `/status` route's `pendingEvents`
    /// field. Only the `id`/`type`/`leased`/`leaseUntil` fields are
    /// populated faithfully; the `manual_edit_apply`-only fields
    /// (`pageUrl`/`chunk`/`repair`/`evidencePath`/`agentAction`/
    /// `manualApplySummary`) depend on `live/manual-apply.mjs`'s
    /// `buildAgentAction`/`summarizeEvent`, which are not ported, so those
    /// keys are left off entirely rather than fabricated.
    pub fn status_summary(&self) -> Vec<Value> {
        let now = now_ms();
        let inner = self.inner.lock().unwrap();
        inner
            .pending_events
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "id": entry.id(),
                    "type": entry.event_type(),
                    "leased": entry.lease_until_ms != 0 && entry.lease_until_ms > now,
                    "leaseUntil": if entry.lease_until_ms == 0 { Value::Null } else { Value::from(entry.lease_until_ms) },
                })
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pure half of `scheduleLeaseFlush`: the earliest future `leaseUntil`
    /// across all pending events (`Math.min` over non-zero leases), or
    /// `None` when nothing is leased (JS: no timer scheduled). The
    /// effectful half — actually waking a parked long-poll when that
    /// deadline passes — is the long-poll wait loop in `http_server`, which
    /// re-checks on each short sleep rather than porting `setTimeout`
    /// 1:1 (there is no async runtime driving this synchronous server).
    pub fn next_lease_deadline_ms(&self) -> Option<u64> {
        let inner = self.inner.lock().unwrap();
        inner
            .pending_events
            .iter()
            .map(|e| e.lease_until_ms)
            .filter(|&t| t > 0)
            .min()
    }
}

impl Default for QueueState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enqueue_dedupes_on_id_and_type() {
        let q = QueueState::new();
        q.enqueue_event(json!({"id": "e1", "type": "generate"}));
        q.enqueue_event(json!({"id": "e1", "type": "generate"}));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn enqueue_allows_same_id_different_type() {
        let q = QueueState::new();
        q.enqueue_event(json!({"id": "e1", "type": "generate"}));
        q.enqueue_event(json!({"id": "e1", "type": "exit"}));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn anonymous_event_is_consumed_on_lease() {
        let q = QueueState::new();
        q.enqueue_event(json!({"type": "exit"}));
        let entry = q.find_available_pending_event().unwrap();
        assert!(q.lease_event(entry.seq, 5_000).is_some());
        assert_eq!(q.len(), 0, "anonymous events have no id to ack later, so lease consumes them");
    }

    #[test]
    fn identified_event_stays_queued_until_acknowledged() {
        let q = QueueState::new();
        q.enqueue_event(json!({"id": "e1", "type": "generate"}));
        let entry = q.find_available_pending_event().unwrap();
        q.lease_event(entry.seq, 5_000);
        assert_eq!(q.len(), 1, "leasing an identified event does not remove it");
        assert!(q.find_available_pending_event().is_none(), "leased event is unavailable until lease expires");
        assert!(q.acknowledge_pending_event("e1").is_some());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn acknowledge_unknown_id_returns_none() {
        let q = QueueState::new();
        assert!(q.acknowledge_pending_event("missing").is_none());
    }

    #[test]
    fn cancel_queued_anonymous_exit_events_only_removes_anonymous_exits() {
        let q = QueueState::new();
        q.enqueue_event(json!({"type": "exit"}));
        q.enqueue_event(json!({"id": "e2", "type": "exit"}));
        q.enqueue_event(json!({"id": "e3", "type": "generate"}));
        let removed = q.cancel_queued_anonymous_exit_events();
        assert_eq!(removed, 1);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn next_lease_deadline_ignores_unleased_entries() {
        let q = QueueState::new();
        q.enqueue_event(json!({"id": "e1", "type": "generate"}));
        assert_eq!(q.next_lease_deadline_ms(), None);
        let entry = q.find_available_pending_event().unwrap();
        q.lease_event(entry.seq, 1_000);
        assert!(q.next_lease_deadline_ms().unwrap() > 0);
    }

    #[test]
    fn find_pending_event_by_id_round_trips() {
        let q = QueueState::new();
        q.enqueue_event(json!({"id": "e1", "type": "generate", "payload": 42}));
        let found = q.find_pending_event_by_id("e1").unwrap();
        assert_eq!(found["payload"], 42);
        assert!(q.find_pending_event_by_id("nope").is_none());
    }
}
