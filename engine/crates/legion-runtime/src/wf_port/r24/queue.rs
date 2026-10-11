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

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Server-to-browser broadcast log (JS `broadcast(msg)` over
    /// `state.sseClients`). Each SSE connection keeps its own cursor into
    /// this bounded log instead of holding a registered writer.
    sse_log: Mutex<SseLog>,
    /// Set once by the `/stop` route; long-lived handlers (SSE, long poll)
    /// observe it and return so the server can join its connection threads.
    shutdown: AtomicBool,
    /// Number of agent long-polls currently parked (JS `state.pendingPolls`).
    active_polls: AtomicUsize,
    /// JS `state.lastAgentPollingBroadcast`.
    last_polling_broadcast: AtomicBool,
    /// Delay between the last SSE client leaving and the synthetic `exit`
    /// event (JS `setTimeout(..., 8000)` on `state.exitTimer`). Injectable so
    /// tests do not sleep for eight seconds.
    exit_grace: Duration,
}

/// Maximum number of broadcast messages retained for lagging SSE readers.
const SSE_LOG_CAP: usize = 256;

struct SseLog {
    /// Sequence number of the most recently published message (0 = none).
    last_seq: u64,
    entries: Vec<(u64, Value)>,
}

/// Queue plus SSE-client bookkeeping under one lock, so the exit grace timer's
/// "no clients remain, enqueue exit" check is atomic with respect to a
/// reconnect.
struct Inner {
    pending_events: Vec<PendingEventEntry>,
    /// JS `state.sseClients.size`: authorized `GET /events` streams open now.
    sse_clients: usize,
    /// Bumped on every connect and disconnect. A grace timer captures the value
    /// it started with and stands down if it has changed (JS `clearTimeout`
    /// on reconnect).
    sse_generation: u64,
}

/// JS `state.exitTimer` delay: 8000 ms after the last SSE client disconnects
/// (`live-server.mjs`, the `/events` close handler).
pub const EXIT_GRACE_DEFAULT: Duration = Duration::from_millis(8000);
/// Sleep granularity while the grace window runs, so shutdown is seen promptly.
const EXIT_GRACE_STEP: Duration = Duration::from_millis(100);

/// Decision half of the exit grace timer, pure so it can be tested without
/// sleeping. JS: `if (state.sseClients.size === 0) enqueueEvent({ type: 'exit' })`.
/// Fires only when no SSE client remains, no connect or disconnect happened
/// since the timer started, and the server is not shutting down.
pub fn exit_grace_should_fire(
    sse_clients: usize,
    started_generation: u64,
    current_generation: u64,
    shutdown: bool,
) -> bool {
    sse_clients == 0 && !shutdown && started_generation == current_generation
}

impl QueueState {
    pub fn new() -> Self {
        Self::with_exit_grace(EXIT_GRACE_DEFAULT)
    }

    /// [`QueueState::new`] with an explicit exit grace delay.
    pub fn with_exit_grace(exit_grace: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                pending_events: Vec::new(),
                sse_clients: 0,
                sse_generation: 0,
            }),
            next_event_seq: AtomicU64::new(1),
            sse_log: Mutex::new(SseLog {
                last_seq: 0,
                entries: Vec::new(),
            }),
            shutdown: AtomicBool::new(false),
            active_polls: AtomicUsize::new(0),
            last_polling_broadcast: AtomicBool::new(false),
            exit_grace,
        }
    }

    /// JS `broadcast(msg)`: append a message for every connected SSE client.
    pub fn publish_sse(&self, msg: Value) {
        let mut log = self.sse_log.lock().unwrap();
        log.last_seq += 1;
        let seq = log.last_seq;
        log.entries.push((seq, msg));
        if log.entries.len() > SSE_LOG_CAP {
            let excess = log.entries.len() - SSE_LOG_CAP;
            log.entries.drain(0..excess);
        }
    }

    /// Cursor value meaning "everything published so far has been seen".
    pub fn sse_cursor(&self) -> u64 {
        self.sse_log.lock().unwrap().last_seq
    }

    /// Broadcast messages published after `after`, oldest first.
    pub fn sse_messages_after(&self, after: u64) -> Vec<(u64, Value)> {
        let log = self.sse_log.lock().unwrap();
        log.entries
            .iter()
            .filter(|(seq, _)| *seq > after)
            .cloned()
            .collect()
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// JS `agentPollingConnected()`: a parked poll, or an event whose lease
    /// is still live.
    pub fn agent_polling_connected(&self) -> bool {
        if self.active_polls.load(Ordering::SeqCst) > 0 {
            return true;
        }
        let now = now_ms();
        let inner = self.inner.lock().unwrap();
        inner
            .pending_events
            .iter()
            .any(|e| e.lease_until_ms > 0 && e.lease_until_ms > now)
    }

    /// JS `broadcastAgentPollingIfChanged()`.
    pub fn broadcast_agent_polling_if_changed(&self) {
        let connected = self.agent_polling_connected();
        let previous = self
            .last_polling_broadcast
            .swap(connected, Ordering::SeqCst);
        if previous != connected {
            self.publish_sse(
                serde_json::json!({ "type": "agent_polling", "connected": connected }),
            );
        }
    }

    /// Call when an agent long-poll starts waiting.
    pub fn poll_started(&self) {
        self.active_polls.fetch_add(1, Ordering::SeqCst);
        self.broadcast_agent_polling_if_changed();
    }

    /// Call when an agent long-poll stops waiting (answered or timed out).
    pub fn poll_finished(&self) {
        let _ = self
            .active_polls
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        self.broadcast_agent_polling_if_changed();
    }

    /// `enqueueEvent(event)`: dedupe on `(event.id, event.type)` already
    /// present and unleased-or-leased (JS dedupes on id+type unconditionally
    /// of lease state — `state.pendingEvents.some(...)` scans everything),
    /// then push with `leaseUntil: 0`.
    pub fn enqueue_event(&self, event: Value) {
        let mut inner = self.inner.lock().unwrap();
        self.enqueue_locked(&mut inner, event);
    }

    /// Body of [`QueueState::enqueue_event`] for callers already holding the
    /// `inner` lock.
    fn enqueue_locked(&self, inner: &mut Inner, event: Value) {
        let id = event.get("id").and_then(Value::as_str).map(str::to_owned);
        let ty = event.get("type").and_then(Value::as_str).map(str::to_owned);
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

    /// An authorized `GET /events` stream opened (JS `state.sseClients.add`).
    /// Bumps the generation so any pending exit grace timer stands down.
    pub fn sse_client_connected(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.sse_clients += 1;
        inner.sse_generation += 1;
    }

    /// An SSE stream ended (JS `req.on('close')`). Returns the generation to
    /// start the exit grace timer with when this left no clients, else `None`.
    pub fn sse_client_disconnected(&self) -> Option<u64> {
        let mut inner = self.inner.lock().unwrap();
        inner.sse_clients = inner.sse_clients.saturating_sub(1);
        inner.sse_generation += 1;
        (inner.sse_clients == 0).then_some(inner.sse_generation)
    }

    /// Number of browser clients currently holding the event stream open.
    pub fn sse_client_count(&self) -> usize {
        self.inner.lock().unwrap().sse_clients
    }

    /// Body of the exit grace timer. Sleeps in short steps so shutdown is seen
    /// promptly, then enqueues the anonymous `exit` event only if
    /// [`exit_grace_should_fire`] still holds. Intended to run on a thread the
    /// caller owns; returns when the window elapses or shutdown begins.
    pub fn run_exit_grace(&self, started_generation: u64) {
        let deadline = Instant::now() + self.exit_grace;
        while !self.is_shutdown() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            thread::sleep((deadline - now).min(EXIT_GRACE_STEP));
        }
        let mut inner = self.inner.lock().unwrap();
        let fire = exit_grace_should_fire(
            inner.sse_clients,
            started_generation,
            inner.sse_generation,
            self.is_shutdown(),
        );
        if fire {
            // Anonymous, so no dedupe; same shape as JS `enqueueEvent({ type: 'exit' })`.
            self.enqueue_locked(&mut inner, serde_json::json!({ "type": "exit" }));
        }
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
        assert_eq!(
            q.len(),
            0,
            "anonymous events have no id to ack later, so lease consumes them"
        );
    }

    #[test]
    fn identified_event_stays_queued_until_acknowledged() {
        let q = QueueState::new();
        q.enqueue_event(json!({"id": "e1", "type": "generate"}));
        let entry = q.find_available_pending_event().unwrap();
        q.lease_event(entry.seq, 5_000);
        assert_eq!(q.len(), 1, "leasing an identified event does not remove it");
        assert!(
            q.find_available_pending_event().is_none(),
            "leased event is unavailable until lease expires"
        );
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

    #[test]
    fn sse_log_delivers_messages_after_cursor_in_order() {
        let q = QueueState::new();
        q.publish_sse(json!({"type": "a"}));
        let cursor = q.sse_cursor();
        q.publish_sse(json!({"type": "b"}));
        q.publish_sse(json!({"type": "c"}));
        let msgs = q.sse_messages_after(cursor);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].1["type"], "b");
        assert_eq!(msgs[1].1["type"], "c");
        assert!(q.sse_messages_after(q.sse_cursor()).is_empty());
    }

    #[test]
    fn agent_polling_broadcast_fires_only_on_change() {
        let q = QueueState::new();
        let start = q.sse_cursor();
        q.poll_started();
        q.poll_started();
        q.poll_finished();
        q.poll_finished();
        let msgs = q.sse_messages_after(start);
        assert_eq!(msgs.len(), 2, "one true edge and one false edge");
        assert_eq!(msgs[0].1["connected"], true);
        assert_eq!(msgs[1].1["connected"], false);
    }

    #[test]
    fn exit_grace_decision_requires_no_clients_same_generation_and_no_shutdown() {
        assert!(exit_grace_should_fire(0, 4, 4, false));
        assert!(
            !exit_grace_should_fire(1, 4, 4, false),
            "a client is connected"
        );
        assert!(
            !exit_grace_should_fire(0, 4, 5, false),
            "a connect or disconnect happened after the timer started"
        );
        assert!(
            !exit_grace_should_fire(0, 4, 4, true),
            "shutdown suppresses the synthetic exit"
        );
    }

    #[test]
    fn last_disconnect_enqueues_anonymous_exit_when_grace_elapses() {
        let q = QueueState::with_exit_grace(Duration::from_millis(5));
        q.sse_client_connected();
        let generation = q.sse_client_disconnected().expect("last client left");
        q.run_exit_grace(generation);
        assert_eq!(q.len(), 1);
        let entry = q.find_available_pending_event().unwrap();
        assert_eq!(entry.event_type(), Some("exit"));
        assert_eq!(
            entry.id(),
            None,
            "shape matches JS enqueueEvent({{ type: 'exit' }})"
        );
    }

    #[test]
    fn disconnect_with_another_client_still_connected_starts_no_grace() {
        let q = QueueState::with_exit_grace(Duration::from_millis(5));
        q.sse_client_connected();
        q.sse_client_connected();
        assert_eq!(q.sse_client_disconnected(), None);
        assert_eq!(q.inner.lock().unwrap().sse_clients, 1);
    }

    #[test]
    fn reconnect_within_grace_cancels_the_pending_exit() {
        let q = QueueState::with_exit_grace(Duration::from_millis(5));
        q.sse_client_connected();
        let generation = q.sse_client_disconnected().unwrap();
        q.sse_client_connected();
        q.run_exit_grace(generation);
        assert_eq!(q.len(), 0);
        assert_eq!(q.inner.lock().unwrap().sse_clients, 1);
    }

    #[test]
    fn shutdown_during_grace_returns_promptly_without_exit() {
        let q = QueueState::with_exit_grace(Duration::from_secs(60));
        q.sse_client_connected();
        let generation = q.sse_client_disconnected().unwrap();
        q.request_shutdown();
        q.run_exit_grace(generation);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn default_exit_grace_matches_js_eight_seconds() {
        assert_eq!(EXIT_GRACE_DEFAULT, Duration::from_millis(8000));
    }
}
