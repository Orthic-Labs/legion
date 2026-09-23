//! Port of the pure pending-event-queue logic in
//! `skills/designer/engine/scripts/live-server.mjs`.
//!
//! The source file is a stateful, self-contained Node `http`/SSE server;
//! this ports its in-memory event-queue bookkeeping (`state.pendingEvents`
//! / `state.pendingPolls` and the functions that mutate them) as a
//! standalone [`EventQueue`] struct driven by an injected clock, since that
//! bookkeeping has a clear input/output contract independent of the HTTP
//! transport. The request handler, SSE broadcast, port probing
//! (`findOpenPort`), and file-backed manual-edit/session-store
//! integrations are not ported — see [`crate::wf_port::w2_019`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch, mirroring JS `Date.now()`. Exposed so
/// tests (and any future caller) can inject a fixed value instead of the
/// wall clock.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Mirrors one `state.pendingEvents` entry: `{ event, leaseUntil, seq }`.
/// `event_id`/`event_type` stand in for the full JS event object; callers
/// that need the rest of the payload keep it alongside by `event_id`.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingEventEntry {
    pub event_id: Option<String>,
    pub event_type: String,
    pub lease_until: u64,
    pub seq: u64,
}

/// Port of `live-server.mjs`'s `state.{pendingEvents,pendingPolls,
/// nextEventSeq,lastAgentPollingBroadcast}` plus the functions that operate
/// on them: `enqueueEvent`, `findAvailablePendingEvent`, `leaseEvent`,
/// `acknowledgePendingEvent`, `findPendingEventById`,
/// `cancelQueuedAnonymousExitEvents`, `agentPollingConnected`, and the
/// "is a chat agent likely attached" freshness check from
/// `chatAgentLikelyActive`.
#[derive(Debug, Default)]
pub struct EventQueue {
    pending_events: Vec<PendingEventEntry>,
    /// Number of currently-parked long-poll requests (`state.pendingPolls
    /// .length`); this port does not model each poll's own resolve
    /// callback, only the count `agentPollingConnected`/`flushPendingPolls`
    /// need.
    pending_poll_count: usize,
    next_event_seq: u64,
    last_poll_at: Option<u64>,
}

/// Freshness window from `CHAT_POLL_FRESHNESS_MS` in `live-server.mjs`.
pub const CHAT_POLL_FRESHNESS_MS: u64 = 60_000;

impl EventQueue {
    pub fn new() -> Self {
        Self {
            pending_events: Vec::new(),
            pending_poll_count: 0,
            next_event_seq: 1,
            last_poll_at: None,
        }
    }

    pub fn pending_events(&self) -> &[PendingEventEntry] {
        &self.pending_events
    }

    /// Port of `enqueueEvent(event)`. A `None` `event_id` (anonymous
    /// event, e.g. a bare `exit`) is never deduped against existing
    /// entries, matching JS's `event.id &&` guard. Returns `true` when the
    /// event was actually queued (JS's early `return` on a duplicate
    /// id+type pair is the `false` case here).
    pub fn enqueue_event(&mut self, event_id: Option<String>, event_type: &str) -> bool {
        if let Some(id) = &event_id {
            let is_duplicate = self.pending_events.iter().any(|entry| {
                entry.event_id.as_deref() == Some(id.as_str()) && entry.event_type == event_type
            });
            if is_duplicate {
                return false;
            }
        }
        let seq = self.next_event_seq;
        self.next_event_seq += 1;
        self.pending_events.push(PendingEventEntry {
            event_id,
            event_type: event_type.to_string(),
            lease_until: 0,
            seq,
        });
        true
    }

    /// Port of `findAvailablePendingEvent(now)`: the first entry whose
    /// lease has expired (or was never leased), in queue order.
    pub fn find_available_pending_event(&self, now: u64) -> Option<&PendingEventEntry> {
        self.pending_events
            .iter()
            .find(|entry| entry.lease_until == 0 || entry.lease_until <= now)
    }

    /// Port of `leaseEvent(entry, leaseMs)` for an id-bearing entry: sets
    /// `leaseUntil = now + leaseMs` and returns the leased event's id.
    /// Anonymous (no-id) entries are removed outright on lease, mirroring
    /// JS's `if (!entry.event?.id) { ...splice...; return entry.event; }`
    /// branch — callers should check [`Self::enqueue_event`]'s `event_id`
    /// separately for that case since there is nothing left to look up
    /// afterward; use [`Self::lease_by_seq`] to drive both branches.
    pub fn lease_by_seq(&mut self, seq: u64, lease_ms: u64, now: u64) -> Option<PendingEventEntry> {
        let idx = self.pending_events.iter().position(|e| e.seq == seq)?;
        if self.pending_events[idx].event_id.is_none() {
            return Some(self.pending_events.remove(idx));
        }
        self.pending_events[idx].lease_until = now + lease_ms;
        Some(self.pending_events[idx].clone())
    }

    /// Port of `acknowledgePendingEvent(id)`. Returns `true` iff an entry
    /// with that id was found and removed.
    pub fn acknowledge_pending_event(&mut self, id: &str) -> bool {
        let idx = self
            .pending_events
            .iter()
            .position(|entry| entry.event_id.as_deref() == Some(id));
        match idx {
            Some(i) => {
                self.pending_events.remove(i);
                true
            }
            None => false,
        }
    }

    /// Port of `findPendingEventById(id)`.
    pub fn find_pending_event_by_id(&self, id: &str) -> Option<&PendingEventEntry> {
        self.pending_events
            .iter()
            .find(|entry| entry.event_id.as_deref() == Some(id))
    }

    /// Port of `cancelQueuedAnonymousExitEvents()`: removes every
    /// unleased-id (`event.id` falsy) `exit` entry. Returns the count
    /// removed.
    pub fn cancel_queued_anonymous_exit_events(&mut self) -> usize {
        let before = self.pending_events.len();
        self.pending_events
            .retain(|entry| !(entry.event_type == "exit" && entry.event_id.is_none()));
        before - self.pending_events.len()
    }

    /// Port of `scheduleLeaseFlush`'s "next wakeup" computation: the
    /// soonest `leaseUntil` strictly in the future, or `None` when nothing
    /// is currently leased (JS: no timer is scheduled).
    pub fn next_lease_wakeup(&self, now: u64) -> Option<u64> {
        self.pending_events
            .iter()
            .map(|entry| entry.lease_until)
            .filter(|&lease_until| lease_until > now)
            .min()
    }

    pub fn set_pending_poll_count(&mut self, count: usize) {
        self.pending_poll_count = count;
    }

    pub fn record_poll_at(&mut self, now: u64) {
        self.last_poll_at = Some(now);
    }

    /// Port of `agentPollingConnected()`: a poll is parked, or some entry
    /// is currently leased.
    pub fn agent_polling_connected(&self, now: u64) -> bool {
        self.pending_poll_count > 0
            || self
                .pending_events
                .iter()
                .any(|entry| entry.lease_until > 0 && entry.lease_until > now)
    }

    /// Port of `chatAgentLikelyActive()`.
    pub fn chat_agent_likely_active(&self, now: u64) -> bool {
        if self.pending_poll_count > 0 {
            return true;
        }
        match self.last_poll_at {
            None => false,
            Some(t) => now.saturating_sub(t) < CHAT_POLL_FRESHNESS_MS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_dedupes_on_matching_id_and_type() {
        let mut q = EventQueue::new();
        assert!(q.enqueue_event(Some("e1".into()), "generate"));
        assert!(!q.enqueue_event(Some("e1".into()), "generate"));
        // Same id, different type is not a duplicate.
        assert!(q.enqueue_event(Some("e1".into()), "steer"));
        assert_eq!(q.pending_events().len(), 2);
    }

    #[test]
    fn enqueue_never_dedupes_anonymous_events() {
        let mut q = EventQueue::new();
        assert!(q.enqueue_event(None, "exit"));
        assert!(q.enqueue_event(None, "exit"));
        assert_eq!(q.pending_events().len(), 2);
    }

    #[test]
    fn find_available_pending_event_skips_leased_entries() {
        let mut q = EventQueue::new();
        q.enqueue_event(Some("e1".into()), "generate");
        q.enqueue_event(Some("e2".into()), "generate");
        let seq1 = q.pending_events()[0].seq;
        q.lease_by_seq(seq1, 10_000, 1_000);
        let available = q.find_available_pending_event(1_000).unwrap();
        assert_eq!(available.event_id.as_deref(), Some("e2"));
    }

    #[test]
    fn find_available_pending_event_returns_entries_whose_lease_expired() {
        let mut q = EventQueue::new();
        q.enqueue_event(Some("e1".into()), "generate");
        let seq1 = q.pending_events()[0].seq;
        q.lease_by_seq(seq1, 1_000, 1_000); // lease_until = 2000
        let available = q.find_available_pending_event(5_000).unwrap();
        assert_eq!(available.event_id.as_deref(), Some("e1"));
    }

    #[test]
    fn lease_by_seq_removes_anonymous_entries_instead_of_leasing() {
        let mut q = EventQueue::new();
        q.enqueue_event(None, "exit");
        let seq = q.pending_events()[0].seq;
        let leased = q.lease_by_seq(seq, 10_000, 1_000).unwrap();
        assert_eq!(leased.event_id, None);
        assert!(q.pending_events().is_empty());
    }

    #[test]
    fn acknowledge_pending_event_removes_matching_entry() {
        let mut q = EventQueue::new();
        q.enqueue_event(Some("e1".into()), "generate");
        assert!(q.acknowledge_pending_event("e1"));
        assert!(!q.acknowledge_pending_event("e1"));
        assert!(q.pending_events().is_empty());
    }

    #[test]
    fn find_pending_event_by_id_looks_up_by_id() {
        let mut q = EventQueue::new();
        q.enqueue_event(Some("e1".into()), "generate");
        assert!(q.find_pending_event_by_id("e1").is_some());
        assert!(q.find_pending_event_by_id("missing").is_none());
    }

    #[test]
    fn cancel_queued_anonymous_exit_events_only_removes_unleased_anonymous_exits() {
        let mut q = EventQueue::new();
        q.enqueue_event(None, "exit");
        q.enqueue_event(Some("e1".into()), "exit");
        q.enqueue_event(None, "generate");
        let removed = q.cancel_queued_anonymous_exit_events();
        assert_eq!(removed, 1);
        assert_eq!(q.pending_events().len(), 2);
        assert!(q
            .pending_events()
            .iter()
            .any(|e| e.event_id.as_deref() == Some("e1")));
    }

    #[test]
    fn next_lease_wakeup_returns_soonest_future_lease() {
        let mut q = EventQueue::new();
        q.enqueue_event(Some("e1".into()), "generate");
        q.enqueue_event(Some("e2".into()), "generate");
        let seq1 = q.pending_events()[0].seq;
        let seq2 = q.pending_events()[1].seq;
        q.lease_by_seq(seq1, 5_000, 1_000); // 6000
        q.lease_by_seq(seq2, 2_000, 1_000); // 3000
        assert_eq!(q.next_lease_wakeup(1_000), Some(3_000));
        assert_eq!(q.next_lease_wakeup(10_000), None);
    }

    #[test]
    fn agent_polling_connected_true_when_poll_parked_or_lease_active() {
        let mut q = EventQueue::new();
        assert!(!q.agent_polling_connected(1_000));
        q.set_pending_poll_count(1);
        assert!(q.agent_polling_connected(1_000));
        q.set_pending_poll_count(0);
        q.enqueue_event(Some("e1".into()), "generate");
        let seq = q.pending_events()[0].seq;
        q.lease_by_seq(seq, 5_000, 1_000);
        assert!(q.agent_polling_connected(2_000));
        assert!(!q.agent_polling_connected(6_000));
    }

    #[test]
    fn chat_agent_likely_active_uses_freshness_window() {
        let mut q = EventQueue::new();
        assert!(!q.chat_agent_likely_active(1_000));
        q.record_poll_at(1_000);
        assert!(q.chat_agent_likely_active(1_000 + CHAT_POLL_FRESHNESS_MS - 1));
        assert!(!q.chat_agent_likely_active(1_000 + CHAT_POLL_FRESHNESS_MS));
        q.set_pending_poll_count(1);
        assert!(q.chat_agent_likely_active(1_000 + CHAT_POLL_FRESHNESS_MS));
    }

    #[test]
    fn now_ms_is_monotonic_reasonable() {
        let a = now_ms();
        let b = now_ms();
        assert!(b >= a);
    }
}
